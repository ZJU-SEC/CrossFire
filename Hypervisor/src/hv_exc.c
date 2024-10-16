/* SPDX-License-Identifier: MIT */

#include "hv.h"
#include "assert.h"
#include "cpu_regs.h"
#include "exception.h"
#include "smp.h"
#include "string.h"
#include "uart.h"
#include "uartproxy.h"
#include "breakpoint.h"
#include "types.h"
#include "breakpoint_wrapper.h"

#define TIME_ACCOUNTING
#define SHADOW_PAGETABLE 1

extern spinlock_t bhl;

#define _SYSREG_ISS(_1, _2, op0, op1, CRn, CRm, op2)                                               \
    (((op0) << ESR_ISS_MSR_OP0_SHIFT) | ((op1) << ESR_ISS_MSR_OP1_SHIFT) |                         \
     ((CRn) << ESR_ISS_MSR_CRn_SHIFT) | ((CRm) << ESR_ISS_MSR_CRm_SHIFT) |                         \
     ((op2) << ESR_ISS_MSR_OP2_SHIFT))
#define SYSREG_ISS(...) _SYSREG_ISS(__VA_ARGS__)

#define PERCPU(x) pcpu[mrs(TPIDR_EL2)].x

struct hv_pcpu_data {
    u32 ipi_queued;
    u32 ipi_pending;
    u32 pmc_pending;
    u64 pmc_irq_mode;
    u64 exc_entry_pmcr0_cnt;
} ALIGNED(64);

struct hv_pcpu_data pcpu[MAX_CPUS];
bool hv_had_triggered_proxy[MAX_CPUS];

void hv_exit_guest(void) __attribute__((noreturn));

static u64 stolen_time = 0;
static u64 exc_entry_time;

extern u64 hv_cpus_in_guest;
extern int hv_pinned_cpu;
extern int hv_want_cpu;

static bool time_stealing = true;
u64 SScnt = 0;
u64 SSsteps[MAX_CPUS] = {0};
static void _hv_exc_proxy(struct exc_info *ctx, uartproxy_boot_reason_t reason, u32 type,
                          void *extra)
{
    int from_el = FIELD_GET(SPSR_M, ctx->spsr) >> 2;

    hv_wdt_breadcrumb('P');

    /*
     * Get all the CPUs into the HV before running the proxy, to make sure they all exit to
     * the guest with a consistent time offset.
     */
    if (time_stealing)
        hv_rendezvous();

    u64 entry_time = mrs(CNTPCT_EL0);

    ctx->elr_phys = hv_translate(ctx->elr, false, false, NULL);
    ctx->far_phys = hv_translate(ctx->far, false, false, NULL);
    ctx->sp_phys = hv_translate(from_el == 0 ? ctx->sp[0] : ctx->sp[1], false, false, NULL);
    ctx->extra = extra;

    struct uartproxy_msg_start start = {
        .reason = reason,
        .code = type,
        .info = ctx,
    };

    hv_wdt_suspend();
    int ret = uartproxy_run(&start);
    hv_wdt_resume();

    switch (ret) {
        case EXC_RET_HANDLED:
            hv_wdt_breadcrumb('p');
            if (time_stealing) {
                u64 lost = mrs(CNTPCT_EL0) - entry_time;
                stolen_time += lost;
            }
            break;
        case EXC_EXIT_GUEST:
            hv_rendezvous();
            spin_unlock(&bhl);
            hv_exit_guest(); // does not return
        default:
            printf("Guest exception not handled, rebooting.\n");
            print_regs(ctx->regs, 0);
            flush_and_reboot(); // does not return
    }
}

static void hv_maybe_switch_cpu(struct exc_info *ctx, uartproxy_boot_reason_t reason, u32 type,
                                void *extra)
{
    while (hv_want_cpu != -1) {
        if (hv_want_cpu == smp_id()) {
            hv_want_cpu = -1;
            _hv_exc_proxy(ctx, reason, type, extra);
        } else {
            // Unlock the HV so the target CPU can get into the proxy
            spin_unlock(&bhl);
            while (hv_want_cpu != -1)
                sysop("dmb sy");
            spin_lock(&bhl);
        }
    }
}

void hv_exc_proxy(struct exc_info *ctx, uartproxy_boot_reason_t reason, u32 type, void *extra)
{
    /*
     * Wait while another CPU is pinned or being switched to.
     * If a CPU switch is requested, handle it before actually handling the
     * exception. We still tell the host the real reason code, though.
     */
    while ((hv_pinned_cpu != -1 && hv_pinned_cpu != smp_id()) || hv_want_cpu != -1) {
        if (hv_want_cpu == smp_id()) {
            hv_want_cpu = -1;
            // printf("[hv_exc_proxy] cpu:%d hv_want_cpu while\n",smp_id());
            _hv_exc_proxy(ctx, reason, type, extra);
        } else {
            // Unlock the HV so the target CPU can get into the proxy
            spin_unlock(&bhl);
            while ((hv_pinned_cpu != -1 && hv_pinned_cpu != smp_id()) || hv_want_cpu != -1)
                sysop("dmb sy");
            spin_lock(&bhl);
        }
    }
    // printf("[hv_exc_proxy] cpu:%d out while\n",smp_id());
    /* Handle the actual exception */
    _hv_exc_proxy(ctx, reason, type, extra);

    /*
     * If as part of handling this exception we want to switch CPUs, handle it without returning
     * to the guest.
     */
    hv_maybe_switch_cpu(ctx, reason, type, extra);
}

void hv_set_time_stealing(bool enabled, bool reset)
{
    time_stealing = enabled;
    if (reset)
        stolen_time = 0;
}

void hv_add_time(s64 time)
{
    stolen_time -= (u64)time;
}

static void hv_update_fiq(void)
{
    u64 hcr = mrs(HCR_EL2);
    bool fiq_pending = false;
    // hv_wdt_breadcrumb('o');
    if (mrs(CNTP_CTL_EL02) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        fiq_pending = true;
        reg_clr(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_P);
    } else {
        reg_set(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_P);
    }
    // hv_wdt_breadcrumb('O');
    if (mrs(CNTV_CTL_EL02) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        fiq_pending = true;
        reg_clr(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_V);
    } else {
        reg_set(SYS_IMP_APL_VM_TMR_FIQ_ENA_EL2, VM_TMR_FIQ_ENA_ENA_V);
    }

    fiq_pending |= PERCPU(ipi_pending) || PERCPU(pmc_pending);
    sysop("isb");
    // hv_wdt_breadcrumb('o');
    if ((hcr & HCR_VF) && !fiq_pending) {
        hv_write_hcr(hcr & ~HCR_VF);
    } else if (!(hcr & HCR_VF) && fiq_pending) {
        hv_write_hcr(hcr | HCR_VF);
    }
}

#define SYSREG_MAP(sr, to)                                                                         \
    case SYSREG_ISS(sr):                                                                           \
        if (is_read)                                                                               \
            regs[rt] = _mrs(sr_tkn(to));                                                           \
        else                                                                                       \
            _msr(sr_tkn(to), regs[rt]);                                                            \
        return true;

#define SYSREG_PASS(sr)                                                                            \
    case SYSREG_ISS(sr):                                                                           \
        if (is_read)                                                                               \
            regs[rt] = _mrs(sr_tkn(sr));                                                           \
        else                                                                                       \
            _msr(sr_tkn(sr), regs[rt]);                                                            \
        return true;

static bool hv_handle_msr_unlocked(struct exc_info *ctx, u64 iss)
{
    u64 reg = iss & (ESR_ISS_MSR_OP0 | ESR_ISS_MSR_OP2 | ESR_ISS_MSR_OP1 | ESR_ISS_MSR_CRn |
                     ESR_ISS_MSR_CRm);
    u64 rt = FIELD_GET(ESR_ISS_MSR_Rt, iss);
    bool is_read = iss & ESR_ISS_MSR_DIR;

    u64 *regs = ctx->regs;

    regs[31] = 0;

    switch (reg) {
        /* Some kind of timer */
        SYSREG_PASS(sys_reg(3, 7, 15, 1, 1));
        SYSREG_PASS(sys_reg(3, 7, 15, 3, 1));
        /* Architectural timer, for ECV */
        SYSREG_MAP(SYS_CNTV_CTL_EL0, SYS_CNTV_CTL_EL02)
        SYSREG_MAP(SYS_CNTV_CVAL_EL0, SYS_CNTV_CVAL_EL02)
        SYSREG_MAP(SYS_CNTV_TVAL_EL0, SYS_CNTV_TVAL_EL02)
        SYSREG_MAP(SYS_CNTP_CTL_EL0, SYS_CNTP_CTL_EL02)
        SYSREG_MAP(SYS_CNTP_CVAL_EL0, SYS_CNTP_CVAL_EL02)
        SYSREG_MAP(SYS_CNTP_TVAL_EL0, SYS_CNTP_TVAL_EL02)
        /* Spammy stuff seen on t600x p-cores */
        SYSREG_PASS(sys_reg(3, 2, 15, 12, 0));
        SYSREG_PASS(sys_reg(3, 2, 15, 13, 0));
        SYSREG_PASS(sys_reg(3, 2, 15, 14, 0));
        SYSREG_PASS(sys_reg(3, 2, 15, 15, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 7, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 8, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 9, 0));
        SYSREG_PASS(sys_reg(3, 1, 15, 10, 0));
        /* Noisy traps */
        SYSREG_MAP(SYS_ACTLR_EL1, SYS_IMP_APL_ACTLR_EL12)
        SYSREG_PASS(SYS_IMP_APL_HID4)
        SYSREG_PASS(SYS_IMP_APL_EHID4)
        /* We don't normally trap hese, but if we do, they're noisy */
        SYSREG_PASS(SYS_IMP_APL_GXF_STATUS_EL1)
        SYSREG_PASS(SYS_IMP_APL_CNTVCT_ALIAS_EL0)
        SYSREG_PASS(SYS_IMP_APL_TPIDR_GL1)
        SYSREG_MAP(SYS_IMP_APL_SPSR_GL1, SYS_IMP_APL_SPSR_GL12)
        SYSREG_MAP(SYS_IMP_APL_ASPSR_GL1, SYS_IMP_APL_ASPSR_GL12)
        SYSREG_MAP(SYS_IMP_APL_ELR_GL1, SYS_IMP_APL_ELR_GL12)
        SYSREG_MAP(SYS_IMP_APL_ESR_GL1, SYS_IMP_APL_ESR_GL12)
        SYSREG_MAP(SYS_IMP_APL_SPRR_PERM_EL1, SYS_IMP_APL_SPRR_PERM_EL12)
        SYSREG_MAP(SYS_IMP_APL_APCTL_EL1, SYS_IMP_APL_APCTL_EL12)
        SYSREG_MAP(SYS_IMP_APL_AMX_CTL_EL1, SYS_IMP_APL_AMX_CTL_EL12)
        /* FIXME:Might be wrong */
        SYSREG_PASS(sys_reg(3, 4, 15, 1, 3))
        /* pass through PMU handling */
        SYSREG_PASS(SYS_IMP_APL_PMCR1)
        SYSREG_PASS(SYS_IMP_APL_PMCR2)
        SYSREG_PASS(SYS_IMP_APL_PMCR3)
        SYSREG_PASS(SYS_IMP_APL_PMCR4)
        SYSREG_PASS(SYS_IMP_APL_PMESR0)
        SYSREG_PASS(SYS_IMP_APL_PMESR1)
        SYSREG_PASS(SYS_IMP_APL_PMSR)
#ifndef DEBUG_PMU_IRQ
        SYSREG_PASS(SYS_IMP_APL_PMC0)
#endif
        SYSREG_PASS(SYS_IMP_APL_PMC1)
        SYSREG_PASS(SYS_IMP_APL_PMC2)
        SYSREG_PASS(SYS_IMP_APL_PMC3)
        SYSREG_PASS(SYS_IMP_APL_PMC4)
        SYSREG_PASS(SYS_IMP_APL_PMC5)
        SYSREG_PASS(SYS_IMP_APL_PMC6)
        SYSREG_PASS(SYS_IMP_APL_PMC7)
        SYSREG_PASS(SYS_IMP_APL_PMC8)
        SYSREG_PASS(SYS_IMP_APL_PMC9)

        /* Outer Sharable TLB maintenance instructions */
        SYSREG_PASS(sys_reg(1, 0, 8, 1, 0)) // TLBI VMALLE1OS
        SYSREG_PASS(sys_reg(1, 0, 8, 1, 1)) // TLBI VAE1OS
        SYSREG_PASS(sys_reg(1, 0, 8, 1, 2)) // TLBI ASIDE1OS
        SYSREG_PASS(sys_reg(1, 0, 8, 5, 1)) // TLBI RVAE1OS

        case SYSREG_ISS(SYS_IMP_APL_IPI_SR_EL1):
            if (is_read)
                regs[rt] = PERCPU(ipi_pending) ? IPI_SR_PENDING : 0;
            else if (regs[rt] & IPI_SR_PENDING)
                PERCPU(ipi_pending) = false;
            return true;

        /* shadow the interrupt mode and state flag */
        case SYSREG_ISS(SYS_IMP_APL_PMCR0):
            if (is_read) {
                u64 val = (mrs(SYS_IMP_APL_PMCR0) & ~PMCR0_IMODE_MASK) | PERCPU(pmc_irq_mode);
                regs[rt] = val | (PERCPU(pmc_pending) ? PMCR0_IACT : 0);
            } else {
                PERCPU(pmc_pending) = !!(regs[rt] & PMCR0_IACT);
                PERCPU(pmc_irq_mode) = regs[rt] & PMCR0_IMODE_MASK;
                msr(SYS_IMP_APL_PMCR0, regs[rt]);
            }
            return true;

        /*
         * Handle this one here because m1n1/Linux (will) use it for explicit cpuidle.
         * We can pass it through; going into deep sleep doesn't break the HV since we
         * don't do any wfis that assume otherwise in m1n1. However, don't het macOS
         * disable WFI ret (when going into systemwide sleep), since that breaks things.
         */
        case SYSREG_ISS(SYS_IMP_APL_CYC_OVRD):
            if (is_read) {
                regs[rt] = mrs(SYS_IMP_APL_CYC_OVRD);
            } else {
                if (regs[rt] & (CYC_OVRD_DISABLE_WFI_RET | CYC_OVRD_FIQ_MODE_MASK))
                    return false;
                msr(SYS_IMP_APL_CYC_OVRD, regs[rt]);
            }
            return true;
            /* clang-format off */
        /* IPI handling */
        SYSREG_PASS(SYS_IMP_APL_IPI_CR_EL1)
        /* M1RACLES reg, handle here due to silly 12.0 "mitigation" */
        case SYSREG_ISS(sys_reg(3, 5, 15, 10, 1)):
            if (is_read)
                regs[rt] = 0;
            return true;
    }
    return false;
}

static bool hv_handle_msr(struct exc_info *ctx, u64 iss)
{
    u64 reg = iss & (ESR_ISS_MSR_OP0 | ESR_ISS_MSR_OP2 | ESR_ISS_MSR_OP1 | ESR_ISS_MSR_CRn |
                     ESR_ISS_MSR_CRm);
    u64 rt = FIELD_GET(ESR_ISS_MSR_Rt, iss);
    bool is_read = iss & ESR_ISS_MSR_DIR;

    u64 *regs = ctx->regs;

    regs[31] = 0;

    switch (reg) {
        /* clang-format on */
        case SYSREG_ISS(SYS_IMP_APL_IPI_RR_LOCAL_EL1): {
            assert(!is_read);
            u64 mpidr = (regs[rt] & 0xff) | (mrs(MPIDR_EL1) & 0xffff00);
            for (int i = 0; i < MAX_CPUS; i++)
                if (mpidr == smp_get_mpidr(i)) {
                    pcpu[i].ipi_queued = true;
                    msr(SYS_IMP_APL_IPI_RR_LOCAL_EL1, regs[rt]);
                    return true;
                }
            return false;
        }
        case SYSREG_ISS(SYS_IMP_APL_IPI_RR_GLOBAL_EL1):
            assert(!is_read);
            u64 mpidr = (regs[rt] & 0xff) | ((regs[rt] & 0xff0000) >> 8);
            for (int i = 0; i < MAX_CPUS; i++) {
                if (mpidr == (smp_get_mpidr(i) & 0xffff)) {
                    pcpu[i].ipi_queued = true;
                    msr(SYS_IMP_APL_IPI_RR_GLOBAL_EL1, regs[rt]);
                    return true;
                }
            }
            return false;
#ifdef DEBUG_PMU_IRQ
        case SYSREG_ISS(SYS_IMP_APL_PMC0):
            if (is_read) {
                regs[rt] = mrs(SYS_IMP_APL_PMC0);
            } else {
                msr(SYS_IMP_APL_PMC0, regs[rt]);
                printf("msr(SYS_IMP_APL_PMC0, 0x%04lx_%08lx)\n", regs[rt] >> 32,
                       regs[rt] & 0xFFFFFFFF);
            }
            return true;
#endif
    }

    return false;
}

static void hv_get_context(struct exc_info *ctx)
{
    ctx->spsr = hv_get_spsr();
    ctx->elr = hv_get_elr();
    ctx->esr = hv_get_esr();
    ctx->far = hv_get_far();
    ctx->afsr1 = hv_get_afsr1();
    ctx->sp[0] = mrs(SP_EL0);
    ctx->sp[1] = mrs(SP_EL1);
    ctx->sp[2] = (u64)ctx;
    ctx->cpu_id = smp_id();
    ctx->mpidr = mrs(MPIDR_EL1);

    sysop("isb");
}

static void hv_exc_entry(void)
{
    // Enable SErrors in the HV, but only if not already pending
    if (!(mrs(ISR_EL1) & 0x100))
        sysop("msr daifclr, 4");

    __atomic_and_fetch(&hv_cpus_in_guest, ~BIT(smp_id()), __ATOMIC_ACQUIRE);
    spin_lock(&bhl);
    hv_wdt_breadcrumb('X');
    exc_entry_time = mrs(CNTPCT_EL0);
    /* disable PMU counters in the hypervisor */
    u64 pmcr0 = mrs(SYS_IMP_APL_PMCR0);
    PERCPU(exc_entry_pmcr0_cnt) = pmcr0 & PMCR0_CNT_MASK;
    msr(SYS_IMP_APL_PMCR0, pmcr0 & ~PMCR0_CNT_MASK);
}

static void hv_exc_exit(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('x');
    hv_update_fiq();
    /* reenable PMU counters */
    reg_set(SYS_IMP_APL_PMCR0, PERCPU(exc_entry_pmcr0_cnt));
    msr(CNTVOFF_EL2, stolen_time);
    spin_unlock(&bhl);
    hv_maybe_exit();
    __atomic_or_fetch(&hv_cpus_in_guest, BIT(smp_id()), __ATOMIC_ACQUIRE);

    hv_set_spsr(ctx->spsr);
    hv_set_elr(ctx->elr);
    msr(SP_EL0, ctx->sp[0]);
    msr(SP_EL1, ctx->sp[1]);
}
u64 saveAddrForSingleStepReinstrument;
// extern bool DEBUGGER_MODE, TDSC_MODE, C_HANDLE__PAUTH_TRAP, SPTE_MODE;
extern bool C_HANDLE__PAUTH_TRAP;
extern u64 savedAddrForSingleStep, kaslrOffset;
extern u32 debugPid;
extern u64 AccurateSavedAddrForSingleStep[MAX_CPUS];
u64 lastPATrapAddr=0;
int lastPATrapCnt = 0;
void print_pa2(struct exc_info *ctx, char* inst_name, int reg1, int reg2, u64 ptr, u64 modifier){
    // if (ctx->elr == lastPATrapAddr){
    //     lastPATrapCnt ++;
    
    // }
    // else{
        printf("elr 0x%lx\t%s x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\tlastrepeat=%x\n",ctx->elr-kaslrOffset, inst_name, reg1, reg2, reg1, ptr, reg2, modifier, SScnt, lastPATrapCnt);
    // }
    // lastPATrapAddr = ctx->elr;
    // lastPATrapCnt = 0;
}
extern u64 PTE_MASK;
extern bool DEBUG;
// extern SSMODE SSmode;
u32 SSmode[MAX_CPUS] = {0}; 
void hv_exc_sync(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('S');
    hv_get_context(ctx);
    bool handled = false;
    u32 ec = FIELD_GET(ESR_EC, ctx->esr);
    u64 elr = 0;
    u32 imm = 0;
    const unsigned int pacia1716=0xd503211f, pacib1716=0xd503215f, paciaz=0xd503231f, paciasp=0xd503233f, pacibz=0xd503235f, pacibsp = 0xd503237f;
    const unsigned int autia1716=0xd503219f, autib1716=0xd50321df, autiaz=0xd503239f, autiasp=0xd50323bf, autibz=0xd50323df, autibsp = 0xd50323ff;
    
    const  unsigned int retaa = 0xd65f0bff, retab=0xd65f0fff;

    
        
        //   12b4:       d63f081f        blraaz  x0 
        //   12b8:       d63f0bdf        blraaz  x30
        const  unsigned int braaz =  0xd61f081f, brabz = 0xd61f0c1f;
        const  unsigned int blraaz = 0xd63f081f, blrabz = 0xd63f0c1f;
        

        
        const  unsigned int paciza = 0xdac123e0, pacizb=0xdac127e0, pacdza=0xdac12be0, pacdzb=0xdac12fe0 , autiza=0xdac133e0, autizb=0xdac137e0 ,autdza=0xdac13be0, autdzb=0xdac13fe0;

    
        
        const  unsigned int braa = 0xd71f0800 , brab = 0xd71f0c00;
        const  unsigned int blraa =0xd73f0800 , blrab= 0xd73f0c00;
        //pac
            
            // 1264:       dac10400        pacib   x0, x0
            // 1268:       dac10800        pacda   x0, x0
            // 126c:       dac10c00        pacdb   x0, x0
        const  unsigned int pacia = 0xdac10000, pacib=0xdac10400, pacda=0xdac10800, pacdb=0xdac10c00, autia=0xdac11000,autib=0xdac11400, autda=0xdac11800, autdb=0xdac11c00;
    
        //  1270:       9ac03000        pacga   x0, x0, x0
        //  1274:       9ade31e0        pacga   x0, x15, x30
        
        const u32 pacga = 0x9ac03000;

    int reg1 = 0, reg2=0, reg3 =0;
    u64 ptr=0, modifier=0, target = 0;
    u32 code = 0;
    bool skip = 0;
    u32 cpuid = smp_id();
    if (SSmode[cpuid] == TDSC){
        code = read32(hv_translate(ctx->elr, false,false, 0));
    }
    switch (ec) {
        case ESR_EC_MSR:
            hv_wdt_breadcrumb('m');
            handled = hv_handle_msr_unlocked(ctx, FIELD_GET(ESR_ISS, ctx->esr));
            break;
        case ESR_EC_IMPDEF:
            hv_wdt_breadcrumb('a');
            switch (FIELD_GET(ESR_ISS, ctx->esr)) {
                case ESR_ISS_IMPDEF_MSR:
                    handled = hv_handle_msr_unlocked(ctx, ctx->afsr1);
                    break;
            }
            break;
        case ESR_EC_SSTEP:
            printf("in ESR_EC_SSTEP\n");
            break;
        case ESR_EC_SSTEP_LOWER:
            
            ctx->elr -= 4;
            SScnt += 1;
            hv_wdt_breadcrumb('t');
            if (DEBUG){
                SSmode[cpuid] = COVERAGE; 
                printf("     ****************************      \n");
                printf("[*] Single Step Trap elr: 0x%lx! SSmode[%d]: %d\n", ctx->elr - kaslrOffset + 4, cpuid, SSmode[cpuid]);
            }
            if (SSmode[cpuid] == NORMAL){ 
                
                handleSingleStepReinstrument();
                turnOffSSServer();
                turnOffSS();
                handled = true;
            }
            else if (SSmode[cpuid] == COVERAGE){
                SSmode[cpuid] = NORMAL; 
                #if ENABLE_MULTICORE
                if (AccurateSavedAddrForSingleStep[cpuid]!=0){
                #else
                if (savedAddrForSingleStep!=0){
                #endif
                    // printf("[*] C handle single step\n");
                    handleSingleStepReinstrument();
                    turnOffSSServer();
                    turnOffSS();
                }
                handled = true;
            }
            else  if(SSmode[cpuid] == TDSC&&C_HANDLE__PAUTH_TRAP==1){
                SSmode[cpuid] = NORMAL; 
                ctx->elr += 4;
                setHCR_APIAPK(0, 1); 
                turnOffSS();
                turnOffSSServer();
                handled = true;
                ctx->elr -= 4;
                
            }
            else if (SSmode[cpuid] == DEBUGGER){// DEBUGGER == 1
                SSmode[cpuid] = NORMAL; 
                if (debugPid == -1 || debugPid == getCurrentPID()){
                    
                    savedAddrForSingleStep = hv_translate(ctx->elr, false, false, 0);
                    ctx->elr += 4;
                    if(SSmode[cpuid] == TDSC&&C_HANDLE__PAUTH_TRAP==0&&in_gl12()){
                        C_HANDLE__PAUTH_TRAP = 1;
                    }
                }else{
                    
                    handleSingleStepReinstrument();
                    turnOffSSServer();
                    turnOffSS();
                    handled = true;
                }
                
            }else if (SSmode[cpuid] == SPTE){
                
                u64 far = hv_get_far(); 
                // printf("exec in SS, elr: 0x%lx, far 0x%lx\n", ctx->elr, far);
                ctx->elr += 4;

                if (SSsteps[cpuid] == 0){
                    
                    SSsteps[cpuid] = ctx->elr;
                    u64 ss = ((mrs(SPSR_EL2))&SPSR_SS);
                    ssdbg_printf("[C%d] first SS SPSR: 0x%lx, elr: 0x%lx, far 0x%lx\n", mrs(TPIDR_EL2), ss, ctx->elr, far);
                    if (ss == 0){
                        
                        ctx->elr -= 4; 
                    }
                    turnOnSS(cpuid, SPTE);
                    ssdbg_printf("[C%d] turn on SS: 0x%lx\n", mrs(TPIDR_EL2), (mrs(SPSR_EL2)&SPSR_SS));
                    handled = true;
                }else{
                    SSmode[cpuid] = NORMAL; 
                    
                    SSsteps[cpuid] = 0;

                    if (is_monitored()){
                        // if ((SScnt%100 == 1))
                        ssdbg_printf("[C%d] second SS: 0x%lx, step%d, pid: %d hooked, \t elr: 0x%lx, far: 0x%lx, (0x%lx)\n", cpuid, (mrs(SPSR_EL2)&SPSR_SS), SScnt, getCurrentPID(), ctx->elr, far, ctx->elr-kaslrOffset);
                    }

                    hv_translate(far, false, false, 0);
                    hv_translate(far, true, false, 0);

                    u64 ttbr = GET_TTBR_FROM_FAR(far);
                    
                    u64* pte_addr = (u64*)pt_walk(far, ttbr, 3, 1, 1);
                    
                    if (pte_addr!=-1){
                        
                        u64 pte = *pte_addr;
                        u64 ipa = pte & PTE_MASK;
                        u64 unhooked_pte_addr = pt_walk(ipa, mrs(VTTBR_EL2), 3, 2, 1);
                        u64 unhooked_pte = read64(unhooked_pte_addr);
                        if ((unhooked_pte & SPTE_CF_IPA_HOOK) != 0){
                            
                            ssdbg_printf("[*] pte_addr: 0x%lx, pte: 0x%lx, ipa: 0x%lx, unhooked_pte_addr: 0x%lx, unhooked_pte: 0x%lx\n", pte_addr, pte, ipa, unhooked_pte_addr, unhooked_pte);
                            ssdbg_printf("[!] SS processed with hooked stage2 pte! hook should not be here, since dabort handles the hook to unhook\n");
                        }else{
                            
                            u64 hooked_pte = (unhooked_pte & PTE_MASK) | SPTE_CF_IPA_HOOK | SPTE_TRACE_READ | PTE_TYPE;
                            write64(unhooked_pte_addr, hooked_pte);
                        }
                        stage2_hook_tlb_flush(far, ipa, unhooked_pte_addr);
                        turnOffSS();
                        turnOffSSServer();
                    }else{
                        printf("exec in SS, far 0x%lx not found in pt_walk\n",far);
                        handled = false;
                    }
                    ctx->elr -= 4; 
                    handled = true;
                }
                
            }
            
            break;
        case ESR_EC_BKPT_LOWER:
            
            hv_wdt_breadcrumb('b');
            printf("[*] python handle breakpoint\n");
            break;
        case ESR_EC_PAUTH_TRAP:
            
            // if (C_HANDLE__PAUTH_TRAP&&!in_gl12()){
            if (C_HANDLE__PAUTH_TRAP){
            reg2 = ((code>>5)&0x1f);
            reg1 = ((code)&0x1f);
            ptr = ctx->regs[reg1];
            modifier = ctx->regs[reg2];
            if (reg2 == 31)
                modifier=ctx->sp[1];
            // bool in_gl = in_gl12();
            // u64 spsr = in_gl ? mrs(SYS_IMP_APL_SPSR_GL1) : (el12 ? mrs(SPSR_EL12) : mrs(SPSR_EL1));
            
            // if (SScnt % 0x1 == 0){
            if (1){
                switch(code){
                    case pacia1716:
                        reg1=17;
                        reg2=16;
                        ptr = ctx->regs[reg1];
                        modifier = ctx->regs[reg2];
                        print_pa2(ctx, "pacia1716", reg1, reg2, ptr, modifier);
                        break;
                    case pacib1716:
                        reg1=17;
                        reg2=16;
                        ptr = ctx->regs[reg1];
                        modifier = ctx->regs[reg2];
                        print_pa2(ctx, "pacib1716", reg1, reg2, ptr, modifier);
                        break;
                    case paciaz:
                        // printf("paciaz \n");
                        break;
                    case paciasp:
                        // printf("paciasp \n");
                        break;
                    case pacibz:
                        // printf("pacibz \n");
                        break;
                    case pacibsp:
                        // printf("elr 0x%lx\tpacibsp\n",ctx->elr-kaslrOffset, code);
                        break;
                    case autia1716:
                        // reg1=17;
                        // reg2=16;
                        // ptr = ctx->regs[reg1];
                        // modifier = ctx->regs[reg2];
                        // print_pa2(ctx, "autia1716", reg1, reg2, ptr, modifier);
                        break;
                    case autib1716:
                        // reg1=17;
                        // reg2=16;
                        // ptr = ctx->regs[reg1];
                        // modifier = ctx->regs[reg2];
                        // print_pa2(ctx, "autib1716", reg1, reg2, ptr, modifier);
                        break;
                    case autiaz:
                        // printf("autiaz \n");
                        break;
                    case autiasp:
                        // printf("autiasp \n");
                        break;
                    case autibz:
                        // printf("autibz \n");
                        break;
                    case autibsp:
                        // printf("autibsp \n");
                        break;
                    case retaa:
                        // printf("elr 0x%lx\tretaa\n",ctx->elr-kaslrOffset, code);
                        break;
                    case retab:
                        // printf("elr 0x%lx\tretab\n",ctx->elr-kaslrOffset, code);
                        break;
                    default:
                        skip = 0;
                        
                        switch (code&0xfffffc1f){
                            case braaz:
                                skip = 1;
                                // reg1 = ((code>>5)&0x1f);
                                // ptr = ctx->regs[reg1];
                                // print_pa2(ctx, "braaz", reg1, -1, ptr, 0);
                                break;
                            case brabz:
                                skip = 1;
                                // reg1 = ((code>>5)&0x1f);
                                // ptr = ctx->regs[reg1];
                                // print_pa2(ctx, "brabz", reg1, -1, ptr, 0);
                                break;
                            case blraaz:
                                skip = 1;
                                // reg1 = ((code>>5)&0x1f);
                                // ptr = ctx->regs[reg1];
                                // print_pa2(ctx, "blraaz", reg1, -1, ptr, 0);
                                break;
                            case blrabz:
                                skip = 1;
                                // reg1 = ((code>>5)&0x1f);
                                // ptr = ctx->regs[reg1];
                                // print_pa2(ctx, "blrabz", reg1, -1, ptr, 0);
                                break;
                        }
                        if (!skip){
                        switch (code&0xffffffe0){
                            case paciza:
                                print_pa2(ctx, "paciza", reg1, -1, ptr, 0);
                                break;
                            case pacizb:
                                print_pa2(ctx, "pacizb", reg1, -1, ptr, 0);
                                break;
                            case pacdza:
                                print_pa2(ctx, "pacdza", reg1, -1, ptr, 0);
                                break;
                            case pacdzb:
                                print_pa2(ctx, "pacdzb", reg1, -1, ptr, 0);
                                break;
                            case autiza:
                                // print_pa2(ctx, "autiza", reg1, -1, ptr, 0);
                                break;
                            case autizb:
                                // print_pa2(ctx, "autizb", reg1, -1, ptr, 0);
                                break;
                            case autdza:
                                // print_pa2(ctx, "autdza", reg1, -1, ptr, 0);
                                break;
                            case autdzb:
                                // print_pa2(ctx, "autdzb", reg1, -1, ptr, 0);
                                break;
                            default:
                                switch (code&0xfffffc00){
                                    case braa:
                                        // reg1 = ((code>>5)&0x1f);
                                        // reg2 = ((code)&0x1f);
                                        // ptr = ctx->regs[reg1];
                                        // modifier = ctx->regs[reg2];
                                        // print_pa2(ctx, "braa", reg1, reg2, ptr, modifier);
                                        // printf("elr 0x%lx\tbraa x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        break;
                                    case brab:
                                        // reg1 = ((code>>5)&0x1f);
                                        // reg2 = ((code)&0x1f);
                                        // ptr = ctx->regs[reg1];
                                        // modifier = ctx->regs[reg2];
                                        // print_pa2(ctx, "brab", reg1, reg2, ptr, modifier);
                                        // printf("elr 0x%lx\tbrab x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        break;
                                    case blraa:
                                        // reg1 = ((code>>5)&0x1f);
                                        // reg2 = ((code)&0x1f);
                                        // ptr = ctx->regs[reg1];
                                        // modifier = ctx->regs[reg2];
                                        // print_pa2(ctx, "blraa", reg1, reg2, ptr, modifier);
                                        // printf("elr 0x%lx\tblraa x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        break;
                                    case blrab:
                                        // reg1 = ((code>>5)&0x1f);
                                        // reg2 = ((code)&0x1f);
                                        // ptr = ctx->regs[reg1];
                                        // modifier = ctx->regs[reg2];
                                        // print_pa2(ctx, "blrab", reg1, reg2, ptr, modifier);
                                        // printf("elr 0x%lx\tblrab x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        break;
                                    case pacia:
                                        // printf("%s ",get_exception_level());
                                        
                                        // printf("elr 0x%lx\tpacia x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        print_pa2(ctx, "pacia", reg1, reg2, ptr, modifier);
                                        break;
                                    case pacib:
                                        // printf("%s ",get_exception_level());
                                        // printf("elr 0x%lx\tpacib x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        print_pa2(ctx, "pacib", reg1, reg2, ptr, modifier);
                                        break;
                                    case pacda:
                                        // printf("%s ",get_exception_level());
                                        // printf("elr 0x%lx\tpacda x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        print_pa2(ctx, "pacda", reg1, reg2, ptr, modifier);
                                        break;
                                    case pacdb:
                                        // printf("%s ",get_exception_level());
                                        // printf("elr 0x%lx\tpacdb x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        print_pa2(ctx, "pacdb", reg1, reg2, ptr, modifier);
                                        break;
                                    case autia:
                                        // printf("elr 0x%lx\tautia x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        // print_pa2(ctx, "autia", reg1, reg2, ptr, modifier);
                                        break;
                                    case autib:
                                        // printf("elr 0x%lx\tautib x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        // print_pa2(ctx, "autib", reg1, reg2, ptr, modifier);
                                        break;
                                    case autda:
                                        // printf("elr 0x%lx\tautda x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        // print_pa2(ctx, "autda", reg1, reg2, ptr, modifier);
                                        break;
                                    case autdb:
                                        // printf("elr 0x%lx\tautdb x%d, x%d\tx%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg1, ptr, reg2, modifier, SScnt);
                                        // print_pa2(ctx, "autdb", reg1, reg2, ptr, modifier);
                                        break;
                                    // case pacga
                                    default:
                                        switch (code&0xffe0fc00)
                                        {
                                        case pacga:
                                            reg1 = ((code)&0x1f);
                                            reg2 = ((code>>5)&0x1f);
                                            reg3 = ((code>>16)&0x1f);
                                            ptr = ctx->regs[reg1];
                                            modifier = ctx->regs[reg2];
                                            target = ctx->regs[reg3];
                                            // printf("%s ",get_exception_level());
                                            printf("elr 0x%lx\tpacga x%d, x%d, x%d\tx%d=0x%lx, x%d=0x%lx, x%d=0x%lx\tcnt=%lx\n",ctx->elr-kaslrOffset, reg1, reg2, reg3, reg1, ptr, reg2, modifier, reg3, target, SScnt);
                                            break;
                                        
                                        default:
                                            // printf("%s ",get_exception_level());
                                            printf("!!!!!!!!error in pauth handle: elr 0x%lx, code=%x\n",ctx->elr-kaslrOffset, code);
                                            break;
                                        }
                                        break;
                                }
                        }}
                        break;
                }
            }
            // if (SScnt%0x100000==0){
            //     printf("[log] elr 0x%lx, code=%x, cnt=%lx\n",ctx->elr-kaslrOffset, code, SScnt);
            // }
            setHCR_APIAPK(1, 1);
            turnOnSS(cpuid, TDSC);
            turnOnSSServer();
            handled = true;
            ctx->elr -= 4;
            }
            // else if(C_HANDLE__PAUTH_TRAP&&in_gl12()){
            //     C_HANDLE__PAUTH_TRAP = 0;
            // }
            break;
        case ESR_EC_HVC:

            imm = mrs(ESR_EL2) & 0xffff;
            ctx->elr -= 4; 
            elr = mrs(ELR_EL2);
            switch (imm) {
                /**
                 * @brief 
                 * 
                 */
                
                // case 0x20: // breakpoint
                //     break;
                

                //     printf("[*] handle kaslr offset : ELR_EL2: 0x%lx, ctx->pc=0x%lx\n", elr, ctx->elr);
                //     // [*] handle kaslr offset : ELR_EL2: 0xfffffe0013338338, ctx->pc=0xfffffe0013338334
                //     handleKaslrOffset(ctx->elr);// in breakpoint.h
                
                //     ctx->regs[10] = ctx->regs[10] + ctx->regs[19];
                    
                //     handled = true;
                //     break;
                
                
                //     /*
                //         com.apple.driver.AppleBCMWLANCore:__text:FFFFFE0008561DB0                 ADRL            X2, aApple80211Key ; "apple80211_key:\n"
                //         com.apple.driver.AppleBCMWLANCore:__text:FFFFFE0008561DB8                 MOV             X0, X20 ; __str // offset: 0x155ddb8
                //     */
                //     //    printf("[*] handle kaslr offset : ELR_EL2: 0x%lx, ctx->pc=0x%lx\n", elr, ctx->elr);
                   
                //    handleWIFI(ctx->elr);// in breakpoint.h
                
                //    ctx->elr -= 4;
                //    handled = true;
                //    break;
                
                //     /**
                //      com.apple.driver.AppleBCMWLANCore:__text:FFFFFE0008561DD4                 B.NE            loc_FFFFFE0008562100 // offset: 0x155ddd4
                //      */
                //     handleAutoRestore(ctx->elr);// in breakpoint.h
                
                //     ctx->elr -= 4;
                //     handled = true;
                //     break;
                
                //     handleDoubleCross1(ctx->elr);// in breakpoint.h
                
                //     ctx->elr -= 4;
                //     handled = true;
                //     break;
                
                //     handleDoubleCross2(ctx->elr);// in breakpoint.h
                
                //     ctx->elr -= 4;
                //     handled = true;
                //     break;
                case 0x16: 
                    printf("[!] why hvc 0x16 occurs?\n");
                case 0x22://
                    printf("[!] why hvc 0x22 occurs?\n");
                case 0x26: 
                    saveAddrForSingleStepReinstrument = ctx->elr;
                    SSmode[cpuid] = COVERAGE;
                    if (DEBUG){
                        printf("------------------------------------------------------------\n");
                        printf("[+] handle hvc 0x26: ctx->elr: 0x%lx, SSmode[cpuid]=%d\n", ctx->elr-kaslrOffset, SSmode[cpuid]);
                    }
                    handleAutoRestoreAndSingleStep(ctx->elr, true);// in breakpoint.h
                    
                    ctx->elr -= 4;
                    handled = true;
                    break;
                
                
                //     // turnOffSingleStep();
                //     turnOffSSServer();
                //     handled = true;
                //     break;
                case 0x51: 
                    /**
                     com.apple.iokit.IONVMeFamily:__text:FFFFFE0009D59D24 57 C2 FE 90+                ADRL            X23, aVirtualIoretur_235 ; "virtual IOReturn AppleNVMeUpdateUC::ext"...
                     */
                    SSmode[cpuid] = NORMAL;
                    printf("[+] PID %d invokes IOConnect External Method\n", getCurrentPID());
                    handleAutoRestoreAndSingleStep(ctx->elr, false);// in breakpoint.h
                    
                    
                    ctx->elr -= 4;
                    handled = true;
                    break;
                case 0x52: 
                
                // com.apple.driver.AppleSMC:__TEXT_EXEC.__text:FFFFFE0008FF3B98 00 19 FF 90+                ADRL            X0, aApplesmcembedd_10 ; "AppleSMCEmbedded::%s(): ENTER powerStat"...
                    SSmode[cpuid] = TDSC;
                    handleAutoRestore(ctx->elr);// in breakpoint.h
                    setHCR_APIAPK(1,1);
                    ctx->elr -= 4;
                    handled = true;
                    reboot();
                    break;

                

                case 0x8b:
                    
                    auto_simulate_syscall_entrance(ctx);
                    if (debugPid == getCurrentPID()){
                        ctx->elr += 4;
                        handled = false;
                    }else{
                        handled = true;
                    }
                    break;
                case 0x8c:
                    
                    
                    auto_simulate_syscall_exit(ctx);
                    handled = true;
                    break;

                case 0x91: 
                    
                    setKcovArea(ctx);
                    handled = true;
                    break;

                case 0x92: 
                    
                    setPID(ctx);
                    handled = true;
                    break;

                case 0x93:
                    
                    SSmode[cpuid] = NORMAL;
                    saveAddrForSingleStepReinstrument = ctx->elr;
                    handleAutoRestoreAndSingleStep(ctx->elr, true);// in breakpoint.h
                    
                    ctx->elr -= 4;
                    handleSniffIOUserClientExternalMethod_Fast(ctx);

                    handled = true;
                    break;
                case 0x99:
                    SSmode[cpuid] = DEBUGGER;
                    if (debugPid == -1 || debugPid == getCurrentPID()){
                        printf("hvc 0x99 cpuid: %d \n",smp_id());
                        handleBreakpointInvocation(ctx->elr);
                        // hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_SYNC, NULL);
                        ctx->elr -= 4;
                        hv_wdt_breadcrumb('=');
                        // handled = true;
                    }else{
                        handleAutoRestoreAndSingleStep(ctx->elr, true);
                        ctx->elr -= 4;
                        handled = true;
                    }
                    break;
                case 0x9a:
                    
                    kextSetDebugPid(ctx);
                    handled = true;
                    break;

                default:
                    printf("Unknown HVC: 0x%x\n", imm);
                    SSmode[cpuid] = NORMAL;
                    handleBreakpointInvocation(ctx->elr);
                    hv_had_triggered_proxy[cpuid] = true;
                    break;

            }
            break;

            case ESR_EC_IABORT_LOWER: 
                hv_wdt_breadcrumb('I');
                printf("[*] C handle iabort\n");
                handled = hv_handle_dabort(ctx);
                break;
    }

    if (handled) {
        hv_wdt_breadcrumb('#');
        ctx->elr += 4;
        // if (ec == ESR_EC_HVC || ec == ESR_EC_SSTEP_LOWER)
            // printf("[*] kernel pc will be set to 0x%lx \n", ctx->elr);
        hv_set_elr(ctx->elr);
        hv_update_fiq();
        hv_wdt_breadcrumb('T');
        return;
    }

    hv_exc_entry();

    switch (ec) {
        case ESR_EC_DABORT_LOWER:
            hv_wdt_breadcrumb('D');
            handled = hv_handle_dabort(ctx);
            break;
        case ESR_EC_MSR:
            hv_wdt_breadcrumb('M');
            handled = hv_handle_msr(ctx, FIELD_GET(ESR_ISS, ctx->esr));
            break;
        case ESR_EC_IMPDEF:
            hv_wdt_breadcrumb('A');
            switch (FIELD_GET(ESR_ISS, ctx->esr)) {
                case ESR_ISS_IMPDEF_MSR:
                    handled = hv_handle_msr(ctx, ctx->afsr1);
                    break;
            }
            break;
    }

    if (handled) {
        hv_wdt_breadcrumb('+');
        ctx->elr += 4;
    } else {
        hv_wdt_breadcrumb('-');
        // VM code can forward a nested SError exception here
        if (FIELD_GET(ESR_EC, ctx->esr) == ESR_EC_SERROR)
            hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_SERROR, NULL);
        else
            hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_SYNC, NULL);
    }

    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('s');
}

void hv_exc_irq(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('I');
    hv_get_context(ctx);
    hv_exc_entry();
    hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_IRQ, NULL);
    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('i');
}

void hv_exc_fiq(struct exc_info *ctx)
{
    bool tick = false;

    hv_maybe_exit();

    if (mrs(CNTP_CTL_EL0) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        msr(CNTP_CTL_EL0, CNTx_CTL_ISTATUS | CNTx_CTL_IMASK | CNTx_CTL_ENABLE);
        tick = true;
    }

    int interruptible_cpu = hv_pinned_cpu;
    if (interruptible_cpu == -1)
        interruptible_cpu = 0;

    if (smp_id() != interruptible_cpu && !(mrs(ISR_EL1) & 0x40) && hv_want_cpu == -1) {
        // Non-interruptible CPU and it was just a timer tick (or spurious), so just update FIQs
        hv_update_fiq();
        hv_arm_tick(true);
        return;
    }

    // Slow (single threaded) path
    hv_wdt_breadcrumb('F');
    hv_get_context(ctx);
    hv_exc_entry();

    // Only poll for HV events in the interruptible CPU
    if (tick) {
        if (smp_id() == interruptible_cpu) {
            hv_tick(ctx);
            hv_arm_tick(false);
        } else {
            hv_arm_tick(true);
        }
    }

    if (mrs(CNTV_CTL_EL0) == (CNTx_CTL_ISTATUS | CNTx_CTL_ENABLE)) {
        msr(CNTV_CTL_EL0, CNTx_CTL_ISTATUS | CNTx_CTL_IMASK | CNTx_CTL_ENABLE);
        hv_exc_proxy(ctx, START_HV, HV_VTIMER, NULL);
    }

    u64 reg = mrs(SYS_IMP_APL_PMCR0);
    if ((reg & (PMCR0_IMODE_MASK | PMCR0_IACT)) == (PMCR0_IMODE_FIQ | PMCR0_IACT)) {
#ifdef DEBUG_PMU_IRQ
        printf("[FIQ] PMC IRQ, masking and delivering to the guest\n");
#endif
        reg_clr(SYS_IMP_APL_PMCR0, PMCR0_IACT | PMCR0_IMODE_MASK);
        PERCPU(pmc_pending) = true;
    }

    reg = mrs(SYS_IMP_APL_UPMCR0);
    if ((reg & UPMCR0_IMODE_MASK) == UPMCR0_IMODE_FIQ && (mrs(SYS_IMP_APL_UPMSR) & UPMSR_IACT)) {
        printf("[FIQ] UPMC IRQ, masking");
        reg_clr(SYS_IMP_APL_UPMCR0, UPMCR0_IMODE_MASK);
        hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_FIQ, NULL);
    }

    if (mrs(SYS_IMP_APL_IPI_SR_EL1) & IPI_SR_PENDING) {
        if (PERCPU(ipi_queued)) {
            PERCPU(ipi_pending) = true;
            PERCPU(ipi_queued) = false;
        }
        msr(SYS_IMP_APL_IPI_SR_EL1, IPI_SR_PENDING);
        sysop("isb");
    }

    hv_maybe_switch_cpu(ctx, START_HV, HV_CPU_SWITCH, NULL);

    // Handles guest timers
    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('f');
}

void hv_exc_serr(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('E');
    hv_get_context(ctx);
    hv_exc_entry();
    hv_exc_proxy(ctx, START_EXCEPTION_LOWER, EXC_SERROR, NULL);
    hv_exc_exit(ctx);
    hv_wdt_breadcrumb('e');
}
