#include "breakpoint.h"
#include "breakpoint_wrapper.h"
#define MAX_BREAKPOINT_SIZE 100
#define NORMAL_BKPT_CODE 0x99




bool C_HANDLE__PAUTH_TRAP = 1;

// SSMODE SSmode = DEBUGGER;
extern u32 SSmode[MAX_CPUS]; 
u32 debugPid = -1;
static struct breakpoint
{
    // u32 num;
    bool isEnable;
    bool inUse;
    u64 addr;
    u64 addrInIDA;
    
    u32 breakpoint_inst;
    
}bk_ins[MAX_BREAKPOINT_SIZE];

struct exc_info *global_ctx;

bool defaultHookHandler(void){
    
    // hv_exc_proxy(global_ctx, START_EXCEPTION_LOWER, EXC_SYNC, NULL);
    return false;
}

extern u64 kaslrOffset;
u64 setBreakpointByAddr_IDA(u64 addr)
{
    printf("[setBreakpointByAddr_IDA] ida addr = 0x%lx\n", addr);
    addr = addr + kaslrOffset;
    printf("[setBreakpointByAddr_IDA] real addr = 0x%lx\n", addr);
    return setBreakpointByAddr(addr);
}
int queryBreakpointIndexByAddr(u64 addr){
    for (int i = 0;i<MAX_BREAKPOINT_SIZE;i++){
        if (bk_ins[i].inUse == 1 && bk_ins[i].addr == addr){
            // printf("[*] repeat bkpt, enabling bkpt %d\n",i);
            // return setBreakpointStatus(i,1);
            return i;
        }
    }
    return -1;
}

u64 setBreakpointByAddr(u64 addr){
    setBreakpointByAddr_with_bkinst(addr, get_brinst_from_brcode(NORMAL_BKPT_CODE));
}

u64 setBreakpointByAddr_with_bkinst(u64 addr, u32 bk_inst)
{
    // if (handler == 0){
    //     handler = defaultHookHandler;
    // }
    int index = 0;
    for (int i = 0;i<MAX_BREAKPOINT_SIZE;i++){
        if (bk_ins[i].inUse == 0){
            index = i;
            break;
        }
    }
    for (int i = 0;i<MAX_BREAKPOINT_SIZE;i++){
        if (bk_ins[i].inUse == 1 && bk_ins[i].addr == addr){
            printf("[*] repeat bkpt, enabling bkpt %d\n",i);
            return setBreakpointStatus(i,1);
        }
    }
    if (index == MAX_BREAKPOINT_SIZE){
        printf("[-] Breakpoint reached max size");
        return false;
    }
    printf("[setBreakpointByAddr] idx = %d\n", index);
    return setBreakpointByIndex(index, addr, bk_inst);
}
u64 setBreakpointByIndex(int index, u64 addr, u32 breakpoint_inst)
{
    if (addr){
        bk_ins[index].addr = addr;
        bk_ins[index].addrInIDA = ((addr-kaslrOffset)&(0x000000ffffffffffLL))|(0xFFFFFE0000000000LL);
        bk_ins[index].breakpoint_inst = breakpoint_inst; 
    }else{
        addr = bk_ins[index].addr;
        breakpoint_inst = bk_ins[index].breakpoint_inst;
    }
    u64 addr_after_trans;
    // bk_ins[index].handler = (void *)handler;
    // u32 replace_data = 0xd4001322;
    if (writeEL1Mem(addr, breakpoint_inst)){
        bk_ins[index].inUse = 1;
        bk_ins[index].isEnable = 1;
        printf("[+] breakpoint index: %d\n", index);
    }
    return addr;
}
bool setBreakpointByFuncName(char *name){
    return false;
}
bool writeEL1Mem(u64 addr, u32 data){
    u64 cpuid = mrs(TPIDR_EL2);
    printf("cpuid: %lu\n", cpuid);
    u64 addr_after_trans = hv_translate(addr, false, false, 0);
    if (addr_after_trans == 0){
        printf("[-] target PA == 0! VA: 0x%lx\n", addr);
        return false;
    }
    write32(addr_after_trans, data);
    disableInstCache(addr_after_trans);
    return true;
}
bool listBreakpoints(void){
    printf("list breakpoints\n");
    for (int i = 0;i<MAX_BREAKPOINT_SIZE;i++){
        if (bk_ins[i].inUse == 1){
            printf("\t%d , addr 0x%lx , addrInIDA 0x%lx , enable=%d\n", i, bk_ins[i].addr, bk_ins[i].addrInIDA, (bk_ins[i].isEnable)?1:0);
        }
    }
    return true;
}
extern u64 AccurateSavedAddrForSingleStep[];
extern u64 savedAddrForSingleStep;
bool disableBreakpointInstrument(int idx){
    u64 cpuid = mrs(TPIDR_EL2);
    // printf("1\n");
    AccurateSavedAddrForSingleStep[cpuid] = 0;
    // printf("cpuid: %d\n", cpuid);
    // printf("2\n");
    u64 addr = bk_ins[idx].addr;
    if (addr == 0){
        printf("[-] disableBreakpointInstrument: addr is 0, idx = %d????\n", idx);
        return true;
    }
    u32 origin_data = getOriginalBackupInstData(addr);
    // printf("3\n");
    writeEL1Mem(addr, origin_data);
    // hv_wdt_breadcrumb('d');
    // printf("4\n");
    // turnOffSS();
    // turnOffSSServer();
    // hv_wdt_breadcrumb('D');
    return true;
}
bool setBreakpointStatus(int idx, int status){
    bk_ins[idx].isEnable = status?1:0;
    if (status == 1){// enable bkp
        setBreakpointByIndex(idx, 0, 0);
    }else{//disable bkp
        disableBreakpointInstrument(idx);
    }
    return true;
}
u32 setDebugPid(u64 pid){
    debugPid = (u32)pid;
    printf("[setDebugPid] pid = %d\n", debugPid);
    return pid;
}
void kextSetDebugPid(struct exc_info *ctx){
    debugPid = (u32)ctx->regs[17];
    return;
}
extern u64 saveAddrForSingleStepReinstrument;
bool handleBreakpointInvocation(u64 elr){
    saveAddrForSingleStepReinstrument = elr;
    u64 cpuid = mrs(TPIDR_EL2);
    // printf("cpuid: %lu\n", cpuid);
    int bkptIdx = queryBreakpointIndexByAddr(elr);
    if (bkptIdx != -1){
        // printf("bkpt id:%d\n",bkptIdx);
        handleAutoRestoreAndSingleStep(elr, true);// in breakpoint.h
        return true;
    }else{
        printf("[handleBreakpointInvocation] error, no available bkpt match the addr\n");
        return false;
    }
    
}
// bool debuggerSingleStepExecute(){


//     u64 elr = mrs(ELR_EL2) - 4;
//     u32 origin_data = getOriginalBackupInstData(elr);
//     writeEL1Mem(elr, origin_data);
    
//     u32 replace_data = 0xd4001342; //hvc 0x9a
//     writeEL1Mem(elr+4, replace_data);

//     return true;

// }

bool dumpEL2Mem(u64 addr, u32 size){
    if (addr > 0xFFFFFE0000000000LL){
        u64 addr1 = hv_translate(addr, false, false, 0);
        printf("[hym1] addr = 0x%lx  > 0xFFFFFE0000000000, tans to be 0x%lx\n", addr, addr1);
    }
    
}

u32 get_brinst_from_brcode(u32 brcode)
{
    u32 breakpoint_inst = 0xd4000000 | ((brcode & 0xffff)<<5) | 0x2;
    return breakpoint_inst;
}

u64 set_breakpoint_in_ida_with_brcode(u64 addr, u32 brcode){
    printf("[set_breakpoint_in_ida_with_brcode] ida addr = 0x%lx\n", addr);
    addr = addr + kaslrOffset;
    printf("[set_breakpoint_in_ida_with_brcode] real addr = 0x%lx\n", addr);
    u32 breakpoint_inst = get_brinst_from_brcode(brcode);
    return setBreakpointByAddr_with_bkinst(addr, breakpoint_inst);
}