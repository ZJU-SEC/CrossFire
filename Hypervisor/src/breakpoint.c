#include "breakpoint.h"
#include "iodev.h"
#include "hv_vm.h"
#include "breakpoint_const.h"
#include "utils.h"

#define ENABLE_MULTICORE false 
#define KASAN 1 
#define AGXFUZZ 1
#define macOSVersion_22g91 1

static u32 cnt = 1, brk_hvc_cc = 0xd4001982;// \x82\x19\x00\xd4

//void printu32(u32 data){
//    for(int i=0;i<32;i+=8){
//        printf("0x%.8lx\n", data)
//    }
//}
DECLARE_SPINLOCK(covlock);

u64 kaslrOffset=0LL;
u64 backuptextBase = 0LL;
u64 autoRestoreNoAgainCnt = 0LL;
u64 autoRestoreAgainCnt = 0LL;
u64 autoRestoreSingleStepCnt = 0LL;
u64 AccurateSavedAddrForSingleStep[MAX_CPUS] = {0};
u32 savedInsDataForSingleStep[MAX_CPUS] = {0};
#if ENABLE_MULTICORE
u64 savedAddrForSingleStep[MAX_CPUS] = {0};
#else
u64 savedAddrForSingleStep = 0LL;
#endif
u64 el1handlerBase = 0LL;
u64 EL2SingeStepCnt = 0LL;
u64 accurateHook = 0LL;
u64 el1handlerSavedAddrOffset = 0x308LL; 
u64 kcovArea = 0LL;
u64 runningKernelEl2base = 0LL;
u64 ttbrKernel = 0LL;
u64 ttbrKEXT = 0LL;


u64 fileTransferArea = 0LL;
u64 EL1fileTransferArea = 0LL;
u32 fileTransferSizeLimit = 0LL;

#define COVER_SIZE (256 << 10)*16
bool DEBUG=0;
unsigned int monitored_pid = -1;
u64 ttbr1_backup = -1;
u64 backup_pt_ttbr = -1;
u64 IPA_hook_blacklist_handoff = -1;

u32 handleKaslrOffset(u64 EL1PC){
    kaslrOffset = EL1PC - 0xFFFFFE0008124334LL;
    
    printf("[+] kaslrOffset: %lx\n", kaslrOffset);
    return 0;
}
u64 setRunningKernelEl2Base(u64 addr){
    runningKernelEl2base = addr;
    return runningKernelEl2base;
}
u64 setKaslrOffset(u64 Offset){
    kaslrOffset = Offset;
    
    // mmu_add_mapping(ram_base | REGION_RWX_EL1_begin, ram_base, REGION_RWX_EL1_end - REGION_RWX_EL1_begin, MAIR_IDX_NORMAL, PERM_RX_EL0);
    return kaslrOffset;
}
u32 setEL2handlerForEL1handlerBase(u64 addr){
    el1handlerBase = addr;
    return 0;
}
u64 fastgetVAtoVal(u64 addr){
    u64 PA = kva_translate(addr, true, false, 0);
    if (PA==0){
        printf("[getCurrentPID] plz check this func whether matches the macOS version\n");
        return 0;
    }
    u64 val = read64(PA);
    return val;
}
u32 getCurrentPID(void){
    u64 tds = mrs(TPIDR_EL1);

    #if macOSVersion_22g91
        #if KASAN
            u64 task_pre_val = fastgetVAtoVal(tds+0x490);
        #else
            u64 task_pre_val = fastgetVAtoVal(tds+0x478);
        #endif
    #else 
    #if macOSVersion_21g72
        #if KASAN
            u64 task_pre_val = fastgetVAtoVal(tds+0x498);
        #else
            u64 task_pre_val = fastgetVAtoVal(tds+0x480);
        #endif
    #endif
    #endif
    u64 task_val = fastgetVAtoVal(task_pre_val+0x20);
    if (task_val == 0LL){
        if (autoRestoreSingleStepCnt%1000==1){
            printf("[!] Error intval1thread_task_va_pa == 0LL, tds: 0x%lx, task_pre_val: 0x%lx\n", tds, task_pre_val);
        }
        return -1;
    }
    u64 pid_pre_val = fastgetVAtoVal(task_val+0x3e0);
    u64 pid_pa = kva_translate(pid_pre_val+0x5c, false,false,0);
    unsigned int now_pid = read32(pid_pa);

    return now_pid;
}

bool is_monitored(void){
    if (monitored_pid == -1)
        return true;
    return monitored_pid == getCurrentPID();
}

u32 getOriginalBackupInstData(u64 addr){
    u32 replace_data = 0;
    u64 binaryOffset = 0;
    if (addr < 0xFFFFFE0000000000LL){
        printf("[hym1] getOriginalBackupInstData addr = 0x%lx  < 0xFFFFFE0000000000\n", addr);
        
        binaryOffset = addr - runningKernelEl2base;
    }else{
        binaryOffset = addr - kaslrOffset - 0xFFFFFE0007004000LL;
    }
    u64 physicalAddrOfReplaceData = binaryOffset + backuptextBase;
    
    __asm__ volatile("ldr\t%w[replace_data], [%[physicalAddrOfReplaceData]]"
    : [replace_data] "=r"(replace_data) // output %0
    : [physicalAddrOfReplaceData] "r"(physicalAddrOfReplaceData)  // input %1
    : "memory");
    if (DEBUG){
        printf("[*] getOriginalBackupInstData | binaryOffset = 0x%lx, physicalAddrOfReplaceData = 0x%lx, replace_data = 0x%x\n", binaryOffset, physicalAddrOfReplaceData, replace_data);    
    }
    return replace_data;
}
bool disableInstCache(u64 addr){
    
    __asm__ volatile(
        "ldr\t x4, %[addr]\n \
        ic\t ivau, x4\n"
    :  // output %0
    : [addr] "m"(addr)  // input %1
    : "x4");
    return true;
}
void restoreCode(u64 addr, bool savePhysicalAddr, bool enableAccurateRestoreSingleStep){
    u64 addr_after_trans;
    // u32 inst_data;
    u32 replace_data = getOriginalBackupInstData(addr);
    
    // do translate to physical addr
    if (addr > 0xFFFFFE0000000000LL)
        addr_after_trans = hv_translate(addr,false, false, 0);
                                    //stage1&2, not write
    else{
        addr_after_trans = addr;
    }
    u32 inst_data = read32(addr_after_trans); 
    if (DEBUG){
        printf("[+] restoreCode | inst at 0x%lx ( PA = 0x%lx ), inst_data: 0x%x\n", addr - kaslrOffset, addr_after_trans, inst_data);
        printf("[*] restoreCode | attempt to write the inst at PA = 0x%lx, to 0x%x\n", addr_after_trans, replace_data);
    }
    u64 cpuid = smp_id();
    if (enableAccurateRestoreSingleStep == false){
        #if ENABLE_MULTICORE
            if (savePhysicalAddr){
                AccurateSavedAddrForSingleStep[cpuid] = addr_after_trans;
                savedInsDataForSingleStep[cpuid] = inst_data;
                savedAddrForSingleStep[cpuid] = addr_after_trans;
                
                
            }
        #else
            savedAddrForSingleStep = addr_after_trans;
        #endif
    }
    else{// handleAutoRestoreAndSingleStep == true
        AccurateSavedAddrForSingleStep[cpuid] = addr_after_trans;
        savedInsDataForSingleStep[cpuid] = inst_data;
        #if ENABLE_MULTICORE
        savedAddrForSingleStep[cpuid] = addr_after_trans;
        #else
        savedAddrForSingleStep = addr_after_trans;
        #endif
        accurateHook += 1;
    }
    
    write32(addr_after_trans, replace_data);

    disableInstCache(addr_after_trans);
    
    if (kcovArea != 0LL){
        if (monitored_pid!=-1){
            
            unsigned int now_pid = getCurrentPID();
            if (now_pid == -1){
                printf("[!] pid fetching fails to -1\n");
            }
            if (now_pid != monitored_pid){
                return;
            }
#if AGXFUZZ
            if (autoRestoreSingleStepCnt%0x100000==1){
#else
            if (autoRestoreSingleStepCnt%0x1000==1)
#endif
                printf("[*] : cpu: 0x%lx, %d invoke, target pid: %d\n", cpuid, now_pid, monitored_pid);

            }
            spin_lock(&covlock);
            u64 numOfPCs = *(u64*)kcovArea;
            *(u64*)kcovArea = numOfPCs + 1;
            if (numOfPCs < COVER_SIZE / 8){
                // printf("numOFPCs should be 0x%lx, in kcovArea is %lx\n", numOfPCs, *(u64*)kcovArea);
                *(u64*)(kcovArea + 8 + numOfPCs * 8) = addr - kaslrOffset;
            }
            else{
#if AGXFUZZ
                if (numOfPCs % 0x10001==0)
#else
                if (numOfPCs % 0x1001==0)
#endif
                {
                    printf("[!] cpuid: %ld, kcovArea is full, numOfPCs: 0x%lx \n", cpuid, numOfPCs);
                }
                
            }
            spin_unlock(&covlock);
        }
        else{
            if (autoRestoreSingleStepCnt%1000==1){
                printf("[!] kcovArea is not null but monitored_pid is -1\n");
            }
        }
        
    }
    
}
void printCov(void){
    u64 numOfPCs = *(u64*)kcovArea;
    printf("[*] numOfPCs: %lx\n", numOfPCs);
    for (int i = 0; i < numOfPCs; i++){
        printf("\t0x%lx\n", *(u64*)(kcovArea + 8 + i * 8));
    }
}
void getPA(u64 addr){
    u64 PA = hv_translate(addr, false, false, 0);
    u64 val = read64(PA);
    printf("[+] VA: 0x%lx -> PA: 0x%lx -> 0x%lx\n", addr, PA, val);
}
u32 handleWIFI(u64 addr){
    
    // printf("[*] handleWIFI kernel pc = %lx, in ida pc = %lx\n", addr, addr - kaslrOffset);
    handleAutoRestore(addr);
    // u64 ttbr = mrs(TTBR1_EL12);
    // if (ttbr != ttbrKernel){
    //     ttbrKernel = ttbr;
    //     u64 binaryOffset = 0;
    //     if (addr < 0xFFFFFE0000000000LL){
    //         printf("[hym1] addr = 0x%lx  < 0xFFFFFE0000000000\n", addr);
    //         binaryOffset = addr - runningKernelEl2base;
    //     }else{
    //         binaryOffset = addr - kaslrOffset - 0xFFFFFE0007004000LL;
    //     }
    //     int order = binarySearch(kextAddrList, 347, binaryOffset);
    //     printf("[*] addr = %lx , ttbrKernel = %lx , name: %s\n", addr, ttbrKernel, kextNameList[order]);
    // }

    // u64 addr_after_trans;
    // u32 inst_data;
    // /**
    //  *  >>> asm("MOV             X0, X20")
    //         '\xe0\x03\x14\xaa'
    
    //  */
    // u32 replace_data = 0xaa1403e0;
    
    //  // do translate to physical addr
    // addr_after_trans = hv_translate(addr, false, false, 0);
    //                                 //stage1&2, not write
    // inst_data = read32(addr_after_trans); 
    // printf("[+] inst at 0x%lx ( PA = 0x%lx ), inst_data: 0x%x\n", addr - kaslrOffset, addr_after_trans, inst_data);
    // printf("[*] attempt to write the inst at PA = 0x%lx, to 0x%x\n", addr_after_trans, replace_data);
    // write32(addr_after_trans, replace_data);

    
    // __asm__ volatile(
    //     "ldr\t x4, %[addr_after_trans]\n
    //     ic\t ivau, x4\n"
    // :  // output %0
    // : [addr_after_trans] "m"(addr_after_trans)  // input %1
    // : "x4");

    return 0;
}

u32 handleAutoRestore(u64 addr){
    
    // printf("[*] handleAutoRestore kernel pc = %lx, in ida pc = %lx\n", addr, addr - kaslrOffset);
    // if (backuptextBase==0){
    //     printf("[!] backuptextBase of handleAutoRestore doesn't initialized\n");
    //     return -1;
    // }else if(kaslrOffset == 0){
    //     printf("[!] kaslrOffset not initialized\n");
    // }
    restoreCode(addr, false, false);

    autoRestoreNoAgainCnt += 1;
    return 0;
}

u32 handleDoubleCross1(u64 addr){
    // restore and write the next
    
    u64 addr_after_trans;
    u64 binaryOffset = addr - kaslrOffset - 0xFFFFFE0007004000LL;
    u64 physicalAddrOfReplaceData = binaryOffset + backuptextBase;
    u32 replace_data = 0;

     
    __asm__ volatile("ldr\t%w[replace_data], [%[physicalAddrOfReplaceData]]"
    : [replace_data] "=r"(replace_data) // output %0
    : [physicalAddrOfReplaceData] "r"(physicalAddrOfReplaceData)  // input %1
    : "memory");

    
    // do translate to physical addr
    addr_after_trans = hv_translate(addr,false, false, 0);

    // restore
    write32(addr_after_trans, replace_data);

    // write the next
    write32(addr_after_trans+4, 0xd40004a2); // write the next to hvc #0x25

    __asm__ volatile(
        "ldr\t x4, %[addr_after_trans]\n \
        ic\t ivau, x4\n"
    :  // output %0
    : [addr_after_trans] "m"(addr_after_trans)  // input %1
    : "x4");

    addr_after_trans += 4;
    __asm__ volatile(
        "ldr\t x4, %[addr_after_trans]\n \
        ic\t ivau, x4\n"
    :  // output %0
    : [addr_after_trans] "m"(addr_after_trans)  // input %1
    : "x4");

    
    return 0;
}

bool clearDataCache(u64 addr){
    // breakpoint    5 , addr 0xfffffe001d82ba0c , addrInIDA 0xfffffe00083afa0c , enable=0
    if(addr > 0xF000000000000000LL){
        addr = hv_translate(addr,false, false, 0);
    }
    if (addr == 0){
        printf("addr == 0\n");
        return false;
    }

    __asm__ volatile(
        "ldr\t x4, %[addr]\n \
        ic\t ivau, x4\n"
    :  // output %0
    : [addr] "m"(addr)  // input %1
    : "x4");

    __asm__ volatile(
        "ldr\t x4, %[addr]\n \
        dc\t cvau, x4\n"
    :  // output %0
    : [addr] "m"(addr)  // input %1
    : "x4");

    // printf("clear cache in 0x%lx\n", addr);
    
    return true;
}

u32 handleDoubleCross2(u64 addr){
    // restore and write the former
    

    u64 addr_after_trans;
    u64 binaryOffset = addr - kaslrOffset - 0xFFFFFE0007004000LL;
    u64 physicalAddrOfReplaceData = binaryOffset + backuptextBase;
    u32 replace_data = 0;

     
    __asm__ volatile("ldr\t%w[replace_data], [%[physicalAddrOfReplaceData]]"
    : [replace_data] "=r"(replace_data) // output %0
    : [physicalAddrOfReplaceData] "r"(physicalAddrOfReplaceData)  // input %1
    : "memory");

    
    // do translate to physical addr
    addr_after_trans = hv_translate(addr,false, false, 0);

    // restore
    write32(addr_after_trans, replace_data);

    // write the former
    write32(addr_after_trans-4, 0xd4000482); // write the former to hvc #0x24

    __asm__ volatile(
        "ldr\t x4, %[addr_after_trans]\n \
        ic\t ivau, x4\n"
    :  // output %0
    : [addr_after_trans] "m"(addr_after_trans)  // input %1
    : "x4");

    addr_after_trans -= 4;
    __asm__ volatile(
        "ldr\t x4, %[addr_after_trans]\n \
        ic\t ivau, x4\n"
    :  // output %0
    : [addr_after_trans] "m"(addr_after_trans)  // input %1
    : "x4");

    autoRestoreAgainCnt += 1;
    return 0;
}

bool turnOnSSServer(void){
    // printf("[+] turnOnSSServer: now mdscr_el1: 0x%lx\n", mrs(MDSCR_EL1));
    msr(MDSCR_EL1, 0x8001);
    return true;
}
bool turnOffSSServer(void){
    msr(MDSCR_EL1, 0x8000);
    return true;
}
extern u32 SSmode[MAX_CPUS]; 

bool turnOnSS(u32 cpuid, SSMODE ss_mode){
    // bool in_gl = in_gl12();
    if (cpuid != -1){
        SSmode[cpuid] = ss_mode;
    }
    u64 spsrel2 = hv_get_spsr();
    // printf("spsr.d = %lx", (spsrel2>>9)&1);
    // u64 spsrel2 = mrs(SPSR_EL2);
    spsrel2 |= SPSR_SS;
    spsrel2 &= ~(SPSR_D); 
    hv_set_spsr(spsrel2);
    
    return true;
}
bool turnOffSS(void){
    u64 spsrel2 = hv_get_spsr();
    spsrel2 &= ~(SPSR_SS);
    // spsrel2 &= ~(SPSR_D);
    
    hv_set_spsr(spsrel2);
    return true;
}
u32 handleAutoRestoreAndSingleStep(u64 addr, bool enableAccurateRestoreSingleStep){ // hvc 0x26 == 0xd40004c2
    if (DEBUG){
        printf("[+] handleAutoRestoreAndSingleStep | addr = 0x%lx\n", addr);
    }
    restoreCode(addr, true, enableAccurateRestoreSingleStep);
    // u64 ttbr = mrs(TTBR1_EL12);
    // if (ttbr != ttbrKEXT){
    //     ttbrKEXT=ttbr;
    //     u64 binaryOffset = 0;
    //     if (addr < 0xFFFFFE0000000000LL){
    //         printf("[hym1] addr = 0x%lx  < 0xFFFFFE0000000000\n", addr);
    //         binaryOffset = addr - runningKernelEl2base;
    //     }else{
    //         binaryOffset = addr - kaslrOffset - 0xFFFFFE0007004000LL;
    //     }
    //     int order = binarySearch(kextAddrList, 347, binaryOffset);
    //     printf("[*] addr = %lx , ttbrKEXT = %lx , name: %s\n", addr, ttbrKEXT, kextNameList[order]);
    // }
    autoRestoreSingleStepCnt += 1;
    // printf("[+] addr = 0x%lx ( 0x%lx ), trigger handleAutoRestoreAndSingleStep\n", addr ,addr - kaslrOffset);
    
    turnOnSSServer();
    // u64 spsrel2 = mrs(SPSR_EL2) ;
    // spsrel2 |= SPSR_SS;
    
    turnOnSS(-1, 0);
    // u64 mdcrel2 = mrs(MDCR_EL2);
    
    // msr(MDCR_EL2, mdcrel2);
    return 0;
}
// extern bool DEBUGGER_MODE;
// extern SSMODE SSmode;


u32 handleSingleStepReinstrument(void)
{
    u64 cpuid = smp_id();
    if (DEBUG){
        printf("[*] handleSingleStepReinstrument | AccurateSavedAddrForSingleStep[%d] = %lx\n", cpuid, AccurateSavedAddrForSingleStep[cpuid]);
    }
    
    if (AccurateSavedAddrForSingleStep[cpuid] != 0){
        // replace_data = 0xd4001262; // hvc 0x93
        // u32 inst_data = read32(AccurateSavedAddrForSingleStep[cpuid]); 
        write32(AccurateSavedAddrForSingleStep[cpuid], savedInsDataForSingleStep[cpuid]);
        EL2SingeStepCnt += 1;
        __asm__ volatile(
            "ldr\t x4, %[addr]\n \
            ic\t ivau, x4\n"
        :  // output %0
        : [addr] "m"(AccurateSavedAddrForSingleStep[cpuid])  // input %1
        : "x4");
        AccurateSavedAddrForSingleStep[cpuid] = 0;
    }else{

        u32 replace_data = 0;
        if (SSmode[cpuid] == COVERAGE){
            replace_data = 0xd40004c2;// hvc 0x26
        }
        else{
            u64 addr = mrs(ELR_EL2)-4; 
            replace_data = getOriginalBackupInstData(addr);
        }
#if ENABLE_MULTICORE
        u32 inst_data = read32(savedAddrForSingleStep[cpuid]); 
        if (DEBUG){
            printf("[+] handleSingleStepReinstrument | PA = 0x%lx inst_data: 0x%x\n", savedAddrForSingleStep[cpuid], inst_data);
            printf("[*] handleSingleStepReinstrument | attempt to write the inst at PA = 0x%lx, to 0x%x\n", savedAddrForSingleStep[cpuid], replace_data);
        }
        
        write32(savedAddrForSingleStep[cpuid], replace_data);
        EL2SingeStepCnt += 1;
        __asm__ volatile(
            "ldr\t x4, %[addr]\n \
            ic\t ivau, x4\n"
        :  // output %0
        : [addr] "m"(savedAddrForSingleStep[cpuid])  // input %1
        : "x4");
#else
        if (savedAddrForSingleStep!=0){
            u32 inst_data = read32(savedAddrForSingleStep); 
            if (DEBUG){
                printf("[+] handleSingleStepReinstrument | PA = 0x%lx inst_data: 0x%x\n", savedAddrForSingleStep, inst_data);
                printf("[*] handleSingleStepReinstrument | attempt to write the inst at PA = 0x%lx, to 0x%x\n", savedAddrForSingleStep, replace_data);
            }
            if (savedAddrForSingleStep!=0 && savedAddrForSingleStep<0xFFFFFE0007004000LL){
                write32(savedAddrForSingleStep, replace_data);
                EL2SingeStepCnt += 1;
                __asm__ volatile(
                    "ldr\t x4, %[addr]\n \
                    ic\t ivau, x4\n"
                :  // output %0
                : [addr] "m"(savedAddrForSingleStep)  // input %1
                : "x4");
            }
        }
#endif
    }

    
    // msr(MDSCR_EL1, 0x8000);

    // u64 spsrel2 = mrs(SPSR_EL2) ;
    // spsrel2 &= ~(SPSR_SS);
    
    return 0;
}



u32 saveBackuptextBase(u64 base){
    backuptextBase = base;
    printf("[+] saved backuptextBase: %lx\n", backuptextBase);
    return 0;
}

u32 switchExceptionRoute(void){
    u64 mdcrel2 = mrs(MDCR_EL2);
    mdcrel2 ^= (1<<8);// TDE = 8
    mdcrel2 ^= (1<<9);// TDA = 9// if TDA and TDE == (0,0) , EL1 access MDSCR_EL1 whill return the real MDSCR_EL1 not just trap
    msr(MDCR_EL2, mdcrel2);
    printf("[+] switched the MDCR_EL2.TDE and MDCR_EL2.TDA, now MDCR_EL2 = %lx\n",mdcrel2);
    // next modify the pagetable of el1handler 16kb page

    return 0;
}
u64 getL2PTEAddr(u64 addr){
    u64 physicalOffset = (addr&((1<<14)-1));
    u64 L3offset = (addr>>14)&((1<<11)-1);
    u64 L2offset = (addr>>25)&((1<<11)-1);
    u64 L1offset = (addr>>36)&((1<<11)-1);
    printf("[+] L1: 0x%lx \t,L2: 0x%lx \t,L3: 0x%lx \t,PhysicalOffset: 0x%lx\n", L1offset, L2offset, L3offset, physicalOffset);
    u64 ttbr = mrs(TTBR1_EL12);
    if (ttbr==0){
        printf("[!] ttbr == 0\n");
        return 0;
    }
    printf(" ttbr: %lx ",ttbr);
    u64 L1PTEAddr = (ttbr + L1offset*8);
    printf(" L1PTEAddr: %lx ",L1PTEAddr);
    if (L1PTEAddr == 0 ){
        printf("[!] L1PTEAddr == 0\n");
        return 0;
    }
    u64 L1PTE = read64(L1PTEAddr);
    printf(" L1PTE: %lx ",L1PTE);
    L1PTE = L1PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1));
    if (L1PTE == 0){
        return 0;
    }
    u64 L2PTEAddr = (L1PTE + L2offset*8);
    printf(" L2PTEAddr: %lx ",L2PTEAddr);
    return L2PTEAddr;
}
u32 analyzeVAddr(u64 addr){
    // 0xfffffe001a750000
    // 46    35     24     13     0
    // 1111 1111 1111 1111 1111 1110 0000 0000 0001 1010 0111 0101 0000 0000 0000 0000
    //   f    f    f    f    f    e    0    0    1    a    7    5    0    0    0    0
    // 1111 1111 1111 1111 1  //  111 1110 0000   //   0000 0001 101  //  0 0111 0101 00 // 00 0000 0000 0000
    if(addr < 0xf000000000000000){
        printf("invalid VA %lx\n", addr);
        return -1;
    }
    printf("in ida: 0x%lx\n", ((addr - kaslrOffset)&(0x00000fffffffffff)|(0xfffff00000000000)));
    u64 L3offset = (addr>>14)&((1<<11)-1);
    u64 L2PTEAddr = getL2PTEAddr(addr);
    if (L2PTEAddr == 0){
        return 0;
    }
    u64 L2PTE = read64(L2PTEAddr);
    printf(" L2PTE: %lx \n",L2PTE);
    if (L2PTE == 0){
        return 0;
    }
    L2PTEAddr = L2PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1));

    u64 L3PTEAddr = (L2PTEAddr + L3offset*8);
    u64 L3PTE = read64(L3PTEAddr);
    if (L3PTE == 0){
        return 0;
    }
    printf(" L3PTE ADDR: %p, L3PTE: %lx \n",L3PTEAddr,L3PTE);
    printf("    AP[1](RO) %d\tAP[0](EL0) %d\tUXN %d\t PXN %d\n",(L3PTE&((u64)1<<7))?1:0,(L3PTE&((u64)1<<6))?1:0,(L3PTE&((u64)1<<54))?1:0,(L3PTE&((u64)1<<53))?1:0); //AP[1]  AP[0]   UXN   PXN
    u64 PA = hv_translate(addr,false, false, 0);
    printf(" PA: 0x%lx\n", PA);
    if (PA!=0){
        printf(" data in PA: 0x%x 0x%lx\n", read32(PA), read64(PA));
    }
    return 0;
}
u32 analyzeEL0Addr(u64 addr){
    u64 physicalOffset = (addr&((1<<14)-1));
    u64 L3offset = (addr>>14)&((1<<11)-1);
    u64 L2offset = (addr>>25)&((1<<11)-1);
    u64 L1offset = (addr>>36)&((1<<11)-1);
    printf("[+] L1: 0x%lx \t,L2: 0x%lx \t,L3: 0x%lx \t,PhysicalOffset: 0x%lx\n", 0, L2offset, L3offset, physicalOffset);
    u64 ttbr = mrs(TTBR0_EL12);
    ttbr = ttbr & (~(0xffff0000000000));
    printf(" ttbr: %lx ",ttbr);
    u64 L1PTEAddr = (ttbr + L1offset*8);
    u64 L1PTE = read64(L1PTEAddr);
    printf(" L1PTE: %lx ",L1PTE);
    if (L1PTE == 0){
        return 0;
    }
    L1PTE = L1PTE &(~(((u64)1<<14)-1));
    u64 L2PTEAddr = (L1PTE + L2offset*8);
    u64 L2PTE = read64(L2PTEAddr);
    printf(" L2PTE: %lx \n",L2PTE);
    if (L2PTE == 0){
        return 0;
    }
    L2PTEAddr = L2PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1));

    u64 L3PTEAddr = (L2PTEAddr + L3offset*8);
    u64 L3PTE = read64(L3PTEAddr);
    if (L3PTE == 0){
        return 0;
    }
    printf(" L3PTE: %lx \n", L3PTE);
    printf("    AP[1](RO) %d\tAP[0](EL0) %d\tUXN %d\t PXN %d\n",(L3PTE&((u64)1<<7))?1:0,(L3PTE&((u64)1<<6))?1:0,(L3PTE&((u64)1<<54))?1:0,(L3PTE&((u64)1<<53))?1:0); //AP[1]  AP[0]   UXN   PXN
    u64 PA = (L3PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1)))|physicalOffset;
    printf(" PA: 0x%lx\n", PA);
    if (PA!=0){
        printf(" data in PA: 0x%x 0x%lx\n", read32(PA), read64(PA));
    }
    return 0;

}
u32 mapEL1HandlerPTE(u64 EL1HandlerEL2base, u64 EL1VAddrBase){
    u64 addr,physicalOffset,L3offset,L2offset,L1offset,ttbr,L1PTEAddr,L1PTE,L2PTEAddr,L2PTE,L3PTEAddr,L3PTE;
    
    u64 kernel_addr = kaslrOffset + 0xFFFFFE0007004000LL;
    // u64 standard_PTE2Addr = getL2PTEAddr(kernel_addr);
    // u64 El1Handler_PTE2Addr = getL2PTEAddr(EL1VAddrBase);
    addr = EL1VAddrBase + 0 * 16 * 1024;

    physicalOffset = (addr&((1<<14)-1));
    L3offset = (addr>>14)&((1<<11)-1);
    L2offset = (addr>>25)&((1<<11)-1);
    L1offset = (addr>>36)&((1<<11)-1);
    // printf("[+] L1: 0x%lx \t,L2: 0x%lx \t,L3: 0x%lx \t,PhysicalOffset: 0x%lx\n", L1offset, L2offset, L3offset, physicalOffset);
    ttbr = mrs(TTBR1_EL12);
    // printf(" ttbr: %lx ",ttbr);
    L1PTEAddr = (ttbr + L1offset*8);
    // printf(" L1PTEAddr: %lx ",L1PTEAddr);
    L1PTE = read64(L1PTEAddr);
    // printf(" L1PTE: %lx ",L1PTE);
    L2PTEAddr = L1PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1));
    if (L1PTE == 0){
        printf("L1 PTE == 0, retry later\n");
        return -1;
    }
    L2PTEAddr = (L2PTEAddr + L2offset*8);
    // printf(" L2PTEAddr: %lx ",L2PTEAddr);
    L2PTE = read64(L2PTEAddr);
    // printf(" L2PTE: %lx \n",L2PTE);
    if (L2PTE == 0){
        printf("L2 PTE uninititialized, change handler size and try again\n");
        return -1;
    }
    // write64(L2PTEAddr,L2PTE&(~1));
    L2PTEAddr = L2PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1));
    L3PTEAddr = (L2PTEAddr + L3offset*8)&(((u64)1<<36)-1);
    L3PTE = ((EL1HandlerEL2base&(~(((u64)1<<14)-1))) + 0 * 16 * 1024 )|((u64)1<<54)|((u64)1<<7)|((u64)1<<6)|3;
    // printf(" [+] Write L3PTE in 0x%lx to 0x%lx \n",L3PTEAddr, L3PTE);
    write64(L3PTEAddr, L3PTE); // ((u64)1<<54): UXN, ((u64)1<<7): RO

    printf("Modify EL1 handler complete, the last page in 0x%lx as follows:\n", addr);
    printf("[*] L1: 0x%lx \t,L2: 0x%lx \t,L3: 0x%lx \t,PhysicalOffset: 0x%lx\n", L1offset, L2offset, L3offset, physicalOffset);
    printf(" ttbr: %lx ",ttbr);
    printf(" L1PTEAddr: %lx ",L1PTEAddr);
    printf(" L1PTE: %lx ",L1PTE);
    printf(" L2PTEAddr: %lx ",L2PTEAddr);
    printf(" L2PTE: %lx \n",L2PTE);
    printf(" L3PTE: %lx \n", L3PTE);
    printf("    AP[1](RO) %d\tAP[0](EL0) %d\tUXN %d\t PXN %d\n",(L3PTE&((u64)1<<7))?1:0,(L3PTE&((u64)1<<6))?1:0,(L3PTE&((u64)1<<54))?1:0,(L3PTE&((u64)1<<53))?1:0); //AP[1]  AP[0]   UXN   PXN
    return 0;
}
u32 mapEL1HandlerPTE_all(u64 EL1HandlerEL2base, u64 EL1VAddrBase){
    
    u64 addr,physicalOffset,L3offset,L2offset,L1offset,ttbr,L1PTEAddr,L1PTE,L2PTEAddr,L2PTE,L3PTEAddr,L3PTE;
    
    u64 kernel_addr = kaslrOffset + 0xFFFFFE0007004000LL;
    u64 standard_PTE2Addr = getL2PTEAddr(kernel_addr);
    u64 El1Handler_PTE2Addr = getL2PTEAddr(EL1VAddrBase);
    
    u64 standard_PTE2 = read64(standard_PTE2Addr);
    write64(El1Handler_PTE2Addr, standard_PTE2-0x8000); // 16kb*2048 == 0x8000kb
    __asm__ volatile(
            "dsb ISHST\n"
            "ldr\t x4, %[El1Handler_PTE2Addr]\n \
             TLBI VAE1, x4\n"
            "dsb ISH\n"
            "isb\n"
            ://output
            : [El1Handler_PTE2Addr] "m"(El1Handler_PTE2Addr)  // input %1
            : "x4"
        );
    int pages = 60;
    for (int i = 0; i<pages; i++) 
    {
        addr = EL1VAddrBase + i * 16 * 1024;
        
        physicalOffset = (addr&((1<<14)-1));
        L3offset = (addr>>14)&((1<<11)-1);
        L2offset = (addr>>25)&((1<<11)-1);
        L1offset = (addr>>36)&((1<<11)-1);
        // printf("[+] L1: 0x%lx \t,L2: 0x%lx \t,L3: 0x%lx \t,PhysicalOffset: 0x%lx\n", L1offset, L2offset, L3offset, physicalOffset);
        ttbr = mrs(TTBR1_EL12);
        // printf(" ttbr: %lx ",ttbr);
        L1PTEAddr = (ttbr + L1offset*8);
        // printf(" L1PTEAddr: %lx ",L1PTEAddr);
        L1PTE = read64(L1PTEAddr);
        // printf(" L1PTE: %lx ",L1PTE);
        L2PTEAddr = L1PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1));
        if (L1PTE == 0){
            printf("L1 PTE == 0, retry later\n");
            return -1;
        }
        L2PTEAddr = (L2PTEAddr + L2offset*8);
        // printf(" L2PTEAddr: %lx ",L2PTEAddr);
        L2PTE = read64(L2PTEAddr);
        // printf(" L2PTE: %lx \n",L2PTE);
        if (L2PTE == 0){
            printf("L2 PTE uninititialized, change handler size and try again\n");
            return -1;
        }
        // write64(L2PTEAddr,L2PTE&(~1));
        L2PTEAddr = L2PTE&(((u64)1<<36)-1)&(~(((u64)1<<14)-1));
        L3PTEAddr = (L2PTEAddr + L3offset*8)&(((u64)1<<36)-1);
        L3PTE = ((EL1HandlerEL2base&(~(((u64)1<<14)-1))) + i * 16 * 1024 )|((u64)1<<54)|((u64)1<<7)|((u64)1<<6)|3;
        // printf(" [+] Write L3PTE in 0x%lx to 0x%lx \n",L3PTEAddr, L3PTE);
        write64(L3PTEAddr, L3PTE); // ((u64)1<<54): UXN, ((u64)1<<7): RO
        __asm__ volatile(
            "dsb ISHST\n"
            "ldr\t x4, %[L3PTEAddr]\n \
             TLBI VAE1, x4\n"
            "dsb ISH\n"
            "isb\n"
            ://output
            : [L3PTEAddr] "m"(L3PTEAddr)  // input %1
            : "x4"
        );
        
    }
    printf("Modify EL1 handler complete, the last page in 0x%lx as follows:\n", addr);
    printf("[*] L1: 0x%lx \t,L2: 0x%lx \t,L3: 0x%lx \t,PhysicalOffset: 0x%lx\n", L1offset, L2offset, L3offset, physicalOffset);
    printf(" ttbr: %lx ",ttbr);
    printf(" L1PTEAddr: %lx ",L1PTEAddr);
    printf(" L1PTE: %lx ",L1PTE);
    printf(" L2PTEAddr: %lx ",L2PTEAddr);
    printf(" L2PTE: %lx \n",L2PTE);
    printf(" L3PTE: %lx \n", L3PTE);
    printf("    AP[1](RO) %d\tAP[0](EL0) %d\tUXN %d\t PXN %d\n",(L3PTE&((u64)1<<7))?1:0,(L3PTE&((u64)1<<6))?1:0,(L3PTE&((u64)1<<54))?1:0,(L3PTE&((u64)1<<53))?1:0); //AP[1]  AP[0]   UXN   PXN


    // printf("[*] next init IPA -> PA\n");
    //[L2 index]  [L3 index] [page offset]
    //*  11 bits     11 bits    14 bits
    // u64 addr,physicalOffset,L3offset,L2offset,L1offset,ttbr,L1PTEAddr,L1PTE,L2PTEAddr,L2PTE,L3PTEAddr,L3PTE;
    // u64 vttbr = mrs(VTTBR_EL2);
    // hv_map_hw(EL1HandlerEL2base, EL1HandlerEL2base, pages* 16 * 1024);//(u64 from, u64 to, u64 size)

    
    sysop("dsb st");
    sysop("isb sy");
    sysop("dsb ishst");
    sysop("tlbi vmalle1is");
    sysop("TLBI ALLE1");
    sysop("dsb ish");
    sysop("isb");
    // for (int i=0; i<pages; i++){
    
    
    //     physicalOffset = (addr&((1<<14)-1));
    //     L3offset = (addr>>14)&((1<<11)-1);
    //     L2offset = (addr>>25)&((1<<11)-1);

    //     L2PTEAddr = (vttbr + L2offset*8);
    //     L2PTE = read64(L2PTEAddr);
    //     if (L2PTE == 0){
    //         printf("VTTBR L2 PTE == 0, retry later\n");
    //         return -1;
    //     }

    // }
    return 0;
}

// void turnOffSingleStep(void){

//     msr(MDSCR_EL1, 0x8000);
//     return;
// }

// inline u32 brkpoint(u64 addr)// the EL1 addr from ida, no kaslr
// {
//     u32 data;
//     u64 addr_after_trans;

//     // do add kaslr offset

//     if (kaslrOffset == 0){
//         printf("[-] kaslrOffset not initialized\n");
//     }

//     addr = addr + kaslrOffset; // kaslrOffset is defined in breakpoint.h


//     // do translate
//     addr_after_trans = hv_translate(addr,false, false, 0);
//                                     //stage1&2, not write

//     // read the instruction from physical memory
//     __asm__ volatile("ldr\t%w[data], [%[addr_after_trans]]"
//     : [data] "=r"(data) // output %0
//     : [addr_after_trans] "r"(addr_after_trans)  // input %1
//     : "memory");

//     printf("0x%.8x\n", data);

//     bk_ins[cnt].num = cnt;
//     bk_ins[cnt++].instruction = data;

//     // hvc #0xcc  : b'\x82\x19\x00\xd4'

//     write32(addr,brk_hvc_cc); 
// //  printf("[*] data: %d", data);

//     return bk_ins[cnt-1].instruction;
// }


bool setKcovArea(struct exc_info *ctx){
    u64 el1KcovArea = ctx->regs[17];
    if (el1KcovArea < 0xF000000000000000LL){
        printf("[hym1] setKcovArea addr = 0x%lx  < 0xF000000000000000\n", el1KcovArea);
        kcovArea = el1KcovArea;
    }else{
        kcovArea = hv_translate(el1KcovArea, false, false, 0);
    }
    // printf("[+] KcovArea is set to %lx\n", kcovArea);
    if(kcovArea == 0LL){
        printf("[-] kcovArea ( %lx ) translate failed\n", el1KcovArea);
        return false;
    }
    // testCov();
    return true;
}
bool testCov(void){
    if (kcovArea != 0){
        int testCovNum = 0x4000;
        for (int i=1; i<=testCovNum; i++){
            if (i%2 == 0)
                *((u64*)kcovArea+i) = 0xfffffff123123;
            else
                *((u64*)kcovArea+i) = 0xdeadbeefcafebabe;
        }
        *(u64*)kcovArea = testCovNum;
        
    }else{
        printf("! kcovArea == 0\n");
    }
}
// int setCnt = 0;
bool setPID(struct exc_info *ctx){
    monitored_pid = (unsigned int)ctx->regs[17];
    // if ((setCnt++)%100==0)
    // printf("[+] PID is set to %d\n", monitored_pid);
    // testCov();
    return true;
}
bool _setHCR_APIAPK(int API, int APK){
    u64 hcr = mrs(HCR_EL2);
    // printf("[*] gl2 receives API=%d, APK=%d\n", API, APK);
    // printf("[*] mrs(HCR_EL2) == %lx\n", hcr);
    
    if (API == 1){
        // printf("enter API == 1\n");
        msr_sync(HCR_EL2, hcr|((((u64)1<<41))));
        hcr = mrs(HCR_EL2);
        // printf("[*] after msr, mrs(HCR_EL2) == %lx\n", hcr);
    }else{
        // printf("enter API == 0\n");
        msr_sync(HCR_EL2, hcr&(~(((u64)1<<41))));
        hcr = mrs(HCR_EL2);
        // printf("[*] after msr, mrs(HCR_EL2) == %lx\n", hcr);
    }

    msr_sync(HCR_EL2, hcr^((u64)(APK^((hcr&((u64)1<<40))?1:0))<<40));
    // hcr = mrs(HCR_EL2);
    // printf("[*] after msr, mrs(HCR_EL2) == %lx\n", hcr);
    // printf("[*] HCR_EL2.API=%d, HCR_EL2.APK=%d\n",(hcr&((u64)1<<41))?1:0, (hcr&((u64)1<<40))?1:0);
    return true;
}
bool setHCR_APIAPK_ForAllCPUs(int API, int APK){
    if (gxf_enabled()){
        u64 cpuid = mrs(TPIDR_EL2);
        for (int i =0;i<8;i++){
            hv_switch_cpu(i);
            gl2_call(_setHCR_APIAPK, API, APK, 0, 0);
        }
        hv_switch_cpu(cpuid);
    }
    else{
        printf("[-] gxf not enabled\n");
    }
    return true;
}
bool setHCR_APIAPK(int API, int APK){
    // if (gxf_enabled())
    if(!in_gl12())
        return gl2_call(_setHCR_APIAPK, API, APK, 0, 0);
    else{
        // printf("[*] in gl2 try to call it directly\n");
        _setHCR_APIAPK(API, APK);
    }
    return true;

}

bool printMemory(u64 EL1start, int bytesize, int maxsize)
{
    if (EL1start == 0){
        return false;
    }
    u64 currAddr = EL1start;
    if (bytesize > maxsize){
        bytesize = maxsize;
    }
    while (currAddr < bytesize + EL1start){
        printf("\t\t\t0x%lx: %lx\n", currAddr, read64(hv_translate(currAddr, false, false, 0)));
        currAddr += 8;
    }
    return true;
}

bool hexdump_1(u64 EL1start, int bytesize, int maxsize){
    if (EL1start == 0){
        return false;
    }
    u64 currAddr = EL1start;
    if (bytesize > maxsize){
        bytesize = maxsize;
    }
    u64 pa = 0;
    if (EL1start < 0xF000000000000000LL){
        printf("[hym1] hexdump_1 addr = 0x%lx  < 0xF000000000000000\n", EL1start);
        pa = EL1start;
    }else{
        pa = hv_translate(EL1start, false, false, 0);
    }
    if (pa == 0){
        printf("[-] hexdump_1: va 0x%lx translate failed\n", EL1start);
        return false;
    }
    printf("\t\t\t0x%lx in ida: 0x%lx pa: 0x%lx\n", currAddr, currAddr - kaslrOffset, pa);
    hexdump((void *)pa, bytesize);
    return true;
}

#define binSize 500
int bin[binSize];

bool handleSniffIOUserClientExternalMethod_Fast(struct exc_info *ctx){ 
    printf("%lx, ", ctx->regs[1]);
    struct IOExternalMethodDispatch *dispatch = (struct IOExternalMethodDispatch *)ctx->regs[3];
    u64 functionEL2Addr = hv_translate((u64)&(dispatch->function) , false, false, 0);
    // printf("\t functionEL2Addr: 0x%lx", functionEL2Addr);
    if (functionEL2Addr == 0){
        printf("\n");
        return false;
    }
    u64 function = read64(functionEL2Addr);
    u64 dePAC_KASLR_Function = ((function-kaslrOffset)&(0x000000ffffffffffLL))|(0xFFFFFE0000000000LL);
    // printf("\t function = 0x%lx -> 0x%lx\n", function, dePAC_KASLR_Function);
    printf("0x%lx\n",dePAC_KASLR_Function);
    u64 binaryOffset = dePAC_KASLR_Function - 0xFFFFFE0007004000LL;
    int order = binarySearch(kextAddrList, 348, binaryOffset);
    bin[order] ++;
    return true;
}

void printBinOrderKextNames(void){
    printf("ExternalMethod Invocation Analysis:\n");
    for (int i=0; i<binSize; i++){
        if (bin[i]!=0){
            printf("%s : %d\n", kextNameList[i], bin[i]);
        }
    }  
}

bool handleSniffIOUserClientExternalMethod(struct exc_info *ctx){
    if (autoRestoreSingleStepCnt%10 == 0)
    {
        printf("\tX0: %lx, this ->\t pa: %lx \n", ctx->regs[0], hv_translate(ctx->regs[0],false,false,0));
        printf("\tX1: %lx, selector ->\t0x%lx\n", ctx->regs[1],ctx->regs[1]);
        printf("\tX2: %lx, arguments* ->\t pa: %lx \n", ctx->regs[2], hv_translate(ctx->regs[2],false,false,0));
        struct IOExternalMethodArguments *args = (struct IOExternalMethodArguments *)ctx->regs[2];
        // printf("trans addr -> %lx\n", (void *)args);
        /**
         * @brief 
         *  const uint64_t *    scalarInput;
            uint32_t            scalarInputCount;

            const void *        structureInput;
            uint32_t            structureInputSize;
        * 
        */
        int inpsize = read32(hv_translate((u64)&(args->scalarInputCount), false, false, 0));
        u64 inp = read64(hv_translate((u64)&(args->scalarInput) , false, false, 0));
        printf("\t         input: %lx, inputSize: %d\n", inp, inpsize);
        printMemory((u64)inp, inpsize*8, 0x20);
        inpsize = read32(hv_translate((u64)&(args->structureInputSize), false, false, 0));
        inp = read64(hv_translate((u64)&(args->structureInput) , false, false, 0));
        printf("\t         inpSt: %lx, inpStSize: %d\n", inp, inpsize);
        printMemory((u64)inp, inpsize*8, 0x20);
        printf("\tX3: %lx, dispatch* ->\t pa: %lx \n", ctx->regs[3], hv_translate(ctx->regs[3],false,false,0));
        printf("\n");

        struct IOExternalMethodDispatch *dispatch = (struct IOExternalMethodDispatch *)ctx->regs[3];
        u64 functionEL2Addr = hv_translate((u64)&(dispatch->function) , false, false, 0);
        printf("\t functionEL2Addr: 0x%lx", functionEL2Addr);
        if (functionEL2Addr == 0){
            printf("\n");
            return false;
        }
        u64 function = read64(functionEL2Addr);
        u64 dePAC_KASLR_Function = ((function-kaslrOffset)&(0x000000ffffffffffLL))|(0xFFFFFE0000000000LL);
        printf("\t function = 0x%lx -> 0x%lx\n", function, dePAC_KASLR_Function);
        u64 binaryOffset = dePAC_KASLR_Function - 0xFFFFFE0007004000LL;
        printf("\t bianryOffset = 0x%lx\n", binaryOffset);
        int order = binarySearch(kextAddrList, 348, binaryOffset);// numSize = total - 1 for index
        printf("\t dispatch func locate in = 0x%lx -> %s \n\n", dePAC_KASLR_Function, kextNameList[order]);

        // printf("\tX4: %lx, target* ->\t pa: %lx \n", ctx->regs[4], hv_translate(ctx->regs[4],false,false,0));
        // printf("\tX5: %lx, reference* ->\t pa: %lx \n", ctx->regs[5], hv_translate(ctx->regs[5],false,false,0));
        return true;
    }
}

const char *get_exception_level(void)
{
    u64 lvl = mrs(CurrentEL);

    if (in_gl12()) {
        if (lvl == 0x04)
            return "GL1";
        else if (lvl == 0x08)
            return "GL2";
    } else {
        if (lvl == 0x04)
            return "EL1";
        else if (lvl == 0x08)
            return "EL2";
    }

    return "?";
}

void panic_auto_process(struct exc_info *ctx){
    //todo
    return;
}

bool glwrite32(u64 addr, u32 value){
    if (addr>0xf000000000000000){
        printf("[-] invalid addr: %lx", addr);
        return 0;
    }
    write32(addr, value);
    return 1;
}

u64 hv_translate_EL0(u64 addr, u64 *par_out)
{
    if (!(mrs(SCTLR_EL12) & SCTLR_M))
        return addr; // MMU off

    u64 save = mrs(PAR_EL1);
    
    // u64 testEL0addr = 0;
    asm("at s12e0r, %0" : : "r"(addr));
    
    printf("testEL0addr s12e0r: 0x%lx\n", addr);
    u64 par = mrs(PAR_EL1);
    if (par_out)
        *par_out = par;
    msr(PAR_EL1, save);
    if (par & PAR_F) {
        printf("hv_translate(0x%lx): fault 0x%lx\n", addr, par);
        // return 0; // fault
    }else {
        return (par & PAR_PA) | (addr & 0xfff);
    }

    asm("at s1e0r, %0" : : "r"(addr));
    
    printf("testEL0addr s1e0r: 0x%lx\n", addr);
    par = mrs(PAR_EL1);
    if (par_out)
        *par_out = par;
    msr(PAR_EL1, save);
    if (par & PAR_F) {
        printf("hv_translate(0x%lx): fault 0x%lx\n", addr, par);
        // return 0; // fault
    }else {
        return (par & PAR_PA) | (addr & 0xfff);
    }
    return 0;
}


extern u64 hook_page_cnt, hook_block_cnt;
int init_backup_pagetable(void){
    if (ttbr1_backup != -1){
        printf("[-] shadow pagetable already set\n");
        return -1;
    }
    ttbr1_backup = mrs(TTBR1_EL12);
    printf("[+] ttbr1_backup: 0x%lx\n", ttbr1_backup);
    u64* pt = backup_pt_init();
    if (pt == 0){
        printf("[-] shadow pagetable init failed\n");
        return -1;
    }
    backup_pt_ttbr = (u64)pt;
    
    
    
    u64 handoff_addr = hv_translate(0xFFFFFE000D72FFC8LL+kaslrOffset, false, false, 0);
    if (handoff_addr == 0){
        printf("[-] handoff_addr translate failed\n");
        return -1;
    }
    IPA_hook_blacklist_handoff = read64(handoff_addr);
    printf("[*] raw handoff_value: 0x%lx\n", IPA_hook_blacklist_handoff);
    IPA_hook_blacklist_handoff = pt_walk(IPA_hook_blacklist_handoff, mrs(TTBR1_EL12), 3, 1, false);
    if (IPA_hook_blacklist_handoff!=-1){
        printf("[+] handoff_value: 0x%lx\n", IPA_hook_blacklist_handoff);
    }else{
        printf("[!] !handoff_value: 0x%lx\n", IPA_hook_blacklist_handoff);
        return -1;
    }
    return 0;
}

void set_backup_pagetable_for_cpuid(int cpuid){
    if (backup_pt_ttbr == -1){
        printf("[-] shadow pagetable not initialized\n");
        return;
    }
    hook_page_cnt = 0;
    fill_backup_pt_per_cpu(mrs(TTBR1_EL12));
    printf("hook_page_cnt: %d, hook_block_cnt: %d\n", hook_page_cnt, hook_block_cnt);
}

// u64 set_ss_mode(u64 mode){
//     SSmode = mode;
//     printf("[+] SSmode change to: 0x%lx\n", SSmode);
//     return (u64) SSmode;
// }

u64 simulate_move_ins(struct exc_info *ctx, int dest, int source, u64 immediate, bool is32){
    if (source != -1){ 
        if (is32){
            ctx->regs[dest] = (u32)ctx->regs[source];
        }else{
            ctx->regs[dest] = ctx->regs[source];
        }
    }else if (immediate != -1){
        if (is32){
            (ctx->regs[dest]) = (u32)immediate;
        }else{
            ctx->regs[dest] = immediate;
        }
    }else{
        printf("[-] simulate_move_ins: invalid input\n");
    }
    return 0;
}


const bool skip_first_syscall = false; 

u64 monitored_pid_syscall_return_addr = (skip_first_syscall)?-1:0;


u64 syscall_cnt = 0;
u64 auto_simulate_syscall_entrance(struct exc_info *ctx){
    // asan mach_syscall FFFFFE0008BDA354 F4 03 00 AA                             MOV             X20, X0
    // H11ANEInDirectPathClient::_ANE_ProgramSendRequest FFFFFE000B509F98 F6 03 00 AA                             MOV             X22, X0

    // dev: _ANE_ProgramSendRequest FFFFFE00096FDF98                 MOV             X22, X0
    // dev mach_syscall  :FFFFFE000866E8EC                 MOV             X19, X0
    simulate_move_ins(ctx, 20, 0, -1, false);
    // if (monitored_pid!=-1 && monitored_pid == getCurrentPID()){
    //     monitored_pid_syscall_return_addr = mrs(ELR_EL12);
    // }
    // if (monitored_pid == getCurrentPID()){
        // if ((syscall_cnt ++)%100==0){
        //     printf("[*] syscall_cnt: %d\n", syscall_cnt);
        // }
    // }
    return 0;
}

bool if_activated_hooked_syscall_exit = false;
u64 auto_simulate_syscall_exit(struct exc_info *ctx){
    if_activated_hooked_syscall_exit = true;
#if macOSVersion_22g91
    #if KASAN
        // FFFFFE0008BDA878 EA C3 00 32                             MOV             W10, #0x1010101
        simulate_move_ins(ctx, 10, -1, 0x1010101, true);
    #else
        // FFFFFE000866EAE0                 MOV             W0, #1  ; sleep_amount
        simulate_move_ins(ctx, 0, -1, 1, true);
    #endif
#endif  
    
    if (monitored_pid!=-1 && monitored_pid == getCurrentPID() && monitored_pid_syscall_return_addr == mrs(ELR_EL12)){
        // monitored_pid_syscall_return_addr[mrs(TPIDR_EL2)] = 0;
        monitored_pid_syscall_return_addr = 0;
    }
    return 0;
}
bool judge_if_not_in_the_same_syscall(int cpu_id){
    // if ( (mrs(ELR_EL12) != monitored_pid_syscall_return_addr[cpu_id]) && monitored_pid_syscall_return_addr[cpu_id] != -1){
    //     monitored_pid_syscall_return_addr[cpu_id] = mrs(ELR_EL12);
    //     return true;
    // }
    if (if_activated_hooked_syscall_exit == false){ 
        printf("[!!!!!] judge_if_not_in_the_same_syscall: kernel isn't patched yet\n");
    }
    if ( (mrs(ELR_EL12) != monitored_pid_syscall_return_addr) && monitored_pid_syscall_return_addr!= -1){
        monitored_pid_syscall_return_addr = mrs(ELR_EL12);
        return true;
    }
    return false;
}