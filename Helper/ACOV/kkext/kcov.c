//
//  kcov.c
//  kkext
//
//  Adapted from SyzGen.
//
#include <mach/mach_types.h>
#include <os/log.h>
#include <libkern/libkern.h>
#include <sys/kern_control.h>
#include "kcov.h"
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/proc.h>
#include <sys/param.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/mman.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <mach/task.h>
#include <mach/task_info.h>
//#include <sys/malloc.h>

kcov_t *gKcov[NUM_OF_KCOV] = {NULL};
kern_ctl_ref gKeCtlRef = NULL;
static char kovArea[COVER_SIZE];
kcov_t kcovg = {NULL, false};
int monitered_pid = -1;

kern_return_t
register_kernelCtrl(
    )
{
    struct kern_ctl_reg KeCtlReg = {0};
    bzero(&KeCtlReg, sizeof(struct kern_ctl_reg));
    strncpy(KeCtlReg.ctl_name, DRIVER_CTL_NAME, strlen(DRIVER_CTL_NAME));
    KeCtlReg.ctl_flags      =    CTL_FLAG_REG_SOCK_STREAM;
    KeCtlReg.ctl_setopt     =    KcovHandleSetOpt;
    KeCtlReg.ctl_getopt     =    KcovHandleGetOpt;
    KeCtlReg.ctl_connect    =    KcovHandleConnect;
    KeCtlReg.ctl_disconnect =    KcovhandleDisconnect;
    KeCtlReg.ctl_send       =    KcovHandleSend;
    
    
    errno_t err = ctl_register(&KeCtlReg, &gKeCtlRef);
    if (err == KERN_SUCCESS) {
        printf("Register KerCtlConnection success: id=%d", KeCtlReg.ctl_id);
    } else {
        printf("Fail to register: err=%d", err);
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

void deregister_kernelCtrl() {
    if (gKeCtlRef == NULL) {
        return;
    }
    
    errno_t err = ctl_deregister(gKeCtlRef);
    if (err) {
        printf("Fail to deregister: err=%d", err);
    }
    gKeCtlRef = NULL;
}

extern mach_vm_address_t mapMemToTargetPid(int pid, char* kovArea);
errno_t KcovHandleSetOpt(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, int opt, void *data, size_t len) {
#if DO_LOG
    printf("[%s.kext] call setOpt %d with unit %d, data=%p, len=%ld\n", DRIVER_NAME, opt, unit, data, len);
#endif
    int error = KERN_INVALID_VALUE;
    int pid = 0;
    switch (opt) {
        case SOCKOPT_SET_ENABLE:
            error = enable_kcov((kcov_t *)unitinfo);// 
            break;
        case SOCKOPT_SET_PID:
            pid = *(int*)data;
#if DO_LOG
            printf("[%s.kext] pid: %d, ready to pass to hym1\n", DRIVER_NAME, pid);
#endif
            asm volatile (
                    "mov X17, %[pid] \n"
                    "hvc #0x92 \n"     // 
                    :
                    : [pid] "r" (pid)
                    : "x17"// 
            );
            
            if (monitered_pid!=pid){
                monitered_pid = pid;
                mapMemToTargetPid(pid, kovArea);
            }
            return KERN_SUCCESS;
        case SOCKOPT_SET_DISABLE:
            disable_kcov((kcov_t *)unitinfo);
            return KERN_SUCCESS;
        case SOCKOPT_GET_COV:
            get_cov(data);
            return KERN_SUCCESS;
        default:
            break;
    }
    return error;
}

errno_t KcovHandleGetOpt(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, int opt, void *data, size_t *len) {
#if DO_LOG
    printf("[%s.kext] call getOpt %d with unit %d\n", DRIVER_NAME, opt, unit);
#endif
    int error = EINVAL;
    switch (opt) {
//        case SOCKOPT_GET_TEST:
//            test_install_breakpoints(data);
//            return KERN_SUCCESS;
//        case SOCKOPT_GET_BP:
//            show_breakpoints(data, len);
//            return KERN_SUCCESS;
        default:
            break;
    }
    return error;
}



errno_t KcovHandleConnect(kern_ctl_ref ctlref, struct sockaddr_ctl *sac, void **unitinfo) {
#if DO_LOG
    printf("[%s.kext] call connect...\n", DRIVER_NAME);
#endif
    for (int i = 0; i < NUM_OF_KCOV; i++) {
//        if (gKcov[i] != NULL) {
//            continue;
//        }
//        memset(kovArea, 0, COVER_SIZE);
        memset(kovArea, 0, 8);
//        kovArea[0]='a';
//        kovArea[1]='b';
#if DO_LOG
        printf("[kov connect value] %p: %s\n", kovArea, kovArea);
#endif
        
//        kcov_t *kcov = _MALLOC(sizeof(kcov_t), M_TEMP, M_ZERO);
//        kcovg.area = NULL;
//        kcovg.enable = false;
        
        gKcov[i] = &kcovg;
        *unitinfo = &kcovg;
        return KERN_SUCCESS;
    }
    
    return KERN_NO_SPACE;
}

errno_t KcovhandleDisconnect(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo) {
#if DO_LOG
    printf("[%s.kext] call disconnect...kCovArea: %p\n", DRIVER_NAME, kovArea);
#endif
    kcov_t *kcov = unitinfo;
    // 
//    for (int i = 0; i < NUM_OF_KCOV; i++) {
//        if (gKcov[i] == kcov) {
//            gKcov[i] = NULL;
//            break;
//        }
//    }
    
    if (kcov) {
        if (kcov->area) {
//            _FREE(kcov->area, M_TEMP);
//            memset(kovArea, 0, COVER_SIZE);
              // 
//            kovArea[0]='a';
//            kovArea[1]='b';
#if DO_LOG
            printf("[kov disconnect value] %p: %s\n", kovArea, kovArea);
#endif
//            kcov->area = NULL; // 
        }
//        _FREE(kcov, M_TEMP);
//        kcovg.enable = false;
//        kcovg.area = NULL;
    }
    return KERN_SUCCESS;
}

//errno_t KcovHandleSend(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, mbuf_t m, int flags) {
//#if DO_LOG
//    printf("[%s.kext] call Send...\n", DRIVER_NAME);
//#endif
//    int error = KERN_SUCCESS;
//    kcov_t *kcov = unitinfo;
//    // release input data (Make sure the input is aligned with 8).
//    mbuf_freem(m);
//    if (kcov && kcov->area) {
//        uint64_t pos = kcov->area[0];
////#if DO_LOG
//        printf("[%s.kext] pcs: 0x%p...\n", DRIVER_NAME, (void*)pos);
////#endif
//        // TODO: Is it necessary to make sure all data can be sent to user space?
//        // The interface is not designed to transfer large amount of data.
//        size_t remain = 0;
//        if ((error = ctl_getenqueuespace(gKeCtlRef, unit, &remain)) != 0) {
//            printf("invalid parameters for getenqueuespace: %d\n", error);
//            return error;
//        }
//        
//        if (remain < sizeof(uint64_t)) {
//            printf("[%s.kext] no space at all\n", DRIVER_NAME);
//            return KERN_NO_SPACE;
//        }
//        remain -= sizeof(uint64_t);
//        
//        if (remain / 8 < pos) {
//            printf("[%s.kext] remaining space is not enough!\n", DRIVER_NAME);
//            pos = remain / 8;
//        }
//        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &pos, sizeof(uint64_t), 0)) != 0) {
//            return error;
//        }
//        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &kcov->area[1], pos*sizeof(uint64_t), 0)) != 0) {
//            return error;
//        }
//    } else {
//        printf("[%s.kext] kcov is NULL\n", DRIVER_NAME);
//        uint64_t pos = 0;
//        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &pos, sizeof(uint64_t), 0)) != 0) {
//            return error;
//        }
//    }
//    return error;
//}

errno_t KcovHandleSend(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, mbuf_t m, int flags) {
#if DO_LOG
    printf("[%s.kext] call Send...\n", DRIVER_NAME);
#endif
    int error = KERN_SUCCESS;
    kcov_t *kcov = unitinfo;
    // release input data (Make sure the input is aligned with 8).
    mbuf_freem(m);
    if (kcov && kcov->area) {
        uint64_t pos = kcov->area[0];
//#if DO_LOG
        printf("[%s.kext] pcs: 0x%p...\n", DRIVER_NAME, (void*)pos);
//#endif
        // The interface is not designed to transfer large amount of data.
        size_t remain = 1000;
        size_t total_pcs = pos; // Total size of data to be sent
        size_t pcs_sent = 0;
        size_t segment_pcs = 1000;
        // 
        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &pos, sizeof(uint64_t), 0)) != 0) {
            return error;
        }
        // 
        while (pcs_sent < total_pcs) {
            
            do
            {
                if ((error = ctl_getenqueuespace(gKeCtlRef, unit, &remain)) != 0) {
                    printf("Invalid parameters for getenqueuespace: %d\n", error);
                    return error;
                }
            }while(remain < segment_pcs);
            

            if (remain < sizeof(uint64_t)) {
                printf("[%s.kext] No space at all\n", DRIVER_NAME);
                return KERN_NO_SPACE;
            }
            size_t pcs_to_send = MIN(segment_pcs, total_pcs - pcs_sent);
#if DO_LOG
            printf("[%s.kext] pcs_sent: 0x%lx, total: 0x%lx, pcs_to_send: 0x%lx, remain: p0x%lx, before sent\n", DRIVER_NAME, pcs_sent, total_pcs, pcs_to_send, total_pcs - pcs_sent);
#endif
            
            if ((error = ctl_enqueuedata(gKeCtlRef, unit, &kcov->area[1] + pcs_sent, pcs_to_send, 0)) != 0) {
                printf("send error, code: %d", error);
                return error;
            }
            
//            ctl_enqueuembuf(gKeCtlRef, unit, m, 0);
            pcs_sent += pcs_to_send;
        }
    } else {
        printf("[%s.kext] kcov is NULL\n", DRIVER_NAME);
        uint64_t pos = 0;
        if ((error = ctl_enqueuedata(gKeCtlRef, unit, &pos, sizeof(uint64_t), 0)) != 0) {
            return error;
        }
    }
    return error;
}


static
kern_return_t
enable_kcov(
    kcov_t *kcov
    )
{
#if DO_LOG
    printf("[%s.kext] kcov enable...\n", DRIVER_NAME);
#endif
//    if (kcovg.area) {
//        _FREE(kcov->area, M_TEMP);
//        memset(kovArea, 0, 8);
        kcovg.area = NULL;
//    }
    
//    kcov->area = _MALLOC(COVER_SIZE, M_TEMP, M_ZERO);
    kcovg.area = (uint64_t *) kovArea;
    kcovg.enable = true;
    
    if (kcovg.area == NULL)
        return KERN_NO_SPACE;
    
    asm volatile (
            "mov X17, %[address] \n"     // 
            "hvc #0x91 \n"     // 
            :
            : [address] "r" (kcov->area)
            : "x17"// 
    );
    // First field is the number of recorded pc.
    
    return KERN_SUCCESS;
}

static
kern_return_t
disable_kcov(
    kcov_t *kcov
    )
{
    // todo: 
    memset(kovArea, 0, 8);
    if (kcov && kcov->area) {
//        _FREE(kcov->area, M_TEMP);
//        memset(kovArea, 0, 8);
//        kcovg.area[0] = 0;
//        kcovg.area = NULL;
    }
    return KERN_SUCCESS;
}

static kern_return_t
get_cov(user_addr_t user_addr){
#if DO_LOG
    printf("[%s.kext] user data addr: %p\n", DRIVER_NAME, (void*)user_addr);
#endif
    int64_t pcs = (int64_t)kovArea[0];
#if DO_LOG
    printf("[%s.kext] pcs: 0x%p...\n", DRIVER_NAME, (void*)pcs);
#endif
    if (pcs > ((COVER_SIZE-8)/8)){
        pcs = (COVER_SIZE-8)/8;
        printf("[%s.kext] remaining space is not enough! max pcs=0x%llx\n", DRIVER_NAME, pcs);
    }
    copyout(kovArea, user_addr, (size_t)pcs*8+8);
    return KERN_SUCCESS;
}
