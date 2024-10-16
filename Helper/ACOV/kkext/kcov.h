//
//  kcov.h
//  kkext
//
//  Adapted from SyzGen.
//
#include <mach/mach_types.h>
#include <libkern/libkern.h>
#include <sys/kern_control.h>

#define DRIVER_NAME "acov"
#define DRIVER_CTL_NAME "com.crossfire.acov"


#define KCOV_FILE "/tmp/kcov"

// Opcode for getopt
#define SOCKOPT_GET_TEST 1
#define SOCKOPT_GET_BP   2

#define SOCKOPT_SET_ENABLE  1
#define SOCKOPT_SET_DISABLE 2
#define SOCKOPT_SET_PID 3
#define SOCKOPT_GET_COV 4


#define NUM_OF_KCOV 1
#define COVER_SIZE (256 << 10)*16//0x40000，

#define DO_LOG 0// 

typedef struct kcov {
    uint64_t *area;
    bool     enable;
} kcov_t;


kern_return_t register_kernelCtrl(void);
void deregister_kernelCtrl(void);
errno_t KcovHandleConnect(kern_ctl_ref ctlref, struct sockaddr_ctl *sac, void **unitinfo);
errno_t KcovhandleDisconnect(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo);
errno_t KcovHandleSend(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, mbuf_t m, int flags);

errno_t KcovHandleSetOpt(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, int opt, void *data, size_t len);
errno_t KcovHandleGetOpt(kern_ctl_ref ctlref, unsigned int unit, void *unitinfo, int opt, void *data, size_t *len);
static kern_return_t enable_kcov(kcov_t *kcov);
static kern_return_t disable_kcov(kcov_t *kcov);
static kern_return_t get_cov(user_addr_t user_addr);
