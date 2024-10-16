//
//  kkext.c
//  kkext
//

#include <mach/mach_types.h>
#include <os/log.h>
#include <libkern/libkern.h>
#include <kcov.h>

kern_return_t kkext_start(kmod_info_t * ki, void *d);
kern_return_t kkext_stop(kmod_info_t *ki, void *d);

kern_return_t kkext_start(kmod_info_t * ki, void *d)
{
    // 
    os_log(OS_LOG_DEFAULT,"testtest");
    
    errno_t err = KERN_SUCCESS;
    printf("[%s.kext] Kernel module is loaded.\n", DRIVER_NAME);
    // register interface
    if ((err = register_kernelCtrl()) != KERN_SUCCESS)
        return err;
    
    return KERN_SUCCESS;
}

kern_return_t kkext_stop(kmod_info_t *ki, void *d)
{
    return KERN_SUCCESS;
}
