//
//  helper.cpp
//  kkext
//

#include <mach/mach_types.h>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSBoolean.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <mach/mach_vm.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <mach/task.h>
#include "kcov.h"

// fake entitlement checkers
class IOFuzzClient{
public:
    OSObject * copyClientEntitlement(task_t task, const char *entitlement);
    OSObject * AMFIcopyClientEntitlement(task_t task, const char *entitlement);
};

OSObject * IOFuzzClient::copyClientEntitlement( task_t task,const char * entitlement ){
    return kOSBooleanTrue;
}

OSObject * IOFuzzClient::AMFIcopyClientEntitlement( task_t task,const char * entitlement ){
    return kOSBooleanTrue;
}

extern char* kovArea;
static bool isMapped = false;
mach_vm_address_t kcovUserAddress=0xcafebabe00000000;
#define _22g91_proc_struct_size 0x780
task_t getTaskForPID(int pid) {
    proc_t process = proc_find(pid);
#if DO_LOG
        printf("[%s.kext] process: %p\n", DRIVER_NAME, process);
#endif
    if (process == NULL) {
        printf("Process with PID %d not found\n", pid);
        return NULL;
    }
    
    task_t task = (task_t)((char*)process + _22g91_proc_struct_size);
    proc_rele(process);
    return task;
}

static mach_vm_address_t mapMemToTargetPid(int pid)
{
    if (isMapped)
        return kcovUserAddress;
    task_t task = getTaskForPID(pid);
    // 
#if DO_LOG
        printf("[%s.kext] task: %p\n", DRIVER_NAME, task);
#endif
    IOMemoryDescriptor* memoryDescriptor = IOMemoryDescriptor::withAddressRange(
        (mach_vm_address_t) kovArea,
        COVER_SIZE,
        kIODirectionInOut,
        kernel_task
    );

    if (!memoryDescriptor) {
#if DO_LOG
        printf("[%s.kext] Failed to create memory descriptor\n", DRIVER_NAME);
#endif
        return -1;
    }

    // 
    IOMemoryMap* kr = memoryDescriptor->createMappingInTask(task, kcovUserAddress, kIOMapStatic);
#if DO_LOG
        printf("[%s.kext] mapped kr: %p\n", DRIVER_NAME, kr);
#endif
    isMapped = true;
    return kcovUserAddress;
}
