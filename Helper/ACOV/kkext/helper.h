//
//  help.hpp
//  kkext
//
#pragma once
#include <mach/vm_types.h>


extern "C" {
    mach_vm_address_t mapMemToTargetPid(int pid);
}

