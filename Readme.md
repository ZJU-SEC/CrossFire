## Introduction

This project aims to provide a method to analyze and further fuzz the cross-XPU memory in macOS using the customized hypervisor based on [m1n1](https://github.com/AsahiLinux/m1n1).

This project employs manipulation of the stage-2 translation entries for cross-XPU memory to monitor access in both user and kernel spaces. Additionally, it utilizes hypervisor calls and single-step traps to comprehensively instrument macOS and record execution traces.

The Hypervisor directory contains the hypervisor code along with its manager, while the Helper directory includes essential scripts and tools such as Instrumentation, ACOV, and Memory-Scan. The Instrumentation tool allows for kernelcache instrumentation in targeted kernel extensions, and ACOV provides a kernel extension interface for managing traces. Additionally, Memory-Scan is used to dump the virtual memory area (VMA) of a specific seed application.

## Setup

**Environment**

- Two Apple M1 Macs.
- A USB-C cable to connect the two devices. The server PC manages the target PC and runs the hypervisor.

1. **Install Hypervisor and macOS (22g91)**

   - [Install macOS 22g91](https://support.apple.com/en-us/102662) in the target PC.
   - Follow the [installation guidance](https://github.com/AsahiLinux/m1n1) to compile the binary in the hypervisor directory by running: `$ make` in server PC.
   - If you see the info below, the compilation is successful:
     ```shell
     ...
     ld.lld: warning: section type mismatch for .iplt
     >>> <internal>:(.iplt): SHT_PROGBITS
     >>> output section .empty: SHT_NOBITS
     RAW   build/m1n1.bin
     rm build/bootlogo_128.bin build/bootlogo_256.bin build/font_retina.bin build/font.bin
     ```
   - Troubleshooting:
     - If you encounter `fatal error: 'mach/mach.h' file not found` or similar errors, install the SDK and Xcode command line tools by running `xcode-select --install`.
     - If you encounter `src/adt.c:4:10: fatal error: 'string.h' file not found`, check if `string.h` is in the `Hypervisor/sysinc` directory. If not, copy `string.h` from the SDK to the `Hypervisor/sysinc` directory.
2. **Build macOS Kernelcache for Instrumentation**

   - Follow the [Apple Kernel Development guide](https://kernelshaman.blogspot.com/2021/02/building-xnu-for-macos-112-intel-apple.html) to build the kernelcache from the macOS installation in server PC.
   - This step prepares the kernelcache for instrumentation, naming it `kernelcache.macho`.
3. **Run Instrumentation Using the Script in `Helper/Instrumentation`**

   1. Backup the original kernelcache to `kernelcache.macho_backup` in server PC.
   2. Follow the steps in `Helper/Instrumentation/Readme.md` to instrument the kernelcache.
4. **Run macOS (22g91 + KASAN) with Hypervisor**

   1. Move `kernelcache.macho` and `kernelcache.macho_backup` to the same directory. The hypervisor will automatically load the `kernelcache.macho_backup` to the memory.
   2. Follow the [instructions](https://github.com/AsahiLinux/docs/wiki/m1n1%3AUser-Guide) to boot macOS with the hypervisor according to your environment. Note that the booting process is customized for the recovery of instrumentation:

   ```c
     ...
     [+] kaslr offset set to be:  0xa0b4000
     Setting secondary CPU RVBARs...
     cpu1: [0x210150000] = 0x81f95c000
     ...
     cpu7: [0x211350000] = 0x81f95c000
     [*] backup kernel path = /mnt/hgfs/macos/kernelcache.macho_backup
     [*] backup text length = 0x56a0000, and it will be written to 0x80e000000, so the top addr will be 0x8136a0000
   ```
5. **Set Trace**

   1. Build the [trace tool](Helper/ACOV/) `Helper/ACOV` using Xcode.
   2. Install `ACOV` in the macOS of the target PC.
6. **Enable Memory Fuzzing**

   1. Run `Helper/Memory-Scan/dumpmap.py` to dump the VMA of the process of one seed application.
   2. Input these areas to enable memory fuzzing through the `rar` command in the hypervisor terminal.
   3. The fuzzing process will be automatically executed in the initial stage for detecting crashes. You can further analyze the cross-XPU memory access point got from the kernel from command `parh` and pinpoint the fuzzing point. You can get the statistics of the cross-XPU memory.

```shell
>>> parh
Address Range Hit Count Sort:
 [7:(0x104e20000 - 0x104e80000), sz:0x60000, IOAccelerator, 
        ulpc:0x1e90332c0,        uspc:0x1e903211c,       klpc: 0x0,      kspc: 0x0
         ul: 5,  us: 9462,       kl: 0,  ks: 0,  hit_count: 9467
        us_lower: 0x104e20030,  us_upper: 0x104e3f330, us_size: 0x1f300,        us_ratio: 0.3248697916666667
---------------------------
, 9:(0x10d2d4000 - 0x10d2d8000), sz:0x4000, IOAccelerator, 
        ulpc:0x0,        uspc:0x1e9030408,       klpc: 0xfffffe000c6107fc,       kspc: 0x0
         ul: 0,  us: 180,        kl: 44,         ks: 0,  hit_count: 224
        us_lower: 0x10d2d4000,  us_upper: 0x10d2d4750, us_size: 0x750,  us_ratio: 0.1142578125
...
```
