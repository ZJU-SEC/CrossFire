
#include "proxy.h"
#include "dart.h"
#include "exception.h"
#include "fb.h"
#include "gxf.h"
#include "heapblock.h"
#include "hv.h"
#include "iodev.h"
#include "kboot.h"
#include "malloc.h"
#include "memory.h"
#include "pcie.h"
#include "pmgr.h"
#include "smp.h"
#include "string.h"
#include "tunables.h"
#include "types.h"
#include "uart.h"
#include "uartproxy.h"
#include "usb.h"
#include "utils.h"
#include "xnuboot.h"
#include "cpu_regs.h"

#include "minilzlib/minlzma.h"
#include "tinf/tinf.h"


typedef unsigned int            __darwin_natural_t;
typedef __darwin_natural_t __darwin_mach_port_name_t; /* Used by mach */
typedef __darwin_mach_port_name_t __darwin_mach_port_t; /* Used by mach */
typedef __darwin_mach_port_t mach_port_t;
typedef uint64_t                io_user_reference_t;

struct IOExternalMethodArguments {
	uint32_t            version;

	uint32_t            selector;

	mach_port_t           asyncWakePort;
	io_user_reference_t * asyncReference;
	uint32_t              asyncReferenceCount;

	const uint64_t *    scalarInput;
	uint32_t            scalarInputCount;

	const void *        structureInput;
	uint32_t            structureInputSize;

	void * structureInputDescriptor;

	uint64_t *          scalarOutput;
	uint32_t            scalarOutputCount;

	void *              structureOutput;
	uint32_t            structureOutputSize;

	void * structureOutputDescriptor;
	uint32_t             structureOutputDescriptorSize;

	uint32_t            __reservedA;

	void **         structureVariableOutputData;

	uint32_t            __reserved[30];
};

struct IOExternalMethodDispatch {
	void* function;
	uint32_t               checkScalarInputCount;
	uint32_t               checkStructureInputSize;
	uint32_t               checkScalarOutputCount;
	uint32_t               checkStructureOutputSize;
};

u32 brkpoint(u64 addr);
u32 handleKaslrOffset(u64 EL1PC);
u32 handleWIFI(u64 EL1PC);
u32 saveBackuptextBase(u64 base);
u32 handleAutoRestore(u64 EL1PC);
u64 setKaslrOffset(u64 Offset);
u32 handleDoubleCross1(u64 addr);
u32 handleDoubleCross2(u64 addr);
u32 handleAutoRestoreAndSingleStep(u64 addr, bool enableAccurateRestoreSingleStep);
u32 handleSingleStepReinstrument(void);
void getPA(u64 addr);
// void inline restoreCode(u64 addr, bool savePhysicalAddr);
u32 switchExceptionRoute(void);
u32 setEL2handlerForEL1handlerBase(u64 addr);
u32 analyzeVAddr(u64 addr);
u32 mapEL1HandlerPTE(u64 EL1HandlerEL2base, u64 EL1VAddrBase);
// void turnOffSingleStep(void);
bool setKcovArea(struct exc_info *ctx);
bool setPID(struct exc_info *ctx);
bool setHCR_APIAPK(int API, int APK);
bool setHCR_APIAPK_ForAllCPUs(int API, int APK);
u32 getCurrentPID(void);
u64 setRunningKernelEl2Base(u64 addr);
bool printMemory(u64 EL1start, int bytesize, int maxsize);
bool handleSniffIOUserClientExternalMethod(struct exc_info *ctx);
void printBinOrderKextNames(void);
bool handleSniffIOUserClientExternalMethod_Fast(struct exc_info *ctx);
u32 getOriginalBackupInstData(u64 addr);
bool disableInstCache(u64 addr);
bool turnOnSSServer(void);
bool turnOffSSServer(void);
bool turnOnSS(u32 cpuid, SSMODE ssmode);
bool turnOffSS(void);
bool hexdump_1(u64 EL1start, int bytesize, int maxsize);
bool clearDataCache(u64 addr);
const char *get_exception_level(void);
bool testCov(void);
void printCov(void);
void panic_auto_process(struct exc_info *ctx);
bool glwrite32(u64 addr, u32 value);
u32 analyzeEL0Addr(u64 addr);
void set_backup_pagetable_for_cpuid(int cpuid);
int init_backup_pagetable(void);
bool is_monitored(void);

u64 uva_hook(u64 va, int size, u64 ttbr0);
u64 kva_hook(u64 va, int size);
// u64 set_ss_mode(u64 mode);

u64 auto_simulate_syscall_entrance(struct exc_info *ctx);
u64 auto_simulate_syscall_exit(struct exc_info *ctx);
bool judge_if_not_in_the_same_syscall(int cpu_id);