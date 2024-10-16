#include "types.h"
u64 setBreakpointByAddr(u64 addr);
u64 setBreakpointByAddr_IDA(u64 addr);
u64 setBreakpointByIndex(int index, u64 addr, u32 breakpoint_inst);
bool disableBreakpointInstrument(int idx);
bool listBreakpoints(void);
bool setBreakpointStatus(int idx, int status);
bool writeEL1Mem(u64 addr, u32 data);
bool handleBreakpointInvocation(u64 elr);
bool dumpEL2Mem(u64 addr, u32 size);
u32 setDebugPid(u64 pid);
void kextSetDebugPid(struct exc_info *ctx);
// bool debuggerSingleStepExecute(void);
u32 get_brinst_from_brcode(u32 brcode);
u64 set_breakpoint_in_ida_with_brcode(u64 addr, u32 brcode);
u64 setBreakpointByAddr_with_bkinst(u64 addr, u32 bkinst);