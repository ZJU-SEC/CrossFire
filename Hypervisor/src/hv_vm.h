#include "hv.h"
#include "assert.h"
#include "cpu_regs.h"
#include "exception.h"
#include "iodev.h"
#include "malloc.h"
#include "smp.h"
#include "string.h"
#include "types.h"
#include "uartproxy.h"
#include "utils.h"

u64 hv_translate(u64 addr, bool s1, bool w, u64 *parout);
u64 ipawalk(u64 addr);
u64 *hv_l3(u64 from);
u64 hv_l4(u64 from);
