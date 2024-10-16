/* SPDX-License-Identifier: MIT */

// #define DEBUG

#include "hv_vm.h"
#include "breakpoint.h"

extern uint64_t ram_base;

#define PAGE_SIZE       0x4000
#define CACHE_LINE_SIZE 64
#define CACHE_LINE_LOG2 6

#define PTE_ACCESS            BIT(10)
#define PTE_SH_NS             (0b11L << 8)
#define PTE_S2AP_RW           (0b11L << 6)
#define PTE_MEMATTR_UNCHANGED (0b1111L << 2)

#define PTE_ATTRIBUTES (PTE_ACCESS | PTE_SH_NS | PTE_S2AP_RW | PTE_MEMATTR_UNCHANGED)

#define PTE_LOWER_ATTRIBUTES GENMASK(13, 2)

#define PTE_VALID BIT(0)
#define PTE_TYPE  BIT(1)

#define PTE_BLOCK 0
#define PTE_TABLE 1
#define PTE_PAGE  1
// #define PTE_SHM_PERM ((0b00 << 6) | (0b11 << 53))

#define VADDR_L4_INDEX_BITS 12
#define VADDR_L3_INDEX_BITS 11
#define VADDR_L2_INDEX_BITS 11
#define VADDR_L1_INDEX_BITS 8

#define VADDR_L4_OFFSET_BITS 2
#define VADDR_L3_OFFSET_BITS 14
#define VADDR_L2_OFFSET_BITS 25
#define VADDR_L1_OFFSET_BITS 36

#define VADDR_L2_ALIGN_MASK GENMASK(VADDR_L2_OFFSET_BITS - 1, VADDR_L3_OFFSET_BITS)
#define VADDR_L3_ALIGN_MASK GENMASK(VADDR_L3_OFFSET_BITS - 1, VADDR_L4_OFFSET_BITS)
#define PTE_TARGET_MASK     GENMASK(49, VADDR_L3_OFFSET_BITS)
#define PTE_TARGET_MASK_L4  GENMASK(49, VADDR_L4_OFFSET_BITS)

#define ENTRIES_PER_L1_TABLE BIT(VADDR_L1_INDEX_BITS)
#define ENTRIES_PER_L2_TABLE BIT(VADDR_L2_INDEX_BITS)
#define ENTRIES_PER_L3_TABLE BIT(VADDR_L3_INDEX_BITS)
#define ENTRIES_PER_L4_TABLE BIT(VADDR_L4_INDEX_BITS)

#define SHADOW_ENTRIES_PER_L1_TABLE BIT(11)
#define SHADOW_ENTRIES_PER_L2_TABLE BIT(VADDR_L2_INDEX_BITS)
#define SHADOW_ENTRIES_PER_L3_TABLE BIT(VADDR_L3_INDEX_BITS)


#define PTE_L3_CF_HOOK_PATTERN_MASK 0xff000000000000f
#define PTE_L3_CF_HOOK_PATTERN      0x060000000000003



#define IS_HW(pte) ((pte) && pte & PTE_VALID)
#define IS_SW(pte) ((pte) && !(pte & PTE_VALID))
#define IS_PTE_RW(pte) ((pte&((u64)1<<6))==0 && (pte&((u64)1<<7))==0 && (pte&((u64)1<<53))!=0 && (pte&((u64)1<<54))!=0)

#define L1_IS_TABLE(pte) ((pte) && FIELD_GET(PTE_TYPE, pte) == PTE_TABLE)

#define L2_IS_TABLE(pte)     ((pte) && FIELD_GET(PTE_TYPE, pte) == PTE_TABLE)
// #define L2_IS_MAPPED_TO_L3_TABLE(pte)     ((pte) && (L2_PTE_MAPPED_TO_L3&pte) != 0)
#define L2_IS_NOT_TABLE(pte) ((pte) && !L2_IS_TABLE(pte))
#define L2_IS_HW_BLOCK(pte)  (IS_HW(pte) && FIELD_GET(PTE_TYPE, pte) == PTE_BLOCK)
#define L2_IS_SW_BLOCK(pte)                                                                        \
    (IS_SW(pte) && FIELD_GET(PTE_TYPE, pte) == PTE_BLOCK && FIELD_GET(SPTE_TYPE, pte) == SPTE_MAP)
#define L3_IS_TABLE(pte)     (IS_SW(pte) && FIELD_GET(PTE_TYPE, pte) == PTE_TABLE)
#define L3_IS_NOT_TABLE(pte) ((pte) && !L3_IS_TABLE(pte))
#define L3_IS_HW_BLOCK(pte)  (IS_HW(pte) && FIELD_GET(PTE_TYPE, pte) == PTE_PAGE)
#define L3_IS_SW_BLOCK(pte)                                                                        \
    (IS_SW(pte) && FIELD_GET(PTE_TYPE, pte) == PTE_BLOCK && FIELD_GET(SPTE_TYPE, pte) == SPTE_MAP)

uint64_t vaddr_bits;
u64 PTE_MASK = 0xfffffc000;

/*
 * We use 16KB page tables for stage 2 translation, and a 64GB (36-bit) guest
 * PA size, which results in the following virtual address space:
 *
 * [L2 index]  [L3 index] [page offset]
 *  11 bits     11 bits    14 bits
 *
 * 32MB L2 mappings look like this:
 * [L2 index]  [page offset]
 *  11 bits     25 bits
 *
 * We implement sub-page granularity mappings for software MMIO hooks, which behave
 * as an additional page table level used only by software. This works like this:
 *
 * [L2 index]  [L3 index] [L4 index]  [Word offset]
 *  11 bits     11 bits    12 bits     2 bits
 *
 * Thus, L4 sub-page tables are twice the size.
 *
 * We use invalid mappings (PTE_VALID == 0) to represent mmiotrace descriptors, but
 * otherwise the page table format is the same. The PTE_TYPE bit is weird, as 0 means
 * block but 1 means both table (at L<3) and page (at L3). For mmiotrace, this is
 * pushed to L4.
 *
 * On SoCs with more than 36-bit PA sizes there is an additional L1 translation level,
 * but no blocks or software mappings are allowed there. This level can have up to 8 bits
 * at this time.
 */

static u64 *hv_Ltop;
static u64 *backup_pt_Ltop;

void hv_pt_init(void)
{
    const uint64_t pa_bits[] = {32, 36, 40, 42, 44, 48, 52};
    uint64_t pa_range = FIELD_GET(ID_AA64MMFR0_PARange, mrs(ID_AA64MMFR0_EL1));

    vaddr_bits = min(44, pa_bits[pa_range]);

    printf("HV: Initializing for %ld-bit PA range\n", vaddr_bits);

    hv_Ltop = memalign(PAGE_SIZE, sizeof(u64) * ENTRIES_PER_L2_TABLE);
    memset(hv_Ltop, 0, sizeof(u64) * ENTRIES_PER_L2_TABLE);

    u64 sl0 = vaddr_bits > 36 ? 2 : 1;

    msr(VTCR_EL2, FIELD_PREP(VTCR_PS, pa_range) |              // Full PA size，36bit FIELD_GET(ID_AA64MMFR0_PARange, mrs(ID_AA64MMFR0_EL1))==0b001 ）
                      FIELD_PREP(VTCR_TG0, 2) |                // Granule size for the VTTBR_EL2, 16KB page size
                      FIELD_PREP(VTCR_SH0, 3) |                // Shareability attribute for memory associated with translation table walks using VTTBR_EL2 or VSTTBR_EL2. 3 for PTWs Inner Sharable
                      FIELD_PREP(VTCR_ORGN0, 1) |              // Normal memory, Outer Write-Back Read-Allocate Write-Allocate Cacheable.  PTWs Cacheable，Outer cacheability attribute for memory associated with translation table walks using VTTBR_EL2 or VSTTBR_EL2.
                      FIELD_PREP(VTCR_IRGN0, 1) |              // PTWs Cacheable，0b01 Normal memory, Inner Write-Back Read-Allocate Write-Allocate Cacheable. Inner cacheability attribute for memory associated with translation table walks using VTTBR_EL2 or VSTTBR_EL2.
                      FIELD_PREP(VTCR_SL0, sl0) |              // 1，Start level，If VTCR_EL2.TG0 is 0b10 (16KB granule) or 0b01 (64KB granule), start at level 2.
                      FIELD_PREP(VTCR_T0SZ, 64 - vaddr_bits)); // Translation region == PA

    msr(VTTBR_EL2, hv_Ltop);
}

static u64 *hv_pt_get_l2(u64 from)
{
    u64 l1idx = from >> VADDR_L1_OFFSET_BITS;

    if (vaddr_bits <= 36) {
        assert(l1idx == 0);
        return hv_Ltop;
    }

    u64 l1d = hv_Ltop[l1idx];

    if (L1_IS_TABLE(l1d))
        return (u64 *)(l1d & PTE_TARGET_MASK);

    
    u64 *l2 = (u64 *)memalign(PAGE_SIZE, ENTRIES_PER_L2_TABLE * sizeof(u64));
    memset64(l2, 0, ENTRIES_PER_L2_TABLE * sizeof(u64));

    l1d = ((u64)l2) | FIELD_PREP(PTE_TYPE, PTE_TABLE) | PTE_VALID;
    hv_Ltop[l1idx] = l1d;
    return l2;
}

static u64* backup_pt_get_page(void){
    u64 *page = (u64 *)memalign(PAGE_SIZE, PAGE_SIZE);
    memset64(page, 0, PAGE_SIZE);
    
    hv_map_hw((u64)page, (u64)page, PAGE_SIZE);
    return page;
}

// u64 hv_get_hook_correctfied_ipa(u64 addr){
//     return addr + IPA_MCAS;
// }

// u64 hv_set_hook_ipa(u64 addr){
//     return addr - IPA_MCAS;
// }

// u64 hv_get_pte_unhooked(u64 hooked_l3_pte){
//     return (hooked_l3_pte + IPA_MCAS);
// }

// u64 hv_get_pte_hooked(u64 unhooked_l3_pte){
//     return (unhooked_l3_pte - IPA_MCAS);
// }

// bool hv_is_ipa_hooked(u64 addr){
//     if ((addr>>VADDR_L1_OFFSET_BITS) == 0){
//         return addr >= 0xc00000000UL;
//     }else{
//         printf("HV hv_is_ipa_hooked: bad IPA addr: %lx\n", addr);
//         return false;
//     }
// }

static void hv_pt_free_l3(u64 *l3)
{
    if (!l3)
        return;

    for (u64 idx = 0; idx < ENTRIES_PER_L3_TABLE; idx++)
        if (IS_SW(l3[idx]) && FIELD_GET(PTE_TYPE, l3[idx]) == PTE_TABLE)
            free((void *)(l3[idx] & PTE_TARGET_MASK));
    free(l3);
}

static void hv_pt_map_l2(u64 from, u64 to, u64 size, u64 incr)
{
    assert((from & MASK(VADDR_L2_OFFSET_BITS)) == 0);
    assert(IS_SW(to) || (to & PTE_TARGET_MASK & MASK(VADDR_L2_OFFSET_BITS)) == 0);
    assert((size & MASK(VADDR_L2_OFFSET_BITS)) == 0);

    to |= FIELD_PREP(PTE_TYPE, PTE_BLOCK);

    for (; size; size -= BIT(VADDR_L2_OFFSET_BITS)) {
        u64 *l2 = hv_pt_get_l2(from);
        u64 idx = (from >> VADDR_L2_OFFSET_BITS) & MASK(VADDR_L2_INDEX_BITS);

        if (L2_IS_TABLE(l2[idx]))
            hv_pt_free_l3((u64 *)(l2[idx] & PTE_TARGET_MASK));

        l2[idx] = to;
        from += BIT(VADDR_L2_OFFSET_BITS);
        to += incr * BIT(VADDR_L2_OFFSET_BITS);
    }
}

static void myhv_pt_map_l2(u64 from, u64 to, u64 size, u64 incr)
{
    assert((from & MASK(VADDR_L2_OFFSET_BITS)) == 0);
    assert(IS_SW(to) || (to & PTE_TARGET_MASK & MASK(VADDR_L2_OFFSET_BITS)) == 0);
    assert((size & MASK(VADDR_L2_OFFSET_BITS)) == 0);

    to |= FIELD_PREP(PTE_TYPE, PTE_BLOCK);

    for (; size; size -= BIT(VADDR_L2_OFFSET_BITS)) {
        u64 *l2 = hv_pt_get_l2(from);
        u64 idx = (from >> VADDR_L2_OFFSET_BITS) & MASK(VADDR_L2_INDEX_BITS);

        if (L2_IS_TABLE(l2[idx]))
            hv_pt_free_l3((u64 *)(l2[idx] & PTE_TARGET_MASK));

        l2[idx] = to;
        printf("PTUPDATE l2 address: %p, l2[%d] address: %p, l2[%d] = %p\n", l2, idx, &l2[idx], idx, to);
        from += BIT(VADDR_L2_OFFSET_BITS);
        to += incr * BIT(VADDR_L2_OFFSET_BITS);
    }
}

static u64 *hv_pt_get_l3(u64 from)
{
    u64 *l2 = hv_pt_get_l2(from);
    u64 l2idx = (from >> VADDR_L2_OFFSET_BITS) & MASK(VADDR_L2_INDEX_BITS);
    u64 l2d = l2[l2idx];

    if (L2_IS_TABLE(l2d))
        return (u64 *)(l2d & PTE_TARGET_MASK);

    u64 *l3 = (u64 *)memalign(PAGE_SIZE, ENTRIES_PER_L3_TABLE * sizeof(u64));
    if (l2d) {
        u64 incr = 0;
        u64 l3d = l2d;
        if (IS_HW(l2d)) {
            l3d &= ~PTE_TYPE;
            l3d |= FIELD_PREP(PTE_TYPE, PTE_PAGE);
            incr = BIT(VADDR_L3_OFFSET_BITS);
        } else if (IS_SW(l2d) && FIELD_GET(SPTE_TYPE, l3d) == SPTE_MAP) {
            incr = BIT(VADDR_L3_OFFSET_BITS);
        }
        for (u64 idx = 0; idx < ENTRIES_PER_L3_TABLE; idx++, l3d += incr)
            l3[idx] = l3d;
    } else {
        memset64(l3, 0, ENTRIES_PER_L3_TABLE * sizeof(u64));
    }

    l2d = ((u64)l3) | FIELD_PREP(PTE_TYPE, PTE_TABLE) | PTE_VALID;
    l2[l2idx] = l2d;
    return l3;
}

static void hv_pt_map_l3(u64 from, u64 to, u64 size, u64 incr)
{
    assert((from & MASK(VADDR_L3_OFFSET_BITS)) == 0);
    assert(IS_SW(to) || (to & PTE_TARGET_MASK & MASK(VADDR_L3_OFFSET_BITS)) == 0);
    assert((size & MASK(VADDR_L3_OFFSET_BITS)) == 0);

    if (IS_HW(to))
        to |= FIELD_PREP(PTE_TYPE, PTE_PAGE);
    else
        to |= FIELD_PREP(PTE_TYPE, PTE_BLOCK);

    for (; size; size -= BIT(VADDR_L3_OFFSET_BITS)) {
        u64 idx = (from >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);
        u64 *l3 = hv_pt_get_l3(from);

        if (L3_IS_TABLE(l3[idx]))
            free((void *)(l3[idx] & PTE_TARGET_MASK));

        l3[idx] = to;
        from += BIT(VADDR_L3_OFFSET_BITS);
        to += incr * BIT(VADDR_L3_OFFSET_BITS);
    }
}

static void myhv_pt_map_l3(u64 from, u64 to, u64 size, u64 incr)
{
    assert((from & MASK(VADDR_L3_OFFSET_BITS)) == 0);
    assert(IS_SW(to) || (to & PTE_TARGET_MASK & MASK(VADDR_L3_OFFSET_BITS)) == 0);
    assert((size & MASK(VADDR_L3_OFFSET_BITS)) == 0);

    if (IS_HW(to))
        to |= FIELD_PREP(PTE_TYPE, PTE_PAGE);
    else
        to |= FIELD_PREP(PTE_TYPE, PTE_BLOCK);

    for (; size; size -= BIT(VADDR_L3_OFFSET_BITS)) {
        u64 idx = (from >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);
        u64 *l3 = hv_pt_get_l3(from);

        if (L3_IS_TABLE(l3[idx]))
            free((void *)(l3[idx] & PTE_TARGET_MASK));

        l3[idx] = to;
        printf("PTUPDATE l3 address: %p, l3[%lu] address: %p, l3[%lu] = %p\n", l3, idx, &l3[idx], idx, to);
        from += BIT(VADDR_L3_OFFSET_BITS);
        to += incr * BIT(VADDR_L3_OFFSET_BITS);
    }
}

static u64 *myhv_pt_get_l4(u64 from)
{
    u64 *l3 = hv_pt_get_l3(from);
    u64 l3idx = (from >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);
    u64 l3d = l3[l3idx];
    printf("VTT INFO l3: %lx, l3idx: %lx, l3[l3idx] address: %p, l3d: %lx\n", l3, l3idx, &l3[l3idx], l3d);
    if (L3_IS_TABLE(l3d)) {
        printf("L3_IS_TABLE, l3d = %lx\n", l3d);
        return (u64 *)(l3d & PTE_TARGET_MASK);
    }

    if (IS_HW(l3d)) {
        printf("l3d is hw, l3d before: %lx\n", l3d);
        assert(FIELD_GET(PTE_TYPE, l3d) == PTE_PAGE);
        l3d &= PTE_TARGET_MASK;
        l3d |= FIELD_PREP(PTE_TYPE, PTE_BLOCK) | FIELD_PREP(SPTE_TYPE, SPTE_MAP);
        printf("l3d is hw, l3d after: %lx\n", l3d);
    }

    u64 *l4 = (u64 *)memalign(PAGE_SIZE, ENTRIES_PER_L4_TABLE * sizeof(u64));
    if (l3d) {
        u64 incr = 0;
        u64 l4d = l3d;
        printf("l4d before: %lx\n", l4d);
        l4d &= ~PTE_TYPE;
        l4d |= FIELD_PREP(PTE_TYPE, PTE_PAGE);
        if (FIELD_GET(SPTE_TYPE, l4d) == SPTE_MAP)
            incr = BIT(VADDR_L4_OFFSET_BITS);
        for (u64 idx = 0; idx < ENTRIES_PER_L4_TABLE; idx++, l4d += incr)
            l4[idx] = l4d;
        printf("l4d after: %lx\n", l4d);
    } else {
        memset64(l4, 0, ENTRIES_PER_L4_TABLE * sizeof(u64));
    }
    printf("l3d before: %lx, l4: %lx\n", l3d, l4);
    l3d = ((u64)l4) | FIELD_PREP(PTE_TYPE, PTE_TABLE);
    printf("l3d after: %lx\n", l3d);
    printf("l3[l3idx] address: %p, l3[l3idx]: %lx set to l3d %lx\n", &l3[l3idx], l3[l3idx], l3d);
    l3[l3idx] = l3d;
    return l4;
}

static u64 *hv_pt_get_l4(u64 from)
{
    u64 *l3 = hv_pt_get_l3(from);
    u64 l3idx = (from >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);
    u64 l3d = l3[l3idx];

    if (L3_IS_TABLE(l3d)) {
        return (u64 *)(l3d & PTE_TARGET_MASK);
    }

    if (IS_HW(l3d)) {
        assert(FIELD_GET(PTE_TYPE, l3d) == PTE_PAGE);
        l3d &= PTE_TARGET_MASK;
        l3d |= FIELD_PREP(PTE_TYPE, PTE_BLOCK) | FIELD_PREP(SPTE_TYPE, SPTE_MAP);
    }

    u64 *l4 = (u64 *)memalign(PAGE_SIZE, ENTRIES_PER_L4_TABLE * sizeof(u64));
    if (l3d) {
        u64 incr = 0;
        u64 l4d = l3d;
        l4d &= ~PTE_TYPE;
        l4d |= FIELD_PREP(PTE_TYPE, PTE_PAGE);
        if (FIELD_GET(SPTE_TYPE, l4d) == SPTE_MAP)
            incr = BIT(VADDR_L4_OFFSET_BITS);
        for (u64 idx = 0; idx < ENTRIES_PER_L4_TABLE; idx++, l4d += incr)
            l4[idx] = l4d;
    } else {
        memset64(l4, 0, ENTRIES_PER_L4_TABLE * sizeof(u64));
    }

    l3d = ((u64)l4) | FIELD_PREP(PTE_TYPE, PTE_TABLE);
    l3[l3idx] = l3d;
    return l4;
}

static void hv_pt_map_l4(u64 from, u64 to, u64 size, u64 incr)
{
    assert((from & MASK(VADDR_L4_OFFSET_BITS)) == 0);
    assert((size & MASK(VADDR_L4_OFFSET_BITS)) == 0);

    assert(!IS_HW(to));

    if (IS_SW(to))
        to |= FIELD_PREP(PTE_TYPE, PTE_PAGE);

    for (; size; size -= BIT(VADDR_L4_OFFSET_BITS)) {
        u64 idx = (from >> VADDR_L4_OFFSET_BITS) & MASK(VADDR_L4_INDEX_BITS);
        u64 *l4 = hv_pt_get_l4(from);

        l4[idx] = to;
        from += BIT(VADDR_L4_OFFSET_BITS);
        to += incr * BIT(VADDR_L4_OFFSET_BITS);
    }
}

static void myhv_pt_map_l4(u64 from, u64 to, u64 size, u64 incr)
{
    assert((from & MASK(VADDR_L4_OFFSET_BITS)) == 0);
    assert((size & MASK(VADDR_L4_OFFSET_BITS)) == 0);

    assert(!IS_HW(to));

    if (IS_SW(to))
        to |= FIELD_PREP(PTE_TYPE, PTE_PAGE);

    for (; size; size -= BIT(VADDR_L4_OFFSET_BITS)) {
        u64 idx = (from >> VADDR_L4_OFFSET_BITS) & MASK(VADDR_L4_INDEX_BITS);
        u64 *l4 = myhv_pt_get_l4(from);
        printf("PTUPDATE l4 address: %p, l4[%d] address: %p, l4[%d] (%p) = %p\n", l4, idx, &l4[idx], idx, l4[idx], to);
        l4[idx] = to;
        // printf l4 address l4[idx] address, l4[%d] = 
        from += BIT(VADDR_L4_OFFSET_BITS);
        to += incr * BIT(VADDR_L4_OFFSET_BITS);
    }
}

int hv_map(u64 from, u64 to, u64 size, u64 incr)
{
    u64 chunk;
    bool hw = IS_HW(to);
    // printf("hv map: from %lx to %lx, size %lx, incr %lx\n",from,to,size,incr);
    if (from & MASK(VADDR_L4_OFFSET_BITS) || size & MASK(VADDR_L4_OFFSET_BITS))
        return -1;

    if (hw && (from & MASK(VADDR_L3_OFFSET_BITS) || size & MASK(VADDR_L3_OFFSET_BITS))) {
        printf("HV: cannot use L4 pages with HW mappings (0x%lx -> 0x%lx)\n", from, to);
        return -1;
    }

    // L4 mappings to boundary
    chunk = min(size, ALIGN_UP(from, BIT(VADDR_L3_OFFSET_BITS)) - from);
    if (chunk) {
        assert(!hw);
        hv_pt_map_l4(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L3 mappings to boundary
    u64 boundary = ALIGN_UP(from, MASK(VADDR_L2_OFFSET_BITS));
    // CPU CTRR doesn't like L2 mappings crossing CTRR boundaries!
    // Map everything below the m1n1 base as L3
    if (boundary >= ram_base && boundary < (u64)_base)
        boundary = ALIGN_UP((u64)_base, MASK(VADDR_L2_OFFSET_BITS));
    chunk = ALIGN_DOWN(min(size, boundary - from), BIT(VADDR_L3_OFFSET_BITS));
    if (chunk) {
        hv_pt_map_l3(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L2 mappings
    chunk = ALIGN_DOWN(size, BIT(VADDR_L2_OFFSET_BITS));
    if (chunk && (!hw || (to & VADDR_L2_ALIGN_MASK) == 0)) {
        hv_pt_map_l2(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L3 mappings to end
    chunk = ALIGN_DOWN(size, BIT(VADDR_L3_OFFSET_BITS));
    if (chunk) {
        hv_pt_map_l3(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L4 mappings to end
    if (size) {
        assert(!hw);
        hv_pt_map_l4(from, to, size, incr);
    }

    return 0;
}

int myhv_map(u64 from, u64 to, u64 size, u64 incr)
{
    u64 chunk;
    bool hw = IS_HW(to);

    if (from & MASK(VADDR_L4_OFFSET_BITS) || size & MASK(VADDR_L4_OFFSET_BITS))
        return -1;

    if (hw && (from & MASK(VADDR_L3_OFFSET_BITS) || size & MASK(VADDR_L3_OFFSET_BITS))) {
        printf("HV: cannot use L4 pages with HW mappings (0x%lx -> 0x%lx)\n", from, to);
        return -1;
    }
    u64 *l2 = hv_pt_get_l2(from);
    u64 *l3 = hv_pt_get_l3(from);
    u64 *l4 = hv_pt_get_l4(from);
    printf("VTT INFO l2: %lx, l3: %lx, l4: %lx\n", l2, l3, l4);
    // L4 mappings to boundary
    chunk = min(size, ALIGN_UP(from, BIT(VADDR_L3_OFFSET_BITS)) - from);
    printf("myhv_map chunk: %lx\n", chunk);
    if (chunk) {
        assert(!hw);
        myhv_pt_map_l4(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L3 mappings to boundary
    u64 boundary = ALIGN_UP(from, MASK(VADDR_L2_OFFSET_BITS));
    printf("myhv_map boundary: %lx\n", boundary);
    // CPU CTRR doesn't like L2 mappings crossing CTRR boundaries!
    // Map everything below the m1n1 base as L3
    if (boundary >= ram_base && boundary < (u64)_base)
        boundary = ALIGN_UP((u64)_base, MASK(VADDR_L2_OFFSET_BITS));
    chunk = ALIGN_DOWN(min(size, boundary - from), BIT(VADDR_L3_OFFSET_BITS));
    printf("myhv_map chunk: %lx\n", chunk);
    if (chunk) {
        myhv_pt_map_l3(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L2 mappings
    chunk = ALIGN_DOWN(size, BIT(VADDR_L2_OFFSET_BITS));
    printf("myhv_map chunk: %lx\n", chunk);
    if (chunk && (!hw || (to & VADDR_L2_ALIGN_MASK) == 0)) {
        myhv_pt_map_l2(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L3 mappings to end
    chunk = ALIGN_DOWN(size, BIT(VADDR_L3_OFFSET_BITS));
    printf("myhv_map chunk: %lx\n", chunk);
    if (chunk) {
        myhv_pt_map_l3(from, to, chunk, incr);
        from += chunk;
        to += incr * chunk;
        size -= chunk;
    }

    // L4 mappings to end
    if (size) {
        assert(!hw);
        printf("myhv_map invoke l4 from: %lx, to: %lx, size: %lx, incr: %lx\n", from, to, size, incr);
        myhv_pt_map_l4(from, to, size, incr);
    }

    return 0;
}

int hv_unmap(u64 from, u64 size)
{
    return hv_map(from, 0, size, 0);
}

int hv_map_hw(u64 from, u64 to, u64 size)
{
    return hv_map(from, to | PTE_ATTRIBUTES | PTE_VALID, size, 1);
}

int hv_map_sw(u64 from, u64 to, u64 size)
{
    return hv_map(from, to | FIELD_PREP(SPTE_TYPE, SPTE_MAP), size, 1);
}
u64 hook_page_cnt = 0;
u64 hook_block_cnt = 0;





int hv_stage2_direct_change_l3(u64 from, u64 to, u64 size)
{
    
    int L3offset = (from>>14)&((1<<11)-1);
    int L2offset = (from>>25)&((1<<11)-1);
    
    u64 L2PTEAddr = (u64)hv_Ltop + L2offset*8;
    u64 L2PTE = read64(L2PTEAddr);
    if (L2PTE == 0){
        printf("L2PTE Addr = 0x%lx, L2PTE = 0x%lx\n", L2PTEAddr, L2PTE);
        return -1;
    }
    
     if (!L2_IS_TABLE(L2PTE)) {
        
        printf("[!] should not be here! L2 is not table, L2PTE: 0x%lx, L2PTEAddr: 0x%lx\n", L2PTE, L2PTEAddr);
        L2PTE = (L2PTE^PTE_VALID);
        write64(L2PTEAddr,L2PTE|SPTE_TRACE_READ|SPTE_CF_IPA_HOOK);
        hook_block_cnt++;
        return 0;
    }

    L2PTEAddr = L2PTE&PTE_MASK;

    u64 L3PTE = read64(L2PTEAddr + L3offset*8);
    if ((L3PTE&SPTE_CF_IPA_HOOK) == 0)
    {
        write64(L2PTEAddr + L3offset*8, to);
        hook_page_cnt++;
    }
    return hook_page_cnt;
}

int hv_stage2_l2_expand_map_to_l3(u64 from){
    
    
    u64 L2_pte_addr = pt_walk(from, (u64)hv_Ltop, 2, 2, 1); 
    u64 L2PTE = read64(L2_pte_addr);
    if (L2_IS_TABLE(L2PTE)){
        
        
        return 0;
    }
    
    {
        u64 real_addr_aligned = (L2PTE&PTE_MASK);
        
        
        u64 *l3 = (u64 *)backup_pt_get_page();
        
        printf("L2PTE: 0x%lx, L2PTEAddr: 0x%lx, real_addr_aligned: 0x%lx, l3: 0x%lx\n", L2PTE, L2_pte_addr, real_addr_aligned, l3);
        
        u64 incr = 0;
        u64 l3d = real_addr_aligned;
        
        
        l3d |= 0x7ff; 
        incr = BIT(VADDR_L3_OFFSET_BITS);
        
        for (u64 idx = 0; idx < ENTRIES_PER_L3_TABLE; idx++, l3d += incr)
            l3[idx] = l3d;
        
        
        write64(L2_pte_addr, ((u64)l3) | PTE_TYPE | PTE_VALID);
    }
    return 0;
}

int hv_map_hook(u64 from, hv_hook_t *hook, u64 size)
{
    return hv_map(from, ((u64)hook) | FIELD_PREP(SPTE_TYPE, SPTE_HOOK), size, 0);
}

u64 hv_translate(u64 addr, bool s1, bool w, u64 *par_out)
{
    if (!(mrs(SCTLR_EL12) & SCTLR_M))
        return addr; // MMU off

    u64 el = FIELD_GET(SPSR_M, hv_get_spsr()) >> 2;
    u64 save = mrs(PAR_EL1);

    if (w) {
        if (s1) {
            if (el == 0)
                asm("at s1e0w, %0" : : "r"(addr));
            else
                asm("at s1e1w, %0" : : "r"(addr));
        } else {
            if (el == 0)
                asm("at s12e0w, %0" : : "r"(addr));
            else
                asm("at s12e1w, %0" : : "r"(addr));
        }
    } else {
        if (s1) {
            if (el == 0)
                asm("at s1e0r, %0" : : "r"(addr));
            else
                asm("at s1e1r, %0" : : "r"(addr));
        } else {
            if (el == 0)
                asm("at s12e0r, %0" : : "r"(addr));
            else
                asm("at s12e1r, %0" : : "r"(addr));
        }
    }

    u64 par = mrs(PAR_EL1);
    if (par_out)
        *par_out = par;
    msr(PAR_EL1, save);

    if (par & PAR_F) {
        // printf("hv_translate(0x%lx, %d, %d): fault 0x%lx\n", addr, s1, w, par);
        // 0b101100001101，bit[2,3,8,9,11]
        return 0; // fault
    } else {
        return (par & PAR_PA) | (addr & 0xfff);
    }
}

u64 kva_translate(u64 addr, bool s1, bool w, u64 *par_out)
{
    if (!(mrs(SCTLR_EL12) & SCTLR_M))
        return addr; // MMU off

    // u64 el = FIELD_GET(SPSR_M, hv_get_spsr()) >> 2;
    u64 el=1;
    u64 save = mrs(PAR_EL1);

    if (w) {
        if (s1) {
            if (el == 0)
                asm("at s1e0w, %0" : : "r"(addr));
            else
                asm("at s1e1w, %0" : : "r"(addr));
        } else {
            if (el == 0)
                asm("at s12e0w, %0" : : "r"(addr));
            else
                asm("at s12e1w, %0" : : "r"(addr));
        }
    } else {
        if (s1) {
            if (el == 0)
                asm("at s1e0r, %0" : : "r"(addr));
            else
                asm("at s1e1r, %0" : : "r"(addr));
        } else {
            if (el == 0)
                asm("at s12e0r, %0" : : "r"(addr));
            else
                asm("at s12e1r, %0" : : "r"(addr));
        }
    }

    u64 par = mrs(PAR_EL1);
    if (par_out)
        *par_out = par;
    msr(PAR_EL1, save);

    if (par & PAR_F) {
        printf("kva_translate(0x%lx, %d, %d): fault 0x%lx\n", addr, s1, w, par);
        return 0; // fault
    } else {
        return (par & PAR_PA) | (addr & 0xfff);
    }
}

u64 uva_translate(u64 addr, bool s1, bool w, u64 *par_out)
{
    if (!(mrs(SCTLR_EL12) & SCTLR_M))
        return addr; // MMU off

    // u64 el = FIELD_GET(SPSR_M, hv_get_spsr()) >> 2;
    u64 el=0;
    u64 save = mrs(PAR_EL1);

    if (w) {
        if (s1) {
            if (el == 0)
                asm("at s1e0w, %0" : : "r"(addr));
            else
                asm("at s1e1w, %0" : : "r"(addr));
        } else {
            if (el == 0)
                asm("at s12e0w, %0" : : "r"(addr));
            else
                asm("at s12e1w, %0" : : "r"(addr));
        }
    } else {
        if (s1) {
            if (el == 0)
                asm("at s1e0r, %0" : : "r"(addr));
            else
                asm("at s1e1r, %0" : : "r"(addr));
        } else {
            if (el == 0)
                asm("at s12e0r, %0" : : "r"(addr));
            else
                asm("at s12e1r, %0" : : "r"(addr));
        }
    }

    u64 par = mrs(PAR_EL1);
    if (par_out)
        *par_out = par;
    msr(PAR_EL1, save);

    if (par & PAR_F) {
        printf("uva_translate(0x%lx, %d, %d): fault 0x%lx\n", addr, s1, w, par);
        return 0; // fault
    } else {
        return (par & PAR_PA) | (addr & 0xfff);
    }
}

// u64 ipawalk(u64 addr)

//     printf("ipawalk(0x%lx)\n", addr);

//     u64 idx = addr >> VADDR_L1_OFFSET_BITS;
//     u64 *l2;
//     if (vaddr_bits > 36) {
//         assert(idx < ENTRIES_PER_L1_TABLE);

//         u64 l1d = hv_Ltop[idx];

//         // printf("  l1d = 0x%lx\n", l2d);

//         if (!L1_IS_TABLE(l1d)) {
//             printf("  result: 0x%lx\n", l1d);
//             return l1d;
//         }
//         l2 = (u64 *)(l1d & PTE_TARGET_MASK);
//     } else {
//         // assert(idx == 0); 
//         if(idx!=0){
//             printf("[!] input IPA!!! retry\n");
//             return 0;
//         }

//     }

//     idx = (addr >> VADDR_L2_OFFSET_BITS) & MASK(VADDR_L2_INDEX_BITS);
//     u64 l2d = l2[idx];
//     printf("  l2d = 0x%lx\n", l2d);

//     if (!L2_IS_TABLE(l2d)) {
//         if (L2_IS_SW_BLOCK(l2d))
//             l2d += addr & (VADDR_L2_ALIGN_MASK | VADDR_L3_ALIGN_MASK);
//         if (L2_IS_HW_BLOCK(l2d)) {
//             l2d &= ~PTE_LOWER_ATTRIBUTES;
//             l2d |= addr & (VADDR_L2_ALIGN_MASK | VADDR_L3_ALIGN_MASK);
//         }

//         printf("  result: 0x%lx\n", l2d);
//         return l2d;
//     }

//     idx = (addr >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);
//     u64 l3d = ((u64 *)(l2d & PTE_TARGET_MASK))[idx];
//     printf("  l3d = 0x%lx\n", l3d);

//     if (!L3_IS_TABLE(l3d)) {
//         if (L3_IS_SW_BLOCK(l3d))
//             l3d += addr & VADDR_L3_ALIGN_MASK;
//         if (L3_IS_HW_BLOCK(l3d)) {
//             l3d &= ~PTE_LOWER_ATTRIBUTES;
//             l3d |= addr & VADDR_L3_ALIGN_MASK;
//         }
//         printf("  result: 0x%lx\n", l3d);
//         return l3d;
//     }

//     idx = (addr >> VADDR_L4_OFFSET_BITS) & MASK(VADDR_L4_INDEX_BITS);
//     printf("  l4 idx = 0x%lx\n", idx);
//     u64 l4d = ((u64 *)(l3d & PTE_TARGET_MASK))[idx];
//     printf("  l4d = 0x%lx\n", l4d);
//     return l4d;
// }
extern u64 SScnt;
u64 hv_pt_walk(u64 addr) 
{
    dprintf("hv_pt_walk(0x%lx)\n", addr);

    u64 idx = addr >> VADDR_L1_OFFSET_BITS;
    u64 *l2;
    if (vaddr_bits > 36) {
        assert(idx < ENTRIES_PER_L1_TABLE);

        u64 l1d = hv_Ltop[idx];

        dprintf("  l1d = 0x%lx\n", l1d);

        if (!L1_IS_TABLE(l1d)) {
            dprintf("  result: 0x%lx\n", l1d);
            return l1d;
        }
        l2 = (u64 *)(l1d & PTE_TARGET_MASK);
    } else {
        assert(idx == 0); 
        l2 = hv_Ltop; 
    }
    idx = (addr >> VADDR_L2_OFFSET_BITS) & MASK(VADDR_L2_INDEX_BITS);
    u64 l2d = l2[idx];
    dprintf("  l2d = 0x%lx\n", l2d);

    if (!L2_IS_TABLE(l2d)) {
        if (L2_IS_SW_BLOCK(l2d))
            l2d += addr & (VADDR_L2_ALIGN_MASK | VADDR_L3_ALIGN_MASK);
        if (L2_IS_HW_BLOCK(l2d)) {
            l2d &= ~PTE_LOWER_ATTRIBUTES;
            l2d |= addr & (VADDR_L2_ALIGN_MASK | VADDR_L3_ALIGN_MASK);
        }
        dprintf("  result: 0x%lx\n", l2d);
        
        
        if ((l2d & SPTE_CF_IPA_HOOK) != 0){
            u64 far = hv_get_far();
            printf("[*] hooked block. far:%p (maybe inconsistent) , addr:%p , pte: %p\n", far, addr, l2d);
            return ((u64)&l2[idx]) | SPTE_CF_IPA_HOOK;
        }
        return l2d;
    }

    idx = (addr >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);
    u64 l3d = ((u64 *)(l2d & PTE_TARGET_MASK))[idx];
    dprintf("  l3d = 0x%lx\n", l3d);

    if (!L3_IS_TABLE(l3d)) {
        if (L3_IS_SW_BLOCK(l3d))
            l3d += addr & VADDR_L3_ALIGN_MASK;
        if (L3_IS_HW_BLOCK(l3d)) {
            l3d &= ~PTE_LOWER_ATTRIBUTES;
            l3d |= addr & VADDR_L3_ALIGN_MASK;
        }
        dprintf("  result: 0x%lx\n", l3d);
        return l3d;
    }else{
        
        
        if ((l3d & SPTE_CF_IPA_HOOK) != 0){
            // u64 far = hv_get_far();
            // if ((SScnt%100 == 0))
                // printf("[C%d] hooked page. far:%p (maybe inconsistent) , addr:%p , pte_addr: 0x%lx, pte: %p\n", mrs(TPIDR_EL2), far, addr, &l3d, l3d);
            return ((u64)&((u64 *)(l2d & PTE_TARGET_MASK))[idx]) | SPTE_CF_IPA_HOOK;
        }

        if (IS_HW(l3d)){
            return l3d;
        }
    }
    idx = (addr >> VADDR_L4_OFFSET_BITS) & MASK(VADDR_L4_INDEX_BITS);
    dprintf("  l4 idx = 0x%lx\n", idx);
    u64 l4d = ((u64 *)(l3d & PTE_TARGET_MASK))[idx];
    dprintf("  l4d = 0x%lx\n", l4d);
    return l4d;
}


u64 myhv_pt_walk(u64 addr)
{
    printf("myhv_pt_walk(0x%lx)\n", addr);

    u64 idx = addr >> VADDR_L1_OFFSET_BITS;
    u64 *l2;
    if (vaddr_bits > 36) {
        assert(idx < ENTRIES_PER_L1_TABLE);

        u64 l1d = hv_Ltop[idx];

        printf("  l1d = 0x%lx\n", l1d);

        if (!L1_IS_TABLE(l1d)) {
            printf("  result: 0x%lx\n", l1d);
            return l1d;
        }
        l2 = (u64 *)(l1d & PTE_TARGET_MASK);
    } else {
        // assert(idx == 0); 
        if (idx!=0){
            printf("[-] invalid addr\n");
            return -1;
        }
        l2 = hv_Ltop; 
    }

    idx = (addr >> VADDR_L2_OFFSET_BITS) & MASK(VADDR_L2_INDEX_BITS);
    u64 l2d = l2[idx];
    printf("  &l2d = %p, l2d = 0x%lx\n", &l2d,l2d);

    if (!L2_IS_TABLE(l2d)) {
        if (L2_IS_SW_BLOCK(l2d)){
            printf("  L2_IS_SW_BLOCK: 0x%lx\n", l2d);
            l2d += addr & (VADDR_L2_ALIGN_MASK | VADDR_L3_ALIGN_MASK);
        }
        if (L2_IS_HW_BLOCK(l2d)) {
            printf("  L2_IS_HW_BLOCK: 0x%lx\n", l2d);
            l2d &= ~PTE_LOWER_ATTRIBUTES;
            l2d |= addr & (VADDR_L2_ALIGN_MASK | VADDR_L3_ALIGN_MASK);
        }

        printf("  result: 0x%lx\n", l2d);
        return l2d;
    }

    idx = (addr >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);
    u64 l3d = ((u64 *)(l2d & PTE_TARGET_MASK))[idx];
    dprintf("  &l3d = %p, l3d = 0x%lx\n", &l3d, l3d);

    if (!L3_IS_TABLE(l3d)) {
        if (L3_IS_SW_BLOCK(l3d)){
            printf("  L3_IS_SW_BLOCK: 0x%lx\n", l3d);
            l3d += addr & VADDR_L3_ALIGN_MASK;
        }
        if (L3_IS_HW_BLOCK(l3d)) {
            printf("  L3_IS_HW_BLOCK: 0x%lx\n", l3d);
            l3d &= ~PTE_LOWER_ATTRIBUTES;
            l3d |= addr & VADDR_L3_ALIGN_MASK;
        }
        dprintf("  result: 0x%lx\n", l3d);
        return l3d;
    }

    idx = (addr >> VADDR_L4_OFFSET_BITS) & MASK(VADDR_L4_INDEX_BITS);
    dprintf("  l4 idx = 0x%lx\n", idx);
    u64 l4d = ((u64 *)(l3d & PTE_TARGET_MASK))[idx];
    dprintf("  &l4d = %p, l4d = 0x%lx\n", &l4d, l4d);
    return l4d;
}


u64 my_vtt_walk(u64 addr, bool return_phyaddr){
    int L3offset = (addr>>14)&((1<<11)-1);
    int L2offset = (addr>>25)&((1<<11)-1);
    u64 physical_offset = addr&((1<<14)-1);
    
    u64 L2PTEAddr = (u64)hv_Ltop + L2offset*8;
    u64 L2PTE = read64(L2PTEAddr);
    if (L2PTE == 0){
        printf("my_vtt_walk L2PTE Addr = 0x%lx, L2PTE = 0x%lx\n", L2PTEAddr, L2PTE);
        return -1;
    }
    
     if (!L2_IS_TABLE(L2PTE)) {
        return L2PTE;
    }

    L2PTEAddr = L2PTE&PTE_MASK;

    u64 L3PTE = read64(L2PTEAddr + L3offset*8);
    if (return_phyaddr){
        return (L3PTE&PTE_MASK) + physical_offset;
    }
    else
        return L3PTE;
}

#define CHECK_RN                                                                                   \
    if (Rn == 31)                                                                                  \
    return false
#define DECODE_OK                                                                                  \
    if (!val)                                                                                      \
    return true

#define EXT(n, b) (((s32)(((u32)(n)) << (32 - (b)))) >> (32 - (b)))

union simd_reg {
    u64 d[2];
    u32 s[4];
    u16 h[8];
    u8 b[16];
};

static bool emulate_load(struct exc_info *ctx, u32 insn, u64 *val, u64 *width, u64 *vaddr)
{
    u64 Rt = insn & 0x1f;
    u64 Rn = (insn >> 5) & 0x1f;
    u64 uimm12 = (insn >> 10) & 0xfff;
    u64 imm9 = EXT((insn >> 12) & 0x1ff, 9);
    u64 imm7 = EXT((insn >> 15) & 0x7f, 7);
    u64 *regs = ctx->regs;

    union simd_reg simd[32];

    *width = insn >> 30;

    if (val)
        dprintf("emulate_load(%p, 0x%08x, 0x%08lx, %ld\n", regs, insn, *val, *width);

    if ((insn & 0x3fe00400) == 0x38400400) {
        // LDRx (immediate) Pre/Post-index
        CHECK_RN;
        DECODE_OK;
        regs[Rn] += imm9;
        regs[Rt] = *val;
    } else if ((insn & 0x3fc00000) == 0x39400000) {
        // LDRx (immediate) Unsigned offset
        DECODE_OK;
        regs[Rt] = *val;
    } else if ((insn & 0x3fa00400) == 0x38800400) {
        // LDRSx (immediate) Pre/Post-index
        CHECK_RN;
        DECODE_OK;
        regs[Rn] += imm9;
        regs[Rt] = (s64)EXT(*val, 8 << *width);
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0x3fa00000) == 0x39800000) {
        // LDRSx (immediate) Unsigned offset
        DECODE_OK;
        regs[Rt] = (s64)EXT(*val, 8 << *width);
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0x3fe04c00) == 0x38604800) {
        // LDRx (register)
        DECODE_OK;
        regs[Rt] = *val;
    // } else if ((insn & 0x885f7c00) == 0x885f7c00){
    
    //     //    1238: c85f7c00      ldxr    x0, [x0]
    //     //    123c: 885f7c00      ldxr    w0, [x0]
    //     DECODE_OK;
    //     // 
    //     if (0xc0000000&insn == 0xc0000000){
    
    //         regs[Rt] = *val;
    //     }else{
    
    //         regs[Rt] =(u32) ((u32)(*val)&0xffffffff);
    //     }
    } else if ((insn & 0x3fa04c00) == 0x38a04800) {
        // LDRSx (register)
        DECODE_OK;
        regs[Rt] = (s64)EXT(*val, 8 << *width);
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0x3fe00c00) == 0x38400000) {
        // LDURx (unscaled)
        DECODE_OK;
        regs[Rt] = *val;
    } else if ((insn & 0x3fa00c00) == 0x38a00000) {
        // LDURSx (unscaled)
        DECODE_OK;
        regs[Rt] = (s64)EXT(*val, (8 << *width));
        if (insn & (1 << 22))
            regs[Rt] &= 0xffffffff;
    } else if ((insn & 0xfec00000) == 0x28400000) {
        // LD[N]P (Signed offset, 32-bit)
        *width = 3;
        *vaddr = regs[Rn] + (imm7 * 4);
        DECODE_OK;
        u64 Rt2 = (insn >> 10) & 0x1f;
        regs[Rt] = val[0] & 0xffffffff;
        regs[Rt2] = val[0] >> 32;
    } else if ((insn & 0xfec00000) == 0xa8400000) {
        // LD[N]P (Signed offset, 64-bit)
        *width = 4;
        *vaddr = regs[Rn] + (imm7 * 8);
        DECODE_OK;
        u64 Rt2 = (insn >> 10) & 0x1f;
        regs[Rt] = val[0];
        regs[Rt2] = val[1];
    } else if ((insn & 0xfec00000) == 0xa8c00000) {
        // LDP (pre/post-increment, 64-bit)
        *width = 4;
        *vaddr = regs[Rn] + ((insn & BIT(24)) ? (imm7 * 8) : 0);
        DECODE_OK;
        regs[Rn] += imm7 * 8;
        u64 Rt2 = (insn >> 10) & 0x1f;
        regs[Rt] = val[0];
        regs[Rt2] = val[1];
    // } else if ((insn & 0xb8200000) == 0xb8200000) {
    //     // LDADD           X8, X8, [X0] -> 0xf8280008
    
    //     // 1240: b83e03de      ldadd   w30, w30, [x30]
    //     // 1244: f8210000      ldadd   x1, x0, [x0]
    //     // 1248: f8200021      ldadd   x0, x1, [x1]
    //     // 124c: b8210021      ldadd   w1, w1, [x1]
        
    //     // *vaddr = regs[Rn];
    //     DECODE_OK;
    //     u64 Xt = (insn >> 16) & 0x1f;
    //     u64 Xt2 = insn & 0x1f;
    //     u64 add_addr = hv_translate(regs[Rn], true, false, 0);
    //     if (hv_is_ipa_hooked(add_addr)){
    //         add_addr = hv_get_hook_correctfied_ipa(add_addr);
    //     }
    
    //         write64(add_addr, val[0] + regs[Xt]);
    //         regs[Xt2] = val[0];
    //         *width = 4;
    //     }else{
    
    //         write32(add_addr, (u32)(val[0] + regs[Xt]));
    //         regs[Xt2] = (u32)val[0]&0xffffffff;
    //         *width = 3;
    //     }
        
    // } else if ((insn & 0x38200000) == 0x38200000){
    //     // 38200000      ldaddb  w0, w0, [x0]
    //     // *vaddr = regs[Rn];
    //     DECODE_OK;
    //     u64 Xt = (insn >> 16) & 0x1f;
    //     u64 Xt2 = insn & 0x1f;
    //     u64 add_addr = hv_translate(regs[Rn], true, false, 0);
    //     if (hv_is_ipa_hooked(add_addr)){
    //         add_addr = hv_get_hook_correctfied_ipa(add_addr);
    //     }
    //     write8(add_addr, val[0] + regs[Xt]);
    //     regs[Xt2] =(u8) val[0];
    //     *width = 1;
    } else if ((insn & 0xfec00000) == 0xac400000) {
        // LD[N]P (SIMD&FP, 128-bit) Signed offset
        *width = 5;
        *vaddr = regs[Rn] + (imm7 * 16);
        DECODE_OK;
        u64 Rt2 = (insn >> 10) & 0x1f;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = val[1];
        simd[Rt2].d[0] = val[2];
        simd[Rt2].d[1] = val[3];
        put_simd_state(simd);
    } else if ((insn & 0x3fc00000) == 0x3d400000) {
        // LDR (immediate, SIMD&FP) Unsigned offset
        *vaddr = regs[Rn] + (uimm12 << *width);
        DECODE_OK;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = 0;
        put_simd_state(simd);
    } else if ((insn & 0x3fe00c00) == 0x3c400000) {
        // LDURx (unscaled, SIMD&FP)
        *vaddr = regs[Rn] + imm9;
        DECODE_OK;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = val[1];
        put_simd_state(simd);
    } else if ((insn & 0xffc00000) == 0x3dc00000) {
        // LDR (immediate, SIMD&FP) Unsigned offset, 128-bit
        *width = 4;
        *vaddr = regs[Rn] + (uimm12 << *width);
        DECODE_OK;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = val[1];
        put_simd_state(simd);
    } else if ((insn & 0xffe00c00) == 0x3cc00000) {
        // LDURx (unscaled, SIMD&FP, 128-bit)
        *width = 4;
        *vaddr = regs[Rn] + imm9;
        DECODE_OK;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = val[1];
        put_simd_state(simd);
    } else if ((insn & 0x3fe00400) == 0x3c400400) {
        // LDR (immediate, SIMD&FP) Pre/Post-index
        CHECK_RN;
        DECODE_OK;
        regs[Rn] += imm9;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = 0;
        put_simd_state(simd);
    } else if ((insn & 0xffe00400) == 0x3cc00400) {
        // LDR (immediate, SIMD&FP) Pre/Post-index, 128-bit
        *width = 4;
        CHECK_RN;
        DECODE_OK;
        regs[Rn] += imm9;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = val[1];
        put_simd_state(simd);
    } else if ((insn & 0x3fe04c00) == 0x3c604800) {
        // LDR (register, SIMD&FP)
        DECODE_OK;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = 0;
        put_simd_state(simd);
    } else if ((insn & 0xffe04c00) == 0x3ce04800) {
        // LDR (register, SIMD&FP), 128-bit
        *width = 4;
        DECODE_OK;
        get_simd_state(simd);
        simd[Rt].d[0] = val[0];
        simd[Rt].d[1] = val[1];
        put_simd_state(simd);
    } else if ((insn & 0xbffffc00) == 0x0d408400) {
        // LD1 (single structure) No offset, 64-bit
        *width = 3;
        DECODE_OK;
        u64 index = (insn >> 30) & 1;
        get_simd_state(simd);
        simd[Rt].d[index] = val[0];
        put_simd_state(simd);
    } else if ((insn & 0x3ffffc00) == 0x08dffc00) {
        // LDAR*
        DECODE_OK;
        regs[Rt] = *val;
    // } else if ((insn & 0x88e07c00 == 0x88e07c00) || (insn & 0x88a0fc00 == 0x88a0fc00)){
    //     // 1238: c8e07c00      casa    x0, x0, [x0]
    //     // 123c: 88e07c00      casa    w0, w0, [x0]
    //     // 1240: c8e17c41      casa    x1, x1, [x2]
    
    //     // 1248: c8a0fc00      casl    x0, x0, [x0]
    //     // 124c: 88a0fc00      casl    w0, w0, [x0]
    
    //     CHECK_RN;
    //     // *vaddr = regs[Rn];
    //     Rt = (insn >> 16) & 0x1f;
    //     u64 Rt2 = 0x1f;
    //     u64 val_addr = hv_translate(regs[Rn], true, false, 0);
    //     if (hv_is_ipa_hooked(val_addr)){
    //         val_addr = hv_get_hook_correctfied_ipa(val_addr);
    //     }
    //     if ((insn & 0xc0000000) == 0xc0000000)
    //     {
    
    //         u64 Xs = regs[Rt];
    //         u64 val = read64(val_addr);
    //         if (Xs == val){
    //             write64(val_addr, regs[Rt2]);
    //         }
    //         regs[Rt] = val;
    //     }else{
    
    //         u32 Ws = regs[Rt];
    //         u32 val = read32(val_addr);
    //         if (Ws == val){
    //             write32(val_addr, (u32)regs[Rt2]);
    //         }
    //         regs[Rt] = (u32)(val);
    //     }
    

    // } else if (insn & 0x08207c00 == 0x08207c00){
    
    //     //   483e7c00      casp    x30, xzr, x0, x1, [x0]
    //     //   083e7c00      casp    w30, wzr, w0, w1, [x0]
    //     CHECK_RN;
    //     // *vaddr = regs[Rn];
    //     u64 val_addr = hv_translate(regs[Rn], true, false, 0);
    //     u64 val_addr2 = hv_translate(regs[Rn]+8, true, false, 0);
    //     Rt = (insn >> 16) & 0x1f;
    //     u64 Rt2 = 0x1f;
    //     if (hv_is_ipa_hooked(val_addr)){
    //         val_addr = hv_get_hook_correctfied_ipa(val_addr);
    //     }
    //     if (hv_is_ipa_hooked(val_addr2)){
    //         val_addr2 = hv_get_hook_correctfied_ipa(val_addr2);
    //     }
    //     if ((insn & 0x40000000) == 0x40000000)
    //     {
    
    //         u64 Xs = regs[Rt];
    //         u64 Xs1 = regs[Rt+1];
    //         u64 val = read64(val_addr);
    //         u64 val1 = read64(val_addr2);
    //         if (Xs == val && Xs1 == val1){
    //             write64(val_addr, regs[Rt2]);
    //             write64(val_addr2, regs[Rt2+1]);
    //         }
    //         regs[Rt] = val;
    //         regs[Rt+1] = val1;
    //         *width = 8;
    //     }else{
    
    //         u32 Ws = regs[Rt];
    //         u32 Ws1 = regs[Rt+1];
    //         u32 val = read32(val_addr);
    //         u32 val1 = read32(val_addr2);
    //         if (Ws == val && Ws1 == val1){
    //             write32(val_addr, (u32)regs[Rt2]);
    //             write32(val_addr2, (u32)regs[Rt2+1]);
    //         }
    //         regs[Rt] = (u32) (val);
    //         regs[Rt+1] =(u32) (val1);
    //         *width = 4;
    //     }
    } else {
        return false;
    }
    return true;
}

static bool emulate_store(struct exc_info *ctx, u32 insn, u64 *val, u64 *width, u64 *vaddr)
{
    u64 Rt = insn & 0x1f;
    u64 Rn = (insn >> 5) & 0x1f;
    u64 imm9 = EXT((insn >> 12) & 0x1ff, 9);
    u64 imm7 = EXT((insn >> 15) & 0x7f, 7);
    u64 *regs = ctx->regs;

    union simd_reg simd[32];

    *width = insn >> 30;

    dprintf("emulate_store(%p, 0x%08x, ..., %ld) = ", regs, insn, *width);

    regs[31] = 0;

    u64 mask = 0xffffffffffffffffUL;

    if (*width < 3)
        mask = (1UL << (8 << *width)) - 1;

    if ((insn & 0x3fe00400) == 0x38000400) {
        // STRx (immediate) Pre/Post-index
        CHECK_RN;
        regs[Rn] += imm9;
        *val = regs[Rt] & mask;
    } else if ((insn & 0x3fc00000) == 0x39000000) {
        // STRx (immediate) Unsigned offset
        *val = regs[Rt] & mask;
    } else if ((insn & 0x3fe04c00) == 0x38204800) {
        // STRx (register)
        *val = regs[Rt] & mask;
    } else if ((insn & 0xfec00000) == 0x28000000) {
        // ST[N]P (Signed offset, 32-bit)
        *vaddr = regs[Rn] + (imm7 * 4);
        u64 Rt2 = (insn >> 10) & 0x1f;
        val[0] = (regs[Rt] & 0xffffffff) | (regs[Rt2] << 32);
        *width = 3;
    // } else if ((insn & 0xfec00000) == 0x28800000) {
    // //stp     w8, w19, [x0], #16   -> Rn == x0, Rt == w8, Rt2 == w19, imm7 == 16
    //     // ST[N]P (immediate, 32-bit, pre/post-index)
    //     CHECK_RN;
    //     *vaddr = regs[Rn] + ((insn & BIT(24)) ? (imm7 * 4) : 0);
    //     regs[Rn] += (imm7 * 4);       
    
    //     val[0] = (regs[Rt] & 0xffffffff) | (regs[Rt2] << 32);
    //     *width = 3;
    } else if ((insn & 0xfec00000) == 0xa8000000) {
        // ST[N]P (Signed offset, 64-bit)
        *vaddr = regs[Rn] + (imm7 * 8);
        u64 Rt2 = (insn >> 10) & 0x1f;
        val[0] = regs[Rt];
        val[1] = regs[Rt2];
        *width = 4;
    } else if ((insn & 0xfec00000) == 0xa8800000) {
        // ST[N]P (immediate, 64-bit, pre/post-index)
        CHECK_RN;
        *vaddr = regs[Rn] + ((insn & BIT(24)) ? (imm7 * 8) : 0);
        regs[Rn] += (imm7 * 8);
        u64 Rt2 = (insn >> 10) & 0x1f;
        val[0] = regs[Rt];
        val[1] = regs[Rt2];
        *width = 4;
    } else if ((insn & 0x3fc00000) == 0x3d000000) {
        // STR (immediate, SIMD&FP) Unsigned offset, 8..64-bit
        get_simd_state(simd);
        *val = simd[Rt].d[0];
    } else if ((insn & 0x3fe04c00) == 0x3c204800) {
        // STR (register, SIMD&FP) 8..64-bit
        get_simd_state(simd);
        *val = simd[Rt].d[0];
    } else if ((insn & 0xffe04c00) == 0x3ca04800) {
        // STR (register, SIMD&FP) 128-bit
        get_simd_state(simd);
        val[0] = simd[Rt].d[0];
        val[1] = simd[Rt].d[1];
        *width = 4;
    } else if ((insn & 0xffc00000) == 0x3d800000) {
        // STR (immediate, SIMD&FP) Unsigned offset, 128-bit
        get_simd_state(simd);
        val[0] = simd[Rt].d[0];
        val[1] = simd[Rt].d[1];
        *width = 4;
    } else if ((insn & 0xffe00000) == 0xbc000000) {
        // STUR (immediate, SIMD&FP) 32-bit
        get_simd_state(simd);
        val[0] = simd[Rt].s[0];
        *width = 2;
    } else if ((insn & 0xffe00000) == 0xfc000000) {
        // STUR (immediate, SIMD&FP) 64-bit
        get_simd_state(simd);
        val[0] = simd[Rt].d[0];
        *width = 3;
    } else if ((insn & 0xffe00000) == 0x3c800000) {
        // STUR (immediate, SIMD&FP) 128-bit
        get_simd_state(simd);
        val[0] = simd[Rt].d[0];
        val[1] = simd[Rt].d[1];
        *width = 4;
    } else if ((insn & 0xffc00000) == 0x2d000000) {
        // STP (SIMD&FP, 128-bit) Signed offset
        *vaddr = regs[Rn] + (imm7 * 4);
        u64 Rt2 = (insn >> 10) & 0x1f;
        get_simd_state(simd);
        val[0] = simd[Rt].s[0] | (((u64)simd[Rt2].s[0]) << 32);
        *width = 3;
    } else if (((insn & 0xffc00000) == 0xad000000) || ((insn & 0xffc00000) == 0xac000000)) {
        // STP (SIMD&FP, 128-bit) Signed offset
        // stp	q0, q1, [x0] --> 0xad000400，
        
        *vaddr = regs[Rn] + (imm7 * 16);
        u64 Rt2 = (insn >> 10) & 0x1f;
        get_simd_state(simd);
        val[0] = simd[Rt].d[0];
        val[1] = simd[Rt].d[1];
        val[2] = simd[Rt2].d[0];
        val[3] = simd[Rt2].d[1];
        *width = 5;
    } else if ((insn & 0x3fe00c00) == 0x38000000) {
        // STURx (unscaled)
        *val = regs[Rt] & mask;
    } else if ((insn & 0xffffffe0) == 0xd50b7420) {
        // DC ZVA
        *vaddr = regs[Rt];
        memset(val, 0, CACHE_LINE_SIZE);
        *width = CACHE_LINE_LOG2;
    } else if ((insn & 0x3ffffc00) == 0x089ffc00) {
        // STL  qR*
        *val = regs[Rt] & mask;
    } else {
        return false;
    }

    dprintf("0x%lx\n", *width);

    return true;
}

static void emit_mmiotrace(u64 pc, u64 addr, u64 *data, u64 width, u64 flags, bool sync)
{
    struct hv_evt_mmiotrace evt = {
        .flags = flags | FIELD_PREP(MMIO_EVT_CPU, smp_id()),
        .pc = pc,
        .addr = addr,
    };

    if (width > 3)
        evt.flags |= FIELD_PREP(MMIO_EVT_WIDTH, 3) | MMIO_EVT_MULTI;
    else
        evt.flags |= FIELD_PREP(MMIO_EVT_WIDTH, width);

    for (int i = 0; i < (1 << width); i += 8) {
        evt.data = *data++;
        hv_wdt_suspend();
        uartproxy_send_event(EVT_MMIOTRACE, &evt, sizeof(evt));
        if (sync) {
            iodev_flush(uartproxy_iodev);
        }
        hv_wdt_resume();
        evt.addr += 8;
    }
}

bool hv_pa_write(struct exc_info *ctx, u64 addr, u64 *val, int width)
{
    sysop("dsb sy");
    exc_count = 0;
    exc_guard = GUARD_SKIP;
    switch (width) {
        case 0:
            write8(addr, val[0]);
            break;
        case 1:
            write16(addr, val[0]);
            break;
        case 2:
            write32(addr, val[0]);
            break;
        case 3:
            write64(addr, val[0]);
            break;
        case 4:
        case 5:
        case 6:
            for (u64 i = 0; i < (1UL << (width - 3)); i++)
                write64(addr + 8 * i, val[i]);
            break;
        default:
            dprintf("HV: unsupported write width %d\n", width);
            exc_guard = GUARD_OFF;
            return false;
    }
    // Make sure we catch SErrors here
    sysop("dsb sy");
    sysop("isb");
    exc_guard = GUARD_OFF;
    if (exc_count) {
        printf("HV: Exception during write to 0x%lx (width: %d)\n", addr, width);
        // Update exception info with "real" cause
        ctx->esr = hv_get_esr();
        ctx->far = hv_get_far();
        return false;
    }
    return true;
}

bool hv_pa_read(struct exc_info *ctx, u64 addr, u64 *val, int width)
{
    sysop("dsb sy");
    exc_count = 0;
    exc_guard = GUARD_SKIP;
    switch (width) {
        case 0:
            val[0] = read8(addr);
            break;
        case 1:
            val[0] = read16(addr);
            break;
        case 2:
            val[0] = read32(addr);
            break;
        case 3:
            val[0] = read64(addr);
            break;
        case 4:
            val[0] = read64(addr);
            val[1] = read64(addr + 8);
            break;
        case 5:
            val[0] = read64(addr);
            val[1] = read64(addr + 8);
            val[2] = read64(addr + 16);
            val[3] = read64(addr + 24);
            break;
        default:
            dprintf("HV: unsupported read width %d\n", width);
            exc_guard = GUARD_OFF;
            return false;
    }
    sysop("dsb sy");
    exc_guard = GUARD_OFF;
    if (exc_count) {
        dprintf("HV: Exception during read from 0x%lx (width: %d)\n", addr, width);
        // Update exception info with "real" cause
        ctx->esr = hv_get_esr();
        ctx->far = hv_get_far();
        return false;
    }
    return true;
}

bool hv_pa_rw(struct exc_info *ctx, u64 addr, u64 *val, bool write, int width)
{
    if (write)
        return hv_pa_write(ctx, addr, val, width);
    else
        return hv_pa_read(ctx, addr, val, width);
}

static bool hv_emulate_rw_aligned(struct exc_info *ctx, u64 pte, u64 vaddr, u64 ipa, u64 *val,
                                  bool is_write, u64 width, u64 elr, u64 par)
{
    assert(pte);
    assert(((ipa & 0x3fff) + (1 << width)) <= 0x4000);

    u64 target = pte & PTE_TARGET_MASK_L4;
    u64 paddr = target | (vaddr & MASK(VADDR_L4_OFFSET_BITS));
    u64 flags = FIELD_PREP(MMIO_EVT_ATTR, FIELD_GET(PAR_ATTR, par)) |
                FIELD_PREP(MMIO_EVT_SH, FIELD_GET(PAR_SH, par));

    // For split ops, treat hardware mapped pages as SPTE_MAP
    if (IS_HW(pte))
        pte = target | FIELD_PREP(PTE_TYPE, PTE_BLOCK) | FIELD_PREP(SPTE_TYPE, SPTE_MAP);

    if (is_write) {
        // Write
        hv_wdt_breadcrumb('3');

        if (pte & SPTE_TRACE_WRITE)
            emit_mmiotrace(elr, ipa, val, width, flags | MMIO_EVT_WRITE, pte & SPTE_TRACE_UNBUF);

        hv_wdt_breadcrumb('4');

        switch (FIELD_GET(SPTE_TYPE, pte)) {
            case SPTE_PROXY_HOOK_R:
                paddr = ipa;
                // fallthrough
            case SPTE_MAP:
                hv_wdt_breadcrumb('5');
                dprintf("HV: SPTE_MAP[W] @0x%lx 0x%lx -> 0x%lx (w=%d): 0x%lx\n", elr, ipa, paddr,
                        1 << width, val[0]);
                if (!hv_pa_write(ctx, paddr, val, width))
                    return false;
                break;
            case SPTE_HOOK: {
                hv_wdt_breadcrumb('6');
                hv_hook_t *hook = (hv_hook_t *)target;
                if (!hook(ctx, ipa, val, true, width))
                    return false;
                dprintf("HV: SPTE_HOOK[W] @0x%lx 0x%lx -> 0x%lx (w=%d) @%p: 0x%lx\n", elr, ipa,
                        paddr, 1 << width, hook, val);
                break;
            }
            case SPTE_PROXY_HOOK_RW:
            case SPTE_PROXY_HOOK_W: {
                hv_wdt_breadcrumb('7');
                struct hv_vm_proxy_hook_data hook = {
                    .flags = FIELD_PREP(MMIO_EVT_WIDTH, width) | MMIO_EVT_WRITE | flags,
                    .id = FIELD_GET(PTE_TARGET_MASK_L4, pte), 
                    .addr = ipa,
                    .data = {0},
                };
                memcpy(hook.data, val, 1 << width);
                hv_exc_proxy(ctx, START_HV, HV_HOOK_VM, &hook);
                break;
            }
            default:
                printf("HV: invalid SPTE 0x%016lx for IPA 0x%lx\n", pte, ipa);
                return false;
        }
    } else {
        hv_wdt_breadcrumb('3');
        switch (FIELD_GET(SPTE_TYPE, pte)) {
            case SPTE_PROXY_HOOK_W:
                paddr = ipa;
                // fallthrough
            case SPTE_MAP:
                hv_wdt_breadcrumb('4');
                if (!hv_pa_read(ctx, paddr, val, width))
                    return false;
                dprintf("HV: SPTE_MAP[R] @0x%lx 0x%lx -> 0x%lx (w=%d): 0x%lx\n", elr, ipa, paddr,
                        1 << width, val[0]);
                break;
            case SPTE_HOOK: {
                hv_wdt_breadcrumb('5');
                hv_hook_t *hook = (hv_hook_t *)target;
                if (!hook(ctx, ipa, val, false, width))
                    return false;
                dprintf("HV: SPTE_HOOK[R] @0x%lx 0x%lx -> 0x%lx (w=%d) @%p: 0x%lx\n", elr, ipa,
                        paddr, 1 << width, hook, val);
                break;
            }
            case SPTE_PROXY_HOOK_RW:
            case SPTE_PROXY_HOOK_R: {
                hv_wdt_breadcrumb('6');
                struct hv_vm_proxy_hook_data hook = {
                    .flags = FIELD_PREP(MMIO_EVT_WIDTH, width) | flags,
                    .id = FIELD_GET(PTE_TARGET_MASK_L4, pte),
                    .addr = ipa,
                };
                hv_exc_proxy(ctx, START_HV, HV_HOOK_VM, &hook);
                memcpy(val, hook.data, 1 << width);
                break;
            }
            default:
                printf("HV: invalid SPTE 0x%016lx for IPA 0x%lx\n", pte, ipa);
                return false;
        }

        hv_wdt_breadcrumb('7');
        if (pte & SPTE_TRACE_READ)
            emit_mmiotrace(elr, ipa, val, width, flags, pte & SPTE_TRACE_UNBUF);
    }

    hv_wdt_breadcrumb('*');

    return true;
}

static bool hv_emulate_rw(struct exc_info *ctx, u64 pte, u64 vaddr, u64 ipa, u8 *val, bool is_write,
                          u64 bytes, u64 elr, u64 par)
{
    u64 aval[HV_MAX_RW_WORDS];

    bool advance = (IS_HW(pte) || (IS_SW(pte) && FIELD_GET(SPTE_TYPE, pte) == SPTE_MAP)) ? 1 : 0;
    u64 off = 0;
    u64 width;

    bool first = true;

    u64 left = bytes;
    u64 paddr = (pte & PTE_TARGET_MASK_L4) | (vaddr & MASK(VADDR_L4_OFFSET_BITS));

    while (left > 0) {
        memset(aval, 0, sizeof(aval));

        if (left >= 64 && (ipa & 63) == 0)
            width = 6;
        else if (left >= 32 && (ipa & 31) == 0)
            width = 5;
        else if (left >= 16 && (ipa & 15) == 0)
            width = 4;
        else if (left >= 8 && (ipa & 7) == 0)
            width = 3;
        else if (left >= 4 && (ipa & 3) == 0)
            width = 2;
        else if (left >= 2 && (ipa & 1) == 0)
            width = 1;
        else
            width = 0;

        u64 chunk = 1 << width;

        /*
        if (chunk != bytes)
            printf("HV: Splitting unaligned %ld-byte %s: %ld bytes @ 0x%lx\n", bytes,
                is_write ? "write" : "read", chunk, vaddr);
        */

        if (is_write)
            memcpy(aval, val + off, chunk);

        if (advance)
            pte = (paddr & PTE_TARGET_MASK_L4) | (pte & ~PTE_TARGET_MASK_L4);

        if (!hv_emulate_rw_aligned(ctx, pte, vaddr, ipa, aval, is_write, width, elr, par)) {
            if (!first)
                printf("HV: WARNING: Failed to emulate split op but part of it did commit!\n");
            return false;
        }

        if (!is_write)
            memcpy(val + off, aval, chunk);

        left -= chunk;
        off += chunk;

        ipa += chunk;
        vaddr += chunk;
        if (advance)
            paddr += chunk;

        first = 0;
    }

    return true;
}
u64 hook_cnt = 0;
void stage2_hook_tlb_flush(u64 far, u64 ipa, u64 pte_addr){
    __asm__ volatile(
                "ldr x4, %[far]\n //\
                tlbi vae1is, x4\n" // vae1, ipas2e1
                "tlbi vae2is, x4\n" 
                "tlbi vale1is, x4\n" 
                "tlbi vale2is, x4\n"
                "tlbi vaale1is, x4\n"
                "tlbi vaae1is, x4\n"

                "ldr x5, %[ipa]\n"
                "tlbi IPAS2E1, x5\n"
                "tlbi IPAS2E1IS, x5\n"
                "tlbi IPAS2LE1IS, x5\n"
                "dc\t cvau, x5\n"

                "ldr x6, %[pte_addr]\n"
                "tlbi IPAS2E1, x6\n"
                "tlbi IPAS2E1IS, x6\n"
                "tlbi IPAS2LE1IS, x6\n"

                "DSB ISH\n" 
                "ISB\n"
            :  // output %0
            : [far] "m" (far), [ipa] "m" (ipa), [pte_addr] "m" (pte_addr)// input %1
            : "x4", "x5", "x6");
}
bool hv_handle_dabort(struct exc_info *ctx)
{
    hv_wdt_breadcrumb('0');
    u64 esr = hv_get_esr();
    bool is_write = esr & ESR_ISS_DABORT_WnR;

    u64 far = hv_get_far();
    u64 par;
    
    u64 ipa = hv_translate(far, true, is_write, &par);
    u64 hpfar = hv_get_hpfar(); 
    // bool CF_hooked_addr = false;
    // CF_hooked_addr = hv_is_ipa_hooked(ipa);
    
    if (!ipa)
    {
        
        int from_el = FIELD_GET(SPSR_M, ctx->spsr) >> 2;
        
        //     ttbr = mrs(TTBR0_EL12);
        u64 ttbr = GET_TTBR_FROM_FAR(far);
        printf("far: 0x%0lx, ttbr: 0x%0lx, ipa: 0x%lx, from_el: %d\n", far, ttbr, ipa, from_el);
        ipa = pt_walk(far, ttbr, 3, 1, false);
    }

    dprintf("hv_handle_abort(): stage 1 0x%0lx -> 0x%lx\n", far, ipa);

    if (!ipa || ipa == -1) {
        printf("HV: stage 1 translation failed at VA far: 0x%0lx, hpfar: 0x%0lx\n", far, hpfar);
        return false;
    }

    if (ipa >= BIT(vaddr_bits)) {
        printf("hv_handle_abort(): IPA out of bounds: 0x%0lx -> 0x%lx\n", far, ipa);
        return false;
    }

    u64 pte = hv_pt_walk(ipa);
    

    if (!pte) {
        printf("HV: Unmapped IPA 0x%lx\n", ipa);
        return false;
    }
    if (FIELD_HAS(pte, SPTE_CF_IPA_HOOK) || IS_HW(pte)){
        
        u64 pte_addr = FIELD_HAS(pte, SPTE_CF_IPA_HOOK) ? (u64)(pte^SPTE_CF_IPA_HOOK) : (u64)pte;
        if (IS_HW(pte))
            pte_addr = pt_walk(far, GET_TTBR_FROM_FAR(far), 3, 1, true);
        
        u64 origin_pte = 0;
        origin_pte = *(u64*)pte_addr;
        // printf("pte_addr: 0x%lx, pte: 0x%lx, origin_pte: 0x%lx\n", pte_addr, pte, origin_pte);
        u64 changed_pte = origin_pte;
        if (FIELD_HAS(pte, SPTE_CF_IPA_HOOK)){
            changed_pte = (origin_pte&PTE_MASK)|0x7ff; 
            write64(pte_addr, changed_pte);
        }
        ssdbg_printf("[C%d] HW:%d, pte_addr: 0x%lx, origin_pte: 0x%lx, changed_pte: 0x%lx, elr: 0x%lx, far: 0x%lx\n", ctx->cpu_id, IS_HW(pte), pte_addr, origin_pte, changed_pte, ctx->elr, far);
        stage2_hook_tlb_flush(far, ipa, pte_addr);
        
        turnOnSSServer();
        turnOnSS(ctx->cpu_id, SPTE);
        hv_translate(far, 0, 0, 0);
        hv_translate(far, 1, 0, 0);

        /* 
        ctx->elr-=4;
        return true;
        */
        return false;
        
    }

    if (IS_HW(pte)) { 
        
        // if (CF_hooked_addr){
        //     pte |= (SPTE_TRACE_WRITE|SPTE_TRACE_READ);
        
        // }else{

        printf("HV: Data abort on mapped page ipa: 0x%lx , (0x%lx -> 0x%lx)\n", ipa, far, pte);
        // Try again, this is usually a race
        ctx->elr -= 4;
        
        return true;
        // }
        
    }
    else{
        assert(IS_SW(pte));
    }

    // if ( (pte & SPTE_CF_IPA_HOOK) != 0){
    //     printf("[*] HV: Data abort on IPA HOOK (far: 0x%lx -> pte: 0x%lx)\n", far, pte);
    //     // pte = my_vtt_walk(ipa);
    //     // u64 new_ipa = my_vtt_walk(ipa, true);
    //     // printf("[*] ipa: 0x%lx -> new_ipa: 0x%lx\n", ipa, new_ipa);
    //     // ipa = new_ipa;
    // }
    hv_wdt_breadcrumb('1');

    u64 elr = ctx->elr;
    u64 elr_pa = hv_translate(elr, false, false, NULL);
    if (!elr_pa) {
        printf("HV: Failed to fetch instruction for data abort at 0x%lx\n", elr);
        return false;
    }

    u32 insn = read32(elr_pa);
    u64 width;

    hv_wdt_breadcrumb('2');

    u64 vaddr = far;

    u8 val[HV_MAX_RW_SIZE] ALIGNED(HV_MAX_RW_SIZE);
    memset(val, 0, sizeof(val));

    if (is_write) {
        hv_wdt_breadcrumb('W');

        if (!emulate_store(ctx, insn, (u64 *)val, &width, &vaddr)) {
            printf("HV: store not emulated: 0x%08x at 0x%lx\n", insn, ipa);
            return false;
        }
    } else {
        hv_wdt_breadcrumb('R');

        if (!emulate_load(ctx, insn, NULL, &width, &vaddr)) {
            printf("HV: load not emulated: 0x%08x at 0x%lx\n", insn, ipa);
            return false;
        }
    }

    /*
     Check for HW page-straddling conditions
     Right now we only support the case where the page boundary is exactly halfway
     through the read/write.
    */
    u64 bytes = 1 << width;
    u64 vaddrp0 = vaddr & ~MASK(VADDR_L3_OFFSET_BITS);
    u64 vaddrp1 = (vaddr + bytes - 1) & ~MASK(VADDR_L3_OFFSET_BITS);

    if (vaddrp0 == vaddrp1) {
        // Easy case, no page straddle
        if (far != vaddr) {
            printf("HV: far != vaddr faulted at 0x%lx (far), but expecting 0x%lx (vaddr)\n", far, vaddr);
            return false;
        }

        if (!hv_emulate_rw(ctx, pte, vaddr, ipa, val, is_write, bytes, elr, par))
            return false;
    } else {
        // Oops, we're straddling a page boundary
        // Treat it as two separate loads or stores

        assert(bytes > 1);
        hv_wdt_breadcrumb('s');

        u64 off = vaddrp1 - vaddr;

        u64 vaddr2;
        const char *other;
        if (far == vaddr) {
            other = "upper";
            vaddr2 = vaddrp1;
        } else {
            if (far != vaddrp1) {
                printf("HV: far != vaddrp1, faulted at 0x%lx, but expecting 0x%lx\n", far, vaddrp1);
                return false;
            }
            other = "lower";
            vaddr2 = vaddr;
        }

        u64 par2;
        u64 ipa2 = hv_translate(vaddr2, true, esr & ESR_ISS_DABORT_WnR, &par2);
        if (!ipa2) {
            printf("HV: %s half stage 1 translation failed at VA 0x%0lx\n", other, vaddr2);
            return false;
        }
        if (ipa2 >= BIT(vaddr_bits)) {
            printf("hv_handle_abort(): %s half IPA out of bounds: 0x%0lx -> 0x%lx\n", other, vaddr2,
                   ipa2);
            return false;
        }

        u64 pte2 = hv_pt_walk(ipa2);
        if (!pte2) {
            printf("HV: Unmapped %s half IPA 0x%lx\n", other, ipa2);
            return false;
        }

        hv_wdt_breadcrumb('S');

        printf("HV: Emulating %s straddling page boundary as two ops @ 0x%lx (%ld bytes)\n",
               is_write ? "write" : "read", vaddr, bytes);

        bool upper_ret;
        if (far == vaddr) {
            if (!hv_emulate_rw(ctx, pte, vaddr, ipa, val, is_write, off, elr, par))
                return false;
            upper_ret =
                hv_emulate_rw(ctx, pte2, vaddr2, ipa2, val + off, is_write, bytes - off, elr, par2);
        } else {
            if (!hv_emulate_rw(ctx, pte2, vaddr2, ipa2, val, is_write, off, elr, par2))
                return false;
            upper_ret =
                hv_emulate_rw(ctx, pte, vaddrp1, ipa, val + off, is_write, bytes - off, elr, par);
        }

        if (!upper_ret) {
            printf("HV: WARNING: Failed to emulate upper half but lower half did commit!\n");
            return false;
        }
    }

    if (vaddrp0 != vaddrp1) {
        printf("HV: Straddled r/w data:\n");
        hexdump(val, bytes);
    }

    hv_wdt_breadcrumb('8');
    if (!is_write && !emulate_load(ctx, insn, (u64 *)val, &width, &vaddr))
        return false;

    hv_wdt_breadcrumb('9');

    return true;
}

extern u64 IPA_hook_blacklist_handoff;

// bool backup_pt_walk_to_L3_change_to_hook(u64 addr){
//     u64 L1offset = (addr >> VADDR_L1_OFFSET_BITS) & MASK(VADDR_L1_INDEX_BITS);
//     u64 L2offset = (addr >> VADDR_L2_OFFSET_BITS) & MASK(VADDR_L2_INDEX_BITS);
//     u64 L3offset = (addr >> VADDR_L3_OFFSET_BITS) & MASK(VADDR_L3_INDEX_BITS);

// }
void backup_pt_fill_L3Table(u64 origin_L2PTE, u64 L2offset, u64 *L3Table){
    u64 L2PTEAddr = (origin_L2PTE & PTE_MASK);
    L3Table = (u64*)((u64)L3Table & PTE_MASK);
    for (u64 i = 0; i < ENTRIES_PER_L3_TABLE; i++){
        u64 origin_L3PTE = read64(L2PTEAddr+8*i);
        
        
        if (origin_L3PTE!=0){
            
            L3Table[i] = origin_L3PTE;
            // if ((origin_L3PTE&((u64)1<<6))==0 && (origin_L3PTE&((u64)1<<7)) == 0 && (origin_L3PTE&((u64)1<<53)!=0 && (origin_L3PTE&((u64)1<<54))!=0))
            //     printf("l3pte addr: %p, pte value: %p, AP[1](RO) %d\tAP[0](EL0) %d\tUXN %d\t PXN %d\n",&L3Table[i],L3Table[i],(origin_L3PTE&((u64)1<<7))?1:0,(origin_L3PTE&((u64)1<<6))?1:0,(origin_L3PTE&((u64)1<<54))?1:0,(origin_L3PTE&((u64)1<<53))?1:0);
            if ((origin_L3PTE&PTE_TYPE) && (origin_L3PTE&((u64)1<<6))==0 && (origin_L3PTE&((u64)1<<7)) == 0 && (origin_L3PTE&((u64)1<<53))!=0 && (origin_L3PTE&((u64)1<<54))!=0){
         
                u64 physical_addr = origin_L3PTE&PTE_MASK;
                // if (physical_addr < 0x800000000){
                    // printf("physical_addr == %p, l3pte addr: %p, pte value: %p, AP[1](RO) %d\tAP[0](EL0) %d\tUXN %d\t PXN %d\n",physical_addr,&L3Table[i],L3Table[i],(origin_L3PTE&((u64)1<<7))?1:0,(origin_L3PTE&((u64)1<<6))?1:0,(origin_L3PTE&((u64)1<<54))?1:0,(origin_L3PTE&((u64)1<<53))?1:0);
                // }
                if (physical_addr >= 0x800000000&& physical_addr<0xbd27ec000 && (origin_L3PTE & PTE_VALID))
                {
                    if (origin_L3PTE != IPA_hook_blacklist_handoff) 
                    {
                        
                        if (physical_addr >= 0x8a0000000 && physical_addr <0x8a2000000){
                            // hv_map(physical_addr, physical_addr|PTE_ATTRIBUTES, 8, 1);
                            hv_stage2_l2_expand_map_to_l3(physical_addr);
                            hv_stage2_direct_change_l3((u64)physical_addr, (u64)physical_addr|PTE_TYPE|SPTE_TRACE_READ|SPTE_CF_IPA_HOOK, 8);
                        }
                        
                        
                        // if (physical_addr >= 0x900500000 && physical_addr <0x901000000){
                        //     hook_page_cnt++;
                        
                        // }

                    }else{
                        printf("[*] L3PTE matches blacklist: %p\n",origin_L3PTE);
                    }
                }
                    
            }
        }
    }
}

void backup_pt_fill_L2Table(u64 origin_L1PTE, u64 L1offset, u64 *L2Table){
    u64 L1PTEAddr = (origin_L1PTE & PTE_MASK);
    L2Table = (u64*)((u64)L2Table & PTE_MASK);
    for (u64 i = 0; i < ENTRIES_PER_L2_TABLE; i++){
        u64 origin_L2PTE = read64(L1PTEAddr + 8*i);
        
        u64 *L3Table = (u64*) L2Table[i];
        bool is_table = (origin_L2PTE&PTE_TYPE);
        if (origin_L2PTE!=0){
            if (is_table){
                if (L3Table == 0){
                L3Table = backup_pt_get_page();// L3Table == L2PTE
                }
                backup_pt_fill_L3Table(origin_L2PTE, i, L3Table);
                // hv_map_hw((u64)L3Table, (u64)L3Table, PAGE_SIZE);
                L2Table[i] = ((u64)L3Table&PTE_MASK)|(origin_L2PTE&(~PTE_MASK));
            }
            else{
                L2Table[i] = origin_L2PTE; 
            }
        }
    }
}

// u64 stage1_pt_walk_and_fill_shadow_pagetable(u64 addr, u64 ttbr){

//     // u64 L3offset = (addr>>14)&((1<<11)-1);
//     // u64 L2offset = (addr>>25)&((1<<11)-1);
//     // u64 L1offset = (addr>>36)&((1<<11)-1);
//     // if (ttbr==0){
//     //     printf("[!] ttbr == 0???\n");
//     //     return 0;
//     // }
//     // u64 L1PTEAddr = (ttbr + L1offset*8);
//     // u64 L1PTE = read64(L1PTEAddr);
//     printf("ia abort addr: %p\n",addr);
//     // fill_backup_pt_per_cpu(mrs(TTBR1_EL12));
// }

extern u64 ttbr1_backup;


u64* backup_pt_init(void){
    backup_pt_Ltop = backup_pt_get_page();
    if (!backup_pt_Ltop) {
        printf("HV: Failed to allocate shadow page table\n");
        return 0;
    }
    memset(backup_pt_Ltop, 0, PAGE_SIZE);

    
    if (ttbr1_backup == -1){
        printf("[!] ttbr1_backup == -1\n");
        return 0;
    }
    printf("backup_pt_Ltop init succeeded: %p\n",backup_pt_Ltop);
    return backup_pt_Ltop;
}



bool fixup_shadow_pt_va_mmio(void){
    
    // for (u64 i=0xfffffe8fffe00000; i<=0xfffffe8fffef0000; i+=0x10000){
        
    // }
    int L1offset = 0x7e8;
    int L2offset = 0x7ff;
    for (int L3offset=0x784; L3offset<=0x784+0x4*0xf; L3offset+=0x4){
        u64 L1PTE = backup_pt_Ltop[L1offset];
        u64 L2PTAddr = L1PTE&PTE_MASK;
        u64 L2PTE = read64(L2PTAddr+L2offset*8);
        u64 *L3PTAddr = (u64*)(L2PTE&PTE_MASK);
        // u64 L3PTE = read64(L3PTAddr+L3offset*8);
        L3PTAddr[L3offset] = 0x60000204d1448f;
    }
    return true;
}

u64 *fill_backup_pt_per_cpu(u64 origin_ttbr){
    
    if (backup_pt_Ltop == -1){
        printf("[!] backup_pt_Ltop == -1, not inited\n");
        return 0;
    }
    printf("[*] fill_backup_pt_per_cpu, origin_ttbr: %p\n", origin_ttbr);
    for (u64 i = 0; i < SHADOW_ENTRIES_PER_L1_TABLE; i++){
        u64 L1PTEAddr = (origin_ttbr + i*8);
        u64 origin_L1PTE = read64(L1PTEAddr);
        if (origin_L1PTE!=0){
            if (backup_pt_Ltop[i] == 0)
                backup_pt_Ltop[i] = (u64)backup_pt_get_page();
            backup_pt_fill_L2Table(origin_L1PTE, i, (u64*)backup_pt_Ltop[i]);

            
            backup_pt_Ltop[i] = (backup_pt_Ltop[i]&PTE_MASK) | (origin_L1PTE&(~PTE_MASK));
        }
    }
    
    return backup_pt_Ltop;
}


u64 ipa_hook(u64 va, u64 ipa)
{
    u64 ipa_trans = hv_pt_walk(ipa);
    if (FIELD_HAS(ipa_trans, SPTE_CF_IPA_HOOK)) {
        printf("ipa: 0x%lx 's stage2 is already hooked\n", ipa);
        return -1;
    }else if(ipa_trans<0x100000000){
        printf("[-] ipa_hook: ipa: 0x%lx<0x100000000\n", ipa);
        return -1;
    }
    hv_stage2_l2_expand_map_to_l3(ipa);
    hv_stage2_direct_change_l3((u64)ipa, (u64)ipa|PTE_TYPE|SPTE_TRACE_READ|SPTE_CF_IPA_HOOK, 8);
    u64 l3_pte_addr = pt_walk(ipa, (u64)hv_Ltop, 3, 2, true);
    stage2_hook_tlb_flush(va, ipa, l3_pte_addr);
    printf("ipa_hook: ipa: 0x%lx, va: 0x%lx, done\n", ipa, va);
    return 0;
}

u64 ipa_unhook(u64 va, u64 ipa){
    
    u64 l3_pte_addr = pt_walk(ipa, (u64)hv_Ltop, 3, 2, true);
    if (l3_pte_addr!=-1){
        u64 origin_pte = 0;
        origin_pte = *(u64*)l3_pte_addr;
        // printf("pte_addr: 0x%lx, pte: 0x%lx, origin_pte: 0x%lx\n", pte_addr, pte, origin_pte);
        u64 changed_pte = origin_pte;
        if (FIELD_HAS(origin_pte, SPTE_CF_IPA_HOOK)){
            changed_pte = (origin_pte&PTE_MASK)|0x7ff; 
            write64(l3_pte_addr, changed_pte);
        }
        // printf("[C%d] HW:%d, pte_addr: 0x%lx, origin_pte: 0x%lx, changed_pte: 0x%lx, elr: 0x%lx, far: 0x%lx\n", mrs(TPIDR_EL2), IS_HW(pte), pte_addr, origin_pte, changed_pte, ctx->elr, va);
        stage2_hook_tlb_flush(va, ipa, l3_pte_addr);
    }else{
        printf("[-] ipa_unhook: ipa: 0x%lx, stage2 l3_pte_addr == -1\n", ipa);
        return -1;
    }
    return 0;
}

u64 va_hook(u64 va, int size, bool is_kernel, u64 ttbr){
    u64 origin_va = va;
    u64 origin_size = size;
    while (size > 0){
        u64 ipa = pt_walk(va, ttbr, 3, 1, false);
        size -= PAGE_SIZE;
        va += PAGE_SIZE;
        if (ipa == 0){
            printf("va: 0x%lx stage1 translation failed\n", va-PAGE_SIZE);
            continue;
        }
        
        ipa_hook(va, ipa);
    }
    printf("%s_hook [0x%lx, 0x%lx) size: 0x%x, done\n", is_kernel?"kva":"uva", origin_va, origin_va+origin_size, origin_size);
    return 0;
}
u64 va_unhook(u64 va, int size, bool is_kernel, u64 ttbr){
    u64 origin_size = size;
    while (size > 0){
        u64 ipa = pt_walk(va, ttbr, 3, 1, false);
        size -= PAGE_SIZE;
        va += PAGE_SIZE;
        if (ipa == 0){
            printf("va: 0x%lx stage1 translation failed\n", va-PAGE_SIZE);
            continue;
        }
        ipa_unhook(va, ipa);
    }
    printf("%s_unhook [0x%lx, 0x%lx) size: 0x%x, done\n", is_kernel?"kva":"uva" ,va, va+origin_size, origin_size);
    return 0;
}

u64 kva_hook(u64 va, int size){
    printf("kva_hook: va: 0x%lx, size: 0x%x\n", va, size);
    if (FIELD_HAS(va, MASK(VADDR_L3_OFFSET_BITS))){
        printf("[*] kva_hook: va: 0x%lx, not aligned, auto aligned to 0x%lx\n", va, va&(~MASK(VADDR_L3_OFFSET_BITS)));
        va = va&(~MASK(VADDR_L3_OFFSET_BITS));
    }
    if (FIELD_HAS(size, MASK(VADDR_L3_OFFSET_BITS))){
        printf("[*] kva_hook: size: 0x%x, not aligned, auto aligned to 0x%x\n", size, size&(~MASK(VADDR_L3_OFFSET_BITS)));
        size = size&(~MASK(VADDR_L3_OFFSET_BITS));
    }
    return va_hook(va, size, true, mrs(TTBR1_EL12));
}
u64 kva_unhook(u64 va, int size){
    printf("kva_unhook: va: 0x%lx, size: 0x%x\n", va, size);
    return va_unhook(va, size, true, mrs(TTBR1_EL12));
}

u64 uva_hook(u64 va, int size, u64 ttbr0){
    printf("uva_hook: va: 0x%lx, size: 0x%x\n", va, size);
    if (FIELD_HAS(va, MASK(VADDR_L3_OFFSET_BITS))){
        printf("[*] uva_hook: va: 0x%lx, not aligned, auto aligned to 0x%lx\n", va, va&(~MASK(VADDR_L3_OFFSET_BITS)));
        va = va&(~MASK(VADDR_L3_OFFSET_BITS));
    }
    if (FIELD_HAS(size, MASK(VADDR_L3_OFFSET_BITS))){
        printf("[*] uva_hook: size: 0x%x, not aligned, auto aligned to 0x%x\n", size, size&(~MASK(VADDR_L3_OFFSET_BITS)));
        size = size&(~MASK(VADDR_L3_OFFSET_BITS));
    }
    return va_hook(va, size, false, ttbr0);
}
u64 uva_unhook(u64 va, int size, u64 ttbr0){
    printf("uva_unhook: va: 0x%lx, size: 0x%x\n", va, size);
    return va_unhook(va, size, false, ttbr0);
}
u64 uva_walk(u64 va, u64 ttbr0){
    // printf("uva_walk: va: 0x%lx, ttbr0: 0x%lx\n", va, ttbr0);
    u64 ipa = pt_walk(va, ttbr0, 3, 1, false);
    // printf("uva_walk: va: 0x%lx, ipa: 0x%lx\n", va, ipa);
    return ipa;
}
u64 pt_walk(u64 addr, u64 ttbr, u64 level, int start_level, bool return_pte_address){
    u64 L1offset = (addr>>36)&((1<<11)-1);
    u64 L2offset = (addr>>25)&((1<<11)-1);
    u64 L3offset = (addr>>14)&((1<<11)-1);
    u64 L1PTE=-1;
    // printf("[*] pt_walk: L1offset: %p, L2offset: %p, L3offset: %p, addr: %p, ttbr: %p, level: %d, start_level: %d\n",L1offset,L2offset,L3offset,addr,ttbr,level,start_level);
    if (start_level == 1){
        u64 L1PTEAddr = (ttbr + L1offset*8);
        L1PTE = read64(L1PTEAddr);
        if (level==1){
            if(return_pte_address)
                return (ttbr + L1offset*8);
            else
            {
                printf("[-] no need to return address in level 1!\n");
                return -1;
            }
            
        }
    }else{
        L1PTE = ttbr;
    }
    if (L1PTE==-1){
        printf("[*] pt_walk: L1offset: %p, L2offset: %p, L3offset: %p, addr: %p, ttbr: %p, level: %d, start_level: %d\n",L1offset,L2offset,L3offset,addr,ttbr,level,start_level);
        printf("Invalid L1PTE=%p, addr: %p, ttbr: %p, level: %d, start_level: %d\n", L1PTE, addr, ttbr ,level,start_level);
        return -1;
    }
    u64 L2PTAddr = L1PTE&PTE_MASK;
    if (L2PTAddr+L2offset*8<0x800000000){
        printf("[*] pt_walk: L1offset: %p, L2offset: %p, L3offset: %p, addr: %p, ttbr: %p, level: %d, start_level: %d\n",L1offset,L2offset,L3offset,addr,ttbr,level,start_level);
        printf("Invalid L2PTAddr=%p, addr: %p, ttbr: %p, level: %d, start_level: %d\n", L2PTAddr+L2offset*8, addr, ttbr ,level,start_level);
        printf("usually caused by autorar() in python, plz check whether the legacy /tmp/addr_range.txt is deleted\n");
        return -1;
    }
    u64 L2PTE = read64(L2PTAddr+L2offset*8);
    if (level==2 || !L2_IS_TABLE(L2PTE)){
        if(return_pte_address){
            if (level==2)
                return L2PTAddr+L2offset*8;
            else
                return -1; 
        }
        else{
            if (!L2_IS_TABLE(L2PTE))
            {
                L2PTE &= ~PTE_LOWER_ATTRIBUTES;
                L2PTE |= addr & (VADDR_L2_ALIGN_MASK | VADDR_L3_ALIGN_MASK);
                return L2PTE;
            }
        }
    }
    u64 L3PTAddr = L2PTE&PTE_MASK;
    if (L3PTAddr+L3offset*8<0x800000000){
        printf("[*] pt_walk: L1offset: %p, L2offset: %p, L3offset: %p, addr: %p, ttbr: %p, level: %d, start_level: %d\n",L1offset,L2offset,L3offset,addr,ttbr,level,start_level);
        printf("Invalid L3PTAddr=%p, addr: %p, ttbr: %p, level: %d, start_level: %d\n", L3PTAddr+L3offset*8, addr, ttbr ,level,start_level);
        return -1;
    }
    u64 L3PTE = read64(L3PTAddr+L3offset*8);
    if(return_pte_address)
        return L3PTAddr+L3offset*8;
    else
        return (L3PTE&(PTE_MASK))|(addr&(BIT(VADDR_L3_OFFSET_BITS)-1));
}

bool hv_handle_iabort(struct exc_info *ctx)
{  
   // ISS = 0x86
    hv_wdt_breadcrumb('0');
    
    // bool is_ins_trans = esr & ESR_ISS_IABORT_TRANS_LV2;

    // u64 far = hv_get_far();//0xfffffe001f48941c
    // u64 par;
    // u64 ipa = hv_translate(far, true, is_ins_trans, &par);
    // stage1_pt_walk_and_fill_shadow_pagetable(far, ttbr1_backup);

    // (L3PTE&((u64)1<<7))?1:0,(L3PTE&((u64)1<<6))?1:0,(L3PTE&((u64)1<<54))?1:0,(L3PTE&((u64)1<<53))?1:0)
    
    return true;
}


