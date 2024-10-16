
import random
import bisect
# from .hv import HV
class Uva:
    def __init__(self, uva, ipa):
        self.uva = uva
        self.ipa = ipa
        
class RawDataWriter:
    def __init__(self, hv):
        self.hv = hv
    def flush_dcache(self, addr, addr_size):
        size = 0
        while size < addr_size:
            self.hv.p.cdc(addr+size)
            size += 0x4000
    def writemem_flush(self, ipa, data, addr_size=0x4000):
        # 
        size = 0
        while size < addr_size:
            self.hv.iface.writemem(ipa+size, data[size:size+0x4000])
            size += 0x4000
        self.flush_dcache(ipa, addr_size)
# 
# mutated_data = ipa_data_mutator.mutate(data)，

banlist_for_fuzz=set({0, 1, 2, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234})



class IPAHookMutator:
    # data_writer = RawDataWriter()
    default_times = 10
    flip_blacklist = banlist_for_fuzz
    enable_blacklist = False # 
    print_verbose = True
    def __init__(self, hv):
        self.hv = hv
    
    def flip(self, data, times, loweroffset=-1, upperoffset=-1):
        """
        loweroffset 
        """
        if loweroffset != -1 and upperoffset != -1:
            flip_bits = random.choices(range(loweroffset, upperoffset), k=times)
            
        elif loweroffset == -1 or upperoffset == -1:
            flip_bits = random.choices(range(8 * len(data)), k=times)
        
        # 
        int_data = int.from_bytes(data, 'big')  
        
        if self.enable_blacklist:
            flip_bits_set = set(flip_bits)
            
            # 
            flip_bits = list(flip_bits_set - self.flip_blacklist)
        
        # 
        for bit in flip_bits:
            int_data ^= (1 << bit)
        
        # 
        return int_data.to_bytes(len(data), 'big')
    
    
    def flip_with_bound(self, mem_range, mutate_times=1):
        size = mem_range.size
        # loweroffset = mem_range.va_start
        # upperoffset = mem_range.va_end
        
        loweroffset = mem_range.user_store_far_lower
        upperoffset = mem_range.user_store_far_upper
        
        # loweroffset = 0
        # upperoffset = 0x900
        
        if loweroffset < 0 or upperoffset < 0:
            loweroffset = mem_range.va_start
            upperoffset = mem_range.va_end
            
        flip_bits = sorted(random.choices(range(loweroffset*8, upperoffset*8), k=mutate_times))
        if self.print_verbose:
            print(f"[*] flip_with_bound: loweroffset: {hex(loweroffset)}, upperoffset: {hex(upperoffset)}, flip_bits: {[hex(i) for i in flip_bits]}")
            
        if self.enable_blacklist:
            flip_bits_set = set(flip_bits)
            
            # 
            flip_bits = sorted(list(flip_bits_set - self.flip_blacklist))
            if self.print_verbose:
                print(f"flip_with_bound: flip_bits after blacklist: {flip_bits}")
        
        # 
        for bit in flip_bits:
            # int_data ^= (1 << bit)
            
            # 
            aligned_byte_addr = (bit//8) 
            remainder = bit % 8
            ipa_aligned = self.hv.ipa_hook_manager.va2phy_aligned(aligned_byte_addr)
            if ipa_aligned == None:
                print(f"[-] flip_with_bound: ipa_aligned is None, byte_addr: {hex(aligned_byte_addr)}")
                continue
            specific_bytes_ipa_addr = ipa_aligned + (aligned_byte_addr & 0x3fff)
            data = self.hv.p.read8(specific_bytes_ipa_addr)
            self.hv.p.write8(specific_bytes_ipa_addr, (data ^ (1 << remainder)))
            if self.print_verbose:
                print(f"[*] flip_with_bound: flipped {hex(aligned_byte_addr)}:{remainder}, data mutate {hex(data)} to: {hex(data ^ (1 << remainder))}")
            self.hv.p.dc_cvau(specific_bytes_ipa_addr, 8)
        
        # self.hv.p.write8(ipa_aligned+0x210+0x1f7, 0x10) # 
        # self.hv.p.dc_cvau(ipa_aligned+0x210+0x1f7, 8) 
        
        
            
            
        
    
    def fast_flip(self, data):
        self.flip(data, self.default_times)
        
class IPAHookLookUp:
    def __init__(self, lvalue, rvalue=-1):
        self.lvalue = lvalue
        # self.rvalue = rvalue

    def __lt__(self, other):
        return self.lvalue < other.va_start
    
class IPAHookMemoryRange:
    
    _id_counter = 0  # 
    
    def __init__(self, va_start, va_end, mem_type):
        self.va_start = va_start
        self.va_end = va_end
        self.mem_type = mem_type
        # self.hit_count = 0#
        self.user_load_count = 0
        self.user_store_count = 0
        self.kernel_load_count = 0
        self.kernel_store_count = 0
        self.id = IPAHookMemoryRange._id_counter  # 
        IPAHookMemoryRange._id_counter += 1  # 
        self.user_load_pc = 0
        self.user_store_pc = 0
        self.user_store_far_upper = 0
        self.user_store_far_lower = 0xffffffffffffffff
        self.kernel_load_pc = 0
        self.kernel_store_pc = 0
        self.on_demand_of_hit_bt = True

    # 
    @property
    def hit_count(self):
        return self.user_load_count + self.user_store_count + self.kernel_load_count + self.kernel_store_count
    @property
    def size(self):
        return self.va_end - self.va_start
    
    def __lt__(self, other):
        # __lt__
        if isinstance(other, IPAHookMemoryRange):
            return self.va_start < other.va_start
        if isinstance(other, IPAHookLookUp):
            return self.va_end <= other.value
        # Comparisons with non-MemoryRange type will be based on va_start
        return self.va_start <= other

    def __contains__(self, item):
        if isinstance(item, IPAHookMemoryRange):
            return self.va_start <= item.va_start < item.va_end < self.va_end
        # __contains__
        return self.va_start <= item and item < self.va_end
    
    def __repr__(self):
        if self.user_store_count!=0:
            ratio = (self.user_store_far_upper-self.user_store_far_lower)/(self.va_end-self.va_start)
            return f"{self.id}:({hex(self.va_start)} - {hex(self.va_end)}), sz:{hex(self.va_end-self.va_start)}, {self.mem_type}, \n\tulpc:{hex(self.user_load_pc)}, \t uspc:{hex(self.user_store_pc)}, \t klpc: {hex(self.kernel_load_pc)}, \t kspc: {hex(self.kernel_store_pc)}\n\t ul: {self.user_load_count},\t us: {self.user_store_count},\t kl: {self.kernel_load_count},\t ks: {self.kernel_store_count},\t hit_count: {self.hit_count}\n\tus_lower: {hex(self.user_store_far_lower)}, \tus_upper: {hex(self.user_store_far_upper)}, us_size: {hex(self.user_store_far_upper-self.user_store_far_lower)}, \tus_ratio: {ratio}\n---------------------------\n"
        else:
            return f"{self.id}:({hex(self.va_start)} - {hex(self.va_end)}), sz:{hex(self.va_end-self.va_start)}, {self.mem_type}, \n\tulpc:{hex(self.user_load_pc)}, \t uspc:{hex(self.user_store_pc)}, \t klpc: {hex(self.kernel_load_pc)}, \t kspc: {hex(self.kernel_store_pc)}\n\t ul: {self.user_load_count},\t us: {self.user_store_count},\t kl: {self.kernel_load_count},\t ks: {self.kernel_store_count},\t hit_count: {self.hit_count}\n---------------------------\n"
class IPAHookManager:
    # 
    va_range_list = []
    hv = None
    # 
    va_range_id_2_user_store_pc = dict()
    user_store_pc_2_va_range = dict()
    user_store_pc_fuzzing_progress = dict() # 
    specified_fuzz_addr_range_by_user_store_pc = -1
    specified_fuzz_addr_range_by_id = -1
    user_far = set() # 
    user_far_list = [] # 
    ipa_hook_total_hit_count = 0
    access_elr = {}
    
    def __init__(self, hv=None):
        self.va2phymapping = dict()
        self.phy2vamapping = dict()
        if hv!=None:
            self.hv = hv
    def add_va2phy_aligned(self, virt_addr, phys_frames):
        virt_addr = virt_addr & 0xFFFFFFFFFFFFC000
        phys_frames = phys_frames & 0xFFFFFFFFFFFFC000
        self.va2phymapping[hex(virt_addr)] = phys_frames  # 
        # self.mapping[]
    def add_phy2va_aligned(self, phys_frame, virt_addr):
        phys_frame = phys_frame & 0xFFFFFFFFFFFFC000
        virt_addr = virt_addr & 0xFFFFFFFFFFFFC000
        self.phy2vamapping[hex(phys_frame)] = virt_addr
    def add_addr_map_aligned(self, virt_addr, phys_frame):
        self.add_va2phy_aligned(virt_addr, phys_frame)
        self.add_phy2va_aligned(phys_frame, virt_addr)
        
    def add_range(self, va_start, va_end, mem_type, is_uva=True):
        # if self.hv == None:
        #     print("[-] add_range: hv is None")
        #     return
        addr_size = va_end - va_start
        size = 0
        while size < addr_size:
            ipa = -1
            if is_uva:
                if self.hv != None:
                    ipa = self.hv.p.uva_walk(va_start+size, self.hv.ttbr0)
            else:
                print(f"[-] add_range add mapping: kva is not supported yet. addr: {hex(va_start)}-{hex(va_end)} {mem_type}")
                return
            size += 0x4000
            # if size <= 0x8000: # debug line
            #     ipa = va_start + 0x900000 - 0x4000 + size # debug line
            if ipa == -1 or ipa == 0:
                print("[-] skip va, add_range add mapping: ipa is -1/0 for addr in va: ", hex(va_start+size))
                continue
            self.add_addr_map_aligned(va_start+size-0x4000, ipa)
            if self.hv != None:
                self.hv.p.ipahook(va_start+size-0x4000, ipa)
        self.va_range_list.append(IPAHookMemoryRange(va_start, va_end, mem_type))
    
    def add_ranges(self, lines):
        # lines = lines.split("\n")
        for line in lines:
            try:
                if not line.strip():# 
                    continue
                addr_type, start, end = line.split(" ")
                start = int(start, 16)
                end = int(end, 16)
                self.add_range(start, end, addr_type)
            except Exception as e:
                print("[-] add_ranges: ", e, "line:" ,line)
        self.va_range_list.sort()
    
    def va2phy_aligned(self, va):
        va = va & 0xFFFFFFFFFFFFC000
        va = hex(va)  # 
        if va in self.va2phymapping:
            return self.va2phymapping[va]
        else:
            return None
    def phy2va_aligned(self, ipa):
        if ipa == None:
            print("[!] phy2va_aligned == None???!")
            return None
        ipa = ipa & 0xFFFFFFFFFFFFC000
        ipa = hex(ipa)  # 
        if ipa in self.phy2vamapping:
            return self.phy2vamapping[ipa]
        else:
            return None
    
    def lookup_va_by_ipa(self, ipa):
        # ipa->va->va_range
        pass
    
    def lookup_va_range_by_far(self, far):
        if self.hv == None:
            print("[-] lookup_va_range_by_far: hv is None")
            return
        ipa = self.hv.p.hv_translate(far, True, False)
        va = self.phy2va_aligned(ipa)
        # 
        if va==None:
            print(f"[-] lookup_va_range_by_ipa ipa: {hex(ipa)}, va is None")
            return None, None
        index = bisect.bisect_right(self.va_range_list, IPAHookLookUp(va)) - 1
        return index, self.va_range_list[index]
    
    def lookup_va_range_by_ipa(self, ipa):
        va = self.phy2va_aligned(ipa)
        # 
        if va==None:
            print(f"[-] lookup_va_range_by_ipa ipa: {hex(ipa)}, va is None")
            return None, None
        index = bisect.bisect_right(self.va_range_list, IPAHookLookUp(va)) - 1
        return index, self.va_range_list[index]
    
    def delete_item_by_id(self, id):
        for i in range(len(self.va_range_list)):
            if self.va_range_list[i].id == id:
                print(f"delete_item_by_id: id {id}, {self.va_range_list[i]} deleted")
                del self.va_range_list[i]
                return
        print("[-] delete_item_by_id: id not found")
    
    def search_item_by_id(self, id):
        for i in range(len(self.va_range_list)):
            if self.va_range_list[i].id == id:
                return self.va_range_list[i]
        return None
    
    
    def get_sorted_address_range_hitcount(self):
        if len(self.va_range_list) == 0:
            print("[-] print_address_range_hitcount: va_range_list is empty")
            return
        # Sort by hit_count in descending order
        ranges = sorted(self.va_range_list, key=lambda x: x.user_load_count + x.user_store_count + x.kernel_load_count + x.kernel_store_count, reverse=True)
        
        return ranges
    
    def print_address_range_hitcount(self):
        print("Address Range Hit Count Sort:\n", self.get_sorted_address_range_hitcount())
        # 
        total_size = 0
        user_store_size = 0
        for r in self.va_range_list:
            if r.user_store_count == 0 or r.user_store_far_upper == r.user_store_far_lower:
                continue
            total_size += r.va_end - r.va_start
            user_store_size += r.user_store_far_upper - r.user_store_far_lower
        if total_size != 0:
            print(f"user store size: {hex(user_store_size)}, total size: {hex(total_size)}, ratio: {user_store_size/total_size}")
        else:
            print("[-] total_size is 0")
    
    def unhook_by_id(self, id, delete_va_list=True):
        # if self.hv == None:
        #     print("[-] add_range: hv is None")
        #     return
        item = self.search_item_by_id(id)
        if item==None:
            print(f"[-] unhook_by_id: id:{id} not found")
            return
        size = 0
        
        while size < item.va_end - item.va_start:
            ipa = self.va2phy_aligned(item.va_start+size)
            size += 0x4000
            if ipa == None:
                print("[-] skip va, unhook_by_id: ipa is -1 for addr in va: ", hex(item.va_start+size))
                continue
            self.hv.p.ipaunhook(item.va_start+size-0x4000,ipa)
        if delete_va_list:
            self.delete_item_by_id(id)
        
    def unhook_by_hitcount(self, hit_count_threshold):
        # 
        for i in range(len(self.va_range_list) - 1, -1, -1): #
            if self.va_range_list[i].hit_count < hit_count_threshold:
                self.unhook_by_id(self.va_range_list[i].id)   
    
    def unhook_all(self, delete_va_list=True):
        if len(self.va_range_list) == 0:
            print("[-] unhook_all: va_range_list is empty")
            return
        for i in range(len(self.va_range_list) - 1, -1, -1):
            self.unhook_by_id(self.va_range_list[i].id, delete_va_list=delete_va_list)            
        
    def ls_user_store_pc(self):
        print("user_store_pc_2_va_range: ", self.user_store_pc_2_va_range)
        print("va_range_id_2_user_store_pc: ", self.va_range_id_2_user_store_pc)
        print("user_store_pc_fuzzing_progress: ", self.user_store_pc_fuzzing_progress)
    
    def set_fuzz_addr_range_by_id(self, id):
        # self.ls_user_store_pc()
        item = self.search_item_by_id(id)
        if item == None:
            print(f"[-] set_fuzz_addr_range_by_id: id:{id} not found")
            return
        upc = item.user_store_pc
        if upc in self.user_store_pc_2_va_range:
            self.specified_fuzz_addr_range_by_user_store_pc = upc# upc
            self.specified_fuzz_addr_range_by_id = id # id 
            print(f"[+] set_fuzz_addr_range_by_user_store_pc: {hex(upc)}, id: {id}")
            
    def clear_fuzz(self):
        self.specified_fuzz_addr_range_by_user_store_pc = -1
        self.specified_fuzz_addr_range_by_id = -1
        print("[+] clear_fuzz")
    
    def pc_2_va_range_id(self, user_store_pc):
        try:
            return self.user_store_pc_2_va_range[user_store_pc].id
        except Exception as e:
            print(f"[-] user_store_pc_2_va_range: {user_store_pc} not found", e)
            return None
    def add_hit_count(self, far, elr, is_write, is_save_pc=True):
        if self.hv == None:
            print("[-] add_hit_count: hv is None")
            return
        ipa = self.hv.p.hv_translate(far, True, False)
        pos, ipa_hook_memory_range = self.lookup_va_range_by_ipa(ipa)
        if pos == None:
            print(f"[-] add_hit_count: ipa:{hex(ipa)} not found")
            return
        if elr & 0x8000000000000000 == 0:
            if is_write:
                self.va_range_list[pos].user_store_count += 1
                # 
                if is_save_pc and self.va_range_list[pos].user_store_pc == 0:
                    self.va_range_list[pos].user_store_pc = elr
                if far < self.va_range_list[pos].user_store_far_lower:
                    self.va_range_list[pos].user_store_far_lower = far
                if far > self.va_range_list[pos].user_store_far_upper:
                    self.va_range_list[pos].user_store_far_upper = far
            else:
                if is_save_pc and self.va_range_list[pos].user_load_pc == 0:
                    self.va_range_list[pos].user_load_pc = elr
                self.va_range_list[pos].user_load_count += 1
        else:
            if is_write:
                if is_save_pc and self.va_range_list[pos].kernel_store_pc == 0:
                    self.va_range_list[pos].kernel_store_pc = elr - self.hv.kaslrOffset
                self.va_range_list[pos].kernel_store_count += 1
            else:
                if is_save_pc and self.va_range_list[pos].kernel_load_pc == 0:
                    self.va_range_list[pos].kernel_load_pc = elr - self.hv.kaslrOffset
                self.va_range_list[pos].kernel_load_count += 1
        # self.va_range_list[pos].hit_count += 1
        return pos, ipa_hook_memory_range
    
    def add_hit_pc(self, far, elr, is_write):
        ipa = self.hv.p.hv_translate(far, True, False)
        pos, ipa_hook_memory_range = self.lookup_va_range_by_ipa(ipa)
        if pos == None:
            print(f"[-] add_hit_pc: ipa:{hex(ipa)} not found")
            return
        if elr & 0x8000000000000000 == 0:
            if is_write:
                self.va_range_list[pos].user_store_pc = elr
            else:
                self.va_range_list[pos].user_load_pc = elr
        else:
            if is_write:
                self.va_range_list[pos].kernel_store_pc = elr - self.hv.kaslrOffset
            else:
                self.va_range_list[pos].kernel_load_pc = elr - self.hv.kaslrOffset
        return pos, ipa_hook_memory_range
    # @deprecated
    def prepareration_for_next_guest_program(self):
        self.hv.ipa_hook_total_hit_count = 0
        self.hv.kernel_mutate_data_on_ipahook = False # 
        self.specified_fuzz_addr_range_by_id = -1
        self.user_far.clear()


class IPAFuzzManager: # fuzzmanager 
    syscall_cycle = 0
    mem_fuzz_mode = -1
    kernel_mutate_data_on_ipahook = False # 
    kernel_consecutive_invoke = 0
    kernel_consecutive_invoke_threshold = 50 # 
    sleep_seconds_after_greater_than_threshold = 2
    moniter_pid_set = set()
    random_choose_user_far_num = 1
    
    
    def __init__(self, ipa_hook_manager: IPAHookManager, hv):
        # if hv!=None:
        self.hv = hv
        # if ipa_hook_manager != None:
        self.ipa_hook_manager = ipa_hook_manager

    def start_rar_cycle(self, pid):
        self.accessed_addr_during_one_syscall = set()
        self.hv.p.dpid(pid)
        self.hv.ipa_monitor_pid = pid
        self.moniter_pid_set.add(pid)
        # self.moniter_pid_set.add(0)

    def reset_status(self):
        self.syscall_cycle = 0
        # self.kernel_mutate_data_on_ipahook = False
        # self.hv.derarall() ，
        self.ipa_hook_manager.unhook_all()
        self.ipa_hook_manager.user_far.clear()
        self.ipa_hook_manager.user_far_list.clear()
        
    def end_this_rar_cycle(self): # 
        # pass
        self.ipa_hook_manager.ipa_hook_total_hit_count = 0
        self.kernel_mutate_data_on_ipahook = False # 
        self.ipa_hook_manager.specified_fuzz_addr_range_by_id = -1
        self.ipa_hook_manager.user_far.clear()
        self.moniter_pid_set.clear()
    
    def end_this_mutate_cycle(self):
        pass
    
    def action_on_ipa_hook_invoke(self, ctx):
        pass
    
    def action_on_syscall_invoke(self):
        pass
    
    def maybe_mutate(self, rate=0.5):
        if random.random() < rate:
            return True
        return False
    
    def judge_if_pid_in_moniter_pid_set(self, pid, ctx):
        far = ctx.far
        if pid not in self.moniter_pid_set:
            if self.kernel_consecutive_invoke < self.kernel_consecutive_invoke_threshold:
                print("[-] pid not match, skip, now pid", pid)
            if pid != 0: # 
                ipa = self.hv.p.hv_translate(far, True, False) # 
                self.hv.p.ipaunhook(far & 0xFFFFFFFFFFFFC000,ipa & 0xFFFFFFFFFFFFC000)# 
            else:
                # 
                self.kernel_consecutive_invoke += 1
                if self.kernel_consecutive_invoke > self.kernel_consecutive_invoke_threshold:
                    if self.kernel_consecutive_invoke % 100 == 0:
                        print(f"[!] kernel_consecutive_invoke:{self.kernel_consecutive_invoke} > threshold:{self.kernel_consecutive_invoke_threshold}, derarall, addr: {hex(far)}, pc: {hex(ctx.elr-self.hv.kaslrOffset)}")
                    # time.sleep(self.sleep_seconds_after_greater_than_threshold)# 
                    # 
                    # self.derarall(delete_va_list=False)
                    ipa = self.hv.p.hv_translate(far, True, False) # 
                    self.hv.p.ipaunhook(far & 0xFFFFFFFFFFFFC000,ipa & 0xFFFFFFFFFFFFC000)
            return False
        return True
    
    # @abstractmethod
    def fuzzprocess(self):
        pass
    
class mode0FuzzManager(IPAFuzzManager):
    # -------------------------------------------- mem_fuzz_mode = 0，
    if_auto_acc_fuzz = True # 
    auto_fuzz = True
    fuzz_specified_addr_range_by_user_store_pc = True
    auto_fuzz_when_totalhitcount_greater_than_this_threshold = 100
    kernel_mutate_data_on_ipahook = False
    
    def __init__(self, ipa_hook_manager, hv):
        super().__init__(ipa_hook_manager, hv)
        
    def fuzzprocess(self):
        print("fuzzprocess:")
        item = self.ipa_hook_manager.search_item_by_id(self.ipa_hook_manager.specified_fuzz_addr_range_by_id)
        if item == None:
            print("[-] fuzzprocess: item == None")
        else:
            print(f"upc: {self.fuzz_specified_addr_range_by_user_store_pc}, id: {self.ipa_hook_manager.specified_fuzz_addr_range_by_id}, {item}")
        print(f"kernel_mutate_data_on_ipahook: {self.kernel_mutate_data_on_ipahook}, total_hit_count: {self.ipa_hook_manager.ipa_hook_total_hit_count}, auto_fuzz:{self.auto_fuzz}, auto_fuzz_when_hit_threshold: {self.auto_fuzz_when_totalhitcount_greater_than_this_threshold}")
    
    def action_on_ipa_hook_invoke(self, ctx):
        return self.handle_ipa_hook_mutate_on_kernel_load(ctx)
    
    def handle_ipa_hook_mutate_on_kernel_load(self, ctx):
        """
        if not hasattr(self, 'hook_addr_ranges'):
            addr_ranges_path = input("input addr_ranges_path: ")
            self.rar(addr_ranges_path)
        """
        # 
        pid = self.hv.p.get_pid()
        far = ctx.far
        if not self.judge_if_pid_in_moniter_pid_set(pid, ctx):
            return True
        
        self.kernel_consecutive_invoke = 0 # judge_if_pid_in_moniter_pid_set
        esrISS = ctx.esr.ISS
        is_write = esrISS & (1<<6) # esr.WnR BIT(6)
        
        # 
        if is_write != 0 and self.kernel_mutate_data_on_ipahook == False:#self.kernel_mutate_data_on_ipahook == False
            # 
            if ctx.elr & 0x8000000000000000 == 0: # "
                # 
                pos, ipa_hook_memory_range = self.ipa_hook_manager.add_hit_count(far, ctx.elr, is_write, False)# False：
                # self.ipa_hook_manager.add_hit_pc(far, ctx.elr, is_write)
                if pos != None:
                    if ipa_hook_memory_range.kernel_load_pc == 0: #
                        return True
                    else:
                        # 
                        if ipa_hook_memory_range.user_store_pc == 0: #
                            ipa_hook_memory_range.user_store_pc = ctx.elr
                            print(ipa_hook_memory_range)
                            print(f"[*] user first hit addr: {hex(far)} on pc:", hex(ctx.elr))
                            if ctx.elr not in self.ipa_hook_manager.user_store_pc_2_va_range: # 
                                self.ipa_hook_manager.user_store_pc_2_va_range[ctx.elr] = ipa_hook_memory_range
                                print("[*] first hit in user_store_pc_2_va_range, added")
                                self.ipa_hook_manager.va_range_id_2_user_store_pc[ipa_hook_memory_range.id] = ctx.elr # 
                                if self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc != -1:
                                    self.ipa_hook_manager.specified_fuzz_addr_range_by_id = self.ipa_hook_manager.pc_2_va_range_id(self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc)
                            # self.bt()
                            else:
                                # 
                                self.ipa_hook_manager.user_store_pc_2_va_range[ctx.elr] = ipa_hook_memory_range
                                self.ipa_hook_manager.va_range_id_2_user_store_pc[ipa_hook_memory_range.id] = ctx.elr
                                try:
                                    if self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc != -1:
                                        fuzz_id = self.ipa_hook_manager.user_store_pc_2_va_range[self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc]
                                        fuzz_item = self.ipa_hook_manager.search_item_by_id(fuzz_id)
                                        print(f"[*] guest restart, updated user_store_pc_2_va_range, continue to fuzz addr id:{fuzz_id}")
                                        if fuzz_item != None:
                                            print(fuzz_item)
                                except Exception as e:
                                    print(e)
                                
                                
                        else:
                            # 
                            if ipa_hook_memory_range.user_store_pc != ctx.elr:
                                # print(ipa_hook_memory_range)
                                pass
                                # print(f"[!] re hit addr: {far} on different pc:", hex(ctx.elr))
                                # self.bt()
                            else:
                                # 
                                pass
                    # self.ipa_hook_manager.add_hit_pc(far, ctx.elr, is_write)
                return True
            return True
        
        
        
        # 
        if ctx.elr & 0x8000000000000000 == 0:
            return True
        # 
        if self.hv.p.judge_if_next_syscall(ctx.cpu_id) == True:
            # 
            self.accessed_addr_during_one_syscall.clear()
            print("-----------------------syscall barriar-----------------------")
        else: # 
            return True
            
        if (ctx.far & 0xFFFFFFFFFFFFC000) not in self.accessed_addr_during_one_syscall:# 
            self.accessed_addr_during_one_syscall.add(ctx.far & 0xFFFFFFFFFFFFC000)
            if ctx.far & 0xFFFFFFFFFFFFC000 not in self.ipa_hook_manager.access_elr:
                self.ipa_hook_manager.access_elr[ctx.far & 0xFFFFFFFFFFFFC000] = set()
            self.ipa_hook_manager.access_elr[ctx.far & 0xFFFFFFFFFFFFC000].add(hex(ctx.elr-self.hv.kaslrOffset))
        else:
            # self.hv.log("[syscall re] pid:", pid, f", Data trace at pc:", hex(ctx.elr-self.hv.kaslrOffset), " addr:", hex(far))
            if ctx.far & 0xFFFFFFFFFFFFC000 not in self.ipa_hook_manager.access_elr:
                self.ipa_hook_manager.access_elr[ctx.far & 0xFFFFFFFFFFFFC000] = set()
            self.ipa_hook_manager.access_elr[ctx.far & 0xFFFFFFFFFFFFC000].add(hex(ctx.elr-self.hv.kaslrOffset))
            return True

        pc = ctx.elr-self.hv.kaslrOffset
        self.hv.log("pid:", pid, f", Data trace at pc:", hex(pc), " addr:", hex(far))
        
        # 
        if self.kernel_mutate_data_on_ipahook == False and self.ipa_hook_manager.ipa_hook_total_hit_count > self.auto_fuzz_when_totalhitcount_greater_than_this_threshold and self.auto_fuzz == True: # 
            try:
                self.kernel_mutate_data_on_ipahook = True
                if self.fuzz_specified_addr_range_by_user_store_pc: # 
                    sorted_ranges = self.ipa_hook_manager.get_sorted_address_range_hitcount()
                    # 
                    pos = 0
                    for i in sorted_ranges:
                        if i.kernel_load_count != 0:# 
                            break
                        else:
                            pos += 1
                    print(f"[*] auto fuzz addr id:{sorted_ranges[pos].id}")
                    if self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc != -1:
                        print("[*] auto fuzz specified addr upc:", hex(self.ipa_hook_manager.va_range_list[pos].user_store_pc), "id:", self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc)
                        self.ipa_hook_manager.specified_fuzz_addr_range_by_id = self.ipa_hook_manager.user_store_pc_2_va_range[self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc].id
                        pass
                    else:#  hv
                        print("[+] no specified addr range by user store pc, auto choose the highest:\n", sorted_ranges[pos])
                        self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc = self.ipa_hook_manager.va_range_id_2_user_store_pc[sorted_ranges[pos].id] 
                        self.ipa_hook_manager.specified_fuzz_addr_range_by_id = sorted_ranges[pos].id
                else:
                    print("[*] auto fuzz all")
                if self.if_auto_acc_fuzz:
                    self.hv.accrar(1)# 
            except Exception as e:
                print(e)
        
        # 
        # kernel load
        ipa = self.hv.p.hv_translate(far, True, False) # 
        pos, ipa_hook_memory_range = self.ipa_hook_manager.lookup_va_range_by_ipa(ipa)
        if pos != None:
            print("id", ipa_hook_memory_range.id, "range hit", hex(self.ipa_hook_manager.phy2va_aligned(ipa)), ipa_hook_memory_range)
            
            self.ipa_hook_manager.ipa_hook_total_hit_count += 1 # 

            self.ipa_hook_manager.va_range_list[pos].kernel_load_count += 1
            self.ipa_hook_manager.va_range_list[pos].kernel_load_pc = pc
            # 
            if self.kernel_mutate_data_on_ipahook: #and self.maybe_mutate(self.hv.data_flip_rate):
                # 
                if self.fuzz_specified_addr_range_by_user_store_pc:
                    # 
                    if self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc != -1:
                        try:
                            # 
                            if ipa_hook_memory_range.id == self.ipa_hook_manager.pc_2_va_range_id(self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc):
                                print(f"[*] fuzz addr upc hit matched:{hex(self.ipa_hook_manager.va_range_list[pos].user_store_pc)}({hex(self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc)}) id:{self.ipa_hook_manager.specified_fuzz_addr_range_by_id}")
                                # self.hv.read_mutate_writeback_flush_aligned(ipa, self.hv.data_flip_times_per_hit)
                                self.hv.data_mutator.flip_with_bound(ipa_hook_memory_range, mutate_times = self.hv.data_flip_times_per_hit) # 
                                # self.hv.read_mutate_writeback_flush_aligned(ipa, self.hv.data_flip_times_per_hit)
                                
                            else:
                                # 
                                ipa_hook_memory_range = self.ipa_hook_manager.user_store_pc_2_va_range[self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc]
                                print(f"[*] fuzz addr upc:{hex(self.ipa_hook_manager.va_range_list[pos].user_store_pc)}({hex(self.ipa_hook_manager.specified_fuzz_addr_range_by_user_store_pc)}) id:{self.ipa_hook_manager.specified_fuzz_addr_range_by_id}")
                                ipa = self.hv.p.hv_translate(ipa_hook_memory_range.va_start, True, False)
                                self.hv.data_mutator.flip_with_bound(ipa_hook_memory_range, mutate_times = self.hv.data_flip_times_per_hit) # 
                                # self.hv.read_mutate_writeback_flush_aligned(ipa, self.hv.data_flip_times_per_hit)
                        except Exception as e:
                            print(e)
                else:# 
                    print(f"[*] fuzz addr id:{self.ipa_hook_manager.va_range_list[pos].id}")
                    self.hv.read_mutate_writeback_flush_aligned(ipa, self.hv.data_flip_times_per_hit)
            if self.ipa_hook_manager.va_range_list[pos].on_demand_of_hit_bt: # 
                # print("[*] first hit, print bt")
                self.hv.bt()
                self.hv.ipa_hook_manager.va_range_list[pos].on_demand_of_hit_bt = False
        else:
            print("[-] addr translation fails", hex(far))
        return True
    
    def end_this_rar_cycle(self):
        # pass
        self.ipa_hook_manager.specified_fuzz_addr_range_by_id = -1 # 
        self.ipa_hook_manager.ipa_hook_total_hit_count = 0
        self.ipa_hook_manager.user_far.clear()
        self.moniter_pid_set.clear()
        self.reset_status()
        self.kernel_mutate_data_on_ipahook = False
class mode1FuzzManager(IPAFuzzManager):
    # -------------------------------------------- mem_fuzz_mode = 1，
        # mode1 
    if_clear_the_user_far_after_syscall = False
    print_verbose_info = False
    only_add_user_write = True
    kernel_mutate_data_on_ipahook = True
    
    def __init__(self, ipa_hook_manager, hv=None):
        self.mem_fuzz_mode = 1
        super().__init__(ipa_hook_manager, hv)
    
    def end_this_rar_cycle(self):
        # pass
        self.ipa_hook_manager.specified_fuzz_addr_range_by_id = -1
        self.ipa_hook_manager.user_far.clear()
        self.moniter_pid_set.clear()
        self.reset_status()
        # self.kernel_mutate_data_on_ipahook = False
        
    def end_this_mutate_cycle(self):
        pass
    
    def fuzzprocess(self):
        # return super().fuzzprocess()
        print("user_far:", self.ipa_hook_manager.user_far)
    
    def action_on_ipa_hook_invoke(self, ctx):
        return self.handle_ipa_hook_add_user_accessed_addr(ctx, self.only_add_user_write)
    
    def handle_ipa_hook_add_user_accessed_addr(self, ctx, only_add_user_write=True):
        """
        
            
        
        
            
        """
        self.ipa_hook_manager.ipa_hook_total_hit_count += 1
        # if self.ipa_hook_total_hit_count % self.add_user_far_per_this_cnt != 1:# 
        #     return True
        pid = self.hv.p.get_pid()
        if not self.judge_if_pid_in_moniter_pid_set(pid, ctx):
            return True
        self.kernel_consecutive_invoke = 0 # judge_if_pid_in_moniter_pid_set
        esrISS = ctx.esr.ISS
        far = ctx.far
        is_write = esrISS & (1<<6) # esr.WnR BIT(6)
        
        pos, ipa_hook_memory_range = self.ipa_hook_manager.add_hit_count(far, ctx.elr, is_write)
        # 
        if ctx.elr & 0x8000000000000000 == 0:
            if is_write or not self.only_add_user_write:
                self.ipa_hook_manager.user_far.add(far) # 
        return True
    
    def action_on_syscall_invoke(self):
        if self.print_verbose_info:
            print("[*] syscall invoke")
        if self.kernel_mutate_data_on_ipahook == False:
            return True
        return self.random_mutate_all_addr() # 
        # return self.mutate_user_accessed_addr()

    def random_mutate_all_addr(self):# 
        if len(self.ipa_hook_manager.va_range_list) == 0:
            return True
        poss = [random.randint(0, len(self.ipa_hook_manager.va_range_list)-1) for _ in range(self.random_choose_user_far_num)]
        if self.print_verbose_info:
            print("[*] random_mutate_all_addr: indexes: ", poss)
        for pos in poss:
            ipa_hook_memory_range = self.ipa_hook_manager.va_range_list[pos]
            # 
            try:
                va = random.randint(ipa_hook_memory_range.va_start, ipa_hook_memory_range.va_end)
            except Exception as e:
                print(e)
                continue
            ipa = self.hv.p.hv_translate(va, True, False)
            if ipa == None or ipa == 0 or ipa == -1:
                if self.print_verbose_info:
                    print("[-] random_mutate_all_addr: ipa is ", ipa)
                continue
            if self.maybe_mutate(self.hv.data_flip_rate):
                # self.hv.read_mutate_writeback_flush_aligned(ipa, self.hv.data_flip_times_per_hit)
                self.data_mutator.flip_with_bound(ipa_hook_memory_range, mutate_times = self.hv.data_flip_times_per_hit) # 
                print(f"[*] random_mutate_all_addr: {ipa_hook_memory_range.id}, {hex(va)}")

    def mutate_user_accessed_addr(self):
        # if self.hv.p.judge_if_next_syscall(self.ctx.cpu_id) == True:
            # self.accessed_addr_during_one_syscall.clear()
            # print("-----------------------syscall barriar-----------------------")
            # self.ipa_hook_manager.user_far.clear() # 
        # 
        # mutated_ids = list()
        # 
        if len(self.ipa_hook_manager.user_far) == 0 or self.kernel_mutate_data_on_ipahook == False:
            if self.print_verbose_info:
                print("[*] skip mutate, user_far is empty or kernel_mutate_data_on_ipahook is False")
            return True
        
        far = random.sample(list(self.ipa_hook_manager.user_far), k=self.random_choose_user_far_num) # 
        # for far in self.ipa_hook_manager.user_far:
        for addr in far:
            ipa = self.hv.p.hv_translate(addr, True, False)
            pos, ipa_hook_memory_range = self.ipa_hook_manager.lookup_va_range_by_ipa(ipa)
            if pos != None:
                if self.maybe_mutate(self.hv.data_flip_rate):
                    if self.print_verbose_info:
                        print(f"[*] syscall mutate: {ipa_hook_memory_range}")
                    # mutated_ids.append((ipa_hook_memory_range.id, hex(far)))
                    self.hv.read_mutate_writeback_flush_aligned(ipa, self.hv.data_flip_times_per_hit)
            # if len(mutated_ids) > 0:
                print("[*] mutate done id: ", (ipa_hook_memory_range.id, hex(addr)))
            else: 
                print(f"[-] mutate_user_accessed_addr: pos is None ? where far={hex(far)}, ipa={hex(ipa)}")
        if self.if_clear_the_user_far_after_syscall:
            self.ipa_hook_manager.user_far.clear()
        return True
       
class mode2FuzzManager(IPAFuzzManager):
    # -------------------------------------------- mem_fuzz_mode = 2，
    # 
    only_add_user_write = True
    ipa_2_hook_memory_range_map = dict()
    randomly_chosen_user_far_quantity = 10
    mutate_per_syscall = 1 # 
    mode2_syscall_cycle_greater_than_this_threshold_then_mutaate = 10 * mutate_per_syscall
    # 
    def __init__(self, ipa_hook_manager, hv=None):
        self.mem_fuzz_mode = 2
        super().__init__(ipa_hook_manager, hv)

    def end_this_rar_cycle(self):# 
        # pass
        # self.hv.ipa_hook_total_hit_count = 0
        self.kernel_mutate_data_on_ipahook = True
        self.reset_status()
        
    def end_this_mutate_cycle(self):
        pass
    
    def action_on_ipa_hook_invoke(self, ctx):
        self.ipa_hook_manager.ipa_hook_total_hit_count += 1
        pid = self.hv.p.get_pid()
        if not self.judge_if_pid_in_moniter_pid_set(pid, ctx):
            return True
        self.kernel_consecutive_invoke = 0 # judge_if_pid_in_moniter_pid_set
        esrISS = ctx.esr.ISS
        far = ctx.far
        is_write = esrISS & (1<<6) # esr.WnR BIT(6)
        
        pos, ipa_hook_memory_range = self.ipa_hook_manager.add_hit_count(far, ctx.elr, is_write)
        self.ipa_hook_manager.add_hit_pc(far, ctx.elr, is_write)
        # 
        if ctx.elr & 0x8000000000000000 == 0:
            if is_write or not self.only_add_user_write:
                self.ipa_hook_manager.user_far.add(far & 0xFFFFFFFFFFFFC000) # 
        return True
    
    def action_on_syscall_invoke(self):
        if self.syscall_cycle == self.mode2_syscall_cycle_greater_than_this_threshold_then_mutaate:
            # self.hv.derarall(delete_va_list=False) # 
            self.ipa_hook_manager.unhook_all(delete_va_list=False)
            self.add_all_16kb_to_mutate() # 
            self.ipa_hook_manager.user_far_list = list(self.ipa_hook_manager.user_far)
        self.syscall_cycle += 1
        self.kernel_mutate_data_on_ipahook = True
        if self.syscall_cycle > self.mode2_syscall_cycle_greater_than_this_threshold_then_mutaate and self.syscall_cycle % self.mutate_per_syscall == 0:
            self.mutate_user_accessed_addr()
            # self.syscall_cycle = 0

    def mutate_user_accessed_addr(self):
        if self.kernel_mutate_data_on_ipahook:
            if len(self.ipa_hook_manager.user_far) == 0:
                print("[-] mutate_user_accessed_addr: user_far is empty!!!!plz recheck")
                return True
            # 
            far_list = random.choices(self.ipa_hook_manager.user_far_list, k=self.randomly_chosen_user_far_quantity) 
            for far in far_list:
                ipa = self.hv.p.hv_translate(far, True, False)
                pos, ipa_hook_memory_range = None, None
                if ipa not in self.ipa_2_hook_memory_range_map:
                    pos, ipa_hook_memory_range = self.ipa_hook_manager.lookup_va_range_by_ipa(ipa)
                    self.ipa_2_hook_memory_range_map[ipa] = (pos, ipa_hook_memory_range)
                else:
                    pos, ipa_hook_memory_range = self.ipa_2_hook_memory_range_map[ipa]
                if pos != None:
                    if self.maybe_mutate(self.hv.data_flip_rate):
                        print(f"[*] syscall mutate: {hex(far)}, pos:{pos}, ipa_hook_memory_range:{ipa_hook_memory_range}")
                        self.hv.read_mutate_writeback_flush_aligned(ipa, self.hv.data_flip_times_per_hit)
    
    def add_all_16kb_to_mutate(self):
        for i in self.ipa_hook_manager.va_range_list:
            if i.va_end - i.va_start == 0x4000:
                print(f"[*] add 16kb to user_far: {i}")
                self.ipa_hook_manager.user_far.add(i.va_start)
                
    def reset_status(self):
        self.syscall_cycle = 0
        self.kernel_mutate_data_on_ipahook = False
        # self.hv.derarall() ，
        self.ipa_hook_manager.unhook_all()
        self.ipa_hook_manager.user_far.clear()
        self.ipa_hook_manager.user_far_list.clear()
        
    def fuzzprocess(self):
        print("user_far:", self.ipa_hook_manager.user_far)
        print(f"syscall_cycle: {self.syscall_cycle}, kernel_mutate_data_on_ipahook: {self.kernel_mutate_data_on_ipahook}, mode2_syscall_cycle_greater_than_this_threshold_then_mutaate: {self.mode2_syscall_cycle_greater_than_this_threshold_then_mutaate}, mutate_per_syscall: {self.mutate_per_syscall}\n  syscall_cycle % mutate_per_syscall = {self.syscall_cycle % self.mutate_per_syscall}")

class mode2FuzzManager_v2(mode2FuzzManager):
    # 
    # 
    #   
    #       
    #   
    def __init__(self, ipa_hook_manager, hv=None):
        super().__init__(ipa_hook_manager, hv)
        
    def end_this_rar_cycle(self):# 
        # pass
        # self.hv.ipa_hook_total_hit_count = 0
        self.kernel_mutate_data_on_ipahook = True
        self.reset_status()
        
    def end_this_mutate_cycle(self):
        pass
    
    # def action_on_ipa_hook_invoke(self, ctx): 
    def action_on_syscall_invoke(self):
        if self.syscall_cycle == self.mode2_syscall_cycle_greater_than_this_threshold_then_mutaate:
            # self.hv.derarall(delete_va_list=False) # 
            self.ipa_hook_manager.unhook_all(delete_va_list=False)
            self.add_all_16kb_to_mutate() # 
            self.ipa_hook_manager.user_far_list = list(self.ipa_hook_manager.user_far)
        self.syscall_cycle += 1
        self.kernel_mutate_data_on_ipahook = True
        if self.syscall_cycle > self.mode2_syscall_cycle_greater_than_this_threshold_then_mutaate and self.syscall_cycle % self.mutate_per_syscall == 1:
            self.mutate_user_accessed_addr()

def test_range_search():
    va_range_list = [
        IPAHookMemoryRange(0x1000, 0x2000, "RW"),
        IPAHookMemoryRange(0x6000, 0x8000, "RW"),
        IPAHookMemoryRange(0x3000, 0x4000, "RO"),
    # more MemoryRange objects...
    ]
    va_range_list.sort()

    # 
    va = 0x6001

    # 
    index = bisect.bisect_right(va_range_list, IPAHookLookUp(va)) - 1
    print("index:", index, va in va_range_list[index])
    if (index != len(va_range_list)):
        print(f"va_range_list[{index}]:", va_range_list[index])
    if index != len(va_range_list) and va in va_range_list[index]:
        print(f"va {hex(va)} 
    else:
        print(f"va {hex(va)} 

def test_ipa_range_manager():
    lines = """IOKit 1082d8000 1082dc000
IOKit 1082fc000 108300000
IOKit 108790000 108794000
IOKit 10879c000 1087a0000
IOSurface 109fbc000 109ff0000
IOKit 10a608000 10a60c000
IOKit 10a610000 10a614000
IOKit 10a618000 10a61c000
IOKit 10a630000 10a634000
IOKit 10a638000 10a63c000"""
    manager = IPAHookManager()
    lines = lines.split("\n")
    manager.add_ranges(lines)
    print("va_range_list: ", manager.va_range_list)
    index, line = manager.lookup_va_range_by_ipa(manager.va2phy_aligned(0x109fbc000))
    manager.va_range_list[index].kernel_load_count += 2
    manager.lookup_va_range_by_ipa(manager.va2phy_aligned(0x1082fc000))
    manager.va_range_list[index].kernel_load_count += 1
    manager.delete_item_by_id(1)
    print("after delete", manager.print_address_range_hitcount())
    manager.unhook_by_hitcount(4)
    print("after unhook", manager.print_address_range_hitcount())
        
if __name__ == "__main__":
    ipa_data_mutator = IPAHookMutator()
    data = b"Some binary data"
    mutated_data = ipa_data_mutator.flip(data, 0)
    print(mutated_data)
    test_ipa_range_manager()
    
    