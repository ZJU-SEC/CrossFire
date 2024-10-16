import idc
import idaapi
import idautils
import ida_name
import ida_funcs
import ida_hexrays
import re
import shutil
import os

# context.arch = "aarch64"
# context.os = "linux"
# context.endian = "little"
# context.word_size = 64


platform = "macOS" 
INST_Kernel = False
INST_Kext = True

INSTUMNET_KEXT_NAME = ["com.apple.iokit.IOGPUFamily", "com.apple.iokit.IOGraphicsFamily", "com.apple.iokit.IOPCIFamily", "com.apple.AGXG13G", "com.apple.AGXFirmwareKextRTBuddy64", "com.apple.AGXFirmwareKextG13GRTBuddy", "com.apple.iokit.IOAVFamily","com.apple.iokit.IOMobileGraphicsFamily", "com.apple.driver.AppleFirmwareKit", "com.apple.driver.AppleH11ANEInterface", "com.apple.driver.DCPAVFamilyProxy", "com.apple.driver.AppleDCP", "com.apple.iokit.IOMobileGraphicsFamily-DCP", "com.apple.driver.IOSlaveProcessor", "com.apple.driver.AppleAVD", "com.apple.driver.AppleAVE2"] # evaluation


origin_file = r"kernelcache.macho_backup"
file =   r"kernelcache.macho"
if platform == "macOS":
    print("macOS, ", os.getcwd())
    origin_file = os.getcwd()+r"\kernelcache.macho_backup"
    file = os.getcwd()+r"\kernelcache.macho"

ass_instrument   = b'\xc2\x04\x00\xd4'
cnt_instrument_again = 0
totalBB = 0
print(r"cp "+origin_file+" "+file)
if os.path.exists(file):
    print('remove',file)
    os.remove(file)
shutil.copyfile(origin_file, file)
print('copyed ', origin_file, 'to ', file)
f = open(file, "r+b")
for seg in idautils.Segments():
    seg_name = idc.get_segm_name(seg)
    seg_start = idc.get_segm_start(seg)
    seg_end = idc.get_segm_end(seg)
    go = False
    for ekn in INSTUMNET_KEXT_NAME:
        if seg_name.startswith(ekn):
            go = True
            break
    if not go:
        continue
    if not seg_name.endswith("__text"):
        continue
    
    if seg_name.startswith("com.apple.kernel"):
        if INST_Kernel == False:
            continue
    else:
        if INST_Kext == False:
            continue
    BBCount = 0
    cnt_instrument_again = 0
    pa_count = 0
    for func_addr in idautils.Functions(seg_start, seg_end):
        func_name = idc.get_func_name(func_addr)
        if seg_name.startswith("com.apple.kernel"):
            continue
        func_end  = idc.find_func_end(func_addr)

        f_blocks = idaapi.FlowChart(idaapi.get_func(func_addr))
        f_blocks_len = f_blocks.size
        for i in range(f_blocks_len):
            bb = f_blocks[i]
            target = bb.start_ea
            if seg_name.startswith("com.apple.kernel"):
                continue
            else:
                if target<seg_start or target>seg_end:
                    # print("[-] no instrument out-scope -> target: ", hex(target), "func_addr: ", hex(func_addr), "func_end: ", hex(func_end))
                    BBCount -= 1
                    continue
            curr_addr = bb.start_ea
            seg = ""
            disasm_seg = ""
            while curr_addr < bb.end_ea:
                inst =  idc.GetDisasm(curr_addr)
                if inst.startswith("PAC") or inst.startswith("AUT") or inst.startswith("NOP"): 

                    pa_count += 1
                    break
                curr_addr += 4
            offset = idaapi.get_fileregion_offset(target)  
            f.seek(offset, 0)
            f.write(ass_instrument)
            cnt_instrument_again = cnt_instrument_again+1
            
        BBCount = BBCount + f_blocks_len
        #if BBCount % 1000 == 0:
        #    print("Progess: {}".format(BBCount/totalBB))
    if BBCount != 0:
        print(seg_name, hex(seg_start), hex(seg_end))
        print("[+] total instrument : {} of {} BBs in {}, single step basic block ratio: {:.2%} ".format(cnt_instrument_again, BBCount, seg_name, cnt_instrument_again/BBCount))
        print("[+] kextfuzz instrument : {} of {} BBs in {}, single step basic block ratio: {:.2%} ".format(pa_count, BBCount, seg_name, pa_count/BBCount))

f.close()
print("[+] done")