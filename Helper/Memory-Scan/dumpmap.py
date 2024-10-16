import subprocess
import re
import socket
import sys
import os
import signal


    
class VM_ENTRY:
    def __init__(self, region_type,start,end,VSIZE,RSDNT,PRT,SHRMOD):
        self.region_type=region_type
        self.start=start
        self.end=end
        self.vsize=VSIZE
        self.rsdnt=RSDNT
        self.prt=PRT
        self.shrmod=SHRMOD

    def isfullfil(self):
        
        return f"Hello, my name is {self.name}!"
def parse2VMEntryObj(line_content):
    pattern = r'^(.*)\s+(\S+)\s+\[\s*(\S+)\s+(\S+).*?(SM=\S+)'
    
    match = re.match(pattern, line_content)
    #print(line_content)

    if match:
        
        regionType = match.group(1)  
        address_range = match.group(2)  
        vsize = match.group(3)  
        rsize = match.group(4)  
        sharemode = match.group(5)  

        return (regionType,address_range,vsize,rsize,sharemode)
    else:
        print("No match found")
        return -1

def parse_vmmapContent(content):
    
    ret_string=""
    filter_memory_list = ["IOAccelerator", "IOSurface"]#"IOKit", "IOSurface" 
    vmmmap_lines=content.splitlines()
    writable_start=-1
    NoWriteable_start=-1
    Legend_start=-1

    vm_entrys=[]
    for i in range(len(vmmmap_lines)):
        if writable_start==-1 and "==== W" in vmmmap_lines[i]:
            writable_start=i+2
            NoWriteable_start=-1
            continue
        if NoWriteable_start==-1 and "==== No" in vmmmap_lines[i]:
            NoWriteable_start=i+2
            continue
        if NoWriteable_start==-1 and "==== Lege" in vmmmap_lines[i]:
            break
        if NoWriteable_start!=-1 and NoWriteable_start<=i:
            continue
            '''
            if vmmmap_lines[i]!="":
                parseRET=parse2VMEntryObj(vmmmap_lines[i])
                if parseRET!=-1:
                    regionType=parseRET[0]
                    address_range=parseRET[1]
                    vsize=parseRET[2]
                    rsize=parseRET[3]
                    sharemode=parseRET[4]
                    if vsize!=rsize:
                        print("No kernel addr")
                        #print(regionType,address_range,vsize,rsize,sharemode.split("=")[1])
                        continue
                    if regionType in filter_memory_list and sharemode.split("=")[1]=="SHM":
                        print(regionType,address_range)
                else:
                    print("fail to parse vmmmap ")
            '''

        if writable_start!=-1 and writable_start<=i:
            if vmmmap_lines[i] != "":
                parseRET=parse2VMEntryObj(vmmmap_lines[i])
                if parseRET!=-1:

                    regionType=parseRET[0].strip()
                    address_range=parseRET[1].strip()
                    vsize=parseRET[2].strip()
                    rsize=parseRET[3].strip()
                    sharemode=parseRET[4].strip()
                    #print(regionType, address_range, vsize, rsize, sharemode.split("=")[1])
                    va_start = int(address_range.split("-")[0], 16)
                    va_end = int(address_range.split("-")[1], 16)
                    # if va_end - va_start > 0x4000:
                    #     continue
                    if vsize!=rsize:
                        #print("No kernel addr")
                        #print(regionType,address_range,vsize,rsize,sharemode.split("=")[1])
                        # continue
                        pass
                    if regionType in filter_memory_list and sharemode.split("=")[1]=="SHM":
                        ret_string+=regionType.replace(" ", "")+" "+address_range.split("-")[0]+" "+address_range.split("-")[1]+"\n"
                else:
                    print("fail to parse vmmmap ")
    return ret_string



def filter_vmmapContent(content):

    return parse_vmmapContent(content)

def run_vmmap(pid):
    
    command = ['vmmap', str(pid)]

    try:
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        
        #print("Command output:")
        return result.stdout

        
        

    except subprocess.CalledProcessError as e:
        
        print("Error executing command:", e)
        return -1


def server_program():
    
    host = socket.gethostname()
    port = 52432  

    server_socket = socket.socket()  
    server_socket.bind((host, port))  

    
    server_socket.listen(1)


    while True:
        print("wait...")
        conn, address = server_socket.accept()  
        print("from: " + str(address))
        while True:
            print("wait for data!")
            
            data = conn.recv(1024).decode()
            print("data:",data)
            if not data:
                
                break
            vmmap_content = run_vmmap(data)
            if vmmap_content != -1:
                send_data=filter_vmmapContent(vmmap_content)
            else:
                send_data="vmmap fail"
            #data = input(" -> ")
            print("send data:",send_data)
            conn.send(send_data.encode())  

    conn.close()  

def get_vmmap_result(pid):
    vmmap_content = run_vmmap(pid)
    if vmmap_content != -1:
        send_data=filter_vmmapContent(vmmap_content)
    else:
        send_data="vmmap fail"
    #data = input(" -> ")
    print(send_data)

def get_pid_by_name(name):
    command = ['pgrep', name]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
    
        if "\n" in result.stdout:
            pids = result.stdout[0:-1].split("\n") 
        print(name, ": pids", pids, ": return ", pids[-1])
        pid = pids[-1]
        return int(pid)
    except Exception as e:
        return -1
    
def sigint_handler(signal, frame):
    pid = get_pid_by_name("ffmpeg")
    os.system("kill -9 "+str(pid))
    sys.exit(0)

def get_res_by_name():
    name = ""
    if len(sys.argv) > 1:
        # print(sys.argv[1])
        name = sys.argv[1]
    else:
        print("Usage: python3 dumpVMMAP.py <process name>")
        exit(0)
    
    command = ['pgrep', name]
    result = subprocess.run(command, capture_output=True, text=True, check=True)
    # server_program()
    if "\n" in result.stdout:
        pids = result.stdout[0:-1].split("\n") 
        # print("pids", pids)
        pid = pids[-1]
        get_vmmap_result(int(pid))
    else:
        get_vmmap_result(int(result.stdout))

def get_res_by_pid():
    pid = ""
    if len(sys.argv) > 1:
        # print(sys.argv[1])
        pid = sys.argv[1]
    else:
        print("Usage: python3 dumpmap.py <process pid>")
        exit(0)
    get_vmmap_result(int(pid))
    
if __name__ == '__main__':
    
    signal.signal(signal.SIGINT, sigint_handler)
    get_res_by_pid()



'''
pid = int(input())
vmmap_content=run_vmmap(pid)
if vmmap_content!=-1:
    filter_vmmapContent(vmmap_content)
'''