import json
from ctypes import *
from ctypes.wintypes import *
import win32security
import win32api;

def AdjustPrivilege( priv ):
    flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
    htoken =  win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
    id = win32security.LookupPrivilegeValue(None, priv)
    newPrivileges = [(id, win32security.SE_PRIVILEGE_ENABLED)]
    win32security.AdjustTokenPrivileges(htoken, 0, newPrivileges)


def ReadMemoryAt(address, pid, length, size):
    
    OpenProcess = windll.kernel32.OpenProcess
    ReadProcessMemory = windll.kernel32.ReadProcessMemory
    GetLastError = windll.kernel32.GetLastError
    
    CloseHandle = windll.kernel32.CloseHandle
    
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_OPERATION = 0x0008
    
    PROCESS_ALL_ACCESS = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION

    address = address;
    
    str_ = b"X"*(size * length);
    
    buffer_ = c_char_p(str_);
    bufferSize = len(buffer_.value)
    bytesRead = c_ulong(0)
    
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if processHandle == 0:
        error = GetLastError();
        return;
    if ReadProcessMemory(processHandle, address, buffer_, bufferSize, byref(bytesRead)):
        #print "Success:"
        pass;
    else:
        error = GetLastError();
        print "Failed."
        exit(0);
    
    CloseHandle(processHandle)
    return str_;


def myDigit(m):
    hexed=("00"+hex(ord(m))).replace("x","");
    hexed=hexed[-2:];
    return hexed;
    
def doit():
    AdjustPrivilege("seDebugPrivilege");
    data = json.load(open('_internal_database_d5w98f4a1.txt'));
    
    items = [];
    
    for item in data:
        if item["version"]["name"] == "1.16.1":
            items.append({"Addr":"0x" + str(item["address"]), "Name":str(item["name"]), "Size":str(item["size"]), "Length":str(item["length"])});

    with (open("Output.txt", "w")) as text_file: 
        for item in items:
            
            address = int(item["Addr"], 16);
            name = item["Name"];
            size = int(item["Size"]);
            length = int(item["Length"]);
            #print("Reading "+str(size*length));
            mem = ReadMemoryAt(address, 1780, length, size)
            
            #            _defaults[0x006D5BBE] = "00000100";
            
            #res = "";
            text_file.write ( "            _defaults["+str(item["Addr"])+"] = \"");
            text_file.write(myDigit(mem[0:1]));
            for m in mem[1:]:
                b=myDigit(m);
                text_file.write(b);
            text_file.write("\";\n");


    
doit();
