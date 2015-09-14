from ctypes import *
from _debugger_defines import *

kernel32 = windll.kernel32

class debugger():
    def __init__(self):
        self.hProcess = None;
        self.Pid = None;
        self.debugger_active = False;
        self.h_thread = None;
        self.context = None;
        self.breakpoints = {};
        pass
    
    def read_process_memory(self,address, length):
        data = "";
        read_buf = create_string_buffer(length);
        count = c_ulong(0);
        if not kernel32.ReadProcessMemory(self.h_process, address, read_buf, length, byref(count)):
            return False;
        else:
            data += read_buf.raw;
            return data;
    def write_process_memory(self, address, data):
        count = c_ulong(0);
        length = len(data);
        c_data = c_char_p(data[count.value:]);
        if not kernel32.WriteProcessMemory(self.h_process, address, c_data, length, byref(count)):
            return False;
        else:
            return True;
    
    def bp_set(self,address):
        if not self.breakpoints.has_key(address):
            try:
                original_byte = self.read_process_memory(address, 1);
                self.write_process_memory(address, "\xCC");
                self.breakpoints[address] = original_byte;
            except:
                return False;
        return True;
    
    def load (self, path_to_exe):
        creation_flags = DEBUG_PROCESS;
        
        startupinfo = STARTUPINFO();
        process_infomation = PROCESS_INFORMATION();
        
        startupinfo.dwFlags = 0x01;
        process_infomation.wShowWindow = 0x0;
        
        startupinfo.cb = sizeof(startupinfo);
        
        if kernel32.CreateProcessA(path_to_exe,
                                   None,
                                   None,
                                   None,
                                   None,
                                   creation_flags,
                                   None,
                                   None,
                                   byref(startupinfo),
                                   byref(process_infomation)):
            print "[*] launched the process!";
            print "[*] PID %d" % process_infomation.dwProcessId;
            self.hProcess = self.open_process(process_infomation.dwProcessId);
        else:
            print "[*] Error: %0x%08x" % kernel32.GetLastError();
        
    def open_process(self, pid):
        return kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid);
    
    def open_thread(self, tid):
        h_thread = kernel32.OpenThread(THREAD_ALL_ACCESS, None, tid);
        if h_thread is not None:
            return h_thread;
        else:
            print "[*] Can't Open thread %d" % tid;
            return False;
    
    def enumerate_threads(self):
        thread_entry = THREADENTRY32();
        thread_list = [];
        snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, self.Pid);
        if snapshot is not None:
            thread_entry.dwSize = sizeof(thread_entry);
            success = kernel32.Thread32First(snapshot, byref(thread_entry));
        while success:
            if thread_entry.th32OwnerProcessID == self.Pid:
                thread_list.append(thread_entry.th32ThreadID);
            success = kernel32.Thread32Next(snapshot, byref(thread_entry));
        kernel32.CloseHandle(snapshot);
        return thread_list;
    
    def get_thread_context (self, tid=None, h_thread=None):
        context = CONTEXT();
        context.ContextFlags = CONTEXT_FULL|CONTEXT_DEBUG_REGISTERS;
        h_thread = self.open_thread(tid);
        if kernel32.GetThreadContext(h_thread, byref(context)):
            kernel32.CloseHandle(h_thread);
            return context;
        else:
            return False;
        
    def attach (self, pid):
        self.Pid = int(pid);
        self.hProcess = self.open_process(self.Pid);
        if kernel32.DebugActiveProcess(self.Pid):
            self.debugger_active = True;
          
        else:
            print "[*] unable to attach to the process:%d " % kernel32.GetLastError();
    def get_debug_event(self):
        debug_event = DEBUG_EVENT();
        continue_status = DBG_CONTINUE;
        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            self.h_thread = self.open_thread(debug_event.dwThreadId);
            self.context = self.get_thread_context(debug_event.dwThreadId);
            print("Event Code:%d Thread ID %d" % (debug_event.dwDebugEventCode, debug_event.dwThreadId));
            if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                exception =  debug_event.u.Exception.ExceptionRecord.ExceptionCode;
                self.exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;
                if exception==EXCEPTION_ACCESS_VIOLATION:
                    print("Access Viloation Detected.");
                elif exception == EXCEPTION_BREAKPOINT:
                    continue_status = self.exception_handler_breakpoint();
                elif exception == EXCEPTION_GUARD_PAGE:
                    print("Guard Page Access Detected");
                elif exception== EXCEPTION_SINGLE_STEP:
                    print("Single Stepping");
                else:
                    pass
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, continue_status); 
    def exception_handler_breakpoint(self):
        print("[*] Inside Breakpoint handler.\naddress:0x%08x"%self.exception_address);
        return DBG_CONTINUE;   
        
    def run(self):
        while self.debugger_active == True:
            self.get_debug_event();
            
    
    def detach(self):
        if kernel32.DebugActiveProcessStop(self.Pid):
            print "[*] finished debugging. Exiting...";
            return True;
        else:
            print "[*] Error";
            return False;
    def func_resolve(self,dll, function):
        handle = kernel32.GetModuleHandleA(dll);
        address = kernel32.GetProcAddress(handle, function);
        kernel32.CloseHandle(handle);
        return address;