from pydbg import *
from pydbg.defines import *
import utils 
import threading
import time
import sys

class snapshotter(object):
    def __init__(self, exe_path):
        self.exe_path = exe_path;
        self.pid = None;
        self.dbg = None;
        self.running = True;
        pydbg_thread = threading.Thread(target = self.start_debugger);
        pydbg_thread.setDaemon(0);
        pydbg_thread.start();
        while self.pid==None:
            time.sleep(1);
        monitor_thread = threading.Thread(target=self.monitor_debugger);
        monitor_thread.setDaemon(0);
        monitor_thread.start();
        
    def monitor_debugger(self):
        while(self.running==True):
            input = raw_input("Enter: 'snap','restore' or 'quit'");
            input = input.lower().strip();
            
            if input=="quit":
                print("[*] exiting the snapshotter.");
                self.running = False;
                self.dbg.ternimate_process();
            elif input=="snap":
                self.dbg.suspend_all_threads();
                self.dbg.process_snapshot();
                self.dbg.resume_all_threads();
            elif input=="restore":
                self.dbg.suspend_all_threads();
                self.dbg.process_restore();
                self.dbg.resume_all_threads();
    
    def start_debugger(self):
        self.dbg = pydbg();
        pid = self.dbg.load(self.exe_path);
        self.pid = self.dbg.pid;
        self.dbg.run();
    
exe_path = "C:\\Windows\\SysWOW64\\calc.exe";
snapshotter(exe_path);