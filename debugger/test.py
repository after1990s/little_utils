import _debugger

debugger = _debugger.debugger();
pid = raw_input("pid:");
debugger.attach(int(pid));
thread_list = debugger.enumerate_threads();
for t in thread_list:
    t_context = debugger.get_thread_context(t);
    print "tid:%08x" % t;
    print "eax:%08x" % t_context.Eax;
printf_addr = debugger.func_resolve("msvcrt.dll", "printf");
debugger.bp_set(printf_addr);
debugger.run();