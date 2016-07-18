# -*- coding: utf-8 -*-  
#!/bin/python
def codegen(paratype, paraname):
    string_code_raw = '''

    private {0} m_{1};
    public {0} {1}
        {{
            get
            {{
                return m_{1};
            }}
            set
            {{
                m_{1} = value;
                if (PropertyChanged != null)
                    PropertyChanged.Invoke(this, new PropertyChangedEventArgs("{1}"));
            }}
        }}'''.format(paratype, paraname)
 
    print(string_code_raw);
def main():
    codegen('String', 'Host_0');
    codegen('String', 'Host_1');
    codegen('String', 'Host_2');
    codegen('String', 'Host_3');
    codegen('Int32', 'HostPort_0');
    codegen('Int32', 'HostPort_1');
    codegen('Int32', 'HostPort_2');
    codegen('Int32', 'HostPort_3');

    codegen('bool', 'VmCheck');
    codegen('Int32', 'VmCpu');
    codegen('Int32', 'VmMemory');
    codegen('Int32', 'VmResHeight');
    codegen('Int32', 'VmResWidth');
    codegen('Int32', 'VmDisk');
    
    codegen('String', 'NoticeTitle');
    codegen('String', 'NoticeContent');
    codegen('String', 'Notice');
    codegen('String', 'TargetFilePath');
    codegen('String', 'TimeMon');
    codegen('String', 'TimeTue');
    codegen('String', 'TimeWed');
    codegen('String', 'TimeThu');
    codegen('String', 'TimeFri');
    codegen('String', 'TimeSat');
    codegen('String', 'TimeSun');
    codegen('bool', 'TimeCheck');
if __name__=='__main__':
    main();
