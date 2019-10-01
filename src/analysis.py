import os
import wmi
import subprocess
import platform
import time
import win32api
import io
import re

import settings
from pefile_analysis import pefile_analysis
from byte_analysis import byte_analysis

def host_info():
    """
    1. 取得掃描端點之硬體、軟體及作業系統資訊(wmi)
    2. 判斷檔案是否註冊於windows系統機碼，開機可自動啟動(wmi) 
    """
    w = wmi.WMI()
    host_info_dict = {}
    
    x = subprocess.check_output('wmic csproduct get UUID')
    host_info_dict['deviceUUID']= x.decode("utf-8").replace('UUID','').replace('\n','').replace('\r','').replace(' ','')
    host_info_dict['deviceName'] = platform.node()
    host_info_dict['os'] = "{}-{}".format(platform.system(),platform.version())
    host_info_dict['processor'] = platform.processor()
    host_info_dict['cpu'] = platform.machine()
    host_info_dict['userName'] = os.getlogin()
    
    totalSize = 0
    for memModule in w.Win32_PhysicalMemory():
        totalSize += int(memModule.Capacity)
    host_info_dict['memoryCapacity'] = totalSize/1048576
    

    registry_list = []
    for s in w.Win32_StartupCommand(): 
        registry_list.append((s.Location, s.Caption, s.Command))
    host_info_dict['registry_list'] = registry_list

    return host_info_dict

def analysis_summary(filepath):
    analysis_dict = {}
    analysis_dict.update(file_info(filepath))
    analysis_dict.update(sigcheck(filepath))
    analysis_dict.update(pefile_analysis(filepath))
    analysis_dict.update(byte_analysis(filepath))
    return analysis_dict

def file_info(filepath):
    created = time.ctime(os.path.getctime(filepath))   # create time
    last_modified = time.ctime(os.path.getmtime(filepath))   # modified time
    last_accessed = time.ctime(os.path.getatime(filepath))   # access time
    file_size = os.stat(filepath).st_size
    file_attribute = win32api.GetFileAttributes(filepath)
    file_info_dict = {
        'file_name':filepath,
        'file_size':file_size,
        'file_attribute':file_attribute,
        'created':created,
        'last_modified':last_modified,
        'last_accessed':last_accessed

    }
    return file_info_dict

def sigcheck(filepath):
    sigcheck_path = os.path.join(settings.resourceDir,'sigcheck64')
    filepath = filepath.replace("\\", "//")

    args = [sigcheck_path,'-i', '-l', '-nobanner',filepath]
    pipe = subprocess.Popen(args, stdout=subprocess.PIPE)
    sigcheck_output = pipe.communicate()[0]
    sigcheck_str = ""

    sigcheck_str = sigcheck_output.decode('utf-8',"replace")
    #print(sigcheck_str)
    sigcheck_str = sigcheck_str.replace('\r\n\t'+'  ', '\n<Certificate>')
    sigcheck_str = sigcheck_str.replace('\r\n\t\t', '\n<Certi Info>')
    sigcheck_str = sigcheck_str.replace('\r\n\t', '\n<attribute>')
    sigcheck_str = sigcheck_str.replace('\t','')
    sigcheck_str += '<end>'
    #print(sigcheck_str)

    sigcheck_dict = {}
    
    for attr in re.findall('<attribute>.*',sigcheck_str):
        attr = attr.replace('<attribute>','')
        attribute_name, attribute_val = attr.split(":",1)
        sigcheck_dict["sigcheck_"+attribute_name] = attribute_val
    
    sigcheck_str_list = [line.replace('\n','').replace('\r','') for line in io.StringIO(sigcheck_str).readlines()]
    signers_dict = signers(sigcheck_str_list)

    sigcheck_dict.update(signers_dict)
    return sigcheck_dict
    
    # print(signers_dict)
    # print(sigcheck_dict)
   
def signers(sigcheck_str_list):
    signer_list = []
    counter_signer_list = []
    
    try:
        signer_start_index = []
        counter_signer_start_index = []

        for index, sigcheck_str in enumerate(sigcheck_str_list):
            if '<attribute>Signers:' in sigcheck_str:
                signer_start_index.append(index)
            elif '<attribute>Counter Signers' in sigcheck_str:
                counter_signer_start_index.append(index)

        #print(signer_start_index)
        #print(counter_signer_start_index)
        for i in range(signer_start_index[0],counter_signer_start_index[0]-1,9):
            signer_list.append(sigcheck_str_list[i+1 : i+10])
        for i in range(signer_start_index[1],counter_signer_start_index[1]-1,9):
            signer_list.append(sigcheck_str_list[i+1 : i+10])
        
        for i in range(counter_signer_start_index[0],signer_start_index[0],9):
            if '<Certificate>' in sigcheck_str_list[i+1]:
                counter_signer_list.append(sigcheck_str_list[i+1 : i+10])
        for i in range(counter_signer_start_index[1],len(sigcheck_str_list),9):
            if '<Certificate>' in sigcheck_str_list[i+1]:
                counter_signer_list.append(sigcheck_str_list[i+1 : i+10])
        #print(signer_list)
        #print(counter_signer_list)

    except ValueError:
        #print(ValueError)
        pass
    except IndexError:
        pass
        #print(IndexError)

    signers_dict = {}
    signers_dict['Signers'] = signer_list
    signers_dict['Counter Signers'] = counter_signer_list

    #print(signers_dict)
    return signers_dict



if __name__ == '__main__':
    t1 = "C:/Users/user/AppData/Local/LINE/bin/LineLauncher.exe"
    t2 = "../testdir/testdir1/python.exe"
    testfiles = [t1,t2]
    
    for t in testfiles:
        sigcheck(t)
    