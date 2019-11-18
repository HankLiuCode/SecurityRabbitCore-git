import os
import wmi
import subprocess
import platform
import re, uuid

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
    mac_addr = re.findall("..",hex(uuid.getnode()))[1:]
    host_info_dict['MAC'] = ":".join(mac_addr)
    
    totalSize = 0
    for memModule in w.Win32_PhysicalMemory():
        totalSize += int(memModule.Capacity)
    host_info_dict['memoryCapacity'] = totalSize/1048576
    
    registry_list = []
    for s in w.Win32_StartupCommand(): 
        registry_list.append((s.Location, s.Caption, s.Command))
    host_info_dict['registry_list'] = registry_list

    return host_info_dict