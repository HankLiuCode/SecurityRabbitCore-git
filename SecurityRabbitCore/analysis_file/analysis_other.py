# !/usr/bin/python 
# coding:utf-8 

import os
import re
import subprocess
import platform
from time import ctime as time_ctime

from .analysis_pefile import analysis_pefile
from .analysis_byte import analysis_byte

# reg key
# packer true false + text
# signers

def analysis_other(filepath, sigcheck_path):
    other_info = basic_file_info(filepath, testMode=True)
    other_info.update(sigcheck(filepath, sigcheck_path))
    return other_info

def basic_file_info(filepath, testMode, isMalware=0):
    created = time_ctime(os.path.getctime(filepath))   # create time
    last_modified = time_ctime(os.path.getmtime(filepath))   # modified time
    last_accessed = time_ctime(os.path.getatime(filepath))   # access time
    file_size = os.stat(filepath).st_size
    file_info_dict = {
        'file_name':filepath,
        'file_size':file_size,
        'created':created,
        'last_modified':last_modified,
        'last_accessed':last_accessed
    }
    if testMode:
        file_info_dict.update({
            'isMalware': isMalware
        })
    return file_info_dict

def sigcheck(filepath, sigcheck_exe_path):
    operating_system = platform.system()
    if operating_system == 'Linux':
        args = ["wine", sigcheck_exe_path, '-i', '-l', '-nobanner', filepath]
    elif operating_system == 'Windows':
        args = [sigcheck_exe_path, '-i','-nobanner', filepath]
    sigcheck_process = subprocess.Popen(args, stdout=subprocess.PIPE)
    sigcheck_str = sigcheck_process.communicate()[0].decode('utf-8', 'ignore')
    sigcheck_str = sigcheck_str.replace('\r\n\t'+'  ', '\n<Certificate>')
    sigcheck_str = sigcheck_str.replace('\r\n\t\t', '\n<Certi Info>')
    sigcheck_str = sigcheck_str.replace('\r\n\t', '\n<attribute>')
    sigcheck_str = sigcheck_str.replace('\t','')

    attributes = {}
    signers = None
    counter_signers = None
    signers_info = None
    counter_signers_info = None

    try:
        attrs = re.findall('<attribute>(?:)(?!Signers|Counter Signers|Catalog)(.*)',sigcheck_str)
        for attr in attrs:
            attr_key = attr.split(":",1)[0]
            attr_val = attr.split(":",1)[1]
            attributes[attr_key] = attr_val
            
        signers_section = re.search('<attribute>Signers:([\s\S]*)<attribute>Counter Signers:',sigcheck_str).group(1)
        signers = re.findall('(?:\s<Certificate>(.*)(?:\s<Certi Info>.*)*)',signers_section)
        signers_info = get_signers_info(signers_section)
        
        counter_signers_section = re.search('<attribute>Counter Signers:([\s\S]*)',sigcheck_str).group(1)
        counter_signers = re.findall('(?:\s<Certificate>(.*)(?:\s<Certi Info>.*)*)', counter_signers_section)
        counter_signers_info = get_signers_info(counter_signers_section)
    except:

        attributes = []
        signers = []
        counter_signers = []
        signers_info = []
        counter_signers_info = []

    sigcheck_dict = {
        'signers':signers_info,
        'counter_signers':counter_signers_info
    }
    sigcheck_dict.update(attributes)
    return sigcheck_dict

def get_signers_info(section_str):
    signers_info = []
    temp_list = []
    for line in section_str.splitlines():
        line = line.strip()
        if '<Certificate>' in line:
            if not len(temp_list) == 0:
                signers_info.append(temp_list)
                temp_list.clear()
            temp_list.append(line.replace('<Certificate>',''))
        elif '<Certi Info>' in line:
            temp_list.append(line.replace('<Certi Info>',''))
    signers_info.append(temp_list)
    
    return signers_info
