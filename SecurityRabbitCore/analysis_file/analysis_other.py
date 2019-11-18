import os
import re
import subprocess
from time import ctime as time_ctime

from .analysis_pefile import analysis_pefile
from .analysis_byte import analysis_byte

# reg key
# packer true false + text
# signers

def analysis_other(filepath, sigcheck_path):
    other_info = basic_file_info(filepath)
    other_info.update(sigcheck(filepath, sigcheck_path))
    return other_info

def basic_file_info(filepath):
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
    return file_info_dict

def sigcheck(filepath, sigcheck_exe_path):
    args = [sigcheck_exe_path, '-i','-nobanner', filepath]
    sigcheck_process = subprocess.Popen(args, stdout=subprocess.PIPE)
    sigcheck_str = sigcheck_process.communicate()[0].decode('utf-8', 'ignore')
    sigcheck_str = sigcheck_str.replace('\r\n\t'+'  ', '\n<Certificate>')
    sigcheck_str = sigcheck_str.replace('\r\n\t\t', '\n<Certi Info>')
    sigcheck_str = sigcheck_str.replace('\r\n\t', '\n<attribute>')
    sigcheck_str = sigcheck_str.replace('\t','')
    
    signers = None
    counter_signers = None
    try:
        signers_info = re.search('<attribute>Signers:([\s\S]*)<attribute>Counter Signers:',sigcheck_str).group(1)
        counter_signers_info = re.search('<attribute>Counter Signers:([\s\S]*)',sigcheck_str).group(1)
        signers = re.findall('(?:\s<Certificate>(.*)(?:\s<Certi Info>.*)*)',signers_info)
        counter_signers = re.findall('(?:\s<Certificate>(.*)(?:\s<Certi Info>.*)*)', counter_signers_info)

    except:
        signers = []
        counter_signers = []

    sigcheck_dict = {
        'signers':signers,
        'counter_signers':counter_signers
    }
    return sigcheck_dict

    

    