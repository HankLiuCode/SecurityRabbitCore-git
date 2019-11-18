import pefile
import peutils
from pefile import ordlookup as pefile_ordlookup
from os import path as os_path


def analysis_pefile(filepath, userdb_filter_txt):
    pe_file = pefile.PE(filepath, fast_load=True)
    #pefile_dump(pe_file)

    pefile_dict={}
    pefile_dict.update(dll_import_analysis(pe_file))
    pefile_dict.update(check_pack(pe_file, userdb_filter_txt))
    pefile_dict.update(pefile_info(pe_file))
    return pefile_dict

def dll_import_analysis(pe_file):
    NETWORKING_AND_INTERNET_DLLS = ['dnsapi.dll', 'dhcpcsvc.dll', 'dhcpcsvc6.dll', 'dhcpsapi.dll', 'connect.dll', 
                           'httpapi.dll', 'netshell.dll', 'iphlpapi.dll', 'netfwv6.dll', 'dhcpcsvc.dll',
                           'hnetcfg.dll', 'netapi32.dll', 'qosname.dll', 'rpcrt4.dll', 'mgmtapi.dll', 'snmpapi.dll',
                           'smbwmiv2.dll', 'tapi32.dll', 'netapi32.dll', 'davclnt.dll', 'websocket.dll',
                           'bthprops.dll', 'wifidisplay.dll', 'wlanapi.dll', 'wcmapi.dll', 'fwpuclnt.dll',
                           'firewallapi.dll', 'winhttp.dll', 'wininet.dll', 'wnvapi.dll', 'ws2_32.dll',
                           'webservices.dll']
    FILE_MANAGEMENT_DLLS = ['advapi32.dll', 'kernel32.dll', 'wofutil.dll', 'lz32.dll']
    EXECUTION_FUNCTIONS = ['winexec']
    
    network_ability = []
    rw_ability = []
    exec_ability = []
    dll_analysis_dict = {}
    n_bool = False
    rw_bool = False
    exec_bool = False

    pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    if hasattr(pe_file, 'DIRECTORY_ENTRY_IMPORT'): 
        for entry in pe_file.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8').lower()
            # check if there is a matching dll import
            if dll in NETWORKING_AND_INTERNET_DLLS:
                network_ability.append(dll)
            if dll in FILE_MANAGEMENT_DLLS:
                rw_ability.append(dll)
            
            for imp in entry.imports:
                # check if there is a matching function import
                if imp in EXECUTION_FUNCTIONS:
                    exec_ability.append((hex(imp.address),imp.name.decode('utf-8')))
            
            if (network_ability != []): 
                n_bool=True 
            if (rw_ability != []): 
                rw_bool=True 
            if (exec_ability != []): 
                exec_bool=True 
                
            dll_analysis_dict = {
                'network_ability' : n_bool,
                'network_ability_dic' : network_ability,
                'rw_ability' : rw_bool,
                'rw_ability_dic' : rw_ability,
                'exec_ability' : exec_bool,
                'exec_ability_dic' : exec_ability,

            }
    return dll_analysis_dict

def pefile_info(pe_file):

    # basic info
    basic_dic = {}
    basic_dic['Machine'] = pe_file.FILE_HEADER.Machine
    basic_dic['NumberOfSections'] = pe_file.FILE_HEADER.NumberOfSections
    basic_dic['TimeDateStamp'] = pe_file.FILE_HEADER.TimeDateStamp
    basic_dic['Characteristics'] = pe_file.FILE_HEADER.Characteristics
    
    basic_dic['AddressOfEntryPoint'] = pe_file.OPTIONAL_HEADER.AddressOfEntryPoint
    basic_dic['ImageBase'] = pe_file.OPTIONAL_HEADER.ImageBase
    
    # section_info [(Name, Virtual Address, Virtual Size, Raw Size, Entropy, SHA256, MD5), ...]
    section_li = []
    for section in pe_file.sections:
        section_li.append([section.Name.decode('ascii').rstrip('\x00'), section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, section.get_entropy(), section.get_hash_sha256(), section.get_hash_md5()])
    basic_dic['Section_info'] = section_li
    
    # import_info { dll : [API, API,....], dll : [API, API,....], ...}
    # pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])   
    import_dic = {}
    pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    if hasattr(pe_file, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe_file.DIRECTORY_ENTRY_IMPORT:
            import_dic[entry.dll.decode('ascii')] = []

            for imp in entry.imports:
                funcname = None
                if not imp.name:  #可能會發生沒有imp.name的情形，為了避免跑錯所以我自己參考pefile套件自己加的
                    funcname = pefile_ordlookup.ordLookup(entry.dll.lower(), imp.ordinal, make_name=True)
                    if not funcname:
                        raise Exception("Unable to look up ordinal %s:%04x" % (entry.dll, imp.ordinal))
                else:
                    funcname = imp.name
                    import_dic[entry.dll.decode('ascii')].append(imp.name.decode('ascii'))

                if not funcname:
                    continue
            # print(import_dic[entry.dll.decode('ascii')])
    # print(import_dic)
    basic_dic['Import_directories'] = import_dic
    
    # export_info   不是每個檔案都有，如果有問題的話可以只保留 exp.name.decode('ascii')即可
    # pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    export_li = []
    pe_file.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
    if hasattr(pe_file, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe_file.DIRECTORY_ENTRY_EXPORT.symbols:
            export_li.append(exp.name.decode('ascii'))    # export_li.append([hex(pe_file.OPTIONAL_HEADER.ImageBase + exp.address), exp.name.decode('ascii'), exp.ordinal])
    basic_dic['Export_directories'] = export_li
    
            
    return basic_dic

def check_pack(pe_file, userdb_filter_txt):
    signatures = None
    with open(userdb_filter_txt,'r',encoding='utf-8') as f:
        sig_data = f.read()
        signatures = peutils.SignatureDatabase(data = sig_data)

    #matches = signatures.match(pe_file, ep_only = True)
    matchall = signatures.match_all(pe_file, ep_only = True)
    if not matchall:
        matchall = []
    return { 'pack' : matchall }