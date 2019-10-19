from hashlib import sha1 as hashlib_sha1
from string import printable as string_printable
from math import log as math_log

def analysis_byte(filepath):
    chunk_size = 8192
    printable_chars = set(bytes(string_printable,'ascii'))
    printable_str_list = []
    sha1 = hashlib_sha1()
    one_gram_byte_dict = {}
    two_gram_byte_dict = {}
    
    for i in range(256):
        one_gram_byte_dict[hex(i)] = 0
    
    for i in range(256):
        for j in range(256):
            two_gram_byte_dict[hex(i)+hex(j)] = 0

    with open(filepath,'rb') as f:
        while True:
            chunk = f.read()
            if not chunk:
                break
            one_gram_byte_analysis(chunk, one_gram_byte_dict)
            two_gram_byte_analysis(chunk, two_gram_byte_dict)
            byte_printable(chunk, printable_chars, printable_str_list)
            sha1.update(chunk)
    entropy = calc_entropy(one_gram_byte_dict)
    
    byte_analysis_dict = {
        'printable_strs' : printable_str_list,
        'entropy' : entropy,
        'file_sha1': sha1.hexdigest()
    }
    byte_analysis_dict.update(one_gram_byte_dict)
    #byte_analysis_dict.update(two_gram_byte_dict)

    return byte_analysis_dict

def one_gram_byte_analysis(chunk,one_gram_byte_dict):
    for byte in chunk:
        one_gram_byte_dict[hex(byte)] += 1

def two_gram_byte_analysis(chunk, two_gram_byte_dict):
    previous_byte = None
    for byte in chunk:
        if previous_byte:
            two_gram_byte_dict[hex(previous_byte)+hex(byte)] += 1
        previous_byte = byte

def byte_printable(chunk,printable_chars,printable_str_list):
    temp_bytes = b""
    for byte in chunk:
        if byte in printable_chars:
            temp_bytes += bytes([byte])
        
        elif not temp_bytes == b"\x00" and len(temp_bytes) > 2:
            printable_str_list.append(temp_bytes.decode("ascii"))
            temp_bytes = b""
        else:
            temp_bytes = b""
    return printable_str_list

def calc_entropy(byte_dict):
    entropy = 0
    total = sum(byte_dict.values())
    for key in byte_dict:
        if byte_dict[key] != 0 :
            freq = byte_dict[key] / total
            entropy = entropy + freq * math_log(freq, 2)
    entropy *= -1
    return entropy
