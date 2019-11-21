# !/usr/bin/python 
# coding:utf-8 
from hashlib import sha1 as hashlib_sha1
from string import printable as string_printable
from math import log as math_log

def analysis_byte(filepath):
    with open(filepath,'rb') as f:
        filebuffer = f.read()
        one_gram_dict = one_gram_byte_analysis(filebuffer)
        printable_strs = byte_printable(filebuffer)
    sha1 = hashlib_sha1()
    sha1.update(filebuffer)
    entropy = calc_entropy(one_gram_dict)
    
    byte_analysis_dict = {
        'printable_strs' : printable_strs,
        'entropy' : entropy,
        'file_sha1': sha1.hexdigest()
    }
    byte_analysis_dict.update(one_gram_dict)

    return byte_analysis_dict

def one_gram_byte_analysis(filebuffer):
    one_gram_byte_dict = {}
    for i in range(256):
        one_gram_byte_dict[hex(i)] = 0
    for byte in filebuffer:
        one_gram_byte_dict[hex(byte)] += 1
    
    return one_gram_byte_dict

def byte_printable(filebuffer):
    char_len_threshhold = 3
    printable_str_list = []
    printable_chars = set(bytes(string_printable,'ascii'))
    temp_bytes = b""
    for byte in filebuffer:
        if byte in printable_chars:
            temp_bytes += bytes([byte])
        
        elif not temp_bytes == b"\x00" and len(temp_bytes) > char_len_threshhold:
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
