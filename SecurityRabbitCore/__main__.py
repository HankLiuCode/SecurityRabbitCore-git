import os
import time
import multiprocessing
import pandas
import json

from module import read_directory, process_files
from analysis import host_info
import argparse
import sys

#problem to be solved
#FileNotFoundError: [WinError 2] 系統找不到指定的檔案。
#ERROR:root:<class 'OSError'>

if __name__ == '__main__':
    multiprocessing.freeze_support()
    parser = argparse.ArgumentParser()
    parser.add_argument("directories", nargs="+", help="the root directory(s) you want to scan")
    parser.add_argument("--scanType", help= "0:quickScan, 1:normalScan, 2:deepScan")
    
    args = parser.parse_args()
    manager = multiprocessing.Manager()
    problem_file_queue = manager.Queue()
    pending_file_queue = manager.Queue()
    pending_dir_queue = manager.Queue()
    processed_file_queue = manager.Queue()

    producers = multiprocessing.Pool()
    for directory in args.directories:
        producers.apply_async(read_directory, args = (directory, pending_file_queue, pending_dir_queue))
    producers.close()
    producers.join()

    consumers = multiprocessing.Pool()
    for i in range(4):
        consumers.apply_async(process_files, args = (pending_file_queue, processed_file_queue, problem_file_queue))
    consumers.close()
    consumers.join()

    all_files = []
    while not processed_file_queue.empty():
        all_files.append(processed_file_queue.get())
    df = pandas.DataFrame(all_files)
    #df.to_json('exeInfo.json')
    df.to_excel('exeInfo.xlsx')
        

    error_files = []
    while not problem_file_queue.empty():
        error_files.append(problem_file_queue.get())
    df = pandas.DataFrame(error_files)
    df.to_json('error.json')

    # Error Report
    # OSError: [WinError 1920] 系統無法存取該檔案。: 'C:/Users/user\\AppData\\Local\\Microsoft\\WindowsApps\\protocolhandler.exe'

    # Race condition in pefileIndex pefileInfo
