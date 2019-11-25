# !/usr/bin/python 
# coding:utf-8 

import os
import datetime
import multiprocessing
import pandas
import json

from module import read_directory, process_files
from analysis_host import host_info
import argparse
import sys

#problem to be solved
#FileNotFoundError: [WinError 2] 系統找不到指定的檔案。
#ERROR:root:<class 'OSError'>


if __name__ == '__main__':
    multiprocessing.freeze_support()
    parser = argparse.ArgumentParser()
    parser.add_argument("directories", nargs="+", help="the root directory(s) you want to scan")
    parser.add_argument("--is_testmode", dest="is_testmode", help="only used in development")
    parser.add_argument("--scan_type", dest="scantype", help= "quick_scan, normal_scan, deep_scan")
    
    args = parser.parse_args()

    manager = multiprocessing.Manager()
    problem_file_queue = manager.Queue()
    pending_file_queue = manager.Queue()
    pending_dir_queue = manager.Queue()
    processed_file_queue = manager.Queue()

    start_time = datetime.datetime.now()

    producers = multiprocessing.Pool()
    for directory in args.directories:
        producers.apply_async(read_directory, args = (directory, pending_file_queue, pending_dir_queue, ['.exe']))
    producers.close()
    producers.join()

    consumers = multiprocessing.Pool()
    for i in range(8):
        consumers.apply_async(process_files, args = (pending_file_queue, processed_file_queue, problem_file_queue))
    consumers.close()
    consumers.join()

    files = []
    while not processed_file_queue.empty():
        tempfile = processed_file_queue.get()
        files.append(tempfile)
        print("[{} files remaining] Add {} to all_files".format(problem_file_queue.qsize(),tempfile['file_name']))
    
    error_files = []
    while not problem_file_queue.empty():
        error_files.append(problem_file_queue.get())
    error_files_df = pandas.DataFrame(error_files)
    
    end_time = datetime.datetime.now()
    files_df = pandas.DataFrame(files)
    data = {}
    data['hostinfo'] = host_info()
    data['fileinfo'] = files_df.to_json(orient="records")
    data['errorfile'] = error_files_df.to_json(orient="records")
    data['metainfo'] = {
        "scan_type":args.scantype,
        "start_time":start_time.ctime(),
        "end_time":end_time.ctime(),
        "scan_duration":(end_time-start_time).seconds
        }

    with open('data.json','w') as f:
        json.dump(data, f)

    # Error Report
    # OSError: [WinError 1920] 系統無法存取該檔案。: 'C:/Users/user\\AppData\\Local\\Microsoft\\WindowsApps\\protocolhandler.exe'
    # Race condition in pefileIndex pefileInfo
