import os
import time
import multiprocessing
import logging
import pandas
import json

from settings import baseDir,dataDir
from analysis import analysis_summary
from analysis import hostinfo
import argparse
import sys


# exists problem when using multiprocessing Queue program won't end
def read_directory(directory, pending_file_queue, pending_dir_queue, examineFileType = ['.exe']):
    for root, dirs, files in os.walk(directory):
        for f in files:
            if os.path.splitext(f)[-1] in examineFileType:
                file_name = os.path.join(root,f)
                pending_file_queue.put(file_name)
                print("{} Added to pending_file_queue... ".format(file_name))
        # for d in dirs:
        #     directory_name = os.path.join(root,d)
        #     pending_dir_queue.put(directory_name)

def process_files(pending_file_queue, processed_file_queue, problem_file_queue):
    while not pending_file_queue.empty():
        file_name = pending_file_queue.get()
        try:
            file_info = analysis_summary.analysis_summary(file_name)
            processed_file_queue.put(file_info)
            print("[{} files remaining] Finished Processing {}...".format(pending_file_queue.qsize(),file_name))
        except OSError:
            logging.exception(OSError)
            error_dict = {
                'file_name' : file_name,
                'error' : OSError,
            }
            problem_file_queue.put(error_dict)
        except:
            logging.exception("Error")
            error_dict = {
                'file_name' : file_name,
                'error' : 'Error',
            }
            problem_file_queue.put(error_dict)

#possible fixes
#https://github.com/pyinstaller/pyinstaller/wiki/Recipe-Multiprocessing

#problem to be solved
#FileNotFoundError: [WinError 2] 系統找不到指定的檔案。
#ERROR:root:<class 'OSError'>

if __name__ == '__main__':
    multiprocessing.freeze_support()
    #parser = argparse.ArgumentParser()
    #parser.add_argument("directories", nargs="+", help="the root directory(s) you want to scan")
    #parser.add_argument("--scanType", help= "0:quickScan, 1:normalScan, 2:deepScan")
    
    #args = parser.parse_args()
    manager = multiprocessing.Manager()
    problem_file_queue = manager.Queue()
    pending_file_queue = manager.Queue()
    pending_dir_queue = manager.Queue()
    processed_file_queue = manager.Queue()

    directories = [r'D:/ProgramFiles/Wireshark']
    producers = multiprocessing.Pool()
    for directory in directories:
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
    #df.to_excel(os.path.join(dataDir,'exeInfo.xlsx'))
    df.to_json('exeInfo.json')
    with open('hostInfo.json','w') as f:
        json.dump(analysis_summary.host_info(), f)
        

    error_files = []
    while not problem_file_queue.empty():
        error_files.append(problem_file_queue.get())
    df = pandas.DataFrame(error_files)
    df.to_json('error.json')

    # Error Report
    # OSError: [WinError 1920] 系統無法存取該檔案。: 'C:/Users/user\\AppData\\Local\\Microsoft\\WindowsApps\\protocolhandler.exe'

    # Race condition in pefileIndex pefileInfo
