import os
import logging
from settings import RESOURCE_DIR
from analysis import analysis_summary

# exists problem when using multiprocessing Queue program won't end
def read_directory(directory, pending_file_queue, pending_dir_queue, examineFileType = ['.exe']):
    try:
        for root, dirs, files in os.walk(directory):
            for f in files:
                if os.path.splitext(f)[-1] in examineFileType:
                    file_name = os.path.join(root,f)
                    pending_file_queue.put(file_name)
                    print("{} Added to pending_file_queue... ".format(file_name))
    except:
        print("Error in read_directory")
        # for d in dirs:
        #     directory_name = os.path.join(root,d)
        #     pending_dir_queue.put(directory_name)

def process_files(pending_file_queue, processed_file_queue, problem_file_queue):
    #sigcheck_exe_path = os.path.join(RESOURCE_DIR,'sigcheck64.exe')
    #userdb_filter_txt = os.path.join(RESOURCE_DIR,'userdb_filter.txt')
    sigcheck_exe_path = 'sigcheck64.exe'
    userdb_filter_txt = 'userdb_filter.txt'
    while not pending_file_queue.empty():
        file_name = pending_file_queue.get()
        try:
            file_info = analysis_summary(file_name, sigcheck_exe_path, userdb_filter_txt)
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