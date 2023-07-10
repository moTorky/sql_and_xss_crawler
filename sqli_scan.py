import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pickle #used to dump data from memory to files
import argparse #parse user args
from req import req
import subprocess


def sqli_scan(loaded_requests_list, headers_file, sqlmap_path, sqlmap_output_dir, sqli_log_file):
    headers_str=''
    with open(headers_file, "r") as f:
        for line in f:
            key, value = line.strip().split(":")
            headers_str+=key.strip()+':'+ value.strip()+'\n'
    headers_str='--headers='+'\''+headers_str+'\''
    print('sqlmap logs saved under sqli_log_files directory')
    out_dir='--output-dir='+sqlmap_output_dir
    # Define the command and arguments for sqlmap.py
    # Define common sqlmap command arguments
    # sqlmap_common_args = ["--batch", "--banner", '--risk=3', '--level=5', out_dir, headers_str,'--time-sec=60']
    for mRequest in loaded_requests_list:
        command='python3 '+sqlmap_path+ ' --batch --banner -v 0 '+out_dir+' '+headers_str+' --technique \'UEBQ\' '
        p = ''
        for param in mRequest.params:
            p += str(param) + "=devmrt\&"
        p=p[:-2]
        if mRequest.method.upper()== 'GET':
            command+='-u '+mRequest.url + '?' + p + ' --method=GET'
            # sqlmap_args = [
            # "-u",
            # mRequest.url + '?' + p, '--method=GET']
            # print('start testing ',mRequest.url+'?'+p)
        else:
            command+='-u '+mRequest.url + ' --data ' + p + ' --method=POST'
            # sqlmap_args = [
            # "-u",
            # mRequest.url, "--data", p, '--method=POST']
            # print('start testing ',mRequest.url,'with following param:',p)
        # Run xsstrike.py with the specified arguments for the current request
        # sqlmapout=subprocess.run(["python3", sqlmap_path] + sqlmap_common_args + sqlmap_args)
        print('trying to execute: ',command,'\n\n')
        output = subprocess.check_output(command, shell=True)
        decoded_output = output.decode("utf-8")
        with open(sqli_log_file, "a+") as f:
            f.write('-----------------------------------------------------------\n')
            f.write('start to scan: '+mRequest.url+' with param: '+p+'\n')
            f.write('------------------------\n')
            if "Parameter: " in decoded_output:
                start_index = decoded_output.find("Parameter:")
                end_index = decoded_output.find("Payload:", start_index)
                filtered_output = decoded_output[start_index:end_index].strip()
                f.write("\nInfected URL: "+mRequest.url+'\n')
                f.write("Infected Parameters: "+'\n')
                f.write(filtered_output+'\n')
                f.write("------------------------------------------")
            else:
                f.write('this endpoint not seem to be infected\n')

#run allon code
# file_path='requests_list.pkl'
# with open(file_path, "rb") as file:
#   loaded_requests_list = pickle.load(file)

# headers_file ='header.txt' 
# sqlmap_path=os.path.join("/usr/share/sqlmap/sqlmap.py")
# # Read headers from file

# test_this=loaded_requests_list[1:3]
# # print(this_url.url,this_url.params,this_url.method)
# sqli_scan(loaded_requests_list,headers_file,sqlmap_path,'./','sqli_log_file')
