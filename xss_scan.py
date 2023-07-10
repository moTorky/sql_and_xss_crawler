import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pickle #used to dump data from memory to files
import argparse #parse user args
from req import req
import subprocess

#test this script
# file_path=dir_name+'/requests_list.pkl'
# with open(file_path, "rb") as file:
# 	loaded_requests_list = pickle.load(file)

# headers_file = 	'header.txt' 
# xsstrike_path=os.path.join("XSStrike/xsstrike.py")
# # Read headers from file
# headers = {}
# with open(headers_file, "r") as f:
#     for line in f:
#         key, value = line.strip().split(":")
#         headers[key.strip()] = value.strip()


# with open('xss_log_file','w') as file:
#     file.write("xsstrike logs")
# Define the command and arguments for xsstrike.py


def xss_scan(loaded_requests_list, headers_file, xsstrike_path, log_file):
    with open(log_file,'w') as file:
        file.write("xsstrike logs\n")

    # Loop over the requests list
    for request in loaded_requests_list:
        # Define the command and arguments for xsstrike.py
        command="python3 "+xsstrike_path
        p = ''
        for param in request.params:
            p += str(param) + "=mrt\&"
        p=p[:-2]
        if request.method.upper()== 'GET':
            command+=' -u '+request.url+'?'+p
        else:
            command+=' -u '+request.url+' --data '+p
        command+=' --headers '+headers_file
        print('try to execute: ',command)
        output = subprocess.check_output(command, shell=True)
        decoded_output = output.decode("utf-8")
        with open(log_file, "a+") as f:
            f.write('\n\n-----------------------------------------------------------\n')
            f.write('start to scan: '+request.url+' with param: '+p+'\n')
            f.write('-----------------------------------------------------------\n')
            f.write(decoded_output)