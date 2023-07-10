import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pickle #used to dump data from memory to files
import argparse #parse user args
from req import req
from get_param import *
from crawl import *
from xss_scan import *
from sqli_scan import *

#help msg and banner and check for sqlmap in /usr/share/sqlmap/sqlmap.py and xsstrike.py in ./XSStrike/xsstrike.py
print('this script depends on \tXSStrike for xss scan and \tsqlmap for sqli scan')

# Get user input
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', help='url', dest='target')
parser.add_argument('--header_file', help='add headers',dest='headers_file', nargs='?', const=True)
args = parser.parse_args()

base_url = args.target #'http://testphp.vulnweb.com/'
headers_file = args.headers_file #'header.txt' 


# Construct absolute paths for xsstrike.py and headers file
headers_path = os.path.join(headers_file)
xsstrike_path = os.path.join("XSStrike/xsstrike.py")
# Construct absolute paths for sqlmap.py and headers file
sqlmap_path = os.path.join("sqlmap-dev/sqlmap.py")

# Verify xsstrike.py file exists at the specified path
if not os.path.isfile(xsstrike_path):
    print("Error: xsstrike.py file not found at", xsstrike_path)
    exit(1)
# Verify headers file exists at the specified path
if not os.path.isfile(headers_path):
    print("Error: Headers file not found at", headers_path)
    exit(1)
# Verify xsstrike.py file exists at the specified path
if not os.path.isfile(sqlmap_path):
    print("Error: sqlmap.py file not found at", sqlmap_path,"plz download it :)")
    exit(1)

# Read headers from file
headers = {}
with open(headers_file, "r") as f:
    for line in f:
        key, value = line.strip().split(":")
        headers[key.strip()] = value.strip()

# Get endpoints
print('------------------------------------------------')
print('crawling:')
print('------------------------------------------------')
endpoints = get_all_endpoints(base_url, headers)
print('list of endpoints: ')
print(endpoints)

domain_name = urlparse(base_url).netloc
dir_name = domain_name.replace(".", "_")
save_data_to_file(dir_name,endpoints)
print('------------------------------------------------')
print('make dir for current target:',dir_name)
print('endpoints saved to :',dir_name+'/list_of_endpoints.txt')
print('------------------------------------------------')


my_reqs=[]
for url in endpoints:
    new_reqs=get_param_for_req(url,headers)
    my_reqs=add_reqs_if_not_exsit(my_reqs,new_reqs)

print('list of found reqstes')
print('------------------------------------ ')
for r in my_reqs:
    print(r.url,': ',r.params,' =>',r.method)

print('-----------------------------------------------------')
print('trying to list of found reqstes dump to requests_list.pkl')
print('-----------------------------------------------------')
try:
    dump_req_and_prams(dir_name,my_reqs)
    print('url+params deumped to : ',dir_name+'/requests_list.pkl')
except Exception as e:
    write_req_and_prams_to_file(dir_name,my_reqs)
    raise e

print('--------------------start xss scan--------------------')
print('xsstrike logs saved to xss_log_file')
with open(dir_name+'/xss_log_file','w') as file:
    file.write("xsstrike logs")
xss_log_file=os.path.join(dir_name+'/xss_log_file')
xss_scan(my_reqs, headers_file, xsstrike_path, xss_log_file)

print('--------------------start sqli scan--------------------')

sqlmap_output_dir=dir_name+'/sqli_log_files'
sqli_log_file=dir_name+'/sqli_log_file'
os.makedirs(sqlmap_output_dir)
print('infected endpoints saved to sqli_log_file')
sqli_scan(my_reqs, headers_file, sqlmap_path, sqlmap_output_dir,sqli_log_file)