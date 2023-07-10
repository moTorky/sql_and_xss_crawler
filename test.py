import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pickle #used to dump data from memory to files
import argparse #parse user args


def get_all_endpoints(base_url, headers):
    domain_name = urlparse(base_url).netloc
    endpoints = set()

    def is_valid(url):
        parsed = urlparse(url)
        return bool(parsed.netloc) and bool(parsed.scheme)

    def get_absolute_url(url):
        return urljoin(base_url, url)

    def crawl(url):
        try:
            response = requests.get(url, headers=headers)
            soup = BeautifulSoup(response.text, "html.parser")

            for a_tag in soup.find_all("a"):
                href = a_tag.attrs.get("href")
                if href and is_valid(base_url+href):
                    endpoint = get_absolute_url(href)
                    print(endpoint)
                    if urlparse(endpoint).netloc == domain_name and endpoint not in endpoints:
                        endpoints.add(endpoint)
                        crawl(endpoint)

            for input_tag in soup.find_all("input"):
                onclick = input_tag.attrs.get("onclick")
                if onclick:
                    url_start = onclick.find("'") + 1
                    url_end = onclick.rfind("'")
                    if url_start != -1 and url_end != -1:
                        url = onclick[url_start:url_end]
                        if is_valid(base_url+url):
                            endpoint = get_absolute_url(url)
                            if urlparse(endpoint).netloc == domain_name and endpoint not in endpoints:
                                endpoints.add(endpoint)
                                crawl(endpoint)

        except requests.exceptions.RequestException:
            pass

    crawl(base_url)
    return endpoints
#---------------------------------------------------------
def save_data_to_file(dir_name, endpoints):
    #Create directory with domain name
    try:
        os.makedirs(dir_name, exist_ok=True)
    except FileExistsError:
        pass
    with open(dir_name+"/list_of_endpoints.txt", "w") as f:
        f.write("\n".join(endpoints))
#---------------------------------------------------------
def get_param_for_req(url, headers):
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    domain_name = url.split("//")[1].split("/")[0]
    my_reqs = []

    for form in soup.find_all('form'):
        params = []

        for form_input in form.find_all('input'):
            param = form_input.get('name')
            params.append(param)
        #check if from send to other url, then check if it sned to same domain or not. finally update the url
        if not form.get('action'):
            if domain_name in form.get('action'):
                parsed_url = urlparse(url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
                url = base_url+form.get('action')
            else:
                break   
        method = form.get('method')
        my_reqs.append(req(url, params, method))

    return my_reqs
#---------------------------------------------------------
class req:
    def __init__(self, url, params, method):
        self.url = url
        self.params = params
        self.method = method
    def __getstate__(self):
        return self.url, self.params, self.method
    def __setstate__(self, state):
        self.url, self.params, self.method = state
#---------------------------------------------------------
def dump_req_and_prams(dir_name,requests_list):
    # Save requests_list to a file
    file_path = os.path.join(dir_name, "requests_list.pkl")
    with open(file_path, "wb") as file:
        pickle.dump(requests_list, file)

    # Load requests_list from the file
    # with open(file_path, "rb") as file:
    # loaded_requests_list = pickle.load(file)
#---------------------------------------------------------
def wite_req_and_prams_to_file(dir_name,requests_list):
    with open(dir_name+'/endpoints_with_param.txt', 'w') as file:
        for cReq in requests_list:
            p = ''
            for param in cReq.params:
                param=str(param)
                p += param + "=mrt&"
            line=cReq.url + '?' + p
            file.write(line + '\n')

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
sqlmap_path = os.path.join("/usr/share/sqlmap/sqlmap.py")

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
endpoints = get_all_endpoints(base_url, headers)
print('------------------------------------------------')
print('crawling:')
print('------------------------------------------------')
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
    new_req=get_param_for_req(url,headers)
    my_reqs.extend(new_req)
print('------------------------------------------------')
print('visit endpoints to get params from html forms')
print('------------------------------------------------')

try:
    dump_req_and_prams(dir_name,my_reqs)
    print('url+params deumped to : ',dir_name+'/requests_list.pkl')
except Exception as e:
    wite_req_and_prams_to_file(dir_name,my_reqs)
    raise e

print('--------------------start xss scan--------------------')
print('xsstrike logs saved to xss_log_file')

import subprocess

with open(dir_name+'/xss_log_file','w') as file:
    file.write("xsstrike logs")
# Define the command and arguments for xsstrike.py

# Define common xsstrike command arguments
xsstrike_common_args = ["--headers", headers_path, "--log-file", "xss_log_file","--file-log-level", "CRITICAL", "--crawl"]

# Loop over the requests list
for request in my_reqs:
    p = ''
    for param in request.params:
        p += str(param) + "=mrt&"
    xsstrike_args = [
        "-u",
        request.url + '?' + p
    ]
    # Run xsstrike.py with the specified arguments for the current request
    subprocess.run(["python3", xsstrike_path] + xsstrike_common_args + xsstrike_args)

print('--------------------start sqli scan--------------------')

os.makedirs(dir_name+'/sqli_log_files')
print('sqlmap logs saved under sqli_log_files directory')

# Define the command and arguments for sqlmap.py
# Define common sqlmap command arguments
sqlmap_output_dir=dir_name+'/sqli_log_files'
sqlmap_common_args = ["--batch", "--banner", '--risk=3', '--level=5', '--output-dir='+sqlmap_output_dir, '--headers='+header_str]

# Loop over the requests list
for request in my_reqs:
    p = ''
    for param in request.params:
        p += str(param) + "=mrt&"
    sqlmap_args = [
        "-u",
        request.url + '?' + p
    ]
    # Run xsstrike.py with the specified arguments for the current request
    subprocess.run(["python3", sqlmap_path] + sqlmap_common_args + sqlmap_args)
