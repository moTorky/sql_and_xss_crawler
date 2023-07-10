import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pickle #used to dump data from memory to files
import argparse #parse user args
from req import req

# list_of_endpoints={'http://testphp.vulnweb.com/showimage.php?file=./pictures/4.jpg', 'http://testphp.vulnweb.com/categories.php', 'http://testphp.vulnweb.com/artists.php?artist=2', 'http://testphp.vulnweb.com/product.php?pic=2', 'http://testphp.vulnweb.com/product.php?pic=5', 'http://testphp.vulnweb.com/showimage.php?file=./pictures/7.jpg', 'http://testphp.vulnweb.com/Details/web-camera-a4tech/2/', 'http://testphp.vulnweb.com/privacy.php', 'http://testphp.vulnweb.com/signup.php', 'http://testphp.vulnweb.com/listproducts.php?cat=2', 'http://testphp.vulnweb.com/listproducts.php?artist=3', 'http://testphp.vulnweb.com/product.php?pic=4', 'http://testphp.vulnweb.com/listproducts.php?artist=2', 'http://testphp.vulnweb.com/index.php', 'http://testphp.vulnweb.com/artists.php?artist=1', 'http://testphp.vulnweb.com/artists.php?artist=3', 'http://testphp.vulnweb.com/Details/color-printer/3/', 'http://testphp.vulnweb.com/listproducts.php?cat=3', 'http://testphp.vulnweb.com/login.php', 'http://testphp.vulnweb.com/showimage.php?file=./pictures/6.jpg', 'http://testphp.vulnweb.com/showimage.php?file=./pictures/5.jpg', 'http://testphp.vulnweb.com/', 'http://testphp.vulnweb.com/cart.php', 'http://testphp.vulnweb.com/userinfo.php', 'http://testphp.vulnweb.com/product.php?pic=6', 'http://testphp.vulnweb.com/product.php?pic=1', 'http://testphp.vulnweb.com/Details/network-attached-storage-dlink/1/', 'http://testphp.vulnweb.com/product.php?pic=3', 'http://testphp.vulnweb.com/listproducts.php?cat=1', 'http://testphp.vulnweb.com/product.php?pic=7', 'http://testphp.vulnweb.com/Mod_Rewrite_Shop/', 'http://testphp.vulnweb.com/listproducts.php?cat=4', 'http://testphp.vulnweb.com/showimage.php?file=./pictures/2.jpg', 'http://testphp.vulnweb.com/AJAX/index.php', 'http://testphp.vulnweb.com/guestbook.php', 'http://testphp.vulnweb.com/hpp/', 'http://testphp.vulnweb.com/showimage.php?file=./pictures/1.jpg', 'http://testphp.vulnweb.com/disclaimer.php', 'http://testphp.vulnweb.com/?pp=12', 'http://testphp.vulnweb.com/listproducts.php?artist=1', 'http://testphp.vulnweb.com/artists.php', 'http://testphp.vulnweb.com/showimage.php?file=./pictures/3.jpg'}

def url_equals(url1, url2):
    # try:
    parsed_url1 = urlparse(url1)
    parsed_url2 = urlparse(url2)
    return parsed_url1.scheme == parsed_url2.scheme and parsed_url1.netloc == parsed_url2.netloc and parsed_url1.path == parsed_url2.path 
    # except Exception as e:
    #     raise e
    # else:
    # 	return False

def add_reqs_if_not_exsit(my_reqs,new_reqs):
    # Check if the request already exists in my_reqs
    working_list=my_reqs.copy()
    for new_req in new_reqs:
        found=False
        for existing_req in working_list:
            if url_equals(existing_req.url, new_req.url) and existing_req.method.upper() == new_req.method.upper():
                # print('\t\twe find this url ',new_req.url,' ',existing_req.url)
                existing_req.params+=new_req.params
                existing_req.params=list(set(existing_req.params))
                found=True
                break
        if not found:
            working_list.append(new_req)
    return working_list

def get_param_for_req(url, headers):
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")
    domain_name = url.split("//")[1].split("/")[0]
    new_reqs=[]
    if '?' in str(url):
        params=[]
        action_parts = url.split('?')[1].split('&')
        # print(url.split('?')[1].split('&'))
        while action_parts:
            cParam = action_parts.pop(0).split('=')[0]
            params.append(cParam)
        # print(params)
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        # print(url,' ',params,' GET')
        r=req(base_url, params, 'GET')
        new_reqs.append(r)

    for form in soup.find_all('form'):
        params = []
        cURL = url
        for form_input in form.find_all('input'):
            param = form_input.get('name')
            params.append(param)
        # Check if the form sends to another URL (not care if it in other domain`domain_name in action`)
        action = form.get('action')
        method = form.get('method')
        embedde_param=[]
        if action:
            if '?' in action:
                action_parts = action.split('?')[1].split('&')
                while action_parts:
                    cParam = action_parts.pop().split('=')[0]
                    embedde_param.append(cParam)
            parsed_url = urlparse(url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
            parsed_url = urlparse(action)
            action= f"{parsed_url.path}"
            cURL = base_url+action
            if method.upper() =='POST' and embedde_param:
            	r=req(cURL, embedde_param, 'GET')
            	new_reqs.append(r)
            else:
            	params+=embedde_param
        # print(cURL,' ',params,' ',method)
        r=req(cURL, params, method)
        new_reqs.append(r)
    return new_reqs

def dump_req_and_prams(dir_name,requests_list):
    # Save requests_list to a file
    file_path = os.path.join(dir_name, "requests_list.pkl")
    with open(file_path, "wb") as file:
        pickle.dump(requests_list, file)

    # Load requests_list from the file
    # with open(file_path, "rb") as file:
    # loaded_requests_list = pickle.load(file)
#---------------------------------------------------------
def write_req_and_prams_to_file(dir_name,requests_list):
    with open(dir_name+'/endpoints_with_param.txt', 'w') as file:
        for cReq in requests_list:
            p = ''
            for param in cReq.params:
                param=str(param)
                p += param + "=mrt&"
            line=cReq.url + '?' + p
            file.write(line + '\n')

# headers_file = 	'header.txt' 

# # Read headers from file
# headers = {}
# with open(headers_file, "r") as f:
#     for line in f:
#         key, value = line.strip().split(":")
#         headers[key.strip()] = value.strip()

# my_reqs=[]
# for url in list_of_endpoints:
#     # print('...')
#     new_reqs=get_param_for_req(url,headers)
#     # print('--------------------------------new list')
#     # for r in new_reqs:
#     #     print(r.url,': ',r.params,' =>',r.method)
#     my_reqs=add_reqs_if_not_exsit(my_reqs,new_reqs)
#     # print('------------------------------------ all list')
#     # for r2 in my_reqs:
#     #     print(r2.url,': ',r2.params,' =>',r2.method)
# print('------------------------------------ list of found reqstes')

# for r in my_reqs:
# 	print(r.url,': ',r.params,' =>',r.method)

# file_path='new_parms.pkl'
# with open(file_path, "wb") as file:
#     pickle.dump(my_reqs, file)

# print('------------------------------------ list of found reqstes dump to new_parms.pkl')