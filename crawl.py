import os
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import pickle #used to dump data from memory to files
import argparse #parse user args
from req import req

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
                    # print(endpoint)
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