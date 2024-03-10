#!/usr/bin/env python3

import requests

def download(url):
    get_response = requests.get(url)
    content = get_response.content()

    file = url.split('/')[-1]

    with open(file, 'wb') as output_file:
        output_file.write(content) 

