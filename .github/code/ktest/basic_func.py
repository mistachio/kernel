#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

import os
import sys
import json
try:
    # requests module doesn't come with the default Python3 package
    import requests
except ImportError:
    print("ERROR: Please install 'requests' module for python3:")
    print("   sudo apt-get install python3-pip")
    print("   sudo pip3 install requests")
    raise
import time


def http_get(url, token):
    headers = {
        'Accept': 'application/json',
        'Authorization': token,
    }
    response = requests.get(url=url, headers=headers)

    if response.status_code != requests.codes.ok:
        raise RuntimeError("Failed request external API, GET request URL: {url}, error: {response}, "
                           "status code: {status_code}".
                           format(url=url, response=response.json(), status_code=response.status_code))

    response_data = response.json()
    return response_data


def http_post(url, post_data_dict, token):

    post_data = json.dumps(post_data_dict)
    # content_length = str(len(post_data))
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': token,
    }
    response = requests.post(url=url, headers=headers, data=post_data)

    if response.status_code != requests.codes.ok:
        raise RuntimeError("Failed request external API, POST request URL: {url} with data: {data}, error: "
                           "{response}, status code: {status_code}".
                           format(url=url, data=post_data, response=response.json(), status_code=response.status_code))
    response_data = response.json()
    return response_data


def http_put(url, post_data_dict, token):

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
        'Authorization': token,
    }
    response = requests.put(url=url, headers=headers, json=post_data_dict)

    if response.status_code != requests.codes.ok:
        raise RuntimeError("Failed request external API, PUT request URL: {url} with data: {data}, error: "
                           "{response}, status code: {status_code}".
                           format(url=url, data=post_data_dict, response=response.json(),
                                  status_code=response.status_code))
    response_data = response.json()
    return response_data


def local_print(message, begin_newline=False):
    if begin_newline:
        print()
    timestamp = time.asctime(time.localtime(time.time()))
    print("{timestamp} {msg}".format(timestamp=timestamp, msg=message))
    sys.stdout.flush()


# for local debug
if __name__ == "__main__":
    print(http_put("http://localhost:8080/api/jobs/cancel", {"job_ids": []}, ""))
