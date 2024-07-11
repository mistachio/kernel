#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

"""
Call sys-pkgpool api to apply or return physical servers

API referenc:
    http://sys-pkgpool.byted.org/swagger/

Requirements:
    None
"""
import basic_func
import random
from concurrent.futures import ThreadPoolExecutor

BASE_URL = "http://sys-pkgpool.byted.org/api/"
URL_APPLY_MACHINES = BASE_URL + "applyMachines"
URL_RETURN_MACHINES = BASE_URL + "returnMachines"
URL_SUBMIT_JOB = BASE_URL + "job"
URL_LIST_JOB = BASE_URL + "jobs"
URL_GET_JOB = BASE_URL + "job" + "/{job_id}"
URL_CANCEL_JOBS = BASE_URL + "jobs/cancel"
URL_GET_Machine_List = BASE_URL + "machineList?arch={arch}"

executor = ThreadPoolExecutor(max_workers=20)
TOKEN = ""
lock_prefix = "kernel_ci_cd_"

CI_PRIORITY = 200
JOB_DESCRIPTION = "apply_only"
JOB_WAITING = "waiting"
JOB_PROCESSING = "processing"


def apply_server(server_ip, job_id, expiration):
    """
    :param server_ip:
    :param job_id:
    :param expiration:
    :return:
    """
    post_data_dict = {
        "user": lock_prefix + str(job_id),
        "expiration": expiration,
        "ips": [
            server_ip
        ],
        "next_server": "10.129.65.104"
    }
    response = basic_func.http_post(URL_APPLY_MACHINES, post_data_dict, TOKEN)
    basic_func.local_print("Install servers by post {url} with data: {post_data}, response: {response}".
                           format(url=URL_APPLY_MACHINES, post_data=post_data_dict, response=response))

    return job_id if response["success_list"] is not None \
                     and len(response["success_list"]) > 0 \
                     and server_ip == response["success_list"][0] \
                     else False


def release_server(server_ip, job_id, key=None):
    """
    :param server_ip:
    :param job_id:
    :param key:
    :return:
    """
    user = lock_prefix + str(job_id) if key is None else key
    return_ip = [server_ip] if type(server_ip) == str else server_ip
    post_data_dict = {
        "user": user,
        "ips": return_ip
    }
    response = basic_func.http_post(URL_RETURN_MACHINES, post_data_dict, TOKEN)
    basic_func.local_print("return servers by post {url} with data: {post_data}, response: {response}".
                           format(url=URL_RETURN_MACHINES, post_data=post_data_dict, response=response))

    return True if response["success_list"] is not None \
                   and len(response["success_list"]) > 0 \
                   else False


def submit_job(job_id, cpu_arch, strategy="random_2"):
    """
    :param job_id:
    :param cpu_arch: "all" "x86_64" "aarch64"
    :param strategy:
    :return: job_id in pkgpool
    """
    user = lock_prefix + str(job_id)
    post_data_dict = {
        "description": JOB_DESCRIPTION,
        "priority": CI_PRIORITY,
        "submitter_email": user,
        "exec_expire": 24 * 5,  # hours
        "test_scheduler_strategy": strategy,
        "test_arch": cpu_arch,
        "dhcp_server": "10.129.65.104",

    }
    response = basic_func.http_post(URL_SUBMIT_JOB, post_data_dict, TOKEN)
    basic_func.local_print("submit job by post {url} with data: {post_data}, response: {response}".
                           format(url=URL_SUBMIT_JOB, post_data=post_data_dict, response=response))

    if response["data"] is not None \
            and response["data"]["job_id"] is not None:
        return response["data"]["job_id"]

    return 0


def get_job_status(job_id):
    url = URL_GET_JOB.format(job_id=job_id)
    job_status = basic_func.http_get(url, TOKEN)
    basic_func.local_print("Get job status from {url}, job status: {status} ".
                           format(url=url, status=job_status))
    return job_status


def get_machine_list(arch):
    if arch is None or arch == "":
        arch = "all"
    url = URL_GET_Machine_List.format(arch=arch)
    machine_list = basic_func.http_get(url, TOKEN)
    basic_func.local_print("Get machine_list from {url}, machine list: {machine_list} ".
                           format(url=url, machine_list=machine_list))
    return machine_list["machine_list"]


def list_job(job_status):
    url = URL_LIST_JOB
    if job_status is not None:
        url = url + "?job_status=" + job_status
    job_list = basic_func.http_get(url, TOKEN)
    basic_func.local_print("list job from {url}, job list: {job_list} ".
                           format(url=url, job_list=job_list))
    return job_list


def cancel_jobs(job_ids):
    """
    :param job_ids: type: list
    :return: job_id in pkgpool
    """
    data_dict = {
        "job_ids": job_ids
    }
    response = basic_func.http_put(URL_CANCEL_JOBS, data_dict, TOKEN)
    basic_func.local_print("cancel job by post {url} with data: {data_dict}, response: {response}".
                           format(url=URL_CANCEL_JOBS, data_dict=data_dict, response=response))

    return
