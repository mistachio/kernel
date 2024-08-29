#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

import os
import sys
import time
import socket
import sys_commands
try:
    # paramiko module doesn't come with the default Python3 package
    import paramiko
except ImportError:
    print("ERROR: Please install 'paramiko' module for python3:")
    print("   sudo apt-get install python3-pip")
    print("   sudo pip3 install paramiko")
    print("   sudo pip3 install --upgrade paramiko")
    print("   sudo pip3 install paramiko[gssapi]")
    raise

class ssh_client:
    # The return value of the 'timeout' command when timeout occurs
    CMD_TIMEOUT_RET_VALUE = 124

    AUTH_METHOD_SSHKEY = "sshkey"
    AUTH_METHOD_KERBEROS = "kerberos"
    AUTH_METHODS = [AUTH_METHOD_SSHKEY, AUTH_METHOD_KERBEROS]

    def __init__(self, default_timeout):
        self._default_timeout = default_timeout
        self._ssh = None
        self._host_addr = None
        self._username = None
        self._auth_method = None
        self._ssh_pubkey_file = None

    def __del__(self):
        self.close()

    def set_username_and_auth(self, username, auth_method,
                              ssh_pubkey_file=None):
        self._username = username

        if auth_method not in self.AUTH_METHODS:
            raise RuntimeError("ERROR. Invalid ssh authentication method. "
                "Please select from: {}".format('/'.join(self.AUTH_METHODS)))

        if auth_method == self.AUTH_METHOD_SSHKEY:
            if ssh_pubkey_file is None:
                raise RuntimeError("ERROR. Must set the ssh public key file "
                    "for the selected authentication method: {}".
                    format(auth_method))
        elif auth_method == self.AUTH_METHOD_KERBEROS:
            #  Should NOT set the ssh public key file for the selected authentication method: kerberos
            ssh_pubkey_file = None

        self._auth_method = auth_method
        self._ssh_pubkey_file = ssh_pubkey_file

    def connect(self, host_addr, timeout=None):
        if self._username is None or self._auth_method is None:
            raise RuntimeError("ERROR. Please set the username and the ssh "
                "authentication method in 'set_username_and_auth' before the "
                "ssh connection")

        self._host_addr = host_addr

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        timeout = self._default_timeout if timeout is None else timeout
        start_time = time.time()
        while True:
            if time.time() - start_time > timeout:
                raise RuntimeError("ERROR. SSH connection to {client} time out".
                    format(client=self._get_client_name()))
            try:
                if self._auth_method == self.AUTH_METHOD_SSHKEY:
                    self._ssh.connect(host_addr, username=self._username,
                                      key_filename=self._ssh_pubkey_file,
                                      timeout=timeout)
                elif self._auth_method == self.AUTH_METHOD_KERBEROS:
                    self._ssh.connect(host_addr, username=self._username,
                                      gss_auth=True,
                                      gss_trust_dns=False,
                                      timeout=timeout)

                break
            except (paramiko.ssh_exception.NoValidConnectionsError,
                    paramiko.ssh_exception.SSHException) as e:
                # SSH transport is not ready. Try again in 1 second.
                self._local_print("retry for ssh {host_addr}, due to ssh_exception: "
                                  "{ssh_exception}".format(host_addr=host_addr, ssh_exception=e))
                time.sleep(1)
                continue

    def close(self):
        if self._ssh is not None:
            self._ssh.close()

    def _local_print(self, message, color=sys_commands.PCOLOR_NONE,
                     out=sys.stdout):
        if out is None:
            return
        # No color if not output to stdout
        c = color if out == sys.stdout else ''
        c_end = sys_commands.PCOLOR_END if out == sys.stdout else ''
        print(c + "SSH {client}: {msg}".format(
              client=self._get_client_name(), msg=message),
              c_end, file=out, flush=True)

    def _get_client_name(self):
        return "{usr}@{host}".format(usr=self._username, host=self._host_addr)

    def exec_command(self, cmd, timeout=None, capture_stdout=False,
                     allow_nonzero=False, out=sys.stdout, nonblock=False,
                     retries=0, retry_wait_secs=60):
        if self._ssh is None:
            raise RuntimeError("ERROR. SSH connection to {} is not established".
                format(self._get_client_name()))

        timeout = self._default_timeout if timeout is None else timeout

        for i in range(retries + 1):
            if i > 0:
                time.sleep(retry_wait_secs)

            if out is not None:
                self._local_print("executing '{cmd}' in {clt} with timeout={tm}...".
                    format(cmd=cmd, clt=self._get_client_name(), tm=timeout),
                    color=sys_commands.PCOLOR_YELLOW, out=out)
            _, ssh_stdout, ssh_stderr = self._ssh.exec_command(command=cmd,
                                                               timeout=timeout)
            if nonblock:
                return None, None

            stdout_content = None
            try:
                if capture_stdout:
                    stdout_content = ""
                stdout_line = ssh_stdout.readline()
                while stdout_line:
                    # Strip the newline at the end, as print will add newline.
                    self._local_print("(stdout)    " + stdout_line.strip(), out=out)
                    if capture_stdout:
                        stdout_content += stdout_line
                    stdout_line = ssh_stdout.readline()

                stderr_line = ssh_stderr.readline()
                while stderr_line:
                    self._local_print("(stderr)    " + stderr_line.strip(), out=out,
                                    color=sys_commands.PCOLOR_PINK)
                    stderr_line = ssh_stderr.readline()

                # Check the command exit value
                ret = ssh_stdout.channel.recv_exit_status()

            except socket.timeout:
                ret = self.CMD_TIMEOUT_RET_VALUE

            if ret == 0:
                return ret, stdout_content
                
        if not allow_nonzero and ret != 0:
            # Raise runtime error if the command doesn't return 0
            is_timeout = (ret == self.CMD_TIMEOUT_RET_VALUE)
            raise RuntimeError("ERROR. SSH command '{cmd}' in {client} returns "
                "{ret} (timeout: {tm})".
                format(cmd=cmd, client=self._get_client_name(), ret=ret,
                       tm=is_timeout))

        return ret, stdout_content

    def scp_file_to_client(self, src_file, dst_file):
        if self._ssh is None:
            raise RuntimeError("ERROR. SSH connection to {} is not established".
                format(self._get_client_name()))

        self._local_print("SCP file '{src}' to '{dst}' in {client}...".format(
            src=src_file, dst=dst_file, client=self._get_client_name()),
            color=sys_commands.PCOLOR_BLUE)
        ftp_client = self._ssh.open_sftp()
        ftp_client.put(src_file, dst_file)
        ftp_client.close()

    def scp_file_from_client(self, src_file, dst_file):
        if self._ssh is None:
            raise RuntimeError("ERROR. SSH connection to {} is not established".
                format(self._get_client_name()))

        self._local_print("SCP file '{src}' in {client} to '{dst}'...".format(
            src=src_file, dst=dst_file, client=self._get_client_name()),
            color=sys_commands.PCOLOR_BLUE)
        ftp_client = self._ssh.open_sftp()
        ftp_client.get(src_file, dst_file)
        ftp_client.close()

    def get_dir_file_attrs(self, dir_path):
        if self._ssh is None:
            raise RuntimeError("ERROR. SSH connection to {} is not established".
                format(self._get_client_name()))

        ftp_client = self._ssh.open_sftp()
        ret = ftp_client.listdir_attr(dir_path)
        ftp_client.close()
        return ret
