#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

import abc
import glob
import os
import socket
import stat
import sys
import time

import sys_commands
from ssh_client import ssh_client

kernel_packages = ["linux-headers*.deb",
                   "linux-image-*-a[m\|r][d\|m]64_*.deb",
                   "linux-libc*.deb"]

def overrides(interface_class):
    def overrider(method):
        assert method.__name__ in dir(interface_class), \
            "ERROR: the function '{}' marked as override doesn't exist ". \
                format(method.__name__) + "in the parent class '{}'". \
                format(interface_class.__name__)
        return method
    return overrider

class machine_manager(metaclass=abc.ABCMeta):
    SSH_PORT = 22

    def __init__(self, machine_name, default_timeout):
        self._default_timeout = default_timeout
        self._ssh_client = ssh_client(default_timeout=default_timeout)
        # self._machine_name is the name of the machine. For KVM machine, this
        # is the KVM domain name. For physical machine, this can be either the
        # machine's hostname or ip address.
        self._machine_name = machine_name
        # the machine's IP address, set in self.wait_for_online
        self._machine_ip = None
        # self._username is the username used to ssh connect to the machine,
        # whichi will be set in self.ssh_username_and_auth function.
        self._username = None

    @abc.abstractmethod
    def is_phy_machine(self):
        pass

    @abc.abstractmethod
    def init_test_environment(self):
        # Initialize the test environment. When returns, the machine should be
        # connected by SSH and ready to accept self.ssh_exec_command for tests.
        pass

    @abc.abstractmethod
    def wait_for_online(self):
        # Wait for the machine to be online (ready for ssh connection) and
        # set self._machine_ip for ssh connection.
        pass

    @abc.abstractmethod
    def reboot(self):
        # subclass to implement the reboot process
        pass

    @abc.abstractmethod
    def install_and_boot_to_kernel(self, kernel_package_dir):
        # Install kernel_packages in the specified directory and reboot into
        # the installed kernel. When returns, the machine should be connected
        # by SSH and ready to accept self.ssh_exec_command in the newly-
        # installed kernel environment.
        pass

    @abc.abstractmethod
    def test_cleanup(self):
        self.ssh_close()
        # subclass to implement the extra cleanup

    @staticmethod
    def check_kernel_dir_err(kernel_package_dir):
        err = False

        # Sanity check: make sure <kernel_package_dir> exists
        if not os.path.isdir(kernel_package_dir):
            print("ERROR: the specified --kernel-package-dir '{dir}' ".
                format(dir=kernel_package_dir) + "doesn't exist.")
            err = True

        # Sanity check: make sure the kernel packages exist in <kernel_package_dir>
        for package in kernel_packages:
            if not glob.glob(os.path.join(kernel_package_dir, package)):
                print("ERROR: the kernel package '{ker}' doesn't exist in ".
                    format(ker=package) + "specified --kernel-package-dir '{dir}'".
                    format(dir=kernel_package_dir))
                err = True

        return err

    @classmethod
    def machine_ssh_open(cls, machine_ip):
        af = socket.AF_INET
        if len(machine_ip.split('.')) != 4:
            af = socket.AF_INET6
        sock = socket.socket(af, socket.SOCK_STREAM)
        res = sock.connect_ex((machine_ip, cls.SSH_PORT))
        sock.close()
        return res == 0

    def get_machine_name(self):
        return self._machine_name

    def get_machine_ip(self):
        return self._machine_ip

    def ssh_username_and_auth(self, username, auth_method,
                              ssh_pubkey_file=None):
        self._username = username
        self._ssh_client.set_username_and_auth(
            username=username, auth_method=auth_method,
            ssh_pubkey_file=ssh_pubkey_file)

    def ssh_connect(self):
        self.wait_for_online()
        self._ssh_client.connect(host_addr=self._machine_ip)
        # Send a pwd command to verify the machine is ready to take ssh command.
        # For the physical machine immediately after reboot, even though the SSH
        # port is open and connected, it may still take a while for the machine
        # to fully come up and execute the first SSH command, so set the timeout
        # to 180 seconds (3 min).
        self._local_print("SSH connected, waiting for machine up to take SSH "
            "command (timeout = 3 minutes)")
        self.ssh_exec_command("pwd", timeout=180, out=None)

    def ssh_close(self):
        self._ssh_client.close()

    def ssh_exec_command(self, cmd, timeout=None, capture_stdout=False,
                         allow_nonzero=False, out=sys.stdout,
                         nonblock=False, retries=0, retry_wait_secs=60):
        return self._ssh_client.exec_command(
            cmd=cmd, timeout=timeout, capture_stdout=capture_stdout,
            allow_nonzero=allow_nonzero, out=out, nonblock=nonblock,
            retries=retries, retry_wait_secs=retry_wait_secs)

    def download_machine_dir_files(self, machine_dir, local_dir):
        try:
            file_attr_list = self._ssh_client.get_dir_file_attrs(machine_dir)
        except FileNotFoundError:
            self._local_print("Directory '{dir}' not found on the machine "
                "'{machine}', ignore download.".format(
                dir=machine_dir, machine=self.get_machine_name()),
                color=sys_commands.PCOLOR_PINK)
            return

        if not os.path.isdir(local_dir):
            self._local_print("Local direcotry '{dir}' not found, ignore "
                "download".format(dir=local_dir),
                color=sys_commands.PCOLOR_PINK)
            return

        for file_attr in file_attr_list:
            mf = os.path.join(machine_dir, file_attr.filename)
            lf = os.path.join(local_dir, file_attr.filename)
            if stat.S_ISDIR(file_attr.st_mode):
                # Create local subdirectory
                os.mkdir(lf)
                self._local_print("Recursively download files in {mf} to {lf}".
                    format(mf=mf, lf=lf), color=sys_commands.PCOLOR_BLUE)
                self.download_machine_dir_files(mf, lf)
            else:
                self._ssh_client.scp_file_from_client(src_file=mf, dst_file=lf)

    def put_file(self, src, dst):
        return self._ssh_client.scp_file_to_client(src_file=src, dst_file=dst)

    def _ssh_apt_update(self):
        # We need --allow-releaseinfo-change option because we may see
        # following errors when debian release a new stable version on latest
        # debian version:
        #
        # Repository
        # 'http://security.debian.org/debian-security buster/updates InRelease'
        # changed its 'Suite' value from 'stable' to 'oldstable'
        #
        # On the other hand, old debian versions (like version 8) does not
        # support --allow-releaseinfo-change option, and they will not have
        # above error too, so the first apt-get update -y will always work on
        # old versions.
        self.ssh_exec_command("sudo apt-get update -y || sudo apt-get update --allow-releaseinfo-change -y",
                timeout=300, retries=3, retry_wait_secs=60)
    def _install_kernel_package(self, kernel_package_dir):
        self._install_depends_package()

        for package in kernel_packages:
            package_path = \
                glob.glob(os.path.join(kernel_package_dir, package))[0]
            package_name = os.path.basename(package_path)

            if self._username == "root":
                ssh_package_path = '/root/{name}'.format(
                    usr=self._username, name=os.path.basename(package_name))
            else:
                ssh_package_path = '/home/{usr}/{name}'.format(
                    usr=self._username, name=os.path.basename(package_name))
            self._ssh_client.scp_file_to_client(src_file=package_path,
                                                dst_file=ssh_package_path)
            try:
                self._dpkg_install(ssh_package_path)
            except:
                ret, stdout_content = self.ssh_exec_command(
                    "sudo lsof /var/lib/dpkg/lock*", allow_nonzero=True)
                if ret == 0:
                    self.ssh_exec_command(
                            "sudo rm -f /var/lib/dpkg/lock*", allow_nonzero=True)
                self._dpkg_install(ssh_package_path)

    def _update_grub(self):
        ret, installed_kernel_version = self.ssh_exec_command(
            "dpkg -I /root/linux-image-*-a[m\|r][d\|m]64_*.deb | grep Description | awk '{print $5}'",
            capture_stdout=True, allow_nonzero=True)
        installed_kernel_version = str(installed_kernel_version).replace('\n', '').replace('\r', '').strip()
        self._local_print("installed_kernel_version: {installed_kernel_version}".format(
            installed_kernel_version=installed_kernel_version))

        if ret != 0:
            raise RuntimeError("failed to get newly installed kernel version")

        get_grub_order = 'index=0 && cat /boot/grub/grub.cfg | grep "Debian GNU/Linux, with Linux " | while read ' \
                         'line; do if [[ $line =~ "{installed_kernel_version}" ]]; then echo $index && exit 0 ; fi ' \
                         '&& let index+=1 ;done'.format(installed_kernel_version=installed_kernel_version)
        ret, grub_order = self.ssh_exec_command(get_grub_order, capture_stdout=True, allow_nonzero=True)
        grub_order = str(grub_order).replace('\n', '').replace('\r', '').strip()
        self._local_print("grub_order: {grub_order}".format(grub_order=grub_order))
        if grub_order is None or "" == grub_order:
            raise RuntimeError("failed to get newly installed kernel in grub file")

        update_grub = "sed -i 's/GRUB_DEFAULT=.*/GRUB_DEFAULT=\"Advanced options for Debian GNU\/Linux>Debian " \
                      "GNU\/Linux, with Linux {installed_kernel_version}\"/g' /etc/default/grub && " \
                      "/usr/sbin/update-grub && " \
                      "/usr/sbin/update-grub2".format(installed_kernel_version=installed_kernel_version)
        self.ssh_exec_command(update_grub, allow_nonzero=True)

    def _dpkg_install(self, path):
        # Install the kerne package
        # Ideally the machine should have all the dependencies installed
        # already (libraries for linux-tools, for example), but in order
        # for the CI procedure to be a bit more robust, we try 'apt-get
        # install -f' first if we need some packages from the apt source,
        # before calling the install a failure.
        self.ssh_exec_command(
            "sudo apt-get install -f -y", timeout=300)
        self.ssh_exec_command(
            "sudo dpkg -i {}".format(path), timeout=900)

    def _local_print(self, message, color=sys_commands.PCOLOR_NONE,
                     begin_newline=False):
        if begin_newline:
            print()
        print(color + "{machine}: {msg}".format(machine=self._machine_name,
                                                msg=message),
              sys_commands.PCOLOR_END, flush=True)

    def trigger_crash(self):
        ret, _ = self.ssh_exec_command("dpkg -l | grep kdump-tools", allow_nonzero=True)
        if ret != 0:
            raise RuntimeError("ERROR. kdump-tools is not installed, could not test crash")

        self.ssh_exec_command("sync")
        self.ssh_exec_command("echo c > /proc/sysrq-trigger", nonblock=True)
        self.ssh_close()
        # Wait for ssh port to be closed to make sure the reboot has started.
        # Set timeout to 30 seconds.
        self._local_print("crash command sent and wait for SSH port close "
                          "(timeout 30 minutes)...")
        start_time = time.time()
        while time.time() - start_time < 300:
            if not self.machine_ssh_open(machine_ip=self._machine_ip):
                # server trigger crash and shutdown successfully
                return
            time.sleep(1)
        self._local_print("ERROR. trigger crash and shutdown failed")
        raise RuntimeError("Time out waiting for SSH connection close "
                           "'{machine}' in 300 seconds".format(machine=self._machine_name))

    def test_kdump(self):
        self.ssh_exec_command("ls /var/crash | grep bak-", allow_nonzero=True)
        _, orig_crash_num = self.ssh_exec_command("ls /var/crash | grep bak- | wc -l", capture_stdout=True)

        self.trigger_crash()
        self.ssh_connect()

        _, new_crash_num = self.ssh_exec_command("ls /var/crash | grep bak- | wc -l", capture_stdout=True)

        if new_crash_num == orig_crash_num:
            self._local_print("ERROR. Test kdump-tools failed, NO new crash file generated",
                              color=sys_commands.PCOLOR_RED)
            return False
        else:
            self.ssh_exec_command("ls /var/crash | grep bak-", allow_nonzero=True)
            self._local_print("Test kdump-tools successfully, new crash file generated",
                              color=sys_commands.PCOLOR_GREEN)
            return True

    def _install_depends_package(self):
        # depends for 'dpkg -i {kernel packages}'
        self._ssh_apt_update()
        self.ssh_exec_command("apt-get install -y libdw1 libnuma1 libunwind8",
                               timeout=300, retries=3, retry_wait_secs=60)
        # self.ssh_exec_command("export DEBIAN_FRONTEND=noninteractive;if [[ $(grep 'bookworm' /etc/os-release) ]]; then apt-get install -y kdump-tools -t lyra-private;else apt-get install -y kdump-tools -t $(lsb_release -c|awk '{print $NF}')-private;fi",
        #                        timeout=300, retries=3, retry_wait_secs=60)
