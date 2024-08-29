#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

import atexit
import os
import random
import re
import subprocess
import tempfile
import time
import uuid

from machine_manager import machine_manager, overrides
from sys_commands import run_subprocess_cmd

DOM_XML_TEMPLATE = '''
<domain type='kvm'>
  <name>{name}</name>
  <uuid>{uuid}</uuid>
  <memory unit='GiB'>{mem_gb}</memory>
  <currentMemory unit='GiB'>{mem_gb}</currentMemory>
  <vcpu placement='static'>{nr_cpus}</vcpu>
  <os>
    <type arch='{arch}' machine='{machine_type}'>hvm</type>
    <boot dev='hd'/>
    {os_opts}
  </os>
  <features>
    <apic/>
  </features>
  <cpu mode='host-passthrough' check='none'/>
  <on_poweroff>destroy</on_poweroff>
  <on_reboot>restart</on_reboot>
  <on_crash>destroy</on_crash>
  <devices>
    <emulator>{qemu_bin}</emulator>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='{image}'/>
      <target dev='vda' bus='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x04' function='0x0'/>
    </disk>
    <controller type='pci' index='0' model='pcie-root'/>
    <controller type='pci' index='2' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='2' port='0x9'/>
      <alias name='pci.2'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x1'/>
    </controller>
    <controller type='pci' index='3' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='3' port='0xa'/>
      <alias name='pci.3'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x2'/>
    </controller>
    <controller type='pci' index='4' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='4' port='0xb'/>
      <alias name='pci.4'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x3'/>
    </controller>
    <controller type='pci' index='5' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='5' port='0xc'/>
      <alias name='pci.5'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x4'/>
    </controller>
    <controller type='pci' index='6' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='6' port='0xd'/>
      <alias name='pci.6'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x5'/>
    </controller>
    <controller type='pci' index='7' model='pcie-root-port'>
      <model name='pcie-root-port'/>
      <target chassis='7' port='0xe'/>
      <alias name='pci.7'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x01' function='0x6'/>
    </controller>
    <interface type='network'>
      <mac address='{mac}'/>
      <source network='default6'/>
      <model type='virtio'/>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </interface>
    <console type='pty'>
      <target type='serial' port='0'/>
    </console>
    <controller type='virtio-serial' index='0'>
      <alias name='virtio-serial0'/>
      <address type='pci' domain='0x0000' bus='0x03' slot='0x00' function='0x0'/>
    </controller>
    <memballoon model='virtio'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
    </memballoon>
    <rng model='virtio'>
      <backend model='random'>/dev/urandom</backend>
      <alias name='rng0'/>
      <address type='pci' domain='0x0000' bus='0x05' slot='0x00' function='0x0'/>
    </rng>
  </devices>
</domain>
'''

class kvm_manager(machine_manager):
    possible_kvm_status = ["running", "idle", "paused", "in shutdown",
                           "shut off", "crashed", "pmsuspended"]

    def __init__(self, kvm_name, default_timeout):
        machine_manager.__init__(self, machine_name=kvm_name,
                                 default_timeout=default_timeout)
        self._kvm_name = kvm_name
        self._image = None

    @overrides(machine_manager)
    def is_phy_machine(self):
        return False

    @overrides(machine_manager)
    def init_test_environment(self):
        if self._image is None:
            raise RuntimeError("Please 'set_image' for cloning before "
                "'init_test_environment'.")

        self.create_guest(self._image, self._kvm_name)

        # Connect SSH
        self.ssh_connect()

    def create_guest(self, image, name):
        self.mac = self.gen_mac()
        arch = os.uname().machine
        qemu_bin = "/usr/bin/qemu-system-" + arch
        os_opts = ''
        if arch == 'aarch64':
            machine_type = 'virt'
            os_opts = '''
                <loader readonly='yes' type='pflash'>/usr/share/AAVMF/AAVMF_CODE.fd</loader>
                <nvram>/tmp/kernel_test_kvm_buster-aarch64_11138735_VARS.fd</nvram>
                '''
        else:
            machine_type = 'q35'
        xml = DOM_XML_TEMPLATE.format(
            qemu_bin=qemu_bin,
            machine_type=machine_type,
            os_opts=os_opts,
            name=name,
            mem_gb=20,
            nr_cpus=20,
            uuid=str(uuid.uuid4()),
            image=os.path.abspath(image),
            mac=self.mac,
            arch=arch,
            )
        domf = tempfile.NamedTemporaryFile(suffix=".xml", mode='w')
        domf.write(xml + "\n")
        domf.flush()
        print("Creating VM...")
        cmd = ['virsh', 'define', domf.name]
        subprocess.check_call(cmd)
        self._virsh_kvm_control("start")
        atexit.register(self.cleanup)

    def gen_mac(self):
        r1 = random.randint(1, 255)
        r2 = random.randint(1, 255)
        r3 = random.randint(1, 255)
        return "52:54:00:%02x:%02x:%02x" % (r1, r2, r3)

    def cleanup(self):
        cmd = ['virsh', 'destroy', self._kvm_name]
        subprocess.call(cmd)
        cmd = ['virsh', 'undefine', self._kvm_name]
        subprocess.call(cmd)

    @overrides(machine_manager)
    def wait_for_online(self):
        # The ip address will be available when KVM is started and online.
        # Poll ip address once every second, and set timeout to 30 seconds,
        # which should be enough for KVM to boot.
        self._local_print("Polling IP address...")
        start_time = time.time()
        while time.time() - start_time < 1800:
            cmd = "virsh domifaddr {} | grep ipv4".format(self._kvm_name)
            res = run_subprocess_cmd(cmd, timeout=self._default_timeout,
                                     no_print=True, capture_stdout=True,
                                     shell=True, allow_nonzero=True)
            if len(res) != 0:
                ip_addr = re.split(r'\s{2,}', res)[-1].split('/')[0]
                self._local_print("Found '{kvm}' IP address: {ip}".
                    format(kvm=self._kvm_name, ip=ip_addr))
                if not machine_manager.machine_ssh_open(ip_addr):
                    self._local_print("SSH not ready, try again...")
                    time.sleep(5)
                    continue
                self._machine_ip = ip_addr
                return

            time.sleep(15)

        raise RuntimeError("Cannot get IP address for ssh for '{kvm}' in 300s".
            format(kvm=self._kvm_name))

    @overrides(machine_manager)
    def reboot(self):
        self.ssh_close()
        self._virsh_kvm_control("shutdown")
        self._wait_for_kvm_status("shut off")
        self._virsh_kvm_control("start")

    @overrides(machine_manager)
    def test_cleanup(self):
        self._local_print("Perform the test cleanup...", begin_newline=True)
        machine_manager.test_cleanup(self)

        # Destroy and undefine KVM (if exist).
        kvm_exist, _ = \
            kvm_manager.check_kvm_status(self._kvm_name,
                                         timeout=self._default_timeout)
        if kvm_exist:
            # Force KVM to be destroyed before undefine it.
            self._virsh_kvm_control("destroy", allow_nonzero=True, timeout=100)
            self._virsh_kvm_control("undefine", args=["--remove-all-storage", "--nvram"], timeout=500)
            # Sanity check
            kvm_exist, _ = \
                kvm_manager.check_kvm_status(self._kvm_name,
                                             timeout=self._default_timeout)
            if kvm_exist:
                raise RuntimeError("ERROR: {kvm} should have been undefined".
                    format(kvm=self._kvm_name))

    @overrides(machine_manager)
    def install_and_boot_to_kernel(self, kernel_package_dir):
        # Install the kernel package
        self._install_kernel_package(kernel_package_dir)
        # Reboot to enter the new kernel
        self.reboot()
        # Reconnect the SSH
        self.ssh_connect()

    def set_image(self, image):
        self._image = image

    def _virsh_kvm_control(self, ctrl, args=[], capture_stdout=False,
                           allow_nonzero=False, timeout=None):
        destroy_cmd = ["virsh", ctrl, self._kvm_name] + args
        timeout = self._default_timeout if timeout is None else timeout
        return run_subprocess_cmd(destroy_cmd, timeout=timeout,
                                  capture_stdout=capture_stdout,
                                  allow_nonzero=allow_nonzero)

    def _wait_for_kvm_status(self, expect_status, timeout=None):
        if expect_status not in self.possible_kvm_status:
            raise RuntimeError("ERROR. Invalid KVM expect_status: '{status}'".
                format(status=expect_status))

        start_time = time.time()
        timeout = self._default_timeout if timeout is None else timeout
        while True:
            kvm_exist, kvm_status = \
                kvm_manager.check_kvm_status(self._kvm_name, timeout)
            if not kvm_exist:
                raise RuntimeError("ERROR. KVM '{kvm}' doesn't exist".
                    format(kvm=self._kvm_name))
            if kvm_status == expect_status:
                return
            time.sleep(1)
            if time.time() - start_time > timeout:
                raise RuntimeError("Timeout waiting for '{k}' to status '{s}'".
                    format(k=self._kvm_name, s=expect_status))

    @staticmethod
    def check_kvm_status(kvm_domain, timeout):
        cmd = "virsh list --all | grep \" {kvm} \"".format(kvm=kvm_domain)
        res = run_subprocess_cmd(cmd, timeout, no_print=True,
                                 capture_stdout=True, shell=True,
                                 allow_nonzero=True)

        kvm_exist, kvm_status = False, None
        if len(res) != 0:
            kvm_exist = True
            kvm_status = re.split(r'\s{2,}', res.replace(kvm_domain, ''))[-1]

        return kvm_exist, kvm_status
