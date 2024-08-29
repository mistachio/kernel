#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

"""
{script} tests the kernel packages (in the specified directory) on either KVM or
Physical machines. {script} interacts with the machine under test (KVM or
Physical) through SSH to install the kernel packages and conduct various kernel
tests.

For KVM, the testing environment is set up by cloning the already prepared base
KVM domain <base_kvm_domain> (specified through --base-kvm) to <test_kvm_domain>
(specified through --test-kvm), and the tests are run in <test_kvm_domain>. When
tests finish, the cloned <test_kvm_domain> will be undefined and deleted.

For Physical machine, two disk partitions need to be specified: --base-partition
and --test-partition. The base partition is where the root file system is mounted
when the test starts, and the test environment is set up by extracting the
prepared testing root file system gzip to the test partition. Then boot into the
test partition, and the tests are run in the test partition. When tests finish,
the machine will be reboot into the base partition to restore to the state where
the test starts. Following are the steps of this process:

1. (in base partition) extract test_root.gzip to the test partition
2. (in base partition) set up grub and reboot to test partition
3. (in test partition) install kernel and run tests
4. (in test partition) set up grub and reboot to base partition
5. (in base partition) finish

"""

import argparse
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor

import sys_commands
from kvm_manager import kvm_manager
from ssh_client import ssh_client
from unit_test import unit_test

multi_executor = ThreadPoolExecutor(max_workers=40)


def local_print(message, color=sys_commands.PCOLOR_NONE, begin_newline=False):
    if begin_newline:
        print()
    print(color + "{script}: {msg}".format(
         script=os.path.basename(__file__), msg=message),
         sys_commands.PCOLOR_END, flush=True)
    sys.stdout.flush()


def check_opts(opts):
    err = False

    # Check the existence of the sshkey file if specified
    if opts.ssh_pubkey_file is not None and \
       not os.path.isfile(opts.ssh_pubkey_file):
        print("ERROR. the specified --ssh-pubkey-file '{file}' ".
            format(file=opts.ssh_pubkey_file) + "doesn't exist.")
        err = True

    if err:
        raise RuntimeError("ERROR. error detected in the argument options.")

def get_opts():
    parser = argparse.ArgumentParser(
        description=__doc__.format(script=os.path.basename(__file__)),
        formatter_class=argparse.RawTextHelpFormatter)

    subparsers = \
        parser.add_subparsers(help="select machine type to run kernel tests",
                              dest="machine_type")
    subparsers.required = True

    # arguments for kernel tests on KVM
    parser_kvm = subparsers.add_parser('kvm', help='kvm virtual machine')

    parser_kvm.add_argument('-i', '--image', type=str, required=True,
                            metavar="<image>",
                            help="Image to create guest")

    parser_kvm.add_argument('-t', '--test-kvm', type=str, required=True,
                            metavar="<test_kvm_domain>",
                            help="name of the test KVM domain, which will be "
                                 "cloned from <base_kvm_domain> for kernel "
                                 "tests")

    # arguments for kernel tests on physical machine
    parser_phy = subparsers.add_parser('phy', help='physical machine')

    parser_phy.add_argument('-n', '--host-name', type=str, required=True,
                            metavar="<phy_host_name>",
                            help="host name of the physical machine to run "
                                 "kernel tests on (either ip or hostname)")

    parser_phy.add_argument('-b', '--base-partition-uuid', type=str, required=True,
                            metavar="<base_partition>",
                            help="the base system partition uuid of the physical"
                                 "machine, where the test partition is "
                                 "prepared from and recovered to")

    parser_phy.add_argument('-t', '--test-partition-uuid', type=str,
                            required=True, metavar="<test_partition>",
                            help="the test partition UUID (should match "
                                 "what's in /etc/fstab for the test image "
                                 "partition)")

    # Add the common arguments for both kvm and physical machine.
    for p in [parser_kvm]:
        p.add_argument('-y', '--tests-yml', type=str,
                       required=True, metavar="<tests_yml>",
                       help="the yml file that lists all the test yml files")

        p.add_argument('-l', "--log-dir", type=str,
                       required=True, metavar="<log_dir>",
                       help="the directory to store the test logs")

        p.add_argument('-k', '--kernel-package-dir', type=str,
                       required=True, metavar="<kernel_package_dir>",
                       help="the directory that has the kernel package "
                            "files (e.g. linux-*.deb) to be tested")

        p.add_argument('-s', '--ssh-auth-method', type=str,
                       required=True, choices=ssh_client.AUTH_METHODS,
                       help="authentication method used for ssh connection")

        p.add_argument('-p', '--ssh-pubkey-file', type=str,
                       help="ssh public key file for sshkey authentication "
                            "(only needed when '-s/--ssh-auth-method sshkey' "
                            "is set")

    return parser.parse_args()

def get_test_machine(opts):
    machine = kvm_manager(kvm_name=opts.test_kvm,
                          default_timeout=10)
    machine.set_image(opts.image)
    return machine

def run_kernel_test(machine, kernel_package_dir, u_tests):
    _, orig_uname = machine.ssh_exec_command("uname -a", capture_stdout=True)

    local_print("Install kernel packages in '{machine}' and verify...".
        format(machine=machine.get_machine_name()), begin_newline=True)

    # Install the kernel packages
    machine.install_and_boot_to_kernel(kernel_package_dir)

    # Verify the new kernel is being used.
    _, new_uname = machine.ssh_exec_command("uname -a", capture_stdout=True)
    local_print("Verify the new kernel is being used. orig_uname:'{orig_uname}, "
                "new_uname:'{new_uname}'".
                format(orig_uname=orig_uname, new_uname=new_uname),
                begin_newline=True)

    ## Verify the new kernel is being used by checking with orig_uname
    #if orig_uname == new_uname:
    #    raise RuntimeError("ERROR. old kernel is still being used in "
    #        "'{machine}' ".format(machine=machine.get_machine_name()) + \
    #        "(by checking 'uname -a')")
    #else:
    #    local_print("The new kernel is correctly installed in {machine}".
    #        format(machine=machine.get_machine_name()))

    out_put_result, print_color, success = u_tests.run_tests(machine)
    return out_put_result, print_color, success


def main():
    opts = get_opts()
    check_opts(opts)
    u_tests = unit_test(opts.tests_yml, opts.log_dir)

    machine = None

    try:
        machine = get_test_machine(opts)
        machine.ssh_username_and_auth("root", opts.ssh_auth_method,
                                      opts.ssh_pubkey_file)
        machine.init_test_environment()
        run_kernel_test(machine, opts.kernel_package_dir, u_tests)
    except BaseException:
        traceback.print_exc()
        sys.stdout.flush()
        sys.exit(1)
    finally:
        if machine is not None:
            machine.test_cleanup()


if __name__ == "__main__":
    main()
    sys.exit(0)
