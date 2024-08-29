#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

import os
import shutil
import sys
import time

import sys_commands

try:
    from schema import And, Optional, Schema, SchemaError, Use
except ImportError:
    print("ERROR: Please install 'schema' module for python3:")
    print("   sudo apt-get install python3-pip")
    print("   sudo pip3 install schema")
    raise
try:
    import yaml
except ImportError:
    print("ERROR: Please install 'yaml' module for python3:")
    print("   sudo apt-get install python3-pip")
    print("   sudo pip3 install pyyaml")
    raise

test_schema = Schema({
    'name': And(Use(str)),
    'repo': {
        'url': And(Use(str)),
        'branch': And(Use(str)),
        'timeout': And(Use(str)),
    },
    'before_test': {
        'script': And(Use(list)),
        'timeout': And(Use(int)),
        'repeat_on_fail': And(Use(int)),
    },
    'test': {
        'script': And(Use(list)),
        'timeout': And(Use(int)),
        'repeat': And(Use(int)),
    },
    Optional('log_dir'): And(Use(list)),
    Optional('test_on_kvm'): And(Use(bool)),
    Optional('copy_kernel_source'): And(Use(bool)),
    Optional('skip_phy_machine'): And(Use(list)),
})

def local_print(message, color=sys_commands.PCOLOR_NONE, begin_newline=False):
    if begin_newline:
        print()
    print(color + "{ts:.3f} {script}: {msg}".format(
         ts=time.time(),
         script=os.path.basename(__file__), msg=message),
         sys_commands.PCOLOR_END, flush=True)

class unit_test:
    def __init__(self, tests_yml, log_dir):
        tests = yaml.load(open(tests_yml, 'r'), Loader=yaml.Loader)
        self._test_list = []
        self._log_dir = log_dir

        # Create a fresh log directory
        if os.path.exists(log_dir):
            shutil.rmtree(log_dir)
        os.mkdir(log_dir)

        # No test specified
        if tests is None:
            return

        t = self._load_and_verify_test_yml(tests_yml)
        # Insert the test yml file name
        t['_yml_file_name'] = os.path.basename(tests_yml)
        self._show_test_config(t)
        # Insert the result dict, which will be filled later in 'run_tests'
        t['_result'] = {
            'skip': False,
            'before_test_fail': True,
            'test_success_num': 0
        }
        self._test_list.append(t)
        


    def run_tests(self, machine):
        success = True
        machine.ssh_exec_command("apt-get install -y git", out=None, timeout=500)
        for test in self._test_list:
            # Check if this machine should be skipped for this test
            if self._test_skip_machine(machine, test):
                test['_result']['skip'] = True
                local_print("{machine} Skip unit test '{test}' ({file})".
                            format(test=test['name'], file=test['_yml_file_name'],
                                   machine=machine.get_machine_name()),
                            color=sys_commands.PCOLOR_GREEN)
                continue

            # Create directory inside the specified log_dir for this test
            local_log_dir = os.path.join(self._log_dir, test['name'] + "-" + machine.get_machine_ip())
            os.mkdir(local_log_dir)
            # Run test
            if self._run_single_test(machine, test, local_log_dir):
                local_print(
                    "{machine} Unit test '{test}' ({file}) SUCCEEDED".
                    format(test=test['name'], file=test['_yml_file_name'],
                           machine=machine.get_machine_name()),
                    color=sys_commands.PCOLOR_GREEN)
            else:
                success = False
                local_print(
                    "{machine} Unit test '{test}' ({file}) FAILED".
                    format(test=test['name'], file=test['_yml_file_name'],
                           machine=machine.get_machine_name()),
                    color=sys_commands.PCOLOR_RED)

        out_put_result, print_color = self._print_test_result(machine)

        # Raise error if any test failed

        if not success and machine.__class__.__name__ != "idc_phy_manager":
            raise RuntimeError("ERROR. Some unit test failed.")

        return out_put_result, print_color, success

    def _show_test_config(self, test):
        local_print("Got unit test '{test}' ({file}):".format(
            test=test['name'], file=test['_yml_file_name']),
            color=sys_commands.PCOLOR_GREEN)
        print(yaml.dump(test))

    def _print_test_result(self, machine):
        out_put_result = []
        result_title = "{machine} Unit Test Result:".format(machine=machine.get_machine_name())
        local_print(result_title, color=sys_commands.PCOLOR_GREEN, begin_newline=True)
        out_put_result.append(result_title)

        print_color = sys_commands.PCOLOR_GREEN
        for test in self._test_list:
            r = test['_result']
            result_str = "{machine}    {test}: ".format(machine=machine.get_machine_name(), test=test['name'])
            if r['skip']:
                result_str += "skipped"
            elif r['before_test_fail']:
                result_str += "failed in before_test"
                print_color = sys_commands.PCOLOR_RED
            else:
                result_str += "{p}/{t} success".format(
                    p=r['test_success_num'], t=test['test']['repeat'])
                if r['test_success_num'] < test['test']['repeat']:
                    print_color = sys_commands.PCOLOR_RED

            local_print(result_str, color=print_color)
            out_put_result.append(result_str)
        return out_put_result, print_color

    def _load_and_verify_test_yml(self, t_yml_file):
        t = yaml.load(open(t_yml_file, 'r'), Loader=yaml.Loader)
        try:
            test_schema.validate(t)
        except SchemaError:
            print("ERROR. Schema error in test yml file: {}".format(t_yml_file))
            raise
        return t

    def _test_skip_machine(self, machine, test):
        if machine.is_phy_machine():
            # machine is physicla machine
            if 'skip_phy_machine' not in test:
                # 'skip_phy_machine' not specified in the test yml, assume not
                # skip any physical machine.
                return False
            return 'all' in test['skip_phy_machine'] or \
                machine.get_machine_ip() in test['skip_phy_machine'] or \
                machine.get_machine_name() in test['skip_phy_machine']
        else:
            # machine is KVM
            if 'test_on_kvm' not in test:
                # 'test_on_kvm' not specified in the test yml, assume skip KVM
                return True
            return not test['test_on_kvm']

    def _run_single_test(self, machine, test, local_log_dir):
        test_name = test['name']

        if "KDUMP-TOOLS-TEST" == test_name:
            # run kdump test
            local_print("==================== run kdump test of kdump-tools ==================== ",
                        color=sys_commands.PCOLOR_GREEN)
            ret = machine.test_kdump()

            test['_result']['before_test_fail'] = False

            test_itr_log_dir = os.path.join(local_log_dir, test_name + ".test")
            os.mkdir(test_itr_log_dir)
            self._copy_test_log(machine, test, test_itr_log_dir)

            if ret:
                test['_result']['test_success_num'] += 1
            return ret

        local_print("{machine} Running unit test '{test}' ({file})".
                    format(test=test_name, file=test['_yml_file_name'],
                           machine=machine.get_machine_name()),
                    color=sys_commands.PCOLOR_GREEN)

        # Check out the test repo
        self._clone_test_repo(machine, test)

        # Run the before test script (return immediately when any command fails)
        build_log = os.path.join(local_log_dir, test_name+".before_test.out")
        local_print("{machine} Running before test tasks for '{t}' (log: {l})...".format(
            machine=machine.get_machine_name(), t=test_name, l=build_log))
        with open(build_log, "a", newline='\n') as log_file:
            for i in range(test['before_test']['repeat_on_fail']):
                local_print("{machine} Running before_test script (iteration {itr}, log: {l})...".
                            format(machine=machine.get_machine_name(), itr=i+1, l=build_log))
                ret = self._machine_exec_test_command(
                    machine, test['before_test']['script'],
                    test['before_test']['timeout'], log_file, "before test script")
                if ret == 0:
                    test['_result']['before_test_fail'] = False
                    break
                time.sleep(60)
            if test['_result']['before_test_fail']:
                return False

        if 'copy_kernel_source' in test:
            if test['copy_kernel_source']:
                self._copy_kernel_source(machine)
        # Run the test (return immediately when any command fails)
        success = True
        for i in range(test['test']['repeat']):
            # Create log directory for this test iteration
            test_itr_log_dir = os.path.join(
                local_log_dir, test_name + ".test.{itr}".format(itr=i+1))
            os.mkdir(test_itr_log_dir)
            test_log = os.path.join(test_itr_log_dir, test_name+".test.out")
            local_print("{machine} Running '{t}' test (iteration {itr}, log: {l})...".
                        format(machine=machine.get_machine_name(), t=test_name, itr=i+1, l=test_log))
            with open(test_log, "a", newline='\n') as log_file:
                ret = self._machine_exec_test_command(
                    machine, test['test']['script'], test['test']['timeout'],
                    log_file, "test script (iteration {itr})".format(itr=i+1))
                # Copy log from the specified test log directories
                self._copy_test_log(machine, test, test_itr_log_dir)
                if ret == 0:
                    test['_result']['test_success_num'] += 1
                else:
                    success = False

        return success

    def _copy_kernel_source(self, machine):
        local_print("====== copy kernel source")
        tarf = "/var/tmp/kernel_source.tar"
        sys_commands.run_subprocess_cmd("git archive HEAD >" + tarf, shell=True, timeout=1000)
        local_print("put file " + tarf)
        machine.put_file(tarf, tarf)
        machine.ssh_exec_command("mkdir -p /var/tmp/kernel_source; tar -C /var/tmp/kernel_source -xf " + tarf)

    def _clone_test_repo(self, machine, test):
        local_print("{machine} Cloning '{test}' test repo...".format(machine=machine.get_machine_name(),
                                                                     test=test['name']))

        if test['repo']['url'] is None:
            local_print("repo is NULL, skipping")
            return

        git_cmd = "git clone --depth 1 --branch {branch} {git}".format(
            branch=test['repo']['branch'], git=test['repo']['url'])
        timeout = test['repo']['timeout']

        if not machine.is_phy_machine():
            local_print("Add 60 seconds to the specified clone timeout in KVM, "
                        "as it takes longer to establish connection in KVM (for some "
                        "reason)")
            timeout += 60

        # Try to clone 3 times to avoid failures due to unstable connection
        try_num = 3
        for i in range(1, try_num+1):
            # If there exists a directory with the same name as the test repo,
            # remove it before cloning.
            test_dir = test['repo']['url'].split('/')[-1].split('.git')[0]
            r, _ = machine.ssh_exec_command("ls {}".format(test_dir), out=None,
                                            allow_nonzero=True)
            if r == 0:
                machine.ssh_exec_command("rm -rf {}".format(test_dir))

            local_print("{machine} Clone try {i}...".format(machine=machine.get_machine_name(), i=i))
            start_time = time.time()
            ret, _ = machine.ssh_exec_command(git_cmd, timeout=timeout,
                                              allow_nonzero=(i<try_num))
            if ret == 0:
                local_print("{machine} Finish cloning in {sec} seconds".format(
                    machine=machine.get_machine_name(), sec=time.time() - start_time),
                    color=sys_commands.PCOLOR_BLUE)
                break

    def _machine_exec_test_command(self, machine, script, timeout, out, run_msg):
        for cmd in script:
            local_print("{machine_ip} Run {msg}: '{cmd}' (timeout: {tm})...".format(
                machine_ip=machine.get_machine_ip(), msg=run_msg, cmd=cmd, tm=timeout),
                color=sys_commands.PCOLOR_YELLOW)

            start_time = time.time()
            ret, _ = machine.ssh_exec_command(cmd, timeout=timeout, out=out,
                                              allow_nonzero=True)
            local_print("{machine_ip} Finish '{cmd}' in {sec} seconds".format(
                machine_ip=machine.get_machine_ip(), cmd=cmd, sec=time.time() - start_time),
                color=sys_commands.PCOLOR_BLUE)
            if ret != 0:
                local_print("{machine_ip} ERROR running'{cmd}' (ret={ret})".format(
                    machine_ip=machine.get_machine_ip(), cmd=cmd, ret=ret), color=sys_commands.PCOLOR_RED)
                return ret

        return 0

    def _copy_test_log(self, machine, test, local_log_dir):
        if 'log_dir' not in test:
            # 'log_dir' not specified in test, so no log needs to be copied
            return

        for test_log_dir in test['log_dir']:
            local_print("{machine} Download test log from '{rd}' in {machine} to '{ld}'".
                        format(rd=test_log_dir, machine=machine.get_machine_name(),
                               ld=local_log_dir))
            machine.download_machine_dir_files(machine_dir=test_log_dir,
                                               local_dir=local_log_dir)
