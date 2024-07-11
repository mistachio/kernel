#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2024 ByteDance.

import os
import re
import subprocess
import sys

PCOLOR_NONE = ''
PCOLOR_RED = '\033[31m'
PCOLOR_GREEN = '\033[32m'
PCOLOR_YELLOW = '\033[33m'
PCOLOR_BLUE = '\033[34m'
PCOLOR_PINK = '\033[35m'
PCOLOR_END = '\033[m'

def local_print(message, color=PCOLOR_NONE):
    print(color + "{script}: {msg}".format(
        script=os.path.basename(__file__), msg=message),
        PCOLOR_END, flush=True)

def run_subprocess_cmd(cmd, timeout, no_print=False, capture_stdout=False,
                       shell=False, allow_nonzero=False):
    if not no_print:
        local_print("executing '{cmd}' with timeout={tm}...".
            format(cmd=cmd if shell else ' '.join(cmd), tm=timeout),
            color=PCOLOR_YELLOW)

    stdout = subprocess.PIPE if capture_stdout else None
    # when nonzero return value is allowed, suppress the stderr.
    stderr = subprocess.DEVNULL if allow_nonzero else None
    res = subprocess.run(cmd, timeout=timeout, stdout=stdout,
                         stderr=stderr, shell=shell)

    if not allow_nonzero and res.returncode != 0:
        # Raise runtime error if the command doesn't return 0
        raise RuntimeError("Command '{cmd}' returns {ret}".
            format(cmd=cmd, ret=res.returncode))

    if capture_stdout:
        # The stdout value is byte sequence, so decode it to convert to string
        # and strip the newline at the end.
        return res.stdout.decode('utf-8').strip()
    else:
        return None
