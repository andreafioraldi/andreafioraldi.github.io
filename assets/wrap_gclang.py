#!/usr/bin/env python3

import subprocess
import json
import sys
import os

script_dir = os.path.dirname(os.path.realpath(os.path.abspath(__file__)))

is_cxx = "++" in sys.argv[0]

def cc_exec(args):
    if os.getenv("GCLANG_PATH"):
        cc_name = os.environ["GCLANG_PATH"]
    else:
        cc_name = "gclang"
    if is_cxx:
        if os.getenv("GCLANGXX_PATH"):
            cc_name = os.environ["GCLANGXX_PATH"]
        else:
            cc_name = "gclang++"
    argv = [cc_name] + args
    #print(" ".join(argv))
    return subprocess.run(argv)

def get_bc(filename):
    if os.getenv("GETBC_PATH"):
        cc_name = os.environ["GETBC_PATH"]
    else:
        cc_name = "get-bc"
    argv = ['get-bc', '-b', '-o', filename + '.bc', filename]
    #print(" ".join(argv))
    return subprocess.run(argv)

def common_opts():
    return [
      "-g",
      #"-fno-inline",
      #"-fno-unroll-loops",
      #"-O0",
      #"-fno-discard-value-names",
    ]

def cc_mode():
    args = common_opts()
    args += sys.argv[1:]
    
    return cc_exec(args)

def ld_mode():
    args = common_opts()
    
    outname = 'a.out'
    
    old_args = sys.argv[1:]
    i = 0
    while i < len(old_args):
        if old_args[i] == '-o':
            outname = old_args[i +1]
            args += [outname + '.bc', '-o', outname]
            i += 1
        elif not old_args[i].endswith(('.c', '.cc', '.cpp', '.h', '.hpp', '.o', '.obj', '.a', '.la')):
            args.append(old_args[i])
        i += 1

    with open(outname + '.link_bc.json', 'w') as j:
        json.dump({'original': old_args, 'stripped': args, 'name': outname}, j)
    
    return cc_exec(old_args)

def is_ld_mode():
    return not ("--version" in sys.argv or "--target-help" in sys.argv or
                "-c" in sys.argv or "-E" in sys.argv or "-S" in sys.argv or
                "-shared" in sys.argv)

if len(sys.argv) <= 1:
  cc_exec([])
elif is_ld_mode():
    ld_mode()
else:
    cc_mode()
