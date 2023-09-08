#!/usr/bin/env python3

import subprocess

command = "msg * You've been hacked."
subprocess.Popen(command, shell=True)