#!/usr/bin/env python3
import subprocess as sp
sp.call("ifconfig eth0 down", shell=True)
sp.call("ifconfig eth0 hw ether 00:11:22:33:44:99", shell=True)
sp.call("ifconfig eth0 up", shell=True)
sp.call("ifconfig")