#!/usr/bin/env python3
from collections import namedtuple
import os, configparser

def get_linux_saved_wifi_passwords(verbose=1):
    network_connections_path = "/etc/NetworkManager/system-connections/"
    fields = ["ssid", "auth-alg", "key-mgmt", "psk"]
    Profile = namedtuple("Profile", [f.replace("-", "_") for f in fields])
    #P = Profile('wewe', 'rer', 'wew', 'ewq2')
    #print(P)
    profiles = []
    directory_list = os.listdir(path=network_connections_path)

    for file in directory_list:
        data = {k.replace("-", "_"): None for k in fields}
        config = configparser.ConfigParser()
        config.read(os.path.join(network_connections_path, file))
        print(config.items())
get_linux_saved_wifi_passwords()