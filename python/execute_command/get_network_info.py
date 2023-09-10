#!/usr/bin/env python3
import subprocess, os, configparser, re
from collections import namedtuple


def get_windows_saved_ssids():
    """Returns a list of saved SSIDs in a Windows machine using netsh command"""
    
    command = "netsh wlan show profile"
    network_profiles = subprocess.check_output(command.split(' '), shell=True).decode()
    network_names = re.findall("(?:Profile\s*:\s*)(.*)", network_profiles)
    return network_names

def get_windows_saved_wifi_passorwds(verbose=1):
    """Extracts saved Wi-Fi passwords saved in a Windows machine, this function extracts data using netsh
    command in Windows
    Args:
        verbose (int, optional): whether to print saved profiles real-time. Defaults to 1.
    Returns:
        [list]: list of extracted profiles, a profile has the fields ["ssid", "ciphers", "key"]
    """
    
    ssids = get_windows_saved_ssids()
    Profile = namedtuple("Profile", ["ssid", "ciphers", "key"])
    profiles = []
    
    for ssid in ssids:
        ssid_details = subprocess.check_output(["netsh", "wlan", "show", "profile", ssid, "key=clear"], shell=True).decode()
        
        ciphers = re.findall("(?:Cipher\s*:\s*)(.*)", ssid_details)
        ciphers = "/".join([c.strip() for c in ciphers])
        
        key = re.findall("(?:Key Content\s*:\s*)(.*)", ssid_details)
        if len(key)!=0:
            key = key[0].strip()
        else:
            key = None
        
        data = {"ssid":ssid.strip(), "ciphers":ciphers, "key":key}
        
        profile = Profile(**data)
        profiles.append(profile)
        
        if verbose>=1:
            print_windows_profile(profile)
    return profiles
    
def print_windows_profile(profile):
	"""Prints a single profile on Windows"""
	print(f"{str(profile.ssid):26}{str(profile.ciphers):13}{str(profile.key):<20}")   
	

def print_windows_profiles(verbose):
    """Prints all extracted SSIDs along with Key on Windows"""
    print("SSID                     CIPHER(S)      KEY")
    print("-"*50)
    get_windows_saved_wifi_passorwds(verbose)



def get_linux_saved_wifi_passwords(verbose=1):   
	"""Extracts saved Wi-Fi passwords saved in a Linux machine, this function extracts data in the
	`/etc/NetworkManager/system-connections/` directory
	Args:
	verbose (int, optional): whether to print saved profiles real-time. Defaults to 1.
	Returns:
	[list]: list of extracted profiles, a profile has the fields ["ssid", "auth-alg", "key-mgmt", "psk"]
	"""
	network_connections_path = "/etc/NetworkManager/system-connections/"
	fields = ["ssid", "auth-alg", "key-mgmt", "psk"]
	Profile = namedtuple("Profile", [f.replace("-", "_") for f in fields])
	profiles = []
	for file in os.listdir(network_connections_path):
		data = { k.replace("-", "_"): None for k in fields }
		config = configparser.ConfigParser()
		config.read(network_connections_path+'/'+file)
		for _, section in config.items():
			for k, v in section.items():
				if k in fields:
					data[k.replace('-','_')] = v
		profile = Profile(**data)
		if verbose>=1:
			print_linux_profile(profile)
		profiles.append(profile)
	return profiles
	
def print_linux_profile(profile):
	"""Prints a single profile on screen"""
	print(f'{str(profile.ssid):23} {str(profile.auth_alg):8} {str(profile.key_mgmt):10} {str(profile.psk):54}')

def print_linux_profiles(verbose):
	"""Prints all extractd SSIDs along with KEY (PSK) on LINUX"""
	print("SSID \t\t\tAUTH\tKEY-MGMT\tPSK")
	print("-"*65)
	get_linux_saved_wifi_passwords(verbose)
	
def print_profiles(verbose = 1):
	if os.name == "posix":
		print_linux_profiles(verbose)
	elif os.name == "nt":
		print_windows_profiles(verbose)
	else:
		raise NotImplemented("Code only works for either LINUX of WINDOWS.")
		
	
if __name__ == "__main__":
	print_profiles()


