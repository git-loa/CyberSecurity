#!/usr/bin/env python3
import os, configparser
from collections import namedtuple
#!/usr/bin/python

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
		print("Coming Soon")
	else:
		raise NotImplemented("Code only works for either LINUX of WINDOWS.")
		
	
if __name__ == "__main__":
	print_profiles()


