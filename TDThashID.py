#!/usr/bin/python
# -*- coding: utf-8 -*-
#Developed by Tiago Neves
#Github: https://github.com/TiagoANeves
#Version: 1.0
#All rights reserved

#Import necessary modules
import os
import re
import json
import requests
import sys
from argparse import ArgumentParser

os.system("clear")

#Color scheme
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Create Banner
def banner():
    print("""%s
	 _______ _____ _______ _               _     _____ _____
 	|__   __|  __ \__   __| |             | |   |_   _|  __ \\
    	   | |  | |  | | | |  | |__   __ _ ___| |__   | | | |  | |
    	   | |  | |  | | | |  | '_ \ / _` / __| '_ \  | | | |  | |
    	   | |  | |__| | | |  | | | | (_| \__ \ | | |_| |_| |__| |
    	   |_|  |_____/  |_|  |_| |_|\__,_|___/_| |_|_____|_____/%s%s
    # Coded By Tiago Neves
    # Github https://github.com/TiagoANeves
    """ % (bcolors.OKBLUE, bcolors.ENDC, bcolors.FAIL))

# Hashes
def hash_id(hash):
    hash_types = []
    # MD5
    if re.match(r"^[a-fA-F0-9]{32}$", hash):
	hash_types.append("MD5")
    # SHA-1
    if re.match(r"^[a-fA-F0-9]{40}$", hash):
	hash_types.append("SHA-1")
    # SHA-224
    if re.match(r"^[a-fA-F0-9]{56}$", hash):
        hash_types.append("SHA-224")
    # SHA-256
    if re.match(r"^[a-fA-F0-9]{64}$", hash):
        hash_types.append("SHA-256")
    # SHA-384
    if re.match(r"^[a-fA-F0-9]{96}$", hash):
        hash_types.append("SHA-384")
    # SHA-512
    if re.match(r"^[a-fA-F0-9]{128}$", hash):
        hash_types.append("SHA-512")
    return hash_types 

# Arguments Parser
parser = ArgumentParser()
parser.add_argument("--hash", help="hash to be identified %s" %bcolors.ENDC)

# Main function
if __name__ == "__main__":
    try:
        banner()
        print "This program will try to identify the different types of hashes \n" + bcolors.ENDC
        args = parser.parse_args()
    except:
        sys.exit(0)
    if len(sys.argv) != 3:
        print bcolors.WARNING + "Usage: python "+sys.argv[0]+" --hash hash\n" + bcolors.ENDC
        print bcolors.WARNING + "Use "+sys.argv[0]+" -h or --help to print the help option\n" + bcolors.ENDC
        sys.exit()
    else:
        print bcolors.HEADER + "\nStarting the program..." + bcolors.ENDC
        print bcolors.HEADER + "\nChecking the hash: %s%s%s\n" %(bcolors.OKGREEN,args.hash,bcolors.ENDC)
	try:
            results = hash_id(args.hash)
            results_len = len(results)
            if results_len >= 0:
                print bcolors.WARNING + "Possible hashs Algorithms:" + bcolors.ENDC
                for result in results:
                    print "%s[+] %s%s%s\n" %(bcolors.OKGREEN,bcolors.OKBLUE,result,bcolors.ENDC)

                decrypt = requests.get('https://lea.kz/api/hash/'+args.hash)
                if decrypt.status_code == 200:
                    decryptcontent = json.loads(decrypt.content)
                    print "%sThis hash was leaked! The plain password is %s%s%s \n" %(bcolors.WARNING,bcolors.OKGREEN,decryptcontent['password'],bcolors.ENDC)
            else:
	        print bcolors.FAIL + "The hash could not be identified...\n" + bcolors.ENDC
        except:
	    print "Error checking the hash"
            sys.exit()
