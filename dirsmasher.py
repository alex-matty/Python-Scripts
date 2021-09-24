#Import required libraries
from urllib import request
import requests
import urllib3
import argparse

#Allow connections to insecure tls/ssl and disable the warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#Get arguments from the user and assign values to variables
parser = argparse.ArgumentParser(description="""Simple tool for website directory bruteforcing created in bash. User needs to provide a Website (either an IP or a URL), a wordlist to use and the extensions you want to find. Tool will find 2** or 3** statuses and print out a list of either files or directories to check out. You will get the status and the complete link to visit.""")
parser.add_argument('-u', '--url', help='URL or IP (provide protocol, \"http://\" or \"https://\"')
parser.add_argument('-w', '--wordlist', help='Dictionary or wordlist to use for the bruteforcing')
parser.add_argument('-x', '--extensions', help='Extensions to look for (separated by commas)')

args = parser.parse_args()

UserURL = args.url
UserWordlist = args.wordlist
UserExtensions = args.extensions

#Colors, to make a pretty layout
G = '\033[92m'  # green
Y = '\033[93m'  # yellow
B = '\033[94m'  # blue
R = '\033[91m'  # red
W = '\033[0m'   # white

#Print Banner and main layout
print("""%s  _____ _____ _____   _____                     _                           
 |  __ \_   _|  __ \ / ____|                   | |                          
 | |  | || | | |__) | (___  _ __ ___   __ _ ___| |__   ___ _ __ _ __  _   _ 
 | |  | || | |  _  / \___ \| '_ ` _ \ / _` / __| '_ \ / _ \ '__| '_ \| | | |
 | |__| || |_| | \ \ ____) | | | | | | (_| \__ \ | | |  __/ |_ | |_) | |_| |
 |_____/_____|_|  \_\_____/|_| |_| |_|\__,_|___/_| |_|\___|_(_)| .__/ \__, |
                                                               | |     __/ |
                                                               |_|    |___/ """ % (G))

print("%sBy MEGANUKE\n" % (W))

print("----------------------------------------------------------------")
print("[-] URL: " + UserURL)
print("[-] Extensions: " + UserWordlist)
print("[-] Wordlist: " + UserExtensions)
print("----------------------------------------------------------------\n")

#Open the file and check if it has comments, if not append it to the list
Wordlist = open(UserWordlist, "r")

for line in Wordlist:
    if not line.startswith("#"):
        lines = Wordlist.read().split('\n')


#Separate the extensions provided and create a list with them.
UserExtensions = UserExtensions.split(',')

counter=0
totalToCheck=len(lines)

#Check every element first without extension to check if there is a directory, and check with every
#extension
for element in lines:
    CheckedURL = UserURL+"/"+element
    req = requests.head(CheckedURL, verify=False)
    req = req.status_code
    if req >= 200 and req <= 399:
        print (Y + "Status Code: " + str(req) + W + "   " + CheckedURL)

    for extension in UserExtensions:
        NewURL = UserURL+"/"+element+"."+extension
        req = requests.head(NewURL, verify=False)
        req = req.status_code
        if req >= 200 and req <= 399:
            print (Y + "Status Code: " + str(req) + W + "   " +NewURL)
    counter+=1

    #Progress bar
    print(B + "Progress: ({}".format(counter) + "/" + str(totalToCheck) + ")", end="\r")

