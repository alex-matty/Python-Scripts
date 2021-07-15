from urllib import request
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

UserURL = input("URL to check: ")
UserWordlist = input("Wordlist to use: ")
UserExtensions = input("Extensions to use: ")

Wordlist = open(UserWordlist, "r")
lines = Wordlist.read().split('\n')

UserExtensions = UserExtensions.split(',')

for element in lines:
    CheckedURL = UserURL+"/"+element
    req = requests.head(CheckedURL, verify=False)
    req = req.status_code
    if req == 200 or req == 301:
        print ("Status Code: "+str(req)+"   "+CheckedURL)

    for extension in UserExtensions:
        NewURL = UserURL+"/"+element+"."+extension
        req = requests.head(NewURL, verify=False)
        req = req.status_code
        if req == 200 or req == 301:
            print ("Staus Code: "+str(req)+ "   "+NewURL)