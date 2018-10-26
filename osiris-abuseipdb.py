#!/usr/bin/python
#
import sys
import requests
import json
from argparse import ArgumentParser

ABUSEIPDB_KEY = "" # Put your AbuseIPDB key here

def checkSingleIP(IP):
    URL = "https://www.abuseipdb.com/check/" + IP + "/json"
    r = requests.post(URL, data = {'key':ABUSEIPDB_KEY, 'days':'90'})

    isList = False
    if (r.text[0]=='['):
        isList = True

    return newParseResult(r.json(), IP, isList)
    #return r.json()

def newParseResult(Result, IP, isList):
    TotalResult = len(Result)
    print("IP: " + IP)

    if (TotalResult == 0):
        print("The IP has not been reported for the last 90 days")
    else:
        if (isList == False):
            # Only one result reported
            print(Result["created"] + " : " + parseResult(Result["category"]))
        else:
            # Multiple results reported
            for i in range(0, TotalResult):
                print(Result[i]["created"] + " : " + parseResult(Result[i]["category"]))
    print("\n")

def parseResult(Result):
    # Result is a List data structure
    FinalString = ""
    Total = len(Result)

    for i in range(0, Total):
        FinalString += translateCategories(Result[i])
        if (i != Total - 1):
            FinalString += ", "

    return FinalString

def translateCategories(Category):
    if (Category == 3):
        return "Fraud Orders"
    elif (Category == 4):
    	return "DDoS Attack"
    elif (Category == 5):
    	return "FTP Brute-Force"
    elif (Category == 6):
    	return "Ping of Death"
    elif (Category == 7):
    	return "Phishing"
    elif (Category == 8):
    	return "Fraud VoIP"
    elif (Category == 9):
    	return "Open Proxy"
    elif (Category == 10):
    	return "Web Spam"
    elif (Category == 11):
    	return "Email Spam"
    elif (Category == 12):
    	return "Blog Spam"
    elif (Category == 13):
    	return "VPN IP"
    elif (Category == 14):
    	return "Port Scan"
    elif (Category == 15):
    	return "Hacking"
    elif (Category == 16):
    	return "SQL Injection"
    elif (Category == 17):
    	return "Spoofing"
    elif (Category == 18):
    	return "Brute-Force"
    elif (Category == 19):
    	return "Bad Web Bot"
    elif (Category == 20):
    	return "Exploited Host"
    elif (Category == 21):
    	return "Web App Attack"
    elif (Category == 22):
    	return "SSH"
    elif (Category == 23):
    	return "IoT Targeted"

def main():
    parser = ArgumentParser(description="This tool accepts an indicator or list of indicators (IP address only) and look up AbuseIPDB result for the past 90 days")
    parser.add_argument("-v", "--value", help="Indicator value to lookup")
    parser.add_argument("-f", "--file", help="File containing indicators (one per line) to lookup")
    args = parser.parse_args()

    if args.value:
        checkSingleIP(args.value)
    elif args.file:
        lines = [line.rstrip('\n') for line in open(args.file)]
        for line in lines:
            checkSingleIP(str(line))

if __name__ == "__main__":
#    main()
    checkSingleIP("") # Put the IP address you want to check here

