#! /usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import datetime
import requests
import getpass
import optparse
import sys
import hashlib
from urllib3.exceptions import InsecureRequestWarning

# Root CA for SSL verification
ROOTCA = ''
CHECKSUM = ''
HOSTNAME = ''
STATUS = False

# credential Ask for user Active Directory authentication information
# with a verification of entered password
def credential():
    #User name capture
    user = input('Enter Active Directory Username: ')
    # start infinite loop
    while True:
        # Capture password without echoing 
        pwd1 = getpass.getpass('%s, enter your password: ' % user)
        pwd2 = getpass.getpass('%s, re-Enter Password: ' % user)
        # Compare the two entered password to avoid typo error
        if pwd1 == pwd2:
            # break infinite loop by returning value
            return user, pwd1

# get_token() will call F5 Big-ip API with username and password to obtain an authentication
# security token
def get_token(session):
    # Build URL
    URL_AUTH = 'https://%s/mgmt/shared/authn/login' % HOSTNAME
    
    # Request user credential
    username, password = credential()

    # prepare payload for request
    payload = {}
    payload['username'] = username
    payload['password'] = password
    payload['loginProviderName'] = 'tmos'

    # set authentication to username and password to obtain the security authentication token
    session.auth = (username, password)

    # send request and handle connectivity error with try/except
    try:
        resp = session.post(URL_AUTH, json.dumps(payload)).json()
    except:
        print("Error sending request to F5 big-ip. Check your hostname or network connection")
        exit(1)
    
    # filter key in response. if 'code' key present, answer was not a 200 and error message with code is printed.
    for k in resp.keys():
        if k == 'code':
            print('security authentication token creation failure. Error: %s, Message: %s' % (resp['code'],resp['message']))
            exit(1)
    
    # Print a successful message log and return the generated token
    print('Security authentication token for user %s was successfully created' % resp['token']['userName'])
    return resp['token']['token']

# create_ucs will call F5 Big-ip API with security token authentication to create a timestamps ucs backup
# file of the F5 Big-ip device configuration
def create_ucs(session):
    URL_UCS = 'https://%s/mgmt/tm/sys/ucs' % HOSTNAME

    # generate a timestamp file name
    ucs_filename = HOSTNAME + '_' + datetime.datetime.now().strftime('%Y-%m-%d-%H%M%S') + '.ucs'

    # prepare the http request payload
    payload = {}
    payload['command'] = 'save'
    payload['name'] = ucs_filename

    # send request and handle connectivity error with try/except
    try:
        resp = session.post(URL_UCS, json.dumps(payload)).json()
    except:
        print("Error sending request to F5 big-ip. Check your hostname or network connection")
        exit(1)
    
    # filter key in response. if 'code' key present, answer was not a 200 and error message with code is printed.
    for k in resp.keys():
        if k == 'code':
            print('UCS backup creation failure. Error: %s, Message: %s' % (resp['code'],resp['message']))
            exit(1)

    # Print a successful message log
    print("UCS backup of file %s on host %s successfully completed" % (resp['name'], HOSTNAME))

    return ucs_filename, checksum(session, ucs_filename)

def checksum(session, filename):
    URL_BASH = 'https://%s/mgmt/tm/util/bash' % HOSTNAME

    # prepare the http request payload
    payload = {}
    payload['command'] = 'run'
    payload['utilCmdArgs'] = '''-c "sha256sum /var/local/ucs/%s"''' % filename
    # send request and handle connectivity error with try/except
    try:
        resp = session.post(URL_BASH, json.dumps(payload)).json()['commandResult']
    except:
        print("Error sending request to F5 big-ip. Check your hostname or network connection")
        exit(1)

    checksum = resp.split()
    
    return checksum[0]

# delete_ucs will call F5 Big-ip API with security token authentication to delete the ucs backup
# file after local download
def delete_ucs(session, ucs_filename):
    URL_BASH = 'https://%s/mgmt/tm/util/bash' % HOSTNAME
    # prepare the http request payload
    payload = {}
    payload['command'] = 'run'
    payload['utilCmdArgs'] = '''-c "rm -f /var/local/ucs/%s"''' % ucs_filename
    # send request and handle connectivity error with try/except
    try:
        session.post(URL_BASH, json.dumps(payload)).json()
    except:
        print("Error sending request to F5 big-ip. Check your hostname or network connection")
        exit(1)

def ucsDownload(ucs_filename, token):
    global STATUS

    # Build request URL
    URL_DOWNLOAD = 'https://%s/mgmt/shared/file-transfer/ucs-downloads/' % HOSTNAME

    # Define chunck size for UCS backup file
    chunk_size = 512 * 1024

    # Define specific request headers
    headers = {
        'Content-Type': 'application/octet-stream',
        'X-F5-Auth-Token': token
    }
    
    # set filename and uri for request
    filename = os.path.basename(ucs_filename)
    uri = '%s%s' % (URL_DOWNLOAD, filename)
    
    requests.packages
    with open(ucs_filename, 'wb') as f:
        start = 0
        end = chunk_size - 1
        size = 0
        current_bytes = 0

        while True:
            content_range = "%s-%s/%s" % (start, end, size)
            headers['Content-Range'] = content_range

            #print headers
            resp = requests.get(uri,
                                headers=headers,
                                verify=False,
                                stream=True)

            if resp.status_code == 200:
                # If the size is zero, then this is the first time through the
                # loop and we don't want to write data because we haven't yet
                # figured out the total size of the file.
                if size > 0:
                    current_bytes += chunk_size
                    for chunk in resp.iter_content(chunk_size):
                        f.write(chunk)

                # Once we've downloaded the entire file, we can break out of
                # the loop
                if end == size:
                    break

            crange = resp.headers['Content-Range']

            # Determine the total number of bytes to read
            if size == 0:
                size = int(crange.split('/')[-1]) - 1

                # If the file is smaller than the chunk size, BIG-IP will
                # return an HTTP 400. So adjust the chunk_size down to the
                # total file size...
                if chunk_size > size:
                    end = size

                # ...and pass on the rest of the code
                continue

            start += chunk_size

            if (current_bytes + chunk_size) > size:
                end = size
            else:
                end = start + chunk_size - 1

    if sha256_checksum(ucs_filename) == CHECKSUM:
        STATUS = True

def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()

def f5Backup(hostname):
    global STATUS, CHECKSUM,HOSTNAME
    counter = 0
    
    HOSTNAME = hostname

    # Disable SSL warning for Insecure request
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    
    # create a new https session
    session = requests.Session()

    # update session header
    session.headers.update({'Content-Type': 'application/json'})
    
    # Disable TLS cert verification
    if ROOTCA == '':
        session.verify = False
    else:
        session.verify = ROOTCA

    # set default request timeout
    session.timeout = '30'

    # get a new authentication security token from F5
    print('Start remote backup F5 big-Ip device %s ' % HOSTNAME)
    token = get_token(session)
    
    # disable username, password authentication and replace by security token 
    # authentication in the session header
    session.auth = None
    session.headers.update({'X-F5-Auth-Token': token})
    
    # create a new F5 big-ip backup file on the F5 device
    print('Creation UCS backup file on F5 device %s' % HOSTNAME)
    ucs_filename, CHECKSUM = create_ucs(session)
    
    # locally download the created ucs backup file
    #download_ucs(session, ucs_filename)
    while not STATUS:
        print("Download file %s attempt %s" % (ucs_filename, counter+1))
        ucsDownload(ucs_filename, token)
        counter+=1
        if counter >2:
            print('UCS backup download failure. inconscistent' \
            'checksum between origin and destination')
            print('program will exit and ucs file will not be deleted from F5 device')
            exit(1)
    
    print('UCS backup checksum verification successful')

    # delete the ucs file from f5 after local download
    # to keep f5 disk space clean
    delete_ucs(session, ucs_filename)

if __name__ == "__main__":
    # Define a new argument parser
    parser=optparse.OptionParser()

    # import options
    parser.add_option('--hostname', help='Pass the F5 Big-ip hostname')

    # Parse arguments
    (opts,args) = parser.parse_args()

    # Check if --hostname argument populated or not
    if not opts.hostname:
        print('--hostname argument is required.')
        exit(1)

    f5Backup(opts.hostname)
