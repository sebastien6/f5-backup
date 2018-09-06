import os
import json
import datetime
from requests import Request, Session
import getpass
import optparse


# Define a new argument parser
parser=optparse.OptionParser()

# import options
parser.add_option('--hostname', help='Pass the F5 Big-ip hostname')

# Parse arguments
(opts,args) = parser.parse_args()

if not opts.hostname:
    print('--hostname argument is required.')
    exit(1)

URL_BASE = 'https://%s/mgmt' % opts.hostname
URL_AUTH = '%s/shared/authn/login' % URL_BASE
URL_UCS = '%s/tm/sys/ucs' % URL_BASE
URL_DOWNLOAD = '%s/shared/file-transfer/ucs-downloads/' % URL_BASE

# credential Ask for user Active Directory authentication information
# with a verification of entered password
def credential():
    #User name capture
    user = input('Enter Active Directory Username: ')
    # start infinite loop
    while True:
        # Capture password without echoing 
        pwd1 = getpass.getpass('Enter Password for AD account: ')
        pwd2 = getpass.getpass('Re-Enter Password for AD account: ')
        # Compare the two entered password to avoid typo error
        if pwd1 == pwd2:
            # break infinite loop by returning value
            return user, pwd1

# get_token() will call F5 Big-ip API with username and password to obtain an authentication
# security token
def get_token(session):
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
    # generate a timestamp file name
    ucs_filename = opts.hostname + '_' + datetime.datetime.now().strftime('%Y-%m-%d-%H%M%S') + '.ucs'

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
    print("UCS backup of file %s on host %s successfully completed" % (resp['name'], opts.hostname))
    return ucs_filename

# delete_ucs will call F5 Big-ip API with security token authentication to delete the ucs backup
# file after local download
def delete_ucs(session, ucs_filename):
    # variable hosting the complete download path
    url = '%s/%s' % (URL_UCS, ucs_filename)

    # send request and handle connectivity error with try/except
    try:
        session.delete(url)
        print("UCS backup file %s on host %s successfully deleted" % (ucs_filename, opts.hostname))
    except:
        print("Error sending request to F5 big-ip. Check your hostname or network connection")
        exit(1)
    
# download_ucs will call F5 Big-ip API with security token authentication to download the latest created
# ucs backup file locally
def download_ucs(session, ucs_filename):
    # variable hosting the complete download path
    url = '%s/%s' % (URL_DOWNLOAD, ucs_filename)

    # enable stream option on session to download large file
    session.stream = True

    # download file from F5 Bip-ip in chuncks to local file to avoid error with
    # header content-size
    try: 
        resp = session.get(url)
        with open(ucs_filename, 'wb') as f:
            for chunk in resp.iter_content(chunk_size=1024): 
                if chunk: # filter out keep-alive new chunks
                    f.write(chunk)
        print('File %s was successfully downlaoded locally' % ucs_filename)
    except:
        print('Error downloading file %s from F5 bigip %s' % (ucs_filename, opts.hostname))

def main():
    # create a new https session
    session = Session()

    # update session header
    session.headers.update({'Content-Type': 'application/json'})
    
    # Disable TLS cert verification
    session.verify = False

    # set default request timeout
    session.timeout = '30'

    # get a new authentication security token from F5
    token = get_token(session)
    
    # disable username, password authentication and replace by security token 
    # authentication in the session header
    session.auth = None
    session.headers.update({'X-F5-Auth-Token': token})

    # create a new F5 big-ip backup file on the F5 device
    ucs_filename = create_ucs(session)
    
    # locally download the created ucs backup file
    download_ucs(session, ucs_filename)

    # delete the ucs file from f5 after local download
    # to keep f5 disk space clean
    delete_ucs(session, ucs_filename)

if __name__ == "__main__":
    main()
