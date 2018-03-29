#!/usr/bin/python

# f5_partition_scalability_tester.py
# Author: Chad Jenison (c.jenison at f5.com)
# Version 1.0
#
# Script to understand scalability limits for BIG-IP Partitions and ASM Policies in partitions
# --virtual option allows attaching policy to one or more virtuals

import argparse
import sys
import requests
import json
import getpass

#Setup command line arguments using Python argparse
parser = argparse.ArgumentParser(description='A tool to parse web log files and add them to an ASM security policy')
parser.add_argument('--bigip', '-b', help='IP or hostname of BIG-IP Management or Self IP', required=True)
parser.add_argument('--user', '-u', help='username to use for authentication', required=True)
parser.add_argument('--policyprefix', help='Prefix for ASM policy name')
parser.add_argument('--partitionprefix', help='Prefix for BIG-IP partition name')
parser.add_argument('--language', '-l', help='Application Language', default='utf-8', choices=['utf-8','auto-detect'])
parser.add_argument('--protocolindependence', '-prot', help='Protocol Independence (false = distinguish between HTTP and HTTPS; true = treat HTTP and HTTPS equivalently)', default='false', choices=['false','true'])
parser.add_argument('--caseinsensitive', '-c', help='Case Insensitive', default='false', choices=['false','true'])
parser.add_argument('--enforcement', '-e', help='Enforcement Mode - Blocking or Transparent', default='blocking', choices=['blocking','transparent'])
parser.add_argument('--template', '-t', choices=['Fundamental', 'Comprehensive'])
parser.add_argument('--virtual', '-v', nargs='*', help='Virtual Server(s) to attach to (with full path [e.g. /Common/test])')
parser.add_argument('--learningmode', '-m', choices=['automatic', 'manual', 'disabled'])
parser.add_argument('--count', help='Number of partitions and policies to create')

args = parser.parse_args()

contentTypeJsonHeader = {'Content-Type': 'application/json'}

#adapted from https://devcentral.f5.com/articles/demystifying-icontrol-rest-6-token-based-authentication
def get_auth_token():
    payload = {}
    payload['username'] = args.user
    payload['password'] = passwd
    payload['loginProviderName'] = 'tmos'
    authurl = 'https://%s/mgmt/shared/authn/login' % args.bigip
    token = bip.post(authurl, headers=contentTypeJsonHeader, auth=(args.user, passwd), data=json.dumps(payload)).json()['token']['token']
    return token

def get_asm_policy_id_from_fullpath(fullPath):
    policies = bip.get('%s/asm/policies/' % (url_base)).json()
    for policy in policies['items']:
        if policy['fullPath'] == fullPath:
	    id = policy['id']
    return id

url_base = ('https://%s/mgmt/tm' % (args.bigip))
user = args.user
passwd = getpass.getpass("Password for " + user + ":")
bip = requests.session()
bip.verify = False
requests.packages.urllib3.disable_warnings()
authtoken = get_auth_token()
authheader = {'X-F5-Auth-Token': authtoken}
bip.headers.update(authheader)

policyTemplates = bip.get('%s/asm/policy-templates/' % (url_base)).json()
for policyTemplate in policyTemplates['items']:
    if policyTemplate['title'] == 'Fundamental' and args.template == 'Fundamental':
        policyTemplateId = policyTemplate['id']
    if policyTemplate['title'] == 'Comprehensive' and args.template == 'Comprehensive':
        policyTemplateId = policyTemplate['id']

# combine two Python Dicts (our auth token and the Content-type json header) in preparation for doing POSTs
postHeaders = authheader
postHeaders.update(contentTypeJsonHeader)

thirdOctet = 0
fourthOctet = 1

for instance in range(1, int(args.count) + 1):
    if fourthOctet == 255:
        thirdOctet += 1
        fourthOctet = 1
    address = '10.0.%s.%s' % (thirdOctet, fourthOctet)
    fourthOctet += 1
    partitionPayloadDict = {'name': '%s%s' % (args.partitionprefix, instance)}
    newPartition = bip.post('%s/auth/partition' % (url_base), headers=postHeaders, data=json.dumps(partitionPayloadDict))
    if newPartition.status_code != 200:
        print ('Problem Creating Partition; exiting...')
        quit()
    virtualPayloadDict = {'name': 'vs%s' % (instance), 'partition': '%s%s' % (args.partitionprefix, instance), 'destination': '/%s%s/%s:80' % (args.partitionprefix, instance, address)}
    virtualPayloadDict['profiles'] = []
    virtualPayloadDict['profiles'].append({'name': 'tcp'})
    virtualPayloadDict['profiles'].append({'name': 'http'})
    virtualPost = bip.post('%s/ltm/virtual' % (url_base), headers=postHeaders, data=json.dumps(virtualPayloadDict))
    if virtualPost.status_code != 200:
        print ('Problem Creating Virtual; exiting...')
        quit()
    else:
        print ('virtual post successful')
    policyPayloadDict = {'name': '%s%s' % (args.policyprefix, instance), 'partition':'%s%s' % (args.partitionprefix, instance), 'caseInsensitive':args.caseinsensitive, 'enforcementMode':args.enforcement, 'applicationLanguage':args.language, 'protocolIndependent':args.protocolindependence}
    if args.template is not None:
        policyPayloadDict.update({'templateReference': policyTemplateId})

    policyPayloadDict.update({'virtualServers' : ['/%s%s/vs%s' % (args.partitionprefix, instance, instance)]})


    print('policyPayloadDict: %s' % (json.dumps(policyPayloadDict, indent=2)))

    addPolicy = bip.post('%s/asm/policies/' % (url_base), headers=postHeaders, data = json.dumps(policyPayloadDict))
    if addPolicy.status_code == 201:
        policyId = addPolicy.json()['id']
        print('Policy ID: %s' % policyId)
        #policyVirtualPayload = {'virtualServers' : ['vs%s' % (instance)]}
        #policyVirtualUpdate = bip.patch('%s/asm/policies/%s' % (url_base, policyId), headers=postHeaders, data=json.dumps(policyVirtualPayload))
    else:
        print ('Unsuccessful attempt to create policy - Status Code: %s' % (addPolicy.status_code))
        print ('Body: %s' % (addPolicy.content))

    if args.learningmode is not None:
        policyBuilderPatchDict = {'learningMode': args.learningmode}
        #updateLearning = bip.patch('%s/asm/policies/%s/policy-builder' % (url_base, policyId), headers=postHeaders, data = json.dumps(policyBuilderPatchDict))
        print ('Set Learning Mode to: %s on policy: %s%s' % (args.learningmode, args.policyprefix, instance))
