#!/usr/bin/python
# Test program to add a large number of address objects and security rules.
# to a firewall policy.
#
# Usage: apitraining.py [-h] [-f FIREWALL] [-u USERNAME] [-p PASSWORD]
#   or run "./apitraining.py" from the command line and answer the prompts or any
#   combination of the two.
#
# Note: If the password has a special character in it, it may need to be
# delimited with "\" when typing in
#
import string
import getpass
import subprocess
import argparse
import urllib
import urllib2
from xml.dom import minidom
import ssl

# Let's just not check SSL certs.
ssl._create_default_https_context = ssl._create_unverified_context

# Handler for the command line arguments, if used.
parser = argparse.ArgumentParser()
parser.add_argument("-f", "--firewall", help="Name or IP address of the firewall")
parser.add_argument("-u", "--username", help="User login")
parser.add_argument("-p", "--password", help="Login password")
parser.add_argument("-c", "--commit", help="Confirm Commit")
args = parser.parse_args()

# Gather the user defined variables, either from the command-line options,
# or if they are not provided, from a user prompt
if args.firewall:
    firewall = args.firewall
else:
    firewall = raw_input("Enter the name or IP of the firewall: ")
if args.username:
    user = args.username
else:
    user = raw_input("Enter the user login: ")
if args.password:
    pw = args.password
else:
    pw = getpass.getpass()
if args.commit == "Y":
    confirmCommit = "Y"
else:
    confirmCommit = raw_input("Commit? Y or N: ")


############################################################################
# Ignore everything above this line
############################################################################


############################################################################
# Understand what the two functions below do but do not modify.
############################################################################

def send_api_request(url, values):
    # Function to send the api request to the firewall and return the
    # parsed response.
    data = urllib.urlencode(values)
    print data + '\n'
    request = urllib2.Request(url, data)
    response = urllib2.urlopen(request).read()
    print response + '\n'
    return minidom.parseString(response)


def get_api_key(hostname, username, password):
    # Function to generate a key using the user defined login credentials
    url = 'https://' + hostname + '/api'
    values = {'type': 'keygen', 'user': username, 'password': password}
    parsedKey = send_api_request(url, values)
    nodes = parsedKey.getElementsByTagName('key')
    key = nodes[0].firstChild.nodeValue
    return key


############################################################################
# All modifications will be made below this line.
############################################################################

def main():
    # Write a loop that will create a large number of
    # address objects and security rules.

    key = get_api_key(firewall, user, pw)
    commit = "<commit></commit>"
    url = 'https://' + firewall + '/api'
    baseAddressA = "172.31.1."
    baseAddressB = "172.31.2."
    baseRuleName = "ScriptRule"
    baseSourceZone = "srczone"
    baseDestinationZone = "dstzone"
    baseService = "service"
    basePort = "10"
    baseNATRule = "nat"
    zoneCount = 1
    addressCount = 101

    # xpath = /config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address
    # key = LUFRPT10VGJKTEV6a0R4L1JXd0ZmbmNvdUEwa25wMlU9d0N5d292d2FXNXBBeEFBUW5pV2xoZz09
    # type=config&action=set&xpath&key=<LUFRPT1YTWR0SkpJNm5yUW9oTDU0SlVCUzVqekxscVE9T3RPVzlqa1I0dkhqVjF0RzB3alJoZz09>
    # &xpath=/entry[@name='Add1']&element=<ip-netmask>10.10.1.1/32</ip-netmask>



    # Loop to create address objects
    for x in range(1, 101):
        AddressA = baseAddressA + str(addressCount)
        AddressB = baseAddressB + str(addressCount)
        AddressAName = "H-" + AddressA
        AddressBName = "H-" + AddressB
        # rule = baseRuleName + str(x)
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/address'
        element = '<entry name="' + AddressAName + '"><ip-netmask>' + AddressA + '</ip-netmask></entry>''<entry name="' + AddressBName + '"><ip-netmask>' + AddressB + '</ip-netmask></entry>'

        values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
        send_api_request(url, values)

        addressCount = addressCount + 1

        if addressCount == 201:
            addressCount = 101

        # xpathrule = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/security/rules'
        # elementrule = "<entry name="'+ rule +'"></entry>"

        values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
        send_api_request(url, values)

    # Loop to create source zones
    for y in range(1, 11):
        SourceZone = baseSourceZone + str(y)
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone'
        element = '<entry name="' + SourceZone + '"><network><layer3></layer3></network></entry>'

        values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
        send_api_request(url, values)

    # Loop to create destination zones
    for z in range(1, 11):
        DestinationZone = baseDestinationZone + str(z)
        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/zone'
        element = '<entry name="' + DestinationZone + '"><network><layer3></layer3></network></entry>'

        values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
        send_api_request(url, values)

    # Loop to create destination ports
    for i in range(1, 101):

        if i < 10:
            ServiceName = baseService + str(i)
            portNumber = basePort + "00" + str(i)

            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/service/entry[@name=\'' + ServiceName + '\']/protocol/tcp'
            element = '<port>' + portNumber + '</port>'

            values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
            send_api_request(url, values)

        elif i < 100:
            ServiceName = baseService + str(i)
            portNumber = basePort + "0" + str(i)

            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/service/entry[@name=\'' + ServiceName + '\']/protocol/tcp'
            element = '<port>' + portNumber + '</port>'

            values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
            send_api_request(url, values)

        else:
            ServiceName = baseService + str(i)
            portNumber = basePort + str(i)

            xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/service/entry[@name=\'' + ServiceName + '\']/protocol/tcp'
            element = '<port>' + portNumber + '</port>'

            values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
            send_api_request(url, values)



            # Loop to create NAT rules
    for n in range(1, 101):
        NATRule = baseNATRule + str(n)
        DestinationZone = baseDestinationZone + str(zoneCount)
        SourceZone = baseSourceZone + str(zoneCount)
        AddressA = baseAddressA + str(addressCount)
        AddressB = baseAddressB + str(addressCount)
        AddressAName = "H-" + AddressA
        AddressBName = "H-" + AddressB
        ServiceName = baseService + str(n)

        xpath = '/config/devices/entry[@name=\'localhost.localdomain\']/vsys/entry[@name=\'vsys1\']/rulebase/nat/rules/entry[@name=\'' + NATRule + '\']'
        element = '<to><member>' + DestinationZone + '</member></to><from><member>' + SourceZone + '</member></from><source><member>' + AddressAName + '</member></source><destination><member>any</member></destination><service>' + ServiceName + '</service><source-translation><static-ip><translated-address>' + AddressBName + '</translated-address></static-ip></source-translation>'

        values = {'type': 'config', 'action': 'set', 'key': key, 'xpath': xpath, 'element': element}
        send_api_request(url, values)

        zoneCount = zoneCount + 1
        addressCount = addressCount + 1

        if zoneCount == 11:
            zoneCount = 1

            # Commit changes to firewall
    if confirmCommit == "Y":
        values = {'type': 'commit', 'key': key, 'cmd': commit}
        send_api_request(url, values)
    elif confirmCommit == "y":
        values = {'type': 'commit', 'key': key, 'cmd': commit}
        send_api_request(url, values)


main()








