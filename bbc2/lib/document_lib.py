# -*- coding: utf-8 -*-
"""
Copyright (c) 2019 beyond-blockchain.org.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import bbclib
import binascii
import hashlib
import msgpack
import string
import sys
sys.path.extend(["../../"])

import threading
import time
import xml.etree.ElementTree as ET

from bbc2.serv import logger
from bbc2.lib import support_lib
from bbclib.libs import bbclib_binary
from flask import current_app


DIC_KEY_TYPES = {
    'ECDSA_SECP256k1': bbclib.KeyType.ECDSA_SECP256k1,
    'ecdsa-secp256k1': bbclib.KeyType.ECDSA_SECP256k1,
    'ECDSA_P256v1': bbclib.KeyType.ECDSA_P256v1,
    'ecdsa-p256v1': bbclib.KeyType.ECDSA_P256v1,
}


def dict2xml(dic):

    root = ET.fromstring('<c/>')
    dict2xml_element(root, dic)

    try:
        current_app.logger.info('JSON to XML: {0}'.format(ET.tostring(root,
                encoding='utf-8').decode()))

    except RuntimeError:
        pass

    return root


def dict2xml_element(element, value):

    if isinstance(value, dict):
        element.set('container', 'true')
        for k, v in value.items():
            if k in ['proof', 'privkey']:
                continue

            if k in ['algo', 'sig', 'pubkey']:
                element.set(k, v)
                continue

            if k.startswith('digest'):
                k = 'digest'

            if k == 'salt' and isinstance(v, dict):
                for kSalt, vSalt in v.items():
                    e = element.find(kSalt)
                    if e is not None:
                        e.set(k, vSalt)
                continue

            e = ET.SubElement(element, k)
            dict2xml_element(e, v)

    elif isinstance(value, list):
        element.set('container', 'true')
        for v in value:
            dict2xml_element(element, v)

    elif isinstance(value, bool):
        if element.text is None:
            element.text = str(value)
        else:
            element.text += ',' + str(value)

    elif isinstance(value, int):
        if element.text is None:
            element.text = str(value)
        else:
            element.text += ',' + str(value)

    elif isinstance(value, str):
        if element.text is None:
            element.text = value
        else:
            element.text += ',' + value


def file(container):

    dat = bytearray()
    for e in container:
        if e.tag == 'digest':
            digest = binascii.a2b_hex(e.text)
            dat.extend(digest)
        elif 'container' in e.attrib and e.attrib['container'] == 'true' \
                and len(e) > 0:
            d = file(e)
            dat.extend(hashlib.sha256(d).digest())
        else:
            string = ET.tostring(e, encoding="utf-8")
            dat.extend(hashlib.sha256(string).digest())

    if 'sig' in container.attrib:
        d = bytes(dat)
        dat = bytearray(hashlib.sha256(d).digest())
        if 'pubkey' not in container.attrib:
            raise ValueError('pubkey not specified')
        pubkey = binascii.a2b_hex(container.attrib['pubkey'])
        if 'algo' in container.attrib:
            key_type = DIC_KEY_TYPES[container.attrib['algo']]
        else:
            key_type = bbclib.DEFAULT_CURVETYPE
        sig = binascii.a2b_hex(container.attrib['sig'])

        signature = bbclib.BBcSignature(key_type=key_type)
        signature.add(signature=sig, pubkey=pubkey)
        if not signature.verify(bytes(dat)):
            raise ValueError('signature not verified')

        dat.extend(pubkey)
        dat.extend(bbclib_binary.to_2byte(key_type))
        dat.extend(sig)

    return bytes(dat)


class Document:

    def __init__(self, document_id=None, root=None):
        self.document_id = document_id
        self.root = root


    def file(self):
        return file(self.root)


    @staticmethod
    def from_xml_string(string):
        return Document(root=ET.fromstring(string))


    def set_document_id(self, document_id):
        self.document_id = document_id


# end of document_lib.py
