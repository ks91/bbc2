# -*- coding: utf-8 -*-
"""
Copyright (c) 2020 beyond-blockchain.org.

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
import datetime
import hashlib
import json
import os
import string
import sys
sys.path.extend(["../../../"])

import time
import xml.etree.ElementTree as ET

import bbc2
from bbc2.serv import bbc_config, service, logger
from bbc2.serv.ethereum import bbc_ethereum
from bbc2.lib import document_lib
from bbc2.lib.support_lib import BYTELEN_BIT256

from brownie import *
from flask import Blueprint, request, abort, jsonify, g, current_app


def abort_by_bad_content_type(content_type):
    abort(400, description='Content-Type {0} is not expected'.format(
            content_type))


def abort_by_bad_json_format():
    abort(400, description='Bad JSON format')


def abort_by_merkle_root_not_found():
    abort(404, description='Merkle root not stored')


def abort_by_subsystem_not_supported():
    abort(400, description='non-supported subsystem')


def abort_by_missing_param(param):
    abort(400, description='{0} is missing'.format(param))


def get_document(request):
    if request.headers['Content-Type'] != 'application/json':
        abort_by_bad_content_type(request.headers['Content-Type'])

    try:
        root = document_lib.dict2xml(request.get_json())

    except Exception as e:
        s = str(e).split(':')
        if s[1].endswith('understand.'):
            abort_by_bad_json_format()
        else:
            s0 = s[0].split()
            abort(int(s0[0]), description=s[1].strip())

    id = root.findtext('id', default='N/A')
    return document_lib.Document(
        document_id=bbclib.get_new_id(id, include_timestamp=False),
        root=root
    )


certify_api = Blueprint('certify_api', __name__)


@certify_api.after_request
def after_request(response):
    return response


@certify_api.before_request
def before_request():
    g.service = service.get_service()


@certify_api.route('/')
def index():
    return jsonify({})


# For testing and demonstration purposes only.
@certify_api.route('/digest', methods=['GET'])
def get_digest():
    document = get_document(request)

    size = len(document.root)

    if size > 1:
        digest = hashlib.sha256(document.file()).digest()

    elif size == 1:
        e = document.root[0]

        if 'container' in e.attrib and e.attrib['container'] == 'true' \
                and len(e) > 0:
            digest = hashlib.sha256(document_lib.file(e)).digest()
        else:
            digest = hashlib.sha256(ET.tostring(e, encoding='utf-8')).digest()

    else:
        abort_by_bad_json_format()

    return jsonify({'digest': bbclib.convert_id_to_string(digest,
            bytelen=BYTELEN_BIT256)})


# For testing and demonstration purposes only.
@certify_api.route('/keypair', methods=['GET'])
def get_keypair():
    keypair = bbclib.KeyPair()
    keypair.generate()

    return jsonify({
        'pubkey': binascii.b2a_hex(keypair.public_key).decode(),
        'privkey': binascii.b2a_hex(keypair.private_key).decode()
    })


@certify_api.route('/proof/<string:domain_id_str>', methods=['GET'])
def get_proof_for_document(domain_id_str):
    document = get_document(request)

    digest = hashlib.sha256(document.file()).digest()
    domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)

    dic = g.service.verify_in_ledger_subsystem(domain_id, digest)

    if dic['result'] == False:
        abort_by_merkle_root_not_found()

    spec = dic['spec']
    if spec['subsystem'] != 'ethereum':
        abort_by_subsystem_not_supported()

    subtree = dic['subtree']

    spec_s = {}
    subtree_s = []

    for k, v in spec.items():
        spec_s[k] = v.decode() if isinstance(v, bytes) else v

    for node in subtree:
        subtree_s.append({
            'position': node['position'],
            'digest': node['digest']
        })

    return jsonify({
        'proof': {
            'spec': spec_s,
            'subtree': subtree_s
        }
    })


@certify_api.route('/register/<string:domain_id_str>', methods=['POST'])
def register_document(domain_id_str):
    document = get_document(request)

    digest = hashlib.sha256(document.file()).digest()
    domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)

    g.service.register_in_ledger_subsystem(domain_id, digest)

    return jsonify({
        'success': 'true'
    })


# For testing and demonstration purposes only.
@certify_api.route('/sign', methods=['GET'])
def sign_document():
    document = get_document(request)

    privkey = request.json.get('privkey')

    if privkey is None:
        abort_by_missing_param('privkey')

    keypair = bbclib.KeyPair(privkey=binascii.a2b_hex(privkey))

    digest = hashlib.sha256(document_lib.file(document.root)).digest()

    sig = keypair.sign(digest)

    return jsonify({
        'algo': 'ecdsa-p256v1',
        'sig': binascii.b2a_hex(sig).decode(),
        'pubkey': binascii.b2a_hex(keypair.public_key).decode()
    })


@certify_api.route('/verify', methods=['GET'])
def verify_certificate():
    document = get_document(request)

    proof = request.json.get('proof')

    if proof is None:
        abort_by_missing_param('proof')

    spec = proof['spec']
    subtree = proof['subtree']

    # private key can be None as it is unused for viewing blockchain.
    eth = bbc_ethereum.BBcEthereum(
        spec['network'],
        private_key=None,
        contract_address=spec['contract_address'],
        project_dir=bbc2.__path__[0] + '/core/ethereum'
    )

    digest = hashlib.sha256(document.file()).digest()

    legacy = False
    block_no, root = eth.verify_and_get_root(digest, subtree, legacy=False)

    if block_no <= 0:
        legacy = True
        try:
            current_app.logger.info('certify: legacy tried: {0}'.format(
                    binascii.b2a_hex(digest).decode()))
        except RunTimeError:
            pass
        block_no, root = eth.verify_and_get_root(digest, subtree, legacy=True)

    if block_no <= 0:
        abort_by_merkle_root_not_found()

    block = network.web3.eth.getBlock(block_no)

    return jsonify({
        'network': spec['network'],
        'contract_address': spec['contract_address'],
        'block': block_no,
        'root': binascii.b2a_hex(root).decode() if legacy \
                else bbclib.convert_id_to_string(root,
                bytelen=BYTELEN_BIT256),
        'time': block['timestamp']
    })


@certify_api.errorhandler(400)
@certify_api.errorhandler(404)
@certify_api.errorhandler(409)
def error_handler(e):
    return jsonify({'error': {
        'code': e.code,
        'name': e.name,
        'description': e.description,
    }}), e.code

@certify_api.errorhandler(ValueError)
@certify_api.errorhandler(KeyError)
def error_handler(e):
    return jsonify({'error': {
        'code': 400,
        'name': 'Bad Request',
        'description': str(e),
    }}), 400


# end of certify_api_body.py
