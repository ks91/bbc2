# -*- coding: utf-8 -*-
"""
Copyright (c) 2023 beyond-blockchain.org.

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

from bbc2.serv import bbc_config, service
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


bbc_api = Blueprint('bbc_api', __name__)


@bbc_api.after_request
def after_request(response):
    return response


@bbc_api.before_request
def before_request():
    g.service = service.get_service()


@bbc_api.route('/')
def index():
    return jsonify({})


@bbc_api.route('/create-domain', methods=['POST'])
def create_domain():
    jreq = request.json

    domain_id = bbclib.convert_idstring_to_bytes(jreq.get('domain_id'))

    g.service.create_domain(domain_id)

    return jsonify({
        'success': 'true'
    })


@bbc_api.route('/disable-ledger-subsystem', methods=['PUT'])
def disable_ledger_subsystem():
    jreq = request.json

    domain_id = bbclib.convert_idstring_to_bytes(jreq.get('domain_id'))

    g.service.disable_ledger_subsystem(domain_id)

    return jsonify({
        'success': 'true'
    })


@bbc_api.route('/enable-ledger-subsystem', methods=['PUT'])
def enable_ledger_subsystem():
    jreq = request.json

    domain_id = bbclib.convert_idstring_to_bytes(jreq.get('domain_id'))

    g.service.enable_ledger_subsystem(domain_id)

    return jsonify({
        'success': 'true'
    })


@bbc_api.route('/register-digest', methods=['POST'])
def register_digest():
    jreq = request.json

    domain_id = bbclib.convert_idstring_to_bytes(jreq.get('domain_id'))
    digest = bbclib.convert_idstring_to_bytes(jreq.get('digest'))

    g.service.register_in_ledger_subsystem(domain_id, digest)

    return jsonify({
        'success': 'true'
    })


@bbc_api.route('/remove-domain', methods=['POST'])
def remove_domain():
    jreq = request.json

    domain_id = bbclib.convert_idstring_to_bytes(jreq.get('domain_id'))

    g.service.remove_domain(domain_id)

    return jsonify({
        'success': 'true'
    })


@bbc_api.route('/verify-digest', methods=['GET'])
def verify_digest():
    jreq = request.json

    domain_id = bbclib.convert_idstring_to_bytes(jreq.get('domain_id'))
    digest = bbclib.convert_idstring_to_bytes(jreq.get('digest'))

    dic = g.service.verify_in_ledger_subsystem(domain_id, digest)

    return jsonify(dic)


@bbc_api.errorhandler(400)
@bbc_api.errorhandler(404)
@bbc_api.errorhandler(409)
def error_handler(e):
    return jsonify({'error': {
        'code': e.code,
        'name': e.name,
        'description': e.description,
    }}), e.code

@bbc_api.errorhandler(ValueError)
@bbc_api.errorhandler(KeyError)
def error_handler(e):
    return jsonify({'error': {
        'code': 400,
        'name': 'Bad Request',
        'description': str(e),
    }}), 400


# end of bbc_api_body.py
