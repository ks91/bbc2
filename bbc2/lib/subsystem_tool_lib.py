# -*- coding: utf-8 -*-
"""
Copyright (c) 2018 beyond-blockchain.org.

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
import argparse
import bbclib
import json
import os
import requests
import sys
sys.path.append(["../.."])

from bbc2.serv import bbc_config


PREFIX_API_BBC = f'http://localhost:{bbc_config.DEFAULT_SERV_PORT}/bbc-api'
HEADERS = {'Content-Type': 'application/json'}


def wait_check_result_msg_type(callback, msg_type):
    dat = callback.synchronize()
    if dat is None:
        print("Error: subsystem is not ready; "
                "make sure of the following conditions:")
        print("  * blockchain network (e.g. via infura.io) is accessible.")
        print("  * bbc_core.py is started with '--ledgersubsystem'.")
        print("  * subsystem is configured with config_tree command.")
        sys.exit(1)
    if dat[KeyType.command] != msg_type:
        sys.stderr.write("XXXXXX not expected result: %d <=> %d(received)\n"
                % (msg_type, dat[KeyType.command]))
    return dat


class SubsystemTool:
    """
    Abstraction of BBc-1 ledger subsystem tool.
    """
    def __init__(self, name=None, tool=None, version=None):

        self.name = name
        self.tool = tool
        self.version = version

        self.domain_id = None

        self.argparser = argparse.ArgumentParser(
                description=self._description_string())
        self.subparsers = self.argparser.add_subparsers(
                dest='command_type', help='select commands')


    def parse_arguments(self):

        self.argparser.add_argument('-4', '--ip4address', type=str,
                default="127.0.0.1", help='bbc_serv IP address (IPv4)')
        self.argparser.add_argument('-6', '--ip6address', type=str,
                help='bbc_serv IP address (IPv6)')
        self.argparser.add_argument('-c', '--config', type=str,
                default=bbc_config.DEFAULT_CONFIG_FILE,
                help='config file name')
        self.argparser.add_argument('-p', '--port', type=int,
                default=bbc_config.DEFAULT_SERV_PORT,
                help='port number of bbc_serv')
        self.argparser.add_argument('-d', '--domain_id', type=str,
                default=None,
                help='domain_id in hexadecimal')
        self.argparser.add_argument('-k', '--node_key', type=str,
                default=None,
                help='path to node key pem file')
        self.argparser.add_argument('-v', '--version', action='store_true',
                help='print version and exit')
        self.argparser.add_argument('-w', '--workingdir', type=str,
                default=bbc_config.DEFAULT_WORKING_DIR,
                help='working directory name')

        # config_demo command
        self.subparsers.add_parser('config_demo',
                help='Create a demo domain and config_tree (common command)')

        # config_tree command
        parser = self.subparsers.add_parser('config_tree',
                help='Configure how to form Merkle trees (common command)')
        parser.add_argument('digests', type=int, action='store',
                help='# of digests to wait before forming a Merkle tree')
        parser.add_argument('seconds', type=int, action='store',
                help='# of seconds to wait before forming a Merkle tree')

        # disable command
        self.subparsers.add_parser('disable',
                help='Disable ledger subsystem (common command)')

        # enable command
        self.subparsers.add_parser('enable',
                help='Enable ledger subsystem (common command)')

        # register_demo command
        parser = self.subparsers.add_parser('register_demo',
                help="Register dummy digests (common command)")
        parser.add_argument('count', type=int, action='store',
                help="# of dummy digests to register "
                "for testing/demo")

        # verify command
        parser = self.subparsers.add_parser('verify',
                help='Verify a digest (common command)')
        parser.add_argument('digest', action='store',
                help='digest to verify (in hexadecimal)')

        self._add_additional_arguments()

        args = self.argparser.parse_args()

        if args.version:
            print(self.tool + ' ' + self.version)
            sys.exit(0)

        if args.domain_id:
            self.domain_id = bbclib.convert_idstring_to_bytes(args.domain_id)

#        if args.node_key and os.path.exists(args.node_key):
#            self.client.set_node_key(args.node_key)

        if args.command_type == 'enable':
            self._enable()
            sys.exit(0)

        if args.command_type == 'disable':
            self._disable()
            sys.exit(0)

        if args.command_type == 'verify':
            self._verify(args)
            sys.exit(0)

        if args.command_type == 'config_tree':
            self._check_domain_id()
            self._config_tree(args)
            sys.exit(0)

        if args.command_type == 'config_demo':
            self.domain_id = bbclib.get_new_id("dummy_domain")
            self._config_demo(args)
            sys.exit(0)

        if args.command_type == 'register_demo':
            self._register_demo(args.count)
            sys.exit(0)

        return args


    def _add_additional_arguments(self):
        pass


    def _check_domain_id(self):
        if self.domain_id is None:
            print("Error: please specify domain_id with '-d DOMAIN_ID'.")
            sys.exit(1)


    def _config_demo(self, args):
        r = requests.post(PREFIX_API_BBC + '/create-domain', headers=HEADERS,
                data=json.dumps({
                    'domain_id': bbclib.convert_id_to_string(self.domain_id)
                }, indent=2))
        res = r.json()

        print("domain_id:")
        print(bbclib.convert_id_to_string(self.domain_id))

        args.digests = 100
        args.seconds = 30
        self._config_tree(args)


    def _config_tree(self, args):
        prevdir = os.getcwd()
        os.chdir(os.path.dirname(os.path.realpath(__file__)))

        bbcConfig = bbc_config.BBcConfig(args.workingdir,
                os.path.join(args.workingdir, args.config))
        config = bbcConfig.get_domain_config(self.domain_id)

        config['use_ledger_subsystem'] = True
        if 'ledger_subsystem' not in config:
            config['ledger_subsystem'] = {
                'subsystem': self.name.lower(),
                'max_digests': 0,
                'max_seconds': 0
            }
        config['ledger_subsystem']['max_digests'] = args.digests
        config['ledger_subsystem']['max_seconds'] = args.seconds

        bbcConfig.update_config()
        os.chdir(prevdir)
        print("You may want to restart bbc_serv.py"
                " (with '--ledgersubsystem').")


    def _description_string(self):
        return "Set up, enable and disable BBc-2 ledger subsystem with %s." \
                % (self.name)


    def _disable(self):
        r = requests.put(PREFIX_API_BBC + '/disable-ledger-subsystem',
                headers=HEADERS,
                data=json.dumps({
                    'domain_id': bbclib.convert_id_to_string(self.domain_id)
                }, indent=2))
        res = r.json()


    def _enable(self):
        r = requests.put(PREFIX_API_BBC + '/enable-ledger-subsystem',
                headers=HEADERS,
                data=json.dumps({
                    'domain_id': bbclib.convert_id_to_string(self.domain_id)
                }, indent=2))
        res = r.json()


    def _register_demo(self, count):
        domain_id_str = bbclib.convert_id_to_string(self.domain_id)

        print("digests:")
        for i in range(count):
            digest = bbclib.get_new_id("dummy %d" % (i))
            digest_str = bbclib.convert_id_to_string(digest)
            r = requests.post(PREFIX_API_BBC + '/register-digest',
                    headers=HEADERS,
                    data=json.dumps({
                        'domain_id': domain_id_str,
                        'digest': digest_str
                    }, indent=2))
            res = r.json()
            print(digest_str)


    def _verify(self, args):
        r = requests.get(PREFIX_API_BBC + '/verify-digest',
                headers=HEADERS,
                data=json.dumps({
                    'domain_id': bbclib.convert_id_to_string(self.domain_id),
                    'digest': args.digest
                }, indent=2))
        dic = r.json()
        if dic['result'] == False:
            print("Failed: digest is not found.")
            return

        block_no = self._verify_by_subsystem(args, dic['spec'], dic['subtree'])

        if block_no <= 0:
            print("Failed: digest is not found.")
        else:
            print("Verified: Merkle root is stored at block %d." % (block_no))


    def _verify_by_subsystem(self, args, spec, subtree):
        pass


# end of core/subsystem_tool_lib.py
