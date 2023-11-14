#!/bin/sh
""":" .

exec python "$0" "$@"
"""
# -*- coding: utf-8 -*-
"""
Copyright (c) 2017 beyond-blockchain.org.

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
from brownie import *
import json
import os
import subprocess
import time

import sys
sys.path.extend(["../"])

import bbc2
from bbc2.lib import subsystem_tool_lib
from bbc2.serv import bbc_config
from bbc2.serv.ethereum import bbc_ethereum


class EthereumSubsystemTool(subsystem_tool_lib.SubsystemTool):

    def __init__(self):
        super().__init__(
            name='Ethereum',
            tool='bbc_eth_tool.py',
            version='0.1'
        )


    def _add_additional_arguments(self):
        self.argparser.add_argument('-n', '--network', type=str,
                default='',
                help='network name')

        # account command
        parser = self.subparsers.add_parser('account',
                help='Set an Ethereum account')
        parser.add_argument('private_key', action='store',
                help='Private key of the account')

        # auto command
        parser = self.subparsers.add_parser('auto',
                help='Automatically set up everything')
        parser.add_argument('project_id', action='store',
                help='INFURA project ID')
        parser.add_argument('private_key', action='store',
                help='Private key of the account')

        # balance command
        self.subparsers.add_parser('balance', help='Show ETH balance')

        # deploy command
        self.subparsers.add_parser('deploy', help='Deploy the anchor contract')

        # deployed command
        parser = self.subparsers.add_parser('deployed',
                help='Use existing anchor contract')
        parser.add_argument('contract_address', action='store',
                help='Anchor contract address')

        # new_account command
        parser = self.subparsers.add_parser('new_account',
                help='Create a new Ethereum account')

        # set_default_network command
        parser = self.subparsers.add_parser('set_default_network',
                help='Set default network with -n option')

        # set_default_network command
        parser = self.subparsers.add_parser('show_default_network',
                help='Show default network')

        # brownie command
        parser = self.subparsers.add_parser('brownie',
                help='Initialize brownie and infura environment')
        parser.add_argument('project_id', action='store',
                help='INFURA project ID')

        # test command
        self.subparsers.add_parser('test', help='Test the anchor contract')


    def _verify_by_subsystem(self, args, spec, subtree):

        if spec['subsystem'] != 'ethereum':
            print("Failed: not stored in an Ethereum subsystem.")
            return 0

        bbcConfig = bbc_ethereum.setup_config(args.workingdir, args.config,
                args.network)
        config = bbcConfig.get_config()

        prevdir = os.getcwd()
        os.chdir(bbc2.__path__[0] + '/serv/ethereum')
        os.environ['WEB3_INFURA_PROJECT_ID'] = \
                config['ethereum']['web3_infura_project_id']

        eth = bbc_ethereum.BBcEthereum(
            config['ethereum']['network'],
            config['ethereum']['private_key'],
            contract_address=spec['contract_address']
        )

        os.chdir(prevdir)

        return eth.verify(bbclib.convert_idstring_to_bytes(args.digest),
                subtree)


if __name__ == '__main__':

    subsystem_tool = EthereumSubsystemTool()
    args = subsystem_tool.parse_arguments()
    bbcConfig = bbc_ethereum.setup_config(args.workingdir, args.config,
            args.network)

    if args.command_type == 'auto':
        print("Setting up brownie.")
        bbc_ethereum.setup_brownie(bbcConfig, args.project_id)
        print("Setting up an Ethereum account.")
        bbc_ethereum.setup_account(bbcConfig, args.private_key)
        print("Deploying the anchor contract.")
        bbc_ethereum.setup_deploy(bbcConfig)

    elif args.command_type == 'balance':
        print(bbc_ethereum.get_balance(bbcConfig))

    elif args.command_type == 'brownie':
        bbc_ethereum.setup_brownie(bbcConfig, args.project_id)

    elif args.command_type == 'show_default_network':
        print(bbcConfig.get_config()['ethereum']['default_network'])

    elif args.command_type == 'set_default_network':
        bbc_ethereum.setup_default_network(bbcConfig, args.network)

    elif args.command_type == 'test':
        bbc_ethereum.setup_test()

    elif args.command_type == 'new_account':
        bbc_ethereum.setup_new_account(bbcConfig)
        print("private_key (copy and save somewhere):")
        print(accounts[0].private_key)
        print("address (copy and save somewhere):")
        print(accounts[0].address)

    elif args.command_type == 'account':
        bbc_ethereum.setup_account(bbcConfig, args.private_key)

    elif args.command_type == 'deploy':
        bbc_ethereum.setup_deploy(bbcConfig)

    elif args.command_type == 'deployed':
        bbc_ethereum.setup_deployed(bbcConfig, args.contract_address)

    sys.exit(0)


# end of utils/bbc_eth_tool.py
