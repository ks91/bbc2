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
import sys
sys.path.extend(["../../"])
import threading

from bbc2.serv import logger
from bbc2.serv.bbc_config import DEFAULT_WORKING_DIR, DEFAULT_SERV_PORT
from bbc2.serv.bbc_config import BBcConfig
from bbc2.serv.ledger_subsystem import LedgerSubsystem


VERSION = "version 0.1"


class BBcService:

    def __init__(self, p2p_port=None, serv_port=None,
            workingdir=DEFAULT_WORKING_DIR, configfile=None,
            default_conffile=None, loglevel='all', logname='-'):
        self.logger = logger.get_logger(key='serv', level=loglevel,
                logname=logname)
        self.logger.info(f'bbc_serv {VERSION}')

        self.lock = threading.Lock()

        self.config = BBcConfig(workingdir, configfile, default_conffile)
        conf = self.config.get_config()
        self.logger.debug(f'config = {conf}')

        self.ledger_subsystems = dict()
        for domain_id_str in conf['domains'].keys():
            domain_id = bbclib.convert_idstring_to_bytes(domain_id_str)
            self.ledger_subsystems[domain_id] = LedgerSubsystem(self.config,
                    domain_id=domain_id, loglevel=loglevel, logname=logname)


    def create_domain(self, domain_id):
        self.lock.acquire()

        config = BBcConfig()
        config.get_domain_config(domain_id, create_if_new=True)
        config.update_config()

        self.lock.release()


    def disable_ledger_subsystem(self, domain_id):
        if domain_id in self.ledger_subsystems:
            self.ledger_subsystems[domain_id].disable()


    def enable_ledger_subsystem(self, domain_id):
        if domain_id in self.ledger_subsystems:
            self.ledger_subsystems[domain_id].enable()


    def register_in_ledger_subsystem(self, domain_id, digest):
        self.lock.acquire()

        if domain_id in self.ledger_subsystems:
            self.ledger_subsystems[domain_id].register_digest(digest)

        self.lock.release()


    def remove_domain(self, domain_id):
        self.lock.acquire()

        config = BBcConfig()
        config.remove_domain_config(domain_id)

        self.lock.release()


    def verify_in_ledger_subsystem(self, domain_id, digest):
        self.lock.acquire()

        if domain_id in self.ledger_subsystems:
            dic = self.ledger_subsystems[domain_id].verify_digest(digest)
        else:
            dic = None

        self.lock.release()
        return dic


service = None


def get_service():
    global service
    return service


def set_service(service_obj):
    global service
    service = service_obj


# end of service.py
