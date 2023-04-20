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
import bbclib
import binascii
import copy
import hashlib
import json
import os
import threading

import sys
sys.path.extend(["../../"])
from bbc2.lib import data_store_lib, support_lib
from bbc2.serv import logger
from bbc2.serv.ethereum import bbc_ethereum


DEFAULT_SUBSYSTEM = 'ethereum'
DEFAULT_CAPACITY = 4096
DEFAULT_INTERVAL = 60 * 60

NAME_OF_DB = 'lss_db'


merkle_branch_table_definition = [
    ["digest", "BLOB"],
    ["leaf_left", "BLOB"],
    ["leaf_right", "BLOB"],
]

merkle_leaf_table_definition = [
    ["digest", "BLOB"],
    ["leaf_left", "BLOB"],
    ["leaf_right", "BLOB"],
    ["prev", "BLOB"],
]

merkle_root_table_definition = [
    ["root", "BLOB"],
    ["spec", "BLOB"],
]


temp_json = {
    "digest": None,
    "left": None,
    "right": None,
    "prev": None,
    "count": 0,
}


class Queue:
    def __init__(self):
        self.queue = []
        self.event = threading.Event()


    def wait_msg(self, flash_others=False):
        ret = None
        while ret is None:
            try:
                if len(self.queue) == 0:
                    self.event.wait()
                self.event.clear()
                ret = self.queue.pop(0)
            except:
                ret = None
        if flash_others:
            self.queue.clear()
            return ret
        return ret


    def append_msg(self, msg):
        self.queue.append(msg)
        self.event.set()


class LedgerSubsystem:
    """Abstraction of an underlying ledger subsystem (typically a blockchain).
        This takes a digest to record and verifies its existence. It forms
        Merkle trees of digests, and only writes their root digests to the
        underlying ledger.
    """

    def __init__(self, config, networking=None, domain_id=None, enabled=False,
            loglevel="all", logname=None):
        """Constructs a ledger subsystem. Currently just supports sqlite3.

        Args:
            config (BBcConfig): The configuration object
            networking: The networking (need access to ledger manager)
            domain_id (bytes): The domain ID.
            enabled (bool): If communication with the subsystem is enabled.
            loglevel (str): The loggging level.
            logname (str): The name of the log.

        """

        self.networking = networking
        self.domain_id = domain_id
        if domain_id is None:
            return

        self.logger = logger.get_logger(key="ledger_subsystem",
                level=loglevel, logname=logname)
        self.queue = Queue()
        self.enabled = enabled
        self.config = config.get_domain_config(self.domain_id)
        if 'ethereum' in self.config:
            self.eth_config = self.config['ethereum']
        else:
            conf = config.get_config()
            self.eth_config = \
                    None if 'ethereum' not in conf else conf['ethereum']
        self.eth = None
        if 'ledger_subsystem' not in self.config:
            self.config['ledger_subsystem'] = {
                'subsystem': DEFAULT_SUBSYSTEM,
                'max_digests': DEFAULT_CAPACITY,
                'max_seconds': DEFAULT_INTERVAL,
            }
        self.capacity = self.config['ledger_subsystem']['max_digests']
        self.interval = self.config['ledger_subsystem']['max_seconds']
        self.timer = None
        self.temp_file_dic = os.path.join(
                support_lib.get_working_dir(self.domain_id),
                'ledger_subsystem.json')

        if self.enabled:
            self.enable()
        thread_loop = threading.Thread(target=self.subsystem_loop)
        thread_loop.setDaemon(True)
        thread_loop.start()


    def append_msg(self, msg):
        self.queue.append_msg(msg=msg)


    def close_merkle_tree(self, jTemp):
        self.logger.debug("closing a merkle tree")
        self.timer.cancel()
        self.timer = threading.Timer(self.interval, self.subsystem_timer)
        self.timer.start()
        digest = None
        if jTemp['left'] is not None:
            jTemp['right'] = jTemp['left']
            msg = binascii.a2b_hex(jTemp['left'])
            digest = hashlib.sha256(msg + msg).digest()
            jTemp['digest'] = str(binascii.b2a_hex(digest), 'utf-8')
            self.write_leaf(jTemp, digest=digest, left=msg, right=msg)
        elif jTemp['prev'] is not None:
            digest = binascii.a2b_hex(jTemp['prev'])
        f = open(self.temp_file_dic, 'w')
        json.dump(temp_json, f, indent=2)
        f.close()
        if digest is None:
            self.logger.debug("nothing to close")
            return
        lBase = self.get_merkle_base(digest)
        while True:
            count = 0
            dLeft = None
            lTop = list()
            for digest in lBase:
                if dLeft is None:
                    dLeft = digest
                else:
                    dRight = digest
                    digest = hashlib.sha256(dLeft + dRight).digest()
                    self.write_branch(digest=digest, left=dLeft, right=dRight)
                    lTop.append(digest)
                    dLeft = None
                count += 1
            if dLeft is not None:
                dRight = dLeft
                digest = hashlib.sha256(dLeft + dRight).digest()
                self.write_branch(digest=digest, left=dLeft, right=dRight)
                lTop.append(digest)
            lBase = lTop
            if count <= 2:
                break
        if self.config['ledger_subsystem']['subsystem'] == 'ethereum':
            self.write_merkle_root(lBase[0])


    def enable(self):
        """Enables communication with the underlying ledger.

        """

        if self.config['ledger_subsystem']['subsystem'] == 'ethereum':
            prevdir = os.getcwd()
            if not os.path.exists('ethereum/contracts/BBcAnchor.sol'):
                os.chdir(os.path.dirname(os.path.realpath(__file__)))
            os.chdir('ethereum')
            os.environ['WEB3_INFURA_PROJECT_ID'] = \
                    self.eth_config['web3_infura_project_id']
            try:
                self.eth = bbc_ethereum.BBcEthereum(
                    self.eth_config['network'],
                    self.eth_config['private_key'],
                    self.eth_config['contract_address']
                )
            except:
                os.chdir(prevdir)
                raise
            os.chdir(prevdir)
        else:
            self.logger.error("Currently, Ethereum only is supported.")
            os.exit(1)
        self.timer = threading.Timer(self.interval, self.subsystem_timer)
        self.timer.start()
        self.enabled = True
        self.logger.debug("enabled")


    def disable(self):
        """Disables communication with the underlying ledger.

        """

        self.timer.cancel()
        self.enabled = False
        self.logger.debug("disabled")


    def get_merkle_base(self, digest):
        lBase = list()
        while True:
            row = self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'select * from merkle_leaf_table where digest=?',
                digest
            )
            if len(row) <= 0:
                break
            lBase.insert(0, row[0][0])
            digest = row[0][3]
        return lBase


    def register_digest(self, digest):
        """Registers a digest.

        Args:
            digest (bytes): The digest to register.

        """

        if self.enabled:
            self.append_msg(digest)
        else:
            self.logger.warning("ledger subsystem not enabled")


    def subsystem_loop(self):
        self.logger.debug('Start subsystem_loop for domain:%s' %
                bbclib.convert_id_to_string(self.domain_id))

        self.db = data_store_lib.Database()
        self.db.setup_db(self.domain_id, NAME_OF_DB, is_app=False)
        self.db.create_table_in_db(self.domain_id, NAME_OF_DB,
                'merkle_branch_table',merkle_branch_table_definition,
                indices=[1, 2])
        self.db.create_table_in_db(self.domain_id, NAME_OF_DB,
                'merkle_leaf_table', merkle_leaf_table_definition,
                indices=[1, 2])
        self.db.create_table_in_db(self.domain_id, NAME_OF_DB,
                'merkle_root_table', merkle_root_table_definition,
                indices=[0])

        while True:
            msg = self.queue.wait_msg()
            if os.path.exists(self.temp_file_dic):
                f = open(self.temp_file_dic, 'r')
                jTemp = json.load(f)
                f.close()
            else:
                jTemp = copy.deepcopy(temp_json)
            if type(msg) == tuple:
                if msg[0] == 'timer':
                    self.logger.debug("got message: %s" % msg[0])
                    self.close_merkle_tree(jTemp)
                elif msg[0] == 'verify':
                    self.logger.debug("got message: %s %s" % (msg[0], msg[1]))
                    self.verify_tree(msg[1], msg[3])
                    msg[2].set()
            else:
                self.logger.debug("got message: %s" % msg)
                digest = None
                if jTemp['left'] is None:
                    jTemp['left'] = str(binascii.b2a_hex(msg), 'utf-8')
                elif jTemp['right'] is None:
                    jTemp['right'] = str(binascii.b2a_hex(msg), 'utf-8')
                    target = binascii.a2b_hex(jTemp['left']) + msg
                    digest = hashlib.sha256(target).digest()
                    jTemp['digest'] = str(binascii.b2a_hex(digest), 'utf-8')
                f = open(self.temp_file_dic, 'w')
                json.dump(jTemp, f, indent=2)
                f.close()
                if jTemp['digest'] is not None:
                    self.write_leaf(jTemp, digest=digest, right=msg)
                if jTemp['count'] >= self.capacity:
                    self.close_merkle_tree(jTemp)


    def subsystem_timer(self):
        self.append_msg(('timer',))


    def verify_digest(self, digest):
        """Verifies whether the specified digest is registered or not.

        Args:
            digest: The digest to verify its existence.

        Returns:
            dictionary (dict): The result (and a Merkle subtree).
        """

        dic = dict()
        if self.enabled:
            e = threading.Event()
            self.append_msg(('verify', digest, e, dic))
            e.wait()
        else:
            self.logger.warning("ledger subsystem not enabled")
        return dic


    def verify_tree(self, digest, dic):
        row = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            ('select * from merkle_leaf_table where '
             'leaf_left=? or leaf_right=?'),
            digest,
            digest
        )
        if len(row) <= 0:
            self.logger.debug("digest not found")
            dic['result'] = False
            return
        subtree = list()
        while True:
            subtree.append({
                'position': 'left' if row[0][2] == digest else 'right',
                'digest': str(binascii.b2a_hex(
                    row[0][1] if row[0][2] == digest else row[0][2]
                ), 'utf-8')
            })
            digest = row[0][0]
            row = self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                ('select * from merkle_branch_table where '
                 'leaf_left=? or leaf_right=?'),
                digest,
                digest
            )
            if len(row) <= 0:
                break
        row = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select * from merkle_root_table where root=?',
            digest
        )
        if len(row) <= 0:
            self.logger.warning("merkle root not found")
            dic['result'] = False
            return
        specList = row[0][1].split(':')
        block = self.eth.test(digest)
        if block <= 0:
            self.logger.warning("merkle root not anchored")
            dic['result'] = False
            return
        spec = {
            'subsystem': specList[0],
            'network': specList[1],
            'contract': specList[2],
            'contract_address': specList[3],
            'block': block,
        }
        dic['result'] = True
        dic['spec'] = spec
        dic['subtree'] = subtree


    def write_branch(self, digest=None, left=None, right=None):
        row = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select * from merkle_branch_table where digest=?',
            digest
        )
        if len(row) > 0:
            self.logger.warning("collision of digests detected")
        else:
            self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'insert into merkle_branch_table values (?, ?, ?)',
                digest,
                left,
                right
            )


    def write_leaf(self, jTemp, digest=None, left=None, right=None):
        if digest is None:
            digest = binascii.a2b_hex(jTemp['digest'])
        if jTemp['prev'] is None:
            prev = bytes()
        else:
            prev = binascii.a2b_hex(jTemp['prev'])
        row = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select * from merkle_leaf_table where digest=?',
            digest
        )
        if len(row) > 0:
            self.logger.warning("collision of digests detected")
        else:
            self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'insert into merkle_leaf_table values (?, ?, ?, ?)',
                digest,
                left if left is not None \
                        else binascii.a2b_hex(jTemp['left']),
                right if right is not None \
                        else binascii.a2b_hex(jTemp['right']),
                prev
            )
        jTemp['prev'] = jTemp['digest']
        jTemp['digest'] = None
        jTemp['left'] = None
        jTemp['right'] = None
        jTemp['count'] += 2
        f = open(self.temp_file_dic, 'w')
        json.dump(jTemp, f, indent=2)
        f.close()


    def write_merkle_root(self, root):
        self.write_root(
            root=root,
            spec='ethereum:%s:BBcAnchor:%s' %
                 (self.eth_config['network'],
                  self.eth_config['contract_address'])
        )
        self.eth.blockingSet(root)


    def write_root(self, root=None, spec=None):
        row = self.db.exec_sql(
            self.domain_id,
            NAME_OF_DB,
            'select * from merkle_root_table where root=?',
            root
        )
        if len(row) > 0:
            self.logger.warning("collision of digests detected")
        else:
            self.db.exec_sql(
                self.domain_id,
                NAME_OF_DB,
                'insert into merkle_root_table values (?, ?)',
                root,
                spec
            )


# end of serv/ledger_subsystem.py
