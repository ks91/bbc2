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
import bbclib
import binascii
import hashlib
import os

import sys
sys.path.extend(["../../"])

from bbc2.serv.bbc_config import DEFAULT_WORKING_DIR
from bbc2.serv import logger


DIR_APP_SUPPORT  = '.bbc2_app'


def get_support_dir(domain_id):
    """Gets application support directory path.

    If the directory does not exist, then the directory is created.

    Args:
        domain_id (bytes): The application domain.

    Returns:
        s_dir (str): The relative path of the application support directory.

    """
    s_domain_id = binascii.b2a_hex(domain_id).decode()
    s_dir = os.environ.get('BBC2_APP_SUPPORT_DIR', DIR_APP_SUPPORT) + '/' \
            + s_domain_id + '/'
    if not os.path.exists(s_dir):
        os.makedirs(s_dir, mode=0o777, exist_ok=True)
    return s_dir


def get_working_dir(domain_id):
    """Gets BBc-2's working directory path.

    If the directory does not exist, then the directory is created.

    Args:
        domain_id (bytes): The application domain.

    Returns:
        s_dir (str): The relative path of the working directory.

    """
    s_domain_id = binascii.b2a_hex(domain_id).decode()
    s_dir = os.environ.get('BBC2_WORKING_DIR', DEFAULT_WORKING_DIR) + '/' \
            + s_domain_id + '/'
    if not os.path.exists(s_dir):
        os.makedirs(s_dir, mode=0o777, exist_ok=True)
    return s_dir


class Constants:

    """Collection of constants to be used in the library or application.

    Common constants are provided. Libraries or applications should derive
    their own constant classes from this.
    """

    MAX_INT8  = 0x7f
    MAX_INT16 = 0x7fff
    MAX_INT32 = 0x7fffffff
    MAX_INT64 = 0x7fffffffffffffff

    O_BIT_NONE = 0


# end of support_lib.py
