# -*- coding: utf-8 -*-
import hashlib
import json
import os
import pytest
import subprocess
import time

import sys
sys.path.extend(["../"])
import bbclib


def test_keypair():
    keypair = bbclib.KeyPair(curvetype=bbclib.DEFAULT_CURVETYPE)
    keypair.generate()

    digest = hashlib.sha256(b'1234').digest()

    sig = keypair.sign(digest)

    signature = bbclib.BBcSignature(key_type=bbclib.DEFAULT_CURVETYPE)
    signature.add(signature=sig, pubkey=keypair.public_key)

    assert signature.verify(digest)


# end of tests/test_bbclib.py
