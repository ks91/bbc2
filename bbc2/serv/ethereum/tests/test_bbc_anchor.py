# -*- coding: utf-8 -*-
from brownie import *
import pytest


def test_my_anchor(BBcAnchor):

    digest0 = 0x000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f
    digest1 = 0x800102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f

    anchor = accounts[0].deploy(BBcAnchor)

    assert anchor.isStored(digest0) == False
    assert anchor.getStored(digest0) == 0

    anchor.store(digest0, {'from': accounts[0]})

    assert anchor.isStored(digest0) == True
    assert anchor.getStored(digest0) > 0

    assert anchor.isStored(digest1) == False

    anchor.store(digest1, {'from': accounts[0]})

    assert anchor.isStored(digest1) == True


# end of test_bbc_anchor.py
