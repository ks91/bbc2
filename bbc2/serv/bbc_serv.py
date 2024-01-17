#!/bin/sh
""":" .

exec python "$0" "$@"
"""
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

from bbc2.serv.bbc_config import DEFAULT_WORKING_DIR, DEFAULT_SERV_PORT
from bbc2.serv.service import BBcService, set_service
from flask import Flask


app = Flask(__name__)
app.json.sort_keys = False


from bbc2.serv.api.bbc_api_body import bbc_api
app.register_blueprint(bbc_api, url_prefix='/bbc-api')

from bbc2.serv.api.certify_api_body import certify_api
app.register_blueprint(certify_api, url_prefix='/certify-api')


app.secret_key = 'P-k3BehQUfepYE8k4jf8FFAufNZYkxW6'


if __name__ == '__main__':
    set_service(BBcService())
    app.run(host='0.0.0.0', threaded=True, port=DEFAULT_SERV_PORT)


# end of bbc_serv.py
