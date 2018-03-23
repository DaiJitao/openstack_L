# Copyright 2014 EasyStack, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import json

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode
from base64 import b64encode
from datetime import datetime
from nova import utils
from oslo_log import log as logging


LOG = logging.getLogger(__name__)

pub_key = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm1KnkNuJb0wIb8huKvRBsCupXBVoRUv+2cbBVf9nov9B5JZGyd1eZg+8fuKVc0m8B4WWyDh7xm5KgoKEXhMtrEK/Tjs/2K/9SaPZyJNZ7g6nsIXVBlnTzf8RL/J8veWkVULrikUqzdFlIaUhKnuDjYXhdWzMM2LLXDWbZGPrQOygPRYMQxkCrYyG2BgeDN2ygC9DCHNm2KdBpSpkmsuE5+ovPPCjkJFMku8IxtIQEizqNQbGfl1Hhsx2ccBBQBUhVjHDx/NlksEPD++++lDet3l5WH6F0a1mDFd5rZ74NFQs2y8T3Gq+E4B0piyvF9I+RezAhFwGMh+jmMs1Tqb5xwIDAQAB'
license_path = '/etc/easystack/license.lic'

first_read = 0
content = None
sign = None


def verify_sign(signature, data):
    rsakey = RSA.importKey(b64decode(pub_key))
    signer = PKCS1_v1_5.new(rsakey)
    digest = SHA256.new()
    digest.update(json.dumps(data))
    if signer.verify(digest, b64decode(signature)):
        return True
    return False


def get_lic_info(lic_loc):
    global first_read
    global content
    global sign
    if 1 == first_read and content is not None and sign is not None:
        return content, sign

    s = None
    try:
        s = open(lic_loc).read()
        if s is not None:
            s = b64decode(s)
            LOG.debug(s)
            json_data = json.loads(s)
            content = json_data['license']
            sign = json_data['signature']
            first_read = 1
            return content, sign
    except IOError:
        LOG.error('License file does not appear to exist.')
    except (KeyError, ValueError):
        LOG.error('License file content is wrong.')

    return '', ''


def reach_node_max(compute, controller=1):
    data, signature = get_lic_info(license_path)
    if data != '' and verify_sign(signature, data):
        max_controller = data.get('max-controller')
        max_compute = data.get('max-compute')
        LOG.debug('Controller %d<-->%d' % (controller, max_controller))
        LOG.debug('Compute %d<-->%d' % (compute, max_compute))
        if compute < max_compute and controller <= max_controller:
            return False
    return True


def is_authorized_machine(sn):
    data, signature = get_lic_info(license_path)
    if data != '' and verify_sign(signature, data):
        if 'trial' == data.get('type'):
            return True
        else:
            if not sn:
                LOG.error('Can not get SN information.')
                return False
            sns = data.get('machine-numbers')
            if sn not in sns:
                LOG.error('The sn that is %s is not in authorized machine list.' % (sn))
                return False
            return True
    return False


def execute(*args, **kwargs):
    return utils.execute(*args, **kwargs)

def get_sn():
    # 1 means System Serial Number, this is normally the SN on back of Server machine,
    # but some small System Integrators' server do not have system SN, just a string:
    # To be filled by O.E.M.
    # 2 means Base Board Serial Number.
    def get_sn_by_type(sn_type):
        out, err = execute('dmidecode', '-t ' + str(sn_type), run_as_root=True)
        for line in out.splitlines():
            if line.find('Serial Number:') > 0:
                sns = line.split(':')
                return sns[1].strip()
    sn = get_sn_by_type(1)
    if sn == 'To be filled by O.E.M.':
        sn = get_sn_by_type(2)
    return sn
