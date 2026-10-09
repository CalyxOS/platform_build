#
# Copyright (C) 2026 The Calyx Institute
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from unittest import mock

import check_target_files_signatures
import common
import test_utils


class RecordCertsTest(test_utils.ReleaseToolsTestCase):

  def setUp(self):
    self.saved_certs = check_target_files_signatures.ALL_CERTS.certs
    check_target_files_signatures.ALL_CERTS.certs = {}
    del check_target_files_signatures.PROBLEMS[:]

  def tearDown(self):
    check_target_files_signatures.ALL_CERTS.certs = self.saved_certs
    del check_target_files_signatures.PROBLEMS[:]
    super().tearDown()

  @staticmethod
  def _RecordCerts(output):
    proc = mock.Mock(returncode=0)
    proc.communicate.return_value = (output, None)
    apk = check_target_files_signatures.APK.__new__(
        check_target_files_signatures.APK)
    with mock.patch.object(common, 'Run', return_value=proc):
      apk.RecordCerts('app.apk')
    return apk

  def test_RecordCerts_SubjectWithColon(self):
    apk = self._RecordCerts(
        'V3.0 Signer: certificate DN: CN=YubiHSM Attestation id:0x1100\n'
        'V3.0 Signer: certificate SHA-256 digest: 9638063b37d9\n'
        'V3.0 Signer: certificate SHA-1 digest: 46e3aef18146\n')
    self.assertEqual([], check_target_files_signatures.PROBLEMS)
    self.assertEqual(frozenset({'46e3aef18146'}), apk.cert_digests)
    self.assertEqual(
        'unknown cert 46e3aef18146 (CN=YubiHSM Attestation id:0x1100)',
        check_target_files_signatures.ALL_CERTS.Get('46e3aef18146'))

  def test_RecordCerts_SignerWithSdkRange(self):
    apk = self._RecordCerts(
        'Signer (minSdkVersion=24, maxSdkVersion=32) certificate DN: CN=app\n'
        'Signer (minSdkVersion=24, maxSdkVersion=32) certificate SHA-1 digest:'
        ' 19da94896ce4\n')
    self.assertEqual([], check_target_files_signatures.PROBLEMS)
    self.assertEqual(frozenset({'19da94896ce4'}), apk.cert_digests)
