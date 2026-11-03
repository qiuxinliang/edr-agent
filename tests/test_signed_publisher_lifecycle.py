import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_signed_publisher_lifecycle as stage


class SignedPublisherRequestTests(unittest.TestCase):
    def setUp(self):
        self.request = dict(schema='edr.signed-publisher-validation.v1',
                            legacy_tag='win_3.2.723', source_commit='a'*40)
        for label, version, identity in (('baseline','3.2.736','101'), ('target','3.2.737','102')):
            proofs = {arch: dict(schema='edr.windows.publisher-verification.v1',
                version=version, arch=arch, verifier_source_commit=stage.VERIFIER_COMMIT,
                thumbprint='A'*40, subject='CN='+('P'*375), subject_der_sha256='b'*64,
                manifest_sha256='c'*64, signature_sha256='d'*64, artifact_sha256='e'*64)
                for arch in ('amd64','arm64')}
            self.request[label] = dict(tag='win_'+version, source_release_id=identity,
                source_run=identity, private_release_id=identity, private_run=identity,
                private_attempt='1', private_commit='f'*40, publisher_verification=proofs)

    def test_both_native_rows_require_real_next_version_and_all_verifier_receipts(self):
        before=copy.deepcopy(self.request)
        for arch in ('amd64','arm64'):
            self.assertEqual(stage.validate_request(self.request,arch),before)
        self.assertEqual(self.request,before)

    def assert_rejected_before_network(self, request, arch='amd64'):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'inputs'
            with patch.object(stage.admission, 'stage') as network:
                with self.assertRaises(ValueError): stage.stage_pair(request,arch,root)
                network.assert_not_called()
                self.assertFalse(root.exists())

    def test_wrong_or_missing_producer_identity_stops_before_network(self):
        for field, value in (('schema','wrong'),('legacy_tag','win_3.2.722'),('source_commit','main')):
            request=copy.deepcopy(self.request);request[field]=value
            with self.subTest(field=field): self.assert_rejected_before_network(request)
        self.assert_rejected_before_network(self.request, 'x86')
        for field in ('source_release_id','source_run','private_release_id','private_run','private_attempt','private_commit'):
            request=copy.deepcopy(self.request);request['target'][field]=''
            with self.subTest(field=field): self.assert_rejected_before_network(request)

    def test_other_architecture_proof_cannot_be_omitted_or_rebound(self):
        fields=dict(schema='wrong', version='3.2.736', arch='amd64',
            verifier_source_commit='0'*40, thumbprint='a'*40, subject='CN=short',
            subject_der_sha256='g'*64, manifest_sha256='', signature_sha256='', artifact_sha256='')
        for field,value in fields.items():
            request=copy.deepcopy(self.request)
            request['target']['publisher_verification']['arm64'][field]=value
            with self.subTest(field=field): self.assert_rejected_before_network(request)
        request=copy.deepcopy(self.request);del request['baseline']['publisher_verification']['arm64']
        self.assert_rejected_before_network(request)

    def test_repair_or_different_certificate_cannot_count_as_real_upgrade(self):
        request=copy.deepcopy(self.request)
        request['target']['tag']='win_3.2.736'
        for proof in request['target']['publisher_verification'].values():proof['version']='3.2.736'
        self.assert_rejected_before_network(request)
        request=copy.deepcopy(self.request)
        request['baseline']['publisher_verification']['amd64']['thumbprint']='B'*40
        self.assert_rejected_before_network(request)
        request=copy.deepcopy(self.request)
        request['baseline']['publisher_verification']['amd64']['subject_der_sha256']='0'*64
        self.assert_rejected_before_network(request)

    def test_duplicate_json_identity_is_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"source_commit":"a","source_commit":"b"}',object_pairs_hook=stage.admission.unique)


if __name__=='__main__':
    unittest.main()
