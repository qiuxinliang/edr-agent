"""Fixed media/identity/routing boundaries; no setup, network or signing."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).parents[1]/'scripts'))
import exact_installed_742_747 as exact


def request():
    value={'schema':exact.SCHEMA}
    for label,version in [('source','3.2.742'),('target','3.2.747')]:
        prefix='edr-agent-win_'+version+'-windows-arm64-';items={a['name']:a for a in exact.ASSETS[label]}
        value[label+'_publisher_proof']=dict(schema='edr.windows.publisher-verification.v1',arch='arm64',version=version,
            verifier_source_commit=exact.checkpoint.PUBLISHER_VERIFIER_COMMIT,thumbprint=exact.THUMBPRINT,
            subject_der_sha256=exact.DER_SHA,subject='CN=fixture metadata; no cryptographic proof fabricated',
            manifest_sha256=items[prefix+'artifact-manifest.json']['digest'][7:],
            signature_sha256=items[prefix+'artifact-manifest.json.p7s']['digest'][7:],
            artifact_sha256=items[prefix+'FDSensor.exe']['digest'][7:])
    return value


class BoundaryTests(unittest.TestCase):
    def test_fixed_request_and_rejections(self):
        exact.validate_request(request())
        for label in ('source','target'):
            for field,bad in [('arch','amd64'),('version','3.2.738'),('verifier_source_commit','f'*40),
                ('thumbprint','A'*40),('subject_der_sha256','0'*64),('artifact_sha256','0'*64),
                ('signature_sha256','0'*64),('manifest_sha256','0'*64)]:
                value=request();value[label+'_publisher_proof'][field]=bad
                with self.subTest(label=label,field=field),self.assertRaises(ValueError):exact.validate_request(value)
        value=request();value['legacy_tag']='win_3.2.723'
        with self.assertRaises(ValueError):exact.validate_request(value)

    def test_route_is_explicit_and_mutually_exclusive(self):
        env=dict(GITHUB_EVENT_NAME='workflow_dispatch',LIFECYCLE_PACKAGE_SCOPE='full',
            LIFECYCLE_ARCHITECTURE='arm64',LIFECYCLE_TARGET_TAG='win_3.2.747',LIFECYCLE_BASELINE_TAG='win_3.2.742')
        raw=json.dumps(request());exact.validate_routing(raw,env)
        self.assertIsNone(exact.validate_routing('',{}))
        for field,bad in [('GITHUB_EVENT_NAME','workflow_call'),('LIFECYCLE_ARCHITECTURE','all'),
            ('LIFECYCLE_PACKAGE_SCOPE','headless'),('LIFECYCLE_TARGET_TAG','win_3.2.748'),
            ('LIFECYCLE_BASELINE_TAG','win_3.2.687'),('CACHE_RECOVERY_SUBSET','true'),
            ('PUBLISHER_VALIDATION_REQUEST','legacy'),('PUBLISHER_VERIFICATION_JSON','{}')]:
            with self.subTest(field=field),self.assertRaises(ValueError):exact.validate_routing(raw,{**env,field:bad})
        with self.assertRaisesRegex(ValueError,'Duplicate'):exact.validate_routing('{"schema":"duplicate",'+raw[1:],env)

    def test_exact_historical_signers_and_asset_set(self):
        for label in ('source','target'):
            rid,tag=exact.RELEASES[label]
            release=dict(id=rid,tag_name=tag,draft=False,prerelease=True,
                body='edr-private-transfer-v1\n'+json.dumps(exact.OWNERS[label]),
                assets=[{**a,'state':'uploaded'} for a in exact.ASSETS[label]])
            exact.validate_release(label,release)
            mutations=[('id',rid+1),('draft',True),('tag_name','wrong'),('body','edr-private-transfer-v1\n{}')]
            for key,bad in mutations:
                with self.subTest(label=label,key=key),self.assertRaises(ValueError):exact.validate_release(label,{**release,key:bad})
            for field in ('id','size','digest'):
                wrong=copy.deepcopy(release);wrong['assets'][0][field]=0 if field!='digest' else 'sha256:'+'0'*64
                with self.subTest(label=label,asset_field=field),self.assertRaises(ValueError):exact.validate_release(label,wrong)
            with self.assertRaises(ValueError):exact.validate_release(label,{**release,'assets':release['assets'][:-1]})

    def test_official_assets_are_not_changed_and_no_setup_can_run_on_rejection(self):
        with tempfile.TemporaryDirectory() as d,patch.object(exact.io_owner,'api') as api,patch.object(exact.io_owner,'fetch') as fetch:
            bad=request();bad['target_publisher_proof']['artifact_sha256']='0'*64
            with self.assertRaises(ValueError):exact.stage(bad,Path(d)/'inputs')
            api.assert_not_called();fetch.assert_not_called();self.assertFalse((Path(d)/'inputs').exists())

    def test_rejected_private_release_does_not_create_stage(self):
        with tempfile.TemporaryDirectory() as d,patch.object(exact.io_owner,'api',return_value={}),patch.object(exact.io_owner,'fetch') as fetch:
            with self.assertRaises(ValueError):exact.stage(request(),Path(d)/'inputs')
            fetch.assert_not_called()
            self.assertFalse((Path(d)/'inputs').exists())


if __name__=='__main__':unittest.main()
