import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from backend.ndc.agent_control_pki import Authority,private_write
from backend.ndc.agent_bootstrap import load,prepare

class BootstrapTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.p=Path(tmp.name);self.root=self.p/"volume";self.root.mkdir()
        ca=Authority(self.p,"100.64.0.9")
        self.obj={"version":1,"agent_id":"a"*32,"origin":"https://100.64.0.9:8443","ca_pem":ca.ca_pem,"ca_sha256":ca.ca_fingerprint,"endpoints":["udp://1.1.1.1"],"token":"b"*43,"expires_at":int(time.time())+600}
        self.path=self.p/"bootstrap.json"
        env=patch.dict(os.environ,{"NDC_AGENT_MTLS":"1","NDC_AGENT_PROTOCOL":"2","NDC_CONTROLLER_URL":self.obj["origin"],"NDC_AGENT_CA_FILE":str(self.root/"controller-ca.pem")})
        env.start();self.addCleanup(env.stop)
    def parsed(self,**changes):
        self.path.write_text(json.dumps(self.obj|changes));return load(self.path)
    def test_idempotent_and_clean(self):
        obj=self.parsed();prepare(self.root,obj);prepare(self.root,obj)
        for name in ("controller-ca.pem","allowed-endpoints.json","enrollment-token"):
            self.assertEqual((self.root/name).stat().st_mode&0o777,0o600)
        private_write(self.root/"identity.json",json.dumps({"id":obj["agent_id"],"controller":obj["origin"],"certificate":"fixture"}).encode())
        private_write(self.root/"control-key.pem",b"keep-key")
        private_write(self.root/"spool.json",b"keep-spool")
        prepare(self.root,self.parsed(token="",expires_at=0))
        prepare(self.root,self.parsed(expires_at=1))
        self.assertFalse((self.root/"enrollment-token").exists())
        self.assertEqual((self.root/"control-key.pem").read_bytes(),b"keep-key")
        self.assertEqual((self.root/"spool.json").read_bytes(),b"keep-spool")
        with self.assertRaises(ValueError):prepare(self.root,self.parsed(agent_id="c"*32))
        with self.assertRaises(ValueError):prepare(self.root,self.parsed(endpoints=["udp://8.8.8.8"]))
    def test_invalid_and_expired(self):
        for changes in ({"ca_sha256":"0"*64},{"origin":"http://100.64.0.9:8443"},{"origin":"https://1.1.1.1:8443"},{"token":"bad"},{"endpoints":[]},{"endpoints":["udp://1.1.1.1"]*2}):
            with self.assertRaises(ValueError):self.parsed(**changes)
        for changes in ({"expires_at":1},{"token":"","expires_at":0}):
            with self.assertRaises(ValueError):prepare(self.root,self.parsed(**changes))
        self.assertEqual(list(self.root.iterdir()),[])
    def test_config_mismatch_and_symlink(self):
        obj=self.parsed()
        with patch.dict(os.environ,{"NDC_AGENT_MTLS":"0"}):
            with self.assertRaises(ValueError):prepare(self.root,obj)
        target=self.p/"target";target.write_text("untouched")
        (self.root/"controller-ca.pem").symlink_to(target)
        with self.assertRaises(OSError):prepare(self.root,obj)
        self.assertEqual(target.read_text(),"untouched")

if __name__=="__main__":unittest.main()
