import time
import unittest
from unittest.mock import patch
import dns.name
import dns.dnssec
import dns.rrset
from cryptography.hazmat.primitives.asymmetric import ec
from backend.ndc.dns_integrity import Agreement,DNSSECCheck,agreement,dnssec_check,verify_pinned

E=["udp://127.0.0.1","udp://127.0.0.2"]
def row(outcome="answer",rcode="NOERROR",name="valid.example.",ip="192.0.2.1",ad=True):
    return {"outcome":outcome,"rcode":rcode,"dnssec":{"ad":ad},"cname_chain":[],
        "answer":[{"name":name,"type":"A","class":"IN","ttl":60,"values":[ip]}] if outcome=="answer" else [],
        "comparison_group":None}

def check(**kw):
    return DNSSECCheck(**({"endpoint":E[0],"positive":{"name":"valid.example","expected_ipv4":"192.0.2.1"},
        "bogus":{"name":"bogus.example","expected_ipv4":"192.0.2.2"}}|kw))

class Tests(unittest.TestCase):
    def test_agreement_excludes_errors(self):
        cfg=Agreement(name="example.test",endpoints=E)
        with patch("backend.ndc.dns_integrity.inspect_one",side_effect=[(row(),("answer",)),(row("dns_error","SERVFAIL"),("error",))]):
            r=agreement(cfg)
        self.assertEqual(r["comparable"],1);self.assertIsNone(r["agreement"])
        with patch("backend.ndc.dns_integrity.inspect_one",side_effect=[(row(),("a",)),(row(),("b",))]):
            self.assertFalse(agreement(cfg)["agreement"])
        with self.assertRaises(ValueError):Agreement(name="example.test",endpoints=[E[0],E[0]])

    def test_control_behavior_and_pinned_bootstrap(self):
        cfg=check()
        good=row();bad=row("dns_error","SERVFAIL");cd=row(name="bogus.example.",ip="192.0.2.2",ad=False)
        with patch("backend.ndc.dns_integrity.bootstrap",return_value=("127.0.0.1",0.,None)) as boot,patch("backend.ndc.dns_integrity.inspect_one",side_effect=[(good,None),(bad,None),(cd,None)]) as inspect:
            r=dnssec_check(cfg)
            self.assertEqual(boot.call_count,1)
            self.assertEqual([x.args[1].checking_disabled for x in inspect.call_args_list],[False,False,True])
            self.assertEqual(len({x.kwargs["pinned"] for x in inspect.call_args_list}),1)
        self.assertEqual(r["behavior"],"consistent_with_validation");self.assertFalse(r["chain_validated"])
        with patch("backend.ndc.dns_integrity.bootstrap",return_value=("127.0.0.1",0.,None)),patch("backend.ndc.dns_integrity.inspect_one",side_effect=[(good,None),(cd,None),(cd,None)]):
            self.assertEqual(dnssec_check(cfg)["behavior"],"bogus_answer_returned")
        with patch("backend.ndc.dns_integrity.bootstrap",return_value=("127.0.0.1",0.,None)),patch("backend.ndc.dns_integrity.inspect_one",side_effect=[(good,None),(bad,None),(bad,None)]):
            self.assertEqual(dnssec_check(cfg)["behavior"],"inconclusive")

    def test_independent_signature_and_tamper(self):
        private=ec.generate_private_key(ec.SECP256R1())
        signer=dns.name.from_text("example.")
        key=dns.dnssec.make_dnskey(private.public_key(),"ECDSAP256SHA256")
        cfg=check(anchor={"signer":signer.to_text(),"dnskey":key.to_text()})
        now=int(time.time());rr=dns.rrset.from_text("valid.example.",60,"IN","A","192.0.2.1")
        sig=dns.dnssec.sign(rr,private,signer,key,inception=now-60,expiration=now+60)
        data=row();data["answer"].append({"name":"valid.example.","type":"RRSIG","class":"IN","ttl":60,"values":[sig.to_text()]})
        self.assertEqual(verify_pinned(data,cfg.positive,cfg.anchor,now)["status"],"valid_under_supplied_key")
        self.assertEqual(verify_pinned(data,cfg.positive,cfg.anchor,now+120)["status"],"signature_not_validated")
        data["answer"][0]["values"]=["192.0.2.9"];cfg.positive.expected_ipv4="192.0.2.9"
        self.assertEqual(verify_pinned(data,cfg.positive,cfg.anchor,now)["status"],"signature_not_validated")
        data["answer"].pop()
        self.assertEqual(verify_pinned(data,cfg.positive,cfg.anchor,now)["status"],"insufficient_evidence")
        with self.assertRaises(ValueError):check(anchor={"signer":"other.test.","dnskey":key.to_text()})

if __name__=="__main__":unittest.main()
