import time
import unittest
from unittest.mock import patch
import dns.name
import dns.dnssec
import dns.rrset
import dns.rdatatype
from cryptography.hazmat.primitives.asymmetric import ec
from backend.ndc.dns_chain import ChainRequest,execute
from backend.ndc.packet_chaos import PacketExperiment,run

class Tests(unittest.TestCase):
    def test_signed_chain_and_tamper(self):
        now=int(time.time())
        parent=dns.name.root;child=dns.name.from_text("fixture.")
        root_private=ec.generate_private_key(ec.SECP256R1())
        child_private=ec.generate_private_key(ec.SECP256R1())
        root=dns.dnssec.make_dnskey(root_private.public_key(),"ECDSAP256SHA256")
        key=dns.dnssec.make_dnskey(child_private.public_key(),"ECDSAP256SHA256")
        rrroot=dns.rrset.from_text(parent,60,"IN","DNSKEY",root.to_text())
        rrchild=dns.rrset.from_text(child,60,"IN","DNSKEY",key.to_text())
        ds=dns.rrset.from_text(child,60,"IN","DS",dns.dnssec.make_ds(child,key,"SHA256").to_text())
        a=dns.rrset.from_text("www.fixture.",60,"IN","A","192.0.2.1")
        def row(rr,private,signer,k):
            sig=dns.dnssec.sign(rr,private,signer,k,inception=now-60,expiration=now+60)
            return {"outcome":"answer","rcode":"NOERROR","cname_chain":[],"answer":[
                {"name":rr.name.to_text(),"type":dns.rdatatype.to_text(rr.rdtype),"class":"IN","ttl":60,"values":[r.to_text() for r in rr]},
                {"name":rr.name.to_text(),"type":"RRSIG","class":"IN","ttl":60,"values":[sig.to_text()]}]}
        data={(".","DNSKEY"):row(rrroot,root_private,parent,root),("fixture.","DS"):row(ds,root_private,parent,root),
            ("fixture.","DNSKEY"):row(rrchild,child_private,child,key),("www.fixture.","A"):row(a,child_private,child,key)}
        cfg=ChainRequest(endpoint="udp://127.0.0.1",name="www.fixture",zones=["fixture"],root_dnskey=root.to_text())
        def probe(endpoint,config,**kwargs):return data[(config.name,config.qtype)],None
        with patch("backend.ndc.dns_chain.bootstrap",return_value=("127.0.0.1",0,None)),patch("backend.ndc.dns_chain.inspect_one",side_effect=probe):
            result=execute(cfg,lambda:now)
            self.assertEqual(result["status"],"validated_under_supplied_root")
            self.assertEqual(len(result["steps"]),4)
            self.assertEqual(result["addresses"],["192.0.2.1"])
            self.assertEqual(execute(cfg,lambda:now+120)["status"],"not_validated")
            original=data[("www.fixture.","A")]
            wildcard=dns.rrset.from_text("*.fixture.",60,"IN","A","192.0.2.1")
            expanded=row(wildcard,child_private,child,key)
            for record in expanded["answer"]:record["name"]="www.fixture."
            data[("www.fixture.","A")]=expanded
            self.assertEqual(execute(cfg,lambda:now)["failed_stage"],"www.fixture. A")
            data[("www.fixture.","A")]=original
            data[("www.fixture.","A")]["answer"][0]["values"]=["192.0.2.9"]
            self.assertEqual(execute(cfg,lambda:now)["failed_stage"],"www.fixture. A")
            data[("fixture.","DS")]["answer"][0]["values"]=[dns.dnssec.make_ds(child,root,"SHA256").to_text()]
            self.assertEqual(execute(cfg,lambda:now)["failed_stage"],"fixture. DS")

    def test_real_udp_fixture(self):
        result=run(PacketExperiment(samples=2,delay_ms=20,timeout_ms=200))
        self.assertEqual((result["baseline_success"],result["fault_success"]),(2,2))
        self.assertTrue(all(r["fixture_received"] for r in result["rows"]))
        self.assertTrue(all(r["elapsed_ms"]>=15 for r in result["rows"] if r["phase"]=="fault"))
        result=run(PacketExperiment(samples=2,loss_pct=100,timeout_ms=100))
        self.assertEqual(result["baseline_success"],2)
        self.assertEqual([r["outcome"] for r in result["rows"] if r["phase"]=="fault"],["timeout","timeout"])
        result=run(PacketExperiment(samples=1,dns="servfail",delay_ms=0))
        self.assertEqual(result["rows"][-1]["outcome"],"dns_servfail")
        with self.assertRaises(ValueError):PacketExperiment(samples=9)

if __name__=="__main__":unittest.main()
