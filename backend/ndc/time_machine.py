"""Immutable manual snapshots of configured monitors, not LAN discovery."""
import json
import math
import uuid
import ipaddress
from .evidence import canonical,digest,Conflict,Capacity
from .models import MonitorConfig
from .monitor_evidence import project

VERSION="monitor-snapshot-v1"
MAX_SNAPSHOTS=200
MAX_BYTES=4*1024*1024
MAX_SNAPSHOT_BYTES=64*1024
OBS_FIELDS=("address","protocol","outcome","http_status")

def install(c):
    c.execute("""CREATE TABLE network_snapshots(
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE, captured_at REAL NOT NULL, label TEXT NOT NULL,
        payload TEXT NOT NULL, content_hash TEXT NOT NULL, size INTEGER NOT NULL)""")
    c.execute("""CREATE TRIGGER network_snapshot_immutable BEFORE UPDATE ON network_snapshots
        BEGIN SELECT RAISE(ABORT,'Immutable snapshot'); END""")

def capture_monitor_inventory(store):
    with store.db() as c:
        c.execute("BEGIN")
        now=store.clock()
        if not math.isfinite(now) or not 0<=now<=253402300799: raise ValueError("Invalid capture clock")
        rows=[]
        for raw in c.execute("""SELECT m.*,s.state AS obs_state,
            EXISTS(SELECT 1 FROM maintenance_windows w WHERE w.monitor_id=m.id AND w.state='active') AS maintenance_active
            FROM monitors m LEFT JOIN observatory_state s ON s.monitor_id=m.id ORDER BY m.id"""):
            m=store.decode(raw)
            cfg=MonitorConfig.model_validate(m["config"])
            settings={"name":cfg.name,"host":cfg.host,"port":cfg.port if cfg.kind!="dns" else None,
                "kind":cfg.kind,"family":cfg.family,"interval_seconds":cfg.interval_seconds,
                "enabled":m["enabled"],"notify":cfg.notify,"failure_count":cfg.failure_count,
                "recovery_count":cfg.recovery_count,"latency_threshold_ms":cfg.latency_ms,"expiry_days":cfg.expiry_days,
                "target_config_hash":digest({"kind":cfg.kind,"host":cfg.host,"port":cfg.port if cfg.kind!="dns" else None,
                    "path":cfg.path if cfg.kind in ("http","https") else None,"endpoint":cfg.endpoint if cfg.kind=="dns" else None})}
            state=json.loads(raw["obs_state"]) if raw["obs_state"] else {}
            at=m["last_at"];result=m["last_result"]
            status="fresh"
            if not m["enabled"]: status="paused"
            elif raw["maintenance_active"]: status="maintenance"
            elif at is None or not isinstance(result,dict): status="not_collected"
            elif not 0<=now-at<=3*cfg.interval_seconds: status="stale"
            elif state.get("prev")!=at: status="not_collected_since_boundary"
            elif result.get("outcome") not in ("healthy","degraded","failed"): status="unknown"
            observation=None
            if status=="fresh":
                record,_=project(m["id"],1,cfg,result,at)
                details=result.get("details") or {}
                address=str(ipaddress.ip_address(details["ip"])) if record.family else None
                values={x.name:x.value for x in record.measurements}
                observation={"observed_at":at,"profile_revision":record.profile_revision,"target_id":record.target_id,
                    "address":address,"family":record.family,"protocol":record.protocol,
                    "outcome":record.outcome,"http_status":values.get("http_status"),
                    "latency_ms":values.get("latency"),"certificate_days_remaining":values.get("certificate_days_remaining"),
                    "source":"monitor_check_commit","evidence_id":None}
            rows.append({"monitor_id":m["id"],"settings":settings,"source_state":m["state"],
                "maintenance_active":bool(raw["maintenance_active"]),"observation_status":status,
                "last_check_at":at,"observation":observation})
        return {"schema_version":1,"methodology":VERSION,"captured_at":now,"inventory_complete":True,
            "scope":"configured_monitors","monitors":rows,
            "limitations":["not_network_discovery","last_check_not_new_probe","address_is_resolved_not_physical_node",
                "latency_and_certificate_days_are_single_check_values","no_dns_rrset_route_or_certificate_fingerprint_yet",
                "evidence_links_may_expire","source_and_derived_reads_not_atomic"]}

def item(row,*,full=True):
    result={k:row[k] for k in ("seq","id","label","captured_at","content_hash","size")}
    if not full and "scope" in row.keys(): result["scope"]=row["scope"]
    if full:
        result["snapshot"]=json.loads(row["payload"])
        if digest(result["snapshot"])!=row["content_hash"]: raise Conflict("Snapshot content checksum mismatch")
    return result

class SnapshotStore:
    def __init__(self,evidence,*,max_snapshots=MAX_SNAPSHOTS,max_bytes=MAX_BYTES):
        self.evidence=evidence;self.max_snapshots=max_snapshots;self.max_bytes=max_bytes
    def create(self,request_id,label,monitors):
        if str(uuid.UUID(request_id))!=request_id or not isinstance(label,str) or not 1<=len(label)<=80 or not label.strip():
            raise ValueError("Invalid snapshot identity or label")
        prior=self.get(request_id)
        if prior:
            if prior["label"]!=label or prior["snapshot"]["scope"]!="configured_monitors": raise Conflict("Snapshot id reused with different request")
            return prior
        data=capture_monitor_inventory(monitors)
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            prior=c.execute("SELECT * FROM network_snapshots WHERE id=?",(request_id,)).fetchone()
            if prior:
                if prior["label"]!=label or item(prior)["snapshot"]["scope"]!="configured_monitors": raise Conflict("Snapshot id reused with different request")
                return item(prior)
            for m in data["monitors"]:
                o=m["observation"]
                if not o: continue
                matches=c.execute("""SELECT id,payload FROM observations WHERE source_kind='monitor'
                    AND json_extract(payload,'$.source_id')=? AND json_extract(payload,'$.observed_at')=?
                    AND json_extract(payload,'$.profile_revision')=? AND json_extract(payload,'$.target_id')=?
                    LIMIT 2""",(m["monitor_id"],o["observed_at"],o["profile_revision"],o["target_id"])).fetchall()
                if len(matches)==1:
                    r=json.loads(matches[0]["payload"])
                    v={x["name"]:x["value"] for x in r["measurements"]}
                    if (r["outcome"],r["protocol"],r["family"],v.get("latency"),v.get("http_status"),v.get("certificate_days_remaining"))==(o["outcome"],o["protocol"],o["family"],o["latency_ms"],o["http_status"],o["certificate_days_remaining"]):
                        o["evidence_id"]=matches[0]["id"]
            raw=canonical(data);size=len(raw.encode("ascii"))
            used=c.execute("SELECT count(*),coalesce(sum(size),0) FROM network_snapshots").fetchone()
            if size>MAX_SNAPSHOT_BYTES or used[0]>=self.max_snapshots or used[1]+size>self.max_bytes:
                raise Capacity("Snapshot capacity reached; explicitly delete an old snapshot")
            c.execute("INSERT INTO network_snapshots(id,captured_at,label,payload,content_hash,size) VALUES(?,?,?,?,?,?)",
                (request_id,data["captured_at"],label,raw,digest(data),size))
            return item(c.execute("SELECT * FROM network_snapshots WHERE id=?",(request_id,)).fetchone())
    def create_probe(self,request_id,label,cfg):
        from .snapshot_probes import capture,config_key
        if str(uuid.UUID(request_id))!=request_id or not isinstance(label,str) or not 1<=len(label)<=80 or not label.strip():
            raise ValueError("Invalid snapshot identity or label")
        def replay(prior):
            if prior["label"]!=label or prior["snapshot"].get("config_key")!=config_key(cfg):
                raise Conflict("Snapshot id reused with different request")
            return prior
        prior=self.get(request_id)
        if prior: return replay(prior)
        usage=self.list(limit=1)["usage"]
        if usage["count"]>=self.max_snapshots or usage["bytes"]>=self.max_bytes:
            raise Capacity("Snapshot capacity reached")
        data=capture(cfg,self.evidence.clock)
        raw=canonical(data);size=len(raw.encode("ascii"))
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            prior=c.execute("SELECT * FROM network_snapshots WHERE id=?",(request_id,)).fetchone()
            if prior: return replay(item(prior))
            used=c.execute("SELECT count(*),coalesce(sum(size),0) FROM network_snapshots").fetchone()
            if size>MAX_SNAPSHOT_BYTES or used[0]>=self.max_snapshots or used[1]+size>self.max_bytes:
                raise Capacity("Snapshot capacity reached; explicitly delete an old snapshot")
            c.execute("INSERT INTO network_snapshots(id,captured_at,label,payload,content_hash,size) VALUES(?,?,?,?,?,?)",
                (request_id,data["captured_at"],label,raw,digest(data),size))
            return item(c.execute("SELECT * FROM network_snapshots WHERE id=?",(request_id,)).fetchone())
    def get(self,id):
        with self.evidence.db() as c:
            r=c.execute("SELECT * FROM network_snapshots WHERE id=?",(id,)).fetchone()
            return item(r) if r else None
    def list(self,*,before=None,limit=50):
        if type(limit) is not int or not 1<=limit<=100: raise ValueError("Invalid limit")
        with self.evidence.db() as c:
            c.execute("BEGIN")
            rows=c.execute("SELECT seq,id,label,captured_at,content_hash,size,json_extract(payload,'$.scope') AS scope FROM network_snapshots WHERE seq<? ORDER BY seq DESC LIMIT ?",
                (before if before is not None else 9223372036854775807,limit+1)).fetchall()
            entries=[item(r,full=False) for r in rows[:limit]]
            count,size=c.execute("SELECT count(*),coalesce(sum(size),0) FROM network_snapshots").fetchone()
            return {"items":entries,"next_before":entries[-1]["seq"] if len(rows)>limit else None,
                "usage":{"count":count,"bytes":size,"max_count":self.max_snapshots,"max_bytes":self.max_bytes}}
    def delete(self,id):
        with self.evidence.db() as c:
            c.execute("BEGIN IMMEDIATE")
            return c.execute("DELETE FROM network_snapshots WHERE id=?",(id,)).rowcount==1
    def compare(self,older,newer):
        with self.evidence.db() as c:
            c.execute("BEGIN")
            rows=[c.execute("SELECT * FROM network_snapshots WHERE id=?",(id,)).fetchone() for id in (older,newer)]
            if any(r is None for r in rows): return None
            a,b=(item(r) for r in rows)
            if a["seq"]>=b["seq"]: raise ValueError("Choose two snapshots in creation order")
            if a["snapshot"]["scope"]!="configured_monitors" or b["snapshot"]["scope"]!="configured_monitors":
                from .snapshot_probes import compare_probes
                return compare_probes(a,b)
            return compare(a,b)

def compare(a,b):
    left,right=a["snapshot"],b["snapshot"]
    if left["methodology"]!=right["methodology"] or left["scope"]!=right["scope"]:
        raise ValueError("Incompatible snapshot scope or version")
    old={m["monitor_id"]:m for m in left["monitors"]}
    new={m["monitor_id"]:m for m in right["monitors"]}
    changes=[]
    for id in sorted(set(old)|set(new)):
        x,y=old.get(id),new.get(id)
        if x is None or y is None:
            known=left["inventory_complete"] if x is None else right["inventory_complete"]
            changes.append({"monitor_id":id,"kind":"monitor_added" if x is None and known else "monitor_removed" if y is None and known else "inventory_unknown",
                "before_name":x["settings"]["name"] if x else None,"after_name":y["settings"]["name"] if y else None,
                "settings":[],"observations":[]})
            continue
        fields=[{"field":k,"before":x["settings"][k],"after":y["settings"][k]} for k in x["settings"] if x["settings"][k]!=y["settings"][k]]
        o,p=x["observation"],y["observation"]
        observed=[]
        compatible=bool(o and p and o["profile_revision"]==p["profile_revision"] and x["settings"]["target_config_hash"]==y["settings"]["target_config_hash"])
        for k in OBS_FIELDS:
            v=o[k] if o else None;w=p[k] if p else None
            status="unknown" if v is None or w is None else "not_comparable" if not compatible else "same_observation" if o["observed_at"]==p["observed_at"] and o["target_id"]==p["target_id"] and v==w else "changed" if v!=w else "unchanged"
            observed.append({"field":k,"before":v,"after":w,"status":status})
        changes.append({"monitor_id":id,"kind":"monitor_retained","before_name":x["settings"]["name"],"after_name":y["settings"]["name"],
            "settings":fields,"observations":observed,"before_status":x["observation_status"],"after_status":y["observation_status"],
            "before_evidence_id":o["evidence_id"] if o else None,"after_evidence_id":p["evidence_id"] if p else None})
    return {"methodology":"monitor-diff-v1","before_id":a["id"],"after_id":b["id"],"changes":changes,
        "limitations":["monitor_removed_is_configuration_removal_not_device_disappearance","unknown_is_not_removal",
            "single_checks_not_continuous_history","address_change_not_proof_of_physical_route_change","no_causal_inference"]}
