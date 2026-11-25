"""Transactional Observatory state in authoritative monitoring.sqlite.
All mutations use the caller's existing monitor transaction; no new worker.
"""
import json
from .observatory import initial_state,advance,VERSION
from .evidence import Event,canonical

MAX_JOURNAL=2000
RETENTION=30*86400

def install(c,now):
    # Called only within schema migration transaction.
    c.execute("""CREATE TABLE observatory_state(
        monitor_id TEXT PRIMARY KEY REFERENCES monitors(id) ON DELETE CASCADE,
        tracking_since REAL NOT NULL,state TEXT NOT NULL)""")
    c.execute("""CREATE TABLE observatory_journal(
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
        at REAL NOT NULL,type TEXT NOT NULL,reason TEXT NOT NULL,
        rule_version TEXT NOT NULL,evidence_id TEXT,baseline_ms REAL,threshold_ms REAL,latency_ms REAL)""")
    c.execute("CREATE INDEX observatory_monitor_seq ON observatory_journal(monitor_id,seq)")
    for r in c.execute("SELECT id,enabled FROM monitors").fetchall():
        create(c,r["id"],bool(r["enabled"]),now,"migration_start")

def create(c,id,enabled,now,reason="monitor_created"):
    c.execute("INSERT INTO observatory_state VALUES(?,?,?)",(id,now,canonical(initial_state())))
    journal(c,id,now,"tracking.started",reason+"_enabled" if enabled else reason+"_paused")

def journal(c,id,at,kind,reason,evidence_id=None,point=None):
    point=point or {}
    seq=c.execute("""INSERT INTO observatory_journal(monitor_id,at,type,reason,rule_version,evidence_id,baseline_ms,threshold_ms,latency_ms)
        VALUES(?,?,?,?,?,?,?,?,?)""",(id,at,kind,reason,VERSION,evidence_id,point.get("baseline_ms"),point.get("threshold_ms"),point.get("latency_ms"))).lastrowid
    c.execute("""DELETE FROM observatory_journal WHERE monitor_id=? AND (at<? OR seq NOT IN
        (SELECT seq FROM observatory_journal WHERE monitor_id=? ORDER BY seq DESC LIMIT ?))""",(id,at-RETENTION,id,MAX_JOURNAL))
    return seq

def load(c,id):
    row=c.execute("SELECT state FROM observatory_state WHERE monitor_id=?",(id,)).fetchone()
    if row is None: raise RuntimeError("Missing observatory state")
    return json.loads(row[0])

def save(c,id,state):
    c.execute("UPDATE observatory_state SET state=? WHERE monitor_id=?",(canonical(state),id))

def boundary(c,id,enabled,now):
    state=load(c,id)
    if state["active"]:
        journal(c,id,now,"anomaly.interrupted","monitor_paused_or_resumed")
    save(c,id,initial_state())
    journal(c,id,now,"monitor.resumed" if enabled else "monitor.paused","owner_toggle")

def finish(c,id,observation,interval,*,evidence_available):
    record=observation.model_dump(mode="json")
    # Projection for overflow may have a placeholder revision; never expose a
    # synthetic identity as a link when the source outbox did not accept it.
    eid=observation.identity if evidence_available else None
    state,point,signals=advance(load(c,id),record,interval,eid)
    save(c,id,state)
    events=[]
    for signal in signals:
        journal(c,id,signal["at"],signal["type"],signal["reason"],eid,point)
        if eid:
            # Link triggering check only. Baseline context is in source journal.
            events.append(Event(event_type=signal["type"],source_kind="monitor",source_id=id,
                source_revision=observation.source_revision,deduplication_key=signal["reason"],
                rule_version=VERSION,observed_at=signal["at"],
                severity="warning" if signal["type"]=="anomaly.detected" else "info",
                confidence="observed",evidence_ids=(eid,)))
    return tuple(events)

def snapshot(c,id,since,before):
    row=c.execute("SELECT tracking_since,state FROM observatory_state WHERE monitor_id=?",(id,)).fetchone()
    if row is None: return None
    state=json.loads(row["state"])
    rows=[dict(r) for r in c.execute("""SELECT seq,at,type,reason,rule_version,evidence_id,baseline_ms,threshold_ms,latency_ms
        FROM observatory_journal WHERE monitor_id=? AND at>=? AND at<? ORDER BY seq""",(id,since,before))]
    prior=c.execute("""SELECT seq,at,type,reason FROM observatory_journal WHERE monitor_id=? AND at<?
        AND type IN ('tracking.started','monitor.paused','monitor.resumed') ORDER BY seq DESC LIMIT 1""",(id,since)).fetchone()
    return {"tracking_since":row["tracking_since"],"rule_version":state["rule_version"],
        "state_at_read":state["state"],"active_at_read":state["active"],"last_check_at":state["prev"],
        "baseline_samples_at_read":len(state["baseline"]),"journal":rows,
        "prior_boundary":dict(prior) if prior else None,"journal_max_entries":MAX_JOURNAL,
        "journal_retention_days":30,"historical_coverage_verified":False}
