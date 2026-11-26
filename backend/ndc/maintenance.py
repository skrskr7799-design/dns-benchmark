"""One non-recurring scheduled maintenance window per monitor.

Actual start/end are scheduler transitions, not claims of activity at planned
timestamps. All changes are made inside the monitor store transaction.
"""
import math
from . import observatory_store as obs

MAX_AHEAD=30*86400
MAX_DURATION=24*3600
RETENTION=30*86400
MAX_HISTORY=200

class MaintenanceConflict(Exception): pass

def install(c):
    c.execute("""CREATE TABLE maintenance_windows(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
        starts_at REAL NOT NULL, ends_at REAL NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('scheduled','active','completed','cancelled','skipped')),
        created_at REAL NOT NULL, applied_at REAL, finished_at REAL,
        CHECK(starts_at<ends_at))""")
    c.execute("""CREATE UNIQUE INDEX maintenance_one_open ON maintenance_windows(monitor_id)
        WHERE state IN ('scheduled','active')""")
    c.execute("CREATE INDEX maintenance_history ON maintenance_windows(monitor_id,id)")

def prune(c,now):
    c.execute("DELETE FROM maintenance_windows WHERE finished_at<?",(now-RETENTION,))
    c.execute("""DELETE FROM maintenance_windows WHERE state NOT IN ('scheduled','active') AND
        id NOT IN (SELECT id FROM maintenance_windows w WHERE w.monitor_id=maintenance_windows.monitor_id
        AND w.state NOT IN ('scheduled','active') ORDER BY id DESC LIMIT ?)""",(MAX_HISTORY,))

def create(c,id,start,end,now):
    if not all(math.isfinite(x) for x in (start,end,now)) or not now+60<=start<=now+MAX_AHEAD or not 60<=end-start<=MAX_DURATION:
        raise ValueError("Start 1 minute to 30 days ahead; duration 1 minute to 24 hours")
    if c.execute("SELECT 1 FROM monitors WHERE id=?",(id,)).fetchone() is None:
        return None
    if c.execute("SELECT 1 FROM maintenance_windows WHERE monitor_id=? AND state IN ('scheduled','active')",(id,)).fetchone():
        raise MaintenanceConflict("A maintenance window already exists")
    seq=c.execute("INSERT INTO maintenance_windows(monitor_id,starts_at,ends_at,state,created_at) VALUES(?,?,?,'scheduled',?)",
        (id,start,end,now)).lastrowid
    obs.journal(c,id,now,"maintenance.scheduled","owner_schedule")
    prune(c,now)
    return dict(c.execute("SELECT * FROM maintenance_windows WHERE id=?",(seq,)).fetchone())

def reset(c,id,now,kind,reason):
    state=obs.load(c,id)
    if state["active"]:
        obs.journal(c,id,now,"anomaly.interrupted","maintenance_boundary")
    obs.save(c,id,obs.initial_state())
    c.execute("UPDATE monitors SET bad=0,good=0,next_at=? WHERE id=?",(now,id))
    obs.journal(c,id,now,kind,reason)

def reconcile(c,now):
    # Only called by the single scheduler, under BEGIN IMMEDIATE; never
    # backdate an applied window or fabricate a pause while process was down.
    rows=c.execute("""SELECT w.* FROM maintenance_windows w JOIN monitors m ON m.id=w.monitor_id
        WHERE w.state IN ('scheduled','active') AND m.running=0 AND
        (w.starts_at<=? OR w.state='active') ORDER BY w.id""",(now,)).fetchall()
    for r in rows:
        id=r["monitor_id"]
        if r["state"]=="scheduled" and r["ends_at"]<=now:
            c.execute("UPDATE maintenance_windows SET state='skipped',finished_at=? WHERE id=?",(now,r["id"]))
            obs.journal(c,id,now,"maintenance.skipped","window_elapsed_before_application")
        elif r["state"]=="scheduled":
            c.execute("UPDATE maintenance_windows SET state='active',applied_at=? WHERE id=?",(now,r["id"]))
            reset(c,id,now,"maintenance.started","scheduler_applied")
        elif r["ends_at"]<=now:
            c.execute("UPDATE maintenance_windows SET state='completed',finished_at=? WHERE id=?",(now,r["id"]))
            reset(c,id,now,"maintenance.ended","scheduler_completed")

def cancel(c,id,seq,now):
    r=c.execute("SELECT * FROM maintenance_windows WHERE monitor_id=? AND id=?",(id,seq)).fetchone()
    if r is None: return None
    if r["state"]=="cancelled": return dict(r)
    if r["state"] not in ("scheduled","active"): raise MaintenanceConflict("Window is already finished")
    c.execute("UPDATE maintenance_windows SET state='cancelled',finished_at=? WHERE id=?",(now,seq))
    if r["state"]=="active":
        reset(c,id,now,"maintenance.ended","owner_cancelled")
    else:
        obs.journal(c,id,now,"maintenance.cancelled","owner_cancelled")
    return dict(c.execute("SELECT * FROM maintenance_windows WHERE id=?",(seq,)).fetchone())

def snapshot(c,id):
    return [dict(r) for r in c.execute("SELECT * FROM maintenance_windows WHERE monitor_id=? ORDER BY id DESC LIMIT ?",(id,MAX_HISTORY+1))]
