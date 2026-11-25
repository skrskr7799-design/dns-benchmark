"""Fixed-purpose isolated worker; accepts only validated operator integration config."""
import json
import sys
import subprocess
from .integrations import Target, snapshot, throughput

def bounded(kind,config,seconds=None):
    limits={"adguard":30,"throughput":12}
    if kind not in limits:
        raise ValueError("Unknown integration")
    # No shell, no user-controlled executable or CLI arguments. Secrets via stdin only.
    completed=subprocess.run([sys.executable,"-m","backend.ndc.integration_worker",kind],
        input=json.dumps(config),text=True,capture_output=True,
        timeout=limits[kind] if seconds is None else seconds,check=False)
    if completed.returncode!=0:
        raise ValueError("Integration worker failed")
    if len(completed.stdout)>2*1024*1024:
        raise ValueError("Integration result too large")
    return json.loads(completed.stdout)

def main():
    kind=sys.argv[1]
    config=json.load(sys.stdin)
    target=Target(config)
    if kind=="adguard":
        result=snapshot(target)
    elif kind=="throughput" and target.username is None:
        result=throughput(target,config["path"])
    else:
        raise ValueError("Invalid integration")
    print(json.dumps(result,allow_nan=False),flush=True)

if __name__=="__main__":
    try:
        main()
    except Exception:
        # Never emit config or upstream exception text.
        sys.exit(1)
