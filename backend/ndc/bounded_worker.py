"""Bounded Linux worker pipes, monotonic deadline, kill/reap on every failure.

Internal commands only. This is resource containment, not an OS sandbox.
"""
import os
import selectors
import subprocess
import time

def bounded_worker(command,body,*,timeout,max_output,env=None):
    data=body.encode("utf-8")
    if len(data)>16384:raise ValueError("Worker input limit")
    if not 1<=max_output<=1048576 or not 0<timeout<=60:raise ValueError("Worker budget")
    deadline=time.monotonic()+timeout
    p=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,env=env,close_fds=True)
    output=bytearray();written=0;errors=0
    try:
        with selectors.DefaultSelector() as sel:
            for stream,mode in ((p.stdin,selectors.EVENT_WRITE),(p.stdout,selectors.EVENT_READ),(p.stderr,selectors.EVENT_READ)):
                os.set_blocking(stream.fileno(),False);sel.register(stream,mode)
            while sel.get_map():
                remaining=deadline-time.monotonic()
                if remaining<=0:raise subprocess.TimeoutExpired(command,timeout)
                for key,mask in sel.select(remaining):
                    stream=key.fileobj
                    if stream is p.stdin:
                        try:written+=os.write(stream.fileno(),data[written:written+4096])
                        except BlockingIOError:continue
                        except BrokenPipeError:written=len(data)
                        if written==len(data):sel.unregister(stream);stream.close()
                    else:
                        try:chunk=os.read(stream.fileno(),8192)
                        except BlockingIOError:continue
                        if not chunk:
                            sel.unregister(stream);stream.close();continue
                        if stream is p.stdout:
                            if len(output)+len(chunk)>max_output:raise RuntimeError("Worker output limit")
                            output.extend(chunk)
                        else:
                            errors+=len(chunk)
                            if errors>65536:raise RuntimeError("Worker diagnostic limit")
            remaining=deadline-time.monotonic()
            if remaining<=0:raise subprocess.TimeoutExpired(command,timeout)
            if p.wait(timeout=remaining)!=0:raise RuntimeError("Worker failed")
            return output.decode("utf-8")
    finally:
        if p.poll() is None:
            p.kill()
        p.wait()
        for stream in (p.stdin,p.stdout,p.stderr):
            stream.close()
