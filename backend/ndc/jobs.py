import threading
import logging
from concurrent.futures import ThreadPoolExecutor
from .storage import ACTIVE
from .probes.dns import measure

log = logging.getLogger(__name__)

class Coordinator:
    def __init__(self, store, probe=measure):
        self.store=store
        self.probe=probe
        self.stop_event=threading.Event()
        self.wake=threading.Event()
        self.lock=threading.Lock()
        self.active_id=None
        self.cancel_event=None
        self.thread=None

    def start(self):
        self.thread=threading.Thread(target=self.loop,daemon=True,name="ndc-coordinator")
        self.thread.start()

    def submit(self, config, legacy=False):
        job_id=self.store.create(config,legacy)
        self.wake.set()
        return job_id

    def cancel(self, job_id):
        with self.lock:
            job=self.store.cancel(job_id)
            if self.active_id==job_id and self.cancel_event is not None:
                self.cancel_event.set()
        self.wake.set()
        return job

    def stop(self):
        self.stop_event.set()
        with self.lock:
            if self.cancel_event is not None:
                self.cancel_event.set()
        self.wake.set()
        if self.thread:
            self.thread.join(10)

    def loop(self):
        while not self.stop_event.is_set():
            try:
                job_id=self.store.claim()
                if job_id:
                    self.execute(job_id)
                else:
                    self.wake.wait(.5)
                    self.wake.clear()
            except Exception:
                log.exception("Coordinator failed")
                self.stop_event.wait(1)

    def execute(self, job_id):
        cancelled=threading.Event()
        with self.lock:
            self.active_id=job_id
            self.cancel_event=cancelled
            job=self.store.get(job_id)
            if job["status"]=="cancelling" or self.stop_event.is_set():
                cancelled.set()
        cfg=job["config"]
        tasks=iter(enumerate(cfg["endpoints"]))
        task_lock=threading.Lock()
        def worker():
            while not cancelled.is_set():
                with task_lock:
                    if cancelled.is_set():
                        return
                    item=next(tasks,None)
                if item is None:
                    return
                ordinal,endpoint=item
                result=self.probe(endpoint,cfg["count"],cfg["mode"],cfg["family"],cancelled)
                if result is not None:
                    self.store.add_result(job_id,ordinal,result)
        try:
            with ThreadPoolExecutor(max_workers=cfg["parallel"]) as pool:
                futures=[pool.submit(worker) for _ in range(cfg["parallel"])]
                for f in futures:
                    f.result()
            status="interrupted" if self.stop_event.is_set() else "cancelled" if cancelled.is_set() else "completed"
            self.store.finish(job_id,status)
        except Exception as exc:
            log.exception("Run failed")
            self.store.finish(job_id,"failed",type(exc).__name__+": "+str(exc)[:200])
        finally:
            with self.lock:
                self.active_id=None
                self.cancel_event=None
