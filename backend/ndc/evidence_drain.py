"""One storage-only worker, independent source cursors and fair bounded turns."""
import logging
import threading
import time
from .evidence import Observation
from .benchmark_evidence import STREAM as BENCHMARK_STREAM
from .monitor_evidence import STREAM as MONITOR_STREAM,decode

log=logging.getLogger(__name__)

class EvidenceDrain:
    def __init__(self,benchmark,monitor,evidence,clock=time.time):
        self.sources={BENCHMARK_STREAM:(benchmark,self.decode_benchmark),MONITOR_STREAM:(monitor,decode)}
        self.evidence=evidence
        self.clock=clock
        self.stop_event=threading.Event()
        self.thread=None
        self.errors={key:None for key in self.sources}
        self.retry={key:0.0 for key in self.sources}
        self.next_prune=0.0
        self.retention_error=None

    @staticmethod
    def decode_benchmark(raw):
        return Observation.model_validate_json(raw),()

    @property
    def last_error(self):
        return self.errors[BENCHMARK_STREAM]

    def once(self,stream,after_commit=None):
        source,decoder=self.sources[stream]
        row=source.pending_evidence()
        if row is None:
            return False
        observation,events=decoder(row["payload"])
        self.evidence.ingest(stream,row["seq"],(observation,),events)
        if after_commit:
            after_commit()
        source.ack_evidence(row["seq"])
        return True

    def tick(self):
        now=self.clock()
        if now>=self.next_prune:
            try:
                self.evidence.prune(before=max(0,now-30*86400))
                self.retention_error=None
                self.next_prune=now+60
            except Exception as exc:
                self.retention_error=type(exc).__name__
                self.next_prune=now+5
        # Alternate sources each turn, bounded work and independent retry.
        for _ in range(16):
            progressed=False
            for stream in self.sources:
                if self.stop_event.is_set():
                    return
                if self.retry[stream]>time.monotonic():
                    continue
                try:
                    progressed=self.once(stream) or progressed
                    self.errors[stream]=None
                except Exception as exc:
                    error=type(exc).__name__
                    if self.errors[stream]!=error:
                        log.warning("Evidence drain %s blocked: %s",stream,error)
                    self.errors[stream]=error
                    self.retry[stream]=time.monotonic()+5
            if not progressed:
                break

    def start(self):
        self.thread=threading.Thread(target=self.loop,name="ndc-evidence-drain",daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(17)

    def loop(self):
        while not self.stop_event.is_set():
            self.tick()
            self.stop_event.wait(.5)
