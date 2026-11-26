"""One inspection lane with a short, bounded background reservation.

No queued HTTP requests or unbounded waiting. The single scheduler thread
retries every tick. A reservation expires if the scheduler stops retrying.
"""
import threading
import time

class InspectionGate:
    def __init__(self,clock=time.monotonic):
        self.clock=clock
        self.lock=threading.Lock()
        self.held=False
        self.background_until=0.
    def acquire(self,blocking=False):
        if blocking:raise ValueError("Inspection gate is nonblocking")
        with self.lock:
            if self.held or self.clock()<self.background_until:return False
            self.held=True
            return True
    def acquire_background(self):
        with self.lock:
            if self.held:
                self.background_until=self.clock()+3
                return False
            self.held=True
            self.background_until=0.
            return True
    def release(self):
        with self.lock:
            if not self.held:raise ValueError("Inspection gate already released")
            self.held=False
