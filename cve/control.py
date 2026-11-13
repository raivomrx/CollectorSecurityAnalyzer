"""Cooperative wall-clock/cancellation control, including rate-limit waits."""
import time
import threading
from cve.exceptions import CveProductDeadline, CveScanCancelled
from cve.exceptions import NvdRequestError

_BACKGROUND_SLOTS=threading.BoundedSemaphore(4)


def interruptible_call(action,cancel_event,timeout=60):
    """Bound a provider task without publishing a late cancelled result."""
    if cancel_event is None:return action(None)
    if not _BACKGROUND_SLOTS.acquire(blocking=False):
        raise NvdRequestError("Provider task capacity is busy; retry incomplete analysis")
    done=threading.Event();result={};stop=threading.Event()
    class Combined:
        def is_set(self):return stop.is_set() or cancel_event.is_set()
    def run():
        try:result['value']=action(Combined())
        except Exception as error:result['error']=error
        finally:_BACKGROUND_SLOTS.release();done.set()
    try:threading.Thread(target=run,name='CSA-provider-task',daemon=True).start()
    except RuntimeError:_BACKGROUND_SLOTS.release();raise
    control=AnalysisControl(cancel_event,time.monotonic()+timeout)
    try:
        while not done.wait(.1):control.check()
        control.check()
    except BaseException:stop.set();raise
    if 'error' in result:raise result['error']
    return result['value']


class AnalysisControl:
    def __init__(self, cancel_event=None, deadline=None):
        self.cancel_event, self.deadline = cancel_event, deadline

    def check(self):
        if self.cancel_event is not None and self.cancel_event.is_set():
            raise CveScanCancelled("CVE scan cancelled")
        if self.deadline is not None and time.monotonic() >= self.deadline:
            raise CveProductDeadline()

    def is_set(self):
        self.check()
        return False

    def wait(self, delay):
        end = time.monotonic()+delay
        while True:
            self.check()
            remaining = end-time.monotonic()
            if remaining <= 0: return False
            if self.cancel_event is not None:
                self.cancel_event.wait(min(.1,remaining))
            else: time.sleep(min(.1,remaining))
