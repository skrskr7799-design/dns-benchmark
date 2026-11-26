import unittest
from backend.ndc.inspection_gate import InspectionGate

class Tests(unittest.TestCase):
    def test_background_reservation(self):
        now=[100.]
        g=InspectionGate(lambda:now[0])
        self.assertTrue(g.acquire())
        self.assertFalse(g.acquire_background())
        g.release()
        for _ in range(20):self.assertFalse(g.acquire())
        self.assertTrue(g.acquire_background())
        self.assertFalse(g.acquire())
        g.release()
        self.assertTrue(g.acquire())
        g.release()
        with self.assertRaises(ValueError):g.release()
    def test_reservation_expires(self):
        now=[100.]
        g=InspectionGate(lambda:now[0]);self.assertTrue(g.acquire())
        self.assertFalse(g.acquire_background());g.release()
        now[0]=102.99;self.assertFalse(g.acquire())
        now[0]=103.;self.assertTrue(g.acquire());g.release()
    def test_single_slot_concurrent_admission(self):
        from concurrent.futures import ThreadPoolExecutor
        g=InspectionGate()
        with ThreadPoolExecutor(max_workers=8) as pool:
            answers=list(pool.map(lambda _:g.acquire(),range(32)))
        self.assertEqual(sum(answers),1);g.release()
if __name__=="__main__":unittest.main()
