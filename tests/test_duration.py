"""Reject incomplete duration evidence and resource regressions."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ports/esp_idf'))
from duration import assess, rounds_for
from resources import check_count


class DurationAcceptance(unittest.TestCase):
    def setUp(self):
        self.output = '\n'.join(
            f'RESOURCE_ROUND round={i} elapsed_us=120000000 total_us={i * 120000000} run=fixture'
            for i in range(1, 4)) + '\n'
        self.samples = [dict(phase='cooldown-end', peak=29761, free=336724,
                             largest=245760, main_stack_free=9000, tcp_stack_free=2140)
                        for _ in range(3)]

    def accepted(self, output=None, samples=None, elapsed=361):
        result = assess(self.output if output is None else output,
                        self.samples if samples is None else samples, 360, elapsed, 'fixture')
        return result['complete_duration'] and result['resource_limits_passed']

    def test_complete(self):
        self.assertTrue(self.accepted())
        self.assertEqual(rounds_for(7200), 60)
        self.assertEqual(rounds_for(28800), 240)
        self.assertEqual(check_count(60, 7200), 6904)

    def test_invalid_configuration(self):
        for value in (True, 0, -120, 119, 121, 28801, 36000, 120.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                rounds_for(value)
        with self.assertRaises(ValueError):
            check_count(59, 7200)
        with self.assertRaises(ValueError):
            check_count(2)

    def test_incomplete_or_inconsistent_markers(self):
        for output in ('', self.output.splitlines()[0], self.output + self.output,
                       self.output.replace('round=2', 'round=1'),
                       self.output.replace('run=fixture', 'run=other'),
                       self.output.replace('elapsed_us=120000000', 'elapsed_us=119999999'),
                       self.output.replace('elapsed_us=120000000', 'elapsed_us=155000001'),
                       self.output.replace('total_us=240000000', 'total_us=239000000')):
            with self.subTest(output=output):
                self.assertFalse(self.accepted(output=output))

    def test_host_duration_and_missing_measurements(self):
        self.assertFalse(self.accepted(elapsed=359))
        self.assertFalse(self.accepted(elapsed=476))
        self.assertFalse(self.accepted(samples=[]))
        self.assertFalse(self.accepted(samples=self.samples[:-1]))

    def test_memory_and_stack_limits(self):
        for key, value in (('peak', 32769), ('free', 294999), ('largest', 229999),
                           ('main_stack_free', 7999), ('tcp_stack_free', 1999)):
            samples = [dict(s) for s in self.samples]
            samples[1][key] = value
            with self.subTest(key=key):
                self.assertFalse(self.accepted(samples=samples))

    def test_warm_growth_and_fragmentation(self):
        for key, delta in (('free', -65), ('free', 129), ('largest', -16)):
            samples = [dict(s) for s in self.samples]
            samples[-1][key] += delta
            with self.subTest(key=key, delta=delta):
                self.assertFalse(self.accepted(samples=samples))


if __name__ == '__main__':
    unittest.main()
