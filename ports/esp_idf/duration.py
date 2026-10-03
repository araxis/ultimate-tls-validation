"""Bounded resource-duration configuration and evidence acceptance."""
import re

ROUND_SECONDS = 120
MAX_SECONDS = 28800


def rounds_for(seconds):
    if type(seconds) is not int or not ROUND_SECONDS <= seconds <= MAX_SECONDS or seconds % ROUND_SECONDS:
        raise ValueError('Duration must be a multiple of 120 seconds from 120 through 28800')
    return seconds // ROUND_SECONDS


def assess(output, samples, seconds, elapsed_seconds, run_id):
    rounds = rounds_for(seconds)
    markers = re.findall(r'^RESOURCE_ROUND round=(\d+) elapsed_us=(\d+) total_us=(\d+) run=(\S+)\r?$', output, re.M)
    complete = len(markers) == rounds
    previous = 0
    for index, (number, elapsed, total, identity) in enumerate(markers, 1):
        elapsed, total = int(elapsed), int(total)
        complete = complete and (int(number) == index and identity == run_id and
            120000000 <= elapsed <= 155000000 and total > previous and
            elapsed <= total - previous <= elapsed + 1000000)
        previous = total
    complete = complete and seconds * 1000000 <= previous <= rounds * 155000000
    complete = complete and seconds <= elapsed_seconds <= rounds * 155 + 10
    cooldown = [s for s in samples if s['phase'] == 'cooldown-end']
    complete = complete and len(cooldown) == rounds and bool(samples)
    bounded = bool(samples) and all(s['peak'] <= 32768 and s['free'] >= 295000 and
        s['largest'] >= 230000 and s['main_stack_free'] >= 8000 and s['tcp_stack_free'] >= 2000 for s in samples)
    if cooldown:
        free = [s['free'] for s in cooldown]
        bounded = bounded and max(free) - min(free) <= 128 and free[-1] >= free[0] - 64
        bounded = bounded and all(s['largest'] >= cooldown[0]['largest'] for s in cooldown)
    else:
        bounded = False
    return {'complete_duration': bool(complete), 'resource_limits_passed': bool(bounded),
            'requested_seconds': seconds, 'rounds': rounds, 'markers': markers,
            'cooldown_free_bytes': [s['free'] for s in cooldown]}
