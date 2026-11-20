#!/usr/bin/env python3
"""PTYの終了がmasterの読み出し待ちになる競合を、実プロセスなしで固定する。"""
import os
from pathlib import Path
import runpy
from unittest.mock import patch

namespace = runpy.run_path(str(Path(__file__).with_name('rpc-privacy-prompts-pty.py')), run_name='cleanup_fixture')
Job = namespace['Job']

def check(stuck=False):
    job = Job.__new__(Job)
    job.pid = 1_000_000_000
    job.fd, writer = os.pipe()
    job.output = b''
    job.owned = {job.pid}
    job.groups = set()
    job.send = lambda _: os.write(writer, b'PTY_EXIT_OUTPUT')
    waits = []
    reaped = False
    def waitpid(pid, options):
        nonlocal reaped
        assert options == os.WNOHANG, 'blocking waitpidは禁止'
        waits.append(options)
        if job.output and not stuck:
            reaped = True
            return pid, 0
        return 0, 0
    def kill(pid, sig):
        if sig == 0 and reaped:
            raise ProcessLookupError()
    tick = iter(range(1000))
    try:
        with patch.object(os, 'tcgetpgrp', return_value=job.pid), \
             patch.object(os, 'waitpid', side_effect=waitpid), \
             patch.object(os, 'kill', side_effect=kill), \
             patch.object(os, 'killpg'), \
             patch.object(namespace['time'], 'monotonic', side_effect=lambda: next(tick) / 10):
            if stuck:
                try:
                    job.close()
                except RuntimeError as error:
                    assert 'timeout' in str(error)
                else:
                    raise AssertionError('回収不能でも上限でFAILにする')
            else:
                job.close()
                assert reaped and job.output == b'PTY_EXIT_OUTPUT', '待つ間もmasterを読む'
                assert len(waits) >= 2
    finally:
        os.close(writer)

check()
check(stuck=True)
print('RPC privacy PTY cleanup: PASS (drain, WNOHANG, bounded failure)')
