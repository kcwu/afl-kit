#!/usr/bin/env python
# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# TODO support exploitable
# TODO support valgrind ?
# TODO support showmap
# TODO ddmin: https://github.com/MarkusTeufelberger/afl-ddmin-mod
# TODO find similar variant but doesn't meet condition
# TODO use wait4() to get child resource
# TODO don't use communicate(), don't keep full stdout, stderr in memory
# TODO how to customize env properly?
# TODO detect asan/msan/ubsan automatically: __asan_default_options __msan_default_options __ubsan_default_options
import argparse
import ctypes
import logging
import os
import re
import resource
import signal
import subprocess
import sys
import tempfile
import textwrap
import time

MSAN_ERROR = 86

g_execs = 0

logger = None


def create_argument_parser():
    parser = argparse.ArgumentParser(
        description='General test case minimizer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Example command:
              %(prog)s -i file.in -o file.out -m none --stdout "'EXPLOITABLE'" -- ~/src/exploitable/triage.py './w3m -T text/html -dump @@'
            '''))
    group = parser.add_argument_group('Required parameters')
    group.add_argument(
        '-i', dest='input', metavar='file', required=True, help='Input file')
    group.add_argument(
        '-o', dest='output', metavar='file', required=True, help='Output file')

    group = parser.add_argument_group('Execution control settings')
    group.add_argument(
        '-t',
        dest='time_limit',
        type=int,
        default=1000,
        metavar='msec',
        help='timeout for each run (default: %(default)s)')
    group.add_argument(
        '-m',
        dest='memory_limit',
        default='50',
        metavar='megs',
        help='memory limit for child process (default: %(default)s)')

    group = parser.add_argument_group('Output conditions')
    group.add_argument('--stdout', metavar='STR', action='append', default=[],
        help='If stdout contains STR; --stdout could be specified multiple times.')
    group.add_argument('--stderr', metavar='STR', action='append', default=[],
        help='If stderr contains STR; --stderr could be specified multiple times.')

    group = parser.add_argument_group('Terminal condition')
    group.add_argument(
        '--auto',
        action='store_true',
        help='guess terminal condition by dry runs')
    group.add_argument(
        '--crash',
        action='store_true',
        help='Crash (got signal or MSAN error)')
    group.add_argument('--returncode', type=int)
    group.add_argument('--signal', type=int)
    group.add_argument(
        '--timeout',
        action='store_true',
        help='Execution time longer than timeout value specified by -t')
    # TODO how to detect? will be caught by --returncode now.
    #group.add_argument(
    #    '--memory_exceeded',
    #    action='store_true',
    #    help='Used more memory than size specified by -m')

    group = parser.add_argument_group('How to deal flaky case')
    group.add_argument(
        '--try', dest='try_', metavar='N', type=int, help='try few times (default: %(default)s)', default=1)
    group.add_argument(
        '--all',
        action='store_true',
        help='only keep if all trials meet conditions; default is any')

    group = parser.add_argument_group('Misc conditions')
    # TODO not implemented yet. For now, use afl-tmin instead.
    #group.add_argument('--aflmap', action='store_true', default=False)

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Show detail information for debugging %(prog)s')
    parser.add_argument('--verbose', '-v', action='count')
    parser.add_argument('--no-aslr', action='store_true', help='Disable ASLR')
    parser.add_argument('--dryrun', action='store_true')

    parser.add_argument('args', nargs='+')

    return parser


def setlimits(opts):
    if opts.memory_limit.isdigit():
        m = int(opts.memory_limit) * 2**20
        resource.setrlimit(resource.RLIMIT_AS, (m, m))
        resource.setrlimit(resource.RLIMIT_DATA, (m, m))
        resource.setrlimit(resource.RLIMIT_STACK, (m, m))
        resource.setrlimit(resource.RLIMIT_RSS, (m, m))


def run_target_once(opts, data):
    """
    return True if match condition
    """
    global g_execs
    logger.debug('run %d', len(data))

    # because we closed the fd and lose the lock, add pid as prefix to avoid
    # racing.
    tmp_fd, tmp_fn = tempfile.mkstemp(prefix='tmin-%d' % os.getpid())
    pid = os.getpid()
    try:
        os.write(tmp_fd, data)
        os.close(tmp_fd)

        found_input_file = False
        cmd = opts.args[:]
        for i in range(len(cmd)):
            if '@@' in cmd[i]:
                found_input_file = True
            cmd[i] = cmd[i].replace('@@', tmp_fn)

        env = os.environ.copy()
        #env = {}
        env.setdefault(
            'ASAN_OPTIONS',
            ':'.join([
                'abort_on_error=1',
                'detect_leaks=0',
                'symbolize=0',
                'allocator_may_return_null=1',
                #'detect_stack_use_after_return=1',
            ]))
        env.setdefault('MSAN_OPTIONS', ':'.join([
            'exit_code=%d' % MSAN_ERROR,
            'symbolize=0',
            'abort_on_error=1',
            'allocator_may_return_null=1',
            'msan_track_origins=0',
        ]))
        # for stack protector
        env['LIBC_FATAL_STDERR_'] = '1'

        if 'AFL_PRELOAD' in env:
            env['LD_PRELOAD'] = env['AFL_PRELOAD']

        if g_execs == 0:
            for k, v in sorted(env.items()):
                logger.debug('env[%r]=%r', k, v)
            logger.debug('run command line=%s', subprocess.list2cmdline(cmd))

        if found_input_file:
            stdin_handle = None
        else:
            stdin_handle = subprocess.PIPE
        if opts.stdout or g_execs == 0:
            stdout_handle = subprocess.PIPE
        else:
            stdout_handle = open('/dev/null', 'w')
        if opts.stderr or g_execs == 0:
            stderr_handle = subprocess.PIPE
        else:
            stderr_handle = open('/dev/null', 'w')

        p = subprocess.Popen(
            cmd,
            stdin=stdin_handle,
            stdout=stdout_handle,
            stderr=stderr_handle,
            env=env,
            preexec_fn=lambda: setlimits(opts))

        t0 = time.time()
        try:
            if opts.time_limit:

                def kill_child(*_args):
                    try:
                        p.kill()
                    except OSError:
                        pass

                signal.signal(signal.SIGALRM, kill_child)
                signal.setitimer(signal.ITIMER_REAL, 0.001 * opts.time_limit)
            if not found_input_file:
                stdout, stderr = p.communicate(data)
            else:
                stdout, stderr = p.communicate()
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
        t1 = time.time()
        crashed = p.returncode < 0 or p.returncode == MSAN_ERROR
    finally:
        # XXX why?
        if pid == os.getpid():
            os.unlink(tmp_fn)

    #logger.info('stdout begin =====')
    #logger.info('%s', stdout)
    #logger.info('stdout end =====')
    #logger.info('stderr begin =====')
    #logger.info('%s', stderr)
    #logger.info('stderr end =====')
    if g_execs == 0 and stderr:
        logger.info('stderr begin (last 8kb, 100 lines) =====')
        stderr = stderr[-8192:]
        stderr = '\n'.join(stderr.splitlines()[-100:])
        logger.info('%s', stderr)
        logger.info('stderr end =====')
    if g_execs == 0:
        logger.info('returncode=%d, t=%.3fs', p.returncode, t1 - t0)
    else:
        logger.debug('returncode=%d, t=%.3fs', p.returncode, t1 - t0)

    g_execs += 1

    if g_execs == 1 and opts.auto:
        opts.returncode = p.returncode
        if opts.returncode != 0:
            logger.info('AUTO: returncode=%s', opts.returncode)
        opts.timeout = opts.time_limit < (t1 - t0) * 1000
        if opts.timeout:
            logger.info('AUTO: timeout=%s', opts.timeout)
        if p.returncode < 0:
            opts.signal = -p.returncode
            logger.info('AUTO: signal=%s', opts.signal)
        m = re.search(r'ERROR: AddressSanitizer: (.+) on', stderr)
        if m:
            opts.stderr = [m.group()]
            m = re.search(r'(READ|WRITE) of size ', stderr)
            if m:
                opts.stderr.append(m.group())
            logger.info('AUTO: stderr=%r', opts.stderr)

    for s in opts.stdout:
        if s not in stdout:
            return False
    for s in opts.stderr:
        if s not in stderr:
            return False

    if opts.returncode is not None and opts.returncode != p.returncode:
        return False
    if opts.timeout is not None and \
        opts.timeout != (opts.time_limit < (t1 - t0) * 1000):
        return False
    if opts.signal and (p.returncode > 0 or opts.signal != -p.returncode):
        return False
    if opts.crash and not crashed:
        return False

    assert data, 'Even empty file meets required conditions! Please check again'

    return True


def run_target(opts, data):
    """
    return True if match condition
    """
    for _ in range(opts.try_):
        if run_target_once(opts, data):
            return True
    return False


def next_p2(v):
    r = 1
    while v > r:
        r *= 2
    return r


TMIN_SET_MIN_SIZE = 4
TMIN_SET_STEPS = 128
TRIM_START_STEPS = 16


def step_normalization(opts, data, dummy_char):
    in_len = len(data)

    alpha_del0 = 0

    set_len = next_p2(in_len / TMIN_SET_STEPS)
    set_pos = 0

    if set_len < TMIN_SET_MIN_SIZE:
        set_len = TMIN_SET_MIN_SIZE

    # TODO optimization?
    while set_pos < in_len:
        use_len = min(set_len, in_len - set_pos)
        if data[set_pos:set_pos + use_len].count(dummy_char) != use_len:
            tmp_buf = data[:set_pos] + dummy_char * use_len + data[set_pos+use_len:]

            if run_target(opts, tmp_buf):
                data = tmp_buf
                alpha_del0 += use_len

        set_pos += set_len

    return data, alpha_del0


def step_block_deletion(opts, data):
    in_len = len(data)

    del_len = next_p2(in_len / TRIM_START_STEPS)
    if not del_len:
        del_len = 1

    while del_len >= 1 and in_len >= 1:
        logger.info('del_len=%d, remain len=%d', del_len, in_len)
        del_pos = 0
        prev_del = True

        while del_pos < in_len:
            tail_len = in_len - del_pos - del_len
            if tail_len < 0:
                tail_len = 0

            # current block == last block and last block failed, so we can skip current block
            if not prev_del and tail_len and \
                data[del_pos - del_len: del_pos] == data[del_pos: del_pos + del_len]:
                del_pos += del_len
                continue

            prev_del = False
            tmp_buf = data[:del_pos] + data[del_pos + del_len:]
            if run_target(opts, tmp_buf):
                data = tmp_buf
                prev_del = True
                in_len = len(data)
                if opts.verbose >= 1:
                    sys.stderr.write('\x1b[sso far len=%d\x1b[u' % in_len)
            else:
                del_pos += del_len

        del_len /= 2

    return data


def step_alphabet_minimization(opts, data, dummy_char):
    """replace a class of character to dummy char"""
    alpha_del1 = 0
    alpha_map = [0] * 256
    for c in data:
        alpha_map[ord(c)] += 1
    alpha_size = 256 - alpha_map.count(0)

    for i in range(256):
        if i == ord(dummy_char) or alpha_map[i] == 0:
            continue

        tmp_buf = data.replace(chr(i), dummy_char)

        if run_target(opts, tmp_buf):
            data = tmp_buf
            alpha_del1 += alpha_map[i]

    return data, alpha_del1


def step_character_minimization(opts, data, dummy_char):
    """replace one character to dummy char"""
    for i in range(len(data)):
        if data[i] == dummy_char:
            continue
        tmp_buf = data[:i] + dummy_char + data[i + 1:]

        if run_target(opts, tmp_buf):
            data = tmp_buf

    return data


# use afl-tmin's minimization strategy
def minimize(opts):
    if opts.input == '-':
        data = orig_data = sys.stdin.read()
    else:
        data = orig_data = file(opts.input).read()
    logger.info('initial len=%d', len(data))

    logger.info('initial dry run')
    assert run_target(opts, data)
    if opts.dryrun:
        return

    alpha_d_total = 0

    dummy_char = '0'

    logger.info('start normalization')
    data, alpha_del0 = step_normalization(opts, data, dummy_char)
    alpha_d_total += alpha_del0
    assert data

    logger.info('start minimize')
    last_data = None
    pass_num = 1
    while data is not last_data:
        logger.info('#%d, remain len=%d', pass_num, len(data))
        last_data = data
        data = step_block_deletion(opts, data)
        assert data

        data, alpha_del1 = step_alphabet_minimization(opts, data, dummy_char)
        assert data
        alpha_d_total += alpha_del1

        data = step_character_minimization(opts, data, dummy_char)
        assert data

        logger.info('#%d, so far len=%d', pass_num, len(data))
        print repr(data)
        pass_num += 1

    logger.info('size: %d -> %d', len(orig_data), len(data))
    logger.info('execs: %d', g_execs)

    return data


def main():
    global logger

    parser = create_argument_parser()
    opts = parser.parse_args()

    log_level = logging.DEBUG if opts.debug else logging.INFO
    logging.basicConfig(
        level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    if opts.no_aslr:
        libc = ctypes.CDLL(None)
        ADDR_NO_RANDOMIZE = 0x0040000
        assert 0 == libc['personality'](ADDR_NO_RANDOMIZE)

    data = minimize(opts)
    if opts.dryrun:
        return

    print repr(data)
    with file(opts.output, 'wb') as f:
        f.write(data)


if __name__ == '__main__':
    main()
