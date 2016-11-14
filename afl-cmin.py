#!/usr/bin/env python
# Copyright 2016 Google Inc.
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
import argparse
import sys
import time
import logging
import os
import subprocess
import shutil
import multiprocessing
import array
import collections
import glob

try:
    from tqdm import tqdm
except ImportError:
    print 'Hint: install python module "tqdm" to show progress bar'
    def tqdm(data, *args, **argd):
        for x in data:
            yield x

parser = argparse.ArgumentParser()

cpu_count = multiprocessing.cpu_count()
group = parser.add_argument_group('Required parameters')
group.add_argument('-i', dest='input', action='append', metavar='dir', required=True,
        help='input directory with the starting corpus')
group.add_argument('-o', dest='output', metavar='dir', required=True,
        help='output directory for minimized files')

group = parser.add_argument_group('Execution control settings')
group.add_argument('-f', dest='stdin_file', metavar='file',
        help='location read by the fuzzed program (stdin)')
group.add_argument('-m', dest='memory_limit', metavar='megs',
        type=lambda x: x if x == 'none' else int(x),
        help='memory limit for child process (100)')
group.add_argument('-t', dest='time_limit', default='none', metavar='msec',
        type=lambda x: x if x == 'none' else int(x),
        help='timeout for each run (none)')
group.add_argument('-Q', dest='qemu_mode', action='store_true', default=False,
        help='use binary-only instrumentation (QEMU mode)')

group = parser.add_argument_group('Minimization settings')
group.add_argument('-C', dest='crash_only', action='store_true',
        help='keep crashing inputs, reject everything else')
group.add_argument('-e', dest='edge_mode', action='store_true', default=False,
        help='solve for edge coverage only, ignore hit counts')

group = parser.add_argument_group('Misc')
group.add_argument('-w', dest='workers', type=int, default=cpu_count/2,
        help='number of concurrent worker (%d)' % (cpu_count / 2))
group.add_argument('--debug', action='store_true')

parser.add_argument('exe', metavar='/path/to/target_app')
parser.add_argument('args', nargs='*')

args = parser.parse_args()
logger = None

def init():
    global logger
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    os.environ['AFL_CMIN_ALLOW_ANY'] = '1'

    if args.stdin_file and args.workers > 1:
        logger.error('-f is only supported with one worker (-w 1)')
        sys.exit(1)

    if args.crash_only:
        os.environ['AFL_CMIN_CRASHES_ONLY'] = '1'
    if args.memory_limit is None:
        args.memory_limit = 100

    if args.memory_limit != 'none' and args.memory_limit < 10:
        logger.error('dangerously low memory limit')
        sys.exit(1)

    if args.time_limit != 'none' and args.time_limit < 10:
        logger.error('dangerously low timeout')
        sys.exit(1)

    if not os.path.isfile(args.exe):
        logger.error('binary "%s" not found or not regular file', args.exe)
        sys.exit(1)

    if not os.environ.get('AFL_SKIP_BIN_CHECK') and not args.qemu_mode:
        if '__AFL_SHM_ID' not in file(args.exe).read():
            logger.error("binary '%s' doesn't appear to be instrumented", args.exe)
            sys.exit(1)

    expanded = []
    for s in args.input:
        expanded += glob.glob(s)
    args.input = expanded

    for dn in args.input:
        if not os.path.isdir(dn):
            logger.error('directory "%s" not found', dn)
            sys.exit(1)

    trace_dir = os.path.join(args.output, '.traces')
    shutil.rmtree(trace_dir, ignore_errors=True)
    try:
        os.rmdir(args.output)
    except OSError:
        pass
    if os.path.exists(args.output):
        logger.error('directory "%s" exists and is not empty - delete it first', args.output)
        sys.exit(1)
    os.makedirs(trace_dir)


def afl_showmap(input_path, first=False):
    cmd = [
            'afl-showmap',
            '-m', str(args.memory_limit),
            '-t', str(args.time_limit),
            '-o', '-',
            '-Z']

    if args.qemu_mode:
        cmd += ['-Q']
    if args.edge_mode:
        cmd += ['-e']
    cmd += ['--', args.exe] + args.args

    if args.stdin_file:
        input_from_file = True
        shutil.copy(input_path, args.stdin_file)
        input_path = args.stdin_file
    for i in range(len(cmd)):
        if '@@' in cmd[i]:
            input_from_file = True
            cmd[i] = cmd[i].replace('@@', input_path)

    if first:
        logger.debug('run command line: %s', subprocess.list2cmdline(cmd))
    if input_from_file:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=1048576)
    else:
        p = subprocess.Popen(cmd, stdin=file(input_path), stdout=subprocess.PIPE, bufsize=1048576)
    out = p.stdout.read()
    p.wait()
    #out = p.communicate()[0]

    a = array.array('l', map(int, out.split()))
    return a

class Worker(multiprocessing.Process):
    def __init__(self, q_in, p_out, r_out):
        super(Worker, self).__init__()
        self.q_in = q_in
        self.p_out = p_out
        self.r_out = r_out

    def run(self):
        m = array.array('l', [0xffffff] * 865536)
        counter = collections.Counter()
        while True:
            # job is ordered by size, small to large
            job = self.q_in.get()
            if job is None:
                break

            idx, input_path = job
            r = afl_showmap(input_path)
            counter.update(r)

            used = False
            for t in r:
                if idx < m[t]:
                    m[t] = idx
                    used = True
            if used:
                trace_fn = os.path.join(args.output, '.traces', '%d' % idx)
                with open(trace_fn, 'wb') as f:
                    f.write(r.tostring())

                self.p_out.put(idx)
            else:
                self.p_out.put(None)

        self.r_out.put((m, counter))


def main():
    init()

    files = (os.path.join(dn, fn) for dn in args.input for fn in os.listdir(dn) if not fn.startswith('.'))
    files = sorted(files, key=lambda input_path: os.path.getsize(input_path))
    if len(files) == 0:
        logger.error('no inputs in the target directory - nothing to be done')
        sys.exit(1)
    logger.info('Found %d input files in %d directories', len(files), len(args.input))

    logger.info('Testing the target binary')
    result = afl_showmap(files[0], first=True)
    if result:
        logger.info('ok, %d tuples recorded', len(result))
    else:
        logger.error('no instrumentation output detected')
        sys.exit(1)

    job_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()
    result_queue = multiprocessing.Queue()

    workers = []
    for _ in range(args.workers):
        p = Worker(job_queue, progress_queue, result_queue)
        p.start()
        workers.append(p)

    logger.info('Obtaining trace results')
    for job in enumerate(files):
        job_queue.put(job)
    for _ in range(args.workers):
        job_queue.put(None)
    job_queue.close()

    effective = 0
    for _ in tqdm(files):
        idx = progress_queue.get()
        if idx is not None:
            effective += 1

    ms = []
    counter = collections.Counter()
    for _ in range(args.workers):
        m, c = result_queue.get()
        ms.append(m)
        counter.update(c)
    best_idxes = map(min, zip(*ms))

    logger.info('Found %d unique tuples across %d files (%d effective)',
            len(counter), len(files), effective)
    all_unique = counter.most_common()

    logger.info('Processing candidates and writing output')
    already_have = set()
    count = 0
    for t, c in tqdm(list(reversed(all_unique))):
        if t in already_have:
            continue

        idx = best_idxes[t]
        input_path = files[idx]
        output_path = os.path.join(args.output, '%d' % idx)
        try:
            os.link(input_path, output_path)
        except OSError:
            shutil.copy(input_path, output_path)

        trace_fn = os.path.join(args.output, '.traces', '%d' % idx)
        result = array.array('l', file(trace_fn).read())
        for t in result:
            already_have.add(t)
        count += 1

    if count == 1:
        logger.warn('all test cases had the same traces, check syntax!')
    logger.info('narrowed down to %s files, saved in "%s"', count, args.output)
    if not os.environ.get('AFL_KEEP_TRACES'):
        trace_dir = os.path.join(args.output, '.traces')
        shutil.rmtree(trace_dir, ignore_errors=True)

if __name__ == '__main__':
    main()
