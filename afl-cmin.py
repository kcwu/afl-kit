#!/usr/bin/env python3
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
import logging
import os
import subprocess
import shutil
import multiprocessing
import array
import collections
import glob
import hashlib
import base64

try:
    from tqdm import tqdm
except ImportError:
    print('Hint: install python module "tqdm" to show progress bar')
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
group.add_argument('-m', dest='memory_limit', default='none', metavar='megs',
        type=lambda x: x if x == 'none' else int(x),
        help='memory limit for child process (default: %(default)s)')
group.add_argument('-t', dest='time_limit', default='none', metavar='msec',
        type=lambda x: x if x == 'none' else int(x),
        help='timeout for each run (default: %(default)s)')
group.add_argument('-O', dest='frida_mode', action='store_true', default=False,
        help='use binary-only instrumentation (FRIDA mode)')
group.add_argument('-Q', dest='qemu_mode', action='store_true', default=False,
        help='use binary-only instrumentation (QEMU mode)')
group.add_argument('-U', dest='unicorn_mode', action='store_true', default=False,
        help='use unicorn-based instrumentation (Unicorn mode)')

group = parser.add_argument_group('Minimization settings')
group.add_argument('--crash-dir', dest='crash_dir', metavar='dir', default=None,
        help="move crashes to a separate dir, always deduplicated")
group.add_argument('-C', dest='crash_only', action='store_true',
        help='keep crashing inputs, reject everything else')
group.add_argument('-e', dest='edge_mode', action='store_true', default=False,
        help='solve for edge coverage only, ignore hit counts')

group = parser.add_argument_group('Misc')
group.add_argument('-w', dest='workers', type=int, default=cpu_count//2,
        help='number of concurrent worker (%d)' % (cpu_count // 2))
group.add_argument('--as_queue', action='store_true',
        help='output file name like "id:000000,hash:value"')
group.add_argument('--no-dedup', action='store_true',
        help='skip deduplication step for corpus files')
group.add_argument('--debug', action='store_true')

parser.add_argument('exe', metavar='/path/to/target_app')
parser.add_argument('args', nargs='*')

args = parser.parse_args()
logger = None
afl_showmap_bin = None

def init():
    global logger
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

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

    if not os.environ.get('AFL_SKIP_BIN_CHECK') and not (args.qemu_mode or args.frida_mode or args.unicorn_mode):
        if b'__AFL_SHM_ID' not in open(args.exe, 'rb').read():
            logger.error("binary '%s' doesn't appear to be instrumented", args.exe)
            sys.exit(1)

    for dn in args.input:
        if not os.path.isdir(dn):
            logger.error('directory "%s" not found', dn)
            sys.exit(1)


    global afl_showmap_bin
    searches = [
        None,
        os.path.dirname(__file__),
        os.getcwd(),
        ]
    if os.environ.get('AFL_PATH'):
        searches.append(os.environ['AFL_PATH'])
  
    for search in searches:
        afl_showmap_bin = shutil.which('afl-showmap', path=search)
        if afl_showmap_bin:
            break
    if not afl_showmap_bin:
        logger.fatal('cannot find afl-showmap, please set AFL_PATH')
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
    if args.crash_dir and not os.path.exists(args.crash_dir):
        os.makedirs(args.crash_dir)
    os.makedirs(trace_dir)

def afl_showmap(input_path, first=False):
    cmd = [
            afl_showmap_bin,
            '-m', str(args.memory_limit),
            '-t', str(args.time_limit),
            '-o', '-',
            '-Z']
    env = os.environ.copy()

    if args.frida_mode:
        cmd += ['-O']
    if args.qemu_mode:
        cmd += ['-Q']
    if args.unicorn_mode:
        cmd += ['-U']
    if args.edge_mode:
        cmd += ['-e']
    cmd += ['--', args.exe] + args.args

    input_from_file = False
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
        env['AFL_CMIN_ALLOW_ANY'] = '1'

    if input_from_file:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, env=env, bufsize=1048576)
    else:
        p = subprocess.Popen(cmd, stdin=open(input_path, 'rb'), stdout=subprocess.PIPE, env=env, bufsize=1048576)
    out = p.stdout.read()
    p.wait()
    #out = p.communicate()[0]

    values = []
    for line in out.split():
      # we get result from stdout and afl-showmap may generate warnings to stdout as well.
      if not line.isdigit():
        continue
      values.append(int(line))
    a = array.array('l', values)

    # return code of afl-showmap is child_crashed * 2 + child_timed_out where
    # child_crashed and child_timed_out are either 0 or 1
    crashed = p.returncode in [2, 3]

    return a, crashed

class Worker(multiprocessing.Process):
    def __init__(self, q_in, p_out, r_out):
        super(Worker, self).__init__()
        self.q_in = q_in
        self.p_out = p_out
        self.r_out = r_out

    def run(self):
        map_size = int(os.environ.get('AFL_MAP_SIZE', '65536'))
        max_value = int('8' + str(map_size))
        m = array.array('l', [0xffffff] * max_value)
        counter = collections.Counter()
        crashes = []
        while True:
            # job is ordered by size, small to large
            job = self.q_in.get()
            if job is None:
                break

            idx, input_path = job
            r, crash = afl_showmap(input_path)
            counter.update(r)

            used = False

            if crash:
                crashes.append(idx)

            # If we aren't saving crashes to a separate dir, handle them
            # the same as other inputs. However, unless AFL_CMIN_ALLOW_ANY=1,
            # afl_showmap will not return any coverage for crashes so they will
            # never be retained.
            if not crash or not args.crash_dir:
                for t in r:
                    if idx < m[t]:
                        m[t] = idx
                        used = True

            if used:
                trace_fn = os.path.join(args.output, '.traces', '%d' % idx)
                with open(trace_fn, 'wb') as f:
                    f.write(r.tobytes())

                self.p_out.put(idx)
            else:
                self.p_out.put(None)

        self.r_out.put((m, counter, crashes))

def hash_file(path):
    m = hashlib.sha1()
    with open(path, 'rb') as f:
      m.update(f.read())
    return m.digest()

def dedup(files):
    with multiprocessing.Pool(args.workers) as pool:
      seen_hash = set()
      result = []
      hashmap = {}
      for i, h in enumerate(pool.map(hash_file, files)):
          if h in seen_hash:
              continue
          seen_hash.add(h)
          result.append(files[i])
          hashmap[files[i]] = h
      return result, hashmap

def collect_files(input_paths):
  paths = []
  for s in input_paths:
      paths += glob.glob(s)

  files = []
  for path in paths:
    for root, dirnames, filenames in os.walk(path, followlinks=True):
      if 'queue' in dirnames:
        # modify in-place
        dirnames[:] = ['queue']
        continue

      for filename in filenames:
        if filename.startswith('.'):
          continue
        files.append(os.path.join(root, filename))
  return files

def main():
    init()

    files = collect_files(args.input)
    if len(files) == 0:
        logger.error('no inputs in the target directory - nothing to be done')
        sys.exit(1)
    logger.info('Found %d input files in %d directories', len(files), len(args.input))

    if not args.no_dedup:
        files, hashmap = dedup(files)
        logger.info('Remain %d files after dedup', len(files))
    else:
        logger.info('Skipping file deduplication.')

    logger.info('Sorting files.')
    files = sorted(files, key=os.path.getsize)

    logger.info('Testing the target binary')
    tuples, _ = afl_showmap(files[0], first=True)
    if tuples:
        logger.info('ok, %d tuples recorded', len(tuples))
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
    crashes = []
    counter = collections.Counter()
    for _ in range(args.workers):
        m, c, crs = result_queue.get()
        ms.append(m)
        counter.update(c)
        crashes.extend(crs)
    best_idxes = list(map(min, zip(*ms)))

    if not args.crash_dir:
        logger.info('Found %d unique tuples across %d files (%d effective)',
            len(counter), len(files), effective)
    else:
        logger.info('Found %d unique tuples across %d files (%d effective, %d crashes)',
            len(counter), len(files), effective, len(crashes))
    all_unique = counter.most_common()

    logger.info('Processing candidates and writing output')
    already_have = set()
    count = 0
    for t, c in tqdm(list(reversed(all_unique))):
        if t in already_have:
            continue

        idx = best_idxes[t]
        input_path = files[idx]
        fn = (base64.b16encode(hashmap[input_path]).decode('utf8').lower()
              if not args.no_dedup
              else os.path.basename(input_path))
        if args.as_queue:
            fn = ('id:%06d,hash:%s' % (count, fn)
                  if not args.no_dedup
                  else 'id:%06d,orig:%s' % (count, fn))
        output_path = os.path.join(args.output, fn)
        try:
            os.link(input_path, output_path)
        except OSError:
            shutil.copy(input_path, output_path)

        trace_fn = os.path.join(args.output, '.traces', '%d' % idx)
        with open(trace_fn, 'rb') as f:
          result = array.array('l', f.read())
        for t in result:
            already_have.add(t)
        count += 1

    if args.crash_dir:
        logger.info('Saving crashes to %s', args.crash_dir)
        crash_files = [files[c] for c in crashes]

        if args.no_dedup:
            # Unless we deduped previously, we have to dedup the crash files
            # now.
            crash_files, hashmap = dedup(crash_files)

        for crash_path in crash_files:
            fn = base64.b16encode(hashmap[crash_path]).lower()
            output_path = os.path.join(args.crash_dir, fn)
            try:
                os.link(crash_path, output_path)
            except OSError:
                try:
                    shutil.copy(crash_path, output_path)
                except shutil.Error:
                    # This error happens when src and dest are hardlinks of the
                    # same file. We have nothing to do in this case, but handle
                    # it gracefully.
                    pass

    if count == 1:
        logger.warn('all test cases had the same traces, check syntax!')
    logger.info('narrowed down to %s files, saved in "%s"', count, args.output)
    if not os.environ.get('AFL_KEEP_TRACES'):
        trace_dir = os.path.join(args.output, '.traces')
        shutil.rmtree(trace_dir, ignore_errors=True)

if __name__ == '__main__':
    main()
