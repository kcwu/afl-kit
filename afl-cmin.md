# afl-cmin.py
Reimplement afl-cmin in python. Use less memory, less disk space, and faster.

## Features/enhancement
 - Support the same command line flags as original afl-cmin.
 - dedup by hash of file content in the beginning.
 - `-i DIR` can be specified multiple times. Also support globbing. Search files
   recursively.
 - `--crash-dir DIR` to copy detected crashes (deduplicated by hash) into `DIR`.
 - `-T WORKERS` to specify number of workers.
 - `--as_queue` output filename like `id:000001,hash:value`.

So, you can use afl-cmin.py in workflow like this

1. Run many instances of afl-fuzz and have multiple queues in `sync_dir.1` directory
2. `afl-cmin.py -i 'sync_dir.1' -o sync_dir.2/prev/queue --as_queue ...`
3. Run another batch of afl-fuzz in `sync_dir.2`. They will automatically sync queue from `sync_dir.2/prev/queue`.

## Non-scientific performance test: 

### 2025 experiment

Following table shows performance numbers (in unit of minutes). Testing
condition:
 - 186k unique input files. 73k output files after cmin.
 - Tested on machine with 64 cores.
 - The fuzzing target uses deferred fork server. Execution speed is about 36/s.

|   worker  | afl-cmin | afl-cmin.py <br/> of 2022 | afl-cmin.py |
| --------: | -------: | ------------------------: | ----------: |
|        1  |  162.2   |           est. 480.0      |  94.3       |
|        2  |          |           est. 240.0      |  48.6       |
|        4  |          |                121.0      |  24.5       |
|        8  |   94.0   |                 61.8      |  12.9       |
|       16  |          |                 32.0      |   6.8       |
|       32  |          |                 17.2      |   3.8       |
|       64  |   76.2   |                 10.6      |   2.5       |

New AFL++'s afl-cmin is much faster than 2016
 - afl-showmap supports fork server since 2020.
 - afl-cmin executes multiple afl-showmap parallelly since 2023.
 - However, the data processing after target execution is still single thread.

As comparison, afl-showmap takes 85 minutes to generate all traces using fork
server.

afl-pcmin no longer works with afl++, so skip it.

### historical experiment as 2016 version

At that time, afl-showmap didn't support fork server and afl-cmin didn't
support parallel processing.

program     | worker | temp disk (mb) | memory | time (min)
----------- | ------ | -------------: | ------ | ---------:
afl-cmin    |     1  |      9782      | 7.8gb  | 27
[afl-pcmin] |     8  |      9762      | 7.8gb  | 13.8
afl-cmin.py |     1  |       359      | <50mb  | 11.9
afl-cmin.py |     8  |      1136      | <250mb | 1.8

[afl-pcmin]: https://github.com/bnagy/afl-trivia

Detail of this table
- the input are 79k unique files, total 472mb. the output are 5k files, total 39mb.
- `temp disk` is the size of `.traces` folder after run with `AFL_KEEP_TRACES=1`.

