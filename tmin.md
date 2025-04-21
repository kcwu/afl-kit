# tmin.py
Similar to afl-tmin, but minimize by different conditions.

## Features/enhancement
 - Support similar command line flags as afl-tmin.
 - Use similar minimization heuristic as afl-tmin.
 - Instead of classifying input by coverage, tmin.py classifies input by
   program output and terminal conditions. Supportted conditions:
     * `--stdout`: stdout contains given string
     * `--stderr`: stderr contains given string
     * `--crash`: program terminated by any signal
     * `--returncode`: program exits with given returncode
     * `--signal`: program terminated by given signal
     * `--timeout`: program terminated due to timeout

## Examples
 - Minimize input while makes sure [exploitable] still output `EXPLOITABLE`.

    `tmin.py -i file.in -o file.out -m none --stdout "'EXPLOITABLE'" -- ~/src/exploitable/triage.py './w3m -T text/html -dump @@'`

 - Minimize input while makes sure the program is still killed by SIGABRT (i.e. assert() fail)

    `tmin.py -i file.in -o file.out --signal 6 -- /path/to/program @@`

[exploitable]: https://github.com/jfoote/exploitable
