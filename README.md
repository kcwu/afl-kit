# afl-kit

## afl-cmin.py
Reimplement afl-cmin in python. Use less memory, less disk space, and faster.

Support the same command line flags as original afl-cmin. Use `-w WORKERS` to specify number of workers.

Non-scientific performance test: 

program     | worker | temp disk (mb) | memory | time (min)
----------- | ------ | -------------- | ------ | ----------
afl-cmin    |     1  |      9782      | 7.8gb  | 27
[afl-pcmin] |     8  |      9762      | 7.8gb  | 13.8
afl-cmin.py |     1  |       359      | <50mb  | 11.9
afl-cmin.py |     8  |      1136      | <250mb | 1.8

[afl-pcmin]: https://github.com/bnagy/afl-trivia

Detail of this table
- the input are 79k files, total 472mb. the output are 5k files, total 39mb.
- `temp disk` is the size of `.traces` folder after run with `AFL_KEEP_TRACES=1`.

## License
Apache License 2.0. Copyright 2016 Google Inc.

This is not an official Google product.

