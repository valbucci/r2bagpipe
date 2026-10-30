# r2bagpipe

A wrapper interface for r2pipe with data caching and loading capabilities.

## Development

- [ ] Radare2 analysis and caching
  - [x] Use data cached with Bin2ML fork
    - See [valbucci/bin2ml](https://github.com/valbucci/bin2ml) (dev branch)
  - [ ] Replicate `bin2ml extract` functionality with internal module.
- [ ] Track cached files
  - [x] Data files from known binary name and output directory
    - `trackers.py` for tracking data paths
  - [ ] Extraction logs (errors/warnings)
- [ ] Data loading, validation and streaming
  - [x] `r2types.py` for type checking
  - [x] `parsers.py` for data parsing and streaming
  - [ ] `loader.py` main module for loading data files
    - [x] Implement data loading and function grouping
    - [ ] Refactor `BinaryDataLoader`

---

This project stems from [BinRankBench](https://github.com/valbucci/binrankbench).
It aims to modularise the data loading/caching and avoid dependency on [Bin2ML](https://github.com/br0kej/bin2ml).
Below is the implementation plan for the future release of v1.0.0.

---

## Features

- Analyse binary files with radare2 and store outputs in a structured manner
- Track cached data files and error logs
- Load, validate, and stream cached data
  - Supported commands are:
    - `ij`: General file information
    - `afij`: General function information
    - `cgj`: Global function callgraph
    - `agij`: CFG-structured opcodes and references
    - `zg; zj`: Zignatures

## Usage

> **WARNING:**
> Below is a general idea of how the project is going to work.
> This is yet to be implemented and is subject to change.

```python
# For data extraction
from r2bagpipe import Bagpipe

r2p = Bagpipe(input="path/to/input_file", 
              output="path/to/output_dir",
              config="path/to/config.yaml")

r2p.setup()   # start r2pipe and set environment variables
r2p.analyze() # submit analysis commands (e.g. aaa; zg)
r2p.stash()   # extract and save analysis data

# For data loading
from r2bagpipe import Bagpipe
from r2bagpipe.typing import R2FunctionInfo # Just for type hinting

r2b = Bagpipe(data="path/to/data_dir")

# If a single binary data directory
print(r2b.length)  # Output: 1
bin_bag = r2b.get()
functions: list[R2FunctionInfo] = bin_bag.functions_info
# ... or if you have limited RAM ...
for function in bin_bag.stream_functions_info():
  func_size = function.get("size")

# If Bag is provided with a root directory with many binary data items 
print(r2b.length)  # Output: 500
for bin_bag in r2b.stream():
  print(bin_bag.bininfo)  # Loaded from ij cache
```
