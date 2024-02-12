## PDB downloader written in python

A simple script for downloading PDB for Windows binaries.
Can be used on linux.

### Usage
```
python download_pdb.py --help
usage: download_pdb.py [-h] -f FILE [-s STORE] [-n] [-o OUTPUT] [-d OUTPUT_DIR]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Path to PE file
  -s STORE, --store STORE
                        PDB store URL
  -n, --no-download     No download. Only print PDB info.
  -o OUTPUT, --output OUTPUT
                        Output filepath
  -d OUTPUT_DIR, --output-dir OUTPUT_DIR
                        Output directory
```

Example:
```
python download_pdb.py -f d3d11.dll
PDB signature: 4B57CB6785D3D4454CE287EAA21B3C6C1
PDB filename: d3d11.pdb
PDB written to d3d11.pdb
```

### Credits
[pefile](https://github.com/erocarrera/pefile) - the magnificent python library for loading PE files
