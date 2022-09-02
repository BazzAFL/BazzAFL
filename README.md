# BazzAFL-based on AFL++
GitHub version: v1.0

This is developed based on AFLplusplus (4.01c), thanks to its amazing maintainers and community!
  
## Getting started

## Prerequisite
Firstly, Please follow the instructions of building afl++  (please refer to README_aflpp) <br/>

We have tested on a machine with Ubuntu 16.04/18.04/20.04 LLVM 13.0.0 <br/>

We recommend running BazzAFL on Ubuntu 16.04/20.04
- LLVM >= 11 (recommend [pre-built LLVM 13.0.0](https://github.com/llvm/llvm-project/releases/tag/llvmorg-13.0.0))
- GLib–2.0 (source:[glib2.0](https://gitlab.gnome.org/GNOME/glib/))

## Build
```bash
    git clone pull https://github.com/BazzAFL/BazzAFL.git
    cd BazzAFL
    make 
```
## Usage
First you need to compile the target program you want to fuzz with `afl-clang-fast` or `afl-clang-fast++`.<br/>

```bash
    export CC=/path/to/BazzAFL/afl-clang-fast
    export CXX=/path/to/BazzAFL/afl-clang-fast++
```
If something goes wrong, make sure your clang and LLVM >= 11 and GLib-2.0 has been installed correctly

```bash
    clang --version
    llvm-config --version
```

Then compile and build the target program <br/>
For example
```bash
    cd testbazz
    unzip -q libtiff-3.9.7.zip
    cd libtiff-Release-v3-9-7
    ./autogen.sh && ./configure --disable-shared
    make -j
    cp tools/tiffsplit ../tiffsplit/    
```
If you want to try BazzAFL on a new program, 
1. Compile the new program from source code using BazzAFL/afl-clang-fast or BazzAFL/afl-clang-fast++
2. Prepare appropriate input files


## Running BazzAFL

```bash
    bash prepare.sh
    ./afl-fuzz -i in -z 4 -o out ./tiffsplit @@ # set AFL_NO_UI=1 is recommended
    # -z --switch of BazzAFL
    # 0 = original AFL++ without any of BazzAFL's optimization on
    # 4 = all three components of BazzAFL are on 
```
PS:In order to improve the efficiency of BazzAFL, the Explore mode is used by default when using the -z option to prevent the total energy of the seed groups too small

## Analyze 

- You can always view the process of BazzAFL in the `plot_data`(by aflpp) and `mb_record` log files, and also observe the generation of the subseeds in the subseeds folder(replaced subseed will be deleted and free at the end of fuzzing in case sth uncertain happens)

