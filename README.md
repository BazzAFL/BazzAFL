# BazzAFL-based on AFL++
GitHub version: v1.0

This is developed based on AFLplusplus (4.01c), thanks to its amazing maintainers and community!



Here is some information to get you started:

* For an overview of the AFL++ documentation and a very helpful graphical guide,
  please visit [docs/README.md](docs/README.md).
* To get you started with tutorials, go to
  [docs/tutorials.md](docs/tutorials.md).
* For releases, see the
  [Releases tab](https://github.com/AFLplusplus/AFLplusplus/releases) and
  [branches](#branches). The best branches to use are, however, `stable` or
  `dev` - depending on your risk appetite. Also take a look at the list of
  [important changes in AFL++](docs/important_changes.md) and the list of
  [features](docs/features.md).
* If you want to use AFL++ for your academic work, check the
  [papers page](https://aflplus.plus/papers/) on the website.
* To cite our work, look at the [Cite](#cite) section.
* For comparisons, use the fuzzbench `aflplusplus` setup, or use
  `afl-clang-fast` with `AFL_LLVM_CMPLOG=1`. You can find the `aflplusplus`
  default configuration on Google's
  [fuzzbench](https://github.com/google/fuzzbench/tree/master/fuzzers/aflplusplus).
  
## Getting started

## Prerequisite
Tested on a machine with Ubuntu 16.04/18.04/20.04 LLVM 13.0.0 <br/>
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
If something goes wrong, make sure your clamg and LLVM >= 11 and GLib-2.0 has been installed correctly

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

