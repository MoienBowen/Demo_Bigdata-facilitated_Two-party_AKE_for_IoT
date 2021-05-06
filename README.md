# Demo of Bigdata-facilitated Two-party AKE for IoT

## Preliminary

1. Install MIRACL (Multiprecision Integer and Rational Arithmetic Cryptographic Library) via [MICRCL GitHub repo](https://github.com/miracl/MIRACL) (e.g. [Instruction for Linux](https://github.com/miracl/MIRACL/blob/master/linux.txt))
2. Copy `miracl.a`，`miracl.h`，`mirdef.h` to the work path
3. Add necessary files into the code (e.g. #include "miracl.h")

## Execution

- Compile: `gcc -O2 demo.c miracl.a -o demo`
- Execute for 128 bits security: `./demo -l`
- Execute for 256 bits security: `./demo -h`

## Paper link

TBD
