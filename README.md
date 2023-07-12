# ECDSA - School project

Elliptic Curve Digital Signature Algorithm (ECDSA) implemented in Haskell.
Educational project, FIT BUT Brno (2022/23). Do not use in production 🫠.

## Compilation

To compile, run `make`.
`ghc` is required for compilation.

Uses *Parsec* and *Random* libraries.

## Usage

Find the expected input format in the `test` directory.

```
flp22-fun option [file]

If [file] is not specified, stdin is used
Options:
- -i - loads the input and prints it back
- -k - generates a key pair
- -s - signs the hash 
- -v - verifies the signature
```

Example:
```
./flp22-fun -k test/test_k.in
```

## Tests

Test files with the .in extension are inputs.
Each input file name contains a switch with which the test is to be run.
The corresponding output is in a file with the same name and the .out extension.

Example of comparing the output of the test_k.in file with the expected output:
```
./flp22-fun -k test/test_k.in norandom | diff test/test_k.out -
```

