 © 2019 Stuart Edward Schechter (Github: @uppajung)
 
# DiceKeys Seeded Cryptography Library

This c++ library is used to support the generation of seeds, symmetric keys, public/private keys, and signing/verification keys from a seed string and a set of derivation parameters specified in JSON format (specifying the type of key, key length, etc.)


## Clone the repository with the ``--recursive`` option

Since we include GoogleTest and opencv as submodules, you will need to clone this repository using the ``--recursive`` directory so that the submodule will be downloaded. (If you forgot, use ``git submodule update --init --recursive``.)

```
git clone --recursive https://github.com/dicekeys/crypto-seeded.git
cd crypto-seeded
```

You will need to set SEEDED_CREATE_AND_RUN_TESTS in order to create/run tests.

#### Prerequisite installs

 - cmake >= 3.15.0
 - ninja

#### Windows
Open this directory in Visual Studio 2019 to automatically build and load tests into test explorer.


#### Compiling and running tests on unix/macos

```
cd read-keysqr
cmake -B build
cd build
make
ctest
```
#### Important note if using Visual Studio (Windows without WSL) with this project

Visual Studio unfortunatly defaults to overriding the working directory for Google Test set by CMAKE. If you don't fix this before running tests, they will fail due to being unable to find the test files.

 To fix this go to Visual Studio's debug menu or tool menu, choose the "options" item, and then go to the "Test Adapter For GoogleTest" tab.
Clear the "Working Directory" field to "${SolutionDir}" (quotes for provided here for dilineation, and should not be copied).

