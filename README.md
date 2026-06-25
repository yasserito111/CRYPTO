# CRYPTO Experiments: VOLE-PSI, BICYCL and RELIC

This repository contains code and tests related to:

* Integration of BICYCL with VOLE-PSI.
* Experiments on CL HSMqk encryption.
* Experiments with RELIC's SHPE and PHPE implementations.

---

# 0. Clone this Repository

```bash
git clone https://github.com/yasserito111/CRYPTO.git
```

---

# 1. Configure and Build VOLE-PSI

## Clone VOLE-PSI

```bash
cd ..
git clone https://github.com/Visa-Research/volepsi.git
cd volepsi
```

## Build

```bash
python3 build.py -DVOLE_PSI_ENABLE_BOOST=ON
```

If the build fails, the most common cause is an outdated compiler.

Check your compiler version:

```bash
g++ --version
```

A recent compiler (GCC ≥ 13) is recommended.

Alternatively, install Clang 16:

```bash
sudo apt install clang-16
```

## Copy the Server Files

Move the following files from this repository into the root directory of `volepsi`:

```text
CRYPTO/FPSUServer.cpp
CRYPTO/FPSUServer_bicycl.cpp
```

Example:

```bash
cp CRYPTO/FPSUServer.cpp volepsi/
cp CRYPTO/FPSUServer_bicycl.cpp volepsi/
```

## Compile FPSUServer

```bash
clang++-16 FPSUServer.cpp \
    -std=c++20 \
    -maes -mpclmul -mavx2 \
    -I. \
    -I./out/install/linux/include \
    -I./volePSI \
    -L./build/volePSI \
    -L./out/install/linux/lib \
    -lvolePSI \
    -llibOTe \
    -lcryptoTools \
    -lcoproto \
    -lmacoro \
    -lbitpolymul \
    -lsodium \
    -lpthread \
    -o FPSUServer
```

Run:

```bash
./FPSUServer
```

---

# 2. BICYCL Setup and Testing

## Clone BICYCL

```bash
git clone https://gite.lirmm.fr/crypto/bicycl.git
```

## Add the Test File

Move:

```text
CRYPTO/test_CL_HSMqk_128.cpp
```

to:

```text
bicycl/tests/
```

Example:

```bash
cp CRYPTO/test_CL_HSMqk_128.cpp bicycl/tests/
```

---

## Modify `tests/CMakeLists.txt`

Add the following target infrastructure:

```cmake
include (CTest)

if ("${CMAKE_GENERATOR}" STREQUAL "Unix Makefiles")
  set (_cmd ${CMAKE_CTEST_COMMAND} --output-on-failure $(ARGS))
else ()
  set (_cmd ${CMAKE_CTEST_COMMAND} --output-on-failure)
endif ()

add_custom_target (check COMMAND ${_cmd} COMMENT "Running the tests")
add_custom_target(tests_build COMMAND ${CMAKE_COMMAND} -E sleep 0)

set (TESTS_LIST
                test_gmp_extras
                test_qfi
                test_CL_HSMqk
                test_CL_threshold
                test_Paillier
                test_Joye_Libert
                test_ec
                test_CL_HSMqk_128 #this line is added you can add your tests here 
                test_threshold_ECDSA
                test_twoPartyECDSA
                test_internals
)

foreach (test ${TESTS_LIST})
  add_executable (${test} ${test}.cpp)
  target_link_libraries (${test} PUBLIC bicycl)
  add_dependencies (tests_build ${test})
  add_dependencies (check ${test})
  add_test (NAME ${test} COMMAND ${test}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endforeach ()

add_custom_command(
  TARGET test_internals POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy
    "${CMAKE_CURRENT_SOURCE_DIR}/test_stddev.csv"
    "$<TARGET_FILE_DIR:test_internals>"
  DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/test_stddev.csv"
  BYPRODUCTS "test_stddev.csv"
)

add_subdirectory(kat)
```

---

## Build the Test

```bash
rm -rf build
cmake -S . -B build
cmake --build build --target test_CL_HSMqk_128 -j
```

Run:

```bash
./build/tests/test_CL_HSMqk_128
```

Once testing is complete, remove the added test entry from `TESTS_LIST` before rebuilding BICYCL for integration with VOLE-PSI.

---

# 3. RELIC Tests (Optional)

These tests are only needed for benchmarking and experimentation.

## Clone RELIC

```bash
git clone https://github.com/relic-toolkit/relic.git
```

Move:

```text
CRYPTO/test_shpe.c
CRYPTO/test_phpe.c
```

to:

```text
relic/demo/general-paillier/
```

---

## Compile SHPE

```bash
gcc -O3 \
    -I build/include \
    -I include \
    -L build/lib \
    -Wl,-rpath,$(pwd)/build/lib \
    -o demo/general-paillier/test_shpe \
    demo/general-paillier/test_shpe.c \
    -lrelic -lm
```

Run:

```bash
./demo/general-paillier/test_shpe
```

Alternatively:

```bash
export LD_LIBRARY_PATH=~/relic/build/lib:$LD_LIBRARY_PATH
./demo/general-paillier/test_shpe
```

For PHPE, replace `shpe` with `phpe`.

---

# 4. Building FPSUServer_bicycl

If you previously modified BICYCL's CMake files for testing, restore the original configuration before compiling the VOLE-PSI integration.

A clean rebuild is recommended:

```bash
rm -rf build
cmake -S . -B build
cmake --build build -j
```

If necessary, completely reinstall BICYCL:

```bash
rm -rf bicycl
git clone https://gite.lirmm.fr/crypto/bicycl.git
```

---

## Compile FPSUServer_bicycl

From the `volepsi` directory:

```bash
clang++-16 FPSUServer_bicycl.cpp \
    -std=c++20 \
    -maes -mpclmul -mavx2 \
    -I. \
    -I./out/install/linux/include \
    -I./volePSI \
    -I$HOME/bicycl/src \
    -L./build/volePSI \
    -L./out/install/linux/lib \
    -o FPSUServer_bicycl \
    -Wl,--start-group \
        -lvolePSI \
        -llibOTe \
        -lbitpolymul \
        -lcoproto \
        -lmacoro \
        -lcryptoTools \
    -Wl,--end-group \
    -lsodium \
    -lgmp \
    -lgmpxx \
    -lssl \
    -lcrypto \
    -lpthread
```

Run:

```bash
./FPSUServer_bicycl
```

---

# Common Error

During development, you may encounter:

```text
clang: error: linker command failed with exit code 1
```

This is expected if BICYCL was previously rebuilt with modified testing CMake files or incompatible build options.

In that case, restore the original BICYCL configuration and perform a clean rebuild before compiling `FPSUServer_bicycl`.
