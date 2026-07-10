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
CRYPTO/test_phpe_128.c
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

For PHPE, replace `shpe` with `phpe_128`.

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

---

# 5. FPSUServer_dimension_N

`FPSUServer_dimension_N.cpp` se compile exactement comme `FPSUServer.cpp`.

Il suffit simplement de remplacer `FPSUServer` par `FPSUServer_dimension_N` dans les commandes.

## Compile

```bash
clang++-16 FPSUServer_dimension_N.cpp \
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
    -o FPSUServer_dimension_N
```

## Run

```bash
./FPSUServer_dimension_N
```

---

## 6. SimplePIR Integration

This section explains how to integrate **SimplePIR** into the `volepsi` project through a Go/C++ bridge (`bridge.go`), then build and run the demo.

### 6.1 Clone SimplePIR

From the project directory:

```bash
cd volepsi
git clone https://github.com/ahenzinger/simplepir.git
cd simplepir
```

The SimplePIR repository exposes the Go package `pir`, which provides the primitives used in `bridge.go` [page:1].

### 6.2 Create `bridge.go`

Create the file:

```bash
nano bridge.go
```

Then paste the following content:

```go
package main

import "C"
import (
	"fmt"
	"sync"

	"github.com/ahenzinger/simplepir/pir"
)

type serverRuntime struct {
	id      int
	db      *pir.Database
	params  pir.Params
	shared  pir.State
	server  pir.State
	offline pir.Msg
	answer  pir.Msg
}

var (
	mu            sync.Mutex
	servers       = make(map[int]*serverRuntime)
	clientState   pir.State
	clientShared  pir.State
	clientQuery   pir.Msg
	queryParams   pir.Params
	queryIndex    uint64
	server1Answer pir.Msg
	server2Answer pir.Msg
	lastRecovered uint64
)

//export GlobalInitPIR
func GlobalInitPIR() {
	fmt.Println("[Go] SimplePIR initialized successfully.")
}

func makeDatabase(size uint64) (*pir.Database, pir.Params) {
	pi := &pir.SimplePIR{}
	params := pi.PickParams(size, 1, 4, 32)

	vals := make([]uint64, 0, size)
	for i := uint64(0); i < size; i++ {
		vals = append(vals, i+1)
	}

	db := pir.MakeDB(size, 1, &params, vals)
	return db, params
}

//export PIRServerSetup
func PIRServerSetup(serverId int, size uint64) {
	mu.Lock()
	defer mu.Unlock()

	if size == 0 {
		size = 8
	}

	db, params := makeDatabase(size)
	pi := &pir.SimplePIR{}
	shared := pi.Init(db.Info, params)
	serverState, offline := pi.Setup(db, shared, params)

	servers[serverId] = &serverRuntime{
		id:      serverId,
		db:      db,
		params:  params,
		shared:  shared,
		server:  serverState,
		offline: offline,
	}

	fmt.Printf("[Go] [Server %d] PIR database built: %d entries, params L=%d M=%d P=%d.\n",
		serverId, size, params.L, params.M, params.P)
}

//export PIRClientQuery
func PIRClientQuery(targetIndex int) {
	mu.Lock()
	defer mu.Unlock()

	s1, ok := servers[3]
	if !ok {
		fmt.Println("[Go] [Client] No initialized server available to generate the query.")
		return
	}

	pi := &pir.SimplePIR{}
	clientStateLocal, query := pi.Query(uint64(targetIndex), s1.shared, s1.params, s1.db.Info)
	clientState = clientStateLocal
	clientShared = s1.shared
	clientQuery = query
	queryParams = s1.params
	queryIndex = uint64(targetIndex)

	fmt.Printf("[Go] [Client] PIR query generated for index %d.\n", targetIndex)
}

//export PIRServerAnswer
func PIRServerAnswer(serverId int) {
	mu.Lock()
	defer mu.Unlock()

	s, ok := servers[serverId]
	if !ok {
		fmt.Printf("[Go] [Server %d] not initialized.\n", serverId)
		return
	}
	if len(clientQuery.Data) == 0 {
		fmt.Println("[Go] [Server] No client query available.")
		return
	}

	pi := &pir.SimplePIR{}
	querySlice := pir.MsgSlice{Data: []pir.Msg{clientQuery}}
	answer := pi.Answer(s.db, querySlice, s.server, s.shared, s.params)

	if serverId == 1 {
		server1Answer = answer
	} else if serverId == 2 {
		server2Answer = answer
	}

	fmt.Printf("[Go] [Server %d] PIR answer computed.\n", serverId)
}

//export PIRClientExtract
func PIRClientExtract() {
	mu.Lock()
	defer mu.Unlock()

	s1, ok := servers[3]
	if !ok {
		fmt.Println("[Go] [Client] Cannot reconstruct without server 1.")
		return
	}
	if len(server1Answer.Data) == 0 {
		fmt.Println("[Go] [Client] No server response available for reconstruction.")
		return
	}

	pi := &pir.SimplePIR{}
	recovered := pi.Recover(queryIndex, 0, s1.offline, clientQuery, server1Answer, clientShared, clientState, queryParams, s1.db.Info)
	lastRecovered = recovered

	fmt.Printf("[Go] [Client] Recovered value: %d.\n", recovered)
}

func main() {}
```

The code follows the public SimplePIR API exposed by the `pir` package [page:1].

### 6.3 Build SimplePIR as a shared library

Inside the `simplepir` directory:

```bash
go mod tidy
go build -buildmode=c-shared -o libsimplepir.so
```

This produces:

- `libsimplepir.so`
- `libsimplepir.h`

The Go toolchain supports `-buildmode=c-shared` to generate a C-compatible shared library with exported symbols [web:17][web:18].

### 6.4 Copy the generated files

Copy the generated artifacts to the project root or to the place expected by your build:

```bash
cp libsimplepir.so ..
cp libsimplepir.h ..
```

Or:

```bash
cd ..
cp simplepir/libsimplepir.so .
cp simplepir/libsimplepir.h .
```

### 6.5 Build `volepsi`

If `volepsi` is not built yet, compile it first:

```bash
cd volepsi
python3 build.py
```

The `volepsi` repository documents building the library and notes that the output library is produced under `out/build/<platform>/` or under the install prefix when using `--install` [web:3].

### 6.6 Compile `pir_demo`

Then compile and link the demo with `volePSI` and `SimplePIR`:

```bash
clang++-16 pir_demo.cpp -std=c++20 -maes -mpclmul -mavx2 \
  -I. -I./out/install/linux/include -I./volePSI -I$HOME/bicycl/src \
  -L./build/volePSI -L./out/install/linux/lib -o pir_demo \
  -Wl,--start-group -lvolePSI -llibOTe -lbitpolymul -lcoproto -lmacoro \
  -lcryptoTools -lsodium -lgmp -lgmpxx -lssl -lcrypto -lpthread \
  -Wl,--end-group -L. -lsimplepir
```

Then run:

```bash
./pir_demo
```

### 6.7 Notes on linking

If your linker cannot find `libsimplepir.so`, make sure the library path is visible at runtime, for example:

```bash
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$(pwd)
```

You can also place `libsimplepir.so` in a standard library directory or adjust the rpath during linking [web:17][web:18].

### 6.8 Compile `FPSUServer_PIR`

Then compile and link the demo with `volePSI` and `SimplePIR`:

```bash
clang++-16 FPSUServer_PIR.cpp -std=c++20 -maes -mpclmul -mavx2 -I. -I./out/install/linux/include -I./volePSI -I$HOME/bicycl/src -L./build/volePSI -L./out/install/linux/lib -o FPSUServer_PIR -Wl,--start-group -lvolePSI -llibOTe -lbitpolymul -lcoproto -lmacoro -lcryptoTools -Wl,--end-group -lsodium -lgmp -lgmpxx -lssl -lcrypto -lpthread -I. -L. -lsimplepir && ./FPSUServer_PIR
```

Then run:

```bash
./FPSUServer_PIR
```
### 6.9 Compile `FPSUServer_p`
Now we're using a function dedicated for the PIR:
sparsedecode

```bash
clang++-16 FPSUServer_p.cpp -std=c++20 -maes -mpclmul -mavx2 -I. -I./out/install/linux/include -I./volePSI -I$HOME/bicycl/src -L./build/volePSI -L./out/install/linux/lib -o FPSUServer_p -Wl,--start-group -lvolePSI -llibOTe -lbitpolymul -lcoproto -lmacoro -lcryptoTools -Wl,--end-group -lsodium -lgmp -lgmpxx -lssl -lcrypto -lpthread -I. -L. -lsimplepir && ./FPSUServer_p
```

Then run:

```bash
./FPSUServer_PIR
```
# Common Error

During development, you may encounter:

```text
clang: error: linker command failed with exit code 1
```

This is expected if BICYCL was previously rebuilt with modified testing CMake files or incompatible build options.

In that case, restore the original BICYCL configuration and perform a clean rebuild before compiling `FPSUServer_bicycl`.
