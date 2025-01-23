Response: The user wants a summary of the functionality of the C++ source code file `v8/test/cctest/wasm/test-run-wasm.cc`.
They also want to know if the code is related to JavaScript and, if so, see an example in JavaScript.

The file name and the content indicate that this C++ file contains tests for the WebAssembly (Wasm) functionality in V8. It seems to define various Wasm modules and execute them to verify the correctness of the Wasm implementation.

Let's break down the code:
- **Includes:** Standard C++ headers and V8-specific headers for Wasm.
- **Macros:**  Shorthand for common Wasm instructions.
- **`WASM_EXEC_TEST`:**  A macro likely defining individual test cases. Each test seems to build a small Wasm module and then execute it, comparing the result with an expected value.
- **Test Naming:** Test names like `Int32Const`, `Int32Add`, `Float32Add`, etc., suggest they are testing specific Wasm instructions and their behavior.
- **`WasmRunner`:** A template class used to build and execute Wasm modules within the tests.
- **`WasmBuilder`:**  Likely used within `WasmRunner` to construct the bytecode of the Wasm module.
- **`CHECK_EQ`:** A macro for asserting equality, used to verify the test results.
- **`FOR_INT32_INPUTS`, `FOR_FLOAT32_INPUTS`, etc.:** Macros likely iterating over various input values to test the Wasm code with different scenarios.
- **Test Categories:**  The tests cover various aspects of Wasm, including:
    - Constants (`Int32Const`)
    - Parameters (`Int32Param`)
    - Arithmetic operations (`Int32Add`, `Float32Add`)
    - Control flow (`IfElse_P`, `Return12`, `BrTable`)
    - Memory access (`LoadMemI32`, `StoreMemI32`)
    - Conversions (`I32ReinterpretF32`)
    - Unary and binary operations
    - Select instruction

**Relationship with JavaScript:**

WebAssembly is designed to be a compilation target for languages like C, C++, and Rust, but it can be executed in JavaScript environments (browsers, Node.js). JavaScript provides APIs to load, compile, and instantiate Wasm modules. This C++ code is part of the V8 JavaScript engine, which includes the Wasm implementation. Therefore, this testing code directly relates to how JavaScript engines handle and execute Wasm.

**JavaScript Example:**

A simple example of how the `Int32Const` test might relate to JavaScript:

```javascript
async function runWasm() {
  const wasmBytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, // Magic number (\0asm)
    0x01, 0x00, 0x00, 0x00, // Version 1
    0x01, 0x07,             // Type section (1 entry)
    0x01,                   // Number of type entries
    0x60, 0x00, 0x01, 0x7f, // Function type: [] -> [i32]
    0x03, 0x02,             // Function section (1 entry)
    0x01, 0x00,             // Function 0 signature index (type 0)
    0x0a, 0x06,             // Code section (1 entry, 6 bytes)
    0x01,                   // Number of function bodies
    0x04,                   // Body size
    0x41, 0x44, 0x33, 0x22, 0x11, // i32.const 0x11223344
    0x0f                   // return
  ]);

  const wasmModule = await WebAssembly.compile(wasmBytes);
  const wasmInstance = await WebAssembly.instantiate(wasmModule);
  const result = wasmInstance.exports.wasm_function_0();
  console.log(result); // Output: 287454020 (0x11223344 in decimal)
}

runWasm();
```

This JavaScript code defines a simple Wasm module that returns the constant integer `0x11223344`. The C++ test `Int32Const` verifies that the V8 engine correctly executes this kind of Wasm code.

This C++ source code file, `test-run-wasm.cc`, is part of the V8 JavaScript engine's testing framework, specifically for testing WebAssembly (Wasm) functionality. Its primary function is to **define and execute a wide range of small, isolated WebAssembly modules to verify the correctness of the V8's Wasm implementation**.

Here's a breakdown of its functionality:

* **Defines numerous test cases:** Each `WASM_EXEC_TEST` macro represents an individual test. These tests cover various aspects of the Wasm specification.
* **Tests individual Wasm instructions:** The test names (e.g., `Int32Const`, `Int32Add`, `Float32Add`, `IfElse_P`, `BrTable`) and the code within them directly correspond to specific Wasm instructions and their expected behavior.
* **Uses `WasmRunner` to build and execute Wasm:** The `WasmRunner` class is a utility for constructing and running Wasm modules within the test environment. It simplifies the process of creating a Wasm module from a sequence of opcodes.
* **Verifies expected outputs:** Each test executes the built Wasm module and uses `CHECK_EQ` (or similar macros) to assert that the actual output matches the expected output. This confirms that the V8 engine is executing the Wasm instructions correctly.
* **Covers different data types:** The tests include operations on various Wasm data types like `i32` (int32), `f32` (float32), `f64` (float64), and more.
* **Tests control flow instructions:** Tests like `IfElse_P`, `Return12`, `BrTable`, `Loop_empty` verify the implementation of Wasm's control flow mechanisms.
* **Tests memory operations:** Tests like `LoadMemI32`, `StoreMemI32` ensure that memory access instructions are working as expected, including handling of alignment and out-of-bounds access.
* **Includes edge cases and boundary conditions:** The tests use macros like `FOR_INT32_INPUTS` to iterate through various input values, including edge cases like minimum and maximum integer values, to ensure robustness.
* **Tests for traps:**  Certain Wasm operations can result in traps (runtime errors). Tests like `Int32DivS_trap` specifically check if these traps are triggered correctly under expected conditions (e.g., division by zero).

**Relationship with JavaScript and a JavaScript Example:**

Yes, this C++ code is intrinsically related to JavaScript. WebAssembly is designed to run within JavaScript environments (browsers, Node.js). The V8 engine, which powers Chrome and Node.js, includes an implementation of a Wasm virtual machine. This C++ file is part of V8's test suite, ensuring that V8's Wasm implementation adheres to the Wasm specification.

Here's how a simple test like `Int32Const` relates to JavaScript:

The `Int32Const` test in the C++ code does the following conceptually:

1. **Builds a Wasm module** that simply returns the integer constant `0x11223344`.
2. **Executes this Wasm module** within the V8 engine.
3. **Checks if the returned value** is indeed `0x11223344`.

Here's an equivalent example of how you might run a similar Wasm module in JavaScript:

```javascript
async function runWasm() {
  // This represents the bytecode for a simple Wasm module that returns the i32 constant 0x11223344
  const wasmBytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x07, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03, 0x02, 0x01, 0x00, 0x0a, 0x06, 0x01, 0x04, 0x41, 0x44, 0x33, 0x22, 0x11, 0x0f
  ]);

  // Compile the Wasm bytecode
  const wasmModule = await WebAssembly.compile(wasmBytes);

  // Instantiate the Wasm module
  const wasmInstance = await WebAssembly.instantiate(wasmModule);

  // Assuming the Wasm module has an exported function named 'wasm_function_0'
  const result = wasmInstance.exports.wasm_function_0();

  console.log(result); // Output: 287454020 (which is the decimal representation of 0x11223344)
}

runWasm();
```

In this JavaScript example:

* We have a `Uint8Array` representing the raw bytes of a WebAssembly module.
* `WebAssembly.compile` compiles these bytes into a `WebAssembly.Module`.
* `WebAssembly.instantiate` creates an instance of the module, providing access to its exports.
* We then call an exported function (`wasm_function_0` in this example, though the C++ test doesn't explicitly name the function) and get the result.

The C++ test in `test-run-wasm.cc` ensures that when JavaScript uses the `WebAssembly` API to load and execute such a module, the V8 engine does it correctly, returning the expected constant value.

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "src/base/overflowing-math.h"
#include "src/utils/utils.h"
#include "src/wasm/code-space-access.h"
#include "src/wasm/compilation-environment-inl.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "test/cctest/cctest.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/test-signatures.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8::internal::wasm {

// for even shorter tests.
#define B1(a) WASM_BLOCK(a)
#define B2(a, b) WASM_BLOCK(a, b)
#define RET(x) x, kExprReturn
#define RET_I8(x) WASM_I32V_2(x), kExprReturn

WASM_EXEC_TEST(Int32Const) {
  WasmRunner<int32_t> r(execution_tier);
  const int32_t kExpectedValue = 0x11223344;
  // return(kExpectedValue)
  r.Build({WASM_I32V_5(kExpectedValue)});
  CHECK_EQ(kExpectedValue, r.Call());
}

WASM_EXEC_TEST(Int32Const_many) {
  FOR_INT32_INPUTS(i) {
    WasmRunner<int32_t> r(execution_tier);
    const int32_t kExpectedValue = i;
    // return(kExpectedValue)
    r.Build({WASM_I32V(kExpectedValue)});
    CHECK_EQ(kExpectedValue, r.Call());
  }
}

WASM_EXEC_TEST(GraphTrimming) {
  // This WebAssembly code requires graph trimming in the TurboFan compiler.
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({kExprLocalGet, 0, kExprLocalGet, 0, kExprLocalGet, 0, kExprI32RemS,
           kExprI32Eq, kExprLocalGet, 0, kExprI32DivS, kExprUnreachable});
  r.Call(1);
}

WASM_EXEC_TEST(Int32Param0) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // return(local[0])
  r.Build({WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Int32Param0_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // local[0]
  r.Build({WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Int32Param1) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // local[1]
  r.Build({WASM_LOCAL_GET(1)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(-111, i)); }
}

WASM_EXEC_TEST(Int32Add) {
  WasmRunner<int32_t> r(execution_tier);
  // 11 + 44
  r.Build({WASM_I32_ADD(WASM_I32V_1(11), WASM_I32V_1(44))});
  CHECK_EQ(55, r.Call());
}

WASM_EXEC_TEST(Int32Add_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 + 13
  r.Build({WASM_I32_ADD(WASM_I32V_1(13), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(base::AddWithWraparound(i, 13), r.Call(i)); }
}

WASM_EXEC_TEST(Int32Add_P_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 + 13
  r.Build({WASM_I32_ADD(WASM_I32V_1(13), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(base::AddWithWraparound(i, 13), r.Call(i)); }
}

static void RunInt32AddTest(TestExecutionTier execution_tier,
                            const uint8_t* code, size_t size) {
  TestSignatures sigs;
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.builder().AddSignature(sigs.ii_v());
  r.builder().AddSignature(sigs.iii_v());
  r.Build(base::VectorOf(code, size));
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      int32_t expected = static_cast<int32_t>(static_cast<uint32_t>(i) +
                                              static_cast<uint32_t>(j));
      CHECK_EQ(expected, r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(Int32Add_P2) {
  static const uint8_t code[] = {
      WASM_I32_ADD(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_block1) {
  static const uint8_t code[] = {
      WASM_BLOCK_X(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)), kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_block2) {
  static const uint8_t code[] = {
      WASM_BLOCK_X(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), kExprBr, DEPTH_0),
      kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Int32Add_multi_if) {
  static const uint8_t code[] = {
      WASM_IF_ELSE_X(1, WASM_LOCAL_GET(0),
                     WASM_SEQ(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)),
                     WASM_SEQ(WASM_LOCAL_GET(1), WASM_LOCAL_GET(0))),
      kExprI32Add};
  RunInt32AddTest(execution_tier, code, sizeof(code));
}

WASM_EXEC_TEST(Float32Add) {
  WasmRunner<int32_t> r(execution_tier);
  // int(11.5f + 44.5f)
  r.Build(
      {WASM_I32_SCONVERT_F32(WASM_F32_ADD(WASM_F32(11.5f), WASM_F32(44.5f)))});
  CHECK_EQ(56, r.Call());
}

WASM_EXEC_TEST(Float64Add) {
  WasmRunner<int32_t> r(execution_tier);
  // return int(13.5d + 43.5d)
  r.Build(
      {WASM_I32_SCONVERT_F64(WASM_F64_ADD(WASM_F64(13.5), WASM_F64(43.5)))});
  CHECK_EQ(57, r.Call());
}

// clang-format messes up the FOR_INT32_INPUTS macros.
// clang-format off
template<typename ctype>
static void TestInt32Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                           ctype(*expected)(ctype, ctype)) {
  FOR_INT32_INPUTS(i) {
    FOR_INT32_INPUTS(j) {
      WasmRunner<ctype> r(execution_tier);
      // Apply {opcode} on two constants.
      r.Build({WASM_BINOP(opcode, WASM_I32V(i), WASM_I32V(j))});
      CHECK_EQ(expected(i, j), r.Call());
    }
  }
  {
    WasmRunner<ctype, ctype, ctype> r(execution_tier);
    // Apply {opcode} on two parameters.
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    FOR_INT32_INPUTS(i) {
      FOR_INT32_INPUTS(j) {
        CHECK_EQ(expected(i, j), r.Call(i, j));
      }
    }
  }
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter.
    r.Build({WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0))});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(expected(i, j), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant.
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j))});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(expected(i, j), r.Call(i));
    }
  }
  auto to_bool = [](ctype value) -> ctype {
    return value == static_cast<ctype>(0xDEADBEEF) ? value : !!value;
  };
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter, followed by {if}.
    r.Build({WASM_IF(WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0)),
                     WASM_RETURN(WASM_ONE)),
             WASM_ZERO});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant, followed by {if}.
    r.Build({WASM_IF(WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j)),
                     WASM_RETURN(WASM_ONE)),
             WASM_ZERO});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(i));
    }
  }
  FOR_INT32_INPUTS(i) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on constant and parameter, followed by {br_if}.
    r.Build({WASM_BR_IFD(0, WASM_ONE,
                         WASM_BINOP(opcode, WASM_I32V(i), WASM_LOCAL_GET(0))),
             WASM_ZERO});
    FOR_INT32_INPUTS(j) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(j));
    }
  }
  FOR_INT32_INPUTS(j) {
    WasmRunner<ctype, ctype> r(execution_tier);
    // Apply {opcode} on parameter and constant, followed by {br_if}.
    r.Build({WASM_BR_IFD(0, WASM_ONE,
                         WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_I32V(j))),
             WASM_ZERO});
    FOR_INT32_INPUTS(i) {
      CHECK_EQ(to_bool(expected(i, j)), r.Call(i));
    }
  }
}
// clang-format on

#define WASM_I32_BINOP_TEST(expr, ctype, expected)                             \
  WASM_EXEC_TEST(I32Binop_##expr) {                                            \
    TestInt32Binop<ctype>(execution_tier, kExprI32##expr,                      \
                          [](ctype a, ctype b) -> ctype { return expected; }); \
  }

WASM_I32_BINOP_TEST(Add, int32_t, base::AddWithWraparound(a, b))
WASM_I32_BINOP_TEST(Sub, int32_t, base::SubWithWraparound(a, b))
WASM_I32_BINOP_TEST(Mul, int32_t, base::MulWithWraparound(a, b))
WASM_I32_BINOP_TEST(DivS, int32_t,
                    (a == kMinInt && b == -1) || b == 0
                        ? static_cast<int32_t>(0xDEADBEEF)
                        : a / b)
WASM_I32_BINOP_TEST(DivU, uint32_t, b == 0 ? 0xDEADBEEF : a / b)
WASM_I32_BINOP_TEST(RemS, int32_t, b == 0 ? 0xDEADBEEF : b == -1 ? 0 : a % b)
WASM_I32_BINOP_TEST(RemU, uint32_t, b == 0 ? 0xDEADBEEF : a % b)
WASM_I32_BINOP_TEST(And, int32_t, a& b)
WASM_I32_BINOP_TEST(Ior, int32_t, a | b)
WASM_I32_BINOP_TEST(Xor, int32_t, a ^ b)
WASM_I32_BINOP_TEST(Shl, int32_t, base::ShlWithWraparound(a, b))
WASM_I32_BINOP_TEST(ShrU, uint32_t, a >> (b & 0x1F))
WASM_I32_BINOP_TEST(ShrS, int32_t, a >> (b & 0x1F))
WASM_I32_BINOP_TEST(Ror, uint32_t, (a >> (b & 0x1F)) | (a << ((32 - b) & 0x1F)))
WASM_I32_BINOP_TEST(Rol, uint32_t, (a << (b & 0x1F)) | (a >> ((32 - b) & 0x1F)))
WASM_I32_BINOP_TEST(Eq, int32_t, a == b)
WASM_I32_BINOP_TEST(Ne, int32_t, a != b)
WASM_I32_BINOP_TEST(LtS, int32_t, a < b)
WASM_I32_BINOP_TEST(LeS, int32_t, a <= b)
WASM_I32_BINOP_TEST(LtU, uint32_t, a < b)
WASM_I32_BINOP_TEST(LeU, uint32_t, a <= b)
WASM_I32_BINOP_TEST(GtS, int32_t, a > b)
WASM_I32_BINOP_TEST(GeS, int32_t, a >= b)
WASM_I32_BINOP_TEST(GtU, uint32_t, a > b)
WASM_I32_BINOP_TEST(GeU, uint32_t, a >= b)

#undef WASM_I32_BINOP_TEST

void TestInt32Unop(TestExecutionTier execution_tier, WasmOpcode opcode,
                   int32_t expected, int32_t a) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return op K
    r.Build({WASM_UNOP(opcode, WASM_I32V(a))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    // return op a
    r.Build({WASM_UNOP(opcode, WASM_LOCAL_GET(0))});
    CHECK_EQ(expected, r.Call(a));
  }
}

WASM_EXEC_TEST(Int32Clz) {
  TestInt32Unop(execution_tier, kExprI32Clz, 0, 0x80001000);
  TestInt32Unop(execution_tier, kExprI32Clz, 1, 0x40000500);
  TestInt32Unop(execution_tier, kExprI32Clz, 2, 0x20000300);
  TestInt32Unop(execution_tier, kExprI32Clz, 3, 0x10000003);
  TestInt32Unop(execution_tier, kExprI32Clz, 4, 0x08050000);
  TestInt32Unop(execution_tier, kExprI32Clz, 5, 0x04006000);
  TestInt32Unop(execution_tier, kExprI32Clz, 6, 0x02000000);
  TestInt32Unop(execution_tier, kExprI32Clz, 7, 0x010000A0);
  TestInt32Unop(execution_tier, kExprI32Clz, 8, 0x00800C00);
  TestInt32Unop(execution_tier, kExprI32Clz, 9, 0x00400000);
  TestInt32Unop(execution_tier, kExprI32Clz, 10, 0x0020000D);
  TestInt32Unop(execution_tier, kExprI32Clz, 11, 0x00100F00);
  TestInt32Unop(execution_tier, kExprI32Clz, 12, 0x00080000);
  TestInt32Unop(execution_tier, kExprI32Clz, 13, 0x00041000);
  TestInt32Unop(execution_tier, kExprI32Clz, 14, 0x00020020);
  TestInt32Unop(execution_tier, kExprI32Clz, 15, 0x00010300);
  TestInt32Unop(execution_tier, kExprI32Clz, 16, 0x00008040);
  TestInt32Unop(execution_tier, kExprI32Clz, 17, 0x00004005);
  TestInt32Unop(execution_tier, kExprI32Clz, 18, 0x00002050);
  TestInt32Unop(execution_tier, kExprI32Clz, 19, 0x00001700);
  TestInt32Unop(execution_tier, kExprI32Clz, 20, 0x00000870);
  TestInt32Unop(execution_tier, kExprI32Clz, 21, 0x00000405);
  TestInt32Unop(execution_tier, kExprI32Clz, 22, 0x00000203);
  TestInt32Unop(execution_tier, kExprI32Clz, 23, 0x00000101);
  TestInt32Unop(execution_tier, kExprI32Clz, 24, 0x00000089);
  TestInt32Unop(execution_tier, kExprI32Clz, 25, 0x00000041);
  TestInt32Unop(execution_tier, kExprI32Clz, 26, 0x00000022);
  TestInt32Unop(execution_tier, kExprI32Clz, 27, 0x00000013);
  TestInt32Unop(execution_tier, kExprI32Clz, 28, 0x00000008);
  TestInt32Unop(execution_tier, kExprI32Clz, 29, 0x00000004);
  TestInt32Unop(execution_tier, kExprI32Clz, 30, 0x00000002);
  TestInt32Unop(execution_tier, kExprI32Clz, 31, 0x00000001);
  TestInt32Unop(execution_tier, kExprI32Clz, 32, 0x00000000);
}

WASM_EXEC_TEST(Int32Ctz) {
  TestInt32Unop(execution_tier, kExprI32Ctz, 32, 0x00000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 31, 0x80000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 30, 0x40000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 29, 0x20000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 28, 0x10000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 27, 0xA8000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 26, 0xF4000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 25, 0x62000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 24, 0x91000000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 23, 0xCD800000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 22, 0x09400000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 21, 0xAF200000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 20, 0xAC100000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 19, 0xE0B80000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 18, 0x9CE40000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 17, 0xC7920000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 16, 0xB8F10000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 15, 0x3B9F8000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 14, 0xDB4C4000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 13, 0xE9A32000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 12, 0xFCA61000);
  TestInt32Unop(execution_tier, kExprI32Ctz, 11, 0x6C8A7800);
  TestInt32Unop(execution_tier, kExprI32Ctz, 10, 0x8CE5A400);
  TestInt32Unop(execution_tier, kExprI32Ctz, 9, 0xCB7D0200);
  TestInt32Unop(execution_tier, kExprI32Ctz, 8, 0xCB4DC100);
  TestInt32Unop(execution_tier, kExprI32Ctz, 7, 0xDFBEC580);
  TestInt32Unop(execution_tier, kExprI32Ctz, 6, 0x27A9DB40);
  TestInt32Unop(execution_tier, kExprI32Ctz, 5, 0xDE3BCB20);
  TestInt32Unop(execution_tier, kExprI32Ctz, 4, 0xD7E8A610);
  TestInt32Unop(execution_tier, kExprI32Ctz, 3, 0x9AFDBC88);
  TestInt32Unop(execution_tier, kExprI32Ctz, 2, 0x9AFDBC84);
  TestInt32Unop(execution_tier, kExprI32Ctz, 1, 0x9AFDBC82);
  TestInt32Unop(execution_tier, kExprI32Ctz, 0, 0x9AFDBC81);
}

WASM_EXEC_TEST(Int32Popcnt) {
  TestInt32Unop(execution_tier, kExprI32Popcnt, 32, 0xFFFFFFFF);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 0, 0x00000000);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 1, 0x00008000);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 13, 0x12345678);
  TestInt32Unop(execution_tier, kExprI32Popcnt, 19, 0xFEDCBA09);
}

WASM_EXEC_TEST(I32Eqz) {
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, 1);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, -1);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, -827343);
  TestInt32Unop(execution_tier, kExprI32Eqz, 0, 8888888);
  TestInt32Unop(execution_tier, kExprI32Eqz, 1, 0);
}


WASM_EXEC_TEST(Int32DivS_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, -1));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32RemS_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_REMS(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(33, r.Call(133, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32DivU_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_DIVU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_EQ(0, r.Call(kMin, -1));
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
}

WASM_EXEC_TEST(Int32RemU_trap) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_I32_REMU(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
  CHECK_EQ(17, r.Call(217, 100));
  const int32_t kMin = std::numeric_limits<int32_t>::min();
  CHECK_TRAP(r.Call(100, 0));
  CHECK_TRAP(r.Call(-1001, 0));
  CHECK_TRAP(r.Call(kMin, 0));
  CHECK_EQ(kMin, r.Call(kMin, -1));
}

WASM_EXEC_TEST(Int32DivS_byzero_const) {
  for (int8_t denom = -2; denom < 8; ++denom) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    r.Build({WASM_I32_DIVS(WASM_LOCAL_GET(0), WASM_I32V_1(denom))});
    for (int32_t val = -7; val < 8; ++val) {
      if (denom == 0) {
        CHECK_TRAP(r.Call(val));
      } else {
        CHECK_EQ(val / denom, r.Call(val));
      }
    }
  }
}

WASM_EXEC_TEST(Int32DivU_byzero_const) {
  for (uint32_t denom = 0xFFFFFFFE; denom < 8; ++denom) {
    WasmRunner<uint32_t, uint32_t> r(execution_tier);
    r.Build({WASM_I32_DIVU(WASM_LOCAL_GET(0), WASM_I32V_1(denom))});

    for (uint32_t val = 0xFFFFFFF0; val < 8; ++val) {
      if (denom == 0) {
        CHECK_TRAP(r.Call(val));
      } else {
        CHECK_EQ(val / denom, r.Call(val));
      }
    }
  }
}

WASM_EXEC_TEST(Int32DivS_trap_effect) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);

  r.Build({WASM_IF_ELSE_I(
      WASM_LOCAL_GET(0),
      WASM_I32_DIVS(WASM_BLOCK_I(WASM_STORE_MEM(MachineType::Int8(), WASM_ZERO,
                                                WASM_LOCAL_GET(0)),
                                 WASM_LOCAL_GET(0)),
                    WASM_LOCAL_GET(1)),
      WASM_I32_DIVS(WASM_BLOCK_I(WASM_STORE_MEM(MachineType::Int8(), WASM_ZERO,
                                                WASM_LOCAL_GET(0)),
                                 WASM_LOCAL_GET(0)),
                    WASM_LOCAL_GET(1)))});
  CHECK_EQ(0, r.Call(0, 100));
  CHECK_TRAP(r.Call(8, 0));
  CHECK_TRAP(r.Call(4, 0));
  CHECK_TRAP(r.Call(0, 0));
}

void TestFloat32Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                      int32_t expected, float a, float b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return K op K
    r.Build({WASM_BINOP(opcode, WASM_F32(a), WASM_F32(b))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, float, float> r(execution_tier);
    // return a op b
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat32BinopWithConvert(TestExecutionTier execution_tier,
                                 WasmOpcode opcode, int32_t expected, float a,
                                 float b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(K op K)
    r.Build(
        {WASM_I32_SCONVERT_F32(WASM_BINOP(opcode, WASM_F32(a), WASM_F32(b)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, float, float> r(execution_tier);
    // return int(a op b)
    r.Build({WASM_I32_SCONVERT_F32(
        WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat32UnopWithConvert(TestExecutionTier execution_tier,
                                WasmOpcode opcode, int32_t expected, float a) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(op(K))
    r.Build({WASM_I32_SCONVERT_F32(WASM_UNOP(opcode, WASM_F32(a)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, float> r(execution_tier);
    // return int(op(a))
    r.Build({WASM_I32_SCONVERT_F32(WASM_UNOP(opcode, WASM_LOCAL_GET(0)))});
    CHECK_EQ(expected, r.Call(a));
  }
}

void TestFloat64Binop(TestExecutionTier execution_tier, WasmOpcode opcode,
                      int32_t expected, double a, double b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return K op K
    r.Build({WASM_BINOP(opcode, WASM_F64(a), WASM_F64(b))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, double, double> r(execution_tier);
    // return a op b
    r.Build({WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat64BinopWithConvert(TestExecutionTier execution_tier,
                                 WasmOpcode opcode, int32_t expected, double a,
                                 double b) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(K op K)
    r.Build(
        {WASM_I32_SCONVERT_F64(WASM_BINOP(opcode, WASM_F64(a), WASM_F64(b)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, double, double> r(execution_tier);
    r.Build({WASM_I32_SCONVERT_F64(
        WASM_BINOP(opcode, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
    CHECK_EQ(expected, r.Call(a, b));
  }
}

void TestFloat64UnopWithConvert(TestExecutionTier execution_tier,
                                WasmOpcode opcode, int32_t expected, double a) {
  {
    WasmRunner<int32_t> r(execution_tier);
    // return int(op(K))
    r.Build({WASM_I32_SCONVERT_F64(WASM_UNOP(opcode, WASM_F64(a)))});
    CHECK_EQ(expected, r.Call());
  }
  {
    WasmRunner<int32_t, double> r(execution_tier);
    // return int(op(a))
    r.Build({WASM_I32_SCONVERT_F64(WASM_UNOP(opcode, WASM_LOCAL_GET(0)))});
    CHECK_EQ(expected, r.Call(a));
  }
}

WASM_EXEC_TEST(Float32Binops) {
  TestFloat32Binop(execution_tier, kExprF32Eq, 1, 8.125f, 8.125f);
  TestFloat32Binop(execution_tier, kExprF32Ne, 1, 8.125f, 8.127f);
  TestFloat32Binop(execution_tier, kExprF32Lt, 1, -9.5f, -9.0f);
  TestFloat32Binop(execution_tier, kExprF32Le, 1, -1111.0f, -1111.0f);
  TestFloat32Binop(execution_tier, kExprF32Gt, 1, -9.0f, -9.5f);
  TestFloat32Binop(execution_tier, kExprF32Ge, 1, -1111.0f, -1111.0f);

  TestFloat32BinopWithConvert(execution_tier, kExprF32Add, 10, 3.5f, 6.5f);
  TestFloat32BinopWithConvert(execution_tier, kExprF32Sub, 2, 44.5f, 42.5f);
  TestFloat32BinopWithConvert(execution_tier, kExprF32Mul, -66, -132.1f, 0.5f);
  TestFloat32BinopWithConvert(execution_tier, kExprF32Div, 11, 22.1f, 2.0f);
}

WASM_EXEC_TEST(Float32Unops) {
  TestFloat32UnopWithConvert(execution_tier, kExprF32Abs, 8, 8.125f);
  TestFloat32UnopWithConvert(execution_tier, kExprF32Abs, 9, -9.125f);
  TestFloat32UnopWithConvert(execution_tier, kExprF32Neg, -213, 213.125f);
  TestFloat32UnopWithConvert(execution_tier, kExprF32Sqrt, 12, 144.4f);
}

WASM_EXEC_TEST(Float64Binops) {
  TestFloat64Binop(execution_tier, kExprF64Eq, 1, 16.25, 16.25);
  TestFloat64Binop(execution_tier, kExprF64Ne, 1, 16.25, 16.15);
  TestFloat64Binop(execution_tier, kExprF64Lt, 1, -32.4, 11.7);
  TestFloat64Binop(execution_tier, kExprF64Le, 1, -88.9, -88.9);
  TestFloat64Binop(execution_tier, kExprF64Gt, 1, 11.7, -32.4);
  TestFloat64Binop(execution_tier, kExprF64Ge, 1, -88.9, -88.9);

  TestFloat64BinopWithConvert(execution_tier, kExprF64Add, 100, 43.5, 56.5);
  TestFloat64BinopWithConvert(execution_tier, kExprF64Sub, 200, 12200.1,
                              12000.1);
  TestFloat64BinopWithConvert(execution_tier, kExprF64Mul, -33, 134, -0.25);
  TestFloat64BinopWithConvert(execution_tier, kExprF64Div, -1111, -2222.3, 2);
}

WASM_EXEC_TEST(Float64Unops) {
  TestFloat64UnopWithConvert(execution_tier, kExprF64Abs, 108, 108.125);
  TestFloat64UnopWithConvert(execution_tier, kExprF64Abs, 209, -209.125);
  TestFloat64UnopWithConvert(execution_tier, kExprF64Neg, -209, 209.125);
  TestFloat64UnopWithConvert(execution_tier, kExprF64Sqrt, 13, 169.4);
}

WASM_EXEC_TEST(Float32Neg) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_F32_NEG(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    CHECK_EQ(0x80000000,
             base::bit_cast<uint32_t>(i) ^ base::bit_cast<uint32_t>(r.Call(i)));
  }
}

WASM_EXEC_TEST(Float64Neg) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_F64_NEG(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    CHECK_EQ(0x8000000000000000,
             base::bit_cast<uint64_t>(i) ^ base::bit_cast<uint64_t>(r.Call(i)));
  }
}

WASM_EXEC_TEST(IfElse_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // if (p0) return 11; else return 22;
  r.Build({WASM_IF_ELSE_I(WASM_LOCAL_GET(0),   // --
                          WASM_I32V_1(11),     // --
                          WASM_I32V_1(22))});  // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(If_empty1) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, kExprEnd, WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 9, i)); }
}

WASM_EXEC_TEST(IfElse_empty1) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, kExprElse, kExprEnd,
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 8, i)); }
}

WASM_EXEC_TEST(IfElse_empty2) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, WASM_NOP, kExprElse, kExprEnd,
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 7, i)); }
}

WASM_EXEC_TEST(IfElse_empty3) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOCAL_GET(0), kExprIf, kVoidCode, kExprElse, WASM_NOP, kExprEnd,
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i - 6, i)); }
}

WASM_EXEC_TEST(If_chain1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // if (p0) 13; if (p0) 14; 15
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_NOP),
           WASM_IF(WASM_LOCAL_GET(0), WASM_NOP), WASM_I32V_1(15)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(15, r.Call(i)); }
}

WASM_EXEC_TEST(If_chain_set) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // if (p0) p1 = 73; if (p0) p1 = 74; p1
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_LOCAL_SET(1, WASM_I32V_2(73))),
           WASM_IF(WASM_LOCAL_GET(0), WASM_LOCAL_SET(1, WASM_I32V_2(74))),
           WASM_LOCAL_GET(1)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 74 : i;
    CHECK_EQ(expected, r.Call(i, i));
  }
}

WASM_EXEC_TEST(IfElse_Unreachable1) {
  WasmRunner<int32_t> r(execution_tier);
  // 0 ? unreachable : 27
  r.Build({WASM_IF_ELSE_I(WASM_ZERO,           // --
                          WASM_UNREACHABLE,    // --
                          WASM_I32V_1(27))});  // --
  CHECK_EQ(27, r.Call());
}

WASM_EXEC_TEST(IfElse_Unreachable2) {
  WasmRunner<int32_t> r(execution_tier);
  // 1 ? 28 : unreachable
  r.Build({WASM_IF_ELSE_I(WASM_I32V_1(1),       // --
                          WASM_I32V_1(28),      // --
                          WASM_UNREACHABLE)});  // --
  CHECK_EQ(28, r.Call());
}

WASM_EXEC_TEST(Return12) {
  WasmRunner<int32_t> r(execution_tier);

  r.Build({RET_I8(12)});
  CHECK_EQ(12, r.Call());
}

WASM_EXEC_TEST(Return17) {
  WasmRunner<int32_t> r(execution_tier);

  r.Build({WASM_BLOCK(RET_I8(17)), WASM_ZERO});
  CHECK_EQ(17, r.Call());
}

WASM_EXEC_TEST(Return_I32) {
  WasmRunner<int32_t, int32_t> r(execution_tier);

  r.Build({RET(WASM_LOCAL_GET(0))});

  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Return_F32) {
  WasmRunner<float, float> r(execution_tier);

  r.Build({RET(WASM_LOCAL_GET(0))});

  FOR_FLOAT32_INPUTS(i) {
    float expect = i;
    float result = r.Call(expect);
    if (std::isnan(expect)) {
      CHECK(std::isnan(result));
    } else {
      CHECK_EQ(expect, result);
    }
  }
}

WASM_EXEC_TEST(Return_F64) {
  WasmRunner<double, double> r(execution_tier);

  r.Build({RET(WASM_LOCAL_GET(0))});

  FOR_FLOAT64_INPUTS(i) {
    double expect = i;
    double result = r.Call(expect);
    if (std::isnan(expect)) {
      CHECK(std::isnan(result));
    } else {
      CHECK_EQ(expect, result);
    }
  }
}

WASM_EXEC_TEST(Select_float_parameters) {
  WasmRunner<float, float, float, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
}

WASM_EXEC_TEST(Select_s128_parameters) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* g0 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* g1 = r.builder().AddGlobal<int32_t>(kWasmS128);
  int32_t* output = r.builder().AddGlobal<int32_t>(kWasmS128);
  // select(v128(0, 1, 2, 3), v128(4, 5, 6, 7), 1) == v128(0, 1, 2, 3)
  for (int i = 0; i < 4; i++) {
    LANE(g0, i) = i;
    LANE(g1, i) = i + 4;
  }
  r.Build(
      {WASM_GLOBAL_SET(2, WASM_SELECT(WASM_GLOBAL_GET(0), WASM_GLOBAL_GET(1),
                                      WASM_LOCAL_GET(0))),
       WASM_ONE});
  r.Call(1);
  for (int i = 0; i < 4; i++) {
    CHECK_EQ(i, LANE(output, i));
  }
}

WASM_EXEC_TEST(SelectWithType_float_parameters) {
  WasmRunner<float, float, float, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT_F(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
  CHECK_FLOAT_EQ(1.0f, r.Call(2.0f, 1.0f, 0));
}

WASM_EXEC_TEST(Select_double_parameters) {
  WasmRunner<double, double, double, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
  CHECK_FLOAT_EQ(1.0f, r.Call(2.0f, 1.0f, 0));
}

WASM_EXEC_TEST(SelectWithType_double_parameters) {
  WasmRunner<double, double, double, int32_t> r(execution_tier);
  r.Build(
      {WASM_SELECT_D(WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), WASM_LOCAL_GET(2))});
  CHECK_FLOAT_EQ(2.0f, r.Call(2.0f, 1.0f, 1));
  CHECK_FLOAT_EQ(1.0f, r.Call(2.0f, 1.0f, 0));
}

WASM_EXEC_TEST(Select) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT(WASM_I32V_1(11), WASM_I32V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(SelectWithType) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT_I(WASM_I32V_1(11), WASM_I32V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select_strict1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // select(a=0, a=1, a=2); return a
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(0, WASM_ZERO),
                       WASM_LOCAL_TEE(0, WASM_I32V_1(1)),
                       WASM_LOCAL_TEE(0, WASM_I32V_1(2))),
           WASM_DROP, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(2, r.Call(i)); }
}

WASM_EXEC_TEST(SelectWithType_strict1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // select(a=0, a=1, a=2); return a
  r.Build({WASM_SELECT_I(WASM_LOCAL_TEE(0, WASM_ZERO),
                         WASM_LOCAL_TEE(0, WASM_I32V_1(1)),
                         WASM_LOCAL_TEE(0, WASM_I32V_1(2))),
           WASM_DROP, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(2, r.Call(i)); }
}

WASM_EXEC_TEST(Select_strict2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a)
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                       WASM_LOCAL_TEE(2, WASM_I32V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(SelectWithType_strict2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a)
  r.Build(
      {WASM_SELECT_I(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                     WASM_LOCAL_TEE(2, WASM_I32V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select_strict3) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a=b)
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                       WASM_LOCAL_TEE(2, WASM_I32V_1(6)),
                       WASM_LOCAL_TEE(0, WASM_LOCAL_GET(1)))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = 5;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(SelectWithType_strict3) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmI32);
  // select(b=5, c=6, a=b)
  r.Build({WASM_SELECT_I(WASM_LOCAL_TEE(1, WASM_I32V_1(5)),
                         WASM_LOCAL_TEE(2, WASM_I32V_1(6)),
                         WASM_LOCAL_TEE(0, WASM_LOCAL_GET(1)))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = 5;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT(WASM_I64V_1(11), WASM_I64V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64WithType) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  // return select(11, 22, a);
  r.Build({WASM_SELECT_L(WASM_I64V_1(11), WASM_I64V_1(22), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64_strict1) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI64);
  r.AllocateLocal(kWasmI64);
  // select(b=5, c=6, a)
  r.Build({WASM_SELECT(WASM_LOCAL_TEE(1, WASM_I64V_1(5)),
                       WASM_LOCAL_TEE(2, WASM_I64V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Select64WithType_strict1) {
  WasmRunner<int64_t, int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI64);
  r.AllocateLocal(kWasmI64);
  // select(b=5, c=6, a)
  r.Build(
      {WASM_SELECT_L(WASM_LOCAL_TEE(1, WASM_I64V_1(5)),
                     WASM_LOCAL_TEE(2, WASM_I64V_1(6)), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) {
    int64_t expected = i ? 5 : 6;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(BrIf_strict) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(
      WASM_BRV_IF(0, WASM_LOCAL_GET(0), WASM_LOCAL_TEE(0, WASM_I32V_2(99))))});

  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Br_height) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(
      WASM_BLOCK(WASM_BRV_IFD(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0)),
                 WASM_RETURN(WASM_I32V_1(9))),
      WASM_BRV(0, WASM_I32V_1(8)))});

  for (int32_t i = 0; i < 5; i++) {
    int32_t expected = i != 0 ? 8 : 9;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Regression_660262) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({kExprI32Const, 0x00, kExprI32Const, 0x00, kExprI32LoadMem, 0x00,
           0x0F, kExprBrTable, 0x00, 0x80, 0x00});  // entries=0
  r.Call();
}

WASM_EXEC_TEST(BrTable0a) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(0)))),
           WASM_I32V_2(91)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(91, r.Call(i)); }
}

WASM_EXEC_TEST(BrTable0b) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {B1(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 1, BR_TARGET(0), BR_TARGET(0)))),
       WASM_I32V_2(92)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(92, r.Call(i)); }
}

WASM_EXEC_TEST(BrTable0c) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 1, BR_TARGET(0),
                                  BR_TARGET(1))),
                 RET_I8(76))),
           WASM_I32V_2(77)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i == 0 ? 76 : 77;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(BrTable1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 0, BR_TARGET(0))), RET_I8(93)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(93, r.Call(i)); }
}

WASM_EXEC_TEST(BrTable_loop) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {B2(B1(WASM_LOOP(WASM_BR_TABLE(WASM_INC_LOCAL_BYV(0, 1), 2, BR_TARGET(2),
                                     BR_TARGET(1), BR_TARGET(0)))),
          RET_I8(99)),
       WASM_I32V_2(98)});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(98, r.Call(-1));
  CHECK_EQ(98, r.Call(-2));
  CHECK_EQ(98, r.Call(-3));
  CHECK_EQ(98, r.Call(-100));
}

WASM_EXEC_TEST(BrTable_br) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 1, BR_TARGET(1), BR_TARGET(0))),
          RET_I8(91)),
       WASM_I32V_2(99)});
  CHECK_EQ(99, r.Call(0));
  CHECK_EQ(91, r.Call(1));
  CHECK_EQ(91, r.Call(2));
  CHECK_EQ(91, r.Call(3));
}

WASM_EXEC_TEST(BrTable_br2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);

  r.Build({B2(B2(B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 3, BR_TARGET(1),
                                     BR_TARGET(2), BR_TARGET(3), BR_TARGET(0))),
                    RET_I8(85)),
                 RET_I8(86)),
              RET_I8(87)),
           WASM_I32V_2(88)});
  CHECK_EQ(86, r.Call(0));
  CHECK_EQ(87, r.Call(1));
  CHECK_EQ(88, r.Call(2));
  CHECK_EQ(85, r.Call(3));
  CHECK_EQ(85, r.Call(4));
  CHECK_EQ(85, r.Call(5));
}

WASM_EXEC_TEST(BrTable4) {
  for (int i = 0; i < 4; ++i) {
    for (int t = 0; t < 4; ++t) {
      uint32_t cases[] = {0, 1, 2, 3};
      cases[i] = t;

      WasmRunner<int32_t, int32_t> r(execution_tier);
      r.Build({B2(B2(B2(B2(B1(WASM_BR_TABLE(
                               WASM_LOCAL_GET(0), 3, BR_TARGET(cases[0]),
                               BR_TARGET(cases[1]), BR_TARGET(cases[2]),
                               BR_TARGET(cases[3]))),
                           RET_I8(70)),
                        RET_I8(71)),
                     RET_I8(72)),
                  RET_I8(73)),
               WASM_I32V_2(75)});

      for (int x = -3; x < 50; ++x) {
        int index = (x > 3 || x < 0) ? 3 : x;
        int32_t expected = 70 + cases[index];
        CHECK_EQ(expected, r.Call(x));
      }
    }
  }
}

WASM_EXEC_TEST(BrTable4x4) {
  for (uint8_t a = 0; a < 4; ++a) {
    for (uint8_t b = 0; b < 4; ++b) {
      for (uint8_t c = 0; c < 4; ++c) {
        for (uint8_t d = 0; d < 4; ++d) {
          for (int i = 0; i < 4; ++i) {
            uint32_t cases[] = {a, b, c, d};

            WasmRunner<int32_t, int32_t> r(execution_tier);
            r.Build({B2(B2(B2(B2(B1(WASM_BR_TABLE(
                                     WASM_LOCAL_GET(0), 3, BR_TARGET(cases[0]),
                                     BR_TARGET(cases[1]), BR_TARGET(cases[2]),
                                     BR_TARGET(cases[3]))),
                                 RET_I8(50)),
                              RET_I8(51)),
                           RET_I8(52)),
                        RET_I8(53)),
                     WASM_I32V_2(55)});

            for (int x = -6; x < 47; ++x) {
              int index = (x > 3 || x < 0) ? 3 : x;
              int32_t expected = 50 + cases[index];
              CHECK_EQ(expected, r.Call(x));
            }
          }
        }
      }
    }
  }
}

WASM_EXEC_TEST(BrTable4_fallthru) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build(
      {B2(B2(B2(B2(B1(WASM_BR_TABLE(WASM_LOCAL_GET(0), 3, BR_TARGET(0),
                                    BR_TARGET(1), BR_TARGET(2), BR_TARGET(3))),
                   WASM_INC_LOCAL_BY(1, 1)),
                WASM_INC_LOCAL_BY(1, 2)),
             WASM_INC_LOCAL_BY(1, 4)),
          WASM_INC_LOCAL_BY(1, 8)),
       WASM_LOCAL_GET(1)});

  CHECK_EQ(15, r.Call(0, 0));
  CHECK_EQ(14, r.Call(1, 0));
  CHECK_EQ(12, r.Call(2, 0));
  CHECK_EQ(8, r.Call(3, 0));
  CHECK_EQ(8, r.Call(4, 0));

  CHECK_EQ(115, r.Call(0, 100));
  CHECK_EQ(114, r.Call(1, 100));
  CHECK_EQ(112, r.Call(2, 100));
  CHECK_EQ(108, r.Call(3, 100));
  CHECK_EQ(108, r.Call(4, 100));
}

WASM_EXEC_TEST(BrTable_loop_target) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {WASM_LOOP_I(WASM_BLOCK(WASM_BR_TABLE(WASM_LOCAL_GET(0), 2, BR_TARGET(0),
                                            BR_TARGET(1), BR_TARGET(1))),
                   WASM_ONE)});

  CHECK_EQ(1, r.Call(0));
}

WASM_EXEC_TEST(I32ReinterpretF32) {
  WasmRunner<int32_t> r(execution_tier);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));

  r.Build({WASM_I32_REINTERPRET_F32(
      WASM_LOAD_MEM(MachineType::Float32(), WASM_ZERO))});

  FOR_FLOAT32_INPUTS(i) {
    float input = i;
    int32_t expected = base::bit_cast<int32_t, float>(input);
    r.builder().WriteMemory(&memory[0], input);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(F32ReinterpretI32) {
  WasmRunner<float> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));

  r.Build({WASM_F32_REINTERPRET_I32(
      WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))});

  FOR_INT32_INPUTS(i) {
    int32_t input = i;
    float expected = base::bit_cast<float, int32_t>(input);
    r.builder().WriteMemory(&memory[0], input);
    float result = r.Call();
    if (std::isnan(expected)) {
      CHECK(std::isnan(result));
      CHECK(IsSameNan(expected, result));
    } else {
      CHECK_EQ(expected, result);
    }
  }
}

// Do not run this test in a simulator because of signalling NaN issues on ia32.
#ifndef USE_SIMULATOR

WASM_EXEC_TEST(SignallingNanSurvivesI32ReinterpretF32) {
  WasmRunner<int32_t> r(execution_tier);

  r.Build({WASM_I32_REINTERPRET_F32(
      WASM_SEQ(kExprF32Const, 0x00, 0x00, 0xA0, 0x7F))});

  // This is a signalling nan.
  CHECK_EQ(0x7FA00000, r.Call());
}

#endif

WASM_EXEC_TEST(LoadMaxUint32Offset) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);

  r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(),  // type
                                U32V_5(0xFFFFFFFF),    // offset
                                WASM_ZERO)});          // index

  CHECK_TRAP32(r.Call());
}

WASM_EXEC_TEST(LoadStoreLoad) {
  WasmRunner<int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));

  r.Build({WASM_STORE_MEM(MachineType::Int32(), WASM_ZERO,
                          WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)),
           WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)});

  FOR_INT32_INPUTS(i) {
    int32_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(UnalignedFloat32Load) {
  WasmRunner<float> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_LOAD_MEM_ALIGNMENT(MachineType::Float32(), WASM_ONE, 2)});
  r.Call();
}

WASM_EXEC_TEST(UnalignedFloat64Load) {
  WasmRunner<double> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_LOAD_MEM_ALIGNMENT(MachineType::Float64(), WASM_ONE, 3)});
  r.Call();
}

WASM_EXEC_TEST(UnalignedInt32Load) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_LOAD_MEM_ALIGNMENT(MachineType::Int32(), WASM_ONE, 2)});
  r.Call();
}

WASM_EXEC_TEST(UnalignedInt32Store) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_SEQ(WASM_STORE_MEM_ALIGNMENT(MachineType::Int32(), WASM_ONE, 2,
                                             WASM_I32V_1(1)),
                    WASM_I32V_1(12))});
  r.Call();
}

WASM_EXEC_TEST(UnalignedFloat32Store) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_SEQ(WASM_STORE_MEM_ALIGNMENT(MachineType::Float32(), WASM_ONE,
                                             2, WASM_F32(1.0)),
                    WASM_I32V_1(12))});
  r.Call();
}

WASM_EXEC_TEST(UnalignedFloat64Store) {
  WasmRunner<int32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.Build({WASM_SEQ(WASM_STORE_MEM_ALIGNMENT(MachineType::Float64(), WASM_ONE,
                                             3, WASM_F64(1.0)),
                    WASM_I32V_1(12))});
  r.Call();
}

WASM_EXEC_TEST(VoidReturn1) {
  const int32_t kExpected = -414444;
  WasmRunner<int32_t> r(execution_tier);

  // Build the test function.
  WasmFunctionCompiler& test_func = r.NewFunction<void>();
  test_func.Build({kExprNop});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION0(test_func.function_index()),
           WASM_I32V_3(kExpected)});

  // Call and check.
  int32_t result = r.Call();
  CHECK_EQ(kExpected, result);
}

WASM_EXEC_TEST(VoidReturn2) {
  const int32_t kExpected = -414444;
  WasmRunner<int32_t> r(execution_tier);

  // Build the test function.
  WasmFunctionCompiler& test_func = r.NewFunction<void>();
  test_func.Build({WASM_RETURN0});

  // Build the calling function.
  r.Build({WASM_CALL_FUNCTION0(test_func.function_index()),
           WASM_I32V_3(kExpected)});

  // Call and check.
  int32_t result = r.Call();
  CHECK_EQ(kExpected, result);
}

WASM_EXEC_TEST(BrEmpty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BRV(0, WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(BrIfEmpty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BRV_IF(0, WASM_LOCAL_GET(0), WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({kExprBlock, kVoidCode, kExprEnd, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty_br1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_BR(0)), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty_brif1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_ZERO)), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_empty_brif2) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_BLOCK(WASM_BR_IF(0, WASM_LOCAL_GET(1))), WASM_LOCAL_GET(0)});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i, i + 1)); }
}

WASM_EXEC_TEST(Block_i) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_f) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_BLOCK_F(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_d) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_BLOCK_D(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Block_br2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV(0, WASM_LOCAL_GET(0)))});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, static_cast<uint32_t>(r.Call(i))); }
}

WASM_EXEC_TEST(Block_If_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // block { if (p0) break 51; 52; }
  r.Build({WASM_BLOCK_I(                      // --
      WASM_IF(WASM_LOCAL_GET(0),              // --
              WASM_BRV(1, WASM_I32V_1(51))),  // --
      WASM_I32V_1(52))});                     // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 51 : 52;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Loop_empty) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({kExprLoop, kVoidCode, kExprEnd, WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_i) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP_I(WASM_LOCAL_GET(0))});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_f) {
  WasmRunner<float, float> r(execution_tier);
  r.Build({WASM_LOOP_F(WASM_LOCAL_GET(0))});
  FOR_FLOAT32_INPUTS(i) { CHECK_FLOAT_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_d) {
  WasmRunner<double, double> r(execution_tier);
  r.Build({WASM_LOOP_D(WASM_LOCAL_GET(0))});
  FOR_FLOAT64_INPUTS(i) { CHECK_DOUBLE_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_empty_br1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_LOOP(WASM_BR(1))), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_empty_brif1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_LOOP(WASM_BR_IF(1, WASM_ZERO))), WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) { CHECK_EQ(i, r.Call(i)); }
}

WASM_EXEC_TEST(Loop_empty_brif2) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOOP_I(WASM_BRV_IF(1, WASM_LOCAL_GET(0), WASM_LOCAL_GET(1)))});
  FOR_UINT32_INPUTS(i) { CHECK_EQ(i, r.Call(i, i + 1)); }
}

WASM_EXEC_TEST(Loop_empty_brif3) {
  WasmRunner<uint32_t, uint32_t, uint32_t, uint32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_BRV_IFD(1, WASM_LOCAL_GET(2), WASM_LOCAL_GET(0))),
           WASM_LOCAL_GET(1)});
  FOR_UINT32_INPUTS(i) {
    FOR_UINT32_INPUTS(j) {
      CHECK_EQ(i, r.Call(0, i, j));
      CHECK_EQ(j, r.Call(1, i, j));
    }
  }
}

WASM_EXEC_TEST(Block_BrIf_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_BLOCK_I(WASM_BRV_IFD(0, WASM_I32V_1(51), WASM_LOCAL_GET(0)),
                        WASM_I32V_1(52))});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 51 : 52;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Block_IfElse_P_assign) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // { if (p0) p0 = 71; else p0 = 72; return p0; }
  r.Build({WASM_IF_ELSE(WASM_LOCAL_GET(0),                    // --
                        WASM_LOCAL_SET(0, WASM_I32V_2(71)),   // --
                        WASM_LOCAL_SET(0, WASM_I32V_2(72))),  // --
           WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 71 : 72;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Block_IfElse_P_return) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // if (p0) return 81; else return 82;
  r.Build({WASM_IF_ELSE(WASM_LOCAL_GET(0),  // --
                        RET_I8(81),         // --
                        RET_I8(82)),        // --
           WASM_ZERO});                     // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 81 : 82;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(Block_If_P_assign) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // { if (p0) p0 = 61; p0; }
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_LOCAL_SET(0, WASM_I32V_1(61))),
           WASM_LOCAL_GET(0)});
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 61 : i;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(DanglingAssign) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // { return 0; p0 = 0; }
  r.Build({WASM_BLOCK_I(RET_I8(99), WASM_LOCAL_TEE(0, WASM_ZERO))});
  CHECK_EQ(99, r.Call(1));
}

WASM_EXEC_TEST(ExprIf_P) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // p0 ? 11 : 22;
  r.Build({WASM_IF_ELSE_I(WASM_LOCAL_GET(0),   // --
                          WASM_I32V_1(11),     // --
                          WASM_I32V_1(22))});  // --
  FOR_INT32_INPUTS(i) {
    int32_t expected = i ? 11 : 22;
    CHECK_EQ(expected, r.Call(i));
  }
}

WASM_EXEC_TEST(CountDown) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0),
                             WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0),
                                                            WASM_I32V_1(1))),
                             WASM_BR(1))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(0, r.Call(1));
  CHECK_EQ(0, r.Call(10));
  CHECK_EQ(0, r.Call(100));
}

WASM_EXEC_TEST(CountDown_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build(
      {WASM_LOOP(
           WASM_IF(WASM_NOT(WASM_LOCAL_GET(0)), WASM_BRV(2, WASM_LOCAL_GET(0))),
           WASM_LOCAL_SET(0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(1))),
           WASM_CONTINUE(0)),
       WASM_LOCAL_GET(0)});
  CHECK_EQ(0, r.Call(1));
  CHECK_EQ(0, r.Call(10));
  CHECK_EQ(0, r.Call(100));
}

WASM_EXEC_TEST(WhileCountDown) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_WHILE(WASM_LOCAL_GET(0),
                      WASM_LOCAL_SET(
                          0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(1)))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(0, r.Call(1));
  CHECK_EQ(0, r.Call(10));
  CHECK_EQ(0, r.Call(100));
}

WASM_EXEC_TEST(Loop_if_break1) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0), WASM_BRV(2, WASM_LOCAL_GET(1))),
                     WASM_LOCAL_SET(0, WASM_I32V_2(99))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(99, r.Call(0, 11));
  CHECK_EQ(65, r.Call(3, 65));
  CHECK_EQ(10001, r.Call(10000, 10001));
  CHECK_EQ(-29, r.Call(-28, -29));
}

WASM_EXEC_TEST(Loop_if_break2) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  r.Build({WASM_LOOP(WASM_BRV_IF(1, WASM_LOCAL_GET(1), WASM_LOCAL_GET(0)),
                     WASM_DROP, WASM_LOCAL_SET(0, WASM_I32V_2(99))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(99, r.Call(0, 33));
  CHECK_EQ(3, r.Call(1, 3));
  CHECK_EQ(10000, r.Call(99, 10000));
  CHECK_EQ(-29, r.Call(-11, -29));
}

WASM_EXEC_TEST(Loop_if_break_fallthru) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0), WASM_BR(2)),
                        WASM_LOCAL_SET(0, WASM_I32V_2(93)))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(93, r.Call(0));
  CHECK_EQ(3, r.Call(3));
  CHECK_EQ(10001, r.Call(10001));
  CHECK_EQ(-22, r.Call(-22));
}

WASM_EXEC_TEST(Loop_if_break_fallthru2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({B1(B1(WASM_LOOP(WASM_IF(WASM_LOCAL_GET(0), WASM_BR(2)),
                           WASM_LOCAL_SET(0, WASM_I32V_2(93))))),
           WASM_LOCAL_GET(0)});
  CHECK_EQ(93, r.Call(0));
  CHECK_EQ(3, r.Call(3));
  CHECK_EQ(10001, r.Call(10001));
  CHECK_EQ(-22, r.Call(-22));
}

WASM_EXEC_TEST(IfBreak1) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_SEQ(WASM_BR(0), WASM_UNREACHABLE)),
           WASM_I32V_2(91)});
  CHECK_EQ(91, r.Call(0));
  CHECK_EQ(91, r.Call(1));
  CHECK_EQ(91, r.Call(-8734));
}

WASM_EXEC_TEST(IfBreak2) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  r.Build({WASM_IF(WASM_LOCAL_GET(0), WASM_SEQ(WASM_BR(0), RET_I8(77))),
           WASM_I32V_2(81)});
  CHECK_EQ(81, r.Call(0));
  CHECK_EQ(81, r.Call(1));
  CHECK_EQ(81, r.Call(-8734));
}

WASM_EXEC_TEST(LoadMemI32) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(1111);

  r.Build({WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO)});

  r.builder().WriteMemory(&memory[0], 99999999);
  CHECK_EQ(99999999, r.Call(0));

  r.builder().WriteMemory(&memory[0], 88888888);
  CHECK_EQ(88888888, r.Call(0));

  r.builder().WriteMemory(&memory[0], 77777777);
  CHECK_EQ(77777777, r.Call(0));
}

WASM_EXEC_TEST(LoadMemI32_alignment) {
  for (uint8_t alignment = 0; alignment <= 2; ++alignment) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.builder().RandomizeMemory(1111);

    r.Build(
        {WASM_LOAD_MEM_ALIGNMENT(MachineType::Int32(), WASM_ZERO, alignment)});

    r.builder().WriteMemory(&memory[0], 0x1A2B3C4D);
    CHECK_EQ(0x1A2B3C4D, r.Call(0));

    r.builder().WriteMemory(&memory[0], 0x5E6F7A8B);
    CHECK_EQ(0x5E6F7A8B, r.Call(0));

    r.builder().WriteMemory(&memory[0], 0x7CA0B1C2);
    CHECK_EQ(0x7CA0B1C2, r.Call(0));
  }
}

WASM_EXEC_TEST(LoadMemI32_oob) {
  WasmRunner<int32_t, uint32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(1111);

  r.Build({WASM_LOAD_MEM(MachineType::Int32(), WASM_LOCAL_GET(0))});

  r.builder().WriteMemory(&memory[0], 88888888);
  CHECK_EQ(88888888, r.Call(0u));
  for (uint32_t offset = kWasmPageSize - 3; offset < kWasmPageSize + 40;
       ++offset) {
    CHECK_TRAP(r.Call(offset));
  }

  for (uint32_t offset = 0x80000000; offset < 0x80000010; ++offset) {
    CHECK_TRAP(r.Call(offset));
  }
}

WASM_EXEC_TEST(LoadMem_offset_oob) {
  static const MachineType machineTypes[] = {
      MachineType::Int8(),   MachineType::Uint8(),  MachineType::Int16(),
      MachineType::Uint16(), MachineType::Int32(),  MachineType::Uint32(),
      MachineType::Int64(),  MachineType::Uint64(), MachineType::Float32(),
      MachineType::Float64()};

  constexpr size_t num_bytes = kWasmPageSize;

  for (size_t m = 0; m < arraysize(machineTypes); ++m) {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<uint8_t>(num_bytes);
    r.builder().RandomizeMemory(1116 + static_cast<int>(m));

    constexpr uint8_t kOffset = 8;
    uint32_t boundary = num_bytes - kOffset - machineTypes[m].MemSize();

    r.Build({WASM_LOAD_MEM_OFFSET(machineTypes[m], kOffset, WASM_LOCAL_GET(0)),
             WASM_DROP, WASM_ZERO});

    CHECK_EQ(0, r.Call(boundary));  // in bounds.

    for (uint32_t offset = boundary + 1; offset < boundary + 19; ++offset) {
      CHECK_TRAP(r.Call(offset));  // out of bounds.
    }
  }
}

WASM_EXEC_TEST(LoadMemI32_offset) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(1111);

  r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(), 4, WASM_LOCAL_GET(0))});

  r.builder().WriteMemory(&memory[0], 66666666);
  r.builder().WriteMemory(&memory[1], 77777777);
  r.builder().WriteMemory(&memory[2], 88888888);
  r.builder().WriteMemory(&memory[3], 99999999);
  CHECK_EQ(77777777, r.Call(0));
  CHECK_EQ(88888888, r.Call(4));
  CHECK_EQ(99999999, r.Call(8));

  r.builder().WriteMemory(&memory[0], 11111111);
  r.builder().WriteMemory(&memory[1], 22222222);
  r.builder().WriteMemory(&memory[2], 33333333);
  r.builder().WriteMemory(&memory[3], 44444444);
  CHECK_EQ(22222222, r.Call(0));
  CHECK_EQ(33333333, r.Call(4));
  CHECK_EQ(44444444, r.Call(8));
}

WASM_EXEC_TEST(LoadMemI32_const_oob_misaligned) {
  // This test accesses memory starting at kRunwayLength bytes before the end of
  // the memory until a few bytes beyond.
  constexpr uint8_t kRunwayLength = 12;
  // TODO(titzer): Fix misaligned accesses on MIPS and re-enable.
  for (uint8_t offset = 0; offset < kRunwayLength + 5; ++offset) {
    for (uint32_t index = kWasmPageSize - kRunwayLength;
         index < kWasmPageSize + 5; ++index) {
      WasmRunner<int32_t> r(execution_tier);
      r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
      r.builder().RandomizeMemory();

      r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(), offset,
                                    WASM_I32V_3(index))});

      if (offset + index + sizeof(int32_t) <= kWasmPageSize) {
        CHECK_EQ(r.builder().raw_val_at<int32_t>(offset + index), r.Call());
      } else {
        CHECK_TRAP(r.Call());
      }
    }
  }
}

WASM_EXEC_TEST(LoadMemI32_const_oob) {
  // This test accesses memory starting at kRunwayLength bytes before the end of
  // the memory until a few bytes beyond.
  constexpr uint8_t kRunwayLength = 24;
  for (uint8_t offset = 0; offset < kRunwayLength + 5; offset += 4) {
    for (uint32_t index = kWasmPageSize - kRunwayLength;
         index < kWasmPageSize + 5; index += 4) {
      WasmRunner<int32_t> r(execution_tier);
      r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
      r.builder().RandomizeMemory();

      r.Build({WASM_LOAD_MEM_OFFSET(MachineType::Int32(), offset,
                                    WASM_I32V_3(index))});

      if (offset + index + sizeof(int32_t) <= kWasmPageSize) {
        CHECK_EQ(r.builder().raw_val_at<int32_t>(offset + index), r.Call());
      } else {
        CHECK_TRAP(r.Call());
      }
    }
  }
}

WASM_EXEC_TEST(StoreMemI32_alignment) {
  const int32_t kWritten = 0x12345678;

  for (uint8_t i = 0; i <= 2; ++i) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.Build({WASM_STORE_MEM_ALIGNMENT(MachineType::Int32(), WASM_ZERO, i,
                                      WASM_LOCAL_GET(0)),
             WASM_LOCAL_GET(0)});
    r.builder().RandomizeMemory(1111);
    memory[0] = 0;

    CHECK_EQ(kWritten, r.Call(kWritten));
    CHECK_EQ(kWritten, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(StoreMemI32_offset) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  const int32_t kWritten = 0xAABBCCDD;

  r.Build({WASM_STORE_MEM_OFFSET(MachineType::Int32(), 4, WASM_LOCAL_GET(0),
                                 WASM_I32V_5(kWritten)),
           WASM_I32V_5(kWritten)});

  for (int i = 0; i < 2; ++i) {
    r.builder().RandomizeMemory(1111);
    r.builder().WriteMemory(&memory[0], 66666666);
    r.builder().WriteMemory(&memory[1], 77777777);
    r.builder().WriteMemory(&memory[2], 88888888);
    r.builder().WriteMemory(&memory[3], 99999999);
    CHECK_EQ(kWritten, r.Call(i * 4));
    CHECK_EQ(66666666, r.builder().ReadMemory(&memory[0]));
    CHECK_EQ(i == 0 ? kWritten : 77777777, r.builder().ReadMemory(&memory[1]));
    CHECK_EQ(i == 1 ? kWritten : 88888888, r.builder().ReadMemory(&memory[2]));
    CHECK_EQ(i == 2 ? kWritten : 99999999, r.builder().ReadMemory(&memory[3]));
  }
}

WASM_EXEC_TEST(StoreMem_offset_oob) {
  // 64-bit cases are handled in test-run-wasm-64.cc
  static const MachineType machineTypes[] = {
      MachineType::Int8(),    MachineType::Uint8(),  MachineType::Int16(),
      MachineType::Uint16(),  MachineType::Int32(),  MachineType::Uint32(),
      MachineType::Float32(), MachineType::Float64()};

  constexpr size_t num_bytes = kWasmPageSize;

  for (size_t m = 0; m < arraysize(machineTypes); ++m) {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(num_bytes);

    r.builder().RandomizeMemory(1119 + static_cast<int>(m));

    r.Build({WASM_STORE_MEM_OFFSET(machineTypes[m], 8, WASM_LOCAL_GET(0),
                                   WASM_LOAD_MEM(machineTypes[m], WASM_ZERO)),
             WASM_ZERO});

    uint8_t memsize = machineTypes[m].MemSize();
    uint32_t boundary = num_bytes - 8 - memsize;
    CHECK_EQ(0, r.Call(boundary));  // in bounds.
    CHECK_EQ(0, memcmp(&memory[0], &memory[8 + boundary], memsize));

    for (uint32_t offset = boundary + 1; offset < boundary + 19; ++offset) {
      CHECK_TRAP(r.Call(offset));  // out of bounds.
    }
  }
}

WASM_EXEC_TEST(Store_i32_narrowed) {
  constexpr uint8_t kOpcodes[] = {kExprI32StoreMem8, kExprI32StoreMem16,
                                  kExprI32StoreMem};
  int stored_size_in_bytes = 0;
  for (auto opcode : kOpcodes) {
    stored_size_in_bytes = std::max(1, stored_size_in_bytes * 2);
    constexpr int kBytes = 24;
    uint8_t expected_memory[kBytes] = {0};
    WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
    constexpr uint32_t kPattern = 0x12345678;

    r.Build({WASM_LOCAL_GET(0),                    // index
             WASM_LOCAL_GET(1),                    // value
             opcode, ZERO_ALIGNMENT, ZERO_OFFSET,  // store
             WASM_ZERO});                          // return value

    for (int i = 0; i <= kBytes - stored_size_in_bytes; ++i) {
      uint32_t pattern = base::bits::RotateLeft32(kPattern, i % 32);
      r.Call(i, pattern);
      for (int b = 0; b < stored_size_in_bytes; ++b) {
        expected_memory[i + b] = static_cast<uint8_t>(pattern >> (b * 8));
      }
      for (int w = 0; w < kBytes; ++w) {
        CHECK_EQ(expected_memory[w], memory[w]);
      }
    }
  }
}

WASM_EXEC_TEST(LoadMemI32_P) {
  const int kNumElems = 8;
  WasmRunner<int32_t, int32_t> r(execution_tier);
  int32_t* memory =
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().RandomizeMemory(2222);

  r.Build({WASM_LOAD_MEM(MachineType::Int32(), WASM_LOCAL_GET(0))});

  for (int i = 0; i < kNumElems; ++i) {
    CHECK_EQ(r.builder().ReadMemory(&memory[i]), r.Call(i * 4));
  }
}

WASM_EXEC_TEST(MemI32_Sum) {
  const int kNumElems = 20;
  WasmRunner<uint32_t, int32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(int32_t));
  const uint8_t kSum = r.AllocateLocal(kWasmI32);

  r.Build(
      {WASM_WHILE(
           WASM_LOCAL_GET(0),
           WASM_BLOCK(WASM_LOCAL_SET(
                          kSum, WASM_I32_ADD(WASM_LOCAL_GET(kSum),
                                             WASM_LOAD_MEM(MachineType::Int32(),
                                                           WASM_LOCAL_GET(0)))),
                      WASM_LOCAL_SET(
                          0, WASM_I32_SUB(WASM_LOCAL_GET(0), WASM_I32V_1(4))))),
       WASM_LOCAL_GET(1)});

  // Run 4 trials.
  for (int i = 0; i < 3; ++i) {
    r.builder().RandomizeMemory(i * 33);
    uint32_t expected = 0;
    for (size_t j = kNumElems - 1; j > 0; --j) {
      expected += r.builder().ReadMemory(&memory[j]);
    }
    uint32_t result = r.Call(4 * (kNumElems - 1));
    CHECK_EQ(expected, result);
  }
}

WASM_EXEC_TEST(CheckMachIntsZero) {
  cons
```