Response:
The user wants a summary of the functionality of the C++ code provided.

Here's a breakdown of the thought process to achieve that:

1. **Identify the Core Purpose:** The filename `wasm-simd-utils.cc` and the numerous functions with names like `RunI8x16UnOpTest`, `RunI16x8BinOpTest`, `RunF32x4BinOpTest`, etc., strongly suggest that this code is about testing SIMD (Single Instruction, Multiple Data) operations in the WebAssembly (Wasm) module of the V8 JavaScript engine.

2. **Recognize the Testing Framework:** The code uses `WasmRunner`, `AddGlobal`, `AllocateLocal`, `Build`, `Call`, and `CHECK_EQ`. These are typical components of a testing framework within V8, specifically designed for testing Wasm. The `FOR_INT8_INPUTS`, `FOR_INT16_INPUTS`, `FOR_FLOAT32_INPUTS`, and `FOR_FLOAT64_INPUTS` macros indicate iteration over different input values for thorough testing.

3. **Categorize the Test Functions:** Notice the pattern in the function names: `Run<DataType><OperationType>OpTest`. This reveals the structure of the tests. We have tests for:
    * Integer types (I8x16, I16x8, I32x4, I64x2)
    * Floating-point types (F16x8, F32x4, F64x2)
    * Unary operations (UnOp)
    * Binary operations (BinOp)
    * Shift operations (ShiftOp)
    * Relational operations (MixedRelationalOpTest, CompareOpTest)

4. **Analyze the Structure of Individual Test Functions:**  Take `RunI8x16UnOpTest` as an example. It follows a consistent pattern:
    * Create a `WasmRunner` instance.
    * Allocate a global variable to store the output.
    * Build a Wasm function that:
        * Takes an input value.
        * Splats (duplicates) the input value across all lanes of a SIMD vector.
        * Performs the unary operation on the SIMD vector.
        * Stores the result in the global variable.
        * Returns a value (likely for success indication).
    * Iterate over various input values using `FOR_INT8_INPUTS`.
    * Call the Wasm function with each input.
    * Retrieve the result from the global variable.
    * Compare the actual result with the expected result using `CHECK_EQ`.

5. **Infer the Purpose of Helper Functions:** Functions like `CheckFloat16LaneResult`, `CheckFloatResult`, and `CheckDoubleResult` are clearly used for comparing floating-point results, considering potential inaccuracies and special values like NaN. `IsCanonical` and `isnan` are helpers for NaN checks. `IsExtreme` likely identifies edge-case floating-point values.

6. **Identify Specific SIMD Operations:**  The code uses macros like `WASM_SIMD_I8x16_SPLAT`, `WASM_SIMD_UNOP`, `WASM_SIMD_BINOP`, and `WASM_SIMD_SHIFT_OP`. These are V8's internal mechanisms for representing SIMD instructions in the Wasm bytecode.

7. **Address the Specific Questions:**
    * **.tq extension:** The code explicitly checks for `.tq` extension and confirms it's not the case here.
    * **Relationship to JavaScript:**  While this C++ code tests Wasm SIMD, Wasm itself is designed to be executed within JavaScript environments. Thus, the SIMD operations tested here directly correspond to the SIMD features available in JavaScript's `WebAssembly.SIMD` proposal (now largely integrated). Provide a JavaScript example demonstrating a similar SIMD operation.
    * **Code Logic Inference:** Select a simple test function (`RunI8x16UnOpTest`) and provide a hypothetical input and expected output based on the operation and the looping over lanes.
    * **Common Programming Errors:** Think about typical mistakes users might make when working with SIMD, like assuming operations are scalar or neglecting to handle lane-wise operations.

8. **Synthesize the Summary:** Combine all the observations into a concise summary highlighting the file's purpose, the types of tests it performs, the use of the testing framework, and the connection to Wasm SIMD functionality.

**Self-Correction/Refinement during the thought process:**

* Initially, one might just say "it tests SIMD". But refining this to specify "Wasm SIMD within V8" is more accurate.
* Recognizing the pattern in the function names is crucial for efficient analysis.
* Remembering that Wasm is executed within a JavaScript environment helps establish the link between the C++ testing code and JavaScript functionality.
*  The request asks for *common* programming errors. Focus on errors directly related to the SIMD context rather than general programming mistakes.
* The prompt asks for a *summary* for part 1. Keep the summary high-level and avoid getting bogged down in the details of every single test function.

By following this systematic thought process, we can accurately and comprehensively describe the functionality of the given V8 source code.```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/cctest/wasm/wasm-simd-utils.h"

#include <cmath>
#include <type_traits>

#include "src/base/logging.h"
#include "src/base/memory.h"
#include "src/common/globals.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/c-signature.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "third_party/fp16/src/include/fp16.h"

namespace v8 {
namespace internal {
namespace wasm {
void RunI8x16UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int8UnOp expected_op) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT8_INPUTS(x) {
    r.Call(x);
    int8_t expected = expected_op(x);
    for (int i = 0; i < 16; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

template <typename T, typename OpType>
void RunI8x16BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       OpType expected_op) {
  WasmRunner<int32_t, T, T> r(execution_tier);
  // Global to hold output.
  T* g = r.builder().template AddGlobal<T>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (T x : compiler::ValueHelper::GetVector<T>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      r.Call(x, y);
      T expected = expected_op(x, y);
      for (int i = 0; i < 16; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunI8x16BinOpTest<int8_t>(TestExecutionTier, WasmOpcode,
                                        Int8BinOp);

template void RunI8x16BinOpTest<uint8_t>(TestExecutionTier, WasmOpcode,
                                         Uint8BinOp);

void RunI8x16ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int8ShiftOp expected_op) {
  // Intentionally shift by 8, should be no-op.
  for (int shift = 1; shift <= 8; shift++) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int8_t* g_imm = r.builder().AddGlobal<int8_t>(kWasmS128);
    int8_t* g_mem = r.builder().AddGlobal<int8_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT8_INPUTS(x) {
      r.Call(x);
      int8_t expected = expected_op(x, shift);
      for (int i = 0; i < 16; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

void RunI8x16MixedRelationalOpTest(TestExecutionTier execution_tier,
                                   WasmOpcode opcode, Int8BinOp expected_op) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_LOCAL_SET(temp3, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                                 WASM_LOCAL_GET(temp2))),
           WASM_SIMD_I8x16_EXTRACT_LANE(0, WASM_LOCAL_GET(temp3))});

  CHECK_EQ(expected_op(0xff, static_cast<uint8_t>(0x7fff)),
           r.Call(0xff, 0x7fff));
  CHECK_EQ(expected_op(0xfe, static_cast<uint8_t>(0x7fff)),
           r.Call(0xfe, 0x7fff));
  CHECK_EQ(expected_op(0xff, static_cast<uint8_t>(0x7ffe)),
           r.Call(0xff, 0x7ffe));
}

void RunI16x8UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int16UnOp expected_op) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int16_t* g = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int16_t expected = expected_op(x);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

template <typename T, typename OpType>
void RunI16x8BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       OpType expected_op) {
  WasmRunner<int32_t, T, T> r(execution_tier);
  // Global to hold output.
  T* g = r.builder().template AddGlobal<T>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (T x : compiler::ValueHelper::GetVector<T>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      r.Call(x, y);
      T expected = expected_op(x, y);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunI16x8BinOpTest<int16_t>(TestExecutionTier, WasmOpcode,
                                         Int16BinOp);
template void RunI16x8BinOpTest<uint16_t>(TestExecutionTier, WasmOpcode,
                                          Uint16BinOp);

void RunI16x8ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int16ShiftOp expected_op) {
  // Intentionally shift by 16, should be no-op.
  for (int shift = 1; shift <= 16; shift++) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int16_t* g_imm = r.builder().AddGlobal<int16_t>(kWasmS128);
    int16_t* g_mem = r.builder().AddGlobal<int16_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT16_INPUTS(x) {
      r.Call(x);
      int16_t expected = expected_op(x, shift);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

void RunI16x8MixedRelationalOpTest(TestExecutionTier execution_tier,
                                   WasmOpcode opcode, Int16BinOp expected_op) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_LOCAL_SET(temp3, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                                 WASM_LOCAL_GET(temp2))),
           WASM_SIMD_I16x8_EXTRACT_LANE(0, WASM_LOCAL_GET(temp3))});

  CHECK_EQ(expected_op(0xffff, static_cast<uint16_t>(0x7fffffff)),
           r.Call(0xffff, 0x7fffffff));
  CHECK_EQ(expected_op(0xfeff, static_cast<uint16_t>(0x7fffffff)),
           r.Call(0xfeff, 0x7fffffff));
  CHECK_EQ(expected_op(0xffff, static_cast<uint16_t>(0x7ffffeff)),
           r.Call(0xffff, 0x7ffffeff));
}

void RunI32x4UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int32UnOp expected_op) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int32_t expected = expected_op(x);
    for (int i = 0; i < 4; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

void RunI32x4BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       Int32BinOp expected_op) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      r.Call(x, y);
      int32_t expected = expected_op(x, y);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

void RunI32x4ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int32ShiftOp expected_op) {
  // Intentionally shift by 32, should be no-op.
  for (int shift = 1; shift <= 32; shift++) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int32_t* g_imm = r.builder().AddGlobal<int32_t>(kWasmS128);
    int32_t* g_mem = r.builder().AddGlobal<int32_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT32_INPUTS(x) {
      r.Call(x);
      int32_t expected = expected_op(x, shift);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

void RunI64x2UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int64UnOp expected_op) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  // Global to hold output.
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT64_INPUTS(x) {
    r.Call(x);
    int64_t expected = expected_op(x);
    for (int i = 0; i < 2; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

void RunI64x2BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       Int64BinOp expected_op) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  // Global to hold output.
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_INT64_INPUTS(x) {
    FOR_INT64_INPUTS(y) {
      r.Call(x, y);
      int64_t expected = expected_op(x, y);
      for (int i = 0; i < 2; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

void RunI64x2ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int64ShiftOp expected_op) {
  // Intentionally shift by 64, should be no-op.
  for (int shift = 1; shift <= 64; shift++) {
    WasmRunner<int32_t, int64_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int64_t* g_imm = r.builder().AddGlobal<int64_t>(kWasmS128);
    int64_t* g_mem = r.builder().AddGlobal<int64_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT64_INPUTS(x) {
      r.Call(x);
      int64_t expected = expected_op(x, shift);
      for (int i = 0; i < 2; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

bool IsCanonical(uint16_t actual) {
  // Canonical NaN has quiet bit and no payload.
  return isnan(actual) && (actual & 0xFE00) == actual;
}

bool isnan(uint16_t f) { return (f & 0x7C00) == 0x7C00 && (f & 0x03FF); }

void CheckFloat16LaneResult(float x, float y, uint16_t expected,
                            uint16_t actual, bool exact) {
  CheckFloat16LaneResult(x, y, y, expected, actual, exact);
}

void CheckFloat16LaneResult(float x, float y, float z, uint16_t expected,
                            uint16_t actual, bool exact) {
  if (isnan(expected)) {
    CHECK(isnan(actual));
    if (std::isnan(x) && IsSameNan(fp16_ieee_from_fp32_value(x), actual)) {
      return;
    }
    if (std::isnan(y) && IsSameNan(fp16_ieee_from_fp32_value(y), actual)) {
      return;
    }
    if (std::isnan(z) && IsSameNan(fp16_ieee_from_fp32_value(z), actual)) {
      return;
    }
    if (IsSameNan(expected, actual)) return;
    if (IsCanonical(actual)) return;
    // This is expected to assert; it's useful for debugging.
    CHECK_EQ(expected, actual);
  } else {
    if (exact) {
      CHECK_EQ(expected, actual);
      return;
    }
    // Otherwise, perform an approximate equality test. First check for
    // equality to handle +/-Infinity where approximate equality doesn't work.
    if (expected == actual) return;

    // 1% error allows all platforms to pass easily.
    constexpr float kApproximationError = 0.01f;
    float f32_expected = fp16_ieee_to_fp32_value(expected);
    float f32_actual = fp16_ieee_to_fp32_value(actual);
    float abs_error = std::abs(f32_expected) * kApproximationError;
    float min = f32_expected - abs_error;
    float max = f32_expected + abs_error;
    CHECK_LE(min, f32_actual);
    CHECK_GE(max, f32_actual);
  }
}

void RunF16x8UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      HalfUnOp expected_op, bool exact) {
  WasmRunner<int32_t, float> r(execution_tier);
  // Global to hold output.
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
Prompt: 
```
这是目录为v8/test/cctest/wasm/wasm-simd-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/wasm-simd-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/cctest/wasm/wasm-simd-utils.h"

#include <cmath>
#include <type_traits>

#include "src/base/logging.h"
#include "src/base/memory.h"
#include "src/common/globals.h"
#include "src/wasm/compilation-environment.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-opcodes-inl.h"
#include "src/wasm/wasm-opcodes.h"
#include "test/cctest/wasm/wasm-run-utils.h"
#include "test/common/c-signature.h"
#include "test/common/value-helper.h"
#include "test/common/wasm/wasm-macro-gen.h"
#include "third_party/fp16/src/include/fp16.h"

namespace v8 {
namespace internal {
namespace wasm {
void RunI8x16UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int8UnOp expected_op) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int8_t* g = r.builder().AddGlobal<int8_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT8_INPUTS(x) {
    r.Call(x);
    int8_t expected = expected_op(x);
    for (int i = 0; i < 16; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

template <typename T, typename OpType>
void RunI8x16BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       OpType expected_op) {
  WasmRunner<int32_t, T, T> r(execution_tier);
  // Global to hold output.
  T* g = r.builder().template AddGlobal<T>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (T x : compiler::ValueHelper::GetVector<T>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      r.Call(x, y);
      T expected = expected_op(x, y);
      for (int i = 0; i < 16; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunI8x16BinOpTest<int8_t>(TestExecutionTier, WasmOpcode,
                                        Int8BinOp);

template void RunI8x16BinOpTest<uint8_t>(TestExecutionTier, WasmOpcode,
                                         Uint8BinOp);

void RunI8x16ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int8ShiftOp expected_op) {
  // Intentionally shift by 8, should be no-op.
  for (int shift = 1; shift <= 8; shift++) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int8_t* g_imm = r.builder().AddGlobal<int8_t>(kWasmS128);
    int8_t* g_mem = r.builder().AddGlobal<int8_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT8_INPUTS(x) {
      r.Call(x);
      int8_t expected = expected_op(x, shift);
      for (int i = 0; i < 16; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

void RunI8x16MixedRelationalOpTest(TestExecutionTier execution_tier,
                                   WasmOpcode opcode, Int8BinOp expected_op) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_LOCAL_SET(temp3, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                                 WASM_LOCAL_GET(temp2))),
           WASM_SIMD_I8x16_EXTRACT_LANE(0, WASM_LOCAL_GET(temp3))});

  CHECK_EQ(expected_op(0xff, static_cast<uint8_t>(0x7fff)),
           r.Call(0xff, 0x7fff));
  CHECK_EQ(expected_op(0xfe, static_cast<uint8_t>(0x7fff)),
           r.Call(0xfe, 0x7fff));
  CHECK_EQ(expected_op(0xff, static_cast<uint8_t>(0x7ffe)),
           r.Call(0xff, 0x7ffe));
}

void RunI16x8UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int16UnOp expected_op) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int16_t* g = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT16_INPUTS(x) {
    r.Call(x);
    int16_t expected = expected_op(x);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

template <typename T, typename OpType>
void RunI16x8BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       OpType expected_op) {
  WasmRunner<int32_t, T, T> r(execution_tier);
  // Global to hold output.
  T* g = r.builder().template AddGlobal<T>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  for (T x : compiler::ValueHelper::GetVector<T>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      r.Call(x, y);
      T expected = expected_op(x, y);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunI16x8BinOpTest<int16_t>(TestExecutionTier, WasmOpcode,
                                         Int16BinOp);
template void RunI16x8BinOpTest<uint16_t>(TestExecutionTier, WasmOpcode,
                                          Uint16BinOp);

void RunI16x8ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int16ShiftOp expected_op) {
  // Intentionally shift by 16, should be no-op.
  for (int shift = 1; shift <= 16; shift++) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int16_t* g_imm = r.builder().AddGlobal<int16_t>(kWasmS128);
    int16_t* g_mem = r.builder().AddGlobal<int16_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT16_INPUTS(x) {
      r.Call(x);
      int16_t expected = expected_op(x, shift);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

void RunI16x8MixedRelationalOpTest(TestExecutionTier execution_tier,
                                   WasmOpcode opcode, Int16BinOp expected_op) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_LOCAL_SET(temp3, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                                 WASM_LOCAL_GET(temp2))),
           WASM_SIMD_I16x8_EXTRACT_LANE(0, WASM_LOCAL_GET(temp3))});

  CHECK_EQ(expected_op(0xffff, static_cast<uint16_t>(0x7fffffff)),
           r.Call(0xffff, 0x7fffffff));
  CHECK_EQ(expected_op(0xfeff, static_cast<uint16_t>(0x7fffffff)),
           r.Call(0xfeff, 0x7fffffff));
  CHECK_EQ(expected_op(0xffff, static_cast<uint16_t>(0x7ffffeff)),
           r.Call(0xffff, 0x7ffffeff));
}

void RunI32x4UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int32UnOp expected_op) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    r.Call(x);
    int32_t expected = expected_op(x);
    for (int i = 0; i < 4; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

void RunI32x4BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       Int32BinOp expected_op) {
  WasmRunner<int32_t, int32_t, int32_t> r(execution_tier);
  // Global to hold output.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_INT32_INPUTS(x) {
    FOR_INT32_INPUTS(y) {
      r.Call(x, y);
      int32_t expected = expected_op(x, y);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

void RunI32x4ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int32ShiftOp expected_op) {
  // Intentionally shift by 32, should be no-op.
  for (int shift = 1; shift <= 32; shift++) {
    WasmRunner<int32_t, int32_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int32_t* g_imm = r.builder().AddGlobal<int32_t>(kWasmS128);
    int32_t* g_mem = r.builder().AddGlobal<int32_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT32_INPUTS(x) {
      r.Call(x);
      int32_t expected = expected_op(x, shift);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

void RunI64x2UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      Int64UnOp expected_op) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  // Global to hold output.
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_INT64_INPUTS(x) {
    r.Call(x);
    int64_t expected = expected_op(x);
    for (int i = 0; i < 2; i++) {
      CHECK_EQ(expected, LANE(g, i));
    }
  }
}

void RunI64x2BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       Int64BinOp expected_op) {
  WasmRunner<int32_t, int64_t, int64_t> r(execution_tier);
  // Global to hold output.
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_INT64_INPUTS(x) {
    FOR_INT64_INPUTS(y) {
      r.Call(x, y);
      int64_t expected = expected_op(x, y);
      for (int i = 0; i < 2; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

void RunI64x2ShiftOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                         Int64ShiftOp expected_op) {
  // Intentionally shift by 64, should be no-op.
  for (int shift = 1; shift <= 64; shift++) {
    WasmRunner<int32_t, int64_t> r(execution_tier);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(1);
    int64_t* g_imm = r.builder().AddGlobal<int64_t>(kWasmS128);
    int64_t* g_mem = r.builder().AddGlobal<int64_t>(kWasmS128);
    uint8_t value = 0;
    uint8_t simd = r.AllocateLocal(kWasmS128);
    // Shift using an immediate, and shift using a value loaded from memory.
    r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(value))),
             WASM_GLOBAL_SET(0, WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(simd),
                                                   WASM_I32V(shift))),
             WASM_GLOBAL_SET(
                 1, WASM_SIMD_SHIFT_OP(
                        opcode, WASM_LOCAL_GET(simd),
                        WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO))),
             WASM_ONE});

    r.builder().WriteMemory(&memory[0], shift);
    FOR_INT64_INPUTS(x) {
      r.Call(x);
      int64_t expected = expected_op(x, shift);
      for (int i = 0; i < 2; i++) {
        CHECK_EQ(expected, LANE(g_imm, i));
        CHECK_EQ(expected, LANE(g_mem, i));
      }
    }
  }
}

bool IsCanonical(uint16_t actual) {
  // Canonical NaN has quiet bit and no payload.
  return isnan(actual) && (actual & 0xFE00) == actual;
}

bool isnan(uint16_t f) { return (f & 0x7C00) == 0x7C00 && (f & 0x03FF); }

void CheckFloat16LaneResult(float x, float y, uint16_t expected,
                            uint16_t actual, bool exact) {
  CheckFloat16LaneResult(x, y, y, expected, actual, exact);
}

void CheckFloat16LaneResult(float x, float y, float z, uint16_t expected,
                            uint16_t actual, bool exact) {
  if (isnan(expected)) {
    CHECK(isnan(actual));
    if (std::isnan(x) && IsSameNan(fp16_ieee_from_fp32_value(x), actual)) {
      return;
    }
    if (std::isnan(y) && IsSameNan(fp16_ieee_from_fp32_value(y), actual)) {
      return;
    }
    if (std::isnan(z) && IsSameNan(fp16_ieee_from_fp32_value(z), actual)) {
      return;
    }
    if (IsSameNan(expected, actual)) return;
    if (IsCanonical(actual)) return;
    // This is expected to assert; it's useful for debugging.
    CHECK_EQ(expected, actual);
  } else {
    if (exact) {
      CHECK_EQ(expected, actual);
      return;
    }
    // Otherwise, perform an approximate equality test. First check for
    // equality to handle +/-Infinity where approximate equality doesn't work.
    if (expected == actual) return;

    // 1% error allows all platforms to pass easily.
    constexpr float kApproximationError = 0.01f;
    float f32_expected = fp16_ieee_to_fp32_value(expected);
    float f32_actual = fp16_ieee_to_fp32_value(actual);
    float abs_error = std::abs(f32_expected) * kApproximationError;
    float min = f32_expected - abs_error;
    float max = f32_expected + abs_error;
    CHECK_LE(min, f32_actual);
    CHECK_GE(max, f32_actual);
  }
}

void RunF16x8UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      HalfUnOp expected_op, bool exact) {
  WasmRunner<int32_t, float> r(execution_tier);
  // Global to hold output.
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    // Extreme values have larger errors so skip them for approximation tests.
    if (!exact && IsExtreme(x)) continue;
    uint16_t expected = expected_op(fp16_ieee_from_fp32_value(x));
    if (!PlatformCanRepresent(expected)) continue;
    r.Call(x);
    for (int i = 0; i < 8; i++) {
      uint16_t actual = LANE(g, i);
      CheckFloat16LaneResult(x, x, expected, actual, exact);
    }
  }
}

void RunF16x8BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       HalfBinOp expected_op) {
  WasmRunner<int32_t, float, float> r(execution_tier);
  // Global to hold output.
  uint16_t* g = r.builder().AddGlobal<uint16_t>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT32_INPUTS(y) {
      if (!PlatformCanRepresent(y)) continue;
      uint16_t expected = expected_op(fp16_ieee_from_fp32_value(x),
                                      fp16_ieee_from_fp32_value(y));
      if (!PlatformCanRepresent(expected)) continue;
      r.Call(x, y);
      for (int i = 0; i < 8; i++) {
        uint16_t actual = LANE(g, i);
        CheckFloat16LaneResult(x, y, expected, actual, true /* exact */);
      }
    }
  }
}

void RunF16x8CompareOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                           HalfCompareOp expected_op) {
  WasmRunner<int32_t, float, float> r(execution_tier);
  // Set up global to hold mask output.
  int16_t* g = r.builder().AddGlobal<int16_t>(kWasmS128);
  // Build fn to splat test values, perform compare op, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_F16x8_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT32_INPUTS(y) {
      if (!PlatformCanRepresent(y)) continue;
      float diff = x - y;  // Model comparison as subtraction.
      if (!PlatformCanRepresent(diff)) continue;
      r.Call(x, y);
      int16_t expected = expected_op(fp16_ieee_from_fp32_value(x),
                                     fp16_ieee_from_fp32_value(y));
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

bool IsExtreme(float x) {
  float abs_x = std::fabs(x);
  const float kSmallFloatThreshold = 1.0e-32f;
  const float kLargeFloatThreshold = 1.0e32f;
  return abs_x != 0.0f &&  // 0 or -0 are fine.
         (abs_x < kSmallFloatThreshold || abs_x > kLargeFloatThreshold);
}

bool IsCanonical(float actual) {
  uint32_t actual_bits = base::bit_cast<uint32_t>(actual);
  // Canonical NaN has quiet bit and no payload.
  return (actual_bits & 0xFFC00000) == actual_bits;
}

void CheckFloatResult(float x, float y, float expected, float actual,
                      bool exact) {
  if (std::isnan(expected)) {
    CHECK(std::isnan(actual));
    if (std::isnan(x) && IsSameNan(x, actual)) return;
    if (std::isnan(y) && IsSameNan(y, actual)) return;
    if (IsSameNan(expected, actual)) return;
    if (IsCanonical(actual)) return;
    // This is expected to assert; it's useful for debugging.
    CHECK_EQ(base::bit_cast<uint32_t>(expected),
             base::bit_cast<uint32_t>(actual));
  } else {
    if (exact) {
      CHECK_EQ(expected, actual);
      // The sign of 0's must match.
      CHECK_EQ(std::signbit(expected), std::signbit(actual));
      return;
    }
    // Otherwise, perform an approximate equality test. First check for
    // equality to handle +/-Infinity where approximate equality doesn't work.
    if (expected == actual) return;

    // 1% error allows all platforms to pass easily.
    constexpr float kApproximationError = 0.01f;
    float abs_error = std::abs(expected) * kApproximationError;
    float min = expected - abs_error;
    float max = expected + abs_error;
    CHECK_LE(min, actual);
    CHECK_GE(max, actual);
  }
}

void RunF32x4UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      FloatUnOp expected_op, bool exact) {
  WasmRunner<int32_t, float> r(execution_tier);
  // Global to hold output.
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    // Extreme values have larger errors so skip them for approximation tests.
    if (!exact && IsExtreme(x)) continue;
    float expected = expected_op(x);
#if V8_OS_AIX
    if (!MightReverseSign<FloatUnOp>(expected_op))
      expected = FpOpWorkaround<float>(x, expected);
#endif
    if (!PlatformCanRepresent(expected)) continue;
    r.Call(x);
    for (int i = 0; i < 4; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x, x, expected, actual, exact);
    }
  }

  FOR_FLOAT32_NAN_INPUTS(f) {
    float x = base::bit_cast<float>(nan_test_array[f]);
    if (!PlatformCanRepresent(x)) continue;
    // Extreme values have larger errors so skip them for approximation tests.
    if (!exact && IsExtreme(x)) continue;
    float expected = expected_op(x);
    if (!PlatformCanRepresent(expected)) continue;
    r.Call(x);
    for (int i = 0; i < 4; i++) {
      float actual = LANE(g, i);
      CheckFloatResult(x, x, expected, actual, exact);
    }
  }
}

namespace {
// Relaxed-simd operations are deterministic only for some range of values.
// Exclude those from being tested. Currently this is only used for f32x4, f64x2
// relaxed min and max.
template <typename T>
typename std::enable_if<std::is_floating_point<T>::value, bool>::type
ShouldSkipTestingConstants(WasmOpcode opcode, T lhs, T rhs) {
  bool has_nan = std::isnan(lhs) || std::isnan(rhs);
  bool zeroes_of_opposite_signs =
      (lhs == 0 && rhs == 0 && (std::signbit(lhs) != std::signbit(rhs)));
  return WasmOpcodes::IsRelaxedSimdOpcode(opcode) &&
         (has_nan || zeroes_of_opposite_signs);
}
}  // namespace

void RunF32x4BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       FloatBinOp expected_op) {
  WasmRunner<int32_t, float, float> r(execution_tier);
  // Global to hold output.
  float* g = r.builder().AddGlobal<float>(kWasmS128);
  // Build fn to splat test values, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT32_INPUTS(y) {
      if (!PlatformCanRepresent(y)) continue;
      if (ShouldSkipTestingConstants(opcode, x, y)) continue;
      float expected = expected_op(x, y);
      if (!PlatformCanRepresent(expected)) continue;
      r.Call(x, y);
      for (int i = 0; i < 4; i++) {
        float actual = g[i];
        CheckFloatResult(x, y, expected, actual, true /* exact */);
      }
    }
  }

  FOR_FLOAT32_NAN_INPUTS(f) {
    float x = base::bit_cast<float>(nan_test_array[f]);
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT32_NAN_INPUTS(j) {
      float y = base::bit_cast<float>(nan_test_array[j]);
      if (!PlatformCanRepresent(y)) continue;
      if (ShouldSkipTestingConstants(opcode, x, y)) continue;
      float expected = expected_op(x, y);
      if (!PlatformCanRepresent(expected)) continue;
      r.Call(x, y);
      for (int i = 0; i < 4; i++) {
        float actual = LANE(g, i);
        CheckFloatResult(x, y, expected, actual, true /* exact */);
      }
    }
  }
}

void RunF32x4CompareOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                           FloatCompareOp expected_op) {
  WasmRunner<int32_t, float, float> r(execution_tier);
  // Set up global to hold mask output.
  int32_t* g = r.builder().AddGlobal<int32_t>(kWasmS128);
  // Build fn to splat test values, perform compare op, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT32_INPUTS(y) {
      if (!PlatformCanRepresent(y)) continue;
      float diff = x - y;  // Model comparison as subtraction.
      if (!PlatformCanRepresent(diff)) continue;
      r.Call(x, y);
      int32_t expected = expected_op(x, y);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, LANE(g, i));
      }
    }
  }
}

bool IsExtreme(double x) {
  double abs_x = std::fabs(x);
  const double kSmallFloatThreshold = 1.0e-298;
  const double kLargeFloatThreshold = 1.0e298;
  return abs_x != 0.0f &&  // 0 or -0 are fine.
         (abs_x < kSmallFloatThreshold || abs_x > kLargeFloatThreshold);
}

bool IsCanonical(double actual) {
  uint64_t actual_bits = base::bit_cast<uint64_t>(actual);
  // Canonical NaN has quiet bit and no payload.
  return (actual_bits & 0xFFF8000000000000) == actual_bits;
}

void CheckDoubleResult(double x, double y, double expected, double actual,
                       bool exact) {
  if (std::isnan(expected)) {
    CHECK(std::isnan(actual));
    if (std::isnan(x) && IsSameNan(x, actual)) return;
    if (std::isnan(y) && IsSameNan(y, actual)) return;
    if (IsSameNan(expected, actual)) return;
    if (IsCanonical(actual)) return;
    // This is expected to assert; it's useful for debugging.
    CHECK_EQ(base::bit_cast<uint64_t>(expected),
             base::bit_cast<uint64_t>(actual));
  } else {
    if (exact) {
      CHECK_EQ(expected, actual);
      // The sign of 0's must match.
      CHECK_EQ(std::signbit(expected), std::signbit(actual));
      return;
    }
    // Otherwise, perform an approximate equality test. First check for
    // equality to handle +/-Infinity where approximate equality doesn't work.
    if (expected == actual) return;

    // 1% error allows all platforms to pass easily.
    constexpr double kApproximationError = 0.01f;
    double abs_error = std::abs(expected) * kApproximationError,
           min = expected - abs_error, max = expected + abs_error;
    CHECK_LE(min, actual);
    CHECK_GE(max, actual);
  }
}

void RunF64x2UnOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                      DoubleUnOp expected_op, bool exact) {
  WasmRunner<int32_t, double> r(execution_tier);
  // Global to hold output.
  double* g = r.builder().AddGlobal<double>(kWasmS128);
  // Build fn to splat test value, perform unop, and write the result.
  uint8_t value = 0;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(0, WASM_SIMD_UNOP(opcode, WASM_LOCAL_GET(temp1))),
           WASM_ONE});

  FOR_FLOAT64_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    // Extreme values have larger errors so skip them for approximation tests.
    if (!exact && IsExtreme(x)) continue;
    double expected = expected_op(x);
#if V8_OS_AIX
    if (!MightReverseSign<DoubleUnOp>(expected_op))
      expected = FpOpWorkaround<double>(x, expected);
#endif
    if (!PlatformCanRepresent(expected)) continue;
    r.Call(x);
    for (int i = 0; i < 2; i++) {
      double actual = LANE(g, i);
      CheckDoubleResult(x, x, expected, actual, exact);
    }
  }

  FOR_FLOAT64_NAN_INPUTS(d) {
    double x = base::bit_cast<double>(double_nan_test_array[d]);
    if (!PlatformCanRepresent(x)) continue;
    // Extreme values have larger errors so skip them for approximation tests.
    if (!exact && IsExtreme(x)) continue;
    double expected = expected_op(x);
    if (!PlatformCanRepresent(expected)) continue;
    r.Call(x);
    for (int i = 0; i < 2; i++) {
      double actual = LANE(g, i);
      CheckDoubleResult(x, x, expected, actual, exact);
    }
  }
}

void RunF64x2BinOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                       DoubleBinOp expected_op) {
  WasmRunner<int32_t, double, double> r(execution_tier);
  // Global to hold output.
  double* g = r.builder().AddGlobal<double>(kWasmS128);
  // Build fn to splat test value, perform binop, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_FLOAT64_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLO
"""


```