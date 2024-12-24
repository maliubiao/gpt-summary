Response: The user wants to understand the functionality of the provided C++ code snippet, which is part 2 of a larger file. The code seems to be related to testing WebAssembly SIMD (Single Instruction, Multiple Data) operations in the V8 JavaScript engine.

Here's a breakdown of the thinking process to summarize the code:

1. **Identify the Core Purpose:** The code defines several template functions (like `RunF64x2BinOpRevecTest`, `RunI8x32UnOpRevecTest`, etc.) that seem to be involved in running tests for specific WebAssembly SIMD operations. The "Revec" in the function names likely indicates a focus on "revectorization," an optimization technique.

2. **Analyze the Function Signatures:** Look at the parameters of these functions. They typically take a `WasmOpcode`, and often an `expected_op` (a function pointer) and a `compiler::IrOpcode::Value` named `revec_opcode`. This confirms the idea of testing specific WASM operations, comparing the actual result with an expected result, and likely targeting a specific internal representation (`IrOpcode`).

3. **Examine the Function Bodies:**  The functions follow a similar pattern:
    * **Feature Check:** They often start with `EXPERIMENTAL_FLAG_SCOPE(revectorize)` and a check for `CpuFeatures::IsSupported(AVX2)` or `CpuFeatures::IsSupported(AVX)`. This indicates that the tests are for SIMD instructions that rely on specific CPU features.
    * **`WasmRunner` Setup:** They create a `WasmRunner` object. This is a V8 testing utility for executing WebAssembly code. The template arguments specify the signature of the WASM function being tested.
    * **Memory Allocation:** They allocate memory using `r.builder().AddMemoryElems()`. This memory is used to store input values and the results of the WASM operation.
    * **WASM Code Construction:**  They use `r.builder()` to construct the WebAssembly code for the test. This involves:
        * Loading data from memory (`WASM_SIMD_LOAD_MEM`, `WASM_SIMD_LOAD_MEM_OFFSET`).
        * Performing the SIMD operation using `WASM_SIMD_UNOP` or `WASM_SIMD_BINOP` with the provided `opcode`.
        * Storing the result back to memory (`WASM_SIMD_STORE_MEM`, `WASM_SIMD_STORE_MEM_OFFSET`).
    * **Input Generation and Execution:** They use `FOR_..._INPUTS` macros to generate various input values for the WASM function. Then, `r.Call()` executes the generated WASM code.
    * **Result Verification:** They use `CHECK_EQ` or `CheckDoubleResult` to compare the actual result in memory with the expected result calculated by `expected_op`.
    * **Revectorization Assertion:** The `TSSimd256VerifyScope` with `BUILD_AND_CHECK_REVEC_NODE` seems to be a way to verify that the compiler correctly applied the "revectorization" optimization.

4. **Identify Common Themes and Patterns:**  Notice the repeated structure across the different `Run...RevecTest` functions. This suggests they are part of a testing framework for different categories of SIMD operations (binary, unary, conversions, etc.) and data types (float64, int8, int32, etc.). The use of templates allows for code reuse across different types.

5. **Connect to JavaScript (if applicable):**  The tests are for *WebAssembly* SIMD, which is directly related to JavaScript's `WebAssembly` API and its SIMD features. Think about how these WASM operations would be exposed in JavaScript. For instance, a `f64x2.add` WASM instruction would correspond to operations on `Float64x2` typed arrays in JavaScript.

6. **Formulate the Summary:** Combine the observations into a concise description of the file's purpose. Emphasize the testing aspect, the focus on SIMD operations and vectorization, and the connection to WebAssembly.

7. **Create JavaScript Examples:**  Based on the understanding of the WASM operations being tested, provide simple JavaScript examples that demonstrate equivalent functionality using `WebAssembly.Module`, `WebAssembly.Instance`, and typed arrays like `Float64Array`.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is this just about basic SIMD testing?
* **Correction:** The "Revec" and the `TSSimd256VerifyScope` point to a specific focus on *revectorization* testing, not just general SIMD functionality.
* **Initial thought:**  How do these C++ tests relate to actual WASM bytecode?
* **Refinement:** The `WasmRunner` is responsible for generating the WASM bytecode internally based on the builder API calls. The C++ code specifies the *logic* of the WASM code to be tested, not the raw bytecode.
* **Initial thought:** Just describe the C++ code.
* **Refinement:** The prompt specifically asks about the connection to JavaScript, so including illustrative JavaScript examples is crucial.

By following these steps, we can arrive at the summary and JavaScript examples provided in the initial good answer.Based on the provided C++ code snippet from `v8/test/cctest/wasm/wasm-simd-utils.cc`, this part of the file focuses on defining **template functions for testing WebAssembly SIMD (Single Instruction, Multiple Data) operations, specifically those involving "revectorization".**

Here's a breakdown of the functionalities:

* **Testing Binary Operations on `f64x2` (two 64-bit floats):** The `RunF64x2BinOpRevecTest` function tests binary operations (like addition, subtraction, multiplication, etc.) on `f64x2` SIMD vectors.
    * It uses a `WasmRunner` to create and execute a WebAssembly function.
    * It allocates memory to store input values and the result.
    * It constructs the WebAssembly code to load two `f64x2` vectors from memory, perform the specified binary operation (`opcode`), and store the result back to memory.
    * It iterates through various combinations of `double` inputs (including regular values and NaNs).
    * It calls the generated WebAssembly function and then uses `CheckDoubleResult` to verify that the computed result matches the expected result calculated by the `expected_op` function (a C++ function representing the same operation).
    * The `EXPERIMENTAL_FLAG_SCOPE(revectorize)` and the `TSSimd256VerifyScope` along with `BUILD_AND_CHECK_REVEC_NODE` indicate that this test specifically checks if the compiler correctly applies "revectorization" optimizations for these SIMD operations, likely targeting 256-bit SIMD instructions (AVX2).

* **Testing Unary Operations on `i8x32` (thirty-two 8-bit integers) with Revectorization:** The `RunI8x32UnOpRevecTest` function tests unary operations on `i8x32` SIMD vectors.
    * Similar to the binary operation test, it sets up a `WasmRunner`, allocates memory, and builds WebAssembly code.
    * The code loads an `i8x32` vector, performs the unary operation, and stores the result.
    * It iterates through various `int8_t` inputs.
    * It calls the WebAssembly function and verifies the result.
    * It also uses the `TSSimd256VerifyScope` to ensure proper revectorization.

* **Testing Conversions between `i32x8`/`u32x8` and `f32x8` with Revectorization:** The `RunI32x8ConvertF32x8RevecTest` and `RunF32x8ConvertI32x8RevecTest` functions test conversions between integer and floating-point SIMD vectors.
    * They check if converting a scalar float to an `i32x8` or `u32x8` (or vice-versa) and performing the operation on the splatted vector works correctly and is properly revectorized.

* **Testing Integer Sign Extensions with Revectorization:** The `RunIntSignExtensionRevecTest` function tests sign extension operations on integer SIMD vectors (e.g., extending `i16x8` to `i32x4`).
    * It checks if the sign extension is performed correctly when revectorization is applied.

* **Testing Integer Narrowing Conversions with Revectorization:** The `RunIntToIntNarrowingRevecTest` function tests narrowing conversions between integer SIMD vectors (e.g., narrowing `i32x4` to `i16x8`).
    * It verifies the correct narrowing and saturation behavior with revectorization.

**Relationship to JavaScript:**

These C++ tests are crucial for ensuring the correctness and performance of WebAssembly SIMD operations when executed in a JavaScript environment like V8. WebAssembly SIMD provides a way to perform parallel computations on vectors of data, which can significantly speed up certain types of JavaScript applications.

**JavaScript Examples:**

While the C++ code is testing the *implementation* of these operations, the functionality it tests directly corresponds to the use of WebAssembly SIMD instructions that can be exposed and utilized within JavaScript.

For example, the `RunF64x2BinOpRevecTest` function testing addition (`kExprF64x2Add`) would relate to the following conceptual JavaScript usage (though the exact API might differ slightly depending on the specific WebAssembly features and JavaScript API being used):

```javascript
// Assume you have a WebAssembly module instance with a memory and an exported function.

// Create Float64Arrays to represent the input vectors
const a = new Float64Array([1.5, 2.5]);
const b = new Float64Array([3.0, 4.0]);
const result = new Float64Array(2);

// Write the input values to WebAssembly memory (assuming you know the memory layout)
const memory = wasmInstance.exports.memory.buffer;
const a_offset = 0; // Example offset
const b_offset = 16; // Example offset
const result_offset = 32; // Example offset

new Float64Array(memory, a_offset, 2).set(a);
new Float64Array(memory, b_offset, 2).set(b);

// Call the WebAssembly function that performs the f64x2.add operation
wasmInstance.exports.myAddF64x2(a_offset, b_offset, result_offset);

// Read the result from WebAssembly memory
const resultArray = new Float64Array(memory, result_offset, 2);

console.log(resultArray); // Expected output: Float64Array [ 4.5, 6.5 ]
```

Similarly, the integer conversion tests would relate to WebAssembly instructions that can be used to convert between integer and floating-point SIMD types, which would be used within JavaScript when working with typed arrays and WebAssembly.

In summary, this part of the C++ file is dedicated to thoroughly testing the implementation of WebAssembly SIMD operations within V8, particularly focusing on ensuring that compiler optimizations like revectorization are applied correctly and that the operations produce the expected results. This directly impacts the performance and correctness of WebAssembly code running in JavaScript environments.

Prompt: 
```
这是目录为v8/test/cctest/wasm/wasm-simd-utils.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""

    FOR_FLOAT64_INPUTS(y) {
      if (!PlatformCanRepresent(y)) continue;
      if (ShouldSkipTestingConstants(opcode, x, y)) continue;
      double expected = expected_op(x, y);
      if (!PlatformCanRepresent(expected)) continue;
      for (int i = 0; i < 2; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 2], x);
        r.builder().WriteMemory(&memory[i + 4], y);
        r.builder().WriteMemory(&memory[i + 6], y);
      }
      r.Call(0, 32, 64);
      for (int i = 0; i < 2; i++) {
        CheckDoubleResult(x, y, expected, memory[i + 8], true /* exact */);
        CheckDoubleResult(x, y, expected, memory[i + 10], true /* exact */);
      }
    }
  }

  FOR_FLOAT64_NAN_INPUTS(f) {
    double x = base::bit_cast<double>(double_nan_test_array[f]);
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT64_NAN_INPUTS(j) {
      double y = base::bit_cast<double>(double_nan_test_array[j]);
      if (!PlatformCanRepresent(y)) continue;
      if (ShouldSkipTestingConstants(opcode, x, y)) continue;
      double expected = expected_op(x, y);
      if (!PlatformCanRepresent(expected)) continue;
      for (int i = 0; i < 2; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 2], x);
        r.builder().WriteMemory(&memory[i + 4], y);
        r.builder().WriteMemory(&memory[i + 6], y);
      }
      r.Call(0, 32, 64);
      for (int i = 0; i < 2; i++) {
        CheckDoubleResult(x, y, expected, memory[i + 8], true /* exact */);
        CheckDoubleResult(x, y, expected, memory[i + 10], true /* exact */);
      }
    }
  }
}

void RunI8x32UnOpRevecTest(WasmOpcode opcode, Int8UnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(64);
  // Build fn to load an I8x32 vector with test value, perform unop, and write
  // the result to another array.
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Unary>);

    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(
            temp1,
            WASM_SIMD_UNOP(opcode, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)))),
        WASM_LOCAL_SET(
            temp2, WASM_SIMD_UNOP(opcode, WASM_SIMD_LOAD_MEM_OFFSET(
                                              offset, WASM_LOCAL_GET(param1)))),
        WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp1)),
        WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                   WASM_LOCAL_GET(temp2)),
        WASM_ONE);
  }
  FOR_INT8_INPUTS(x) {
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[18], x);
    r.Call(0, 32);
    int8_t expected = expected_op(x);
    CHECK_EQ(expected, memory[33]);
    CHECK_EQ(expected, memory[50]);
  }
}

template <typename IntType>
void RunI32x8ConvertF32x8RevecTest(WasmOpcode opcode,
                                   ConvertToIntOp expected_op,
                                   compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, float> r(TestExecutionTier::kTurbofan);
  IntType* memory = r.builder().AddMemoryElems<IntType>(8);
  uint8_t param1 = 0;
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Unary>);
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_SIMD_STORE_MEM(
            WASM_ZERO,
            WASM_SIMD_UNOP(opcode, WASM_SIMD_UNOP(kExprF32x4Splat,
                                                  WASM_LOCAL_GET(param1)))),
        WASM_SIMD_STORE_MEM_OFFSET(
            offset, WASM_ZERO,
            WASM_SIMD_UNOP(opcode, WASM_SIMD_UNOP(kExprF32x4Splat,
                                                  WASM_LOCAL_GET(param1)))),
        WASM_ONE);
  }
  bool is_unsigned = std::is_same_v<IntType, uint32_t>;
  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    CHECK_EQ(1, r.Call(x));
    IntType expected_value = expected_op(x, is_unsigned);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_value, memory[i]);
    }
  }
}

// Explicit instantiations of uses.
template void RunI32x8ConvertF32x8RevecTest<int32_t>(WasmOpcode, ConvertToIntOp,
                                                     compiler::IrOpcode::Value);
template void RunI32x8ConvertF32x8RevecTest<uint32_t>(
    WasmOpcode, ConvertToIntOp, compiler::IrOpcode::Value);

template <typename IntType>
void RunF32x8ConvertI32x8RevecTest(WasmOpcode opcode,
                                   compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(8);
  uint8_t param1 = 0;
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Unary>);
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_SIMD_STORE_MEM(
            WASM_ZERO,
            WASM_SIMD_UNOP(opcode, WASM_SIMD_UNOP(kExprI32x4Splat,
                                                  WASM_LOCAL_GET(param1)))),
        WASM_SIMD_STORE_MEM_OFFSET(
            offset, WASM_ZERO,
            WASM_SIMD_UNOP(opcode, WASM_SIMD_UNOP(kExprI32x4Splat,
                                                  WASM_LOCAL_GET(param1)))),
        WASM_ONE);
  }
  bool is_unsigned = std::is_same_v<IntType, uint32_t>;
  FOR_INT32_INPUTS(x) {
    CHECK_EQ(1, r.Call(x));
    float expected_value = is_unsigned
                               ? static_cast<float>(static_cast<uint32_t>(x))
                               : static_cast<float>(x);
    for (int i = 0; i < 8; i++) {
      CHECK_EQ(expected_value, memory[i]);
    }
  }
}

// Explicit instantiations of uses.
template void RunF32x8ConvertI32x8RevecTest<uint32_t>(
    WasmOpcode, compiler::IrOpcode::Value);
template void RunF32x8ConvertI32x8RevecTest<int32_t>(WasmOpcode,
                                                     compiler::IrOpcode::Value);

template <typename NarrowIntType, typename WideIntType>
void RunIntSignExtensionRevecTest(WasmOpcode opcode_low, WasmOpcode opcode_high,
                                  WasmOpcode splat_op,
                                  compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  WideIntType* memory =
      r.builder().AddMemoryElems<WideIntType>(32 / sizeof(WideIntType));
  uint8_t param1 = 0;
  uint8_t temp = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Unary>);
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(temp, WASM_SIMD_UNOP(splat_op, WASM_LOCAL_GET(param1))),
        WASM_SIMD_STORE_MEM(WASM_ZERO,
                            WASM_SIMD_UNOP(opcode_low, WASM_LOCAL_GET(temp))),
        WASM_SIMD_STORE_MEM_OFFSET(
            offset, WASM_ZERO,
            WASM_SIMD_UNOP(opcode_high, WASM_LOCAL_GET(temp))),
        WASM_ONE);
  }
  for (NarrowIntType x : compiler::ValueHelper::GetVector<NarrowIntType>()) {
    CHECK_EQ(1, r.Call(x));
    auto expected_value = static_cast<WideIntType>(x);
    for (int i = 0; i < static_cast<int>(32 / sizeof(WideIntType)); i++) {
      CHECK_EQ(expected_value, memory[i]);
    }
  }
}

// Explicit instantiations of uses.
template void RunIntSignExtensionRevecTest<int16_t, int32_t>(
    WasmOpcode, WasmOpcode, WasmOpcode, compiler::IrOpcode::Value);
template void RunIntSignExtensionRevecTest<uint16_t, uint32_t>(
    WasmOpcode, WasmOpcode, WasmOpcode, compiler::IrOpcode::Value);
template void RunIntSignExtensionRevecTest<int32_t, int64_t>(
    WasmOpcode, WasmOpcode, WasmOpcode, compiler::IrOpcode::Value);
template void RunIntSignExtensionRevecTest<uint32_t, uint64_t>(
    WasmOpcode, WasmOpcode, WasmOpcode, compiler::IrOpcode::Value);
template void RunIntSignExtensionRevecTest<int8_t, int16_t>(
    WasmOpcode, WasmOpcode, WasmOpcode, compiler::IrOpcode::Value);
template void RunIntSignExtensionRevecTest<uint8_t, uint16_t>(
    WasmOpcode, WasmOpcode, WasmOpcode, compiler::IrOpcode::Value);

template <typename S, typename T>
void RunIntToIntNarrowingRevecTest(WasmOpcode opcode,
                                   compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  static_assert(sizeof(S) == 2 * sizeof(T),
                "the element size of dst vector must be half of src vector in "
                "integer to integer narrowing");
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  uint32_t count = 6 * kSimd128Size / sizeof(S);
  S* memory = r.builder().AddMemoryElems<S>(count);
  // Build fn perform binary operation on two 256 bit vectors a and b,
  // store the result in c:
  //   simd128 *a,*b,*c;
  //   *c = *a bin_op *b;
  //   *(c+1) = *(a+1) bin_op *(b+1);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Binop>);

    r.Build(
        {WASM_LOCAL_SET(
             temp1,
             WASM_SIMD_BINOP(opcode, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                             WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)))),
         WASM_LOCAL_SET(
             temp2,
             WASM_SIMD_BINOP(
                 opcode,
                 WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1)),
                 WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param2)))),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param3), WASM_LOCAL_GET(temp1)),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param3),
                                    WASM_LOCAL_GET(temp2)),
         WASM_ONE});
  }

  constexpr uint32_t lanes = kSimd128Size / sizeof(S);
  for (S x : compiler::ValueHelper::GetVector<S>()) {
    for (S y : compiler::ValueHelper::GetVector<S>()) {
      for (uint32_t i = 0; i < lanes; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + lanes], x);
        r.builder().WriteMemory(&memory[i + lanes * 2], y);
        r.builder().WriteMemory(&memory[i + lanes * 3], y);
      }
      r.Call(0, 32, 64);
      T expected_x = base::saturated_cast<T>(x);
      T expected_y = base::saturated_cast<T>(y);
      T* output = reinterpret_cast<T*>(memory + lanes * 4);
      for (uint32_t i = 0; i < lanes; i++) {
        CHECK_EQ(expected_x, output[i]);
        CHECK_EQ(expected_y, output[i + lanes]);
        CHECK_EQ(expected_x, output[i + lanes * 2]);
        CHECK_EQ(expected_y, output[i + lanes * 3]);
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunIntToIntNarrowingRevecTest<int32_t, int16_t>(
    WasmOpcode, compiler::IrOpcode::Value revec_opcode);
template void RunIntToIntNarrowingRevecTest<int32_t, uint16_t>(
    WasmOpcode, compiler::IrOpcode::Value revec_opcode);
template void RunIntToIntNarrowingRevecTest<int16_t, int8_t>(
    WasmOpcode, compiler::IrOpcode::Value revec_opcode);
template void RunIntToIntNarrowingRevecTest<int16_t, uint8_t>(
    WasmOpcode, compiler::IrOpcode::Value revec_opcode);
#endif  // V8_ENABLE_WASM_SIMD256_REVEC

}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""


```