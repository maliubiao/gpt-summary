Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/test/cctest/wasm/wasm-simd-utils.cc`.

Here's a plan to address the request:

1. **Identify the core purpose:** The code appears to be testing WebAssembly SIMD (Single Instruction, Multiple Data) operations.
2. **Analyze the functions:**  Break down the code into individual test functions and understand what each one does. Look for patterns in the function names (e.g., `RunF64x2BinOpTest`, `RunI8x32BinOpRevecTest`).
3. **Identify key components:** Look for common elements like `WasmRunner`, `WasmOpcode`, input generation (`FOR_FLOAT64_INPUTS`), expected vs. actual results, and the use of globals and memory.
4. **Explain the role of "Revec":**  The presence of "Revec" in function names suggests a focus on testing vectorized operations, specifically for 256-bit SIMD.
5. **Connect to WebAssembly and SIMD:** Explain how the code relates to testing the correctness of WebAssembly SIMD instructions.
6. **Address the specific instructions:** Check if it's a `.tq` file, if it relates to JavaScript, provide JavaScript examples if possible, give input/output examples where logical reasoning is involved, and illustrate common programming errors.
7. **Summarize the functionality:**  Provide a concise overview of the code's purpose.
这是提供的v8源代码 `v8/test/cctest/wasm/wasm-simd-utils.cc` 的一部分，主要功能是 **测试 WebAssembly SIMD (Single Instruction, Multiple Data) 指令的正确性**。更具体地说，它包含了一系列用于测试不同 SIMD 操作的 C++ 函数。

以下是代码片段中各个函数的功能归纳：

**1. `RunF64x2BinOpTest`**:

*   **功能**: 测试对 `float64x2` (包含两个 64 位浮点数的 SIMD 向量) 执行二元操作 (例如加法、减法等) 的结果是否正确。
*   **测试方法**:
    *   使用 `WasmRunner` 创建一个 WebAssembly 函数，该函数接收两个 `double` 类型的输入。
    *   在 WebAssembly 函数中，将这两个输入组合成 `float64x2` 向量，执行指定的二元操作 (`opcode`)，并将结果存储在一个全局变量中。
    *   C++ 代码生成各种 `double` 类型的输入组合 (包括正常的浮点数和 NaN)。
    *   对于每种输入组合，调用 WebAssembly 函数，并从全局变量中读取结果。
    *   将 WebAssembly 函数的实际结果与 C++ 代码中预期的结果 (`expected_op`) 进行比较，使用 `CheckDoubleResult` 进行精确比较。
*   **代码逻辑推理 (假设输入与输出)**:
    *   **假设输入**: `x = 3.0`, `y = 2.0`, `opcode` 代表加法。
    *   **预期输出**: WebAssembly 函数会将 `3.0` 和 `2.0` 打包成一个 `float64x2` 向量，然后执行加法操作。全局变量 `g` 的两个 lane 应该分别为 `3.0 + 3.0 = 6.0` 和 `2.0 + 2.0 = 4.0` (因为代码中使用了 `WASM_SIMD_F64x2_SPLAT` 将输入值复制到向量的两个 lane)。
*   **用户常见的编程错误 (在编写 WebAssembly 或使用 SIMD 时)**:
    *   **类型不匹配**: 将整数类型的操作应用于浮点数类型的向量，或者反之。例如，尝试对 `float64x2` 向量执行按位与操作。
    *   **lane 索引错误**: 访问向量中不存在的 lane。例如，对于 `float64x2` 向量，有效的 lane 索引只有 0 和 1。
    *   **未处理 NaN**: 浮点数运算中未正确处理 NaN (Not a Number) 值，导致程序出现意外结果。

**2. `RunF64x2CompareOpTest`**:

*   **功能**: 测试 `float64x2` 向量的比较操作 (例如大于、小于、等于)。比较操作的结果是一个掩码，指示向量的哪些 lane 满足比较条件。
*   **测试方法**:
    *   创建一个 WebAssembly 函数，该函数接收两个 `double` 输入。
    *   在 WebAssembly 函数中，创建两个 `float64x2` 向量 `temp1` 和 `temp2`。`temp1` 的两个 lane 分别设置为 `y` 和 `x`，`temp2` 的两个 lane 都设置为 `y`。
    *   执行比较操作 (`opcode`)，比较 `temp1` 和 `temp2`，并将结果掩码存储在全局变量 `g` 中。
    *   C++ 代码生成各种 `double` 输入组合。
    *   对于每种输入组合，调用 WebAssembly 函数，并检查全局变量 `g` 中的掩码值是否与预期一致。
*   **代码逻辑推理 (假设输入与输出)**:
    *   **假设输入**: `x = 5.0`, `y = 3.0`, `opcode` 代表大于比较。
    *   **预期输出**:
        *   `temp1` 的 lane 0 为 3.0，lane 1 为 5.0。
        *   `temp2` 的 lane 0 为 3.0，lane 1 为 3.0。
        *   比较 `temp1 > temp2`：
            *   lane 0: `3.0 > 3.0` 为假 (0)。
            *   lane 1: `5.0 > 3.0` 为真 (通常用全 1 表示，例如 `0xFFFFFFFFFFFFFFFF`)。
        *   全局变量 `g` 的 lane 0 应该为 0，lane 1 应该为全 1 的 64 位整数。

**3. `RunI8x32BinOpRevecTest`, `RunI16x16UnOpRevecTest`, `RunI16x16BinOpRevecTest`, `RunI16x16ShiftOpRevecTest`, `RunI32x8UnOpRevecTest`, `RunI32x8BinOpRevecTest`, `RunI32x8ShiftOpRevecTest`, `RunI64x4BinOpRevecTest`, `RunI64x4ShiftOpRevecTest`, `RunF32x8UnOpRevecTest`, `RunF32x8BinOpRevecTest`, `RunF64x4UnOpRevecTest`, `RunF64x4BinOpRevecTest`**:

*   这些函数遵循类似的模式，用于测试不同类型和宽度的 SIMD 向量的各种操作。
*   **命名模式**:
    *   `Run[数据类型][向量宽度]OpRevecTest`
    *   例如：`RunI8x32BinOpRevecTest` 表示测试 `int8x32` (包含 32 个 8 位整数的 SIMD 向量) 的二元操作，且涉及到 "Revec" (revectorization)。
*   **"Revec" 的含义**:  "Revec" 通常指 "revectorization"，这是一种编译器优化技术，用于将标量操作转换为 SIMD 操作，以提高性能。这些带有 "Revec" 的测试函数很可能专注于测试在启用向量化优化的情况下，SIMD 指令的执行是否正确。它们通常会利用 256 位的 SIMD 寄存器 (例如 AVX2 指令集)，一次处理更多的 SIMD 数据。
*   **测试方法**:
    *   与之前的测试类似，使用 `WasmRunner` 创建 WebAssembly 函数。
    *   在 WebAssembly 函数中，从内存中加载数据到 SIMD 向量，执行相应的操作 (一元、二元、移位等)，并将结果存储回内存。
    *   C++ 代码准备测试数据，写入内存，调用 WebAssembly 函数，然后从内存中读取结果。
    *   将实际结果与预期结果进行比较。
*   **涉及到的 SIMD 类型**: `i8x32`, `i16x16`, `i32x8`, `i64x4`, `f32x8`, `f64x4`。
*   **涉及到的操作**: 一元操作 (例如取反)，二元操作 (例如加法、减法)，移位操作。
*   **对 CPU 特性的依赖**: 这些带有 "Revec" 的测试通常会检查 CPU 是否支持 AVX2 等 256 位 SIMD 指令集。

**关于 `.tq` 文件和 JavaScript 的关系:**

*   你提供的代码是 `.cc` 文件，是 C++ 源代码。如果 `v8/test/cctest/wasm/wasm-simd-utils.cc` 以 `.tq` 结尾，那么它会是 V8 Torque 源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言。
*   虽然这个 C++ 文件本身不是 JavaScript 代码，但它测试的 WebAssembly SIMD 功能旨在 **与 JavaScript 中的 WebAssembly API 交互**。JavaScript 可以创建、编译和执行包含 SIMD 指令的 WebAssembly 模块。

**JavaScript 示例 (假设 `RunF64x2BinOpTest` 测试的是加法操作):**

```javascript
async function testWasmSimdAdd() {
  const buffer = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM 标头
    0x01, 0x07, 0x01, 0x00, 0x01, 0x7f,             // 导入部分 (导入一个全局变量)
    0x02, 0x09, 0x01, 0x00, 0x01, 0x7e, 0x01, 0x7e, 0x00, // 函数类型部分 (接收两个 double，返回 void)
    0x03, 0x02, 0x01, 0x00,                             // 函数导入部分
    0x04, 0x04, 0x01, 0x7b, 0x00, 0x0b,                 // 全局变量部分 (s128 类型)
    0x0a, 0x19, 0x01, 0x17, 0x00, 0x20, 0x00, 0x20, 0x01, 0xd3, 0x09, 0x00, 0x24, 0x00, 0x21, 0x00, 0x01, 0x7f, 0x0b, // 代码部分
    0x00, 0x0a, 0x08, 0x01, 0x06, 0x00, 0x3b, 0x04, 0x00, 0x00, // 导出部分
  ]);
  const module = await WebAssembly.compile(buffer);
  const globalVal = new WebAssembly.Global({ value: 'i64' }, 0n); // 创建一个全局变量
  const instance = await WebAssembly.instantiate(module, { '': { 'global': globalVal } });

  const addFunc = instance.exports.f;

  const input1 = 3.0;
  const input2 = 2.0;
  addFunc(input1, input2); // 调用 WASM 函数

  // 从全局变量中读取结果 (需要根据 WASM 代码的实现来解析 s128)
  const result = globalVal.value;
  console.log("WASM SIMD 加法结果:", result);
}

testWasmSimdAdd();
```

**请注意**: 上面的 JavaScript 代码只是一个简化的示例，用于说明 JavaScript 如何调用 WebAssembly SIMD 函数。实际的 WebAssembly 代码和结果解析会更复杂。

**归纳一下 `v8/test/cctest/wasm/wasm-simd-utils.cc` (提供的代码片段) 的功能 (作为第 2 部分的总结):**

这段 C++ 代码片段是 V8 引擎中用于测试 WebAssembly SIMD 指令功能正确性的测试代码。它定义了一系列测试函数，针对不同数据类型 (例如 `float64x2`, `int8x32`) 和操作类型 (例如二元运算、比较运算、移位运算) 的 SIMD 指令进行测试。这些测试通过创建 WebAssembly 模块，执行 SIMD 操作，并将结果与预期值进行比较来验证 V8 引擎中 SIMD 指令的实现是否正确。 特别地，带有 "Revec" 的测试函数专注于测试在启用向量化优化 (例如 AVX2) 的情况下，SIMD 指令的执行是否符合预期。虽然这段代码是 C++ 编写的，但它直接关系到 JavaScript 中 WebAssembly SIMD API 的功能和正确性。

### 提示词
```
这是目录为v8/test/cctest/wasm/wasm-simd-utils.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/wasm-simd-utils.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
AT64_INPUTS(y) {
      if (!PlatformCanRepresent(x)) continue;
      if (ShouldSkipTestingConstants(opcode, x, y)) continue;
      double expected = expected_op(x, y);
      if (!PlatformCanRepresent(expected)) continue;
      r.Call(x, y);
      for (int i = 0; i < 2; i++) {
        double actual = LANE(g, i);
        CheckDoubleResult(x, y, expected, actual, true /* exact */);
      }
    }
  }

  FOR_FLOAT64_NAN_INPUTS(d) {
    double x = base::bit_cast<double>(double_nan_test_array[d]);
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT64_NAN_INPUTS(j) {
      double y = base::bit_cast<double>(double_nan_test_array[j]);
      double expected = expected_op(x, y);
      if (!PlatformCanRepresent(expected)) continue;
      if (ShouldSkipTestingConstants(opcode, x, y)) continue;
      r.Call(x, y);
      for (int i = 0; i < 2; i++) {
        double actual = LANE(g, i);
        CheckDoubleResult(x, y, expected, actual, true /* exact */);
      }
    }
  }
}

void RunF64x2CompareOpTest(TestExecutionTier execution_tier, WasmOpcode opcode,
                           DoubleCompareOp expected_op) {
  WasmRunner<int32_t, double, double> r(execution_tier);
  // Set up global to hold mask output.
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  // Build fn to splat test values, perform compare op, and write the result.
  uint8_t value1 = 0, value2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  // Make the lanes of each temp compare differently:
  // temp1 = y, x and temp2 = y, y.
  r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value1))),
           WASM_LOCAL_SET(temp1,
                          WASM_SIMD_F64x2_REPLACE_LANE(1, WASM_LOCAL_GET(temp1),
                                                       WASM_LOCAL_GET(value2))),
           WASM_LOCAL_SET(temp2, WASM_SIMD_F64x2_SPLAT(WASM_LOCAL_GET(value2))),
           WASM_GLOBAL_SET(0, WASM_SIMD_BINOP(opcode, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
           WASM_ONE});

  FOR_FLOAT64_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT64_INPUTS(y) {
      if (!PlatformCanRepresent(y)) continue;
      double diff = x - y;  // Model comparison as subtraction.
      if (!PlatformCanRepresent(diff)) continue;
      r.Call(x, y);
      int64_t expected0 = expected_op(x, y);
      int64_t expected1 = expected_op(y, y);
      CHECK_EQ(expected0, LANE(g, 0));
      CHECK_EQ(expected1, LANE(g, 1));
    }
  }
}

#ifdef V8_ENABLE_WASM_SIMD256_REVEC
template <typename T, typename OpType>
void RunI8x32BinOpRevecTest(WasmOpcode opcode, OpType expected_op,
                            compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  T* memory = r.builder().AddMemoryElems<T>(96);
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
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(
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
        WASM_ONE);
  }
  for (T x : compiler::ValueHelper::GetVector<T>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      for (int i = 0; i < 16; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 16], x);
        r.builder().WriteMemory(&memory[i + 32], y);
        r.builder().WriteMemory(&memory[i + 48], y);
      }
      r.Call(0, 32, 64);
      T expected = expected_op(x, y);
      for (int i = 0; i < 16; i++) {
        CHECK_EQ(expected, memory[i + 64]);
        CHECK_EQ(expected, memory[i + 80]);
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunI8x32BinOpRevecTest<int8_t>(
    WasmOpcode, Int8BinOp, compiler::IrOpcode::Value revec_opcode);

template void RunI8x32BinOpRevecTest<uint8_t>(
    WasmOpcode, Uint8BinOp, compiler::IrOpcode::Value revec_opcode);

void RunI16x16UnOpRevecTest(WasmOpcode opcode, Int16UnOp expected_op,
                            compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  int16_t* memory = r.builder().AddMemoryElems<int16_t>(32);
  // Build fn to load an I16x16 vector with test value, perform unop, and write
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
  FOR_INT16_INPUTS(x) {
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[10], x);
    r.Call(0, 32);
    int16_t expected = expected_op(x);
    CHECK_EQ(expected, memory[17]);
    CHECK_EQ(expected, memory[26]);
  }
}

template <typename T, typename OpType>
void RunI16x16BinOpRevecTest(WasmOpcode opcode, OpType expected_op,
                             compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  T* memory = r.builder().AddMemoryElems<T>(48);
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
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(
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
        WASM_ONE);
  }
  for (T x : compiler::ValueHelper::GetVector<T>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      for (int i = 0; i < 8; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 8], x);
        r.builder().WriteMemory(&memory[i + 16], y);
        r.builder().WriteMemory(&memory[i + 24], y);
      }
      r.Call(0, 32, 64);
      T expected = expected_op(x, y);
      for (int i = 0; i < 8; i++) {
        CHECK_EQ(expected, memory[i + 32]);
        CHECK_EQ(expected, memory[i + 40]);
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunI16x16BinOpRevecTest<int16_t>(
    WasmOpcode, Int16BinOp, compiler::IrOpcode::Value revec_opcode);

template void RunI16x16BinOpRevecTest<uint16_t>(
    WasmOpcode, Uint16BinOp, compiler::IrOpcode::Value revec_opcode);

void RunI16x16ShiftOpRevecTest(WasmOpcode opcode, Int16ShiftOp expected_op,
                               compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  for (int shift = 1; shift <= 8; shift++) {
    WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
    int16_t* memory = r.builder().AddMemoryElems<int16_t>(34);
    // Build fn to load an I16x16 vector with test value, shift using an
    // immediate and a value loaded from memory. Write the result to another
    // array.
    uint8_t param1 = 0;
    uint8_t param2 = 1;
    uint8_t temp1 = r.AllocateLocal(kWasmI32);
    uint8_t temp2 = r.AllocateLocal(kWasmS128);
    uint8_t temp3 = r.AllocateLocal(kWasmS128);
    constexpr uint8_t offset = 16;

    {
      TSSimd256VerifyScope ts_scope(
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                        compiler::turboshaft::Opcode::kSimd256Shift>);
      BUILD_AND_CHECK_REVEC_NODE(
          r, revec_opcode,
          WASM_LOCAL_SET(temp2,
                         WASM_SIMD_SHIFT_OP(
                             opcode, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                             WASM_I32V(shift))),
          WASM_LOCAL_SET(temp3,
                         WASM_SIMD_SHIFT_OP(opcode,
                                            WASM_SIMD_LOAD_MEM_OFFSET(
                                                offset, WASM_LOCAL_GET(param1)),
                                            WASM_I32V(shift))),
          WASM_LOCAL_SET(temp1,
                         WASM_LOAD_MEM(MachineType::Int32(), WASM_I32V(64))),
          WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2),
                              WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(temp2),
                                                 WASM_LOCAL_GET(temp1))),
          WASM_SIMD_STORE_MEM_OFFSET(
              offset, WASM_LOCAL_GET(param2),
              WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(temp3),
                                 WASM_LOCAL_GET(temp1))),
          WASM_ONE);
    }
    r.builder().WriteMemory(reinterpret_cast<int32_t*>(&memory[32]), shift);
    FOR_INT16_INPUTS(x) {
      r.builder().WriteMemory(&memory[1], x);
      r.builder().WriteMemory(&memory[10], x);
      r.Call(0, 32);
      // Shift twice
      int16_t expected = expected_op(expected_op(x, shift), shift);
      CHECK_EQ(expected, memory[17]);
      CHECK_EQ(expected, memory[26]);
    }
  }
}

void RunI32x8UnOpRevecTest(WasmOpcode opcode, Int32UnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(16);
  // Build fn to load an I32x8 vector with test value, perform unop, and write
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
  FOR_INT32_INPUTS(x) {
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[6], x);
    r.Call(0, 32);
    int32_t expected = expected_op(x);
    CHECK_EQ(expected, memory[9]);
    CHECK_EQ(expected, memory[14]);
  }
}

template <typename T, typename OpType>
void RunI32x8BinOpRevecTest(WasmOpcode opcode, OpType expected_op,
                            compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  T* memory = r.builder().AddMemoryElems<T>(24);
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
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(
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
        WASM_ONE);
  }
  for (T x : compiler::ValueHelper::GetVector<T>()) {
    for (T y : compiler::ValueHelper::GetVector<T>()) {
      for (int i = 0; i < 4; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 4], x);
        r.builder().WriteMemory(&memory[i + 8], y);
        r.builder().WriteMemory(&memory[i + 12], y);
      }
      r.Call(0, 32, 64);
      T expected = expected_op(x, y);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, memory[i + 16]);
        CHECK_EQ(expected, memory[i + 20]);
      }
    }
  }
}

// Explicit instantiations of uses.
template void RunI32x8BinOpRevecTest<int32_t>(WasmOpcode, Int32BinOp,
                                              compiler::IrOpcode::Value);

template void RunI32x8BinOpRevecTest<uint32_t>(WasmOpcode, Uint32BinOp,
                                               compiler::IrOpcode::Value);

void RunI32x8ShiftOpRevecTest(WasmOpcode opcode, Int32ShiftOp expected_op,
                              compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  for (int shift = 1; shift <= 16; shift++) {
    WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
    int32_t* memory = r.builder().AddMemoryElems<int32_t>(17);
    // Build fn to load an I32x8 vector with test value, shift using an
    // immediate and a value loaded from memory. Write the result to another
    // array.
    uint8_t param1 = 0;
    uint8_t param2 = 1;
    uint8_t temp1 = r.AllocateLocal(kWasmI32);
    uint8_t temp2 = r.AllocateLocal(kWasmS128);
    uint8_t temp3 = r.AllocateLocal(kWasmS128);
    constexpr uint8_t offset = 16;

    {
      TSSimd256VerifyScope ts_scope(
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                        compiler::turboshaft::Opcode::kSimd256Shift>);
      BUILD_AND_CHECK_REVEC_NODE(
          r, revec_opcode,
          WASM_LOCAL_SET(temp2,
                         WASM_SIMD_SHIFT_OP(
                             opcode, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                             WASM_I32V(shift))),
          WASM_LOCAL_SET(temp3,
                         WASM_SIMD_SHIFT_OP(opcode,
                                            WASM_SIMD_LOAD_MEM_OFFSET(
                                                offset, WASM_LOCAL_GET(param1)),
                                            WASM_I32V(shift))),
          WASM_LOCAL_SET(temp1,
                         WASM_LOAD_MEM(MachineType::Int32(), WASM_I32V(64))),
          WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2),
                              WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(temp2),
                                                 WASM_LOCAL_GET(temp1))),
          WASM_SIMD_STORE_MEM_OFFSET(
              offset, WASM_LOCAL_GET(param2),
              WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(temp3),
                                 WASM_LOCAL_GET(temp1))),
          WASM_ONE);
    }
    r.builder().WriteMemory(&memory[16], shift);
    FOR_INT32_INPUTS(x) {
      r.builder().WriteMemory(&memory[1], x);
      r.builder().WriteMemory(&memory[6], x);
      r.Call(0, 32);
      // Shift twice
      int32_t expected = expected_op(expected_op(x, shift), shift);
      CHECK_EQ(expected, memory[9]);
      CHECK_EQ(expected, memory[14]);
    }
  }
}

void RunI64x4BinOpRevecTest(WasmOpcode opcode, Int64BinOp expected_op,
                            compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  int64_t* memory = r.builder().AddMemoryElems<int64_t>(12);
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
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(
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
        WASM_ONE);
  }
  FOR_INT64_INPUTS(x) {
    FOR_INT64_INPUTS(y) {
      for (int i = 0; i < 2; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 2], x);
        r.builder().WriteMemory(&memory[i + 4], y);
        r.builder().WriteMemory(&memory[i + 6], y);
      }
      r.Call(0, 32, 64);
      int64_t expected = expected_op(x, y);
      for (int i = 0; i < 2; i++) {
        CHECK_EQ(expected, memory[i + 8]);
        CHECK_EQ(expected, memory[i + 10]);
      }
    }
  }
}

void RunI64x4ShiftOpRevecTest(WasmOpcode opcode, Int64ShiftOp expected_op,
                              compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  for (int shift = 1; shift <= 32; shift++) {
    WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
    int64_t* memory = r.builder().AddMemoryElems<int64_t>(9);
    // Build fn to load an I64x4 vector with test value, shift using an
    // immediate and a value loaded from memory. Write the result to another
    // array.
    uint8_t param1 = 0;
    uint8_t param2 = 1;
    uint8_t temp1 = r.AllocateLocal(kWasmI32);
    uint8_t temp2 = r.AllocateLocal(kWasmS128);
    uint8_t temp3 = r.AllocateLocal(kWasmS128);
    constexpr uint8_t offset = 16;

    {
      TSSimd256VerifyScope ts_scope(
          r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                        compiler::turboshaft::Opcode::kSimd256Shift>);
      BUILD_AND_CHECK_REVEC_NODE(
          r, revec_opcode,
          WASM_LOCAL_SET(temp2,
                         WASM_SIMD_SHIFT_OP(
                             opcode, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                             WASM_I32V(shift))),
          WASM_LOCAL_SET(temp3,
                         WASM_SIMD_SHIFT_OP(opcode,
                                            WASM_SIMD_LOAD_MEM_OFFSET(
                                                offset, WASM_LOCAL_GET(param1)),
                                            WASM_I32V(shift))),
          WASM_LOCAL_SET(temp1,
                         WASM_LOAD_MEM(MachineType::Int32(), WASM_I32V(64))),
          WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2),
                              WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(temp2),
                                                 WASM_LOCAL_GET(temp1))),
          WASM_SIMD_STORE_MEM_OFFSET(
              offset, WASM_LOCAL_GET(param2),
              WASM_SIMD_SHIFT_OP(opcode, WASM_LOCAL_GET(temp3),
                                 WASM_LOCAL_GET(temp1))),
          WASM_ONE);
    }
    r.builder().WriteMemory(reinterpret_cast<int32_t*>(&memory[8]), shift);
    FOR_INT64_INPUTS(x) {
      r.builder().WriteMemory(&memory[0], x);
      r.builder().WriteMemory(&memory[3], x);
      r.Call(0, 32);
      // Shift twice
      int64_t expected = expected_op(expected_op(x, shift), shift);
      CHECK_EQ(expected, memory[4]);
      CHECK_EQ(expected, memory[7]);
    }
  }
}

void RunF32x8UnOpRevecTest(WasmOpcode opcode, FloatUnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(16);
  // Build fn to load a F32x8 vector with test value, perform unop, and write
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
  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    float expected = expected_op(x);
#if V8_OS_AIX
    if (!MightReverseSign<FloatUnOp>(expected_op))
      expected = FpOpWorkaround<float>(x, expected);
#endif
    if (!PlatformCanRepresent(expected)) continue;
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[6], x);
    r.Call(0, 32);
    CheckFloatResult(x, x, expected, memory[9]);
    CheckFloatResult(x, x, expected, memory[14]);
  }

  FOR_FLOAT32_NAN_INPUTS(f) {
    float x = base::bit_cast<float>(nan_test_array[f]);
    if (!PlatformCanRepresent(x)) continue;
    float expected = expected_op(x);
    if (!PlatformCanRepresent(expected)) continue;
    r.builder().WriteMemory(&memory[1], x);
    r.builder().WriteMemory(&memory[6], x);
    r.Call(0, 32);
    CheckFloatResult(x, x, expected, memory[9]);
    CheckFloatResult(x, x, expected, memory[14]);
  }
}

void RunF32x8BinOpRevecTest(WasmOpcode opcode, FloatBinOp expected_op,
                            compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  float* memory = r.builder().AddMemoryElems<float>(24);
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
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(
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
        WASM_ONE);
  }
  FOR_FLOAT32_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    FOR_FLOAT32_INPUTS(y) {
      if (!PlatformCanRepresent(y)) continue;
      if (ShouldSkipTestingConstants(opcode, x, y)) continue;
      float expected = expected_op(x, y);
      if (!PlatformCanRepresent(expected)) continue;
      for (int i = 0; i < 4; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 4], x);
        r.builder().WriteMemory(&memory[i + 8], y);
        r.builder().WriteMemory(&memory[i + 12], y);
      }
      r.Call(0, 32, 64);
      for (int i = 0; i < 4; i++) {
        CheckFloatResult(x, y, expected, memory[i + 16], true /* exact */);
        CheckFloatResult(x, y, expected, memory[i + 20], true /* exact */);
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
      for (int i = 0; i < 4; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 4], x);
        r.builder().WriteMemory(&memory[i + 8], y);
        r.builder().WriteMemory(&memory[i + 12], y);
      }
      r.Call(0, 32, 64);
      for (int i = 0; i < 4; i++) {
        CheckFloatResult(x, y, expected, memory[i + 16], true /* exact */);
        CheckFloatResult(x, y, expected, memory[i + 20], true /* exact */);
      }
    }
  }
}

void RunF64x4UnOpRevecTest(WasmOpcode opcode, DoubleUnOp expected_op,
                           compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  double* memory = r.builder().AddMemoryElems<double>(8);
  // Build fn to load a F64x4 vector with test value, perform unop, and write
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
  FOR_FLOAT64_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
    double expected = expected_op(x);
#if V8_OS_AIX
    if (!MightReverseSign<DoubleUnOp>(expected_op))
      expected = FpOpWorkaround<double>(x, expected);
#endif
    if (!PlatformCanRepresent(expected)) continue;
    r.builder().WriteMemory(&memory[0], x);
    r.builder().WriteMemory(&memory[3], x);
    r.Call(0, 32);
    CheckDoubleResult(x, x, expected, memory[4]);
    CheckDoubleResult(x, x, expected, memory[7]);
  }

  FOR_FLOAT64_NAN_INPUTS(d) {
    double x = base::bit_cast<double>(double_nan_test_array[d]);
    if (!PlatformCanRepresent(x)) continue;
    double expected = expected_op(x);
    if (!PlatformCanRepresent(expected)) continue;
    r.builder().WriteMemory(&memory[0], x);
    r.builder().WriteMemory(&memory[3], x);
    r.Call(0, 32);
    CheckDoubleResult(x, x, expected, memory[4]);
    CheckDoubleResult(x, x, expected, memory[7]);
  }
}

void RunF64x4BinOpRevecTest(WasmOpcode opcode, DoubleBinOp expected_op,
                            compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  double* memory = r.builder().AddMemoryElems<double>(12);
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
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(
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
        WASM_ONE);
  }
  FOR_FLOAT64_INPUTS(x) {
    if (!PlatformCanRepresent(x)) continue;
```