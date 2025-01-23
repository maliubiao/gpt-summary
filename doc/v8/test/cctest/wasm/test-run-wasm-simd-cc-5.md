Response:
The user wants to understand the functionality of the provided C++ code snippet from a V8 source file.

Here's a breakdown of the request and how to address each point:

1. **List the functionality:**  The code defines several tests using the `TEST` macro. Each test seems to focus on a specific WebAssembly SIMD (Single Instruction, Multiple Data) operation and checks if the Turbofan compiler can correctly "revectorize" these operations for 256-bit SIMD instructions (AVX2).

2. **Check for .tq extension:** The filename ends with `.cc`, not `.tq`. Thus, it's a C++ source file, not a Torque file.

3. **Relationship with JavaScript and examples:** WebAssembly SIMD features are exposed to JavaScript. I need to find corresponding JavaScript APIs for the operations tested in the C++ code.

4. **Code logic reasoning with input/output:** The tests involve setting up memory with specific values, executing the WebAssembly code, and verifying the output in memory. I need to analyze the operations and provide example inputs and expected outputs for a representative test case.

5. **Common programming errors:**  When working with SIMD in JavaScript/WebAssembly, incorrect data alignment and out-of-bounds memory access are common issues.

6. **Summarize the functionality:** Based on the above points, I need to provide a concise summary of the file's purpose.

**Mental Sandbox:**

*   I can identify the tested WebAssembly SIMD operations by looking at the `kExpr...` constants (e.g., `kExprS128Xor`, `kExprS128AndNot`, `kExprI32x4Ne`).
*   The `Run...RevecTest` functions likely encapsulate the logic for setting up the WebAssembly module and running it.
*   The presence of `EXPERIMENTAL_FLAG_SCOPE(revectorize)` and `CpuFeatures::IsSupported(AVX/AVX2)` indicates that these tests are specifically for verifying the optimization of SIMD operations on processors with AVX2 support.
*   For the JavaScript examples, I'll need to map the WebAssembly opcodes to their JavaScript `SIMD` counterparts (e.g., `SIMD.Int32x4.xor`, `SIMD.Int32x4.andNot`).
*   For the input/output example, the `RunWasmTurbofan_S256Xor` test seems like a good candidate because it's straightforward (bitwise XOR). I'll choose some simple integer inputs.
*   For common errors, I'll focus on memory access issues related to SIMD operations.

**Constraint Checklist & Confidence Score:**

1. List functionality: Yes
2. Check for .tq: Yes
3. Javascript examples: Yes
4. Input/output reasoning: Yes
5. Common errors: Yes
6. Summarize functionality: Yes

Confidence Score: 5/5 - I can address all parts of the request.

Strategizing complete. I will now generate the response based on the outlined steps.
这是一个V8源代码文件，其主要功能是**测试V8的Turbofan编译器在处理WebAssembly SIMD (Single Instruction, Multiple Data) 指令时的优化能力，特别是针对可以将多个 128 位 SIMD 操作 "revectorize" 成单个 256 位 SIMD 操作的情况。**

具体来说，这个文件包含了一系列的单元测试，每个测试都针对一个特定的WebAssembly SIMD指令，例如：

*   **位运算:** XOR, AND NOT, SELECT
*   **比较运算:** 不等于 (Ne), 大于 (GtU), 大于等于 (GeS, GeU)
*   **移位运算:** 左移 (Shl), 算术右移 (ShrS), 逻辑右移 (ShrU)
*   **算术运算 (带饱和):** 加法饱和 (AddSatS, AddSatU), 减法饱和 (SubSatS, SubSatU)
*   **扩展乘法:** 将较小的数据类型相乘得到较大的数据类型
*   **向量操作:** 负数 (Neg), 绝对值 (Abs)
*   **浮点运算:** 加法 (Add), 绝对值 (Abs)
*   **加载和存储操作:** 从内存加载 SIMD 向量, 将 SIMD 向量存储到内存, 以及提取 SIMD 向量中的元素。
*   **混洗 (Shuffle) 操作:** 重新排列 SIMD 向量中的元素。
*   **解包 (Unpack) 操作:** 将两个较小的 SIMD 向量合并成一个较大的 SIMD 向量。

**关于文件扩展名：**

`v8/test/cctest/wasm/test-run-wasm-simd.cc` 的扩展名是 `.cc`，这表明它是一个 **C++源代码文件**。如果它以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的功能关系及示例：**

WebAssembly 的 SIMD 功能可以通过 JavaScript 的 `SIMD` API 来使用。这个 C++ 文件测试的 WebAssembly SIMD 指令在 JavaScript 中都有对应的操作。

例如，C++ 代码中的 `kExprS128Xor` (128位 SIMD XOR 操作) 对应于 JavaScript 中的 `SIMD.Int32x4.xor()` (假设操作的是 32 位整数的 4 通道向量)。

```javascript
// JavaScript 示例：执行 128 位 SIMD XOR 操作
const a = SIMD.Int32x4(1, 2, 3, 4);
const b = SIMD.Int32x4(5, 6, 7, 8);
const result = SIMD.Int32x4.xor(a, b);
// result 的值将是 SIMD.Int32x4(1 ^ 5, 2 ^ 6, 3 ^ 7, 4 ^ 8)
// 即 SIMD.Int32x4(4, 4, 4, 12)
```

C++ 代码中的 `kExprS128AndNot` (128位 SIMD AND NOT 操作) 对应于 JavaScript 中的 `SIMD.Int32x4.andNot()`。

```javascript
// JavaScript 示例：执行 128 位 SIMD AND NOT 操作
const a = SIMD.Int32x4(0b1100, 0b1010, 0b0110, 0b0011);
const b = SIMD.Int32x4(0b1010, 0b0101, 0b1100, 0b0000);
const result = SIMD.Int32x4.andNot(a, b);
// result 的值将是 SIMD.Int32x4((~0b1010) & 0b1100, (~0b0101) & 0b1010, (~0b1100) & 0b0110, (~0b0000) & 0b0011)
```

C++ 代码中的 `kExprS128Select` (128位 SIMD 选择操作) 对应于 JavaScript 中的 `SIMD.Int32x4.select()`。

```javascript
// JavaScript 示例：执行 128 位 SIMD 选择操作
const mask = SIMD.Int32x4(0, -1, 0, -1); // -1 在二进制中是全 1， 0 是全 0
const a = SIMD.Int32x4(1, 2, 3, 4);
const b = SIMD.Int32x4(5, 6, 7, 8);
const result = SIMD.Int32x4.select(mask, a, b);
// result 的值将是 SIMD.Int32x4(b[0], a[1], b[2], a[3])
// 即 SIMD.Int32x4(5, 2, 7, 4)
```

**代码逻辑推理 (以 `RunWasmTurbofan_S256Xor` 为例)：**

假设输入以下值：

*   **内存地址 `param1` (对应内存中的向量 a):**  `[1, 2, 3, 4, 5, 6, 7, 8]` (解释为两个 i32x4 向量)
*   **内存地址 `param2` (对应内存中的向量 b):**  `[9, 10, 11, 12, 13, 14, 15, 16]` (解释为两个 i32x4 向量)
*   **内存地址 `param3` (存储结果的地址):**  某个预先分配的内存区域

测试代码会构建一个 WebAssembly 函数，该函数执行以下操作：

1. 从内存地址 `param1` 加载一个 256 位的向量 (对应两个 128 位的 `i32x4` 向量)。
2. 从内存地址 `param2` 加载另一个 256 位的向量。
3. 对这两个 256 位的向量执行按位异或 (`S256Xor`) 操作。
4. 将结果存储到内存地址 `param3`。

**预期输出：**

存储在 `param3` 的内存中的值将是：

`[1^9, 2^10, 3^11, 4^12, 5^13, 6^14, 7^15, 8^16]`

即：

`[8, 8, 8, 8, 8, 8, 8, 24]`

**涉及用户常见的编程错误：**

在使用 SIMD 指令时，用户常见的编程错误包括：

1. **类型不匹配：**  例如，尝试对不同类型的 SIMD 向量执行操作，或者将标量值与 SIMD 向量错误地混合使用。
    ```javascript
    // 错误示例：尝试将 Int32x4 与 Float32x4 相加
    const intVec = SIMD.Int32x4(1, 2, 3, 4);
    const floatVec = SIMD.Float32x4(1.0, 2.0, 3.0, 4.0);
    // 这通常会导致错误
    // const result = SIMD.Int32x4.add(intVec, floatVec);
    ```

2. **内存对齐问题：**  SIMD 指令通常要求操作数在内存中进行特定的对齐。如果数据未对齐，可能会导致性能下降或程序崩溃。
    ```c++
    // 假设 memory 是一个字节数组
    int unaligned_ptr = reinterpret_cast<int*>(&memory[1]); // 未对齐的指针
    // 尝试使用 unaligned_ptr 加载 SIMD 数据可能会有问题
    // __m128i data = _mm_loadu_si128(reinterpret_cast<__m128i*>(unaligned_ptr));
    ```

3. **越界访问：**  SIMD 操作一次处理多个数据元素。如果操作涉及到内存访问，必须确保访问不会超出分配的内存范围。
    ```javascript
    function processArray(arr) {
      if (arr.length < 4) {
        // 错误：如果数组长度小于 4，尝试创建 Int32x4 会出错
        // return SIMD.Int32x4(arr[0], arr[1], arr[2], arr[3]);
        return;
      }
      const vec = SIMD.Int32x4(arr[0], arr[1], arr[2], arr[3]);
      return vec;
    }
    ```

4. **错误的混洗掩码：**  在使用混洗指令时，提供的掩码值必须在有效范围内，否则会导致未定义的行为。

**第 6 部分功能归纳：**

这部分代码主要测试了 V8 的 Turbofan 编译器在处理以下 WebAssembly SIMD 指令并将其 "revectorize" 为 256 位操作时的正确性：

*   **256 位向量的按位异或 (S256Xor)**
*   **256 位向量的按位与非 (S256AndNot)**
*   **256 位向量的选择 (S256Select)**
*   **32 位整数 8 通道向量的不等于比较 (I32x8Ne)**
*   **32 位无符号整数 8 通道向量的大于比较 (I32x8GtU)**
*   **32 位整数 8 通道向量的大于等于比较 (I32x8GeS, I32x8GeU)**
*   **32 位整数 8 通道向量的左移 (I32x8Shl)**
*   **32 位整数 8 通道向量的算术右移 (I32x8ShrS)**
*   **32 位整数 8 通道向量的逻辑右移 (I32x8ShrU)**
*   **16 位整数 16 通道向量的取负 (I16x16Neg)**
*   **16 位整数 16 通道向量的绝对值 (I16x16Abs)**
*   **16 位整数 16 通道向量的饱和加法 (I16x16AddSatS, I16x16AddSatU)**
*   **16 位整数 16 通道向量的饱和减法 (I16x16SubSatS, I16x16SubSatU)**
*   **16 位整数 16 通道向量的不等于比较 (WasmTurbofan_I16x16Ne)**
*   **16 位无符号整数 16 通道向量的大于比较 (WasmTurbofan_I16x16GtU)**
*   **16 位整数 16 通道向量的大于等于比较 (WasmTurbofan_I16x16GeS, WasmTurbofan_I16x16GeU)**
*   **扩展乘法操作 (将较小的整数类型相乘得到较大的整数类型，例如 I16x16ExtMulI8x16S, I16x16ExtMulI8x16U, I32x8ExtMulI16x8S, I32x8ExtMulI16x8U, I64x4ExtMulI32x4S, I64x4ExtMulI32x4U)**
*   **16 位整数 16 通道向量的移位操作 (I16x16Shl, I16x16ShrS, I16x16ShrU)**
*   **8 位整数 32 通道向量的取负和绝对值 (I8x32Neg, I8x32Abs)**
*   **8 位整数 32 通道向量的饱和加减法 (I8x32AddSatS, I8x32SubSatS, I8x32AddSatU, I8x32SubSatU)**
*   **8 位整数 32 通道向量的比较操作 (I8x32Ne, I8x32GtU, I8x32GeS, I8x32GeU)**
*   **32 位浮点数 4 通道向量的加法 (F32x4AddRevec)**
*   **加载、存储和提取操作的组合 (LoadStoreExtractRevec, reversed version, 以及涉及到 shuffle 的情况)**
*   **特定的混洗操作 (F32x4ShuffleForSplatRevec, ShuffleVpshufd, I8x32ShuffleShufps, I8x32ShuffleS32x8UnpackLow, I8x32ShuffleS32x8UnpackHigh)**

这些测试用例旨在验证当启用 "revectorize" 优化时，Turbofan 编译器是否能够正确地将多个 128 位 SIMD 操作组合成更高效的 256 位 SIMD 指令，从而提升 WebAssembly 代码的执行性能。每个测试通常会设置一些输入数据，执行相应的 WebAssembly 代码，并检查输出结果是否符合预期。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-simd.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
rbofan_S256Xor) {
  RunI32x8BinOpRevecTest(kExprS128Xor, BitwiseXor,
                         compiler::IrOpcode::kS256Xor);
}

TEST(RunWasmTurbofan_S256AndNot) {
  RunI32x8BinOpRevecTest(kExprS128AndNot, BitwiseAndNot,
                         compiler::IrOpcode::kS256AndNot);
}

TEST(RunWasmTurbofan_S256Select) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(32);
  // Build fn perform bitwise selection on two 256 bit vectors a and b, mask c,
  // store the result in d:
  //   simd128 *a,*b,*c,*d;
  //   *d = select(*a, *b, *c);
  //   *(d+1) = select(*(a+1), *(b+1), *(c+1))
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;
  uint8_t param4 = 3;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(),
        TSSimd256VerifyScope::VerifyHaveOpWithKind<
            compiler::turboshaft::Simd256TernaryOp,
            compiler::turboshaft::Simd256TernaryOp::Kind::kS256Select>);
    BUILD_AND_CHECK_REVEC_NODE(
        r, compiler::IrOpcode::kS256Select,
        WASM_LOCAL_SET(
            temp1,
            WASM_SIMD_SELECT(32x4, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                             WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)),
                             WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param3)))),
        WASM_LOCAL_SET(
            temp2,
            WASM_SIMD_SELECT(
                32x4, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1)),
                WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param2)),
                WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param3)))),
        WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param4), WASM_LOCAL_GET(temp1)),
        WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param4),
                                   WASM_LOCAL_GET(temp2)),
        WASM_ONE);
  }
  for (auto x : compiler::ValueHelper::GetVector<int32_t>()) {
    for (auto y : compiler::ValueHelper::GetVector<int32_t>()) {
      for (auto z : compiler::ValueHelper::GetVector<int32_t>()) {
        for (int i = 0; i < 4; i++) {
          r.builder().WriteMemory(&memory[i], x);
          r.builder().WriteMemory(&memory[i + 4], x);
          r.builder().WriteMemory(&memory[i + 8], y);
          r.builder().WriteMemory(&memory[i + 12], y);
          r.builder().WriteMemory(&memory[i + 16], z);
          r.builder().WriteMemory(&memory[i + 20], z);
        }
        CHECK_EQ(1, r.Call(0, 32, 64, 96));
        int32_t expected = BitwiseSelect(x, y, z);
        for (int i = 0; i < 4; i++) {
          CHECK_EQ(expected, memory[i + 24]);
          CHECK_EQ(expected, memory[i + 28]);
        }
      }
    }
  }
}

TEST(RunWasmTurbofan_I32x8Ne) {
  RunI32x8BinOpRevecTest(kExprI32x4Ne, NotEqual, compiler::IrOpcode::kI32x8Ne);
}

TEST(RunWasmTurbofan_I32x8GtU) {
  RunI32x8BinOpRevecTest<uint32_t>(kExprI32x4GtU, UnsignedGreater,
                                   compiler::IrOpcode::kI32x8GtU);
}

TEST(RunWasmTurbofan_I32x8GeS) {
  RunI32x8BinOpRevecTest(kExprI32x4GeS, GreaterEqual,
                         compiler::IrOpcode::kI32x8GeS);
}

TEST(RunWasmTurbofan_I32x8GeU) {
  RunI32x8BinOpRevecTest<uint32_t>(kExprI32x4GeU, UnsignedGreaterEqual,
                                   compiler::IrOpcode::kI32x8GeU);
}

TEST(RunWasmTurbofan_I32x8Shl) {
  RunI32x8ShiftOpRevecTest(kExprI32x4Shl, LogicalShiftLeft,
                           compiler::IrOpcode::kI32x8Shl);
}

TEST(RunWasmTurbofan_I32x8ShrS) {
  RunI32x8ShiftOpRevecTest(kExprI32x4ShrS, ArithmeticShiftRight,
                           compiler::IrOpcode::kI32x8ShrS);
}

TEST(RunWasmTurbofan_I32x8ShrU) {
  RunI32x8ShiftOpRevecTest(kExprI32x4ShrU, LogicalShiftRight,
                           compiler::IrOpcode::kI32x8ShrU);
}

TEST(RunWasmTurbofan_I16x16Neg) {
  RunI16x16UnOpRevecTest(kExprI16x8Neg, base::NegateWithWraparound,
                         compiler::IrOpcode::kI16x16Neg);
}

TEST(RunWasmTurbofan_I16x16Abs) {
  RunI16x16UnOpRevecTest(kExprI16x8Abs, Abs, compiler::IrOpcode::kI16x16Abs);
}

TEST(RunWasmTurbofan_I16x16AddSatS) {
  RunI16x16BinOpRevecTest<int16_t>(kExprI16x8AddSatS, SaturateAdd,
                                   compiler::IrOpcode::kI16x16AddSatS);
}

TEST(RunWasmTurbofan_I16x16SubSatS) {
  RunI16x16BinOpRevecTest<int16_t>(kExprI16x8SubSatS, SaturateSub,
                                   compiler::IrOpcode::kI16x16SubSatS);
}

TEST(RunWasmTurbofan_I16x16AddSatU) {
  RunI16x16BinOpRevecTest<uint16_t>(kExprI16x8AddSatU, SaturateAdd,
                                    compiler::IrOpcode::kI16x16AddSatU);
}

TEST(RunWasmTurbofan_I16x16SubSatU) {
  RunI16x16BinOpRevecTest<uint16_t>(kExprI16x8SubSatU, SaturateSub,
                                    compiler::IrOpcode::kI16x16SubSatU);
}

TEST(WasmTurbofan_I16x16Ne) {
  RunI16x16BinOpRevecTest(kExprI16x8Ne, NotEqual,
                          compiler::IrOpcode::kI16x16Ne);
}

TEST(WasmTurbofan_I16x16GtU) {
  RunI16x16BinOpRevecTest<uint16_t>(kExprI16x8GtU, UnsignedGreater,
                                    compiler::IrOpcode::kI16x16GtU);
}

TEST(WasmTurbofan_I16x16GeS) {
  RunI16x16BinOpRevecTest(kExprI16x8GeS, GreaterEqual,
                          compiler::IrOpcode::kI16x16GeS);
}

TEST(WasmTurbofan_I16x16GeU) {
  RunI16x16BinOpRevecTest<uint16_t>(kExprI16x8GeU, UnsignedGreaterEqual,
                                    compiler::IrOpcode::kI16x16GeU);
}

template <typename S, typename T, typename OpType = T (*)(S, S)>
void RunExtMulRevecTest(WasmOpcode opcode_low, WasmOpcode opcode_high,
                        OpType expected_op,
                        compiler::IrOpcode::Value revec_opcode) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  static_assert(sizeof(T) == 2 * sizeof(S),
                "the element size of dst vector must be twice of src vector in "
                "extended integer multiplication");
  WasmRunner<int32_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  uint32_t count = 4 * kSimd128Size / sizeof(S);
  S* memory = r.builder().AddMemoryElems<S>(count);
  // Build fn perform extmul on two 128 bit vectors a and b, store the result in
  // c:
  //   simd128 *a,*b,*c;
  //   *c = *a op_low *b;
  //   *(c+1) = *a op_high *b;
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Binop>);
    BUILD_AND_CHECK_REVEC_NODE(
        r, revec_opcode,
        WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
        WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2))),
        WASM_LOCAL_SET(temp3, WASM_SIMD_BINOP(opcode_low, WASM_LOCAL_GET(temp1),
                                              WASM_LOCAL_GET(temp2))),
        WASM_LOCAL_SET(temp4,
                       WASM_SIMD_BINOP(opcode_high, WASM_LOCAL_GET(temp1),
                                       WASM_LOCAL_GET(temp2))),
        WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param3), WASM_LOCAL_GET(temp3)),
        WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param3),
                                   WASM_LOCAL_GET(temp4)),
        WASM_ONE);
  }

  constexpr uint32_t lanes = kSimd128Size / sizeof(S);
  for (S x : compiler::ValueHelper::GetVector<S>()) {
    for (S y : compiler::ValueHelper::GetVector<S>()) {
      for (uint32_t i = 0; i < lanes; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + lanes], y);
      }
      r.Call(0, 16, 32);
      T expected = expected_op(x, y);
      T* output = reinterpret_cast<T*>(memory + lanes * 2);
      for (uint32_t i = 0; i < lanes; i++) {
        CHECK_EQ(expected, output[i]);
      }
    }
  }
}

TEST(RunWasmTurbofan_I16x16ExtMulI8x16S) {
  RunExtMulRevecTest<int8_t, int16_t>(kExprI16x8ExtMulLowI8x16S,
                                      kExprI16x8ExtMulHighI8x16S, MultiplyLong,
                                      compiler::IrOpcode::kI16x16ExtMulI8x16S);
}

TEST(RunWasmTurbofan_I16x16ExtMulI8x16U) {
  RunExtMulRevecTest<uint8_t, uint16_t>(
      kExprI16x8ExtMulLowI8x16U, kExprI16x8ExtMulHighI8x16U, MultiplyLong,
      compiler::IrOpcode::kI16x16ExtMulI8x16U);
}

TEST(RunWasmTurbofan_I32x8ExtMulI16x8S) {
  RunExtMulRevecTest<int16_t, int32_t>(kExprI32x4ExtMulLowI16x8S,
                                       kExprI32x4ExtMulHighI16x8S, MultiplyLong,
                                       compiler::IrOpcode::kI32x8ExtMulI16x8S);
}

TEST(RunWasmTurbofan_I32x8ExtMulI16x8U) {
  RunExtMulRevecTest<uint16_t, uint32_t>(
      kExprI32x4ExtMulLowI16x8U, kExprI32x4ExtMulHighI16x8U, MultiplyLong,
      compiler::IrOpcode::kI32x8ExtMulI16x8U);
}

TEST(RunWasmTurbofan_I64x4ExtMulI32x4S) {
  RunExtMulRevecTest<int32_t, int64_t>(kExprI64x2ExtMulLowI32x4S,
                                       kExprI64x2ExtMulHighI32x4S, MultiplyLong,
                                       compiler::IrOpcode::kI64x4ExtMulI32x4S);
}

TEST(RunWasmTurbofan_I64x4ExtMulI32x4U) {
  RunExtMulRevecTest<uint32_t, uint64_t>(
      kExprI64x2ExtMulLowI32x4U, kExprI64x2ExtMulHighI32x4U, MultiplyLong,
      compiler::IrOpcode::kI64x4ExtMulI32x4U);
}

TEST(RunWasmTurbofan_I16x16Shl) {
  RunI16x16ShiftOpRevecTest(kExprI16x8Shl, LogicalShiftLeft,
                            compiler::IrOpcode::kI16x16Shl);
}

TEST(RunWasmTurbofan_I16x16ShrS) {
  RunI16x16ShiftOpRevecTest(kExprI16x8ShrS, ArithmeticShiftRight,
                            compiler::IrOpcode::kI16x16ShrS);
}

TEST(RunWasmTurbofan_I16x16ShrU) {
  RunI16x16ShiftOpRevecTest(kExprI16x8ShrU, LogicalShiftRight,
                            compiler::IrOpcode::kI16x16ShrU);
}

TEST(RunWasmTurbofan_I8x32Neg) {
  RunI8x32UnOpRevecTest(kExprI8x16Neg, base::NegateWithWraparound,
                        compiler::IrOpcode::kI8x32Neg);
}

TEST(RunWasmTurbofan_I8x32Abs) {
  RunI8x32UnOpRevecTest(kExprI8x16Abs, Abs, compiler::IrOpcode::kI8x32Abs);
}

TEST(RunWasmTurbofan_I8x32AddSatS) {
  RunI8x32BinOpRevecTest<int8_t>(kExprI8x16AddSatS, SaturateAdd,
                                 compiler::IrOpcode::kI8x32AddSatS);
}

TEST(RunWasmTurbofan_I8x32SubSatS) {
  RunI8x32BinOpRevecTest<int8_t>(kExprI8x16SubSatS, SaturateSub,
                                 compiler::IrOpcode::kI8x32SubSatS);
}

TEST(RunWasmTurbofan_I8x32AddSatU) {
  RunI8x32BinOpRevecTest<uint8_t>(kExprI8x16AddSatU, SaturateAdd,
                                  compiler::IrOpcode::kI8x32AddSatU);
}

TEST(RunWasmTurbofan_I8x32SubSatU) {
  RunI8x32BinOpRevecTest<uint8_t>(kExprI8x16SubSatU, SaturateSub,
                                  compiler::IrOpcode::kI8x32SubSatU);
}

TEST(RunWasmTurbofan_I8x32Ne) {
  RunI8x32BinOpRevecTest(kExprI8x16Ne, NotEqual, compiler::IrOpcode::kI8x32Ne);
}

TEST(RunWasmTurbofan_I8x32GtU) {
  RunI8x32BinOpRevecTest<uint8_t>(kExprI8x16GtU, UnsignedGreater,
                                  compiler::IrOpcode::kI8x32GtU);
}

TEST(RunWasmTurbofan_I8x32GeS) {
  RunI8x32BinOpRevecTest(kExprI8x16GeS, GreaterEqual,
                         compiler::IrOpcode::kI8x32GeS);
}

TEST(RunWasmTurbofan_I8x32GeU) {
  RunI8x32BinOpRevecTest<uint8_t>(kExprI8x16GeU, UnsignedGreaterEqual,
                                  compiler::IrOpcode::kI8x32GeU);
}

TEST(RunWasmTurbofan_F32x4AddRevec) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<float, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  uint8_t temp5 = r.AllocateLocal(kWasmF32);
  uint8_t temp6 = r.AllocateLocal(kWasmF32);
  constexpr uint8_t offset = 16;

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpWithKind<
                      compiler::turboshaft::Simd256BinopOp,
                      compiler::turboshaft::Simd256BinopOp::Kind::kF32x8Add>);
    // Add a F32x8 vector by a constant vector and store the result to memory.
    r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_F32x4_SPLAT(WASM_F32(10.0f))),
             WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
             WASM_LOCAL_SET(
                 temp3, WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp2))),
             WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM_OFFSET(
                                       offset, WASM_LOCAL_GET(param1))),
             WASM_LOCAL_SET(
                 temp4, WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp2))),
             WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp3)),
             WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                        WASM_LOCAL_GET(temp4)),
             WASM_LOCAL_SET(temp5,
                            WASM_SIMD_F32x4_EXTRACT_LANE(
                                1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)))),
             WASM_LOCAL_SET(temp6, WASM_SIMD_F32x4_EXTRACT_LANE(
                                       2, WASM_SIMD_LOAD_MEM_OFFSET(
                                              offset, WASM_LOCAL_GET(param2)))),
             WASM_BINOP(kExprF32Add, WASM_LOCAL_GET(temp5),
                        WASM_LOCAL_GET(temp6))});
  }
  r.builder().WriteMemory(&memory[1], 1.0f);
  r.builder().WriteMemory(&memory[6], 2.0f);
  CHECK_EQ(23.0f, r.Call(0, 32));
}

TEST(RunWasmTurbofan_LoadStoreExtractRevec) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<float, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmF32);
  uint8_t temp4 = r.AllocateLocal(kWasmF32);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(r.zone());
    // Load a F32x8 vector, calculate the Abs and store the result to memory.
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
         WASM_LOCAL_SET(
             temp2, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1))),
         WASM_SIMD_STORE_MEM(
             WASM_LOCAL_GET(param2),
             WASM_SIMD_UNOP(kExprF32x4Abs, WASM_LOCAL_GET(temp1))),
         WASM_SIMD_STORE_MEM_OFFSET(
             offset, WASM_LOCAL_GET(param2),
             WASM_SIMD_UNOP(kExprF32x4Abs, WASM_LOCAL_GET(temp2))),
         WASM_LOCAL_SET(temp3,
                        WASM_SIMD_F32x4_EXTRACT_LANE(
                            1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)))),
         WASM_LOCAL_SET(temp4, WASM_SIMD_F32x4_EXTRACT_LANE(
                                   2, WASM_SIMD_LOAD_MEM_OFFSET(
                                          offset, WASM_LOCAL_GET(param2)))),
         WASM_BINOP(kExprF32Add,
                    WASM_BINOP(kExprF32Add, WASM_LOCAL_GET(temp3),
                               WASM_LOCAL_GET(temp4)),
                    WASM_SIMD_F32x4_EXTRACT_LANE(2, WASM_LOCAL_GET(temp2)))});
  }
  r.builder().WriteMemory(&memory[1], -1.0f);
  r.builder().WriteMemory(&memory[6], 2.0f);
  CHECK_EQ(5.0f, r.Call(0, 32));
}

#ifdef V8_TARGET_ARCH_X64
TEST(RunWasmTurbofan_LoadStoreExtract2Revec) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<float, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmF32);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(r.zone());
    // Load two F32x4 vectors, calculate the Abs and store to memory. Sum up the
    // two F32x4 vectors from both temp and memory. Revectorization still
    // succeeds as we can omit the lane 0 extract on x64.
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
         WASM_LOCAL_SET(
             temp2, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1))),
         WASM_SIMD_STORE_MEM(
             WASM_LOCAL_GET(param2),
             WASM_SIMD_UNOP(kExprF32x4Abs, WASM_LOCAL_GET(temp1))),
         WASM_SIMD_STORE_MEM_OFFSET(
             offset, WASM_LOCAL_GET(param2),
             WASM_SIMD_UNOP(kExprF32x4Abs, WASM_LOCAL_GET(temp2))),
         WASM_LOCAL_SET(
             temp3,
             WASM_BINOP(kExprF32Add,
                        WASM_SIMD_F32x4_EXTRACT_LANE(
                            1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2))),
                        WASM_SIMD_F32x4_EXTRACT_LANE(
                            1, WASM_SIMD_LOAD_MEM_OFFSET(
                                   offset, WASM_LOCAL_GET(param2))))),
         WASM_BINOP(kExprF32Add, WASM_LOCAL_GET(temp3),
                    WASM_SIMD_F32x4_EXTRACT_LANE(
                        1, WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp1),
                                           WASM_LOCAL_GET(temp2))))});
  }
  r.builder().WriteMemory(&memory[1], 1.0f);
  r.builder().WriteMemory(&memory[5], -2.0f);
  CHECK_EQ(2.0f, r.Call(0, 32));
}

TEST(RunWasmTurbofan_LoadStoreOOBRevec) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(r.zone());
    // Load a F32x8 vectori, calculate the Abs and store the result to memory.
    r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
             WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM_OFFSET(
                                       offset, WASM_LOCAL_GET(param1))),
             WASM_SIMD_STORE_MEM(
                 WASM_LOCAL_GET(param2),
                 WASM_SIMD_UNOP(kExprF32x4Abs, WASM_LOCAL_GET(temp1))),
             WASM_SIMD_STORE_MEM_OFFSET(
                 offset, WASM_LOCAL_GET(param2),
                 WASM_SIMD_UNOP(kExprF32x4Abs, WASM_LOCAL_GET(temp2))),
             WASM_ONE});
  }
  r.builder().WriteMemory(&memory[1], -1.0f);
  r.builder().WriteMemory(&memory[6], 2.0f);
  CHECK_TRAP(r.Call(0, kWasmPageSize - 16));
  CHECK_EQ(1.0f,
           r.builder().ReadMemory(&memory[kWasmPageSize / sizeof(float) - 3]));
}
#endif  // V8_TARGET_ARCH_X64

TEST(RunWasmTurbofan_ReversedLoadStoreExtractRevec) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<float, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmF32);
  uint8_t temp4 = r.AllocateLocal(kWasmF32);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(r.zone());
    // Load a F32x8 vector and store the result to memory in the order from the
    // high 128-bit address.
    r.Build(
        {WASM_LOCAL_SET(
             temp1, WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1))),
         WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
         WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                    WASM_LOCAL_GET(temp1)),
         WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp2)),
         WASM_LOCAL_SET(temp3,
                        WASM_SIMD_F32x4_EXTRACT_LANE(
                            1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)))),
         WASM_LOCAL_SET(temp4, WASM_SIMD_F32x4_EXTRACT_LANE(
                                   2, WASM_SIMD_LOAD_MEM_OFFSET(
                                          offset, WASM_LOCAL_GET(param2)))),
         WASM_BINOP(kExprF32Add,
                    WASM_BINOP(kExprF32Add, WASM_LOCAL_GET(temp3),
                               WASM_LOCAL_GET(temp4)),
                    WASM_SIMD_F32x4_EXTRACT_LANE(1, WASM_LOCAL_GET(temp2)))});
  }
  r.builder().WriteMemory(&memory[1], 1.0f);
  r.builder().WriteMemory(&memory[6], 2.0f);
  CHECK_EQ(4.0f, r.Call(0, 32));
}

TEST(RunWasmTurbofan_F32x4ShuffleForSplatRevec) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<float, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  float* memory =
      r.builder().AddMemoryElems<float>(kWasmPageSize / sizeof(float));
  constexpr Shuffle splat_shuffle = {8, 9, 10, 11, 8, 9, 10, 11,
                                     8, 9, 10, 11, 8, 9, 10, 11};
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  uint8_t temp5 = r.AllocateLocal(kWasmF32);
  uint8_t temp6 = r.AllocateLocal(kWasmF32);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(r.zone());
    // Add a F32x8 vector to a splat shuffle vector and store the result to
    // memory.
    r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1))),
             WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2))),
             WASM_LOCAL_SET(temp3,
                            WASM_SIMD_I8x16_SHUFFLE_OP(
                                kExprI8x16Shuffle, splat_shuffle,
                                WASM_LOCAL_GET(temp2), WASM_LOCAL_GET(temp2))),
             WASM_LOCAL_SET(
                 temp4, WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp3))),
             WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM_OFFSET(
                                       offset, WASM_LOCAL_GET(param1))),
             WASM_LOCAL_SET(
                 temp2, WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp3))),
             WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp4)),
             WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                        WASM_LOCAL_GET(temp2)),
             WASM_LOCAL_SET(temp5,
                            WASM_SIMD_F32x4_EXTRACT_LANE(
                                0, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)))),
             WASM_LOCAL_SET(temp6, WASM_SIMD_F32x4_EXTRACT_LANE(
                                       3, WASM_SIMD_LOAD_MEM_OFFSET(
                                              offset, WASM_LOCAL_GET(param2)))),
             WASM_BINOP(kExprF32Add, WASM_LOCAL_GET(temp5),
                        WASM_LOCAL_GET(temp6))});
  }
  r.builder().WriteMemory(&memory[0], 1.0f);
  r.builder().WriteMemory(&memory[7], 2.0f);
  r.builder().WriteMemory(&memory[10], 10.0f);
  CHECK_EQ(23.0f, r.Call(0, 32));
}

TEST(RunWasmTurbofan_ShuffleVpshufd) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(16);
  // I32x4, shuffle=[1,2,3,0]
  constexpr std::array<int8_t, 16> shuffle = {4,  5,  6,  7,  8, 9, 10, 11,
                                              12, 13, 14, 15, 0, 1, 2,  3};
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Shufd>);

    BUILD_AND_CHECK_REVEC_NODE(
        r, compiler::IrOpcode::kI8x32Shuffle,
        WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_ZERO)),
        WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM_OFFSET(16, WASM_ZERO)),

        WASM_SIMD_STORE_MEM_OFFSET(
            16 * 2, WASM_ZERO,
            WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                       WASM_LOCAL_GET(temp1),
                                       WASM_LOCAL_GET(temp1))),
        WASM_SIMD_STORE_MEM_OFFSET(
            16 * 3, WASM_ZERO,
            WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                       WASM_LOCAL_GET(temp2),
                                       WASM_LOCAL_GET(temp2))),
        WASM_ONE);
  }
  std::pair<std::vector<int>, std::vector<int>> test_case = {
      {1, 2, 3, 4, 5, 6, 7, 8}, {2, 3, 4, 1, 6, 7, 8, 5}};

  auto input = test_case.first;
  auto expected_output = test_case.second;

  for (int i = 0; i < 8; ++i) {
    r.builder().WriteMemory(&memory[i], input[i]);
  }

  r.Call();

  for (int i = 0; i < 8; ++i) {
    CHECK_EQ(expected_output[i], r.builder().ReadMemory(&memory[i + 8]));
  }
}

TEST(RunWasmTurbofan_I8x32ShuffleShufps) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(24);
  constexpr std::array<int8_t, 16> shuffle = {0,  1,  2,  3,  8,  9,  10, 11,
                                              16, 17, 18, 19, 24, 25, 26, 27};
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Shufps>);
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_ZERO)),
         WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM_OFFSET(16, WASM_ZERO)),
         WASM_LOCAL_SET(temp3, WASM_SIMD_LOAD_MEM_OFFSET(16 * 2, WASM_ZERO)),
         WASM_LOCAL_SET(temp4, WASM_SIMD_LOAD_MEM_OFFSET(16 * 3, WASM_ZERO)),

         WASM_SIMD_STORE_MEM_OFFSET(
             16 * 4, WASM_ZERO,
             WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                        WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp3))),
         WASM_SIMD_STORE_MEM_OFFSET(
             16 * 5, WASM_ZERO,
             WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                        WASM_LOCAL_GET(temp2),
                                        WASM_LOCAL_GET(temp4))),
         WASM_ONE});
  }
  std::vector<std::pair<std::vector<int>, std::vector<int>>> test_cases = {
      {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {0, 2, 8, 10, 4, 6, 12, 14}}}};

  for (auto pair : test_cases) {
    auto input = pair.first;
    auto expected_output = pair.second;
    for (int i = 0; i < 16; ++i) {
      r.builder().WriteMemory(&memory[i], input[i]);
    }
    r.Call();
    for (int i = 0; i < 8; ++i) {
      CHECK_EQ(expected_output[i], r.builder().ReadMemory(&memory[i + 16]));
    }
  }
}

TEST(RunWasmTurbofan_I8x32ShuffleS32x8UnpackLow) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(24);
  // shuffle32x4 [0,4,1,5]
  constexpr std::array<int8_t, 16> shuffle = {0, 1, 2, 3, 16, 17, 18, 19,
                                              4, 5, 6, 7, 20, 21, 22, 23};
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Unpack>);

    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_ZERO)),
         WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM_OFFSET(16, WASM_ZERO)),
         WASM_LOCAL_SET(temp3, WASM_SIMD_LOAD_MEM_OFFSET(16 * 2, WASM_ZERO)),
         WASM_LOCAL_SET(temp4, WASM_SIMD_LOAD_MEM_OFFSET(16 * 3, WASM_ZERO)),

         WASM_SIMD_STORE_MEM_OFFSET(
             16 * 4, WASM_ZERO,
             WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                        WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp3))),
         WASM_SIMD_STORE_MEM_OFFSET(
             16 * 5, WASM_ZERO,
             WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                        WASM_LOCAL_GET(temp2),
                                        WASM_LOCAL_GET(temp4))),
         WASM_ONE});
  }
  std::vector<std::pair<std::vector<int>, std::vector<int>>> test_cases = {
      {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {0, 8, 1, 9, 4, 12, 5, 13}}}};

  for (auto pair : test_cases) {
    auto input = pair.first;
    auto expected_output = pair.second;
    for (int i = 0; i < 16; ++i) {
      r.builder().WriteMemory(&memory[i], input[i]);
    }
    r.Call();
    for (int i = 0; i < 8; ++i) {
      CHECK_EQ(expected_output[i], r.builder().ReadMemory(&memory[i + 16]));
    }
  }
}

TEST(RunWasmTurbofan_I8x32ShuffleS32x8UnpackHigh) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t> r(TestExecutionTier::kTurbofan);
  int32_t* memory = r.builder().AddMemoryElems<int32_t>(24);
  // shuffle32x4 [2,6,3,7]
  constexpr std::array<int8_t, 16> shuffle = {8,  9,  10, 11, 24, 25, 26, 27,
                                              12, 13, 14, 15, 28, 29, 30, 31};
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  uint8_t temp4 = r.AllocateLocal(kWasmS128);

  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Unpack>);
    r.Build(
        {WASM_LOCAL_SET(temp1, WASM_SIMD_LOAD_MEM(WASM_ZERO)),
         WASM_LOCAL_SET(temp2, WASM_SIMD_LOAD_MEM_OFFSET(16, WASM_ZERO)),
         WASM_LOCAL_SET(temp3, WASM_SIMD_LOAD_MEM_OFFSET(16 * 2, WASM_ZERO)),
         WASM_LOCAL_SET(temp4, WASM_SIMD_LOAD_MEM_OFFSET(16 * 3, WASM_ZERO)),

         WASM_SIMD_STORE_MEM_OFFSET(
             16 * 4, WASM_ZERO,
             WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                        WASM_LOCAL_GET(temp1),
                                        WASM_LOCAL_GET(temp3))),
         WASM_SIMD_STORE_MEM_OFFSET(
             16 * 5, WASM_ZERO,
             WASM_SIMD_I8x16_SHUFFLE_OP(kExprI8x16Shuffle, shuffle,
                                        WASM_LOCAL_GET(temp2),
                                        WASM_LOCAL_GET(temp4))),
         WASM_ONE});
  }
  std::vector<std::pair<std::vector<int>, std::vector<int>>> test_cases = {
      {{{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {2, 10, 3, 11, 6, 14, 7, 15}}}};

  for (auto pair : test_cases) {
    auto input = pair.first;
    auto expected_output = pair.second;
    for (int i = 0; i < 16; ++i) {
      r.builder().WriteMemory(&memory[i], input[i]);
    }
    r.Call();
    for (int i = 0; i < 8; ++i) {
      CHECK_EQ(expected_output[i], r.builder().ReadMemory(&memory[i + 16]));
    }
  }
}

TEST(RunWasmTurbofan_ShuffleToS256Load8x8U) {
  SKIP_TEST_IF_NO_TURBOSHAFT;
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatu
```