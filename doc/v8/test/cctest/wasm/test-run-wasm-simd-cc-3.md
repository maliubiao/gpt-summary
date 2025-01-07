Response:
The user wants a summary of the provided C++ code, which is a part of the V8 JavaScript engine's test suite. The specific file `test-run-wasm-simd.cc` suggests it tests WebAssembly SIMD (Single Instruction, Multiple Data) functionality.

Here's a breakdown of the thinking process to generate the response:

1. **Identify the core purpose:** The filename `test-run-wasm-simd.cc` clearly indicates the file's purpose: testing the execution of WebAssembly code that utilizes SIMD instructions.

2. **Analyze code structure:** The code consists of numerous `WASM_EXEC_TEST` macros. Each of these defines a separate test case. This is a common pattern in testing frameworks. The names of these test cases (e.g., `I8x16Swizzle`, `I8x16ShuffleFuzz`, `ReductionTestlanes`) give clues about the specific SIMD operations being tested.

3. **Categorize test functionalities:** Based on the test names and the operations within them (e.g., `kExprI8x16Swizzle`, `kExprI8x16Shuffle`, `kExprV128AnyTrue`, `kExprI32x4ExtractLane`, memory load/store operations), the tests can be grouped into categories:
    * Swizzling (rearranging bytes within a SIMD vector)
    * Shuffling (rearranging lanes between two SIMD vectors)
    * Boolean reductions (checking if all or any lanes are true)
    * Lane extraction and replacement
    * Arithmetic operations with SIMD vectors
    * Interaction between integer and floating-point SIMD vectors
    * Local variable operations with SIMD vectors
    * Loop structures with SIMD vectors
    * Global variable access with SIMD vectors
    * Memory load and store operations (including different offsets and alignments)
    * Load splat operations (loading a single value into all lanes of a SIMD vector)
    * Load extend operations (loading and extending smaller integer types to larger ones)
    * Load zero operations (loading and zero-extending or just zeroing out lanes)

4. **Address specific instructions:** The prompt asks about `.tq` files (Torque), JavaScript relevance, code logic, and common errors.
    * **`.tq` files:**  The analysis correctly determines that this file is `.cc`, not `.tq`, so it's not a Torque source file.
    * **JavaScript relevance:** WebAssembly is closely related to JavaScript, as it's a compilation target. The tests ensure that WebAssembly SIMD behaves as expected within the V8 engine, which executes JavaScript. While the C++ code isn't directly JavaScript, it tests features that WebAssembly (and thus potentially JavaScript interacting with WebAssembly) will use.
    * **Code logic:** The tests often involve setting up input SIMD vectors (sometimes using globals or constants), performing a SIMD operation, and then checking the output against an expected value. Examples like `I8x16Swizzle` with specific input/index/expected values illustrate this.
    * **Common errors:**  Memory access errors (out-of-bounds) are explicitly tested, which aligns with common programming mistakes when dealing with memory.

5. **Handle the "Part 4 of 9" instruction:** This indicates the user is going through a series of files. The summary should reflect that this is a portion of a larger testing effort focused on SIMD.

6. **Structure the response:** Organize the findings logically. Start with the main function, then break down the functionalities into categories. Address the specific questions in the prompt.

7. **Refine the language:** Use clear and concise language. Avoid overly technical jargon where possible, or explain it briefly. Ensure the tone is informative and helpful.

By following these steps, the generated response accurately describes the purpose and functionality of the provided V8 test file.
```cpp
    for (int i = 1; i < lanes_s; i++) {
      CHECK_EQ(0, LANE(global, i));
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    r.builder().AddGlobal<S>(kWasmS128);
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_LOCAL_GET(0))),
             WASM_ONE});

    // Load zeros load 16 bytes, so should trap from -15.
    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(S128Load8Zero) {
  RunLoadZeroTest<int8_t>(execution_tier, kExprS128Load8Zero);
}

WASM_EXEC_TEST(S128Load16Zero) {
  RunLoadZeroTest<int16_t>(execution_tier, kExprS128Load16Zero);
}

WASM_EXEC_TEST(S128Load32Zero) {
  RunLoadZeroTest<int32_t>(execution_tier, kExprS128Load32Zero);
}

WASM_EXEC_TEST(S128Load64Zero) {
  RunLoadZeroTest<int64_t>(execution_tier, kExprS128Load64Zero);
}
```

### 功能列举:

`v8/test/cctest/wasm/test-run-wasm-simd.cc` 文件是 V8 JavaScript 引擎的测试套件的一部分，专门用于测试 WebAssembly 的 SIMD (Single Instruction, Multiple Data) 指令的执行。

具体来说，这部分代码测试了以下 SIMD 操作：

* **`I8x16Swizzle`**:  测试 `i8x16.swizzle` 指令，该指令根据第二个 SIMD 向量提供的索引重新排列第一个 SIMD 向量中的 16 个字节。
* **`I8x16ShuffleFuzz`**: 通过随机组合多个 shuffle 模式来模糊测试 `i8x16.shuffle` 指令。
* **`I8x16Shuffle` (通过 `RunShuffleOpTest` 调用)**: 测试 `i8x16.shuffle` 指令，该指令从两个输入的 i8x16 向量中选择 16 个字节创建一个新的 i8x16 向量。
* **Boolean Reduction Operations (`ReductionTestlanes`)**: 测试布尔归约操作，例如 `v128.anytrue` 和 `iXXxN.alltrue`，用于检查 SIMD 向量中的任何或所有元素是否为真。
* **Lane Extraction (`SimdI32x4ExtractWithF32x4`, `SimdF32x4ExtractWithI32x4`, `SimdF32x4ExtractLane`)**: 测试从 SIMD 向量中提取特定通道的值。
* **Arithmetic Operations with Mixed Types (`SimdF32x4AddWithI32x4`, `SimdI32x4AddWithF32x4`)**: 测试将不同类型的 SIMD 向量（例如，浮点数和整数）组合在一起的算术运算。
* **Local Variable Operations (`SimdI32x4Local`, `SimdI32x4SplatFromExtract`)**: 测试对 SIMD 向量执行的本地变量操作。
* **Loop Structures with SIMD (`SimdI32x4For`, `SimdF32x4For`)**: 测试在循环结构中使用 SIMD 指令。
* **Global Variable Access (`SimdI32x4GetGlobal`, `SimdI32x4SetGlobal`, `SimdF32x4GetGlobal`, `SimdF32x4SetGlobal`)**: 测试从全局变量读取和写入 SIMD 向量。
* **Memory Load and Store Operations (`SimdLoadStoreLoad`, `SimdLoadStoreLoadMemargOffset`)**: 测试将 SIMD 向量加载和存储到内存中，包括带有偏移量的操作。
* **Load Splat Operations (`S128Load8SplatOffset`, `S128Load8Splat`, `S128Load16Splat`, `S128Load32Splat`, `S128Load64Splat`)**: 测试从内存中加载单个值并将其复制到 SIMD 向量的所有通道中。
* **Load Extend Operations (`S128Load8x8U`, `S128Load8x8S`, `S128Load16x4U`, `S128Load16x4S`, `S128Load32x2U`, `S128Load32x2S`)**: 测试从内存中加载较小的数据类型并将其零扩展或符号扩展为较大的数据类型，然后存储到 SIMD 向量中。
* **Load Zero Operations (`S128Load8Zero`, `S128Load16Zero`, `S128Load32Zero`, `S128Load64Zero`)**: 测试从内存中加载指定大小的值，并将加载的值放置在 SIMD 向量的低位通道中，其余通道填充零。

### 关于文件类型和 JavaScript 关系:

* **文件类型**:  `v8/test/cctest/wasm/test-run-wasm-simd.cc` 以 `.cc` 结尾，表明它是一个 C++ 源文件。 如果它以 `.tq` 结尾，那它才是一个 V8 Torque 源代码文件。
* **JavaScript 关系**: WebAssembly 的设计目标是在现代 Web 浏览器中以接近本地的速度运行代码。V8 引擎是 Chrome 和 Node.js 中使用的 JavaScript 引擎，它也负责执行 WebAssembly 代码。因此，`test-run-wasm-simd.cc` 中的测试直接关系到 JavaScript 中使用 WebAssembly SIMD 功能的正确性。

**JavaScript 示例**:

虽然 C++ 代码本身不是 JavaScript，但它测试的 WebAssembly SIMD 功能可以在 JavaScript 中通过 `WebAssembly` API 使用。

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const i8_array = new Int8Array(memory.buffer);
i8_array[0] = 10;
i8_array[1] = 20;
i8_array[2] = 30;
i8_array[3] = 40;
// ... more data

WebAssembly.instantiateStreaming(fetch('your_wasm_module.wasm'), {
  env: {
    memory: memory
  }
}).then(result => {
  const wasm_exports = result.instance.exports;
  // 假设 wasm 模块导出了一个使用 SIMD 的函数
  const simd_result = wasm_exports.some_simd_function();
  console.log(simd_result);
});
```

在这个例子中，`your_wasm_module.wasm` 可能会包含使用 SIMD 指令的代码，这些指令的功能与 `test-run-wasm-simd.cc` 中测试的功能类似。V8 引擎在执行这段 WebAssembly 代码时，会运行到 SIMD 指令，而 `test-run-wasm-simd.cc` 的目的就是确保这些指令在 V8 中的实现是正确的。

### 代码逻辑推理 (假设输入与输出):

以 `I8x16Swizzle` 测试中的一个用例为例：

**假设输入:**

* **`si.input`**:  `{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}`
* **`si.indices`**: `{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}`

**代码逻辑:** `WASM_SIMD_BINOP(kExprI8x16Swizzle, WASM_GLOBAL_GET(1), WASM_GLOBAL_GET(2))` 会根据 `indices` 中的值从 `input` 中选取字节。

**预期输出 (`si.expected`):** `{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0}`

在这个例子中，索引是反向的，所以输出也是输入的反向。

**另一个例子 (常量索引优化):**

**假设输入:**

* **`si.input`**:  任意 16 个字节的值，例如全为 0。
* **`si.indices` (常量)**: `{15, 0, 14, 1, 13, 2, 12, 3, 11, 4, 10, 5, 9, 6, 8, 7}`

**代码逻辑:** `WASM_SIMD_BINOP(kExprI8x16Swizzle, WASM_GLOBAL_GET(1), WASM_SIMD_CONSTANT(si.indices))` 会根据常量索引重新排列 `input` 中的字节。

**预期输出 (`si.expected`):**  如果 `input` 全为 0，则 `expected` 也全为 0。如果 `input` 为 `{0, 1, 2, ..., 15}`，则 `expected` 将会是 `{15, 0, 14, 1, 13, 2, 12, 3, 11, 4, 10, 5, 9, 6, 8, 7}`。

### 用户常见的编程错误:

* **错误的 Swizzle/Shuffle 索引**:  对于 `i8x16.swizzle` 和 `i8x16.shuffle` 指令，提供超出范围的索引会导致未定义的行为或错误的结果。例如，在 `I8x16Swizzle` 测试中，有测试用例故意使用超出范围的索引，预期结果是 0。

   ```c++
   // all indices are out of range
   {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {16, 17, 18, 19, 20, 124, 125, 126, 127, -1, -2, -3, -4, -5, -6, -7},
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}};
   ```

   **JavaScript 中的类似错误**:

   ```javascript
   // 假设你有一个 WebAssembly 函数接收两个 i8x16 向量和一个索引数组
   function swizzle(input, indices) {
     // ... wasm 代码执行 swizzle 操作
   }

   const input = new Int8Array([0, 1, 2, ...]);
   const indices = new Int8Array([16, 17, 18, ...]); // 错误：索引超出范围

   // 调用 wasm 函数可能会产生意外结果或错误
   swizzle(input, indices);
   ```

* **内存访问越界**:  在进行 SIMD 加载和存储操作时，如果提供的内存地址加上偏移量超出了分配的内存范围，会导致错误。测试用例中包含了对这些越界情况的测试 (`SimdLoadStoreLoad` 和 `SimdLoadStoreLoadMemargOffset` 中的 OOB 测试)。

   **JavaScript 中的类似错误**:

   ```javascript
   const memory = new WebAssembly.Memory({ initial: 1 });
   const i32_array = new Int32Array(memory.buffer);

   // 尝试访问超出内存边界的索引
   const value = i32_array[WebAssembly.Memory.PAGE_SIZE / 4]; // 错误：超出范围
   ```

* **类型不匹配**:  尝试将不兼容类型的 SIMD 向量进行操作，例如将 `f32x4` 向量直接赋值给 `i32x4` 向量，可能会导致错误。虽然 WebAssembly 允许一些重新解释操作，但直接的类型不匹配通常是不允许的。

### 功能归纳 (针对第 4 部分，共 9 部分):

作为 9 个测试文件中的第 4 个，`v8/test/cctest/wasm/test-run-wasm-simd.cc` 的主要功能是 **系统地测试 V8 引擎中 WebAssembly SIMD 指令的执行逻辑是否正确**。

这部分侧重于 **字节级别的操作 (swizzle, shuffle)、基本的布尔归约、SIMD 向量与标量之间的通道提取和替换，以及开始涉及到内存加载和存储操作**。它通过大量的独立测试用例，覆盖了不同 SIMD 指令的不同使用场景和边界条件，以确保 V8 能够正确地编译和执行这些指令。  结合其他部分的测试，可以全面验证 V8 对 WebAssembly SIMD 功能的完整性和正确性支持。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-simd.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共9部分，请归纳一下它的功能

"""
13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
    {{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {15, 0, 14, 1, 13, 2, 12, 3, 11, 4, 10, 5, 9, 6, 8, 7},
     {0, 15, 1, 14, 2, 13, 3, 12, 4, 11, 5, 10, 6, 9, 7, 8}},
    {{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
     {0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30},
     {15, 13, 11, 9, 7, 5, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0}},
    // all indices are out of range
    {{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
     {16, 17, 18, 19, 20, 124, 125, 126, 127, -1, -2, -3, -4, -5, -6, -7},
     {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}}};

static constexpr base::Vector<const SwizzleTestArgs> swizzle_test_vector =
    base::ArrayVector(swizzle_test_args);

WASM_EXEC_TEST(I8x16Swizzle) {
  // RunBinaryLaneOpTest set up the two globals to be consecutive integers,
  // [0-15] and [16-31]. Using [0-15] as the indices will not sufficiently test
  // swizzle since the expected result is a no-op, using [16-31] will result in
  // all 0s.
  {
    WasmRunner<int32_t> r(execution_tier);
    static const int kElems = kSimd128Size / sizeof(uint8_t);
    uint8_t* dst = r.builder().AddGlobal<uint8_t>(kWasmS128);
    uint8_t* src0 = r.builder().AddGlobal<uint8_t>(kWasmS128);
    uint8_t* src1 = r.builder().AddGlobal<uint8_t>(kWasmS128);
    r.Build({WASM_GLOBAL_SET(
                 0, WASM_SIMD_BINOP(kExprI8x16Swizzle, WASM_GLOBAL_GET(1),
                                    WASM_GLOBAL_GET(2))),
             WASM_ONE});

    for (SwizzleTestArgs si : swizzle_test_vector) {
      for (int i = 0; i < kElems; i++) {
        LANE(src0, i) = si.input[i];
        LANE(src1, i) = si.indices[i];
      }

      CHECK_EQ(1, r.Call());

      for (int i = 0; i < kElems; i++) {
        CHECK_EQ(LANE(dst, i), si.expected[i]);
      }
    }
  }

  {
    // We have an optimization for constant indices, test this case.
    for (SwizzleTestArgs si : swizzle_test_vector) {
      WasmRunner<int32_t> r(execution_tier);
      uint8_t* dst = r.builder().AddGlobal<uint8_t>(kWasmS128);
      uint8_t* src0 = r.builder().AddGlobal<uint8_t>(kWasmS128);
      r.Build({WASM_GLOBAL_SET(
                   0, WASM_SIMD_BINOP(kExprI8x16Swizzle, WASM_GLOBAL_GET(1),
                                      WASM_SIMD_CONSTANT(si.indices))),
               WASM_ONE});

      for (int i = 0; i < kSimd128Size; i++) {
        LANE(src0, i) = si.input[i];
      }

      CHECK_EQ(1, r.Call());

      for (int i = 0; i < kSimd128Size; i++) {
        CHECK_EQ(LANE(dst, i), si.expected[i]);
      }
    }
  }
}

// Combine 3 shuffles a, b, and c by applying both a and b and then applying c
// to those two results.
Shuffle Combine(const Shuffle& a, const Shuffle& b, const Shuffle& c) {
  Shuffle result;
  for (int i = 0; i < kSimd128Size; ++i) {
    result[i] = c[i] < kSimd128Size ? a[c[i]] : b[c[i] - kSimd128Size];
  }
  return result;
}

const Shuffle& GetRandomTestShuffle(v8::base::RandomNumberGenerator* rng) {
  return test_shuffles[static_cast<ShuffleKey>(rng->NextInt(kNumShuffleKeys))];
}

// Test shuffles that are random combinations of 3 test shuffles. Completely
// random shuffles almost always generate the slow general shuffle code, so
// don't exercise as many code paths.
WASM_EXEC_TEST(I8x16ShuffleFuzz) {
  v8::base::RandomNumberGenerator* rng = CcTest::random_number_generator();
  static const int kTests = 100;
  for (int i = 0; i < kTests; ++i) {
    auto shuffle = Combine(GetRandomTestShuffle(rng), GetRandomTestShuffle(rng),
                           GetRandomTestShuffle(rng));
    RunShuffleOpTest(execution_tier, kExprI8x16Shuffle, shuffle);
  }
}

void AppendShuffle(const Shuffle& shuffle, std::vector<uint8_t>* buffer) {
  uint8_t opcode[] = {WASM_SIMD_OP(kExprI8x16Shuffle)};
  for (size_t i = 0; i < arraysize(opcode); ++i) buffer->push_back(opcode[i]);
  for (size_t i = 0; i < kSimd128Size; ++i) buffer->push_back((shuffle[i]));
}

void BuildShuffle(const std::vector<Shuffle>& shuffles,
                  std::vector<uint8_t>* buffer) {
  // Perform the leaf shuffles on globals 0 and 1.
  size_t row_index = (shuffles.size() - 1) / 2;
  for (size_t i = row_index; i < shuffles.size(); ++i) {
    uint8_t operands[] = {WASM_GLOBAL_GET(0), WASM_GLOBAL_GET(1)};
    for (size_t j = 0; j < arraysize(operands); ++j)
      buffer->push_back(operands[j]);
    AppendShuffle(shuffles[i], buffer);
  }
  // Now perform inner shuffles in the correct order on operands on the stack.
  do {
    for (size_t i = row_index / 2; i < row_index; ++i) {
      AppendShuffle(shuffles[i], buffer);
    }
    row_index /= 2;
  } while (row_index != 0);
  uint8_t epilog[] = {kExprGlobalSet, static_cast<uint8_t>(0), WASM_ONE};
  for (size_t j = 0; j < arraysize(epilog); ++j) buffer->push_back(epilog[j]);
}

void RunWasmCode(TestExecutionTier execution_tier,
                 const std::vector<uint8_t>& code,
                 std::array<int8_t, kSimd128Size>* result) {
  WasmRunner<int32_t> r(execution_tier);
  // Set up two test patterns as globals, e.g. [0, 1, 2, 3] and [4, 5, 6, 7].
  int8_t* src0 = r.builder().AddGlobal<int8_t>(kWasmS128);
  int8_t* src1 = r.builder().AddGlobal<int8_t>(kWasmS128);
  for (int i = 0; i < kSimd128Size; ++i) {
    LANE(src0, i) = i;
    LANE(src1, i) = kSimd128Size + i;
  }
  r.Build(code.data(), code.data() + code.size());
  CHECK_EQ(1, r.Call());
  for (size_t i = 0; i < kSimd128Size; i++) {
    (*result)[i] = LANE(src0, i);
  }
}

// Boolean unary operations are 'AllTrue' and 'AnyTrue', which return an integer
// result. Use relational ops on numeric vectors to create the boolean vector
// test inputs. Test inputs with all true, all false, one true, and one false.
#define WASM_SIMD_BOOL_REDUCTION_TEST(format, lanes, int_type)                \
  WASM_EXEC_TEST(ReductionTest##lanes) {                                      \
    WasmRunner<int32_t> r(execution_tier);                                    \
    if (lanes == 2) return;                                                   \
    uint8_t zero = r.AllocateLocal(kWasmS128);                                \
    uint8_t one_one = r.AllocateLocal(kWasmS128);                             \
    uint8_t reduced = r.AllocateLocal(kWasmI32);                              \
    r.Build(                                                                  \
        {WASM_LOCAL_SET(zero, WASM_SIMD_I##format##_SPLAT(int_type(0))),      \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(zero),    \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(one_one,                                              \
                        WASM_SIMD_I##format##_REPLACE_LANE(                   \
                            lanes - 1, WASM_LOCAL_GET(zero), int_type(1))),   \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprV128AnyTrue,                        \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_EQ(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Eq,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_LOCAL_SET(                                                      \
             reduced, WASM_SIMD_UNOP(kExprI##format##AllTrue,                 \
                                     WASM_SIMD_BINOP(kExprI##format##Ne,      \
                                                     WASM_LOCAL_GET(one_one), \
                                                     WASM_LOCAL_GET(zero)))), \
         WASM_IF(WASM_I32_NE(WASM_LOCAL_GET(reduced), WASM_ZERO),             \
                 WASM_RETURN(WASM_ZERO)),                                     \
         WASM_ONE});                                                          \
    CHECK_EQ(1, r.Call());                                                    \
  }

WASM_SIMD_BOOL_REDUCTION_TEST(64x2, 2, WASM_I64V)
WASM_SIMD_BOOL_REDUCTION_TEST(32x4, 4, WASM_I32V)
WASM_SIMD_BOOL_REDUCTION_TEST(16x8, 8, WASM_I32V)
WASM_SIMD_BOOL_REDUCTION_TEST(8x16, 16, WASM_I32V)

WASM_EXEC_TEST(SimdI32x4ExtractWithF32x4) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_IF_ELSE_I(WASM_I32_EQ(WASM_SIMD_I32x4_EXTRACT_LANE(
                                      0, WASM_SIMD_F32x4_SPLAT(WASM_F32(30.5))),
                                  WASM_I32_REINTERPRET_F32(WASM_F32(30.5))),
                      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdF32x4ExtractWithI32x4) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build(
      {WASM_IF_ELSE_I(WASM_F32_EQ(WASM_SIMD_F32x4_EXTRACT_LANE(
                                      0, WASM_SIMD_I32x4_SPLAT(WASM_I32V(15))),
                                  WASM_F32_REINTERPRET_I32(WASM_I32V(15))),
                      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdF32x4ExtractLane) {
  WasmRunner<float> r(execution_tier);
  r.AllocateLocal(kWasmF32);
  r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(0, WASM_SIMD_F32x4_EXTRACT_LANE(
                                 0, WASM_SIMD_F32x4_SPLAT(WASM_F32(30.5)))),
           WASM_LOCAL_SET(1, WASM_SIMD_F32x4_SPLAT(WASM_LOCAL_GET(0))),
           WASM_SIMD_F32x4_EXTRACT_LANE(1, WASM_LOCAL_GET(1))});
  CHECK_EQ(30.5, r.Call());
}

WASM_EXEC_TEST(SimdF32x4AddWithI32x4) {
  // Choose two floating point values whose sum is normal and exactly
  // representable as a float.
  const int kOne = 0x3F800000;
  const int kTwo = 0x40000000;
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_IF_ELSE_I(
      WASM_F32_EQ(
          WASM_SIMD_F32x4_EXTRACT_LANE(
              0, WASM_SIMD_BINOP(kExprF32x4Add,
                                 WASM_SIMD_I32x4_SPLAT(WASM_I32V(kOne)),
                                 WASM_SIMD_I32x4_SPLAT(WASM_I32V(kTwo)))),
          WASM_F32_ADD(WASM_F32_REINTERPRET_I32(WASM_I32V(kOne)),
                       WASM_F32_REINTERPRET_I32(WASM_I32V(kTwo)))),
      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdI32x4AddWithF32x4) {
  WasmRunner<int32_t> r(execution_tier);
  r.Build({WASM_IF_ELSE_I(
      WASM_I32_EQ(
          WASM_SIMD_I32x4_EXTRACT_LANE(
              0, WASM_SIMD_BINOP(kExprI32x4Add,
                                 WASM_SIMD_F32x4_SPLAT(WASM_F32(21.25)),
                                 WASM_SIMD_F32x4_SPLAT(WASM_F32(31.5)))),
          WASM_I32_ADD(WASM_I32_REINTERPRET_F32(WASM_F32(21.25)),
                       WASM_I32_REINTERPRET_F32(WASM_F32(31.5)))),
      WASM_I32V(1), WASM_I32V(0))});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdI32x4Local) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(0, WASM_SIMD_I32x4_SPLAT(WASM_I32V(31))),
           WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_LOCAL_GET(0))});
  CHECK_EQ(31, r.Call());
}

WASM_EXEC_TEST(SimdI32x4SplatFromExtract) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(0, WASM_SIMD_I32x4_EXTRACT_LANE(
                                 0, WASM_SIMD_I32x4_SPLAT(WASM_I32V(76)))),
           WASM_LOCAL_SET(1, WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(0))),
           WASM_SIMD_I32x4_EXTRACT_LANE(1, WASM_LOCAL_GET(1))});
  CHECK_EQ(76, r.Call());
}

WASM_EXEC_TEST(SimdI32x4For) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmS128);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_SIMD_I32x4_SPLAT(WASM_I32V(31))),
       WASM_LOCAL_SET(1, WASM_SIMD_I32x4_REPLACE_LANE(1, WASM_LOCAL_GET(1),
                                                      WASM_I32V(53))),
       WASM_LOCAL_SET(1, WASM_SIMD_I32x4_REPLACE_LANE(2, WASM_LOCAL_GET(1),
                                                      WASM_I32V(23))),
       WASM_LOCAL_SET(0, WASM_I32V(0)),
       WASM_LOOP(
           WASM_LOCAL_SET(1,
                          WASM_SIMD_BINOP(kExprI32x4Add, WASM_LOCAL_GET(1),
                                          WASM_SIMD_I32x4_SPLAT(WASM_I32V(1)))),
           WASM_IF(WASM_I32_NE(WASM_INC_LOCAL(0), WASM_I32V(5)), WASM_BR(1))),
       WASM_LOCAL_SET(0, WASM_I32V(1)),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_LOCAL_GET(1)),
                           WASM_I32V(36)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(1, WASM_LOCAL_GET(1)),
                           WASM_I32V(58)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(2, WASM_LOCAL_GET(1)),
                           WASM_I32V(28)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_SIMD_I32x4_EXTRACT_LANE(3, WASM_LOCAL_GET(1)),
                           WASM_I32V(36)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_LOCAL_GET(0)});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(SimdF32x4For) {
  WasmRunner<int32_t> r(execution_tier);
  r.AllocateLocal(kWasmI32);
  r.AllocateLocal(kWasmS128);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_SIMD_F32x4_SPLAT(WASM_F32(21.25))),
       WASM_LOCAL_SET(1, WASM_SIMD_F32x4_REPLACE_LANE(3, WASM_LOCAL_GET(1),
                                                      WASM_F32(19.5))),
       WASM_LOCAL_SET(0, WASM_I32V(0)),
       WASM_LOOP(
           WASM_LOCAL_SET(
               1, WASM_SIMD_BINOP(kExprF32x4Add, WASM_LOCAL_GET(1),
                                  WASM_SIMD_F32x4_SPLAT(WASM_F32(2.0)))),
           WASM_IF(WASM_I32_NE(WASM_INC_LOCAL(0), WASM_I32V(3)), WASM_BR(1))),
       WASM_LOCAL_SET(0, WASM_I32V(1)),
       WASM_IF(WASM_F32_NE(WASM_SIMD_F32x4_EXTRACT_LANE(0, WASM_LOCAL_GET(1)),
                           WASM_F32(27.25)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_SIMD_F32x4_EXTRACT_LANE(3, WASM_LOCAL_GET(1)),
                           WASM_F32(25.5)),
               WASM_LOCAL_SET(0, WASM_I32V(0))),
       WASM_LOCAL_GET(0)});
  CHECK_EQ(1, r.Call());
}

template <typename T, int numLanes = 4>
void SetVectorByLanes(T* v, const std::array<T, numLanes>& arr) {
  for (int lane = 0; lane < numLanes; lane++) {
    LANE(v, lane) = arr[lane];
  }
}

template <typename T>
const T GetScalar(T* v, int lane) {
  DCHECK_GE(lane, 0);
  DCHECK_LT(static_cast<uint32_t>(lane), kSimd128Size / sizeof(T));
  return LANE(v, lane);
}

WASM_EXEC_TEST(SimdI32x4GetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Pad the globals with a few unused slots to get a non-zero offset.
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  int32_t* global = r.builder().AddGlobal<int32_t>(kWasmS128);
  SetVectorByLanes(global, {{0, 1, 2, 3}});
  r.AllocateLocal(kWasmI32);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_I32V(1)),
       WASM_IF(WASM_I32_NE(WASM_I32V(0),
                           WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_I32V(1),
                           WASM_SIMD_I32x4_EXTRACT_LANE(1, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_I32V(2),
                           WASM_SIMD_I32x4_EXTRACT_LANE(2, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_I32_NE(WASM_I32V(3),
                           WASM_SIMD_I32x4_EXTRACT_LANE(3, WASM_GLOBAL_GET(4))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_LOCAL_GET(1)});
  CHECK_EQ(1, r.Call(0));
}

WASM_EXEC_TEST(SimdI32x4SetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  // Pad the globals with a few unused slots to get a non-zero offset.
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  r.builder().AddGlobal<int32_t>(kWasmI32);  // purposefully unused
  int32_t* global = r.builder().AddGlobal<int32_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_SPLAT(WASM_I32V(23))),
           WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_REPLACE_LANE(
                                  1, WASM_GLOBAL_GET(4), WASM_I32V(34))),
           WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_REPLACE_LANE(
                                  2, WASM_GLOBAL_GET(4), WASM_I32V(45))),
           WASM_GLOBAL_SET(4, WASM_SIMD_I32x4_REPLACE_LANE(
                                  3, WASM_GLOBAL_GET(4), WASM_I32V(56))),
           WASM_I32V(1)});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(GetScalar(global, 0), 23);
  CHECK_EQ(GetScalar(global, 1), 34);
  CHECK_EQ(GetScalar(global, 2), 45);
  CHECK_EQ(GetScalar(global, 3), 56);
}

WASM_EXEC_TEST(SimdF32x4GetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  float* global = r.builder().AddGlobal<float>(kWasmS128);
  SetVectorByLanes<float>(global, {{0.0, 1.5, 2.25, 3.5}});
  r.AllocateLocal(kWasmI32);
  r.Build(
      {WASM_LOCAL_SET(1, WASM_I32V(1)),
       WASM_IF(WASM_F32_NE(WASM_F32(0.0),
                           WASM_SIMD_F32x4_EXTRACT_LANE(0, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_F32(1.5),
                           WASM_SIMD_F32x4_EXTRACT_LANE(1, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_F32(2.25),
                           WASM_SIMD_F32x4_EXTRACT_LANE(2, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_IF(WASM_F32_NE(WASM_F32(3.5),
                           WASM_SIMD_F32x4_EXTRACT_LANE(3, WASM_GLOBAL_GET(0))),
               WASM_LOCAL_SET(1, WASM_I32V(0))),
       WASM_LOCAL_GET(1)});
  CHECK_EQ(1, r.Call(0));
}

WASM_EXEC_TEST(SimdF32x4SetGlobal) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  float* global = r.builder().AddGlobal<float>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_SPLAT(WASM_F32(13.5))),
           WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_REPLACE_LANE(
                                  1, WASM_GLOBAL_GET(0), WASM_F32(45.5))),
           WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_REPLACE_LANE(
                                  2, WASM_GLOBAL_GET(0), WASM_F32(32.25))),
           WASM_GLOBAL_SET(0, WASM_SIMD_F32x4_REPLACE_LANE(
                                  3, WASM_GLOBAL_GET(0), WASM_F32(65.0))),
           WASM_I32V(1)});
  CHECK_EQ(1, r.Call(0));
  CHECK_EQ(GetScalar(global, 0), 13.5f);
  CHECK_EQ(GetScalar(global, 1), 45.5f);
  CHECK_EQ(GetScalar(global, 2), 32.25f);
  CHECK_EQ(GetScalar(global, 3), 65.0f);
}

WASM_EXEC_TEST(SimdLoadStoreLoad) {
  {
    WasmRunner<int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    // Load memory, store it, then reload it and extract the first lane. Use a
    // non-zero offset into the memory of 1 lane (4 bytes) to test indexing.
    r.Build(
        {WASM_SIMD_STORE_MEM(WASM_I32V(8), WASM_SIMD_LOAD_MEM(WASM_I32V(4))),
         WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_SIMD_LOAD_MEM(WASM_I32V(8)))});

    FOR_INT32_INPUTS(i) {
      int32_t expected = i;
      r.builder().WriteMemory(&memory[1], expected);
      CHECK_EQ(expected, r.Call());
    }
  }

  {
    // OOB tests for loads.
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.Build({WASM_SIMD_I32x4_EXTRACT_LANE(
        0, WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(0)))});

    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }

  {
    // OOB tests for stores.
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    r.Build(
        {WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(0), WASM_SIMD_LOAD_MEM(WASM_ZERO)),
         WASM_ONE});

    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(SimdLoadStoreLoadMemargOffset) {
  {
    WasmRunner<int32_t> r(execution_tier);
    int32_t* memory =
        r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
    constexpr uint8_t offset_1 = 4;
    constexpr uint8_t offset_2 = 8;
    // Load from memory at offset_1, store to offset_2, load from offset_2, and
    // extract first lane. We use non-zero memarg offsets to test offset
    // decoding.
    r.Build({WASM_SIMD_STORE_MEM_OFFSET(
                 offset_2, WASM_ZERO,
                 WASM_SIMD_LOAD_MEM_OFFSET(offset_1, WASM_ZERO)),
             WASM_SIMD_I32x4_EXTRACT_LANE(
                 0, WASM_SIMD_LOAD_MEM_OFFSET(offset_2, WASM_ZERO))});

    FOR_INT32_INPUTS(i) {
      int32_t expected = i;
      // Index 1 of memory (int32_t) will be bytes 4 to 8.
      r.builder().WriteMemory(&memory[1], expected);
      CHECK_EQ(expected, r.Call());
    }
  }

  {
    // OOB tests for loads with offsets.
    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      WasmRunner<int32_t> r(execution_tier);
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
      r.Build({WASM_SIMD_I32x4_EXTRACT_LANE(
          0, WASM_SIMD_LOAD_MEM_OFFSET(U32V_3(offset), WASM_ZERO))});
      CHECK_TRAP(r.Call());
    }
  }

  {
    // OOB tests for stores with offsets
    for (uint32_t offset = kWasmPageSize - (kSimd128Size - 1);
         offset < kWasmPageSize; ++offset) {
      WasmRunner<int32_t, uint32_t> r(execution_tier);
      r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
      r.Build({WASM_SIMD_STORE_MEM_OFFSET(U32V_3(offset), WASM_ZERO,
                                          WASM_SIMD_LOAD_MEM(WASM_ZERO)),
               WASM_ONE});
      CHECK_TRAP(r.Call(offset));
    }
  }
}

// Test a multi-byte opcode with offset values that encode into valid opcodes.
// This is to exercise decoding logic and make sure we get the lengths right.
WASM_EXEC_TEST(S128Load8SplatOffset) {
  // This offset is [82, 22] when encoded, which contains valid opcodes.
  constexpr int offset = 4354;
  WasmRunner<int32_t> r(execution_tier);
  int8_t* memory = r.builder().AddMemoryElems<int8_t>(kWasmPageSize);
  int8_t* global = r.builder().AddGlobal<int8_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(
               0, WASM_SIMD_LOAD_OP_OFFSET(kExprS128Load8Splat, WASM_I32V(0),
                                           U32V_2(offset))),
           WASM_ONE});

  // We don't really care about all valid values, so just test for 1.
  int8_t x = 7;
  r.builder().WriteMemory(&memory[offset], x);
  r.Call();
  for (int i = 0; i < 16; i++) {
    CHECK_EQ(x, LANE(global, i));
  }
}

template <typename T>
void RunLoadSplatTest(TestExecutionTier execution_tier, WasmOpcode op) {
  constexpr int lanes = 16 / sizeof(T);
  constexpr int mem_index = 16;  // Load from mem index 16 (bytes).
  {
    WasmRunner<int32_t> r(execution_tier);
    T* memory = r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));
    T* global = r.builder().AddGlobal<T>(kWasmS128);
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_I32V(mem_index))),
             WASM_ONE});

    for (T x : compiler::ValueHelper::GetVector<T>()) {
      // 16-th byte in memory is lanes-th element (size T) of memory.
      r.builder().WriteMemory(&memory[lanes], x);
      r.Call();
      for (int i = 0; i < lanes; i++) {
        CHECK_EQ(x, LANE(global, i));
      }
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));
    r.builder().AddGlobal<T>(kWasmS128);

    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_LOCAL_GET(0))),
             WASM_ONE});

    // Load splats load sizeof(T) bytes.
    for (uint32_t offset = kWasmPageSize - (sizeof(T) - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(S128Load8Splat) {
  RunLoadSplatTest<int8_t>(execution_tier, kExprS128Load8Splat);
}

WASM_EXEC_TEST(S128Load16Splat) {
  RunLoadSplatTest<int16_t>(execution_tier, kExprS128Load16Splat);
}

WASM_EXEC_TEST(S128Load32Splat) {
  RunLoadSplatTest<int32_t>(execution_tier, kExprS128Load32Splat);
}

WASM_EXEC_TEST(S128Load64Splat) {
  RunLoadSplatTest<int64_t>(execution_tier, kExprS128Load64Splat);
}

template <typename S, typename T>
void RunLoadExtendTest(TestExecutionTier execution_tier, WasmOpcode op) {
  static_assert(sizeof(S) < sizeof(T),
                "load extend should go from smaller to larger type");
  constexpr int lanes_s = 16 / sizeof(S);
  constexpr int lanes_t = 16 / sizeof(T);
  constexpr int mem_index = 16;  // Load from mem index 16 (bytes).
  // Load extends always load 64 bits, so alignment values can be from 0 to 3.
  for (uint8_t alignment = 0; alignment <= 3; alignment++) {
    WasmRunner<int32_t> r(execution_tier);
    S* memory = r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    T* global = r.builder().AddGlobal<T>(kWasmS128);
    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP_ALIGNMENT(
                                    op, WASM_I32V(mem_index), alignment)),
             WASM_ONE});

    for (S x : compiler::ValueHelper::GetVector<S>()) {
      for (int i = 0; i < lanes_s; i++) {
        // 16-th byte in memory is lanes-th element (size T) of memory.
        r.builder().WriteMemory(&memory[lanes_s + i], x);
      }
      r.Call();
      for (int i = 0; i < lanes_t; i++) {
        CHECK_EQ(static_cast<T>(x), LANE(global, i));
      }
    }
  }

  // Test for offset.
  {
    WasmRunner<int32_t> r(execution_tier);
    S* memory = r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    T* global = r.builder().AddGlobal<T>(kWasmS128);
    constexpr uint8_t offset = sizeof(S);
    r.Build(
        {WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP_OFFSET(op, WASM_ZERO, offset)),
         WASM_ONE});

    // Let max_s be the max_s value for type S, we set up the memory as such:
    // memory = [max_s, max_s - 1, ... max_s - (lane_s - 1)].
    constexpr S max_s = std::numeric_limits<S>::max();
    for (int i = 0; i < lanes_s; i++) {
      // Integer promotion due to -, static_cast to narrow.
      r.builder().WriteMemory(&memory[i], static_cast<S>(max_s - i));
    }

    r.Call();

    // Loads will be offset by sizeof(S), so will always start from (max_s - 1).
    for (int i = 0; i < lanes_t; i++) {
      // Integer promotion due to -, static_cast to narrow.
      T expected = static_cast<T>(max_s - i - 1);
      CHECK_EQ(expected, LANE(global, i));
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    r.builder().AddGlobal<T>(kWasmS128);

    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_LOCAL_GET(0))),
             WASM_ONE});

    // Load extends load 8 bytes, so should trap from -7.
    for (uint32_t offset = kWasmPageSize - 7; offset < kWasmPageSize;
         ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(S128Load8x8U) {
  RunLoadExtendTest<uint8_t, uint16_t>(execution_tier, kExprS128Load8x8U);
}

WASM_EXEC_TEST(S128Load8x8S) {
  RunLoadExtendTest<int8_t, int16_t>(execution_tier, kExprS128Load8x8S);
}
WASM_EXEC_TEST(S128Load16x4U) {
  RunLoadExtendTest<uint16_t, uint32_t>(execution_tier, kExprS128Load16x4U);
}

WASM_EXEC_TEST(S128Load16x4S) {
  RunLoadExtendTest<int16_t, int32_t>(execution_tier, kExprS128Load16x4S);
}

WASM_EXEC_TEST(S128Load32x2U) {
  RunLoadExtendTest<uint32_t, uint64_t>(execution_tier, kExprS128Load32x2U);
}

WASM_EXEC_TEST(S128Load32x2S) {
  RunLoadExtendTest<int32_t, int64_t>(execution_tier, kExprS128Load32x2S);
}

template <typename S>
void RunLoadZeroTest(TestExecutionTier execution_tier, WasmOpcode op) {
  constexpr int lanes_s = kSimd128Size / sizeof(S);
  constexpr int mem_index = 16;  // Load from mem index 16 (bytes).
  constexpr S sentinel = S{-1};
  S* memory;
  S* global;

  auto initialize_builder = [=](WasmRunner<int32_t>* r) -> std::tuple<S*, S*> {
    S* memory = r->builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    S* global = r->builder().AddGlobal<S>(kWasmS128);
    r->builder().RandomizeMemory();
    r->builder().WriteMemory(&memory[lanes_s], sentinel);
    return std::make_tuple(memory, global);
  };

  // Check all supported alignments.
  constexpr int max_alignment = base::bits::CountTrailingZeros(sizeof(S));
  for (uint8_t alignment = 0; alignment <= max_alignment; alignment++) {
    WasmRunner<int32_t> r(execution_tier);
    std::tie(memory, global) = initialize_builder(&r);

    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_I32V(mem_index))),
             WASM_ONE});
    r.Call();

    // Only first lane is set to sentinel.
    CHECK_EQ(sentinel, LANE(global, 0));
    // The other lanes are zero.
    for 
"""


```