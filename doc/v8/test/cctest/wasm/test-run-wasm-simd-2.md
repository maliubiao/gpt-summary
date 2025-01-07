Response: The user wants a summary of the C++ code functionality in the provided snippet. It's the third part of a five-part file. The code seems to be testing WebAssembly SIMD (Single Instruction, Multiple Data) instructions.

Here's a breakdown of the thinking process to summarize the code:

1. **Identify the Core Purpose:** The file name `test-run-wasm-simd.cc` and the presence of `WASM_EXEC_TEST` macros strongly suggest this is a test file for WebAssembly SIMD functionality within the V8 JavaScript engine.

2. **Examine the `WASM_EXEC_TEST` Macros:** Each `WASM_EXEC_TEST` defines an individual test case. The names of these tests (e.g., `S128Load32Zero`, `S128Load8Lane`, `S128Store8Lane`, `I32x4AnyTrue`, `BitSelect`, `S128Const`, etc.) indicate the specific SIMD instructions or categories of instructions being tested.

3. **Analyze the Test Structure:**  Most tests follow a similar pattern:
    * **Setup:**  Creating a `WasmRunner` object, optionally allocating memory or globals.
    * **Build:**  Constructing WebAssembly bytecode using WASM_* macros to represent SIMD instructions. This often involves loading data into SIMD registers, performing operations, and storing the results.
    * **Call:** Executing the generated WebAssembly code.
    * **Check:** Verifying the results by comparing the actual output (in memory or globals) with the expected output using `CHECK_EQ` or `CHECK_TRAP`.

4. **Group Similar Tests:** Notice groups of tests related to specific operations:
    * **Loads:** `S128Load32Zero`, `S128Load64Zero`, `S128Load8Lane`, `S128Load16Lane`, `S128Load32Lane`, `S128Load64Lane`. These test different load instructions with variations like zero-extension and lane selection.
    * **Stores:** `S128Store8Lane`, `S128Store16Lane`, `S128Store32Lane`, `S128Store64Lane`. These test different store instructions with lane selection.
    * **Logical Operations:** `S32x4AnyTrue`, `I32x4AllTrue`, `V128AnytrueWithNegativeZero`. These test logical operations on SIMD vectors.
    * **Constants:** `S128Const`, `S128ConstAllZero`, `S128ConstAllOnes`. These test the ability to create SIMD vectors with constant values.
    * **Comparisons:** `I8x16LeUMixed`, `I8x16LtUMixed`, etc. These test comparison operations between SIMD vectors.
    * **Lane Extraction/Insertion:** `I16x8ExtractLaneU_I8x16Splat`.
    * **Extended Arithmetic:** `AddExtAddPairwiseI32Right`, `AddExtAddPairwiseI16Left`, etc. These test operations that combine elements of SIMD vectors.
    * **Bitwise Select:** `BitSelect`.
    * **Revectorization (Marked by `#ifdef V8_ENABLE_WASM_SIMD256_REVEC` and `TEST(RunWasmTurbofan_...)`):**  These tests are specifically for the Turbofan compiler's ability to optimize SIMD code for 256-bit registers (AVX/AVX2). They test various operations like constants, extraction, arithmetic, logical operations, shifts, conversions, shuffles, and load/store operations in the context of 256-bit SIMD.

5. **Identify Key Concepts:** The code demonstrates testing of:
    * **Loading and storing SIMD vectors from/to memory.**
    * **Performing arithmetic, logical, and comparison operations on entire SIMD vectors.**
    * **Selecting specific lanes within a SIMD vector.**
    * **Creating SIMD vectors with constant values.**
    * **Handling memory access boundaries (OOB - Out Of Bounds).**
    * **Unsigned and signed operations.**
    * **Revectorization optimizations for wider SIMD registers.**

6. **Consider the JavaScript Connection:**  WebAssembly is designed to be a compilation target for languages like C++ and can be executed in JavaScript environments. The SIMD instructions tested here directly correspond to SIMD operations available in JavaScript's WebAssembly API.

7. **Formulate the Summary:** Based on the above analysis, construct a concise summary highlighting the main functionalities tested in this code snippet. Include examples of how these SIMD operations translate to JavaScript.
这是 `v8/test/cctest/wasm/test-run-wasm-simd.cc` 文件的一部分，主要功能是**测试 WebAssembly SIMD (Single Instruction, Multiple Data) 指令的执行。**

具体来说，这部分代码侧重于测试以下几类 SIMD 指令：

* **加载和存储指令 (Load and Store):**
    * `S128Load32Zero` 和 `S128Load64Zero`: 测试从内存加载 128 位数据，并将未使用的字节用零填充。
    * `S128Load8Lane`, `S128Load16Lane`, `S128Load32Lane`, `S128Load64Lane`: 测试从内存加载 128 位数据，但只更新指定通道的值，其余通道保持不变。
    * `S128Store8Lane`, `S128Store16Lane`, `S128Store32Lane`, `S128Store64Lane`: 测试将 SIMD 寄存器中指定通道的值存储到内存中。
* **逻辑比较指令 (Logical Comparisons):**
    * `SformatAnyTrue` (例如 `S32x4AnyTrue`, `S16x8AnyTrue`, `S8x16AnyTrue`): 测试检查 SIMD 向量中是否有任何通道为真。
    * `IformatAllTrue` (例如 `I64x2AllTrue`, `I32x4AllTrue`, `I16x8AllTrue`, `I8x16AllTrue`): 测试检查 SIMD 向量中是否所有通道都为真。
    * `V128AnytrueWithNegativeZero`: 特殊的 `anytrue` 测试用例，用于确保正确处理浮点数中的正零和负零。
* **位选择指令 (Bit Select):**
    * `BitSelect`: 测试根据一个掩码向量，从两个源向量中选择位组成新的向量。
* **常量指令 (Constant):**
    * `S128Const`: 测试创建包含任意常量值的 SIMD 向量。
    * `S128ConstAllZero`: 测试创建包含全零的 SIMD 向量。
    * `S128ConstAllOnes`: 测试创建包含全一的 SIMD 向量。
* **带符号/无符号比较指令 (Signed/Unsigned Comparisons):**
    * `I8x16LeUMixed`, `I8x16LtUMixed`, `I8x16GeUMixed`, `I8x16GtUMixed`: 测试有符号和无符号的比较操作。
    * `I16x8LeUMixed`, `I16x8LtUMixed`, `I16x8GeUMixed`, `I16x8GtUMixed`: 测试有符号和无符号的比较操作。
* **通道提取指令 (Extract Lane):**
    * `I16x8ExtractLaneU_I8x16Splat`: 测试从 SIMD 向量中提取指定通道的值，并进行符号/无符号扩展。
* **扩展加法指令 (Extended Add):**
    * `AddExtAddPairwiseI32Right`, `AddExtAddPairwiseI32Left`, `AddExtAddPairwiseI16Right`, `AddExtAddPairwiseI16Left`, `AddExtAddPairwiseI32RightUnsigned`, `AddExtAddPairwiseI32LeftUnsigned`: 测试将较小数据类型的 SIMD 向量进行成对的扩展加法。
* **回归测试 (Regression Test):**
    * `Regress_12237`: 针对特定 bug 的回归测试。
* **通用通道提取测试 (Generic Extract Lane Tests):**
    * `I16X8ExtractLaneS`, `I16X8ExtractLaneI`, `I8x16ExtractLaneS`, `I8x16ExtractLaneI`:  使用宏定义来测试提取不同大小通道的值。
* **基于 Revectorization 的 256 位 SIMD 测试 (Conditional Compilation):**
    * 这部分代码被 `#ifdef V8_ENABLE_WASM_SIMD256_REVEC` 包裹，表明这些测试只有在启用了 256 位 SIMD 重向量化优化时才会编译和执行。
    * 这部分测试覆盖了 256 位 SIMD 常量、提取、算术、逻辑、转换、Shuffle 以及加载存储等操作。

**与 JavaScript 的关系及举例:**

这些 C++ 测试代码验证了 V8 引擎中 WebAssembly SIMD 指令的正确性。这些指令在 JavaScript 中可以通过 `WebAssembly.SIMD` API 来使用。

例如，C++ 代码中的 `WASM_EXEC_TEST(S128Load32Zero)` 测试了加载一个 128 位 SIMD 值并将未使用的字节置零的操作。  这对应于 JavaScript 中的 `v128.load32Zero(offset)` 操作。

**C++ 代码片段中的 `S128Load32Zero` 测试：**

```c++
WASM_EXEC_TEST(S128Load32Zero) {
  RunLoadZeroTest<int32_t>(execution_tier, kExprS128Load32Zero);
}
```

**对应的 JavaScript 代码：**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const buffer = new Uint8Array(memory.buffer);
const i32 = new Int32Array(memory.buffer);
const v128Ty = WebAssembly.SIMD.v128;

// 假设在内存的某个位置存储了一些数据
i32[0] = 10;
i32[1] = 20;
i32[2] = 30;
i32[3] = 40;

const v = v128Ty.load32Zero(buffer, 0); // 从 buffer 的偏移量 0 加载 128 位

// v 现在是一个 SIMD 向量，它的值可能类似于 [10, 20, 30, 40]，
// 但是 load32Zero 会确保加载的是 32 位整数，并将其扩展到 128 位，
// 其余部分用零填充。具体行为取决于 WASM 规范对该指令的定义。
```

**C++ 代码片段中的 `S128Load8Lane` 测试：**

```c++
WASM_EXEC_TEST(S128Load8Lane) {
  RunLoadLaneTest<int8_t>(execution_tier, kExprS128Load8Lane, kExprI8x16Splat);
}
```

**对应的 JavaScript 代码：**

```javascript
const memory = new WebAssembly.Memory({ initial: 1 });
const buffer = new Uint8Array(memory.buffer);
const v128Ty = WebAssembly.SIMD.v128;
const i8x16 = WebAssembly.SIMD.int8x16;

// 创建一个初始的 SIMD 向量
let v = i8x16.splat(5); // v 的所有 16 个通道都初始化为 5

// 在 buffer 的偏移量 0 存储值 10
buffer[0] = 10;

// 使用 load8Lane 加载 buffer 偏移量 0 的 8 位值，并将其放入 v 的第 0 个通道
v = v128Ty.load8Lane(v, buffer, 0, 0); // 第一个 0 是要加载的内存偏移，第二个 0 是要替换的通道索引

// 现在 v 的第 0 个通道的值是 10，其余通道的值仍然是 5
```

总而言之，这部分 C++ 代码是 V8 引擎中用于测试 WebAssembly SIMD 功能的核心部分，它确保了各种 SIMD 指令在不同场景下的正确执行，并为 JavaScript 中使用的 `WebAssembly.SIMD` API 提供了可靠的基础。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
(int i = 1; i < lanes_s; i++) {
      CHECK_EQ(S{0}, LANE(global, i));
    }
  }

  {
    // Use memarg to specific offset.
    WasmRunner<int32_t> r(execution_tier);
    std::tie(memory, global) = initialize_builder(&r);

    r.Build(
        {WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP_OFFSET(op, WASM_ZERO, mem_index)),
         WASM_ONE});
    r.Call();

    // Only first lane is set to sentinel.
    CHECK_EQ(sentinel, LANE(global, 0));
    // The other lanes are zero.
    for (int i = 1; i < lanes_s; i++) {
      CHECK_EQ(S{0}, LANE(global, i));
    }
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<S>(kWasmPageSize / sizeof(S));
    r.builder().AddGlobal<S>(kWasmS128);

    r.Build({WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(op, WASM_LOCAL_GET(0))),
             WASM_ONE});

    // Load extends load sizeof(S) bytes.
    for (uint32_t offset = kWasmPageSize - (sizeof(S) - 1);
         offset < kWasmPageSize; ++offset) {
      CHECK_TRAP(r.Call(offset));
    }
  }
}

WASM_EXEC_TEST(S128Load32Zero) {
  RunLoadZeroTest<int32_t>(execution_tier, kExprS128Load32Zero);
}

WASM_EXEC_TEST(S128Load64Zero) {
  RunLoadZeroTest<int64_t>(execution_tier, kExprS128Load64Zero);
}

template <typename T>
void RunLoadLaneTest(TestExecutionTier execution_tier, WasmOpcode load_op,
                     WasmOpcode splat_op) {
  uint8_t const_op = static_cast<uint8_t>(
      splat_op == kExprI64x2Splat ? kExprI64Const : kExprI32Const);

  constexpr uint8_t lanes_s = kSimd128Size / sizeof(T);
  constexpr int mem_index = 16;  // Load from mem index 16 (bytes).
  constexpr uint8_t splat_value = 33;
  T sentinel = T{-1};

  T* memory;
  T* global;

  auto build_fn = [=, &memory, &global](WasmRunner<int32_t>& r, int mem_index,
                                        uint8_t lane, uint8_t alignment,
                                        uint8_t offset) {
    memory = r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));
    global = r.builder().AddGlobal<T>(kWasmS128);
    r.builder().WriteMemory(&memory[lanes_s], sentinel);
    // Splat splat_value, then only load and replace a single lane with the
    // sentinel value.
    r.Build({WASM_I32V(mem_index), const_op, splat_value,
             WASM_SIMD_OP(splat_op), WASM_SIMD_OP(load_op), alignment, offset,
             lane, kExprGlobalSet, 0, WASM_ONE});
  };

  auto check_results = [=](T* global, int sentinel_lane = 0) {
    // Only one lane is loaded, the rest of the lanes are unchanged.
    for (uint8_t i = 0; i < lanes_s; i++) {
      T expected = i == sentinel_lane ? sentinel : static_cast<T>(splat_value);
      CHECK_EQ(expected, LANE(global, i));
    }
  };

  for (uint8_t lane_index = 0; lane_index < lanes_s; ++lane_index) {
    WasmRunner<int32_t> r(execution_tier);
    build_fn(r, mem_index, lane_index, /*alignment=*/0, /*offset=*/0);
    r.Call();
    check_results(global, lane_index);
  }

  // Check all possible alignments.
  constexpr int max_alignment = base::bits::CountTrailingZeros(sizeof(T));
  for (uint8_t alignment = 0; alignment <= max_alignment; ++alignment) {
    WasmRunner<int32_t> r(execution_tier);
    build_fn(r, mem_index, /*lane=*/0, alignment, /*offset=*/0);
    r.Call();
    check_results(global);
  }

  {
    // Use memarg to specify offset.
    int lane_index = 0;
    WasmRunner<int32_t> r(execution_tier);
    build_fn(r, /*mem_index=*/0, /*lane=*/0, /*alignment=*/0,
             /*offset=*/mem_index);
    r.Call();
    check_results(global, lane_index);
  }

  // Test for OOB.
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));
    r.builder().AddGlobal<T>(kWasmS128);

    r.Build({WASM_LOCAL_GET(0), const_op, splat_value, WASM_SIMD_OP(splat_op),
             WASM_SIMD_OP(load_op), ZERO_ALIGNMENT, ZERO_OFFSET, 0,
             kExprGlobalSet, 0, WASM_ONE});

    // Load lane load sizeof(T) bytes.
    for (uint32_t index = kWasmPageSize - (sizeof(T) - 1);
         index < kWasmPageSize; ++index) {
      CHECK_TRAP(r.Call(index));
    }
  }
}

WASM_EXEC_TEST(S128Load8Lane) {
  RunLoadLaneTest<int8_t>(execution_tier, kExprS128Load8Lane, kExprI8x16Splat);
}

WASM_EXEC_TEST(S128Load16Lane) {
  RunLoadLaneTest<int16_t>(execution_tier, kExprS128Load16Lane,
                           kExprI16x8Splat);
}

WASM_EXEC_TEST(S128Load32Lane) {
  RunLoadLaneTest<int32_t>(execution_tier, kExprS128Load32Lane,
                           kExprI32x4Splat);
}

WASM_EXEC_TEST(S128Load64Lane) {
  RunLoadLaneTest<int64_t>(execution_tier, kExprS128Load64Lane,
                           kExprI64x2Splat);
}

template <typename T>
void RunStoreLaneTest(TestExecutionTier execution_tier, WasmOpcode store_op,
                      WasmOpcode splat_op) {
  constexpr uint8_t lanes = kSimd128Size / sizeof(T);
  constexpr int mem_index = 16;  // Store to mem index 16 (bytes).
  constexpr uint8_t splat_value = 33;
  uint8_t const_op = static_cast<uint8_t>(
      splat_op == kExprI64x2Splat ? kExprI64Const : kExprI32Const);

  T* memory;  // Will be set by build_fn.

  auto build_fn = [=, &memory](WasmRunner<int32_t>& r, int mem_index,
                               uint8_t lane_index, uint8_t alignment,
                               uint8_t offset) {
    memory = r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));
    // Splat splat_value, then only Store and replace a single lane.
    r.Build({WASM_I32V(mem_index), const_op, splat_value,
             WASM_SIMD_OP(splat_op), WASM_SIMD_OP(store_op), alignment, offset,
             lane_index, WASM_ONE});
    r.builder().BlankMemory();
  };

  auto check_results = [=](WasmRunner<int32_t>& r, T* memory) {
    for (uint8_t i = 0; i < lanes; i++) {
      CHECK_EQ(0, r.builder().ReadMemory(&memory[i]));
    }

    CHECK_EQ(splat_value, r.builder().ReadMemory(&memory[lanes]));

    for (uint8_t i = lanes + 1; i < lanes * 2; i++) {
      CHECK_EQ(0, r.builder().ReadMemory(&memory[i]));
    }
  };

  for (uint8_t lane_index = 0; lane_index < lanes; lane_index++) {
    WasmRunner<int32_t> r(execution_tier);
    build_fn(r, mem_index, lane_index, ZERO_ALIGNMENT, ZERO_OFFSET);
    r.Call();
    check_results(r, memory);
  }

  // Check all possible alignments.
  constexpr int max_alignment = base::bits::CountTrailingZeros(sizeof(T));
  for (uint8_t alignment = 0; alignment <= max_alignment; ++alignment) {
    WasmRunner<int32_t> r(execution_tier);
    build_fn(r, mem_index, /*lane_index=*/0, alignment, ZERO_OFFSET);
    r.Call();
    check_results(r, memory);
  }

  {
    // Use memarg for offset.
    WasmRunner<int32_t> r(execution_tier);
    build_fn(r, /*mem_index=*/0, /*lane_index=*/0, ZERO_ALIGNMENT, mem_index);
    r.Call();
    check_results(r, memory);
  }

  // OOB stores
  {
    WasmRunner<int32_t, uint32_t> r(execution_tier);
    r.builder().AddMemoryElems<T>(kWasmPageSize / sizeof(T));

    r.Build({WASM_LOCAL_GET(0), const_op, splat_value, WASM_SIMD_OP(splat_op),
             WASM_SIMD_OP(store_op), ZERO_ALIGNMENT, ZERO_OFFSET, 0, WASM_ONE});

    // StoreLane stores sizeof(T) bytes.
    for (uint32_t index = kWasmPageSize - (sizeof(T) - 1);
         index < kWasmPageSize; ++index) {
      CHECK_TRAP(r.Call(index));
    }
  }
}

WASM_EXEC_TEST(S128Store8Lane) {
  RunStoreLaneTest<int8_t>(execution_tier, kExprS128Store8Lane,
                           kExprI8x16Splat);
}

WASM_EXEC_TEST(S128Store16Lane) {
  RunStoreLaneTest<int16_t>(execution_tier, kExprS128Store16Lane,
                            kExprI16x8Splat);
}

WASM_EXEC_TEST(S128Store32Lane) {
  RunStoreLaneTest<int32_t>(execution_tier, kExprS128Store32Lane,
                            kExprI32x4Splat);
}

WASM_EXEC_TEST(S128Store64Lane) {
  RunStoreLaneTest<int64_t>(execution_tier, kExprS128Store64Lane,
                            kExprI64x2Splat);
}

#define WASM_SIMD_ANYTRUE_TEST(format, lanes, max, param_type)                 \
  WASM_EXEC_TEST(S##format##AnyTrue) {                                         \
    WasmRunner<int32_t, param_type> r(execution_tier);                         \
    if (lanes == 2) return;                                                    \
    uint8_t simd = r.AllocateLocal(kWasmS128);                                 \
    r.Build(                                                                   \
        {WASM_LOCAL_SET(simd, WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(0))), \
         WASM_SIMD_UNOP(kExprV128AnyTrue, WASM_LOCAL_GET(simd))});             \
    CHECK_EQ(1, r.Call(max));                                                  \
    CHECK_EQ(1, r.Call(5));                                                    \
    CHECK_EQ(0, r.Call(0));                                                    \
  }
WASM_SIMD_ANYTRUE_TEST(32x4, 4, 0xffffffff, int32_t)
WASM_SIMD_ANYTRUE_TEST(16x8, 8, 0xffff, int32_t)
WASM_SIMD_ANYTRUE_TEST(8x16, 16, 0xff, int32_t)

// Special any true test cases that splats a -0.0 double into a i64x2.
// This is specifically to ensure that our implementation correct handles that
// 0.0 and -0.0 will be different in an anytrue (IEEE753 says they are equals).
WASM_EXEC_TEST(V128AnytrueWithNegativeZero) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  uint8_t simd = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(simd, WASM_SIMD_I64x2_SPLAT(WASM_LOCAL_GET(0))),
           WASM_SIMD_UNOP(kExprV128AnyTrue, WASM_LOCAL_GET(simd))});
  CHECK_EQ(1, r.Call(0x8000000000000000));
  CHECK_EQ(0, r.Call(0x0000000000000000));
}

#define WASM_SIMD_ALLTRUE_TEST(format, lanes, max, param_type)                 \
  WASM_EXEC_TEST(I##format##AllTrue) {                                         \
    WasmRunner<int32_t, param_type> r(execution_tier);                         \
    if (lanes == 2) return;                                                    \
    uint8_t simd = r.AllocateLocal(kWasmS128);                                 \
    r.Build(                                                                   \
        {WASM_LOCAL_SET(simd, WASM_SIMD_I##format##_SPLAT(WASM_LOCAL_GET(0))), \
         WASM_SIMD_UNOP(kExprI##format##AllTrue, WASM_LOCAL_GET(simd))});      \
    CHECK_EQ(1, r.Call(max));                                                  \
    CHECK_EQ(1, r.Call(0x1));                                                  \
    CHECK_EQ(0, r.Call(0));                                                    \
  }
WASM_SIMD_ALLTRUE_TEST(64x2, 2, 0xffffffffffffffff, int64_t)
WASM_SIMD_ALLTRUE_TEST(32x4, 4, 0xffffffff, int32_t)
WASM_SIMD_ALLTRUE_TEST(16x8, 8, 0xffff, int32_t)
WASM_SIMD_ALLTRUE_TEST(8x16, 16, 0xff, int32_t)

WASM_EXEC_TEST(BitSelect) {
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t simd = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(
               simd, WASM_SIMD_SELECT(
                         32x4, WASM_SIMD_I32x4_SPLAT(WASM_I32V(0x01020304)),
                         WASM_SIMD_I32x4_SPLAT(WASM_I32V(0)),
                         WASM_SIMD_I32x4_SPLAT(WASM_LOCAL_GET(0)))),
           WASM_SIMD_I32x4_EXTRACT_LANE(0, WASM_LOCAL_GET(simd))});
  CHECK_EQ(0x01020304, r.Call(0xFFFFFFFF));
}

void RunSimdConstTest(TestExecutionTier execution_tier,
                      const std::array<uint8_t, kSimd128Size>& expected) {
  WasmRunner<uint32_t> r(execution_tier);
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t* src0 = r.builder().AddGlobal<uint8_t>(kWasmS128);
  r.Build({WASM_GLOBAL_SET(temp1, WASM_SIMD_CONSTANT(expected)), WASM_ONE});
  CHECK_EQ(1, r.Call());
  for (size_t i = 0; i < expected.size(); i++) {
    CHECK_EQ(LANE(src0, i), expected[i]);
  }
}

WASM_EXEC_TEST(S128Const) {
  std::array<uint8_t, kSimd128Size> expected;
  // Test for generic constant
  for (int i = 0; i < kSimd128Size; i++) {
    expected[i] = i;
  }
  RunSimdConstTest(execution_tier, expected);

  // Keep the first 4 lanes as 0, set the remaining ones.
  for (int i = 0; i < 4; i++) {
    expected[i] = 0;
  }
  for (int i = 4; i < kSimd128Size; i++) {
    expected[i] = i;
  }
  RunSimdConstTest(execution_tier, expected);

  // Check sign extension logic used to pack int32s into int64.
  expected = {0};
  // Set the top bit of lane 3 (top bit of first int32), the rest can be 0.
  expected[3] = 0x80;
  RunSimdConstTest(execution_tier, expected);
}

WASM_EXEC_TEST(S128ConstAllZero) {
  std::array<uint8_t, kSimd128Size> expected = {0};
  RunSimdConstTest(execution_tier, expected);
}

WASM_EXEC_TEST(S128ConstAllOnes) {
  std::array<uint8_t, kSimd128Size> expected;
  // Test for generic constant
  for (int i = 0; i < kSimd128Size; i++) {
    expected[i] = 0xff;
  }
  RunSimdConstTest(execution_tier, expected);
}

WASM_EXEC_TEST(I8x16LeUMixed) {
  RunI8x16MixedRelationalOpTest(execution_tier, kExprI8x16LeU,
                                UnsignedLessEqual);
}
WASM_EXEC_TEST(I8x16LtUMixed) {
  RunI8x16MixedRelationalOpTest(execution_tier, kExprI8x16LtU, UnsignedLess);
}
WASM_EXEC_TEST(I8x16GeUMixed) {
  RunI8x16MixedRelationalOpTest(execution_tier, kExprI8x16GeU,
                                UnsignedGreaterEqual);
}
WASM_EXEC_TEST(I8x16GtUMixed) {
  RunI8x16MixedRelationalOpTest(execution_tier, kExprI8x16GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I16x8LeUMixed) {
  RunI16x8MixedRelationalOpTest(execution_tier, kExprI16x8LeU,
                                UnsignedLessEqual);
}
WASM_EXEC_TEST(I16x8LtUMixed) {
  RunI16x8MixedRelationalOpTest(execution_tier, kExprI16x8LtU, UnsignedLess);
}
WASM_EXEC_TEST(I16x8GeUMixed) {
  RunI16x8MixedRelationalOpTest(execution_tier, kExprI16x8GeU,
                                UnsignedGreaterEqual);
}
WASM_EXEC_TEST(I16x8GtUMixed) {
  RunI16x8MixedRelationalOpTest(execution_tier, kExprI16x8GtU, UnsignedGreater);
}

WASM_EXEC_TEST(I16x8ExtractLaneU_I8x16Splat) {
  // Test that we are correctly signed/unsigned extending when extracting.
  WasmRunner<int32_t, int32_t> r(execution_tier);
  uint8_t simd_val = r.AllocateLocal(kWasmS128);
  r.Build({WASM_LOCAL_SET(simd_val, WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(0))),
           WASM_SIMD_I16x8_EXTRACT_LANE_U(0, WASM_LOCAL_GET(simd_val))});
  CHECK_EQ(0xfafa, r.Call(0xfa));
}

enum ExtAddSide { LEFT, RIGHT };

template <typename T, typename U>
void RunAddExtAddPairwiseTest(
    TestExecutionTier execution_tier, ExtAddSide extAddSide,
    WasmOpcode addOpcode,
    const std::array<T, kSimd128Size / sizeof(T)> addInput,
    WasmOpcode extAddOpcode,
    const std::array<U, kSimd128Size / sizeof(U)> extAddInput,
    const std::array<T, kSimd128Size / sizeof(T)> expectedOutput) {
  WasmRunner<int32_t> r(execution_tier);
  T* x = r.builder().AddGlobal<T>(kWasmS128);
  for (size_t i = 0; i < addInput.size(); i++) {
    LANE(x, i) = addInput[i];
  }
  U* y = r.builder().AddGlobal<U>(kWasmS128);
  for (size_t i = 0; i < extAddInput.size(); i++) {
    LANE(y, i) = extAddInput[i];
  }
  switch (extAddSide) {
    case LEFT:
      // x = add(extadd_pairwise_s(y), x)
      r.Build({WASM_GLOBAL_SET(
                   0, WASM_SIMD_BINOP(
                          addOpcode,
                          WASM_SIMD_UNOP(extAddOpcode, WASM_GLOBAL_GET(1)),
                          WASM_GLOBAL_GET(0))),

               WASM_ONE});
      break;
    case RIGHT:
      // x = add(x, extadd_pairwise_s(y))
      r.Build({WASM_GLOBAL_SET(
                   0, WASM_SIMD_BINOP(
                          addOpcode, WASM_GLOBAL_GET(0),
                          WASM_SIMD_UNOP(extAddOpcode, WASM_GLOBAL_GET(1)))),

               WASM_ONE});
      break;
  }
  r.Call();

  for (size_t i = 0; i < expectedOutput.size(); i++) {
    CHECK_EQ(expectedOutput[i], LANE(x, i));
  }
}

WASM_EXEC_TEST(AddExtAddPairwiseI32Right) {
  RunAddExtAddPairwiseTest<int32_t, int16_t>(
      execution_tier, RIGHT, kExprI32x4Add, {1, 2, 3, 4},
      kExprI32x4ExtAddPairwiseI16x8S, {-1, -2, -3, -4, -5, -6, -7, -8},
      {-2, -5, -8, -11});
}

WASM_EXEC_TEST(AddExtAddPairwiseI32Left) {
  RunAddExtAddPairwiseTest<int32_t, int16_t>(
      execution_tier, LEFT, kExprI32x4Add, {1, 2, 3, 4},
      kExprI32x4ExtAddPairwiseI16x8S, {-1, -2, -3, -4, -5, -6, -7, -8},
      {-2, -5, -8, -11});
}

WASM_EXEC_TEST(AddExtAddPairwiseI16Right) {
  RunAddExtAddPairwiseTest<int16_t, int8_t>(
      execution_tier, RIGHT, kExprI16x8Add, {1, 2, 3, 4, 5, 6, 7, 8},
      kExprI16x8ExtAddPairwiseI8x16S,
      {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16},
      {-2, -5, -8, -11, -14, -17, -20, -23});
}

WASM_EXEC_TEST(AddExtAddPairwiseI16Left) {
  RunAddExtAddPairwiseTest<int16_t, int8_t>(
      execution_tier, LEFT, kExprI16x8Add, {1, 2, 3, 4, 5, 6, 7, 8},
      kExprI16x8ExtAddPairwiseI8x16S,
      {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
      {4, 9, 14, 19, 24, 29, 34, 39});
}

WASM_EXEC_TEST(AddExtAddPairwiseI32RightUnsigned) {
  RunAddExtAddPairwiseTest<uint32_t, uint16_t>(
      execution_tier, RIGHT, kExprI32x4Add, {1, 2, 3, 4},
      kExprI32x4ExtAddPairwiseI16x8U, {1, 2, 3, 4, 5, 6, 7, 8}, {4, 9, 14, 19});
}

WASM_EXEC_TEST(AddExtAddPairwiseI32LeftUnsigned) {
  RunAddExtAddPairwiseTest<uint32_t, uint16_t>(
      execution_tier, LEFT, kExprI32x4Add, {1, 2, 3, 4},
      kExprI32x4ExtAddPairwiseI16x8U, {1, 2, 3, 4, 5, 6, 7, 8}, {4, 9, 14, 19});
}

// Regression test from https://crbug.com/v8/12237 to exercise a codegen bug
// for i64x2.gts which overwrote one of the inputs.
WASM_EXEC_TEST(Regress_12237) {
  WasmRunner<int32_t, int64_t> r(execution_tier);
  int64_t* g = r.builder().AddGlobal<int64_t>(kWasmS128);
  uint8_t value = 0;
  uint8_t temp = r.AllocateLocal(kWasmS128);
  int64_t local = 123;
  r.Build({WASM_LOCAL_SET(
               temp, WASM_SIMD_OPN(kExprI64x2Splat, WASM_LOCAL_GET(value))),
           WASM_GLOBAL_SET(
               0, WASM_SIMD_BINOP(
                      kExprI64x2GtS, WASM_LOCAL_GET(temp),
                      WASM_SIMD_BINOP(kExprI64x2Sub, WASM_LOCAL_GET(temp),
                                      WASM_LOCAL_GET(temp)))),
           WASM_ONE});
  r.Call(local);
  int64_t expected = Greater(local, local - local);
  for (size_t i = 0; i < kSimd128Size / sizeof(int64_t); i++) {
    CHECK_EQ(expected, LANE(g, 0));
  }
}

#define WASM_EXTRACT_I16x8_TEST(Sign, Type)                                  \
  WASM_EXEC_TEST(I16X8ExtractLane##Sign) {                                   \
    WasmRunner<int32_t, int32_t> r(execution_tier);                          \
    uint8_t int_val = r.AllocateLocal(kWasmI32);                             \
    uint8_t simd_val = r.AllocateLocal(kWasmS128);                           \
    r.Build({WASM_LOCAL_SET(simd_val,                                        \
                            WASM_SIMD_I16x8_SPLAT(WASM_LOCAL_GET(int_val))), \
             WASM_SIMD_CHECK_LANE_U(I16x8, simd_val, I32, int_val, 0),       \
             WASM_SIMD_CHECK_LANE_U(I16x8, simd_val, I32, int_val, 2),       \
             WASM_SIMD_CHECK_LANE_U(I16x8, simd_val, I32, int_val, 4),       \
             WASM_SIMD_CHECK_LANE_U(I16x8, simd_val, I32, int_val, 6),       \
             WASM_ONE});                                                     \
    FOR_##Type##_INPUTS(x) { CHECK_EQ(1, r.Call(x)); }                       \
  }
WASM_EXTRACT_I16x8_TEST(S, UINT16) WASM_EXTRACT_I16x8_TEST(I, INT16)
#undef WASM_EXTRACT_I16x8_TEST

#define WASM_EXTRACT_I8x16_TEST(Sign, Type)                                  \
  WASM_EXEC_TEST(I8x16ExtractLane##Sign) {                                   \
    WasmRunner<int32_t, int32_t> r(execution_tier);                          \
    uint8_t int_val = r.AllocateLocal(kWasmI32);                             \
    uint8_t simd_val = r.AllocateLocal(kWasmS128);                           \
    r.Build({WASM_LOCAL_SET(simd_val,                                        \
                            WASM_SIMD_I8x16_SPLAT(WASM_LOCAL_GET(int_val))), \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 1),       \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 3),       \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 5),       \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 7),       \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 9),       \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 10),      \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 11),      \
             WASM_SIMD_CHECK_LANE_U(I8x16, simd_val, I32, int_val, 13),      \
             WASM_ONE});                                                     \
    FOR_##Type##_INPUTS(x) { CHECK_EQ(1, r.Call(x)); }                       \
  }
    WASM_EXTRACT_I8x16_TEST(S, UINT8) WASM_EXTRACT_I8x16_TEST(I, INT8)
#undef WASM_EXTRACT_I8x16_TEST

#ifdef V8_ENABLE_WASM_SIMD256_REVEC

void RunSimd256ConstTest(const std::array<uint8_t, kSimd128Size>& expected) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(32);
  uint8_t param1 = 0;
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Constant>);
    BUILD_AND_CHECK_REVEC_NODE(
        r, compiler::IrOpcode::kS256Const,
        WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param1),
                            WASM_SIMD_CONSTANT(expected)),
        WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param1),
                                   WASM_SIMD_CONSTANT(expected)),
        WASM_ONE);
  }
  CHECK_EQ(1, r.Call(0));
  for (size_t i = 0; i < expected.size(); i++) {
    CHECK_EQ(memory[i], expected[i]);
    CHECK_EQ(memory[i + 16], expected[i]);
  }
}

TEST(RunWasmTurbofan_S256Const) {
  // All zeroes
  std::array<uint8_t, kSimd128Size> expected = {0};
  RunSimd256ConstTest(expected);

  // All ones
  for (int i = 0; i < kSimd128Size; i++) {
    expected[i] = 0xff;
  }
  RunSimd256ConstTest(expected);

  // Test for generic constant
  for (int i = 0; i < kSimd128Size; i++) {
    expected[i] = i;
  }
  RunSimd256ConstTest(expected);

  // Keep the first 4 lanes as 0, set the remaining ones.
  for (int i = 0; i < 4; i++) {
    expected[i] = 0;
  }
  for (int i = 4; i < kSimd128Size; i++) {
    expected[i] = i;
  }
  RunSimd256ConstTest(expected);

  // Check sign extension logic used to pack int32s into int64.
  expected = {0};
  // Set the top bit of lane 3 (top bit of first int32), the rest can be 0.
  expected[3] = 0x80;
  RunSimd256ConstTest(expected);
}

TEST(RunWasmTurbofan_ExtractF128) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX) || !CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int64_t, int32_t, int32_t, int32_t> r(
      TestExecutionTier::kTurbofan);
  int64_t* memory = r.builder().AddMemoryElems<int64_t>(12);
  // Add two 256 bit vectors a and b, store the result in c and return the sum
  // of all the int64 elements in c:
  //   simd128 *a,*b,*c,*d;
  //   *c = *a + *b;
  //   *(c+1) = *(a+1) + *(b+1);
  //   *d = *c + *(c+1);
  //   return LANE(d, 0) + LANE(d,1);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t param3 = 2;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  uint8_t temp3 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Extract128Lane>);
    BUILD_AND_CHECK_REVEC_NODE(
        r, compiler::IrOpcode::kI64x4Add,
        WASM_LOCAL_SET(
            temp1, WASM_SIMD_BINOP(kExprI64x2Add,
                                   WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param1)),
                                   WASM_SIMD_LOAD_MEM(WASM_LOCAL_GET(param2)))),
        WASM_LOCAL_SET(
            temp2,
            WASM_SIMD_BINOP(
                kExprI64x2Add,
                WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param1)),
                WASM_SIMD_LOAD_MEM_OFFSET(offset, WASM_LOCAL_GET(param2)))),
        WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param3), WASM_LOCAL_GET(temp1)),
        WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param3),
                                   WASM_LOCAL_GET(temp2)),
        WASM_LOCAL_SET(temp3,
                       WASM_SIMD_BINOP(kExprI64x2Add, WASM_LOCAL_GET(temp1),
                                       WASM_LOCAL_GET(temp2))),
        WASM_I64_ADD(WASM_SIMD_I64x2_EXTRACT_LANE(0, WASM_LOCAL_GET(temp3)),
                     WASM_SIMD_I64x2_EXTRACT_LANE(1, WASM_LOCAL_GET(temp3))));
  }
  for (int64_t x : compiler::ValueHelper::GetVector<int64_t>()) {
    for (int64_t y : compiler::ValueHelper::GetVector<int64_t>()) {
      for (int i = 0; i < 4; i++) {
        r.builder().WriteMemory(&memory[i], x);
        r.builder().WriteMemory(&memory[i + 4], y);
      }
      int64_t expected = base::AddWithWraparound(x, y);
      CHECK_EQ(r.Call(0, 32, 64), expected * 4);
      for (int i = 0; i < 4; i++) {
        CHECK_EQ(expected, memory[i + 8]);
      }
    }
  }
}

TEST(RunWasmTurbofan_F32x8Abs) {
  RunF32x8UnOpRevecTest(kExprF32x4Abs, std::abs, compiler::IrOpcode::kF32x8Abs);
}

TEST(RunWasmTurbofan_F32x8Neg) {
  RunF32x8UnOpRevecTest(kExprF32x4Neg, Negate, compiler::IrOpcode::kF32x8Neg);
}

TEST(RunWasmTurbofan_F32x8Sqrt) {
  RunF32x8UnOpRevecTest(kExprF32x4Sqrt, std::sqrt,
                        compiler::IrOpcode::kF32x8Sqrt);
}

TEST(RunWasmTurbofan_F32x8Min) {
  RunF32x8BinOpRevecTest(kExprF32x4Min, JSMin, compiler::IrOpcode::kF32x8Min);
}

TEST(RunWasmTurbofan_F32x8Max) {
  RunF32x8BinOpRevecTest(kExprF32x4Max, JSMax, compiler::IrOpcode::kF32x8Max);
}

TEST(RunWasmTurbofan_F32x8Pmin) {
  RunF32x8BinOpRevecTest(kExprF32x4Pmin, Minimum,
                         compiler::IrOpcode::kF32x8Pmin);
}

TEST(RunWasmTurbofan_F32x8Pmax) {
  RunF32x8BinOpRevecTest(kExprF32x4Pmax, Maximum,
                         compiler::IrOpcode::kF32x8Pmax);
}

TEST(RunWasmTurbofan_I64x4Shl) {
  RunI64x4ShiftOpRevecTest(kExprI64x2Shl, LogicalShiftLeft,
                           compiler::IrOpcode::kI64x4Shl);
}

TEST(RunWasmTurbofan_I64x4ShrU) {
  RunI64x4ShiftOpRevecTest(kExprI64x2ShrU, LogicalShiftRight,
                           compiler::IrOpcode::kI64x4ShrU);
}

TEST(RunWasmTurbofan_I64x4Ne) {
  RunI64x4BinOpRevecTest(kExprI64x2Ne, NotEqual, compiler::IrOpcode::kI64x4Ne);
}

TEST(RunWasmTurbofan_I64x4GeS) {
  RunI64x4BinOpRevecTest(kExprI64x2GeS, GreaterEqual,
                         compiler::IrOpcode::kI64x4GeS);
}

TEST(RunWasmTurbofan_F64x4Abs) {
  RunF64x4UnOpRevecTest(kExprF64x2Abs, std::abs, compiler::IrOpcode::kF64x4Abs);
}

TEST(RunWasmTurbofan_F64x4Neg) {
  RunF64x4UnOpRevecTest(kExprF64x2Neg, Negate, compiler::IrOpcode::kF64x4Neg);
}

TEST(RunWasmTurbofan_F64x4Sqrt) {
  RunF64x4UnOpRevecTest(kExprF64x2Sqrt, std::sqrt,
                        compiler::IrOpcode::kF64x4Sqrt);
}

TEST(RunWasmTurbofan_F64x4Min) {
  RunF64x4BinOpRevecTest(kExprF64x2Min, JSMin, compiler::IrOpcode::kF64x4Min);
}

TEST(RunWasmTurbofan_F64x4Max) {
  RunF64x4BinOpRevecTest(kExprF64x2Max, JSMax, compiler::IrOpcode::kF64x4Max);
}

TEST(RunWasmTurbofan_F64x4Pmin) {
  RunF64x4BinOpRevecTest(kExprF64x2Pmin, Minimum,
                         compiler::IrOpcode::kF64x4Pmin);
}

TEST(RunWasmTurbofan_F64x4Pmax) {
  RunF64x4BinOpRevecTest(kExprF64x2Pmax, Maximum,
                         compiler::IrOpcode::kF64x4Pmax);
}

TEST(RunWasmTurbofan_I32x8SConvertF32x8) {
  RunI32x8ConvertF32x8RevecTest<int32_t>(
      kExprI32x4SConvertF32x4, ConvertToInt,
      compiler::IrOpcode::kI32x8SConvertF32x8);
}

TEST(RunWasmTurbofan_I32x8UConvertF32x8) {
  RunI32x8ConvertF32x8RevecTest<uint32_t>(
      kExprI32x4UConvertF32x4, ConvertToInt,
      compiler::IrOpcode::kI32x8UConvertF32x8);
}

TEST(RunWasmTurbofan_F32x8SConvertI32x8) {
  RunF32x8ConvertI32x8RevecTest<int32_t>(
      kExprF32x4SConvertI32x4, compiler::IrOpcode::kF32x8SConvertI32x8);
}

TEST(RunWasmTurbofan_F32x8UConvertI32x8) {
  RunF32x8ConvertI32x8RevecTest<uint32_t>(
      kExprF32x4UConvertI32x4, compiler::IrOpcode::kF32x8UConvertI32x8);
}

TEST(RunWasmTurbofan_I64x4SConvertI32x4) {
  RunIntSignExtensionRevecTest<int32_t, int64_t>(
      kExprI64x2SConvertI32x4Low, kExprI64x2SConvertI32x4High, kExprI32x4Splat,
      compiler::IrOpcode::kI64x4SConvertI32x4);
}

TEST(RunWasmTurbofan_I64x4UConvertI32x4) {
  RunIntSignExtensionRevecTest<uint32_t, uint64_t>(
      kExprI64x2UConvertI32x4Low, kExprI64x2UConvertI32x4High, kExprI32x4Splat,
      compiler::IrOpcode::kI64x4UConvertI32x4);
}

TEST(RunWasmTurbofan_I32x8SConvertI16x8) {
  RunIntSignExtensionRevecTest<int16_t, int32_t>(
      kExprI32x4SConvertI16x8Low, kExprI32x4SConvertI16x8High, kExprI16x8Splat,
      compiler::IrOpcode::kI32x8SConvertI16x8);
}

TEST(RunWasmTurbofan_I32x8UConvertI16x8) {
  RunIntSignExtensionRevecTest<uint16_t, uint32_t>(
      kExprI32x4UConvertI16x8Low, kExprI32x4UConvertI16x8High, kExprI16x8Splat,
      compiler::IrOpcode::kI32x8UConvertI16x8);
}

TEST(RunWasmTurbofan_I16x16SConvertI8x16) {
  RunIntSignExtensionRevecTest<int8_t, int16_t>(
      kExprI16x8SConvertI8x16Low, kExprI16x8SConvertI8x16High, kExprI8x16Splat,
      compiler::IrOpcode::kI16x16SConvertI8x16);
}

TEST(RunWasmTurbofan_I16x16UConvertI8x16) {
  RunIntSignExtensionRevecTest<uint8_t, uint16_t>(
      kExprI16x8UConvertI8x16Low, kExprI16x8UConvertI8x16High, kExprI8x16Splat,
      compiler::IrOpcode::kI16x16UConvertI8x16);
}

TEST(RunWasmTurbofan_I32x8Neg) {
  RunI32x8UnOpRevecTest(kExprI32x4Neg, base::NegateWithWraparound,
                        compiler::IrOpcode::kI32x8Neg);
}

TEST(RunWasmTurbofan_I32x8Abs) {
  RunI32x8UnOpRevecTest(kExprI32x4Abs, std::abs, compiler::IrOpcode::kI32x8Abs);
}

template <typename Narrow, typename Wide>
void RunExtAddPairwiseRevecTest(WasmOpcode ext_add_pairwise) {
  EXPERIMENTAL_FLAG_SCOPE(revectorize);
  if (!CpuFeatures::IsSupported(AVX2)) return;
  WasmRunner<int32_t, int32_t, int32_t> r(TestExecutionTier::kTurbofan);
  // [intput1(128bit)|intput2(128bit)|output(256bit)]
  Narrow* memory =
      r.builder().AddMemoryElems<Narrow>(kSimd128Size / sizeof(Narrow) * 4);
  uint8_t param1 = 0;
  uint8_t param2 = 1;
  uint8_t temp1 = r.AllocateLocal(kWasmS128);
  uint8_t temp2 = r.AllocateLocal(kWasmS128);
  constexpr uint8_t offset = 16;
  {
    TSSimd256VerifyScope ts_scope(
        r.zone(), TSSimd256VerifyScope::VerifyHaveOpcode<
                      compiler::turboshaft::Opcode::kSimd256Unary>);
    r.Build({WASM_LOCAL_SET(temp1, WASM_SIMD_UNOP(ext_add_pairwise,
                                                  WASM_SIMD_LOAD_MEM(
                                                      WASM_LOCAL_GET(param1)))),
             WASM_LOCAL_SET(
                 temp2, WASM_SIMD_UNOP(ext_add_pairwise,
                                       WASM_SIMD_LOAD_MEM_OFFSET(
                                           offset, WASM_LOCAL_GET(param1)))),
             WASM_SIMD_STORE_MEM(WASM_LOCAL_GET(param2), WASM_LOCAL_GET(temp1)),
             WASM_SIMD_STORE_MEM_OFFSET(offset, WASM_LOCAL_GET(param2),
                                        WASM_LOCAL_GET(temp2)),
             WASM_ONE});
  }
  for (Narrow x : compiler::ValueHelper::GetVector<Narrow>()) {
    for (int i = 0; i < static_cast<int>(kSimd128Size / sizeof(Narrow) * 2);
         i++) {
      r.builder().WriteMemory(&memory[i], x);
    }
    r.Call(0, 32);
    Wide expected = AddLong<Wide>(x, x);
    for (int i = 0; i < static_cast<int>(kSimd128Size / sizeof(Wide) * 2);
         i++) {
      CHECK_EQ(memcmp((const void*)&expected,
                      &memory[kSimd128Size / sizeof(Narrow) * 2 + i * 2], 2),
               0);
    }
  }
}

TEST(RunWasmTurbofan_I16x16ExtAddPairwiseI8x32S) {
  RunExtAddPairwiseRevecTest<int8_t, int16_t>(kExprI16x8ExtAddPairwiseI8x16S);
}

TEST(RunWasmTurbofan_I16x16ExtAddPairwiseI8x32U) {
  RunExtAddPairwiseRevecTest<uint8_t, uint16_t>(kExprI16x8ExtAddPairwiseI8x16U);
}

TEST(RunWasmTurbofan_I32x8ExtAddPairwiseI16x16S) {
  RunExtAddPairwiseRevecTest<int16_t, int32_t>(kExprI32x4ExtAddPairwiseI16x8S);
}

TEST(RunWasmTurbofan_I32x8ExtAddPairwiseI16x16U) {
  RunExtAddPairwiseRevecTest<uint16_t, uint32_t>(
      kExprI32x4ExtAddPairwiseI16x8U);
}

TEST(RunWasmTurbofan_S256Not) {
  RunI32x8UnOpRevecTest(kExprS128Not, BitwiseNot, compiler::IrOpcode::kS256Not);
}

TEST(RunWasmTurbofan_S256And) {
  RunI32x8BinOpRevecTest(kExprS128And, BitwiseAnd,
                         compiler::IrOpcode::kS256And);
}

TEST(RunWasmTurbofan_S256Or) {
  RunI32x8BinOpRevecTest(kExprS128Or, BitwiseOr, compiler::IrOpcode::kS256Or);
}

TEST(RunWasmTurbofan_S256Xor) {
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
"""


```