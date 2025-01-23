Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the V8 JavaScript engine's test suite.

Here's a breakdown of the request and how to approach it:

1. **Identify the core functionality:** The code is testing WebAssembly SIMD (Single Instruction, Multiple Data) instructions. Specifically, it seems to be testing load and store operations for different data types and lane sizes within a 128-bit vector.

2. **Address specific instructions:**
    * **.tq suffix:** The user is asking if the file were a Torque file. The provided snippet is C++, so the answer is no.
    * **JavaScript relation:** Since it's testing WebAssembly SIMD, which JavaScript can invoke, there is a relationship. An example of how JavaScript uses these features would be beneficial.
    * **Code logic inference:** The test cases often involve setting up memory, globals, performing operations, and then checking the results. A simple example with input and expected output would be useful.
    * **Common programming errors:**  The code explicitly tests for out-of-bounds memory access, which is a common error. This should be highlighted.

3. **Summarize overall functionality:** Combine the observations from the individual test cases to provide a high-level overview.

4. **Handle the "part 5 of 9" instruction:** This suggests that there are related files. While I don't have access to the other parts, I should keep the summary focused on the provided snippet and acknowledge its role as part of a larger testing effort.

**Mental Sandbox:**

* Imagine each `WASM_EXEC_TEST` as a distinct test case.
* Focus on the operations being performed within each test (e.g., `WASM_SIMD_LOAD_OP`, `WASM_GLOBAL_SET`, `WASM_SIMD_STORE_OP`).
* Notice the patterns: testing different data types (int8, int16, int32, int64), lane operations, load/store with offsets and alignments, and out-of-bounds checks.
* Consider how these operations relate to the SIMD concept – performing the same operation on multiple data elements simultaneously.
* For the JavaScript example, think about how a WebAssembly module with SIMD instructions would be called from JavaScript.

**Constraint Checklist & Confidence Score:**

1. List the functionalities? Yes.
2. Check for .tq suffix? Yes.
3. Explain Javascript relation? Yes.
4. Provide Javascript example? Yes.
5. Explain code logic with input/output? Yes.
6. Illustrate common errors? Yes.
7. Summarize functionality? Yes.
8. Acknowledge part 5 of 9? Yes.

Confidence Score: 5/5

Strategizing complete. I will now generate the response based on these steps.
这是v8/test/cctest/wasm/test-run-wasm-simd.cc的第5部分代码，它主要专注于测试 **WebAssembly (Wasm) 的 SIMD (Single Instruction, Multiple Data) 指令** 的功能，特别是关于 **加载 (load) 和存储 (store) 操作** 的测试。

具体来说，这部分代码测试了以下功能：

1. **带零扩展的加载指令 (Load Zero):**
   - `S128Load32Zero`:  测试将内存中的 32 位整数加载到 SIMD 寄存器中，并将剩余的通道（lane）用零填充。
   - `S128Load64Zero`:  测试将内存中的 64 位整数加载到 SIMD 寄存器中，并将剩余的通道用零填充。

2. **带通道索引的加载指令 (Load Lane):**
   - `S128Load8Lane`, `S128Load16Lane`, `S128Load32Lane`, `S128Load64Lane`:  测试从内存中加载特定通道的数据到 SIMD 寄存器的指定通道，同时保持其他通道的值不变。这些测试覆盖了 8 位、16 位、32 位和 64 位的数据类型。

3. **带通道索引的存储指令 (Store Lane):**
   - `S128Store8Lane`, `S128Store16Lane`, `S128Store32Lane`, `S128Store64Lane`: 测试将 SIMD 寄存器中特定通道的数据存储到内存中的指定位置。这些测试也覆盖了 8 位、16 位、32 位和 64 位的数据类型。

4. **`v128.anytrue` 指令:**
   - `S32x4AnyTrue`, `S16x8AnyTrue`, `S8x16AnyTrue`: 测试 `v128.anytrue` 指令，该指令检查 SIMD 寄存器中是否有任何通道的值为真（非零）。
   - `V128AnytrueWithNegativeZero`: 特殊测试用例，用于验证 `v128.anytrue` 正确处理负零 (`-0.0`)，根据 IEEE 753 标准，负零和正零在相等性比较中被认为是相等的，但在 `anytrue` 中应该被认为是真。

5. **`iXXxY.alltrue` 指令:**
   - `I64x2AllTrue`, `I32x4AllTrue`, `I16x8AllTrue`, `I8x16AllTrue`: 测试 `iXXxY.alltrue` 指令，该指令检查 SIMD 寄存器中是否所有通道的值都为真（非零）。

6. **`v128.bitselect` 指令:**
   - `BitSelect`: 测试 `v128.bitselect` 指令，该指令根据掩码 SIMD 寄存器的位来从两个源 SIMD 寄存器中选择位。

7. **`v128.const` 指令:**
   - `S128Const`: 测试创建包含特定常数值的 SIMD 寄存器。
   - `S128ConstAllZero`: 测试创建所有通道都为零的 SIMD 寄存器。
   - `S128ConstAllOnes`: 测试创建所有通道都为一的 SIMD 寄存器。

8. **混合大小的有符号/无符号比较指令:**
   - `I8x16LeUMixed`, `I8x16LtUMixed`, `I8x16GeUMixed`, `I8x16GtUMixed`: 测试 8 位整数的带符号和无符号混合比较操作。
   - `I16x8LeUMixed`, `I16x8LtUMixed`, `I16x8GeUMixed`, `I16x8GtUMixed`: 测试 16 位整数的带符号和无符号混合比较操作。

9. **带符号/无符号扩展的通道提取指令:**
   - `I16x8ExtractLaneU_I8x16Splat`: 测试从 `i8x16` SIMD 寄存器中提取一个通道并无符号扩展到 16 位。

10. **扩展加法配对指令 (ExtAddPairwise):**
    - `AddExtAddPairwiseI32Right`, `AddExtAddPairwiseI32Left`, `AddExtAddPairwiseI16Right`, `AddExtAddPairwiseI16Left`, `AddExtAddPairwiseI32RightUnsigned`, `AddExtAddPairwiseI32LeftUnsigned`:  测试将较小位宽的 SIMD 向量中的相邻元素配对相加，并将结果存储到较大位宽的 SIMD 向量中的操作。这些测试涵盖了有符号和无符号的情况。

11. **回归测试:**
    - `Regress_12237`:  针对一个特定的代码生成 bug 进行回归测试，该 bug 涉及 `i64x2.gts` 指令。

12. **通用的通道提取指令:**
    - `I16X8ExtractLaneS`, `I16X8ExtractLaneI`: 测试从 `i16x8` SIMD 寄存器中提取指定通道的值，分别进行有符号和无符号扩展。
    - `I8x16ExtractLaneS`, `I8x16ExtractLaneI`: 测试从 `i8x16` SIMD 寄存器中提取指定通道的值，分别进行有符号和无符号扩展。

13. **SIMD256 相关测试 (使用了 `#ifdef V8_ENABLE_WASM_SIMD256_REVEC`):** 这部分测试涉及实验性的 256 位 SIMD 指令，需要特定的编译选项和 CPU 特性支持。
    - `RunWasmTurbofan_S256Const`: 测试 256 位 SIMD 常量。
    - `RunWasmTurbofan_ExtractF128`: 测试从 256 位 SIMD 寄存器中提取 128 位数据。
    - 以及一系列针对 256 位 SIMD 浮点和整数运算的测试，例如 `F32x8Abs`, `F32x8Neg`, `I64x4Shl` 等。

**如果 `v8/test/cctest/wasm/test-run-wasm-simd.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**

但这部分代码是以 `.cc` 结尾的，所以它是 **C++ 源代码**，而不是 Torque 代码。Torque 文件通常用于定义 V8 的内置函数和类型系统。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

是的，这部分代码测试的 WebAssembly SIMD 功能与 JavaScript 有密切关系。JavaScript 可以加载和执行 WebAssembly 模块，而这些模块可以使用 SIMD 指令来提升性能。

**JavaScript 示例：**

```javascript
async function runWasmSimd() {
  const response = await fetch('your_wasm_module.wasm'); // 假设你有一个编译好的 wasm 模块
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  // 假设你的 wasm 模块导出了一个使用 SIMD 的函数
  const simdAdd = instance.exports.simdAdd;

  // 模拟一些输入数据
  const input1 = new Int32Array([1, 2, 3, 4]);
  const input2 = new Int32Array([5, 6, 7, 8]);

  // 将输入数据传递给 wasm 函数 (具体方式取决于 wasm 模块的接口)
  // 这里假设 wasm 函数直接操作内存或者接受数组作为参数
  // ... (可能需要先将 JavaScript ArrayBuffer 写入 wasm 线性内存) ...

  // 调用 wasm 函数
  // simdAdd();

  // ... (从 wasm 线性内存中读取结果) ...
  // const output = new Int32Array(instance.exports.memory.buffer, offset, 4);
  // console.log(output);
}

runWasmSimd();
```

在这个例子中，`your_wasm_module.wasm` 可能包含了使用了类似这部分 C++ 代码正在测试的 SIMD 指令的函数。JavaScript 通过 `WebAssembly` API 加载和执行这个模块。

**如果有代码逻辑推理，请给出假设输入与输出:**

以 `WASM_EXEC_TEST(S128Load32Zero)` 为例：

**假设输入：**

- 内存地址 1000 处存储了一个 32 位整数值：`0x12345678`。
- SIMD 寄存器 `global` 的初始状态为任意值。

**代码逻辑：**

```c++
{
  WasmRunner<int32_t> r(execution_tier);
  std::tie(memory, global) = initialize_builder(&r);

  r.Build(
      {WASM_GLOBAL_SET(0, WASM_SIMD_LOAD_OP(kExprS128Load32Zero, WASM_ZERO))});
  r.Call();

  // ... 检查 global 的值 ...
}
```

这段代码构建了一个 WebAssembly 函数，该函数执行以下操作：

1. 从内存地址 0（`WASM_ZERO`）加载一个 32 位整数到 SIMD 寄存器。由于没有指定偏移量，默认从内存的起始位置加载。  **需要注意的是，实际测试中通常会先写入数据到内存中，这里为了简化假设已经存在数据。**
2. 将加载的值设置到全局 SIMD 变量 `global` 中。
3. `kExprS128Load32Zero` 表示加载 32 位，并将剩余的 96 位（128 - 32）用零填充。

**假设输出（`global` 的值）：**

如果内存地址 0 处存储的是 `0x12345678`，并且假设 SIMD 寄存器的通道是小端序，那么 `global` 的值（作为一个 128 位向量）的字节表示将会是：

`78 56 34 12 00 00 00 00 00 00 00 00 00 00 00 00`

其中，前 4 个字节是加载的 32 位整数，后面的 12 个字节是零填充。

**如果涉及用户常见的编程错误，请举例说明:**

这部分代码中，与内存访问相关的测试（例如 `S128Load8Lane` 中的 OOB 测试）直接关联了用户常见的编程错误：**越界内存访问 (Out-Of-Bounds Access)**。

**C++ 示例 (模拟 WebAssembly 中的错误)：**

```c++
#include <iostream>
#include <vector>

int main() {
  std::vector<int> memory = {1, 2, 3, 4}; // 模拟 WebAssembly 线性内存

  // 尝试访问超出内存边界的元素
  int index = 10;
  if (index < memory.size()) {
    std::cout << memory[index] << std::endl;
  } else {
    std::cerr << "Error: Index out of bounds!" << std::endl;
    // 这在 WebAssembly 中会导致 trap
  }

  return 0;
}
```

在 WebAssembly 中，尝试加载或存储超出分配的内存范围会导致 **trap (陷阱)**，程序执行会中止。  这部分测试代码通过 `CHECK_TRAP(r.Call(offset))` 来验证当加载或存储操作超出内存边界时是否会正确触发 trap。

**这是第5部分，共9部分，请归纳一下它的功能:**

作为 `v8/test/cctest/wasm/test-run-wasm-simd.cc` 的第 5 部分，这部分代码的主要功能是 **全面测试 WebAssembly SIMD 指令中的加载和存储操作，以及一些基本的 SIMD 运算和常量操作。** 它涵盖了不同数据类型、通道操作、内存对齐、边界检查以及一些特定的指令行为。这些测试旨在确保 V8 引擎正确地实现了 WebAssembly SIMD 规范，并且能够安全可靠地执行这些指令。 结合其他部分，这个文件旨在提供一个完整的 WebAssembly SIMD 功能的测试套件。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-simd.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-simd.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共9部分，请归纳一下它的功能
```

### 源代码
```cpp
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

TEST(RunWasmTu
```