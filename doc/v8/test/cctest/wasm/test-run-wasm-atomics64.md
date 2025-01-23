Response:
The user wants to understand the functionality of the C++ code provided. I need to break down the code and explain its purpose.

Here's a plan:

1. **Identify the main purpose:** The file name and the content suggest it's testing WebAssembly's 64-bit atomic operations.
2. **Analyze the structure:** Notice the use of `WasmRunner`, `WASM_EXEC_TEST`, and helper functions like `RunU64BinOp`, `RunU32BinOp`, etc. These are testing infrastructure components.
3. **Explain the core testing logic:**  The tests generally involve:
    - Setting up shared memory.
    - Performing an atomic operation (load, store, add, compare-and-exchange, etc.).
    - Verifying the result in memory and the return value of the operation.
4. **Address the specific questions:**
    - Is it Torque? No, it's C++.
    - Is it related to JavaScript? Yes, WebAssembly is executed in JavaScript environments.
    - Provide JavaScript examples where relevant (simulating the atomic operations is not directly possible in standard JS, but I can show how these operations might be used conceptually).
    - Code logic reasoning: Explain the input and output of the tests.
    - Common programming errors: Relate the atomic operations to concurrency issues and data races.
这个C++源代码文件 `v8/test/cctest/wasm/test-run-wasm-atomics64.cc` 的主要功能是 **测试 V8 引擎中 WebAssembly 的 64 位原子操作的正确性**。

更具体地说，它做了以下几件事情：

1. **定义了一系列的测试用例 (using `WASM_EXEC_TEST` macro):**  每个测试用例针对一个特定的 64 位原子操作或其变体。
2. **使用了 `WasmRunner` 类:** 这是一个 V8 内部的测试工具，用于构建和执行 WebAssembly 模块。
3. **创建了共享的 WebAssembly 内存:**  测试原子操作需要在多个执行单元之间共享内存，因此代码中使用了 `r.builder().SetMemoryShared()`。
4. **执行各种 64 位原子操作:**  例如 `i64.atomic.add`, `i64.atomic.cmpxchg`, `i64.atomic.load`, `i64.atomic.store` 等。  这些操作有不同的变体，例如操作不同大小的内存单元 (8-bit, 16-bit, 32-bit, 64-bit)。
5. **验证原子操作的结果:**  每个测试用例会写入一些初始值到内存中，然后执行原子操作，并检查内存中的值是否符合预期，以及原子操作的返回值是否正确。
6. **使用了宏来简化测试用例的编写:**  例如 `WASM_ATOMIC_OPERATION_LIST` 和 `TEST_OPERATION` 宏用于批量生成类似的测试。
7. **测试了 "drop" 和 "convert" 场景:**  这些场景涉及到 WebAssembly 代码优化，例如当原子操作的结果被丢弃 (`WASM_DROP`) 或转换为较小的类型 (`kExprI32ConvertI64`) 时，确保原子操作仍然能正确执行。
8. **测试了非恒定索引的场景:** 确保即使访问内存的索引不是编译时常量，原子操作也能正常工作。
9. **测试了原子操作的 "fail" 情况:**  例如 `i64.atomic.cmpxchg` 在比较失败时的行为。
10. **测试了原子操作在特定优化场景下的行为:** 例如，当原子操作的结果没有被使用时，确保它仍然被认为是具有副作用的操作。

**关于你的问题:**

* **如果 `v8/test/cctest/wasm/test-run-wasm-atomics64.cc` 以 `.tq` 结尾，那它是个 v8 torque 源代码。**  你的判断是正确的。以 `.tq` 结尾的文件是 V8 的 Torque 语言的源代码，用于定义 V8 的内置函数和运行时代码。但这个文件以 `.cc` 结尾，所以是 C++ 源代码。

* **如果它与 javascript 的功能有关系，请用 javascript 举例说明。**

   WebAssembly 的原子操作是为了支持多线程 WebAssembly 应用。在 JavaScript 中，你可以通过 `SharedArrayBuffer` 来创建共享内存，并在 WebAssembly 模块中使用原子操作来安全地访问和修改这部分共享内存。

   以下是一个概念性的 JavaScript 示例，展示了如何与这些原子操作相关的 WebAssembly 模块交互：

   ```javascript
   // 创建一个共享的 ArrayBuffer
   const sharedBuffer = new SharedArrayBuffer(8); // 8 字节用于存储一个 64 位整数
   const int64Array = new BigInt64Array(sharedBuffer);

   // 加载并实例化 WebAssembly 模块 (假设模块中导出了一个执行原子操作的函数)
   WebAssembly.instantiateStreaming(fetch('wasm_atomics.wasm'), { /* imports */ })
     .then(result => {
       const wasmInstance = result.instance;

       // 初始值
       int64Array[0] = 10n;

       // 调用 WebAssembly 函数执行原子加法 (假设 add 是一个导出的函数，
       // 它将给定的值原子地加到共享内存的指定位置)
       const addedValue = 5n;
       wasmInstance.exports.add(0, addedValue); // 0 是内存中的偏移量

       // 从共享内存中读取结果
       console.log(int64Array[0]); // 输出应该是 15n
     });
   ```

   **请注意:**  这个 JavaScript 示例是概念性的。你需要一个编译好的 WebAssembly 模块 (`wasm_atomics.wasm`)，其中包含使用了 64 位原子操作的代码，并且导出了可以从 JavaScript 调用的函数。

* **如果有代码逻辑推理，请给出假设输入与输出。**

   让我们以 `WASM_EXEC_TEST(I64AtomicAdd)` 这个测试用例为例，它调用了 `RunU64BinOp` 函数：

   **假设输入:**

   * **初始内存值 (`i`):** 假设 `i` 是 `10n` (BigInt 表示 64 位整数)。
   * **要加的值 (`j`):** 假设 `j` 是 `5n`。

   **代码逻辑:**

   1. `WasmRunner` 构建一个 WebAssembly 模块，其中包含一个原子加法操作 (`kExprI64AtomicAdd`)。
   2. 将初始值 `10n` 写入共享内存的起始位置 (`memory[0]`)。
   3. 调用 WebAssembly 函数，将 `j` (即 `5n`) 原子地加到内存地址 0 的值上。
   4. `CHECK_EQ(initial, r.Call(j));`  这行代码检查 `r.Call(j)` 的返回值。在 `RunU64BinOp` 中，`r.Call(j)` 实际上并不使用 `j`，而是返回内存中的初始值（在原子操作之前）。所以，返回值应该是 `10n`。
   5. `uint64_t expected = expected_op(i, j);`  `expected_op` 在这里是 `Add` 函数，它执行普通的加法。所以 `expected` 是 `10n + 5n = 15n`。
   6. `CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));` 这行代码检查共享内存地址 0 的值是否为预期的结果 `15n`。

   **预期输出:**

   * `r.Call(j)` 的返回值应该等于初始值 `10n`。
   * 执行原子加法后，共享内存地址 0 的值应该变为 `15n`。

* **如果涉及用户常见的编程错误，请举例说明。**

   使用原子操作时，常见的编程错误通常与 **并发** 和 **数据竞争** 有关：

   1. **忘记使用原子操作:**  在多线程环境中，如果多个线程同时访问和修改共享变量，而不使用原子操作进行同步，可能会导致数据竞争。例如：

      ```c++
      // 假设在多个线程中执行
      uint64_t shared_counter = 0;

      void increment_counter() {
        // 错误：非原子操作
        shared_counter++;
      }
      ```

      在没有原子操作的情况下，`shared_counter++` 实际上包含多个步骤（读取、加法、写入），这些步骤可能被其他线程打断，导致最终结果不正确。应该使用 `kExprI64AtomicAdd` 或类似的原子操作。

   2. **对齐问题:** 原子操作通常要求访问的内存地址是对齐的。例如，64 位原子操作通常需要 8 字节对齐。如果访问未对齐的地址，可能会导致程序崩溃或未定义的行为。WebAssembly 的原子操作会强制进行对齐检查，但用户在手动管理内存时可能会犯这个错误。

   3. **ABA 问题 (仅适用于 CompareExchange):**  在使用 CompareExchange 时，如果一个值从 A 变为 B，然后再变回 A，另一个线程可能错误地认为该值没有发生变化，从而导致逻辑错误。

      ```c++
      // 线程 1
      uint64_t expected = current_value;
      uint64_t new_value = ...;
      // 原子地将 current_value 设置为 new_value，如果 current_value 等于 expected
      bool success = r.builder().CompareExchange(&memory[0], expected, new_value);

      // 线程 2 在线程 1 执行期间可能做了以下事情：
      // 1. 将 memory[0] 的值从 expected 修改为 other_value
      // 2. 将 memory[0] 的值从 other_value 修改回 expected

      // 此时，线程 1 的 CompareExchange 可能会成功，尽管值经历了变化。
      ```

   4. **过度使用或不当使用内存顺序 (Memory Ordering):** 虽然这个文件没有直接涉及到内存顺序，但在更复杂的原子操作场景中，理解和正确使用内存顺序（例如，`std::memory_order_relaxed`, `std::memory_order_acquire`, `std::memory_order_release` 等）对于确保跨线程的正确同步至关重要。不正确的内存顺序可能导致难以调试的并发错误。

总的来说，`v8/test/cctest/wasm/test-run-wasm-atomics64.cc` 是一个非常重要的测试文件，它确保了 V8 引擎正确地实现了 WebAssembly 的 64 位原子操作，这对于构建可靠的多线程 WebAssembly 应用至关重要。

### 提示词
```
这是目录为v8/test/cctest/wasm/test-run-wasm-atomics64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-atomics64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/cctest/wasm/wasm-atomics-utils.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_atomics_64 {

void RunU64BinOp(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                 Uint64BinOp expected_op) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_I32V_1(0), WASM_LOCAL_GET(0),
                              MachineRepresentation::kWord64)});

  FOR_UINT64_INPUTS(i) {
    uint64_t initial = i;
    FOR_UINT64_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(j));
      uint64_t expected = expected_op(i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                 \
  WASM_EXEC_TEST(I64Atomic##Name) {                          \
    RunU64BinOp(execution_tier, kExprI64Atomic##Name, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

void RunU32BinOp(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                 Uint32BinOp expected_op) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_I32V_1(0), WASM_LOCAL_GET(0),
                              MachineRepresentation::kWord32)});

  FOR_UINT32_INPUTS(i) {
    uint32_t initial = i;
    FOR_UINT32_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(j));
      uint32_t expected = expected_op(i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                      \
  WASM_EXEC_TEST(I64Atomic##Name##32U) {                          \
    RunU32BinOp(execution_tier, kExprI64Atomic##Name##32U, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

void RunU16BinOp(TestExecutionTier tier, WasmOpcode wasm_op,
                 Uint16BinOp expected_op) {
  WasmRunner<uint64_t, uint64_t> r(tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_I32V_1(0), WASM_LOCAL_GET(0),
                              MachineRepresentation::kWord16)});

  FOR_UINT16_INPUTS(i) {
    uint16_t initial = i;
    FOR_UINT16_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(j));
      uint16_t expected = expected_op(i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                      \
  WASM_EXEC_TEST(I64Atomic##Name##16U) {                          \
    RunU16BinOp(execution_tier, kExprI64Atomic##Name##16U, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

void RunU8BinOp(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                Uint8BinOp expected_op) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_I32V_1(0), WASM_LOCAL_GET(0),
                              MachineRepresentation::kWord8)});

  FOR_UINT8_INPUTS(i) {
    uint8_t initial = i;
    FOR_UINT8_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(j));
      uint8_t expected = expected_op(i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                    \
  WASM_EXEC_TEST(I64Atomic##Name##8U) {                         \
    RunU8BinOp(execution_tier, kExprI64Atomic##Name##8U, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

WASM_EXEC_TEST(I64AtomicCompareExchange) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange, WASM_I32V_1(0), WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1), MachineRepresentation::kWord64)});

  FOR_UINT64_INPUTS(i) {
    uint64_t initial = i;
    FOR_UINT64_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(i, j));
      uint64_t expected = CompareExchange(initial, i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

WASM_EXEC_TEST(I64AtomicCompareExchange32U) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange32U, WASM_I32V_1(0), WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1), MachineRepresentation::kWord32)});

  FOR_UINT32_INPUTS(i) {
    uint32_t initial = i;
    FOR_UINT32_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(i, j));
      uint32_t expected = CompareExchange(initial, i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

WASM_EXEC_TEST(I64AtomicCompareExchange16U) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange16U, WASM_I32V_1(0), WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1), MachineRepresentation::kWord16)});

  FOR_UINT16_INPUTS(i) {
    uint16_t initial = i;
    FOR_UINT16_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(i, j));
      uint16_t expected = CompareExchange(initial, i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

WASM_EXEC_TEST(I32AtomicCompareExchange8U) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange8U, WASM_I32V_1(0), WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1), MachineRepresentation::kWord8)});
  FOR_UINT8_INPUTS(i) {
    uint8_t initial = i;
    FOR_UINT8_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call(i, j));
      uint8_t expected = CompareExchange(initial, i, j);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

WASM_EXEC_TEST(I64AtomicLoad) {
  WasmRunner<uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad, WASM_ZERO,
                                MachineRepresentation::kWord64)});

  FOR_UINT64_INPUTS(i) {
    uint64_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(I64AtomicLoad32U) {
  WasmRunner<uint64_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad32U, WASM_ZERO,
                                MachineRepresentation::kWord32)});

  FOR_UINT32_INPUTS(i) {
    uint32_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(I64AtomicLoad16U) {
  WasmRunner<uint64_t> r(execution_tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad16U, WASM_ZERO,
                                MachineRepresentation::kWord16)});

  FOR_UINT16_INPUTS(i) {
    uint16_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(I64AtomicLoad8U) {
  WasmRunner<uint64_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad8U, WASM_ZERO,
                                MachineRepresentation::kWord8)});

  FOR_UINT8_INPUTS(i) {
    uint8_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(I64AtomicStoreLoad) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI64AtomicStore, WASM_ZERO, WASM_LOCAL_GET(0),
                             MachineRepresentation::kWord64),
       WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad, WASM_ZERO,
                            MachineRepresentation::kWord64)});

  FOR_UINT64_INPUTS(i) {
    uint64_t expected = i;
    CHECK_EQ(expected, r.Call(i));
    CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(I64AtomicStoreLoad32U) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI64AtomicStore32U, WASM_ZERO,
                             WASM_LOCAL_GET(0), MachineRepresentation::kWord32),
       WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad32U, WASM_ZERO,
                            MachineRepresentation::kWord32)});

  FOR_UINT32_INPUTS(i) {
    uint32_t expected = i;
    CHECK_EQ(expected, r.Call(i));
    CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(I64AtomicStoreLoad16U) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI64AtomicStore16U, WASM_ZERO,
                             WASM_LOCAL_GET(0), MachineRepresentation::kWord16),
       WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad16U, WASM_ZERO,
                            MachineRepresentation::kWord16)});

  FOR_UINT16_INPUTS(i) {
    uint16_t expected = i;
    CHECK_EQ(expected, r.Call(i));
    CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(I64AtomicStoreLoad8U) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI64AtomicStore8U, WASM_ZERO,
                             WASM_LOCAL_GET(0), MachineRepresentation::kWord8),
       WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad8U, WASM_ZERO,
                            MachineRepresentation::kWord8)});

  FOR_UINT8_INPUTS(i) {
    uint8_t expected = i;
    CHECK_EQ(expected, r.Call(i));
    CHECK_EQ(i, r.builder().ReadMemory(&memory[0]));
  }
}

// Drop tests verify atomic operations are run correctly when the
// entire 64-bit output is optimized out
void RunDropTest(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                 Uint64BinOp op) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_I32V_1(0), WASM_LOCAL_GET(0),
                              MachineRepresentation::kWord64),
           WASM_DROP, WASM_LOCAL_GET(0)});

  uint64_t initial = 0x1111222233334444, local = 0x1111111111111111;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(local, r.Call(local));
  uint64_t expected = op(initial, local);
  CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
}

#define TEST_OPERATION(Name)                                 \
  WASM_EXEC_TEST(I64Atomic##Name##Drop) {                    \
    RunDropTest(execution_tier, kExprI64Atomic##Name, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

WASM_EXEC_TEST(I64AtomicSub16UDrop) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_BINOP(kExprI64AtomicSub16U, WASM_I32V_1(0),
                          WASM_LOCAL_GET(0), MachineRepresentation::kWord16),
       WASM_DROP, WASM_LOCAL_GET(0)});

  uint16_t initial = 0x7, local = 0xffe0;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(local, r.Call(local));
  uint16_t expected = Sub(initial, local);
  CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(I64AtomicCompareExchangeDrop) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
               kExprI64AtomicCompareExchange, WASM_I32V_1(0), WASM_LOCAL_GET(0),
               WASM_LOCAL_GET(1), MachineRepresentation::kWord64),
           WASM_DROP, WASM_LOCAL_GET(1)});

  uint64_t initial = 0x1111222233334444, local = 0x1111111111111111;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(local, r.Call(initial, local));
  uint64_t expected = CompareExchange(initial, initial, local);
  CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(I64AtomicStoreLoadDrop) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI64AtomicStore, WASM_ZERO, WASM_LOCAL_GET(0),
                             MachineRepresentation::kWord64),
       WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad, WASM_ZERO,
                            MachineRepresentation::kWord64),
       WASM_DROP, WASM_LOCAL_GET(1)});

  uint64_t store_value = 0x1111111111111111, expected = 0xC0DE;
  CHECK_EQ(expected, r.Call(store_value, expected));
  CHECK_EQ(store_value, r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(I64AtomicAddConvertDrop) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_BINOP(kExprI64AtomicAdd, WASM_I32V_1(0), WASM_LOCAL_GET(0),
                          MachineRepresentation::kWord64),
       kExprI32ConvertI64, WASM_DROP, WASM_LOCAL_GET(0)});

  uint64_t initial = 0x1111222233334444, local = 0x1111111111111111;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(local, r.Call(local));
  uint64_t expected = Add(initial, local);
  CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(I64AtomicLoadConvertDrop) {
  WasmRunner<uint32_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_LOAD_OP(
      kExprI64AtomicLoad, WASM_ZERO, MachineRepresentation::kWord64))});

  uint64_t initial = 0x1111222233334444;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(static_cast<uint32_t>(initial), r.Call(initial));
}

// Convert tests verify atomic operations are run correctly when the
// upper half of the 64-bit output is optimized out
void RunConvertTest(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                    Uint64BinOp op) {
  WasmRunner<uint32_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_BINOP(
      wasm_op, WASM_ZERO, WASM_LOCAL_GET(0), MachineRepresentation::kWord64))});

  uint64_t initial = 0x1111222233334444, local = 0x1111111111111111;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(static_cast<uint32_t>(initial), r.Call(local));
  uint64_t expected = op(initial, local);
  CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
}

#define TEST_OPERATION(Name)                                    \
  WASM_EXEC_TEST(I64AtomicConvert##Name) {                      \
    RunConvertTest(execution_tier, kExprI64Atomic##Name, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

WASM_EXEC_TEST(I64AtomicConvertCompareExchange) {
  WasmRunner<uint32_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange, WASM_I32V_1(0), WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1), MachineRepresentation::kWord64))});

  uint64_t initial = 0x1111222233334444, local = 0x1111111111111111;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(static_cast<uint32_t>(initial), r.Call(initial, local));
  uint64_t expected = CompareExchange(initial, initial, local);
  CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
}

// The WASM_I64_EQ operation is used here to test that the index node
// is lowered correctly.
void RunNonConstIndexTest(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                          Uint64BinOp op, MachineRepresentation rep) {
  WasmRunner<uint32_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_I32_CONVERT_I64(
      WASM_ATOMICS_BINOP(wasm_op, WASM_I64_EQ(WASM_I64V(1), WASM_I64V(0)),
                         WASM_LOCAL_GET(0), rep))});

  uint64_t initial = 0x1111222233334444, local = 0x5555666677778888;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(static_cast<uint32_t>(initial), r.Call(local));
  CHECK_EQ(static_cast<uint32_t>(op(initial, local)),
           static_cast<uint32_t>(r.builder().ReadMemory(&memory[0])));
}

// Test a set of Narrow operations
#define TEST_OPERATION(Name)                                              \
  WASM_EXEC_TEST(I64AtomicConstIndex##Name##Narrow) {                     \
    RunNonConstIndexTest(execution_tier, kExprI64Atomic##Name##32U, Name, \
                         MachineRepresentation::kWord32);                 \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

// Test a set of Regular operations
#define TEST_OPERATION(Name)                                         \
  WASM_EXEC_TEST(I64AtomicConstIndex##Name) {                        \
    RunNonConstIndexTest(execution_tier, kExprI64Atomic##Name, Name, \
                         MachineRepresentation::kWord64);            \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

WASM_EXEC_TEST(I64AtomicNonConstIndexCompareExchangeNarrow) {
  WasmRunner<uint32_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange16U, WASM_I64_EQ(WASM_I64V(1), WASM_I64V(0)),
      WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), MachineRepresentation::kWord16))});

  uint64_t initial = 0x4444333322221111, local = 0x9999888877776666;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(static_cast<uint16_t>(initial), r.Call(initial, local));
  CHECK_EQ(static_cast<uint16_t>(CompareExchange(initial, initial, local)),
           static_cast<uint16_t>(r.builder().ReadMemory(&memory[0])));
}

WASM_EXEC_TEST(I64AtomicNonConstIndexCompareExchange) {
  WasmRunner<uint32_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange, WASM_I64_EQ(WASM_I64V(1), WASM_I64V(0)),
      WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), MachineRepresentation::kWord64))});

  uint64_t initial = 4444333322221111, local = 0x9999888877776666;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(static_cast<uint32_t>(initial), r.Call(initial, local));
  CHECK_EQ(CompareExchange(initial, initial, local),
           r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(I64AtomicNonConstIndexLoad8U) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_LOAD_OP(
      kExprI64AtomicLoad8U, WASM_I64_EQ(WASM_I64V(1), WASM_I64V(0)),
      MachineRepresentation::kWord8))});

  uint64_t expected = 0xffffeeeeddddcccc;
  r.builder().WriteMemory(&memory[0], expected);
  CHECK_EQ(static_cast<uint8_t>(expected), r.Call());
}

WASM_EXEC_TEST(I64AtomicCompareExchangeFail) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange, WASM_I32V_1(0), WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1), MachineRepresentation::kWord64)});

  uint64_t initial = 0x1111222233334444, local = 0x1111111111111111,
           test = 0x2222222222222222;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(initial, r.Call(test, local));
  // No memory change on failed compare exchange
  CHECK_EQ(initial, r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(I64AtomicCompareExchange32UFail) {
  WasmRunner<uint64_t, uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange32U, WASM_I32V_1(0), WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1), MachineRepresentation::kWord32)});

  uint64_t initial = 0x1111222233334444, test = 0xffffffff, local = 0xeeeeeeee;
  r.builder().WriteMemory(&memory[0], initial);
  CHECK_EQ(static_cast<uint32_t>(initial), r.Call(test, local));
  // No memory change on failed compare exchange
  CHECK_EQ(initial, r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(AtomicStoreNoConsideredEffectful) {
  // Use {Load} instead of {ProtectedLoad}.
  FLAG_SCOPE(wasm_enforce_bounds_checks);
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_LOAD_MEM(MachineType::Int64(), WASM_ZERO),
           WASM_ATOMICS_STORE_OP(kExprI64AtomicStore, WASM_ZERO, WASM_I64V(20),
                                 MachineRepresentation::kWord64),
           kExprI64Eqz});
  CHECK_EQ(1, r.Call());
}

void RunNoEffectTest(TestExecutionTier execution_tier, WasmOpcode wasm_op) {
  // Use {Load} instead of {ProtectedLoad}.
  FLAG_SCOPE(wasm_enforce_bounds_checks);
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemoryElems<int64_t>(kWasmPageSize / sizeof(int64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_LOAD_MEM(MachineType::Int64(), WASM_ZERO),
           WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_I64V(20),
                              MachineRepresentation::kWord64),
           WASM_DROP, kExprI64Eqz});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(AtomicAddNoConsideredEffectful) {
  RunNoEffectTest(execution_tier, kExprI64AtomicAdd);
}

WASM_EXEC_TEST(AtomicExchangeNoConsideredEffectful) {
  RunNoEffectTest(execution_tier, kExprI64AtomicExchange);
}

WASM_EXEC_TEST(AtomicCompareExchangeNoConsideredEffectful) {
  // Use {Load} instead of {ProtectedLoad}.
  FLAG_SCOPE(wasm_enforce_bounds_checks);
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_LOAD_MEM(MachineType::Int64(), WASM_ZERO),
           WASM_ATOMICS_TERNARY_OP(kExprI64AtomicCompareExchange, WASM_ZERO,
                                   WASM_I64V(0), WASM_I64V(30),
                                   MachineRepresentation::kWord64),
           WASM_DROP, kExprI64Eqz});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(I64AtomicLoadUseOnlyLowWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the low word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_LOAD_OP(
      kExprI64AtomicLoad, WASM_I32V(8), MachineRepresentation::kWord64))});
  CHECK_EQ(0x90abcdef, r.Call());
}

WASM_EXEC_TEST(I64AtomicLoadUseOnlyHighWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the high word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(
      WASM_I64_ROR(WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad, WASM_I32V(8),
                                        MachineRepresentation::kWord64),
                   WASM_I64V(32)))});
  CHECK_EQ(0x12345678, r.Call());
}

WASM_EXEC_TEST(I64AtomicAddUseOnlyLowWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the low word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(
      WASM_ATOMICS_BINOP(kExprI64AtomicAdd, WASM_I32V(8), WASM_I64V(1),
                         MachineRepresentation::kWord64))});
  CHECK_EQ(0x90abcdef, r.Call());
}

WASM_EXEC_TEST(I64AtomicAddUseOnlyHighWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the high word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(WASM_I64_ROR(
      WASM_ATOMICS_BINOP(kExprI64AtomicAdd, WASM_I32V(8), WASM_I64V(1),
                         MachineRepresentation::kWord64),
      WASM_I64V(32)))});
  CHECK_EQ(0x12345678, r.Call());
}

WASM_EXEC_TEST(I64AtomicCompareExchangeUseOnlyLowWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the low word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange, WASM_I32V(8), WASM_I64V(1),
      WASM_I64V(memory[1]), MachineRepresentation::kWord64))});
  CHECK_EQ(0x90abcdef, r.Call());
}

WASM_EXEC_TEST(I64AtomicCompareExchangeUseOnlyHighWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the high word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(WASM_I64_ROR(
      WASM_ATOMICS_TERNARY_OP(kExprI64AtomicCompareExchange, WASM_I32V(8),
                              WASM_I64V(1), WASM_I64V(memory[1]),
                              MachineRepresentation::kWord64),
      WASM_I64V(32)))});
  CHECK_EQ(0x12345678, r.Call());
}

WASM_EXEC_TEST(I64AtomicExchangeUseOnlyLowWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the low word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(
      WASM_ATOMICS_BINOP(kExprI64AtomicExchange, WASM_I32V(8), WASM_I64V(1),
                         MachineRepresentation::kWord64))});
  CHECK_EQ(0x90abcdef, r.Call());
}

WASM_EXEC_TEST(I64AtomicExchangeUseOnlyHighWord) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  uint64_t initial = 0x1234567890abcdef;
  r.builder().WriteMemory(&memory[1], initial);
  r.builder().SetMemoryShared();
  // Test that we can use just the high word of an I64AtomicLoad.
  r.Build({WASM_I32_CONVERT_I64(WASM_I64_ROR(
      WASM_ATOMICS_BINOP(kExprI64AtomicExchange, WASM_I32V(8), WASM_I64V(1),
                         MachineRepresentation::kWord64),
      WASM_I64V(32)))});
  CHECK_EQ(0x12345678, r.Call());
}

WASM_EXEC_TEST(I64AtomicCompareExchange32UZeroExtended) {
  WasmRunner<uint32_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));
  memory[1] = 0;
  r.builder().SetMemoryShared();
  // Test that the high word of the expected value is cleared in the return
  // value.
  r.Build({WASM_I64_EQZ(
      WASM_ATOMICS_TERNARY_OP(kExprI64AtomicCompareExchange32U, WASM_I32V(8),
                              WASM_I64V(0x1234567800000000), WASM_I64V(0),
                              MachineRepresentation::kWord32))});
  CHECK_EQ(1, r.Call());
}

}  // namespace test_run_wasm_atomics_64
}  // namespace wasm
}  // namespace internal
}  // namespace v8
```