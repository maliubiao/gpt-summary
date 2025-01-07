Response:
Let's break down the thought process for analyzing this C++ code.

1. **Understand the Goal:** The request asks for the functionality of the given C++ file. It also has specific sub-questions about Torque, JavaScript relevance, logic, and common errors. The filename `test-run-wasm-atomics.cc` immediately suggests this file is testing WebAssembly atomic operations.

2. **High-Level Structure:**  Scan the file for major components. We see includes (`#include`), namespaces (`namespace v8 { namespace internal { namespace wasm { namespace test_run_wasm_atomics { ... } } } }`), and a series of function definitions. The `WASM_EXEC_TEST` macros stand out, likely indicating individual test cases.

3. **Key Data Structures and Types:** Look for relevant types and structures. `TestExecutionTier`, `WasmOpcode`, `Uint32BinOp`, `Uint16BinOp`, `Uint8BinOp`, `Uint64BinOp`, `WasmRunner`, and the various `FOR_UINT*INPUTS` macros are important. The presence of `kWasmPageSize` hints at memory management. `MachineRepresentation` points towards low-level details.

4. **Analyzing the `Run...BinOp` Functions:**  These functions appear to be the core logic for testing atomic binary operations. Notice the patterns:
    * They take `TestExecutionTier` and `WasmOpcode` as arguments, suggesting they are parameterized tests.
    * They use `WasmRunner` to create and execute WebAssembly code.
    * They allocate shared memory using `AddMemoryElems` and `SetMemoryShared`.
    * They build WebAssembly code using `r.Build()`, employing the `WASM_ATOMICS_BINOP` macro.
    * They use nested loops (`FOR_UINT*INPUTS`) to test various input combinations.
    * They write to memory (`r.builder().WriteMemory`), call the WebAssembly function (`r.Call`), and read back from memory (`r.builder().ReadMemory`).
    * They compare the actual result with an `expected_op` result.

5. **Understanding the Macros:**  The `WASM_ATOMICS_BINOP`, `WASM_ATOMICS_TERNARY_OP`, `WASM_ATOMICS_LOAD_OP`, `WASM_ATOMICS_STORE_OP`, and `WASM_ATOMICS_FENCE` macros are crucial. They represent different atomic WebAssembly instructions. The `WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)` suggests a way to automatically generate tests for various atomic operations.

6. **Dissecting Individual `WASM_EXEC_TEST` Blocks:** These are the individual test cases. They generally call one of the `Run...BinOp` functions or implement a specific test scenario like compare-exchange, load, store, or trapping. Pay attention to the specific WebAssembly opcodes being tested (e.g., `kExprI32AtomicAdd`, `kExprI32AtomicCompareExchange`).

7. **Focus on Specific Questions:**
    * **Torque:** The prompt specifically asks about `.tq` files. The code is `.cc`, so it's C++, not Torque.
    * **JavaScript Relevance:** The file tests *WebAssembly* atomics. WebAssembly runs in JavaScript environments. Atomic operations allow for safer concurrency in shared memory scenarios between JavaScript and WebAssembly, or between different WebAssembly modules. This is the key connection.
    * **Logic and Examples:** Choose a simple `Run...BinOp` example like `RunU32BinOp` for `kExprI32AtomicAdd`. Trace the execution flow with sample inputs. Show how the initial value is read, the operation is performed, and the updated value is written back.
    * **Common Errors:** Think about typical concurrency issues: race conditions, incorrect assumptions about shared memory. The compare-exchange test with `_fail` explicitly demonstrates one such scenario. Out-of-bounds access is also tested (`_trap` tests).

8. **Synthesize and Organize:**  Structure the answer logically. Start with a general overview, then detail the functionalities. Address each sub-question from the prompt systematically. Use clear language and provide code snippets or examples where appropriate.

9. **Refine and Review:** Reread the answer and the original code to ensure accuracy and completeness. Are there any ambiguities?  Is the explanation clear and concise?  Could examples be improved?  For instance, initially, I might have just said "it tests atomic operations," but it's better to be specific about *which* atomic operations (add, sub, and, or, xor, exchange, compare-exchange, load, store, fence). Also, explicitly mentioning the shared memory aspect is important.

This iterative process of scanning, analyzing, understanding, and synthesizing allows for a comprehensive understanding of the code and the ability to address the specific requirements of the prompt.
这个 C++ 代码文件 `v8/test/cctest/wasm/test-run-wasm-atomics.cc` 的主要功能是**测试 V8 引擎中 WebAssembly 的原子操作 (atomic operations) 的实现是否正确**。

以下是更详细的分解：

**1. 功能概述:**

* **测试各种原子操作:** 该文件包含了针对 WebAssembly 中各种原子操作的测试用例，例如：
    * **二元原子操作 (Binary Atomic Operations):**  `add`, `sub`, `and`, `or`, `xor`, `exchange`。这些操作会原子地读取内存中的值，与给定的操作数进行运算，然后将结果写回内存。
    * **比较并交换 (Compare and Exchange):** `compareExchange`。这个操作会原子地比较内存中的值是否等于预期值，如果相等则将其替换为新值。
    * **加载 (Load):** `load`。原子地从共享内存中读取值。
    * **存储 (Store):** `store`。原子地将值写入共享内存。
    * **栅栏 (Fence):** `fence`。确保内存操作的顺序性。

* **针对不同的数据类型:** 测试用例覆盖了 `i32` (32位整数) 和 `i64` (64位整数) 两种基本数据类型，以及它们的无符号变体 `u8`, `u16`。

* **测试不同的执行层 (Execution Tier):** 代码中使用 `TestExecutionTier execution_tier` 参数，表明测试可以在 V8 的不同执行层（例如：解释器，基线编译器，优化编译器）上运行，以确保原子操作在各种情况下都能正确工作。

* **测试常量和变量操作数:** 针对原子二元操作，测试了操作数是立即数 (常量) 和局部变量两种情况。

* **测试边界情况和错误处理:** 包括了针对内存访问越界 (out-of-bounds) 的测试 (`_trap` 后缀)，验证在这种情况下是否会产生预期的 trap 异常。

* **验证操作的原子性:** 虽然代码本身没有显式地创建多线程来证明原子性，但这些测试的设计思路是假设在并发环境下，这些操作能够保证数据的一致性。

**2. 代码结构解析:**

* **`RunU32BinOp`, `RunU16BinOp`, `RunU8BinOp`, `RunU64BinOp`:** 这些函数是用于测试原子二元操作的通用框架。它们接收执行层、Wasm 操作码和期望的操作函数作为参数。
    * 它们会创建一个 `WasmRunner` 对象，用于构建和执行 WebAssembly 代码。
    * 使用 `AddMemoryElems` 添加共享内存。
    * 使用 `WASM_ATOMICS_BINOP` 宏构建 WebAssembly 指令。
    * 使用 `FOR_UINT*INPUTS` 宏遍历不同的输入值组合。
    * 执行 WebAssembly 代码并检查内存中的值是否与预期一致。

* **`RunU*_BinOp_Const`:** 这些函数与上面的类似，但用于测试原子二元操作中操作数是常量的情况。

* **`WASM_EXEC_TEST` 宏:**  这是一个用于定义测试用例的宏。例如 `WASM_EXEC_TEST(I32AtomicAdd)` 定义了一个名为 `I32AtomicAdd` 的测试。

* **`WASM_ATOMIC_OPERATION_LIST` 宏:** 这个宏很可能定义在其他地方，它会展开为一系列针对不同原子操作的 `TEST_OPERATION` 宏调用，从而批量生成测试用例。

* **`CompareExchange` 函数:**  这是一个在 C++ 代码中定义的辅助函数，用于计算比较并交换操作的预期结果。

* **针对特定原子操作的测试用例:** 例如 `WASM_EXEC_TEST(I32AtomicCompareExchange)`, `WASM_EXEC_TEST(I32AtomicLoad)`, `WASM_EXEC_TEST(I32AtomicStoreLoad)` 等，它们调用相应的 `Run...` 函数或直接构建特定的 WebAssembly 代码来测试特定原子操作的功能。

**3. 关于 .tq 结尾:**

如果 `v8/test/cctest/wasm/test-run-wasm-atomics.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是一种 V8 使用的领域特定语言，用于生成高效的 JavaScript 内置函数和运行时代码。  然而，根据你提供的代码，这个文件以 `.cc` 结尾，所以它是一个 **C++ 源代码文件**。

**4. 与 JavaScript 的关系:**

WebAssembly 的原子操作是为了支持多线程 WebAssembly 应用而设计的。当 WebAssembly 模块在 JavaScript 环境中运行时，它可以与 JavaScript 代码共享内存（通过 `SharedArrayBuffer`）。原子操作允许 WebAssembly 和 JavaScript 安全地访问和修改共享内存，避免出现竞态条件等并发问题。

**JavaScript 示例:**

```javascript
// 创建一个共享的 ArrayBuffer
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const ia = new Int32Array(sab);

// 假设有一个 WebAssembly 模块实例，其中包含原子操作

// JavaScript 中设置共享内存的初始值
Atomics.store(ia, 0, 10);
console.log("JavaScript 设置的值:", Atomics.load(ia, 0)); // 输出: JavaScript 设置的值: 10

// 假设 WebAssembly 模块中执行了原子加操作 (i32.atomic.add)
// 并且它操作的是共享内存的索引 0，加上了 5。

// WebAssembly 执行后，JavaScript 中读取共享内存的值
console.log("WebAssembly 原子加后的值:", Atomics.load(ia, 0)); // 输出: WebAssembly 原子加后的值: 15
```

在这个例子中，JavaScript 使用 `Atomics` API 来操作共享内存，而 WebAssembly 可以使用其原子指令（如 `i32.atomic.add`）来执行相同的操作，保证数据的一致性。

**5. 代码逻辑推理 (假设输入与输出):**

以 `RunU32BinOp` 函数和 `I32AtomicAdd` 测试为例：

**假设输入:**

* `execution_tier`:  假设是 `kInterpreted` (解释器执行层)。
* `wasm_op`: `kExprI32AtomicAdd` (WebAssembly 的原子加操作码)。
* `expected_op`: 是一个 C++ 函数，实现了无符号 32 位整数的加法。
* 共享内存的初始值为 `initial = 5`。
* 原子加操作的操作数为 `j = 3`。

**代码执行流程:**

1. `WasmRunner` 构建一个简单的 WebAssembly 函数，该函数会执行 `i32.atomic.add offset=0, p0`，其中 `p0` 是函数的参数（对应于 `j`）。
2. `r.builder().WriteMemory(&memory[0], initial);` 将初始值 5 写入共享内存的起始位置。
3. `CHECK_EQ(initial, r.Call(j));`  执行 WebAssembly 函数。原子加操作会读取内存中的值 5，加上 `j` (3)，得到 8，然后将 8 写回内存。该原子操作会返回操作前的原始值，所以 `r.Call(j)` 的返回值应该是 5。
4. `uint32_t expected = expected_op(i, j);` 计算期望的结果，这里 `i` 是初始值 5，`j` 是操作数 3，所以 `expected` 是 5 + 3 = 8。
5. `CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));`  读取共享内存中的值，并与期望的结果 8 进行比较，应该相等。

**假设输出:**

* `r.Call(j)` 的返回值是 `5`。
* 共享内存中的最终值是 `8`。

**6. 涉及用户常见的编程错误:**

* **竞态条件 (Race Condition):** 在没有正确使用原子操作或锁的情况下，多个线程或 WebAssembly 实例同时访问和修改共享内存可能导致数据不一致。例如，两个线程同时对一个变量进行加 1 操作，如果没有原子性保证，最终结果可能只加了 1 而不是 2。

   **JavaScript 例子 (非原子操作导致竞态):**

   ```javascript
   const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
   const ia = new Int32Array(sab);
   Atomics.store(ia, 0, 0);

   function increment() {
       const currentValue = Atomics.load(ia, 0);
       Atomics.store(ia, 0, currentValue + 1);
   }

   const worker1 = new Worker(/* ... */);
   const worker2 = new Worker(/* ... */);

   worker1.postMessage({ type: 'increment' });
   worker2.postMessage({ type: 'increment' });

   // 最终 ia[0] 的值可能为 1 而不是 2
   ```

* **数据竞争 (Data Race):**  当多个线程同时访问同一个内存位置，并且至少有一个线程在写入，而没有采取同步措施时，就会发生数据竞争。原子操作可以避免某些类型的数据竞争。

* **内存越界访问:** 就像测试用例 `I32AtomicLoad_trap` 等所示，尝试对共享内存进行越界访问会导致错误。

* **对非共享内存使用原子操作:**  虽然代码中 `AtomicFence` 的测试特意不使用共享内存，但通常情况下，原子操作是为共享内存设计的。对非共享内存使用原子操作可能没有意义，或者行为未定义。

总而言之，`v8/test/cctest/wasm/test-run-wasm-atomics.cc` 是一个关键的测试文件，用于确保 V8 引擎中 WebAssembly 原子操作的正确性和可靠性，这对于支持多线程 WebAssembly 应用至关重要。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-atomics.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/test/cctest/wasm/test-run-wasm-atomics.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "test/cctest/wasm/wasm-atomics-utils.h"
#include "test/common/wasm/wasm-macro-gen.h"

namespace v8 {
namespace internal {
namespace wasm {
namespace test_run_wasm_atomics {

void RunU32BinOp(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                 Uint32BinOp expected_op) {
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_LOCAL_GET(0),
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

void RunU32BinOp_Const(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                       Uint32BinOp expected_op) {
  FOR_UINT32_INPUTS(i) {
    WasmRunner<uint32_t> r(execution_tier);
    uint32_t* memory =
        r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));

    r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_I32V(i),
                                MachineRepresentation::kWord32)});

    FOR_UINT32_INPUTS(j) {
      uint32_t initial = j;
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call());
      uint32_t expected = expected_op(j, i);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                       \
  WASM_EXEC_TEST(I32Atomic##Name) {                                \
    RunU32BinOp(execution_tier, kExprI32Atomic##Name, Name);       \
    RunU32BinOp_Const(execution_tier, kExprI32Atomic##Name, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

void RunU16BinOp(TestExecutionTier tier, WasmOpcode wasm_op,
                 Uint16BinOp expected_op) {
  WasmRunner<uint32_t, uint32_t> r(tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_LOCAL_GET(0),
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

void RunU16BinOp_Const(TestExecutionTier tier, WasmOpcode wasm_op,
                       Uint16BinOp expected_op) {
  FOR_UINT16_INPUTS(i) {
    WasmRunner<uint32_t> r(tier);
    uint16_t* memory =
        r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));

    r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_I32V(i),
                                MachineRepresentation::kWord16)});

    FOR_UINT16_INPUTS(j) {
      uint16_t initial = j;
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call());
      uint16_t expected = expected_op(j, i);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                            \
  WASM_EXEC_TEST(I32Atomic##Name##16U) {                                \
    RunU16BinOp(execution_tier, kExprI32Atomic##Name##16U, Name);       \
    RunU16BinOp_Const(execution_tier, kExprI32Atomic##Name##16U, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

void RunU8BinOp(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                Uint8BinOp expected_op) {
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_LOCAL_GET(0),
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

void RunU8BinOp_Const(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                      Uint8BinOp expected_op) {
  FOR_UINT8_INPUTS(i) {
    WasmRunner<uint32_t> r(execution_tier);
    uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);

    r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_I32V(i),
                                MachineRepresentation::kWord8)});

    FOR_UINT8_INPUTS(j) {
      uint8_t initial = j;
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call());
      uint8_t expected = expected_op(j, i);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                          \
  WASM_EXEC_TEST(I32Atomic##Name##8U) {                               \
    RunU8BinOp(execution_tier, kExprI32Atomic##Name##8U, Name);       \
    RunU8BinOp_Const(execution_tier, kExprI32Atomic##Name##8U, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

void RunU64BinOp(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                 Uint64BinOp expected_op) {
  WasmRunner<uint64_t, uint64_t> r(execution_tier);
  uint64_t* memory =
      r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_LOCAL_GET(0),
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

void RunU64BinOp_Const(TestExecutionTier execution_tier, WasmOpcode wasm_op,
                       Uint64BinOp expected_op) {
  FOR_UINT64_INPUTS(i) {
    WasmRunner<uint64_t> r(execution_tier);
    uint64_t* memory =
        r.builder().AddMemoryElems<uint64_t>(kWasmPageSize / sizeof(uint64_t));

    r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_I64V_10(i),
                                MachineRepresentation::kWord64)});

    FOR_UINT64_INPUTS(j) {
      uint64_t initial = j;
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_EQ(initial, r.Call());
      uint64_t expected = expected_op(j, i);
      CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
    }
  }
}

#define TEST_OPERATION(Name)                                       \
  WASM_EXEC_TEST(I64Atomic##Name) {                                \
    RunU64BinOp(execution_tier, kExprI64Atomic##Name, Name);       \
    RunU64BinOp_Const(execution_tier, kExprI64Atomic##Name, Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

WASM_EXEC_TEST(I32AtomicCompareExchange) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(kExprI32AtomicCompareExchange, WASM_ZERO,
                                   WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                   MachineRepresentation::kWord32)});

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

WASM_EXEC_TEST(I32AtomicCompareExchange16U) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(kExprI32AtomicCompareExchange16U, WASM_ZERO,
                                   WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                   MachineRepresentation::kWord16)});

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
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(kExprI32AtomicCompareExchange8U, WASM_ZERO,
                                   WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                   MachineRepresentation::kWord8)});

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

WASM_EXEC_TEST(I32AtomicCompareExchange_fail) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(kExprI32AtomicCompareExchange, WASM_ZERO,
                                   WASM_LOCAL_GET(0), WASM_LOCAL_GET(1),
                                   MachineRepresentation::kWord32)});

  // The original value at the memory location.
  uint32_t old_val = 4;
  // The value we use as the expected value for the compare-exchange so that it
  // fails.
  uint32_t expected = 6;
  // The new value for the compare-exchange.
  uint32_t new_val = 5;

  r.builder().WriteMemory(&memory[0], old_val);
  CHECK_EQ(old_val, r.Call(expected, new_val));
}

WASM_EXEC_TEST(I32AtomicLoad) {
  WasmRunner<uint32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad, WASM_ZERO,
                                MachineRepresentation::kWord32)});

  FOR_UINT32_INPUTS(i) {
    uint32_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(I32AtomicLoad16U) {
  WasmRunner<uint32_t> r(execution_tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad16U, WASM_ZERO,
                                MachineRepresentation::kWord16)});

  FOR_UINT16_INPUTS(i) {
    uint16_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(I32AtomicLoad8U) {
  WasmRunner<uint32_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad8U, WASM_ZERO,
                                MachineRepresentation::kWord8)});

  FOR_UINT8_INPUTS(i) {
    uint8_t expected = i;
    r.builder().WriteMemory(&memory[0], expected);
    CHECK_EQ(expected, r.Call());
  }
}

WASM_EXEC_TEST(I32AtomicStoreLoad) {
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI32AtomicStore, WASM_ZERO, WASM_LOCAL_GET(0),
                             MachineRepresentation::kWord32),
       WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad, WASM_ZERO,
                            MachineRepresentation::kWord32)});

  FOR_UINT32_INPUTS(i) {
    uint32_t expected = i;
    CHECK_EQ(expected, r.Call(i));
    CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(I32AtomicStoreLoad16U) {
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint16_t* memory =
      r.builder().AddMemoryElems<uint16_t>(kWasmPageSize / sizeof(uint16_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI32AtomicStore16U, WASM_ZERO,
                             WASM_LOCAL_GET(0), MachineRepresentation::kWord16),
       WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad16U, WASM_ZERO,
                            MachineRepresentation::kWord16)});

  FOR_UINT16_INPUTS(i) {
    uint16_t expected = i;
    CHECK_EQ(expected, r.Call(i));
    CHECK_EQ(expected, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(I32AtomicStoreLoad8U) {
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint8_t* memory = r.builder().AddMemoryElems<uint8_t>(kWasmPageSize);
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI32AtomicStore8U, WASM_ZERO,
                             WASM_LOCAL_GET(0), MachineRepresentation::kWord8),
       WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad8U, WASM_ZERO,
                            MachineRepresentation::kWord8)});

  FOR_UINT8_INPUTS(i) {
    uint8_t expected = i;
    CHECK_EQ(expected, r.Call(i));
    CHECK_EQ(i, r.builder().ReadMemory(&memory[0]));
  }
}

WASM_EXEC_TEST(I32AtomicStoreParameter) {
  WasmRunner<uint32_t, uint32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();

  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI32AtomicStore, WASM_ZERO, WASM_LOCAL_GET(0),
                             MachineRepresentation::kWord32),
       WASM_ATOMICS_BINOP(kExprI32AtomicAdd, WASM_ZERO, WASM_LOCAL_GET(0),
                          MachineRepresentation::kWord32)});
  CHECK_EQ(10, r.Call(10));
  CHECK_EQ(20, r.builder().ReadMemory(&memory[0]));
}

WASM_EXEC_TEST(AtomicFence) {
  WasmRunner<uint32_t> r(execution_tier);
  // Note that this test specifically doesn't use a shared memory, as the fence
  // instruction does not target a particular linear memory. It may occur in
  // modules which declare no memory, or a non-shared memory, without causing a
  // validation error.

  r.Build({WASM_ATOMICS_FENCE, WASM_ZERO});
  CHECK_EQ(0, r.Call());
}

WASM_EXEC_TEST(AtomicStoreNoConsideredEffectful) {
  // Use {Load} instead of {ProtectedLoad}.
  FLAG_SCOPE(wasm_enforce_bounds_checks);
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().SetMemoryShared();
  r.Build(
      {WASM_LOAD_MEM(MachineType::Int64(), WASM_ZERO),
       WASM_ATOMICS_STORE_OP(kExprI32AtomicStore, WASM_ZERO, WASM_I32V_1(20),
                             MachineRepresentation::kWord32),
       kExprI64Eqz});
  CHECK_EQ(1, r.Call());
}

void RunNoEffectTest(TestExecutionTier execution_tier, WasmOpcode wasm_op) {
  // Use {Load} instead of {ProtectedLoad}.
  FLAG_SCOPE(wasm_enforce_bounds_checks);
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_LOAD_MEM(MachineType::Int64(), WASM_ZERO),
           WASM_ATOMICS_BINOP(wasm_op, WASM_ZERO, WASM_I32V_1(20),
                              MachineRepresentation::kWord32),
           WASM_DROP, kExprI64Eqz});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(AtomicAddNoConsideredEffectful) {
  RunNoEffectTest(execution_tier, kExprI32AtomicAdd);
}

WASM_EXEC_TEST(AtomicExchangeNoConsideredEffectful) {
  RunNoEffectTest(execution_tier, kExprI32AtomicExchange);
}

WASM_EXEC_TEST(AtomicCompareExchangeNoConsideredEffectful) {
  // Use {Load} instead of {ProtectedLoad}.
  FLAG_SCOPE(wasm_enforce_bounds_checks);
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemoryElems<int32_t>(kWasmPageSize / sizeof(int32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_LOAD_MEM(MachineType::Int32(), WASM_ZERO),
           WASM_ATOMICS_TERNARY_OP(kExprI32AtomicCompareExchange, WASM_ZERO,
                                   WASM_ZERO, WASM_I32V_1(30),
                                   MachineRepresentation::kWord32),
           WASM_DROP, kExprI32Eqz});
  CHECK_EQ(1, r.Call());
}

WASM_EXEC_TEST(I32AtomicLoad_trap) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad, WASM_I32V_3(kWasmPageSize),
                                MachineRepresentation::kWord32)});
  CHECK_TRAP(r.Call());
}

WASM_EXEC_TEST(I64AtomicLoad_trap) {
  WasmRunner<uint64_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_LOAD_OP(kExprI64AtomicLoad, WASM_I32V_3(kWasmPageSize),
                                MachineRepresentation::kWord64)});
  CHECK_TRAP64(r.Call());
}

WASM_EXEC_TEST(I32AtomicStore_trap) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI32AtomicStore, WASM_I32V_3(kWasmPageSize),
                             WASM_ZERO, MachineRepresentation::kWord32),
       WASM_ZERO});
  CHECK_TRAP(r.Call());
}

WASM_EXEC_TEST(I64AtomicStore_trap) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build(
      {WASM_ATOMICS_STORE_OP(kExprI64AtomicStore, WASM_I32V_3(kWasmPageSize),
                             WASM_ZERO64, MachineRepresentation::kWord64),
       WASM_ZERO});
  CHECK_TRAP(r.Call());
}

WASM_EXEC_TEST(I32AtomicLoad_NotOptOut) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_I32_AND(
      WASM_ATOMICS_LOAD_OP(kExprI32AtomicLoad, WASM_I32V_3(kWasmPageSize),
                           MachineRepresentation::kWord32),
      WASM_ZERO)});
  CHECK_TRAP(r.Call());
}

void RunU32BinOp_OOB(TestExecutionTier execution_tier, WasmOpcode wasm_op) {
  WasmRunner<uint32_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_I32V_3(kWasmPageSize), WASM_ZERO,
                              MachineRepresentation::kWord32)});

  CHECK_TRAP(r.Call());
}

#define TEST_OPERATION(Name)                               \
  WASM_EXEC_TEST(OOB_I32Atomic##Name) {                    \
    RunU32BinOp_OOB(execution_tier, kExprI32Atomic##Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

void RunU64BinOp_OOB(TestExecutionTier execution_tier, WasmOpcode wasm_op) {
  WasmRunner<uint64_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();

  r.Build({WASM_ATOMICS_BINOP(wasm_op, WASM_I32V_3(kWasmPageSize), WASM_ZERO64,
                              MachineRepresentation::kWord64)});

  CHECK_TRAP64(r.Call());
}

#define TEST_OPERATION(Name)                               \
  WASM_EXEC_TEST(OOB_I64Atomic##Name) {                    \
    RunU64BinOp_OOB(execution_tier, kExprI64Atomic##Name); \
  }
WASM_ATOMIC_OPERATION_LIST(TEST_OPERATION)
#undef TEST_OPERATION

WASM_EXEC_TEST(I32AtomicCompareExchange_trap) {
  WasmRunner<uint32_t, uint32_t, uint32_t> r(execution_tier);
  uint32_t* memory =
      r.builder().AddMemoryElems<uint32_t>(kWasmPageSize / sizeof(uint32_t));
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI32AtomicCompareExchange, WASM_I32V_3(kWasmPageSize),
      WASM_LOCAL_GET(0), WASM_LOCAL_GET(1), MachineRepresentation::kWord32)});

  FOR_UINT32_INPUTS(i) {
    uint32_t initial = i;
    FOR_UINT32_INPUTS(j) {
      r.builder().WriteMemory(&memory[0], initial);
      CHECK_TRAP(r.Call(i, j));
    }
  }
}

WASM_EXEC_TEST(I64AtomicCompareExchange_trap) {
  WasmRunner<uint64_t> r(execution_tier);
  r.builder().AddMemory(kWasmPageSize);
  r.builder().SetMemoryShared();
  r.Build({WASM_ATOMICS_TERNARY_OP(
      kExprI64AtomicCompareExchange, WASM_I32V_3(kWasmPageSize), WASM_ZERO64,
      WASM_ZERO64, MachineRepresentation::kWord64)});

  CHECK_TRAP64(r.Call());
}

}  // namespace test_run_wasm_atomics
}  // namespace wasm
}  // namespace internal
}  // namespace v8

"""

```