Response: The user wants a summary of the C++ code provided, which is a test file for WebAssembly atomics. I need to identify the core functionalities being tested and if/how these relate to JavaScript.

**Plan:**

1. **Identify the main purpose of the file:** It's a C++ test file within the V8 project, specifically for testing WebAssembly atomic operations.
2. **Analyze the test structure:** The code uses macros and helper functions (`RunU32BinOp`, `RunU16BinOp`, `RunU8BinOp`, `RunU64BinOp`) to systematically test different atomic operations.
3. **Identify the tested atomic operations:** Look for the `WASM_ATOMIC_OPERATION_LIST` macro usage and the specific atomic opcodes (e.g., `kExprI32AtomicAdd`, `kExprI32AtomicCompareExchange`).
4. **Explain the test methodology:** The tests generally involve setting up a WebAssembly module with shared memory, performing an atomic operation, and verifying the result.
5. **Connect to JavaScript:** Explain how these atomic operations in WebAssembly are exposed to JavaScript through the `SharedArrayBuffer` and `Atomics` API. Provide JavaScript examples demonstrating equivalent operations.
这个C++源代码文件 `test-run-wasm-atomics.cc` 是 V8 JavaScript 引擎的测试文件，专门用于测试 WebAssembly 的原子操作 (atomics) 功能。

**功能归纳:**

该文件的主要功能是：

1. **定义了一系列测试用例，用于验证 WebAssembly 原子操作的正确性。**  这些测试覆盖了不同数据类型（uint32_t, uint16_t, uint8_t, uint64_t）的原子操作。
2. **测试了各种原子操作的组合和边界情况。** 包括：
    * **二元原子操作 (Binary Atomic Operations):**  例如 Add (添加), Sub (减法), And (按位与), Or (按位或), Xor (按位异或), Exchange (交换)。
    * **比较并交换原子操作 (Compare and Exchange Atomic Operation):** 用于原子地比较内存中的值，并在匹配时更新它。
    * **加载 (Load) 和存储 (Store) 原子操作。**
    * **原子栅栏 (Atomic Fence):** 用于确保内存操作的顺序性。
3. **使用了 `WasmRunner` 工具类来创建和执行 WebAssembly 模块。**  这使得测试能够方便地构建 WebAssembly 代码片段并执行。
4. **使用了宏 (`TEST_OPERATION`, `WASM_ATOMIC_OPERATION_LIST`) 来简化测试用例的编写。**
5. **测试了原子操作在不同执行层 (execution tier) 的行为。**
6. **测试了原子操作与常量值的组合。**
7. **测试了原子操作的越界访问 (out-of-bounds access) 是否会触发陷阱 (trap)。**
8. **测试了原子操作在没有副作用的情况下是否被正确处理。**

**与 JavaScript 的关系及示例:**

WebAssembly 的原子操作是为了支持多线程编程而引入的，它允许不同的 WebAssembly 实例（在不同的线程中运行）安全地访问和修改共享内存。  这些原子操作在 JavaScript 中通过 `SharedArrayBuffer` 和 `Atomics` API 暴露出来。

**`SharedArrayBuffer`:** 允许在多个 agent (例如，不同的 worker 线程) 之间共享一块内存区域。

**`Atomics`:** 提供了一组静态方法，用于对 `SharedArrayBuffer` 进行原子操作。  这些方法与 WebAssembly 的原子指令相对应。

**JavaScript 示例:**

假设我们有一个 `SharedArrayBuffer` 实例 `sab` 和一个 `Int32Array` 视图 `view` 指向它：

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1); // 创建一个可以存储一个 32 位整数的共享内存
const view = new Int32Array(sab);

// 初始值
console.log(Atomics.load(view, 0)); // 输出: 0

// 原子加法 (对应 WebAssembly 的 i32.atomic.add)
Atomics.add(view, 0, 5);
console.log(Atomics.load(view, 0)); // 输出: 5

// 原子减法 (对应 WebAssembly 的 i32.atomic.sub)
Atomics.sub(view, 0, 2);
console.log(Atomics.load(view, 0)); // 输出: 3

// 原子交换 (对应 WebAssembly 的 i32.atomic.exchange)
const oldValue = Atomics.exchange(view, 0, 10);
console.log(oldValue); // 输出: 3
console.log(Atomics.load(view, 0)); // 输出: 10

// 原子比较并交换 (对应 WebAssembly 的 i32.atomic.cmpxchg)
// 如果 view[0] 的值是 10，则将其设置为 20，并返回旧值 10
const compareResult = Atomics.compareExchange(view, 0, 10, 20);
console.log(compareResult); // 输出: 10
console.log(Atomics.load(view, 0)); // 输出: 20

// 原子按位与 (对应 WebAssembly 的 i32.atomic.and)
Atomics.and(view, 0, 3); // 20 的二进制是 10100，3 的二进制是 00011，按位与结果是 00000
console.log(Atomics.load(view, 0)); // 输出: 0

// 原子栅栏 (对应 WebAssembly 的 atomic.fence)
// 确保此操作之前的内存访问在之后的访问之前完成 (在多线程上下文中很重要)
Atomics.fence();
```

**总结:**

`test-run-wasm-atomics.cc` 文件通过一系列 C++ 测试用例，详细地验证了 WebAssembly 原子操作的正确性和各种场景下的行为。这些原子操作的功能最终会通过 JavaScript 的 `SharedArrayBuffer` 和 `Atomics` API 暴露给开发者，以便在多线程 JavaScript 应用中使用共享内存进行安全的数据同步。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-atomics.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

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