Response: The user wants to understand the functionality of the C++ code provided. The code seems to be testing WebAssembly atomic operations on 64-bit integers. I need to break down its core purpose and relate it to JavaScript.

**Plan:**

1. **Identify the core functionality:** The code uses `WasmRunner` to execute WebAssembly code snippets that perform atomic operations. It tests different atomic operations like `add`, `sub`, `exchange`, `compareExchange`, `load`, and `store` on 64-bit integers and smaller sizes (32-bit, 16-bit, 8-bit).
2. **Explain the testing methodology:** The code iterates through various input values and checks if the WebAssembly execution matches the expected results based on C++ implementations of the atomic operations.
3. **Relate to JavaScript:**  Explain how these WebAssembly atomic operations are exposed in JavaScript through the `SharedArrayBuffer` and `Atomics` objects.
4. **Provide JavaScript examples:**  Demonstrate how to perform equivalent atomic operations in JavaScript.
这个C++源代码文件 `test-run-wasm-atomics64.cc` 的功能是 **测试 WebAssembly 中关于 64 位原子操作的实现是否正确**。

具体来说，它做了以下几点：

1. **定义和测试各种 64 位原子操作：**  代码针对 WebAssembly 中定义的各种 64 位原子操作（例如 `i64.atomic.add`、`i64.atomic.sub`、`i64.atomic.exchange`、`i64.atomic.compare_exchange`、`i64.atomic.load`、`i64.atomic.store`）进行了详尽的测试。它还测试了操作不同大小的数据（32位、16位、8位）时的原子操作，例如 `i64.atomic.add32u`。

2. **使用 `WasmRunner` 执行 WebAssembly 代码片段：**  代码使用 `WasmRunner` 类来构建和执行包含原子操作的 WebAssembly 代码片段。`WasmRunner` 提供了一种便捷的方式来定义 WebAssembly 模块，设置内存，调用函数并检查结果。

3. **模拟共享内存环境：**  通过 `r.builder().SetMemoryShared()`，代码模拟了 WebAssembly 的共享内存环境，这是原子操作发挥作用的前提。

4. **对比 WebAssembly 执行结果与预期结果：**  对于每个测试用例，代码会预先计算出期望的结果（通过 C++ 的函数，例如 `Add`、`Sub`、`CompareExchange`），然后执行相应的 WebAssembly 原子操作，并比较执行后的内存状态和返回值是否与预期一致。

5. **覆盖不同的执行层（Execution Tier）：**  `TestExecutionTier` 参数允许在不同的 V8 执行层（例如解释器、编译器）上运行测试，以确保在各种情况下原子操作的正确性。

6. **测试优化场景：**  代码还包含了一些特殊的测试用例，例如带有 `WASM_DROP` 指令的测试（例如 `I64AtomicAddDrop`），用于验证当原子操作的结果被丢弃时，其副作用是否仍然正确执行。 还有一些转换测试（例如 `I64AtomicConvertAdd`），验证当原子操作的结果被转换为较小类型时是否正确。

7. **测试非固定索引的情况：**  部分测试用例使用了非固定的内存索引（例如 `WASM_I64_EQ(WASM_I64V(1), WASM_I64V(0))`），以确保索引的计算不会影响原子操作的正确性。

8. **测试 CompareExchange 的失败情况：**  专门的测试用例 (`I64AtomicCompareExchangeFail`) 验证了 `compareExchange` 操作在比较失败时不会修改内存。

**与 Javascript 的关系和举例：**

这个 C++ 文件测试的 WebAssembly 原子操作是 JavaScript 中 `SharedArrayBuffer` 和 `Atomics` 对象的基础。`SharedArrayBuffer` 允许在多个 worker 或主线程之间共享内存，而 `Atomics` 对象提供了一组静态方法，用于对 `SharedArrayBuffer` 中的数据执行原子操作，以避免数据竞争。

JavaScript 中的 `Atomics` API 提供了与 WebAssembly 原子操作相对应的功能。例如：

* **WebAssembly `i64.atomic.add` 对应 JavaScript `Atomics.add()`:**

```javascript
const sab = new SharedArrayBuffer(8); // 创建一个 8 字节的 SharedArrayBuffer
const ta = new BigInt64Array(sab);    // 创建一个 BigInt64Array 视图

Atomics.store(ta, 0, 10n); // 在索引 0 处存储初始值 10
console.log(Atomics.add(ta, 0, 5n)); // 将索引 0 处的值原子地加 5，并返回原始值 10
console.log(Atomics.load(ta, 0));    // 输出修改后的值 15n
```

* **WebAssembly `i64.atomic.compare_exchange` 对应 JavaScript `Atomics.compareExchange()`:**

```javascript
const sab = new SharedArrayBuffer(8);
const ta = new BigInt64Array(sab);

Atomics.store(ta, 0, 10n);
console.log(Atomics.compareExchange(ta, 0, 10n, 20n)); // 如果索引 0 处的值是 10，则替换为 20，返回原始值 10
console.log(Atomics.load(ta, 0)); // 输出修改后的值 20n

Atomics.store(ta, 0, 10n);
console.log(Atomics.compareExchange(ta, 0, 15n, 20n)); // 如果索引 0 处的值是 15，则替换为 20，但现在是 10，所以不替换，返回原始值 10
console.log(Atomics.load(ta, 0)); // 输出未修改的值 10n
```

* **WebAssembly `i64.atomic.load` 对应 JavaScript `Atomics.load()`:**

```javascript
const sab = new SharedArrayBuffer(8);
const ta = new BigInt64Array(sab);

Atomics.store(ta, 0, 100n);
console.log(Atomics.load(ta, 0)); // 输出 100n
```

* **WebAssembly `i64.atomic.store` 对应 JavaScript `Atomics.store()`:**

```javascript
const sab = new SharedArrayBuffer(8);
const ta = new BigInt64Array(sab);

Atomics.store(ta, 0, 200n);
console.log(Atomics.load(ta, 0)); // 输出 200n
```

总而言之，`test-run-wasm-atomics64.cc` 是 V8 引擎中用于确保 WebAssembly 的 64 位原子操作实现符合规范并能正确工作的测试文件。这些原子操作在 JavaScript 中通过 `SharedArrayBuffer` 和 `Atomics` API 暴露出来，用于实现多线程环境下的安全数据共享。

Prompt: 
```
这是目录为v8/test/cctest/wasm/test-run-wasm-atomics64.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```