Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Identify the Core Functionality:** The code heavily uses macros like `FOREACH_ATOMIC_BINOP`, `FOREACH_ATOMIC_COMPARE_EXCHANGE_OP`, etc., and instruction handler functions named `s2s_...`. The "atomic" prefix strongly suggests this section deals with atomic operations on shared memory. The "Simd" prefix suggests SIMD (Single Instruction, Multiple Data) operations. This gives us two main areas to focus on.

2. **Analyze Atomic Operations:**
    * **Macros for Generation:** The `FOREACH_` macros are a pattern for code generation. They take a base macro (`ATOMIC_BINOP`, `ATOMIC_COMPARE_EXCHANGE_OP`, etc.) and expand it for various data types and operations. This is a common C++ technique to avoid repetitive code.
    * **Individual Atomic Operations:**  Look at the names of the generated functions (e.g., `s2s_I64AtomicAdd`). The naming convention clearly indicates the data type (I32, I64), the operation (Add, Sub, Xor, Exchange, CompareExchange), and sometimes the size and signedness (8U, 16U, 32U).
    * **Common Structure:** The `INSTRUCTION_HANDLER_FUNC` macro defines the structure of these functions. They take `code`, `sp` (stack pointer), and `wasm_runtime` as arguments. They generally:
        * Pop values from the stack (`pop<...>`).
        * Read the memory offset.
        * Calculate the effective memory address.
        * Perform alignment and bounds checks.
        * Use `std::atomic<...>` to perform the atomic operation.
        * Push the result back onto the stack (`push<...>`).
        * Advance to the next instruction (`NextOp()`).
    * **Purpose:** Atomic operations are essential for concurrent programming, ensuring data integrity when multiple threads or processes access shared memory. They prevent race conditions.

3. **Analyze SIMD Operations:**
    * **Similar Macro Pattern:** Again, `SPLAT_CASE`, `EXTRACT_LANE_CASE`, `BINOP_CASE`, etc., indicate code generation for SIMD instructions.
    * **SIMD Operations:** The function names and the expressions within the macros reveal the SIMD operations being implemented: `Add`, `Sub`, `Mul`, `Div`, `Min`, `Max`, `Abs`, `Neg`, `Sqrt`, comparisons (`Eq`, `Ne`, `Gt`, etc.), bitwise operations (`And`, `Or`, `Xor`), lane manipulation (`ExtractLane`, `ReplaceLane`), and memory load/store.
    * **Data Types:** Pay attention to the data types involved (F64x2, F32x4, I64x2, I32x4, I16x8, I8x16). These represent vectors of different primitive types.
    * **Lane Concept:**  The `LANE` macro and the access to `s.val[LANE(i, s)]` indicate that these operations work on individual "lanes" or elements within the SIMD vector.
    * **Purpose:** SIMD instructions allow parallel execution of the same operation on multiple data elements, significantly improving performance for data-parallel tasks.

4. **Look for Connections to JavaScript:**
    * **Atomic Operations and SharedArrayBuffer:**  Atomic operations in WebAssembly directly relate to JavaScript's `SharedArrayBuffer` and `Atomics` object. This connection is crucial.
    * **SIMD.js (Historical Context):** While not explicitly used in the provided code, it's important to know that SIMD operations in WebAssembly are related to the now-deprecated SIMD.js proposal. The concepts are similar. WebAssembly's SIMD is the modern approach.

5. **Consider Potential Errors:**
    * **Unaligned Access:** The code explicitly checks for alignment (`IsAligned`). This points to a common programming error where data is accessed at memory addresses that are not multiples of the data size.
    * **Out-of-Bounds Access:** The code also checks for memory bounds (`IsInBounds`). Accessing memory outside the allocated region is another frequent error.
    * **Race Conditions (Atomic Operations):**  While atomic operations *prevent* race conditions when used correctly, improper use or lack of atomicity in other parts of the code can still lead to issues.

6. **Infer Overall Function:** Based on the analysis, the primary purpose of this code is to implement the *interpreter* logic for specific WebAssembly instructions related to atomic operations and SIMD. It handles the runtime execution of these instructions within the V8 engine's interpreter.

7. **Structure the Explanation:**  Organize the findings into clear sections: core functionality, atomic operations, SIMD operations, JavaScript relationship, potential errors, and the overall function. Use examples (even simple ones) to illustrate the concepts.

8. **Address Specific Instructions:** The prompt asks about the `.tq` extension and the "part 6 of 15" aspect.
    * **`.tq`:** Recognize that `.tq` indicates Torque, V8's internal language for implementing built-in functions. Since the file is `.cc`, it's regular C++, not Torque.
    * **"Part 6 of 15":** Acknowledge this and infer that this file represents a specific functional area within the broader WebAssembly interpreter implementation.

By following these steps, we can systematically analyze the code snippet and generate a comprehensive explanation that addresses all the points raised in the prompt. The key is to break down the code into its constituent parts, understand the purpose of each part, and then synthesize the findings into a coherent overview.
好的，让我们来分析一下这段 V8 源代码 `v8/src/wasm/interpreter/wasm-interpreter.cc` 的功能。

**功能归纳：**

这段代码是 V8 引擎中 WebAssembly 解释器的一部分，主要负责实现 **原子操作 (Atomic Operations)** 和 **SIMD (Single Instruction, Multiple Data) 操作** 的执行逻辑。当 WebAssembly 代码在解释器模式下运行时，遇到这些特定的指令时，会调用这里定义的处理函数。

**具体功能分解：**

1. **原子操作 (Atomic Operations):**
   - 代码定义了一系列用于执行原子操作的指令处理函数，这些操作确保在多线程环境中对共享内存的访问是安全的，避免出现数据竞争。
   - 通过宏 `FOREACH_ATOMIC_..._OP` 和 `ATOMIC_..._OP` 定义了多种原子操作，涵盖了不同数据类型（`I32`, `I64` 及其 8U, 16U, 32U 版本）和操作类型（`Add`, `Sub`, `And`, `Or`, `Xor`, `Exchange`, `CompareExchange`, `Load`, `Store`）。
   - 这些函数会从栈中弹出操作数，读取内存偏移量和索引，计算有效内存地址，进行对齐和越界检查，然后使用 `std::atomic` 模板提供的原子操作函数（如 `std::atomic_fetch_add`, `std::atomic_exchange`, `std::atomic_compare_exchange_strong`）来执行相应的原子操作，并将结果推回栈中。

2. **SIMD 操作 (SIMD Operations):**
   - 代码定义了一系列用于执行 SIMD 操作的指令处理函数，SIMD 允许单个指令同时操作多个数据，从而提高并行计算性能。
   - 通过宏 `SPLAT_CASE`, `EXTRACT_LANE_CASE`, `BINOP_CASE`, `UNOP_CASE`, `CMPOP_CASE`, `REPLACE_LANE_CASE` 定义了多种 SIMD 操作，涵盖了不同的数据类型 (`F64x2`, `F32x4`, `I64x2`, `I32x4`, `I16x8`, `I8x16`) 和操作类型（算术运算、比较运算、位运算、lane 的提取和替换、加载和存储）。
   - 这些函数会从栈中弹出 SIMD 操作数（`Simd128` 类型），执行相应的 SIMD 操作，并将结果推回栈中。例如，`s2s_SimdF64x2Add` 函数会将两个 `float64x2` 向量相加。

**关于文件扩展名和 Torque：**

你提供的代码片段是 C++ 代码，因此 `v8/src/wasm/interpreter/wasm-interpreter.cc` 是一个 C++ 源文件。如果该文件以 `.tq` 结尾，那么它将是 V8 的 Torque 源代码。Torque 是一种用于定义 V8 内部运行时函数的领域特定语言，它能够生成 C++ 代码。

**与 JavaScript 的关系及示例：**

WebAssembly 的原子操作和 SIMD 操作可以直接在 JavaScript 中通过 `SharedArrayBuffer` 和 `Atomics` 对象，以及 `WebAssembly.SIMD` API（虽然该 API 已被移除，但其概念仍然存在于 WebAssembly 本身）来使用。

**原子操作 JavaScript 示例：**

```javascript
const sab = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * 1);
const view = new Int32Array(sab);

// 假设在不同的线程/worker 中
// 线程 1:
Atomics.add(view, 0, 5); // 原子地将 view[0] 的值加上 5

// 线程 2:
Atomics.load(view, 0); // 原子地读取 view[0] 的值
```

这段 C++ 代码中的原子操作指令处理函数，例如 `s2s_I32AtomicAdd`，就对应了 JavaScript 中 `Atomics.add` 这样的操作。当 WebAssembly 代码执行到相应的原子加法指令时，解释器会调用 `s2s_I32AtomicAdd` 来完成操作。

**SIMD 操作 JavaScript 示例（基于概念，因为 `WebAssembly.SIMD` 已移除）：**

虽然 `WebAssembly.SIMD` API 被移除了，但 WebAssembly 本身支持 SIMD 指令，并且可以通过一些库或者直接编写 WebAssembly 代码来利用。

在概念上，如果存在 `WebAssembly.SIMD`，可能会有类似的操作：

```javascript
// 假设 WebAssembly.SIMD 存在
const f64x2_type = WebAssembly.SIMD.float64x2;
const a = f64x2_type(1.0, 2.0);
const b = f64x2_type(3.0, 4.0);
const result = WebAssembly.SIMD.f64x2.add(a, b); // 向量加法
// result 将表示 [4.0, 6.0]
```

这段 C++ 代码中的 SIMD 指令处理函数，例如 `s2s_SimdF64x2Add`，就对应了这种概念上的 JavaScript SIMD 操作。

**代码逻辑推理与假设输入输出：**

以 `s2s_I32AtomicAdd` 为例：

**假设输入：**

- WebAssembly 代码中包含 `i32.atomic.add` 指令。
- 栈顶依次存储着：要增加的值 (例如 `5`)，内存地址的索引 (例如 `10`)，以及内存偏移量（例如 `0`）。
- `wasm_runtime` 指向当前 WebAssembly 实例的运行时环境，包括内存信息。
- 内存中地址 `10` 处存储的初始值为 `20`。

**执行过程：**

1. `s2s_I32AtomicAdd` 函数被调用。
2. 从栈中弹出值 `val = 5`，索引 `index = 10`。
3. 读取偏移量 `offset = 0`。
4. 计算有效地址 `effective_index = offset + index = 0 + 10 = 10`。
5. 进行对齐和越界检查（假设都通过）。
6. 从 `wasm_runtime` 获取内存起始地址 `memory_start`。
7. 计算目标内存地址 `address = memory_start + effective_index`。
8. 使用 `std::atomic_fetch_add` 原子地将地址 `address` 处的值加上 `val`。
9. 原子操作后的结果（原始值 `20`）被推回栈顶。
10. 执行 `NextOp()`，继续执行下一条指令。

**输出：**

- 栈顶增加了一个元素，其值为原子操作前的原始值 `20`。
- WebAssembly 实例的内存中，地址 `10` 处的值变为 `25`。

**用户常见的编程错误示例：**

1. **非对齐访问：**
   - 错误代码（WebAssembly 伪代码）：
     ```wasm
     i32.const 1  // 索引
     i32.atomic.load (offset=0) // 假设加载一个 i32，需要 4 字节对齐
     ```
   - 说明：如果内存起始地址不是 4 的倍数，那么访问索引为 1 的 `i32` 就会导致非对齐访问，这段 C++ 代码中的 `IsAligned` 检查会捕获这个错误并触发 trap。

2. **内存越界访问：**
   - 错误代码（WebAssembly 伪代码）：
     ```wasm
     i32.const 1000000 // 假设内存大小远小于此
     i32.atomic.store (offset=0)
     i32.const 5
     ```
   - 说明：如果提供的索引加上偏移量超出了 WebAssembly 实例的内存大小，`IsInBounds` 检查会失败，导致 `kTrapMemOutOfBounds` 错误。

3. **在单线程环境下过度使用原子操作：**
   - 虽然原子操作保证了多线程安全，但在单线程环境下不必要地使用原子操作可能会带来性能损耗，因为原子操作通常比普通操作更昂贵。

**作为第 6 部分的功能归纳：**

作为整个 WebAssembly 解释器实现的第 6 部分，这段代码专注于提供 **并发和并行处理** 的基础能力。它实现了 WebAssembly 规范中关于原子操作和 SIMD 操作的关键部分，使得 WebAssembly 能够安全高效地在多线程环境中运行，并利用 SIMD 指令进行数据并行计算，从而提升性能。这部分功能对于构建高性能的 WebAssembly 应用至关重要，特别是在需要处理大量数据或进行复杂计算的场景下。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
64_t, I64, std::atomic_fetch_xor) \
  V(I64AtomicXor8U, Uint8, uint8_t, I32, uint64_t, I64, std::atomic_fetch_xor) \
  V(I64AtomicXor16U, Uint16, uint16_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_xor)                                                     \
  V(I64AtomicXor32U, Uint32, uint32_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_xor)                                                     \
  V(I64AtomicExchange, Uint64, uint64_t, I64, uint64_t, I64,                   \
    std::atomic_exchange)                                                      \
  V(I64AtomicExchange8U, Uint8, uint8_t, I32, uint64_t, I64,                   \
    std::atomic_exchange)                                                      \
  V(I64AtomicExchange16U, Uint16, uint16_t, I32, uint64_t, I64,                \
    std::atomic_exchange)                                                      \
  V(I64AtomicExchange32U, Uint32, uint32_t, I32, uint64_t, I64,                \
    std::atomic_exchange)

#define ATOMIC_BINOP(name, Type, ctype, type, op_ctype, op_type, operation) \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype val = static_cast<ctype>(pop<op_ctype>(sp, code, wasm_runtime));  \
                                                                            \
    uint64_t offset = Read<uint64_t>(code);                                 \
    uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);                 \
    uint64_t effective_index = offset + index;                              \
    /* Check alignment. */                                                  \
    if (V8_UNLIKELY(!IsAligned(effective_index, sizeof(ctype)))) {          \
      TRAP(TrapReason::kTrapUnalignedAccess)                                \
    }                                                                       \
    /* Check bounds. */                                                     \
    if (V8_UNLIKELY(                                                        \
            effective_index < index ||                                      \
            !base::IsInBounds<uint64_t>(effective_index, sizeof(ctype),     \
                                        wasm_runtime->GetMemorySize()))) {  \
      TRAP(TrapReason::kTrapMemOutOfBounds)                                 \
    }                                                                       \
    static_assert(sizeof(std::atomic<ctype>) == sizeof(ctype),              \
                  "Size mismatch for types std::atomic<" #ctype             \
                  ">, and " #ctype);                                        \
                                                                            \
    uint8_t* memory_start = wasm_runtime->GetMemoryStart();                 \
    uint8_t* address = memory_start + effective_index;                      \
    op_ctype result = static_cast<op_ctype>(                                \
        operation(reinterpret_cast<std::atomic<ctype>*>(address), val));    \
    push<op_ctype>(sp, code, wasm_runtime, result);                         \
    NextOp();                                                               \
  }
FOREACH_ATOMIC_BINOP(ATOMIC_BINOP)
#undef ATOMIC_BINOP

#define FOREACH_ATOMIC_COMPARE_EXCHANGE_OP(V)                          \
  V(I32AtomicCompareExchange, Uint32, uint32_t, I32, uint32_t, I32)    \
  V(I32AtomicCompareExchange8U, Uint8, uint8_t, I32, uint32_t, I32)    \
  V(I32AtomicCompareExchange16U, Uint16, uint16_t, I32, uint32_t, I32) \
  V(I64AtomicCompareExchange, Uint64, uint64_t, I64, uint64_t, I64)    \
  V(I64AtomicCompareExchange8U, Uint8, uint8_t, I32, uint64_t, I64)    \
  V(I64AtomicCompareExchange16U, Uint16, uint16_t, I32, uint64_t, I64) \
  V(I64AtomicCompareExchange32U, Uint32, uint32_t, I32, uint64_t, I64)

#define ATOMIC_COMPARE_EXCHANGE_OP(name, Type, ctype, type, op_ctype, op_type) \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,       \
                                      WasmInterpreterRuntime* wasm_runtime,    \
                                      int64_t r0, double fp0) {                \
    ctype new_val = static_cast<ctype>(pop<op_ctype>(sp, code, wasm_runtime)); \
    ctype old_val = static_cast<ctype>(pop<op_ctype>(sp, code, wasm_runtime)); \
                                                                               \
    uint64_t offset = Read<uint64_t>(code);                                    \
    uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);                    \
    uint64_t effective_index = offset + index;                                 \
    /* Check alignment. */                                                     \
    if (V8_UNLIKELY(!IsAligned(effective_index, sizeof(ctype)))) {             \
      TRAP(TrapReason::kTrapUnalignedAccess)                                   \
    }                                                                          \
    /* Check bounds. */                                                        \
    if (V8_UNLIKELY(                                                           \
            effective_index < index ||                                         \
            !base::IsInBounds<uint64_t>(effective_index, sizeof(ctype),        \
                                        wasm_runtime->GetMemorySize()))) {     \
      TRAP(TrapReason::kTrapMemOutOfBounds)                                    \
    }                                                                          \
    static_assert(sizeof(std::atomic<ctype>) == sizeof(ctype),                 \
                  "Size mismatch for types std::atomic<" #ctype                \
                  ">, and " #ctype);                                           \
                                                                               \
    uint8_t* memory_start = wasm_runtime->GetMemoryStart();                    \
    uint8_t* address = memory_start + effective_index;                         \
                                                                               \
    std::atomic_compare_exchange_strong(                                       \
        reinterpret_cast<std::atomic<ctype>*>(address), &old_val, new_val);    \
    push<op_ctype>(sp, code, wasm_runtime, static_cast<op_ctype>(old_val));    \
    NextOp();                                                                  \
  }
FOREACH_ATOMIC_COMPARE_EXCHANGE_OP(ATOMIC_COMPARE_EXCHANGE_OP)
#undef ATOMIC_COMPARE_EXCHANGE_OP

#define FOREACH_ATOMIC_LOAD_OP(V)                           \
  V(I32AtomicLoad, Uint32, uint32_t, I32, uint32_t, I32)    \
  V(I32AtomicLoad8U, Uint8, uint8_t, I32, uint32_t, I32)    \
  V(I32AtomicLoad16U, Uint16, uint16_t, I32, uint32_t, I32) \
  V(I64AtomicLoad, Uint64, uint64_t, I64, uint64_t, I64)    \
  V(I64AtomicLoad8U, Uint8, uint8_t, I32, uint64_t, I64)    \
  V(I64AtomicLoad16U, Uint16, uint16_t, I32, uint64_t, I64) \
  V(I64AtomicLoad32U, Uint32, uint32_t, I32, uint64_t, I64)

#define ATOMIC_LOAD_OP(name, Type, ctype, type, op_ctype, op_type)          \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    uint64_t offset = Read<uint64_t>(code);                                 \
    uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);                 \
    uint64_t effective_index = offset + index;                              \
    /* Check alignment. */                                                  \
    if (V8_UNLIKELY(!IsAligned(effective_index, sizeof(ctype)))) {          \
      TRAP(TrapReason::kTrapUnalignedAccess)                                \
    }                                                                       \
    /* Check bounds. */                                                     \
    if (V8_UNLIKELY(                                                        \
            effective_index < index ||                                      \
            !base::IsInBounds<uint64_t>(effective_index, sizeof(ctype),     \
                                        wasm_runtime->GetMemorySize()))) {  \
      TRAP(TrapReason::kTrapMemOutOfBounds)                                 \
    }                                                                       \
    static_assert(sizeof(std::atomic<ctype>) == sizeof(ctype),              \
                  "Size mismatch for types std::atomic<" #ctype             \
                  ">, and " #ctype);                                        \
                                                                            \
    uint8_t* memory_start = wasm_runtime->GetMemoryStart();                 \
    uint8_t* address = memory_start + effective_index;                      \
                                                                            \
    ctype val =                                                             \
        std::atomic_load(reinterpret_cast<std::atomic<ctype>*>(address));   \
    push<op_ctype>(sp, code, wasm_runtime, static_cast<op_ctype>(val));     \
    NextOp();                                                               \
  }
FOREACH_ATOMIC_LOAD_OP(ATOMIC_LOAD_OP)
#undef ATOMIC_LOAD_OP

#define FOREACH_ATOMIC_STORE_OP(V)                           \
  V(I32AtomicStore, Uint32, uint32_t, I32, uint32_t, I32)    \
  V(I32AtomicStore8U, Uint8, uint8_t, I32, uint32_t, I32)    \
  V(I32AtomicStore16U, Uint16, uint16_t, I32, uint32_t, I32) \
  V(I64AtomicStore, Uint64, uint64_t, I64, uint64_t, I64)    \
  V(I64AtomicStore8U, Uint8, uint8_t, I32, uint64_t, I64)    \
  V(I64AtomicStore16U, Uint16, uint16_t, I32, uint64_t, I64) \
  V(I64AtomicStore32U, Uint32, uint32_t, I32, uint64_t, I64)

#define ATOMIC_STORE_OP(name, Type, ctype, type, op_ctype, op_type)         \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype val = static_cast<ctype>(pop<op_ctype>(sp, code, wasm_runtime));  \
                                                                            \
    uint64_t offset = Read<uint64_t>(code);                                 \
    uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);                 \
    uint64_t effective_index = offset + index;                              \
    /* Check alignment. */                                                  \
    if (V8_UNLIKELY(!IsAligned(effective_index, sizeof(ctype)))) {          \
      TRAP(TrapReason::kTrapUnalignedAccess)                                \
    }                                                                       \
    /* Check bounds. */                                                     \
    if (V8_UNLIKELY(                                                        \
            effective_index < index ||                                      \
            !base::IsInBounds<uint64_t>(effective_index, sizeof(ctype),     \
                                        wasm_runtime->GetMemorySize()))) {  \
      TRAP(TrapReason::kTrapMemOutOfBounds)                                 \
    }                                                                       \
    static_assert(sizeof(std::atomic<ctype>) == sizeof(ctype),              \
                  "Size mismatch for types std::atomic<" #ctype             \
                  ">, and " #ctype);                                        \
                                                                            \
    uint8_t* memory_start = wasm_runtime->GetMemoryStart();                 \
    uint8_t* address = memory_start + effective_index;                      \
                                                                            \
    std::atomic_store(reinterpret_cast<std::atomic<ctype>*>(address), val); \
    NextOp();                                                               \
  }
FOREACH_ATOMIC_STORE_OP(ATOMIC_STORE_OP)
#undef ATOMIC_STORE_OP

////////////////////////////////////////////////////////////////////////////////
// SIMD instructions.

#if V8_TARGET_BIG_ENDIAN
#define LANE(i, type) ((sizeof(type.val) / sizeof(type.val[0])) - (i)-1)
#else
#define LANE(i, type) (i)
#endif

#define SPLAT_CASE(format, stype, valType, op_type, num)                       \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##format##Splat(                            \
      const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime, \
      int64_t r0, double fp0) {                                                \
    valType v = pop<valType>(sp, code, wasm_runtime);                          \
    stype s;                                                                   \
    for (int i = 0; i < num; i++) s.val[i] = v;                                \
    push<Simd128>(sp, code, wasm_runtime, Simd128(s));                         \
    NextOp();                                                                  \
  }
SPLAT_CASE(F64x2, float64x2, double, F64, 2)
SPLAT_CASE(F32x4, float32x4, float, F32, 4)
SPLAT_CASE(I64x2, int64x2, int64_t, I64, 2)
SPLAT_CASE(I32x4, int32x4, int32_t, I32, 4)
SPLAT_CASE(I16x8, int16x8, int32_t, I32, 8)
SPLAT_CASE(I8x16, int8x16, int32_t, I32, 16)
#undef SPLAT_CASE

#define EXTRACT_LANE_CASE(format, stype, op_type, name)                        \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##format##ExtractLane(                      \
      const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime, \
      int64_t r0, double fp0) {                                                \
    uint16_t lane = ReadI16(code);                                             \
    DCHECK_LT(lane, 4);                                                        \
    Simd128 v = pop<Simd128>(sp, code, wasm_runtime);                          \
    stype s = v.to_##name();                                                   \
    push(sp, code, wasm_runtime, s.val[LANE(lane, s)]);                        \
    NextOp();                                                                  \
  }
EXTRACT_LANE_CASE(F64x2, float64x2, F64, f64x2)
EXTRACT_LANE_CASE(F32x4, float32x4, F32, f32x4)
EXTRACT_LANE_CASE(I64x2, int64x2, I64, i64x2)
EXTRACT_LANE_CASE(I32x4, int32x4, I32, i32x4)
#undef EXTRACT_LANE_CASE

// Unsigned extracts require a bit more care. The underlying array in Simd128 is
// signed (see wasm-value.h), so when casted to uint32_t it will be signed
// extended, e.g. int8_t -> int32_t -> uint32_t. So for unsigned extracts, we
// will cast it int8_t -> uint8_t -> uint32_t. We add the DCHECK to ensure that
// if the array type changes, we know to change this function.
#define EXTRACT_LANE_EXTEND_CASE(format, stype, name, sign, extended_type)     \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##format##ExtractLane##sign(                \
      const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime, \
      int64_t r0, double fp0) {                                                \
    uint16_t lane = ReadI16(code);                                             \
    DCHECK_LT(lane, 16);                                                       \
    Simd128 s = pop<Simd128>(sp, code, wasm_runtime);                          \
    stype ss = s.to_##name();                                                  \
    auto res = ss.val[LANE(lane, ss)];                                         \
    DCHECK(std::is_signed<decltype(res)>::value);                              \
    if (std::is_unsigned<extended_type>::value) {                              \
      using unsigned_type = std::make_unsigned<decltype(res)>::type;           \
      push(sp, code, wasm_runtime,                                             \
           static_cast<extended_type>(static_cast<unsigned_type>(res)));       \
    } else {                                                                   \
      push(sp, code, wasm_runtime, static_cast<extended_type>(res));           \
    }                                                                          \
    NextOp();                                                                  \
  }
EXTRACT_LANE_EXTEND_CASE(I16x8, int16x8, i16x8, S, int32_t)
EXTRACT_LANE_EXTEND_CASE(I16x8, int16x8, i16x8, U, uint32_t)
EXTRACT_LANE_EXTEND_CASE(I8x16, int8x16, i8x16, S, int32_t)
EXTRACT_LANE_EXTEND_CASE(I8x16, int8x16, i8x16, U, uint32_t)
#undef EXTRACT_LANE_EXTEND_CASE

#define BINOP_CASE(op, name, stype, count, expr)                              \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype s2 = pop<Simd128>(sp, code, wasm_runtime).to_##name();              \
    stype s1 = pop<Simd128>(sp, code, wasm_runtime).to_##name();              \
    stype res;                                                                \
    for (size_t i = 0; i < count; ++i) {                                      \
      auto a = s1.val[LANE(i, s1)];                                           \
      auto b = s2.val[LANE(i, s2)];                                           \
      res.val[LANE(i, res)] = expr;                                           \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
BINOP_CASE(F64x2Add, f64x2, float64x2, 2, a + b)
BINOP_CASE(F64x2Sub, f64x2, float64x2, 2, a - b)
BINOP_CASE(F64x2Mul, f64x2, float64x2, 2, a* b)
BINOP_CASE(F64x2Div, f64x2, float64x2, 2, base::Divide(a, b))
BINOP_CASE(F64x2Min, f64x2, float64x2, 2, JSMin(a, b))
BINOP_CASE(F64x2Max, f64x2, float64x2, 2, JSMax(a, b))
BINOP_CASE(F64x2Pmin, f64x2, float64x2, 2, std::min(a, b))
BINOP_CASE(F64x2Pmax, f64x2, float64x2, 2, std::max(a, b))
BINOP_CASE(F32x4RelaxedMin, f32x4, float32x4, 4, std::min(a, b))
BINOP_CASE(F32x4RelaxedMax, f32x4, float32x4, 4, std::max(a, b))
BINOP_CASE(F64x2RelaxedMin, f64x2, float64x2, 2, std::min(a, b))
BINOP_CASE(F64x2RelaxedMax, f64x2, float64x2, 2, std::max(a, b))
BINOP_CASE(F32x4Add, f32x4, float32x4, 4, a + b)
BINOP_CASE(F32x4Sub, f32x4, float32x4, 4, a - b)
BINOP_CASE(F32x4Mul, f32x4, float32x4, 4, a* b)
BINOP_CASE(F32x4Div, f32x4, float32x4, 4, a / b)
BINOP_CASE(F32x4Min, f32x4, float32x4, 4, JSMin(a, b))
BINOP_CASE(F32x4Max, f32x4, float32x4, 4, JSMax(a, b))
BINOP_CASE(F32x4Pmin, f32x4, float32x4, 4, std::min(a, b))
BINOP_CASE(F32x4Pmax, f32x4, float32x4, 4, std::max(a, b))
BINOP_CASE(I64x2Add, i64x2, int64x2, 2, base::AddWithWraparound(a, b))
BINOP_CASE(I64x2Sub, i64x2, int64x2, 2, base::SubWithWraparound(a, b))
BINOP_CASE(I64x2Mul, i64x2, int64x2, 2, base::MulWithWraparound(a, b))
BINOP_CASE(I32x4Add, i32x4, int32x4, 4, base::AddWithWraparound(a, b))
BINOP_CASE(I32x4Sub, i32x4, int32x4, 4, base::SubWithWraparound(a, b))
BINOP_CASE(I32x4Mul, i32x4, int32x4, 4, base::MulWithWraparound(a, b))
BINOP_CASE(I32x4MinS, i32x4, int32x4, 4, a < b ? a : b)
BINOP_CASE(I32x4MinU, i32x4, int32x4, 4,
           static_cast<uint32_t>(a) < static_cast<uint32_t>(b) ? a : b)
BINOP_CASE(I32x4MaxS, i32x4, int32x4, 4, a > b ? a : b)
BINOP_CASE(I32x4MaxU, i32x4, int32x4, 4,
           static_cast<uint32_t>(a) > static_cast<uint32_t>(b) ? a : b)
BINOP_CASE(S128And, i32x4, int32x4, 4, a& b)
BINOP_CASE(S128Or, i32x4, int32x4, 4, a | b)
BINOP_CASE(S128Xor, i32x4, int32x4, 4, a ^ b)
BINOP_CASE(S128AndNot, i32x4, int32x4, 4, a & ~b)
BINOP_CASE(I16x8Add, i16x8, int16x8, 8, base::AddWithWraparound(a, b))
BINOP_CASE(I16x8Sub, i16x8, int16x8, 8, base::SubWithWraparound(a, b))
BINOP_CASE(I16x8Mul, i16x8, int16x8, 8, base::MulWithWraparound(a, b))
BINOP_CASE(I16x8MinS, i16x8, int16x8, 8, a < b ? a : b)
BINOP_CASE(I16x8MinU, i16x8, int16x8, 8,
           static_cast<uint16_t>(a) < static_cast<uint16_t>(b) ? a : b)
BINOP_CASE(I16x8MaxS, i16x8, int16x8, 8, a > b ? a : b)
BINOP_CASE(I16x8MaxU, i16x8, int16x8, 8,
           static_cast<uint16_t>(a) > static_cast<uint16_t>(b) ? a : b)
BINOP_CASE(I16x8AddSatS, i16x8, int16x8, 8, SaturateAdd<int16_t>(a, b))
BINOP_CASE(I16x8AddSatU, i16x8, int16x8, 8, SaturateAdd<uint16_t>(a, b))
BINOP_CASE(I16x8SubSatS, i16x8, int16x8, 8, SaturateSub<int16_t>(a, b))
BINOP_CASE(I16x8SubSatU, i16x8, int16x8, 8, SaturateSub<uint16_t>(a, b))
BINOP_CASE(I16x8RoundingAverageU, i16x8, int16x8, 8,
           RoundingAverageUnsigned<uint16_t>(a, b))
BINOP_CASE(I16x8Q15MulRSatS, i16x8, int16x8, 8,
           SaturateRoundingQMul<int16_t>(a, b))
BINOP_CASE(I16x8RelaxedQ15MulRS, i16x8, int16x8, 8,
           SaturateRoundingQMul<int16_t>(a, b))
BINOP_CASE(I8x16Add, i8x16, int8x16, 16, base::AddWithWraparound(a, b))
BINOP_CASE(I8x16Sub, i8x16, int8x16, 16, base::SubWithWraparound(a, b))
BINOP_CASE(I8x16MinS, i8x16, int8x16, 16, a < b ? a : b)
BINOP_CASE(I8x16MinU, i8x16, int8x16, 16,
           static_cast<uint8_t>(a) < static_cast<uint8_t>(b) ? a : b)
BINOP_CASE(I8x16MaxS, i8x16, int8x16, 16, a > b ? a : b)
BINOP_CASE(I8x16MaxU, i8x16, int8x16, 16,
           static_cast<uint8_t>(a) > static_cast<uint8_t>(b) ? a : b)
BINOP_CASE(I8x16AddSatS, i8x16, int8x16, 16, SaturateAdd<int8_t>(a, b))
BINOP_CASE(I8x16AddSatU, i8x16, int8x16, 16, SaturateAdd<uint8_t>(a, b))
BINOP_CASE(I8x16SubSatS, i8x16, int8x16, 16, SaturateSub<int8_t>(a, b))
BINOP_CASE(I8x16SubSatU, i8x16, int8x16, 16, SaturateSub<uint8_t>(a, b))
BINOP_CASE(I8x16RoundingAverageU, i8x16, int8x16, 16,
           RoundingAverageUnsigned<uint8_t>(a, b))
#undef BINOP_CASE

#define UNOP_CASE(op, name, stype, count, expr)                               \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype s = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    stype res;                                                                \
    for (size_t i = 0; i < count; ++i) {                                      \
      auto a = s.val[LANE(i, s)];                                             \
      res.val[LANE(i, res)] = expr;                                           \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }
UNOP_CASE(F64x2Abs, f64x2, float64x2, 2, std::abs(a))
UNOP_CASE(F64x2Neg, f64x2, float64x2, 2, -a)
UNOP_CASE(F64x2Sqrt, f64x2, float64x2, 2, std::sqrt(a))
UNOP_CASE(F64x2Ceil, f64x2, float64x2, 2, ceil(a))
UNOP_CASE(F64x2Floor, f64x2, float64x2, 2, floor(a))
UNOP_CASE(F64x2Trunc, f64x2, float64x2, 2, trunc(a))
UNOP_CASE(F64x2NearestInt, f64x2, float64x2, 2, nearbyint(a))
UNOP_CASE(F32x4Abs, f32x4, float32x4, 4, std::abs(a))
UNOP_CASE(F32x4Neg, f32x4, float32x4, 4, -a)
UNOP_CASE(F32x4Sqrt, f32x4, float32x4, 4, std::sqrt(a))
UNOP_CASE(F32x4Ceil, f32x4, float32x4, 4, ceilf(a))
UNOP_CASE(F32x4Floor, f32x4, float32x4, 4, floorf(a))
UNOP_CASE(F32x4Trunc, f32x4, float32x4, 4, truncf(a))
UNOP_CASE(F32x4NearestInt, f32x4, float32x4, 4, nearbyintf(a))
UNOP_CASE(I64x2Neg, i64x2, int64x2, 2, base::NegateWithWraparound(a))
UNOP_CASE(I32x4Neg, i32x4, int32x4, 4, base::NegateWithWraparound(a))
// Use llabs which will work correctly on both 64-bit and 32-bit.
UNOP_CASE(I64x2Abs, i64x2, int64x2, 2, std::llabs(a))
UNOP_CASE(I32x4Abs, i32x4, int32x4, 4, std::abs(a))
UNOP_CASE(S128Not, i32x4, int32x4, 4, ~a)
UNOP_CASE(I16x8Neg, i16x8, int16x8, 8, base::NegateWithWraparound(a))
UNOP_CASE(I16x8Abs, i16x8, int16x8, 8, std::abs(a))
UNOP_CASE(I8x16Neg, i8x16, int8x16, 16, base::NegateWithWraparound(a))
UNOP_CASE(I8x16Abs, i8x16, int8x16, 16, std::abs(a))
UNOP_CASE(I8x16Popcnt, i8x16, int8x16, 16,
          base::bits::CountPopulation<uint8_t>(a))
#undef UNOP_CASE

#define BITMASK_CASE(op, name, stype, count)                                  \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype s = pop<Simd128>(sp, code, wasm_runtime).to_##name();               \
    int32_t res = 0;                                                          \
    for (size_t i = 0; i < count; ++i) {                                      \
      bool sign = std::signbit(static_cast<double>(s.val[LANE(i, s)]));       \
      res |= (sign << i);                                                     \
    }                                                                         \
    push<int32_t>(sp, code, wasm_runtime, res);                               \
    NextOp();                                                                 \
  }
BITMASK_CASE(I8x16BitMask, i8x16, int8x16, 16)
BITMASK_CASE(I16x8BitMask, i16x8, int16x8, 8)
BITMASK_CASE(I32x4BitMask, i32x4, int32x4, 4)
BITMASK_CASE(I64x2BitMask, i64x2, int64x2, 2)
#undef BITMASK_CASE

#define CMPOP_CASE(op, name, stype, out_stype, count, expr)                   \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##op(const uint8_t* code, uint32_t* sp,    \
                                        WasmInterpreterRuntime* wasm_runtime, \
                                        int64_t r0, double fp0) {             \
    stype s2 = pop<Simd128>(sp, code, wasm_runtime).to_##name();              \
    stype s1 = pop<Simd128>(sp, code, wasm_runtime).to_##name();              \
    out_stype res;                                                            \
    for (size_t i = 0; i < count; ++i) {                                      \
      auto a = s1.val[LANE(i, s1)];                                           \
      auto b = s2.val[LANE(i, s2)];                                           \
      auto result = expr;                                                     \
      res.val[LANE(i, res)] = result ? -1 : 0;                                \
    }                                                                         \
    push<Simd128>(sp, code, wasm_runtime, Simd128(res));                      \
    NextOp();                                                                 \
  }

CMPOP_CASE(F64x2Eq, f64x2, float64x2, int64x2, 2, a == b)
CMPOP_CASE(F64x2Ne, f64x2, float64x2, int64x2, 2, a != b)
CMPOP_CASE(F64x2Gt, f64x2, float64x2, int64x2, 2, a > b)
CMPOP_CASE(F64x2Ge, f64x2, float64x2, int64x2, 2, a >= b)
CMPOP_CASE(F64x2Lt, f64x2, float64x2, int64x2, 2, a < b)
CMPOP_CASE(F64x2Le, f64x2, float64x2, int64x2, 2, a <= b)
CMPOP_CASE(F32x4Eq, f32x4, float32x4, int32x4, 4, a == b)
CMPOP_CASE(F32x4Ne, f32x4, float32x4, int32x4, 4, a != b)
CMPOP_CASE(F32x4Gt, f32x4, float32x4, int32x4, 4, a > b)
CMPOP_CASE(F32x4Ge, f32x4, float32x4, int32x4, 4, a >= b)
CMPOP_CASE(F32x4Lt, f32x4, float32x4, int32x4, 4, a < b)
CMPOP_CASE(F32x4Le, f32x4, float32x4, int32x4, 4, a <= b)
CMPOP_CASE(I64x2Eq, i64x2, int64x2, int64x2, 2, a == b)
CMPOP_CASE(I64x2Ne, i64x2, int64x2, int64x2, 2, a != b)
CMPOP_CASE(I64x2LtS, i64x2, int64x2, int64x2, 2, a < b)
CMPOP_CASE(I64x2GtS, i64x2, int64x2, int64x2, 2, a > b)
CMPOP_CASE(I64x2LeS, i64x2, int64x2, int64x2, 2, a <= b)
CMPOP_CASE(I64x2GeS, i64x2, int64x2, int64x2, 2, a >= b)
CMPOP_CASE(I32x4Eq, i32x4, int32x4, int32x4, 4, a == b)
CMPOP_CASE(I32x4Ne, i32x4, int32x4, int32x4, 4, a != b)
CMPOP_CASE(I32x4GtS, i32x4, int32x4, int32x4, 4, a > b)
CMPOP_CASE(I32x4GeS, i32x4, int32x4, int32x4, 4, a >= b)
CMPOP_CASE(I32x4LtS, i32x4, int32x4, int32x4, 4, a < b)
CMPOP_CASE(I32x4LeS, i32x4, int32x4, int32x4, 4, a <= b)
CMPOP_CASE(I32x4GtU, i32x4, int32x4, int32x4, 4,
           static_cast<uint32_t>(a) > static_cast<uint32_t>(b))
CMPOP_CASE(I32x4GeU, i32x4, int32x4, int32x4, 4,
           static_cast<uint32_t>(a) >= static_cast<uint32_t>(b))
CMPOP_CASE(I32x4LtU, i32x4, int32x4, int32x4, 4,
           static_cast<uint32_t>(a) < static_cast<uint32_t>(b))
CMPOP_CASE(I32x4LeU, i32x4, int32x4, int32x4, 4,
           static_cast<uint32_t>(a) <= static_cast<uint32_t>(b))
CMPOP_CASE(I16x8Eq, i16x8, int16x8, int16x8, 8, a == b)
CMPOP_CASE(I16x8Ne, i16x8, int16x8, int16x8, 8, a != b)
CMPOP_CASE(I16x8GtS, i16x8, int16x8, int16x8, 8, a > b)
CMPOP_CASE(I16x8GeS, i16x8, int16x8, int16x8, 8, a >= b)
CMPOP_CASE(I16x8LtS, i16x8, int16x8, int16x8, 8, a < b)
CMPOP_CASE(I16x8LeS, i16x8, int16x8, int16x8, 8, a <= b)
CMPOP_CASE(I16x8GtU, i16x8, int16x8, int16x8, 8,
           static_cast<uint16_t>(a) > static_cast<uint16_t>(b))
CMPOP_CASE(I16x8GeU, i16x8, int16x8, int16x8, 8,
           static_cast<uint16_t>(a) >= static_cast<uint16_t>(b))
CMPOP_CASE(I16x8LtU, i16x8, int16x8, int16x8, 8,
           static_cast<uint16_t>(a) < static_cast<uint16_t>(b))
CMPOP_CASE(I16x8LeU, i16x8, int16x8, int16x8, 8,
           static_cast<uint16_t>(a) <= static_cast<uint16_t>(b))
CMPOP_CASE(I8x16Eq, i8x16, int8x16, int8x16, 16, a == b)
CMPOP_CASE(I8x16Ne, i8x16, int8x16, int8x16, 16, a != b)
CMPOP_CASE(I8x16GtS, i8x16, int8x16, int8x16, 16, a > b)
CMPOP_CASE(I8x16GeS, i8x16, int8x16, int8x16, 16, a >= b)
CMPOP_CASE(I8x16LtS, i8x16, int8x16, int8x16, 16, a < b)
CMPOP_CASE(I8x16LeS, i8x16, int8x16, int8x16, 16, a <= b)
CMPOP_CASE(I8x16GtU, i8x16, int8x16, int8x16, 16,
           static_cast<uint8_t>(a) > static_cast<uint8_t>(b))
CMPOP_CASE(I8x16GeU, i8x16, int8x16, int8x16, 16,
           static_cast<uint8_t>(a) >= static_cast<uint8_t>(b))
CMPOP_CASE(I8x16LtU, i8x16, int8x16, int8x16, 16,
           static_cast<uint8_t>(a) < static_cast<uint8_t>(b))
CMPOP_CASE(I8x16LeU, i8x16, int8x16, int8x16, 16,
           static_cast<uint8_t>(a) <= static_cast<uint8_t>(b))
#undef CMPOP_CASE

#define REPLACE_LANE_CASE(format, name, stype, ctype, op_type)                 \
  INSTRUCTION_HANDLER_FUNC s2s_Simd##format##ReplaceLane(                      \
      const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime, \
      int64_t r0, double fp0) {                                                \
    uint16_t lane = ReadI16(code);                                             \
    DCHECK_LT(lane, 16);                                                       \
    ctype new_val = pop<ctype>(sp, code, wasm_runtime);                        \
    Simd128 simd_val = pop<Simd128>(sp, code, wasm_runtime);                   \
    stype s = simd_val.to_##name();                                            \
    s.val[LANE(lane, s)] = new_val;                                            \
    push<Simd128>(sp, code, wasm_runtime, Simd128(s));                         \
    NextOp();                                                                  \
  }
REPLACE_LANE_CASE(F64x2, f64x2, float64x2, double, F64)
REPLACE_LANE_CASE(F32x4, f32x4, float32x4, float, F32)
REPLACE_LANE_CASE(I64x2, i64x2, int64x2, int64_t, I64)
REPLACE_LANE_CASE(I32x4, i32x4, int32x4, int32_t, I32)
REPLACE_LANE_CASE(I16x8, i16x8, int16x8, int32_t, I32)
REPLACE_LANE_CASE(I8x16, i8x16, int8x16, int32_t, I32)
#undef REPLACE_LANE_CASE

INSTRUCTION_HANDLER_FUNC s2s_SimdS128LoadMem(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;

  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(Simd128),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  uint8_t* address = memory_start + effective_index;
  Simd128 s =
      base::ReadUnalignedValue<Simd128>(reinterpret_cast<Address>(address));
  push<Simd128>(sp, code, wasm_runtime, Simd128(s));

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_SimdS128StoreMem(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  Simd128 val = pop<Simd128>(sp, code, wasm_runtime);

  uint8_t* memory_start = wasm_runtime->GetMemoryStart();
  uint64_t offset = Read<uint64_t>(code);

  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t
```