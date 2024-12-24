Response: The user wants a summary of the functionality of the provided C++ code snippet, which is part 3 of 8 of the `wasm-interpreter.cc` file in the V8 JavaScript engine. I need to analyze the code and identify the operations it performs. The code consists of several C++ functions named `s2s_...`, `r2s_...`, and `INSTRUCTION_HANDLER_FUNC`, which seem to be handling different WebAssembly instructions within the interpreter.

Key observations:

1. **Stack Pointer Manipulation:** The functions frequently use a `uint32_t* sp` which suggests they are working with a stack. Operations like `pop` and `push` confirm this.
2. **Memory Access:**  The code interacts with memory using `wasm_runtime->GetMemoryStart()`, `base::ReadUnalignedValue`, and `base::WriteUnalignedValue`. Bounds checking is also present.
3. **Wasm Types:**  References to `WasmRef` and `Simd128` indicate the code is dealing with WebAssembly specific data types.
4. **Atomic Operations:**  A section of the code deals with atomic operations like `AtomicNotify`, `I32AtomicWait`, `std::atomic_fetch_add`, etc.
5. **SIMD Operations:**  Another section handles SIMD (Single Instruction, Multiple Data) operations on types like `float64x2`, `float32x4`, `int32x4`, etc.
6. **Instruction Dispatch:** The `NextOp()` call at the end of most functions suggests this code is part of an interpreter loop that processes instructions sequentially.
7. **Tracing:** The `#ifdef V8_ENABLE_DRUMBRAKE_TRACING` blocks suggest the code has debugging or tracing capabilities.

Based on these observations, the primary function of this code snippet is to implement the execution logic for a subset of WebAssembly instructions within the V8 interpreter. It handles data manipulation, memory access, atomic operations, and SIMD operations.

Regarding the relationship with JavaScript, this code is part of the underlying implementation that enables JavaScript to execute WebAssembly code. When JavaScript calls a WebAssembly function, the V8 engine uses this interpreter (or a more optimized compilation path) to execute the corresponding WebAssembly instructions.

To illustrate with a JavaScript example, let's consider a simple WebAssembly module that adds two numbers and how this C++ code might be involved:

```javascript
// Example JavaScript code
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM header
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // Function signature (i32, i32) -> i32
  0x03, 0x02, 0x01, 0x00, // Import section (none)
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b // Code section (local.get 0, local.get 1, i32.add, end)
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const add = wasmInstance.exports.add;
const result = add(5, 10); // Calling the WebAssembly function
console.log(result); // Output: 15
```

When `add(5, 10)` is called in JavaScript, the V8 engine will:

1. Identify that it needs to execute WebAssembly code.
2. Locate the compiled or interpreted code for the `add` function.
3. If the interpreter is used, it will step through the WebAssembly instructions (`local.get`, `i32.add`).
4. **The C++ code in this snippet is responsible for implementing the behavior of these instructions.** For example, it would have functions to handle `local.get` (fetching values from the stack or local variables) and `i32.add` (performing the integer addition).

The `COPYSLOT` family of functions in the provided code could be used to move data between stack slots, which might be relevant for handling local variables. The atomic and SIMD instructions demonstrate the interpreter's ability to handle more complex WebAssembly features that might be exposed through JavaScript APIs.
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的C++源代码文件的**第3部分**，主要负责实现 **WebAssembly 解释器中与数据操作相关的指令** 的执行逻辑。

具体来说，这部分代码包含了处理以下操作的指令处理器函数：

**1. 数据复制 (Slot Copying):**

*   **`s2s_CopySlot64x2`**:  将栈中两个连续的 64 位值复制到另一个栈位置。
*   **`s2s_CopySlot32`**: 将栈中的一个 32 位值复制到另一个栈位置。
*   **`s2s_CopySlot32x2`**: 将栈中两个连续的 32 位值复制到另一个栈位置。
*   **`s2s_CopySlot64`**: 将栈中的一个 64 位值复制到另一个栈位置。
*   **`s2s_CopySlot128`**: 将栈中的一个 128 位值 (SIMD 类型) 复制到另一个栈位置。
*   **`s2s_CopySlotRef`**: 复制一个 WebAssembly 引用类型的值。
*   **`s2s_PreserveCopySlot32`**: 将一个 32 位值复制到目标位置，并将目标位置的原值保存到另一个位置。
*   **`s2s_PreserveCopySlot64`**: 将一个 64 位值复制到目标位置，并将目标位置的原值保存到另一个位置。
*   **`s2s_PreserveCopySlot128`**: 将一个 128 位值复制到目标位置，并将目标位置的原值保存到另一个位置。
*   **`s2s_PreserveCopySlotRef`**: 将一个引用类型值复制到目标位置，并将目标位置的原值保存到另一个位置。

**2. 寄存器到栈的复制:**

*   **`r2s_CopyR0ToSlot32`**: 将通用寄存器 `r0` 中的 32 位值复制到栈位置。
*   **`r2s_CopyR0ToSlot64`**: 将通用寄存器 `r0` 中的 64 位值复制到栈位置。
*   **`r2s_CopyFp0ToSlot32`**: 将浮点寄存器 `fp0` 中的 32 位浮点值复制到栈位置。
*   **`r2s_CopyFp0ToSlot64`**: 将浮点寄存器 `fp0` 中的 64 位浮点值复制到栈位置。
*   **`r2s_PreserveCopyR0ToSlot32`**: 将通用寄存器 `r0` 中的 32 位值复制到栈位置，并将栈位置的原值保存到另一个位置。
*   **`r2s_PreserveCopyR0ToSlot64`**: 将通用寄存器 `r0` 中的 64 位值复制到栈位置，并将栈位置的原值保存到另一个位置。
*   **`r2s_PreserveCopyFp0ToSlot32`**: 将浮点寄存器 `fp0` 中的 32 位浮点值复制到栈位置，并将栈位置的原值保存到另一个位置。
*   **`r2s_PreserveCopyFp0ToSlot64`**: 将浮点寄存器 `fp0` 中的 64 位浮点值复制到栈位置，并将栈位置的原值保存到另一个位置。

**3. 引用类型操作:**

*   **`s2s_RefNull`**: 将一个空引用值推入栈。
*   **`s2s_RefIsNull`**: 检查栈顶的引用是否为空，并将结果 (0 或 1) 推入栈。
*   **`s2s_RefFunc`**: 将一个函数引用推入栈。
*   **`s2s_RefEq`**: 比较栈顶的两个引用是否相等，并将结果 (0 或 1) 推入栈。

**4. 内存操作:**

*   **`s2s_MemoryInit`**: 从数据段初始化内存。
*   **`s2s_DataDrop`**:  释放一个数据段。
*   **`s2s_MemoryCopy`**: 在内存中复制数据。
*   **`s2s_MemoryFill`**: 用指定的值填充内存。

**5. 表操作:**

*   **`s2s_TableGet`**: 从表中获取一个元素。
*   **`s2s_TableSet`**: 在表中设置一个元素。
*   **`s2s_TableInit`**: 从元素段初始化表。
*   **`s2s_ElemDrop`**: 释放一个元素段。
*   **`s2s_TableCopy`**: 复制表中的元素。
*   **`s2s_TableGrow`**: 增加表的大小。
*   **`s2s_TableSize`**: 获取表的大小。
*   **`s2s_TableFill`**: 用指定的值填充表。

**6. 控制流操作:**

*   **`s2s_Unreachable`**:  触发一个无法到达的陷阱。
*   **`s2s_Unwind`**:  用于异常处理，中断当前的调用链。
*   **`s2s_OnLoopBackwardJump`**:  在循环向后跳转时执行，通常用于重置 HandleScope。
*   **`s2s_Nop`**:  空操作，不执行任何动作。

**7. 原子操作 (Atomics):**

*   **`s2s_AtomicNotify`**:  唤醒等待在共享内存位置的线程。
*   **`s2s_I32AtomicWait`**:  让当前线程等待在共享内存位置上的一个特定 32 位值。
*   **`s2s_I64AtomicWait`**:  让当前线程等待在共享内存位置上的一个特定 64 位值。
*   **`s2s_AtomicFence`**:  插入一个内存屏障，确保内存操作的顺序。
*   一系列 `s2s_I32Atomic...` 和 `s2s_I64Atomic...` 函数，用于执行各种原子操作，如加法、减法、与、或、异或、交换和比较交换等。

**8. SIMD 操作:**

*   一系列 `s2s_Simd...` 函数，用于执行 SIMD (Single Instruction, Multiple Data) 操作，例如：
    *   **`s2s_SimdF64x2Splat`**: 将一个双精度浮点数复制到 SIMD 向量的所有通道。
    *   **`s2s_SimdF64x2ExtractLane`**: 从 SIMD 向量中提取指定通道的双精度浮点数。
    *   各种 SIMD 算术运算 (加、减、乘、除、最小值、最大值等)。
    *   各种 SIMD 位运算 (与、或、异或、非等)。
    *   各种 SIMD 比较运算 (等于、不等于、大于、小于等)。
    *   **`s2s_SimdF64x2ReplaceLane`**: 替换 SIMD 向量中指定通道的值。
    *   **`s2s_SimdS128LoadMem`**: 从内存加载一个 128 位 SIMD 值。
    *   **`s2s_SimdS128StoreMem`**: 将一个 128 位 SIMD 值存储到内存。

**与 JavaScript 的关系 (举例):**

这部分 C++ 代码是 V8 引擎执行 WebAssembly 代码的关键组成部分。当 JavaScript 代码执行 WebAssembly 模块时，V8 会使用这个解释器来逐条执行 WebAssembly 的指令。

例如，假设有一个简单的 WebAssembly 函数，它将两个数字相加：

```assembly
;; WebAssembly 代码片段
local.get 0
local.get 1
i32.add
return
```

对应的 JavaScript 代码可能是这样的：

```javascript
const wasmCode = new Uint8Array([
  // ... (WebAssembly 模块的二进制数据) ...
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const add = wasmInstance.exports.add;
const result = add(5, 10);
console.log(result); // 输出 15
```

当 JavaScript 调用 `add(5, 10)` 时，V8 的解释器会执行 WebAssembly 的指令：

1. **`local.get 0`**: 解释器可能会调用类似 `s2s_CopySlot32` 或内部的栈操作来获取局部变量 0 的值 (5) 并将其放到栈顶。
2. **`local.get 1`**: 类似地，解释器会获取局部变量 1 的值 (10) 并放到栈顶。
3. **`i32.add`**: 解释器会调用一个负责处理 `i32.add` 指令的函数（这部分代码可能在其他部分），该函数会从栈顶弹出两个值 (10 和 5)，执行 32 位整数加法，并将结果 (15) 推回栈顶。
4. **`return`**: 解释器会从栈顶弹出返回值 (15) 并将其返回给 JavaScript。

**再举一个 SIMD 的例子：**

假设 WebAssembly 代码使用 SIMD 指令将两个包含四个浮点数的向量相加：

```assembly
;; WebAssembly 代码片段
local.get 0  ;; 获取第一个 f32x4 向量
local.get 1  ;; 获取第二个 f32x4 向量
f32x4.add    ;; 执行向量加法
return
```

对应的 JavaScript 代码可能是：

```javascript
const wasmCode = new Uint8Array([
  // ... (包含 SIMD 指令的 WebAssembly 模块的二进制数据) ...
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const addVectors = wasmInstance.exports.addVectors;
const vector1 = new Float32Array([1, 2, 3, 4]);
const vector2 = new Float32Array([5, 6, 7, 8]);
const resultVector = addVectors(vector1, vector2);
console.log(resultVector); // 输出 Float32Array [6, 8, 10, 12]
```

当 `addVectors(vector1, vector2)` 被调用时，V8 解释器执行 `f32x4.add` 指令时，会调用 `s2s_SimdF32x4Add` 函数，该函数会从栈中弹出两个 `Simd128` 类型的值（表示两个浮点向量），然后执行向量加法，并将结果 `Simd128` 推回栈中。

总而言之，这部分 C++ 代码为 WebAssembly 解释器提供了执行各种数据操作、内存访问、原子操作和 SIMD 操作的基础，是 V8 引擎支持 WebAssembly 功能的核心组成部分。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共8部分，请归纳一下它的功能

"""
;
  uint32_t from0 = ReadI32(code);
  uint32_t from1 = ReadI32(code);

  base::WriteUnalignedValue<uint64_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint64_t>(
          reinterpret_cast<Address>(sp + from0)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT64 %d %d %" PRIx64 "\n", from0, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  to += sizeof(uint64_t) / sizeof(uint32_t);

  base::WriteUnalignedValue<uint64_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint64_t>(
          reinterpret_cast<Address>(sp + from1)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT64 %d %d %" PRIx64 "\n", from1, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot32(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace("COPYSLOT32 %d %d %08x\n", from, to,
                        *reinterpret_cast<int32_t*>(sp + to));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot32x2(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + from)));
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT32 %d %d %08x\n", from, to,
        base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  from = ReadI32(code);
  to = ReadI32(code);
  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + from)));
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT32 %d %d %08x\n", from, to,
        base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot64(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<uint64_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT64 %d %d %" PRIx64 "\n", from, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot128(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<Simd128>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<Simd128>(reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT128 %d %d %" PRIx64 "`%" PRIx64 "\n", from, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)),
        base::ReadUnalignedValue<uint64_t>(
            reinterpret_cast<Address>(sp + to + sizeof(uint64_t))));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot64x2(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<uint64_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + from)));
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT64 %d %d %" PRIx64 "\n", from, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  from = ReadI32(code);
  to = ReadI32(code);
  base::WriteUnalignedValue<uint64_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + from)));
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYSLOT64 %d %d %" PRIx64 "\n", from, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlotRef(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  wasm_runtime->StoreWasmRef(to, wasm_runtime->ExtractWasmRef(from));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace("COPYSLOTREF %d %d\n", from, to);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_PreserveCopySlot32(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);

  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + preserve),
      base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + to)));
  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "PRESERVECOPYSLOT32 %d %d %08x\n", from, to,
        base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_PreserveCopySlot64(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);

  base::WriteUnalignedValue<uint64_t>(
      reinterpret_cast<Address>(sp + preserve),
      base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  base::WriteUnalignedValue<uint64_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "PRESERVECOPYSLOT64 %d %d %" PRIx64 "\n", from, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_PreserveCopySlot128(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);

  base::WriteUnalignedValue<Simd128>(
      reinterpret_cast<Address>(sp + preserve),
      base::ReadUnalignedValue<Simd128>(reinterpret_cast<Address>(sp + to)));
  base::WriteUnalignedValue<Simd128>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<Simd128>(reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "PRESERVECOPYSLOT64 %d %d %" PRIx64 "`%" PRIx64 "\n", from, to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)),
        base::ReadUnalignedValue<uint64_t>(
            reinterpret_cast<Address>(sp + to + sizeof(uint64_t))));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_PreserveCopySlotRef(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t from = ReadI32(code);
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);

  wasm_runtime->StoreWasmRef(preserve, wasm_runtime->ExtractWasmRef(to));
  wasm_runtime->StoreWasmRef(to, wasm_runtime->ExtractWasmRef(from));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace("PRESERVECOPYSLOTREF %d %d\n", from, to);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_CopyR0ToSlot32(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<int32_t>(reinterpret_cast<Address>(sp + to),
                                     static_cast<int32_t>(r0));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYR0TOSLOT32 %d %08x\n", to,
        base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_CopyR0ToSlot64(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<int64_t>(reinterpret_cast<Address>(sp + to), r0);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYR0TOSLOT64 %d %" PRIx64 "\n", to,
        base::ReadUnalignedValue<int64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_CopyFp0ToSlot32(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<float>(reinterpret_cast<Address>(sp + to),
                                   static_cast<float>(fp0));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYFP0TOSLOT32 %d %08x\n", to,
        base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_CopyFp0ToSlot64(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  base::WriteUnalignedValue<double>(reinterpret_cast<Address>(sp + to), fp0);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "COPYFP0TOSLOT64 %d %" PRIx64 "\n", to,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_PreserveCopyR0ToSlot32(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);
  base::WriteUnalignedValue<int32_t>(
      reinterpret_cast<Address>(sp + preserve),
      base::ReadUnalignedValue<int32_t>(reinterpret_cast<Address>(sp + to)));
  base::WriteUnalignedValue<int32_t>(reinterpret_cast<Address>(sp + to),
                                     static_cast<int32_t>(r0));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "PRESERVECOPYR0TOSLOT32 %d %d %08x\n", to, preserve,
        base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_PreserveCopyR0ToSlot64(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);
  base::WriteUnalignedValue<int64_t>(
      reinterpret_cast<Address>(sp + preserve),
      base::ReadUnalignedValue<int64_t>(reinterpret_cast<Address>(sp + to)));
  base::WriteUnalignedValue<int64_t>(reinterpret_cast<Address>(sp + to), r0);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "PRESERVECOPYR0TOSLOT64 %d %d %" PRIx64 "\n", to, preserve,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_PreserveCopyFp0ToSlot32(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);
  base::WriteUnalignedValue<float>(
      reinterpret_cast<Address>(sp + preserve),
      base::ReadUnalignedValue<float>(reinterpret_cast<Address>(sp + to)));
  base::WriteUnalignedValue<float>(reinterpret_cast<Address>(sp + to),
                                   static_cast<float>(fp0));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "PRESERVECOPYFP0TOSLOT32 %d %d %08x\n", to, preserve,
        base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_PreserveCopyFp0ToSlot64(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  uint32_t preserve = ReadI32(code);
  base::WriteUnalignedValue<double>(
      reinterpret_cast<Address>(sp + preserve),
      base::ReadUnalignedValue<double>(reinterpret_cast<Address>(sp + to)));
  base::WriteUnalignedValue<double>(reinterpret_cast<Address>(sp + to), fp0);

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace(
        "PRESERVECOPYFP0TOSLOT64 %d %d %" PRIx64 "\n", to, preserve,
        base::ReadUnalignedValue<uint64_t>(reinterpret_cast<Address>(sp + to)));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefNull(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  const uint32_t ref_bitfield = ReadI32(code);
  ValueType ref_type = ValueType::FromRawBitField(ref_bitfield);

  push<WasmRef>(
      sp, code, wasm_runtime,
      handle(wasm_runtime->GetNullValue(ref_type), wasm_runtime->GetIsolate()));

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefIsNull(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  push<int32_t>(sp, code, wasm_runtime, wasm_runtime->IsRefNull(ref) ? 1 : 0);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefFunc(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);
  push<WasmRef>(sp, code, wasm_runtime, wasm_runtime->GetFunctionRef(index));

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_RefEq(const uint8_t* code, uint32_t* sp,
                                   WasmInterpreterRuntime* wasm_runtime,
                                   int64_t r0, double fp0) {
  WasmRef lhs = pop<WasmRef>(sp, code, wasm_runtime);
  WasmRef rhs = pop<WasmRef>(sp, code, wasm_runtime);
  push<int32_t>(sp, code, wasm_runtime, lhs.is_identical_to(rhs) ? 1 : 0);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_MemoryInit(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t data_segment_index = ReadI32(code);
  uint64_t size = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t src = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t dst = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  wasm_runtime->MemoryInit(code, data_segment_index, dst, src, size);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_DataDrop(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);

  wasm_runtime->DataDrop(index);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_MemoryCopy(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint64_t size = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t src = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t dst = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  wasm_runtime->MemoryCopy(code, dst, src, size);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_MemoryFill(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint64_t size = pop<uint32_t>(sp, code, wasm_runtime);
  uint32_t value = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t dst = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  wasm_runtime->MemoryFill(code, dst, value, size);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TableGet(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint32_t table_index = ReadI32(code);
  uint32_t entry_index = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  WasmRef ref;
  if (wasm_runtime->TableGet(code, table_index, entry_index, &ref)) {
    push<WasmRef>(sp, code, wasm_runtime, ref);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TableSet(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint32_t table_index = ReadI32(code);
  WasmRef ref = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t entry_index = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  wasm_runtime->TableSet(code, table_index, entry_index, ref);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TableInit(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t table_index = ReadI32(code);
  uint32_t element_segment_index = ReadI32(code);
  uint32_t size = pop<uint32_t>(sp, code, wasm_runtime);
  uint32_t src = pop<uint32_t>(sp, code, wasm_runtime);
  uint32_t dst = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  wasm_runtime->TableInit(code, table_index, element_segment_index, dst, src,
                          size);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ElemDrop(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  uint32_t index = ReadI32(code);

  wasm_runtime->ElemDrop(index);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TableCopy(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t dst_table_index = ReadI32(code);
  uint32_t src_table_index = ReadI32(code);
  auto size = pop<uint32_t>(sp, code, wasm_runtime);
  auto src = pop<uint32_t>(sp, code, wasm_runtime);
  auto dst = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  wasm_runtime->TableCopy(code, dst_table_index, src_table_index, dst, src,
                          size);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TableGrow(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t table_index = ReadI32(code);
  uint32_t delta = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef value = pop<WasmRef>(sp, code, wasm_runtime);

  uint32_t result = wasm_runtime->TableGrow(table_index, delta, value);
  push<int32_t>(sp, code, wasm_runtime, result);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TableSize(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t table_index = ReadI32(code);

  uint32_t size = wasm_runtime->TableSize(table_index);
  push<int32_t>(sp, code, wasm_runtime, size);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_TableFill(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
  uint32_t table_index = ReadI32(code);
  uint32_t count = pop<uint32_t>(sp, code, wasm_runtime);
  WasmRef value = pop<WasmRef>(sp, code, wasm_runtime);
  uint32_t start = pop<uint32_t>(sp, code, wasm_runtime);

  // This function can trap.
  wasm_runtime->TableFill(code, table_index, count, value, start);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_Unreachable(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0){
    TRAP(TrapReason::kTrapUnreachable)}

INSTRUCTION_HANDLER_FUNC
    s2s_Unwind(const uint8_t* code, uint32_t* sp,
               WasmInterpreterRuntime* wasm_runtime, int64_t r0, double fp0) {
  // Break the chain of calls.
}
PWasmOp* s_unwind_func_addr = s2s_Unwind;
InstructionHandler s_unwind_code = InstructionHandler::k_s2s_Unwind;

INSTRUCTION_HANDLER_FUNC s2s_OnLoopBackwardJump(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  wasm_runtime->ResetCurrentHandleScope();

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_Nop(const uint8_t* code, uint32_t* sp,
                                 WasmInterpreterRuntime* wasm_runtime,
                                 int64_t r0, double fp0) {
  NextOp();
}

////////////////////////////////////////////////////////////////////////////////
// Atomics operators

INSTRUCTION_HANDLER_FUNC s2s_AtomicNotify(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  int32_t val = pop<int32_t>(sp, code, wasm_runtime);

  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;
  // Check alignment.
  const uint32_t align_mask = sizeof(int32_t) - 1;
  if (V8_UNLIKELY((effective_index & align_mask) != 0)) {
    TRAP(TrapReason::kTrapUnalignedAccess)
  }
  // Check bounds.
  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(uint64_t),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }

  int32_t result = wasm_runtime->AtomicNotify(effective_index, val);
  push<int32_t>(sp, code, wasm_runtime, result);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_I32AtomicWait(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  int64_t timeout = pop<int64_t>(sp, code, wasm_runtime);
  int32_t val = pop<int32_t>(sp, code, wasm_runtime);

  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;
  // Check alignment.
  const uint32_t align_mask = sizeof(int32_t) - 1;
  if (V8_UNLIKELY((effective_index & align_mask) != 0)) {
    TRAP(TrapReason::kTrapUnalignedAccess)
  }
  // Check bounds.
  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(uint64_t),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }
  // Check atomics wait allowed.
  if (!wasm_runtime->AllowsAtomicsWait()) {
    TRAP(TrapReason::kTrapUnreachable)
  }

  int32_t result = wasm_runtime->I32AtomicWait(effective_index, val, timeout);
  push<int32_t>(sp, code, wasm_runtime, result);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_I64AtomicWait(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  int64_t timeout = pop<int64_t>(sp, code, wasm_runtime);
  int64_t val = pop<int64_t>(sp, code, wasm_runtime);

  uint64_t offset = Read<uint64_t>(code);
  uint64_t index = pop<uint32_t>(sp, code, wasm_runtime);
  uint64_t effective_index = offset + index;
  // Check alignment.
  const uint32_t align_mask = sizeof(int64_t) - 1;
  if (V8_UNLIKELY((effective_index & align_mask) != 0)) {
    TRAP(TrapReason::kTrapUnalignedAccess)
  }
  // Check bounds.
  if (V8_UNLIKELY(effective_index < index ||
                  !base::IsInBounds<uint64_t>(effective_index, sizeof(uint64_t),
                                              wasm_runtime->GetMemorySize()))) {
    TRAP(TrapReason::kTrapMemOutOfBounds)
  }
  // Check atomics wait allowed.
  if (!wasm_runtime->AllowsAtomicsWait()) {
    TRAP(TrapReason::kTrapUnreachable)
  }

  int32_t result = wasm_runtime->I64AtomicWait(effective_index, val, timeout);
  push<int32_t>(sp, code, wasm_runtime, result);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_AtomicFence(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  std::atomic_thread_fence(std::memory_order_seq_cst);
  NextOp();
}

#define FOREACH_ATOMIC_BINOP(V)                                                \
  V(I32AtomicAdd, Uint32, uint32_t, I32, uint32_t, I32, std::atomic_fetch_add) \
  V(I32AtomicAdd8U, Uint8, uint8_t, I32, uint32_t, I32, std::atomic_fetch_add) \
  V(I32AtomicAdd16U, Uint16, uint16_t, I32, uint32_t, I32,                     \
    std::atomic_fetch_add)                                                     \
  V(I32AtomicSub, Uint32, uint32_t, I32, uint32_t, I32, std::atomic_fetch_sub) \
  V(I32AtomicSub8U, Uint8, uint8_t, I32, uint32_t, I32, std::atomic_fetch_sub) \
  V(I32AtomicSub16U, Uint16, uint16_t, I32, uint32_t, I32,                     \
    std::atomic_fetch_sub)                                                     \
  V(I32AtomicAnd, Uint32, uint32_t, I32, uint32_t, I32, std::atomic_fetch_and) \
  V(I32AtomicAnd8U, Uint8, uint8_t, I32, uint32_t, I32, std::atomic_fetch_and) \
  V(I32AtomicAnd16U, Uint16, uint16_t, I32, uint32_t, I32,                     \
    std::atomic_fetch_and)                                                     \
  V(I32AtomicOr, Uint32, uint32_t, I32, uint32_t, I32, std::atomic_fetch_or)   \
  V(I32AtomicOr8U, Uint8, uint8_t, I32, uint32_t, I32, std::atomic_fetch_or)   \
  V(I32AtomicOr16U, Uint16, uint16_t, I32, uint32_t, I32,                      \
    std::atomic_fetch_or)                                                      \
  V(I32AtomicXor, Uint32, uint32_t, I32, uint32_t, I32, std::atomic_fetch_xor) \
  V(I32AtomicXor8U, Uint8, uint8_t, I32, uint32_t, I32, std::atomic_fetch_xor) \
  V(I32AtomicXor16U, Uint16, uint16_t, I32, uint32_t, I32,                     \
    std::atomic_fetch_xor)                                                     \
  V(I32AtomicExchange, Uint32, uint32_t, I32, uint32_t, I32,                   \
    std::atomic_exchange)                                                      \
  V(I32AtomicExchange8U, Uint8, uint8_t, I32, uint32_t, I32,                   \
    std::atomic_exchange)                                                      \
  V(I32AtomicExchange16U, Uint16, uint16_t, I32, uint32_t, I32,                \
    std::atomic_exchange)                                                      \
  V(I64AtomicAdd, Uint64, uint64_t, I64, uint64_t, I64, std::atomic_fetch_add) \
  V(I64AtomicAdd8U, Uint8, uint8_t, I32, uint64_t, I64, std::atomic_fetch_add) \
  V(I64AtomicAdd16U, Uint16, uint16_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_add)                                                     \
  V(I64AtomicAdd32U, Uint32, uint32_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_add)                                                     \
  V(I64AtomicSub, Uint64, uint64_t, I64, uint64_t, I64, std::atomic_fetch_sub) \
  V(I64AtomicSub8U, Uint8, uint8_t, I32, uint64_t, I64, std::atomic_fetch_sub) \
  V(I64AtomicSub16U, Uint16, uint16_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_sub)                                                     \
  V(I64AtomicSub32U, Uint32, uint32_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_sub)                                                     \
  V(I64AtomicAnd, Uint64, uint64_t, I64, uint64_t, I64, std::atomic_fetch_and) \
  V(I64AtomicAnd8U, Uint8, uint8_t, I32, uint64_t, I64, std::atomic_fetch_and) \
  V(I64AtomicAnd16U, Uint16, uint16_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_and)                                                     \
  V(I64AtomicAnd32U, Uint32, uint32_t, I32, uint64_t, I64,                     \
    std::atomic_fetch_and)                                                     \
  V(I64AtomicOr, Uint64, uint64_t, I64, uint64_t, I64, std::atomic_fetch_or)   \
  V(I64AtomicOr8U, Uint8, uint8_t, I32, uint64_t, I64, std::atomic_fetch_or)   \
  V(I64AtomicOr16U, Uint16, uint16_t, I32, uint64_t, I64,                      \
    std::atomic_fetch_or)                                                      \
  V(I64AtomicOr32U, Uint32, uint32_t, I32, uint64_t, I64,                      \
    std::atomic_fetch_or)                                                      \
  V(I64AtomicXor, Uint64, uint64_t, I64, uint64_t, I64, std::atomic_fetch_xor) \
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
"""


```