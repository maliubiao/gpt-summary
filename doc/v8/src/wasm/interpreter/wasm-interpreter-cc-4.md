Response:
Let's break down the thought process for analyzing this C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc`.

**1. Initial Understanding & Context:**

* **Source File and Path:** The path `v8/src/wasm/interpreter/wasm-interpreter.cc` immediately tells us this code is part of V8's WebAssembly interpreter. The "interpreter" part is crucial – this code is about *executing* WebAssembly instructions directly, rather than compiling them to native machine code.
* **Language:** The code is clearly C++. Keywords like `uint32_t`, `Address`, `reinterpret_cast`, `#ifdef`, and function definitions confirm this.
* **Purpose:**  Given the path and the presence of functions named like `s2s_CopySlot32`, `r2s_CopyR0ToSlot64`, etc., the primary purpose seems to be handling individual WebAssembly instructions. The `s2s` and `r2s` prefixes likely indicate the source and destination of data (stack-to-stack, register-to-stack).

**2. Analyzing Individual Instruction Handlers:**

* **Common Structure:** Most of the provided functions follow a similar pattern:
    * Take `code`, `sp`, `wasm_runtime`, `r0`, `fp0` as arguments. These likely represent the instruction stream, stack pointer, runtime environment, general-purpose register 0, and floating-point register 0, respectively.
    * Read operands from the `code` stream using `ReadI32` (or `Read`).
    * Perform an operation, often involving memory access using `base::WriteUnalignedValue` and `base::ReadUnalignedValue`. The `reinterpret_cast<Address>(sp + ...)` part indicates accessing memory relative to the stack pointer.
    * Include `#ifdef V8_ENABLE_DRUMBRAKE_TRACING` blocks for debugging and logging.
    * Call `NextOp()` to move to the next instruction.

* **Specific Instruction Semantics:** By looking at the function names and the operations performed, we can infer the meaning of each instruction handler:
    * `CopySlot...`: Copies data between stack slots. The number suffix (32, 64, 128) indicates the data size in bits.
    * `PreserveCopySlot...`: Copies data between stack slots, while also preserving the original value of the destination slot.
    * `CopyR0ToSlot...`, `CopyFp0ToSlot...`: Copies the value from register `r0` (integer) or `fp0` (floating-point) to a stack slot.
    * `PreserveCopyR0ToSlot...`, `PreserveCopyFp0ToSlot...`: Similar to above, but preserves the original stack slot value.
    * `RefNull`, `RefIsNull`, `RefFunc`, `RefEq`: Handle WebAssembly reference types (null, checking for null, getting a function reference, comparing references).
    * `MemoryInit`, `DataDrop`, `MemoryCopy`, `MemoryFill`: Implement memory manipulation instructions.
    * `TableGet`, `TableSet`, `TableInit`, `ElemDrop`, `TableCopy`, `TableGrow`, `TableSize`, `TableFill`: Implement table manipulation instructions.
    * `Unreachable`, `Unwind`, `OnLoopBackwardJump`, `Nop`: Control flow and no-operation instructions.

**3. Identifying Potential Relationships with JavaScript:**

* **WebAssembly's Role:** WebAssembly is designed to be a compilation target for languages like C, C++, and Rust, but it also integrates deeply with JavaScript in the browser.
* **JavaScript API for WebAssembly:** JavaScript provides an API (`WebAssembly`) to load, compile, and execute WebAssembly modules. The interpreter handles the execution part when direct compilation isn't used or for debugging.
* **Data Sharing:**  The "slots" being manipulated likely correspond to the WebAssembly stack, which holds intermediate values during computation. JavaScript can pass data to and receive data from WebAssembly modules.

**4. Code Logic Inference (Example with `s2s_CopySlot32`):**

* **Assumptions:**
    * `sp` points to the base of the current stack frame.
    * Stack grows downwards (lower memory addresses).
    * `code` points to the current instruction byte.
* **Input:** Let's say the `code` stream contains the following bytes (after the opcode for `s2s_CopySlot32`):
    * `from` (4 bytes): `0x00000004` (decimal 4)
    * `to` (4 bytes): `0x00000008` (decimal 8)
* **State before:** Assume `sp` points to memory address `0x1000`.
    * `sp + 4` (address `0x1004`) contains the value `0x12345678`.
    * `sp + 8` (address `0x1008`) contains the value `0xABCDEF01`.
* **Execution:**
    1. `from` is read as 4.
    2. `to` is read as 8.
    3. The value at `sp + 4` (which is `0x12345678`) is read.
    4. This value is written to `sp + 8`.
* **Output:**
    * `sp + 8` (address `0x1008`) now contains `0x12345678`.
    * The value at `sp + 4` remains `0x12345678`.

**5. Common Programming Errors:**

* **Incorrect Stack Management:** If the `from` or `to` indices are calculated incorrectly, the code might read from or write to the wrong memory locations, leading to crashes or unexpected behavior.
* **Type Mismatches:** While the code uses `uint32_t` for indices, errors could occur if the WebAssembly code tries to access data with an incompatible size.
* **Unaligned Access:** The code uses `base::WriteUnalignedValue`. While this handles unaligned access, it can be slower on some architectures. A programmer might incorrectly assume data is always aligned.
* **Out-of-Bounds Access:**  Providing `from` or `to` values that are outside the valid stack frame would cause memory access violations.

**6. Addressing the `.tq` Check:**

* The code snippet is clearly C++, not Torque. The presence of C++ keywords and the file extension `.cc` confirm this.

**7. Synthesizing the Summary:**

Based on the analysis above, we can formulate a summary of the code's functionality.

By following this structured approach, we can effectively analyze the provided code snippet and address all the requirements of the prompt.
这是目录为`v8/src/wasm/interpreter/wasm-interpreter.cc`的 V8 源代码片段。根据提供的信息，我们可以分析它的功能如下：

**核心功能：WebAssembly 解释器指令处理**

这段代码是 V8 引擎中 WebAssembly 解释器的核心部分，它定义了用于处理各种 WebAssembly 指令的函数。每个 `INSTRUCTION_HANDLER_FUNC` 定义了一个特定的 WebAssembly 操作的执行逻辑。

**具体功能分解：**

1. **数据移动和复制 (COPYSLOT 系列):**
   - `s2s_CopySlot64x2`, `s2s_CopySlot32`, `s2s_CopySlot32x2`, `s2s_CopySlot64`, `s2s_CopySlot128`, `s2s_CopySlotRef`: 这些函数负责在 WebAssembly 解释器栈上的不同位置之间复制数据。
   - `s2s_CopySlot64x2` 复制两个 64 位的值。
   - `s2s_CopySlot32` 复制一个 32 位的值。
   - `s2s_CopySlot32x2` 复制两个 32 位的值。
   - `s2s_CopySlot64` 复制一个 64 位的值。
   - `s2s_CopySlot128` 复制一个 128 位的值 (SIMD 数据类型)。
   - `s2s_CopySlotRef` 复制一个 WebAssembly 引用。
   - `s2s_PreserveCopySlot32`, `s2s_PreserveCopySlot64`, `s2s_PreserveCopySlot128`, `s2s_PreserveCopySlotRef`: 这些函数在复制数据的同时，还会将目标位置的原始值保存到另一个位置。

2. **寄存器到栈的复制 (CopyR0ToSlot, CopyFp0ToSlot 系列):**
   - `r2s_CopyR0ToSlot32`, `r2s_CopyR0ToSlot64`: 将通用寄存器 `r0` 中的 32 位或 64 位整数值复制到栈上的指定位置。
   - `r2s_CopyFp0ToSlot32`, `r2s_CopyFp0ToSlot64`: 将浮点寄存器 `fp0` 中的 32 位或 64 位浮点数值复制到栈上的指定位置。
   - `r2s_PreserveCopyR0ToSlot32`, `r2s_PreserveCopyR0ToSlot64`, `r2s_PreserveCopyFp0ToSlot32`, `r2s_PreserveCopyFp0ToSlot64`:  类似于上面的函数，但在复制之前会保存目标栈位置的原始值。

3. **引用类型操作 (RefNull, RefIsNull, RefFunc, RefEq):**
   - `s2s_RefNull`:  将一个指定类型的 null 引用推入栈。
   - `s2s_RefIsNull`: 从栈中弹出一个引用，并将其是否为 null 的结果（1 或 0）推入栈。
   - `s2s_RefFunc`:  根据索引获取一个函数引用并推入栈。
   - `s2s_RefEq`: 从栈中弹出两个引用，并将其是否相等的比较结果（1 或 0）推入栈。

4. **内存操作 (MemoryInit, DataDrop, MemoryCopy, MemoryFill):**
   - `s2s_MemoryInit`:  将数据段中的一部分内容复制到线性内存中。
   - `s2s_DataDrop`:  丢弃一个数据段，使其无法再被 `memory.init` 访问。
   - `s2s_MemoryCopy`:  在线性内存的不同区域之间复制数据。
   - `s2s_MemoryFill`:  用指定的值填充线性内存的指定区域。

5. **表操作 (TableGet, TableSet, TableInit, ElemDrop, TableCopy, TableGrow, TableSize, TableFill):**
   - `s2s_TableGet`:  从指定的表中的指定索引处获取一个引用并推入栈。
   - `s2s_TableSet`:  将一个引用设置到指定表中的指定索引处。
   - `s2s_TableInit`:  将元素段中的一部分内容复制到表中。
   - `s2s_ElemDrop`:  丢弃一个元素段，使其无法再被 `table.init` 访问。
   - `s2s_TableCopy`:  在不同的表之间复制条目。
   - `s2s_TableGrow`:  增加表的大小。
   - `s2s_TableSize`:  获取表的大小并推入栈。
   - `s2s_TableFill`:  用指定的值填充表的指定区域。

6. **控制流 (Unreachable, Unwind, OnLoopBackwardJump, Nop):**
   - `s2s_Unreachable`:  触发一个不可达的陷阱 (trap)。
   - `s2s_Unwind`:  用于处理异常或控制流跳转，打破正常的调用链。
   - `s2s_OnLoopBackwardJump`:  在循环向后跳转时执行，通常用于重置 handle scope。
   - `s2s_Nop`:  空操作，不执行任何操作。

7. **原子操作 (AtomicNotify, I32AtomicWait, I64AtomicWait, AtomicFence，以及 FOREACH_ATOMIC_BINOP 定义的原子操作):**
   - `s2s_AtomicNotify`:  唤醒等待在共享内存位置的线程。
   - `s2s_I32AtomicWait`, `s2s_I64AtomicWait`:  使当前线程休眠，直到共享内存位置的值发生变化。
   - `s2s_AtomicFence`:  插入一个内存屏障，确保操作的顺序性。
   - `FOREACH_ATOMIC_BINOP` 定义了一系列原子二元操作，例如原子加、减、与、或、异或、交换等，用于在多线程环境中安全地操作共享内存。

**关于 .tq 结尾：**

如果 `v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是一种用于 V8 内部实现的领域特定语言，用于生成高效的 C++ 代码。然而，从你提供的文件名来看，它以 `.cc` 结尾，所以它是 **C++ 源代码**。

**与 JavaScript 的关系：**

这段 C++ 代码是 V8 引擎的一部分，V8 引擎是 JavaScript 的运行时环境。WebAssembly 旨在与 JavaScript 并行运行，并可以通过 JavaScript API 进行交互。

**JavaScript 示例：**

假设 WebAssembly 模块中有一个函数，它需要将两个整数相加并返回结果。解释器执行 `i32.add` 指令时，其内部逻辑会类似于 C++ 中实现的加法操作。

```javascript
// 假设已经加载并实例化了一个 WebAssembly 模块 'wasmModule'
const instance = wasmModule.instance;
const addFunction = instance.exports.add; // 假设导出了一个名为 'add' 的函数

const result = addFunction(5, 10); // JavaScript 调用 WebAssembly 函数
console.log(result); // 输出 15
```

在 WebAssembly 模块的执行过程中，当遇到需要进行基本操作（如加法、数据复制等）的指令时，V8 的解释器（如果使用解释器执行）就会调用类似于这段 C++ 代码中定义的处理函数。例如，当执行 `local.get` 和 `local.set` 指令时，解释器可能会使用类似于 `s2s_CopySlot32` 或 `r2s_CopyR0ToSlot32` 的逻辑来操作 WebAssembly 栈上的局部变量。

**代码逻辑推理示例：**

**假设输入：**

- `code` 指向 `s2s_CopySlot32` 指令的操作数，包含 `from = 4` 和 `to = 8`。
- `sp` 指向栈底，例如地址 `0x1000`。
- 栈上 `sp + 4` 的位置存储着值 `0xABCDEF00`。
- 栈上 `sp + 8` 的位置存储着值 `0x12345678`。

**执行 `s2s_CopySlot32`：**

1. `ReadI32(code)` 读取 `from` 的值，得到 `4`。
2. `ReadI32(code)` 读取 `to` 的值，得到 `8`。
3. `base::ReadUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + from))` 读取地址 `0x1004` 的值，得到 `0xABCDEF00`。
4. `base::WriteUnalignedValue<uint32_t>(reinterpret_cast<Address>(sp + to), ...)` 将值 `0xABCDEF00` 写入地址 `0x1008`。

**输出：**

- 栈上 `sp + 8` 的位置现在存储着值 `0xABCDEF00`。
- 栈上 `sp + 4` 的值保持不变，仍然是 `0xABCDEF00`。

**用户常见的编程错误示例：**

在使用 WebAssembly 时，一些常见的编程错误可能会导致解释器中的这些代码被触发或产生预期外的行为：

1. **栈溢出：**  如果 WebAssembly 代码执行过程中使用的栈空间超过了限制，可能会导致访问无效的内存地址，虽然这里的代码片段主要处理指令，栈溢出会在更底层的栈管理中体现。

2. **类型不匹配：**  例如，尝试将一个 64 位的值写入一个 32 位的栈槽，或者对引用类型进行错误的操作。

3. **越界访问内存或表：** WebAssembly 代码可能会尝试访问线性内存或表的超出其分配范围的索引，这会导致 `MemoryInit`、`MemoryCopy`、`TableGet`、`TableSet` 等函数中的边界检查失败并触发陷阱。

   ```javascript
   // 假设一个 WebAssembly 模块尝试访问超出内存边界的位置
   const memory = instance.exports.memory;
   const memArray = new Uint8Array(memory.buffer);
   const invalidIndex = 65536; // 假设内存只有 65536 字节
   try {
       const value = memArray[invalidIndex]; // 这将导致错误
   } catch (e) {
       console.error("内存访问越界错误:", e);
   }
   ```

4. **原子操作使用不当：** 在多线程 WebAssembly 应用中，如果没有正确使用原子操作进行同步，可能会导致数据竞争和未定义的行为。例如，在没有先调用 `AtomicWait` 的情况下就调用 `AtomicNotify` 可能不会产生预期的效果。

**归纳功能（第 5 部分，共 15 部分）：**

作为第 5 部分，这段代码主要关注 **WebAssembly 解释器中用于数据操作、引用类型处理、内存和表操作以及基本控制流指令的处理逻辑**。它定义了执行这些核心指令的具体步骤，包括从指令流中读取操作数，在栈上操作数据，以及与 WebAssembly 运行时环境进行交互。  考虑到这是 15 部分中的一部分，可以推测之前的部分可能涉及指令的解码、调用栈管理等，而后续部分可能会涵盖更复杂的控制流、函数调用、以及与其他 V8 内部机制的交互。  这一部分是解释器执行 WebAssembly 代码的核心构建块。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
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
  V(I64AtomicXor, Uint64, uint64_t, I64, uint
```