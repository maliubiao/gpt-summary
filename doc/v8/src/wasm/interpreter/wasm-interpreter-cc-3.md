Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc`. The request has several constraints:

1. **List Functionality:**  I need to identify the main actions performed by the code.
2. **Torque Check:** Determine if the file *could* be a Torque file based on its extension.
3. **JavaScript Relation:** If the code relates to JavaScript functionality, provide a JavaScript example.
4. **Logic Inference:** If there's conditional logic, provide a hypothetical input and output.
5. **Common Errors:** Point out potential user programming errors the code might help catch or handle.
6. **Part of Series:** Acknowledge that this is part 4 of 15.
7. **Summarize Functionality:** Provide a concise overview of the code's purpose.

Let's break down the code snippet:

* **Macros for Instruction Handlers:**  The code uses macros like `INSTRUCTION_HANDLER_FUNC` to define functions that handle specific WebAssembly instructions.
* **Stack Manipulation:**  Functions like `push` and `pop` indicate stack operations, which are core to the execution of WebAssembly.
* **Type Conversions:**  Macros like `FOREACH_CONVERT_UNOP` and `FOREACH_REINTERPRET_UNOP` suggest operations for converting and reinterpreting data types.
* **Bitwise Operations:** `FOREACH_BITS_UNOP` points to bit manipulation instructions.
* **Sign Extension:** `FOREACH_EXTENSION_UNOP` handles sign extension of integer types.
* **Saturated Truncation:** `FOREACH_TRUNCSAT_UNOP` deals with converting floating-point numbers to integers with saturation.
* **Memory Operations:** `MemoryGrow` and `MemorySize` are clearly related to WebAssembly memory management.
* **Control Flow:**  Instructions like `Return`, `Branch`, `BranchIf`, `If`, `Else`, `Catch`, and `BrTable` indicate control flow mechanisms.
* **Function Calls:** `CallFunction`, `ReturnCall`, `CallImportedFunction`, `ReturnCallImportedFunction`, and `CallIndirect` handle various function call scenarios.
* **Data Copying:** `CopySlotMulti` and `CopySlot_*` functions are responsible for moving data on the stack.

**Mental Sandbox:**

* **Torque Check:**  The extension is `.cc`, not `.tq`, so it's not a Torque file.
* **JavaScript Relation:**  WebAssembly is often used in conjunction with JavaScript. The stack operations and function calls are fundamental to how WebAssembly interacts within a JavaScript environment.
* **Logic Inference:** The `BranchIf` instructions are good candidates for demonstrating conditional logic.
* **Common Errors:** Type mismatches and stack overflow/underflow are common WebAssembly programming errors that this interpreter might help detect (though not directly shown in this snippet).

**Plan of Action:**

1. State the main function: interpreting WebAssembly instructions.
2. Confirm it's C++ and not Torque.
3. Provide a simple JavaScript example of calling a WebAssembly function.
4. Demonstrate the `BranchIf` logic with a simple input/output example.
5. Mention type errors and stack issues as common problems.
6. Summarize the functionality concisely.

Okay, planning complete. I'm ready to generate the response.
这是 v8 源代码文件 `v8/src/wasm/interpreter/wasm-interpreter.cc` 的一个代码片段，它主要负责 **解释执行 WebAssembly (Wasm) 代码**。

以下是它的一些主要功能：

1. **指令处理 (Instruction Handling):**
   - 代码中定义了大量的 `INSTRUCTION_HANDLER_FUNC` 函数，每个函数对应一个特定的 WebAssembly 指令。
   - 这些函数负责执行该指令的操作，例如：
     - **数据操作:**  类型转换 (`s2r_I32ConvertF32S`, `r2s_F64ReinterpretI64`), 位运算 (`r2r_I32Clz`),  符号扩展 (`r2r_I32SExtendI8`),  饱和截断 (`r2r_I32SConvertSatF32`).
     - **内存操作:**  `s2s_MemoryGrow`, `s2s_MemorySize` 用于操作 WebAssembly 线性内存。
     - **控制流:**  `s2s_Return`, `s2s_Branch`, `r2s_BranchIf`, `s2s_If`, `s2s_Else`, `s2s_Catch`, `s2s_BrTable` 用于控制代码的执行流程。
     - **函数调用:** `s2s_CallFunction`, `s2s_ReturnCall`, `s2s_CallImportedFunction`, `s2s_ReturnCallImportedFunction`, `s2s_CallIndirect`, `s2s_ReturnCallIndirect` 用于处理不同类型的函数调用。
     - **栈操作:**  `push` 和 `pop` 用于操作模拟的 WebAssembly 栈。
     - **数据复制:** `s2s_CopySlotMulti`, `s2s_CopySlot_ll`, `s2s_CopySlot_lq`, `s2s_CopySlot_ql`, `s2s_CopySlot_qq` 用于在栈上复制数据。
   - 每个指令处理函数通常会读取指令的操作数，执行相应的计算或操作，并更新程序计数器 (`NextOp()`) 以执行下一条指令。

2. **类型转换和重解释:**
   - 代码定义了用于不同数值类型之间转换的指令处理函数，例如将整数转换为浮点数，或反之。
   - "reinterpret" 操作允许将一块内存视为不同的类型，而不进行实际的数值转换。

3. **控制流管理:**
   - 代码实现了 WebAssembly 的分支、循环、条件语句等控制流结构。
   - `Branch` 和 `BranchIf` 指令根据条件跳转到代码的不同位置。
   - `If` 和 `Else` 指令实现了条件执行。
   - `BrTable` 指令实现了跳转表。

4. **函数调用机制:**
   - 代码处理直接函数调用 (`CallFunction`), 尾调用优化 (`ReturnCall`), 调用导入的函数 (`CallImportedFunction`), 以及通过函数表进行的间接调用 (`CallIndirect`)。
   - 它涉及到栈帧的创建、参数传递、返回值处理等。

5. **内存管理:**
   - `MemoryGrow` 用于增加 WebAssembly 实例的线性内存大小。
   - `MemorySize` 用于获取当前内存大小。

**关于您的问题中的其他点:**

* **.tq 结尾:**  `v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.cc` 结尾，因此它是 **C++ 源代码**，而不是 V8 Torque 源代码。Torque 文件通常以 `.tq` 结尾。
* **与 JavaScript 的关系:**  WebAssembly 经常在 JavaScript 环境中使用。这段 C++ 代码是 V8 引擎的一部分，V8 负责执行 JavaScript 和 WebAssembly 代码。当 JavaScript 代码加载并执行一个 WebAssembly 模块时，V8 会使用这个解释器（或其他执行策略）来执行 WebAssembly 的指令。

   **JavaScript 示例:**

   ```javascript
   async function runWasm() {
     const response = await fetch('your_wasm_module.wasm');
     const bytes = await response.arrayBuffer();
     const module = await WebAssembly.instantiate(bytes);
     const instance = module.instance;

     // 假设 wasm 模块导出一个名为 'add' 的函数，接收两个 i32 参数并返回一个 i32
     const result = instance.exports.add(5, 10);
     console.log(result); // 输出 15
   }

   runWasm();
   ```

   在这个例子中，JavaScript 代码加载并实例化了一个 WebAssembly 模块。当 `instance.exports.add(5, 10)` 被调用时，V8 引擎内部可能会使用类似 `wasm-interpreter.cc` 中的代码来解释执行 WebAssembly 的 `add` 函数。

* **代码逻辑推理 (以 `r2s_BranchIf` 为例):**

   **假设输入:**
   - `code` 指向 `r2s_BranchIf` 指令及其后续的偏移量。
   - `sp` 指向当前栈顶。
   - `wasm_runtime` 是 WebAssembly 运行时环境。
   - `r0` 寄存器中存储着一个整数值，表示条件 (例如，1 表示真，0 表示假)。

   **假设 `r0` 的值为 1 (真):**
   1. `cond = r0;`  // `cond` 被赋值为 1。
   2. `int32_t if_true_offset = ReadI32(code);` // 从 `code` 中读取分支目标的偏移量。假设这个偏移量是 10。
   3. `if (cond)` // 条件为真 (1)。
   4. `code += (if_true_offset - kCodeOffsetSize);` // `code` 指针向前移动 10 个字节（减去指令本身的大小）。

   **输出:**
   - 程序计数器 `code` 指向分支目标指令。

   **假设 `r0` 的值为 0 (假):**
   1. `cond = r0;`  // `cond` 被赋值为 0。
   2. `int32_t if_true_offset = ReadI32(code);` // 读取偏移量 (假设为 10)。
   3. `if (cond)` // 条件为假 (0)。
   4. `// 条件不满足，不执行分支。`

   **输出:**
   - 程序计数器 `code` 指向 `r2s_BranchIf` 指令之后的下一条顺序执行的指令。

* **用户常见的编程错误:**

   这段代码主要处理底层的 WebAssembly 执行，与用户直接编写的 WebAssembly 代码错误有一定的距离。但是，V8 的解释器在执行过程中可能会遇到由用户 WebAssembly 代码引起的错误，例如：
   - **类型不匹配:**  例如，尝试将一个浮点数作为整数使用，或者在函数调用时传递了错误的参数类型。 代码中的类型转换和重解释操作就与此相关。
   - **栈溢出/下溢:**  不正确的栈操作可能导致栈指针超出范围。`push` 和 `pop` 操作需要谨慎使用。
   - **访问越界内存:**  WebAssembly 试图访问超出其线性内存范围的地址。
   - **间接调用类型签名不匹配:**  当使用 `CallIndirect` 时，如果被调用函数的签名与函数表中的签名不匹配，就会发生错误。
   - **除零错误:**  整数除法或取模运算中除数为零。

   **举例说明 (类型不匹配):**

   假设一个 WebAssembly 函数期望接收一个 `i32` 类型的参数，但实际调用时传递了一个 `f32` 类型的值。解释器在执行到相应的指令时，可能会发现类型不匹配，并抛出一个错误。虽然这段 C++ 代码本身不直接抛出“用户编程错误”，但它在执行 WebAssembly 指令时，如果遇到违反 WebAssembly 规范的情况，会触发运行时错误或陷阱。

**归纳一下它的功能 (作为第 4 部分):**

作为 v8 WebAssembly 解释器的核心部分，这段代码片段实现了 **WebAssembly 虚拟机的指令集** 的一个子集，专注于 **数值运算、类型转换、控制流和函数调用** 的处理。它负责按照 WebAssembly 字节码的指示，一步一步地执行代码，并与运行时环境交互以进行内存管理和外部函数调用。这部分代码是 WebAssembly 代码在 V8 中得以执行的关键组成部分。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共15部分，请归纳一下它的功能
```

### 源代码
```cpp
int64_t r0, double fp0) {               \
    to_ctype val = static_cast<from_ctype>(from_reg);                         \
    push<to_ctype>(sp, code, wasm_runtime, val);                              \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    to_reg = static_cast<to_ctype>(pop<from_ctype>(sp, code, wasm_runtime));  \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    to_ctype val = pop<from_ctype>(sp, code, wasm_runtime);                   \
    push<to_ctype>(sp, code, wasm_runtime, val);                              \
    NextOp();                                                                 \
  }
FOREACH_OTHER_CONVERT_UNOP(DEFINE_UNOP)
#undef DEFINE_UNOP

////////////////////////////////////////////////////////////////////////////////
// Numeric reinterpret operators

#define FOREACH_REINTERPRET_UNOP(V)                        \
  V(F32ReinterpretI32, int32_t, I32, r0, float, F32, fp0)  \
  V(F64ReinterpretI64, int64_t, I64, r0, double, F64, fp0) \
  V(I32ReinterpretF32, float, F32, fp0, int32_t, I32, r0)  \
  V(I64ReinterpretF64, double, F64, fp0, int64_t, I64, r0)

#define DEFINE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type,  \
                    to_reg)                                                    \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,       \
                                      WasmInterpreterRuntime* wasm_runtime,    \
                                      int64_t r0, double fp0) {                \
    from_ctype value = static_cast<from_ctype>(from_reg);                      \
    to_reg =                                                                   \
        base::ReadUnalignedValue<to_ctype>(reinterpret_cast<Address>(&value)); \
    NextOp();                                                                  \
  }                                                                            \
                                                                               \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,       \
                                      WasmInterpreterRuntime* wasm_runtime,    \
                                      int64_t r0, double fp0) {                \
    from_ctype val = static_cast<from_ctype>(from_reg);                        \
    push<to_ctype>(                                                            \
        sp, code, wasm_runtime,                                                \
        base::ReadUnalignedValue<to_ctype>(reinterpret_cast<Address>(&val)));  \
    NextOp();                                                                  \
  }                                                                            \
                                                                               \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,       \
                                      WasmInterpreterRuntime* wasm_runtime,    \
                                      int64_t r0, double fp0) {                \
    from_ctype val = pop<from_ctype>(sp, code, wasm_runtime);                  \
    to_reg =                                                                   \
        base::ReadUnalignedValue<to_ctype>(reinterpret_cast<Address>(&val));   \
    NextOp();                                                                  \
  }                                                                            \
                                                                               \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,       \
                                      WasmInterpreterRuntime* wasm_runtime,    \
                                      int64_t r0, double fp0) {                \
    from_ctype val = pop<from_ctype>(sp, code, wasm_runtime);                  \
    push<to_ctype>(                                                            \
        sp, code, wasm_runtime,                                                \
        base::ReadUnalignedValue<to_ctype>(reinterpret_cast<Address>(&val)));  \
    NextOp();                                                                  \
  }
FOREACH_REINTERPRET_UNOP(DEFINE_UNOP)
#undef DEFINE_UNOP

////////////////////////////////////////////////////////////////////////////////
// Bit operators

#define FOREACH_BITS_UNOP(V)                                                   \
  V(I32Clz, uint32_t, I32, uint32_t, I32, base::bits::CountLeadingZeros(val))  \
  V(I32Ctz, uint32_t, I32, uint32_t, I32, base::bits::CountTrailingZeros(val)) \
  V(I32Popcnt, uint32_t, I32, uint32_t, I32, base::bits::CountPopulation(val)) \
  V(I32Eqz, uint32_t, I32, int32_t, I32, val == 0 ? 1 : 0)                     \
  V(I64Clz, uint64_t, I64, uint64_t, I64, base::bits::CountLeadingZeros(val))  \
  V(I64Ctz, uint64_t, I64, uint64_t, I64, base::bits::CountTrailingZeros(val)) \
  V(I64Popcnt, uint64_t, I64, uint64_t, I64, base::bits::CountPopulation(val)) \
  V(I64Eqz, uint64_t, I64, int32_t, I32, val == 0 ? 1 : 0)

#define DEFINE_REG_BINOP(name, from_ctype, from_type, to_ctype, to_type, op) \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,     \
                                      WasmInterpreterRuntime* wasm_runtime,  \
                                      int64_t r0, double fp0) {              \
    from_ctype val = static_cast<from_ctype>(r0);                            \
    r0 = static_cast<to_ctype>(op);                                          \
    NextOp();                                                                \
  }                                                                          \
                                                                             \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,     \
                                      WasmInterpreterRuntime* wasm_runtime,  \
                                      int64_t r0, double fp0) {              \
    from_ctype val = static_cast<from_ctype>(r0);                            \
    push<to_ctype>(sp, code, wasm_runtime, op);                              \
    NextOp();                                                                \
  }                                                                          \
                                                                             \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,     \
                                      WasmInterpreterRuntime* wasm_runtime,  \
                                      int64_t r0, double fp0) {              \
    from_ctype val = pop<from_ctype>(sp, code, wasm_runtime);                \
    r0 = op;                                                                 \
    NextOp();                                                                \
  }                                                                          \
                                                                             \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,     \
                                      WasmInterpreterRuntime* wasm_runtime,  \
                                      int64_t r0, double fp0) {              \
    from_ctype val = pop<from_ctype>(sp, code, wasm_runtime);                \
    push<to_ctype>(sp, code, wasm_runtime, op);                              \
    NextOp();                                                                \
  }
FOREACH_BITS_UNOP(DEFINE_REG_BINOP)
#undef DEFINE_REG_BINOP

////////////////////////////////////////////////////////////////////////////////
// Sign extension operators

#define FOREACH_EXTENSION_UNOP(V)              \
  V(I32SExtendI8, int8_t, I32, int32_t, I32)   \
  V(I32SExtendI16, int16_t, I32, int32_t, I32) \
  V(I64SExtendI8, int8_t, I64, int64_t, I64)   \
  V(I64SExtendI16, int16_t, I64, int64_t, I64) \
  V(I64SExtendI32, int32_t, I64, int64_t, I64)

#define DEFINE_UNOP(name, from_ctype, from_type, to_ctype, to_type)         \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    from_ctype val = static_cast<from_ctype>(static_cast<to_ctype>(r0));    \
    r0 = static_cast<to_ctype>(val);                                        \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    from_ctype val = static_cast<from_ctype>(static_cast<to_ctype>(r0));    \
    push<to_ctype>(sp, code, wasm_runtime, val);                            \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    from_ctype val =                                                        \
        static_cast<from_ctype>(pop<to_ctype>(sp, code, wasm_runtime));     \
    r0 = static_cast<to_ctype>(val);                                        \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    from_ctype val =                                                        \
        static_cast<from_ctype>(pop<to_ctype>(sp, code, wasm_runtime));     \
    push<to_ctype>(sp, code, wasm_runtime, val);                            \
    NextOp();                                                               \
  }
FOREACH_EXTENSION_UNOP(DEFINE_UNOP)
#undef DEFINE_UNOP

////////////////////////////////////////////////////////////////////////////////
// Saturated truncation operators

#define FOREACH_TRUNCSAT_UNOP(V)                            \
  V(I32SConvertSatF32, float, F32, fp0, int32_t, I32, r0)   \
  V(I32UConvertSatF32, float, F32, fp0, uint32_t, I32, r0)  \
  V(I32SConvertSatF64, double, F64, fp0, int32_t, I32, r0)  \
  V(I32UConvertSatF64, double, F64, fp0, uint32_t, I32, r0) \
  V(I64SConvertSatF32, float, F32, fp0, int64_t, I64, r0)   \
  V(I64UConvertSatF32, float, F32, fp0, uint64_t, I64, r0)  \
  V(I64SConvertSatF64, double, F64, fp0, int64_t, I64, r0)  \
  V(I64UConvertSatF64, double, F64, fp0, uint64_t, I64, r0)

#define DEFINE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                    to_reg)                                                   \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    to_reg =                                                                  \
        base::saturated_cast<to_ctype>(static_cast<from_ctype>(from_reg));    \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    to_ctype val =                                                            \
        base::saturated_cast<to_ctype>(static_cast<from_ctype>(from_reg));    \
    push<to_ctype>(sp, code, wasm_runtime, val);                              \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    to_reg = base::saturated_cast<to_ctype>(                                  \
        pop<from_ctype>(sp, code, wasm_runtime));                             \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    to_ctype val = base::saturated_cast<to_ctype>(                            \
        pop<from_ctype>(sp, code, wasm_runtime));                             \
    push<to_ctype>(sp, code, wasm_runtime, val);                              \
    NextOp();                                                                 \
  }
FOREACH_TRUNCSAT_UNOP(DEFINE_UNOP)
#undef DEFINE_UNOP

////////////////////////////////////////////////////////////////////////////////

INSTRUCTION_HANDLER_FUNC s2s_MemoryGrow(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t delta_pages = pop<uint32_t>(sp, code, wasm_runtime);

  int32_t result = wasm_runtime->MemoryGrow(delta_pages);

  push<int32_t>(sp, code, wasm_runtime, result);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_MemorySize(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint64_t result = wasm_runtime->MemorySize();
  if (wasm_runtime->IsMemory64()) {
    push<uint64_t>(sp, code, wasm_runtime, result);
  } else {
    push<uint32_t>(sp, code, wasm_runtime, static_cast<uint32_t>(result));
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_Return(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  // Break the chain of calls.
  ReadI32(code);
}

INSTRUCTION_HANDLER_FUNC s2s_Branch(const uint8_t* code, uint32_t* sp,
                                    WasmInterpreterRuntime* wasm_runtime,
                                    int64_t r0, double fp0) {
  int32_t target_offset = ReadI32(code);
  code += (target_offset - kCodeOffsetSize);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_BranchIf(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  int64_t cond = r0;

  int32_t if_true_offset = ReadI32(code);
  if (cond) {
    // If condition is true, jump to the target branch.
    code += (if_true_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_BranchIf(const uint8_t* code, uint32_t* sp,
                                      WasmInterpreterRuntime* wasm_runtime,
                                      int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);

  int32_t if_true_offset = ReadI32(code);
  if (cond) {
    // If condition is true, jump to the target branch.
    code += (if_true_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_BranchIfWithParams(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int64_t cond = r0;

  int32_t if_false_offset = ReadI32(code);
  if (!cond) {
    // If condition is not true, jump to the false branch.
    code += (if_false_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_BranchIfWithParams(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);

  int32_t if_false_offset = ReadI32(code);
  if (!cond) {
    // If condition is not true, jump to the false branch.
    code += (if_false_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_If(const uint8_t* code, uint32_t* sp,
                                WasmInterpreterRuntime* wasm_runtime,
                                int64_t r0, double fp0) {
  int64_t cond = r0;

  int32_t target_offset = ReadI32(code);
  if (!cond) {
    code += (target_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_If(const uint8_t* code, uint32_t* sp,
                                WasmInterpreterRuntime* wasm_runtime,
                                int64_t r0, double fp0) {
  int32_t cond = pop<int32_t>(sp, code, wasm_runtime);

  int32_t target_offset = ReadI32(code);
  if (!cond) {
    code += (target_offset - kCodeOffsetSize);
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_Else(const uint8_t* code, uint32_t* sp,
                                  WasmInterpreterRuntime* wasm_runtime,
                                  int64_t r0, double fp0) {
  int32_t target_offset = ReadI32(code);
  code += (target_offset - kCodeOffsetSize);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_Catch(const uint8_t* code, uint32_t* sp,
                                   WasmInterpreterRuntime* wasm_runtime,
                                   int64_t r0, double fp0) {
  int32_t target_offset = ReadI32(code);
  code += (target_offset - kCodeOffsetSize);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CallFunction(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint32_t function_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  wasm_runtime->ExecuteFunction(code, function_index, stack_pos,
                                ref_stack_fp_offset, slot_offset,
                                return_slot_offset);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ReturnCall(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0) {
  uint32_t rets_size = ReadI32(code);
  uint32_t args_size = ReadI32(code);
  uint32_t rets_refs = ReadI32(code);
  uint32_t args_refs = ReadI32(code);
  uint32_t function_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // Moves back the stack frame to the caller stack frame.
  wasm_runtime->UnwindCurrentStackFrame(sp, slot_offset, rets_size, args_size,
                                        rets_refs, args_refs,
                                        ref_stack_fp_offset);

  // Do not call wasm_runtime->ExecuteFunction(), which would add a
  // new C++ stack frame.
  wasm_runtime->PrepareTailCall(code, function_index, stack_pos,
                                return_slot_offset);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CallImportedFunction(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t function_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  wasm_runtime->ExecuteImportedFunction(code, function_index, stack_pos,
                                        ref_stack_fp_offset, slot_offset,
                                        return_slot_offset);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ReturnCallImportedFunction(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t rets_size = ReadI32(code);
  uint32_t args_size = ReadI32(code);
  uint32_t rets_refs = ReadI32(code);
  uint32_t args_refs = ReadI32(code);
  uint32_t function_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // Moves back the stack frame to the caller stack frame.
  wasm_runtime->UnwindCurrentStackFrame(sp, slot_offset, rets_size, args_size,
                                        rets_refs, args_refs,
                                        ref_stack_fp_offset);

  wasm_runtime->ExecuteImportedFunction(code, function_index, stack_pos, 0, 0,
                                        return_slot_offset);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CallIndirect(const uint8_t* code, uint32_t* sp,
                                          WasmInterpreterRuntime* wasm_runtime,
                                          int64_t r0, double fp0) {
  uint32_t entry_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint32_t table_index = ReadI32(code);
  uint32_t sig_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // This function can trap.
  wasm_runtime->ExecuteIndirectCall(code, table_index, sig_index, entry_index,
                                    stack_pos, sp, ref_stack_fp_offset,
                                    slot_offset, return_slot_offset, false);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_ReturnCallIndirect(
    const uint8_t* code, uint32_t* sp, WasmInterpreterRuntime* wasm_runtime,
    int64_t r0, double fp0) {
  uint32_t rets_size = ReadI32(code);
  uint32_t args_size = ReadI32(code);
  uint32_t rets_refs = ReadI32(code);
  uint32_t args_refs = ReadI32(code);
  uint32_t entry_index = pop<uint32_t>(sp, code, wasm_runtime);
  uint32_t table_index = ReadI32(code);
  uint32_t sig_index = ReadI32(code);
  uint32_t stack_pos = ReadI32(code);
  uint32_t slot_offset = ReadI32(code);
  uint32_t ref_stack_fp_offset = ReadI32(code);
  uint32_t return_slot_offset = 0;
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution) {
    return_slot_offset = ReadI32(code);
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  // Moves back the stack frame to the caller stack frame.
  wasm_runtime->UnwindCurrentStackFrame(sp, slot_offset, rets_size, args_size,
                                        rets_refs, args_refs,
                                        ref_stack_fp_offset);

  // This function can trap.
  wasm_runtime->ExecuteIndirectCall(code, table_index, sig_index, entry_index,
                                    stack_pos, sp, 0, 0, return_slot_offset,
                                    true);
  NextOp();
}

INSTRUCTION_HANDLER_FUNC r2s_BrTable(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint32_t cond = static_cast<int32_t>(r0);

  uint32_t table_length = ReadI32(code);
  uint32_t index = cond < table_length ? cond : table_length;

  int32_t target_offset = base::ReadUnalignedValue<int32_t>(
      reinterpret_cast<Address>(code + index * kCodeOffsetSize));
  code += (target_offset + index * kCodeOffsetSize);

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_BrTable(const uint8_t* code, uint32_t* sp,
                                     WasmInterpreterRuntime* wasm_runtime,
                                     int64_t r0, double fp0) {
  uint32_t cond = pop<uint32_t>(sp, code, wasm_runtime);

  uint32_t table_length = ReadI32(code);
  uint32_t index = cond < table_length ? cond : table_length;

  int32_t target_offset = base::ReadUnalignedValue<int32_t>(
      reinterpret_cast<Address>(code + index * kCodeOffsetSize));
  code += (target_offset + index * kCodeOffsetSize);

  NextOp();
}

const uint32_t kCopySlotMultiIs64Flag = 0x80000000;
const uint32_t kCopySlotMultiIs64Mask = ~kCopySlotMultiIs64Flag;

INSTRUCTION_HANDLER_FUNC s2s_CopySlotMulti(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  uint32_t params_count = ReadI32(code);
  uint32_t to = ReadI32(code);
  for (uint32_t i = 0; i < params_count; i++) {
    uint32_t from = ReadI32(code);
    bool is_64 = from & kCopySlotMultiIs64Flag;
    from &= kCopySlotMultiIs64Mask;
    if (is_64) {
      base::WriteUnalignedValue<uint64_t>(
          reinterpret_cast<Address>(sp + to),
          base::ReadUnalignedValue<uint64_t>(
              reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution &&
          v8_flags.trace_drumbrake_execution_verbose) {
        wasm_runtime->Trace("COPYSLOT64 %d %d %" PRIx64 "\n", from, to,
                            base::ReadUnalignedValue<uint64_t>(
                                reinterpret_cast<Address>(sp + to)));
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      to += sizeof(uint64_t) / sizeof(uint32_t);
    } else {
      base::WriteUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(sp + to),
          base::ReadUnalignedValue<uint32_t>(
              reinterpret_cast<Address>(sp + from)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      if (v8_flags.trace_drumbrake_execution &&
          v8_flags.trace_drumbrake_execution_verbose) {
        wasm_runtime->Trace("COPYSLOT32 %d %d %08x\n", from, to,
                            *reinterpret_cast<int32_t*>(sp + to));
      }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

      to += sizeof(uint32_t) / sizeof(uint32_t);
    }
  }

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot_ll(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  uint32_t from0 = ReadI32(code);
  uint32_t from1 = ReadI32(code);

  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(sp + from0)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace("COPYSLOT32 %d %d %08x\n", from0, to,
                        *reinterpret_cast<int32_t*>(sp + to));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  to += sizeof(uint32_t) / sizeof(uint32_t);

  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(sp + from1)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace("COPYSLOT32 %d %d %08x\n", from1, to,
                        *reinterpret_cast<int32_t*>(sp + to));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot_lq(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
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

  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(sp + from1)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace("COPYSLOT32 %d %d %08x\n", from1, to,
                        *reinterpret_cast<int32_t*>(sp + to));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  NextOp();
}

INSTRUCTION_HANDLER_FUNC s2s_CopySlot_ql(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t to = ReadI32(code);
  uint32_t from0 = ReadI32(code);
  uint32_t from1 = ReadI32(code);

  base::WriteUnalignedValue<uint32_t>(
      reinterpret_cast<Address>(sp + to),
      base::ReadUnalignedValue<uint32_t>(
          reinterpret_cast<Address>(sp + from0)));

#ifdef V8_ENABLE_DRUMBRAKE_TRACING
  if (v8_flags.trace_drumbrake_execution &&
      v8_flags.trace_drumbrake_execution_verbose) {
    wasm_runtime->Trace("COPYSLOT32 %d %d %08x\n", from0, to,
                        *reinterpret_cast<int32_t*>(sp + to));
  }
#endif  // V8_ENABLE_DRUMBRAKE_TRACING

  to += sizeof(uint32_t) / sizeof(uint32_t);

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

INSTRUCTION_HANDLER_FUNC s2s_CopySlot_qq(const uint8_t* code, uint32_t* sp,
                                         WasmInterpreterRuntime* wasm_runtime,
                                         int64_t r0, double fp0) {
  uint32_t to = ReadI32(code)
```