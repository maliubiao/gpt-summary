Response: The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of an 8-part file. The code defines a set of instruction handlers for a WebAssembly (Wasm) interpreter. The naming convention of the functions (e.g., `r2r_I32Add`, `s2s_F64Le`) suggests that these handlers implement specific Wasm instructions.

Here's a breakdown of the patterns in the code:

1. **Macros for Defining Instruction Handlers:** The code extensively uses macros like `DEFINE_BINOP` and `DEFINE_UNOP` to generate instruction handler functions. This pattern indicates a desire for code reuse and a systematic way to define handlers for different Wasm operations.

2. **Binary Operations:**  The code defines handlers for various binary operations (operations involving two operands) like addition, subtraction, multiplication, division, bitwise operations, and comparisons. The prefixes `r2r_`, `r2s_`, `s2r_`, and `s2s_` likely indicate the location of the operands:
   - `r` means the operand is in a register (`r0` for integers, `fp0` for floats).
   - `s` means the operand is on the stack (pointed to by `sp`).

3. **Unary Operations:**  Similarly, handlers are defined for unary operations (operations with one operand) like negation, absolute value, rounding functions, and conversions.

4. **Type Conversions and Reinterpretations:** There are handlers for converting between different numeric types (e.g., integer to float) and for reinterpreting the bit representation of a value as a different type.

5. **Control Flow Instructions:** The latter part of the code defines handlers for control flow instructions like `Return`, `Branch`, `BranchIf`, `If`, `Else`, `CallFunction`, `ReturnCall`, `CallImportedFunction`, `ReturnCallImportedFunction`, `CallIndirect`, `ReturnCallIndirect`, and `BrTable`. These handlers manage the execution flow of the Wasm program.

6. **Memory Operations:**  Handlers like `s2s_MemoryGrow` and `s2s_MemorySize` deal with the Wasm linear memory.

7. **Stack Manipulation:**  Handlers like `s2s_CopySlotMulti`, `s2s_CopySlot_ll`, etc., are involved in manipulating the Wasm execution stack.

8. **Relationship to JavaScript:**  Wasm is designed to be a compilation target for languages like C++ and can run in web browsers alongside JavaScript. The interaction happens through the WebAssembly JavaScript API.

**Hypothesized Functionality:** This part of the `wasm-interpreter.cc` file likely focuses on implementing the core arithmetic, logical, type conversion, and control flow instructions of the WebAssembly specification. It defines how the interpreter should behave when it encounters these specific opcodes in the Wasm bytecode.

**Illustrative JavaScript Example:** To show the relationship with JavaScript, consider a simple Wasm module that adds two numbers:

```wasm
(module
  (func $add (param $p1 i32) (param $p2 i32) (result i32)
    local.get $p1
    local.get $p2
    i32.add
  )
  (export "add" (func $add))
)
```

When this Wasm module is loaded and executed in a JavaScript environment:

```javascript
async function runWasm() {
  const response = await fetch('module.wasm'); // Assuming the wasm module is in 'module.wasm'
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  let result = instance.exports.add(5, 10);
  console.log(result); // Output: 15
}

runWasm();
```

Internally, when `instance.exports.add(5, 10)` is called, the JavaScript engine (like V8) will execute the Wasm bytecode. The `i32.add` instruction in the Wasm bytecode would be handled by a function similar to the `s2s_I32Add` function defined in the C++ code snippet. This C++ code provides the low-level implementation of how the addition operation is performed within the interpreter.

这个C++代码文件是V8引擎中WebAssembly解释器的第二部分，主要负责实现**WebAssembly指令的执行逻辑**，特别是针对**二元运算、比较运算、类型转换、位运算、以及控制流指令**。

具体来说，这部分代码定义了大量的**指令处理函数 (Instruction Handler Functions)**，每个函数对应一个或多个WebAssembly指令。 这些函数负责从栈中弹出操作数（或从寄存器中获取），执行相应的操作，并将结果推回栈中（或存储到寄存器）。

以下是代码中主要的功能分类和相应的解释：

**1. 二元运算 (Binary Operations):**

*   定义了各种算术运算（加、减、乘、除）、位运算（与、或、异或）的指令处理函数。
*   使用了宏 `DEFINE_BINOP` 来简化类似指令处理函数的定义，通过 `FOREACH_..._BINOP` 宏来批量定义不同类型的二元运算。
*   区分了操作数来源和结果去向的不同情况：
    *   `r2r_...`:  操作数从寄存器和栈中获取，结果存储到寄存器。
    *   `r2s_...`:  操作数从寄存器和栈中获取，结果存储到栈。
    *   `s2r_...`:  操作数从栈中获取，结果存储到寄存器。
    *   `s2s_...`:  操作数从栈中获取，结果存储到栈。
*   针对除法和求余运算，还处理了除零陷阱 (`TRAP(TrapReason::kTrapDivByZero)`, `TRAP(TrapReason::kTrapRemByZero)`)。

**2. 比较运算 (Comparison Operators):**

*   定义了各种比较操作（等于、不等于、小于、小于等于、大于、大于等于）的指令处理函数。
*   比较结果通常是布尔值 (0 或 1)，被作为 `int32_t` 推入栈或存储到寄存器中。

**3. 更多二元运算 (More Binary Operators):**

*   包含了移位操作（左移、右移）、循环移位、最小值、最大值以及浮点数符号复制等更复杂的二元运算。

**4. 一元运算 (Unary Operators):**

*   定义了各种一元运算的指令处理函数，例如取绝对值、取反、向上取整、向下取整、截断、四舍五入到最近的整数、平方根等。

**5. 数值转换运算符 (Numeric Conversion Operators):**

*   定义了不同数值类型之间转换的指令处理函数，例如 `i32` 到 `i64`，浮点数到整数等。
*   在浮点数到整数的转换中，会检查是否超出目标类型的表示范围，如果超出则触发陷阱 (`TRAP(TrapReason::kTrapFloatUnrepresentable)`)。

**6. 数值重解释运算符 (Numeric Reinterpret Operators):**

*   定义了将一种数值类型的二进制表示重新解释为另一种数值类型的指令处理函数，例如将 `i32` 的二进制表示解释为 `f32`。

**7. 位运算符 (Bit Operators):**

*   定义了位操作相关的指令处理函数，例如计算前导零个数、尾随零个数、人口计数（popcount）、判断是否为零。

**8. 符号扩展运算符 (Sign Extension Operators):**

*   定义了将较小的有符号整数扩展为较大有符号整数的指令处理函数。

**9. 饱和截断运算符 (Saturated Truncation Operators):**

*   定义了将浮点数转换为整数的指令处理函数，如果转换结果超出整数类型的表示范围，则饱和到该类型的最大或最小值，而不是触发陷阱。

**10. 内存操作 (Memory Operations):**

*   `s2s_MemoryGrow`: 处理内存增长指令。
*   `s2s_MemorySize`: 处理获取当前内存大小指令。

**11. 控制流指令 (Control Flow Instructions):**

*   `s2s_Return`: 处理返回指令。
*   `s2s_Branch`: 处理无条件跳转指令。
*   `r2s_BranchIf`, `s2s_BranchIf`: 处理条件跳转指令。
*   `r2s_BranchIfWithParams`, `s2s_BranchIfWithParams`: 处理带有参数的条件跳转指令。
*   `r2s_If`, `s2s_If`: 处理 `if` 块的开始。
*   `s2s_Else`: 处理 `else` 块的开始。
*   `s2s_Catch`: 处理异常捕获。
*   `s2s_CallFunction`: 处理函数调用指令。
*   `s2s_ReturnCall`: 处理尾调用指令。
*   `s2s_CallImportedFunction`: 处理调用导入函数指令。
*   `s2s_ReturnCallImportedFunction`: 处理尾调用导入函数指令。
*   `s2s_CallIndirect`: 处理间接函数调用指令。
*   `s2s_ReturnCallIndirect`: 处理尾调用间接函数指令。
*   `r2s_BrTable`, `s2s_BrTable`: 处理 `br_table` 指令（分支表）。

**12. 栈操作 (Stack Operations):**

*   `s2s_CopySlotMulti`, `s2s_CopySlot_ll`, `s2s_CopySlot_lq`, `s2s_CopySlot_ql`, `s2s_CopySlot_qq`: 处理栈槽的复制操作，用于函数调用时参数的传递或局部变量的赋值。

**与 JavaScript 的关系 (Illustrative Example in JavaScript):**

WebAssembly 可以在现代浏览器中与 JavaScript 代码一起运行。JavaScript 可以加载、编译和实例化 WebAssembly 模块，并调用其导出的函数。

假设有以下简单的 WebAssembly 代码 (Text format):

```wasm
(module
  (func $add (param $a i32) (param $b i32) (result i32)
    local.get $a
    local.get $b
    i32.add
  )
  (export "add" (func $add))
)
```

当这段 WebAssembly 代码在 JavaScript 中被调用时，例如：

```javascript
async function runWasm() {
  const response = await fetch('my_module.wasm'); // 假设 wasm 文件名为 my_module.wasm
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  let result = instance.exports.add(5, 3);
  console.log(result); // 输出: 8
}

runWasm();
```

在这个例子中，当 JavaScript 调用 `instance.exports.add(5, 3)` 时，V8 引擎会执行 WebAssembly 的 `i32.add` 指令。 在 `wasm-interpreter.cc` 的这个部分中，`s2s_I32Add` (或者类似的，取决于操作数的位置) 函数就会被调用来实际执行这个加法运算。 它会从 WebAssembly 栈中弹出 `5` 和 `3`，将它们相加，然后将结果 `8` 推回栈中（或者存储到寄存器中，供后续指令使用）。

**总结:**

这部分 `wasm-interpreter.cc` 代码是 WebAssembly 解释器执行核心逻辑的关键部分，它定义了如何处理各种 WebAssembly 指令，包括算术运算、逻辑运算、类型转换、控制流以及内存操作等。 这些指令的执行使得 WebAssembly 能够在 JavaScript 引擎中运行，并与 JavaScript 代码进行交互。

### 提示词
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```
NE_BINOP)
#undef DEFINE_BINOP

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else {                                                                \
      reg = static_cast<ctype>(lval op rval);                               \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, lval op rval);                    \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else {                                                                \
      reg = static_cast<ctype>(lval op rval);                               \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapDivByZero)                                      \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, lval op rval);                    \
    }                                                                       \
    NextOp();                                                               \
  }
FOREACH_UNSIGNED_DIV_BINOP(DEFINE_BINOP)
#undef DEFINE_BINOP

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapRemByZero)                                      \
    } else {                                                                \
      reg = static_cast<ctype>(op(lval, rval));                             \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapRemByZero)                                      \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, op(lval, rval));                  \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapRemByZero);                                     \
    } else {                                                                \
      reg = static_cast<ctype>(op(lval, rval));                             \
    }                                                                       \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    if (rval == 0) {                                                        \
      TRAP(TrapReason::kTrapRemByZero)                                      \
    } else {                                                                \
      push<ctype>(sp, code, wasm_runtime, op(lval, rval));                  \
    }                                                                       \
    NextOp();                                                               \
  }
FOREACH_REM_BINOP(DEFINE_BINOP)
#undef DEFINE_BINOP

////////////////////////////////////////////////////////////////////////////////
// Comparison operators

#define FOREACH_COMPARISON_BINOP(V) \
  V(I32Eq, uint32_t, r0, ==, I32)   \
  V(I32Ne, uint32_t, r0, !=, I32)   \
  V(I32LtU, uint32_t, r0, <, I32)   \
  V(I32LeU, uint32_t, r0, <=, I32)  \
  V(I32GtU, uint32_t, r0, >, I32)   \
  V(I32GeU, uint32_t, r0, >=, I32)  \
  V(I32LtS, int32_t, r0, <, I32)    \
  V(I32LeS, int32_t, r0, <=, I32)   \
  V(I32GtS, int32_t, r0, >, I32)    \
  V(I32GeS, int32_t, r0, >=, I32)   \
  V(I64Eq, uint64_t, r0, ==, I64)   \
  V(I64Ne, uint64_t, r0, !=, I64)   \
  V(I64LtU, uint64_t, r0, <, I64)   \
  V(I64LeU, uint64_t, r0, <=, I64)  \
  V(I64GtU, uint64_t, r0, >, I64)   \
  V(I64GeU, uint64_t, r0, >=, I64)  \
  V(I64LtS, int64_t, r0, <, I64)    \
  V(I64LeS, int64_t, r0, <=, I64)   \
  V(I64GtS, int64_t, r0, >, I64)    \
  V(I64GeS, int64_t, r0, >=, I64)   \
  V(F32Eq, float, fp0, ==, F32)     \
  V(F32Ne, float, fp0, !=, F32)     \
  V(F32Lt, float, fp0, <, F32)      \
  V(F32Le, float, fp0, <=, F32)     \
  V(F32Gt, float, fp0, >, F32)      \
  V(F32Ge, float, fp0, >=, F32)     \
  V(F64Eq, double, fp0, ==, F64)    \
  V(F64Ne, double, fp0, !=, F64)    \
  V(F64Lt, double, fp0, <, F64)     \
  V(F64Le, double, fp0, <=, F64)    \
  V(F64Gt, double, fp0, >, F64)     \
  V(F64Ge, double, fp0, >=, F64)

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    r0 = (lval op rval) ? 1 : 0;                                            \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<int32_t>(sp, code, wasm_runtime, lval op rval ? 1 : 0);            \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    r0 = (lval op rval) ? 1 : 0;                                            \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<int32_t>(sp, code, wasm_runtime, lval op rval ? 1 : 0);            \
    NextOp();                                                               \
  }
FOREACH_COMPARISON_BINOP(DEFINE_BINOP)
#undef DEFINE_BINOP

////////////////////////////////////////////////////////////////////////////////
// More binary operators

#define FOREACH_MORE_BINOP(V)                                                \
  V(I32Shl, uint32_t, r0, (lval << (rval & 31)), I32)                        \
  V(I32ShrU, uint32_t, r0, (lval >> (rval & 31)), I32)                       \
  V(I32ShrS, int32_t, r0, (lval >> (rval & 31)), I32)                        \
  V(I64Shl, uint64_t, r0, (lval << (rval & 63)), I64)                        \
  V(I64ShrU, uint64_t, r0, (lval >> (rval & 63)), I64)                       \
  V(I64ShrS, int64_t, r0, (lval >> (rval & 63)), I64)                        \
  V(I32Rol, uint32_t, r0, (base::bits::RotateLeft32(lval, rval & 31)), I32)  \
  V(I32Ror, uint32_t, r0, (base::bits::RotateRight32(lval, rval & 31)), I32) \
  V(I64Rol, uint64_t, r0, (base::bits::RotateLeft64(lval, rval & 63)), I64)  \
  V(I64Ror, uint64_t, r0, (base::bits::RotateRight64(lval, rval & 63)), I64) \
  V(F32Min, float, fp0, (JSMin<float>(lval, rval)), F32)                     \
  V(F32Max, float, fp0, (JSMax<float>(lval, rval)), F32)                     \
  V(F64Min, double, fp0, (JSMin<double>(lval, rval)), F64)                   \
  V(F64Max, double, fp0, (JSMax<double>(lval, rval)), F64)                   \
  V(F32CopySign, float, fp0,                                                 \
    Float32::FromBits((base::ReadUnalignedValue<uint32_t>(                   \
                           reinterpret_cast<Address>(&lval)) &               \
                       ~kFloat32SignBitMask) |                               \
                      (base::ReadUnalignedValue<uint32_t>(                   \
                           reinterpret_cast<Address>(&rval)) &               \
                       kFloat32SignBitMask))                                 \
        .get_scalar(),                                                       \
    F32)                                                                     \
  V(F64CopySign, double, fp0,                                                \
    Float64::FromBits((base::ReadUnalignedValue<uint64_t>(                   \
                           reinterpret_cast<Address>(&lval)) &               \
                       ~kFloat64SignBitMask) |                               \
                      (base::ReadUnalignedValue<uint64_t>(                   \
                           reinterpret_cast<Address>(&rval)) &               \
                       kFloat64SignBitMask))                                 \
        .get_scalar(),                                                       \
    F64)

#define DEFINE_BINOP(name, ctype, reg, op, type)                            \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    reg = static_cast<ctype>(op);                                           \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = static_cast<ctype>(reg);                                   \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<ctype>(sp, code, wasm_runtime, op);                                \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    reg = static_cast<ctype>(op);                                           \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype rval = pop<ctype>(sp, code, wasm_runtime);                        \
    ctype lval = pop<ctype>(sp, code, wasm_runtime);                        \
    push<ctype>(sp, code, wasm_runtime, op);                                \
    NextOp();                                                               \
  }
FOREACH_MORE_BINOP(DEFINE_BINOP)
#undef DEFINE_BINOP

////////////////////////////////////////////////////////////////////////////////
// Unary operators

#define FOREACH_SIMPLE_UNOP(V)                       \
  V(F32Abs, float, fp0, abs(val), F32)               \
  V(F32Neg, float, fp0, -val, F32)                   \
  V(F32Ceil, float, fp0, ceilf(val), F32)            \
  V(F32Floor, float, fp0, floorf(val), F32)          \
  V(F32Trunc, float, fp0, truncf(val), F32)          \
  V(F32NearestInt, float, fp0, nearbyintf(val), F32) \
  V(F32Sqrt, float, fp0, sqrt(val), F32)             \
  V(F64Abs, double, fp0, abs(val), F64)              \
  V(F64Neg, double, fp0, (-val), F64)                \
  V(F64Ceil, double, fp0, ceil(val), F64)            \
  V(F64Floor, double, fp0, floor(val), F64)          \
  V(F64Trunc, double, fp0, trunc(val), F64)          \
  V(F64NearestInt, double, fp0, nearbyint(val), F64) \
  V(F64Sqrt, double, fp0, sqrt(val), F64)

#define DEFINE_UNOP(name, ctype, reg, op, type)                             \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype val = static_cast<ctype>(reg);                                    \
    reg = static_cast<ctype>(op);                                           \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype val = static_cast<ctype>(reg);                                    \
    push<ctype>(sp, code, wasm_runtime, op);                                \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype val = pop<ctype>(sp, code, wasm_runtime);                         \
    reg = static_cast<ctype>(op);                                           \
    NextOp();                                                               \
  }                                                                         \
                                                                            \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,    \
                                      WasmInterpreterRuntime* wasm_runtime, \
                                      int64_t r0, double fp0) {             \
    ctype val = pop<ctype>(sp, code, wasm_runtime);                         \
    push<ctype>(sp, code, wasm_runtime, op);                                \
    NextOp();                                                               \
  }
FOREACH_SIMPLE_UNOP(DEFINE_UNOP)
#undef DEFINE_UNOP

////////////////////////////////////////////////////////////////////////////////
// Numeric conversion operators

#define FOREACH_ADDITIONAL_CONVERT_UNOP(V) \
  V(I32ConvertI64, int64_t, I64, r0, int32_t, I32, r0)

INSTRUCTION_HANDLER_FUNC r2r_I32ConvertI64(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  r0 &= 0xffffffff;
  NextOp();
}
INSTRUCTION_HANDLER_FUNC r2s_I32ConvertI64(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  push<int32_t>(sp, code, wasm_runtime, r0 & 0xffffffff);
  NextOp();
}
INSTRUCTION_HANDLER_FUNC s2r_I32ConvertI64(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  r0 = 0xffffffff & pop<int64_t>(sp, code, wasm_runtime);
  NextOp();
}
INSTRUCTION_HANDLER_FUNC s2s_I32ConvertI64(const uint8_t* code, uint32_t* sp,
                                           WasmInterpreterRuntime* wasm_runtime,
                                           int64_t r0, double fp0) {
  push<int32_t>(sp, code, wasm_runtime,
                0xffffffff & pop<int64_t>(sp, code, wasm_runtime));
  NextOp();
}

#define FOREACH_I64_CONVERT_FROM_FLOAT_UNOP(V)          \
  V(I64SConvertF32, float, F32, fp0, int64_t, I64, r0)  \
  V(I64SConvertF64, double, F64, fp0, int64_t, I64, r0) \
  V(I64UConvertF32, float, F32, fp0, uint64_t, I64, r0) \
  V(I64UConvertF64, double, F64, fp0, uint64_t, I64, r0)

#define FOREACH_I32_CONVERT_FROM_FLOAT_UNOP(V)          \
  V(I32SConvertF32, float, F32, fp0, int32_t, I32, r0)  \
  V(I32UConvertF32, float, F32, fp0, uint32_t, I32, r0) \
  V(I32SConvertF64, double, F64, fp0, int32_t, I32, r0) \
  V(I32UConvertF64, double, F64, fp0, uint32_t, I32, r0)

#define FOREACH_OTHER_CONVERT_UNOP(V)                     \
  V(I64SConvertI32, int32_t, I32, r0, int64_t, I64, r0)   \
  V(I64UConvertI32, uint32_t, I32, r0, uint64_t, I64, r0) \
  V(F32SConvertI32, int32_t, I32, r0, float, F32, fp0)    \
  V(F32UConvertI32, uint32_t, I32, r0, float, F32, fp0)   \
  V(F32SConvertI64, int64_t, I64, r0, float, F32, fp0)    \
  V(F32UConvertI64, uint64_t, I64, r0, float, F32, fp0)   \
  V(F32ConvertF64, double, F64, fp0, float, F32, fp0)     \
  V(F64SConvertI32, int32_t, I32, r0, double, F64, fp0)   \
  V(F64UConvertI32, uint32_t, I32, r0, double, F64, fp0)  \
  V(F64SConvertI64, int64_t, I64, r0, double, F64, fp0)   \
  V(F64UConvertI64, uint64_t, I64, r0, double, F64, fp0)  \
  V(F64ConvertF32, float, F32, fp0, double, F64, fp0)

#define FOREACH_CONVERT_UNOP(V)          \
  FOREACH_I64_CONVERT_FROM_FLOAT_UNOP(V) \
  FOREACH_I32_CONVERT_FROM_FLOAT_UNOP(V) \
  FOREACH_OTHER_CONVERT_UNOP(V)

#define DEFINE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                    to_reg)                                                   \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    if (!base::IsValueInRangeForNumericType<to_ctype>(from_reg)) {            \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_reg = static_cast<to_ctype>(static_cast<from_ctype>(from_reg));      \
    }                                                                         \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    if (!base::IsValueInRangeForNumericType<to_ctype>(from_reg)) {            \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_ctype val = static_cast<from_ctype>(from_reg);                       \
      push<to_ctype>(sp, code, wasm_runtime, val);                            \
    }                                                                         \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    from_ctype from_val = pop<from_ctype>(sp, code, wasm_runtime);            \
    if (!base::IsValueInRangeForNumericType<to_ctype>(from_val)) {            \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_reg = static_cast<to_ctype>(from_val);                               \
    }                                                                         \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    from_ctype from_val = pop<from_ctype>(sp, code, wasm_runtime);            \
    if (!base::IsValueInRangeForNumericType<to_ctype>(from_val)) {            \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_ctype val = static_cast<to_ctype>(from_val);                         \
      push<to_ctype>(sp, code, wasm_runtime, val);                            \
    }                                                                         \
    NextOp();                                                                 \
  }
FOREACH_I64_CONVERT_FROM_FLOAT_UNOP(DEFINE_UNOP)
#undef DEFINE_UNOP

#define DEFINE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                    to_reg)                                                   \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    if (!is_inbounds<to_ctype>(from_reg)) {                                   \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_reg = static_cast<to_ctype>(static_cast<from_ctype>(from_reg));      \
    }                                                                         \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    if (!is_inbounds<to_ctype>(from_reg)) {                                   \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_ctype val = static_cast<from_ctype>(from_reg);                       \
      push<to_ctype>(sp, code, wasm_runtime, val);                            \
    }                                                                         \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    from_ctype from_val = pop<from_ctype>(sp, code, wasm_runtime);            \
    if (!is_inbounds<to_ctype>(from_val)) {                                   \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_reg = static_cast<to_ctype>(from_val);                               \
    }                                                                         \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC s2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    from_ctype from_val = pop<from_ctype>(sp, code, wasm_runtime);            \
    if (!is_inbounds<to_ctype>(from_val)) {                                   \
      TRAP(TrapReason::kTrapFloatUnrepresentable)                             \
    } else {                                                                  \
      to_ctype val = static_cast<to_ctype>(from_val);                         \
      push<to_ctype>(sp, code, wasm_runtime, val);                            \
    }                                                                         \
    NextOp();                                                                 \
  }
FOREACH_I32_CONVERT_FROM_FLOAT_UNOP(DEFINE_UNOP)
#undef DEFINE_UNOP

#define DEFINE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                    to_reg)                                                   \
  INSTRUCTION_HANDLER_FUNC r2r_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
                                      int64_t r0, double fp0) {               \
    to_reg = static_cast<to_ctype>(static_cast<from_ctype>(from_reg));        \
    NextOp();                                                                 \
  }                                                                           \
                                                                              \
  INSTRUCTION_HANDLER_FUNC r2s_##name(const uint8_t* code, uint32_t* sp,      \
                                      WasmInterpreterRuntime* wasm_runtime,   \
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