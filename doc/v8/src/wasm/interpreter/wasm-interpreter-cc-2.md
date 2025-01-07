Response:
The user wants a summary of the provided C++ code snippet, specifically focusing on its function within the V8 WebAssembly interpreter.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Functionality:** The code is a series of macro definitions (`DEFINE_BINOP`, `DEFINE_UNOP`) and macro invocations (`FOREACH_*_BINOP`, `FOREACH_*_UNOP`). These macros generate C++ function definitions. The names of the generated functions (e.g., `r2r_I32Add`, `s2s_F64Sqrt`) strongly suggest they handle WebAssembly instructions. The prefixes `r2r`, `r2s`, `s2r`, `s2s` likely indicate how operands are sourced (register or stack) and where the result is placed (register or stack).

2. **Categorize the Operations:** The `FOREACH_*` macros are grouped by operation type: arithmetic (`FOREACH_SIGNED_DIV_BINOP`, `FOREACH_UNSIGNED_DIV_BINOP`, `FOREACH_REM_BINOP`), comparison (`FOREACH_COMPARISON_BINOP`), bitwise and other binary operations (`FOREACH_MORE_BINOP`), unary operations (`FOREACH_SIMPLE_UNOP`), and type conversions (`FOREACH_CONVERT_UNOP`). This organization helps understand the code's scope.

3. **Explain the Macro Structure:**  Explain how the `DEFINE_*OP` macros work. They take a name, data type, register, operator, and type information as arguments and generate the four handler functions (`r2r_`, `r2s_`, `s2r_`, `s2s_`). This is crucial for understanding how the repetitive code is generated.

4. **Decipher the Handler Function Names:** Break down the `r2r_`, `r2s_`, etc., naming convention to clarify how operands and results are handled. This is key to understanding the different execution paths for the same operation.

5. **Connect to WebAssembly Instructions:**  Explain that these functions directly implement the behavior of WebAssembly instructions. The macro names often mirror the names of WebAssembly opcodes (e.g., `I32Add`, `F64Sqrt`).

6. **Address Specific User Questions:**
    * **`.tq` extension:** Explicitly state that this is `.cc` and not a Torque file.
    * **Relationship to JavaScript:** Explain that while this code directly executes WebAssembly, WebAssembly itself is often generated from or interacts with JavaScript. Provide a simple JavaScript example that would lead to the execution of WebAssembly code, and thus potentially involve these interpreter functions.
    * **Code Logic Inference:** Choose a simple example like `I32Add` and illustrate the stack manipulation and register usage with hypothetical input and output for the different `r2r`, `r2s`, etc., variations.
    * **Common Programming Errors:** Focus on the division by zero and unrepresentable float conversion traps, as these are explicitly handled in the code. Provide simple WebAssembly (or conceptually similar JavaScript) examples that would trigger these errors.

7. **Summarize the Overall Functionality:** Combine the individual pieces into a concise summary, emphasizing that the code provides the core execution logic for many WebAssembly operations within the interpreter.

8. **Review and Refine:** Read through the generated response to ensure clarity, accuracy, and completeness. Make sure all aspects of the user's prompt have been addressed. For example, explicitly stating this is *part 3 of 15* reinforces that this is a component of a larger system.
好的，根据提供的代码片段，以下是关于 `v8/src/wasm/interpreter/wasm-interpreter.cc` 第 3 部分的功能归纳：

**功能归纳：**

这段代码主要定义了 WebAssembly 解释器中用于执行多种**二元运算**和**一元运算**的指令处理函数。这些函数负责从操作数栈或寄存器中获取操作数，执行相应的运算，并将结果写回寄存器或压入操作数栈。

**具体功能点：**

1. **二元运算指令处理：**
   -  定义了大量用于处理不同类型（整数 i32/i64，浮点数 f32/f64）的二元算术运算（加、减、乘、除、余数）、位运算（与、或、异或、左移、右移、循环移位）和比较运算（等于、不等于、小于、小于等于、大于、大于等于）的指令处理函数。
   -  针对每种运算，都定义了四种形式的指令处理函数，根据操作数和结果的位置进行区分：
      - `r2r_`: 右操作数在寄存器，结果写入寄存器。
      - `r2s_`: 右操作数在寄存器，结果压入栈。
      - `s2r_`: 右操作数在栈，结果写入寄存器。
      - `s2s_`: 右操作数在栈，结果压入栈。
   -  包含了对除零错误 (`TrapReason::kTrapDivByZero`) 和求余零错误 (`TrapReason::kTrapRemByZero`) 的处理。

2. **比较运算指令处理：**
   -  定义了处理各种类型比较运算的指令处理函数，结果为布尔值（0 或 1）。
   -  同样针对每种比较运算定义了 `r2r_`、`r2s_`、`s2r_`、`s2s_` 四种形式。

3. **其他二元运算指令处理：**
   -  定义了最小值 (`Min`)、最大值 (`Max`) 和符号复制 (`CopySign`) 等其他二元运算的指令处理函数。

4. **一元运算指令处理：**
   -  定义了处理浮点数的一元运算，如绝对值 (`Abs`)、取反 (`Neg`)、向上取整 (`Ceil`)、向下取整 (`Floor`)、截断取整 (`Trunc`)、取最近整数 (`NearestInt`) 和平方根 (`Sqrt`)。
   -  同样针对每种一元运算定义了 `r2r_`、`r2s_`、`s2r_`、`s2s_` 四种形式。

5. **类型转换指令处理：**
   -  定义了各种类型转换操作的指令处理函数，包括：
      - 整数类型之间的转换 (`I32ConvertI64`)。
      - 浮点数转换为整数 (`I64SConvertF32`, `I32UConvertF64` 等)。
      - 整数转换为浮点数 (`F32SConvertI32`, `F64UConvertI64` 等)。
      - 浮点数类型之间的转换 (`F32ConvertF64`, `F64ConvertF32`)。
   -  在浮点数到整数的转换中，包含了对无法表示的浮点数的陷阱处理 (`TrapReason::kTrapFloatUnrepresentable`) 和越界检查。

**关于代码特性的回答：**

* **是否为 Torque 源代码：**  根据您提供的信息，文件名为 `wasm-interpreter.cc`，以 `.cc` 结尾，因此它是一个 **C++ 源代码**，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。

* **与 JavaScript 的关系：**  WebAssembly 可以在现代浏览器中运行，并且可以与 JavaScript 代码相互调用。这段 C++ 代码是 V8 引擎中 WebAssembly 解释器的核心部分，负责直接执行 WebAssembly 的指令。当 JavaScript 调用 WebAssembly 模块中的函数时，或者当 WebAssembly 代码执行到某个操作时，就有可能触发这些指令处理函数的执行。

   **JavaScript 示例：**

   ```javascript
   // 假设有一个名为 'wasmModule' 的 WebAssembly 模块实例
   const result = wasmModule.exports.add(5, 10); // 调用 WebAssembly 模块中的 'add' 函数
   console.log(result); // 输出结果

   // 在 WebAssembly 模块的 'add' 函数的实现中，
   // 如果使用了加法操作，V8 的解释器（如果使用解释执行）
   // 就会调用类似于这段 C++ 代码中定义的处理加法指令的函数。
   ```

* **代码逻辑推理（假设输入与输出）：**

   **假设输入：**  WebAssembly 代码执行到一个 `i32.add` 指令，并且：
   -  寄存器 `r0` 中存储着值 `10`。
   -  操作数栈顶的值为 `5`。

   **对应的指令处理函数（假设是 `r2r_I32Add`）：**

   ```c++
   INSTRUCTION_HANDLER_FUNC r2r_I32Add(const uint8_t* code, uint32_t* sp,
                                       WasmInterpreterRuntime* wasm_runtime,
                                       int64_t r0, double fp0) {
     uint32_t rval = static_cast<uint32_t>(r0);
     uint32_t lval = pop<uint32_t>(sp, code, wasm_runtime);
     r0 = static_cast<uint32_t>(lval + rval);
     NextOp();
   }
   ```

   **输出：**
   -  操作数栈顶元素被弹出。
   -  寄存器 `r0` 的值更新为 `15` (5 + 10)。
   -  程序计数器（由 `NextOp()` 更新，此处代码片段未显示）指向下一条指令。

* **用户常见的编程错误举例：**

   1. **除零错误：** 在进行除法或求余运算时，如果除数为零，会导致程序崩溃或产生意想不到的结果。这段代码中通过 `TRAP(TrapReason::kTrapDivByZero)` 和 `TRAP(TrapReason::kTrapRemByZero)` 显式地处理了这种情况。

      **WebAssembly 示例 (可能导致错误):**

      ```wasm
      (module
        (func (export "divide") (param $a i32) (param $b i32) (result i32)
          local.get $a
          local.get $b
          i32.div_s  ;; 有符号整数除法
        )
      )
      ```

      **如果 JavaScript 调用 `wasmModule.exports.divide(10, 0)`，就会触发除零错误。**

   2. **浮点数到整数转换的精度丢失或溢出：** 当将一个超出整数表示范围的浮点数转换为整数时，或者当浮点数的小数部分被截断时，会发生精度丢失或溢出。这段代码中通过 `!base::IsValueInRangeForNumericType` 和 `!is_inbounds` 来检查并处理了浮点数到整数转换时可能出现的 `TrapReason::kTrapFloatUnrepresentable` 错误。

      **WebAssembly 示例 (可能导致错误):**

      ```wasm
      (module
        (func (export "floatToInt") (param $f f64) (result i32)
          local.get $f
          i32.trunc_s/f64  ;; 将 f64 截断为有符号 i32
        )
      )
      ```

      **如果 JavaScript 调用 `wasmModule.exports.floatToInt(Number.MAX_SAFE_INTEGER + 1)`，由于 `Number.MAX_SAFE_INTEGER + 1` 无法安全地表示为 i32，可能会触发 `kTrapFloatUnrepresentable` 错误。**

**总结：**

这段代码是 V8 的 WebAssembly 解释器中负责执行各种基本运算的核心部分。它通过宏定义生成了大量的指令处理函数，涵盖了整数和浮点数的算术、位运算、比较运算以及类型转换。代码中也考虑了常见的运行时错误，例如除零和无法表示的浮点数转换。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第3部分，共15部分，请归纳一下它的功能

"""
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
                                   
"""


```