Response:
The user wants to understand the functionality of a specific V8 source code file: `v8/src/wasm/interpreter/wasm-interpreter.cc`. They've provided a snippet of this file and have several constraints:

1. **List Functionalities:** Describe what this code does.
2. **Torque Check:** Determine if the file is a Torque file based on its extension.
3. **JavaScript Relation:** If it's related to JavaScript functionality, provide a JavaScript example.
4. **Logic Inference:** If the code involves logic, give an example with input and output.
5. **Common Errors:**  If it relates to typical programming mistakes, illustrate with an example.
6. **Part of a Series:** This is part 13 of 15, so summarize its function within the larger context.

Let's break down the provided code snippet:

* **Macros:** The code heavily uses C++ macros like `FOREACH_ARITHMETIC_BINOP`, `EXECUTE_BINOP`, `EMIT_INSTR_HANDLER`, etc. This suggests it's implementing a dispatch mechanism or a code generation strategy based on different WebAssembly opcodes.
* **`switch (mode)`:**  The `switch (mode)` statements inside the macros hint at handling different register allocation or operand passing conventions (R2R, R2S, S2R, S2S).
* **`kExpr...` cases:** The `case kExpr...` lines clearly correspond to WebAssembly instruction opcodes (e.g., `kExprI32Add`, `kExprStructNew`, `kExprArrayGet`).
* **Stack Manipulation:**  Functions like `type##Pop()` and `type##Push()` suggest this code is working with a stack-based virtual machine or interpreter.
* **"EMIT_INSTR_HANDLER"**: This likely generates code or calls a handler function to execute the corresponding WebAssembly instruction.
* **GC Instructions:**  Presence of cases like `kExprStructNew`, `kExprArrayGet`, `kExprRefCast` indicates handling of WebAssembly's Garbage Collection features.

**Plan:**

1. **Functionalities:**  The core function is to interpret WebAssembly bytecode. It handles various instructions, including arithmetic, memory access, control flow, and GC operations.
2. **Torque Check:**  The file ends with `.cc`, not `.tq`, so it's not Torque.
3. **JavaScript Relation:**  This code is fundamental to *how* V8 executes WebAssembly, which is directly linked to JavaScript's ability to run WebAssembly modules. A simple JavaScript example would be loading and running a WebAssembly module.
4. **Logic Inference:**  Let's pick a simple binary operation like `kExprI32Add`. We can assume the stack holds two I32 values, and the operation adds them and pushes the result.
5. **Common Errors:** Type mismatches or stack underflow are potential errors this code implicitly helps manage (or would cause issues if not handled).
6. **Summary:** Given it's part 13 of 15 related to the interpreter, it's likely focusing on the core execution logic of WebAssembly instructions. Earlier parts probably handled parsing/compilation, and later parts might deal with optimizations or integration.

**Self-Correction:**  The `EMIT_INSTR_HANDLER` hints at something more than direct interpretation. It might be involved in generating machine code or some intermediate representation. However, since it's within the `interpreter` directory, the *primary* function is likely interpretation, potentially with some form of optimized dispatch or code emission. The "RegMode" also suggests register management within the interpreter. The focus seems to be on handling individual Wasm instructions.
基于您提供的代码片段，我们可以分析 `v8/src/wasm/interpreter/wasm-interpreter.cc` 的一些关键功能：

**主要功能：WebAssembly 字节码的解释执行**

这段代码是 V8 引擎中 WebAssembly 解释器的核心部分，负责执行 WebAssembly 模块中的各种指令。它通过一个大的 `switch` 语句来处理不同的 WebAssembly 操作码（`kExpr...`）。

**具体功能点：**

1. **二元运算 (Binary Operations)：**
   - 代码中定义了处理各种二元运算的宏 `FOREACH_ARITHMETIC_BINOP` 和 `FOREACH_MORE_BINOP`，例如加法、减法、乘法、比较等。
   - 它根据不同的操作数寄存器模式 (`mode`)（例如，寄存器到寄存器 `kR2R`，寄存器到栈 `kR2S`，栈到寄存器 `kS2R`，栈到栈 `kS2S`）选择不同的处理方式。
   - `EMIT_INSTR_HANDLER` 宏很可能用于调用具体的指令处理函数。

2. **可能触发陷阱的二元运算 (Trapping Binary Operations)：**
   - `FOREACH_TRAPPING_BINOP` 宏处理可能导致运行时错误的二元运算，例如除零错误。

3. **一元运算 (Unary Operations)：**
   - `FOREACH_SIMPLE_UNOP` 处理简单的的一元运算。
   - `FOREACH_ADDITIONAL_CONVERT_UNOP`, `FOREACH_OTHER_CONVERT_UNOP`, `FOREACH_REINTERPRET_UNOP`, `FOREACH_TRUNCSAT_UNOP`, `FOREACH_I64_CONVERT_FROM_FLOAT_UNOP`, `FOREACH_I32_CONVERT_FROM_FLOAT_UNOP`, `FOREACH_BITS_UNOP`, `FOREACH_EXTENSION_UNOP` 处理各种类型转换、位运算和符号扩展等一元运算。

4. **引用类型操作 (Reference Type Operations)：**
   - 处理 `kExprRefNull`（空引用）、`kExprRefIsNull`（判断是否为空引用）、`kExprRefFunc`（获取函数引用）、`kExprRefEq`（引用相等性比较）、`kExprRefAsNonNull`（断言非空引用）等操作。

5. **结构体操作 (Struct Operations)：**
   - 处理 `kExprStructNew`（创建结构体）、`kExprStructNewDefault`（创建默认值结构体）、`kExprStructGet`（获取结构体字段）、`kExprStructSet`（设置结构体字段）等操作。

6. **数组操作 (Array Operations)：**
   - 处理 `kExprArrayNew`（创建数组）、`kExprArrayNewFixed`（创建固定大小数组）、`kExprArrayNewDefault`（创建默认值数组）、`kExprArrayLen`（获取数组长度）、`kExprArrayGet`（获取数组元素）、`kExprArraySet`（设置数组元素）、`kExprArrayFill`（填充数组）、`kExprArrayCopy` (复制数组) 以及与 data 和 elem 段相关的数组初始化操作 (`kExprArrayNewData`, `kExprArrayNewElem`, `kExprArrayInitData`, `kExprArrayInitElem`)。

7. **I31 类型操作 (I31 Operations)：**
   - 处理 `kExprRefI31`（创建 i31 引用）、`kExprI31GetS` 和 `kExprI31GetU`（获取 i31 值）。

8. **类型转换和测试 (Type Conversion and Testing)：**
   - 处理 `kExprRefCast` 和 `kExprRefCastNull`（类型转换）、`kExprRefTest` 和 `kExprRefTestNull`（类型测试）。
   - 处理 `kExprAnyConvertExtern`（将内部引用转换为外部引用）和 `kExprExternConvertAny`（将外部引用转换为内部引用）。

9. **内存操作 (Memory Operations)：**
   - 处理 `kExprMemoryInit`（内存初始化）、`kExprDataDrop`（丢弃数据段）、`kExprMemoryCopy`（内存复制）、`kExprMemoryFill`（内存填充）。

10. **表操作 (Table Operations)：**
    - 处理 `kExprTableInit` (表初始化)。

**关于文件类型：**

`v8/src/wasm/interpreter/wasm-interpreter.cc` 的扩展名是 `.cc`，这表明它是一个 **C++ 源代码文件**。如果它的扩展名是 `.tq`，那它才是一个 V8 Torque 源代码文件。

**与 JavaScript 的关系：**

`v8/src/wasm/interpreter/wasm-interpreter.cc` 是 V8 引擎执行 WebAssembly 代码的核心组件之一。JavaScript 可以加载和执行 WebAssembly 模块。当 JavaScript 调用 WebAssembly 模块中的函数时，V8 引擎会使用这个解释器（或其他执行机制）来执行相应的 WebAssembly 指令。

**JavaScript 示例：**

```javascript
async function runWasm() {
  const response = await fetch('your_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  
Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第13部分，共15部分，请归纳一下它的功能

"""
##name);           \
        type##Pop();                              \
        type##Pop();                              \
        return RegMode::k##type##Reg;             \
      case kS2S:                                  \
        EMIT_INSTR_HANDLER(s2s_##name);           \
        type##Pop();                              \
        type##Pop();                              \
        type##Push();                             \
        return RegMode::kNoReg;                   \
    }                                             \
    break;                                        \
  }
      FOREACH_ARITHMETIC_BINOP(EXECUTE_BINOP)
      FOREACH_MORE_BINOP(EXECUTE_BINOP)
#undef EXECUTE_BINOP

#define EXECUTE_BINOP(name, ctype, reg, op, type)         \
  case kExpr##name: {                                     \
    switch (mode) {                                       \
      case kR2R:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2r_##name, instr.pc); \
        type##Pop();                                      \
        return RegMode::k##type##Reg;                     \
      case kR2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(r2s_##name, instr.pc); \
        type##Pop();                                      \
        type##Push();                                     \
        return RegMode::kNoReg;                           \
      case kS2R:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2r_##name, instr.pc); \
        type##Pop();                                      \
        type##Pop();                                      \
        return RegMode::k##type##Reg;                     \
      case kS2S:                                          \
        EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc); \
        type##Pop();                                      \
        type##Pop();                                      \
        type##Push();                                     \
        return RegMode::kNoReg;                           \
    }                                                     \
    break;                                                \
  }
      FOREACH_TRAPPING_BINOP(EXECUTE_BINOP)
#undef EXECUTE_BINOP

#define EXECUTE_UNOP(name, ctype, reg, op, type) \
  case kExpr##name: {                            \
    switch (mode) {                              \
      case kR2R:                                 \
        EMIT_INSTR_HANDLER(r2r_##name);          \
        return RegMode::k##type##Reg;            \
      case kR2S:                                 \
        EMIT_INSTR_HANDLER(r2s_##name);          \
        type##Push();                            \
        return RegMode::kNoReg;                  \
      case kS2R:                                 \
        EMIT_INSTR_HANDLER(s2r_##name);          \
        type##Pop();                             \
        return RegMode::k##type##Reg;            \
      case kS2S:                                 \
        EMIT_INSTR_HANDLER(s2s_##name);          \
        type##Pop();                             \
        type##Push();                            \
        return RegMode::kNoReg;                  \
    }                                            \
    break;                                       \
  }
      FOREACH_SIMPLE_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                     to_reg)                                                   \
  case kExpr##name: {                                                          \
    switch (mode) {                                                            \
      case kR2R:                                                               \
        EMIT_INSTR_HANDLER(r2r_##name);                                        \
        return RegMode::k##to_type##Reg;                                       \
      case kR2S:                                                               \
        EMIT_INSTR_HANDLER(r2s_##name);                                        \
        to_type##Push();                                                       \
        return RegMode::kNoReg;                                                \
      case kS2R:                                                               \
        EMIT_INSTR_HANDLER(s2r_##name);                                        \
        from_type##Pop();                                                      \
        return RegMode::k##to_type##Reg;                                       \
      case kS2S:                                                               \
        EMIT_INSTR_HANDLER(s2s_##name);                                        \
        from_type##Pop();                                                      \
        to_type##Push();                                                       \
        return RegMode::kNoReg;                                                \
    }                                                                          \
    break;                                                                     \
  }
      FOREACH_ADDITIONAL_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_OTHER_CONVERT_UNOP(EXECUTE_UNOP)
      FOREACH_REINTERPRET_UNOP(EXECUTE_UNOP)
      FOREACH_TRUNCSAT_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, from_reg, to_ctype, to_type, \
                     to_reg)                                                   \
  case kExpr##name: {                                                          \
    switch (mode) {                                                            \
      case kR2R:                                                               \
        EMIT_INSTR_HANDLER_WITH_PC(r2r_##name, instr.pc);                      \
        return RegMode::k##to_type##Reg;                                       \
      case kR2S:                                                               \
        EMIT_INSTR_HANDLER_WITH_PC(r2s_##name, instr.pc);                      \
        to_type##Push();                                                       \
        return RegMode::kNoReg;                                                \
      case kS2R:                                                               \
        EMIT_INSTR_HANDLER_WITH_PC(s2r_##name, instr.pc);                      \
        from_type##Pop();                                                      \
        return RegMode::k##to_type##Reg;                                       \
      case kS2S:                                                               \
        EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc);                      \
        from_type##Pop();                                                      \
        to_type##Push();                                                       \
        return RegMode::kNoReg;                                                \
    }                                                                          \
    break;                                                                     \
  }
      FOREACH_I64_CONVERT_FROM_FLOAT_UNOP(EXECUTE_UNOP)
      FOREACH_I32_CONVERT_FROM_FLOAT_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type, op) \
  case kExpr##name: {                                                    \
    switch (mode) {                                                      \
      case kR2R:                                                         \
        EMIT_INSTR_HANDLER(r2r_##name);                                  \
        return RegMode::k##to_type##Reg;                                 \
      case kR2S:                                                         \
        EMIT_INSTR_HANDLER(r2s_##name);                                  \
        to_type##Push();                                                 \
        return RegMode::kNoReg;                                          \
      case kS2R:                                                         \
        EMIT_INSTR_HANDLER(s2r_##name);                                  \
        from_type##Pop();                                                \
        return RegMode::k##to_type##Reg;                                 \
      case kS2S:                                                         \
        EMIT_INSTR_HANDLER(s2s_##name);                                  \
        from_type##Pop();                                                \
        to_type##Push();                                                 \
        return RegMode::kNoReg;                                          \
    }                                                                    \
    break;                                                               \
  }
      FOREACH_BITS_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

#define EXECUTE_UNOP(name, from_ctype, from_type, to_ctype, to_type) \
  case kExpr##name: {                                                \
    switch (mode) {                                                  \
      case kR2R:                                                     \
        EMIT_INSTR_HANDLER(r2r_##name);                              \
        return RegMode::k##to_type##Reg;                             \
      case kR2S:                                                     \
        EMIT_INSTR_HANDLER(r2s_##name);                              \
        to_type##Push();                                             \
        return RegMode::kNoReg;                                      \
      case kS2R:                                                     \
        EMIT_INSTR_HANDLER(s2r_##name);                              \
        from_type##Pop();                                            \
        return RegMode::k##to_type##Reg;                             \
      case kS2S:                                                     \
        EMIT_INSTR_HANDLER(s2s_##name);                              \
        from_type##Pop();                                            \
        to_type##Push();                                             \
        return RegMode::kNoReg;                                      \
    }                                                                \
    break;                                                           \
  }
      FOREACH_EXTENSION_UNOP(EXECUTE_UNOP)
#undef EXECUTE_UNOP

    case kExprRefNull: {
      EMIT_INSTR_HANDLER(s2s_RefNull);
      ValueType value_type =
          ValueType::RefNull(HeapType(instr.optional.ref_type));
      EmitI32Const(value_type.raw_bit_field());
      RefPush(value_type);
      break;
    }

    case kExprRefIsNull:
      EMIT_INSTR_HANDLER(s2s_RefIsNull);
      RefPop();
      I32Push();
      break;

    case kExprRefFunc: {
      EMIT_INSTR_HANDLER(s2s_RefFunc);
      EmitI32Const(instr.optional.index);
      ValueType value_type =
          ValueType::Ref(module_->functions[instr.optional.index].sig_index);
      RefPush(value_type);
      break;
    }

    case kExprRefEq:
      EMIT_INSTR_HANDLER(s2s_RefEq);
      RefPop();
      RefPop();
      I32Push();
      break;

    case kExprRefAsNonNull: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_RefAsNonNull, instr.pc);
      ValueType value_type = RefPop();
      RefPush(value_type);
      break;
    }

    case kExprStructNew: {
      EMIT_INSTR_HANDLER(s2s_StructNew);
      EmitI32Const(instr.optional.index);
      // Pops args
      const StructType* struct_type =
          module_->struct_type(instr.optional.gc_field_immediate.struct_index);
      for (uint32_t i = struct_type->field_count(); i > 0;) {
        i--;
        ValueKind kind = struct_type->field(i).kind();
        Pop(kind);
      }

      RefPush(ValueType::Ref(instr.optional.index));
      break;
    }

    case kExprStructNewDefault: {
      EMIT_INSTR_HANDLER(s2s_StructNewDefault);
      EmitI32Const(instr.optional.index);
      RefPush(ValueType::Ref(instr.optional.index));
      break;
    }

    case kExprStructGet:
    case kExprStructGetS:
    case kExprStructGetU: {
      bool is_signed = (instr.opcode == wasm::kExprStructGetS);
      const StructType* struct_type =
          module_->struct_type(instr.optional.gc_field_immediate.struct_index);
      uint32_t field_index = instr.optional.gc_field_immediate.field_index;
      ValueType value_type = struct_type->field(field_index);
      ValueKind kind = value_type.kind();
      int offset = StructFieldOffset(struct_type, field_index);
      switch (kind) {
        case kI8:
          if (is_signed) {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I8SStructGet, instr.pc);
          } else {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I8UStructGet, instr.pc);
          }
          RefPop();
          EmitI32Const(offset);
          I32Push();
          break;
        case kI16:
          if (is_signed) {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I16SStructGet, instr.pc);
          } else {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I16UStructGet, instr.pc);
          }
          RefPop();
          EmitI32Const(offset);
          I32Push();
          break;
        case kI32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I32StructGet, instr.pc);
          RefPop();
          EmitI32Const(offset);
          I32Push();
          break;
        case kI64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I64StructGet, instr.pc);
          RefPop();
          EmitI32Const(offset);
          I64Push();
          break;
        case kF32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F32StructGet, instr.pc);
          RefPop();
          EmitI32Const(offset);
          F32Push();
          break;
        case kF64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F64StructGet, instr.pc);
          RefPop();
          EmitI32Const(offset);
          F64Push();
          break;
        case kS128:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_S128StructGet, instr.pc);
          RefPop();
          EmitI32Const(offset);
          S128Push();
          break;
        case kRef:
        case kRefNull:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefStructGet, instr.pc);
          RefPop();
          EmitI32Const(offset);
          RefPush(value_type);
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprStructSet: {
      const StructType* struct_type =
          module_->struct_type(instr.optional.gc_field_immediate.struct_index);
      uint32_t field_index = instr.optional.gc_field_immediate.field_index;
      int offset = StructFieldOffset(struct_type, field_index);
      ValueKind kind = struct_type->field(field_index).kind();
      switch (kind) {
        case kI8:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I8StructSet, instr.pc);
          EmitI32Const(offset);
          I32Pop();
          break;
        case kI16:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I16StructSet, instr.pc);
          EmitI32Const(offset);
          I32Pop();
          break;
        case kI32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I32StructSet, instr.pc);
          EmitI32Const(offset);
          I32Pop();
          break;
        case kI64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I64StructSet, instr.pc);
          EmitI32Const(offset);
          I64Pop();
          break;
        case kF32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F32StructSet, instr.pc);
          EmitI32Const(offset);
          F32Pop();
          break;
        case kF64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F64StructSet, instr.pc);
          EmitI32Const(offset);
          F64Pop();
          break;
        case kS128:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_S128StructSet, instr.pc);
          EmitI32Const(offset);
          S128Pop();
          break;
        case kRef:
        case kRefNull:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefStructSet, instr.pc);
          EmitI32Const(offset);
          RefPop();
          break;
        default:
          UNREACHABLE();
      }
      RefPop();  // The object to set the field to.
      break;
    }

    case kExprArrayNew: {
      uint32_t array_index = instr.optional.gc_array_new_fixed.array_index;
      const ArrayType* array_type = module_->array_type(array_index);
      ValueType element_type = array_type->element_type();
      ValueKind kind = element_type.kind();

      // Pop a single value to be used to initialize the array.
      switch (kind) {
        case kI8:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I8ArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();  // Array length.
          I32Pop();  // Initialization value.
          break;
        case kI16:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I16ArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();
          I32Pop();
          break;
        case kI32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I32ArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();
          I32Pop();
          break;
        case kI64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I64ArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();
          I64Pop();
          break;
        case kF32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F32ArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();
          F32Pop();
          break;
        case kF64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F64ArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();
          F64Pop();
          break;
        case kS128:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_S128ArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();
          S128Pop();
          break;
        case kRef:
        case kRefNull:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefArrayNew, instr.pc);
          EmitI32Const(array_index);
          I32Pop();
          RefPop();
          break;
        default:
          UNREACHABLE();
      }
      RefPush(ValueType::Ref(array_index));  // Push the new array.
      break;
    }

    case kExprArrayNewFixed: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayNewFixed, instr.pc);
      uint32_t length = instr.optional.gc_array_new_fixed.length;
      uint32_t array_index = instr.optional.gc_array_new_fixed.array_index;
      EmitI32Const(array_index);
      EmitI32Const(length);
      const ArrayType* array_type = module_->array_type(array_index);
      ValueType element_type = array_type->element_type();
      ValueKind kind = element_type.kind();
      // Pop values to initialize the array.
      for (uint32_t i = 0; i < length; i++) {
        switch (kind) {
          case kI8:
          case kI16:
          case kI32:
            I32Pop();
            break;
          case kI64:
            I64Pop();
            break;
          case kF32:
            F32Pop();
            break;
          case kF64:
            F64Pop();
            break;
          case kS128:
            S128Pop();
            break;
          case kRef:
          case kRefNull:
            RefPop();
            break;
          default:
            UNREACHABLE();
        }
      }
      RefPush(ValueType::Ref(array_index));  // Push the new array.
      break;
    }

    case kExprArrayNewDefault: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayNewDefault, instr.pc);
      EmitI32Const(instr.optional.index);
      I32Pop();
      RefPush(ValueType::Ref(instr.optional.index));  // Push the new array.
      break;
    }

    case kExprArrayNewData: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayNewData, instr.pc);
      uint32_t array_index =
          instr.optional.gc_array_new_or_init_data.array_index;
      EmitI32Const(array_index);
      uint32_t data_index = instr.optional.gc_array_new_or_init_data.data_index;
      EmitI32Const(data_index);
      I32Pop();
      I32Pop();
      RefPush(ValueType::Ref(array_index));  // Push the new array.
      break;
    }

    case kExprArrayNewElem: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayNewElem, instr.pc);
      uint32_t array_index =
          instr.optional.gc_array_new_or_init_data.array_index;
      EmitI32Const(array_index);
      uint32_t data_index = instr.optional.gc_array_new_or_init_data.data_index;
      EmitI32Const(data_index);
      I32Pop();
      I32Pop();
      RefPush(ValueType::Ref(array_index));  // Push the new array.
      break;
    }

    case kExprArrayInitData: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayInitData, instr.pc);
      uint32_t array_index =
          instr.optional.gc_array_new_or_init_data.array_index;
      EmitI32Const(array_index);
      uint32_t data_index = instr.optional.gc_array_new_or_init_data.data_index;
      EmitI32Const(data_index);
      I32Pop();  // size
      I32Pop();  // src offset
      I32Pop();  // dest offset
      RefPop();  // array to initialize
      break;
    }

    case kExprArrayInitElem: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayInitElem, instr.pc);
      uint32_t array_index =
          instr.optional.gc_array_new_or_init_data.array_index;
      EmitI32Const(array_index);
      uint32_t data_index = instr.optional.gc_array_new_or_init_data.data_index;
      EmitI32Const(data_index);
      I32Pop();  // size
      I32Pop();  // src offset
      I32Pop();  // dest offset
      RefPop();  // array to initialize
      break;
    }

    case kExprArrayLen: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayLen, instr.pc);
      RefPop();
      I32Push();
      break;
    }

    case kExprArrayCopy: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_ArrayCopy, instr.pc);
      EmitI32Const(instr.optional.gc_array_copy.dest_array_index);
      EmitI32Const(instr.optional.gc_array_copy.src_array_index);
      I32Pop();  // size
      I32Pop();  // src offset
      RefPop();  // src array
      I32Pop();  // dest offset
      RefPop();  // dest array
      break;
    }

    case kExprArrayGet:
    case kExprArrayGetS:
    case kExprArrayGetU: {
      bool is_signed = (instr.opcode == wasm::kExprArrayGetS);
      const ArrayType* array_type = module_->array_type(instr.optional.index);
      ValueType element_type = array_type->element_type();
      ValueKind kind = element_type.kind();
      switch (kind) {
        case kI8:
          if (is_signed) {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I8SArrayGet, instr.pc);
          } else {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I8UArrayGet, instr.pc);
          }
          I32Pop();
          RefPop();
          I32Push();
          break;
        case kI16:
          if (is_signed) {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I16SArrayGet, instr.pc);
          } else {
            EMIT_INSTR_HANDLER_WITH_PC(s2s_I16UArrayGet, instr.pc);
          }
          I32Pop();
          RefPop();
          I32Push();
          break;
        case kI32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I32ArrayGet, instr.pc);
          I32Pop();
          RefPop();
          I32Push();
          break;
        case kI64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I64ArrayGet, instr.pc);
          I32Pop();
          RefPop();
          I64Push();
          break;
        case kF32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F32ArrayGet, instr.pc);
          I32Pop();
          RefPop();
          F32Push();
          break;
        case kF64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F64ArrayGet, instr.pc);
          I32Pop();
          RefPop();
          F64Push();
          break;
        case kS128:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_S128ArrayGet, instr.pc);
          I32Pop();
          RefPop();
          S128Push();
          break;
        case kRef:
        case kRefNull:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefArrayGet, instr.pc);
          I32Pop();
          RefPop();
          RefPush(element_type);
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprArraySet: {
      const ArrayType* array_type = module_->array_type(instr.optional.index);
      ValueKind kind = array_type->element_type().kind();
      switch (kind) {
        case kI8:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I8ArraySet, instr.pc);
          I32Pop();
          I32Pop();
          RefPop();
          break;
        case kI16:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I16ArraySet, instr.pc);
          I32Pop();
          I32Pop();
          RefPop();
          break;
        case kI32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I32ArraySet, instr.pc);
          I32Pop();
          I32Pop();
          RefPop();
          break;
        case kI64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I64ArraySet, instr.pc);
          I64Pop();
          I32Pop();
          RefPop();
          break;
        case kF32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F32ArraySet, instr.pc);
          F32Pop();
          I32Pop();
          RefPop();
          break;
        case kF64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F64ArraySet, instr.pc);
          F64Pop();
          I32Pop();
          RefPop();
          break;
        case kS128:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_S128ArraySet, instr.pc);
          S128Pop();
          I32Pop();
          RefPop();
          break;
        case kRef:
        case kRefNull:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefArraySet, instr.pc);
          RefPop();
          I32Pop();
          RefPop();
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprArrayFill: {
      const ArrayType* array_type = module_->array_type(instr.optional.index);
      ValueKind kind = array_type->element_type().kind();
      switch (kind) {
        case kI8:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I8ArrayFill, instr.pc);
          I32Pop();  // The size of the filled slice.
          I32Pop();  // The value with which to fill the array.
          I32Pop();  // The offset at which to begin filling.
          RefPop();  // The array to fill.
          break;
        case kI16:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I16ArrayFill, instr.pc);
          I32Pop();
          I32Pop();
          I32Pop();
          RefPop();
          break;
        case kI32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I32ArrayFill, instr.pc);
          I32Pop();
          I32Pop();
          I32Pop();
          RefPop();
          break;
        case kI64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_I64ArrayFill, instr.pc);
          I32Pop();
          I64Pop();
          I32Pop();
          RefPop();
          break;
        case kF32:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F32ArrayFill, instr.pc);
          I32Pop();
          F32Pop();
          I32Pop();
          RefPop();
          break;
        case kF64:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_F64ArrayFill, instr.pc);
          I32Pop();
          F64Pop();
          I32Pop();
          RefPop();
          break;
        case kS128:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_S128ArrayFill, instr.pc);
          I32Pop();
          S128Pop();
          I32Pop();
          RefPop();
          break;
        case kRef:
        case kRefNull:
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefArrayFill, instr.pc);
          I32Pop();
          RefPop();
          I32Pop();
          RefPop();
          break;
        default:
          UNREACHABLE();
      }
      break;
    }

    case kExprRefI31: {
      EMIT_INSTR_HANDLER(s2s_RefI31);
      I32Pop();
      RefPush(ValueType::Ref(HeapType::kI31));
      break;
    }

    case kExprI31GetS: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_I31GetS, instr.pc);
      RefPop();
      I32Push();
      break;
    }

    case kExprI31GetU: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_I31GetU, instr.pc);
      RefPop();
      I32Push();
      break;
    }

    case kExprRefCast:
    case kExprRefCastNull: {
      bool null_succeeds = (instr.opcode == kExprRefCastNull);
      HeapType target_type = instr.optional.gc_heap_type_immediate.type();
      ValueType resulting_value_type = ValueType::RefMaybeNull(
          target_type, null_succeeds ? kNullable : kNonNullable);

      ValueType obj_type = slots_[stack_.back()].value_type;
      DCHECK(obj_type.is_object_reference());

      // This logic ensures that code generation can assume that functions
      // can only be cast to function types, and data objects to data types.
      if (V8_UNLIKELY(TypeCheckAlwaysSucceeds(obj_type, target_type))) {
        if (obj_type.is_nullable() && !null_succeeds) {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_AssertNotNullTypecheck, instr.pc);
          ValueType value_type = RefPop();
          EmitI32Const(value_type.raw_bit_field());
          RefPush(resulting_value_type);
        } else {
          // Just forward the ref object.
        }
      } else if (V8_UNLIKELY(TypeCheckAlwaysFails(obj_type, target_type,
                                                  null_succeeds))) {
        // Unrelated types. The only way this will not trap is if the object
        // is null.
        if (obj_type.is_nullable() && null_succeeds) {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_AssertNullTypecheck, instr.pc);
          ValueType value_type = RefPop();
          EmitI32Const(value_type.raw_bit_field());
          RefPush(resulting_value_type);
        } else {
          // In this case we just trap.
          EMIT_INSTR_HANDLER_WITH_PC(s2s_TrapIllegalCast, instr.pc);
        }
      } else {
        if (instr.opcode == kExprRefCast) {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefCast, instr.pc);
        } else {
          EMIT_INSTR_HANDLER_WITH_PC(s2s_RefCastNull, instr.pc);
        }
        EmitI32Const(instr.optional.gc_heap_type_immediate.type_representation);
        ValueType value_type = RefPop();
        EmitI32Const(value_type.raw_bit_field());
        RefPush(resulting_value_type);
      }
      break;
    }

    case kExprRefTest:
    case kExprRefTestNull: {
      bool null_succeeds = (instr.opcode == kExprRefTestNull);
      HeapType target_type = instr.optional.gc_heap_type_immediate.type();

      ValueType obj_type = slots_[stack_.back()].value_type;
      DCHECK(obj_type.is_object_reference());

      // This logic ensures that code generation can assume that functions
      // can only be cast to function types, and data objects to data types.
      if (V8_UNLIKELY(TypeCheckAlwaysSucceeds(obj_type, target_type))) {
        // Type checking can still fail for null.
        if (obj_type.is_nullable() && !null_succeeds) {
          EMIT_INSTR_HANDLER(s2s_RefIsNonNull);
          RefPop();
          I32Push();  // bool
        } else {
          EMIT_INSTR_HANDLER(s2s_RefTestSucceeds);
          RefPop();
          I32Push();  // bool=true
        }
      } else if (V8_UNLIKELY(TypeCheckAlwaysFails(obj_type, target_type,
                                                  null_succeeds))) {
        EMIT_INSTR_HANDLER(s2s_RefTestFails);
        RefPop();
        I32Push();  // bool=false
      } else {
        if (instr.opcode == kExprRefTest) {
          EMIT_INSTR_HANDLER(s2s_RefTest);
        } else {
          EMIT_INSTR_HANDLER(s2s_RefTestNull);
        }
        EmitI32Const(instr.optional.gc_heap_type_immediate.type_representation);
        ValueType value_type = RefPop();
        EmitI32Const(value_type.raw_bit_field());
        I32Push();  // bool
      }
      break;
    }

    case kExprAnyConvertExtern: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_AnyConvertExtern, instr.pc);
      ValueType extern_val = RefPop();
      ValueType intern_type = ValueType::RefMaybeNull(
          HeapType::kAny, Nullability(extern_val.is_nullable()));
      RefPush(intern_type);
      break;
    }

    case kExprExternConvertAny: {
      EMIT_INSTR_HANDLER(s2s_ExternConvertAny);
      ValueType value_type = RefPop();
      ValueType extern_type = ValueType::RefMaybeNull(
          HeapType::kExtern, Nullability(value_type.is_nullable()));
      RefPush(extern_type);
      break;
    }

    case kExprMemoryInit:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_MemoryInit, instr.pc);
      EmitI32Const(instr.optional.index);
      I32Pop();
      I32Pop();
      I32Pop();
      break;

    case kExprDataDrop:
      EMIT_INSTR_HANDLER(s2s_DataDrop);
      EmitI32Const(instr.optional.index);
      break;

    case kExprMemoryCopy:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_MemoryCopy, instr.pc);
      I32Pop();
      I32Pop();
      I32Pop();
      break;

    case kExprMemoryFill:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_MemoryFill, instr.pc);
      I32Pop();
      I32Pop();
      I32Pop();
      break;

    case kExprTableInit:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_TableInit, instr.pc);
      EmitI32Const(instr.optional.table_init.table_index);

"""


```