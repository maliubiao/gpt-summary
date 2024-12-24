Response: The user wants to understand the functionality of the C++ code snippet provided. The code seems to be part of a WebAssembly interpreter, specifically handling the execution of different WebAssembly instructions.

Here's a breakdown of the thought process to arrive at the answer:

1. **Identify the Core Structure:** The code uses a large `switch` statement based on `instr.opcode`. This immediately suggests it's dispatching execution to different handlers based on the type of WebAssembly instruction.

2. **Analyze the `case` blocks:** Each `case` corresponds to a specific WebAssembly instruction (e.g., `kExprI32Add`, `kExprF64Sqrt`, `kExprRefNull`, `kExprStructNew`).

3. **Recognize Common Patterns:**  Several macros like `EXECUTE_BINOP`, `EXECUTE_UNOP`, `ATOMIC_BINOP`, `BINOP_CASE`, `UNOP_CASE`, etc., are used. These macros generate similar code blocks for different operations, indicating a structured approach to handling instructions based on their type (binary, unary, atomic, SIMD).

4. **Focus on the Actions within `case` blocks:**  Inside each `case`, the code generally does the following:
    * Calls `EMIT_INSTR_HANDLER` (or `EMIT_INSTR_HANDLER_WITH_PC`). This suggests invoking a specific function or code sequence to perform the instruction's logic. The `_WITH_PC` variant likely includes the program counter for debugging or error reporting.
    * Manipulates a stack:  Calls to `Pop()`, `Push()`, `I32Pop()`, `F64Push()`, `RefPop()`, `S128Push()` indicate interaction with a stack data structure, which is common in interpreters for managing operands. The prefixes (e.g., `I32`, `F64`, `Ref`, `S128`) specify the data type being pushed or popped.
    * Emits constants: Calls to `EmitI32Const()` and `EmitI64Const()` suggest generating or placing constant values onto the stack or as part of the instruction handling.
    * Returns a `RegMode`:  The return value `RegMode::kNoReg` or `RegMode::kI32Reg` hints at register management or tracking the location of results (stack vs. register).

5. **Infer High-Level Functionality:** Based on the instruction opcodes and the actions within the `case` blocks, it's clear the code is responsible for:
    * **Arithmetic and Logical Operations:** Handling instructions like addition, subtraction, multiplication, division, bitwise operations.
    * **Memory Access:**  Dealing with loads (`LoadMem`), stores (`StoreMem`), and memory manipulation (`MemoryCopy`, `MemoryFill`).
    * **Control Flow (Implicit):** While not explicitly shown in this snippet, the interpreter as a whole manages control flow. This part focuses on the execution of individual instructions.
    * **Function Calls (Indirectly):** Instructions like `kExprCallFunction` would be handled elsewhere, but the setup for such calls (parameter passing via the stack) is evident.
    * **Data Type Handling:** The code is aware of various WebAssembly data types (i32, i64, f32, f64, references, SIMD vectors).
    * **Garbage Collection (GC) Related Operations:** Instructions like `kExprRefNull`, `kExprStructNew`, `kExprArrayNew`, `kExprRefCast` directly relate to object creation, manipulation, and type checking in a garbage-collected environment.
    * **SIMD (Single Instruction, Multiple Data) Operations:** The presence of `kExprF64x2Add`, `kExprI32x4Shl`, etc., and the `S128Push`/`S128Pop` calls indicate support for SIMD instructions for parallel processing.
    * **Atomic Operations:** Instructions prefixed with `kExprAtomic` manage shared memory access in multi-threaded scenarios.
    * **Table Operations:** Instructions like `kExprTableGet`, `kExprTableSet`, `kExprTableGrow` manage function tables.

6. **Connect to JavaScript (if applicable):**  Since this is part of V8, the connection to JavaScript is crucial. WebAssembly code is often executed within a JavaScript environment. Think about how JavaScript interacts with WebAssembly:
    * **Compilation and Execution:** JavaScript can compile and instantiate WebAssembly modules.
    * **Function Calls:** JavaScript can call WebAssembly functions, and vice-versa. The interpreter is the engine that runs the WebAssembly code when a JavaScript calls a WebAssembly function.
    * **Memory Sharing:** JavaScript and WebAssembly can share memory. Instructions like `kExprMemory...` are how WebAssembly interacts with this shared memory.
    * **Import/Export:** JavaScript provides imports to WebAssembly and consumes exports from it.

7. **Structure the Answer:** Organize the findings logically:
    * Start with a concise summary of the file's purpose.
    * Elaborate on the core functionality by listing the types of instructions handled.
    * Explain the relationship with JavaScript, using concrete examples of how JavaScript code would lead to the execution of these instructions.
    * Address the "part 7 of 8" aspect, indicating the file's role within the larger interpreter structure.

By following these steps, we can effectively analyze the code snippet and generate a comprehensive explanation of its functionality and its connection to JavaScript.
这个C++源代码文件 `wasm-interpreter.cc` 的第7部分，主要负责 **执行 WebAssembly 的各种指令 (opcodes)**。 它定义了当解释器遇到特定指令时应该执行的具体操作。

**更具体地说，这部分代码着重于处理以下类型的 WebAssembly 指令：**

* **数学和算术运算:**  例如加法 (`kExprI32Add`, `kExprF64Sub`)，乘法，除法，取模等。
* **位运算:** 例如与 (`kExprI32And`)，或，异或，移位等。
* **类型转换:**  例如将整数转换为浮点数 (`kExprF32ConvertI32S`)，扩展和截断操作。
* **引用类型操作:**  例如创建空引用 (`kExprRefNull`)，检查引用是否为空 (`kExprRefIsNull`)，获取函数引用 (`kExprRefFunc`)，引用相等性比较 (`kExprRefEq`)，类型转换 (`kExprRefCast`, `kExprRefCastNull`)，类型测试 (`kExprRefTest`, `kExprRefTestNull`)。
* **结构体操作:** 创建结构体 (`kExprStructNew`, `kExprStructNewDefault`)，获取结构体字段 (`kExprStructGet`, `kExprStructGetS`, `kExprStructGetU`)，设置结构体字段 (`kExprStructSet`)。
* **数组操作:** 创建数组 (`kExprArrayNew`, `kExprArrayNewFixed`, `kExprArrayNewDefault`, `kExprArrayNewData`, `kExprArrayNewElem`)，初始化数组 (`kExprArrayInitData`, `kExprArrayInitElem`)，获取数组长度 (`kExprArrayLen`)，复制数组 (`kExprArrayCopy`)，获取数组元素 (`kExprArrayGet`, `kExprArrayGetS`, `kExprArrayGetU`)，设置数组元素 (`kExprArraySet`)，填充数组 (`kExprArrayFill`)。
* **i31 类型操作:** 创建 i31 类型的引用 (`kExprRefI31`)，获取 i31 引用的值 (`kExprI31GetS`, `kExprI31GetU`)。
* **`anyref` 和 `externref` 转换:**  在 `anyref` (可以持有任何 wasm 引用) 和 `externref` (通常用于表示 JavaScript 对象) 之间进行转换 (`kExprAnyConvertExtern`, `kExprExternConvertAny`)。
* **内存操作:** 初始化内存段 (`kExprMemoryInit`)，丢弃数据段 (`kExprDataDrop`)，复制内存 (`kExprMemoryCopy`)，填充内存 (`kExprMemoryFill`)。
* **表操作:** 初始化表 (`kExprTableInit`)，丢弃元素段 (`kExprElemDrop`)，复制表 (`kExprTableCopy`)，增长表大小 (`kExprTableGrow`)，获取表大小 (`kExprTableSize`)，填充表 (`kExprTableFill`)。
* **原子操作:**  用于多线程环境中的原子操作，例如通知等待线程 (`kExprAtomicNotify`)，等待原子变量的值 (`kExprI32AtomicWait`, `kExprI64AtomicWait`)，原子栅栏 (`kExprAtomicFence`)，以及各种原子读-修改-写操作 (`kExprI32AtomicAdd`, `kExprI64AtomicLoad`).
* **SIMD (Single Instruction, Multiple Data) 操作:**  处理向量化运算，例如创建 SIMD 值 (`kExprF64x2Splat`, `kExprS128Const`)，提取通道 (`kExprF64x2ExtractLane`)，执行 SIMD 加减乘除比较等操作 (`kExprF64x2Add`, `kExprI32x4Eq`)，以及 SIMD 的加载和存储操作 (`kExprS128LoadMem`, `kExprS128StoreMem`)。

**与 JavaScript 的关系以及 JavaScript 示例：**

该文件是 V8 JavaScript 引擎中 WebAssembly 解释器的一部分。当 JavaScript 代码执行 WebAssembly 模块时，如果 V8 选择解释执行 (而不是编译成机器码)，那么这个文件中的代码会被调用来执行 WebAssembly 的指令。

例如，考虑以下 JavaScript 代码：

```javascript
const wasmCode = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0,  // wasm header
  10, 8, 1, 6, 0, 65, 10, 16, 0, // function section (add 10)
  3, 2, 1, 1,
  10, 5, 1, 3, 0, 6A, 0B        // code section (local.get 0, i32.const 10, i32.add, end)
]);
const wasmModule = new WebAssembly.Module(wasmCode);
const wasmInstance = new WebAssembly.Instance(wasmModule);
const result = wasmInstance.exports.add(5);
console.log(result); // 输出 15
```

在这个例子中，WebAssembly 代码定义了一个名为 `add` 的函数，它接受一个参数并加上 10。当 JavaScript 调用 `wasmInstance.exports.add(5)` 时，V8 引擎会执行以下步骤 (简化)：

1. **查找导出的函数 `add`。**
2. **准备调用栈和参数。**
3. **开始执行 `add` 函数的 WebAssembly 指令。**

在这个 `add` 函数的执行过程中，`wasm-interpreter.cc` 的第 7 部分会处理以下指令 (对应的十六进制代码):

* `00` (`local.get 0`):  这个指令会将局部变量 0 的值 (也就是 JavaScript 传递的参数 5) 推入栈中。这部分逻辑可能在其他文件中，但栈的操作与当前文件相关。
* `6A` (`i32.const 10`):  `wasm-interpreter.cc` 的 `case kExprI32Const:` 分支会被执行，将整数常量 10 推入栈中。 代码中会调用 `EmitI32Const(10)` 和 `I32Push()`。
* `6A` (`i32.add`): `wasm-interpreter.cc` 的 `case kExprI32Add:` 分支会被执行。 代码中会调用 `EMIT_INSTR_HANDLER(s2s_I32Add)`，然后 `I32Pop()` 两次 (弹出 10 和 5)，执行加法，并将结果 (15) 推入栈中 (`I32Push()`)。
* `0B` (`end`):  表示函数执行结束。

**总结来说，`wasm-interpreter.cc` 的第 7 部分是 V8 引擎中负责解释执行 WebAssembly 指令的核心组件之一。 它包含了大量针对不同 WebAssembly 指令的具体处理逻辑，使得 JavaScript 能够成功地运行 WebAssembly 代码。**

**关于 “这是第7部分，共8部分”：** 这暗示了 `wasm-interpreter.cc` 文件被拆分成了多个部分，可能是为了组织代码、提高可读性或方便并行开发。 第 7 部分专注于指令的执行逻辑，其他部分可能负责解释器的初始化、调用栈管理、错误处理等。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第7部分，共8部分，请归纳一下它的功能

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
      EmitI32Const(instr.optional.table_init.element_segment_index);
      I32Pop();
      I32Pop();
      I32Pop();
      break;

    case kExprElemDrop:
      EMIT_INSTR_HANDLER(s2s_ElemDrop);
      EmitI32Const(instr.optional.index);
      break;

    case kExprTableCopy:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_TableCopy, instr.pc);
      EmitI32Const(instr.optional.table_copy.dst_table_index);
      EmitI32Const(instr.optional.table_copy.src_table_index);
      I32Pop();
      I32Pop();
      I32Pop();
      break;

    case kExprTableGrow:
      EMIT_INSTR_HANDLER(s2s_TableGrow);
      EmitI32Const(instr.optional.index);
      I32Pop();
      RefPop();
      I32Push();
      break;

    case kExprTableSize:
      EMIT_INSTR_HANDLER(s2s_TableSize);
      EmitI32Const(instr.optional.index);
      I32Push();
      break;

    case kExprTableFill:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_TableFill, instr.pc);
      EmitI32Const(instr.optional.index);
      I32Pop();
      RefPop();
      I32Pop();
      break;

    case kExprAtomicNotify:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_AtomicNotify, instr.pc);
      I32Pop();  // val
      EmitI64Const(instr.optional.offset);
      I32Pop();  // memory index
      I32Push();
      break;

    case kExprI32AtomicWait:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_I32AtomicWait, instr.pc);
      I64Pop();  // timeout
      I32Pop();  // val
      EmitI64Const(instr.optional.offset);
      I32Pop();  // memory index
      I32Push();
      break;

    case kExprI64AtomicWait:
      EMIT_INSTR_HANDLER_WITH_PC(s2s_I64AtomicWait, instr.pc);
      I64Pop();  // timeout
      I64Pop();  // val
      EmitI64Const(instr.optional.offset);
      I32Pop();  // memory index
      I32Push();
      break;

    case kExprAtomicFence:
      EMIT_INSTR_HANDLER(s2s_AtomicFence);
      break;

#define ATOMIC_BINOP(name, Type, ctype, type, op_ctype, op_type, operation) \
  case kExpr##name: {                                                       \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc);                       \
    op_type##Pop();                                                         \
    EmitI64Const(instr.optional.offset);                                    \
    I32Pop();                                                               \
    op_type##Push();                                                        \
    return RegMode::kNoReg;                                                 \
  }
      FOREACH_ATOMIC_BINOP(ATOMIC_BINOP)
#undef ATOMIC_BINOP

#define ATOMIC_COMPARE_EXCHANGE_OP(name, Type, ctype, type, op_ctype, op_type) \
  case kExpr##name: {                                                          \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc);                          \
    op_type##Pop();                                                            \
    op_type##Pop();                                                            \
    EmitI64Const(instr.optional.offset);                                       \
    I32Pop();                                                                  \
    op_type##Push();                                                           \
    return RegMode::kNoReg;                                                    \
  }
      FOREACH_ATOMIC_COMPARE_EXCHANGE_OP(ATOMIC_COMPARE_EXCHANGE_OP)
#undef ATOMIC_COMPARE_EXCHANGE_OP

#define ATOMIC_LOAD_OP(name, Type, ctype, type, op_ctype, op_type) \
  case kExpr##name: {                                              \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc);              \
    EmitI64Const(instr.optional.offset);                           \
    I32Pop();                                                      \
    op_type##Push();                                               \
    return RegMode::kNoReg;                                        \
  }
      FOREACH_ATOMIC_LOAD_OP(ATOMIC_LOAD_OP)
#undef ATOMIC_LOAD_OP

#define ATOMIC_STORE_OP(name, Type, ctype, type, op_ctype, op_type) \
  case kExpr##name: {                                               \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_##name, instr.pc);               \
    op_type##Pop();                                                 \
    EmitI64Const(instr.optional.offset);                            \
    I32Pop();                                                       \
    return RegMode::kNoReg;                                         \
  }
      FOREACH_ATOMIC_STORE_OP(ATOMIC_STORE_OP)
#undef ATOMIC_STORE_OP

#define SPLAT_CASE(format, stype, valType, op_type, num) \
  case kExpr##format##Splat: {                           \
    EMIT_INSTR_HANDLER(s2s_Simd##format##Splat);         \
    op_type##Pop();                                      \
    S128Push();                                          \
    return RegMode::kNoReg;                              \
  }
      SPLAT_CASE(F64x2, float64x2, double, F64, 2)
      SPLAT_CASE(F32x4, float32x4, float, F32, 4)
      SPLAT_CASE(I64x2, int64x2, int64_t, I64, 2)
      SPLAT_CASE(I32x4, int32x4, int32_t, I32, 4)
      SPLAT_CASE(I16x8, int16x8, int32_t, I32, 8)
      SPLAT_CASE(I8x16, int8x16, int32_t, I32, 16)
#undef SPLAT_CASE

#define EXTRACT_LANE_CASE(format, stype, op_type, name) \
  case kExpr##format##ExtractLane: {                    \
    EMIT_INSTR_HANDLER(s2s_Simd##format##ExtractLane);  \
    /* emit 8 bits ? */                                 \
    EmitI16Const(instr.optional.simd_lane);             \
    S128Pop();                                          \
    op_type##Push();                                    \
    return RegMode::kNoReg;                             \
  }
      EXTRACT_LANE_CASE(F64x2, float64x2, F64, f64x2)
      EXTRACT_LANE_CASE(F32x4, float32x4, F32, f32x4)
      EXTRACT_LANE_CASE(I64x2, int64x2, I64, i64x2)
      EXTRACT_LANE_CASE(I32x4, int32x4, I32, i32x4)
#undef EXTRACT_LANE_CASE

#define EXTRACT_LANE_EXTEND_CASE(format, stype, name, sign, extended_type) \
  case kExpr##format##ExtractLane##sign: {                                 \
    EMIT_INSTR_HANDLER(s2s_Simd##format##ExtractLane##sign);               \
    /* emit 8 bits ? */                                                    \
    EmitI16Const(instr.optional.simd_lane);                                \
    S128Pop();                                                             \
    I32Push();                                                             \
    return RegMode::kNoReg;                                                \
  }
      EXTRACT_LANE_EXTEND_CASE(I16x8, int16x8, i16x8, S, int32_t)
      EXTRACT_LANE_EXTEND_CASE(I16x8, int16x8, i16x8, U, uint32_t)
      EXTRACT_LANE_EXTEND_CASE(I8x16, int8x16, i8x16, S, int32_t)
      EXTRACT_LANE_EXTEND_CASE(I8x16, int8x16, i8x16, U, uint32_t)
#undef EXTRACT_LANE_EXTEND_CASE

#define BINOP_CASE(op, name, stype, count, expr) \
  case kExpr##op: {                              \
    EMIT_INSTR_HANDLER(s2s_Simd##op);            \
    S128Pop();                                   \
    S128Pop();                                   \
    S128Push();                                  \
    return RegMode::kNoReg;                      \
  }
      BINOP_CASE(F64x2Add, f64x2, float64x2, 2, a + b)
      BINOP_CASE(F64x2Sub, f64x2, float64x2, 2, a - b)
      BINOP_CASE(F64x2Mul, f64x2, float64x2, 2, a * b)
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
      BINOP_CASE(F32x4Mul, f32x4, float32x4, 4, a * b)
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
      BINOP_CASE(S128And, i32x4, int32x4, 4, a & b)
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

#define UNOP_CASE(op, name, stype, count, expr) \
  case kExpr##op: {                             \
    EMIT_INSTR_HANDLER(s2s_Simd##op);           \
    S128Pop();                                  \
    S128Push();                                 \
    return RegMode::kNoReg;                     \
  }
      UNOP_CASE(F64x2Abs, f64x2, float64x2, 2, std::abs(a))
      UNOP_CASE(F64x2Neg, f64x2, float64x2, 2, -a)
      UNOP_CASE(F64x2Sqrt, f64x2, float64x2, 2, std::sqrt(a))
      UNOP_CASE(F64x2Ceil, f64x2, float64x2, 2,
                (AixFpOpWorkaround<double, &ceil>(a)))
      UNOP_CASE(F64x2Floor, f64x2, float64x2, 2,
                (AixFpOpWorkaround<double, &floor>(a)))
      UNOP_CASE(F64x2Trunc, f64x2, float64x2, 2,
                (AixFpOpWorkaround<double, &trunc>(a)))
      UNOP_CASE(F64x2NearestInt, f64x2, float64x2, 2,
                (AixFpOpWorkaround<double, &nearbyint>(a)))
      UNOP_CASE(F32x4Abs, f32x4, float32x4, 4, std::abs(a))
      UNOP_CASE(F32x4Neg, f32x4, float32x4, 4, -a)
      UNOP_CASE(F32x4Sqrt, f32x4, float32x4, 4, std::sqrt(a))
      UNOP_CASE(F32x4Ceil, f32x4, float32x4, 4,
                (AixFpOpWorkaround<float, &ceilf>(a)))
      UNOP_CASE(F32x4Floor, f32x4, float32x4, 4,
                (AixFpOpWorkaround<float, &floorf>(a)))
      UNOP_CASE(F32x4Trunc, f32x4, float32x4, 4,
                (AixFpOpWorkaround<float, &truncf>(a)))
      UNOP_CASE(F32x4NearestInt, f32x4, float32x4, 4,
                (AixFpOpWorkaround<float, &nearbyintf>(a)))
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

#define BITMASK_CASE(op, name, stype, count) \
  case kExpr##op: {                          \
    EMIT_INSTR_HANDLER(s2s_Simd##op);        \
    S128Pop();                               \
    I32Push();                               \
    return RegMode::kNoReg;                  \
  }
      BITMASK_CASE(I8x16BitMask, i8x16, int8x16, 16)
      BITMASK_CASE(I16x8BitMask, i16x8, int16x8, 8)
      BITMASK_CASE(I32x4BitMask, i32x4, int32x4, 4)
      BITMASK_CASE(I64x2BitMask, i64x2, int64x2, 2)
#undef BITMASK_CASE

#define CMPOP_CASE(op, name, stype, out_stype, count, expr) \
  case kExpr##op: {                                         \
    EMIT_INSTR_HANDLER(s2s_Simd##op);                       \
    S128Pop();                                              \
    S128Pop();                                              \
    S128Push();                                             \
    return RegMode::kNoReg;                                 \
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

#define REPLACE_LANE_CASE(format, name, stype, ctype, op_type) \
  case kExpr##format##ReplaceLane: {                           \
    EMIT_INSTR_HANDLER(s2s_Simd##format##ReplaceLane);         \
    /* emit 8 bits ? */                                        \
    EmitI16Const(instr.optional.simd_lane);                    \
    op_type##Pop();                                            \
    S128Pop();                                                 \
    S128Push();                                                \
    return RegMode::kNoReg;                                    \
  }
      REPLACE_LANE_CASE(F64x2, f64x2, float64x2, double, F64)
      REPLACE_LANE_CASE(F32x4, f32x4, float32x4, float, F32)
      REPLACE_LANE_CASE(I64x2, i64x2, int64x2, int64_t, I64)
      REPLACE_LANE_CASE(I32x4, i32x4, int32x4, int32_t, I32)
      REPLACE_LANE_CASE(I16x8, i16x8, int16x8, int32_t, I32)
      REPLACE_LANE_CASE(I8x16, i8x16, int8x16, int32_t, I32)
#undef REPLACE_LANE_CASE

    case kExprS128LoadMem: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_SimdS128LoadMem, instr.pc);
      EmitI64Const(instr.optional.offset);
      I32Pop();
      S128Push();
      return RegMode::kNoReg;
    }

    case kExprS128StoreMem: {
      EMIT_INSTR_HANDLER_WITH_PC(s2s_SimdS128StoreMem, instr.pc);
      S128Pop();
      EmitI64Const(instr.optional.offset);
      I32Pop();
      return RegMode::kNoReg;
    }

#define SHIFT_CASE(op, name, stype, count, expr) \
  case kExpr##op: {                              \
    EMIT_INSTR_HANDLER(s2s_Simd##op);            \
    I32Pop();                                    \
    S128Pop();                                   \
    S128Push();                                  \
    return RegMode::kNoReg;                      \
  }
      SHIFT_CASE(I64x2Shl, i64x2, int64x2, 2,
                 static_cast<uint64_t>(a) << (shift % 64))
      SHIFT_CASE(I64x2ShrS, i64x2, int64x2, 2, a >> (shift % 64))
      SHIFT_CASE(I64x2ShrU, i64x2, int64x2, 2,
                 static_cast<uint64_t>(a) >> (shift % 64))
      SHIFT_CASE(I32x4Shl, i32x4, int32x4, 4,
                 static_cast<uint32_t>(a) << (shift % 32))
      SHIFT_CASE(I32x4ShrS, i32x4, int32x4, 4, a >> (shift % 32))
      SHIFT_CASE(I32x4ShrU, i32x4, int32x4, 4,
                 static_cast<uint32_t>(a) >> (shift % 32))
      SHIFT_CASE(I16x8Shl, i16x8, int16x8, 8,
                 static_cast<uint16_t>(a) << (shift % 16))
      SHIFT_CASE(I16x8ShrS, i16x8, int16x8, 8, a >> (shift % 16))
      SHIFT_CASE(I16x8ShrU, i16x8, int16x8, 8,
                 static_cast<uint16_t>(a) >> (shift % 16))
      SHIFT_CASE(I8x16Shl, i8x16, int8x16, 16,
                 static_cast<uint8_t>(a) << (shift % 8))
      SHIFT_CASE(I8x16ShrS, i8x16, int8x16, 16, a >> (shift % 8))
      SHIFT_CASE(I8x16ShrU, i8x16, int8x16, 16,
                 static_cast<uint8_t>(a) >> (shift % 8))
#undef SHIFT_CASE

#define EXT_MUL_CASE(op)              \
  case kExpr##op: {                   \
    EMIT_INSTR_HANDLER(s2s_Simd##op); \
    S128Pop();                        \
    S128Pop();                        \
    S128Push();                       \
    return RegMode::kNoReg;           \
  }
      EXT_MUL_CASE(I16x8ExtMulLowI8x16S)
      EXT_MUL_CASE(I16x8ExtMulHighI8x16S)
      EXT_MUL_CASE(I16x8ExtMulLowI8x16U)
      EXT_MUL_CASE(I16x8ExtMulHighI8x16U)
      EXT_MUL_CASE(I32x4ExtMulLowI16x8S)
      EXT_MUL_CASE(I32x4ExtMulHighI16x8S)
      EXT_MUL_CASE(I32x4ExtMulLowI16x8U)
      EXT_MUL_CASE(I32x4ExtMulHighI16x8U)
      EXT_MUL_CASE(I64x2ExtMulLowI32x4S)
      EXT_MUL_CASE(I64x2ExtMulHighI32x4S)
      EXT_MUL_CASE(I64x2ExtMulLowI32x4U)
      EXT_MUL_CASE(I64x2ExtMulHighI32x4U)
#undef EXT_MUL_CASE

#define CONVERT_CASE(op, src_type, name, dst_type, count, start_index, ctype, \
                     expr)                                                    \
  case kExpr##op: {                                                           \
    EMIT_INSTR_HANDLER(s2s_Simd##op);                                         \
    S128Pop();                                                                \
    S128Push();                                                               \
    return RegMode::kNoReg;                                                   \
  }
      CONVERT_CASE(F32x4SConvertI32x4, int32x4, i32x4, float32x4, 4, 0, int32_t,
                   static_cast<float>(a))
      CONVERT_CASE(F32x4UConvertI32x4, int32x4, i32x4, float32x4, 4, 0,
                   uint32_t, static_cast<float>(a))
      CONVERT_CASE(I32x4SConvertF32x4, float32x4, f32x4, int32x4, 4, 0, float,
                   base::saturated_cast<int32_t>(a))
      CONVERT_CASE(I32x4UConvertF32x4, float32x4, f32x4, int32x4, 4, 0, float,
                   base::saturated_cast<uint32_t>(a))
      CONVERT_CASE(I32x4RelaxedTruncF32x4S, float32x4, f32x4, int32x4, 4, 0,
                   float, base::saturated_cast<int32_t>(a))
      CONVERT_CASE(I32x4RelaxedTruncF32x4U, float32x4, f32x4, int32x4, 4, 0,
                   float, base::saturated_cast<uint32_t>(a))
      CONVERT_CASE(I64x2SConvertI32x4Low, int32x4, i32x4, int64x2, 2, 0,
                   int32_t, a)
      CONVERT_CASE(I64x2SConvertI32x4High, int32x4, i32x4, int64x2, 2, 2,
                   int32_t, a)
      CONVERT_CASE(I64x2UConvertI32x4Low, int32x4, i32x4, int64x2, 2, 0,
                   uint32_t, a)
      CONVERT_CASE(I64x2UConvertI32x4High, int32x4, i32x4, int64x2, 2, 2,
                   uint32_t, a)
      CONVERT_CASE(I32x4SConvertI16x8High, int16x8, i16x8, int32x4, 4, 4,
                   int16_t, a)
      CONVERT_CASE(I32x4UConvertI16x8High, int16x8, i16x8, int32x4, 4, 4,
                   uint16_t, a)
      CONVERT_CASE(I32x4SConvertI16x8Low, int16x8, i16x8, int32x4, 4, 0,
                   int16_t, a)
      CONVERT_CASE(I32x4UConvertI16x8Low, int16x8, i16x8, int32x4, 4, 0,
                   uint16_t, a)
      CONVERT_CASE(I16x8SConvertI8x16High, int8x16, i8x16, int16x8, 8, 8,
                   int8_t, a)
      CONVERT_CASE(I16x8UConvertI8x16High, int8x16, i8x16, int16x8, 8, 8,
                   uint8_t, a)
      CONVERT_CASE(I16x8SConvertI8x16Low, int8x16, i8x16, int16x8, 8, 0, int8_t,
                   a)
      CONVERT_CASE(I16x8UConvertI8x16Low, int8x16, i8x16, int16x8, 8, 0,
                   uint8_t, a)
      CONVERT_CASE(F64x2ConvertLowI32x4S, int32x4, i32x4, float64x2, 2, 0,
                   int32_t, static_cast<double>(a))
      CONVERT_CASE(F64x2ConvertLowI32x4U, int32x4, i32x4, float64x2, 2, 0,
                   uint32_t, static_cast<double>(a))
      CONVERT_CASE(I32x4TruncSatF64x2SZero, float64x2, f64x2, int32x4, 2, 0,
                   double, base::saturated_cast<int32_t>(a))
      CONVERT_CASE(I32x4TruncSatF64x2UZero, float64x2, f64x2, int32x4, 2, 0,
                   double, base::saturated_cast<uint32_t>(a))
      CONVERT_CASE(I32x4RelaxedTruncF64x2SZero, float64x2, f64x2, int32x4, 2, 0,
                   double, base::saturated_cast<int32_t>(a))
      CONVERT_CASE(I32x4RelaxedTruncF64x2UZero, float64x2, f64x2, int32x4, 2, 0,
                   double, base::saturated_cast<uint32_t>(a))
      CONVERT_CASE(F32x4DemoteF64x2Zero, float64x2, f64x2, float32x4, 2, 0,
                   float, DoubleToFloat32(a))
      CONVERT_CASE(F64x2PromoteLowF32x4, float32x4, f32x4, float64x2, 2, 0,
                   float, static_cast<double>(a))
#undef CONVERT_CASE

#define PACK_CASE(op, src_type, name, dst_type, count, dst_ctype) \
  case kExpr##op: {                                               \
    EMIT_INSTR_HANDLER(s2s_Simd##op);                             \
    S128Pop();                                                    \
    S128Pop();                                                    \
    S128Push();                                                   \
    return RegMode::kNoReg;                                       \
  }
      PACK_CASE(I16x8SConvertI32x4, int32x4, i32x4, int16x8, 8, int16_t)
      PACK_CASE(I16x8UConvertI32x4, int32x4, i32x4, int16x8, 8, uint16_t)
      PACK_CASE(I8x16SConvertI16x8, int16x8, i16x8, int8x16, 16, int8_t)
      PACK_CASE(I8x16UConvertI16x8, int16x8, i16x8, int8x16, 16, uint8_t)
#undef PACK_CASE

#define SELECT_CASE(op)               \
  case kExpr##op: {                   \
    EMIT_INSTR_HANDLER(s2s_Simd##op); \
    S128Pop();                        \
    S128Pop();                        \
    S128Pop();                        \
    S128Push();                       \
    return RegMode::kNoReg;           \
  }
      SELECT_CASE(I8x16RelaxedLaneSelect)
      SELECT_CASE(I16x8RelaxedLaneSelect)
      SELECT_CASE(I32x4RelaxedLaneSelect)
      SELECT_CASE(I64x2RelaxedLaneSelect)
      SELECT_CASE(S128Select)
#undef SELECT_CASE

    case kExprI32x4DotI16x8S: {
      EMIT_INSTR_HANDLER(s2s_SimdI32x4DotI16x8S);
      S128Pop();
      S128Pop();
      S128Push();
      return RegMode::kNoReg;
    }

    case kExprS128Const: {
      PushConstSlot<Simd128>(
          simd_immediates_[instr.optional.simd_immediate_index]);
      return RegMode::kNoReg;
    }

    case kExprI16x8DotI8x16I7x16S: {
      EMIT_INSTR_HANDLER(s2s_SimdI16x8DotI8x16I7x16S);
      S128Pop();
      S128Pop();
      S128Push();
      return RegMode::kNoReg;
    }

    case kExprI32x4DotI8x16I7x16AddS: {
      EMIT_INSTR_HANDLER(s2s_SimdI32x4DotI8x16I7x16AddS);
      S128Pop();
      S128Pop();
      S128Pop();
      S128Push();
      return RegMode::kNoReg;
    }

    case kExprI8x16RelaxedSwizzle: {
      EMIT_INSTR_HANDLER(s2s_SimdI8x16RelaxedSwizzle);
      S128Pop();
      S128Pop();
      S128Push();
      return RegMode::kNoReg;
    }

    case kExprI8x16Swizzle: {
      EMIT_INSTR_HANDLER(s2s_SimdI8x16Swizzle);
      S128Pop();
      S128Pop();
      S128Push();
      return RegMode::kNoReg;
    }

    case kExprI8x16Shuffle: {
      uint32_t slot_index = CreateConstSlot(
          simd_immediates_[instr.optional.simd_immediate_index]);
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      TracePushConstSlot(slot_index);
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
      EMIT_INSTR_HANDLER(s2s_SimdI8x16Shuffle);
      PushSlot(slot_index);
      S128Pop();
      S128Pop();
      S128Pop();
      S128Push();
      return RegMode::kNoReg;
    }

    case kExprV128AnyTrue: {
      EMIT_INSTR_HANDLER(s2s_SimdV128AnyTrue);
      S128Pop();
      I32Push();
      return RegMode::kNoReg;
    }

#define REDUCTION_CASE(op, name, stype, count, operation) \
  case kExpr##op: {                                       \
    EMIT_INSTR_HANDLER(s2s_Simd##op);                     \
    S128Pop();                                            \
    I32Push();                                            \
    return RegMode::kNoReg;                               \
  }
      REDUCTION_CASE(I64x2AllTrue, i64x2, int64x2, 2, &)
      REDUCTION_CASE(I32x4AllTrue, i32x4, int32x4, 4, &)
      REDUCTION_CASE(I16x8AllTrue, i16x8, int16x8, 8, &)
      REDUCTION_CASE(I8x16AllTrue, i8x16, int8x16, 16, &)
#undef REDUCTION_CASE

#define QFM_CASE(op, name, stype, count, operation) \
  case kExpr##op: {                                 \
    EMIT_INSTR_HANDLER(s2s_Simd##op);               \
    S128Pop();                                      \
    S128Pop();                                      \
    S128Pop();                                      \
    S128Push();                                     \
    return RegMode::kNoReg;                         \
  }
      QFM_CASE(F32x4Qfma, f32x4, float32x4, 4, +)
      QFM_CASE(F32x4Qfms, f32x4, float32x4, 4, -)
      QFM_CASE(F64x2Qfma, f64x2, float64x2, 2, +)
      QFM_CASE(F64x2Qfms, f64x2, float64x2, 2, -)
#undef QFM_CASE

#define LOAD_SPLAT_CASE(op)                                 \
  case kExprS128##op: {                                     \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_SimdS128##op, instr.pc); \
    EmitI64Const(instr.optional.offset);                    \
    I32Pop();                                               \
    S128Push();                                             \
    return RegMode::kNoReg;                                 \
  }
      LOAD_SPLAT_CASE(Load8Splat)
      LOAD_SPLAT_CASE(Load16Splat)
      LOAD_SPLAT_CASE(Load32Splat)
      LOAD_SPLAT_CASE(Load64Splat)
#undef LOAD_SPLAT_CASE

#define LOAD_EXTEND_CASE(op)                                \
  case kExprS128##op: {                                     \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_SimdS128##op, instr.pc); \
    EmitI64Const(instr.optional.offset);                    \
    I32Pop();                                               \
    S128Push();                                             \
    return RegMode::kNoReg;                                 \
  }
      LOAD_EXTEND_CASE(Load8x8S)
      LOAD_EXTEND_CASE(Load8x8U)
      LOAD_EXTEND_CASE(Load16x4S)
      LOAD_EXTEND_CASE(Load16x4U)
      LOAD_EXTEND_CASE(Load32x2S)
      LOAD_EXTEND_CASE(Load32x2U)
#undef LOAD_EXTEND_CASE

#define LOAD_ZERO_EXTEND_CASE(op, load_type)                \
  case kExprS128##op: {                                     \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_SimdS128##op, instr.pc); \
    EmitI64Const(instr.optional.offset);                    \
    I32Pop();                                               \
    S128Push();                                             \
    return RegMode::kNoReg;                                 \
  }
      LOAD_ZERO_EXTEND_CASE(Load32Zero, I32)
      LOAD_ZERO_EXTEND_CASE(Load64Zero, I64)
#undef LOAD_ZERO_EXTEND_CASE

#define LOAD_LANE_CASE(op)                                   \
  case kExprS128##op: {                                      \
    EMIT_INSTR_HANDLER_WITH_PC(s2s_SimdS128##op, instr.pc);  \
    S128Pop();                                               \
    EmitI64Const(instr.optional.simd_loadstore_lane.offset); \
    I32Pop();                                                \
    /* emit 8 bits ? */                                      \
    EmitI16Const(instr.optional.simd_loadstore_lane.lane);   \
    S128Push();                                              \
    return RegMode::kNoReg;                           
"""


```