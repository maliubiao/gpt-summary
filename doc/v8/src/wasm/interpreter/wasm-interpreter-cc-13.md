Response:
Let's break down the thought process for analyzing this V8 code snippet.

1. **Understanding the Context:** The prompt states this is a snippet from `v8/src/wasm/interpreter/wasm-interpreter.cc`, specifically the 14th of 15 parts. This immediately tells us we're dealing with the *interpreter* for WebAssembly within V8. The `.cc` extension confirms it's C++ code. The "part 14 of 15" suggests we're nearing the end of a large function or a logical block handling specific operations.

2. **Initial Code Scan and Pattern Recognition:** The code consists of a large `switch` statement based on `instr.opcode`. Inside each `case`, we see calls to `EMIT_INSTR_HANDLER` (sometimes with `_WITH_PC`), followed by operations that manipulate a stack (e.g., `I32Pop`, `I32Push`, `S128Push`, `RefPop`). Constants are often pushed onto the stack using `EmitI32Const`, `EmitI64Const`, or by creating constant slots using `PushConstSlot`.

3. **Focusing on the `case` Labels:**  The `case` labels (e.g., `kExprElemDrop`, `kExprTableCopy`, `kExprAtomicNotify`, `kExprI32AtomicWait`, and numerous `kExpr...` for SIMD operations) are the most informative part. They directly correspond to WebAssembly instructions. This is the primary clue to the code's functionality.

4. **Deconstructing a Single `case`:** Let's take `kExprElemDrop` as an example:
   - `EMIT_INSTR_HANDLER(s2s_ElemDrop);`: This likely calls a function (`s2s_ElemDrop`) responsible for the core logic of the `elem.drop` instruction within the interpreter. The `s2s_` prefix probably means "stack-to-stack" operation.
   - `EmitI32Const(instr.optional.index);`: This pushes an integer constant onto the stack. `instr.optional.index` likely holds the index of the element segment to drop.

5. **Identifying Common Themes:**  As we examine more cases, patterns emerge:
   - **Table Operations:**  `kExprTableCopy`, `kExprTableGrow`, `kExprTableSize`, `kExprTableFill` clearly deal with WebAssembly tables.
   - **Atomic Operations:** `kExprAtomicNotify`, `kExprI32AtomicWait`, `kExprI64AtomicWait`, `kExprAtomicFence`, and the `FOREACH_ATOMIC_*` macros indicate support for WebAssembly's atomics feature for shared memory concurrency.
   - **SIMD Operations:** A large portion of the code is dedicated to `kExpr...` instructions related to SIMD (Single Instruction, Multiple Data) operations. These include arithmetic, logical, comparison, lane manipulation, and conversions on vectors of different data types (e.g., `F64x2`, `F32x4`, `I32x4`). The `S128Push` and `S128Pop` clearly indicate the manipulation of 128-bit SIMD values.

6. **Inferring the Role of `EMIT_INSTR_HANDLER`:**  This macro likely encapsulates the common setup or bookkeeping required before or after executing the specific WebAssembly instruction's logic. The `_WITH_PC` variant probably passes the program counter, useful for debugging or exception handling.

7. **Understanding the Stack Operations:** The `I32Pop`, `I32Push`, `RefPop`, `S128Pop`, `S128Push` calls suggest a stack-based architecture for the interpreter. Operands are pushed onto the stack, the instruction operates on them, and the result is pushed back.

8. **Considering the "Torque" Aspect:** The prompt mentions ".tq" files and Torque. Based on the provided C++ code, this file isn't a `.tq` file. Torque is a V8-specific language for generating runtime code, often used for performance-critical parts. The interpreter itself is typically written in C++.

9. **JavaScript Relationship (and Example):** WebAssembly code is often loaded and executed within a JavaScript environment. The instructions in this code snippet directly correspond to operations that a JavaScript program might trigger when interacting with a WebAssembly module. For example, `kExprTableCopy` relates to the `Table.copy()` method in the WebAssembly JavaScript API.

10. **Code Logic Inference and Assumptions:**  For `kExprTableCopy`, we can infer:
    - *Input:* The stack contains the destination table index, the source table index, the starting offset in the destination table, the starting offset in the source table, and the number of elements to copy.
    - *Output:*  The `EMIT_INSTR_HANDLER` likely performs the actual memory copying. The pops indicate the consumption of input values from the stack.

11. **Common Programming Errors:** For atomic operations like `kExprAtomicNotify`, a common error is providing an incorrect memory address or offset, leading to crashes or unexpected behavior. For SIMD operations, type mismatches or incorrect lane indices are frequent errors.

12. **Synthesizing the Functionality (Part 14 Summary):** Given that this is part 14 of 15, it's likely covering a specific *group* of WebAssembly instructions. The heavy presence of SIMD and atomic operations suggests this section is dedicated to handling these more advanced features of WebAssembly.

13. **Final Review:** Read through the analysis, ensuring it directly addresses all points in the prompt and provides clear explanations and examples. Make sure the language is precise and avoids unnecessary jargon.
好的，让我们来分析一下这段 V8 源代码片段的功能。

**1. 功能概述**

这段代码是 V8 的 WebAssembly 解释器 (`wasm-interpreter.cc`) 中处理多种 WebAssembly 指令的 `switch` 语句的一部分。具体来说，它负责解释和执行以下类型的指令：

* **表操作指令 (Table Operations):**  例如 `table.init`, `elem.drop`, `table.copy`, `table.grow`, `table.size`, `table.fill`。这些指令用于操作 WebAssembly 模块中的表（`Table`），表是存储引用类型元素的结构。
* **原子操作指令 (Atomic Operations):** 例如 `atomic.notify`, `i32.atomic.wait`, `i64.atomic.wait`, `atomic.fence` 以及各种原子读、写、比较交换等操作。 这些指令用于在共享内存多线程环境中进行同步和原子访问。
* **SIMD 指令 (SIMD Operations):**  大量的 `kExpr...` 开头的 `case` 分支处理各种 SIMD (Single Instruction, Multiple Data) 指令。这些指令允许并行地对多个数据元素执行相同的操作，从而提高性能。包括：
    * **创建 SIMD 值:** `f64x2.splat`, `f32x4.splat`, `i32x4.const` 等。
    * **访问 SIMD 元素:** `f64x2.extract_lane`, `i32x4.replace_lane` 等。
    * **SIMD 算术和逻辑运算:** `f64x2.add`, `i32x4.sub`, `s128.and`, `s128.or` 等。
    * **SIMD 比较运算:** `f64x2.eq`, `i32x4.gt_s` 等。
    * **SIMD 位移运算:** `i64x2.shl`, `i32x4.shr_u` 等。
    * **SIMD 类型转换和打包解包:** `f32x4.convert_i32x4_s`, `i16x8.pack_i32x4_s` 等。
    * **SIMD 选择操作:** `v128.select` 等。
    * **SIMD 点积运算:** `i32x4.dot_i16x8_s`。
    * **SIMD 洗牌 (shuffle) 和混合 (swizzle) 操作:** `i8x16.shuffle`, `i8x16.swizzle`。
    * **SIMD 归约操作:** `i64x2.all_true`, `i32x4.any_true`。
    * **SIMD 融合乘加/减 (fused multiply-add/subtract) 操作:** `f32x4.qfma`, `f64x2.qfms`。
    * **SIMD 加载和存储:** `s128.load`, `s128.store`, `s128.load8_splat` 等。

**2. 关于 .tq 文件**

如果 `v8/src/wasm/interpreter/wasm-interpreter.cc` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**文件。Torque 是一种 V8 内部使用的领域特定语言，用于生成高效的 C++ 代码，通常用于实现 JavaScript 内置函数和一些性能关键的运行时部分。

**但实际上， `wasm-interpreter.cc` 是一个 C++ 文件，而不是 Torque 文件。**  Torque 文件通常用于更底层的、与 JavaScript 运行时更紧密相关的部分。解释器通常用 C++ 实现。

**3. 与 JavaScript 的关系 (及示例)**

这段代码直接负责解释 WebAssembly 指令，而 WebAssembly 模块通常在 JavaScript 环境中加载和执行。因此，这段代码的功能与 JavaScript 代码有着密切的关系。

**JavaScript 示例：**

假设有一个 WebAssembly 模块定义了一个表和一个函数来初始化表中的元素：

```javascript
// JavaScript 代码
const wasmCode = `
  (module
    (table (ref null) 10)
    (func $init_table (param $idx i32) (param $val funcref)
      (table.set 0 (local.get $idx) (local.get $val))
    )
    (export "init_table" (func $init_table))
  )
`;

const wasmModule = new WebAssembly.Module(Uint8Array.from(atob(wasmCode), c => c.charCodeAt(0)));
const wasmInstance = new WebAssembly.Instance(wasmModule);

const myFunc = () => console.log("Hello from WASM table!");

// 调用 WebAssembly 的初始化函数，这将触发 wasm-interpreter.cc 中的 table.set 指令的执行
wasmInstance.exports.init_table(5, myFunc);
```

在这个例子中，当 JavaScript 调用 `wasmInstance.exports.init_table(5, myFunc)` 时，WebAssembly 解释器（其中就包括 `wasm-interpreter.cc`）会执行 `table.set` 指令，该指令对应的逻辑就在这段 C++ 代码中处理。

**SIMD 指令的 JavaScript 映射：**

```javascript
// JavaScript 代码
const wasmCodeSIMD = `
  (module
    (func $add_vectors (param $a v128) (param $b v128) (result v128)
      (v128.add.i32x4 (local.get $a) (local.get $b))
    )
    (export "add_vectors" (func $add_vectors))
  )
`;

const wasmModuleSIMD = new WebAssembly.Module(Uint8Array.from(atob(wasmCodeSIMD), c => c.charCodeAt(0)));
const wasmInstanceSIMD = new WebAssembly.Instance(wasmModuleSIMD);

const vectorA = new Uint32Array([1, 2, 3, 4]);
const vectorB = new Uint32Array([5, 6, 7, 8]);

const wasmVectorA = new WebAssembly.I32x4(vectorA[0], vectorA[1], vectorA[2], vectorA[3]);
const wasmVectorB = new WebAssembly.I32x4(vectorB[0], vectorB[1], vectorB[2], vectorB[3]);

// 调用 WebAssembly 的 SIMD 函数，这将触发 wasm-interpreter.cc 中的 v128.add.i32x4 指令的执行
const resultVector = wasmInstanceSIMD.exports.add_vectors(wasmVectorA, wasmVectorB);

console.log(resultVector); // 输出类似: I32x4 {0: 6, 1: 8, 2: 10, 3: 12}
```

当 JavaScript 调用 `wasmInstanceSIMD.exports.add_vectors` 并传入 `WebAssembly.I32x4` 类型的参数时，`wasm-interpreter.cc` 中的 `kExprI32x4Add` 分支的代码会被执行。

**4. 代码逻辑推理 (假设输入与输出)**

以 `kExprTableCopy` 指令为例：

**假设输入 (在解释器内部的栈上):**

* **栈顶:** 要复制的元素数量 (i32)
* **栈顶 - 1:** 源表中的起始索引 (i32)
* **栈顶 - 2:** 目标表中的起始索引 (i32)
* **栈顶 - 3:** 源表的索引 (i32)
* **栈顶 - 4:** 目标表的索引 (i32)

**代码逻辑:**

1. `EMIT_INSTR_HANDLER_WITH_PC(s2s_TableCopy, instr.pc);`:  调用处理 `table.copy` 指令的处理器函数 `s2s_TableCopy`，并传递程序计数器 `instr.pc`。这个函数会执行实际的表元素复制操作。
2. `EmitI32Const(instr.optional.table_copy.dst_table_index);`: 将目标表的索引推送到栈上 (虽然之后会被 `I32Pop()` 弹出，这可能是为了传递参数或作为中间状态)。
3. `EmitI32Const(instr.optional.table_copy.src_table_index);`: 将源表的索引推送到栈上 (同样，之后会被弹出)。
4. `I32Pop();`: 弹出栈顶元素 (元素数量)。
5. `I32Pop();`: 弹出栈顶元素 (源表中的起始索引)。
6. `I32Pop();`: 弹出栈顶元素 (目标表中的起始索引)。

**假设输出 (可能由 `s2s_TableCopy` 函数产生):**

* 如果复制成功，可能不会在栈上留下任何特定的返回值。
* 如果复制过程中发生错误（例如，索引越界），可能会触发异常或返回错误码（但这部分逻辑可能在 `s2s_TableCopy` 内部处理，而不是在这里的栈操作中体现）。

**注意:** 这里的 "输入" 和 "输出" 指的是解释器在执行该指令时操作的内部状态，特别是操作数栈。

**5. 涉及用户常见的编程错误 (示例)**

* **表操作指令:**
    * **索引越界:**  在使用 `table.set`、`table.get`、`table.copy` 等指令时，如果提供的索引超出了表的范围，会导致运行时错误。
        ```javascript
        // 假设表的大小是 10
        wasmInstance.exports.init_table(15, myFunc); // 错误：索引 15 超出范围
        ```
    * **类型不匹配:** 尝试将错误类型的引用设置到表中。
        ```javascript
        wasmInstance.exports.init_table(0, 123); // 错误：尝试将数字设置为 funcref
        ```
* **原子操作指令:**
    * **未对齐的内存访问:** 原子操作通常要求访问的内存地址是对齐的。未对齐的访问可能导致崩溃或未定义的行为。
    * **竞态条件 (Race Condition):** 在多线程环境下，如果没有正确地使用原子操作进行同步，可能会出现竞态条件，导致数据不一致。
* **SIMD 指令:**
    * **类型不匹配:**  对不同类型的 SIMD 值进行运算，例如尝试将 `f32x4` 和 `i32x4` 相加。
    * **通道 (Lane) 索引错误:**  在使用 `extract_lane` 或 `replace_lane` 等指令时，如果提供的通道索引超出了向量的维度，会导致错误。
    * **位移量过大:**  对于位移指令，位移量通常需要小于元素类型的位数。例如，对 `i32x4` 进行左移，位移量应小于 32。

**6. 功能归纳 (针对第 14 部分)**

考虑到这是 15 个部分中的第 14 部分，我们可以推断这一部分主要集中在处理 WebAssembly 中相对高级和复杂的功能：**表操作、原子操作和 SIMD 指令**。

这部分代码负责解释器执行这些特定指令时的行为，包括从操作数栈中获取操作数、调用相应的处理函数（例如 `s2s_TableCopy`），以及操作栈来产生或消费结果。

由于涉及原子操作和 SIMD，这一部分的功能对于支持并发编程和高性能计算至关重要。

总而言之，这段 `wasm-interpreter.cc` 的代码片段是 V8 的 WebAssembly 解释器的核心组成部分，负责将 WebAssembly 的高级指令转换为可以在 V8 内部执行的操作。第 14 部分尤其关注表操作、保证线程安全的原子操作以及利用硬件并行性的 SIMD 指令。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第14部分，共15部分，请归纳一下它的功能

"""
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