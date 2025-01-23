Response:
Let's break down the thought process for analyzing the provided C++ header file `wasm-opcodes.h`.

**1. Initial Skim and High-Level Understanding:**

The first step is a quick read-through to grasp the overall purpose. Keywords like "WebAssembly," "opcodes," and the structure of `#define FOREACH_*_OPCODE` macros immediately jump out. This suggests the file is about defining the instruction set for WebAssembly within the V8 JavaScript engine.

**2. Identifying Key Sections:**

The `#define FOREACH_*_OPCODE(V)` macros are the core of the file. Each macro represents a category of WebAssembly opcodes. I would mentally (or literally) list these categories:

* Control Flow
* Misc (Calls, Locals, Globals, Constants)
* Memory Loads
* Memory Stores
* Misc Memory
* Simple (Arithmetic, Logic, Comparisons)
* ASM.js Compatibility (Internal)
* SIMD (Single Instruction, Multiple Data)
* Relaxed SIMD

This categorization provides a functional overview of the WebAssembly instructions supported by V8.

**3. Analyzing the Macro Structure:**

The pattern `V(OpcodeName, HexCode, Signature, WATName)` is consistent across all the macros. This structure is crucial.

* `OpcodeName`: The internal name used within V8.
* `HexCode`: The byte code representation in the WebAssembly binary format.
* `Signature`: A shorthand for the input and output types of the opcode. The comments mention `i`, `l`, `f`, `d`, `s`, and `v`, which need to be mapped to their WebAssembly types (int32, int64, float32, float64, v128, void).
* `WATName`: The standard textual representation used in WebAssembly text format (WAT).

Understanding this structure is key to understanding the data within the file.

**4. Connecting to WebAssembly Concepts:**

With the categories and the macro structure understood, I would start connecting the opcodes to my knowledge of WebAssembly. For example:

* **Control Flow:**  `Block`, `Loop`, `If`, `Else`, `Br`, `Return` are fundamental control flow structures in WebAssembly.
* **Memory Access:** `I32LoadMem`, `I32StoreMem` clearly relate to reading and writing data to linear memory.
* **Arithmetic/Logic:** `I32Add`, `I32Sub`, `F32Mul`, `I64And`, etc., represent standard arithmetic and logical operations.
* **SIMD:** Opcodes starting with `S128` or having prefixes like `I8x16`, `F32x4` indicate support for SIMD operations, which operate on multiple data elements simultaneously.

**5. Addressing Specific Instructions:**

For specific instructions, I would consider:

* **Purpose:** What does this instruction do?
* **Inputs:** What data does it operate on?
* **Outputs:** What is the result?
* **Relationship to JavaScript:** Can this be directly mapped to a JavaScript operation? (Often, the answer is no for low-level opcodes, but higher-level concepts like function calls have parallels).

**6. Considering the "Torque" and JavaScript Aspects:**

The prompt asks about `.tq` files and JavaScript relevance.

* **`.tq` (Torque):**  If the file *were* `.tq`, it would indicate a higher-level language used within V8 for defining runtime built-ins. Since the file is `.h`, this part of the condition is false.
* **JavaScript Relevance:**  While the opcodes themselves are low-level, the *concepts* they represent are fundamental to JavaScript's execution when it interacts with WebAssembly. Calling a WebAssembly function from JavaScript involves these opcodes. Memory sharing between JavaScript and WebAssembly uses these load/store opcodes.

**7. Identifying Potential Programming Errors:**

Thinking about how these opcodes are used can reveal common errors:

* **Memory Access Errors:** Incorrect offsets or bounds when loading/storing.
* **Type Mismatches:** Providing the wrong type of data to an opcode.
* **Unreachable Code:**  Intentionally or unintentionally using the `Unreachable` opcode.
* **Divide by Zero:**  Applying division operations (`DivS`, `DivU`) with a zero divisor.

**8. Structuring the Output:**

Finally, organize the findings into a clear and logical structure, addressing each part of the prompt:

* **File Functionality:** Summarize the core purpose (defining WebAssembly opcodes).
* **Torque Check:** Explicitly state the file is not `.tq`.
* **JavaScript Relationship:** Explain the connection, even if indirect, and provide examples (function calls, memory).
* **Code Logic (with Assumptions):** Choose a simple opcode (like `I32Add`) and demonstrate its input/output.
* **Common Errors:** Provide concrete examples of mistakes related to WebAssembly programming.
* **Overall Function Summary:** Reiterate the primary role of the file.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just a list of opcodes."  **Correction:** It's a *structured* list with metadata (hex code, signature, WAT name), which is important.
* **Initial thought:** "These opcodes directly map to JavaScript." **Correction:**  They are lower-level. JavaScript interacts with WebAssembly *using* these opcodes at a lower level.
* **Realization:** The `FOREACH_*` macros are a code generation technique. The same definition is likely used to generate different data structures or code within V8.

By following these steps, combining knowledge of WebAssembly and V8 internals, and iteratively refining understanding, a comprehensive analysis of the `wasm-opcodes.h` file can be achieved.
好的，让我们来分析一下 `v8/src/wasm/wasm-opcodes.h` 这个文件。

**文件功能归纳：**

`v8/src/wasm/wasm-opcodes.h` 文件是 V8 引擎中用于定义 WebAssembly 操作码（opcodes）的头文件。它为 V8 的 WebAssembly 实现提供了所有可能的 WebAssembly 指令的枚举和相关信息。

**具体功能点：**

1. **定义 WebAssembly 操作码枚举：**  文件中使用大量的宏 (`#define FOREACH_*_OPCODE(V)`) 来定义不同类别的 WebAssembly 操作码。每个宏展开后会定义一系列以 `kExpr` 开头的常量，例如 `kExprUnreachable`，`kExprNop` 等。这些常量在 V8 的 WebAssembly 代码中被用来标识和处理不同的指令。

2. **关联操作码的二进制表示：** 每个操作码都与一个唯一的二进制值关联（例如 `Unreachable` 的二进制值是 `0x00`）。这对于 WebAssembly 模块的解码和执行至关重要。

3. **提供操作码的签名信息：**  宏定义中还包含操作码的签名信息，例如 `i_i`、`l_i`、`v_ii` 等。这些签名描述了操作码的输入和输出类型。例如，`i_i` 表示输入两个 `i32` 类型的值，输出一个 `i32` 类型的值。这里的 `i` 代表 `int32`， `l` 代表 `int64`， `f` 代表 `float32`， `d` 代表 `float64`， `v` 代表 `void`， `s` 代表 `v128`。

4. **提供操作码的 WAT (WebAssembly Text Format) 名称：**  每个操作码都有一个对应的文本格式名称，例如 "unreachable"、"nop" 等。这用于 WebAssembly 代码的文本表示，方便开发者阅读和编写。

5. **为不同类别的操作码分组：** 文件通过不同的 `FOREACH_*_OPCODE` 宏将操作码分成了不同的类别，例如控制流操作、内存操作、算术运算、SIMD 操作等，方便代码的组织和管理。

6. **支持扩展的常量表达式：** 文件中通过 `FOREACH_SIMPLE_EXTENDED_CONST_OPCODE` 定义了可以在常量表达式中使用的操作码。

7. **支持 ASM.js 兼容性：**  `FOREACH_ASMJS_COMPAT_OPCODE` 定义了一些为了兼容 ASM.js 而存在的操作码。

8. **支持 SIMD (Single Instruction, Multiple Data) 操作：** 文件中包含了大量的 `FOREACH_SIMD_*_OPCODE` 宏，定义了 WebAssembly 的 SIMD 指令集。

**关于文件后缀名和 Torque：**

根据描述，如果 `v8/src/wasm/wasm-opcodes.h` 以 `.tq` 结尾，那么它才是一个 V8 Torque 源代码文件。由于该文件后缀是 `.h`，所以它是一个标准的 C++ 头文件，而不是 Torque 文件。 Torque 是 V8 用于编写高效的内置函数的领域特定语言。

**与 JavaScript 的关系及示例：**

`v8/src/wasm/wasm-opcodes.h` 中定义的操作码是 WebAssembly 虚拟机执行的指令集。当你在 JavaScript 中加载并执行 WebAssembly 模块时，V8 引擎会解析 WebAssembly 字节码，并将其转换为这些操作码序列来执行。

例如，WebAssembly 中的 `i32.add` 操作码（对应 C++ 中的 `kExprI32Add`）执行的是两个 32 位整数的加法。在 JavaScript 中调用一个执行加法的 WebAssembly 函数时，引擎最终会执行到这个 `i32.add` 操作码。

```javascript
// 假设你有一个 WebAssembly 模块 instance，其中导出了一个名为 'add' 的函数
// 该函数接收两个 i32 类型的参数并返回它们的和

async function runWasm() {
  const response = await fetch('path/to/your/module.wasm'); // 替换为你的 wasm 文件路径
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const instance = module.instance;

  const result = instance.exports.add(5, 10);
  console.log(result); // 输出 15
}

runWasm();
```

在这个 JavaScript 例子中，当 `instance.exports.add(5, 10)` 被调用时，如果 `add` 函数的 WebAssembly 代码实现是执行两个输入的加法，那么 V8 引擎在执行该 WebAssembly 函数时会遇到并执行 `i32.add` 这个操作码。

**代码逻辑推理（假设）：**

假设我们有以下 WebAssembly 指令序列（简化表示）：

1. `local.get 0`  // 获取局部变量 0 的值
2. `i32.const 5`   // 将常量 5 推入栈
3. `i32.add`       // 执行加法，弹出栈顶两个值相加，结果推入栈
4. `return`        // 返回栈顶的值

**假设输入：** 局部变量 0 的值为 10。

**输出：** 函数返回值为 15。

**推理过程：**

1. 执行 `local.get 0`：将局部变量 0 的值（10）推入栈。 栈: `[10]`
2. 执行 `i32.const 5`：将常量 5 推入栈。 栈: `[10, 5]`
3. 执行 `i32.add`：从栈顶弹出 5 和 10，执行加法 10 + 5 = 15，将结果 15 推入栈。 栈: `[15]`
4. 执行 `return`：返回栈顶的值 15。

**用户常见的编程错误举例：**

1. **类型不匹配：** WebAssembly 是强类型语言。如果操作码期望接收特定类型的参数，但实际传入了不同类型的值，就会导致错误。例如，`i32.add` 期望两个 `i32`，如果尝试将一个 `f32` 和一个 `i32` 相加，就会出错。

   ```javascript
   // WebAssembly 侧如果定义了 add 函数接收两个 i32
   // 但 JavaScript 传递了浮点数，可能会导致类型错误
   instance.exports.add(1.5, 2); // 可能会导致 wasm 执行错误
   ```

2. **内存访问越界：** 当使用内存相关的操作码（如 `i32.load` 或 `i32.store`）时，如果提供的内存地址超出了 WebAssembly 线性内存的范围，会导致运行时错误。

   ```javascript
   // 假设 wasm 模块的内存大小有限
   const memory = new WebAssembly.Memory({ initial: 1 }); // 1 页内存
   // ...
   // 如果 wasm 代码尝试访问超出这块内存的地址，就会出错
   // 例如，尝试读取偏移量很大的数据
   // 错误示例（实际 wasm 代码会更复杂）：
   // i32.load offset=1000000  // 如果内存只有几页，这将越界
   ```

3. **栈溢出或下溢：**  在复杂的 WebAssembly 函数中，如果操作不当，可能会导致虚拟机栈溢出（push 过多数据）或下溢（pop 空栈）。

4. **整数溢出：**  对于有符号或无符号的整数运算，如果结果超出了其表示范围，可能会发生溢出，导致意想不到的结果。

   ```javascript
   // WebAssembly 中的整数运算可能发生溢出
   // 例如，i32.add 两个很大的正数，结果可能变成负数
   ```

**总结：**

`v8/src/wasm/wasm-opcodes.h` 文件在 V8 引擎的 WebAssembly 实现中扮演着核心角色，它定义了所有 WebAssembly 指令的规范，包括其二进制表示、类型签名和文本格式名称。这对于 V8 正确解析、编译和执行 WebAssembly 代码至关重要。理解这个文件的内容有助于深入了解 WebAssembly 的底层执行机制以及 V8 如何实现对 WebAssembly 的支持。

### 提示词
```
这是目录为v8/src/wasm/wasm-opcodes.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-opcodes.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_OPCODES_H_
#define V8_WASM_WASM_OPCODES_H_

#include <memory>

#include "src/common/globals.h"
#include "src/common/message-template.h"
#include "src/wasm/value-type.h"
#include "src/wasm/wasm-constants.h"

namespace v8 {
namespace internal {

namespace wasm {

struct WasmModule;

V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                           const FunctionSig& function);

V8_EXPORT_PRIVATE bool IsJSCompatibleSignature(const CanonicalSig* sig);

// Format of all opcode macros: kExprName, binary, signature, wat name

// Control expressions and blocks.
#define FOREACH_CONTROL_OPCODE(V)           \
  V(Unreachable, 0x00, _, "unreachable")    \
  V(Nop, 0x01, _, "nop")                    \
  V(Block, 0x02, _, "block")                \
  V(Loop, 0x03, _, "loop")                  \
  V(If, 0x04, _, "if")                      \
  V(Else, 0x05, _, "else")                  \
  V(Try, 0x06, _, "try")                    \
  V(Catch, 0x07, _, "catch")                \
  V(Throw, 0x08, _, "throw")                \
  V(Rethrow, 0x09, _, "rethrow")            \
  V(TryTable, 0x1f, _, "try_table")         \
  V(ThrowRef, 0x0a, _, "throw_ref")         \
  V(End, 0x0b, _, "end")                    \
  V(Br, 0x0c, _, "br")                      \
  V(BrIf, 0x0d, _, "br_if")                 \
  V(BrTable, 0x0e, _, "br_table")           \
  V(Return, 0x0f, _, "return")              \
  V(Delegate, 0x18, _, "delegate")          \
  V(CatchAll, 0x19, _, "catch_all")         \
  V(BrOnNull, 0xd5, _, "br_on_null")        \
  V(BrOnNonNull, 0xd6, _, "br_on_non_null") \
  V(NopForTestingUnsupportedInLiftoff, 0x16, _, "nop_for_testing")

// Constants, locals, globals, calls, etc.
#define FOREACH_MISC_OPCODE(V)                           \
  V(CallFunction, 0x10, _, "call")                       \
  V(CallIndirect, 0x11, _, "call_indirect")              \
  V(ReturnCall, 0x12, _, "return_call")                  \
  V(ReturnCallIndirect, 0x13, _, "return_call_indirect") \
  V(CallRef, 0x14, _, "call_ref")                        \
  V(ReturnCallRef, 0x15, _, "return_call_ref")           \
  V(Drop, 0x1a, _, "drop")                               \
  V(Select, 0x1b, _, "select")                           \
  V(SelectWithType, 0x1c, _, "select")                   \
  V(LocalGet, 0x20, _, "local.get")                      \
  V(LocalSet, 0x21, _, "local.set")                      \
  V(LocalTee, 0x22, _, "local.tee")                      \
  V(GlobalGet, 0x23, _, "global.get")                    \
  V(GlobalSet, 0x24, _, "global.set")                    \
  V(TableGet, 0x25, _, "table.get")                      \
  V(TableSet, 0x26, _, "table.set")                      \
  V(I32Const, 0x41, _, "i32.const")                      \
  V(I64Const, 0x42, _, "i64.const")                      \
  V(F32Const, 0x43, _, "f32.const")                      \
  V(F64Const, 0x44, _, "f64.const")                      \
  V(RefNull, 0xd0, _, "ref.null")                        \
  V(RefIsNull, 0xd1, _, "ref.is_null")                   \
  V(RefFunc, 0xd2, _, "ref.func")                        \
  V(RefAsNonNull, 0xd4, _, "ref.as_non_null")            \
  V(RefEq, 0xd3, _, "ref.eq")

// Load memory expressions.
#define FOREACH_LOAD_MEM_OPCODE(V)            \
  V(I32LoadMem, 0x28, i_i, "i32.load")        \
  V(I64LoadMem, 0x29, l_i, "i64.load")        \
  V(F32LoadMem, 0x2a, f_i, "f32.load")        \
  V(F64LoadMem, 0x2b, d_i, "f64.load")        \
  V(I32LoadMem8S, 0x2c, i_i, "i32.load8_s")   \
  V(I32LoadMem8U, 0x2d, i_i, "i32.load8_u")   \
  V(I32LoadMem16S, 0x2e, i_i, "i32.load16_s") \
  V(I32LoadMem16U, 0x2f, i_i, "i32.load16_u") \
  V(I64LoadMem8S, 0x30, l_i, "i64.load8_s")   \
  V(I64LoadMem8U, 0x31, l_i, "i64.load8_u")   \
  V(I64LoadMem16S, 0x32, l_i, "i64.load16_s") \
  V(I64LoadMem16U, 0x33, l_i, "i64.load16_u") \
  V(I64LoadMem32S, 0x34, l_i, "i64.load32_s") \
  V(I64LoadMem32U, 0x35, l_i, "i64.load32_u") \
  V(F32LoadMemF16, 0xfc30, f_i, "f32.load_f16")

// Store memory expressions.
#define FOREACH_STORE_MEM_OPCODE(V)           \
  V(I32StoreMem, 0x36, v_ii, "i32.store")     \
  V(I64StoreMem, 0x37, v_il, "i64.store")     \
  V(F32StoreMem, 0x38, v_if, "f32.store")     \
  V(F64StoreMem, 0x39, v_id, "f64.store")     \
  V(I32StoreMem8, 0x3a, v_ii, "i32.store8")   \
  V(I32StoreMem16, 0x3b, v_ii, "i32.store16") \
  V(I64StoreMem8, 0x3c, v_il, "i64.store8")   \
  V(I64StoreMem16, 0x3d, v_il, "i64.store16") \
  V(I64StoreMem32, 0x3e, v_il, "i64.store32") \
  V(F32StoreMemF16, 0xfc31, v_if, "f32.store_f16")

// Miscellaneous memory expressions
#define FOREACH_MISC_MEM_OPCODE(V)        \
  V(MemorySize, 0x3f, i_v, "memory.size") \
  V(MemoryGrow, 0x40, i_i, "memory.grow")

// Expressions with signatures.

// Opcodes that can also be used in constant expressions (via the 'extended
// constant expressions' proposal).
#define FOREACH_SIMPLE_EXTENDED_CONST_OPCODE(V) \
  V(I32Add, 0x6a, i_ii, "i32.add")              \
  V(I32Sub, 0x6b, i_ii, "i32.sub")              \
  V(I32Mul, 0x6c, i_ii, "i32.mul")              \
  V(I64Add, 0x7c, l_ll, "i64.add")              \
  V(I64Sub, 0x7d, l_ll, "i64.sub")              \
  V(I64Mul, 0x7e, l_ll, "i64.mul")

#define FOREACH_SIMPLE_NON_CONST_OPCODE(V)               \
  V(I32Eqz, 0x45, i_i, "i32.eqz")                        \
  V(I32Eq, 0x46, i_ii, "i32.eq")                         \
  V(I32Ne, 0x47, i_ii, "i32.ne")                         \
  V(I32LtS, 0x48, i_ii, "i32.lt_s")                      \
  V(I32LtU, 0x49, i_ii, "i32.lt_u")                      \
  V(I32GtS, 0x4a, i_ii, "i32.gt_s")                      \
  V(I32GtU, 0x4b, i_ii, "i32.gt_u")                      \
  V(I32LeS, 0x4c, i_ii, "i32.le_s")                      \
  V(I32LeU, 0x4d, i_ii, "i32.le_u")                      \
  V(I32GeS, 0x4e, i_ii, "i32.ge_s")                      \
  V(I32GeU, 0x4f, i_ii, "i32.ge_u")                      \
  V(I64Eqz, 0x50, i_l, "i64.eqz")                        \
  V(I64Eq, 0x51, i_ll, "i64.eq")                         \
  V(I64Ne, 0x52, i_ll, "i64.ne")                         \
  V(I64LtS, 0x53, i_ll, "i64.lt_s")                      \
  V(I64LtU, 0x54, i_ll, "i64.lt_u")                      \
  V(I64GtS, 0x55, i_ll, "i64.gt_s")                      \
  V(I64GtU, 0x56, i_ll, "i64.gt_u")                      \
  V(I64LeS, 0x57, i_ll, "i64.le_s")                      \
  V(I64LeU, 0x58, i_ll, "i64.le_u")                      \
  V(I64GeS, 0x59, i_ll, "i64.ge_s")                      \
  V(I64GeU, 0x5a, i_ll, "i64.ge_u")                      \
  V(F32Eq, 0x5b, i_ff, "f32.eq")                         \
  V(F32Ne, 0x5c, i_ff, "f32.ne")                         \
  V(F32Lt, 0x5d, i_ff, "f32.lt")                         \
  V(F32Gt, 0x5e, i_ff, "f32.gt")                         \
  V(F32Le, 0x5f, i_ff, "f32.le")                         \
  V(F32Ge, 0x60, i_ff, "f32.ge")                         \
  V(F64Eq, 0x61, i_dd, "f64.eq")                         \
  V(F64Ne, 0x62, i_dd, "f64.ne")                         \
  V(F64Lt, 0x63, i_dd, "f64.lt")                         \
  V(F64Gt, 0x64, i_dd, "f64.gt")                         \
  V(F64Le, 0x65, i_dd, "f64.le")                         \
  V(F64Ge, 0x66, i_dd, "f64.ge")                         \
  V(I32Clz, 0x67, i_i, "i32.clz")                        \
  V(I32Ctz, 0x68, i_i, "i32.ctz")                        \
  V(I32Popcnt, 0x69, i_i, "i32.popcnt")                  \
  V(I32DivS, 0x6d, i_ii, "i32.div_s")                    \
  V(I32DivU, 0x6e, i_ii, "i32.div_u")                    \
  V(I32RemS, 0x6f, i_ii, "i32.rem_s")                    \
  V(I32RemU, 0x70, i_ii, "i32.rem_u")                    \
  V(I32And, 0x71, i_ii, "i32.and")                       \
  V(I32Ior, 0x72, i_ii, "i32.or")                        \
  V(I32Xor, 0x73, i_ii, "i32.xor")                       \
  V(I32Shl, 0x74, i_ii, "i32.shl")                       \
  V(I32ShrS, 0x75, i_ii, "i32.shr_s")                    \
  V(I32ShrU, 0x76, i_ii, "i32.shr_u")                    \
  V(I32Rol, 0x77, i_ii, "i32.rotl")                      \
  V(I32Ror, 0x78, i_ii, "i32.rotr")                      \
  V(I64Clz, 0x79, l_l, "i64.clz")                        \
  V(I64Ctz, 0x7a, l_l, "i64.ctz")                        \
  V(I64Popcnt, 0x7b, l_l, "i64.popcnt")                  \
  V(I64DivS, 0x7f, l_ll, "i64.div_s")                    \
  V(I64DivU, 0x80, l_ll, "i64.div_u")                    \
  V(I64RemS, 0x81, l_ll, "i64.rem_s")                    \
  V(I64RemU, 0x82, l_ll, "i64.rem_u")                    \
  V(I64And, 0x83, l_ll, "i64.and")                       \
  V(I64Ior, 0x84, l_ll, "i64.or")                        \
  V(I64Xor, 0x85, l_ll, "i64.xor")                       \
  V(I64Shl, 0x86, l_ll, "i64.shl")                       \
  V(I64ShrS, 0x87, l_ll, "i64.shr_s")                    \
  V(I64ShrU, 0x88, l_ll, "i64.shr_u")                    \
  V(I64Rol, 0x89, l_ll, "i64.rotl")                      \
  V(I64Ror, 0x8a, l_ll, "i64.rotr")                      \
  V(F32Abs, 0x8b, f_f, "f32.abs")                        \
  V(F32Neg, 0x8c, f_f, "f32.neg")                        \
  V(F32Ceil, 0x8d, f_f, "f32.ceil")                      \
  V(F32Floor, 0x8e, f_f, "f32.floor")                    \
  V(F32Trunc, 0x8f, f_f, "f32.trunc")                    \
  V(F32NearestInt, 0x90, f_f, "f32.nearest")             \
  V(F32Sqrt, 0x91, f_f, "f32.sqrt")                      \
  V(F32Add, 0x92, f_ff, "f32.add")                       \
  V(F32Sub, 0x93, f_ff, "f32.sub")                       \
  V(F32Mul, 0x94, f_ff, "f32.mul")                       \
  V(F32Div, 0x95, f_ff, "f32.div")                       \
  V(F32Min, 0x96, f_ff, "f32.min")                       \
  V(F32Max, 0x97, f_ff, "f32.max")                       \
  V(F32CopySign, 0x98, f_ff, "f32.copysign")             \
  V(F64Abs, 0x99, d_d, "f64.abs")                        \
  V(F64Neg, 0x9a, d_d, "f64.neg")                        \
  V(F64Ceil, 0x9b, d_d, "f64.ceil")                      \
  V(F64Floor, 0x9c, d_d, "f64.floor")                    \
  V(F64Trunc, 0x9d, d_d, "f64.trunc")                    \
  V(F64NearestInt, 0x9e, d_d, "f64.nearest")             \
  V(F64Sqrt, 0x9f, d_d, "f64.sqrt")                      \
  V(F64Add, 0xa0, d_dd, "f64.add")                       \
  V(F64Sub, 0xa1, d_dd, "f64.sub")                       \
  V(F64Mul, 0xa2, d_dd, "f64.mul")                       \
  V(F64Div, 0xa3, d_dd, "f64.div")                       \
  V(F64Min, 0xa4, d_dd, "f64.min")                       \
  V(F64Max, 0xa5, d_dd, "f64.max")                       \
  V(F64CopySign, 0xa6, d_dd, "f64.copysign")             \
  V(I32ConvertI64, 0xa7, i_l, "i32.wrap_i64")            \
  V(I32SConvertF32, 0xa8, i_f, "i32.trunc_f32_s")        \
  V(I32UConvertF32, 0xa9, i_f, "i32.trunc_f32_u")        \
  V(I32SConvertF64, 0xaa, i_d, "i32.trunc_f64_s")        \
  V(I32UConvertF64, 0xab, i_d, "i32.trunc_f64_u")        \
  V(I64SConvertI32, 0xac, l_i, "i64.extend_i32_s")       \
  V(I64UConvertI32, 0xad, l_i, "i64.extend_i32_u")       \
  V(I64SConvertF32, 0xae, l_f, "i64.trunc_f32_s")        \
  V(I64UConvertF32, 0xaf, l_f, "i64.trunc_f32_u")        \
  V(I64SConvertF64, 0xb0, l_d, "i64.trunc_f64_s")        \
  V(I64UConvertF64, 0xb1, l_d, "i64.trunc_f64_u")        \
  V(F32SConvertI32, 0xb2, f_i, "f32.convert_i32_s")      \
  V(F32UConvertI32, 0xb3, f_i, "f32.convert_i32_u")      \
  V(F32SConvertI64, 0xb4, f_l, "f32.convert_i64_s")      \
  V(F32UConvertI64, 0xb5, f_l, "f32.convert_i64_u")      \
  V(F32ConvertF64, 0xb6, f_d, "f32.demote_f64")          \
  V(F64SConvertI32, 0xb7, d_i, "f64.convert_i32_s")      \
  V(F64UConvertI32, 0xb8, d_i, "f64.convert_i32_u")      \
  V(F64SConvertI64, 0xb9, d_l, "f64.convert_i64_s")      \
  V(F64UConvertI64, 0xba, d_l, "f64.convert_i64_u")      \
  V(F64ConvertF32, 0xbb, d_f, "f64.promote_f32")         \
  V(I32ReinterpretF32, 0xbc, i_f, "i32.reinterpret_f32") \
  V(I64ReinterpretF64, 0xbd, l_d, "i64.reinterpret_f64") \
  V(F32ReinterpretI32, 0xbe, f_i, "f32.reinterpret_i32") \
  V(F64ReinterpretI64, 0xbf, d_l, "f64.reinterpret_i64") \
  V(I32SExtendI8, 0xc0, i_i, "i32.extend8_s")            \
  V(I32SExtendI16, 0xc1, i_i, "i32.extend16_s")          \
  V(I64SExtendI8, 0xc2, l_l, "i64.extend8_s")            \
  V(I64SExtendI16, 0xc3, l_l, "i64.extend16_s")          \
  V(I64SExtendI32, 0xc4, l_l, "i64.extend32_s")

#define FOREACH_SIMPLE_OPCODE(V)          \
  FOREACH_SIMPLE_EXTENDED_CONST_OPCODE(V) \
  FOREACH_SIMPLE_NON_CONST_OPCODE(V)

#define FOREACH_SIMPLE_PROTOTYPE_OPCODE(V)

// For compatibility with Asm.js.
// These opcodes are not spec'ed (or visible) externally; the idea is
// to use unused ranges for internal purposes.
#define FOREACH_ASMJS_COMPAT_OPCODE(V)                         \
  V(F64Acos, 0xdc, d_d, "f64.acos")                            \
  V(F64Asin, 0xdd, d_d, "f64.asin")                            \
  V(F64Atan, 0xde, d_d, "f64.atan")                            \
  V(F64Cos, 0xdf, d_d, "f64.cos")                              \
  V(F64Sin, 0xe0, d_d, "f64.sin")                              \
  V(F64Tan, 0xe1, d_d, "f64.tan")                              \
  V(F64Exp, 0xe2, d_d, "f64.exp")                              \
  V(F64Log, 0xe3, d_d, "f64.log")                              \
  V(F64Atan2, 0xe4, d_dd, "f64.atan2")                         \
  V(F64Pow, 0xe5, d_dd, "f64.pow")                             \
  V(F64Mod, 0xe6, d_dd, "f64.mod")                             \
  V(I32AsmjsDivS, 0xe7, i_ii, "i32.asmjs_div_s")               \
  V(I32AsmjsDivU, 0xe8, i_ii, "i32.asmjs_div_u")               \
  V(I32AsmjsRemS, 0xe9, i_ii, "i32.asmjs_rem_s")               \
  V(I32AsmjsRemU, 0xea, i_ii, "i32.asmjs_rem_u")               \
  V(I32AsmjsLoadMem8S, 0xeb, i_i, "i32.asmjs_load8_s")         \
  V(I32AsmjsLoadMem8U, 0xec, i_i, "i32.asmjs_load8_u")         \
  V(I32AsmjsLoadMem16S, 0xed, i_i, "i32.asmjs_load16_s")       \
  V(I32AsmjsLoadMem16U, 0xee, i_i, "i32.asmjs_load16_u")       \
  V(I32AsmjsLoadMem, 0xef, i_i, "i32.asmjs_load32")            \
  V(F32AsmjsLoadMem, 0xf0, f_i, "f32.asmjs_load")              \
  V(F64AsmjsLoadMem, 0xf1, d_i, "f64.asmjs_load")              \
  V(I32AsmjsStoreMem8, 0xf2, i_ii, "i32.asmjs_store8")         \
  V(I32AsmjsStoreMem16, 0xf3, i_ii, "i32.asmjs_store16")       \
  V(I32AsmjsStoreMem, 0xf4, i_ii, "i32.asmjs_store")           \
  V(F32AsmjsStoreMem, 0xf5, f_if, "f32.asmjs_store")           \
  V(F64AsmjsStoreMem, 0xf6, d_id, "f64.asmjs_store")           \
  V(I32AsmjsSConvertF32, 0xf7, i_f, "i32.asmjs_convert_f32_s") \
  V(I32AsmjsUConvertF32, 0xf8, i_f, "i32.asmjs_convert_f32_u") \
  V(I32AsmjsSConvertF64, 0xf9, i_d, "i32.asmjs_convert_f64_s") \
  V(I32AsmjsUConvertF64, 0xfa, i_d, "i32.asmjs_convert_f64_u")

#define FOREACH_SIMD_MEM_OPCODE(V)                     \
  V(S128LoadMem, 0xfd00, s_i, "v128.load")             \
  V(S128Load8x8S, 0xfd01, s_i, "v128.load8x8_s")       \
  V(S128Load8x8U, 0xfd02, s_i, "v128.load8x8_u")       \
  V(S128Load16x4S, 0xfd03, s_i, "v128.load16x4_s")     \
  V(S128Load16x4U, 0xfd04, s_i, "v128.load16x4_u")     \
  V(S128Load32x2S, 0xfd05, s_i, "v128.load32x2_s")     \
  V(S128Load32x2U, 0xfd06, s_i, "v128.load32x2_u")     \
  V(S128Load8Splat, 0xfd07, s_i, "v128.load8_splat")   \
  V(S128Load16Splat, 0xfd08, s_i, "v128.load16_splat") \
  V(S128Load32Splat, 0xfd09, s_i, "v128.load32_splat") \
  V(S128Load64Splat, 0xfd0a, s_i, "v128.load64_splat") \
  V(S128StoreMem, 0xfd0b, v_is, "v128.store")          \
  V(S128Load32Zero, 0xfd5c, s_i, "v128.load32_zero")   \
  V(S128Load64Zero, 0xfd5d, s_i, "v128.load64_zero")

#define FOREACH_SIMD_MEM_1_OPERAND_OPCODE(V)            \
  V(S128Load8Lane, 0xfd54, s_is, "v128.load8_lane")     \
  V(S128Load16Lane, 0xfd55, s_is, "v128.load16_lane")   \
  V(S128Load32Lane, 0xfd56, s_is, "v128.load32_lane")   \
  V(S128Load64Lane, 0xfd57, s_is, "v128.load64_lane")   \
  V(S128Store8Lane, 0xfd58, v_is, "v128.store8_lane")   \
  V(S128Store16Lane, 0xfd59, v_is, "v128.store16_lane") \
  V(S128Store32Lane, 0xfd5a, v_is, "v128.store32_lane") \
  V(S128Store64Lane, 0xfd5b, v_is, "v128.store64_lane")

#define FOREACH_SIMD_CONST_OPCODE(V) V(S128Const, 0xfd0c, _, "v128.const")

#define FOREACH_SIMD_MASK_OPERAND_OPCODE(V) \
  V(I8x16Shuffle, 0xfd0d, s_ss, "i8x16.shuffle")

#define FOREACH_SIMD_MVP_0_OPERAND_OPCODE(V)                                 \
  V(I8x16Swizzle, 0xfd0e, s_ss, "i8x16.swizzle")                             \
  V(I8x16Splat, 0xfd0f, s_i, "i8x16.splat")                                  \
  V(I16x8Splat, 0xfd10, s_i, "i16x8.splat")                                  \
  V(I32x4Splat, 0xfd11, s_i, "i32x4.splat")                                  \
  V(I64x2Splat, 0xfd12, s_l, "i64x2.splat")                                  \
  V(F32x4Splat, 0xfd13, s_f, "f32x4.splat")                                  \
  V(F64x2Splat, 0xfd14, s_d, "f64x2.splat")                                  \
  V(I8x16Eq, 0xfd23, s_ss, "i8x16.eq")                                       \
  V(I8x16Ne, 0xfd24, s_ss, "i8x16.ne")                                       \
  V(I8x16LtS, 0xfd25, s_ss, "i8x16.lt_s")                                    \
  V(I8x16LtU, 0xfd26, s_ss, "i8x16.lt_u")                                    \
  V(I8x16GtS, 0xfd27, s_ss, "i8x16.gt_s")                                    \
  V(I8x16GtU, 0xfd28, s_ss, "i8x16.gt_u")                                    \
  V(I8x16LeS, 0xfd29, s_ss, "i8x16.le_s")                                    \
  V(I8x16LeU, 0xfd2a, s_ss, "i8x16.le_u")                                    \
  V(I8x16GeS, 0xfd2b, s_ss, "i8x16.ge_s")                                    \
  V(I8x16GeU, 0xfd2c, s_ss, "i8x16.ge_u")                                    \
  V(I16x8Eq, 0xfd2d, s_ss, "i16x8.eq")                                       \
  V(I16x8Ne, 0xfd2e, s_ss, "i16x8.ne")                                       \
  V(I16x8LtS, 0xfd2f, s_ss, "i16x8.lt_s")                                    \
  V(I16x8LtU, 0xfd30, s_ss, "i16x8.lt_u")                                    \
  V(I16x8GtS, 0xfd31, s_ss, "i16x8.gt_s")                                    \
  V(I16x8GtU, 0xfd32, s_ss, "i16x8.gt_u")                                    \
  V(I16x8LeS, 0xfd33, s_ss, "i16x8.le_s")                                    \
  V(I16x8LeU, 0xfd34, s_ss, "i16x8.le_u")                                    \
  V(I16x8GeS, 0xfd35, s_ss, "i16x8.ge_s")                                    \
  V(I16x8GeU, 0xfd36, s_ss, "i16x8.ge_u")                                    \
  V(I32x4Eq, 0xfd37, s_ss, "i32x4.eq")                                       \
  V(I32x4Ne, 0xfd38, s_ss, "i32x4.ne")                                       \
  V(I32x4LtS, 0xfd39, s_ss, "i32x4.lt_s")                                    \
  V(I32x4LtU, 0xfd3a, s_ss, "i32x4.lt_u")                                    \
  V(I32x4GtS, 0xfd3b, s_ss, "i32x4.gt_s")                                    \
  V(I32x4GtU, 0xfd3c, s_ss, "i32x4.gt_u")                                    \
  V(I32x4LeS, 0xfd3d, s_ss, "i32x4.le_s")                                    \
  V(I32x4LeU, 0xfd3e, s_ss, "i32x4.le_u")                                    \
  V(I32x4GeS, 0xfd3f, s_ss, "i32x4.ge_s")                                    \
  V(I32x4GeU, 0xfd40, s_ss, "i32x4.ge_u")                                    \
  V(F32x4Eq, 0xfd41, s_ss, "f32x4.eq")                                       \
  V(F32x4Ne, 0xfd42, s_ss, "f32x4.ne")                                       \
  V(F32x4Lt, 0xfd43, s_ss, "f32x4.lt")                                       \
  V(F32x4Gt, 0xfd44, s_ss, "f32x4.gt")                                       \
  V(F32x4Le, 0xfd45, s_ss, "f32x4.le")                                       \
  V(F32x4Ge, 0xfd46, s_ss, "f32x4.ge")                                       \
  V(F64x2Eq, 0xfd47, s_ss, "f64x2.eq")                                       \
  V(F64x2Ne, 0xfd48, s_ss, "f64x2.ne")                                       \
  V(F64x2Lt, 0xfd49, s_ss, "f64x2.lt")                                       \
  V(F64x2Gt, 0xfd4a, s_ss, "f64x2.gt")                                       \
  V(F64x2Le, 0xfd4b, s_ss, "f64x2.le")                                       \
  V(F64x2Ge, 0xfd4c, s_ss, "f64x2.ge")                                       \
  V(S128Not, 0xfd4d, s_s, "v128.not")                                        \
  V(S128And, 0xfd4e, s_ss, "v128.and")                                       \
  V(S128AndNot, 0xfd4f, s_ss, "v128.andnot")                                 \
  V(S128Or, 0xfd50, s_ss, "v128.or")                                         \
  V(S128Xor, 0xfd51, s_ss, "v128.xor")                                       \
  V(S128Select, 0xfd52, s_sss, "v128.bitselect")                             \
  V(V128AnyTrue, 0xfd53, i_s, "v128.any_true")                               \
  V(F32x4DemoteF64x2Zero, 0xfd5e, s_s, "f32x4.demote_f64x2_zero")            \
  V(F64x2PromoteLowF32x4, 0xfd5f, s_s, "f64x2.promote_low_f32x4")            \
  V(I8x16Abs, 0xfd60, s_s, "i8x16.abs")                                      \
  V(I8x16Neg, 0xfd61, s_s, "i8x16.neg")                                      \
  V(I8x16Popcnt, 0xfd62, s_s, "i8x16.popcnt")                                \
  V(I8x16AllTrue, 0xfd63, i_s, "i8x16.all_true")                             \
  V(I8x16BitMask, 0xfd64, i_s, "i8x16.bitmask")                              \
  V(I8x16SConvertI16x8, 0xfd65, s_ss, "i8x16.narrow_i16x8_s")                \
  V(I8x16UConvertI16x8, 0xfd66, s_ss, "i8x16.narrow_i16x8_u")                \
  V(F32x4Ceil, 0xfd67, s_s, "f32x4.ceil")                                    \
  V(F32x4Floor, 0xfd68, s_s, "f32x4.floor")                                  \
  V(F32x4Trunc, 0xfd69, s_s, "f32x4.trunc")                                  \
  V(F32x4NearestInt, 0xfd6a, s_s, "f32x4.nearest")                           \
  V(I8x16Shl, 0xfd6b, s_si, "i8x16.shl")                                     \
  V(I8x16ShrS, 0xfd6c, s_si, "i8x16.shr_s")                                  \
  V(I8x16ShrU, 0xfd6d, s_si, "i8x16.shr_u")                                  \
  V(I8x16Add, 0xfd6e, s_ss, "i8x16.add")                                     \
  V(I8x16AddSatS, 0xfd6f, s_ss, "i8x16.add_sat_s")                           \
  V(I8x16AddSatU, 0xfd70, s_ss, "i8x16.add_sat_u")                           \
  V(I8x16Sub, 0xfd71, s_ss, "i8x16.sub")                                     \
  V(I8x16SubSatS, 0xfd72, s_ss, "i8x16.sub_sat_s")                           \
  V(I8x16SubSatU, 0xfd73, s_ss, "i8x16.sub_sat_u")                           \
  V(F64x2Ceil, 0xfd74, s_s, "f64x2.ceil")                                    \
  V(F64x2Floor, 0xfd75, s_s, "f64x2.floor")                                  \
  V(I8x16MinS, 0xfd76, s_ss, "i8x16.min_s")                                  \
  V(I8x16MinU, 0xfd77, s_ss, "i8x16.min_u")                                  \
  V(I8x16MaxS, 0xfd78, s_ss, "i8x16.max_s")                                  \
  V(I8x16MaxU, 0xfd79, s_ss, "i8x16.max_u")                                  \
  V(F64x2Trunc, 0xfd7a, s_s, "f64x2.trunc")                                  \
  V(I8x16RoundingAverageU, 0xfd7b, s_ss, "i8x16.avgr_u")                     \
  V(I16x8ExtAddPairwiseI8x16S, 0xfd7c, s_s, "i16x8.extadd_pairwise_i8x16_s") \
  V(I16x8ExtAddPairwiseI8x16U, 0xfd7d, s_s, "i16x8.extadd_pairwise_i8x16_u") \
  V(I32x4ExtAddPairwiseI16x8S, 0xfd7e, s_s, "i32x4.extadd_pairwise_i16x8_s") \
  V(I32x4ExtAddPairwiseI16x8U, 0xfd7f, s_s, "i32x4.extadd_pairwise_i16x8_u") \
  V(I16x8Abs, 0xfd80, s_s, "i16x8.abs")                                      \
  V(I16x8Neg, 0xfd81, s_s, "i16x8.neg")                                      \
  V(I16x8Q15MulRSatS, 0xfd82, s_ss, "i16x8.q15mulr_sat_s")                   \
  V(I16x8AllTrue, 0xfd83, i_s, "i16x8.all_true")                             \
  V(I16x8BitMask, 0xfd84, i_s, "i16x8.bitmask")                              \
  V(I16x8SConvertI32x4, 0xfd85, s_ss, "i16x8.narrow_i32x4_s")                \
  V(I16x8UConvertI32x4, 0xfd86, s_ss, "i16x8.narrow_i32x4_u")                \
  V(I16x8SConvertI8x16Low, 0xfd87, s_s, "i16x8.extend_low_i8x16_s")          \
  V(I16x8SConvertI8x16High, 0xfd88, s_s, "i16x8.extend_high_i8x16_s")        \
  V(I16x8UConvertI8x16Low, 0xfd89, s_s, "i16x8.extend_low_i8x16_u")          \
  V(I16x8UConvertI8x16High, 0xfd8a, s_s, "i16x8.extend_high_i8x16_u")        \
  V(I16x8Shl, 0xfd8b, s_si, "i16x8.shl")                                     \
  V(I16x8ShrS, 0xfd8c, s_si, "i16x8.shr_s")                                  \
  V(I16x8ShrU, 0xfd8d, s_si, "i16x8.shr_u")                                  \
  V(I16x8Add, 0xfd8e, s_ss, "i16x8.add")                                     \
  V(I16x8AddSatS, 0xfd8f, s_ss, "i16x8.add_sat_s")                           \
  V(I16x8AddSatU, 0xfd90, s_ss, "i16x8.add_sat_u")                           \
  V(I16x8Sub, 0xfd91, s_ss, "i16x8.sub")                                     \
  V(I16x8SubSatS, 0xfd92, s_ss, "i16x8.sub_sat_s")                           \
  V(I16x8SubSatU, 0xfd93, s_ss, "i16x8.sub_sat_u")                           \
  V(F64x2NearestInt, 0xfd94, s_s, "f64x2.nearest")                           \
  V(I16x8Mul, 0xfd95, s_ss, "i16x8.mul")                                     \
  V(I16x8MinS, 0xfd96, s_ss, "i16x8.min_s")                                  \
  V(I16x8MinU, 0xfd97, s_ss, "i16x8.min_u")                                  \
  V(I16x8MaxS, 0xfd98, s_ss, "i16x8.max_s")                                  \
  V(I16x8MaxU, 0xfd99, s_ss, "i16x8.max_u")                                  \
  V(I16x8RoundingAverageU, 0xfd9b, s_ss, "i16x8.avgr_u")                     \
  V(I16x8ExtMulLowI8x16S, 0xfd9c, s_ss, "i16x8.extmul_low_i8x16_s")          \
  V(I16x8ExtMulHighI8x16S, 0xfd9d, s_ss, "i16x8.extmul_high_i8x16_s")        \
  V(I16x8ExtMulLowI8x16U, 0xfd9e, s_ss, "i16x8.extmul_low_i8x16_u")          \
  V(I16x8ExtMulHighI8x16U, 0xfd9f, s_ss, "i16x8.extmul_high_i8x16_u")        \
  V(I32x4Abs, 0xfda0, s_s, "i32x4.abs")                                      \
  V(I32x4Neg, 0xfda1, s_s, "i32x4.neg")                                      \
  V(I32x4AllTrue, 0xfda3, i_s, "i32x4.all_true")                             \
  V(I32x4BitMask, 0xfda4, i_s, "i32x4.bitmask")                              \
  V(I32x4SConvertI16x8Low, 0xfda7, s_s, "i32x4.extend_low_i16x8_s")          \
  V(I32x4SConvertI16x8High, 0xfda8, s_s, "i32x4.extend_high_i16x8_s")        \
  V(I32x4UConvertI16x8Low, 0xfda9, s_s, "i32x4.extend_low_i16x8_u")          \
  V(I32x4UConvertI16x8High, 0xfdaa, s_s, "i32x4.extend_high_i16x8_u")        \
  V(I32x4Shl, 0xfdab, s_si, "i32x4.shl")                                     \
  V(I32x4ShrS, 0xfdac, s_si, "i32x4.shr_s")                                  \
  V(I32x4ShrU, 0xfdad, s_si, "i32x4.shr_u")                                  \
  V(I32x4Add, 0xfdae, s_ss, "i32x4.add")                                     \
  V(I32x4Sub, 0xfdb1, s_ss, "i32x4.sub")                                     \
  V(I32x4Mul, 0xfdb5, s_ss, "i32x4.mul")                                     \
  V(I32x4MinS, 0xfdb6, s_ss, "i32x4.min_s")                                  \
  V(I32x4MinU, 0xfdb7, s_ss, "i32x4.min_u")                                  \
  V(I32x4MaxS, 0xfdb8, s_ss, "i32x4.max_s")                                  \
  V(I32x4MaxU, 0xfdb9, s_ss, "i32x4.max_u")                                  \
  V(I32x4DotI16x8S, 0xfdba, s_ss, "i32x4.dot_i16x8_s")                       \
  V(I32x4ExtMulLowI16x8S, 0xfdbc, s_ss, "i32x4.extmul_low_i16x8_s")          \
  V(I32x4ExtMulHighI16x8S, 0xfdbd, s_ss, "i32x4.extmul_high_i16x8_s")        \
  V(I32x4ExtMulLowI16x8U, 0xfdbe, s_ss, "i32x4.extmul_low_i16x8_u")          \
  V(I32x4ExtMulHighI16x8U, 0xfdbf, s_ss, "i32x4.extmul_high_i16x8_u")        \
  V(I64x2Abs, 0xfdc0, s_s, "i64x2.abs")                                      \
  V(I64x2Neg, 0xfdc1, s_s, "i64x2.neg")                                      \
  V(I64x2AllTrue, 0xfdc3, i_s, "i64x2.all_true")                             \
  V(I64x2BitMask, 0xfdc4, i_s, "i64x2.bitmask")                              \
  V(I64x2SConvertI32x4Low, 0xfdc7, s_s, "i64x2.extend_low_i32x4_s")          \
  V(I64x2SConvertI32x4High, 0xfdc8, s_s, "i64x2.extend_high_i32x4_s")        \
  V(I64x2UConvertI32x4Low, 0xfdc9, s_s, "i64x2.extend_low_i32x4_u")          \
  V(I64x2UConvertI32x4High, 0xfdca, s_s, "i64x2.extend_high_i32x4_u")        \
  V(I64x2Shl, 0xfdcb, s_si, "i64x2.shl")                                     \
  V(I64x2ShrS, 0xfdcc, s_si, "i64x2.shr_s")                                  \
  V(I64x2ShrU, 0xfdcd, s_si, "i64x2.shr_u")                                  \
  V(I64x2Add, 0xfdce, s_ss, "i64x2.add")                                     \
  V(I64x2Sub, 0xfdd1, s_ss, "i64x2.sub")                                     \
  V(I64x2Mul, 0xfdd5, s_ss, "i64x2.mul")                                     \
  V(I64x2Eq, 0xfdd6, s_ss, "i64x2.eq")                                       \
  V(I64x2Ne, 0xfdd7, s_ss, "i64x2.ne")                                       \
  V(I64x2LtS, 0xfdd8, s_ss, "i64x2.lt_s")                                    \
  V(I64x2GtS, 0xfdd9, s_ss, "i64x2.gt_s")                                    \
  V(I64x2LeS, 0xfdda, s_ss, "i64x2.le_s")                                    \
  V(I64x2GeS, 0xfddb, s_ss, "i64x2.ge_s")                                    \
  V(I64x2ExtMulLowI32x4S, 0xfddc, s_ss, "i64x2.extmul_low_i32x4_s")          \
  V(I64x2ExtMulHighI32x4S, 0xfddd, s_ss, "i64x2.extmul_high_i32x4_s")        \
  V(I64x2ExtMulLowI32x4U, 0xfdde, s_ss, "i64x2.extmul_low_i32x4_u")          \
  V(I64x2ExtMulHighI32x4U, 0xfddf, s_ss, "i64x2.extmul_high_i32x4_u")        \
  V(F32x4Abs, 0xfde0, s_s, "f32x4.abs")                                      \
  V(F32x4Neg, 0xfde1, s_s, "f32x4.neg")                                      \
  V(F32x4Sqrt, 0xfde3, s_s, "f32x4.sqrt")                                    \
  V(F32x4Add, 0xfde4, s_ss, "f32x4.add")                                     \
  V(F32x4Sub, 0xfde5, s_ss, "f32x4.sub")                                     \
  V(F32x4Mul, 0xfde6, s_ss, "f32x4.mul")                                     \
  V(F32x4Div, 0xfde7, s_ss, "f32x4.div")                                     \
  V(F32x4Min, 0xfde8, s_ss, "f32x4.min")                                     \
  V(F32x4Max, 0xfde9, s_ss, "f32x4.max")                                     \
  V(F32x4Pmin, 0xfdea, s_ss, "f32x4.pmin")                                   \
  V(F32x4Pmax, 0xfdeb, s_ss, "f32x4.pmax")                                   \
  V(F64x2Abs, 0xfdec, s_s, "f64x2.abs")                                      \
  V(F64x2Neg, 0xfded, s_s, "f64x2.neg")                                      \
  V(F64x2Sqrt, 0xfdef, s_s, "f64x2.sqrt")                                    \
  V(F64x2Add, 0xfdf0, s_ss, "f64x2.add")                                     \
  V(F64x2Sub, 0xfdf1, s_ss, "f64x2.sub")                                     \
  V(F64x2Mul, 0xfdf2, s_ss, "f64x2.mul")                                     \
  V(F64x2Div, 0xfdf3, s_ss, "f64x2.div")                                     \
  V(F64x2Min, 0xfdf4, s_ss, "f64x2.min")                                     \
  V(F64x2Max, 0xfdf5, s_ss, "f64x2.max")                                     \
  V(F64x2Pmin, 0xfdf6, s_ss, "f64x2.pmin")                                   \
  V(F64x2Pmax, 0xfdf7, s_ss, "f64x2.pmax")                                   \
  V(I32x4SConvertF32x4, 0xfdf8, s_s, "i32x4.trunc_sat_f32x4_s")              \
  V(I32x4UConvertF32x4, 0xfdf9, s_s, "i32x4.trunc_sat_f32x4_u")              \
  V(F32x4SConvertI32x4, 0xfdfa, s_s, "f32x4.convert_i32x4_s")                \
  V(F32x4UConvertI32x4, 0xfdfb, s_s, "f32x4.convert_i32x4_u")                \
  V(I32x4TruncSatF64x2SZero, 0xfdfc, s_s, "i32x4.trunc_sat_f64x2_s_zero")    \
  V(I32x4TruncSatF64x2UZero, 0xfdfd, s_s, "i32x4.trunc_sat_f64x2_u_zero")    \
  V(F64x2ConvertLowI32x4S, 0xfdfe, s_s, "f64x2.convert_low_i32x4_s")         \
  V(F64x2ConvertLowI32x4U, 0xfdff, s_s, "f64x2.convert_low_i32x4_u")

#define FOREACH_RELAXED_SIMD_OPCODE(V)                                     \
  V(I8x16RelaxedSwizzle, 0xfd100, s_ss, "i8x16.relaxed_swizzle")           \
  V(I32x4RelaxedTruncF32x4S, 0xfd101, s_s, "i32x4.relaxed_trunc_f32x4_s")  \
  V(I32x4RelaxedTruncF32x4U, 0xfd102, s_s, "i32x4.relaxed_trunc_f32x4_u")  \
```