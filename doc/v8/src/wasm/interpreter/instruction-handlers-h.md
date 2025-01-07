Response:
Let's break down the thought process for analyzing the provided C++ header file.

**1. Initial Scan and Identification of Key Information:**

   - **File Path:** `v8/src/wasm/interpreter/instruction-handlers.h`. This immediately tells us it's related to the WebAssembly interpreter within the V8 engine. The `instruction-handlers` part is a strong clue about its purpose.
   - **Copyright and License:** Standard boilerplate, indicating the file belongs to the V8 project and its usage is governed by a BSD license. Not directly functional, but important for legal context.
   - **`#if !V8_ENABLE_WEBASSEMBLY`:** This preprocessor directive is crucial. It confirms that this header is *only* meant to be included when WebAssembly support is enabled in V8. This is a fundamental constraint.
   - **`#ifndef V8_WASM_INTERPRETER_INSTRUCTION_HANDLERS_H_` and `#define V8_WASM_INTERPRETER_INSTRUCTION_HANDLERS_H_`:**  Standard include guards to prevent multiple inclusions of the header file, avoiding compilation errors. Not directly functional for the *code* within, but essential for correct compilation.
   - **`#define FOREACH_*_INSTR_HANDLER(V)` macros:** This is the core of the file's structure. These macros define lists of instruction handler names. The `FOREACH_` prefix suggests these are meant to be iterated over, likely to generate code or data structures.
   - **Naming Conventions:** The instruction handler names follow a pattern like `(r|s)2(r|s)_<DataType><Operation>`. This hints at the structure of the interpreter's internal workings and how operands are handled. `r` and `s` likely stand for register and stack, respectively. Data types are `I32`, `I64`, `F32`, `F64`, `S128`, `Ref`. Operations are things like `LoadMem`, `StoreMem`, `Add`, `Sub`, `Eq`, etc.

**2. Deeper Analysis of the Macros:**

   - **`FOREACH_LOAD_STORE_INSTR_HANDLER`:** This clearly deals with instructions that load data from memory or store data to memory. The variations in the names (e.g., `I32LoadMem8S`, `I32LoadMem`) suggest different data types and sizes, as well as signedness (`S`, `U`). The `_LocalSet` suffix indicates a variant that also sets a local variable after loading.
   - **`FOREACH_LOAD_STORE_DUPLICATED_INSTR_HANDLER`:**  The name suggests redundancy. Looking at the listed handlers, it seems to be combining load/store operations with other actions (like `LocalGet`). This likely represents optimized or combined instruction handlers.
   - **`FOREACH_NO_BOUNDSCHECK_INSTR_HANDLER`:** This is a big clue about optimization. These instructions *don't* perform bounds checking on memory accesses. This is significant for performance but requires the caller to ensure safety. The listed instructions cover a wide range: global variable access, dropping values, selection, arithmetic, comparisons, bitwise operations, unary operations, and type conversions/reinterpretations.

**3. Answering the Specific Questions:**

   - **Functionality:** Based on the macro names and the included handlers, the core function is to define a set of *instruction handlers* for the WebAssembly interpreter. These handlers represent the low-level operations the interpreter can perform.
   - **`.tq` extension:** The text explicitly states that *if* the file ended in `.tq`, it would be a Torque source file. Since it ends in `.h`, it's a standard C++ header. Therefore, this part of the question is a distractor to test careful reading.
   - **Relationship to JavaScript:**  WebAssembly is designed to run alongside JavaScript in web browsers. While the *internal implementation* in this header isn't directly exposed to JavaScript, the *effects* of these instructions are. For example, a WebAssembly `i32.add` instruction corresponds to the `+` operator in JavaScript when performing arithmetic on numbers that fit within a 32-bit integer. The provided JavaScript examples illustrate this conceptually.
   - **Code Logic Reasoning (Hypothetical Input/Output):**  Because the header only *declares* instruction handlers and doesn't provide their *implementation*, we can't provide concrete input/output examples for the *handlers themselves*. We can, however, illustrate the *WebAssembly instructions* and their expected behavior, which the handlers would implement. This is what the examples for `i32.load`, `i32.store`, and `i32.add` do.
   - **Common Programming Errors:**  Relating the instructions to errors requires understanding how these instructions are used in WebAssembly. Out-of-bounds memory access is a classic error associated with load/store operations. Integer overflow/underflow is relevant to arithmetic operations. Type mismatch errors can occur with conversion operations.
   - **Summary of Functionality:** Combining the observations, the file's main job is to define (through macros) all the individual operations that the WebAssembly interpreter needs to execute. It's a central catalog of these operations, likely used to generate dispatch tables or similar structures within the interpreter.

**4. Self-Correction/Refinement:**

   - Initially, I might have focused too much on the individual instruction names. Realizing the importance of the `#define FOREACH_*` macros and their purpose in generating lists is key.
   - The distinction between the *declaration* of handlers in the header and their *implementation* elsewhere is important for answering the input/output question. We can only demonstrate the behavior of the *WebAssembly instructions* themselves.
   - Recognizing the `.tq` part as a conditional statement and concluding that this file is *not* a Torque file is crucial.

By following this thought process, systematically analyzing the file's content and considering the context of WebAssembly and the V8 engine, we arrive at a comprehensive understanding of its functionality.
好的，我们来分析一下 `v8/src/wasm/interpreter/instruction-handlers.h` 这个V8源代码文件的功能。

**功能概览**

`v8/src/wasm/interpreter/instruction-handlers.h` 文件定义了一系列宏，这些宏用于列举 WebAssembly 解释器中各种指令的处理函数。 简单来说，这个头文件就像一个索引或目录，列出了解释器能够处理的所有 WebAssembly 指令。

**详细功能拆解**

1. **指令枚举:** 文件中使用 `#define FOREACH_*_INSTR_HANDLER(V)` 这样的宏来定义不同类别的 WebAssembly 指令。`FOREACH_LOAD_STORE_INSTR_HANDLER` 列出了内存加载和存储指令，`FOREACH_NO_BOUNDSCHECK_INSTR_HANDLER` 列出了不需要进行边界检查的指令，等等。

2. **宏 `V` 的作用:**  在这些 `FOREACH` 宏中， `V` 通常是一个宏参数，它代表着你想要对列表中的每个指令执行的操作。在实际的代码中，这个 `V` 会被替换成具体的代码，例如定义处理函数、生成查找表等等。

3. **指令命名规范:**  从指令的命名可以看出一些规律，例如 `r2r_I32LoadMem`、`s2s_I32Add`。 这些名称似乎包含了以下信息：
   -  `r` 或 `s`：可能表示操作数来自寄存器 (register) 或栈 (stack)。
   -  `2`：可能表示操作数个数。
   -  数据类型：例如 `I32` (32位整数)、`I64` (64位整数)、`F32` (32位浮点数)、`F64` (64位浮点数) 等。
   -  操作类型：例如 `LoadMem` (加载内存)、`StoreMem` (存储内存)、`Add` (加法) 等。

**关于 .tq 扩展名**

正如你所说，如果 `v8/src/wasm/interpreter/instruction-handlers.h` 以 `.tq` 结尾，那么它将是一个 V8 Torque 源代码文件。 Torque 是一种用于编写 V8 内部代码的领域特定语言，它可以生成 C++ 代码。 由于该文件以 `.h` 结尾，它是一个标准的 C++ 头文件，其中包含宏定义。

**与 JavaScript 的关系 (通过 WebAssembly)**

`v8/src/wasm/interpreter/instruction-handlers.h` 中定义的指令处理函数是 WebAssembly 解释器执行 WebAssembly 代码的基础。 WebAssembly 是一种可以由现代 Web 浏览器运行的低级字节码格式。 因此，这个文件间接地与 JavaScript 功能相关，因为它定义了执行 WebAssembly 代码的方式，而 WebAssembly 可以与 JavaScript 代码互操作。

**JavaScript 示例**

虽然 `instruction-handlers.h` 本身不是 JavaScript 代码，但它定义的行为对应于 WebAssembly 指令，这些指令可以通过 JavaScript 来调用。

例如，`r2r_I32Add` 对应于 WebAssembly 的 `i32.add` 指令。 如果你在 WebAssembly 模块中有以下代码：

```wasm
(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )
)
```

这段 WebAssembly 代码定义了一个名为 "add" 的函数，它接受两个 i32 类型的参数，并将它们相加。  当 JavaScript 调用这个 WebAssembly 函数时，V8 的 WebAssembly 解释器最终会执行与 `i32.add` 指令对应的处理逻辑，这部分逻辑的声明就包含在 `instruction-handlers.h` 中。

在 JavaScript 中调用这个 WebAssembly 函数可能是这样的：

```javascript
async function runWasm() {
  const response = await fetch('module.wasm'); // 假设你的 WebAssembly 模块名为 module.wasm
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.compile(buffer);
  const instance = await WebAssembly.instantiate(module);

  const result = instance.exports.add(5, 3);
  console.log(result); // 输出 8
}

runWasm();
```

在这个例子中，`instance.exports.add(5, 3)` 的执行最终会触发 WebAssembly 解释器中 `i32.add` 指令的处理。

**代码逻辑推理 (假设输入与输出)**

由于 `instruction-handlers.h` 只是声明了指令处理的接口（通过宏枚举），并没有提供具体的实现，我们无法直接进行代码逻辑推理并给出具体的输入输出。 这些宏会在其他 C++ 文件中被使用，以实现具体的指令处理函数。

然而，我们可以针对具体的 WebAssembly 指令来推断。 例如，对于 `r2r_I32LoadMem`:

**假设输入：**
- 解释器的当前状态，包括内存、寄存器等。
- 指令操作数：
    - 一个表示内存地址的 32 位整数 (来自一个寄存器)。

**预期输出：**
- 解释器的状态更新：
    - 从指定内存地址加载一个 32 位整数。
    - 将加载的值存储到另一个寄存器中。

**用户常见的编程错误 (与 WebAssembly 相关)**

与这里列出的指令相关的常见编程错误通常发生在编写 WebAssembly 代码时，或者在 JavaScript 与 WebAssembly 交互时：

1. **内存越界访问:**  使用 `i32.load` 或 `i32.store` 等指令访问超出 WebAssembly 线性内存范围的地址。 这会导致运行时错误。

   **示例 (WebAssembly):**
   ```wasm
   (module
     (memory (export "mem") 1)
     (func (export "store_oob")
       i32.const 65536  // 内存大小为 1 页 (65536 字节)，这里访问的是边界外
       i32.const 123
       i32.store
     )
   )
   ```

   当执行 `store_oob` 函数时，会尝试将值存储到超出分配内存的地址，导致错误。

2. **类型不匹配:**  在 WebAssembly 指令中使用了错误的数据类型。 例如，尝试将一个浮点数存储到需要整数的内存位置。

   **示例 (WebAssembly):**
   ```wasm
   (module
     (memory (export "mem") 1)
     (func (export "store_type_mismatch")
       i32.const 0
       f32.const 1.23
       f32.store // 假设这里应该是 i32.store
     )
   )
   ```

3. **整数溢出/下溢:** 在进行算术运算时，结果超出了整数类型的表示范围。  WebAssembly 的算术指令通常会回绕，但这种行为可能不是预期。

   **示例 (WebAssembly):**
   ```wasm
   (module
     (func (export "overflow") (result i32)
       i32.const 2147483647 // i32 的最大值
       i32.const 1
       i32.add          // 结果会溢出，回绕到最小值
     )
   )
   ```

4. **除零错误:**  执行除法指令时，除数为零。 对于整数除法，这会导致 trap (运行时错误)。

   **示例 (WebAssembly):**
   ```wasm
   (module
     (func (export "divide_by_zero") (result i32)
       i32.const 10
       i32.const 0
       i32.div_s
     )
   )
   ```

**归纳功能 (针对第 1 部分)**

`v8/src/wasm/interpreter/instruction-handlers.h` 文件的主要功能是：

- **作为 WebAssembly 解释器中各种指令处理函数的索引或目录。**
- **使用宏定义来枚举不同类别的 WebAssembly 指令 (例如，加载/存储、算术、比较等)。**
- **为后续定义具体的指令处理逻辑提供基础结构。**

总而言之，这个头文件是 V8 的 WebAssembly 解释器架构的关键组成部分，它组织和列出了解释器需要实现的所有基本操作。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/instruction-handlers.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/instruction-handlers.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_INTERPRETER_INSTRUCTION_HANDLERS_H_
#define V8_WASM_INTERPRETER_INSTRUCTION_HANDLERS_H_

#define FOREACH_LOAD_STORE_INSTR_HANDLER(V) \
  /* LoadMem */                             \
  V(r2r_I32LoadMem8S)                       \
  V(r2r_I32LoadMem8U)                       \
  V(r2r_I32LoadMem16S)                      \
  V(r2r_I32LoadMem16U)                      \
  V(r2r_I64LoadMem8S)                       \
  V(r2r_I64LoadMem8U)                       \
  V(r2r_I64LoadMem16S)                      \
  V(r2r_I64LoadMem16U)                      \
  V(r2r_I64LoadMem32S)                      \
  V(r2r_I64LoadMem32U)                      \
  V(r2r_I32LoadMem)                         \
  V(r2r_I64LoadMem)                         \
  V(r2r_F32LoadMem)                         \
  V(r2r_F64LoadMem)                         \
  V(r2s_I32LoadMem8S)                       \
  V(r2s_I32LoadMem8U)                       \
  V(r2s_I32LoadMem16S)                      \
  V(r2s_I32LoadMem16U)                      \
  V(r2s_I64LoadMem8S)                       \
  V(r2s_I64LoadMem8U)                       \
  V(r2s_I64LoadMem16S)                      \
  V(r2s_I64LoadMem16U)                      \
  V(r2s_I64LoadMem32S)                      \
  V(r2s_I64LoadMem32U)                      \
  V(r2s_I32LoadMem)                         \
  V(r2s_I64LoadMem)                         \
  V(r2s_F32LoadMem)                         \
  V(r2s_F64LoadMem)                         \
  V(s2r_I32LoadMem8S)                       \
  V(s2r_I32LoadMem8U)                       \
  V(s2r_I32LoadMem16S)                      \
  V(s2r_I32LoadMem16U)                      \
  V(s2r_I64LoadMem8S)                       \
  V(s2r_I64LoadMem8U)                       \
  V(s2r_I64LoadMem16S)                      \
  V(s2r_I64LoadMem16U)                      \
  V(s2r_I64LoadMem32S)                      \
  V(s2r_I64LoadMem32U)                      \
  V(s2r_I32LoadMem)                         \
  V(s2r_I64LoadMem)                         \
  V(s2r_F32LoadMem)                         \
  V(s2r_F64LoadMem)                         \
  V(s2s_I32LoadMem8S)                       \
  V(s2s_I32LoadMem8U)                       \
  V(s2s_I32LoadMem16S)                      \
  V(s2s_I32LoadMem16U)                      \
  V(s2s_I64LoadMem8S)                       \
  V(s2s_I64LoadMem8U)                       \
  V(s2s_I64LoadMem16S)                      \
  V(s2s_I64LoadMem16U)                      \
  V(s2s_I64LoadMem32S)                      \
  V(s2s_I64LoadMem32U)                      \
  V(s2s_I32LoadMem)                         \
  V(s2s_I64LoadMem)                         \
  V(s2s_F32LoadMem)                         \
  V(s2s_F64LoadMem)                         \
  /* LoadMem_LocalSet */                    \
  V(s2s_I32LoadMem8S_LocalSet)              \
  V(s2s_I32LoadMem8U_LocalSet)              \
  V(s2s_I32LoadMem16S_LocalSet)             \
  V(s2s_I32LoadMem16U_LocalSet)             \
  V(s2s_I64LoadMem8S_LocalSet)              \
  V(s2s_I64LoadMem8U_LocalSet)              \
  V(s2s_I64LoadMem16S_LocalSet)             \
  V(s2s_I64LoadMem16U_LocalSet)             \
  V(s2s_I64LoadMem32S_LocalSet)             \
  V(s2s_I64LoadMem32U_LocalSet)             \
  V(s2s_I32LoadMem_LocalSet)                \
  V(s2s_I64LoadMem_LocalSet)                \
  V(s2s_F32LoadMem_LocalSet)                \
  V(s2s_F64LoadMem_LocalSet)                \
  /* StoreMem */                            \
  V(r2s_I32StoreMem8)                       \
  V(r2s_I32StoreMem16)                      \
  V(r2s_I64StoreMem8)                       \
  V(r2s_I64StoreMem16)                      \
  V(r2s_I64StoreMem32)                      \
  V(r2s_I32StoreMem)                        \
  V(r2s_I64StoreMem)                        \
  V(r2s_F32StoreMem)                        \
  V(r2s_F64StoreMem)                        \
  V(s2s_I32StoreMem8)                       \
  V(s2s_I32StoreMem16)                      \
  V(s2s_I64StoreMem8)                       \
  V(s2s_I64StoreMem16)                      \
  V(s2s_I64StoreMem32)                      \
  V(s2s_I32StoreMem)                        \
  V(s2s_I64StoreMem)                        \
  V(s2s_F32StoreMem)                        \
  V(s2s_F64StoreMem)                        \
  /* LoadStoreMem */                        \
  V(r2s_I32LoadStoreMem)                    \
  V(r2s_I64LoadStoreMem)                    \
  V(r2s_F32LoadStoreMem)                    \
  V(r2s_F64LoadStoreMem)                    \
  V(s2s_I32LoadStoreMem)                    \
  V(s2s_I64LoadStoreMem)                    \
  V(s2s_F32LoadStoreMem)                    \
  V(s2s_F64LoadStoreMem)

#define FOREACH_LOAD_STORE_DUPLICATED_INSTR_HANDLER(V) \
  /* LoadMem_LocalSet */                               \
  V(r2s_I32LoadMem8S_LocalSet)                         \
  V(r2s_I32LoadMem8U_LocalSet)                         \
  V(r2s_I32LoadMem16S_LocalSet)                        \
  V(r2s_I32LoadMem16U_LocalSet)                        \
  V(r2s_I64LoadMem8S_LocalSet)                         \
  V(r2s_I64LoadMem8U_LocalSet)                         \
  V(r2s_I64LoadMem16S_LocalSet)                        \
  V(r2s_I64LoadMem16U_LocalSet)                        \
  V(r2s_I64LoadMem32S_LocalSet)                        \
  V(r2s_I64LoadMem32U_LocalSet)                        \
  V(r2s_I32LoadMem_LocalSet)                           \
  V(r2s_I64LoadMem_LocalSet)                           \
  V(r2s_F32LoadMem_LocalSet)                           \
  V(r2s_F64LoadMem_LocalSet)                           \
  /* LocalGet_StoreMem */                              \
  V(s2s_LocalGet_I32StoreMem8)                         \
  V(s2s_LocalGet_I32StoreMem16)                        \
  V(s2s_LocalGet_I64StoreMem8)                         \
  V(s2s_LocalGet_I64StoreMem16)                        \
  V(s2s_LocalGet_I64StoreMem32)                        \
  V(s2s_LocalGet_I32StoreMem)                          \
  V(s2s_LocalGet_I64StoreMem)                          \
  V(s2s_LocalGet_F32StoreMem)                          \
  V(s2s_LocalGet_F64StoreMem)

#define FOREACH_NO_BOUNDSCHECK_INSTR_HANDLER(V) \
  /* GlobalGet */                               \
  V(s2r_I32GlobalGet)                           \
  V(s2r_I64GlobalGet)                           \
  V(s2r_F32GlobalGet)                           \
  V(s2r_F64GlobalGet)                           \
  V(s2s_I32GlobalGet)                           \
  V(s2s_I64GlobalGet)                           \
  V(s2s_F32GlobalGet)                           \
  V(s2s_F64GlobalGet)                           \
  V(s2s_S128GlobalGet)                          \
  V(s2s_RefGlobalGet)                           \
  /* GlobalSet */                               \
  V(r2s_I32GlobalSet)                           \
  V(r2s_I64GlobalSet)                           \
  V(r2s_F32GlobalSet)                           \
  V(r2s_F64GlobalSet)                           \
  V(s2s_I32GlobalSet)                           \
  V(s2s_I64GlobalSet)                           \
  V(s2s_F32GlobalSet)                           \
  V(s2s_F64GlobalSet)                           \
  V(s2s_S128GlobalSet)                          \
  V(s2s_RefGlobalSet)                           \
  /* Drop */                                    \
  V(r2s_I32Drop)                                \
  V(r2s_I64Drop)                                \
  V(r2s_F32Drop)                                \
  V(r2s_F64Drop)                                \
  V(r2s_RefDrop)                                \
  V(s2s_I32Drop)                                \
  V(s2s_I64Drop)                                \
  V(s2s_F32Drop)                                \
  V(s2s_F64Drop)                                \
  V(s2s_S128Drop)                               \
  V(s2s_RefDrop)                                \
  /* Select */                                  \
  V(r2r_I32Select)                              \
  V(r2r_I64Select)                              \
  V(r2r_F32Select)                              \
  V(r2r_F64Select)                              \
  V(r2s_I32Select)                              \
  V(r2s_I64Select)                              \
  V(r2s_F32Select)                              \
  V(r2s_F64Select)                              \
  V(r2s_S128Select)                             \
  V(r2s_RefSelect)                              \
  V(s2r_I32Select)                              \
  V(s2r_I64Select)                              \
  V(s2r_F32Select)                              \
  V(s2r_F64Select)                              \
  V(s2s_I32Select)                              \
  V(s2s_I64Select)                              \
  V(s2s_F32Select)                              \
  V(s2s_F64Select)                              \
  V(s2s_S128Select)                             \
  V(s2s_RefSelect)                              \
  /* Binary arithmetic operators. */            \
  V(r2r_I32Add)                                 \
  V(r2r_I32Sub)                                 \
  V(r2r_I32Mul)                                 \
  V(r2r_I32And)                                 \
  V(r2r_I32Ior)                                 \
  V(r2r_I32Xor)                                 \
  V(r2r_I64Add)                                 \
  V(r2r_I64Sub)                                 \
  V(r2r_I64Mul)                                 \
  V(r2r_I64And)                                 \
  V(r2r_I64Ior)                                 \
  V(r2r_I64Xor)                                 \
  V(r2r_F32Add)                                 \
  V(r2r_F32Sub)                                 \
  V(r2r_F32Mul)                                 \
  V(r2r_F64Add)                                 \
  V(r2r_F64Sub)                                 \
  V(r2r_F64Mul)                                 \
  V(r2r_I32DivS)                                \
  V(r2r_I64DivS)                                \
  V(r2r_I32DivU)                                \
  V(r2r_I64DivU)                                \
  V(r2r_F32Div)                                 \
  V(r2r_F64Div)                                 \
  V(r2r_I32RemS)                                \
  V(r2r_I64RemS)                                \
  V(r2r_I32RemU)                                \
  V(r2r_I64RemU)                                \
  V(r2s_I32Add)                                 \
  V(r2s_I32Sub)                                 \
  V(r2s_I32Mul)                                 \
  V(r2s_I32And)                                 \
  V(r2s_I32Ior)                                 \
  V(r2s_I32Xor)                                 \
  V(r2s_I64Add)                                 \
  V(r2s_I64Sub)                                 \
  V(r2s_I64Mul)                                 \
  V(r2s_I64And)                                 \
  V(r2s_I64Ior)                                 \
  V(r2s_I64Xor)                                 \
  V(r2s_F32Add)                                 \
  V(r2s_F32Sub)                                 \
  V(r2s_F32Mul)                                 \
  V(r2s_F64Add)                                 \
  V(r2s_F64Sub)                                 \
  V(r2s_F64Mul)                                 \
  V(r2s_I32DivS)                                \
  V(r2s_I64DivS)                                \
  V(r2s_I32DivU)                                \
  V(r2s_I64DivU)                                \
  V(r2s_F32Div)                                 \
  V(r2s_F64Div)                                 \
  V(r2s_I32RemS)                                \
  V(r2s_I64RemS)                                \
  V(r2s_I32RemU)                                \
  V(r2s_I64RemU)                                \
  V(s2r_I32Add)                                 \
  V(s2r_I32Sub)                                 \
  V(s2r_I32Mul)                                 \
  V(s2r_I32And)                                 \
  V(s2r_I32Ior)                                 \
  V(s2r_I32Xor)                                 \
  V(s2r_I64Add)                                 \
  V(s2r_I64Sub)                                 \
  V(s2r_I64Mul)                                 \
  V(s2r_I64And)                                 \
  V(s2r_I64Ior)                                 \
  V(s2r_I64Xor)                                 \
  V(s2r_F32Add)                                 \
  V(s2r_F32Sub)                                 \
  V(s2r_F32Mul)                                 \
  V(s2r_F64Add)                                 \
  V(s2r_F64Sub)                                 \
  V(s2r_F64Mul)                                 \
  V(s2r_I32DivS)                                \
  V(s2r_I64DivS)                                \
  V(s2r_I32DivU)                                \
  V(s2r_I64DivU)                                \
  V(s2r_F32Div)                                 \
  V(s2r_F64Div)                                 \
  V(s2r_I32RemS)                                \
  V(s2r_I64RemS)                                \
  V(s2r_I32RemU)                                \
  V(s2r_I64RemU)                                \
  V(s2s_I32Add)                                 \
  V(s2s_I32Sub)                                 \
  V(s2s_I32Mul)                                 \
  V(s2s_I32And)                                 \
  V(s2s_I32Ior)                                 \
  V(s2s_I32Xor)                                 \
  V(s2s_I64Add)                                 \
  V(s2s_I64Sub)                                 \
  V(s2s_I64Mul)                                 \
  V(s2s_I64And)                                 \
  V(s2s_I64Ior)                                 \
  V(s2s_I64Xor)                                 \
  V(s2s_F32Add)                                 \
  V(s2s_F32Sub)                                 \
  V(s2s_F32Mul)                                 \
  V(s2s_F64Add)                                 \
  V(s2s_F64Sub)                                 \
  V(s2s_F64Mul)                                 \
  V(s2s_I32DivS)                                \
  V(s2s_I64DivS)                                \
  V(s2s_I32DivU)                                \
  V(s2s_I64DivU)                                \
  V(s2s_F32Div)                                 \
  V(s2s_F64Div)                                 \
  V(s2s_I32RemS)                                \
  V(s2s_I64RemS)                                \
  V(s2s_I32RemU)                                \
  V(s2s_I64RemU)                                \
  /* Comparison operators. */                   \
  V(r2r_I32Eq)                                  \
  V(r2r_I32Ne)                                  \
  V(r2r_I32LtU)                                 \
  V(r2r_I32LeU)                                 \
  V(r2r_I32GtU)                                 \
  V(r2r_I32GeU)                                 \
  V(r2r_I32LtS)                                 \
  V(r2r_I32LeS)                                 \
  V(r2r_I32GtS)                                 \
  V(r2r_I32GeS)                                 \
  V(r2r_I64Eq)                                  \
  V(r2r_I64Ne)                                  \
  V(r2r_I64LtU)                                 \
  V(r2r_I64LeU)                                 \
  V(r2r_I64GtU)                                 \
  V(r2r_I64GeU)                                 \
  V(r2r_I64LtS)                                 \
  V(r2r_I64LeS)                                 \
  V(r2r_I64GtS)                                 \
  V(r2r_I64GeS)                                 \
  V(r2r_F32Eq)                                  \
  V(r2r_F32Ne)                                  \
  V(r2r_F32Lt)                                  \
  V(r2r_F32Le)                                  \
  V(r2r_F32Gt)                                  \
  V(r2r_F32Ge)                                  \
  V(r2r_F64Eq)                                  \
  V(r2r_F64Ne)                                  \
  V(r2r_F64Lt)                                  \
  V(r2r_F64Le)                                  \
  V(r2r_F64Gt)                                  \
  V(r2r_F64Ge)                                  \
  V(r2s_I32Eq)                                  \
  V(r2s_I32Ne)                                  \
  V(r2s_I32LtU)                                 \
  V(r2s_I32LeU)                                 \
  V(r2s_I32GtU)                                 \
  V(r2s_I32GeU)                                 \
  V(r2s_I32LtS)                                 \
  V(r2s_I32LeS)                                 \
  V(r2s_I32GtS)                                 \
  V(r2s_I32GeS)                                 \
  V(r2s_I64Eq)                                  \
  V(r2s_I64Ne)                                  \
  V(r2s_I64LtU)                                 \
  V(r2s_I64LeU)                                 \
  V(r2s_I64GtU)                                 \
  V(r2s_I64GeU)                                 \
  V(r2s_I64LtS)                                 \
  V(r2s_I64LeS)                                 \
  V(r2s_I64GtS)                                 \
  V(r2s_I64GeS)                                 \
  V(r2s_F32Eq)                                  \
  V(r2s_F32Ne)                                  \
  V(r2s_F32Lt)                                  \
  V(r2s_F32Le)                                  \
  V(r2s_F32Gt)                                  \
  V(r2s_F32Ge)                                  \
  V(r2s_F64Eq)                                  \
  V(r2s_F64Ne)                                  \
  V(r2s_F64Lt)                                  \
  V(r2s_F64Le)                                  \
  V(r2s_F64Gt)                                  \
  V(r2s_F64Ge)                                  \
  V(s2r_I32Eq)                                  \
  V(s2r_I32Ne)                                  \
  V(s2r_I32LtU)                                 \
  V(s2r_I32LeU)                                 \
  V(s2r_I32GtU)                                 \
  V(s2r_I32GeU)                                 \
  V(s2r_I32LtS)                                 \
  V(s2r_I32LeS)                                 \
  V(s2r_I32GtS)                                 \
  V(s2r_I32GeS)                                 \
  V(s2r_I64Eq)                                  \
  V(s2r_I64Ne)                                  \
  V(s2r_I64LtU)                                 \
  V(s2r_I64LeU)                                 \
  V(s2r_I64GtU)                                 \
  V(s2r_I64GeU)                                 \
  V(s2r_I64LtS)                                 \
  V(s2r_I64LeS)                                 \
  V(s2r_I64GtS)                                 \
  V(s2r_I64GeS)                                 \
  V(s2r_F32Eq)                                  \
  V(s2r_F32Ne)                                  \
  V(s2r_F32Lt)                                  \
  V(s2r_F32Le)                                  \
  V(s2r_F32Gt)                                  \
  V(s2r_F32Ge)                                  \
  V(s2r_F64Eq)                                  \
  V(s2r_F64Ne)                                  \
  V(s2r_F64Lt)                                  \
  V(s2r_F64Le)                                  \
  V(s2r_F64Gt)                                  \
  V(s2r_F64Ge)                                  \
  V(s2s_I32Eq)                                  \
  V(s2s_I32Ne)                                  \
  V(s2s_I32LtU)                                 \
  V(s2s_I32LeU)                                 \
  V(s2s_I32GtU)                                 \
  V(s2s_I32GeU)                                 \
  V(s2s_I32LtS)                                 \
  V(s2s_I32LeS)                                 \
  V(s2s_I32GtS)                                 \
  V(s2s_I32GeS)                                 \
  V(s2s_I64Eq)                                  \
  V(s2s_I64Ne)                                  \
  V(s2s_I64LtU)                                 \
  V(s2s_I64LeU)                                 \
  V(s2s_I64GtU)                                 \
  V(s2s_I64GeU)                                 \
  V(s2s_I64LtS)                                 \
  V(s2s_I64LeS)                                 \
  V(s2s_I64GtS)                                 \
  V(s2s_I64GeS)                                 \
  V(s2s_F32Eq)                                  \
  V(s2s_F32Ne)                                  \
  V(s2s_F32Lt)                                  \
  V(s2s_F32Le)                                  \
  V(s2s_F32Gt)                                  \
  V(s2s_F32Ge)                                  \
  V(s2s_F64Eq)                                  \
  V(s2s_F64Ne)                                  \
  V(s2s_F64Lt)                                  \
  V(s2s_F64Le)                                  \
  V(s2s_F64Gt)                                  \
  V(s2s_F64Ge)                                  \
  /* More binary operators. */                  \
  V(r2r_I32Shl)                                 \
  V(r2r_I32ShrU)                                \
  V(r2r_I32ShrS)                                \
  V(r2r_I64Shl)                                 \
  V(r2r_I64ShrU)                                \
  V(r2r_I64ShrS)                                \
  V(r2r_I32Rol)                                 \
  V(r2r_I32Ror)                                 \
  V(r2r_I64Rol)                                 \
  V(r2r_I64Ror)                                 \
  V(r2r_F32Min)                                 \
  V(r2r_F32Max)                                 \
  V(r2r_F64Min)                                 \
  V(r2r_F64Max)                                 \
  V(r2r_F32CopySign)                            \
  V(r2r_F64CopySign)                            \
  V(r2s_I32Shl)                                 \
  V(r2s_I32ShrU)                                \
  V(r2s_I32ShrS)                                \
  V(r2s_I64Shl)                                 \
  V(r2s_I64ShrU)                                \
  V(r2s_I64ShrS)                                \
  V(r2s_I32Rol)                                 \
  V(r2s_I32Ror)                                 \
  V(r2s_I64Rol)                                 \
  V(r2s_I64Ror)                                 \
  V(r2s_F32Min)                                 \
  V(r2s_F32Max)                                 \
  V(r2s_F64Min)                                 \
  V(r2s_F64Max)                                 \
  V(r2s_F32CopySign)                            \
  V(r2s_F64CopySign)                            \
  V(s2r_I32Shl)                                 \
  V(s2r_I32ShrU)                                \
  V(s2r_I32ShrS)                                \
  V(s2r_I64Shl)                                 \
  V(s2r_I64ShrU)                                \
  V(s2r_I64ShrS)                                \
  V(s2r_I32Rol)                                 \
  V(s2r_I32Ror)                                 \
  V(s2r_I64Rol)                                 \
  V(s2r_I64Ror)                                 \
  V(s2r_F32Min)                                 \
  V(s2r_F32Max)                                 \
  V(s2r_F64Min)                                 \
  V(s2r_F64Max)                                 \
  V(s2r_F32CopySign)                            \
  V(s2r_F64CopySign)                            \
  V(s2s_I32Shl)                                 \
  V(s2s_I32ShrU)                                \
  V(s2s_I32ShrS)                                \
  V(s2s_I64Shl)                                 \
  V(s2s_I64ShrU)                                \
  V(s2s_I64ShrS)                                \
  V(s2s_I32Rol)                                 \
  V(s2s_I32Ror)                                 \
  V(s2s_I64Rol)                                 \
  V(s2s_I64Ror)                                 \
  V(s2s_F32Min)                                 \
  V(s2s_F32Max)                                 \
  V(s2s_F64Min)                                 \
  V(s2s_F64Max)                                 \
  V(s2s_F32CopySign)                            \
  V(s2s_F64CopySign)                            \
  /* Unary operators. */                        \
  V(r2r_F32Abs)                                 \
  V(r2r_F32Neg)                                 \
  V(r2r_F32Ceil)                                \
  V(r2r_F32Floor)                               \
  V(r2r_F32Trunc)                               \
  V(r2r_F32NearestInt)                          \
  V(r2r_F32Sqrt)                                \
  V(r2r_F64Abs)                                 \
  V(r2r_F64Neg)                                 \
  V(r2r_F64Ceil)                                \
  V(r2r_F64Floor)                               \
  V(r2r_F64Trunc)                               \
  V(r2r_F64NearestInt)                          \
  V(r2r_F64Sqrt)                                \
  V(r2s_F32Abs)                                 \
  V(r2s_F32Neg)                                 \
  V(r2s_F32Ceil)                                \
  V(r2s_F32Floor)                               \
  V(r2s_F32Trunc)                               \
  V(r2s_F32NearestInt)                          \
  V(r2s_F32Sqrt)                                \
  V(r2s_F64Abs)                                 \
  V(r2s_F64Neg)                                 \
  V(r2s_F64Ceil)                                \
  V(r2s_F64Floor)                               \
  V(r2s_F64Trunc)                               \
  V(r2s_F64NearestInt)                          \
  V(r2s_F64Sqrt)                                \
  V(s2r_F32Abs)                                 \
  V(s2r_F32Neg)                                 \
  V(s2r_F32Ceil)                                \
  V(s2r_F32Floor)                               \
  V(s2r_F32Trunc)                               \
  V(s2r_F32NearestInt)                          \
  V(s2r_F32Sqrt)                                \
  V(s2r_F64Abs)                                 \
  V(s2r_F64Neg)                                 \
  V(s2r_F64Ceil)                                \
  V(s2r_F64Floor)                               \
  V(s2r_F64Trunc)                               \
  V(s2r_F64NearestInt)                          \
  V(s2r_F64Sqrt)                                \
  V(s2s_F32Abs)                                 \
  V(s2s_F32Neg)                                 \
  V(s2s_F32Ceil)                                \
  V(s2s_F32Floor)                               \
  V(s2s_F32Trunc)                               \
  V(s2s_F32NearestInt)                          \
  V(s2s_F32Sqrt)                                \
  V(s2s_F64Abs)                                 \
  V(s2s_F64Neg)                                 \
  V(s2s_F64Ceil)                                \
  V(s2s_F64Floor)                               \
  V(s2s_F64Trunc)                               \
  V(s2s_F64NearestInt)                          \
  V(s2s_F64Sqrt)                                \
  /* Numeric conversion operators. */           \
  V(r2r_I32ConvertI64)                          \
  V(r2r_I64SConvertF32)                         \
  V(r2r_I64SConvertF64)                         \
  V(r2r_I64UConvertF32)                         \
  V(r2r_I64UConvertF64)                         \
  V(r2r_I32SConvertF32)                         \
  V(r2r_I32UConvertF32)                         \
  V(r2r_I32SConvertF64)                         \
  V(r2r_I32UConvertF64)                         \
  V(r2r_I64SConvertI32)                         \
  V(r2r_I64UConvertI32)                         \
  V(r2r_F32SConvertI32)                         \
  V(r2r_F32UConvertI32)                         \
  V(r2r_F32SConvertI64)                         \
  V(r2r_F32UConvertI64)                         \
  V(r2r_F32ConvertF64)                          \
  V(r2r_F64SConvertI32)                         \
  V(r2r_F64UConvertI32)                         \
  V(r2r_F64SConvertI64)                         \
  V(r2r_F64UConvertI64)                         \
  V(r2r_F64ConvertF32)                          \
  V(r2s_I32ConvertI64)                          \
  V(r2s_I64SConvertF32)                         \
  V(r2s_I64SConvertF64)                         \
  V(r2s_I64UConvertF32)                         \
  V(r2s_I64UConvertF64)                         \
  V(r2s_I32SConvertF32)                         \
  V(r2s_I32UConvertF32)                         \
  V(r2s_I32SConvertF64)                         \
  V(r2s_I32UConvertF64)                         \
  V(r2s_I64SConvertI32)                         \
  V(r2s_I64UConvertI32)                         \
  V(r2s_F32SConvertI32)                         \
  V(r2s_F32UConvertI32)                         \
  V(r2s_F32SConvertI64)                         \
  V(r2s_F32UConvertI64)                         \
  V(r2s_F32ConvertF64)                          \
  V(r2s_F64SConvertI32)                         \
  V(r2s_F64UConvertI32)                         \
  V(r2s_F64SConvertI64)                         \
  V(r2s_F64UConvertI64)                         \
  V(r2s_F64ConvertF32)                          \
  V(s2r_I32ConvertI64)                          \
  V(s2r_I64SConvertF32)                         \
  V(s2r_I64SConvertF64)                         \
  V(s2r_I64UConvertF32)                         \
  V(s2r_I64UConvertF64)                         \
  V(s2r_I32SConvertF32)                         \
  V(s2r_I32UConvertF32)                         \
  V(s2r_I32SConvertF64)                         \
  V(s2r_I32UConvertF64)                         \
  V(s2r_I64SConvertI32)                         \
  V(s2r_I64UConvertI32)                         \
  V(s2r_F32SConvertI32)                         \
  V(s2r_F32UConvertI32)                         \
  V(s2r_F32SConvertI64)                         \
  V(s2r_F32UConvertI64)                         \
  V(s2r_F32ConvertF64)                          \
  V(s2r_F64SConvertI32)                         \
  V(s2r_F64UConvertI32)                         \
  V(s2r_F64SConvertI64)                         \
  V(s2r_F64UConvertI64)                         \
  V(s2r_F64ConvertF32)                          \
  V(s2s_I32ConvertI64)                          \
  V(s2s_I64SConvertF32)                         \
  V(s2s_I64SConvertF64)                         \
  V(s2s_I64UConvertF32)                         \
  V(s2s_I64UConvertF64)                         \
  V(s2s_I32SConvertF32)                         \
  V(s2s_I32UConvertF32)                         \
  V(s2s_I32SConvertF64)                         \
  V(s2s_I32UConvertF64)                         \
  V(s2s_I64SConvertI32)                         \
  V(s2s_I64UConvertI32)                         \
  V(s2s_F32SConvertI32)                         \
  V(s2s_F32UConvertI32)                         \
  V(s2s_F32SConvertI64)                         \
  V(s2s_F32UConvertI64)                         \
  V(s2s_F32ConvertF64)                          \
  V(s2s_F64SConvertI32)                         \
  V(s2s_F64UConvertI32)                         \
  V(s2s_F64SConvertI64)                         \
  V(s2s_F64UConvertI64)                         \
  V(s2s_F64ConvertF32)                          \
  /* Numeric reinterpret operators. */          \
  V(r2r_F32ReinterpretI32)                      \
  V(r2r_F64ReinterpretI64)                      \
  V(r2r_I32ReinterpretF32)                      \
  V(r2r_I64ReinterpretF64)                      \
  V(r2s_F32ReinterpretI32)                      \
  V(r2s_F64ReinterpretI64)                      \
  V(r2s_I32ReinterpretF32)                      \
  V(r2s_I64ReinterpretF64)                      \
  V(s2r_F32ReinterpretI32)                      \
  V(s2r_F64ReinterpretI64)                      \
  V(s2r_I32ReinterpretF32)                      \
  V(s2r_I64ReinterpretF64)                      \
  V(s2s_F32ReinterpretI32)                      \
  V(s2s_F64ReinterpretI64)                      \
  V(s2s_I32ReinterpretF32)                      \
  V(s2s_I64ReinterpretF64)                      \
  /* Bit operators. */                          \
  V(r2r_I32Clz)                                 \
  V(r2r_I32Ctz)                                 \
  V(r2r_I32Popcnt)             
"""


```