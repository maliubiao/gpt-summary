Response:
The user wants to understand the functionality of the C++ header file `v8/test/common/wasm/wasm-macro-gen.h`.

Here's a breakdown of the thought process to analyze the code and fulfill the request:

1. **Identify the core purpose:** The file name itself suggests it's related to WebAssembly (Wasm) and macro generation. The inclusion of `src/wasm/wasm-opcodes.h` further confirms this. The comments at the beginning also mention Wasm. Therefore, the primary function is likely to provide a set of macros to simplify the construction of Wasm bytecode.

2. **Examine the macros:**  Go through the defined macros and group them by functionality. Notice patterns like `U32_LE`, `U16_LE`, `U32V_X`, `WASM_...`.

    * **Endianness conversion:** Macros like `U32_LE` and `U16_LE` clearly handle little-endian byte ordering. This is important for Wasm's binary format.

    * **Wasm header:** `WASM_MODULE_HEADER` suggests the creation of the initial bytes of a Wasm module.

    * **Index handling:** `SIG_INDEX`, `FUNC_INDEX`, `EXCEPTION_INDEX` and related macros likely deal with encoding indices within the Wasm binary. The `U32V_1` naming convention hints at variable-length integer encoding (LEB128).

    * **Segment flags:**  `ACTIVE_NO_INDEX`, `PASSIVE`, etc., are likely constants representing different segment types in a Wasm module.

    * **Control flow:** Macros starting with `WASM_BLOCK`, `WASM_LOOP`, `WASM_IF`, `WASM_TRY`, `WASM_BR` directly map to Wasm control flow instructions. The suffixes like `_I`, `_L`, `_F`, `_D`, `_T`, `_R`, `_X` likely indicate the return type of the block/loop/if.

    * **Constants:**  `WASM_ZERO`, `WASM_ONE`, `WASM_ZERO64`, `WASM_ONE64` are shortcuts for common constant values. The `I32V_MIN`, `I32V_MAX`, etc., macros relate to the range of LEB128 encoded integers.

    * **Section handling:** The `SECTION` macro is used to define Wasm sections with their corresponding codes and content.

    * **Type conversions:** The `ToByte` constexpr functions provide type conversions to `uint8_t`.

    * **Load/Store operations:** `WASM_LOAD_MEM`, `WASM_STORE_MEM` and their variants clearly relate to memory access operations. The `LoadStoreOpcodeOf` function confirms this by mapping `MachineType` to specific Wasm opcodes.

    * **Function calls:** `WASM_CALL_FUNCTION`, `WASM_RETURN_CALL_FUNCTION` are for invoking Wasm functions.

    * **Object operations (GC):** Macros starting with `WASM_GC_OP`, such as `WASM_STRUCT_NEW`, `WASM_STRUCT_GET`, and `WASM_REF_NULL`, deal with garbage-collected object manipulation, a more recent addition to Wasm.

3. **Check for Torque relevance:** The prompt specifically asks about `.tq` files and Torque. This file ends in `.h`, not `.tq`, so it's not a Torque source file.

4. **Consider JavaScript relationship:** Wasm is designed to work closely with JavaScript. The macros here are used to *generate* the Wasm bytecode. While they don't *directly* execute JavaScript, they are crucial for creating Wasm modules that can be loaded and executed within a JavaScript environment. Provide a simple JavaScript example showing how a Wasm module (potentially built using these macros) is used.

5. **Think about code logic and examples:** The macros primarily *assemble* bytecode. There isn't complex *runtime* logic here. However, demonstrate how these macros are used by constructing a simple Wasm snippet (e.g., adding two numbers). Show the input values to the macros and the resulting bytecode sequence.

6. **Identify potential programming errors:**  Focus on the common mistakes related to manual bytecode construction. Incorrect opcode usage, wrong argument order, invalid index values, and exceeding LEB128 encoding limits are good examples.

7. **Summarize the functionality:** Concisely describe the purpose of the header file as a collection of macros for generating Wasm bytecode, highlighting its benefits (readability, reduced errors).

8. **Structure the response:** Organize the information into clear sections based on the user's request: functionality, Torque relevance, JavaScript relationship, code logic, common errors, and summary. Use formatting (bullet points, code blocks) to improve readability.

**(Self-Correction/Refinement during the process):**

* Initially, I might have focused too much on individual macro definitions. It's more important to group them by function to provide a higher-level understanding.
*  Realized that while there's no complex logic *within* the macros, demonstrating *their usage* involves a simple logical operation (addition).
* Considered whether to include all macros in the examples. Decided to keep the examples simple and focus on demonstrating the core concepts.
*  Ensured that the JavaScript example clearly shows the interaction between JavaScript and Wasm, even though the macros themselves don't directly involve JavaScript code.
这是一个V8源代码头文件，主要功能是为生成WebAssembly (Wasm) 字节码提供便捷的宏定义。它简化了手动构建Wasm二进制格式的过程，提高了代码的可读性和可维护性。

**功能归纳:**

该头文件定义了一系列C++宏，用于生成各种Wasm指令和数据结构，包括：

* **字节序处理:**  提供了将整数转换为小端字节序的宏 (`U32_LE`, `U16_LE`)，这对于Wasm二进制格式至关重要。
* **Wasm模块头部:** 定义了生成Wasm模块魔数和版本的宏 (`WASM_MODULE_HEADER`)。
* **索引处理:**  提供了用于生成不同类型索引的宏 (`SIG_INDEX`, `FUNC_INDEX`, `EXCEPTION_INDEX`)，通常使用LEB128编码。
* **段标志:** 定义了用于表示Wasm段的不同状态的宏 (`ACTIVE_NO_INDEX`, `PASSIVE`, 等)。
* **控制流指令:**  包含了用于生成各种Wasm控制流指令的宏，例如 `WASM_BLOCK`, `WASM_LOOP`, `WASM_IF`, `WASM_BR`, `WASM_RETURN` 等。这些宏可以方便地构造复杂的控制流结构。
* **常量:**  定义了生成常量值的宏，例如 `WASM_I32V`, `WASM_I64V`, `WASM_F32`, `WASM_F64`，以及预定义的零和一的常量 (`WASM_ZERO`, `WASM_ONE`)。
* **局部变量和全局变量操作:**  提供了用于获取和设置局部变量和全局变量的宏 (`WASM_LOCAL_GET`, `WASM_LOCAL_SET`, `WASM_GLOBAL_GET`, `WASM_GLOBAL_SET`)。
* **内存操作:**  定义了用于加载和存储内存的宏 (`WASM_LOAD_MEM`, `WASM_STORE_MEM`)，可以指定不同的数据类型、对齐方式和偏移量。
* **表格操作:**  提供了用于操作Wasm表格的宏 (`WASM_TABLE_GET`, `WASM_TABLE_SET`)。
* **函数调用:**  定义了用于调用Wasm函数的宏 (`WASM_CALL_FUNCTION`)。
* **结构体和引用类型操作 (GC提案相关):** 包含了一些用于创建、访问和操作结构体以及引用类型的宏，这些可能与WebAssembly的垃圾回收 (GC) 提案有关 (`WASM_STRUCT_NEW`, `WASM_STRUCT_GET`, `WASM_REF_NULL` 等)。
* **异常处理:**  提供了用于生成 `try-catch` 和 `throw` 等异常处理指令的宏 (`WASM_TRY_T`, `WASM_THROW`)。
* **LEB128 编码辅助:**  定义了用于生成 LEB128 格式无符号整数的宏 (`U32V_1` 到 `U32V_5`, `U64V_1` 到 `U64V_10`)。
* **辅助宏:**  提供了一些辅助宏，例如 `COUNT_ARGS` 用于计算参数数量，`SECTION` 用于定义Wasm的各个段。

**如果v8/test/common/wasm/wasm-macro-gen.h以.tq结尾，那它是个v8 torque源代码**

你说的没错。如果文件以 `.tq` 结尾，那么它就是一个 V8 Torque 源代码文件。Torque 是一种用于编写 V8 内部函数的领域特定语言。由于这个文件以 `.h` 结尾，所以它是 C++ 头文件。

**如果它与javascript的功能有关系，请用javascript举例说明**

虽然 `wasm-macro-gen.h` 是 C++ 头文件，用于 *生成* Wasm 字节码，但生成的 Wasm 模块最终会在 JavaScript 环境中运行。 因此，它与 JavaScript 功能有密切关系。

例如，假设我们使用 `wasm-macro-gen.h` 中的宏生成了一个简单的 Wasm 模块，该模块包含一个将两个整数相加的函数。以下 JavaScript 代码可以加载和调用这个 Wasm 模块：

```javascript
async function loadAndRunWasm() {
  const wasmBytes = new Uint8Array([
    0x00, 0x61, 0x73, 0x6d, // Magic number (\0asm)
    0x01, 0x00, 0x00, 0x00, // Version 1

    // Type section (define function signature)
    0x01, // Section ID: Type
    0x07, // Section size
    0x01, // Number of types
    0x60, // Function type
    0x02, 0x7f, 0x7f, // Two i32 parameters
    0x01, 0x7f,       // One i32 result

    // Function section (define functions)
    0x03, // Section ID: Function
    0x02, // Section size
    0x01, // Number of functions
    0x00, // Type index (referencing the function signature above)

    // Export section (export the function)
    0x07, // Section ID: Export
    0x07, // Section size
    0x01, // Number of exports
    0x03, 0x61, 0x64, 0x64, // Export name: "add"
    0x00, 0x00, // Export kind: function, function index 0

    // Code section (function bodies)
    0x0a, // Section ID: Code
    0x09, // Section size
    0x01, // Number of function bodies
    0x07, // Body size
    0x00, // Number of locals
    0x20, 0x00, // local.get 0
    0x20, 0x01, // local.get 1
    0x6a,       // i32.add
    0x0f         // return
  ]);

  const wasmModule = await WebAssembly.compile(wasmBytes);
  const wasmInstance = await WebAssembly.instantiate(wasmModule);

  const result = wasmInstance.exports.add(5, 10);
  console.log(result); // 输出: 15
}

loadAndRunWasm();
```

在这个例子中，`wasmBytes` 数组包含了手动构建的 Wasm 模块的二进制数据。 `wasm-macro-gen.h` 中的宏可以用来更方便地生成这个 `wasmBytes` 数组。例如，上述的 `i32.add` 指令可以使用一个宏来表示，而不是直接写 `0x6a`。

**如果有代码逻辑推理，请给出假设输入与输出**

`wasm-macro-gen.h` 本身不包含运行时代码逻辑，它主要是定义宏。但是，我们可以展示如何使用这些宏来生成具有特定逻辑的 Wasm 代码。

**假设输入 (使用宏):**

```c++
#include "v8/test/common/wasm/wasm-macro-gen.h"

const uint8_t kAddFunction[] = {
  WASM_MODULE_HEADER,
  SECTION(Type,
    1, // num types
    WASM_FUNCTION_SIGNATURE({WASM_I32, WASM_I32}, {WASM_I32})
  ),
  SECTION(Function,
    1, // num functions
    0  // type index
  ),
  SECTION(Export,
    1, // num exports
    WASM_EXPORT_FUNCTION("add", 0)
  ),
  SECTION(Code,
    1, // num functions
    WASM_FUNCTION_BODY(
      0, // no locals
      WASM_LOCAL_GET(0),
      WASM_LOCAL_GET(1),
      WASM_I32_ADD,
      WASM_RETURN0
    )
  )
};
```

**假设输出 (生成的 Wasm 字节码):**

```
00 61 73 6d 01 00 00 00 01 07 01 60 02 7f 7f 01 7f 03 02 01 00 07 07 01 03 61 64 64 00 00 0a 07 01 05 00 20 00 20 01 6a 0f
```

这个字节码表示一个简单的 Wasm 模块，它导出一个名为 "add" 的函数，该函数接受两个 i32 类型的参数并返回它们的和。

**如果涉及用户常见的编程错误，请举例说明**

在使用 `wasm-macro-gen.h` 或者手动构建 Wasm 字节码时，用户可能会犯以下编程错误：

1. **错误的指令操作码:** 使用了错误的 Wasm 指令操作码。例如，错误地使用了 `WASM_I32_SUB` (减法) 而不是 `WASM_I32_ADD` (加法)。
2. **错误的参数顺序或类型:**  Wasm 指令对参数的顺序和类型有严格的要求。例如，对于 `WASM_LOCAL_SET(index, value)`，确保 `value` 在 `index` 之前被压入栈。
3. **栈溢出或下溢:**  在执行 Wasm 代码时，操作栈需要正确管理。不正确的指令序列可能导致栈溢出 (尝试从空栈中弹出) 或下溢 (在栈满时尝试压入)。
4. **LEB128 编码错误:**  在手动编码索引或大小等值时，可能会错误地进行 LEB128 编码，导致解析错误。例如，未能正确设置 continuation bit (最高位)。
5. **类型不匹配:**  在进行类型转换或操作时，可能会发生类型不匹配的错误。例如，尝试将一个浮点数存储到需要整数类型的位置。
6. **超出边界的访问:** 尝试访问不存在的局部变量、全局变量或表格索引。

**示例 (使用宏时可能犯的错误):**

假设用户想生成一个将局部变量设置为 10 的指令，但错误地使用了宏的顺序：

```c++
// 错误示例
const uint8_t kSetLocal[] = {
  WASM_LOCAL_SET(0, WASM_I32V_1(10)) // 错误：WASM_LOCAL_SET 应该在值之后
};
```

正确的写法应该是：

```c++
const uint8_t kSetLocal[] = {
  WASM_I32V_1(10),
  WASM_LOCAL_SET(0)
};
```

这个错误是因为 `WASM_LOCAL_SET` 宏期望栈顶是需要设置的值。错误的顺序会导致 Wasm 虚拟机尝试将 `WASM_LOCAL_SET` 指令本身解释为要设置的值，从而导致类型错误或程序崩溃。

**这是第1部分，共2部分，请归纳一下它的功能**

`v8/test/common/wasm/wasm-macro-gen.h` 的主要功能是 **提供一组 C++ 宏，用于简化生成 WebAssembly (Wasm) 字节码的过程**。 这些宏抽象了 Wasm 二进制格式的细节，使得开发者可以使用更具可读性和易于维护的方式来构造 Wasm 模块。 它不是 Torque 源代码，但生成的 Wasm 模块最终会在 JavaScript 环境中运行。 虽然它本身不包含运行时逻辑，但可以用来生成包含特定逻辑的 Wasm 代码。 使用这些宏或手动构建 Wasm 字节码时，可能会遇到各种编程错误，例如指令操作码错误、参数顺序错误、栈管理错误、LEB128 编码错误和类型不匹配等。

Prompt: 
```
这是目录为v8/test/common/wasm/wasm-macro-gen.h的一个v8源代码， 请列举一下它的功能, 
如果v8/test/common/wasm/wasm-macro-gen.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_WASM_MACRO_GEN_H_
#define V8_WASM_MACRO_GEN_H_

#include "src/wasm/wasm-opcodes.h"

namespace v8::internal::wasm {

static constexpr uint8_t ToByte(int x) {
  DCHECK_EQ(static_cast<uint8_t>(x), x);
  return static_cast<uint8_t>(x);
}
static constexpr uint8_t ToByte(ValueTypeCode type_code) {
  return static_cast<uint8_t>(type_code);
}
static constexpr uint8_t ToByte(ModuleTypeIndex type_index) {
  DCHECK_EQ(static_cast<uint8_t>(type_index.index), type_index.index);
  return static_cast<uint8_t>(type_index.index);
}

}  // namespace v8::internal::wasm

#define U32_LE(v)                                          \
  static_cast<uint8_t>(v), static_cast<uint8_t>((v) >> 8), \
      static_cast<uint8_t>((v) >> 16), static_cast<uint8_t>((v) >> 24)

#define U16_LE(v) static_cast<uint8_t>(v), static_cast<uint8_t>((v) >> 8)

#define WASM_MODULE_HEADER U32_LE(kWasmMagic), U32_LE(kWasmVersion)

#define SIG_INDEX(v) U32V_1(v)
#define FUNC_INDEX(v) U32V_1(v)
#define EXCEPTION_INDEX(v) U32V_1(v)
#define NO_NAME U32V_1(0)
#define ENTRY_COUNT(v) U32V_1(v)

// Segment flags
#define ACTIVE_NO_INDEX 0
#define PASSIVE 1
#define ACTIVE_WITH_INDEX 2
#define DECLARATIVE 3
#define PASSIVE_WITH_ELEMENTS 5
#define ACTIVE_WITH_ELEMENTS 6
#define DECLARATIVE_WITH_ELEMENTS 7

// The table index field in an element segment was repurposed as a flags field.
// To specify a table index, we have to set the flag value to 2, followed by
// the table index.
#define TABLE_INDEX0 static_cast<uint8_t>(ACTIVE_NO_INDEX)
#define TABLE_INDEX(v) static_cast<uint8_t>(ACTIVE_WITH_INDEX), U32V_1(v)

#define ZERO_ALIGNMENT 0
#define ZERO_OFFSET 0

#define BR_TARGET(v) U32V_1(v)

#define MASK_7 ((1 << 7) - 1)
#define MASK_14 ((1 << 14) - 1)
#define MASK_21 ((1 << 21) - 1)
#define MASK_28 ((1 << 28) - 1)

#define U32V_1(x) static_cast<uint8_t>((x)&MASK_7)
#define U32V_2(x)                            \
  static_cast<uint8_t>(((x)&MASK_7) | 0x80), \
      static_cast<uint8_t>(((x) >> 7) & MASK_7)
#define U32V_3(x)                                         \
  static_cast<uint8_t>((((x)) & MASK_7) | 0x80),          \
      static_cast<uint8_t>((((x) >> 7) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((x) >> 14) & MASK_7)
#define U32V_4(x)                                          \
  static_cast<uint8_t>(((x)&MASK_7) | 0x80),               \
      static_cast<uint8_t>((((x) >> 7) & MASK_7) | 0x80),  \
      static_cast<uint8_t>((((x) >> 14) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((x) >> 21) & MASK_7)
#define U32V_5(x)                                          \
  static_cast<uint8_t>(((x)&MASK_7) | 0x80),               \
      static_cast<uint8_t>((((x) >> 7) & MASK_7) | 0x80),  \
      static_cast<uint8_t>((((x) >> 14) & MASK_7) | 0x80), \
      static_cast<uint8_t>((((x) >> 21) & MASK_7) | 0x80), \
      static_cast<uint8_t>((((x) >> 28) & MASK_7))

#define U64V_1(x) U32V_1(static_cast<uint32_t>(x))
#define U64V_2(x) U32V_2(static_cast<uint32_t>(x))
#define U64V_3(x) U32V_3(static_cast<uint32_t>(x))
#define U64V_4(x) U32V_4(static_cast<uint32_t>(x))
#define U64V_5(x)                                                  \
  static_cast<uint8_t>((uint64_t{x} & MASK_7) | 0x80),             \
      static_cast<uint8_t>(((uint64_t{x} >> 7) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((uint64_t{x} >> 14) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 21) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 28) & MASK_7))
#define U64V_6(x)                                                  \
  static_cast<uint8_t>((uint64_t{x} & MASK_7) | 0x80),             \
      static_cast<uint8_t>(((uint64_t{x} >> 7) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((uint64_t{x} >> 14) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 21) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 28) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 35) & MASK_7))
#define U64V_10(x)                                                 \
  static_cast<uint8_t>((uint64_t{x} & MASK_7) | 0x80),             \
      static_cast<uint8_t>(((uint64_t{x} >> 7) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((uint64_t{x} >> 14) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 21) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 28) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 35) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 42) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 49) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((uint64_t{x} >> 56) & MASK_7) | 0x80), \
      static_cast<uint8_t>((uint64_t{x} >> 63) & MASK_7)

// Convenience macros for building Wasm bytecode directly into a byte array.

//------------------------------------------------------------------------------
// Control.
//------------------------------------------------------------------------------
#define WASM_NOP kExprNop
#define WASM_END kExprEnd

#define ARITY_0 0
#define ARITY_1 1
#define ARITY_2 2
#define DEPTH_0 0
#define DEPTH_1 1
#define DEPTH_2 2

#define WASM_HEAP_TYPE(heap_type) \
  static_cast<uint8_t>((heap_type).code() & 0x7f)

#define WASM_REF_TYPE(type)                        \
  (type).kind() == kRef ? kRefCode : kRefNullCode, \
      WASM_HEAP_TYPE((type).heap_type())

#define WASM_BLOCK(...) kExprBlock, kVoidCode, __VA_ARGS__, kExprEnd
#define WASM_BLOCK_I(...) kExprBlock, kI32Code, __VA_ARGS__, kExprEnd
#define WASM_BLOCK_L(...) kExprBlock, kI64Code, __VA_ARGS__, kExprEnd
#define WASM_BLOCK_F(...) kExprBlock, kF32Code, __VA_ARGS__, kExprEnd
#define WASM_BLOCK_D(...) kExprBlock, kF64Code, __VA_ARGS__, kExprEnd
#define WASM_BLOCK_T(t, ...) \
  kExprBlock, static_cast<uint8_t>((t).value_type_code()), __VA_ARGS__, kExprEnd

#define WASM_BLOCK_R(type, ...) \
  kExprBlock, WASM_REF_TYPE(type), __VA_ARGS__, kExprEnd

#define WASM_BLOCK_X(typeidx, ...) \
  kExprBlock, ToByte(typeidx), __VA_ARGS__, kExprEnd

#define WASM_INFINITE_LOOP kExprLoop, kVoidCode, kExprBr, DEPTH_0, kExprEnd

#define WASM_LOOP(...) kExprLoop, kVoidCode, __VA_ARGS__, kExprEnd
#define WASM_LOOP_I(...) kExprLoop, kI32Code, __VA_ARGS__, kExprEnd
#define WASM_LOOP_L(...) kExprLoop, kI64Code, __VA_ARGS__, kExprEnd
#define WASM_LOOP_F(...) kExprLoop, kF32Code, __VA_ARGS__, kExprEnd
#define WASM_LOOP_D(...) kExprLoop, kF64Code, __VA_ARGS__, kExprEnd

#define WASM_LOOP_T(t, ...) \
  kExprLoop, static_cast<uint8_t>((t).value_type_code()), __VA_ARGS__, kExprEnd

#define WASM_LOOP_R(t, ...) kExprLoop, TYPE_IMM(t), __VA_ARGS__, kExprEnd

#define WASM_LOOP_X(typeidx, ...) \
  kExprLoop, ToByte(typeidx), __VA_ARGS__, kExprEnd

#define WASM_IF(cond, ...) cond, kExprIf, kVoidCode, __VA_ARGS__, kExprEnd

#define WASM_IF_T(t, cond, ...)                                            \
  cond, kExprIf, static_cast<uint8_t>((t).value_type_code()), __VA_ARGS__, \
      kExprEnd

#define WASM_IF_R(t, cond, ...) \
  cond, kExprIf, TYPE_IMM(t), __VA_ARGS__, kExprEnd

#define WASM_IF_X(typeidx, cond, ...) \
  cond, kExprIf, ToByte(typeidx), __VA_ARGS__, kExprEnd

#define WASM_IF_ELSE(cond, tstmt, fstmt) \
  cond, kExprIf, kVoidCode, tstmt, kExprElse, fstmt, kExprEnd

#define WASM_IF_ELSE_I(cond, tstmt, fstmt) \
  cond, kExprIf, kI32Code, tstmt, kExprElse, fstmt, kExprEnd
#define WASM_IF_ELSE_L(cond, tstmt, fstmt) \
  cond, kExprIf, kI64Code, tstmt, kExprElse, fstmt, kExprEnd
#define WASM_IF_ELSE_F(cond, tstmt, fstmt) \
  cond, kExprIf, kF32Code, tstmt, kExprElse, fstmt, kExprEnd
#define WASM_IF_ELSE_D(cond, tstmt, fstmt) \
  cond, kExprIf, kF64Code, tstmt, kExprElse, fstmt, kExprEnd

#define WASM_IF_ELSE_T(t, cond, tstmt, fstmt)                        \
  cond, kExprIf, static_cast<uint8_t>((t).value_type_code()), tstmt, \
      kExprElse, fstmt, kExprEnd

#define WASM_IF_ELSE_R(t, cond, tstmt, fstmt) \
  cond, kExprIf, WASM_REF_TYPE(t), tstmt, kExprElse, fstmt, kExprEnd

#define WASM_IF_ELSE_X(typeidx, cond, tstmt, fstmt) \
  cond, kExprIf, ToByte(typeidx), tstmt, kExprElse, fstmt, kExprEnd

#define WASM_TRY_T(t, trystmt) \
  kExprTry, static_cast<uint8_t>((t).value_type_code()), trystmt, kExprEnd
#define WASM_TRY_CATCH_T(t, trystmt, catchstmt, except)                       \
  kExprTry, static_cast<uint8_t>((t).value_type_code()), trystmt, kExprCatch, \
      except, catchstmt, kExprEnd
#define WASM_TRY_CATCH_CATCH_T(t, trystmt, except1, catchstmt1, except2,      \
                               catchstmt2)                                    \
  kExprTry, static_cast<uint8_t>((t).value_type_code()), trystmt, kExprCatch, \
      except1, catchstmt1, kExprCatch, except2, catchstmt2, kExprEnd
#define WASM_TRY_CATCH_R(t, trystmt, catchstmt) \
  kExprTry, WASM_REF_TYPE(t), trystmt, kExprCatch, catchstmt, kExprEnd
#define WASM_TRY_CATCH_ALL_T(t, trystmt, catchstmt)               \
  kExprTry, static_cast<uint8_t>((t).value_type_code()), trystmt, \
      kExprCatchAll, catchstmt, kExprEnd
#define WASM_TRY_DELEGATE(trystmt, depth) \
  kExprTry, kVoidCode, trystmt, kExprDelegate, depth
#define WASM_TRY_DELEGATE_T(t, trystmt, depth)                    \
  kExprTry, static_cast<uint8_t>((t).value_type_code()), trystmt, \
      kExprDelegate, depth

#define WASM_SELECT(tval, fval, cond) tval, fval, cond, kExprSelect
#define WASM_SELECT_I(tval, fval, cond) \
  tval, fval, cond, kExprSelectWithType, U32V_1(1), kI32Code
#define WASM_SELECT_L(tval, fval, cond) \
  tval, fval, cond, kExprSelectWithType, U32V_1(1), kI64Code
#define WASM_SELECT_F(tval, fval, cond) \
  tval, fval, cond, kExprSelectWithType, U32V_1(1), kF32Code
#define WASM_SELECT_D(tval, fval, cond) \
  tval, fval, cond, kExprSelectWithType, U32V_1(1), kF64Code
#define WASM_SELECT_R(tval, fval, cond) \
  tval, fval, cond, kExprSelectWithType, U32V_1(1), kExternRefCode
#define WASM_SELECT_A(tval, fval, cond) \
  tval, fval, cond, kExprSelectWithType, U32V_1(1), kFuncRefCode

#define WASM_BR(depth) kExprBr, static_cast<uint8_t>(depth)
#define WASM_BR_IF(depth, cond) cond, kExprBrIf, static_cast<uint8_t>(depth)
#define WASM_BR_IFD(depth, val, cond) \
  val, cond, kExprBrIf, static_cast<uint8_t>(depth), kExprDrop
#define WASM_CONTINUE(depth) kExprBr, static_cast<uint8_t>(depth)
#define WASM_UNREACHABLE kExprUnreachable
#define WASM_RETURN(...) __VA_ARGS__, kExprReturn
#define WASM_RETURN0 kExprReturn

#define WASM_BR_TABLE(key, count, ...) \
  key, kExprBrTable, U32V_1(count), __VA_ARGS__

#define WASM_THROW(index) kExprThrow, static_cast<uint8_t>(index)

//------------------------------------------------------------------------------
// Misc expressions.
//------------------------------------------------------------------------------
#define WASM_STMTS(...) __VA_ARGS__
#define WASM_ZERO WASM_I32V_1(0)
#define WASM_ONE WASM_I32V_1(1)
#define WASM_ZERO64 WASM_I64V_1(0)
#define WASM_ONE64 WASM_I64V_1(1)

#define I32V_MIN(length) -(1 << (6 + (7 * ((length)-1))))
#define I32V_MAX(length) ((1 << (6 + (7 * ((length)-1)))) - 1)
#define I64V_MIN(length) -(1LL << (6 + (7 * ((length)-1))))
#define I64V_MAX(length) ((1LL << (6 + 7 * ((length)-1))) - 1)

#define I32V_IN_RANGE(value, length) \
  ((value) >= I32V_MIN(length) && (value) <= I32V_MAX(length))
#define I64V_IN_RANGE(value, length) \
  ((value) >= I64V_MIN(length) && (value) <= I64V_MAX(length))

#define WASM_NO_LOCALS 0

//------------------------------------------------------------------------------
// Helpers for encoding sections and other fields with length prefix.
//------------------------------------------------------------------------------

template <typename... Args>
std::integral_constant<size_t, sizeof...(Args)> CountArgsHelper(Args...);
#define COUNT_ARGS(...) (decltype(CountArgsHelper(__VA_ARGS__))::value)

template <size_t num>
struct CheckLEB1 : std::integral_constant<size_t, num> {
  static_assert(num <= I32V_MAX(1), "LEB range check");
};
#define CHECK_LEB1(num) CheckLEB1<num>::value

#define ADD_COUNT(...) CHECK_LEB1(COUNT_ARGS(__VA_ARGS__)), __VA_ARGS__

#define SECTION(name, ...) k##name##SectionCode, ADD_COUNT(__VA_ARGS__)

namespace v8 {
namespace internal {
namespace wasm {

inline void CheckI32v(int32_t value, int length) {
  DCHECK(length >= 1 && length <= 5);
  DCHECK(length == 5 || I32V_IN_RANGE(value, length));
}

inline void CheckI64v(int64_t value, int length) {
  DCHECK(length >= 1 && length <= 10);
  DCHECK(length == 10 || I64V_IN_RANGE(value, length));
}

inline WasmOpcode LoadStoreOpcodeOf(MachineType type, bool store) {
  switch (type.representation()) {
    case MachineRepresentation::kWord8:
      return store ? kExprI32StoreMem8
                   : type.IsSigned() ? kExprI32LoadMem8S : kExprI32LoadMem8U;
    case MachineRepresentation::kWord16:
      return store ? kExprI32StoreMem16
                   : type.IsSigned() ? kExprI32LoadMem16S : kExprI32LoadMem16U;
    case MachineRepresentation::kWord32:
      return store ? kExprI32StoreMem : kExprI32LoadMem;
    case MachineRepresentation::kWord64:
      return store ? kExprI64StoreMem : kExprI64LoadMem;
    case MachineRepresentation::kFloat32:
      return store ? kExprF32StoreMem : kExprF32LoadMem;
    case MachineRepresentation::kFloat64:
      return store ? kExprF64StoreMem : kExprF64LoadMem;
    case MachineRepresentation::kSimd128:
      return store ? kExprS128StoreMem : kExprS128LoadMem;
    default:
      UNREACHABLE();
  }
}

// See comment on {WasmOpcode} for the encoding.
// This method handles opcodes with decoded length up to 3 bytes. Update if we
// exceed that opcode length.
inline uint16_t ExtractPrefixedOpcodeBytes(WasmOpcode opcode) {
  return (opcode > 0xffff) ? opcode & 0x0fff : opcode & 0xff;
}

}  // namespace wasm
}  // namespace internal
}  // namespace v8

//------------------------------------------------------------------------------
// Int32 Const operations
//------------------------------------------------------------------------------
#define WASM_I32V(val) WASM_I32V_5(val)

#define WASM_I32V_1(val)                                    \
  static_cast<uint8_t>(CheckI32v((val), 1), kExprI32Const), \
      U32V_1(static_cast<int32_t>(val))
#define WASM_I32V_2(val)                                    \
  static_cast<uint8_t>(CheckI32v((val), 2), kExprI32Const), \
      U32V_2(static_cast<int32_t>(val))
#define WASM_I32V_3(val)                                    \
  static_cast<uint8_t>(CheckI32v((val), 3), kExprI32Const), \
      U32V_3(static_cast<int32_t>(val))
#define WASM_I32V_4(val)                                    \
  static_cast<uint8_t>(CheckI32v((val), 4), kExprI32Const), \
      U32V_4(static_cast<int32_t>(val))
#define WASM_I32V_5(val)                                    \
  static_cast<uint8_t>(CheckI32v((val), 5), kExprI32Const), \
      U32V_5(static_cast<int32_t>(val))

//------------------------------------------------------------------------------
// Int64 Const operations
//------------------------------------------------------------------------------
#define WASM_I64V(val)                                                    \
  kExprI64Const,                                                          \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 21) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 28) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 35) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 42) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 49) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 56) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 63) & MASK_7)

#define WASM_I64V_1(val)                                        \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 1), \
                       kExprI64Const),                          \
      static_cast<uint8_t>(static_cast<int64_t>(val) & MASK_7)
#define WASM_I64V_2(val)                                                 \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 2),          \
                       kExprI64Const),                                   \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80), \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 7) & MASK_7)
#define WASM_I64V_3(val)                                                 \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 3),          \
                       kExprI64Const),                                   \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80), \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) | \
                           0x80),                                        \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 14) & MASK_7)
#define WASM_I64V_4(val)                                                  \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 4),           \
                       kExprI64Const),                                    \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 21) & MASK_7)
#define WASM_I64V_5(val)                                                  \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 5),           \
                       kExprI64Const),                                    \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 21) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 28) & MASK_7)
#define WASM_I64V_6(val)                                                  \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 6),           \
                       kExprI64Const),                                    \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 21) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 28) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 35) & MASK_7)
#define WASM_I64V_7(val)                                                  \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 7),           \
                       kExprI64Const),                                    \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 21) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 28) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 35) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 42) & MASK_7)
#define WASM_I64V_8(val)                                                  \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 8),           \
                       kExprI64Const),                                    \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 21) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 28) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 35) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 42) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 49) & MASK_7)
#define WASM_I64V_9(val)                                                  \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 9),           \
                       kExprI64Const),                                    \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 21) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 28) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 35) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 42) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 49) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 56) & MASK_7)
#define WASM_I64V_10(val)                                                 \
  static_cast<uint8_t>(CheckI64v(static_cast<int64_t>(val), 10),          \
                       kExprI64Const),                                    \
      static_cast<uint8_t>((static_cast<int64_t>(val) & MASK_7) | 0x80),  \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 7) & MASK_7) |  \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 14) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 21) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 28) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 35) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 42) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 49) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>(((static_cast<int64_t>(val) >> 56) & MASK_7) | \
                           0x80),                                         \
      static_cast<uint8_t>((static_cast<int64_t>(val) >> 63) & MASK_7)

#define WASM_F32(val)                                                         \
  kExprF32Const,                                                              \
      static_cast<uint8_t>(base::bit_cast<int32_t>(static_cast<float>(val))), \
      static_cast<uint8_t>(                                                   \
          base::bit_cast<uint32_t>(static_cast<float>(val)) >> 8),            \
      static_cast<uint8_t>(                                                   \
          base::bit_cast<uint32_t>(static_cast<float>(val)) >> 16),           \
      static_cast<uint8_t>(                                                   \
          base::bit_cast<uint32_t>(static_cast<float>(val)) >> 24)
#define WASM_F64(val)                                                \
  kExprF64Const,                                                     \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val))),       \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val)) >> 8),  \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val)) >> 16), \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val)) >> 24), \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val)) >> 32), \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val)) >> 40), \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val)) >> 48), \
      static_cast<uint8_t>(                                          \
          base::bit_cast<uint64_t>(static_cast<double>(val)) >> 56)

#define WASM_LOCAL_GET(index) kExprLocalGet, static_cast<uint8_t>(index)
#define WASM_LOCAL_SET(index, val) \
  val, kExprLocalSet, static_cast<uint8_t>(index)
#define WASM_LOCAL_TEE(index, val) \
  val, kExprLocalTee, static_cast<uint8_t>(index)
#define WASM_DROP kExprDrop
#define WASM_GLOBAL_GET(index) kExprGlobalGet, static_cast<uint8_t>(index)
#define WASM_GLOBAL_SET(index, val) \
  val, kExprGlobalSet, static_cast<uint8_t>(index)
#define WASM_TABLE_GET(table_index, index) \
  index, kExprTableGet, static_cast<uint8_t>(table_index)
#define WASM_TABLE_SET(table_index, index, val) \
  index, val, kExprTableSet, static_cast<uint8_t>(table_index)
#define WASM_LOAD_MEM(type, index)                             \
  index,                                                       \
      static_cast<uint8_t>(                                    \
          v8::internal::wasm::LoadStoreOpcodeOf(type, false)), \
      ZERO_ALIGNMENT, ZERO_OFFSET
#define WASM_STORE_MEM(type, index, val)                                       \
  index, val,                                                                  \
      static_cast<uint8_t>(v8::internal::wasm::LoadStoreOpcodeOf(type, true)), \
      ZERO_ALIGNMENT, ZERO_OFFSET
#define WASM_LOAD_MEM_OFFSET(type, offset, index)              \
  index,                                                       \
      static_cast<uint8_t>(                                    \
          v8::internal::wasm::LoadStoreOpcodeOf(type, false)), \
      ZERO_ALIGNMENT, offset
#define WASM_STORE_MEM_OFFSET(type, offset, index, val)                        \
  index, val,                                                                  \
      static_cast<uint8_t>(v8::internal::wasm::LoadStoreOpcodeOf(type, true)), \
      ZERO_ALIGNMENT, offset
#define WASM_LOAD_MEM_ALIGNMENT(type, index, alignment)        \
  index,                                                       \
      static_cast<uint8_t>(                                    \
          v8::internal::wasm::LoadStoreOpcodeOf(type, false)), \
      alignment, ZERO_OFFSET
#define WASM_STORE_MEM_ALIGNMENT(type, index, alignment, val)                  \
  index, val,                                                                  \
      static_cast<uint8_t>(v8::internal::wasm::LoadStoreOpcodeOf(type, true)), \
      alignment, ZERO_OFFSET
#define WASM_F16_LOAD_MEM(index) \
  index, WASM_NUMERIC_OP(kExprF32LoadMemF16), ZERO_ALIGNMENT, ZERO_OFFSET
#define WASM_F16_STORE_MEM(index, val) \
  index, val, WASM_NUMERIC_OP(kExprF32StoreMemF16), ZERO_ALIGNMENT, ZERO_OFFSET
#define WASM_RETHROW(index) kExprRethrow, static_cast<uint8_t>(index)

#define WASM_CALL_FUNCTION0(index) \
  kExprCallFunction, static_cast<uint8_t>(index)
#define WASM_CALL_FUNCTION(index, ...) \
  __VA_ARGS__, kExprCallFunction, static_cast<uint8_t>(index)

#define WASM_RETURN_CALL_FUNCTION0(index) \
  kExprReturnCall, static_cast<uint8_t>(index)
#define WASM_RETURN_CALL_FUNCTION(index, ...) \
  __VA_ARGS__, kExprReturnCall, static_cast<uint8_t>(index)

#define TABLE_ZERO 0

//------------------------------------------------------------------------------
// Heap-allocated object operations.
//------------------------------------------------------------------------------
#define WASM_GC_OP(op) kGCPrefix, static_cast<uint8_t>(op)
#define WASM_STRUCT_NEW(typeidx, ...) \
  __VA_ARGS__, WASM_GC_OP(kExprStructNew), ToByte(typeidx)
#define WASM_STRUCT_NEW_DEFAULT(typeidx) \
  WASM_GC_OP(kExprStructNewDefault), ToByte(typeidx)
#define WASM_STRUCT_GET(typeidx, fieldidx, struct_obj)     \
  struct_obj, WASM_GC_OP(kExprStructGet), ToByte(typeidx), \
      static_cast<uint8_t>(fieldidx)
#define WASM_STRUCT_GET_S(typeidx, fieldidx, struct_obj)    \
  struct_obj, WASM_GC_OP(kExprStructGetS), ToByte(typeidx), \
      static_cast<uint8_t>(fieldidx)
#define WASM_STRUCT_GET_U(typeidx, fieldidx, struct_obj)    \
  struct_obj, WASM_GC_OP(kExprStructGetU), ToByte(typeidx), \
      static_cast<uint8_t>(fieldidx)
#define WASM_STRUCT_SET(typeidx, fieldidx, struct_obj, value)     \
  struct_obj, value, WASM_GC_OP(kExprStructSet), ToByte(typeidx), \
      static_cast<uint8_t>(fieldidx)
#define WASM_REF_NULL(type_encoding) kExprRefNull, ToByte(type_encoding)
#define WASM_REF_FUNC(index) kExprRefFunc, index
#define WASM_REF_IS_NULL(val) val, kExprRefIsNull
#define WASM_REF_AS_NON_NULL(val) val, kExprRefAsNonNull
#define WASM_REF_EQ(lhs, rhs) lhs, rhs, kExprRefEq
#define WASM_REF_TEST(ref, typeidx) \
  ref, WASM_GC_OP(kExprRefTest), ToByte(typeidx)
#define WASM_REF_TEST_NULL(ref, typeidx) \
  ref, WASM_GC_OP(kExprRefTestNull), ToByte(typeidx)
#define WASM_REF_CAST(ref, typeidx) \
  ref, WASM_GC_OP(kExprRefCast), ToByte(typeidx)
#define WASM_REF_CAST_NULL(ref, typeidx) \
  ref, WASM_GC_OP(kExprRefCastNull), ToByte(typeidx)
// Takes a reference value from the value stack to allow sequences of
// conditional branches.
#define WASM_BR_ON_CAST(depth, sourcetype, targettype)   \
  WASM_GC_OP(kExprBrOnCast),                       
"""


```