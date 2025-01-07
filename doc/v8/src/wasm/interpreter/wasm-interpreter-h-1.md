Response:
The user wants me to analyze a C++ header file (`wasm-interpreter.h`) which is a part of the V8 JavaScript engine.
The goal is to understand its functionality based on the provided code snippet.
The provided code snippet seems to be a part of a lookup table for WebAssembly opcodes and some data structures related to the WebAssembly interpreter.

Here's a breakdown of my thought process:

1. **Identify the core data structure:** The initial part of the provided code defines a `kRegModes` array. This array maps WebAssembly opcodes (identified by their byte value) to pairs of `RegMode`. This strongly suggests that the file is related to how the interpreter handles different register types for various WASM operations.

2. **Analyze `RegMode`:** The existence of `RegMode::kI32Reg`, `RegMode::kI64Reg`, `RegMode::kF32Reg`, `RegMode::kF64Reg`, and `RegMode::kNoReg` suggests that the interpreter needs to track the types of values being processed.

3. **Connect to WebAssembly:** The comments like `// 0x6f I32RemS` clearly link the byte values to specific WebAssembly instructions. This confirms that the code deals with the execution of WebAssembly bytecode.

4. **Consider the file name:** The path `v8/src/wasm/interpreter/wasm-interpreter.h` confirms this is part of the WebAssembly interpreter within V8. The `.h` extension indicates a header file, likely containing declarations of classes, structs, enums, and constants used by the interpreter.

5. **Examine other data structures:**
    - `ExternalCallResult`: This enum likely represents the outcome of calling an external function from within the WebAssembly code.
    - `BranchOnCastData`: This struct seems related to type checking and branching during cast operations in WebAssembly.
    - `WasmInstruction`: This is a crucial struct. It encapsulates information about a single WebAssembly instruction, including its opcode, length, position, and optional data. The `Optional` union suggests different kinds of data are associated with various instructions (e.g., indices, immediate values, branch table information).
    - `Slot`: This struct likely represents a slot on the interpreter's stack, storing the value type, offset, and potentially a reference stack index.

6. **Look for connections to JavaScript:**  While the code is primarily about WebAssembly execution, the purpose of the V8 engine is to run JavaScript. WebAssembly's integration with JavaScript is a key aspect. The presence of "ref" types hints at interaction with JavaScript object references. The `ExternalCallResult` also suggests the possibility of calling JavaScript functions from WebAssembly.

7. **Infer functionality from data structures and constants:**
    - `kSlotSize`: Defines the size of a stack slot.
    - `kCodeOffsetSize`: Defines the size of a code offset.
    - `kInstructionTableSize`, `kInstructionTableMask`: These constants suggest the existence of a table for instruction handlers.
    - `InstructionHandler`: This enum likely lists identifiers for functions that handle the execution of different WebAssembly instructions. The `FOREACH_INSTR_HANDLER` macro strongly supports this.
    - `WasmEHData`, `WasmEHDataGenerator`: These classes seem to handle WebAssembly exception handling (EH). The structures within (`TryBlock`, `CatchHandler`, `CatchBlock`) are standard components of exception handling mechanisms.
    - `WasmBytecode`, `WasmBytecodeGenerator`: These classes are responsible for representing and generating the interpreted bytecode for a WebAssembly function. This includes information about the code itself, stack frame size, function signature, and exception handling data.

8. **Address the specific questions:**
    - **Functionality:** List the inferred functionalities.
    - **`.tq` extension:** Confirm that `.h` is C++ and `.tq` would indicate Torque.
    - **Relationship to JavaScript:** Explain the likely connection through interoperability.
    - **JavaScript example:** Provide a simple example demonstrating WebAssembly being used within JavaScript.
    - **Code logic reasoning:** Select a simple opcode and explain its input/output based on `RegMode`.
    - **Common programming errors:** Discuss typical WebAssembly errors that the interpreter might encounter.
    - **Summary of functionality:** Condense the identified functionalities into a concise summary.

9. **Structure the response:** Organize the findings logically, addressing each part of the user's request. Use clear and concise language. Provide code examples where appropriate.

By following these steps, I can analyze the provided code snippet and provide a comprehensive answer to the user's query.
这是v8源代码文件 `v8/src/wasm/interpreter/wasm-interpreter.h` 的第二部分，主要包含以下功能：

**1. WebAssembly 指令定义和元数据:**

* **`kRegModes` 数组:**  这个常量数组定义了每个 WebAssembly 指令（通过其操作码索引）所需的输入和输出寄存器模式 (`RegMode`). 例如，`{RegMode::kI32Reg, RegMode::kI32Reg}` 表示该指令操作 32 位整数寄存器。`RegMode::kNoReg` 表示没有寄存器操作。这对于解释器模拟 WebAssembly 的操作数栈和寄存器至关重要。
* **`kSlotSize` 和 `kCodeOffsetSize`:** 定义了栈槽和代码偏移量的大小，通常是 32 位整数。

**2. 外部调用处理:**

* **`ExternalCallResult` 枚举:**  定义了从 WebAssembly 调用外部函数的结果，可能是正常返回 (`EXTERNAL_RETURNED`) 或抛出异常 (`EXTERNAL_EXCEPTION`)。

**3. 类型转换分支数据:**

* **`BranchOnCastData` 结构体:** 存储了类型转换分支指令 (`br_on_cast`) 的相关信息，例如目标标签深度、是否允许空值以及目标类型。

**4. WebAssembly 指令结构体:**

* **`WasmInstruction` 结构体:**  这是表示单个 WebAssembly 指令的核心结构体。
    * **`orig`:** 原始操作码字节。
    * **`opcode`:**  对应的 `WasmOpcode` 枚举值。
    * **`length`:** 指令的字节长度。
    * **`pc`:**  指令在代码流中的程序计数器 (Program Counter)。
    * **`optional` union:**  一个联合体，用于存储不同类型指令的额外信息，例如：
        * **`index`:** 全局变量、局部变量、标签、内存、表 的索引。
        * **`i32`, `i64`, `f32`, `f64`:**  立即数。
        * **`offset`:** 内存访问偏移量。
        * **`depth`:**  控制流指令的深度。
        * **`indirect_call`:**  间接调用指令的表索引和签名索引。
        * **`br_table`:**  `br_table` 指令的表格计数和标签索引。
        * **`block`:** `block`, `loop`, `if` 等块结构的信息，包括签名索引和返回值类型。
        * **其他 GC (垃圾回收) 和 SIMD 相关的数据。**
    * **`InputRegMode()` 和 `SupportsToRegister()`:**  辅助方法，用于获取指令的输入寄存器模式和是否支持将结果写入寄存器。

**5. 栈槽 (Slot) 结构体:**

* **`Slot` 结构体:**  表示解释器栈上的一个槽位，用于存储 WebAssembly 的值。
    * **`value_type`:** 存储在该槽位中的值的类型 (`ValueType`)。
    * **`slot_offset`:** 该槽位在栈帧中的偏移量。
    * **`ref_stack_index`:**  如果该槽位存储的是引用类型，则指向引用栈的索引。

**6. 指令处理函数:**

* **`trace_PushSlot` 函数模板:**  一个用于在执行过程中追踪栈操作的函数模板。
* **`value_type` 函数模板和特化:**  根据 C++ 类型返回对应的 `ValueType`，方便类型推断。
* **`kInstructionTableSize` 和 `kInstructionTableMask`:**  定义了指令处理函数表的尺寸和掩码。
* **`InstructionHandler` 枚举:**  定义了各种指令处理函数的 ID。每个枚举值都对应一个特定的指令处理逻辑。`FOREACH_INSTR_HANDLER` 宏用于自动生成这些枚举值。
* **`ReadFnId` 函数:**  从字节码流中读取 `InstructionHandler`。

**7. 异常处理 (Exception Handling) 数据结构:**

* **`WasmEHData` 类:**  用于存储和管理 WebAssembly 函数的异常处理信息。
    * **`CatchHandler` 结构体:**  表示一个 `catch` 处理程序，包含捕获块的索引、异常标签索引和代码偏移量。
    * **`TryBlock` 结构体:**  表示一个 `try` 块，包含父块或匹配的 `try` 块的索引、祖先 `try` 块的索引、委托 `try` 块的索引、`catch` 处理程序列表和结束指令的代码偏移量。
    * **`CatchBlock` 结构体:**  表示一个 `catch` 块，包含对应的 `try` 块索引以及捕获参数在栈上的偏移量和引用栈索引。
    * 提供了获取 `TryBlock`、父 `TryBlock`、委托 `TryBlock` 的方法，以及获取 `catch` 块结束指令偏移量和异常载荷槽偏移量的方法。
    * 包含用于设置和获取捕获的异常的方法。
* **`WasmEHDataGenerator` 类:**  继承自 `WasmEHData`，用于生成 WebAssembly 异常处理信息。提供了添加 `try` 块、`catch` 块、委托块和结束 `try-catch` 块的方法，以及记录可能抛出异常的指令的方法。

**8. WebAssembly 字节码表示:**

* **`WasmBytecode` 类:**  表示 WebAssembly 函数的字节码。
    * 存储了代码数据、代码长度、栈帧大小、函数签名、解释器代码、块数量、常量槽数据、引用槽数量以及异常处理数据。
    * 提供了访问代码、代码大小、函数索引、块数量、函数签名、参数/返回值/局部变量数量和大小的方法。
    * 提供了计算参数和返回值在槽位中大小的静态方法。
    * 提供了获取与代码偏移量对应的 `TryBlock` 以及与 `catch` 块相关的异常载荷信息的方法。
* **`WasmBytecodeGenerator` 类:**  用于生成 `WasmBytecode` 对象。
    * 包含一个 `BlockData` 内部结构体，用于跟踪代码生成过程中每个块的信息。
    * 提供了添加字节码、管理操作数栈、处理控制流指令（`block`、`loop`、`if`、`else`、`try`、`catch`）、处理分支跳转、管理常量槽等方法。
    * 维护了槽位信息 (`slots_`) 和常量槽缓存 (`i32_const_cache_` 等)。

**归纳一下 `v8/src/wasm/interpreter/wasm-interpreter.h` 的功能（基于提供的第二部分代码）：**

这段代码定义了 V8 中 WebAssembly 解释器的核心数据结构和枚举，用于表示和处理 WebAssembly 字节码的执行。它包括：

* **WebAssembly 指令的元数据:**  定义了每个指令的寄存器操作模式。
* **WebAssembly 指令的表示:**  `WasmInstruction` 结构体用于存储单个指令的详细信息。
* **解释器栈的表示:** `Slot` 结构体用于表示栈上的槽位。
* **指令处理函数的定义:**  `InstructionHandler` 枚举定义了不同指令的处理函数 ID。
* **WebAssembly 异常处理机制的表示:** `WasmEHData` 和 `WasmEHDataGenerator` 类用于存储和生成异常处理信息。
* **WebAssembly 字节码的表示和生成:** `WasmBytecode` 和 `WasmBytecodeGenerator` 类用于存储和生成 WebAssembly 函数的解释器可执行字节码。

**关于问题中的其他点：**

* **`.tq` 结尾:**  如果 `v8/src/wasm/interpreter/wasm-interpreter.h` 以 `.tq` 结尾，那么它确实是一个 V8 Torque 源代码文件。但从你提供的文件路径来看，它以 `.h` 结尾，所以是 C++ 头文件。

* **与 JavaScript 的关系:**  WebAssembly 允许 JavaScript 代码加载和执行 WebAssembly 模块。V8 引擎负责编译和解释 JavaScript 代码以及执行 WebAssembly 模块。`wasm-interpreter.h` 中定义的数据结构和类是 V8 执行 WebAssembly 代码的关键部分。

**JavaScript 示例:**

```javascript
async function loadWasm() {
  const response = await fetch('my_wasm_module.wasm');
  const buffer = await response.arrayBuffer();
  const module = await WebAssembly.instantiate(buffer);
  const add = module.instance.exports.add; // 假设 WASM 模块导出了一个名为 add 的函数
  const result = add(5, 3);
  console.log(result); // 输出 8
}

loadWasm();
```

在这个例子中，JavaScript 使用 `WebAssembly.instantiate` 加载和实例化一个 WebAssembly 模块。V8 引擎在幕后会解析 WASM 字节码，并使用类似 `wasm-interpreter.h` 中定义的数据结构和逻辑来执行导出的函数（如 `add`）。

* **代码逻辑推理 (假设输入与输出):**

假设我们执行 `I32Add` 指令 (操作码 0x6a)。

**假设输入:**

1. 解释器当前执行到操作码 `0x6a`。
2. 操作数栈顶的两个槽位分别存储着两个 `i32` 类型的值，例如 `a = 10` 和 `b = 5`。
3. 指令的 `kRegModes` 定义为 `{RegMode::kI32Reg, RegMode::kI32Reg}`，表示需要两个 32 位整数寄存器作为输入。

**代码逻辑 (简化):**

解释器会：

1. 从操作数栈弹出栈顶的两个值 (`b` 和 `a`)，并将它们加载到两个 32 位整数寄存器中。
2. 执行 32 位整数加法操作：`result = a + b`。
3. 将结果 (`result = 15`) 推送到操作数栈顶，类型为 `i32`。

**假设输出:**

操作数栈顶会有一个新的槽位，存储着 `i32` 类型的值 `15`。

* **用户常见的编程错误 (举例说明):**

在编写 WebAssembly 代码时，一个常见的错误是**类型不匹配**。例如，尝试对浮点数执行整数运算，或者将一个不兼容类型的引用赋值给另一个引用。

**WebAssembly 示例 (WAT 文本格式):**

```wasm
(module
  (func $f (param $p i32) (result f32)
    local.get $p
    f32.convert_i32_s  ;; 将 i32 转换为 f32
    local.get $p
    f32.add           ;; 将 f32 与 i32 相加 - 这是一个类型错误
  )
  (export "my_func" (func $f))
)
```

如果 WebAssembly 解释器执行到 `f32.add` 指令时，发现栈顶的两个操作数分别是 `f32` 和 `i32` 类型，就会抛出一个类型错误。 `wasm-interpreter.h` 中定义的 `RegMode` 和类型检查机制就是为了捕获这类错误。

Prompt: 
```
这是目录为v8/src/wasm/interpreter/wasm-interpreter.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/interpreter/wasm-interpreter.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
/ 0x6f I32RemS
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x70 I32RemU
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x71 I32And
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x72 I32Ior
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x73 I32Xor
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x74 I32Shl
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x75 I32ShrS
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x76 I32ShrU
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x77 I32Rol
    {RegMode::kI32Reg, RegMode::kI32Reg},  // 0x78 I32Ror

    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x79 I64Clz
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x7a I64Ctz
    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0x7b I64Popcnt
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x7c I64Add
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x7d I64Sub
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x7e I64Mul
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x7f I64DivS
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x80 I64DivU
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x81 I64RemS
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x82 I64RemU
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x83 I64And
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x84 I64Ior
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x85 I64Xor
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x86 I64Shl
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x87 I64ShrS
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x88 I64ShrU
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x89 I64Rol
    {RegMode::kI64Reg, RegMode::kI64Reg},  // 0x8a I64Ror

    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x8b F32Abs
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x8c F32Neg
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x8d F32Ceil
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x8e F32Floor
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x8f F32Trunc
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x90 F32NearestInt
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x91 F32Sqrt
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x92 F32Add
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x93 F32Sub
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x94 F32Mul
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x95 F32Div
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x96 F32Min
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x97 F32Max
    {RegMode::kF32Reg, RegMode::kF32Reg},  // 0x98 F32CopySign

    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0x99 F64Abs
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0x9a F64Neg
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0x9b F64Ceil
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0x9c F64Floor
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0x9d F64Trunc
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0x9e F64NearestInt
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0x9f F64Sqrt
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0xa0 F64Add
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0xa1 F64Sub
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0xa2 F64Mul
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0xa3 F64Div
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0xa4 F64Min
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0xa5 F64Max
    {RegMode::kF64Reg, RegMode::kF64Reg},  // 0xa6 F64CopySign

    {RegMode::kI64Reg, RegMode::kI32Reg},  // 0xa7 I32ConvertI64
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0xa8 I32SConvertF32
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0xa9 I32UConvertF32
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0xaa I32SConvertF64
    {RegMode::kF64Reg, RegMode::kI32Reg},  // 0xab I32UConvertF64
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0xac I64SConvertI32
    {RegMode::kI32Reg, RegMode::kI64Reg},  // 0xad I64UConvertI32
    {RegMode::kF32Reg, RegMode::kI64Reg},  // 0xae I64SConvertF32
    {RegMode::kF32Reg, RegMode::kI64Reg},  // 0xaf I64UConvertF32
    {RegMode::kF64Reg, RegMode::kI64Reg},  // 0xb0 I64SConvertF64
    {RegMode::kF64Reg, RegMode::kI64Reg},  // 0xb1 I64UConvertF64
    {RegMode::kI32Reg, RegMode::kF32Reg},  // 0xb2 F32SConvertI32
    {RegMode::kI32Reg, RegMode::kF32Reg},  // 0xb3 F32UConvertI32
    {RegMode::kI64Reg, RegMode::kF32Reg},  // 0xb4 F32SConvertI64
    {RegMode::kI64Reg, RegMode::kF32Reg},  // 0xb5 F32UConvertI64
    {RegMode::kF64Reg, RegMode::kF32Reg},  // 0xb6 F32ConvertF64
    {RegMode::kI32Reg, RegMode::kF64Reg},  // 0xb7 F64SConvertI32
    {RegMode::kI32Reg, RegMode::kF64Reg},  // 0xb8 F64UConvertI32
    {RegMode::kI64Reg, RegMode::kF64Reg},  // 0xb9 F64SConvertI64
    {RegMode::kI64Reg, RegMode::kF64Reg},  // 0xba F64UConvertI64
    {RegMode::kF32Reg, RegMode::kF64Reg},  // 0xbb F64ConvertF32
    {RegMode::kF32Reg, RegMode::kI32Reg},  // 0xbc I32ReinterpretF32
    {RegMode::kF64Reg, RegMode::kI64Reg},  // 0xbd I64ReinterpretF64
    {RegMode::kI32Reg, RegMode::kF32Reg},  // 0xbe F32ReinterpretI32
    {RegMode::kI64Reg, RegMode::kF64Reg},  // 0xbf F64ReinterpretI64

    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc0 I32SExtendI8
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc1 I32SExtendI16
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc2 I64SExtendI8
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc3 I64SExtendI16
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc4 I64SExtendI32

    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc5 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc6 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc7 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc8 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xc9 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xca (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xcb (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xcc (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xcd (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xce (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xcf (reserved)

    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd0 RefNull - ref
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd1 RefIsNull - ref
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd2 RefFunc - ref
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd3 RefEq - ref
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd4 RefAsNonNull
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd5 BrOnNull
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd6 BrOnNonNull
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd7 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd8 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xd9 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xda (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xdb (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xdc (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xdd (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xde (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xdf (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe0 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe1 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe2 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe3 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe4 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe5 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe6 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe7 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe8 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xe9 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xea (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xeb (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xec (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xed (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xee (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xef (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf0 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf1 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf2 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf3 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf4 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf5 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf6 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf7 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf8 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xf9 (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xfa (reserved)
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xfb - GC prefix
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xfc - Numeric prefix
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xfd - Simd prefix
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xfe - Atomic prefix
    {RegMode::kNoReg, RegMode::kNoReg},  // 0xff (reserved)
};

static const size_t kSlotSize = sizeof(int32_t);
static const ptrdiff_t kCodeOffsetSize = sizeof(int32_t);

enum ExternalCallResult {
  // The function was executed and returned normally.
  EXTERNAL_RETURNED,
  // The function was executed, threw an exception.
  EXTERNAL_EXCEPTION
};

struct BranchOnCastData {
  uint32_t label_depth;
  uint32_t src_is_null : 1;   //  BrOnCastFlags
  uint32_t res_is_null : 1;   //  BrOnCastFlags
  uint32_t target_type : 30;  //  HeapType
};

struct WasmInstruction {
  union Optional {
    uint32_t index;  // global/local/label/memory/table index
    int32_t i32;
    int64_t i64;
    float f32;
    double f64;
    uint64_t offset;
    uint32_t depth;
    struct IndirectCall {
      uint32_t table_index;
      uint32_t sig_index;
    } indirect_call;
    struct BrTable {
      uint32_t table_count;
      uint32_t labels_index;
    } br_table;
    struct Block {
      ModuleTypeIndex sig_index;
      uint32_t value_type_bitfield;  // return type or kVoid if no return type
                                     // or kBottom if sig_index is valid.
      constexpr ValueType value_type() const {
        return ValueType::FromRawBitField(value_type_bitfield);
      }
    } block;
    struct TableInit {
      uint32_t table_index;
      uint32_t element_segment_index;
    } table_init;
    struct TableCopy {
      uint32_t dst_table_index;
      uint32_t src_table_index;
    } table_copy;
    uint8_t simd_lane : 4;
    struct SimdLaneLoad {
      uint8_t lane : 4;
      uint8_t : 0;
      uint64_t offset : 48;
    } simd_loadstore_lane;
    struct GC_FieldImmediate {
      uint32_t struct_index;
      uint32_t field_index;
    } gc_field_immediate;
    struct GC_MemoryImmediate {
      uint32_t memory_index;
      uint32_t length;
    } gc_memory_immediate;
    struct GC_HeapTypeImmediate {
      uint32_t length;
      HeapType::Representation type_representation;
      constexpr HeapType type() const { return HeapType(type_representation); }
    } gc_heap_type_immediate;
    struct GC_ArrayNewFixed {
      uint32_t array_index;
      uint32_t length;
    } gc_array_new_fixed;
    struct GC_ArrayNewOrInitData {
      uint32_t array_index;
      uint32_t data_index;
    } gc_array_new_or_init_data;
    struct GC_ArrayCopy {
      uint32_t dest_array_index;
      uint32_t src_array_index;
    } gc_array_copy;
    BranchOnCastData br_on_cast_data;
    size_t simd_immediate_index;
    HeapType::Representation ref_type;
  };

  WasmInstruction()
      : orig(0x00), opcode(kExprUnreachable), length(0), pc(0), optional({}) {}
  WasmInstruction(uint8_t orig, WasmOpcode opcode, int length, uint32_t pc,
                  Optional optional)
      : orig(orig),
        opcode(opcode),
        length(length),
        pc(pc),
        optional(optional) {}

  operator bool() const { return length > 0; }

  RegMode InputRegMode() const { return kRegModes[orig].from; }
  bool SupportsToRegister() const {
    return kRegModes[orig].to != RegMode::kNoReg;
  }
  uint8_t orig;
  WasmOpcode opcode;
  uint32_t length;
  uint32_t pc;
  Optional optional;
};

struct Slot {
  ValueType value_type;
  uint32_t slot_offset;
  uint32_t ref_stack_index;

  constexpr ValueKind kind() const { return value_type.kind(); }
};

template <typename T>
INSTRUCTION_HANDLER_FUNC trace_PushSlot(const uint8_t* code, uint32_t* sp,
                                        WasmInterpreterRuntime* wasm_runtime,
                                        int64_t r0, double fp0);

template <typename T>
static inline ValueType value_type() {
  UNREACHABLE();
}
template <>
inline ValueType value_type<int32_t>() {
  return kWasmI32;
}
template <>
inline ValueType value_type<uint32_t>() {
  return kWasmI32;
}
template <>
inline ValueType value_type<int64_t>() {
  return kWasmI64;
}
template <>
inline ValueType value_type<uint64_t>() {
  return kWasmI64;
}
template <>
inline ValueType value_type<float>() {
  return kWasmF32;
}
template <>
inline ValueType value_type<double>() {
  return kWasmF64;
}
template <>
inline ValueType value_type<Simd128>() {
  return kWasmS128;
}
template <>
inline ValueType value_type<WasmRef>() {
  return kWasmAnyRef;  // TODO(paolosev@microsoft.com)
}

static constexpr uint32_t kInstructionTableSize = 2048;
static constexpr uint32_t kInstructionTableMask = kInstructionTableSize - 1;

#define DEFINE_INSTR_HANDLER(name) k_##name,
enum InstructionHandler : uint16_t {
  FOREACH_INSTR_HANDLER(DEFINE_INSTR_HANDLER)
#ifdef V8_ENABLE_DRUMBRAKE_TRACING
      FOREACH_TRACE_INSTR_HANDLER(DEFINE_INSTR_HANDLER)
#endif  // V8_ENABLE_DRUMBRAKE_TRACING
          kInstructionCount
};
#undef DEFINE_INSTR_HANDLER

inline InstructionHandler ReadFnId(const uint8_t*& code) {
  InstructionHandler result = base::ReadUnalignedValue<InstructionHandler>(
      reinterpret_cast<Address>(code));
  code += sizeof(InstructionHandler);
  return result;
}

extern PWasmOp* s_unwind_func_addr;
extern InstructionHandler s_unwind_code;

class WasmEHData {
 public:
  static const int kCatchAllTagIndex = -1;

  // Zero is always the id of a function main block, so it cannot identify a
  // try block.
  static const int kDelegateToCallerIndex = 0;

  typedef int BlockIndex;

  struct CatchHandler {
    BlockIndex catch_block_index;
    int tag_index;
    CodeOffset code_offset;
  };

  struct TryBlock {
    TryBlock(BlockIndex parent_or_matching_try_block,
             BlockIndex ancestor_try_index)
        : ancestor_try_index(ancestor_try_index),
          parent_or_matching_try_block(parent_or_matching_try_block),
          delegate_try_index(-1),
          end_instruction_code_offset(0) {}

    void SetDelegated(BlockIndex delegate_try_index) {
      this->delegate_try_index = delegate_try_index;
    }
    bool IsTryDelegate() const { return delegate_try_index >= 0; }

    // The index of the first TryBlock that is a direct ancestor of this
    // TryBlock.
    BlockIndex ancestor_try_index;

    // If this TryBlock is contained in a CatchBlock, this is the matching
    // TryBlock index of the CatchBlock. Otherwise it matches
    // ancestor_try_index.
    BlockIndex parent_or_matching_try_block;

    BlockIndex delegate_try_index;
    std::vector<CatchHandler> catch_handlers;
    size_t end_instruction_code_offset;
  };

  struct CatchBlock {
    BlockIndex try_block_index;
    uint32_t first_param_slot_offset;
    uint32_t first_param_ref_stack_index;
  };

  const TryBlock* GetTryBlock(CodeOffset code_offset) const;
  const TryBlock* GetParentTryBlock(const TryBlock* try_block) const;
  const TryBlock* GetDelegateTryBlock(const TryBlock* try_block) const;

  size_t GetEndInstructionOffsetFor(BlockIndex catch_block_index) const;

  struct ExceptionPayloadSlotOffsets {
    uint32_t first_param_slot_offset;
    uint32_t first_param_ref_stack_index;
  };
  ExceptionPayloadSlotOffsets GetExceptionPayloadStartSlotOffsets(
      BlockIndex catch_block_index) const;

  void SetCaughtException(Isolate* isolate, BlockIndex catch_block_index,
                          Handle<Object> exception);
  Handle<Object> GetCaughtException(Isolate* isolate,
                                    BlockIndex catch_block_index) const;

 protected:
  BlockIndex GetTryBranchOf(BlockIndex catch_block_index) const;

  std::unordered_map<CodeOffset, BlockIndex> code_trycatch_map_;
  std::unordered_map<BlockIndex, TryBlock> try_blocks_;
  std::unordered_map<BlockIndex, CatchBlock> catch_blocks_;
};

class WasmEHDataGenerator : public WasmEHData {
 public:
  WasmEHDataGenerator() : current_try_block_index_(-1) {}

  void AddTryBlock(BlockIndex try_block_index,
                   BlockIndex parent_or_matching_try_block_index,
                   BlockIndex ancestor_try_block_index);
  void AddCatchBlock(BlockIndex catch_block_index, int tag_index,
                     uint32_t first_param_slot_offset,
                     uint32_t first_param_ref_stack_index,
                     CodeOffset code_offset);
  void AddDelegatedBlock(BlockIndex delegated_try_block_index);
  BlockIndex EndTryCatchBlocks(BlockIndex block_index, CodeOffset code_offset);
  void RecordPotentialExceptionThrowingInstruction(WasmOpcode opcode,
                                                   CodeOffset code_offset);

  BlockIndex GetCurrentTryBlockIndex() const {
    return current_try_block_index_;
  }

 private:
  BlockIndex current_try_block_index_;
};

class WasmBytecode {
 public:
  WasmBytecode(int func_index, const uint8_t* code_data, size_t code_length,
               uint32_t stack_frame_size, const FunctionSig* signature,
               const InterpreterCode* interpreter_code, size_t blocks_count,
               const uint8_t* const_slots_data, size_t const_slots_length,
               uint32_t ref_slots_count, const WasmEHData&& eh_data,
               const std::map<CodeOffset, pc_t>&& code_pc_map);

  inline const uint8_t* GetCode() const { return code_bytes_; }
  inline size_t GetCodeSize() const { return code_.size(); }

  inline bool InitializeSlots(uint8_t* sp, size_t stack_space) const;

  pc_t GetPcFromTrapCode(const uint8_t* current_code) const;

  inline int GetFunctionIndex() const { return func_index_; }

  inline uint32_t GetBlocksCount() const { return blocks_count_; }

  inline const FunctionSig* GetFunctionSignature() const { return signature_; }
  inline ValueType return_type(size_t index) const;
  inline ValueType arg_type(size_t index) const;
  inline ValueType local_type(size_t index) const;

  inline uint32_t args_count() const { return args_count_; }
  inline uint32_t args_slots_size() const { return args_slots_size_; }
  inline uint32_t return_count() const { return return_count_; }
  inline uint32_t rets_slots_size() const { return rets_slots_size_; }
  inline uint32_t locals_count() const { return locals_count_; }
  inline uint32_t locals_slots_size() const { return locals_slots_size_; }
  inline uint32_t const_slots_size_in_bytes() const {
    return static_cast<uint32_t>(const_slots_values_.size());
  }

  inline uint32_t ref_args_count() const { return ref_args_count_; }
  inline uint32_t ref_rets_count() const { return ref_rets_count_; }
  inline uint32_t ref_locals_count() const { return ref_locals_count_; }
  inline uint32_t ref_slots_count() const { return ref_slots_count_; }
  inline uint32_t internal_ref_slots_count() const {
    // Ref slots for arguments and return value are allocated by the caller and
    // not counted in internal_ref_slots_count().
    return ref_slots_count_ - ref_rets_count_ - ref_args_count_;
  }

  inline uint32_t frame_size() { return total_frame_size_in_bytes_; }

  static inline uint32_t ArgsSizeInSlots(const FunctionSig* sig);
  static inline uint32_t RetsSizeInSlots(const FunctionSig* sig);
  static inline uint32_t RefArgsCount(const FunctionSig* sig);
  static inline uint32_t RefRetsCount(const FunctionSig* sig);
  static inline bool ContainsSimd(const FunctionSig* sig);
  static inline bool HasRefOrSimdArgs(const FunctionSig* sig);
  static inline uint32_t JSToWasmWrapperPackedArraySize(const FunctionSig* sig);
  static inline uint32_t RefLocalsCount(const InterpreterCode* wasm_code);
  static inline uint32_t LocalsSizeInSlots(const InterpreterCode* wasm_code);

  const WasmEHData::TryBlock* GetTryBlock(CodeOffset code_offset) const {
    return eh_data_.GetTryBlock(code_offset);
  }
  const WasmEHData::TryBlock* GetParentTryBlock(
      const WasmEHData::TryBlock* try_block) const {
    return eh_data_.GetParentTryBlock(try_block);
  }
  WasmEHData::ExceptionPayloadSlotOffsets GetExceptionPayloadStartSlotOffsets(
      WasmEHData::BlockIndex catch_block_index) const {
    return eh_data_.GetExceptionPayloadStartSlotOffsets(catch_block_index);
  }
  Handle<Object> GetCaughtException(Isolate* isolate,
                                    uint32_t catch_block_index) const {
    return eh_data_.GetCaughtException(isolate, catch_block_index);
  }

 private:
  std::vector<uint8_t> code_;
  const uint8_t* code_bytes_;
  const FunctionSig* signature_;
  const InterpreterCode* interpreter_code_;
  std::vector<uint8_t> const_slots_values_;

  int func_index_;
  uint32_t blocks_count_;
  uint32_t args_count_;
  uint32_t args_slots_size_;
  uint32_t return_count_;
  uint32_t rets_slots_size_;
  uint32_t locals_count_;
  uint32_t locals_slots_size_;
  uint32_t total_frame_size_in_bytes_;
  uint32_t ref_args_count_;
  uint32_t ref_rets_count_;
  uint32_t ref_locals_count_;
  uint32_t ref_slots_count_;

  WasmEHData eh_data_;

  // TODO(paolosev@microsoft.com) slow! Use std::unordered_map ?
  std::map<CodeOffset, pc_t> code_pc_map_;
};

class WasmBytecodeGenerator {
 public:
  WasmBytecodeGenerator(uint32_t function_index, InterpreterCode* wasm_code,
                        const WasmModule* module);

  std::unique_ptr<WasmBytecode> GenerateBytecode();

 private:
  struct BlockData {
    BlockData(WasmOpcode opcode, uint32_t begin_code_offset,
              int32_t parent_block_index, uint32_t stack_size,
              WasmInstruction::Optional::Block signature,
              uint32_t first_block_index, uint32_t rets_slots_count,
              uint32_t params_slots_count, int32_t parent_try_block_index)
        : opcode_(opcode),
          stack_size_(stack_size),
          begin_code_offset_(begin_code_offset),
          end_code_offset_(0),
          parent_block_index_(parent_block_index),
          if_else_block_index_(-1),
          signature_(signature),
          first_block_index_(first_block_index),
          rets_slots_count_(rets_slots_count),
          params_slots_count_(params_slots_count),
          parent_try_block_index_(parent_try_block_index),
          is_unreachable_(false) {}

    bool IsRootBlock() const { return parent_block_index_ < 0; }
    bool IsBlock() const { return opcode_ == kExprBlock; }
    bool IsLoop() const { return opcode_ == kExprLoop; }
    bool IsIf() const { return opcode_ == kExprIf; }
    bool IsElse() const { return opcode_ == kExprElse; }
    bool HasElseBranch() const { return if_else_block_index_ > 0; }
    bool IsTry() const { return opcode_ == kExprTry; }
    bool IsCatch() const { return opcode_ == kExprCatch; }
    bool IsCatchAll() const { return opcode_ == kExprCatchAll; }

    void SaveParams(uint32_t* from, size_t params_count) {
      DCHECK(IsIf());
      if_block_params_ = base::SmallVector<uint32_t, 4>(params_count);
      for (size_t i = 0; i < params_count; i++) {
        if_block_params_[i] = from[i];
      }
    }
    uint32_t GetParam(size_t index) const {
      DCHECK(IsIf());
      DCHECK_LE(index, if_block_params_.size());
      return if_block_params_[index];
    }

    WasmOpcode opcode_;
    uint32_t stack_size_;
    uint32_t begin_code_offset_;
    uint32_t end_code_offset_;
    int32_t parent_block_index_;
    int32_t if_else_block_index_;
    base::SmallVector<uint32_t, 4> branch_code_offsets_;
    WasmInstruction::Optional::Block signature_;
    uint32_t first_block_index_;
    uint32_t rets_slots_count_;
    uint32_t params_slots_count_;
    int32_t parent_try_block_index_;
    bool is_unreachable_;
    base::SmallVector<uint32_t, 4> if_block_params_;
  };

  uint32_t const_slots_start() const {
    return rets_slots_size_ + args_slots_size_;
  }

  inline uint32_t GetStackFrameSize() const { return slot_offset_; }

  uint32_t CurrentCodePos() const {
    return static_cast<uint32_t>(code_.size());
  }

  WasmInstruction DecodeInstruction(pc_t pc, Decoder& decoder);
  void DecodeGCOp(WasmOpcode opcode, WasmInstruction::Optional* optional,
                  Decoder* decoder, InterpreterCode* code, pc_t pc,
                  int* const len);
  void DecodeNumericOp(WasmOpcode opcode, WasmInstruction::Optional* optional,
                       Decoder* decoder, InterpreterCode* code, pc_t pc,
                       int* const len);
  void DecodeAtomicOp(WasmOpcode opcode, WasmInstruction::Optional* optional,
                      Decoder* decoder, InterpreterCode* code, pc_t pc,
                      int* const len);
  bool DecodeSimdOp(WasmOpcode opcode, WasmInstruction::Optional* optional,
                    Decoder* decoder, InterpreterCode* code, pc_t pc,
                    int* const len);

  inline bool ToRegisterIsAllowed(const WasmInstruction& instr);
  RegMode EncodeInstruction(const WasmInstruction& instr, RegMode curr_reg_mode,
                            RegMode next_reg_mode);

  bool EncodeSuperInstruction(RegMode& reg_mode,
                              const WasmInstruction& curr_instr,
                              const WasmInstruction& next_instr);

  uint32_t ScanConstInstructions() const;

  void Emit(const void* buff, size_t len) {
    code_.insert(code_.end(), static_cast<const uint8_t*>(buff),
                 static_cast<const uint8_t*>(buff) + len);
  }

  inline void I32Push(bool emit = true);
  inline void I64Push(bool emit = true);
  inline void F32Push(bool emit = true);
  inline void F64Push(bool emit = true);
  inline void S128Push(bool emit = true);
  inline void RefPush(ValueType type, bool emit = true);
  inline void Push(ValueType type);

  inline void I32Pop(bool emit = true) { Pop(kI32, emit); }
  inline void I64Pop(bool emit = true) { Pop(kI64, emit); }
  inline void F32Pop(bool emit = true) { Pop(kF32, emit); }
  inline void F64Pop(bool emit = true) { Pop(kF64, emit); }
  inline void S128Pop(bool emit = true) { Pop(kS128, emit); }

  inline ValueType RefPop(bool emit = true) {
    DCHECK(wasm::is_reference(slots_[stack_.back()].kind()));
    uint32_t ref_index = slots_[stack_.back()].ref_stack_index;
    ValueType value_type = slots_[stack_.back()].value_type;
    DCHECK(value_type.is_object_reference());
    PopSlot();
    if (emit) Emit(&ref_index, sizeof(uint32_t));
    return value_type;
  }

#ifdef DEBUG
  bool CheckEqualKind(ValueKind value_kind, ValueKind stack_slot_kind) {
    if (is_reference(value_kind)) {
      return is_reference(stack_slot_kind);
    } else if (value_kind == kI8 || value_kind == kI16) {
      return stack_slot_kind == kI32;
    } else {
      return value_kind == stack_slot_kind;
    }
  }
#endif  // DEBUG

  inline void Pop(ValueKind kind, bool emit = true) {
    if (kind == kRefNull || kind == kRef) {
      RefPop(emit);
      return;
    }
    DCHECK(CheckEqualKind(kind, slots_[stack_.back()].kind()));
    uint32_t slot_offset = PopSlot();
    if (emit) Emit(&slot_offset, sizeof(uint32_t));
  }

  void EmitI16Const(int16_t value) { Emit(&value, sizeof(value)); }
  void EmitI32Const(int32_t value) { Emit(&value, sizeof(value)); }
  void EmitI64Const(int64_t value) { Emit(&value, sizeof(value)); }
  void EmitF32Const(float value) { Emit(&value, sizeof(value)); }
  void EmitF64Const(double value) { Emit(&value, sizeof(value)); }

  inline void EmitFnId(InstructionHandler func, uint32_t pc = UINT_MAX) {
    // If possible, compacts two consecutive CopySlot32 or CopySlot64
    // instructions into a single instruction, to save one dispatch.
    if (TryCompactInstructionHandler(func)) return;

    if (pc != UINT_MAX) {
      code_pc_map_[code_.size()] = pc;
    }

    last_instr_offset_ = CurrentCodePos();

    Emit(&func, sizeof(func));
  }

  void EmitCopySlot(ValueType value_type, uint32_t from_slot_index,
                    uint32_t to_slot_index, bool copy_from_reg = false);

  inline bool IsMemory64() const;
  inline bool IsMultiMemory() const;

  inline ValueKind GetGlobalType(uint32_t index) const;
  inline void EmitGlobalIndex(uint32_t index);

  uint32_t ReserveBlockSlots(uint8_t opcode,
                             const WasmInstruction::Optional::Block& block_data,
                             size_t* rets_slots_count,
                             size_t* params_slots_count);
  void StoreBlockParamsIntoSlots(uint32_t target_block_index,
                                 bool update_stack);
  void StoreBlockParamsAndResultsIntoSlots(uint32_t target_block_index,
                                           WasmOpcode opcode);

  inline bool HasVoidSignature(
      const WasmBytecodeGenerator::BlockData& block_data) const;
  inline uint32_t ParamsCount(
      const WasmBytecodeGenerator::BlockData& block_data) const;
  inline ValueType GetParamType(
      const WasmBytecodeGenerator::BlockData& block_data, size_t index) const;
  inline uint32_t ReturnsCount(
      const WasmBytecodeGenerator::BlockData& block_data) const;
  inline ValueType GetReturnType(
      const WasmBytecodeGenerator::BlockData& block_data, size_t index) const;

  void PreserveArgsAndLocals();

  int32_t BeginBlock(WasmOpcode opcode,
                     const WasmInstruction::Optional::Block signature);
  inline void BeginElseBlock(uint32_t if_block_index, bool dummy);
  int32_t EndBlock(WasmOpcode opcode);

  void Return();
  inline void EmitBranchOffset(uint32_t delta);
  inline void EmitIfElseBranchOffset();
  inline void EmitTryCatchBranchOffset();
  inline void EmitBranchTableOffset(uint32_t delta, uint32_t code_pos);
  inline uint32_t GetCurrentBranchDepth() const;
  inline int32_t GetTargetBranch(uint32_t delta) const;
  int GetCurrentTryBlockIndex(bool return_matching_try_for_catch_blocks) const;
  void PatchBranchOffsets();
  void PatchLoopJumpInstructions();
  void RestoreIfElseParams(uint32_t if_block_index);

  bool HasSharedSlot(uint32_t stack_index) const;
  bool FindSharedSlot(uint32_t stack_index, uint32_t* new_slot_index);

  inline const FunctionSig* GetFunctionSignature(uint32_t function_index) const;

  inline ValueKind GetTopStackType(RegMode reg_mode) const;

  inline uint32_t function_index() const { return function_index_; }

  std::vector<Slot> slots_;

  inline uint32_t CreateSlot(ValueType value_type) {
    switch (value_type.kind()) {
      case kI32:
        return CreateSlot<int32_t>(value_type);
      case kI64:
        return CreateSlot<int64_t>(value_type);
      case kF32:
        return CreateSlot<float>(value_type);
      case kF64:
        return CreateSlot<double>(value_type);
      case kS128:
        return CreateSlot<Simd128>(value_type);
      case kRef:
      case kRefNull:
        return CreateSlot<WasmRef>(value_type);
      default:
        UNREACHABLE();
    }
  }

  template <typename T>
  inline uint32_t CreateSlot(ValueType value_type) {
    // A gcc bug causes "error: explicit specialization in non-namespace scope"
    // with explicit specializations here:
    // https://gcc.gnu.org/bugzilla/show_bug.cgi?id=85282
    if constexpr (std::is_same_v<T, WasmRef>) {
      return CreateWasmRefSlot(value_type);
    }
    uint32_t slot_index = static_cast<uint32_t>(slots_.size());
    slots_.push_back({value_type, slot_offset_, 0});
    slot_offset_ += sizeof(T) / kSlotSize;
    return slot_index;
  }
  inline uint32_t CreateWasmRefSlot(ValueType value_type) {
    uint32_t slot_index = static_cast<uint32_t>(slots_.size());
    slots_.push_back({value_type, slot_offset_, ref_slots_count_});
    slot_offset_ += sizeof(WasmRef) / kSlotSize;
    ref_slots_count_++;
    return slot_index;
  }

  template <typename T>
  inline uint32_t GetConstSlot(T value) {
    if constexpr (std::is_same_v<T, int32_t>) {
      return GetI32ConstSlot(value);
    }
    if constexpr (std::is_same_v<T, int64_t>) {
      return GetI64ConstSlot(value);
    }
    if constexpr (std::is_same_v<T, float>) {
      return GetF32ConstSlot(value);
    }
    if constexpr (std::is_same_v<T, double>) {
      return GetF64ConstSlot(value);
    }
    if constexpr (std::is_same_v<T, Simd128>) {
      return GetS128ConstSlot(value);
    }
    UNREACHABLE();
  }
  inline uint32_t GetI32ConstSlot(int32_t value) {
    auto it = i32_const_cache_.find(value);
    if (it != i32_const_cache_.end()) {
      return it->second;
    }
    return UINT_MAX;
  }
  inline uint32_t GetI64ConstSlot(int64_t value) {
    auto it = i64_const_cache_.find(value);
    if (it != i64_const_cache_.end()) {
      return it->second;
    }
    retu
"""


```