Response:
My thought process to analyze the given C++ header file and provide a comprehensive explanation involved several steps:

1. **Understanding the Request:** I first broke down the request into its core components:
    * Explain the functionality of `v8/src/objects/code-inl.h`.
    * Identify if it's a Torque file (checking the `.tq` extension).
    * If related to JavaScript, provide a JavaScript example.
    * If there's code logic, give example inputs and outputs.
    * If it relates to common programming errors, provide examples.

2. **Initial File Inspection:** I scanned the header file for keywords and patterns to get a general idea of its purpose. Key observations included:
    * Inclusion of other V8 headers (`code.h`, `deoptimization-data-inl.h`, etc.) suggesting it's part of the V8 object system.
    * The `OBJECT_CONSTRUCTORS_IMPL` macros, strongly indicating it defines the implementation of object constructors.
    * Accessor macros (`INT_ACCESSORS`, `UINT16_ACCESSORS`, `ACCESSORS`, `RELAXED_UINT32_ACCESSORS`, `CODE_POINTER_ACCESSORS`) implying it provides ways to access and manipulate the internal fields of `Code` and `GcSafeCode` objects.
    * Mentions of "bytecode," "deoptimization," "safepoint," "instruction stream," suggesting it deals with the execution and optimization aspects of code within V8.
    * `GcSafeCode` seems to be a wrapper providing safe access to `Code` properties.

3. **Functionality Deduction - Core Purpose:** Based on the included headers, the object constructor macros, and the prevalence of accessors, I concluded that `code-inl.h` primarily provides the *inline* implementations for the `Code` and `GcSafeCode` objects defined in `code.h`. Inline implementations are crucial for performance as they allow the compiler to potentially insert the function body directly at the call site, avoiding function call overhead. The "inl" suffix is a standard convention for this.

4. **Specific Functionality Breakdown:** I then went through the code block by block, analyzing the purpose of each section:
    * **`OBJECT_CONSTRUCTORS_IMPL`:** Clearly for defining constructors.
    * **`GcSafeCode`:**  Identified it as a wrapper providing a safe (presumably garbage-collection aware) way to access `Code` object properties. The forwarding accessors (`GCSAFE_CODE_FWD_ACCESSOR`) confirm this.
    * **Accessors (e.g., `instruction_start`, `metadata_size`):**  Recognized these as providing controlled access to the internal fields of the `Code` object. The `INT_ACCESSORS`, etc., macros make it easy to spot these.
    * **Methods related to deoptimization (`CanDeoptAt`, `deoptimization_data`):**  Deduced that this file plays a role in handling code deoptimization, a process where optimized code is discarded in favor of less optimized but correct code.
    * **Methods related to instruction stream (`raw_instruction_stream`, `instruction_stream`):**  Understood this relates to accessing the actual machine instructions of the compiled code.
    * **Methods related to bytecode (`GetBytecodeOffsetForBaselinePC`, `GetBaselinePCForBytecodeOffset`):**  Recognized these as functions for mapping between bytecode offsets and program counter (PC) values, essential for debugging and optimization at the bytecode level.
    * **Methods related to safepoints (`safepoint_table_address`, `stack_slots`):**  Inferred that these are related to garbage collection safepoints, locations in the code where the garbage collector can safely interrupt execution.
    * **Methods related to weak objects (`CanContainWeakObjects`, `IsWeakObject`):**  Realized this section deals with how the garbage collector handles objects that might be collected if no strong references exist.
    * **Methods for setting and getting flags and properties:**  Recognized standard accessor and mutator patterns.
    * **`FromTargetAddress`:**  Understood this as a way to retrieve a `Code` object given an address within its instruction stream.
    * **`SetInstructionStreamAndInstructionStart`:**  Recognized this as a function to atomically update related fields.

5. **Answering Specific Questions:** After understanding the functionality, I addressed the specific points in the request:
    * **`.tq` extension:**  Clearly, the file ends with `.h`, so it's not a Torque file.
    * **Relationship to JavaScript:**  Since the file deals with code execution, optimization, and deoptimization, all fundamental aspects of running JavaScript in V8, the relationship is strong. I then thought of a simple JavaScript function as an example that would eventually be compiled into `Code` objects.
    * **Code Logic and Examples:** I picked a representative function, `GetOffsetFromInstructionStart`, and created a hypothetical scenario with input PC values to demonstrate its behavior.
    * **Common Programming Errors:** I considered typical errors that might occur when interacting with low-level concepts like code pointers or incorrect assumptions about code structure, linking them to potential issues if developers were to directly interact with these internal V8 structures (which they generally shouldn't).

6. **Structuring the Output:**  Finally, I organized my findings into a clear and structured format, addressing each part of the original request explicitly. I used headings and bullet points for readability. I also made sure to explain the significance of inline implementations.

Essentially, my process was a combination of code inspection, knowledge of common software engineering patterns (like accessors and inline functions), and understanding of the high-level concepts within a JavaScript engine like V8 (compilation, optimization, garbage collection). The request itself provided valuable hints about the file's purpose (e.g., mentioning Torque and JavaScript).
## 功能列举：v8/src/objects/code-inl.h

`v8/src/objects/code-inl.h` 文件是 V8 引擎中关于 `Code` 对象的内联实现部分。它的主要功能是提供对 `Code` 对象及其相关属性进行高效访问和操作的方法。`Code` 对象在 V8 中代表了已编译的 JavaScript 代码，是 V8 执行 JavaScript 代码的核心组成部分。

具体来说，`code-inl.h` 提供了以下功能：

1. **`Code` 和 `GcSafeCode` 对象的构造和类型转换:**
   - 定义了 `Code` 和 `GcSafeCode` 对象的构造器 (`OBJECT_CONSTRUCTORS_IMPL`)。
   - 提供了 `GcSafeCode` 到 `Code` 的不安全类型转换方法 `UnsafeCastToCode()`。

2. **`GcSafeCode` 对象的访问器 (Forward Accessors):**
   - 定义了一系列宏 `GCSAFE_CODE_FWD_ACCESSOR` 用于将 `GcSafeCode` 的访问请求转发给底层的 `Code` 对象。
   - 这些访问器允许安全地访问 `Code` 对象的一些基本属性，例如：
     - 代码的起始和结束地址 (`instruction_start`, `instruction_end`)
     - 是否是内置函数 (`is_builtin`, `builtin_id`)
     - 代码类型 (`kind`)
     - 是否是特定的 trampoline 内置函数 (`is_interpreter_trampoline_builtin`, `is_baseline_trampoline_builtin`, `is_baseline_leave_frame_builtin`)
     - 是否包含指令流 (`has_instruction_stream`)
     - 是否经过 Maglev 或 Turbofan 优化 (`is_maglevved`, `is_turbofanned`)
     - 是否有标签化的输出参数 (`has_tagged_outgoing_params`)
     - 是否标记为需要反优化 (`marked_for_deoptimization`)
     - 原始指令流 (`raw_instruction_stream`)
     - 栈槽数量 (`stack_slots`)
     - WebAssembly 相关参数计数和起始位置 (`wasm_js_tagged_parameter_count`, `wasm_js_first_tagged_parameter`)
     - 常量池地址 (`constant_pool`)
     - 安全点表地址 (`safepoint_table_address`)

3. **`GcSafeCode` 对象的其他方法:**
   - 提供根据程序计数器 (PC) 获取相对于指令开始的偏移量的方法 (`GetOffsetFromInstructionStart`)。
   - 提供根据 PC 获取指令起始和结束地址的方法 (`InstructionStart`, `InstructionEnd`).
   - 提供判断指定 PC 地址是否可以进行反优化的方法 (`CanDeoptAt`).
   - 提供获取原始指令流的方法，并考虑代码段压缩 (`raw_instruction_stream(PtrComprCageBase code_cage_base)`)。

4. **`Code` 对象的属性访问器:**
   - 使用 `INT_ACCESSORS`、`INT32_ACCESSORS`、`UINT16_ACCESSORS` 等宏定义了直接访问 `Code` 对象内部字段的访问器，例如：
     - 指令大小 (`instruction_size`)
     - 元数据大小 (`metadata_size`)
     - 处理器表偏移量 (`handler_table_offset`)
     - 代码注释偏移量 (`code_comments_offset`)
     - 展开信息偏移量 (`unwinding_info_offset`)
     - 参数数量 (`parameter_count`)

5. **`Code` 对象的复杂属性访问和设置:**
   - 提供了访问和设置反优化数据 (`deoptimization_data`, `set_deoptimization_data`) 的方法。
   - 提供了判断是否使用反优化数据的方法 (`uses_deoptimization_data`)。
   - 提供了清除反优化数据和解释器数据的方法 (`clear_deoptimization_data_and_interpreter_data`)。
   - 提供了判断是否存在反优化数据或解释器数据的方法 (`has_deoptimization_data_or_interpreter_data`)。
   - 提供了访问和设置字节码或解释器数据的方法 (`bytecode_or_interpreter_data`, `set_bytecode_or_interpreter_data`)，用于 Baseline 代码。
   - 提供了访问和设置源码位置表和字节码偏移表的方法 (`source_position_table`, `set_source_position_table`, `bytecode_offset_table`, `set_bytecode_offset_table`)。
   - 提供了判断是否存在源码位置表或字节码偏移表的方法 (`has_source_position_table_or_bytecode_offset_table`, `has_source_position_table`, `has_bytecode_offset_table`).
   - 提供了清除源码位置表和字节码偏移表的方法 (`clear_source_position_table_and_bytecode_offset_table`).
   - 提供了访问和设置 `CodeWrapper` 的方法 (`wrapper`, `set_wrapper`).

6. **获取代码执行相关地址和大小:**
   - 提供了获取源码位置表的方法，考虑了 Baseline 代码的情况 (`SourcePositionTable`).
   - 提供了获取代码体起始和结束地址以及大小的方法 (`body_start`, `body_end`, `body_size`).
   - 提供了获取指令结束地址的方法 (`instruction_end`).
   - 提供了获取元数据起始和结束地址的方法 (`metadata_start`, `metadata_end`).
   - 提供了根据 PC 获取指令起始地址的方法，区分了是否是内建函数 (`InstructionStart`).
   - 提供了根据 PC 获取指令结束地址的方法 (`InstructionEnd`).
   - 提供了根据 PC 获取相对于指令开始的偏移量的方法 (`GetOffsetFromInstructionStart`).
   - 提供了获取安全点表、处理器表、常量池、代码注释等元数据区域的地址和大小的方法。

7. **处理重定位信息:**
   - 提供了获取重定位信息起始、结束地址和大小的方法 (`relocation_start`, `relocation_end`, `relocation_size`).

8. **判断地址是否在代码范围内:**
   - 提供了判断给定的地址是否在当前 `Code` 对象的指令范围内的函数 (`contains`).

9. **计算 `Code` 对象的大小:**
   - 提供了计算包含元数据的 `Code` 对象大小的方法 (`SizeIncludingMetadata`).

10. **获取和设置代码的各种标志 (flags):**
    - 提供了获取和设置代码标志的方法 (`flags`, `set_flags`)。
    - 提供了初始化代码标志的方法 (`initialize_flags`)。
    - 提供了访问和设置特定标志位的方法，例如：是否上下文相关 (`is_context_specialized`)，是否是 Turbofan 生成的代码 (`is_turbofanned`)，是否标记为反优化 (`marked_for_deoptimization`)，内嵌对象是否已清除 (`embedded_objects_cleared`)，是否可以包含弱对象 (`can_have_weak_objects`)。

11. **处理 Baseline 代码的字节码偏移:**
    - 提供了在 Baseline 代码中根据 PC 获取字节码偏移量的方法 (`GetBytecodeOffsetForBaselinePC`).
    - 提供了在 Baseline 代码中根据字节码偏移量获取 PC 的方法 (`GetBaselinePCForBytecodeOffset`, `GetBaselineStartPCForBytecodeOffset`, `GetBaselineEndPCForBytecodeOffset`).
    - 提供了获取下一个要执行的字节码对应的 PC 的方法 (`GetBaselinePCForNextExecutedBytecode`).

12. **判断代码的特性:**
    - 提供了判断代码是否检查分层编译状态的方法 (`checks_tiering_state`).
    - 提供了判断代码是否具有标签化的输出参数的方法 (`has_tagged_outgoing_params`).
    - 提供了判断代码是否是 Maglev 生成的代码的方法 (`is_maglevved`).
    - 提供了判断代码是否是 WebAssembly 代码的方法 (`is_wasm_code`).

13. **处理内联字节码大小:**
    - 提供了获取和设置内联字节码大小的方法 (`inlined_bytecode_size`, `set_inlined_bytecode_size`).

14. **处理 WebAssembly 到 JavaScript 的调用参数信息:**
    - 提供了设置和获取 WebAssembly 到 JavaScript 调用的标签化参数计数和起始位置的方法 (`set_wasm_js_tagged_parameter_count`, `wasm_js_tagged_parameter_count`, `set_wasm_js_first_tagged_parameter`, `wasm_js_first_tagged_parameter`).

15. **处理 OSR (On-Stack Replacement) 偏移量:**
    - 提供了获取和设置 OSR 偏移量的方法 (`osr_offset`, `set_osr_offset`).

16. **处理安全点信息:**
    - 提供了判断代码是否使用安全点表的方法 (`uses_safepoint_table`).
    - 提供了获取栈槽数量的方法 (`stack_slots`).

17. **处理内嵌对象:**
    - 提供了判断代码是否可以包含弱对象以及判断给定的对象是否是弱对象的方法 (`CanContainWeakObjects`, `IsWeakObject`, `IsWeakObjectInOptimizedCode`, `IsWeakObjectInDeoptimizationLiteralArray`).
    - 提供了遍历反优化字面量的方法 (`IterateDeoptimizationLiterals`).

18. **处理指令流:**
    - 提供了获取和设置原始指令流的方法 (`raw_instruction_stream`, `set_raw_instruction_stream`)。
    - 提供了判断是否存在指令流的方法 (`has_instruction_stream`).
    - 提供了获取指令流对象的方法 (`instruction_stream`, `unchecked_instruction_stream`).

19. **处理指令起始地址:**
    - 提供了获取和设置指令起始地址的方法 (`instruction_start`, `set_instruction_start`)，并考虑了沙箱环境。
    - 提供了根据目标地址获取 `Code` 对象的方法 (`FromTargetAddress`).
    - 提供了设置指令流和指令起始地址的方法 (`SetInstructionStreamAndInstructionStart`).
    - 提供了为 Off-Heap 内建函数设置指令起始地址的方法 (`SetInstructionStartForOffHeapBuiltin`).
    - 提供了在序列化时清除指令起始地址的方法 (`ClearInstructionStartForSerialization`).
    - 提供了更新指令起始地址的方法 (`UpdateInstructionStart`).

20. **清除填充数据:**
    - 提供了清除 `Code` 对象末尾填充数据的方法 (`clear_padding`).

21. **处理内置函数 ID:**
    - 提供了设置和获取内置函数 ID 的方法 (`set_builtin_id`, `builtin_id`).
    - 提供了判断是否是内置函数的方法 (`is_builtin`).
    - 提供了判断是否是特定的 trampoline 内置函数的方法 (`is_interpreter_trampoline_builtin`, `is_baseline_trampoline_builtin`, `is_baseline_leave_frame_builtin`).

22. **处理代码类型:**
    - 提供了判断代码是否是优化代码的方法 (`is_optimized_code`).

## 关于文件后缀为 `.tq`

如果 `v8/src/objects/code-inl.h` 以 `.tq` 结尾，那么它确实是一个 **V8 Torque 源代码**文件。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现内置函数和运行时功能。

然而，根据您提供的文件内容，该文件以 `.h` 结尾，因此它是一个 **C++ 头文件**，包含了 `Code` 对象的内联实现。

## 与 JavaScript 功能的关系及示例

`v8/src/objects/code-inl.h` 中定义的功能与 JavaScript 的执行密切相关。`Code` 对象是 V8 执行 JavaScript 代码的基础。每当 V8 编译一段 JavaScript 代码（无论是通过解释器、Baseline 编译器还是优化编译器），都会生成一个或多个 `Code` 对象来存储编译后的指令。

例如，考虑以下简单的 JavaScript 函数：

```javascript
function add(a, b) {
  return a + b;
}
```

当 V8 首次遇到这个函数时，可能会通过解释器将其编译成字节码，并存储在一个与该函数关联的 `Code` 对象中（`CodeKind::INTERPRETED_FUNCTION`）。随着函数的执行次数增加，V8 可能会使用 Baseline 编译器 (Liftoff) 生成更高效的机器码，并创建一个新的 `Code` 对象 (`CodeKind::BASELINE`). 如果函数变得“热点”，Turbofan 或 Maglev 等优化编译器会进一步生成优化的机器码，并创建相应的 `Code` 对象 (`CodeKind::TURBOFANED_JS_FUNCTION` 或 `CodeKind::MAGLEV`).

**JavaScript 示例说明 `Code` 对象的一些属性:**

假设 V8 已经为 `add` 函数生成了一个经过 Turbofan 优化的 `Code` 对象。我们可以想象一下这个 `Code` 对象的一些属性：

- `kind()`: 返回 `CodeKind::TURBOFANED_JS_FUNCTION`，表示这是一个经过 Turbofan 优化的 JavaScript 函数。
- `instruction_start()`: 指向该函数编译后机器码在内存中的起始地址。
- `instruction_size()`: 表示该函数编译后机器码的大小。
- `deoptimization_data()`:  如果该优化代码包含可以被反优化的点，则会包含反优化数据，用于在运行时发生某些情况时回退到非优化的版本。
- `has_safepoint_table()`:  返回 `true`，因为 Turbofan 生成的代码通常包含安全点表，用于垃圾回收。
- `stack_slots()`:  表示该函数执行时需要的栈槽数量。

## 代码逻辑推理及示例

`GcSafeCode::CanDeoptAt` 方法提供了一个代码逻辑推理的例子。

**假设输入:**

- `isolate`: 当前 V8 隔离区 (Isolate) 的指针。
- `pc`: 一个程序计数器地址，指向 `GcSafeCode` 对象所代表的代码的某个位置。
- `GcSafeCode` 对象代表一个已经过优化的函数，并且包含反优化数据。
- `deopt_data` (从 `Code` 对象中获取) 包含以下反优化点信息:
    - 反优化点 1: `Pc`: `instruction_start() + 0x10`, `BytecodeOffset`: 5
    - 反优化点 2: `Pc`: `instruction_start() + 0x20`, `BytecodeOffset`: 10
    - 反优化点 3: `Pc`: `-1`, `BytecodeOffset`: 15 (表示一个无效的 PC)

**推理:**

该方法遍历 `deopt_data` 中的反优化点。对于每个反优化点，它会检查：

1. `deopt_data->Pc(i).value() != -1`: 确保 PC 值有效。
2. `code_start_address + deopt_data->Pc(i).value() == pc`:  计算反优化点的实际地址，并与输入的 `pc` 进行比较。
3. `deopt_data->GetBytecodeOffsetOrBuiltinContinuationId(i) != BytecodeOffset::None()`: 确保反优化点关联了一个有效的字节码偏移量或内置函数延续 ID。

**输出:**

- 如果输入 `pc` 等于 `instruction_start() + 0x10`，则输出 `true`。
- 如果输入 `pc` 等于 `instruction_start() + 0x20`，则输出 `true`。
- 对于任何其他 `pc` 值，包括与无效反优化点相关的地址，输出 `false`。

## 用户常见的编程错误

虽然开发者通常不会直接操作 `v8/src/objects/code-inl.h` 中定义的结构和方法，但理解其背后的概念可以帮助避免一些与性能和内存管理相关的常见编程错误。

**示例 1: 过度依赖动态特性和运行时类型检查**

JavaScript 的灵活性有时会导致开发者编写过度依赖动态特性和运行时类型检查的代码。V8 需要为这些动态行为生成更复杂的 `Code` 对象，并且可能导致更多的反优化。

```javascript
function process(input) {
  if (typeof input === 'number') {
    return input * 2;
  } else if (typeof input === 'string') {
    return input.toUpperCase();
  }
  return null;
}

console.log(process(5));
console.log(process("hello"));
console.log(process({}));
```

在这个例子中，`process` 函数接受不同类型的输入。V8 可能会生成多个版本的 `Code` 对象来处理不同的类型，或者生成包含类型检查的 `Code`，这可能不如针对特定类型的优化代码高效。

**示例 2: 创建大量小的、生命周期短的函数**

创建大量小的、生命周期短的函数会导致 V8 频繁地编译和回收 `Code` 对象，增加垃圾回收的压力。

```javascript
function createIncrementer(start) {
  return function() {
    return start++;
  }
}

for (let i = 0; i < 10000; i++) {
  let increment = createIncrementer(i);
  increment();
}
```

在这个例子中，循环创建了大量的闭包函数。虽然 V8 能够处理这种情况，但过度使用可能会影响性能。

**示例 3: 编写导致频繁反优化的代码**

某些 JavaScript 模式或操作可能导致 V8 的优化代码被频繁反优化，例如：

- 在优化代码执行过程中改变对象的形状（添加或删除属性）。
- 访问未初始化的变量。
- 使用 `eval` 或 `with` 等动态特性。

理解 `Code` 对象及其生命周期有助于开发者编写更易于 V8 引擎优化的高性能 JavaScript 代码。虽然开发者不需要直接操作 `code-inl.h` 中的代码，但了解 V8 内部如何表示和管理已编译的代码，可以帮助他们更好地理解 JavaScript 性能优化的原理。

### 提示词
```
这是目录为v8/src/objects/code-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/code-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2017 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_CODE_INL_H_
#define V8_OBJECTS_CODE_INL_H_

#include "src/baseline/bytecode-offset-iterator.h"
#include "src/codegen/code-desc.h"
#include "src/heap/heap-layout-inl.h"
#include "src/heap/heap-write-barrier-inl.h"
#include "src/objects/code.h"
#include "src/objects/deoptimization-data-inl.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/instruction-stream-inl.h"
#include "src/objects/trusted-object-inl.h"
#include "src/snapshot/embedded/embedded-data-inl.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

OBJECT_CONSTRUCTORS_IMPL(Code, ExposedTrustedObject)
OBJECT_CONSTRUCTORS_IMPL(GcSafeCode, HeapObject)

Tagged<Code> GcSafeCode::UnsafeCastToCode() const {
  return UncheckedCast<Code>(*this);
}

#define GCSAFE_CODE_FWD_ACCESSOR(ReturnType, Name) \
  ReturnType GcSafeCode::Name() const { return UnsafeCastToCode()->Name(); }
GCSAFE_CODE_FWD_ACCESSOR(Address, instruction_start)
GCSAFE_CODE_FWD_ACCESSOR(Address, instruction_end)
GCSAFE_CODE_FWD_ACCESSOR(bool, is_builtin)
GCSAFE_CODE_FWD_ACCESSOR(Builtin, builtin_id)
GCSAFE_CODE_FWD_ACCESSOR(CodeKind, kind)
GCSAFE_CODE_FWD_ACCESSOR(bool, is_interpreter_trampoline_builtin)
GCSAFE_CODE_FWD_ACCESSOR(bool, is_baseline_trampoline_builtin)
GCSAFE_CODE_FWD_ACCESSOR(bool, is_baseline_leave_frame_builtin)
GCSAFE_CODE_FWD_ACCESSOR(bool, has_instruction_stream)
GCSAFE_CODE_FWD_ACCESSOR(bool, is_maglevved)
GCSAFE_CODE_FWD_ACCESSOR(bool, is_turbofanned)
GCSAFE_CODE_FWD_ACCESSOR(bool, has_tagged_outgoing_params)
GCSAFE_CODE_FWD_ACCESSOR(bool, marked_for_deoptimization)
GCSAFE_CODE_FWD_ACCESSOR(Tagged<Object>, raw_instruction_stream)
GCSAFE_CODE_FWD_ACCESSOR(uint32_t, stack_slots)
GCSAFE_CODE_FWD_ACCESSOR(uint16_t, wasm_js_tagged_parameter_count)
GCSAFE_CODE_FWD_ACCESSOR(uint16_t, wasm_js_first_tagged_parameter)
GCSAFE_CODE_FWD_ACCESSOR(Address, constant_pool)
GCSAFE_CODE_FWD_ACCESSOR(Address, safepoint_table_address)
#undef GCSAFE_CODE_FWD_ACCESSOR

int GcSafeCode::GetOffsetFromInstructionStart(Isolate* isolate,
                                              Address pc) const {
  return UnsafeCastToCode()->GetOffsetFromInstructionStart(isolate, pc);
}

Address GcSafeCode::InstructionStart(Isolate* isolate, Address pc) const {
  return UnsafeCastToCode()->InstructionStart(isolate, pc);
}

Address GcSafeCode::InstructionEnd(Isolate* isolate, Address pc) const {
  return UnsafeCastToCode()->InstructionEnd(isolate, pc);
}

bool GcSafeCode::CanDeoptAt(Isolate* isolate, Address pc) const {
  if (!UnsafeCastToCode()->uses_deoptimization_data()) return false;
  Tagged<DeoptimizationData> deopt_data = UncheckedCast<DeoptimizationData>(
      UnsafeCastToCode()->unchecked_deoptimization_data());
  Address code_start_address = instruction_start();
  for (int i = 0; i < deopt_data->DeoptCount(); i++) {
    if (deopt_data->Pc(i).value() == -1) continue;
    Address address = code_start_address + deopt_data->Pc(i).value();
    if (address == pc && deopt_data->GetBytecodeOffsetOrBuiltinContinuationId(
                             i) != BytecodeOffset::None()) {
      return true;
    }
  }
  return false;
}

Tagged<Object> GcSafeCode::raw_instruction_stream(
    PtrComprCageBase code_cage_base) const {
  return UnsafeCastToCode()->raw_instruction_stream(code_cage_base);
}

INT_ACCESSORS(Code, instruction_size, kInstructionSizeOffset)
INT_ACCESSORS(Code, metadata_size, kMetadataSizeOffset)
INT_ACCESSORS(Code, handler_table_offset, kHandlerTableOffsetOffset)
INT_ACCESSORS(Code, code_comments_offset, kCodeCommentsOffsetOffset)
INT32_ACCESSORS(Code, unwinding_info_offset, kUnwindingInfoOffsetOffset)
UINT16_ACCESSORS(Code, parameter_count, kParameterCountOffset)
inline uint16_t Code::parameter_count_without_receiver() const {
  return parameter_count() - 1;
}

inline Tagged<ProtectedFixedArray> Code::deoptimization_data() const {
  DCHECK(uses_deoptimization_data());
  return Cast<ProtectedFixedArray>(
      ReadProtectedPointerField(kDeoptimizationDataOrInterpreterDataOffset));
}

inline void Code::set_deoptimization_data(Tagged<ProtectedFixedArray> value,
                                          WriteBarrierMode mode) {
  DCHECK(uses_deoptimization_data());
  DCHECK(!HeapLayout::InYoungGeneration(value));

  WriteProtectedPointerField(kDeoptimizationDataOrInterpreterDataOffset, value);
  CONDITIONAL_PROTECTED_POINTER_WRITE_BARRIER(
      *this, kDeoptimizationDataOrInterpreterDataOffset, value, mode);
}

inline bool Code::uses_deoptimization_data() const {
  return CodeKindUsesDeoptimizationData(kind());
}

inline void Code::clear_deoptimization_data_and_interpreter_data() {
  ClearProtectedPointerField(kDeoptimizationDataOrInterpreterDataOffset);
}

inline bool Code::has_deoptimization_data_or_interpreter_data() const {
  return !IsProtectedPointerFieldEmpty(
      kDeoptimizationDataOrInterpreterDataOffset);
}

Tagged<TrustedObject> Code::bytecode_or_interpreter_data() const {
  DCHECK_EQ(kind(), CodeKind::BASELINE);
  return ReadProtectedPointerField(kDeoptimizationDataOrInterpreterDataOffset);
}
void Code::set_bytecode_or_interpreter_data(Tagged<TrustedObject> value,
                                            WriteBarrierMode mode) {
  DCHECK(kind() == CodeKind::BASELINE);
  DCHECK(IsBytecodeArray(value) || IsInterpreterData(value));

  WriteProtectedPointerField(kDeoptimizationDataOrInterpreterDataOffset, value);
  CONDITIONAL_PROTECTED_POINTER_WRITE_BARRIER(
      *this, kDeoptimizationDataOrInterpreterDataOffset, value, mode);
}

inline Tagged<TrustedByteArray> Code::source_position_table() const {
  DCHECK(has_source_position_table());
  return Cast<TrustedByteArray>(
      ReadProtectedPointerField(kPositionTableOffset));
}

inline void Code::set_source_position_table(Tagged<TrustedByteArray> value,
                                            WriteBarrierMode mode) {
  DCHECK(!CodeKindUsesBytecodeOffsetTable(kind()));

  WriteProtectedPointerField(kPositionTableOffset, value);
  CONDITIONAL_PROTECTED_POINTER_WRITE_BARRIER(*this, kPositionTableOffset,
                                              value, mode);
}

inline Tagged<TrustedByteArray> Code::bytecode_offset_table() const {
  DCHECK(has_bytecode_offset_table());
  return Cast<TrustedByteArray>(
      ReadProtectedPointerField(kPositionTableOffset));
}

inline void Code::set_bytecode_offset_table(Tagged<TrustedByteArray> value,
                                            WriteBarrierMode mode) {
  DCHECK(CodeKindUsesBytecodeOffsetTable(kind()));

  WriteProtectedPointerField(kPositionTableOffset, value);
  CONDITIONAL_PROTECTED_POINTER_WRITE_BARRIER(*this, kPositionTableOffset,
                                              value, mode);
}

bool Code::has_source_position_table_or_bytecode_offset_table() const {
  return TaggedField<Object, kPositionTableOffset>::load(*this) != Smi::zero();
}

bool Code::has_source_position_table() const {
  bool has_table = has_source_position_table_or_bytecode_offset_table() &&
                   !CodeKindUsesBytecodeOffsetTable(kind());
  DCHECK_IMPLIES(!CodeKindMayLackSourcePositionTable(kind()), has_table);
  return has_table;
}

bool Code::has_bytecode_offset_table() const {
  return has_source_position_table_or_bytecode_offset_table() &&
         CodeKindUsesBytecodeOffsetTable(kind());
}

void Code::clear_source_position_table_and_bytecode_offset_table() {
  TaggedField<Object, kPositionTableOffset>::store(*this, Smi::zero());
}

ACCESSORS(Code, wrapper, Tagged<CodeWrapper>, kWrapperOffset)

Tagged<TrustedByteArray> Code::SourcePositionTable(
    Isolate* isolate, Tagged<SharedFunctionInfo> sfi) const {
  DisallowGarbageCollection no_gc;

  if (kind() == CodeKind::BASELINE) {
    return sfi->GetBytecodeArray(isolate)->SourcePositionTable(isolate);
  }

  if (!has_source_position_table()) {
    return *isolate->factory()->empty_trusted_byte_array();
  }

  return source_position_table();
}

Address Code::body_start() const { return instruction_start(); }

Address Code::body_end() const { return body_start() + body_size(); }

int Code::body_size() const { return instruction_size() + metadata_size(); }

Address Code::instruction_end() const {
  return instruction_start() + instruction_size();
}

Address Code::metadata_start() const {
  if (has_instruction_stream()) {
    static_assert(InstructionStream::kOnHeapBodyIsContiguous);
    return instruction_start() + instruction_size();
  }
  // An embedded builtin. Remapping is irrelevant wrt the metadata section so
  // we can simply use the global blob.
  // TODO(jgruber): Consider adding this as a physical Code field to avoid the
  // lookup. Alternatively, rename this (and callers) to camel-case to clarify
  // it's more than a simple accessor.
  static_assert(!InstructionStream::kOffHeapBodyIsContiguous);
  return EmbeddedData::FromBlob().MetadataStartOf(builtin_id());
}

Address Code::InstructionStart(Isolate* isolate, Address pc) const {
  if (V8_LIKELY(has_instruction_stream())) return instruction_start();
  // Note we intentionally don't bounds-check that `pc` is within the returned
  // instruction area.
  return EmbeddedData::FromBlobForPc(isolate, pc)
      .InstructionStartOf(builtin_id());
}

Address Code::InstructionEnd(Isolate* isolate, Address pc) const {
  return InstructionStart(isolate, pc) + instruction_size();
}

int Code::GetOffsetFromInstructionStart(Isolate* isolate, Address pc) const {
  const Address offset = pc - InstructionStart(isolate, pc);
  DCHECK_LE(offset, instruction_size());
  return static_cast<int>(offset);
}

Address Code::metadata_end() const {
  return metadata_start() + metadata_size();
}

Address Code::safepoint_table_address() const {
  return metadata_start() + safepoint_table_offset();
}

int Code::safepoint_table_size() const {
  return handler_table_offset() - safepoint_table_offset();
}

bool Code::has_safepoint_table() const { return safepoint_table_size() > 0; }

Address Code::handler_table_address() const {
  return metadata_start() + handler_table_offset();
}

int Code::handler_table_size() const {
  return constant_pool_offset() - handler_table_offset();
}

bool Code::has_handler_table() const { return handler_table_size() > 0; }

int Code::constant_pool_size() const {
  const int size = code_comments_offset() - constant_pool_offset();
  if (!V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    DCHECK_EQ(size, 0);
    return 0;
  }
  DCHECK_GE(size, 0);
  return size;
}

bool Code::has_constant_pool() const { return constant_pool_size() > 0; }

Tagged<ProtectedFixedArray> Code::unchecked_deoptimization_data() const {
  return UncheckedCast<ProtectedFixedArray>(
      ReadProtectedPointerField(kDeoptimizationDataOrInterpreterDataOffset));
}

uint8_t* Code::relocation_start() const {
  return V8_LIKELY(has_instruction_stream())
             ? instruction_stream()->relocation_start()
             : nullptr;
}

uint8_t* Code::relocation_end() const {
  return V8_LIKELY(has_instruction_stream())
             ? instruction_stream()->relocation_end()
             : nullptr;
}

int Code::relocation_size() const {
  return V8_LIKELY(has_instruction_stream())
             ? instruction_stream()->relocation_size()
             : 0;
}

bool Code::contains(Isolate* isolate, Address inner_pointer) const {
  const Address start = InstructionStart(isolate, inner_pointer);
  if (inner_pointer < start) return false;
  return inner_pointer < start + instruction_size();
}

int Code::InstructionStreamObjectSize() const {
  return InstructionStream::SizeFor(body_size());
}

int Code::SizeIncludingMetadata() const {
  int size = InstructionStreamObjectSize();
  size += relocation_size();
  if (uses_deoptimization_data()) {
    size += deoptimization_data()->Size();
  }
  return size;
}

CodeKind Code::kind() const { return KindField::decode(flags(kRelaxedLoad)); }

int Code::GetBytecodeOffsetForBaselinePC(Address baseline_pc,
                                         Tagged<BytecodeArray> bytecodes) {
  DisallowGarbageCollection no_gc;
  CHECK(!is_baseline_trampoline_builtin());
  if (is_baseline_leave_frame_builtin()) return kFunctionExitBytecodeOffset;
  CHECK_EQ(kind(), CodeKind::BASELINE);
  baseline::BytecodeOffsetIterator offset_iterator(
      Cast<TrustedByteArray>(bytecode_offset_table()), bytecodes);
  Address pc = baseline_pc - instruction_start();
  offset_iterator.AdvanceToPCOffset(pc);
  return offset_iterator.current_bytecode_offset();
}

uintptr_t Code::GetBaselinePCForBytecodeOffset(
    int bytecode_offset, BytecodeToPCPosition position,
    Tagged<BytecodeArray> bytecodes) {
  DisallowGarbageCollection no_gc;
  CHECK_EQ(kind(), CodeKind::BASELINE);
  baseline::BytecodeOffsetIterator offset_iterator(
      Cast<TrustedByteArray>(bytecode_offset_table()), bytecodes);
  offset_iterator.AdvanceToBytecodeOffset(bytecode_offset);
  uintptr_t pc = 0;
  if (position == kPcAtStartOfBytecode) {
    pc = offset_iterator.current_pc_start_offset();
  } else {
    DCHECK_EQ(position, kPcAtEndOfBytecode);
    pc = offset_iterator.current_pc_end_offset();
  }
  return pc;
}

uintptr_t Code::GetBaselineStartPCForBytecodeOffset(
    int bytecode_offset, Tagged<BytecodeArray> bytecodes) {
  return GetBaselinePCForBytecodeOffset(bytecode_offset, kPcAtStartOfBytecode,
                                        bytecodes);
}

uintptr_t Code::GetBaselineEndPCForBytecodeOffset(
    int bytecode_offset, Tagged<BytecodeArray> bytecodes) {
  return GetBaselinePCForBytecodeOffset(bytecode_offset, kPcAtEndOfBytecode,
                                        bytecodes);
}

uintptr_t Code::GetBaselinePCForNextExecutedBytecode(
    int bytecode_offset, Tagged<BytecodeArray> bytecodes) {
  DisallowGarbageCollection no_gc;
  CHECK_EQ(kind(), CodeKind::BASELINE);
  baseline::BytecodeOffsetIterator offset_iterator(
      Cast<TrustedByteArray>(bytecode_offset_table()), bytecodes);
  Handle<BytecodeArray> bytecodes_handle(
      reinterpret_cast<Address*>(&bytecodes));
  interpreter::BytecodeArrayIterator bytecode_iterator(bytecodes_handle,
                                                       bytecode_offset);
  interpreter::Bytecode bytecode = bytecode_iterator.current_bytecode();
  if (bytecode == interpreter::Bytecode::kJumpLoop) {
    return GetBaselineStartPCForBytecodeOffset(
        bytecode_iterator.GetJumpTargetOffset(), bytecodes);
  } else {
    DCHECK(!interpreter::Bytecodes::IsJump(bytecode));
    DCHECK(!interpreter::Bytecodes::IsSwitch(bytecode));
    DCHECK(!interpreter::Bytecodes::Returns(bytecode));
    return GetBaselineEndPCForBytecodeOffset(bytecode_offset, bytecodes);
  }
}

inline bool Code::checks_tiering_state() const {
  bool checks_state = (builtin_id() == Builtin::kCompileLazy ||
                       builtin_id() == Builtin::kInterpreterEntryTrampoline ||
                       CodeKindCanTierUp(kind()));
  return checks_state ||
         (CodeKindCanDeoptimize(kind()) && marked_for_deoptimization());
}

inline constexpr bool CodeKindHasTaggedOutgoingParams(CodeKind kind) {
  return kind != CodeKind::JS_TO_WASM_FUNCTION &&
         kind != CodeKind::C_WASM_ENTRY && kind != CodeKind::WASM_FUNCTION;
}

inline bool Code::has_tagged_outgoing_params() const {
#if V8_ENABLE_WEBASSEMBLY
  return CodeKindHasTaggedOutgoingParams(kind()) &&
         builtin_id() != Builtin::kWasmCompileLazy;
#else
  return CodeKindHasTaggedOutgoingParams(kind());
#endif
}

inline bool Code::is_context_specialized() const {
  return IsContextSpecializedField::decode(flags(kRelaxedLoad));
}

inline bool Code::is_turbofanned() const {
  return IsTurbofannedField::decode(flags(kRelaxedLoad));
}

inline bool Code::is_maglevved() const { return kind() == CodeKind::MAGLEV; }

unsigned Code::inlined_bytecode_size() const {
  unsigned size = RELAXED_READ_UINT_FIELD(*this, kInlinedBytecodeSizeOffset);
  DCHECK(CodeKindIsOptimizedJSFunction(kind()) || size == 0);
  return size;
}

void Code::set_inlined_bytecode_size(unsigned size) {
  DCHECK(CodeKindIsOptimizedJSFunction(kind()) || size == 0);
  RELAXED_WRITE_UINT_FIELD(*this, kInlinedBytecodeSizeOffset, size);
}

// For optimized on-heap wasm-js wrappers, we repurpose the (otherwise unused)
// 32-bit InlinedBytecodeSize field to encode two 16 values needed for scanning
// the frame: the count and starting offset of incoming tagged parameters.
// TODO(wasm): Eventually the wrappers should be managed off-heap by the wasm
// engine. Remove these accessors when that is the case.
void Code::set_wasm_js_tagged_parameter_count(uint16_t count) {
  DCHECK_EQ(kind(), CodeKind::WASM_TO_JS_FUNCTION);
  RELAXED_WRITE_UINT16_FIELD(*this, kInlinedBytecodeSizeOffset, count);
}

uint16_t Code::wasm_js_tagged_parameter_count() const {
  DCHECK_EQ(kind(), CodeKind::WASM_TO_JS_FUNCTION);
  return RELAXED_READ_UINT16_FIELD(*this, kInlinedBytecodeSizeOffset);
}

void Code::set_wasm_js_first_tagged_parameter(uint16_t count) {
  DCHECK_EQ(kind(), CodeKind::WASM_TO_JS_FUNCTION);
  RELAXED_WRITE_UINT16_FIELD(*this, kInlinedBytecodeSizeOffset + 2, count);
}

uint16_t Code::wasm_js_first_tagged_parameter() const {
  DCHECK_EQ(kind(), CodeKind::WASM_TO_JS_FUNCTION);
  return RELAXED_READ_UINT16_FIELD(*this, kInlinedBytecodeSizeOffset + 2);
}

BytecodeOffset Code::osr_offset() const {
  return BytecodeOffset(RELAXED_READ_INT32_FIELD(*this, kOsrOffsetOffset));
}

void Code::set_osr_offset(BytecodeOffset offset) {
  RELAXED_WRITE_INT32_FIELD(*this, kOsrOffsetOffset, offset.ToInt());
}

bool Code::uses_safepoint_table() const {
  return is_turbofanned() || is_maglevved() || is_wasm_code();
}

uint32_t Code::stack_slots() const {
  DCHECK_IMPLIES(safepoint_table_size() > 0, uses_safepoint_table());
  if (safepoint_table_size() == 0) return 0;
  DCHECK(safepoint_table_size() >=
         static_cast<int>(sizeof(SafepointTableStackSlotsField_t)));
  static_assert(kSafepointTableStackSlotsOffset == 0);
  return base::Memory<SafepointTableStackSlotsField_t>(
      safepoint_table_address() + kSafepointTableStackSlotsOffset);
}

bool Code::marked_for_deoptimization() const {
  return MarkedForDeoptimizationField::decode(flags(kRelaxedLoad));
}

void Code::set_marked_for_deoptimization(bool flag) {
  DCHECK_IMPLIES(flag, AllowDeoptimization::IsAllowed(
                           GetIsolateFromWritableObject(*this)));
  int32_t previous = flags(kRelaxedLoad);
  int32_t updated = MarkedForDeoptimizationField::update(previous, flag);
  set_flags(updated, kRelaxedStore);
}

bool Code::embedded_objects_cleared() const {
  return Code::EmbeddedObjectsClearedField::decode(flags(kRelaxedLoad));
}

void Code::set_embedded_objects_cleared(bool flag) {
  DCHECK_IMPLIES(flag, marked_for_deoptimization());
  int32_t previous = flags(kRelaxedLoad);
  int32_t updated = Code::EmbeddedObjectsClearedField::update(previous, flag);
  set_flags(updated, kRelaxedStore);
}

inline bool Code::can_have_weak_objects() const {
  return CanHaveWeakObjectsField::decode(flags(kRelaxedLoad));
}

inline void Code::set_can_have_weak_objects(bool value) {
  int32_t previous = flags(kRelaxedLoad);
  int32_t updated = CanHaveWeakObjectsField::update(previous, value);
  set_flags(updated, kRelaxedStore);
}

bool Code::is_wasm_code() const { return kind() == CodeKind::WASM_FUNCTION; }

int Code::constant_pool_offset() const {
  if (!V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // Redirection needed since the field doesn't exist in this case.
    return code_comments_offset();
  }
  return ReadField<int>(kConstantPoolOffsetOffset);
}

void Code::set_constant_pool_offset(int value) {
  if (!V8_EMBEDDED_CONSTANT_POOL_BOOL) {
    // Redirection needed since the field doesn't exist in this case.
    return;
  }
  DCHECK_LE(value, metadata_size());
  WriteField<int>(kConstantPoolOffsetOffset, value);
}

Address Code::constant_pool() const {
  if (!has_constant_pool()) return kNullAddress;
  return metadata_start() + constant_pool_offset();
}

Address Code::code_comments() const {
  return metadata_start() + code_comments_offset();
}

int Code::code_comments_size() const {
  return builtin_jump_table_info_offset() - code_comments_offset();
}

bool Code::has_code_comments() const { return code_comments_size() > 0; }

int32_t Code::builtin_jump_table_info_offset() const {
  if (!V8_BUILTIN_JUMP_TABLE_INFO_BOOL) {
    // Redirection needed since the field doesn't exist in this case.
    return unwinding_info_offset();
  }
  return ReadField<int32_t>(kBuiltinJumpTableInfoOffsetOffset);
}

void Code::set_builtin_jump_table_info_offset(int32_t value) {
  if (!V8_BUILTIN_JUMP_TABLE_INFO_BOOL) {
    // Redirection needed since the field doesn't exist in this case.
    return;
  }
  DCHECK_LE(value, metadata_size());
  WriteField<int32_t>(kBuiltinJumpTableInfoOffsetOffset, value);
}

Address Code::builtin_jump_table_info() const {
  return metadata_start() + builtin_jump_table_info_offset();
}

int Code::builtin_jump_table_info_size() const {
  return unwinding_info_offset() - builtin_jump_table_info_offset();
}

bool Code::has_builtin_jump_table_info() const {
  return builtin_jump_table_info_size() > 0;
}

Address Code::unwinding_info_start() const {
  return metadata_start() + unwinding_info_offset();
}

Address Code::unwinding_info_end() const { return metadata_end(); }

int Code::unwinding_info_size() const {
  return static_cast<int>(unwinding_info_end() - unwinding_info_start());
}

bool Code::has_unwinding_info() const { return unwinding_info_size() > 0; }

// static
Tagged<Code> Code::FromTargetAddress(Address address) {
  return InstructionStream::FromTargetAddress(address)->code(kAcquireLoad);
}

bool Code::CanContainWeakObjects() {
  return is_optimized_code() && can_have_weak_objects();
}

bool Code::IsWeakObject(Tagged<HeapObject> object) {
  return (CanContainWeakObjects() && IsWeakObjectInOptimizedCode(object));
}

bool Code::IsWeakObjectInOptimizedCode(Tagged<HeapObject> object) {
  Tagged<Map> map_object = object->map(kAcquireLoad);
  if (InstanceTypeChecker::IsMap(map_object)) {
    return Cast<Map>(object)->CanTransition();
  }
  return InstanceTypeChecker::IsPropertyCell(map_object) ||
         InstanceTypeChecker::IsJSReceiver(map_object) ||
         InstanceTypeChecker::IsContext(map_object);
}

bool Code::IsWeakObjectInDeoptimizationLiteralArray(Tagged<Object> object) {
  // Maps must be strong because they can be used as part of the description for
  // how to materialize an object upon deoptimization, in which case it is
  // possible to reach the code that requires the Map without anything else
  // holding a strong pointer to that Map.
  return IsHeapObject(object) && !IsMap(object) &&
         Code::IsWeakObjectInOptimizedCode(Cast<HeapObject>(object));
}

void Code::IterateDeoptimizationLiterals(RootVisitor* v) {
  if (!uses_deoptimization_data()) {
    DCHECK(kind() == CodeKind::BASELINE ||
           !has_deoptimization_data_or_interpreter_data());
    return;
  }

  auto deopt_data = Cast<DeoptimizationData>(deoptimization_data());
  if (deopt_data->length() == 0) return;

  Tagged<DeoptimizationLiteralArray> literals = deopt_data->LiteralArray();
  const int literals_length = literals->length();
  for (int i = 0; i < literals_length; ++i) {
    Tagged<MaybeObject> maybe_literal = literals->get_raw(i);
    Tagged<HeapObject> heap_literal;
    if (maybe_literal.GetHeapObject(&heap_literal)) {
      v->VisitRootPointer(Root::kStackRoots, "deoptimization literal",
                          FullObjectSlot(&heap_literal));
    }
  }
}

Tagged<Object> Code::raw_instruction_stream() const {
  PtrComprCageBase cage_base = code_cage_base();
  return Code::raw_instruction_stream(cage_base);
}

Tagged<Object> Code::raw_instruction_stream(PtrComprCageBase cage_base) const {
  return ExternalCodeField<Object>::load(cage_base, *this);
}

void Code::set_raw_instruction_stream(Tagged<Object> value,
                                      WriteBarrierMode mode) {
  ExternalCodeField<Object>::Release_Store(*this, value);
  CONDITIONAL_WRITE_BARRIER(*this, kInstructionStreamOffset, value, mode);
}

bool Code::has_instruction_stream() const {
#if defined(V8_COMPRESS_POINTERS) || !defined(V8_HOST_ARCH_64_BIT)
  const uint32_t value = ReadField<uint32_t>(kInstructionStreamOffset);
#else
  const uint64_t value = ReadField<uint64_t>(kInstructionStreamOffset);
#endif
  SLOW_DCHECK(value == 0 || !HeapLayout::InReadOnlySpace(*this));
  return value != 0;
}

bool Code::has_instruction_stream(RelaxedLoadTag tag) const {
#if defined(V8_COMPRESS_POINTERS) || !defined(V8_HOST_ARCH_64_BIT)
  const uint32_t value =
      RELAXED_READ_INT32_FIELD(*this, kInstructionStreamOffset);
#else
  const uint64_t value =
      RELAXED_READ_INT64_FIELD(*this, kInstructionStreamOffset);
#endif
  SLOW_DCHECK(value == 0 || !HeapLayout::InReadOnlySpace(*this));
  return value != 0;
}

PtrComprCageBase Code::code_cage_base() const {
#ifdef V8_EXTERNAL_CODE_SPACE
  return PtrComprCageBase(ExternalCodeCompressionScheme::base());
#else   // V8_EXTERNAL_CODE_SPACE
  // Without external code space: `code_cage_base == main_cage_base`. We can
  // get the main cage base from any heap object, including objects in RO
  // space.
  return GetPtrComprCageBase(*this);
#endif  // V8_EXTERNAL_CODE_SPACE
}

Tagged<InstructionStream> Code::instruction_stream() const {
  PtrComprCageBase cage_base = code_cage_base();
  return Code::instruction_stream(cage_base);
}

Tagged<InstructionStream> Code::unchecked_instruction_stream() const {
  return UncheckedCast<InstructionStream>(raw_instruction_stream());
}

Tagged<InstructionStream> Code::instruction_stream(
    PtrComprCageBase cage_base) const {
  DCHECK(has_instruction_stream());
  return ExternalCodeField<InstructionStream>::load(cage_base, *this);
}

Tagged<InstructionStream> Code::instruction_stream(RelaxedLoadTag tag) const {
  PtrComprCageBase cage_base = code_cage_base();
  return Code::instruction_stream(cage_base, tag);
}

Tagged<InstructionStream> Code::instruction_stream(PtrComprCageBase cage_base,
                                                   RelaxedLoadTag tag) const {
  DCHECK(has_instruction_stream());
  return ExternalCodeField<InstructionStream>::Relaxed_Load(cage_base, *this);
}

Tagged<Object> Code::raw_instruction_stream(RelaxedLoadTag tag) const {
  PtrComprCageBase cage_base = code_cage_base();
  return Code::raw_instruction_stream(cage_base, tag);
}

Tagged<Object> Code::raw_instruction_stream(PtrComprCageBase cage_base,
                                            RelaxedLoadTag tag) const {
  return ExternalCodeField<Object>::Relaxed_Load(cage_base, *this);
}

DEF_GETTER(Code, instruction_start, Address) {
#ifdef V8_ENABLE_SANDBOX
  return ReadCodeEntrypointViaCodePointerField(kSelfIndirectPointerOffset,
                                               entrypoint_tag());
#else
  return ReadField<Address>(kInstructionStartOffset);
#endif
}

void Code::set_instruction_start(IsolateForSandbox isolate, Address value) {
#ifdef V8_ENABLE_SANDBOX
  WriteCodeEntrypointViaCodePointerField(kSelfIndirectPointerOffset, value,
                                         entrypoint_tag());
#else
  WriteField<Address>(kInstructionStartOffset, value);
#endif
}

CodeEntrypointTag Code::entrypoint_tag() const {
  switch (kind()) {
    case CodeKind::BYTECODE_HANDLER:
      return kBytecodeHandlerEntrypointTag;
    case CodeKind::BUILTIN:
      return Builtins::EntrypointTagFor(builtin_id());
    case CodeKind::REGEXP:
      return kRegExpEntrypointTag;
    case CodeKind::WASM_FUNCTION:
    case CodeKind::WASM_TO_CAPI_FUNCTION:
    case CodeKind::WASM_TO_JS_FUNCTION:
      return kWasmEntrypointTag;
    case CodeKind::JS_TO_WASM_FUNCTION:
      return kJSEntrypointTag;
    default:
      // TODO(saelo): eventually we'll want this to be UNREACHABLE().
      return kDefaultCodeEntrypointTag;
  }
}

void Code::SetInstructionStreamAndInstructionStart(
    IsolateForSandbox isolate, Tagged<InstructionStream> code,
    WriteBarrierMode mode) {
  set_raw_instruction_stream(code, mode);
  set_instruction_start(isolate, code->instruction_start());
}

void Code::SetInstructionStartForOffHeapBuiltin(IsolateForSandbox isolate,
                                                Address entry) {
  DCHECK(!has_instruction_stream());
  set_instruction_start(isolate, entry);
}

void Code::ClearInstructionStartForSerialization(IsolateForSandbox isolate) {
#ifdef V8_ENABLE_SANDBOX
  // The instruction start is stored in this object's code pointer table.
  WriteField<CodePointerHandle>(kSelfIndirectPointerOffset,
                                kNullCodePointerHandle);
#else
  set_instruction_start(isolate, kNullAddress);
#endif  // V8_ENABLE_SANDBOX
}

void Code::UpdateInstructionStart(IsolateForSandbox isolate,
                                  Tagged<InstructionStream> istream) {
  DCHECK_EQ(raw_instruction_stream(), istream);
  set_instruction_start(isolate, istream->instruction_start());
}

void Code::clear_padding() {
  memset(reinterpret_cast<void*>(address() + kUnalignedSize), 0,
         kSize - kUnalignedSize);
}

RELAXED_UINT32_ACCESSORS(Code, flags, kFlagsOffset)

void Code::initialize_flags(CodeKind kind, bool is_context_specialized,
                            bool is_turbofanned) {
  DCHECK(!CodeKindIsInterpretedJSFunction(kind));
  uint32_t value = KindField::encode(kind) |
                   IsContextSpecializedField::encode(is_context_specialized) |
                   IsTurbofannedField::encode(is_turbofanned);
  static_assert(FIELD_SIZE(kFlagsOffset) == kInt32Size);
  set_flags(value, kRelaxedStore);
}

// Ensure builtin_id field fits into int16_t, so that we can rely on sign
// extension to convert int16_t{-1} to kNoBuiltinId.
// If the asserts fail, update the code that use kBuiltinIdOffset below.
static_assert(static_cast<int>(Builtin::kNoBuiltinId) == -1);
static_assert(Builtins::kBuiltinCount < std::numeric_limits<int16_t>::max());

void Code::set_builtin_id(Builtin builtin_id) {
  static_assert(FIELD_SIZE(kBuiltinIdOffset) == kInt16Size);
  Relaxed_WriteField<int16_t>(kBuiltinIdOffset,
                              static_cast<int16_t>(builtin_id));
}

Builtin Code::builtin_id() const {
  // Rely on sign-extension when converting int16_t to int to preserve
  // kNoBuiltinId value.
  static_assert(FIELD_SIZE(kBuiltinIdOffset) == kInt16Size);
  static_assert(static_cast<int>(static_cast<int16_t>(Builtin::kNoBuiltinId)) ==
                static_cast<int>(Builtin::kNoBuiltinId));
  int value = ReadField<int16_t>(kBuiltinIdOffset);
  return static_cast<Builtin>(value);
}

bool Code::is_builtin() const { return builtin_id() != Builtin::kNoBuiltinId; }

bool Code::is_optimized_code() const {
  return CodeKindIsOptimizedJSFunction(kind());
}

inline bool Code::is_interpreter_trampoline_builtin() const {
  return IsInterpreterTrampolineBuiltin(builtin_id());
}

inline bool Code::is_baseline_trampoline_builtin() const {
  return IsBaselineTrampolineBuiltin(builtin_id());
}

inline bool Code::is_baseline_leave_frame_builtin() const {
  return builtin_id() == Builtin::kBaselineLeaveFrame;
}

OBJECT_CONSTRUCTORS_IMPL(CodeWrapper, Struct)
CODE_POINTER_ACCESSORS(CodeWrapper, code, kCodeOffset)

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_OBJECTS_CODE_INL_H_
```