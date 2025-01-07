Response:
Let's break down the thought process for summarizing the `wasm-module.h` file.

1. **Initial Understanding of the Request:** The request asks for a functional summary of a C++ header file (`wasm-module.h`) related to WebAssembly within the V8 JavaScript engine. It also has specific constraints about file extensions (`.tq`) and JavaScript relationships. The "Part 1 of 2" suggests more content is coming, so the summary should focus on the provided snippet.

2. **Scanning for Key Information:** The first step is to quickly scan the header file for recurring keywords, data structures, and overall structure. I'd look for:
    * `#ifndef`, `#define`: Indicates a header guard, standard practice.
    * `#include`:  Lists dependencies, hinting at related concepts (e.g., `signature.h`, `wasm-constants.h`).
    * `namespace v8::internal::wasm`:  Confirms the file's location and purpose within V8.
    * `struct`, `class`, `enum`: Defines the core data structures and types.
    * Comments:  Often provide high-level explanations of the purpose of structures or sections. The copyright notice is less relevant for a functional summary.
    * `constexpr`, `inline`:  Hints at performance considerations and compile-time behavior.
    * `using`:  Creates aliases for types, improving readability.
    * `V8_EXPORT_PRIVATE`:  Indicates intended visibility and API boundaries.

3. **Identifying Core Data Structures and Their Roles:**  The `struct` declarations are central to understanding the module's structure. I would go through each one, noting its name and the purpose suggested by its members and comments:
    * `WireBytesRef`: References sections of the raw WebAssembly bytecode.
    * `WasmFunction`: Represents a WebAssembly function, including its signature, code location, and import/export status.
    * `WasmGlobal`: Represents a global variable, its type, mutability, and initialization.
    * `WasmTag`: Represents an exception tag.
    * `WasmMemory`: Represents the module's memory, including size limits and bounds checking strategy.
    * `WasmDataSegment`:  Represents data segments used to initialize memory.
    * `WasmElemSegment`: Represents element segments used to initialize tables.
    * `WasmImport`, `WasmExport`: Represent imports and exports of functions, globals, memories, etc.
    * `WasmCompilationHint`:  Provides hints for the compiler.
    * `AdaptiveMap`: A template for efficiently storing sparse or dense data.
    * `LazilyGeneratedNames`: Stores function names, loaded on demand.
    * `AsmJsOffsetInformation`: Stores source code position information for asm.js modules.
    * `TypeDefinition`: Represents different kinds of types (functions, structs, arrays).
    * `WasmDebugSymbols`: Contains debugging information.
    * `CallSiteFeedback`, `FunctionTypeFeedback`, `TypeFeedbackStorage`:  Structures related to performance optimization through type feedback.
    * `WasmTable`: Represents a WebAssembly table.
    * `WasmModule`: The central structure representing the entire parsed WebAssembly module.

4. **Grouping Functionality:**  As I identify the data structures, I start to see patterns and groupings of related concepts. For instance:
    * Imports and Exports: `WasmImport`, `WasmExport`.
    * Memory Management: `WasmMemory`, `WasmDataSegment`.
    * Function Representation: `WasmFunction`, `FunctionSig`.
    * Type System: `TypeDefinition`, `FunctionSig`, `StructType`, `ArrayType`.
    * Optimization: `CallSiteFeedback`, `FunctionTypeFeedback`, `TypeFeedbackStorage`.

5. **Inferring Overall Purpose:**  Based on the identified structures and their members, I can infer the overall purpose of the header file: to define the in-memory representation of a parsed WebAssembly module within V8. This representation is used during compilation, instantiation, and execution.

6. **Addressing Specific Constraints:**
    * **`.tq` extension:** The header doesn't end in `.tq`, so it's not a Torque source file.
    * **JavaScript relationship:** Many elements have a direct relationship to JavaScript functionality (e.g., calling WebAssembly functions from JavaScript, accessing memory). However, the header itself is C++. I'll need to provide a JavaScript example related to the concepts defined in the header.
    * **Code logic/inference:** The header defines *data structures*, not the logic that operates on them. Therefore, it's hard to give a specific input/output example. The *structure* itself is the output of parsing the WebAssembly bytecode. However, the `UpdateComputedInformation` function within `WasmMemory` is a small piece of logic where I can provide an example.
    * **Common programming errors:**  Since this is a data structure definition, the "errors" would be related to misinterpreting or incorrectly using the defined structures in the V8 codebase. A good example is incorrect memory access, which WebAssembly's bounds checking tries to prevent.

7. **Drafting the Summary:**  I would start drafting the summary, focusing on the key functionalities and data structures identified. I'd use clear and concise language, avoiding overly technical jargon where possible.

8. **Adding Examples and Explanations:**  I'd then add the JavaScript example, the input/output for `UpdateComputedInformation`, and the example of a common programming error related to memory access.

9. **Refining and Organizing:** Finally, I'd review the summary for clarity, accuracy, and organization. I'd ensure that all the points from the initial request are addressed. The "Part 1 of 2" instruction reminds me to keep the summary focused on the provided content and avoid making assumptions about the next part.

This iterative process of scanning, identifying, grouping, inferring, and refining allows for a comprehensive and accurate summary of the header file's functionality. The focus is on what the data structures *represent* and their role in the broader WebAssembly implementation within V8.
好的，这是对 `v8/src/wasm/wasm-module.h` 文件功能的归纳：

**功能归纳：**

`v8/src/wasm/wasm-module.h` 文件是 V8 JavaScript 引擎中用于表示 WebAssembly 模块的**核心数据结构定义**。它定义了在 V8 内部如何存储和管理 WebAssembly 模块的各种组件信息，为后续的编译、实例化和执行过程提供了必要的数据基础。

**具体功能点：**

1. **WebAssembly 模块的静态表示：**  该头文件定义了 `WasmModule` 结构体，它是 WebAssembly 模块在 V8 中的静态表示。它包含了模块的所有关键信息，例如：
    * **类型信息 (`types`)：**  存储函数签名、结构体类型和数组类型的定义。
    * **函数信息 (`functions`)：**  存储模块中定义的函数，包括签名、索引、代码位置等。
    * **全局变量信息 (`globals`)：**  存储模块中定义的全局变量，包括类型、可变性、初始化表达式等。
    * **内存信息 (`memories`)：**  存储模块的内存定义，包括初始大小、最大大小、是否共享等。
    * **数据段信息 (`data_segments`)：**  存储用于初始化内存的数据段。
    * **表格信息 (`tables`)：**  存储模块的表格定义，包括元素类型、初始大小、最大大小等。
    * **导入导出信息 (`import_table`, `export_table`)：**  存储模块的导入和导出定义。
    * **标签信息 (`tags`)：** 存储异常标签的定义。
    * **元素段信息 (`elem_segments`)：** 存储用于初始化表格的元素段。
    * **编译提示信息 (`compilation_hints`)：**  存储关于如何编译函数的提示。
    * **调试信息 (`debug_symbols`)：** 存储调试相关的信息，如源地图。
    * **分支提示信息 (`branch_hints`)：** 存储代码分支预测的提示信息。

2. **定义 WebAssembly 的基本构成元素：**  该头文件还定义了构成 WebAssembly 模块的各种基本元素的结构体，例如：
    * `WasmFunction`：表示一个 WebAssembly 函数。
    * `WasmGlobal`：表示一个 WebAssembly 全局变量。
    * `WasmMemory`：表示一个 WebAssembly 内存。
    * `WasmTable`：表示一个 WebAssembly 表格。
    * `WasmImport` 和 `WasmExport`：分别表示导入和导出。
    * `FunctionSig`：表示函数签名。
    * `ConstantExpression`：表示常量表达式。

3. **辅助数据结构：**  除了核心的模块和元素定义，还包含一些辅助数据结构，例如：
    * `WireBytesRef`：用于引用 WebAssembly 字节码中的一段数据。
    * `AdaptiveMap`：一种自适应的映射表，用于存储稀疏或稠密的数据。
    * `LazilyGeneratedNames`：用于延迟生成函数名称。
    * `AsmJsOffsetInformation`：用于存储 asm.js 模块的源位置信息。
    * `TypeFeedbackStorage`，`FunctionTypeFeedback`，`CallSiteFeedback`： 用于存储类型反馈信息，用于优化 WebAssembly 代码的执行。

4. **枚举类型和常量：**  定义了一些枚举类型和常量，用于表示 WebAssembly 的各种属性，例如：
    * `ModuleOrigin`：表示模块的来源（WebAssembly 或 asm.js）。
    * `AddressType`：表示地址类型 (i32 或 i64)。
    * `BoundsCheckStrategy`：表示边界检查策略。
    * `WasmElemSegment::Status`：表示元素段的状态。
    * `ImportExportKindCode`：表示导入导出的类型。

**关于文件扩展名和 JavaScript 关系：**

* **文件扩展名：**  `v8/src/wasm/wasm-module.h` 的扩展名是 `.h`，表明它是一个 **C++ 头文件**。如果该文件以 `.tq` 结尾，则它会是一个 **V8 Torque 源代码文件**，Torque 是 V8 用于定义运行时内置函数的领域特定语言。

* **JavaScript 关系：**  `v8/src/wasm/wasm-module.h` 中定义的数据结构直接关系到 JavaScript 中如何使用 WebAssembly。例如，当你在 JavaScript 中创建一个 WebAssembly 模块实例时，V8 内部会解析 WebAssembly 字节码并使用 `WasmModule` 结构体来存储模块的信息。

**JavaScript 示例：**

```javascript
// 假设你已经获取了 WebAssembly 的字节码 (wasmBytes)
WebAssembly.instantiate(wasmBytes).then(result => {
  const instance = result.instance;
  const exportedFunction = instance.exports.myFunction; // 访问导出的函数
  const memory = instance.exports.memory; // 访问导出的内存

  // 调用导出的 WebAssembly 函数
  const resultValue = exportedFunction(10, 20);
  console.log(resultValue);

  // 访问 WebAssembly 内存
  const buffer = new Uint8Array(memory.buffer);
  console.log(buffer[0]);
});
```

在这个 JavaScript 示例中：

* `WebAssembly.instantiate` 会解析 WebAssembly 字节码。V8 内部会使用 `wasm-module.h` 中定义的结构体来存储解析后的模块信息，包括导出的函数 (`myFunction`) 和内存 (`memory`)。
* `instance.exports.myFunction` 和 `instance.exports.memory` 对应于 `WasmModule` 结构体中的 `export_table` 和相应的函数/内存定义。

**代码逻辑推理 (关于 `UpdateComputedInformation`)：**

`UpdateComputedInformation` 函数用于计算 `WasmMemory` 结构体中的 `min_memory_size` 和 `max_memory_size`。

**假设输入：**

```c++
WasmMemory memory;
memory.initial_pages = 10;   // 初始 10 页 (640KB)
memory.maximum_pages = 20;   // 最大 20 页 (1280KB)
memory.address_type = AddressType::kI32; // 32 位地址
ModuleOrigin origin = kWasmOrigin;
```

**输出：**

```c++
UpdateComputedInformation(&memory, origin);
// memory.min_memory_size 将会是 655360 (10 * 64 * 1024)
// memory.max_memory_size 将会是 1310720 (20 * 64 * 1024)，但会受到平台和引擎限制。
// memory.bounds_checks 的值取决于 v8_flags 和平台特性。
```

**用户常见的编程错误（与 WebAssembly 相关的，但不直接是 `wasm-module.h` 的错误）：**

`wasm-module.h` 定义的是数据结构，本身不会直接导致用户的编程错误。然而，理解这些数据结构对于避免与 WebAssembly 相关的编程错误至关重要。一个常见的错误是 **越界内存访问**。

**示例：**

假设一个 WebAssembly 模块导出了一个内存 `memory`，其大小被定义为 10 页（640KB）。在 JavaScript 中，用户可能会尝试访问超出这个范围的内存地址：

```javascript
WebAssembly.instantiate(wasmBytes).then(result => {
  const memory = result.instance.exports.memory;
  const buffer = new Uint8Array(memory.buffer);

  // 尝试访问超出内存大小的索引（假设内存大小是 640KB，索引范围是 0 到 655359）
  const invalidIndex = 655360;
  const value = buffer[invalidIndex]; // 这将导致错误 (RangeError 或类似的错误)
  console.log(value);
});
```

V8 引擎会根据 `WasmMemory` 结构体中存储的内存大小信息，在运行时检测到这种越界访问并抛出错误。`wasm-module.h` 中定义的 `min_memory_size` 和 `max_memory_size` 就用于进行这种边界检查。

**总结：**

`v8/src/wasm/wasm-module.h` 是 V8 引擎中 WebAssembly 功能的核心，它定义了表示 WebAssembly 模块及其组成部分的关键数据结构。理解这些结构对于理解 V8 如何处理 WebAssembly 模块至关重要，并有助于避免与 WebAssembly 相关的编程错误。

Prompt: 
```
这是目录为v8/src/wasm/wasm-module.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/wasm-module.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#if !V8_ENABLE_WEBASSEMBLY
#error This header should only be included if WebAssembly is enabled.
#endif  // !V8_ENABLE_WEBASSEMBLY

#ifndef V8_WASM_WASM_MODULE_H_
#define V8_WASM_WASM_MODULE_H_

#include <map>
#include <memory>
#include <optional>

#include "src/base/platform/mutex.h"
#include "src/base/vector.h"
#include "src/codegen/signature.h"
#include "src/common/globals.h"
#include "src/handles/handles.h"
#include "src/trap-handler/trap-handler.h"
#include "src/wasm/branch-hint-map.h"
#include "src/wasm/constant-expression.h"
#include "src/wasm/struct-types.h"
#include "src/wasm/wasm-constants.h"
#include "src/wasm/wasm-init-expr.h"
#include "src/wasm/wasm-limits.h"
#include "src/wasm/well-known-imports.h"

namespace v8::internal {
class WasmModuleObject;
}

namespace v8::internal::wasm {

using WasmName = base::Vector<const char>;

struct AsmJsOffsets;
class ErrorThrower;
#if V8_ENABLE_DRUMBRAKE
class WasmInterpreterRuntime;
#endif  // V8_ENABLE_DRUMBRAKE
class WellKnownImportsList;

enum class AddressType : uint8_t { kI32, kI64 };

inline constexpr const char* AddressTypeToStr(AddressType address_type) {
  return address_type == AddressType::kI32 ? "i32" : "i64";
}

inline std::ostream& operator<<(std::ostream& os, AddressType address_type) {
  return os << AddressTypeToStr(address_type);
}

// Reference to a string in the wire bytes.
class WireBytesRef {
 public:
  constexpr WireBytesRef() = default;
  constexpr WireBytesRef(uint32_t offset, uint32_t length)
      : offset_(offset), length_(length) {
    DCHECK_IMPLIES(offset_ == 0, length_ == 0);
    DCHECK_LE(offset_, offset_ + length_);  // no uint32_t overflow.
  }

  uint32_t offset() const { return offset_; }
  uint32_t length() const { return length_; }
  uint32_t end_offset() const { return offset_ + length_; }
  bool is_empty() const { return length_ == 0; }
  bool is_set() const { return offset_ != 0; }

 private:
  uint32_t offset_ = 0;
  uint32_t length_ = 0;
};

// Static representation of a wasm function.
struct WasmFunction {
  const FunctionSig* sig = nullptr;  // signature of the function.
  uint32_t func_index = 0;           // index into the function table.
  ModuleTypeIndex sig_index{0};      // index into the signature table.
  // TODO(clemensb): Should we add canonical_sig_id and canonical_sig?
  WireBytesRef code = {};            // code of this function.
  bool imported = false;
  bool exported = false;
  bool declared = false;
};

// Static representation of a wasm global variable.
struct WasmGlobal {
  ValueType type;                // type of the global.
  bool mutability = false;       // {true} if mutable.
  ConstantExpression init = {};  // the initialization expression of the global.
  union {
    // Index of imported mutable global.
    uint32_t index;
    // Offset into global memory (if not imported & mutable). Expressed in bytes
    // for value-typed globals, and in tagged words for reference-typed globals.
    uint32_t offset;
  };
  bool shared = false;
  bool imported = false;
  bool exported = false;
};

// Note: An exception tag signature only uses the params portion of a function
// signature.
using WasmTagSig = FunctionSig;

// Static representation of a wasm tag type.
struct WasmTag {
  explicit WasmTag(const WasmTagSig* sig, ModuleTypeIndex sig_index)
      : sig(sig), sig_index(sig_index) {}
  const FunctionSig* ToFunctionSig() const { return sig; }

  const WasmTagSig* sig;  // type signature of the tag.
  ModuleTypeIndex sig_index;
};

enum ModuleOrigin : uint8_t {
  kWasmOrigin,
  kAsmJsSloppyOrigin,
  kAsmJsStrictOrigin
};

enum BoundsCheckStrategy : int8_t {
  // Emit protected instructions, use the trap handler for OOB detection.
  kTrapHandler,
  // Emit explicit bounds checks.
  kExplicitBoundsChecks,
  // Emit no bounds checks at all (for testing only).
  kNoBoundsChecks
};

// Static representation of a wasm memory.
struct WasmMemory {
  // Index into the memory table.
  uint32_t index = 0;
  // Initial size of the memory in 64k pages.
  uint32_t initial_pages = 0;
  // Maximum declared size of the memory in 64k pages. The actual memory size at
  // runtime is capped at {kV8MaxWasmMemory32Pages} / {kV8MaxWasmMemory64Pages}.
  uint64_t maximum_pages = 0;
  bool is_shared = false;
  bool has_maximum_pages = false;
  AddressType address_type = AddressType::kI32;
  bool imported = false;
  bool exported = false;

  // Computed information, cached here for faster compilation.
  // Updated via {UpdateComputedInformation}.
  // Smallest size this memory can have at runtime, in bytes.
  uintptr_t min_memory_size = 0;
  // Largest size this memory can have at runtime (via declared maximum and
  // engine limits), in bytes.
  uintptr_t max_memory_size = 0;

  BoundsCheckStrategy bounds_checks = kExplicitBoundsChecks;

  bool is_memory64() const { return address_type == AddressType::kI64; }
};

inline void UpdateComputedInformation(WasmMemory* memory, ModuleOrigin origin) {
  const uintptr_t platform_max_pages =
      memory->is_memory64() ? kV8MaxWasmMemory64Pages : kV8MaxWasmMemory32Pages;
  memory->min_memory_size = static_cast<uintptr_t>(std::min<uint64_t>(
                                platform_max_pages, memory->initial_pages)) *
                            kWasmPageSize;
  memory->max_memory_size = static_cast<uintptr_t>(std::min<uint64_t>(
                                platform_max_pages, memory->maximum_pages)) *
                            kWasmPageSize;

  if (!v8_flags.wasm_bounds_checks) {
    memory->bounds_checks = kNoBoundsChecks;
  } else if (v8_flags.wasm_enforce_bounds_checks) {
    // Explicit bounds checks requested via flag (for testing).
    memory->bounds_checks = kExplicitBoundsChecks;
  } else if (origin != kWasmOrigin) {
    // Asm.js modules can't use trap handling.
    memory->bounds_checks = kExplicitBoundsChecks;
  } else if (memory->is_memory64() && !v8_flags.wasm_memory64_trap_handling) {
    // Memory64 currently always requires explicit bounds checks.
    memory->bounds_checks = kExplicitBoundsChecks;
  } else if (trap_handler::IsTrapHandlerEnabled()) {
    if constexpr (kSystemPointerSize == 4) UNREACHABLE();
    memory->bounds_checks = kTrapHandler;
  } else {
    // If the trap handler is not enabled, fall back to explicit bounds checks.
    memory->bounds_checks = kExplicitBoundsChecks;
  }
}

// Static representation of a wasm literal stringref.
struct WasmStringRefLiteral {
  explicit WasmStringRefLiteral(const WireBytesRef& source) : source(source) {}
  WireBytesRef source;  // start offset in the module bytes.
};

// Static representation of a wasm data segment.
struct WasmDataSegment {
  explicit WasmDataSegment(bool is_active, bool is_shared,
                           uint32_t memory_index, ConstantExpression dest_addr,
                           WireBytesRef source)
      : active(is_active),
        shared(is_shared),
        memory_index(memory_index),
        dest_addr(dest_addr),
        source(source) {}

  static WasmDataSegment PassiveForTesting() {
    return WasmDataSegment{false, false, 0, {}, {}};
  }

  bool active = true;     // true if copied automatically during instantiation.
  bool shared = false;    // true if shared.
  uint32_t memory_index;  // memory index (if active).
  ConstantExpression dest_addr;  // destination memory address (if active).
  WireBytesRef source;           // start offset in the module bytes.
};

// Static representation of wasm element segment (table initializer).
struct WasmElemSegment {
  enum Status {
    kStatusActive,      // copied automatically during instantiation.
    kStatusPassive,     // copied explicitly after instantiation.
    kStatusDeclarative  // purely declarative and never copied.
  };
  enum ElementType { kFunctionIndexElements, kExpressionElements };

  // Construct an active segment.
  WasmElemSegment(bool shared, ValueType type, uint32_t table_index,
                  ConstantExpression offset, ElementType element_type,
                  uint32_t element_count, uint32_t elements_wire_bytes_offset)
      : status(kStatusActive),
        shared(shared),
        type(type),
        table_index(table_index),
        offset(std::move(offset)),
        element_type(element_type),
        element_count(element_count),
        elements_wire_bytes_offset(elements_wire_bytes_offset) {}

  // Construct a passive or declarative segment, which has no table index or
  // offset.
  WasmElemSegment(Status status, bool shared, ValueType type,
                  ElementType element_type, uint32_t element_count,
                  uint32_t elements_wire_bytes_offset)
      : status(status),
        shared(shared),
        type(type),
        table_index(0),
        element_type(element_type),
        element_count(element_count),
        elements_wire_bytes_offset(elements_wire_bytes_offset) {
    DCHECK_NE(status, kStatusActive);
  }

  // Default constructor. Constucts an invalid segment.
  WasmElemSegment()
      : status(kStatusActive),
        shared(false),
        type(kWasmBottom),
        table_index(0),
        element_type(kFunctionIndexElements),
        element_count(0),
        elements_wire_bytes_offset(0) {}

  WasmElemSegment(const WasmElemSegment&) = delete;
  WasmElemSegment(WasmElemSegment&&) V8_NOEXCEPT = default;
  WasmElemSegment& operator=(const WasmElemSegment&) = delete;
  WasmElemSegment& operator=(WasmElemSegment&&) V8_NOEXCEPT = default;

  Status status;
  bool shared;
  ValueType type;
  uint32_t table_index;
  ConstantExpression offset;
  ElementType element_type;
  uint32_t element_count;
  uint32_t elements_wire_bytes_offset;
};

// Static representation of a wasm import.
struct WasmImport {
  WireBytesRef module_name;   // module name.
  WireBytesRef field_name;    // import name.
  ImportExportKindCode kind;  // kind of the import.
  uint32_t index = 0;         // index into the respective space.
};

// Static representation of a wasm export.
struct WasmExport {
  WireBytesRef name;          // exported name.
  ImportExportKindCode kind;  // kind of the export.
  uint32_t index = 0;         // index into the respective space.
};

enum class WasmCompilationHintStrategy : uint8_t {
  kDefault = 0,
  kLazy = 1,
  kEager = 2,
  kLazyBaselineEagerTopTier = 3,
};

enum class WasmCompilationHintTier : uint8_t {
  kDefault = 0,
  kBaseline = 1,
  kOptimized = 2,
};

// Static representation of a wasm compilation hint
struct WasmCompilationHint {
  WasmCompilationHintStrategy strategy;
  WasmCompilationHintTier baseline_tier;
  WasmCompilationHintTier top_tier;
};

#define SELECT_WASM_COUNTER(counters, origin, prefix, suffix)     \
  ((origin) == kWasmOrigin ? (counters)->prefix##_wasm_##suffix() \
                           : (counters)->prefix##_asm_##suffix())

// Uses a map as backing storage when sparsely, or a vector when densely
// populated. Requires {Value} to implement `bool is_set()` to identify
// uninitialized objects.
template <class Value>
class AdaptiveMap {
 public:
  // The technical limitation here is that index+1 must not overflow. Since
  // we have significantly lower maximums on anything that can be named,
  // we can have a tighter limit here to reject useless entries early.
  static constexpr uint32_t kMaxKey = 10'000'000;
  static_assert(kMaxKey < std::numeric_limits<uint32_t>::max());

  AdaptiveMap() : map_(new MapType()) {}

  explicit AdaptiveMap(const AdaptiveMap&) = delete;
  AdaptiveMap& operator=(const AdaptiveMap&) = delete;

  AdaptiveMap(AdaptiveMap&& other) V8_NOEXCEPT { *this = std::move(other); }

  AdaptiveMap& operator=(AdaptiveMap&& other) V8_NOEXCEPT {
    mode_ = other.mode_;
    vector_.swap(other.vector_);
    map_.swap(other.map_);
    return *this;
  }

  void FinishInitialization();

  bool is_set() const { return mode_ != kInitializing; }

  void Put(uint32_t key, const Value& value) {
    DCHECK(mode_ == kInitializing);
    DCHECK_LE(key, kMaxKey);
    map_->insert(std::make_pair(key, value));
  }

  void Put(uint32_t key, Value&& value) {
    DCHECK(mode_ == kInitializing);
    DCHECK_LE(key, kMaxKey);
    map_->insert(std::make_pair(key, std::move(value)));
  }

  const Value* Get(uint32_t key) const {
    if (mode_ == kDense) {
      if (key >= vector_.size()) return nullptr;
      if (!vector_[key].is_set()) return nullptr;
      return &vector_[key];
    } else {
      DCHECK(mode_ == kSparse || mode_ == kInitializing);
      auto it = map_->find(key);
      if (it == map_->end()) return nullptr;
      return &it->second;
    }
  }

  bool Has(uint32_t key) const {
    if (mode_ == kDense) {
      return key < vector_.size() && vector_[key].is_set();
    } else {
      DCHECK(mode_ == kSparse || mode_ == kInitializing);
      return map_->find(key) != map_->end();
    }
  }

  size_t EstimateCurrentMemoryConsumption() const;

 private:
  static constexpr uint32_t kLoadFactor = 4;
  using MapType = std::map<uint32_t, Value>;
  enum Mode { kDense, kSparse, kInitializing };

  Mode mode_{kInitializing};
  std::vector<Value> vector_;
  std::unique_ptr<MapType> map_;
};
using NameMap = AdaptiveMap<WireBytesRef>;
using IndirectNameMap = AdaptiveMap<AdaptiveMap<WireBytesRef>>;

struct ModuleWireBytes;

class V8_EXPORT_PRIVATE LazilyGeneratedNames {
 public:
  WireBytesRef LookupFunctionName(ModuleWireBytes wire_bytes,
                                  uint32_t function_index);

  void AddForTesting(int function_index, WireBytesRef name);
  bool Has(uint32_t function_index);

  size_t EstimateCurrentMemoryConsumption() const;

 private:
  // Lazy loading must guard against concurrent modifications from multiple
  // {WasmModuleObject}s.
  mutable base::Mutex mutex_;
  bool has_functions_{false};
  NameMap function_names_;
};

class V8_EXPORT_PRIVATE AsmJsOffsetInformation {
 public:
  explicit AsmJsOffsetInformation(base::Vector<const uint8_t> encoded_offsets);

  // Destructor defined in wasm-module.cc, where the definition of
  // {AsmJsOffsets} is available.
  ~AsmJsOffsetInformation();

  int GetSourcePosition(int func_index, int byte_offset,
                        bool is_at_number_conversion);

  std::pair<int, int> GetFunctionOffsets(int func_index);

 private:
  void EnsureDecodedOffsets();

  // The offset information table is decoded lazily, hence needs to be
  // protected against concurrent accesses.
  // Exactly one of the two fields below will be set at a time.
  mutable base::Mutex mutex_;

  // Holds the encoded offset table bytes.
  base::OwnedVector<const uint8_t> encoded_offsets_;

  // Holds the decoded offset table.
  std::unique_ptr<AsmJsOffsets> decoded_offsets_;
};

// Used as the supertype for a type at the top of the type hierarchy.
constexpr ModuleTypeIndex kNoSuperType = ModuleTypeIndex::Invalid();

struct TypeDefinition {
  enum Kind : int8_t { kFunction, kStruct, kArray };

  constexpr TypeDefinition(const FunctionSig* sig, ModuleTypeIndex supertype,
                           bool is_final, bool is_shared)
      : function_sig(sig),
        supertype{supertype},
        kind(kFunction),
        is_final(is_final),
        is_shared(is_shared) {}

  constexpr TypeDefinition(const StructType* type, ModuleTypeIndex supertype,
                           bool is_final, bool is_shared)
      : struct_type(type),
        supertype{supertype},
        kind(kStruct),
        is_final(is_final),
        is_shared(is_shared) {}

  constexpr TypeDefinition(const ArrayType* type, ModuleTypeIndex supertype,
                           bool is_final, bool is_shared)
      : array_type(type),
        supertype{supertype},
        kind(kArray),
        is_final(is_final),
        is_shared(is_shared) {}
  constexpr TypeDefinition() = default;

  bool operator==(const TypeDefinition& other) const {
    if (supertype != other.supertype) return false;
    if (kind != other.kind) return false;
    if (is_final != other.is_final) return false;
    if (is_shared != other.is_shared) return false;
    if (kind == kFunction) return *function_sig == *other.function_sig;
    if (kind == kStruct) return *struct_type == *other.struct_type;
    DCHECK_EQ(kArray, kind);
    return *array_type == *other.array_type;
  }

  bool operator!=(const TypeDefinition& other) const {
    return !(*this == other);
  }

  union {
    const FunctionSig* function_sig = nullptr;
    const StructType* struct_type;
    const ArrayType* array_type;
  };
  ModuleTypeIndex supertype{kNoSuperType};
  Kind kind = kFunction;
  bool is_final = false;
  bool is_shared = false;
  uint8_t subtyping_depth = 0;
};

struct V8_EXPORT_PRIVATE WasmDebugSymbols {
  static constexpr int kNumTypes = 3;
  enum Type { SourceMap, EmbeddedDWARF, ExternalDWARF, None };
  Type type = Type::None;
  WireBytesRef external_url;
};

class CallSiteFeedback {
 public:
  struct PolymorphicCase {
    int function_index;
    int absolute_call_frequency;
  };

  // Regular constructor: uninitialized/unknown, monomorphic, or polymorphic.
  CallSiteFeedback() : index_or_count_(-1), frequency_or_ool_(0) {}
  CallSiteFeedback(int function_index, int call_count)
      : index_or_count_(function_index), frequency_or_ool_(call_count) {}
  CallSiteFeedback(PolymorphicCase* polymorphic_cases, int num_cases)
      : index_or_count_(-num_cases),
        frequency_or_ool_(reinterpret_cast<intptr_t>(polymorphic_cases)) {}

  // Copying and assignment: prefer moving, as it's cheaper.
  // The code below makes sure external polymorphic storage is copied and/or
  // freed as appropriate.
  CallSiteFeedback(const CallSiteFeedback& other) V8_NOEXCEPT { *this = other; }
  CallSiteFeedback(CallSiteFeedback&& other) V8_NOEXCEPT { *this = other; }
  CallSiteFeedback& operator=(const CallSiteFeedback& other) V8_NOEXCEPT {
    index_or_count_ = other.index_or_count_;
    if (other.is_polymorphic()) {
      int num_cases = other.num_cases();
      PolymorphicCase* polymorphic = new PolymorphicCase[num_cases];
      for (int i = 0; i < num_cases; i++) {
        polymorphic[i].function_index = other.function_index(i);
        polymorphic[i].absolute_call_frequency = other.call_count(i);
      }
      frequency_or_ool_ = reinterpret_cast<intptr_t>(polymorphic);
    } else {
      frequency_or_ool_ = other.frequency_or_ool_;
    }
    return *this;
  }
  CallSiteFeedback& operator=(CallSiteFeedback&& other) V8_NOEXCEPT {
    if (this != &other) {
      index_or_count_ = other.index_or_count_;
      frequency_or_ool_ = other.frequency_or_ool_;
      other.frequency_or_ool_ = 0;
    }
    return *this;
  }

  ~CallSiteFeedback() {
    if (is_polymorphic()) delete[] polymorphic_storage();
  }

  int num_cases() const {
    if (is_monomorphic()) return 1;
    if (is_invalid()) return 0;
    return -index_or_count_;
  }
  int function_index(int i) const {
    DCHECK(!is_invalid());
    if (is_monomorphic()) return index_or_count_;
    return polymorphic_storage()[i].function_index;
  }
  int call_count(int i) const {
    if (index_or_count_ >= 0) return static_cast<int>(frequency_or_ool_);
    return polymorphic_storage()[i].absolute_call_frequency;
  }
  bool has_non_inlineable_targets() const {
    return has_non_inlineable_targets_;
  }
  void set_has_non_inlineable_targets(bool has_non_inlineable_targets) {
    has_non_inlineable_targets_ = has_non_inlineable_targets;
  }

 private:
  bool is_monomorphic() const { return index_or_count_ >= 0; }
  bool is_polymorphic() const { return index_or_count_ <= -2; }
  bool is_invalid() const { return index_or_count_ == -1; }
  const PolymorphicCase* polymorphic_storage() const {
    DCHECK(is_polymorphic());
    return reinterpret_cast<PolymorphicCase*>(frequency_or_ool_);
  }

  int index_or_count_;
  bool has_non_inlineable_targets_ = false;
  intptr_t frequency_or_ool_;
};

struct FunctionTypeFeedback {
  // {feedback_vector} is computed from {call_targets} and the instance-specific
  // feedback vector by {TransitiveTypeFeedbackProcessor}.
  std::vector<CallSiteFeedback> feedback_vector;

  // {call_targets} has one entry per "call", "call_indirect", and "call_ref" in
  // the function.
  // For "call", it holds the index of the called function, for "call_indirect"
  // and "call_ref" the value will be a sentinel {kCallIndirect} / {kCallRef}.
  base::OwnedVector<uint32_t> call_targets;

  // {tierup_priority} is updated and used when triggering tier-up.
  // TODO(clemensb): This does not belong here; find a better place.
  int tierup_priority = 0;

  static constexpr uint32_t kUninitializedLiftoffFrameSize = 1;
  // The size of the stack frame in liftoff in bytes.
  uint32_t liftoff_frame_size : 31 = kUninitializedLiftoffFrameSize;
  // Flag whether the cached {feedback_vector} has to be reprocessed as the data
  // is outdated (signaled by a deopt).
  // This is set by the deoptimizer, so that the next tierup trigger performs
  // the reprocessing. The deoptimizer can't update the cached data, as the new
  // feedback (which caused the deopt) hasn't been processed yet and processing
  // it can trigger allocations. After returning to liftoff, the feedback is
  // updated (which is guaranteed to happen before the next tierup trigger).
  bool needs_reprocessing_after_deopt : 1 = false;

  static constexpr uint32_t kCallRef = 0xFFFFFFFF;
  static constexpr uint32_t kCallIndirect = kCallRef - 1;
  static_assert(kV8MaxWasmTotalFunctions < kCallIndirect);
};

struct TypeFeedbackStorage {
  std::unordered_map<uint32_t, FunctionTypeFeedback> feedback_for_function;
  std::unordered_map<uint32_t, uint32_t> deopt_count_for_function;
  // Accesses to {feedback_for_function} and {deopt_count_for_function} are
  // guarded by this mutex. Multiple reads are allowed (shared lock), but only
  // exclusive writes. Currently known users of the mutex are:
  // - LiftoffCompiler: writes {call_targets}.
  // - TransitiveTypeFeedbackProcessor: reads {call_targets},
  //   writes {feedback_vector}, reads {feedback_vector.size()}.
  // - TriggerTierUp: increments {tierup_priority}.
  // - WasmGraphBuilder: reads {feedback_vector}.
  // - Feedback vector allocation: reads {call_targets.size()}.
  // - PGO ProfileGenerator: reads everything.
  // - PGO deserializer: writes everything, currently not locked, relies on
  //   being called before multi-threading enters the picture.
  // - Deoptimizer: sets needs_reprocessing_after_deopt.
  mutable base::SharedMutex mutex;

  WellKnownImportsList well_known_imports;

  size_t EstimateCurrentMemoryConsumption() const;
};

struct WasmTable {
  ValueType type = kWasmVoid;
  uint32_t initial_size = 0;
  // The declared maximum size; at runtime the actual size is limited to a
  // 32-bit value (kV8MaxWasmTableSize).
  uint64_t maximum_size = 0;
  bool has_maximum_size = false;
  AddressType address_type = AddressType::kI32;
  bool shared = false;
  bool imported = false;
  bool exported = false;
  ConstantExpression initial_value = {};

  bool is_table64() const { return address_type == AddressType::kI64; }
};

// Static representation of a module.
struct V8_EXPORT_PRIVATE WasmModule {
  // ================ Fields ===================================================
  // The signature zone is also used to store the signatures of C++ functions
  // called with the V8 fast API. These signatures are added during
  // instantiation, so the `signature_zone` may be changed even when the
  // `WasmModule` is already `const`.
  mutable Zone signature_zone;
  int start_function_index = -1;   // start function, >= 0 if any

  // Size of the buffer required for all globals that are not imported and
  // mutable.
  uint32_t untagged_globals_buffer_size = 0;
  uint32_t tagged_globals_buffer_size = 0;
  uint32_t num_imported_globals = 0;
  uint32_t num_imported_mutable_globals = 0;
  uint32_t num_imported_functions = 0;
  uint32_t num_imported_tables = 0;
  uint32_t num_imported_tags = 0;
  uint32_t num_declared_functions = 0;  // excluding imported
  // This field is updated when decoding the functions. At this point in time
  // with streaming compilation there can already be background threads running
  // turbofan compilations which will read this to decide on inlining budgets.
  // This can only happen with eager compilation as code execution only starts
  // after the module has been fully decoded and therefore it does not affect
  // production configurations.
  std::atomic<uint32_t> num_small_functions = 0;
  uint32_t num_exported_functions = 0;
  uint32_t num_declared_data_segments = 0;  // From the DataCount section.
  // Position and size of the code section (payload only, i.e. without section
  // ID and length).
  WireBytesRef code = {0, 0};
  WireBytesRef name = {0, 0};
  // Position and size of the name section (payload only, i.e. without section
  // ID and length).
  WireBytesRef name_section = {0, 0};
  // Set to true if this module has wasm-gc types in its type section.
  bool is_wasm_gc = false;
  // Set to true if this module has any shared elements other than memories.
  bool has_shared_part = false;

  std::vector<TypeDefinition> types;  // by type index
  // Maps each type index to its global (cross-module) canonical index as per
  // isorecursive type canonicalization.
  std::vector<CanonicalTypeIndex> isorecursive_canonical_type_ids;
  std::vector<WasmFunction> functions;
  std::vector<WasmGlobal> globals;
  std::vector<WasmDataSegment> data_segments;
  std::vector<WasmTable> tables;
  std::vector<WasmMemory> memories;
  std::vector<WasmImport> import_table;
  std::vector<WasmExport> export_table;
  std::vector<WasmTag> tags;
  std::vector<WasmStringRefLiteral> stringref_literals;
  std::vector<WasmElemSegment> elem_segments;
  std::vector<WasmCompilationHint> compilation_hints;
  BranchHintInfo branch_hints;
  // Pairs of module offsets and mark id.
  std::vector<std::pair<uint32_t, uint32_t>> inst_traces;

  // This is the only member of {WasmModule} where we store dynamic information
  // that's not a decoded representation of the wire bytes.
  // TODO(jkummerow): Rename.
  mutable TypeFeedbackStorage type_feedback;

  const ModuleOrigin origin;
  mutable LazilyGeneratedNames lazily_generated_names;
  std::array<WasmDebugSymbols, WasmDebugSymbols::kNumTypes> debug_symbols{};

  // Asm.js source position information. Only available for modules compiled
  // from asm.js.
  std::unique_ptr<AsmJsOffsetInformation> asm_js_offset_information;

  // {validated_functions} is atomically updated when functions get validated
  // (during compilation, streaming decoding, or via explicit validation).
  static_assert(sizeof(std::atomic<uint8_t>) == 1);
  static_assert(alignof(std::atomic<uint8_t>) == 1);
  mutable std::unique_ptr<std::atomic<uint8_t>[]> validated_functions;

  // ================ Constructors =============================================
  explicit WasmModule(ModuleOrigin = kWasmOrigin);
  WasmModule(const WasmModule&) = delete;
  WasmModule& operator=(const WasmModule&) = delete;

  // ================ Interface for tests ======================================
  // Tests sometimes add times iteratively instead of all at once via module
  // decoding.
  void AddTypeForTesting(TypeDefinition type) {
    types.push_back(type);
    if (type.supertype.valid()) {
      // Set the subtyping depth. Outside of unit tests this is done by the
      // module decoder.
      DCHECK_GT(types.size(), 0);
      DCHECK_LT(type.supertype.index, types.size() - 1);
      types.back().subtyping_depth =
          this->type(type.supertype).subtyping_depth + 1;
    }
    // Isorecursive canonical type will be computed later.
    isorecursive_canonical_type_ids.push_back(CanonicalTypeIndex{kNoSuperType});
  }

  void AddSignatureForTesting(const FunctionSig* sig, ModuleTypeIndex supertype,
                              bool is_final, bool is_shared) {
    DCHECK_NOT_NULL(sig);
    AddTypeForTesting(TypeDefinition(sig, supertype, is_final, is_shared));
  }

  void AddStructTypeForTesting(const StructType* type,
                               ModuleTypeIndex supertype, bool is_final,
                               bool is_shared) {
    DCHECK_NOT_NULL(type);
    AddTypeForTesting(TypeDefinition(type, supertype, is_final, is_shared));
  }

  void AddArrayTypeForTesting(const ArrayType* type, ModuleTypeIndex supertype,
                              bool is_final, bool is_shared) {
    DCHECK_NOT_NULL(type);
    AddTypeForTesting(TypeDefinition(type, supertype, is_final, is_shared));
  }

  // ================ Accessors ================================================
  bool has_type(ModuleTypeIndex index) const {
    return index.index < types.size();
  }

  TypeDefinition type(ModuleTypeIndex index) const {
    size_t num_types = types.size();
    V8_ASSUME(index.index < num_types);
    return types[index.index];
  }

  CanonicalTypeIndex canonical_type_id(ModuleTypeIndex index) const {
    size_t num_types = isorecursive_canonical_type_ids.size();
    V8_ASSUME(index.index < num_types);
    return isorecursive_canonical_type_ids[index.index];
  }

  bool has_signature(ModuleTypeIndex index) const {
    return index.index < types.size() &&
           types[index.index].kind == TypeDefinition::kFunction;
  }
  const FunctionSig* signature(ModuleTypeIndex index) const {
    DCHECK(has_signature(index));
    size_t num_types = types.size();
    V8_ASSUME(index.index < num_types);
    return types[index.index].function_sig;
  }

  CanonicalTypeIndex canonical_sig_id(ModuleTypeIndex index) const {
    DCHECK(has_signature(index));
    size_t num_types = isorecursive_canonical_type_ids.size();
    V8_ASSUME(index.index < num_types);
    return isorecursive_canonical_type_ids[index.index];
  }

  bool has_struct(ModuleTypeIndex index) const {
    return index.index < types.size() &&
           types[index.index].kind == TypeDefinition::kStruct;
  }

  const StructType* struct_type(ModuleTypeIndex index) const {
    DCHECK(has_struct(index));
    size_t num_types = types.size();
    V8_ASSUME(index.index < num_types);
    return types[index.index].struct_type;
  }

  bool has_array(ModuleTypeIndex index) const {
    return index.index < types.size() &&
           types[index.index].kind == TypeDefinition::kArray;
  }
  const ArrayType* array_type(ModuleTypeIndex index) const {
    DCHECK(has_array(index));
    size_t num_types = types.size();
    V8_ASSUME(index.index < num_types);
    return types[index.index].array_type;
  }

  ModuleTypeIndex supertype(ModuleTypeIndex index) const {
    size_t num_types = types.size();
    V8_ASSUME(index.index < num_types);
    return types[index.index].supertype;
  }
  bool has_supertype(ModuleTypeIndex index) const {
    return supertype(index).valid();
  }

  // Linear search. Returns CanonicalTypeIndex::Invalid() if types are empty.
  CanonicalTypeIndex MaxCanonicalTypeIndex() const {
    if (isorecursive_canonical_type_ids.empty()) {
      return CanonicalTypeIndex::Invalid();
    }
    return *std::max_element(isorecursive_canonical_type_ids.begin(),
                             isorecursive_canonical_type_ids.end());
  }

  bool function_is_shared(int func_index) const {
    return type(functions[func_index].sig_index).is_shared;
  }

  bool function_was_validated(int func_index) const {
    DCHECK_NOT_NULL(validated_functions);
    static_assert(sizeof(validated_functions[0]) == 1);
    DCHECK_LE(num_imported_functions, func_index);
    int pos = func_index - num_imported_functions;
    DCHECK_LE(pos, num_declared_functions);
    uint8_t byte =
        validated_functions[pos >> 3].load(std::memory_order_relaxed);
    DCHECK_IMPLIES(origin != kWasmOrigin, byte == 0xff);
    return byte & (1 << (pos & 7));
  }

  void set_function_validated(int func_index) const {
    DCHECK_EQ(kWasmOrigin, origin);
    DCHECK_NOT_NULL(validated_functions);
    DCHECK_LE(num_imported_functions, func_index);
    int pos = func_index - num_imported_functions;
    DCHECK_LE(pos, num_declared_functions);
    std::atomic<uint8_t>* atomic_byte = &validated_functions[pos >> 3];
    uint8_t old_byte = atomic_byte->load(std::memory_order_relaxed);
    uint8_t new_bit = 1 << (pos & 7);
    while ((old_byte & new_bit) == 0 &&
           !atomic_byte->compare_exchange_weak(old_byte, old_byte | new_bit,
                                               std::memory_order_relaxed)) {
      // Retry with updated {old_byte}.
    }
  }

  void set_all_functions_validated() const {
    DCHECK_EQ(kWasmOrigin, origin);
    if (num_declared_functions == 0) return;
    DCHECK_NOT_NULL(validated_functions);
    size_t num_words = (nu
"""


```