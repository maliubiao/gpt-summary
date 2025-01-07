Response:
Let's break down the thought process to analyze the provided C++ code snippet and fulfill the user's request.

**1. Understanding the Goal:**

The user wants to understand the purpose of the `v8/src/compiler/machine-operator.cc` file in V8. They've also provided specific instructions regarding file extensions, JavaScript relevance, logical reasoning, common errors, and a final summary for this first part.

**2. Initial Code Scan & Keyword Identification:**

I immediately scanned the code for prominent keywords and patterns. I noticed:

* **Headers:** `#include`, indicating dependencies on other V8 components.
* **Namespaces:** `v8::internal::compiler`, clearly placing this code within the V8 compiler.
* **Operators:** Overloaded operators like `==`, `!=`, `<<`, `hash_value`. This suggests the code is defining how certain data structures are compared, hashed, and printed.
* **Structures/Classes:** `StoreRepresentation`, `AtomicStoreParameters`, `AtomicLoadParameters`, `AtomicOpParameters`, `MemoryAccessKind`, `LoadTransformation`, `LoadTransformParameters`, `LoadLaneParameters`, `StoreLaneParameters`, `StackSlotRepresentation`, `ShiftKind`, `TruncateKind`. These are likely key data structures used in the compiler's machine code generation phase.
* **Enums/Enum-like structures:** `MemoryAccessKind`, `LoadTransformation`, `ShiftKind`, `TruncateKind`.
* **Macros:** `PURE_BINARY_OP_LIST_32`, `PURE_BINARY_OP_LIST_64`, `PURE_SIMD_OP_LIST`. These suggest lists of related operations.
* **`DCHECK`:**  These are debug assertions, indicating assumptions made within the code.
* **`UNREACHABLE()`:** This signifies a code path that should never be executed, often in `switch` statements for exhaustive enums.
* **`V8_ENABLE_WEBASSEMBLY` and `IF_WASM`:**  Conditional compilation related to WebAssembly.

**3. Inferring Functionality - First Pass:**

Based on the keywords, I formed an initial hypothesis:

* This file seems to define data structures and related operations that represent machine-level operations within the V8 compiler.
* The "Machine Operator" name is a strong clue. It likely deals with how higher-level code is translated into instructions for the target machine.
* The presence of "Store," "Load," "Atomic," "Shift," and "Truncate" hints at memory access and low-level arithmetic/logical operations.
* The SIMD lists further point to support for Single Instruction, Multiple Data operations, often used for performance.

**4. Addressing Specific Instructions:**

* **File Extension:** The user explicitly mentioned `.tq`. The current file is `.cc`. Therefore, it's *not* a Torque file. This is a straightforward check.

* **JavaScript Relevance:**  Machine-level operations are indirectly related to JavaScript. JavaScript code eventually gets compiled down to machine code. The operations defined here are part of that translation process. To illustrate, I thought about basic arithmetic operations in JavaScript and how they would map to machine instructions (e.g., `+` to `Int32Add`, `*` to `Int32Mul`). Memory access is also crucial (e.g., accessing object properties). This led to the example of `let x = a + b;`.

* **Logical Reasoning (Hypothetical Input/Output):**  The code primarily defines data structures and comparisons. Direct input/output in the sense of a function call isn't the main purpose. However, I could reason about *how* these structures would be used. For example, if a compiler needs to represent a "store integer to memory," it would use `StoreRepresentation` with the appropriate type. If it's an atomic store, `AtomicStoreParameters` would be used. The input would be the *need* to represent such an operation, and the output would be a correctly configured data structure. I considered the example of storing an integer and the need for a write barrier for objects.

* **Common Programming Errors:**  I thought about scenarios where developers might misuse or misunderstand low-level concepts. Data type mismatches, incorrect memory alignment, and race conditions with atomic operations came to mind. The unaligned access and atomic operation examples were direct results of this thinking.

**5. Refining the Understanding:**

After the initial pass and addressing the specific instructions, I refined my understanding:

* The file is about *representing* machine operations, not *executing* them directly.
* The overloaded operators are essential for comparing and storing these representations efficiently (e.g., in sets or maps within the compiler).
* The parameters (like `StoreRepresentation`, `AtomicLoadParameters`) encapsulate the details of each machine operation (data type, memory access characteristics, atomicity, etc.).
* The macros provide a concise way to define groups of related operators with shared characteristics.

**6. Structuring the Answer:**

Finally, I structured the answer to address each of the user's points systematically:

* Start with a concise summary of the file's purpose.
* Address the `.tq` file extension.
* Explain the JavaScript relationship with a concrete example.
* Provide the hypothetical input/output for logical reasoning.
* Give examples of common programming errors.
* Conclude with a summary of the file's functionality based on the analysis.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the *execution* of these operations. I corrected myself to emphasize that this file is about *representation*.
* I made sure to connect the abstract concepts (like `StoreRepresentation`) to more concrete programming concepts (like storing a variable).
* I double-checked that my JavaScript examples were relevant and easy to understand.

By following this process of scanning, hypothesizing, addressing specific instructions, refining understanding, and structuring the answer, I was able to produce a comprehensive response to the user's request.
这是对 v8 源代码文件 `v8/src/compiler/machine-operator.cc` 的第一部分分析。

**功能归纳：**

该文件定义了用于表示底层机器操作的数据结构和相关辅助函数。它不是 V8 Torque 源代码，因为它以 `.cc` 结尾。该文件是 V8 编译器中负责将高级语言（如 JavaScript）翻译成机器码的关键部分。它定义了各种机器操作的参数和属性，例如加载、存储、原子操作、位运算和 SIMD 操作等。

**详细功能点：**

1. **定义机器操作的参数结构体：**
   - `StoreRepresentation`: 表示存储操作的类型（例如，存储一个字节、一个整数、一个浮点数）以及是否需要写屏障（用于垃圾回收）。
   - `AtomicStoreParameters`: 表示原子存储操作的参数，包括存储表示、内存顺序和访问类型。
   - `AtomicLoadParameters`: 表示原子加载操作的参数，包括数据表示、内存顺序和访问类型。
   - `AtomicOpParameters`: 表示原子算术/逻辑操作的参数，包括操作类型和访问类型。
   - `MemoryAccessKind`: 表示内存访问的类型，例如正常访问、非对齐访问或受陷阱处理程序保护的访问。
   - `LoadTransformation`: 表示加载操作的转换，主要用于 SIMD 指令中的数据重排和扩展。
   - `LoadTransformParameters`: 包含内存访问类型和加载转换类型的参数结构体。
   - `LoadLaneParameters`: 用于 SIMD 加载通道操作的参数，包括内存访问类型、数据表示和通道索引。
   - `StoreLaneParameters`: 用于 SIMD 存储通道操作的参数，包括内存访问类型、数据表示和通道索引。
   - `StackSlotRepresentation`: 表示栈槽的尺寸和对齐方式。
   - `ShiftKind`: 表示移位操作的类型，例如普通移位或移出零的移位。
   - `TruncateKind`: 表示截断操作的类型。

2. **提供操作符重载：**
   - 提供了 `==`, `!=`, `hash_value`, `<<` 等操作符的重载，用于比较、哈希和打印上述参数结构体，方便在编译器内部使用和调试。

3. **提供访问参数的辅助函数：**
   - 提供了诸如 `LoadRepresentationOf`, `AtomicLoadParametersOf`, `StoreRepresentationOf` 等函数，用于从 `Operator` 对象中提取特定的参数结构体。`Operator` 是 V8 编译器中表示操作的基类。

4. **定义机器操作的枚举：**
   - 通过宏 `PURE_BINARY_OP_LIST_32`, `PURE_BINARY_OP_LIST_64`, `PURE_SIMD_OP_LIST` 定义了各种 32 位、64 位和 SIMD 的二元操作，例如按位与、按位或、加法、减法、乘法等等。这些宏展开后会定义对应的 `IrOpcode`（中间表示操作码）。

**关于 V8 Torque 源代码：**

根据代码内容，`v8/src/compiler/machine-operator.cc` 不是以 `.tq` 结尾，因此它不是 V8 Torque 源代码。Torque 是一种用于定义 V8 内置函数和优化的领域特定语言。`.cc` 文件通常包含 C++ 代码。

**与 JavaScript 功能的关系及 JavaScript 示例：**

`v8/src/compiler/machine-operator.cc` 中定义的操作直接对应于 CPU 可以执行的指令。当 V8 编译 JavaScript 代码时，会将 JavaScript 的各种操作转换为这些底层的机器操作。

例如：

```javascript
let a = 10;
let b = 5;
let sum = a + b; // JavaScript 的加法操作
```

在 V8 的编译过程中，`a + b` 这个 JavaScript 的加法操作可能会被转换为 `machine-operator.cc` 中定义的 `Int32Add` (如果 `a` 和 `b` 可以被推断为 32 位整数) 或者其他类似的加法操作。

又例如，访问对象的属性：

```javascript
const obj = { x: 1 };
let value = obj.x; // JavaScript 的属性访问
```

这个属性访问可能会被转换为 `LoadRepresentationOf` 返回的加载操作，具体加载的类型取决于属性 `x` 的类型。如果 `x` 是一个数字，可能会对应加载一个整数或浮点数。

**代码逻辑推理及假设输入输出：**

这个文件主要是定义数据结构和辅助函数，而不是实现具体的算法逻辑。因此，直接给出假设输入输出进行代码逻辑推理不太适用。不过，可以考虑一下这些数据结构在编译器中的使用场景：

**假设输入：** 编译器需要表示一个将 32 位整数值存储到内存地址 `ptr` 的操作，并且这个存储操作需要写屏障（例如，存储的是一个对象引用）。

**推断输出：** 编译器会创建一个 `Operator` 对象，其操作码为 `IrOpcode::kStore`，并附带一个 `StoreRepresentation` 参数，该参数的 `representation()` 成员将是表示 32 位整数的类型，`write_barrier_kind()` 成员将是表示需要写屏障的类型。

**涉及用户常见的编程错误：**

虽然这个文件本身不直接涉及用户的 JavaScript 代码，但其中定义的概念与一些常见的编程错误相关：

1. **数据类型不匹配：** 在 JavaScript 中，类型是动态的，但在底层编译时，需要明确数据类型。如果 JavaScript 代码中存在类型不一致的情况，例如尝试将一个字符串当做数字进行位运算，编译器可能会生成一些类型转换或错误处理的代码。

   ```javascript
   let x = 10;
   let y = "5";
   let result = x & y; // 位运算，但 y 是字符串
   ```
   V8 的编译过程需要处理 `y` 的类型，可能会将其转换为数字，这可能导致非预期的结果。

2. **内存对齐问题：**  `MemoryAccessKind::kUnaligned`  表明 V8 需要处理非对齐的内存访问。在某些硬件架构上，非对齐的内存访问会导致性能下降甚至程序崩溃。用户虽然不需要直接处理，但了解这个概念有助于理解为什么某些操作可能比其他操作更慢。

3. **原子操作的误用：** 原子操作用于多线程编程中保证数据一致性。如果用户在不需要原子操作的场景下使用了它，可能会导致不必要的性能损失。反之，在需要原子操作的场景下没有使用，可能会导致数据竞争。

**总结（针对第 1 部分）：**

`v8/src/compiler/machine-operator.cc` 的第 1 部分主要负责定义 V8 编译器中用于描述底层机器操作的各种数据结构（如 `StoreRepresentation`, `AtomicLoadParameters` 等）和辅助函数。这些结构体封装了机器操作的类型、参数和属性，为编译器的后续阶段（如指令选择和代码生成）提供了必要的信息。它定义了基本的数据类型和操作，是 V8 将 JavaScript 代码转换为高效机器码的基础。该文件不是 Torque 源代码，而是标准的 C++ 代码。 其中定义的操作与 JavaScript 的各种功能息息相关，因为最终 JavaScript 的执行依赖于这些底层的机器指令。

Prompt: 
```
这是目录为v8/src/compiler/machine-operator.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/machine-operator.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2014 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/machine-operator.h"

#include <optional>

#include "src/base/lazy-instance.h"
#include "src/compiler/opcodes.h"
#include "src/compiler/operator.h"

namespace v8 {
namespace internal {
namespace compiler {

bool operator==(StoreRepresentation lhs, StoreRepresentation rhs) {
  return lhs.representation() == rhs.representation() &&
         lhs.write_barrier_kind() == rhs.write_barrier_kind();
}


bool operator!=(StoreRepresentation lhs, StoreRepresentation rhs) {
  return !(lhs == rhs);
}


size_t hash_value(StoreRepresentation rep) {
  return base::hash_combine(rep.representation(), rep.write_barrier_kind());
}


std::ostream& operator<<(std::ostream& os, StoreRepresentation rep) {
  return os << rep.representation() << ", " << rep.write_barrier_kind();
}

bool operator==(AtomicStoreParameters lhs, AtomicStoreParameters rhs) {
  return lhs.store_representation() == rhs.store_representation() &&
         lhs.order() == rhs.order() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicStoreParameters lhs, AtomicStoreParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicStoreParameters params) {
  return base::hash_combine(hash_value(params.store_representation()),
                            params.order(), params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicStoreParameters params) {
  return os << params.store_representation() << ", " << params.order();
}

bool operator==(AtomicLoadParameters lhs, AtomicLoadParameters rhs) {
  return lhs.representation() == rhs.representation() &&
         lhs.order() == rhs.order() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicLoadParameters lhs, AtomicLoadParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicLoadParameters params) {
  return base::hash_combine(params.representation(), params.order(),
                            params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicLoadParameters params) {
  return os << params.representation() << ", " << params.order();
}

bool operator==(AtomicOpParameters lhs, AtomicOpParameters rhs) {
  return lhs.type() == rhs.type() && lhs.kind() == rhs.kind();
}

bool operator!=(AtomicOpParameters lhs, AtomicOpParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(AtomicOpParameters params) {
  return base::hash_combine(params.type(), params.kind());
}

std::ostream& operator<<(std::ostream& os, AtomicOpParameters params) {
  return os << params.type() << ", " << params.kind();
}

size_t hash_value(MemoryAccessKind kind) { return static_cast<size_t>(kind); }

std::ostream& operator<<(std::ostream& os, MemoryAccessKind kind) {
  switch (kind) {
    case MemoryAccessKind::kNormal:
      return os << "kNormal";
    case MemoryAccessKind::kUnaligned:
      return os << "kUnaligned";
    case MemoryAccessKind::kProtectedByTrapHandler:
      return os << "kProtected";
  }
  UNREACHABLE();
}

size_t hash_value(LoadTransformation rep) { return static_cast<size_t>(rep); }

std::ostream& operator<<(std::ostream& os, LoadTransformation rep) {
  switch (rep) {
    case LoadTransformation::kS128Load8Splat:
      return os << "kS128Load8Splat";
    case LoadTransformation::kS128Load16Splat:
      return os << "kS128Load16Splat";
    case LoadTransformation::kS128Load32Splat:
      return os << "kS128Load32Splat";
    case LoadTransformation::kS128Load64Splat:
      return os << "kS128Load64Splat";
    case LoadTransformation::kS128Load8x8S:
      return os << "kS128Load8x8S";
    case LoadTransformation::kS128Load8x8U:
      return os << "kS128Load8x8U";
    case LoadTransformation::kS128Load16x4S:
      return os << "kS128Load16x4S";
    case LoadTransformation::kS128Load16x4U:
      return os << "kS128Load16x4U";
    case LoadTransformation::kS128Load32x2S:
      return os << "kS128Load32x2S";
    case LoadTransformation::kS128Load32x2U:
      return os << "kS128Load32x2U";
    case LoadTransformation::kS128Load32Zero:
      return os << "kS128Load32Zero";
    case LoadTransformation::kS128Load64Zero:
      return os << "kS128Load64Zero";
    // Simd256
    case LoadTransformation::kS256Load8Splat:
      return os << "kS256Load8Splat";
    case LoadTransformation::kS256Load16Splat:
      return os << "kS256Load16Splat";
    case LoadTransformation::kS256Load32Splat:
      return os << "kS256Load32Splat";
    case LoadTransformation::kS256Load64Splat:
      return os << "kS256Load64Splat";
    case LoadTransformation::kS256Load8x16S:
      return os << "kS256Load8x16S";
    case LoadTransformation::kS256Load8x16U:
      return os << "kS256Load8x16U";
    case LoadTransformation::kS256Load8x8U:
      return os << "kS256Load8x8U";
    case LoadTransformation::kS256Load16x8S:
      return os << "kS256Load16x8S";
    case LoadTransformation::kS256Load16x8U:
      return os << "kS256Load16x8U";
    case LoadTransformation::kS256Load32x4S:
      return os << "kS256Load32x4S";
    case LoadTransformation::kS256Load32x4U:
      return os << "kS256Load32x4U";
  }
  UNREACHABLE();
}

size_t hash_value(LoadTransformParameters params) {
  return base::hash_combine(params.kind, params.transformation);
}

std::ostream& operator<<(std::ostream& os, LoadTransformParameters params) {
  return os << "(" << params.kind << " " << params.transformation << ")";
}

#if V8_ENABLE_WEBASSEMBLY
LoadTransformParameters const& LoadTransformParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kLoadTransform, op->opcode());
  return OpParameter<LoadTransformParameters>(op);
}

bool operator==(LoadTransformParameters lhs, LoadTransformParameters rhs) {
  return lhs.transformation == rhs.transformation && lhs.kind == rhs.kind;
}

bool operator!=(LoadTransformParameters lhs, LoadTransformParameters rhs) {
  return !(lhs == rhs);
}

size_t hash_value(LoadLaneParameters params) {
  return base::hash_combine(params.kind, params.rep, params.laneidx);
}

std::ostream& operator<<(std::ostream& os, LoadLaneParameters params) {
  return os << "(" << params.kind << " " << params.rep << " "
            << static_cast<uint32_t>(params.laneidx) << ")";
}

LoadLaneParameters const& LoadLaneParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kLoadLane, op->opcode());
  return OpParameter<LoadLaneParameters>(op);
}

bool operator==(LoadLaneParameters lhs, LoadLaneParameters rhs) {
  return lhs.kind == rhs.kind && lhs.rep == rhs.rep &&
         lhs.laneidx == rhs.laneidx;
}

size_t hash_value(StoreLaneParameters params) {
  return base::hash_combine(params.kind, params.rep, params.laneidx);
}

std::ostream& operator<<(std::ostream& os, StoreLaneParameters params) {
  return os << "(" << params.kind << " " << params.rep << " "
            << static_cast<unsigned int>(params.laneidx) << ")";
}

StoreLaneParameters const& StoreLaneParametersOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kStoreLane, op->opcode());
  return OpParameter<StoreLaneParameters>(op);
}

bool operator==(StoreLaneParameters lhs, StoreLaneParameters rhs) {
  return lhs.kind == rhs.kind && lhs.rep == rhs.rep &&
         lhs.laneidx == rhs.laneidx;
}
#endif  // V8_ENABLE_WEBASSEMBLY

LoadRepresentation LoadRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kLoad == op->opcode() ||
         IrOpcode::kProtectedLoad == op->opcode() ||
         IrOpcode::kLoadTrapOnNull == op->opcode() ||
         IrOpcode::kUnalignedLoad == op->opcode() ||
         IrOpcode::kLoadImmutable == op->opcode());
  return OpParameter<LoadRepresentation>(op);
}

AtomicLoadParameters AtomicLoadParametersOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32AtomicLoad == op->opcode() ||
         IrOpcode::kWord64AtomicLoad == op->opcode());
  return OpParameter<AtomicLoadParameters>(op);
}

AtomicOpParameters AtomicOpParametersOf(Operator const* op) {
  DCHECK(IrOpcode::isAtomicOpOpcode(IrOpcode::Value(op->opcode())));
  return OpParameter<AtomicOpParameters>(op);
}

StoreRepresentation const& StoreRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kStore == op->opcode() ||
         IrOpcode::kProtectedStore == op->opcode() ||
         IrOpcode::kStoreTrapOnNull == op->opcode() ||
         IrOpcode::kStoreIndirectPointer == op->opcode());
  return OpParameter<StoreRepresentation>(op);
}

StorePairRepresentation const& StorePairRepresentationOf(Operator const* op) {
  DCHECK(IrOpcode::kStorePair == op->opcode());
  return OpParameter<StorePairRepresentation>(op);
}

AtomicStoreParameters const& AtomicStoreParametersOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32AtomicStore == op->opcode() ||
         IrOpcode::kWord64AtomicStore == op->opcode());
  return OpParameter<AtomicStoreParameters>(op);
}

UnalignedStoreRepresentation const& UnalignedStoreRepresentationOf(
    Operator const* op) {
  DCHECK_EQ(IrOpcode::kUnalignedStore, op->opcode());
  return OpParameter<UnalignedStoreRepresentation>(op);
}

bool operator==(StackSlotRepresentation lhs, StackSlotRepresentation rhs) {
  return lhs.size() == rhs.size() && lhs.alignment() == rhs.alignment();
}

bool operator!=(StackSlotRepresentation lhs, StackSlotRepresentation rhs) {
  return !(lhs == rhs);
}

size_t hash_value(StackSlotRepresentation rep) {
  return base::hash_combine(rep.size(), rep.alignment());
}

std::ostream& operator<<(std::ostream& os, StackSlotRepresentation rep) {
  return os << rep.size() << ", " << rep.alignment();
}

StackSlotRepresentation const& StackSlotRepresentationOf(Operator const* op) {
  DCHECK_EQ(IrOpcode::kStackSlot, op->opcode());
  return OpParameter<StackSlotRepresentation>(op);
}

MachineType AtomicOpType(Operator const* op) {
  const AtomicOpParameters params = OpParameter<AtomicOpParameters>(op);
  return params.type();
}

size_t hash_value(ShiftKind kind) { return static_cast<size_t>(kind); }
V8_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os, ShiftKind kind) {
  switch (kind) {
    case ShiftKind::kNormal:
      return os << "Normal";
    case ShiftKind::kShiftOutZeros:
      return os << "ShiftOutZeros";
  }
}

ShiftKind ShiftKindOf(Operator const* op) {
  DCHECK(IrOpcode::kWord32Sar == op->opcode() ||
         IrOpcode::kWord64Sar == op->opcode());
  return OpParameter<ShiftKind>(op);
}

size_t hash_value(TruncateKind kind) { return static_cast<size_t>(kind); }

std::ostream& operator<<(std::ostream& os, TruncateKind kind) {
  switch (kind) {
    case TruncateKind::kArchitectureDefault:
      return os << "kArchitectureDefault";
    case TruncateKind::kSetOverflowToMin:
      return os << "kSetOverflowToMin";
  }
}

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_BINARY_OP_LIST_32(V)                                           \
  V(Word32And, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)    \
  V(Word32Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word32Xor, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)    \
  V(Word32Shl, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Shr, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Ror, Operator::kNoProperties, 2, 0, 1)                            \
  V(Word32Equal, Operator::kCommutative, 2, 0, 1)                           \
  V(Int32Add, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Int32Sub, Operator::kNoProperties, 2, 0, 1)                             \
  V(Int32Mul, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Int32MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  V(Int32Div, Operator::kNoProperties, 2, 1, 1)                             \
  V(Int32Mod, Operator::kNoProperties, 2, 1, 1)                             \
  V(Int32LessThan, Operator::kNoProperties, 2, 0, 1)                        \
  V(Int32LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                 \
  V(Uint32Div, Operator::kNoProperties, 2, 1, 1)                            \
  V(Uint32LessThan, Operator::kNoProperties, 2, 0, 1)                       \
  V(Uint32LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                \
  V(Uint32Mod, Operator::kNoProperties, 2, 1, 1)                            \
  V(Uint32MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_BINARY_OP_LIST_64(V)                                            \
  V(Word64And, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word64Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Word64Xor, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)     \
  V(Word64Shl, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64Shr, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64Ror, Operator::kNoProperties, 2, 0, 1)                             \
  V(Word64RorLowerable, Operator::kNoProperties, 2, 1, 1)                    \
  V(Word64Equal, Operator::kCommutative, 2, 0, 1)                            \
  V(Int64Add, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Int64Sub, Operator::kNoProperties, 2, 0, 1)                              \
  V(Int64Mul, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)      \
  V(Int64MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1)  \
  V(Int64Div, Operator::kNoProperties, 2, 1, 1)                              \
  V(Int64Mod, Operator::kNoProperties, 2, 1, 1)                              \
  V(Int64LessThan, Operator::kNoProperties, 2, 0, 1)                         \
  V(Int64LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)                  \
  V(Uint64MulHigh, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  V(Uint64Div, Operator::kNoProperties, 2, 1, 1)                             \
  V(Uint64Mod, Operator::kNoProperties, 2, 1, 1)                             \
  V(Uint64LessThan, Operator::kNoProperties, 2, 0, 1)                        \
  V(Uint64LessThanOrEqual, Operator::kNoProperties, 2, 0, 1)

// The format is:
// V(Name, properties, value_input_count, control_input_count, output_count)
#define PURE_SIMD_OP_LIST(V)                                                   \
  IF_WASM(V, F64x2Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x2Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F64x2Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F64x2Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x2Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F64x2Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F64x2Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F64x2Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x2Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F64x2Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x2Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F64x2Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F64x2Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F64x2Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x2Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F64x2Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F64x2Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F64x2Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F64x2Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F64x2NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F64x2ConvertLowI32x4S, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, F64x2ConvertLowI32x4U, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, F64x2PromoteLowF32x4, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F32x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4SConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x4UConvertI32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F32x4Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x4Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F32x4Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x4Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F32x4Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x4Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F32x4Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F32x4Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x4Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F32x4Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F32x4Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F32x4Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x4Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F32x4Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F32x4Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F32x4Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x4Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F32x4Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F32x4Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x4NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F32x4DemoteF64x2Zero, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F16x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F16x8Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, F16x8Sqrt, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F16x8Ceil, Operator::kNoProperties, 1, 0, 1)                      \
  IF_WASM(V, F16x8Floor, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8Trunc, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F16x8NearestInt, Operator::kNoProperties, 1, 0, 1)                \
  IF_WASM(V, F16x8Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F16x8Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F16x8Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, F16x8Div, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, F16x8Min, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F16x8Max, Operator::kAssociative | Operator::kCommutative, 2, 0,  \
          1)                                                                   \
  IF_WASM(V, F16x8Pmin, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F16x8Pmax, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, F16x8Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F16x8Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, F16x8Lt, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F16x8Le, Operator::kNoProperties, 2, 0, 1)                        \
  IF_WASM(V, F16x8SConvertI16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F16x8UConvertI16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I16x8UConvertF16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I16x8SConvertF16x8, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, F16x8DemoteF32x4Zero, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F16x8DemoteF64x2Zero, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F32x4PromoteLowF16x8, Operator::kNoProperties, 1, 0, 1)           \
  IF_WASM(V, F16x8Qfma, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, F16x8Qfms, Operator::kNoProperties, 3, 0, 1)                      \
  IF_WASM(V, I64x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I64x2Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I64x2SplatI32Pair, Operator::kNoProperties, 2, 0, 1)              \
  IF_WASM(V, I64x2Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I64x2Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I64x2SConvertI32x4Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I64x2SConvertI32x4High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I64x2UConvertI32x4Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I64x2UConvertI32x4High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I64x2BitMask, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I64x2Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I64x2Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I64x2Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I64x2Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I64x2Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I64x2GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I64x2ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I64x2ExtMulLowI32x4S, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I64x2ExtMulHighI32x4S, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I64x2ExtMulLowI32x4U, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I64x2ExtMulHighI32x4U, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I32x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I32x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I32x4SConvertF32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I32x4SConvertI16x8Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I32x4SConvertI16x8High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I32x4Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I32x4Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x4Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I32x4Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I32x4MinS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4MaxS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I32x4Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I32x4GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4UConvertF32x4, Operator::kNoProperties, 1, 0, 1)             \
  IF_WASM(V, I32x4UConvertI16x8Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I32x4UConvertI16x8High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I32x4ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I32x4MinU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4MaxU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I32x4GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I32x4Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I32x4BitMask, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I32x4DotI16x8S, Operator::kCommutative, 2, 0, 1)                  \
  IF_WASM(V, I32x4ExtMulLowI16x8S, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I32x4ExtMulHighI16x8S, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I32x4ExtMulLowI16x8U, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I32x4ExtMulHighI16x8U, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I32x4ExtAddPairwiseI16x8S, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I32x4ExtAddPairwiseI16x8U, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I32x4TruncSatF64x2SZero, Operator::kNoProperties, 1, 0, 1)        \
  IF_WASM(V, I32x4TruncSatF64x2UZero, Operator::kNoProperties, 1, 0, 1)        \
  IF_WASM(V, I16x16Splat, Operator::kNoProperties, 1, 0, 1)                    \
  IF_WASM(V, I16x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I16x8SConvertI8x16Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I16x8SConvertI8x16High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I16x8Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I16x8Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x8SConvertI32x4, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I16x8Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x8AddSatS, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I16x8Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8SubSatS, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I16x8Mul, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I16x8MinS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8MaxS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8Eq, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I16x8Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I16x8GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8UConvertI8x16Low, Operator::kNoProperties, 1, 0, 1)          \
  IF_WASM(V, I16x8UConvertI8x16High, Operator::kNoProperties, 1, 0, 1)         \
  IF_WASM(V, I16x8ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I16x8UConvertI32x4, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I16x8AddSatU, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I16x8SubSatU, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I16x8MinU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8MaxU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I16x8GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I16x8RoundingAverageU, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I16x8Q15MulRSatS, Operator::kCommutative, 2, 0, 1)                \
  IF_WASM(V, I16x8Abs, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I16x8BitMask, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I16x8ExtMulLowI8x16S, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I16x8ExtMulHighI8x16S, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I16x8ExtMulLowI8x16U, Operator::kCommutative, 2, 0, 1)            \
  IF_WASM(V, I16x8ExtMulHighI8x16U, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I16x8ExtAddPairwiseI8x16S, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I16x8ExtAddPairwiseI8x16U, Operator::kNoProperties, 1, 0, 1)      \
  IF_WASM(V, I8x32Splat, Operator::kNoProperties, 1, 0, 1)                     \
  V(I8x16Splat, Operator::kNoProperties, 1, 0, 1)                              \
  IF_WASM(V, F64x4Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, F32x8Splat, Operator::kNoProperties, 1, 0, 1)                     \
  IF_WASM(V, I8x16Neg, Operator::kNoProperties, 1, 0, 1)                       \
  IF_WASM(V, I8x16Shl, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16ShrS, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I8x16SConvertI16x8, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I8x16Add, Operator::kCommutative, 2, 0, 1)                        \
  IF_WASM(V, I8x16AddSatS, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I8x16Sub, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16SubSatS, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I8x16MinS, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x16MaxS, Operator::kCommutative, 2, 0, 1)                       \
  V(I8x16Eq, Operator::kCommutative, 2, 0, 1)                                  \
  IF_WASM(V, I8x16Ne, Operator::kCommutative, 2, 0, 1)                         \
  IF_WASM(V, I8x16GtS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16GeS, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16ShrU, Operator::kNoProperties, 2, 0, 1)                      \
  IF_WASM(V, I8x16UConvertI16x8, Operator::kNoProperties, 2, 0, 1)             \
  IF_WASM(V, I8x16AddSatU, Operator::kCommutative, 2, 0, 1)                    \
  IF_WASM(V, I8x16SubSatU, Operator::kNoProperties, 2, 0, 1)                   \
  IF_WASM(V, I8x16MinU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x16MaxU, Operator::kCommutative, 2, 0, 1)                       \
  IF_WASM(V, I8x16GtU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16GeU, Operator::kNoProperties, 2, 0, 1)                       \
  IF_WASM(V, I8x16RoundingAverageU, Operator::kCommutative, 2, 0, 1)           \
  IF_WASM(V, I8x16Popcnt, Operator::kNoProperties, 1, 0, 1)                    \
  IF_WASM(V, I8x16Abs, Operator::kNoProperties, 1, 0, 1)                       \
  V(I8x16BitMask, Operator::kNoProperties, 1, 0, 1)                            \
  IF_WASM(V, S128Zero, Operator::kNoProperties, 0, 0, 1)                       \
  IF_WASM(V, S128And, Operator::kAssociative | Operator::kCommutative, 2, 0,   \
          1)                                                                   \
  IF_WASM(V, S128Or, Operator::kAssociative | Operator::kCommutative, 2, 0, 1) \
  IF_WASM(V, S128Xor, Operator::kAssociative | Operator::kCommutative, 2, 0,   \
          1)                                                                   \
  IF_WASM(V, S128Not, Operator::kNoProperties, 1, 0, 1)                        \
  IF_WASM(V, S128Select, Operator::kNoProperties, 3, 0, 1)                     \
  IF_WASM(V, S128AndNot, Operator::kNoProperties, 2, 0, 1)                     \
  IF_WASM(V, V128AnyTrue, Operator::kNoProperties, 1, 0, 1)                    \
  IF_WASM(V, I64x2AllTrue, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I32x4AllTrue, Operator::kNoProperties, 1, 0, 1)                   \
  IF_WASM(V, I16x8AllTrue, Operator::kNoProperties, 1, 0, 1)                   \
 
"""


```