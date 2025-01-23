Response:
My thinking process to analyze the provided C++ code snippet and fulfill the request goes like this:

1. **Identify the Core Functionality:** The file name `code-stub-assembler.cc` and the class name `CodeStubAssembler` immediately suggest this code is about generating machine code stubs. The "assembler" part hints at low-level code manipulation.

2. **Scan for Key Concepts and Data Structures:** I looked for important terms and types. Keywords like `Builtin`, `Operation`, `TNode`, `Label`, `BranchGenerator`, `FeedbackVector`, `Smi`, `Float64T`, `IntPtrT`, `Word32T`, `String`, `Context`, `Heap`, and `ReadOnlyRoots` are crucial. These point to the code's role in V8's internal workings, particularly around code generation, object representation, and runtime behavior.

3. **Analyze the Constructor and Initialization:** The constructor initializes the `CodeStubAssembler` and checks for a debug flag (`v8_flags.csa_trap_on_node`). This indicates debugging and targeted code generation capabilities.

4. **Examine the `Dcheck` and `Check` Functions:** These are assertion mechanisms. `Dcheck` is for debug builds, while `Check` is more general. They're used to verify assumptions within the generated code. The `FailAssert` function is called when an assertion fails, indicating a potential error in the code generation logic.

5. **Understand `IncrementCallCount`:** This function interacts with `FeedbackVector` and slots. This is part of V8's performance optimization strategy, tracking how often code is executed to inform later optimizations.

6. **Explore Constant Accessors:** The macros `HEAP_CONSTANT_ACCESSOR` and `HEAP_CONSTANT_TEST` are used extensively. These generate functions to access pre-defined constants within the V8 heap (e.g., `TrueConstant`, `UndefinedConstant`). This highlights the reliance on the existing V8 object model.

7. **Delve into Numeric Operations:**  A significant portion of the code deals with numeric types (`BInt`, `Float64T`, `IntPtrT`, `Smi`). There are functions for rounding, comparisons, and bitwise operations. The fallback implementations for operations like `Float64Ceil` when hardware support isn't available illustrate the need for cross-platform compatibility.

8. **Investigate Type Conversions:** Functions like `TaggedToParameter`, `TaggedIndexToIntPtr`, `IntPtrToTaggedIndex`, `SmiToTaggedIndex`, and `SmiFromInt32` demonstrate the code's responsibility for converting between different V8 internal representations of values (tagged pointers, SMIs, raw integers).

9. **Identify Potential Connections to JavaScript:** Although the code is C++, I looked for concepts that directly relate to JavaScript. The mention of `BigInt` comparisons, float rounding (which aligns with JavaScript's `Math.round`, `Math.ceil`, etc.), and the overall goal of generating code for the V8 engine strongly suggest a connection.

10. **Infer the Relationship to Torque:** The prompt mentions `.tq` files and their relation to Torque. The code snippet itself *includes* a header file related to Torque (`#include "src/codegen/code-stub-assembler-inl.h"` which likely contains definitions used by both). This implies `code-stub-assembler.cc` is the C++ implementation of some functionalities that might be *defined* using Torque.

11. **Formulate the Summary:**  Based on the above analysis, I synthesized the main functionalities: generating low-level code stubs, providing an abstraction layer over machine code generation, offering debugging and assertion mechanisms, supporting performance optimization through feedback, and providing utilities for numeric operations and type conversions.

12. **Address Specific Prompt Questions:**  I systematically went through each part of the request:
    * **Functionalities:**  List the discovered functionalities.
    * **Torque:** Confirm it's likely a C++ implementation, not a Torque source file.
    * **JavaScript Relationship:** Identify related JavaScript features (BigInt, Math functions) and provide illustrative examples.
    * **Logic Reasoning:** Choose a relatively simple function (`SelectInt32Constant`) to demonstrate input-output.
    * **Common Errors:**  Think about potential mistakes when using such a low-level API (incorrect type conversions, assuming hardware support).
    * **Overall Summary:**  Reiterate the core purpose of the file.

13. **Refine and Organize:** I organized the information logically, using headings and bullet points for clarity. I ensured the examples were concise and illustrative. I tried to use the terminology used in the code and the prompt.

This iterative process of scanning, analyzing, connecting concepts, and then synthesizing information allows me to understand the purpose and functionality of a complex piece of code even without in-depth prior knowledge. The prompt's hints about Torque and the desired information helped guide my analysis.
好的，根据您提供的 V8 源代码 `v8/src/codegen/code-stub-assembler.cc` 的第一部分，我可以归纳一下它的功能：

**主要功能：提供用于生成代码桩（Code Stub）的汇编器接口**

`CodeStubAssembler` 类是 V8 引擎中用于动态生成低级机器代码的关键组件。它提供了一组高级抽象，允许开发者以一种更结构化和类型安全的方式编写汇编代码，而无需直接操作原始的机器指令。

**具体功能点：**

1. **代码生成基础:**
   - 提供了 `CodeStubAssembler` 类，继承自 `compiler::CodeAssembler`，作为代码生成的基础框架。
   - 包含用于定义和使用标签 (`Label`)，实现条件分支 (`BranchGenerator`) 的机制。
   - 支持在代码生成过程中添加注释 (`Comment`)，提高可读性。

2. **调试和断言支持:**
   - 提供了 `Dcheck` 和 `Check` 宏/函数，用于在调试和非调试模式下进行断言检查，帮助开发者验证代码生成的正确性。
   - `FailAssert` 函数用于在断言失败时生成错误信息并终止执行。
   - `HandleBreakOnNode` 函数支持根据命令行参数在特定的代码节点设置断点，用于调试。

3. **常量处理:**
   - 提供了便捷的方法来创建和选择常量，例如 `Int32Constant`, `IntPtrConstant`, `BooleanConstant`, `SmiConstant` 等。
   - 提供了访问 V8 堆中预定义常量的宏 (`HEAP_CONSTANT_ACCESSOR`, `HEAP_CONSTANT_TEST`)，例如 `TrueConstant`, `FalseConstant`, `UndefinedConstant` 等。

4. **反馈向量 (Feedback Vector) 操作:**
   - 提供了 `IncrementCallCount` 函数，用于递增反馈向量中特定槽位的调用计数，这是 V8 优化管线的一部分，用于收集运行时性能数据。

5. **数值运算支持:**
   - 提供了各种数值类型 (`BInt`, `Float64T`, `IntPtrT` 等) 的操作，例如比较、选择、转换等。
   - 包含浮点数运算的辅助函数，如 `Float64AlmostEqual`, `Float64Round`, `Float64Ceil`, `Float64Floor`, `Float64RoundToEven`, `Float64Trunc`，这些函数实现了 JavaScript 中 `Math` 对象的一些方法。

6. **位运算支持:**
   - 提供了位运算相关的函数，例如 `PopulationCountFallback` (计算 population count 或 set bits 的数量), `PopulationCount64`, `PopulationCount32`, `CountTrailingZeros64`, `CountTrailingZeros32`, `CountLeadingZeros64`, `CountLeadingZeros32`。

7. **类型转换和标记指针处理:**
   - 提供了在不同 V8 内部表示之间进行类型转换的函数，例如 `TaggedToParameter`, `TaggedIndexToIntPtr`, `IntPtrToTaggedIndex`, `SmiToTaggedIndex`, `SmiFromInt32`, `SmiFromUint32`。这些函数处理了 V8 中对象的标记指针 (`Tagged`) 和非标记指针之间的转换。

**关于 .tq 文件的说明：**

您是对的，如果 `v8/src/codegen/code-stub-assembler.cc` 文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码**。 Torque 是一种 V8 特有的领域特定语言 (DSL)，用于更安全、更易于维护地生成高效的 C++ 代码，这些 C++ 代码随后用于构建 V8 的内置函数和运行时代码。

然而，根据您提供的文件名，`code-stub-assembler.cc` 是一个 **C++ 源代码** 文件。 它的作用是提供 Torque 生成的 C++ 代码的基础设施和工具函数。 Torque 生成的代码会使用 `CodeStubAssembler` 提供的 API 来构建代码桩。

**与 JavaScript 的关系及示例：**

`CodeStubAssembler` 生成的代码桩通常用于实现 V8 引擎的内置函数和运行时功能，这些功能直接暴露给 JavaScript。

**例子：实现 `Math.ceil()`**

`CodeStubAssembler` 中的 `Float64Ceil` 函数 (以及其可能的底层实现) 最终会被用于实现 JavaScript 的 `Math.ceil()` 函数。

```javascript
// JavaScript 示例
console.log(Math.ceil(3.14)); // 输出 4
console.log(Math.ceil(-3.14)); // 输出 -3
```

在 V8 内部，当 JavaScript 引擎执行 `Math.ceil(3.14)` 时，它可能会调用一个由 `CodeStubAssembler` 生成的代码桩，该代码桩会使用类似于 `Float64Ceil` 的逻辑来计算结果。

**代码逻辑推理示例：**

**假设输入：**

```c++
TNode<BoolT> condition = ...; // 假设 condition 的值为 true
int true_value = 10;
int false_value = 20;
```

**代码：**

```c++
TNode<Int32T> result = SelectInt32Constant(condition, true_value, false_value);
```

**输出：**

`result` 将会是一个表示整数值 `10` 的 `TNode<Int32T>`。

**推理：**

`SelectInt32Constant` 函数会根据 `condition` 的真假来选择返回 `true_value` 或 `false_value` 的常量表示。 因为假设 `condition` 为 `true`，所以返回了 `true_value` (10)。

**用户常见的编程错误（在使用类似 API 时）：**

由于 `CodeStubAssembler` 是一个相对底层的 API，用户在使用它或类似的接口时容易犯以下错误：

1. **类型不匹配：** 试图将不兼容的 `TNode` 类型传递给函数，例如将 `TNode<Smi>` 传递给期望 `TNode<IntPtrT>` 的函数。
   ```c++
   TNode<Smi> smi_val = SmiConstant(5);
   // 错误：IntPtrAdd 期望 TNode<IntPtrT>
   // TNode<IntPtrT> result = IntPtrAdd(smi_val, IntPtrConstant(1));
   ```

2. **忘记处理边界情况：** 在代码生成逻辑中没有充分考虑到所有可能的输入和状态，可能导致意外的行为或崩溃。
   ```c++
   // 假设一个函数需要加载数组的某个元素
   TNode<IntPtrT> index = ...;
   TNode<FixedArray> array = ...;
   // 没有检查 index 是否越界
   // TNode<Object> element = LoadFixedArrayElement(array, index);
   ```

3. **不正确的内存管理（如果涉及手动内存操作，但 `CodeStubAssembler` 通常提供抽象，降低了这种风险）：**  在需要手动管理内存的情况下，可能出现内存泄漏或悬 dangling 指针。

4. **假设特定架构或指令集：**  编写的代码可能依赖于特定 CPU 架构的指令，导致在其他架构上无法正常工作。 `CodeStubAssembler` 尝试提供架构无关的抽象，但有时仍然需要注意。

**总结：**

`v8/src/codegen/code-stub-assembler.cc` 的第一部分定义了 `CodeStubAssembler` 类，它是 V8 引擎用于生成高效机器代码的基础工具。 它提供了一组用于构建代码桩的抽象，包括控制流、常量处理、数值运算、类型转换和断言机制。 虽然不是 Torque 源代码，但它是 Torque 生成的代码所依赖的关键组件，并且直接服务于 V8 引擎的 JavaScript 执行。

### 提示词
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共23部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/code-stub-assembler.h"

#include <stdio.h>

#include <functional>
#include <optional>

#include "include/v8-internal.h"
#include "src/base/macros.h"
#include "src/builtins/builtins-inl.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/tnode.h"
#include "src/common/globals.h"
#include "src/execution/frame-constants.h"
#include "src/execution/frames-inl.h"
#include "src/execution/frames.h"
#include "src/execution/protectors.h"
#include "src/heap/heap-inl.h"  // For MutablePageMetadata. TODO(jkummerow): Drop.
#include "src/heap/mutable-page-metadata.h"
#include "src/logging/counters.h"
#include "src/numbers/integer-literal-inl.h"
#include "src/objects/api-callbacks.h"
#include "src/objects/cell.h"
#include "src/objects/descriptor-array.h"
#include "src/objects/function-kind.h"
#include "src/objects/heap-number.h"
#include "src/objects/instance-type-checker.h"
#include "src/objects/instance-type-inl.h"
#include "src/objects/instance-type.h"
#include "src/objects/js-generator.h"
#include "src/objects/oddball.h"
#include "src/objects/ordered-hash-table-inl.h"
#include "src/objects/property-cell.h"
#include "src/objects/property-descriptor-object.h"
#include "src/objects/tagged-field.h"
#include "src/roots/roots.h"
#include "third_party/v8/codegen/fp16-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

#ifdef DEBUG
#define CSA_DCHECK_BRANCH(csa, gen, ...) \
  (csa)->Dcheck(gen, #gen, __FILE__, __LINE__, CSA_DCHECK_ARGS(__VA_ARGS__))
#else
#define CSA_DCHECK_BRANCH(csa, ...) ((void)0)
#endif

namespace {

Builtin BigIntComparisonBuiltinOf(Operation const& op) {
  switch (op) {
    case Operation::kLessThan:
      return Builtin::kBigIntLessThan;
    case Operation::kGreaterThan:
      return Builtin::kBigIntGreaterThan;
    case Operation::kLessThanOrEqual:
      return Builtin::kBigIntLessThanOrEqual;
    case Operation::kGreaterThanOrEqual:
      return Builtin::kBigIntGreaterThanOrEqual;
    default:
      UNREACHABLE();
  }
}

}  // namespace

CodeStubAssembler::CodeStubAssembler(compiler::CodeAssemblerState* state)
    : compiler::CodeAssembler(state),
      TorqueGeneratedExportedMacrosAssembler(state) {
  if (v8_flags.csa_trap_on_node != nullptr) {
    HandleBreakOnNode();
  }
}

void CodeStubAssembler::HandleBreakOnNode() {
  // v8_flags.csa_trap_on_node should be in a form "STUB,NODE" where STUB is a
  // string specifying the name of a stub and NODE is number specifying node id.
  const char* name = state()->name();
  size_t name_length = strlen(name);
  if (strncmp(v8_flags.csa_trap_on_node, name, name_length) != 0) {
    // Different name.
    return;
  }
  size_t option_length = strlen(v8_flags.csa_trap_on_node);
  if (option_length < name_length + 2 ||
      v8_flags.csa_trap_on_node[name_length] != ',') {
    // Option is too short.
    return;
  }
  const char* start = &v8_flags.csa_trap_on_node[name_length + 1];
  char* end;
  int node_id = static_cast<int>(strtol(start, &end, 10));
  if (start == end) {
    // Bad node id.
    return;
  }
  BreakOnNode(node_id);
}

void CodeStubAssembler::Dcheck(const BranchGenerator& branch,
                               const char* message, const char* file, int line,
                               std::initializer_list<ExtraNode> extra_nodes,
                               const SourceLocation& loc) {
#if defined(DEBUG)
  if (v8_flags.debug_code) {
    Check(branch, message, file, line, extra_nodes, loc);
  }
#endif
}

void CodeStubAssembler::Dcheck(const NodeGenerator<BoolT>& condition_body,
                               const char* message, const char* file, int line,
                               std::initializer_list<ExtraNode> extra_nodes,
                               const SourceLocation& loc) {
#if defined(DEBUG)
  if (v8_flags.debug_code) {
    Check(condition_body, message, file, line, extra_nodes, loc);
  }
#endif
}

void CodeStubAssembler::Dcheck(TNode<Word32T> condition_node,
                               const char* message, const char* file, int line,
                               std::initializer_list<ExtraNode> extra_nodes,
                               const SourceLocation& loc) {
#if defined(DEBUG)
  if (v8_flags.debug_code) {
    Check(condition_node, message, file, line, extra_nodes, loc);
  }
#endif
}

void CodeStubAssembler::Check(const BranchGenerator& branch,
                              const char* message, const char* file, int line,
                              std::initializer_list<ExtraNode> extra_nodes,
                              const SourceLocation& loc) {
  Label ok(this);
  Label not_ok(this, Label::kDeferred);
  if (message != nullptr) {
    Comment({"[ Assert: ", loc}, message);
  } else {
    Comment({"[ Assert: ", loc});
  }
  branch(&ok, &not_ok);

  BIND(&not_ok);
  std::vector<FileAndLine> file_and_line;
  if (file != nullptr) {
    file_and_line.push_back({file, line});
  }
  FailAssert(message, file_and_line, extra_nodes, loc);

  BIND(&ok);
  Comment({"] Assert", SourceLocation()});
}

void CodeStubAssembler::Check(const NodeGenerator<BoolT>& condition_body,
                              const char* message, const char* file, int line,
                              std::initializer_list<ExtraNode> extra_nodes,
                              const SourceLocation& loc) {
  BranchGenerator branch = [=, this](Label* ok, Label* not_ok) {
    TNode<BoolT> condition = condition_body();
    Branch(condition, ok, not_ok);
  };

  Check(branch, message, file, line, extra_nodes, loc);
}

void CodeStubAssembler::Check(TNode<Word32T> condition_node,
                              const char* message, const char* file, int line,
                              std::initializer_list<ExtraNode> extra_nodes,
                              const SourceLocation& loc) {
  BranchGenerator branch = [=, this](Label* ok, Label* not_ok) {
    Branch(condition_node, ok, not_ok);
  };

  Check(branch, message, file, line, extra_nodes, loc);
}

void CodeStubAssembler::IncrementCallCount(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot_id) {
  Comment("increment call count");
  TNode<Smi> call_count =
      CAST(LoadFeedbackVectorSlot(feedback_vector, slot_id, kTaggedSize));
  // The lowest {FeedbackNexus::CallCountField::kShift} bits of the call
  // count are used as flags. To increment the call count by 1 we hence
  // have to increment by 1 << {FeedbackNexus::CallCountField::kShift}.
  TNode<Smi> new_count = SmiAdd(
      call_count, SmiConstant(1 << FeedbackNexus::CallCountField::kShift));
  // Count is Smi, so we don't need a write barrier.
  StoreFeedbackVectorSlot(feedback_vector, slot_id, new_count,
                          SKIP_WRITE_BARRIER, kTaggedSize);
}

void CodeStubAssembler::FastCheck(TNode<BoolT> condition) {
  Label ok(this), not_ok(this, Label::kDeferred);
  Branch(condition, &ok, &not_ok);
  BIND(&not_ok);
  Unreachable();
  BIND(&ok);
}

void CodeStubAssembler::FailAssert(
    const char* message, const std::vector<FileAndLine>& files_and_lines,
    std::initializer_list<ExtraNode> extra_nodes, const SourceLocation& loc) {
  DCHECK_NOT_NULL(message);
  base::EmbeddedVector<char, 1024> chars;
  std::stringstream stream;
  for (auto it = files_and_lines.rbegin(); it != files_and_lines.rend(); ++it) {
    if (it->first != nullptr) {
      stream << " [" << it->first << ":" << it->second << "]";
#ifndef DEBUG
      // To limit the size of these strings in release builds, we include only
      // the innermost macro's file name and line number.
      break;
#endif
    }
  }
  std::string files_and_lines_text = stream.str();
  if (!files_and_lines_text.empty()) {
    SNPrintF(chars, "%s%s", message, files_and_lines_text.c_str());
    message = chars.begin();
  }
  TNode<String> message_node = StringConstant(message);

#ifdef DEBUG
  // Only print the extra nodes in debug builds.
  for (auto& node : extra_nodes) {
    CallRuntime(Runtime::kPrintWithNameForAssert, SmiConstant(0),
                StringConstant(node.second), node.first);
  }
#endif

  AbortCSADcheck(message_node);
  Unreachable();
}

TNode<Int32T> CodeStubAssembler::SelectInt32Constant(TNode<BoolT> condition,
                                                     int true_value,
                                                     int false_value) {
  return SelectConstant<Int32T>(condition, Int32Constant(true_value),
                                Int32Constant(false_value));
}

TNode<IntPtrT> CodeStubAssembler::SelectIntPtrConstant(TNode<BoolT> condition,
                                                       int true_value,
                                                       int false_value) {
  return SelectConstant<IntPtrT>(condition, IntPtrConstant(true_value),
                                 IntPtrConstant(false_value));
}

TNode<Boolean> CodeStubAssembler::SelectBooleanConstant(
    TNode<BoolT> condition) {
  return SelectConstant<Boolean>(condition, TrueConstant(), FalseConstant());
}

TNode<Smi> CodeStubAssembler::SelectSmiConstant(TNode<BoolT> condition,
                                                Tagged<Smi> true_value,
                                                Tagged<Smi> false_value) {
  return SelectConstant<Smi>(condition, SmiConstant(true_value),
                             SmiConstant(false_value));
}

TNode<Smi> CodeStubAssembler::NoContextConstant() {
  return SmiConstant(Context::kNoContext);
}

#define HEAP_CONSTANT_ACCESSOR(rootIndexName, rootAccessorName, name)          \
  TNode<RemoveTagged<decltype(std::declval<Heap>().rootAccessorName())>::type> \
      CodeStubAssembler::name##Constant() {                                    \
    return UncheckedCast<RemoveTagged<                                         \
        decltype(std::declval<Heap>().rootAccessorName())>::type>(             \
        LoadRoot(RootIndex::k##rootIndexName));                                \
  }
HEAP_MUTABLE_IMMOVABLE_OBJECT_LIST(HEAP_CONSTANT_ACCESSOR)
#undef HEAP_CONSTANT_ACCESSOR

#define HEAP_CONSTANT_ACCESSOR(rootIndexName, rootAccessorName, name)       \
  TNode<RemoveTagged<                                                       \
      decltype(std::declval<ReadOnlyRoots>().rootAccessorName())>::type>    \
      CodeStubAssembler::name##Constant() {                                 \
    return UncheckedCast<RemoveTagged<                                      \
        decltype(std::declval<ReadOnlyRoots>().rootAccessorName())>::type>( \
        LoadRoot(RootIndex::k##rootIndexName));                             \
  }
HEAP_IMMUTABLE_IMMOVABLE_OBJECT_LIST(HEAP_CONSTANT_ACCESSOR)
#undef HEAP_CONSTANT_ACCESSOR

#define HEAP_CONSTANT_TEST(rootIndexName, rootAccessorName, name)    \
  TNode<BoolT> CodeStubAssembler::Is##name(TNode<Object> value) {    \
    return TaggedEqual(value, name##Constant());                     \
  }                                                                  \
  TNode<BoolT> CodeStubAssembler::IsNot##name(TNode<Object> value) { \
    return TaggedNotEqual(value, name##Constant());                  \
  }
HEAP_IMMOVABLE_OBJECT_LIST(HEAP_CONSTANT_TEST)
#undef HEAP_CONSTANT_TEST

TNode<BInt> CodeStubAssembler::BIntConstant(int value) {
#if defined(BINT_IS_SMI)
  return SmiConstant(value);
#elif defined(BINT_IS_INTPTR)
  return IntPtrConstant(value);
#else
#error Unknown architecture.
#endif
}

template <>
TNode<Smi> CodeStubAssembler::IntPtrOrSmiConstant<Smi>(int value) {
  return SmiConstant(value);
}

template <>
TNode<IntPtrT> CodeStubAssembler::IntPtrOrSmiConstant<IntPtrT>(int value) {
  return IntPtrConstant(value);
}

template <>
TNode<UintPtrT> CodeStubAssembler::IntPtrOrSmiConstant<UintPtrT>(int value) {
  return Unsigned(IntPtrConstant(value));
}

template <>
TNode<RawPtrT> CodeStubAssembler::IntPtrOrSmiConstant<RawPtrT>(int value) {
  return ReinterpretCast<RawPtrT>(IntPtrConstant(value));
}

bool CodeStubAssembler::TryGetIntPtrOrSmiConstantValue(
    TNode<Smi> maybe_constant, int* value) {
  Tagged<Smi> smi_constant;
  if (TryToSmiConstant(maybe_constant, &smi_constant)) {
    *value = Smi::ToInt(smi_constant);
    return true;
  }
  return false;
}

bool CodeStubAssembler::TryGetIntPtrOrSmiConstantValue(
    TNode<IntPtrT> maybe_constant, int* value) {
  int32_t int32_constant;
  if (TryToInt32Constant(maybe_constant, &int32_constant)) {
    *value = int32_constant;
    return true;
  }
  return false;
}

TNode<IntPtrT> CodeStubAssembler::IntPtrRoundUpToPowerOfTwo32(
    TNode<IntPtrT> value) {
  Comment("IntPtrRoundUpToPowerOfTwo32");
  CSA_DCHECK(this, UintPtrLessThanOrEqual(value, IntPtrConstant(0x80000000u)));
  value = Signed(IntPtrSub(value, IntPtrConstant(1)));
  for (int i = 1; i <= 16; i *= 2) {
    value = Signed(WordOr(value, WordShr(value, IntPtrConstant(i))));
  }
  return Signed(IntPtrAdd(value, IntPtrConstant(1)));
}

TNode<BoolT> CodeStubAssembler::WordIsPowerOfTwo(TNode<IntPtrT> value) {
  intptr_t constant;
  if (TryToIntPtrConstant(value, &constant)) {
    return BoolConstant(base::bits::IsPowerOfTwo(constant));
  }
  // value && !(value & (value - 1))
  return IntPtrEqual(Select<IntPtrT>(
                         IntPtrEqual(value, IntPtrConstant(0)),
                         [=, this] { return IntPtrConstant(1); },
                         [=, this] {
                           return WordAnd(value,
                                          IntPtrSub(value, IntPtrConstant(1)));
                         }),
                     IntPtrConstant(0));
}

TNode<BoolT> CodeStubAssembler::Float64AlmostEqual(TNode<Float64T> x,
                                                   TNode<Float64T> y,
                                                   double max_relative_error) {
  TVARIABLE(BoolT, result, BoolConstant(true));
  Label done(this);

  GotoIf(Float64Equal(x, y), &done);
  GotoIf(Float64LessThan(Float64Div(Float64Abs(Float64Sub(x, y)),
                                    Float64Max(Float64Abs(x), Float64Abs(y))),
                         Float64Constant(max_relative_error)),
         &done);

  result = BoolConstant(false);
  Goto(&done);

  BIND(&done);
  return result.value();
}

TNode<Float64T> CodeStubAssembler::Float64Round(TNode<Float64T> x) {
  TNode<Float64T> one = Float64Constant(1.0);
  TNode<Float64T> one_half = Float64Constant(0.5);

  Label return_x(this);

  // Round up {x} towards Infinity.
  TVARIABLE(Float64T, var_x, Float64Ceil(x));

  GotoIf(Float64LessThanOrEqual(Float64Sub(var_x.value(), one_half), x),
         &return_x);
  var_x = Float64Sub(var_x.value(), one);
  Goto(&return_x);

  BIND(&return_x);
  return var_x.value();
}

TNode<Float64T> CodeStubAssembler::Float64Ceil(TNode<Float64T> x) {
  TVARIABLE(Float64T, var_x, x);
  Label round_op_supported(this), round_op_fallback(this), return_x(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  Branch(UniqueInt32Constant(IsFloat64RoundUpSupported()), &round_op_supported,
         &round_op_fallback);

  BIND(&round_op_supported);
  {
    // This optional operation is used behind a static check and we rely
    // on the dead code elimination to remove this unused unsupported
    // instruction. We generate builtins this way in order to ensure that
    // builtins PGO profiles are interchangeable between architectures.
    var_x = Float64RoundUp(x);
    Goto(&return_x);
  }

  BIND(&round_op_fallback);
  {
    TNode<Float64T> one = Float64Constant(1.0);
    TNode<Float64T> zero = Float64Constant(0.0);
    TNode<Float64T> two_52 = Float64Constant(4503599627370496.0E0);
    TNode<Float64T> minus_two_52 = Float64Constant(-4503599627370496.0E0);

    Label return_minus_x(this);

    // Check if {x} is greater than zero.
    Label if_xgreaterthanzero(this), if_xnotgreaterthanzero(this);
    Branch(Float64GreaterThan(x, zero), &if_xgreaterthanzero,
           &if_xnotgreaterthanzero);

    BIND(&if_xgreaterthanzero);
    {
      // Just return {x} unless it's in the range ]0,2^52[.
      GotoIf(Float64GreaterThanOrEqual(x, two_52), &return_x);

      // Round positive {x} towards Infinity.
      var_x = Float64Sub(Float64Add(two_52, x), two_52);
      GotoIfNot(Float64LessThan(var_x.value(), x), &return_x);
      var_x = Float64Add(var_x.value(), one);
      Goto(&return_x);
    }

    BIND(&if_xnotgreaterthanzero);
    {
      // Just return {x} unless it's in the range ]-2^52,0[
      GotoIf(Float64LessThanOrEqual(x, minus_two_52), &return_x);
      GotoIfNot(Float64LessThan(x, zero), &return_x);

      // Round negated {x} towards Infinity and return the result negated.
      TNode<Float64T> minus_x = Float64Neg(x);
      var_x = Float64Sub(Float64Add(two_52, minus_x), two_52);
      GotoIfNot(Float64GreaterThan(var_x.value(), minus_x), &return_minus_x);
      var_x = Float64Sub(var_x.value(), one);
      Goto(&return_minus_x);
    }

    BIND(&return_minus_x);
    var_x = Float64Neg(var_x.value());
    Goto(&return_x);
  }
  BIND(&return_x);
  return var_x.value();
}

TNode<Float64T> CodeStubAssembler::Float64Floor(TNode<Float64T> x) {
  TVARIABLE(Float64T, var_x, x);
  Label round_op_supported(this), round_op_fallback(this), return_x(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  Branch(UniqueInt32Constant(IsFloat64RoundDownSupported()),
         &round_op_supported, &round_op_fallback);

  BIND(&round_op_supported);
  {
    // This optional operation is used behind a static check and we rely
    // on the dead code elimination to remove this unused unsupported
    // instruction. We generate builtins this way in order to ensure that
    // builtins PGO profiles are interchangeable between architectures.
    var_x = Float64RoundDown(x);
    Goto(&return_x);
  }

  BIND(&round_op_fallback);
  {
    TNode<Float64T> one = Float64Constant(1.0);
    TNode<Float64T> zero = Float64Constant(0.0);
    TNode<Float64T> two_52 = Float64Constant(4503599627370496.0E0);
    TNode<Float64T> minus_two_52 = Float64Constant(-4503599627370496.0E0);

    Label return_minus_x(this);

    // Check if {x} is greater than zero.
    Label if_xgreaterthanzero(this), if_xnotgreaterthanzero(this);
    Branch(Float64GreaterThan(x, zero), &if_xgreaterthanzero,
           &if_xnotgreaterthanzero);

    BIND(&if_xgreaterthanzero);
    {
      // Just return {x} unless it's in the range ]0,2^52[.
      GotoIf(Float64GreaterThanOrEqual(x, two_52), &return_x);

      // Round positive {x} towards -Infinity.
      var_x = Float64Sub(Float64Add(two_52, x), two_52);
      GotoIfNot(Float64GreaterThan(var_x.value(), x), &return_x);
      var_x = Float64Sub(var_x.value(), one);
      Goto(&return_x);
    }

    BIND(&if_xnotgreaterthanzero);
    {
      // Just return {x} unless it's in the range ]-2^52,0[
      GotoIf(Float64LessThanOrEqual(x, minus_two_52), &return_x);
      GotoIfNot(Float64LessThan(x, zero), &return_x);

      // Round negated {x} towards -Infinity and return the result negated.
      TNode<Float64T> minus_x = Float64Neg(x);
      var_x = Float64Sub(Float64Add(two_52, minus_x), two_52);
      GotoIfNot(Float64LessThan(var_x.value(), minus_x), &return_minus_x);
      var_x = Float64Add(var_x.value(), one);
      Goto(&return_minus_x);
    }

    BIND(&return_minus_x);
    var_x = Float64Neg(var_x.value());
    Goto(&return_x);
  }
  BIND(&return_x);
  return var_x.value();
}

TNode<Float64T> CodeStubAssembler::Float64RoundToEven(TNode<Float64T> x) {
  TVARIABLE(Float64T, var_result);
  Label round_op_supported(this), round_op_fallback(this), done(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  Branch(UniqueInt32Constant(IsFloat64RoundTiesEvenSupported()),
         &round_op_supported, &round_op_fallback);

  BIND(&round_op_supported);
  {
    // This optional operation is used behind a static check and we rely
    // on the dead code elimination to remove this unused unsupported
    // instruction. We generate builtins this way in order to ensure that
    // builtins PGO profiles are interchangeable between architectures.
    var_result = Float64RoundTiesEven(x);
    Goto(&done);
  }

  BIND(&round_op_fallback);
  {
    // See ES#sec-touint8clamp for details.
    TNode<Float64T> f = Float64Floor(x);
    TNode<Float64T> f_and_half = Float64Add(f, Float64Constant(0.5));

    Label return_f(this), return_f_plus_one(this);

    GotoIf(Float64LessThan(f_and_half, x), &return_f_plus_one);
    GotoIf(Float64LessThan(x, f_and_half), &return_f);
    {
      TNode<Float64T> f_mod_2 = Float64Mod(f, Float64Constant(2.0));
      Branch(Float64Equal(f_mod_2, Float64Constant(0.0)), &return_f,
             &return_f_plus_one);
    }

    BIND(&return_f);
    var_result = f;
    Goto(&done);

    BIND(&return_f_plus_one);
    var_result = Float64Add(f, Float64Constant(1.0));
    Goto(&done);
  }
  BIND(&done);
  return var_result.value();
}

TNode<Float64T> CodeStubAssembler::Float64Trunc(TNode<Float64T> x) {
  TVARIABLE(Float64T, var_x, x);
  Label trunc_op_supported(this), trunc_op_fallback(this), return_x(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  Branch(UniqueInt32Constant(IsFloat64RoundTruncateSupported()),
         &trunc_op_supported, &trunc_op_fallback);

  BIND(&trunc_op_supported);
  {
    // This optional operation is used behind a static check and we rely
    // on the dead code elimination to remove this unused unsupported
    // instruction. We generate builtins this way in order to ensure that
    // builtins PGO profiles are interchangeable between architectures.
    var_x = Float64RoundTruncate(x);
    Goto(&return_x);
  }

  BIND(&trunc_op_fallback);
  {
    TNode<Float64T> one = Float64Constant(1.0);
    TNode<Float64T> zero = Float64Constant(0.0);
    TNode<Float64T> two_52 = Float64Constant(4503599627370496.0E0);
    TNode<Float64T> minus_two_52 = Float64Constant(-4503599627370496.0E0);

    Label return_minus_x(this);

    // Check if {x} is greater than 0.
    Label if_xgreaterthanzero(this), if_xnotgreaterthanzero(this);
    Branch(Float64GreaterThan(x, zero), &if_xgreaterthanzero,
           &if_xnotgreaterthanzero);

    BIND(&if_xgreaterthanzero);
    {
      Label round_op_supported(this), round_op_fallback(this);
      Branch(UniqueInt32Constant(IsFloat64RoundDownSupported()),
             &round_op_supported, &round_op_fallback);
      BIND(&round_op_supported);
      {
        // This optional operation is used behind a static check and we rely
        // on the dead code elimination to remove this unused unsupported
        // instruction. We generate builtins this way in order to ensure that
        // builtins PGO profiles are interchangeable between architectures.
        var_x = Float64RoundDown(x);
        Goto(&return_x);
      }
      BIND(&round_op_fallback);
      {
        // Just return {x} unless it's in the range ]0,2^52[.
        GotoIf(Float64GreaterThanOrEqual(x, two_52), &return_x);

        // Round positive {x} towards -Infinity.
        var_x = Float64Sub(Float64Add(two_52, x), two_52);
        GotoIfNot(Float64GreaterThan(var_x.value(), x), &return_x);
        var_x = Float64Sub(var_x.value(), one);
        Goto(&return_x);
      }
    }

    BIND(&if_xnotgreaterthanzero);
    {
      Label round_op_supported(this), round_op_fallback(this);
      Branch(UniqueInt32Constant(IsFloat64RoundUpSupported()),
             &round_op_supported, &round_op_fallback);
      BIND(&round_op_supported);
      {
        // This optional operation is used behind a static check and we rely
        // on the dead code elimination to remove this unused unsupported
        // instruction. We generate builtins this way in order to ensure that
        // builtins PGO profiles are interchangeable between architectures.
        var_x = Float64RoundUp(x);
        Goto(&return_x);
      }
      BIND(&round_op_fallback);
      {
        // Just return {x} unless its in the range ]-2^52,0[.
        GotoIf(Float64LessThanOrEqual(x, minus_two_52), &return_x);
        GotoIfNot(Float64LessThan(x, zero), &return_x);

        // Round negated {x} towards -Infinity and return result negated.
        TNode<Float64T> minus_x = Float64Neg(x);
        var_x = Float64Sub(Float64Add(two_52, minus_x), two_52);
        GotoIfNot(Float64GreaterThan(var_x.value(), minus_x), &return_minus_x);
        var_x = Float64Sub(var_x.value(), one);
        Goto(&return_minus_x);
      }
    }

    BIND(&return_minus_x);
    var_x = Float64Neg(var_x.value());
    Goto(&return_x);
  }
  BIND(&return_x);
  return var_x.value();
}

TNode<IntPtrT> CodeStubAssembler::PopulationCountFallback(
    TNode<UintPtrT> value) {
  // Taken from slow path of base::bits::CountPopulation, the comments here show
  // C++ code and comments from there for reference.
  // Fall back to divide-and-conquer popcount (see "Hacker's Delight" by Henry
  // S. Warren,  Jr.), chapter 5-1.
  constexpr uintptr_t mask[] = {static_cast<uintptr_t>(0x5555555555555555),
                                static_cast<uintptr_t>(0x3333333333333333),
                                static_cast<uintptr_t>(0x0f0f0f0f0f0f0f0f)};

  // TNode<UintPtrT> value = Unsigned(value_word);
  TNode<UintPtrT> lhs, rhs;

  // Start with 64 buckets of 1 bits, holding values from [0,1].
  // {value = ((value >> 1) & mask[0]) + (value & mask[0])}
  lhs = WordAnd(WordShr(value, UintPtrConstant(1)), UintPtrConstant(mask[0]));
  rhs = WordAnd(value, UintPtrConstant(mask[0]));
  value = UintPtrAdd(lhs, rhs);

  // Having 32 buckets of 2 bits, holding values from [0,2] now.
  // {value = ((value >> 2) & mask[1]) + (value & mask[1])}
  lhs = WordAnd(WordShr(value, UintPtrConstant(2)), UintPtrConstant(mask[1]));
  rhs = WordAnd(value, UintPtrConstant(mask[1]));
  value = UintPtrAdd(lhs, rhs);

  // Having 16 buckets of 4 bits, holding values from [0,4] now.
  // {value = ((value >> 4) & mask[2]) + (value & mask[2])}
  lhs = WordAnd(WordShr(value, UintPtrConstant(4)), UintPtrConstant(mask[2]));
  rhs = WordAnd(value, UintPtrConstant(mask[2]));
  value = UintPtrAdd(lhs, rhs);

  // Having 8 buckets of 8 bits, holding values from [0,8] now.
  // From this point on, the buckets are bigger than the number of bits
  // required to hold the values, and the buckets are bigger the maximum
  // result, so there's no need to mask value anymore, since there's no
  // more risk of overflow between buckets.
  // {value = (value >> 8) + value}
  lhs = WordShr(value, UintPtrConstant(8));
  value = UintPtrAdd(lhs, value);

  // Having 4 buckets of 16 bits, holding values from [0,16] now.
  // {value = (value >> 16) + value}
  lhs = WordShr(value, UintPtrConstant(16));
  value = UintPtrAdd(lhs, value);

  if (Is64()) {
    // Having 2 buckets of 32 bits, holding values from [0,32] now.
    // {value = (value >> 32) + value}
    lhs = WordShr(value, UintPtrConstant(32));
    value = UintPtrAdd(lhs, value);
  }

  // Having 1 buckets of sizeof(intptr_t) bits, holding values from [0,64] now.
  // {return static_cast<unsigned>(value & 0xff)}
  return Signed(WordAnd(value, UintPtrConstant(0xff)));
}

TNode<Int64T> CodeStubAssembler::PopulationCount64(TNode<Word64T> value) {
  if (IsWord64PopcntSupported()) {
    return Word64Popcnt(value);
  }

  if (Is32()) {
    // Unsupported.
    UNREACHABLE();
  }

  return ReinterpretCast<Int64T>(
      PopulationCountFallback(ReinterpretCast<UintPtrT>(value)));
}

TNode<Int32T> CodeStubAssembler::PopulationCount32(TNode<Word32T> value) {
  if (IsWord32PopcntSupported()) {
    return Word32Popcnt(value);
  }

  if (Is32()) {
    TNode<IntPtrT> res =
        PopulationCountFallback(ReinterpretCast<UintPtrT>(value));
    return ReinterpretCast<Int32T>(res);
  } else {
    TNode<IntPtrT> res = PopulationCountFallback(
        ReinterpretCast<UintPtrT>(ChangeUint32ToUint64(value)));
    return TruncateInt64ToInt32(ReinterpretCast<Int64T>(res));
  }
}

TNode<Int64T> CodeStubAssembler::CountTrailingZeros64(TNode<Word64T> value) {
  if (IsWord64CtzSupported()) {
    return Word64Ctz(value);
  }

  if (Is32()) {
    // Unsupported.
    UNREACHABLE();
  }

  // Same fallback as in base::bits::CountTrailingZeros.
  // Fall back to popcount (see "Hacker's Delight" by Henry S. Warren, Jr.),
  // chapter 5-4. On x64, since is faster than counting in a loop and faster
  // than doing binary search.
  TNode<Word64T> lhs = Word64Not(value);
  TNode<Word64T> rhs = Uint64Sub(Unsigned(value), Uint64Constant(1));
  return PopulationCount64(Word64And(lhs, rhs));
}

TNode<Int32T> CodeStubAssembler::CountTrailingZeros32(TNode<Word32T> value) {
  if (IsWord32CtzSupported()) {
    return Word32Ctz(value);
  }

  if (Is32()) {
    // Same fallback as in Word64CountTrailingZeros.
    TNode<Word32T> lhs = Word32BitwiseNot(value);
    TNode<Word32T> rhs = Int32Sub(Signed(value), Int32Constant(1));
    return PopulationCount32(Word32And(lhs, rhs));
  } else {
    TNode<Int64T> res64 = CountTrailingZeros64(ChangeUint32ToUint64(value));
    return TruncateInt64ToInt32(Signed(res64));
  }
}

TNode<Int64T> CodeStubAssembler::CountLeadingZeros64(TNode<Word64T> value) {
  return Word64Clz(value);
}

TNode<Int32T> CodeStubAssembler::CountLeadingZeros32(TNode<Word32T> value) {
  return Word32Clz(value);
}

template <>
TNode<Smi> CodeStubAssembler::TaggedToParameter(TNode<Smi> value) {
  return value;
}

template <>
TNode<IntPtrT> CodeStubAssembler::TaggedToParameter(TNode<Smi> value) {
  return SmiUntag(value);
}

TNode<IntPtrT> CodeStubAssembler::TaggedIndexToIntPtr(
    TNode<TaggedIndex> value) {
  return Signed(WordSarShiftOutZeros(BitcastTaggedToWordForTagAndSmiBits(value),
                                     IntPtrConstant(kSmiTagSize)));
}

TNode<TaggedIndex> CodeStubAssembler::IntPtrToTaggedIndex(
    TNode<IntPtrT> value) {
  return ReinterpretCast<TaggedIndex>(
      BitcastWordToTaggedSigned(WordShl(value, IntPtrConstant(kSmiTagSize))));
}

TNode<Smi> CodeStubAssembler::TaggedIndexToSmi(TNode<TaggedIndex> value) {
  if (SmiValuesAre32Bits()) {
    DCHECK_EQ(kSmiShiftSize, 31);
    return BitcastWordToTaggedSigned(
        WordShl(BitcastTaggedToWordForTagAndSmiBits(value),
                IntPtrConstant(kSmiShiftSize)));
  }
  DCHECK(SmiValuesAre31Bits());
  DCHECK_EQ(kSmiShiftSize, 0);
  return ReinterpretCast<Smi>(value);
}

TNode<TaggedIndex> CodeStubAssembler::SmiToTaggedIndex(TNode<Smi> value) {
  if (kSystemPointerSize == kInt32Size) {
    return ReinterpretCast<TaggedIndex>(value);
  }
  if (SmiValuesAre32Bits()) {
    DCHECK_EQ(kSmiShiftSize, 31);
    return ReinterpretCast<TaggedIndex>(BitcastWordToTaggedSigned(
        WordSar(BitcastTaggedToWordForTagAndSmiBits(value),
                IntPtrConstant(kSmiShiftSize))));
  }
  DCHECK(SmiValuesAre31Bits());
  DCHECK_EQ(kSmiShiftSize, 0);
  // Just sign-extend the lower 32 bits.
  TNode<Int32T> raw =
      TruncateWordToInt32(BitcastTaggedToWordForTagAndSmiBits(value));
  return ReinterpretCast<TaggedIndex>(
      BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(raw)));
}

TNode<Smi> CodeStubAssembler::NormalizeSmiIndex(TNode<Smi> smi_index) {
  if (COMPRESS_POINTERS_BOOL) {
    TNode<Int32T> raw =
        TruncateWordToInt32(BitcastTaggedToWordForTagAndSmiBits(smi_index));
    smi_index = BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(raw));
  }
  return smi_index;
}

TNode<Smi> CodeStubAssembler::SmiFromInt32(TNode<Int32T> value) {
  if (COMPRESS_POINTERS_BOOL) {
    static_assert(!COMPRESS_POINTERS_BOOL || (kSmiShiftSize + kSmiTagSize == 1),
                  "Use shifting instead of add");
    return BitcastWordToTaggedSigned(
        ChangeUint32ToWord(Int32Add(value, value)));
  }
  return SmiTag(ChangeInt32ToIntPtr(value));
}

TNode<Smi> CodeStubAssembler::SmiFromUint32(TNode<Uint32T> value) {
  CSA_DCHECK(this, IntPtrLessThan(ChangeUint32ToWord(value),
                                  IntPtrConstant(Smi::kMaxValue)));
  return SmiFromInt32(Signed(value));
}

TNode<BoolT> CodeStubAssembler::IsValidPositiveSmi(TNode<IntPtrT> value) {
  intptr_t constant_value;
  if (TryToIntPtrConstant(value, &constant_value)) {
```