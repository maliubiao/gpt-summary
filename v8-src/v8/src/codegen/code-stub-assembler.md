Response: My thinking process to summarize the given C++ code and relate it to JavaScript goes like this:

1. **Identify the Core Class:** The first thing I notice is the class `CodeStubAssembler`. The filename itself, `code-stub-assembler.cc`, strongly suggests this is the central component.

2. **Analyze the Constructor:** The constructor takes a `compiler::CodeAssemblerState*`. This hints at a connection to the compiler and code generation within V8. The `TorqueGeneratedExportedMacrosAssembler` inheritance reinforces the idea of code generation, likely related to Torque, V8's language for expressing builtins. The `v8_flags.csa_trap_on_node` handling suggests debugging or testing capabilities during code generation.

3. **Examine Key Methods:** I scan the provided methods, grouping them by function:
    * **Assertions/Checks:** `Dcheck`, `Check`, `FailAssert`. These are for internal validation during development, similar to `console.assert()` in JavaScript.
    * **Constants:**  A large number of methods ending in `Constant()` (e.g., `NoContextConstant`, `UndefinedConstant`). This points to the class's role in providing access to common V8 values.
    * **Type Checks:** Methods starting with `Is` or `IsNot` (e.g., `IsSmi`, `IsHeapNumberMap`). These are for determining the type of JavaScript values within the generated code.
    * **Numeric Operations:**  A wide range of methods for integer and floating-point arithmetic, bitwise operations, and conversions (e.g., `SmiAdd`, `Float64Add`, `SmiToInt32`, `Float64Round`).
    * **Tagged Value Manipulation:** Methods for working with tagged values (Smis, heap object pointers), including tagging, untagging, and conversions (e.g., `SmiTag`, `SmiUntag`, `TaggedIndexToIntPtr`).
    * **Memory Allocation:** `AllocateRaw`, `AllocateInNewSpace`, `Allocate`. This is crucial for dynamically creating objects in the V8 heap.
    * **Control Flow:** While not explicitly methods, the use of `Label` and the branching instructions (`Branch`, `GotoIf`) are fundamental to code generation.
    * **External Calls:**  `CallRuntime`, `CallCFunction`. These allow the generated code to interact with V8's runtime system and C++ functions.
    * **ToBoolean Conversion:** `BranchIfToBooleanIsTrue`. This implements JavaScript's "truthiness" rules.

4. **Infer Overall Functionality:** Based on the methods, I can conclude that `CodeStubAssembler` provides a high-level interface within the V8 compiler to:
    * Generate low-level machine code.
    * Manipulate V8's internal data structures (tagged values, heap objects).
    * Perform type checks and conversions.
    * Implement JavaScript semantics for operations.
    * Interact with the V8 runtime.
    * Facilitate debugging.

5. **Relate to JavaScript:**  The key is to connect these low-level operations to observable JavaScript behavior. I consider examples where these operations would be necessary:
    * **Type Checks:**  `typeof`, `instanceof`.
    * **Numeric Operations:**  `+`, `-`, `*`, `/`, `Math.floor`, `parseInt`.
    * **Truthiness:** `if` statements, `&&`, `||`, `!`.
    * **Object Creation:** `new Object()`, object literals.
    * **Function Calls:**  The `IncrementCallCount` method directly relates to how V8 tracks function execution.

6. **Formulate the Summary:** I synthesize the findings into a concise description, highlighting the core purpose and its relation to JavaScript. I emphasize that it's a *tool* for the compiler, not directly exposed to JavaScript.

7. **Create JavaScript Examples:** For each related JavaScript feature, I provide a simple code snippet demonstrating the concept. I explain *how* the `CodeStubAssembler` might be involved behind the scenes, without going into excessive technical detail (as that's not the goal of the summary). I focus on illustrative examples.

8. **Review and Refine:** I read through the summary and examples to ensure clarity, accuracy, and conciseness. I make sure the connection to JavaScript is clear and easy to understand. I note that this is only the first part of the file, implying further functionalities will be revealed in subsequent parts.

Essentially, I'm "reverse-engineering" the functionality of the C++ code by examining its methods and inferring its purpose within the broader context of the V8 JavaScript engine. Then, I bridge the gap by showing concrete JavaScript examples that rely on the underlying mechanisms provided by `CodeStubAssembler`.
这个C++代码文件 `code-stub-assembler.cc` 是 V8 JavaScript 引擎中 **CodeStubAssembler** 类的实现的一部分。 **CodeStubAssembler** 是一个用于生成优化的机器码（也称为 "code stubs"）的工具，这些机器码用于处理 V8 引擎内部的各种操作，尤其是那些需要高性能执行的低级操作。

**主要功能归纳:**

1. **提供高级抽象用于生成机器码:**  `CodeStubAssembler` 隐藏了直接操作汇编指令的复杂性，提供了一组 C++ 方法，可以方便地生成与特定平台相关的机器码。这使得 V8 开发者可以用更简洁、更易于理解的方式编写底层的代码生成逻辑。

2. **处理 V8 内部对象和类型:**  该文件包含了大量用于操作 V8 内部数据类型（例如 `Smi`，`HeapObject`，`Float64` 等）的方法。这些方法可以进行类型检查、转换、算术运算、比较等操作。

3. **支持控制流:** `CodeStubAssembler` 提供了用于生成条件分支 (`Branch`)、跳转 (`Goto`)、标签 (`Label`) 等控制流指令的机制。

4. **提供访问 V8 运行时功能的接口:**  通过 `CallRuntime` 和 `CallCFunction` 等方法，`CodeStubAssembler` 生成的代码可以调用 V8 运行时系统提供的函数或底层的 C++ 函数。

5. **支持内联缓存 (Inline Caching) 和性能优化:**  Code stubs 经常被用于实现内联缓存，通过在运行时生成针对特定类型的优化代码来提高性能。

6. **提供断言和调试机制:**  `Dcheck` 和 `Check` 等方法用于在开发和调试阶段插入断言，帮助开发者验证生成的代码的正确性。

**与 JavaScript 的关系及 JavaScript 举例:**

`CodeStubAssembler` 生成的机器码 **直接参与** 了 JavaScript 代码的执行过程。许多 JavaScript 的底层操作，例如算术运算、类型转换、属性访问、函数调用等，都可能最终由 `CodeStubAssembler` 生成的 code stubs 来执行。

**JavaScript 例子:**

考虑以下简单的 JavaScript 加法操作：

```javascript
function add(a, b) {
  return a + b;
}

add(1, 2);
```

当 V8 执行 `add(1, 2)` 时，可能会发生以下与 `CodeStubAssembler` 相关的过程：

1. **类型检查:** V8 需要检查 `a` 和 `b` 的类型。如果它们都是小的整数 (Smis)，V8 可以使用专门针对 Smi 加法的 code stub 来执行加法。 `CodeStubAssembler` 中可能存在生成这类 Smi 加法 code stub 的代码。

2. **Smi 加法:**  如果 `a` 和 `b` 都是 Smi，V8 可能会调用一个由 `CodeStubAssembler` 生成的、针对 Smi 加法优化的 code stub。这个 code stub 会执行底层的机器码指令来完成加法操作，例如：

   ```assembly
   // 假设的 x64 汇编指令
   mov rax, [参数 a 的位置]  ; 将 a 加载到 rax 寄存器
   mov rbx, [参数 b 的位置]  ; 将 b 加载到 rbx 寄存器
   add rax, rbx              ; 执行加法
   jo overflow_label          ; 如果溢出则跳转到溢出处理标签
   // ... 将结果返回 ...
   ```

   `CodeStubAssembler` 中的相关 C++ 代码可能如下（简化示例）：

   ```c++
   // 在 CodeStubAssembler 中定义 Smi 加法 code stub 的生成逻辑
   void GenerateSmiAddStub() {
     Register lhs = rax; // 假设使用 rax 寄存器
     Register rhs = rbx; // 假设使用 rbx 寄存器

     // 从参数中加载 Smi 值
     Move(ArgumentAt(0), lhs);
     Move(ArgumentAt(1), rhs);

     // 执行 Smi 加法 (实际会更复杂，需要处理标签和溢出)
     Add(lhs, rhs);

     // ... 返回结果 ...
   }
   ```

3. **非 Smi 加法:** 如果 `a` 或 `b` 不是 Smi（例如是浮点数或对象），V8 可能会选择不同的 code stub 或更通用的执行路径来处理加法。`CodeStubAssembler` 也会负责生成处理这些更复杂情况的 code stubs。

**总结:**

`CodeStubAssembler` 是 V8 引擎中一个核心的底层工具，它负责生成高效的机器码来执行各种内部操作，这些操作是 JavaScript 代码执行的基础。尽管 JavaScript 开发者不会直接接触 `CodeStubAssembler`，但其生成的代码对 JavaScript 的性能至关重要。这个文件的第一部分主要关注提供构建 code stubs 的基础工具和操作 V8 内部类型的基本功能。后面的部分很可能会扩展到更具体的操作和优化策略。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第1部分，共12部分，请归纳一下它的功能

"""
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
    return (static_cast<uintptr_t>(constant_value) <=
            static_cast<uintptr_t>(Smi::kMaxValue))
               ? Int32TrueConstant()
               : Int32FalseConstant();
  }

  return UintPtrLessThanOrEqual(value, IntPtrConstant(Smi::kMaxValue));
}

TNode<Smi> CodeStubAssembler::SmiTag(TNode<IntPtrT> value) {
  int32_t constant_value;
  if (TryToInt32Constant(value, &constant_value) &&
      Smi::IsValid(constant_value)) {
    return SmiConstant(constant_value);
  }
  if (COMPRESS_POINTERS_BOOL) {
    return SmiFromInt32(TruncateIntPtrToInt32(value));
  }
  TNode<Smi> smi =
      BitcastWordToTaggedSigned(WordShl(value, SmiShiftBitsConstant()));
  return smi;
}

TNode<IntPtrT> CodeStubAssembler::SmiUntag(TNode<Smi> value) {
  intptr_t constant_value;
  if (TryToIntPtrConstant(value, &constant_value)) {
    return IntPtrConstant(constant_value >> (kSmiShiftSize + kSmiTagSize));
  }
  TNode<IntPtrT> raw_bits = BitcastTaggedToWordForTagAndSmiBits(value);
  if (COMPRESS_POINTERS_BOOL) {
    return ChangeInt32ToIntPtr(Word32SarShiftOutZeros(
        TruncateIntPtrToInt32(raw_bits), SmiShiftBitsConstant32()));
  }
  return Signed(WordSarShiftOutZeros(raw_bits, SmiShiftBitsConstant()));
}

TNode<Int32T> CodeStubAssembler::SmiToInt32(TNode<Smi> value) {
  if (COMPRESS_POINTERS_BOOL) {
    return Signed(Word32SarShiftOutZeros(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(value)),
        SmiShiftBitsConstant32()));
  }
  TNode<IntPtrT> result = SmiUntag(value);
  return TruncateIntPtrToInt32(result);
}

TNode<Uint32T> CodeStubAssembler::PositiveSmiToUint32(TNode<Smi> value) {
  DCHECK(SmiGreaterThanOrEqual(value, SmiConstant(0)));
  return Unsigned(SmiToInt32(value));
}

TNode<IntPtrT> CodeStubAssembler::PositiveSmiUntag(TNode<Smi> value) {
  return ChangePositiveInt32ToIntPtr(SmiToInt32(value));
}

TNode<Float64T> CodeStubAssembler::SmiToFloat64(TNode<Smi> value) {
  return ChangeInt32ToFloat64(SmiToInt32(value));
}

TNode<Smi> CodeStubAssembler::SmiMax(TNode<Smi> a, TNode<Smi> b) {
  return SelectConstant<Smi>(SmiLessThan(a, b), b, a);
}

TNode<Smi> CodeStubAssembler::SmiMin(TNode<Smi> a, TNode<Smi> b) {
  return SelectConstant<Smi>(SmiLessThan(a, b), a, b);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrAdd(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_overflow) {
  TNode<PairT<IntPtrT, BoolT>> pair = IntPtrAddWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrSub(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_overflow) {
  TNode<PairT<IntPtrT, BoolT>> pair = IntPtrSubWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrMul(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_overflow) {
  TNode<PairT<IntPtrT, BoolT>> pair = IntPtrMulWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrDiv(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_div_zero) {
  GotoIf(IntPtrEqual(b, IntPtrConstant(0)), if_div_zero);
  return IntPtrDiv(a, b);
}

TNode<IntPtrT> CodeStubAssembler::TryIntPtrMod(TNode<IntPtrT> a,
                                               TNode<IntPtrT> b,
                                               Label* if_div_zero) {
  GotoIf(IntPtrEqual(b, IntPtrConstant(0)), if_div_zero);
  return IntPtrMod(a, b);
}

TNode<Int32T> CodeStubAssembler::TryInt32Mul(TNode<Int32T> a, TNode<Int32T> b,
                                             Label* if_overflow) {
  TNode<PairT<Int32T, BoolT>> pair = Int32MulWithOverflow(a, b);
  TNode<BoolT> overflow = Projection<1>(pair);
  GotoIf(overflow, if_overflow);
  return Projection<0>(pair);
}

TNode<Smi> CodeStubAssembler::TrySmiAdd(TNode<Smi> lhs, TNode<Smi> rhs,
                                        Label* if_overflow) {
  if (SmiValuesAre32Bits()) {
    return BitcastWordToTaggedSigned(
        TryIntPtrAdd(BitcastTaggedToWordForTagAndSmiBits(lhs),
                     BitcastTaggedToWordForTagAndSmiBits(rhs), if_overflow));
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32AddWithOverflow(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(lhs)),
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(rhs)));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<Int32T> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(result));
  }
}

TNode<Smi> CodeStubAssembler::TrySmiSub(TNode<Smi> lhs, TNode<Smi> rhs,
                                        Label* if_overflow) {
  if (SmiValuesAre32Bits()) {
    TNode<PairT<IntPtrT, BoolT>> pair =
        IntPtrSubWithOverflow(BitcastTaggedToWordForTagAndSmiBits(lhs),
                              BitcastTaggedToWordForTagAndSmiBits(rhs));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<IntPtrT> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(result);
  } else {
    DCHECK(SmiValuesAre31Bits());
    TNode<PairT<Int32T, BoolT>> pair = Int32SubWithOverflow(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(lhs)),
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(rhs)));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<Int32T> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(result));
  }
}

TNode<Smi> CodeStubAssembler::TrySmiAbs(TNode<Smi> a, Label* if_overflow) {
  if (SmiValuesAre32Bits()) {
    TNode<PairT<IntPtrT, BoolT>> pair =
        IntPtrAbsWithOverflow(BitcastTaggedToWordForTagAndSmiBits(a));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<IntPtrT> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(result);
  } else {
    CHECK(SmiValuesAre31Bits());
    CHECK(IsInt32AbsWithOverflowSupported());
    TNode<PairT<Int32T, BoolT>> pair = Int32AbsWithOverflow(
        TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(a)));
    TNode<BoolT> overflow = Projection<1>(pair);
    GotoIf(overflow, if_overflow);
    TNode<Int32T> result = Projection<0>(pair);
    return BitcastWordToTaggedSigned(ChangeInt32ToIntPtr(result));
  }
}

TNode<Number> CodeStubAssembler::NumberMax(TNode<Number> a, TNode<Number> b) {
  // TODO(danno): This could be optimized by specifically handling smi cases.
  TVARIABLE(Number, result);
  Label done(this), greater_than_equal_a(this), greater_than_equal_b(this);
  GotoIfNumberGreaterThanOrEqual(a, b, &greater_than_equal_a);
  GotoIfNumberGreaterThanOrEqual(b, a, &greater_than_equal_b);
  result = NanConstant();
  Goto(&done);
  BIND(&greater_than_equal_a);
  result = a;
  Goto(&done);
  BIND(&greater_than_equal_b);
  result = b;
  Goto(&done);
  BIND(&done);
  return result.value();
}

TNode<Number> CodeStubAssembler::NumberMin(TNode<Number> a, TNode<Number> b) {
  // TODO(danno): This could be optimized by specifically handling smi cases.
  TVARIABLE(Number, result);
  Label done(this), greater_than_equal_a(this), greater_than_equal_b(this);
  GotoIfNumberGreaterThanOrEqual(a, b, &greater_than_equal_a);
  GotoIfNumberGreaterThanOrEqual(b, a, &greater_than_equal_b);
  result = NanConstant();
  Goto(&done);
  BIND(&greater_than_equal_a);
  result = b;
  Goto(&done);
  BIND(&greater_than_equal_b);
  result = a;
  Goto(&done);
  BIND(&done);
  return result.value();
}

TNode<Number> CodeStubAssembler::SmiMod(TNode<Smi> a, TNode<Smi> b) {
  TVARIABLE(Number, var_result);
  Label return_result(this, &var_result),
      return_minuszero(this, Label::kDeferred),
      return_nan(this, Label::kDeferred);

  // Untag {a} and {b}.
  TNode<Int32T> int_a = SmiToInt32(a);
  TNode<Int32T> int_b = SmiToInt32(b);

  // Return NaN if {b} is zero.
  GotoIf(Word32Equal(int_b, Int32Constant(0)), &return_nan);

  // Check if {a} is non-negative.
  Label if_aisnotnegative(this), if_aisnegative(this, Label::kDeferred);
  Branch(Int32LessThanOrEqual(Int32Constant(0), int_a), &if_aisnotnegative,
         &if_aisnegative);

  BIND(&if_aisnotnegative);
  {
    // Fast case, don't need to check any other edge cases.
    TNode<Int32T> r = Int32Mod(int_a, int_b);
    var_result = SmiFromInt32(r);
    Goto(&return_result);
  }

  BIND(&if_aisnegative);
  {
    if (SmiValuesAre32Bits()) {
      // Check if {a} is kMinInt and {b} is -1 (only relevant if the
      // kMinInt is actually representable as a Smi).
      Label join(this);
      GotoIfNot(Word32Equal(int_a, Int32Constant(kMinInt)), &join);
      GotoIf(Word32Equal(int_b, Int32Constant(-1)), &return_minuszero);
      Goto(&join);
      BIND(&join);
    }

    // Perform the integer modulus operation.
    TNode<Int32T> r = Int32Mod(int_a, int_b);

    // Check if {r} is zero, and if so return -0, because we have to
    // take the sign of the left hand side {a}, which is negative.
    GotoIf(Word32Equal(r, Int32Constant(0)), &return_minuszero);

    // The remainder {r} can be outside the valid Smi range on 32bit
    // architectures, so we cannot just say SmiFromInt32(r) here.
    var_result = ChangeInt32ToTagged(r);
    Goto(&return_result);
  }

  BIND(&return_minuszero);
  var_result = MinusZeroConstant();
  Goto(&return_result);

  BIND(&return_nan);
  var_result = NanConstant();
  Goto(&return_result);

  BIND(&return_result);
  return var_result.value();
}

TNode<Number> CodeStubAssembler::SmiMul(TNode<Smi> a, TNode<Smi> b) {
  TVARIABLE(Number, var_result);
  TVARIABLE(Float64T, var_lhs_float64);
  TVARIABLE(Float64T, var_rhs_float64);
  Label return_result(this, &var_result);

  // Both {a} and {b} are Smis. Convert them to integers and multiply.
  TNode<Int32T> lhs32 = SmiToInt32(a);
  TNode<Int32T> rhs32 = SmiToInt32(b);
  auto pair = Int32MulWithOverflow(lhs32, rhs32);

  TNode<BoolT> overflow = Projection<1>(pair);

  // Check if the multiplication overflowed.
  Label if_overflow(this, Label::kDeferred), if_notoverflow(this);
  Branch(overflow, &if_overflow, &if_notoverflow);
  BIND(&if_notoverflow);
  {
    // If the answer is zero, we may need to return -0.0, depending on the
    // input.
    Label answer_zero(this), answer_not_zero(this);
    TNode<Int32T> answer = Projection<0>(pair);
    TNode<Int32T> zero = Int32Constant(0);
    Branch(Word32Equal(answer, zero), &answer_zero, &answer_not_zero);
    BIND(&answer_not_zero);
    {
      var_result = ChangeInt32ToTagged(answer);
      Goto(&return_result);
    }
    BIND(&answer_zero);
    {
      TNode<Int32T> or_result = Word32Or(lhs32, rhs32);
      Label if_should_be_negative_zero(this), if_should_be_zero(this);
      Branch(Int32LessThan(or_result, zero), &if_should_be_negative_zero,
             &if_should_be_zero);
      BIND(&if_should_be_negative_zero);
      {
        var_result = MinusZeroConstant();
        Goto(&return_result);
      }
      BIND(&if_should_be_zero);
      {
        var_result = SmiConstant(0);
        Goto(&return_result);
      }
    }
  }
  BIND(&if_overflow);
  {
    var_lhs_float64 = SmiToFloat64(a);
    var_rhs_float64 = SmiToFloat64(b);
    TNode<Float64T> value =
        Float64Mul(var_lhs_float64.value(), var_rhs_float64.value());
    var_result = AllocateHeapNumberWithValue(value);
    Goto(&return_result);
  }

  BIND(&return_result);
  return var_result.value();
}

TNode<Smi> CodeStubAssembler::TrySmiDiv(TNode<Smi> dividend, TNode<Smi> divisor,
                                        Label* bailout) {
  // Both {a} and {b} are Smis. Bailout to floating point division if {divisor}
  // is zero.
  GotoIf(TaggedEqual(divisor, SmiConstant(0)), bailout);

  // Do floating point division if {dividend} is zero and {divisor} is
  // negative.
  Label dividend_is_zero(this), dividend_is_not_zero(this);
  Branch(TaggedEqual(dividend, SmiConstant(0)), &dividend_is_zero,
         &dividend_is_not_zero);

  BIND(&dividend_is_zero);
  {
    GotoIf(SmiLessThan(divisor, SmiConstant(0)), bailout);
    Goto(&dividend_is_not_zero);
  }
  BIND(&dividend_is_not_zero);

  TNode<Int32T> untagged_divisor = SmiToInt32(divisor);
  TNode<Int32T> untagged_dividend = SmiToInt32(dividend);

  // Do floating point division if {dividend} is kMinInt (or kMinInt - 1
  // if the Smi size is 31) and {divisor} is -1.
  Label divisor_is_minus_one(this), divisor_is_not_minus_one(this);
  Branch(Word32Equal(untagged_divisor, Int32Constant(-1)),
         &divisor_is_minus_one, &divisor_is_not_minus_one);

  BIND(&divisor_is_minus_one);
  {
    GotoIf(Word32Equal(
               untagged_dividend,
               Int32Constant(kSmiValueSize == 32 ? kMinInt : (kMinInt >> 1))),
           bailout);
    Goto(&divisor_is_not_minus_one);
  }
  BIND(&divisor_is_not_minus_one);

  TNode<Int32T> untagged_result = Int32Div(untagged_dividend, untagged_divisor);
  TNode<Int32T> truncated = Int32Mul(untagged_result, untagged_divisor);

  // Do floating point division if the remainder is not 0.
  GotoIf(Word32NotEqual(untagged_dividend, truncated), bailout);

  return SmiFromInt32(untagged_result);
}

TNode<Smi> CodeStubAssembler::SmiLexicographicCompare(TNode<Smi> x,
                                                      TNode<Smi> y) {
  TNode<ExternalReference> smi_lexicographic_compare =
      ExternalConstant(ExternalReference::smi_lexicographic_compare_function());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  return CAST(CallCFunction(smi_lexicographic_compare, MachineType::AnyTagged(),
                            std::make_pair(MachineType::Pointer(), isolate_ptr),
                            std::make_pair(MachineType::AnyTagged(), x),
                            std::make_pair(MachineType::AnyTagged(), y)));
}

TNode<Object> CodeStubAssembler::GetCoverageInfo(
    TNode<SharedFunctionInfo> sfi) {
  TNode<ExternalReference> f =
      ExternalConstant(ExternalReference::debug_get_coverage_info_function());
  TNode<ExternalReference> isolate_ptr =
      ExternalConstant(ExternalReference::isolate_address());
  return CAST(CallCFunction(f, MachineType::AnyTagged(),
                            std::make_pair(MachineType::Pointer(), isolate_ptr),
                            std::make_pair(MachineType::TaggedPointer(), sfi)));
}

TNode<Int32T> CodeStubAssembler::TruncateWordToInt32(TNode<WordT> value) {
  if (Is64()) {
    return TruncateInt64ToInt32(ReinterpretCast<Int64T>(value));
  }
  return ReinterpretCast<Int32T>(value);
}

TNode<Int32T> CodeStubAssembler::TruncateIntPtrToInt32(TNode<IntPtrT> value) {
  if (Is64()) {
    return TruncateInt64ToInt32(ReinterpretCast<Int64T>(value));
  }
  return ReinterpretCast<Int32T>(value);
}

TNode<Word32T> CodeStubAssembler::TruncateWord64ToWord32(TNode<Word64T> value) {
  return TruncateInt64ToInt32(ReinterpretCast<Int64T>(value));
}

TNode<BoolT> CodeStubAssembler::TaggedIsSmi(TNode<MaybeObject> a) {
  static_assert(kSmiTagMask < kMaxUInt32);
  return Word32Equal(
      Word32And(TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(a)),
                Int32Constant(kSmiTagMask)),
      Int32Constant(0));
}

TNode<BoolT> CodeStubAssembler::TaggedIsNotSmi(TNode<MaybeObject> a) {
  return Word32BinaryNot(TaggedIsSmi(a));
}

TNode<BoolT> CodeStubAssembler::TaggedIsPositiveSmi(TNode<Object> a) {
#if defined(V8_HOST_ARCH_32_BIT) || defined(V8_31BIT_SMIS_ON_64BIT_ARCH)
  return Word32Equal(
      Word32And(
          TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(a)),
          Uint32Constant(static_cast<uint32_t>(kSmiTagMask | kSmiSignMask))),
      Int32Constant(0));
#else
  return WordEqual(WordAnd(BitcastTaggedToWordForTagAndSmiBits(a),
                           IntPtrConstant(kSmiTagMask | kSmiSignMask)),
                   IntPtrConstant(0));
#endif
}

TNode<BoolT> CodeStubAssembler::WordIsAligned(TNode<WordT> word,
                                              size_t alignment) {
  DCHECK(base::bits::IsPowerOfTwo(alignment));
  DCHECK_LE(alignment, kMaxUInt32);
  return Word32Equal(
      Int32Constant(0),
      Word32And(TruncateWordToInt32(word),
                Uint32Constant(static_cast<uint32_t>(alignment) - 1)));
}

#if DEBUG
void CodeStubAssembler::Bind(Label* label, AssemblerDebugInfo debug_info) {
  CodeAssembler::Bind(label, debug_info);
}
#endif  // DEBUG

void CodeStubAssembler::Bind(Label* label) { CodeAssembler::Bind(label); }

TNode<Float64T> CodeStubAssembler::LoadDoubleWithHoleCheck(
    TNode<FixedDoubleArray> array, TNode<IntPtrT> index, Label* if_hole) {
  return LoadFixedDoubleArrayElement(array, index, if_hole);
}

void CodeStubAssembler::BranchIfJSReceiver(TNode<Object> object, Label* if_true,
                                           Label* if_false) {
  GotoIf(TaggedIsSmi(object), if_false);
  static_assert(LAST_JS_RECEIVER_TYPE == LAST_TYPE);
  Branch(IsJSReceiver(CAST(object)), if_true, if_false);
}

void CodeStubAssembler::GotoIfForceSlowPath(Label* if_true) {
#ifdef V8_ENABLE_FORCE_SLOW_PATH
  bool enable_force_slow_path = true;
#else
  bool enable_force_slow_path = false;
#endif

  Label done(this);
  // Use UniqueInt32Constant instead of BoolConstant here in order to ensure
  // that the graph structure does not depend on the value of the predicate
  // (BoolConstant uses cached nodes).
  GotoIf(UniqueInt32Constant(!enable_force_slow_path), &done);
  {
    // This optional block is used behind a static check and we rely
    // on the dead code elimination to remove it. We generate builtins this
    // way in order to ensure that builtins PGO profiles are agnostic to
    // V8_ENABLE_FORCE_SLOW_PATH value.
    const TNode<ExternalReference> force_slow_path_addr =
        ExternalConstant(ExternalReference::force_slow_path(isolate()));
    const TNode<Uint8T> force_slow = Load<Uint8T>(force_slow_path_addr);
    Branch(force_slow, if_true, &done);
  }
  BIND(&done);
}

TNode<HeapObject> CodeStubAssembler::AllocateRaw(TNode<IntPtrT> size_in_bytes,
                                                 AllocationFlags flags,
                                                 TNode<RawPtrT> top_address,
                                                 TNode<RawPtrT> limit_address) {
  Label if_out_of_memory(this, Label::kDeferred);

  // TODO(jgruber,jkummerow): Extract the slow paths (= probably everything
  // but bump pointer allocation) into a builtin to save code space. The
  // size_in_bytes check may be moved there as well since a non-smi
  // size_in_bytes probably doesn't fit into the bump pointer region
  // (double-check that).

  intptr_t size_in_bytes_constant;
  bool size_in_bytes_is_constant = false;
  if (TryToIntPtrConstant(size_in_bytes, &size_in_bytes_constant)) {
    size_in_bytes_is_constant = true;
    CHECK(Internals::IsValidSmi(size_in_bytes_constant));
    CHECK_GT(size_in_bytes_constant, 0);
  } else {
    GotoIfNot(IsValidPositiveSmi(size_in_bytes), &if_out_of_memory);
  }

  TNode<RawPtrT> top = Load<RawPtrT>(top_address);
  TNode<RawPtrT> limit = Load<RawPtrT>(limit_address);

  // If there's not enough space, call the runtime.
  TVARIABLE(Object, result);
  Label runtime_call(this, Label::kDeferred), no_runtime_call(this), out(this);

  bool needs_double_alignment = flags & AllocationFlag::kDoubleAlignment;

  Label next(this);
  GotoIf(IsRegularHeapObjectSize(size_in_bytes), &next);

  TNode<Smi> runtime_flags = SmiConstant(
      Smi::FromInt(AllocateDoubleAlignFlag::encode(needs_double_alignment)));
  result = CallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                       SmiTag(size_in_bytes), runtime_flags);
  Goto(&out);

  BIND(&next);

  TVARIABLE(IntPtrT, adjusted_size, size_in_bytes);

  if (needs_double_alignment) {
    Label next(this);
    GotoIfNot(WordAnd(top, IntPtrConstant(kDoubleAlignmentMask)), &next);

    adjusted_size = IntPtrAdd(size_in_bytes, IntPtrConstant(4));
    Goto(&next);

    BIND(&next);
  }

  adjusted_size = AlignToAllocationAlignment(adjusted_size.value());
  TNode<IntPtrT> new_top =
      IntPtrAdd(UncheckedCast<IntPtrT>(top), adjusted_size.value());

  Branch(UintPtrGreaterThanOrEqual(new_top, limit), &runtime_call,
         &no_runtime_call);

  BIND(&runtime_call);
  {
    TNode<Smi> runtime_flags = SmiConstant(
        Smi::FromInt(AllocateDoubleAlignFlag::encode(needs_double_alignment)));
    if (flags & AllocationFlag::kPretenured) {
      result =
          CallRuntime(Runtime::kAllocateInOldGeneration, NoContextConstant(),
                      SmiTag(size_in_bytes), runtime_flags);
    } else {
      result =
          CallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                      SmiTag(size_in_bytes), runtime_flags);
    }
    Goto(&out);
  }

  // When there is enough space, return `top' and bump it up.
  BIND(&no_runtime_call);
  {
    StoreNoWriteBarrier(MachineType::PointerRepresentation(), top_address,
                        new_top);

    TVARIABLE(IntPtrT, address, UncheckedCast<IntPtrT>(top));

    if (needs_double_alignment) {
      Label next(this);
      GotoIf(IntPtrEqual(adjusted_size.value(), size_in_bytes), &next);

      // Store a filler and increase the address by 4.
      StoreNoWriteBarrier(MachineRepresentation::kTagged, top,
                          OnePointerFillerMapConstant());
      address = IntPtrAdd(UncheckedCast<IntPtrT>(top), IntPtrConstant(4));
      Goto(&next);

      BIND(&next);
    }

    result = BitcastWordToTagged(
        IntPtrAdd(address.value(), IntPtrConstant(kHeapObjectTag)));
    Goto(&out);
  }

  if (!size_in_bytes_is_constant) {
    BIND(&if_out_of_memory);
    CallRuntime(Runtime::kFatalProcessOutOfMemoryInAllocateRaw,
                NoContextConstant());
    Unreachable();
  }

  BIND(&out);
  if (v8_flags.sticky_mark_bits && (flags & AllocationFlag::kPretenured)) {
    CSA_DCHECK(this, IsMarked(result.value()));
  }
  return UncheckedCast<HeapObject>(result.value());
}

TNode<HeapObject> CodeStubAssembler::AllocateRawUnaligned(
    TNode<IntPtrT> size_in_bytes, AllocationFlags flags,
    TNode<RawPtrT> top_address, TNode<RawPtrT> limit_address) {
  DCHECK_EQ(flags & AllocationFlag::kDoubleAlignment, 0);
  return AllocateRaw(size_in_bytes, flags, top_address, limit_address);
}

TNode<HeapObject> CodeStubAssembler::AllocateRawDoubleAligned(
    TNode<IntPtrT> size_in_bytes, AllocationFlags flags,
    TNode<RawPtrT> top_address, TNode<RawPtrT> limit_address) {
#if defined(V8_HOST_ARCH_32_BIT)
  return AllocateRaw(size_in_bytes, flags | AllocationFlag::kDoubleAlignment,
                     top_address, limit_address);
#elif defined(V8_HOST_ARCH_64_BIT)
#ifdef V8_COMPRESS_POINTERS
// TODO(ishell, v8:8875): Consider using aligned allocations once the
// allocation alignment inconsistency is fixed. For now we keep using
// unaligned access since both x64 and arm64 architectures (where pointer
// compression is supported) allow unaligned access to doubles and full words.
#endif  // V8_COMPRESS_POINTERS
  // Allocation on 64 bit machine is naturally double aligned
  return AllocateRaw(size_in_bytes, flags & ~AllocationFlag::kDoubleAlignment,
                     top_address, limit_address);
#else
#error Architecture not supported
#endif
}

TNode<HeapObject> CodeStubAssembler::AllocateInNewSpace(
    TNode<IntPtrT> size_in_bytes, AllocationFlags flags) {
  DCHECK(flags == AllocationFlag::kNone ||
         flags == AllocationFlag::kDoubleAlignment);
  CSA_DCHECK(this, IsRegularHeapObjectSize(size_in_bytes));
  return Allocate(size_in_bytes, flags);
}

TNode<HeapObject> CodeStubAssembler::Allocate(TNode<IntPtrT> size_in_bytes,
                                              AllocationFlags flags) {
  Comment("Allocate");
  if (v8_flags.single_generation) flags |= AllocationFlag::kPretenured;
  bool const new_space = !(flags & AllocationFlag::kPretenured);
  if (!(flags & AllocationFlag::kDoubleAlignment)) {
    TNode<HeapObject> heap_object =
        OptimizedAllocate(size_in_bytes, new_space ? AllocationType::kYoung
                                                   : AllocationType::kOld);
    if (v8_flags.sticky_mark_bits && !new_space) {
      CSA_DCHECK(this, IsMarked(heap_object));
    }
    return heap_object;
  }
  TNode<ExternalReference> top_address = ExternalConstant(
      new_space
          ? ExternalReference::new_space_allocation_top_address(isolate())
          : ExternalReference::old_space_allocation_top_address(isolate()));

#ifdef DEBUG
  // New space is optional and if disabled both top and limit return
  // kNullAddress.
  if (ExternalReference::new_space_allocation_top_address(isolate())
          .address() != kNullAddress) {
    Address raw_top_address =
        ExternalReference::new_space_allocation_top_address(isolate())
            .address();
    Address raw_limit_address =
        ExternalReference::new_space_allocation_limit_address(isolate())
            .address();

    CHECK_EQ(kSystemPointerSize, raw_limit_address - raw_top_address);
  }

  DCHECK_EQ(kSystemPointerSize,
            ExternalReference::old_space_allocation_limit_address(isolate())
                    .address() -
                ExternalReference::old_space_allocation_top_address(isolate())
                    .address());
#endif

  TNode<IntPtrT> limit_address =
      IntPtrAdd(ReinterpretCast<IntPtrT>(top_address),
                IntPtrConstant(kSystemPointerSize));

  if (flags & AllocationFlag::kDoubleAlignment) {
    return AllocateRawDoubleAligned(size_in_bytes, flags,
                                    ReinterpretCast<RawPtrT>(top_address),
                                    ReinterpretCast<RawPtrT>(limit_address));
  } else {
    return AllocateRawUnaligned(size_in_bytes, flags,
                                ReinterpretCast<RawPtrT>(top_address),
                                ReinterpretCast<RawPtrT>(limit_address));
  }
}

TNode<HeapObject> CodeStubAssembler::AllocateInNewSpace(int size_in_bytes,
                                                        AllocationFlags flags) {
  CHECK(flags == AllocationFlag::kNone ||
        flags == AllocationFlag::kDoubleAlignment);
  DCHECK_LE(size_in_bytes, kMaxRegularHeapObjectSize);
  return CodeStubAssembler::Allocate(IntPtrConstant(size_in_bytes), flags);
}

TNode<HeapObject> CodeStubAssembler::Allocate(int size_in_bytes,
                                              AllocationFlags flags) {
  return CodeStubAssembler::Allocate(IntPtrConstant(size_in_bytes), flags);
}

TNode<BoolT> CodeStubAssembler::IsRegularHeapObjectSize(TNode<IntPtrT> size) {
  return UintPtrLessThanOrEqual(size,
                                IntPtrConstant(kMaxRegularHeapObjectSize));
}

void CodeStubAssembler::BranchIfToBooleanIsTrue(TNode<Object> value,
                                                Label* if_true,
                                                Label* if_false) {
  Label if_smi(this, Label::kDeferred), if_heapnumber(this, Label::kDeferred),
      if_bigint(this, Label::kDeferred);

  // Check if {value} is a Smi.
  GotoIf(TaggedIsSmi(value), &if_smi);

  TNode<HeapObject> value_heapobject = CAST(value);

#if V8_STATIC_ROOTS_BOOL
  // Check if {object} is a falsey root or the true value.
  // Undefined is the first root, so it's the smallest possible pointer
  // value, which means we don't have to subtract it for the range check.
  ReadOnlyRoots roots(isolate());
  static_assert(StaticReadOnlyRoot::kFirstAllocatedRoot ==
                StaticReadOnlyRoot::kUndefinedValue);
  static_assert(StaticReadOnlyRoot::kUndefinedValue + sizeof(Undefined) ==
                StaticReadOnlyRoot::kNullValue);
  static_assert(StaticReadOnlyRoot::kNullValue + sizeof(Null) ==
                StaticReadOnlyRoot::kempty_string);
  static_assert(StaticReadOnlyRoot::kempty_string +
                    SeqOneByteString::SizeFor(0) ==
                StaticReadOnlyRoot::kFalseValue);
  static_assert(StaticReadOnlyRoot::kFalseValue + sizeof(False) ==
                StaticReadOnlyRoot::kTrueValue);
  TNode<Word32T> object_as_word32 =
      TruncateIntPtrToInt32(BitcastTaggedToWord(value_heapobject));
  TNode<Word32T> true_as_word32 = Int32Constant(StaticReadOnlyRoot::kTrueValue);
  GotoIf(Uint32LessThan(object_as_word32, true_as_word32), if_false);
  GotoIf(Word32Equal(object_as_word32, true_as_word32), if_true);
#else
  // Rule out false {value}.
  GotoIf(TaggedEqual(value, FalseConstant()), if_false);

  // Fast path on true {value}.
  GotoIf(TaggedEqual(value, TrueConstant()), if_true);

  // Check if {value} is the empty string.
  GotoIf(IsEmptyString(value_heapobject), if_false);
#endif

  // The {value} is a HeapObject, load its map.
  TNode<Map> value_map = LoadMap(value_heapobject);

  // Only null, undefined and document.all have the undetectable bit set,
  // so we can return false immediately when that bit is set. With static roots
  // we've already checked for null and undefined, but we need to check the
  // undetectable bit for document.all anyway on the common path and it doesn't
  // help to check the undetectable object protector in builtins since we can't
  // deopt.
  GotoIf(IsUndetectableMap(value_map), if_false);

  // We still need to handle numbers specially, but all other {value}s
  // that make it here yield true.
  GotoIf(IsHeapNumberMap(value_map), &if_heapnumber);
  Branch(IsBigInt(value_heapobject), &if_bigint, if_true);

  BIND(&if_smi);
  {
    // Check if the Smi {value} is a zero.
    Branch(TaggedEqual(value, SmiConstant(0)), if_false, if_true);
  }

  BIND(&if_heapnumber);
  {
    // Load the floating point value of {value}.
    TNode<Float64T> value_value = LoadObjectField<Float64T>(
        value_heapobject, offsetof(HeapNumber, value_));

    // Check if the floating point {value} is neither 0.0, -0.0 nor NaN.
    Branch(Float64LessThan(Float64Constant(0.0), Float64Abs(value_value)),
           if_true, if_false);
  }

  BIND(&if_bigint);
  {
    TNode<BigInt> bigint = CAST(value);
    TNode<Word32T> bitfield = LoadBigIntBitfield(bigint);
    TNode<Uint32T> length = DecodeWord32<BigIntBase::LengthBits>(bitfield);
    Branch(Word32Equal(length, Int32Constant(0)), if_false, if_true);
  }
}

TNode<RawPtrT> CodeStubAssembler::LoadSandboxedPointerFromObject(
    TNode<HeapObject> object, TNode<IntPtrT> field_offset) {
#ifdef V8_ENABLE_SANDBOX
  return ReinterpretCast<RawPtrT>(
      LoadObjectField<SandboxedPtrT>(object, field_offset));
#else
  return LoadObjectField<RawPtrT>(object, field_offset);
#endif  // V8_ENABLE_SANDBOX
}

void CodeStubAssembler::StoreSandboxedPointerToObject(TNode<HeapObject> object,
                                                      TNode<IntPtrT> offset,
                                                      TNode<RawPtrT> pointer) {
#ifdef V8_ENABLE_SANDBOX
  TNode<SandboxedPtrT> sbx_ptr = ReinterpretCast<SandboxedPtrT>(pointer);

  // Ensure pointer points into the sandbox.
  TNode<ExternalReference> sandbox_base_address =
      ExternalConstant(ExternalReference::sandbox_base_address());
  TNode<ExternalReference> sandbox_end_address =
      ExternalConstant(ExternalReference::sandbox_end_address());
  TNode<UintPtrT> sandbox_base = Load<UintPtrT>(sandbox_base_address);
  TNode<UintPtrT> sandbox_end = Load<UintPtrT>(sandbox_end_address);
  CSA_CHECK(this, UintPtrGreaterThanOrEqual(sbx_ptr, sandbox_base));
  CSA_CHECK(this, UintPtrLessThan(sbx_ptr, sandbox_end));

  StoreObjectFieldNoWriteBarrier<SandboxedPtrT>(object, offset, sbx_ptr);
#else
  StoreObjectFieldNoWriteBarrier<RawPtrT>(object, offset, pointer);
#endif  // V8_ENABLE_SANDBOX
}

TNode<RawPtrT> CodeStubAssembler::EmptyBackingStoreBufferConstant() {
#ifdef V8_ENABLE_SANDBOX
  // TODO(chromium:1218005) consider creating a LoadSandboxedPointerConstant()
  // if more of these constants are required later on.
  TNode<ExternalReference> empty_backing_store_buffer =
      ExternalConstant(ExternalReference::empty_backing_store_buffer());
  return Load<RawPtrT>(empty_backing_store_buffer);
#else
  return ReinterpretCast<RawPtrT>(IntPtrConstant(0));
#endif  // V8_ENABLE_SANDBOX
}

TNode<UintPtrT> CodeStubAssembler::LoadBoundedSizeFromObject(
    TNode<Hea
"""


```