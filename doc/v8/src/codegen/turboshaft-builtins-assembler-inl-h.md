Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Initial Scan for Purpose:**  The filename itself gives a strong clue: `turboshaft-builtins-assembler-inl.h`. "Turboshaft" refers to V8's newer compiler pipeline. "Builtins" suggests it's related to core, pre-defined functions. "Assembler" implies it helps generate low-level code. ".inl.h" signifies it's an inline header, likely containing template definitions.

2. **Copyright and Includes:**  The copyright notice confirms it's a V8 file. The `#include` directives point to various Turboshaft and general V8 components:
    * `globals.h`:  Fundamental V8 definitions.
    * `access-builder.h`, `assembler.h`, `machine-lowering-reducer-inl.h`, `operation-matcher.h`, `runtime-call-descriptors.h`, `sidetable.h`: These are clearly Turboshaft-specific, indicating this file is deeply involved in the Turboshaft compilation process.
    * `bytecode-register.h`:  Suggests a connection to V8's bytecode interpreter.
    * `elements-kind.h`:  Relates to how JavaScript arrays are stored internally.

3. **`DEFINE_TURBOSHAFT_ALIASES()`:** This macro simplifies the code by creating shorter aliases for common Turboshaft types. This is a common practice in large C++ projects to improve readability. Recognizing the `V<T>`, `ConstOrV<T>`, `Label`, etc., helps understand the basic data types being manipulated.

4. **`BUILTIN_REDUCER(name)`:** This macro is clearly for defining "reducers."  The `TURBOSHAFT_REDUCER_BOILERPLATE` part suggests it's part of the Turboshaft compiler's internal structure, likely for code transformations or optimizations.

5. **Namespace `v8::internal::detail` and `BuiltinArgumentsTS`:** The `detail` namespace often houses internal implementation details. `BuiltinArgumentsTS` is a template class likely designed to handle arguments passed to built-in functions. The methods like `GetLengthWithReceiver()`, `AtIndex()`, and the `Iterator` class strongly suggest it's abstracting the process of accessing arguments on the stack.

6. **Reducer Classes (`FeedbackCollectorReducer`, `NoFeedbackCollectorReducer`, `BuiltinsReducer`):** These are central to the file's functionality. The naming is quite descriptive:
    * `FeedbackCollectorReducer`:  Deals with collecting feedback information during execution, used for optimizations. Keywords like "FeedbackVector," "LoadFeedbackVectorSlot," and "UpdateFeedback" are key.
    * `NoFeedbackCollectorReducer`:  A no-op version, likely used when feedback collection isn't needed or is disabled.
    * `BuiltinsReducer`:  Contains common logic for implementing built-in functions within the Turboshaft pipeline. `EmitBuiltinProlog`, `EmitEpilog`, `PopAndReturn`, and the various conversion functions (`TruncateTaggedToWord32`, `TaggedToWord32OrBigIntImpl`) are important. The comments in `PopAndReturn` are particularly insightful about its purpose.

7. **`TurboshaftBuiltinsAssembler`:** This is the main class, inheriting from `TSAssembler`. The multiple template parameters (`Reducer`, `BuiltinsReducer`, `FeedbackReducer`, etc.) indicate a layered or modular design for the assembler.

8. **Connecting to JavaScript (Hypothesis and Verification):** Based on the names and functionality, the connection to JavaScript is through the *implementation* of built-in JavaScript functions. Think of functions like `Array.push()`, `Math.sin()`, `String.prototype.substring()`, etc. These built-ins are implemented at a lower level, and this file provides tools for that implementation within the Turboshaft compiler.

9. **Example Generation (JavaScript and C++ Analog):**
    * **JavaScript:**  Simple examples that would trigger built-in calls are easy to create.
    * **C++ (Conceptual):** The C++ examples are more about illustrating *how* the assembler might be used *within* V8's codebase, rather than something a typical user would write. Focus on demonstrating the usage of the provided classes and methods.

10. **Logic Reasoning (Example):** Choose a relatively straightforward piece of logic, like `TaggedToWord32OrBigIntImpl`, and walk through its control flow. Identify the assumptions (e.g., the input `value` is a JavaScript value) and the outputs (a 32-bit integer or potentially transitioning to BigInt handling).

11. **Common Programming Errors (Thinking like a V8 Developer):**  Consider the constraints and potential pitfalls of working at this low level. Incorrectly handling tagged values, forgetting write barriers, or making assumptions about data types are all potential issues.

12. **Review and Refine:** After drafting the explanation, reread the code and the explanation to ensure consistency and accuracy. Add details where needed and clarify any confusing points. For instance, initially, I might not have fully grasped the significance of `PopAndReturn`, but the comments within the code itself provided the crucial context.

This iterative process of scanning, identifying key components, making hypotheses, and then verifying those hypotheses through closer inspection of the code and comments is key to understanding complex source code like this. The naming conventions used by the V8 team are also a significant help.
`v8/src/codegen/turboshaft-builtins-assembler-inl.h`是V8 JavaScript引擎中Turboshaft编译管道的一部分，它定义了一个用于生成内置函数（built-ins）汇编代码的内联头文件。 由于文件以 `.h` 结尾而不是 `.tq`，它不是 Torque 源代码，而是标准的 C++ 头文件。

**功能列举：**

1. **定义 Turboshaft 汇编器别名：**  使用宏 `DEFINE_TURBOSHAFT_ALIASES()` 定义了 Turboshaft 汇编器中常用的类型别名，例如 `V<T>` (表示一个值)，`ConstOrV<T>` (表示常量或值)，`Label` (表示代码标签) 等。这提高了代码的可读性。

2. **定义 Builtin Reducer 宏：**  宏 `BUILTIN_REDUCER(name)` 用于简化定义内置函数的 "reducer" 类。Reducer 是 Turboshaft 编译管道中的一个概念，用于执行代码转换和优化。

3. **提供访问内置函数参数的工具：**  模板类 `BuiltinArgumentsTS` 提供了一种方便的方式来访问传递给内置函数的参数。它可以获取参数的数量，并根据索引访问特定的参数。它还提供了一个迭代器来遍历所有参数。

4. **实现反馈收集机制（FeedbackCollector）：**  模板类 `FeedbackCollectorReducer` 提供了一组方法来收集和更新反馈向量（Feedback Vector）。反馈向量用于存储关于代码执行情况的信息，以便 Turboshaft 可以进行更有效的优化。这包括：
   - 合并和覆盖反馈信息 (`CombineFeedback`, `OverwriteFeedback`)
   - 加载和存储反馈向量中的槽位 (`LoadFeedbackVectorSlot`, `StoreFeedbackVectorSlot`)
   - 设置反馈槽位和反馈向量 (`SetFeedbackSlot`, `SetFeedbackVector`)
   - 根据是否开启 JIT-less 模式加载反馈向量 (`LoadFeedbackVectorOrUndefinedIfJitless`)
   - 更新反馈信息 (`UpdateFeedback`)

5. **提供无反馈收集器的选择 (NoFeedbackCollector)：** 模板类 `NoFeedbackCollectorReducer` 提供了一个不执行任何反馈收集的版本。这可能用于某些不需要或无法收集反馈的内置函数。

6. **实现内置函数的基础功能 (BuiltinsReducer)：**  模板类 `BuiltinsReducer` 提供了构建内置函数的基本框架和实用工具，包括：
   - 发射内置函数的序言和尾声 (`EmitBuiltinProlog`, `EmitEpilog`)，处理异常情况。
   - 获取 JavaScript 上下文参数 (`JSContextParameter`)。
   - 执行栈检查 (`PerformStackCheck`)。
   - 执行弹出参数并返回的操作 (`PopAndReturn`)，这通常用于 CSA/Torque 内置函数。
   - 将 Tagged 值转换为 32 位整数 (`TruncateTaggedToWord32`)，并处理 BigInt。
   - 判断是否为 BigInt 类型 (`IsBigIntInstanceType`, `IsSmallBigInt`)。
   - 进行内存对齐 (`AlignTagged`)。
   - 计算元素的偏移量 (`ElementOffsetFromIndex`)。
   - 实现 Tagged 值到 Word32 或 BigInt 的转换逻辑 (`TaggedToWord32OrBigIntImpl`)，处理数字、奇数值 (oddball) 和需要转换的情况。

7. **定义 Turboshaft 内置函数汇编器类：**  模板类 `TurboshaftBuiltinsAssembler` 是一个集成了上述功能的汇编器，它基于 Turboshaft 的 `TSAssembler`。

**与 JavaScript 功能的关系和 JavaScript 示例：**

这个头文件中的代码与 V8 引擎内部的实现密切相关，特别是与内置函数的编译和执行有关。内置函数是 JavaScript 语言提供的核心功能，例如 `Array.prototype.push`、`Math.sin`、`String.prototype.substring` 等。

当 JavaScript 代码调用这些内置函数时，V8 的 Turboshaft 编译器会使用这里定义的汇编器来生成高效的机器代码。

**JavaScript 示例：**

```javascript
// 调用 Array.prototype.push，这是一个内置函数
const arr = [1, 2, 3];
arr.push(4);
console.log(arr); // 输出: [1, 2, 3, 4]

// 调用 Math.sin，也是一个内置函数
const angle = Math.PI / 2;
const sineValue = Math.sin(angle);
console.log(sineValue); // 输出: 1

// 调用 String.prototype.substring
const str = "hello";
const sub = str.substring(1, 4);
console.log(sub); // 输出: ell
```

当 V8 编译这些 JavaScript 代码时，对于 `arr.push(4)`、`Math.sin(angle)` 和 `str.substring(1, 4)` 的调用，Turboshaft 编译器会使用 `TurboshaftBuiltinsAssembler` 来生成相应的机器码，这些机器码实现了这些内置函数的具体逻辑。

**代码逻辑推理和假设输入输出：**

考虑 `BuiltinsReducer::TruncateTaggedToWord32` 函数，它尝试将一个 JavaScript 值转换为 32 位整数。

**假设输入：**
- `context`: 当前的 JavaScript 执行上下文。
- `value`:  一个 JavaScript 值，可以是 Smi (小整数)、HeapNumber (堆上的数字对象)、BigInt 或其他需要转换的对象。

**可能的输出：**
- 如果 `value` 是一个 Smi，则直接解包 Smi 并返回其 32 位表示。
- 如果 `value` 是一个 HeapNumber，则加载其浮点数值，并截断为 32 位整数返回。
- 如果 `value` 是一个 BigInt，则可能会执行不同的处理（在这个简化的函数中，它会跳转到 `if_bigint` 标签，虽然该标签在本例中未明确定义）。
- 如果 `value` 是其他类型，则可能需要调用运行时函数将其转换为数字，然后再进行截断。

**例如，如果输入 `value` 是 Smi(10)：**

1. `TruncateTaggedToWord32` 会检查 `value` 是否为 Smi。
2. 条件成立，会执行 `__ UntagSmi(V<Smi>::Cast(value))`，将 Smi 解包为 32 位整数 `10`。
3. 跳转到 `is_number` 标签，返回 `10`。

**如果输入 `value` 是一个 HeapNumber，其浮点值为 `3.14`：**

1. `TruncateTaggedToWord32` 会检查 `value` 是否为 Smi，不成立。
2. 将 `value` 转换为 `HeapObject`。
3. 加载 `value` 的 Map，并检查是否为 `HeapNumberMap`。
4. 条件成立，加载 HeapNumber 的浮点值 `3.14`。
5. 调用 `__ JSTruncateFloat64ToWord32(value_float64)`，将 `3.14` 截断为 `3`。
6. 跳转到 `is_number` 标签，返回 `3`。

**涉及用户常见的编程错误：**

虽然这个头文件是 V8 引擎内部的代码，但它处理的逻辑与用户在 JavaScript 编程中可能遇到的错误有关，例如：

1. **类型错误：**  在 JavaScript 中，对非数字类型的值执行数学运算或位运算可能会导致意外的结果或错误。例如：
   ```javascript
   console.log("5" + 2); // 输出 "52"，字符串拼接
   console.log("5" * 2); // 输出 10，字符串被转换为数字
   console.log(null + 5); // 输出 5，null 被转换为 0
   ```
   `TruncateTaggedToWord32` 这样的函数就需要处理各种可能的输入类型，并在必要时进行转换，这反映了 JavaScript 的动态类型特性。

2. **精度损失：** 将浮点数截断为整数会丢失小数部分。用户可能没有意识到这一点，导致计算结果不准确。
   ```javascript
   console.log(Math.trunc(3.9)); // 输出 3
   console.log(parseInt(3.9));   // 输出 3
   ```
   `__ JSTruncateFloat64ToWord32` 就体现了这个截断的过程。

3. **BigInt 的使用不当：**  虽然 BigInt 允许表示任意精度的整数，但在与普通数字混合运算时需要显式转换，否则会抛出 `TypeError`。
   ```javascript
   const bigInt = 9007199254740991n;
   // console.log(bigInt + 1); // TypeError: Cannot mix BigInt and other types
   console.log(bigInt + BigInt(1));
   ```
   `TruncateTaggedToWord32` 中对 BigInt 的处理反映了这种类型差异。

总而言之，`v8/src/codegen/turboshaft-builtins-assembler-inl.h` 是 V8 引擎中一个关键的组件，它为 Turboshaft 编译器提供了生成高效内置函数机器码的能力，并且其内部的逻辑与 JavaScript 的类型系统、运算规则以及用户可能遇到的编程错误息息相关。

Prompt: 
```
这是目录为v8/src/codegen/turboshaft-builtins-assembler-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/turboshaft-builtins-assembler-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2024 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_CODEGEN_TURBOSHAFT_BUILTINS_ASSEMBLER_INL_H_
#define V8_CODEGEN_TURBOSHAFT_BUILTINS_ASSEMBLER_INL_H_

#include <iterator>

#include "src/common/globals.h"
#include "src/compiler/turboshaft/access-builder.h"
#include "src/compiler/turboshaft/assembler.h"
#include "src/compiler/turboshaft/machine-lowering-reducer-inl.h"
#include "src/compiler/turboshaft/operation-matcher.h"
#include "src/compiler/turboshaft/runtime-call-descriptors.h"
#include "src/compiler/turboshaft/sidetable.h"
#include "src/interpreter/bytecode-register.h"
#include "src/objects/elements-kind.h"

#define DEFINE_TURBOSHAFT_ALIASES()                                            \
  template <typename T>                                                        \
  using V = compiler::turboshaft::V<T>;                                        \
  template <typename T>                                                        \
  using ConstOrV = compiler::turboshaft::ConstOrV<T>;                          \
  template <typename T>                                                        \
  using OptionalV = compiler::turboshaft::OptionalV<T>;                        \
  template <typename... Ts>                                                    \
  using Label = compiler::turboshaft::Label<Ts...>;                            \
  template <typename... Ts>                                                    \
  using LoopLabel = compiler::turboshaft::LoopLabel<Ts...>;                    \
  using Block = compiler::turboshaft::Block;                                   \
  using OpIndex = compiler::turboshaft::OpIndex;                               \
  using Word32 = compiler::turboshaft::Word32;                                 \
  using Word64 = compiler::turboshaft::Word64;                                 \
  using WordPtr = compiler::turboshaft::WordPtr;                               \
  using Float32 = compiler::turboshaft::Float32;                               \
  using Float64 = compiler::turboshaft::Float64;                               \
  using RegisterRepresentation = compiler::turboshaft::RegisterRepresentation; \
  using MemoryRepresentation = compiler::turboshaft::MemoryRepresentation;     \
  using BuiltinCallDescriptor = compiler::turboshaft::BuiltinCallDescriptor;   \
  using AccessBuilderTS = compiler::turboshaft::AccessBuilderTS;

#define BUILTIN_REDUCER(name)          \
  TURBOSHAFT_REDUCER_BOILERPLATE(name) \
  DEFINE_TURBOSHAFT_ALIASES()

namespace v8::internal {

#include "src/compiler/turboshaft/define-assembler-macros.inc"

enum IsKnownTaggedPointer { kNo, kYes };

namespace detail {

// TODO(nicohartmann): Rename once CSA is (mostly) gone.
template <typename Assembler>
class BuiltinArgumentsTS {
 public:
  DEFINE_TURBOSHAFT_ALIASES()

  auto& Asm() const { return *assembler_; }

  // |argc| specifies the number of arguments passed to the builtin.
  template <typename T>
  BuiltinArgumentsTS(Assembler* assembler, V<T> argc,
                     OptionalV<WordPtr> fp = {})
      : assembler_(assembler) {
    if constexpr (std::is_same_v<T, WordPtr>) {
      argc_ = argc;
    } else {
      if constexpr (std::is_same_v<T, Word32>) {
        DCHECK((std::is_same_v<WordPtr, Word64>));
        argc_ = assembler_->ChangeInt32ToInt64(argc);
      } else {
        static_assert(std::is_same_v<T, Word64>);
        DCHECK((std::is_same_v<WordPtr, Word32>));
        argc_ = assembler_->TruncateWord64ToWord32(argc);
      }
    }
    if (fp.has_value()) {
      fp_ = fp.value();
    } else {
      fp_ = __ FramePointer();
    }
    const intptr_t offset =
        (StandardFrameConstants::kFixedSlotCountAboveFp + 1) *
        kSystemPointerSize;
    // base_ points to the first argument, not the receiver
    // whether present or not.
    base_ = __ WordPtrAdd(fp_, offset);
  }

  V<WordPtr> GetLengthWithReceiver() const { return argc_; }

  V<WordPtr> GetLengthWithoutReceiver() const {
    return __ WordPtrSub(argc_, kJSArgcReceiverSlots);
  }

  V<Object> AtIndex(ConstOrV<WordPtr> index) const {
    TSA_DCHECK(this, __ UintPtrLessThan(index, GetLengthWithoutReceiver()));
    return V<Object>::Cast(
        __ LoadOffHeap(AtIndexPtr(index), MemoryRepresentation::AnyTagged()));
  }

  class Iterator {
   public:
    using iterator_type = V<WordPtr>;
    using value_type = V<Object>;

    // {end} is the iterator-typical exclusive one past the last element.
    Iterator(const BuiltinArgumentsTS* args, ConstOrV<WordPtr> begin_index,
             ConstOrV<WordPtr> end_index)
        : args_(args), begin_index_(begin_index), end_index_(end_index) {}

    template <typename A>
    iterator_type Begin(A& assembler) {
      DCHECK(!end_offset_.valid());
      // Pre-compute the end offset.
      end_offset_ = args_->AtIndexPtr(assembler.resolve(end_index_));
      return args_->AtIndexPtr(assembler.resolve(begin_index_));
    }

    template <typename A>
    OptionalV<Word32> IsEnd(A& assembler,
                            iterator_type current_iterator) const {
      return assembler.UintPtrLessThanOrEqual(end_offset_, current_iterator);
    }

    template <typename A>
    iterator_type Advance(A& assembler, iterator_type current_iterator) const {
      return assembler.WordPtrAdd(
          current_iterator, ElementsKindToByteSize(SYSTEM_POINTER_ELEMENTS));
    }

    template <typename A>
    value_type Dereference(A& assembler, iterator_type current_iterator) const {
      return V<Object>::Cast(assembler.LoadOffHeap(
          current_iterator, MemoryRepresentation::AnyTagged()));
    }

   private:
    const BuiltinArgumentsTS* args_;
    ConstOrV<WordPtr> begin_index_;
    ConstOrV<WordPtr> end_index_;
    V<WordPtr> end_offset_;
  };

  Iterator Range(ConstOrV<WordPtr> begin, ConstOrV<WordPtr> end) const {
    return Iterator(this, begin, end);
  }

  Iterator Range(ConstOrV<WordPtr> begin) const {
    return Iterator(this, begin, GetLengthWithoutReceiver());
  }

  Iterator Range() const {
    return Iterator(this, 0, GetLengthWithoutReceiver());
  }

 private:
  V<WordPtr> AtIndexPtr(ConstOrV<WordPtr> index) const {
    V<WordPtr> offset =
        assembler_->ElementOffsetFromIndex(index, SYSTEM_POINTER_ELEMENTS, 0);
    return __ WordPtrAdd(base_, offset);
  }

  Assembler* assembler_;
  V<WordPtr> argc_;
  V<WordPtr> fp_;
  V<WordPtr> base_;
};

}  // namespace detail

template <typename Next>
class FeedbackCollectorReducer : public Next {
 public:
  BUILTIN_REDUCER(FeedbackCollector)

  using FeedbackVectorOrUndefined = Union<FeedbackVector, Undefined>;
  static constexpr bool HasFeedbackCollector() { return true; }

  void CombineFeedback(int additional_feedback) {
    __ CodeComment("CombineFeedback");
    feedback_ = __ SmiBitwiseOr(
        feedback_, __ SmiConstant(Smi::FromInt(additional_feedback)));
  }

  void OverwriteFeedback(int new_feedback) {
    __ CodeComment("OverwriteFeedback");
    feedback_ = __ SmiConstant(Smi::FromInt(new_feedback));
  }

  void CombineFeedbackOnException(int additional_feedback) {
    feedback_on_exception_ = __ SmiConstant(Smi::FromInt(additional_feedback));
  }

  void CombineExceptionFeedback() {
    feedback_ = __ SmiBitwiseOr(feedback_, feedback_on_exception_);
  }

  V<Word32> FeedbackIs(int checked_feedback) {
    return __ SmiEqual(feedback_,
                       __ SmiConstant(Smi::FromInt(checked_feedback)));
  }

  V<FeedbackVectorOrUndefined> LoadFeedbackVector() {
    return V<FeedbackVectorOrUndefined>::Cast(
        __ LoadRegister(interpreter::Register::feedback_vector()));
  }

  V<WordPtr> LoadFeedbackVectorLength(V<FeedbackVector> feedback_vector) {
    V<Word32> length = __ LoadField(feedback_vector,
                                    AccessBuilderTS::ForFeedbackVectorLength());
    return ChangePositiveInt32ToIntPtr(length);
  }

  V<MaybeObject> LoadFeedbackVectorSlot(V<FeedbackVector> feedback_vector,
                                        V<WordPtr> slot,
                                        int additional_offset = 0) {
    __ CodeComment("LoadFeedbackVectorSlot");
    int32_t header_size =
        FeedbackVector::kRawFeedbackSlotsOffset + additional_offset;
    V<WordPtr> offset =
        __ ElementOffsetFromIndex(slot, HOLEY_ELEMENTS, header_size);
    TSA_SLOW_DCHECK(this, IsOffsetInBounds(
                              offset, LoadFeedbackVectorLength(feedback_vector),
                              FeedbackVector::kHeaderSize));
    return V<MaybeObject>::Cast(
        __ Load(feedback_vector, offset,
                compiler::turboshaft::LoadOp::Kind::TaggedBase(),
                MemoryRepresentation::AnyTagged()));
  }

  void StoreFeedbackVectorSlot(
      V<FeedbackVector> feedback_vector, V<WordPtr> slot, V<Object> value,
      WriteBarrierMode barrier_mode = UPDATE_WRITE_BARRIER,
      int additional_offset = 0) {
    __ CodeComment("StoreFeedbackVectorSlot");
    DCHECK(IsAligned(additional_offset, kTaggedSize));
    int header_size =
        FeedbackVector::kRawFeedbackSlotsOffset + additional_offset;
    V<WordPtr> offset =
        __ ElementOffsetFromIndex(slot, HOLEY_ELEMENTS, header_size);
    TSA_DCHECK(this, IsOffsetInBounds(offset,
                                      LoadFeedbackVectorLength(feedback_vector),
                                      FeedbackVector::kHeaderSize));
    switch (barrier_mode) {
      case SKIP_WRITE_BARRIER: {
        __ Store(feedback_vector, offset, value,
                 compiler::turboshaft::StoreOp::Kind::TaggedBase(),
                 MemoryRepresentation::AnyTagged(),
                 compiler::WriteBarrierKind::kNoWriteBarrier);
        return;
      }
      case UNSAFE_SKIP_WRITE_BARRIER:
        UNIMPLEMENTED();
      case UPDATE_WRITE_BARRIER:
        UNIMPLEMENTED();
      case UPDATE_EPHEMERON_KEY_WRITE_BARRIER:
        UNREACHABLE();
    }
  }

  void SetFeedbackSlot(V<WordPtr> slot_id) { slot_id_ = slot_id; }
  void SetFeedbackVector(V<FeedbackVector> feedback_vector) {
    TSA_DCHECK(this, IsFeedbackVector(feedback_vector));
    maybe_feedback_vector_ = feedback_vector;
    feedback_ = __ SmiConstant(Smi::FromInt(0));
    feedback_on_exception_ = feedback_.Get();
  }

  void LoadFeedbackVectorOrUndefinedIfJitless() {
#ifndef V8_JITLESS
    maybe_feedback_vector_ = LoadFeedbackVector();
#else
    maybe_feedback_vector_ = __ UndefinedConstant();
#endif
    feedback_ = __ SmiConstant(Smi::FromInt(0));
    feedback_on_exception_ = feedback_.Get();
  }

  static constexpr UpdateFeedbackMode DefaultUpdateFeedbackMode() {
#ifndef V8_JITLESS
    return UpdateFeedbackMode::kOptionalFeedback;
#else
    return UpdateFeedbackMode::kNoFeedback;
#endif  // !V8_JITLESS
  }

  void UpdateFeedback() {
    __ CodeComment("UpdateFeedback");
    if (mode_ == UpdateFeedbackMode::kNoFeedback) {
#ifdef V8_JITLESS
      TSA_DCHECK(this, __ IsUndefined(maybe_feedback_vector_));
      return;
#else
      UNREACHABLE();
#endif  // !V8_JITLESS
    }

    Label<> done(this);
    if (mode_ == UpdateFeedbackMode::kOptionalFeedback) {
      GOTO_IF(__ IsUndefined(maybe_feedback_vector_), done);
    } else {
      DCHECK_EQ(mode_, UpdateFeedbackMode::kGuaranteedFeedback);
    }

    V<FeedbackVector> feedback_vector =
        V<FeedbackVector>::Cast(maybe_feedback_vector_);

    V<MaybeObject> feedback_element =
        LoadFeedbackVectorSlot(feedback_vector, slot_id_);
    V<Smi> previous_feedback = V<Smi>::Cast(feedback_element);
    V<Smi> combined_feedback = __ SmiBitwiseOr(previous_feedback, feedback_);
    IF_NOT (__ SmiEqual(previous_feedback, combined_feedback)) {
      StoreFeedbackVectorSlot(feedback_vector, slot_id_, combined_feedback,
                              SKIP_WRITE_BARRIER);
      // TODO(nicohartmann):
      // ReportFeedbackUpdate(maybe_feedback_vector_, slot_id_,
      // "UpdateFeedback");
    }
    GOTO(done);

    BIND(done);
  }

  V<Smi> SmiBitwiseOr(V<Smi> a, V<Smi> b) {
    return __ BitcastWord32ToSmi(
        __ Word32BitwiseOr(__ BitcastSmiToWord32(a), __ BitcastSmiToWord32(b)));
  }

  V<Word32> SmiEqual(V<Smi> a, V<Smi> b) {
    return __ Word32Equal(__ BitcastSmiToWord32(a), __ BitcastSmiToWord32(b));
  }

  V<WordPtr> ChangePositiveInt32ToIntPtr(V<Word32> input) {
    TSA_DCHECK(this, __ Int32LessThanOrEqual(0, input));
    return __ ChangeUint32ToUintPtr(input);
  }

  V<Word32> IsFeedbackVector(V<HeapObject> heap_object) {
    V<Map> map = __ LoadMapField(heap_object);
    return __ IsFeedbackVectorMap(map);
  }

  V<Word32> IsOffsetInBounds(V<WordPtr> offset, V<WordPtr> length,
                             int header_size,
                             ElementsKind kind = HOLEY_ELEMENTS) {
    // Make sure we point to the last field.
    int element_size = 1 << ElementsKindToShiftSize(kind);
    int correction = header_size - element_size;
    V<WordPtr> last_offset =
        __ ElementOffsetFromIndex(length, kind, correction);
    return __ IntPtrLessThanOrEqual(offset, last_offset);
  }

 private:
  V<FeedbackVectorOrUndefined> maybe_feedback_vector_;
  V<WordPtr> slot_id_;
  compiler::turboshaft::Var<Smi, assembler_t> feedback_{this};
  compiler::turboshaft::Var<Smi, assembler_t> feedback_on_exception_{this};
  UpdateFeedbackMode mode_ = DefaultUpdateFeedbackMode();
};

template <typename Next>
class NoFeedbackCollectorReducer : public Next {
 public:
  BUILTIN_REDUCER(NoFeedbackCollector)

  static constexpr bool HasFeedbackCollector() { return false; }

  void CombineFeedback(int additional_feedback) {}

  void OverwriteFeedback(int new_feedback) {}

  V<Word32> FeedbackIs(int checked_feedback) { UNREACHABLE(); }

  void UpdateFeedback() {}
  void CombineExceptionFeedback() {}
};

template <typename Next>
class BuiltinsReducer : public Next {
 public:
  BUILTIN_REDUCER(Builtins)

  using BuiltinArgumentsTS = detail::BuiltinArgumentsTS<assembler_t>;

  void EmitBuiltinProlog(Builtin builtin_id) {
    // Bind the entry block.
    __ Bind(__ NewBlock());
    // Eagerly emit all parameters such that they are guaranteed to be in the
    // entry block (assembler will cache them).
    const compiler::CallDescriptor* desc =
        __ data() -> builtin_call_descriptor();
    for (int i = 0; i < static_cast<int>(desc->ParameterCount()); ++i) {
      __ Parameter(i, RegisterRepresentation::FromMachineType(
                          desc->GetParameterType(i)));
    }
    // TODO(nicohartmann): CSA tracks some debug information here.
    // Emit stack check.
    if (Builtins::KindOf(builtin_id) == Builtins::TSJ) {
      __ PerformStackCheck(__ JSContextParameter());
    }
  }

  void EmitEpilog(Block* catch_block) {
    DCHECK_EQ(__ HasFeedbackCollector(), catch_block != nullptr);
    if (catch_block) {
      // If the handler can potentially throw, we catch the exception here and
      // update the feedback vector before we rethrow the exception.
      if (__ Bind(catch_block)) {
        V<Object> exception = __ CatchBlockBegin();
        __ CombineExceptionFeedback();
        __ UpdateFeedback();
        __ template CallRuntime<
            compiler::turboshaft::RuntimeCallDescriptor::ReThrow>(
            __ data()->isolate(), __ NoContextConstant(), {exception});
        __ Unreachable();
      }
    }
  }

  V<Context> JSContextParameter() {
    return __ template Parameter<Context>(
        compiler::Linkage::GetJSCallContextParamIndex(static_cast<int>(
            __ data()->builtin_call_descriptor()->JSParameterCount())));
  }

  void PerformStackCheck(V<Context> context) {
    __ JSStackCheck(context,
                    OptionalV<compiler::turboshaft::FrameState>::Nullopt(),
                    compiler::turboshaft::JSStackCheckOp::Kind::kBuiltinEntry);
  }

  void PopAndReturn(BuiltinArgumentsTS& arguments,
                    compiler::turboshaft::V<Object> return_value) {
    // PopAndReturn is supposed to be using ONLY in CSA/Torque builtins for
    // dropping ALL JS arguments that are currently located on the stack.
    // The check below ensures that there are no directly accessible stack
    // parameters from current builtin, which implies that the builtin with
    // JS calling convention (TFJ) was created with kDontAdaptArgumentsSentinel.
    // This simplifies semantics of this instruction because in case of presence
    // of directly accessible stack parameters it's impossible to distinguish
    // the following cases:
    // 1) stack parameter is included in JS arguments (and therefore it will be
    //    dropped as a part of 'pop' number of arguments),
    // 2) stack parameter is NOT included in JS arguments (and therefore it
    // should
    //    be dropped in ADDITION to the 'pop' number of arguments).
    // Additionally, in order to simplify assembly code, PopAndReturn is also
    // not allowed in builtins with stub linkage and parameters on stack.
    CHECK_EQ(__ data()->builtin_call_descriptor()->ParameterSlotCount(), 0);
    V<WordPtr> pop_count = arguments.GetLengthWithReceiver();
    std::initializer_list<const OpIndex> temp{return_value};
    __ Return(__ TruncateWordPtrToWord32(pop_count), base::VectorOf(temp));
  }

  V<Word32> TruncateTaggedToWord32(V<Context> context, V<Object> value) {
    Label<Word32> is_number(this);
    TaggedToWord32OrBigIntImpl<Object::Conversion::kToNumber>(
        context, value, IsKnownTaggedPointer::kNo, is_number);

    BIND(is_number, number);
    return number;
  }

  V<Word32> IsBigIntInstanceType(ConstOrV<Word32> instance_type) {
    return InstanceTypeEqual(instance_type, BIGINT_TYPE);
  }
  V<Word32> IsSmallBigInt(V<BigInt> value) { UNIMPLEMENTED(); }
  V<Word32> InstanceTypeEqual(ConstOrV<Word32> instance_type,
                              ConstOrV<Word32> other_instance_type) {
    return __ Word32Equal(instance_type, other_instance_type);
  }

  V<WordPtr> AlignTagged(V<WordPtr> size) {
    return __ WordPtrBitwiseAnd(__ WordPtrAdd(size, kObjectAlignmentMask),
                                ~kObjectAlignmentMask);
  }

  V<WordPtr> ElementOffsetFromIndex(ConstOrV<WordPtr> index, ElementsKind kind,
                                    intptr_t base_size) {
    const int element_size_shift = ElementsKindToShiftSize(kind);
    if (std::optional<intptr_t> constant_index = TryToIntPtrConstant(index)) {
      return __ WordPtrConstant(base_size +
                                (1 << element_size_shift) * (*constant_index));
    }
    if (element_size_shift == 0) {
      return __ WordPtrAdd(base_size, index);
    } else {
      DCHECK_LT(0, element_size_shift);
      return __ WordPtrAdd(base_size,
                           __ WordPtrShiftLeft(index, element_size_shift));
    }
  }

  std::optional<intptr_t> TryToIntPtrConstant(ConstOrV<WordPtr> index) {
    if (index.is_constant()) return index.constant_value();
    intptr_t value;
    if (matcher_.MatchIntegralWordPtrConstant(index.value(), &value)) {
      return value;
    }
    return std::nullopt;
  }

  template <Object::Conversion Conversion>
  void TaggedToWord32OrBigIntImpl(V<Context> context, V<Object> value,
                                  IsKnownTaggedPointer is_known_tagged_pointer,
                                  Label<Word32>& if_number,
                                  Label<BigInt>* if_bigint = nullptr,
                                  Label<BigInt>* if_bigint64 = nullptr) {
    DCHECK_EQ(Conversion == Object::Conversion::kToNumeric,
              if_bigint != nullptr);

    if (is_known_tagged_pointer == IsKnownTaggedPointer::kNo) {
      IF (__ IsSmi(value)) {
        __ CombineFeedback(BinaryOperationFeedback::kSignedSmall);
        GOTO(if_number, __ UntagSmi(V<Smi>::Cast(value)));
      }
    }

    ScopedVar<HeapObject> value_heap_object(this, V<HeapObject>::Cast(value));
    WHILE(1) {
      V<Map> map = __ LoadMapField(value_heap_object);

      IF (__ IsHeapNumberMap(map)) {
        __ CombineFeedback(BinaryOperationFeedback::kNumber);
        V<Float64> value_float64 =
            __ LoadHeapNumberValue(V<HeapNumber>::Cast(value_heap_object));
        GOTO(if_number, __ JSTruncateFloat64ToWord32(value_float64));
      }

      V<Word32> instance_type = __ LoadInstanceTypeField(map);
      if (Conversion == Object::Conversion::kToNumeric) {
        IF (IsBigIntInstanceType(instance_type)) {
          V<BigInt> value_bigint = V<BigInt>::Cast(value_heap_object);
          if (Is64() && if_bigint64) {
            IF (IsSmallBigInt(value_bigint)) {
              __ CombineFeedback(BinaryOperationFeedback::kBigInt64);
              GOTO(*if_bigint64, value_bigint);
            }
          }
          __ CombineFeedback(BinaryOperationFeedback::kBigInt);
          GOTO(*if_bigint, value_bigint);
        }
      }

      // Not HeapNumber (or BigInt if conversion == kToNumeric).
      if (__ HasFeedbackCollector()) {
        // We do not require an Or with earlier feedback here because once we
        // convert the value to a Numeric, we cannot reach this path. We can
        // only reach this path on the first pass when the feedback is kNone.
        TSA_DCHECK(this, __ FeedbackIs(BinaryOperationFeedback::kNone));
      }
      IF (InstanceTypeEqual(instance_type, ODDBALL_TYPE)) {
        __ OverwriteFeedback(BinaryOperationFeedback::kNumberOrOddball);
        V<Float64> oddball_value =
            __ LoadField(V<Oddball>::Cast(value_heap_object),
                         AccessBuilderTS::ForHeapNumberOrOddballOrHoleValue());
        GOTO(if_number, __ JSTruncateFloat64ToWord32(oddball_value));
      }

      // Not an oddball either -> convert.
      V<Object> converted_value;
      // TODO(nicohartmann): We have to make sure that we store the feedback if
      // any of those calls throws an exception.
      __ OverwriteFeedback(BinaryOperationFeedback::kAny);

      using Builtin =
          std::conditional_t<Conversion == Object::Conversion::kToNumeric,
                             BuiltinCallDescriptor::NonNumberToNumeric,
                             BuiltinCallDescriptor::NonNumberToNumber>;
      converted_value = __ template CallBuiltin<Builtin>(
          isolate(), context, {V<JSAnyNotNumber>::Cast(value_heap_object)});

      GOTO_IF(__ IsSmi(converted_value), if_number,
              __ UntagSmi(V<Smi>::Cast(converted_value)));
      value_heap_object = V<HeapObject>::Cast(converted_value);
    }

    __ Unreachable();
  }

 private:
  compiler::turboshaft::OperationMatcher matcher_{__ data()->graph()};
  Isolate* isolate() { return __ data() -> isolate(); }
};

template <template <typename> typename Reducer,
          template <typename> typename FeedbackReducer>
class TurboshaftBuiltinsAssembler
    : public compiler::turboshaft::TSAssembler<
          Reducer, BuiltinsReducer, FeedbackReducer,
          compiler::turboshaft::MachineLoweringReducer,
          compiler::turboshaft::VariableReducer> {
 public:
  using Base = compiler::turboshaft::TSAssembler<
      Reducer, BuiltinsReducer, FeedbackReducer,
      compiler::turboshaft::MachineLoweringReducer,
      compiler::turboshaft::VariableReducer>;
  TurboshaftBuiltinsAssembler(compiler::turboshaft::PipelineData* data,
                              compiler::turboshaft::Graph& graph,
                              Zone* phase_zone)
      : Base(data, graph, graph, phase_zone) {}

  using Base::Asm;
};

#include "src/compiler/turboshaft/undef-assembler-macros.inc"

}  // namespace v8::internal

#endif  // V8_CODEGEN_TURBOSHAFT_BUILTINS_ASSEMBLER_INL_H_

"""

```