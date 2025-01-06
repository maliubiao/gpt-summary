Response: Let's break down the thought process for analyzing the C++ code and explaining its relationship to JavaScript.

1. **Understand the Goal:** The request asks for a summary of the C++ code's functionality and its connection to JavaScript, with examples. This means we need to identify the core concepts, how they are implemented, and how those concepts relate to JavaScript's type system.

2. **Initial Scan and Keyword Spotting:**  A quick skim of the code reveals keywords like `Type`, `Word32`, `Word64`, `Float32`, `Float64`, `Tuple`, `Any`, `None`, `SubtypeOf`, `Equals`, `LeastUpperBound`, `Intersect`, `AllocateOnHeap`. These are strong indicators that the code is about defining and manipulating types. The namespace `v8::internal::compiler::turboshaft` suggests this is part of V8's compiler and likely involved in type analysis during optimization.

3. **Core Data Structures: The `Type` Class:** The central element is the `Type` class. The `kind_` member and the switch statement in `Equals`, `IsSubtypeOf`, and `PrintTo` immediately suggest an enum-like structure defining different type categories. We can identify the fundamental types being handled: `None`, `Word32`, `Word64`, `Float32`, `Float64`, `Tuple`, and `Any`.

4. **Detailed Examination of Specific Type Classes:**  The code provides details about `WordType` and `FloatType`. We see sub-kinds like `Range` and `Set` for representing number types. This is a crucial detail: V8's compiler isn't just tracking "number," it's tracking *ranges* and *sets* of numbers for finer-grained analysis. The `LeastUpperBound` and `Intersect` methods indicate type merging and intersection logic, common operations in type systems.

5. **Connecting to JavaScript:**  The key is to map these C++ type concepts to JavaScript's dynamic typing. JavaScript has primitive types like numbers, and while it doesn't have explicit integer vs. float distinctions at the language level, the *engine* can benefit from knowing if a value is likely an integer or a float for optimization.

    * **Numbers:** `Word32`, `Word64`, `Float32`, `Float64` directly relate to JavaScript's `Number` type. The ranges and sets are internal representations for optimization. The concept of `NaN` and `-0` in `FloatType` is directly relevant to JavaScript's handling of these special numeric values.
    * **Tuples:** While JavaScript doesn't have a built-in "tuple" type in the same way, arrays often behave like tuples in practice. The concept of a fixed-size sequence with potentially different types at each position is present.
    * **`Any` and `None`:** `Any` maps to the broadest possible type in JavaScript (or the absence of specific type information), while `None` represents an impossible type, which can occur in control flow analysis.

6. **Illustrative JavaScript Examples:** To solidify the connection, we need examples that demonstrate how these internal types manifest in JavaScript behavior.

    * **Number Ranges:** Examples showing how V8 might infer integer ranges during loop optimizations are relevant.
    * **Sets of Numbers:** Demonstrating how conditional checks can narrow down the possible values of a variable and how V8 could represent this internally as a set.
    * **Floating-Point Specifics:**  Highlighting the importance of `NaN` and `-0` for correctness in JavaScript.
    * **Tuples (Arrays):**  Showing how V8 can reason about the types of elements within an array, even if JavaScript itself doesn't enforce strict tuple typing.

7. **Explaining the "Why":** It's not enough to say "this C++ type relates to this JavaScript concept." We need to explain *why* this internal type system exists. The core reason is **optimization**. By tracking more precise type information, Turboshaft can generate more efficient machine code. This involves:

    * **Eliminating redundant checks:** If V8 knows a value is definitely an integer, it doesn't need to perform checks for floating-point operations.
    * **Choosing specialized instructions:**  Knowing if a value is a 32-bit integer vs. a 64-bit integer allows for selecting appropriate CPU instructions.
    * **Inlining and other optimizations:** More precise type information enables more aggressive optimizations.

8. **Structuring the Explanation:**  A clear structure is essential for conveying the information effectively. A good approach is:

    * **High-Level Summary:** Start with a concise overview of the file's purpose.
    * **Detailed Breakdown of Key Classes:** Explain the `Type` class and its subtypes.
    * **Relationship to JavaScript:**  Explicitly connect the C++ types to JavaScript concepts, providing concrete examples.
    * **Purpose of the Type System:** Explain *why* this complex system exists within V8.

9. **Refinement and Clarity:**  Review the explanation for clarity and accuracy. Ensure that the technical terms are explained adequately and that the JavaScript examples are easy to understand. For example, explaining the concept of "least upper bound" in the context of type inference.

By following this thought process, we can dissect the C++ code, understand its role within the V8 engine, and effectively communicate its connection to the seemingly loosely-typed world of JavaScript. The key is to bridge the gap between the low-level implementation details and the high-level behavior observed by JavaScript developers.
这个 C++ 源代码文件 `types.cc` 定义了 Turboshaft 图编译框架中的类型系统。Turboshaft 是 V8 引擎中新一代的编译器，旨在提升 JavaScript 代码的执行效率。

**主要功能归纳:**

1. **定义了各种数据类型:** 该文件定义了 Turboshaft 编译器在中间表示 (IR) 中使用的各种数据类型，包括：
   - `Type`:  一个基类，表示所有可能的类型。
   - `Word32Type`, `Word64Type`: 表示 32 位和 64 位整数类型，可以表示值的范围或者值的集合。
   - `Float32Type`, `Float64Type`: 表示 32 位和 64 位浮点数类型，可以表示值的范围或者值的集合，并能区分 `NaN` 和 `-0` 等特殊值。
   - `TupleType`: 表示元组类型，即固定大小的元素序列，每个元素可以是不同的类型。
   - `None`: 表示空类型或者不可达到的类型。
   - `Any`: 表示任意类型。

2. **实现了类型操作:**  该文件实现了各种类型操作，包括：
   - `Equals`: 判断两个类型是否相等。
   - `IsSubtypeOf`: 判断一个类型是否是另一个类型的子类型。
   - `LeastUpperBound`: 计算两个类型的最小公共父类型 (Least Upper Bound)。这在类型推断和合并时非常有用。
   - `Intersect`: 计算两个类型的交集。
   - `PrintTo`: 将类型信息打印到输出流，用于调试和日志记录。
   - `ParseFromString`: 从字符串解析类型信息。
   - `AllocateOnHeap`: 在堆上分配 `TurboshaftType` 对象，用于在 V8 的堆管理系统中表示类型。

3. **支持类型表示的精细化:**  对于数值类型 (`Word32`, `Word64`, `Float32`, `Float64`)，它不仅仅是简单的 "整数" 或 "浮点数"，还可以表示值的范围 (`Range`) 或者值的集合 (`Set`)。 这使得 Turboshaft 能够进行更精确的类型分析和优化。

**与 JavaScript 的关系及 JavaScript 举例说明:**

这个文件定义的类型系统是 V8 引擎内部用于优化 JavaScript 代码执行的工具。虽然 JavaScript 是一门动态类型语言，但在 V8 的编译和优化阶段，了解变量的类型信息对于生成高效的机器码至关重要。Turboshaft 使用这个类型系统来推断和跟踪 JavaScript 代码中变量的类型，从而进行各种优化。

以下是一些 JavaScript 代码示例，以及 Turboshaft 类型系统可能如何在内部表示和利用这些类型信息进行优化：

**例子 1: 整数运算**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10);
```

在 Turboshaft 编译 `add` 函数时，如果它能推断出 `a` 和 `b` 在调用时总是整数（例如，通过观察之前的调用或者使用类型反馈），它可能会将 `a` 和 `b` 的类型表示为 `Word32` 的某个范围或者集合，例如 `Word32[5, 5]` 和 `Word32[10, 10]`。然后，编译器可以生成针对整数加法优化的机器码，而无需进行额外的类型检查。

**例子 2: 浮点数运算**

```javascript
function square(x) {
  return x * x;
}

square(3.14);
```

如果 Turboshaft 推断出 `x` 是一个浮点数，它可能会将 `x` 的类型表示为 `Float64` 的某个范围，例如 `Float64[3.14, 3.14]`。 这允许编译器生成针对浮点数乘法优化的指令。 值得注意的是，`Float32Type` 和 `Float64Type` 能够区分 `NaN` 和 `-0`，这在处理浮点数运算时非常重要，因为这些特殊值有特殊的行为。

**例子 3: 条件判断和类型收窄**

```javascript
function process(value) {
  if (typeof value === 'number') {
    return value * 2;
  } else {
    return value.toUpperCase();
  }
}

process(7);
process("hello");
```

在 `process` 函数中，`typeof value === 'number'` 这个条件判断会影响 `value` 的类型。在 `if` 分支中，Turboshaft 可能会将 `value` 的类型收窄为某种数值类型（例如 `Word32` 或 `Float64`），而在 `else` 分支中，可能会收窄为字符串类型。  `LeastUpperBound` 函数在这种情况下可能用于合并两个分支的返回类型。

**例子 4: 数组 (可以近似理解为 Tuple)**

```javascript
function getPoint(point) {
  return `x: ${point[0]}, y: ${point[1]}`;
}

getPoint([1, 2]);
```

虽然 JavaScript 的数组是动态的，但在某些情况下，Turboshaft 可能会将数组视为类似元组的结构进行分析。 例如，如果 `point` 总是传入一个包含两个数字的数组，Turboshaft 可能会在内部将其表示为 `TupleType`，其中第一个元素是 `Word32` 或 `Float64`，第二个元素也是 `Word32` 或 `Float64`。

**总结:**

`v8/src/compiler/turboshaft/types.cc` 文件定义了 Turboshaft 编译器用于表示和操作类型信息的内部机制。虽然 JavaScript 是动态类型的，但 V8 引擎为了优化性能，会在编译阶段尽可能地推断和利用类型信息。这个文件定义的类型系统是实现这种优化的关键组成部分。它允许 Turboshaft 进行更精细的类型分析，从而生成更高效的机器码，最终提升 JavaScript 代码的执行速度。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/types.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
// Copyright 2022 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/compiler/turboshaft/types.h"

#include <optional>
#include <sstream>
#include <string_view>

#include "src/base/logging.h"
#include "src/compiler/turboshaft/type-parser.h"
#include "src/heap/factory.h"
#include "src/objects/turboshaft-types-inl.h"

namespace v8::internal::compiler::turboshaft {

namespace {

std::pair<uint32_t, uint32_t> uint64_to_high_low(uint64_t value) {
  return {static_cast<uint32_t>(value >> 32), static_cast<uint32_t>(value)};
}

}  // namespace

bool Type::Equals(const Type& other) const {
  DCHECK(!IsInvalid());
  DCHECK(!other.IsInvalid());

  if (kind_ != other.kind_) return false;
  switch (kind_) {
    case Kind::kInvalid:
      UNREACHABLE();
    case Kind::kNone:
      return true;
    case Kind::kWord32:
      return AsWord32().Equals(other.AsWord32());
    case Kind::kWord64:
      return AsWord64().Equals(other.AsWord64());
    case Kind::kFloat32:
      return AsFloat32().Equals(other.AsFloat32());
    case Kind::kFloat64:
      return AsFloat64().Equals(other.AsFloat64());
    case Kind::kTuple:
      return AsTuple().Equals(other.AsTuple());
    case Kind::kAny:
      return true;
  }
}

bool Type::IsSubtypeOf(const Type& other) const {
  DCHECK(!IsInvalid());
  DCHECK(!other.IsInvalid());

  if (other.IsAny() || IsNone()) return true;
  if (kind_ != other.kind_) return false;

  switch (kind_) {
    case Kind::kInvalid:
    case Kind::kNone:
      UNREACHABLE();
    case Kind::kWord32:
      return AsWord32().IsSubtypeOf(other.AsWord32());
    case Kind::kWord64:
      return AsWord64().IsSubtypeOf(other.AsWord64());
    case Kind::kFloat32:
      return AsFloat32().IsSubtypeOf(other.AsFloat32());
    case Kind::kFloat64:
      return AsFloat64().IsSubtypeOf(other.AsFloat64());
    case Kind::kTuple:
      return AsTuple().IsSubtypeOf(other.AsTuple());
    case Kind::kAny:
      UNREACHABLE();
  }
}

void Type::PrintTo(std::ostream& stream) const {
  switch (kind_) {
    case Kind::kInvalid:
      UNREACHABLE();
    case Kind::kNone:
      stream << "None";
      break;
    case Kind::kWord32: {
      AsWord32().PrintTo(stream);
      break;
    }
    case Kind::kWord64: {
      AsWord64().PrintTo(stream);
      break;
    }
    case Kind::kFloat32: {
      AsFloat32().PrintTo(stream);
      break;
    }
    case Kind::kFloat64: {
      AsFloat64().PrintTo(stream);
      break;
    }
    case Kind::kTuple: {
      AsTuple().PrintTo(stream);
      break;
    }
    case Kind::kAny: {
      stream << "Any";
      break;
    }
  }
}

void Type::Print() const {
  StdoutStream os;
  PrintTo(os);
  os << '\n';
}

// static
Type Type::LeastUpperBound(const Type& lhs, const Type& rhs, Zone* zone) {
  if (lhs.IsAny() || rhs.IsAny()) return Type::Any();
  if (lhs.IsNone()) return rhs;
  if (rhs.IsNone()) return lhs;

  // TODO(nicohartmann@): We might use more precise types here but currently
  // there is not much benefit in that.
  if (lhs.kind() != rhs.kind()) return Type::Any();

  switch (lhs.kind()) {
    case Type::Kind::kInvalid:
    case Type::Kind::kNone:
    case Type::Kind::kAny:
      UNREACHABLE();
    case Type::Kind::kWord32:
      return Word32Type::LeastUpperBound(lhs.AsWord32(), rhs.AsWord32(), zone);
    case Type::Kind::kWord64:
      return Word64Type::LeastUpperBound(lhs.AsWord64(), rhs.AsWord64(), zone);
    case Type::Kind::kFloat32:
      return Float32Type::LeastUpperBound(lhs.AsFloat32(), rhs.AsFloat32(),
                                          zone);
    case Type::Kind::kFloat64:
      return Float64Type::LeastUpperBound(lhs.AsFloat64(), rhs.AsFloat64(),
                                          zone);
    case Type::Kind::kTuple:
      return TupleType::LeastUpperBound(lhs.AsTuple(), rhs.AsTuple(), zone);
  }
}

std::optional<Type> Type::ParseFromString(const std::string_view& str,
                                          Zone* zone) {
  TypeParser parser(str, zone);
  return parser.Parse();
}

Handle<TurboshaftType> Type::AllocateOnHeap(Factory* factory) const {
  DCHECK_NOT_NULL(factory);
  switch (kind_) {
    case Kind::kInvalid:
      UNREACHABLE();
    case Kind::kNone:
      UNIMPLEMENTED();
    case Kind::kWord32:
      return AsWord32().AllocateOnHeap(factory);
    case Kind::kWord64:
      return AsWord64().AllocateOnHeap(factory);
    case Kind::kFloat32:
      return AsFloat32().AllocateOnHeap(factory);
    case Kind::kFloat64:
      return AsFloat64().AllocateOnHeap(factory);
    case Kind::kTuple:
      UNIMPLEMENTED();
    case Kind::kAny:
      UNIMPLEMENTED();
  }
}

template <size_t Bits>
bool WordType<Bits>::Contains(word_t value) const {
  switch (sub_kind()) {
    case SubKind::kRange: {
      if (is_wrapping()) return range_to() >= value || range_from() <= value;
      return range_from() <= value && value <= range_to();
    }
    case SubKind::kSet: {
      for (int i = 0; i < set_size(); ++i) {
        if (set_element(i) == value) return true;
      }
      return false;
    }
  }
}

template <size_t Bits>
bool WordType<Bits>::Equals(const WordType<Bits>& other) const {
  if (sub_kind() != other.sub_kind()) return false;
  switch (sub_kind()) {
    case SubKind::kRange:
      return (range_from() == other.range_from() &&
              range_to() == other.range_to()) ||
             (is_any() && other.is_any());
    case SubKind::kSet: {
      if (set_size() != other.set_size()) return false;
      for (int i = 0; i < set_size(); ++i) {
        if (set_element(i) != other.set_element(i)) return false;
      }
      return true;
    }
  }
}

template <size_t Bits>
bool WordType<Bits>::IsSubtypeOf(const WordType<Bits>& other) const {
  if (other.is_any()) return true;
  switch (sub_kind()) {
    case SubKind::kRange: {
      if (other.is_set()) return false;
      DCHECK(other.is_range());
      if (is_wrapping() == other.is_wrapping()) {
        return range_from() >= other.range_from() &&
               range_to() <= other.range_to();
      }
      return !is_wrapping() && (range_to() <= other.range_to() ||
                                range_from() >= other.range_from());
    }
    case SubKind::kSet: {
      if (other.is_set() && set_size() > other.set_size()) return false;
      for (int i = 0; i < set_size(); ++i) {
        if (!other.Contains(set_element(i))) return false;
      }
      return true;
    }
  }
}

template <size_t Bits, typename word_t = typename WordType<Bits>::word_t>
WordType<Bits> LeastUpperBoundFromRanges(word_t l_from, word_t l_to,
                                         word_t r_from, word_t r_to,
                                         Zone* zone) {
  const bool lhs_wrapping = l_to < l_from;
  const bool rhs_wrapping = r_to < r_from;
  // Case 1: Both ranges non-wrapping
  // lhs ---|XXX|--  --|XXX|---  -|XXXXXX|-  ---|XX|--- -|XX|------
  // rhs -|XXX|----  ----|XXX|-  ---|XX|---  -|XXXXXX|- ------|XX|-
  // ==> -|XXXXX|--  --|XXXXX|-  -|XXXXXX|-  -|XXXXXX|- -|XXXXXXX|-
  if (!lhs_wrapping && !rhs_wrapping) {
    return WordType<Bits>::Range(std::min(l_from, r_from), std::max(l_to, r_to),
                                 zone);
  }
  // Case 2: Both ranges wrapping
  // lhs XXX|----|XXX   X|---|XXXXXX   XXXXXX|---|X   XX|--|XXXXXX
  // rhs X|---|XXXXXX   XXX|----|XXX   XX|--|XXXXXX   XXXXXX|--|XX
  // ==> XXX|-|XXXXXX   XXX|-|XXXXXX   XXXXXXXXXXXX   XXXXXXXXXXXX
  if (lhs_wrapping && rhs_wrapping) {
    const auto from = std::min(l_from, r_from);
    const auto to = std::max(l_to, r_to);
    if (to >= from) return WordType<Bits>::Any();
    auto result = WordType<Bits>::Range(from, to, zone);
    DCHECK(result.is_wrapping());
    return result;
  }

  if (rhs_wrapping)
    return LeastUpperBoundFromRanges<Bits>(r_from, r_to, l_from, l_to, zone);
  DCHECK(lhs_wrapping);
  DCHECK(!rhs_wrapping);
  // Case 3 & 4: lhs is wrapping, rhs is not
  // lhs XXX|----|XXX   XXX|----|XXX   XXXXX|--|XXX   X|-------|XX
  // rhs -------|XX|-   -|XX|-------   ----|XXXXX|-   ---|XX|-----
  // ==> XXX|---|XXXX   XXXX|---|XXX   XXXXXXXXXXXX   XXXXXX|--|XX
  if (r_from <= l_to) {
    if (r_to <= l_to)
      return WordType<Bits>::Range(l_from, l_to, zone);       // y covered by x
    if (r_to >= l_from) return WordType<Bits>::Any();         // ex3
    auto result = WordType<Bits>::Range(l_from, r_to, zone);  // ex 1
    DCHECK(result.is_wrapping());
    return result;
  } else if (r_to >= l_from) {
    if (r_from >= l_from)
      return WordType<Bits>::Range(l_from, l_to, zone);       // y covered by x
    DCHECK_GT(r_from, l_to);                                  // handled above
    auto result = WordType<Bits>::Range(r_from, l_to, zone);  // ex 2
    DCHECK(result.is_wrapping());
    return result;
  } else {
    const auto df = r_from - l_to;
    const auto dt = l_from - r_to;
    WordType<Bits> result =
        df > dt ? WordType<Bits>::Range(r_from, l_to, zone)  // ex 4
                : WordType<Bits>::Range(l_from, r_to, zone);
    DCHECK(result.is_wrapping());
    return result;
  }
}

template <size_t Bits>
// static
WordType<Bits> WordType<Bits>::LeastUpperBound(const WordType<Bits>& lhs,
                                               const WordType<Bits>& rhs,
                                               Zone* zone) {
  if (lhs.is_set()) {
    if (!rhs.is_set()) {
      if (lhs.set_size() == 1) {
        word_t e = lhs.set_element(0);
        if (rhs.is_wrapping()) {
          // If {rhs} already contains e, {rhs} is the upper bound.
          if (e <= rhs.range_to() || rhs.range_from() <= e) return rhs;
          return (e - rhs.range_to() < rhs.range_from() - e)
                     ? Range(rhs.range_from(), e, zone)
                     : Range(e, rhs.range_to(), zone);
        }
        return Range(std::min(e, rhs.range_from()), std::max(e, rhs.range_to()),
                     zone);
      }

      // TODO(nicohartmann@): A wrapping range may be a better fit in some
      // cases.
      return LeastUpperBoundFromRanges<Bits>(
          lhs.unsigned_min(), lhs.unsigned_max(), rhs.range_from(),
          rhs.range_to(), zone);
    }

    // Both sides are sets. We try to construct the combined set.
    base::SmallVector<word_t, kMaxSetSize * 2> result_elements;
    base::vector_append(result_elements, lhs.set_elements());
    base::vector_append(result_elements, rhs.set_elements());
    DCHECK(!result_elements.empty());
    base::sort(result_elements);
    auto it = std::unique(result_elements.begin(), result_elements.end());
    result_elements.pop_back(std::distance(it, result_elements.end()));
    if (result_elements.size() <= kMaxSetSize) {
      return Set(result_elements, zone);
    }
    // We have to construct a range instead.
    // TODO(nicohartmann@): A wrapping range may be a better fit in some cases.
    return Range(result_elements.front(), result_elements.back(), zone);
  } else if (rhs.is_set()) {
    return LeastUpperBound(rhs, lhs, zone);
  }

  // Both sides are ranges.
  return LeastUpperBoundFromRanges<Bits>(
      lhs.range_from(), lhs.range_to(), rhs.range_from(), rhs.range_to(), zone);
}

template <size_t Bits>
Type WordType<Bits>::Intersect(const WordType<Bits>& lhs,
                               const WordType<Bits>& rhs,
                               ResolutionMode resolution_mode, Zone* zone) {
  if (lhs.is_any()) return rhs;
  if (rhs.is_any()) return lhs;

  if (lhs.is_set() || rhs.is_set()) {
    const auto& x = lhs.is_set() ? lhs : rhs;
    const auto& y = lhs.is_set() ? rhs : lhs;
    base::SmallVector<word_t, kMaxSetSize * 2> result_elements;
    for (int i = 0; i < x.set_size(); ++i) {
      const word_t element = x.set_element(i);
      if (y.Contains(element)) result_elements.push_back(element);
    }
    if (result_elements.empty()) return Type::None();
    DCHECK(detail::is_unique_and_sorted(result_elements));
    return Set(result_elements, zone);
  }

  DCHECK(lhs.is_range() && rhs.is_range());
  const bool lhs_wrapping = lhs.is_wrapping();
  if (!lhs_wrapping && !rhs.is_wrapping()) {
    const auto result_from = std::max(lhs.range_from(), rhs.range_from());
    const auto result_to = std::min(lhs.range_to(), rhs.range_to());
    return result_to < result_from
               ? Type::None()
               : WordType::Range(result_from, result_to, zone);
  }

  if (lhs_wrapping && rhs.is_wrapping()) {
    const auto result_from = std::max(lhs.range_from(), rhs.range_from());
    const auto result_to = std::min(lhs.range_to(), rhs.range_to());
    auto result = WordType::Range(result_from, result_to, zone);
    DCHECK(result.is_wrapping());
    return result;
  }

  const auto& x = lhs_wrapping ? lhs : rhs;
  const auto& y = lhs_wrapping ? rhs : lhs;
  DCHECK(x.is_wrapping());
  DCHECK(!y.is_wrapping());
  auto subrange_low = Intersect(y, Range(0, x.range_to(), zone),
                                ResolutionMode::kPreciseOrInvalid, zone);
  DCHECK(!subrange_low.IsInvalid());
  auto subrange_high = Intersect(
      y, Range(x.range_from(), std::numeric_limits<word_t>::max(), zone),
      ResolutionMode::kPreciseOrInvalid, zone);
  DCHECK(!subrange_high.IsInvalid());

  if (subrange_low.IsNone()) return subrange_high;
  if (subrange_high.IsNone()) return subrange_low;
  auto s_l = subrange_low.template AsWord<Bits>();
  auto s_h = subrange_high.template AsWord<Bits>();

  switch (resolution_mode) {
    case ResolutionMode::kPreciseOrInvalid:
      return Type::Invalid();
    case ResolutionMode::kOverApproximate:
      return LeastUpperBound(s_l, s_h, zone);
    case ResolutionMode::kGreatestLowerBound:
      return (s_l.unsigned_max() - s_l.unsigned_min() <
              s_h.unsigned_max() - s_h.unsigned_min())
                 ? s_h
                 : s_l;
  }
}

template <size_t Bits>
void WordType<Bits>::PrintTo(std::ostream& stream) const {
  stream << (Bits == 32 ? "Word32" : "Word64");
  switch (sub_kind()) {
    case SubKind::kRange:
      stream << "[0x" << std::hex << range_from() << ", 0x" << range_to()
             << std::dec << "]";
      break;
    case SubKind::kSet:
      stream << "{" << std::hex;
      for (int i = 0; i < set_size(); ++i) {
        stream << (i == 0 ? "0x" : ", 0x");
        stream << set_element(i);
      }
      stream << std::dec << "}";
      break;
  }
}

template <size_t Bits>
Handle<TurboshaftType> WordType<Bits>::AllocateOnHeap(Factory* factory) const {
  if constexpr (Bits == 32) {
    if (is_range()) {
      return factory->NewTurboshaftWord32RangeType(range_from(), range_to(),
                                                   AllocationType::kYoung);
    } else {
      DCHECK(is_set());
      auto result = factory->NewTurboshaftWord32SetType(set_size(),
                                                        AllocationType::kYoung);
      for (int i = 0; i < set_size(); ++i) {
        result->set_elements(i, set_element(i));
      }
      return result;
    }
  } else {
    if (is_range()) {
      const auto [from_high, from_low] = uint64_to_high_low(range_from());
      const auto [to_high, to_low] = uint64_to_high_low(range_to());
      return factory->NewTurboshaftWord64RangeType(
          from_high, from_low, to_high, to_low, AllocationType::kYoung);
    } else {
      DCHECK(is_set());
      auto result = factory->NewTurboshaftWord64SetType(set_size(),
                                                        AllocationType::kYoung);
      for (int i = 0; i < set_size(); ++i) {
        const auto [high, low] = uint64_to_high_low(set_element(i));
        result->set_elements_high(i, high);
        result->set_elements_low(i, low);
      }
      return result;
    }
  }
}

template <size_t Bits>
bool FloatType<Bits>::Contains(float_t value) const {
  if (IsMinusZero(value)) return has_minus_zero();
  if (std::isnan(value)) return has_nan();
  switch (sub_kind()) {
    case SubKind::kOnlySpecialValues:
      return false;
    case SubKind::kRange: {
      return range_min() <= value && value <= range_max();
    }
    case SubKind::kSet: {
      for (int i = 0; i < set_size(); ++i) {
        if (set_element(i) == value) return true;
      }
      return false;
    }
  }
}

template <size_t Bits>
bool FloatType<Bits>::Equals(const FloatType<Bits>& other) const {
  if (sub_kind() != other.sub_kind()) return false;
  if (special_values() != other.special_values()) return false;
  switch (sub_kind()) {
    case SubKind::kOnlySpecialValues:
      return true;
    case SubKind::kRange: {
      return range() == other.range();
    }
    case SubKind::kSet: {
      if (set_size() != other.set_size()) {
        return false;
      }
      for (int i = 0; i < set_size(); ++i) {
        if (set_element(i) != other.set_element(i)) return false;
      }
      return true;
    }
  }
}

template <size_t Bits>
bool FloatType<Bits>::IsSubtypeOf(const FloatType<Bits>& other) const {
  if (special_values() & ~other.special_values()) return false;
  switch (sub_kind()) {
    case SubKind::kOnlySpecialValues:
      return true;
    case SubKind::kRange:
      if (!other.is_range()) {
        // This relies on the fact that we don't have singleton ranges.
        DCHECK_NE(range_min(), range_max());
        return false;
      }
      return other.range_min() <= range_min() &&
             range_max() <= other.range_max();
    case SubKind::kSet: {
      switch (other.sub_kind()) {
        case SubKind::kOnlySpecialValues:
          return false;
        case SubKind::kRange:
          return other.range_min() <= min() && max() <= other.range_max();
        case SubKind::kSet:
          for (int i = 0; i < set_size(); ++i) {
            if (!other.Contains(set_element(i))) return false;
          }
          return true;
      }
    }
  }
}

template <size_t Bits>
// static
FloatType<Bits> FloatType<Bits>::LeastUpperBound(const FloatType<Bits>& lhs,
                                                 const FloatType<Bits>& rhs,
                                                 Zone* zone) {
  uint32_t special_values = lhs.special_values() | rhs.special_values();
  if (lhs.is_any() || rhs.is_any()) {
    return Any(special_values);
  }

  const bool lhs_finite = lhs.is_set() || lhs.is_only_special_values();
  const bool rhs_finite = rhs.is_set() || rhs.is_only_special_values();

  if (lhs_finite && rhs_finite) {
    base::SmallVector<float_t, kMaxSetSize * 2> result_elements;
    if (lhs.is_set()) base::vector_append(result_elements, lhs.set_elements());
    if (rhs.is_set()) base::vector_append(result_elements, rhs.set_elements());
    if (result_elements.empty()) {
      return OnlySpecialValues(special_values);
    }
    base::sort(result_elements);
    auto it = std::unique(result_elements.begin(), result_elements.end());
    result_elements.pop_back(std::distance(it, result_elements.end()));
    if (result_elements.size() <= kMaxSetSize) {
      return Set(result_elements, special_values, zone);
    }
    return Range(result_elements.front(), result_elements.back(),
                 special_values, zone);
  } else if (lhs.is_only_special_values()) {
    return ReplacedSpecialValues(rhs, special_values).template AsFloat<Bits>();
  } else if (rhs.is_only_special_values()) {
    return ReplacedSpecialValues(lhs, special_values).template AsFloat<Bits>();
  }

  // We need to construct a range.
  float_t result_min = std::min(lhs.range_or_set_min(), rhs.range_or_set_min());
  float_t result_max = std::max(lhs.range_or_set_max(), rhs.range_or_set_max());
  return Range(result_min, result_max, special_values, zone);
}

template <size_t Bits>
// static
Type FloatType<Bits>::Intersect(const FloatType<Bits>& lhs,
                                const FloatType<Bits>& rhs, Zone* zone) {
  const uint32_t special_values = lhs.special_values() & rhs.special_values();
  if (lhs.is_any()) return ReplacedSpecialValues(rhs, special_values);
  if (rhs.is_any()) return ReplacedSpecialValues(lhs, special_values);
  if (lhs.is_only_special_values() || rhs.is_only_special_values()) {
    return special_values ? OnlySpecialValues(special_values) : Type::None();
  }

  if (lhs.is_set() || rhs.is_set()) {
    const auto& x = lhs.is_set() ? lhs : rhs;
    const auto& y = lhs.is_set() ? rhs : lhs;
    base::SmallVector<float_t, kMaxSetSize * 2> result_elements;
    for (int i = 0; i < x.set_size(); ++i) {
      const float_t element = x.set_element(i);
      if (y.Contains(element)) result_elements.push_back(element);
    }
    if (result_elements.empty()) {
      return special_values ? OnlySpecialValues(special_values) : Type::None();
    }
    return Set(result_elements, special_values, zone);
  }

  DCHECK(lhs.is_range() && rhs.is_range());
  const float_t result_min = std::max(lhs.min(), rhs.min());
  const float_t result_max = std::min(lhs.max(), rhs.max());
  if (result_min < result_max) {
    return Range(result_min, result_max, special_values, zone);
  } else if (result_min == result_max) {
    return Set({result_min}, special_values, zone);
  }
  return special_values ? OnlySpecialValues(special_values) : Type::None();
}

template <size_t Bits>
void FloatType<Bits>::PrintTo(std::ostream& stream) const {
  auto PrintSpecials = [this](auto& stream) {
    if (has_nan()) {
      stream << "NaN" << (has_minus_zero() ? "|MinusZero" : "");
    } else {
      DCHECK(has_minus_zero());
      stream << "MinusZero";
    }
  };
  stream << (Bits == 32 ? "Float32" : "Float64");
  switch (sub_kind()) {
    case SubKind::kOnlySpecialValues:
      PrintSpecials(stream);
      break;
    case SubKind::kRange:
      stream << "[" << range_min() << ", " << range_max() << "]";
      if (has_special_values()) {
        stream << "|";
        PrintSpecials(stream);
      }
      break;
    case SubKind::kSet:
      stream << "{";
      for (int i = 0; i < set_size(); ++i) {
        if (i != 0) stream << ", ";
        stream << set_element(i);
      }
      if (has_special_values()) {
        stream << "}|";
        PrintSpecials(stream);
      } else {
        stream << "}";
      }
      break;
  }
}

template <size_t Bits>
Handle<TurboshaftType> FloatType<Bits>::AllocateOnHeap(Factory* factory) const {
  float_t min = 0.0f, max = 0.0f;
  constexpr uint32_t padding = 0;
  if (is_only_special_values()) {
    min = std::numeric_limits<float_t>::infinity();
    max = -std::numeric_limits<float_t>::infinity();
    return factory->NewTurboshaftFloat64RangeType(
        special_values(), padding, min, max, AllocationType::kYoung);
  } else if (is_range()) {
    std::tie(min, max) = minmax();
    return factory->NewTurboshaftFloat64RangeType(
        special_values(), padding, min, max, AllocationType::kYoung);
  } else {
    DCHECK(is_set());
    auto result = factory->NewTurboshaftFloat64SetType(
        special_values(), set_size(), AllocationType::kYoung);
    for (int i = 0; i < set_size(); ++i) {
      result->set_elements(i, set_element(i));
    }
    return result;
  }
}

bool TupleType::Equals(const TupleType& other) const {
  if (size() != other.size()) return false;
  for (int i = 0; i < size(); ++i) {
    if (!element(i).Equals(other.element(i))) return false;
  }
  return true;
}

bool TupleType::IsSubtypeOf(const TupleType& other) const {
  if (size() != other.size()) return false;
  for (int i = 0; i < size(); ++i) {
    if (!element(i).IsSubtypeOf(other.element(i))) return false;
  }
  return true;
}

// static
Type TupleType::LeastUpperBound(const TupleType& lhs, const TupleType& rhs,
                                Zone* zone) {
  if (lhs.size() != rhs.size()) return Type::Any();
  Payload p;
  p.array = zone->AllocateArray<Type>(lhs.size());
  for (int i = 0; i < lhs.size(); ++i) {
    p.array[i] = Type::LeastUpperBound(lhs.element(i), rhs.element(i), zone);
  }
  return TupleType{static_cast<uint8_t>(lhs.size()), p};
}

void TupleType::PrintTo(std::ostream& stream) const {
  stream << "(";
  for (int i = 0; i < size(); ++i) {
    if (i != 0) stream << ", ";
    element(i).PrintTo(stream);
  }
  stream << ")";
}

template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) WordType<32>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) WordType<64>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) FloatType<32>;
template class EXPORT_TEMPLATE_DEFINE(V8_EXPORT_PRIVATE) FloatType<64>;

}  // namespace v8::internal::compiler::turboshaft

"""

```