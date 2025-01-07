Response:
Let's break down the thought process for analyzing this V8 header file.

1. **Initial Understanding - Context is Key:** The first thing to notice is the path: `v8/src/compiler/turboshaft/typer.h`. This tells us a lot:
    * `v8`: It's part of the V8 JavaScript engine.
    * `src/compiler`:  It's involved in the compilation process, not runtime execution.
    * `turboshaft`: This likely refers to a specific, newer or experimental part of the V8 compiler pipeline. Knowing this helps manage expectations – it's likely related to advanced type analysis.
    * `typer.h`:  The name strongly suggests its purpose: determining or inferring the *types* of values within the Turboshaft compiler. The `.h` extension confirms it's a C++ header file.

2. **Skimming for Core Components:** Next, quickly scan the file for significant structures and patterns.
    * **Includes:**  The `#include` directives point to fundamental V8 and standard library components: `logging`, `vector`, `operations.h`, `representations.h`, `types.h`. This reinforces the idea that this file deals with internal compiler structures and type representations.
    * **Namespaces:** The `v8::internal::compiler::turboshaft` namespace clearly delineates its belonging to the Turboshaft compiler.
    * **Templates:** The heavy use of templates like `array_min`, `array_max`, `WordOperationTyper`, and `FloatOperationTyper` is a key observation. Templates in C++ are often used for generic programming, meaning these structures and functions can work with different data types (like 32-bit and 64-bit words, or single and double-precision floats). This suggests the Typer needs to handle various primitive types.
    * **`WordOperationTyper`:**  This struct is clearly designed to handle operations on word-sized integers. It has methods like `FromElements`, `MakeRange`, `Add`, `Subtract`, and comparison operators (`UnsignedLessThan`, etc.). The comments within these methods provide valuable clues about their logic (handling wrapping ranges, set vs. range representations).
    * **`FloatOperationTyper`:** This struct mirrors `WordOperationTyper` but for floating-point numbers. It includes methods like `Range`, `Set`, `Add`, `Subtract`, `Multiply`, `Divide`, `Modulus`, `Min`, `Max`. The comments here highlight the nuances of floating-point arithmetic (NaN, -0, infinities).
    * **Helper Functions:** `array_min` and `array_max` are simple utilities for finding the minimum and maximum of an array, specifically handling NaN values.

3. **Deeper Dive into Key Structures (Focusing on Functionality):**  Now, examine the key structs more closely to understand their purpose:

    * **`WordOperationTyper`:**
        * **Purpose:** To perform type inference for arithmetic and comparison operations on word-sized integers.
        * **Type Representation:** Uses `WordType` which can be a set of specific values or a range. This is a common technique in static analysis to represent possible values.
        * **Range Handling:** The `MakeRange` functions and the logic within `Add` and `Subtract` demonstrate the Typer's ability to work with and manipulate ranges of values, including wrapping ranges (where the range wraps around the maximum value). This is crucial for handling unsigned integers.
        * **Comparison:** The `UnsignedLessThan` and related functions show how the Typer reasons about the possible outcomes of comparisons and how to refine the types of the operands based on the comparison result. The "RestrictionFor..." methods are vital for control-flow refinement within the compiler.
        * **Widening:** The `WidenMaximal` and `WidenExponential` methods address the problem of *type widening*. When the set of possible values becomes too large, the Typer needs to abstract the type to a broader range. The exponential widening strategy helps balance precision with efficiency.

    * **`FloatOperationTyper`:**
        * **Purpose:** Similar to `WordOperationTyper`, but for floating-point numbers.
        * **Complexity:** The logic here is more involved due to the intricacies of floating-point arithmetic (NaN, positive and negative zero, infinities).
        * **Set and Range Representations:** Also uses set and range representations for `FloatType`.
        * **Special Value Handling:**  Pays close attention to NaN and -0.
        * **Operation-Specific Logic:** Each arithmetic operation (`Add`, `Subtract`, `Multiply`, `Divide`, `Modulus`) has its own specific implementation, reflecting the different ways these operations behave with floating-point numbers. The comments are crucial for understanding the reasoning behind these implementations. The `ProductSet` helper function is used when both operands are represented as sets.

4. **Connecting to JavaScript (if applicable):**  Consider how these type operations relate to JavaScript behavior. While the header is C++, the types being manipulated ultimately represent JavaScript values.

    * **Word Operations:** Correspond to operations on integers in JavaScript (though JavaScript integers have quirks). Unsigned comparisons are less common in typical JavaScript but might arise from bitwise operations or when dealing with low-level data.
    * **Float Operations:** Directly relate to JavaScript's Number type, which is a double-precision floating-point number. The handling of NaN and -0 is essential for correctly modeling JavaScript's floating-point behavior.

5. **Considering Common Programming Errors:** Think about how the Typer's logic might prevent or detect common JavaScript errors.

    * **Type Mismatches:** By tracking types, the compiler can potentially identify operations performed on incompatible types (though JavaScript is dynamically typed, so this happens at runtime, but the compiler can still optimize based on inferred types).
    * **NaN and Infinity:** The explicit handling of NaN and Infinity in `FloatOperationTyper` suggests the compiler is designed to reason about these special values, which can be sources of bugs in JavaScript.
    * **Integer Overflow/Underflow:** While JavaScript numbers are generally floats, the `WordOperationTyper` might be relevant for internal representations or when dealing with bitwise operations. The wrapping range logic hints at handling potential overflows.

6. **Structuring the Summary:** Finally, organize the findings into a coherent summary, addressing the specific points requested in the prompt:

    * **Core Function:** Clearly state the main purpose of the header file.
    * **Torque:** Check the file extension.
    * **JavaScript Relation:** Explain how the Typer's functionality relates to JavaScript concepts and provide illustrative examples.
    * **Code Logic/Inference:** Select a representative example (like the `Add` method in `WordOperationTyper`) and explain its input, logic, and output.
    * **Common Errors:** Give examples of JavaScript errors that the Typer's analysis might help with.
    * **Concise Summary:**  Provide a brief overall summary of the file's role.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  "Is this about static typing in JavaScript?"  **Correction:** JavaScript is dynamically typed, but the compiler performs *type inference* to optimize. This header is about that inference process.
* **Initial thought:** "The `WordOperationTyper` is only for 32/64 bit integers." **Refinement:** While it's templated for 32/64 bits, these could be used to represent various integer-like values internally, not just exactly matching JavaScript's integer type.
* **Focus on *how* it works, not just *what* it does:**  Instead of just saying "it adds types," explain the different type representations (set, range) and the logic for combining them.

By following this structured approach, combining initial understanding with detailed examination and considering the broader context of the V8 compiler and JavaScript, we can effectively analyze and summarize the functionality of this header file.好的，让我们来分析一下 `v8/src/compiler/turboshaft/typer.h` 这个 V8 源代码文件。

**功能归纳：**

`v8/src/compiler/turboshaft/typer.h` 定义了一组用于在 V8 的 Turboshaft 编译器中进行类型推断和操作的工具和模板。它的主要功能可以概括为：

1. **定义了用于表示和操作类型信息的结构体和工具函数。**  特别是针对字 (Word) 类型和浮点数 (Float) 类型，提供了专门的 `WordOperationTyper` 和 `FloatOperationTyper` 模板结构体。
2. **实现了对基本算术运算（加法、减法、乘法、除法、取模）和比较运算进行类型推断的逻辑。** 这些逻辑考虑了各种边界情况，例如 NaN (非数字)、正负零、无穷大等。
3. **提供了类型范围表示和操作的功能。** 例如，可以将一组离散的值表示为一个集合 (Set) 或一个连续的范围 (Range)，并提供了在两者之间转换的机制。
4. **实现了类型拓宽 (Widening) 的策略。** 当类型信息变得过于具体或庞大时，需要将其抽象化为一个更宽泛的类型，以提高编译效率。文件中定义了 `WidenMaximal` 和 `WidenExponential` 两种拓宽策略。
5. **为比较操作（如小于、小于等于）的结果提供了类型推断，并能根据比较结果限制操作数的类型范围。** 这对于优化控制流和条件语句非常重要。

**关于文件类型和 JavaScript 关系：**

* **文件类型:** `v8/src/compiler/turboshaft/typer.h` 的后缀是 `.h`，这表明它是一个 C++ 头文件，而不是 Torque 源代码文件。Torque 文件的后缀通常是 `.tq`。
* **与 JavaScript 的关系:** 这个文件中的代码直接服务于 V8 JavaScript 引擎的编译过程。Turboshaft 是 V8 中一个新的编译器管道，`typer.h` 中的代码负责分析 JavaScript 代码中变量和表达式的类型，以便编译器能够进行更有效的优化。

**JavaScript 示例说明：**

虽然 `typer.h` 是 C++ 代码，但它的目的是理解和优化 JavaScript 代码。以下是一些与文件中功能相关的 JavaScript 示例：

* **类型推断:**

```javascript
function add(a, b) {
  return a + b;
}

add(5, 10); // Turboshaft 的 Typer 可以推断出 a 和 b 可能是数字类型，返回结果也是数字类型。
add("hello", " world"); // Typer 可以推断出 a 和 b 可能是字符串类型，返回结果也是字符串类型。
```

* **范围表示:**

```javascript
function checkRange(x) {
  if (x > 0 && x < 10) {
    // Typer 可能会将 x 的类型表示为一个 0 到 10 的开区间范围。
    return "in range";
  } else {
    return "out of range";
  }
}
```

* **浮点数处理:**

```javascript
let nanValue = NaN;
let positiveZero = 0;
let negativeZero = -0;
let infinityValue = Infinity;

let result1 = nanValue + 5; // Typer 会知道结果可能是 NaN
let result2 = positiveZero / infinityValue; // Typer 会处理正负零和无穷大的运算
```

**代码逻辑推理示例（基于 `WordOperationTyper::Add`）：**

**假设输入：**

* `lhs` 的类型是 `Word32Type::Range(5, 10, zone)`，表示一个 32 位无符号整数范围，值为 5 到 10。
* `rhs` 的类型是 `Word32Type::Set({2, 4}, zone)`，表示一个 32 位无符号整数集合，值为 2 或 4。
* `zone` 是内存分配区域。

**代码逻辑 (`WordOperationTyper::Add`)：**

由于 `rhs` 是一个集合，代码会遍历 `lhs` 范围内的所有可能值与 `rhs` 集合中的每个元素进行相加，生成结果集合。

**输出：**

`Word32Type::Set({7, 9, 11, 14}, zone)`

**推理过程：**

* 5 + 2 = 7
* 5 + 4 = 9
* 6 + 2 = 8
* 6 + 4 = 10
* 7 + 2 = 9
* 7 + 4 = 11
* 8 + 2 = 10
* 8 + 4 = 12
* 9 + 2 = 11
* 9 + 4 = 13
* 10 + 2 = 12
* 10 + 4 = 14

去除重复项并排序得到 `{7, 8, 9, 10, 11, 12, 13, 14}`。如果结果集合大小没有超过 `kMaxSetSize`，则返回该集合。如果超过了，则会尝试将其表示为一个范围。

**用户常见的编程错误示例：**

* **类型假设错误:** 开发者可能错误地假设某个变量总是特定的类型，而忽略了 JavaScript 的动态类型特性。Typer 可以帮助编译器识别潜在的类型不匹配问题。

```javascript
function process(input) {
  return input.toUpperCase(); // 开发者可能假设 input 是字符串
}

process("hello"); // 正常工作
process(123);    // 运行时错误，因为数字没有 toUpperCase 方法

// Typer 可能会尝试推断 input 的多种可能性类型，并为潜在的错误路径生成代码。
```

* **浮点数比较错误:**  直接比较浮点数是否相等可能会由于精度问题导致错误。Typer 可以帮助理解浮点数运算的潜在结果范围。

```javascript
let a = 0.1 + 0.2;
let b = 0.3;

if (a === b) { // 结果通常为 false，因为浮点数运算存在精度问题
  console.log("相等");
} else {
  console.log("不相等"); // 实际会输出这个
}

// Typer 可以分析 0.1 + 0.2 的结果范围，并意识到它可能不完全等于 0.3。
```

* **未处理 NaN 的情况:**  浮点数运算可能产生 NaN，如果不进行处理，可能会导致程序逻辑错误。

```javascript
function safeDivide(a, b) {
  if (b === 0) {
    return 0; // 尝试避免除零错误
  }
  return a / b;
}

let result = safeDivide(10, 0); // result 的值是 Infinity，而不是 0
let anotherResult = safeDivide(0, 0); // anotherResult 的值是 NaN

// Typer 可以帮助分析除法运算可能产生 NaN 或 Infinity 的情况，并提醒开发者进行处理。
```

**总结一下 `v8/src/compiler/turboshaft/typer.h` 的功能：**

这个头文件是 V8 Turboshaft 编译器中类型推断的核心组件。它定义了表示和操作类型信息的结构，并实现了对各种运算进行类型分析的逻辑。其目的是为了更精确地理解 JavaScript 代码中变量和表达式的类型，从而使编译器能够进行更有效的代码优化。它处理了包括基本类型、范围、浮点数的特殊值以及类型拓宽等复杂场景，并在编译时为潜在的运行时错误提供了一定的分析能力。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/typer.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/turboshaft/typer.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2023 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_COMPILER_TURBOSHAFT_TYPER_H_
#define V8_COMPILER_TURBOSHAFT_TYPER_H_

#include <limits>

#include "src/base/logging.h"
#include "src/base/vector.h"
#include "src/compiler/turboshaft/operations.h"
#include "src/compiler/turboshaft/representations.h"
#include "src/compiler/turboshaft/types.h"

namespace v8::internal::compiler::turboshaft {

// Returns the array's least element, ignoring NaN.
// There must be at least one non-NaN element.
// Any -0 is converted to 0.
template <typename T, size_t N>
T array_min(const std::array<T, N>& a) {
  DCHECK_NE(0, N);
  T x = +std::numeric_limits<T>::infinity();
  for (size_t i = 0; i < N; ++i) {
    if (!std::isnan(a[i])) {
      x = std::min(a[i], x);
    }
  }
  DCHECK(!std::isnan(x));
  return x == T{0} ? T{0} : x;  // -0 -> 0
}

// Returns the array's greatest element, ignoring NaN.
// There must be at least one non-NaN element.
// Any -0 is converted to 0.
template <typename T, size_t N>
T array_max(const std::array<T, N>& a) {
  DCHECK_NE(0, N);
  T x = -std::numeric_limits<T>::infinity();
  for (size_t i = 0; i < N; ++i) {
    if (!std::isnan(a[i])) {
      x = std::max(a[i], x);
    }
  }
  DCHECK(!std::isnan(x));
  return x == T{0} ? T{0} : x;  // -0 -> 0
}

template <size_t Bits>
struct WordOperationTyper {
  static_assert(Bits == 32 || Bits == 64);
  using word_t = uint_type<Bits>;
  using type_t = WordType<Bits>;
  using ElementsVector = base::SmallVector<word_t, type_t::kMaxSetSize * 2>;
  static constexpr word_t max = std::numeric_limits<word_t>::max();

  static type_t FromElements(ElementsVector elements, Zone* zone) {
    base::sort(elements);
    auto it = std::unique(elements.begin(), elements.end());
    elements.pop_back(std::distance(it, elements.end()));
    DCHECK(!elements.empty());
    if (elements.size() <= type_t::kMaxSetSize) {
      return type_t::Set(elements, zone);
    }

    auto range = MakeRange(base::VectorOf(elements));
    auto result = type_t::Range(range.first, range.second, zone);
    DCHECK(
        base::all_of(elements, [&](word_t e) { return result.Contains(e); }));
    return result;
  }

  static std::pair<word_t, word_t> MakeRange(const type_t& t) {
    if (t.is_range()) return t.range();
    DCHECK(t.is_set());
    return MakeRange(t.set_elements());
  }

  // This function tries to find a somewhat reasonable range for a given set of
  // values. If the elements span no more than half of the range, we just
  // construct the range from min(elements) to max(elements) Otherwise, we
  // consider a wrapping range because it is likely that there is a larger gap
  // in the middle of the elements. For that, we start with a wrapping range
  // from max(elements) to min(elements) and then incrementally add another
  // element either by increasing the 'to' or decreasing the 'from' of the
  // range, whichever leads to a smaller range.
  static std::pair<word_t, word_t> MakeRange(
      base::Vector<const word_t> elements) {
    DCHECK(!elements.empty());
    DCHECK(detail::is_unique_and_sorted(elements));
    if (elements[elements.size() - 1] - elements[0] <= max / 2) {
      // Construct a non-wrapping range.
      return {elements[0], elements[elements.size() - 1]};
    }
    // Construct a wrapping range.
    size_t from_index = elements.size() - 1;
    size_t to_index = 0;
    while (to_index + 1 < from_index) {
      if ((elements[to_index + 1] - elements[to_index]) <
          (elements[from_index] - elements[from_index - 1])) {
        ++to_index;
      } else {
        --from_index;
      }
    }
    return {elements[from_index], elements[to_index]};
  }

  static word_t distance(const std::pair<word_t, word_t>& range) {
    return distance(range.first, range.second);
  }
  static word_t distance(word_t from, word_t to) {
    return is_wrapping(from, to) ? (max - from + to) : to - from;
  }

  static bool is_wrapping(const std::pair<word_t, word_t>& range) {
    return is_wrapping(range.first, range.second);
  }
  static bool is_wrapping(word_t from, word_t to) { return from > to; }

  static type_t Add(const type_t& lhs, const type_t& rhs, Zone* zone) {
    if (lhs.is_any() || rhs.is_any()) return type_t::Any();

    // If both sides are decently small sets, we produce the product set (which
    // we convert to a range if it exceeds the set limit).
    if (lhs.is_set() && rhs.is_set()) {
      ElementsVector result_elements;
      for (int i = 0; i < lhs.set_size(); ++i) {
        for (int j = 0; j < rhs.set_size(); ++j) {
          result_elements.push_back(lhs.set_element(i) + rhs.set_element(j));
        }
      }
      return FromElements(std::move(result_elements), zone);
    }

    // Otherwise just construct a range.
    std::pair<word_t, word_t> x = MakeRange(lhs);
    std::pair<word_t, word_t> y = MakeRange(rhs);

    // If the result would not be a complete range, we compute it.
    // Check: (lhs.to - lhs.from + 1) + rhs.to - rhs.from < max
    // =====> (lhs.to - lhs.from + 1) < max - rhs.to + rhs.from
    // =====> (lhs.to - lhs.from + 1) < max - (rhs.to - rhs.from)
    if (distance(x) + 1 < max - distance(y)) {
      return type_t::Range(x.first + y.first, x.second + y.second, zone);
    }

    return type_t::Any();
  }

  static type_t Subtract(const type_t& lhs, const type_t& rhs, Zone* zone) {
    if (lhs.is_any() || rhs.is_any()) return type_t::Any();

    // If both sides are decently small sets, we produce the product set (which
    // we convert to a range if it exceeds the set limit).
    if (lhs.is_set() && rhs.is_set()) {
      ElementsVector result_elements;
      for (int i = 0; i < lhs.set_size(); ++i) {
        for (int j = 0; j < rhs.set_size(); ++j) {
          result_elements.push_back(lhs.set_element(i) - rhs.set_element(j));
        }
      }
      return FromElements(std::move(result_elements), zone);
    }

    // Otherwise just construct a range.
    std::pair<word_t, word_t> x = MakeRange(lhs);
    std::pair<word_t, word_t> y = MakeRange(rhs);

    if (!is_wrapping(x) && !is_wrapping(y)) {
      // If the result would not be a complete range, we compute it.
      // Check: (lhs.to - lhs.from + 1) + rhs.to - rhs.from < max
      // =====> (lhs.to - lhs.from + 1) < max - rhs.to + rhs.from
      // =====> (lhs.to - lhs.from + 1) < max - (rhs.to - rhs.from)
      if (distance(x) + 1 < max - distance(y)) {
        return type_t::Range(x.first - y.second, x.second - y.first, zone);
      }
    }

    // TODO(nicohartmann@): Improve the wrapping cases.
    return type_t::Any();
  }

  static Word32Type UnsignedLessThan(const type_t& lhs, const type_t& rhs,
                                     Zone* zone) {
    bool can_be_true = lhs.unsigned_min() < rhs.unsigned_max();
    bool can_be_false = lhs.unsigned_max() >= rhs.unsigned_min();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  static Word32Type UnsignedLessThanOrEqual(const type_t& lhs,
                                            const type_t& rhs, Zone* zone) {
    bool can_be_true = lhs.unsigned_min() <= rhs.unsigned_max();
    bool can_be_false = lhs.unsigned_max() > rhs.unsigned_min();

    if (!can_be_true) return Word32Type::Constant(0);
    if (!can_be_false) return Word32Type::Constant(1);
    return Word32Type::Set({0, 1}, zone);
  }

  // Computes the ranges to which the sides of the unsigned comparison (lhs <
  // rhs) can be restricted when the comparison is true. When the comparison is
  // true, we learn: lhs cannot be >= rhs.max and rhs cannot be <= lhs.min.
  static std::pair<Type, Type> RestrictionForUnsignedLessThan_True(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    Type restrict_lhs;
    if (rhs.unsigned_max() == 0) {
      // There is no value for lhs that could make (lhs < 0) true.
      restrict_lhs = Type::None();
    } else {
      restrict_lhs = type_t::Range(0, next_smaller(rhs.unsigned_max()), zone);
    }

    Type restrict_rhs;
    if (lhs.unsigned_min() == max) {
      // There is no value for rhs that could make (max < rhs) true.
      restrict_rhs = Type::None();
    } else {
      restrict_rhs = type_t::Range(next_larger(lhs.unsigned_min()), max, zone);
    }

    return {restrict_lhs, restrict_rhs};
  }

  // Computes the ranges to which the sides of the unsigned comparison (lhs <
  // rhs) can be restricted when the comparison is false. When the comparison is
  // false, we learn: lhs cannot be < rhs.min and rhs cannot be > lhs.max.
  static std::pair<Type, Type> RestrictionForUnsignedLessThan_False(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    return {type_t::Range(rhs.unsigned_min(), max, zone),
            type_t::Range(0, lhs.unsigned_max(), zone)};
  }

  // Computes the ranges to which the sides of the unsigned comparison (lhs <=
  // rhs) can be restricted when the comparison is true. When the comparison is
  // true, we learn: lhs cannot be > rhs.max and rhs cannot be < lhs.min.
  static std::pair<Type, Type> RestrictionForUnsignedLessThanOrEqual_True(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    return {type_t::Range(0, rhs.unsigned_max(), zone),
            type_t::Range(lhs.unsigned_min(), max, zone)};
  }

  // Computes the ranges to which the sides of the unsigned comparison (lhs <=
  // rhs) can be restricted when the comparison is false. When the comparison is
  // false, we learn: lhs cannot be <= rhs.min and rhs cannot be >= lhs.max.
  static std::pair<Type, Type> RestrictionForUnsignedLessThanOrEqual_False(
      const type_t& lhs, const type_t& rhs, Zone* zone) {
    Type restrict_lhs;
    if (rhs.unsigned_min() == max) {
      // There is no value for lhs that could make (lhs <= max) false.
      restrict_lhs = Type::None();
    } else {
      restrict_lhs = type_t::Range(next_larger(rhs.unsigned_min()), max, zone);
    }

    Type restrict_rhs;
    if (lhs.unsigned_max() == 0) {
      // There is no value for rhs that could make (0 <= rhs) false.
      restrict_rhs = Type::None();
    } else {
      restrict_rhs = type_t::Range(0, next_smaller(lhs.unsigned_max()), zone);
    }

    return {restrict_lhs, restrict_rhs};
  }

  // WidenMaximal widens one of the boundary to the extreme immediately.
  static type_t WidenMaximal(const type_t& old_type, const type_t& new_type,
                             Zone* zone) {
    if (new_type.is_any()) return new_type;
    if (old_type.is_wrapping() || new_type.is_wrapping()) return type_t::Any();

    word_t result_from = new_type.unsigned_min();
    if (result_from < old_type.unsigned_min()) result_from = 0;
    word_t result_to = new_type.unsigned_max();
    if (result_to > old_type.unsigned_max()) {
      result_to = std::numeric_limits<word_t>::max();
    }
    return type_t::Range(result_from, result_to, zone);
  }

  // Performs exponential widening, which means that the number of values
  // described by the resulting type is at least doubled with respect to the
  // {old_type}. If {new_type} is already twice the size of {old_type},
  // {new_type} may be returned directly.
  static type_t WidenExponential(const type_t& old_type, type_t new_type,
                                 Zone* zone) {
    if (new_type.is_any()) return new_type;
    word_t old_from, old_to, new_from, new_to;
    if (old_type.is_set()) {
      const word_t old_size = old_type.set_size();
      if (new_type.is_set()) {
        const word_t new_size = new_type.set_size();
        if (new_size >= 2 * old_size) return new_type;
        std::tie(new_from, new_to) = MakeRange(new_type);
      } else {
        DCHECK(new_type.is_range());
        std::tie(new_from, new_to) = new_type.range();
      }
      if (distance(new_from, new_to) >= 2 * old_size) {
        return type_t::Range(new_from, new_to, zone);
      }
      std::tie(old_from, old_to) = MakeRange(old_type);
    } else {
      DCHECK(old_type.is_range());
      std::tie(old_from, old_to) = old_type.range();
      if (new_type.is_set()) {
        std::tie(new_from, new_to) = MakeRange(new_type);
      } else {
        DCHECK(new_type.is_range());
        std::tie(new_from, new_to) = new_type.range();
      }
    }

    // If the old type is already quite large, we go to full range.
    if (distance(old_from, old_to) >= std::numeric_limits<word_t>::max() / 4) {
      return type_t::Any();
    }

    const word_t min_size = 2 * (distance(old_from, old_to) + 1);
    if (distance(new_from, new_to) >= min_size) {
      return type_t::Range(new_from, new_to, zone);
    }

    // If old is wrapping (and so is new).
    if (is_wrapping(old_from, old_to)) {
      DCHECK(is_wrapping(new_from, new_to));
      if (new_from < old_from) {
        DCHECK_LE(old_to, new_to);
        // We widen the `from` (although `to` might have grown, too).
        DCHECK_LT(new_to, min_size);
        word_t result_from =
            std::numeric_limits<word_t>::max() - (min_size - new_to);
        DCHECK_LT(result_from, new_from);
        DCHECK_LE(min_size, distance(result_from, new_to));
        return type_t::Range(result_from, new_to, zone);
      } else {
        DCHECK_EQ(old_from, new_from);
        // We widen the `to`.
        DCHECK_LT(std::numeric_limits<word_t>::max() - new_from, min_size);
        word_t result_to =
            min_size - (std::numeric_limits<word_t>::max() - new_from);
        DCHECK_GT(result_to, new_to);
        DCHECK_LE(min_size, distance(new_from, result_to));
        return type_t::Range(new_from, result_to, zone);
      }
    }

    // If old is not wrapping, but new is.
    if (is_wrapping(new_from, new_to)) {
      if (new_to < old_to) {
        // If wrapping was caused by to growing over max, grow `to` further
        // (although `from` might have grown, too).
        DCHECK_LT(std::numeric_limits<word_t>::max() - new_from, min_size);
        word_t result_to =
            min_size - (std::numeric_limits<word_t>::max() - new_from);
        DCHECK_LT(new_to, result_to);
        return type_t::Range(new_from, result_to, zone);
      } else {
        DCHECK_LT(old_from, new_from);
        // If wrapping was caused by `from` growing below 0, grow `from`
        // further.
        DCHECK_LT(new_to, min_size);
        word_t result_from =
            std::numeric_limits<word_t>::max() - (min_size - new_to);
        DCHECK_LT(result_from, new_from);
        return type_t::Range(result_from, new_to, zone);
      }
    }

    // Neither old nor new is wrapping.
    if (new_from < old_from) {
      DCHECK_LE(old_to, new_to);
      // Check if we can widen the `from`.
      if (new_to >= min_size) {
        // We can decrease `from` without going below 0.
        word_t result_from = new_to - min_size;
        DCHECK_LT(result_from, new_from);
        return type_t::Range(result_from, new_to, zone);
      } else {
        // We cannot grow `from` enough, so we also have to grow `to`.
        return type_t::Range(0, min_size, zone);
      }
    } else {
      DCHECK_EQ(old_from, new_from);
      // Check if we can widen the `to`.
      if (new_from <= std::numeric_limits<word_t>::max() - min_size) {
        // We can increase `to` without going above max.
        word_t result_to = new_from + min_size;
        DCHECK_GT(result_to, new_to);
        return type_t::Range(new_from, result_to, zone);
      } else {
        // We cannot grow `to` enough, so we also have to grow `from`.
        return type_t::Range(std::numeric_limits<word_t>::max() - min_size,
                             std::numeric_limits<word_t>::max(), zone);
      }
    }
  }
};

template <size_t Bits>
struct FloatOperationTyper {
  static_assert(Bits == 32 || Bits == 64);
  using float_t = std::conditional_t<Bits == 32, float, double>;
  using type_t = FloatType<Bits>;
  static constexpr float_t inf = std::numeric_limits<float_t>::infinity();
  static constexpr int kSetThreshold = type_t::kMaxSetSize;

  static type_t Range(float_t min, float_t max, uint32_t special_values,
                      Zone* zone) {
    DCHECK_LE(min, max);
    DCHECK_IMPLIES(detail::is_minus_zero(min),
                   (special_values & type_t::kMinusZero));
    DCHECK_IMPLIES(detail::is_minus_zero(max),
                   (special_values & type_t::kMinusZero));
    if (min == max) return Set({min + float_t{0}}, special_values, zone);
    return type_t::Range(min, max, special_values, zone);
  }

  static type_t Set(std::vector<float_t> elements, uint32_t special_values,
                    Zone* zone) {
    base::sort(elements);
    elements.erase(std::unique(elements.begin(), elements.end()),
                   elements.end());
    if (base::erase_if(elements, [](float_t v) { return std::isnan(v); }) > 0) {
      special_values |= type_t::kNaN;
    }
    if (base::erase_if(elements, [](float_t v) { return IsMinusZero(v); }) >
        0) {
      special_values |= type_t::kMinusZero;
    }
    if (elements.empty()) {
      DCHECK_NE(0, special_values);
      return type_t::OnlySpecialValues(special_values);
    }
    return type_t::Set(elements, special_values, zone);
  }

  // Check if the elements in the set are all integers. This ignores special
  // values (NaN, -0)!
  static bool IsIntegerSet(const type_t& t) {
    if (!t.is_set()) return false;
    int size = t.set_size();
    DCHECK_LT(0, size);

    float_t unused_ipart;
    float_t min = t.set_element(0);
    if (std::modf(min, &unused_ipart) != 0.0) return false;
    if (min == -inf) return false;
    float_t max = t.set_element(size - 1);
    if (std::modf(max, &unused_ipart) != 0.0) return false;
    if (max == inf) return false;

    for (int i = 1; i < size - 1; ++i) {
      if (std::modf(t.set_element(i), &unused_ipart) != 0.0) return false;
    }
    return true;
  }

  static bool IsZeroish(const type_t& l) {
    return l.has_nan() || l.has_minus_zero() || l.Contains(0);
  }

  // Tries to construct the product of two sets where values are generated using
  // {combine}. Returns Type::Invalid() if a set cannot be constructed (e.g.
  // because the result exceeds the maximal number of set elements).
  static Type ProductSet(const type_t& l, const type_t& r,
                         uint32_t special_values, Zone* zone,
                         std::function<float_t(float_t, float_t)> combine) {
    DCHECK(l.is_set());
    DCHECK(r.is_set());

    std::vector<float_t> results;
    auto CombineWithLeft = [&](float_t left) {
      for (int j = 0; j < r.set_size(); ++j) {
        results.push_back(combine(left, r.set_element(j)));
      }
      if (r.has_minus_zero()) results.push_back(combine(left, -0.0));
      if (r.has_nan()) results.push_back(combine(left, nan_v<Bits>));
    };

    for (int i = 0; i < l.set_size(); ++i) {
      CombineWithLeft(l.set_element(i));
    }
    if (l.has_minus_zero()) CombineWithLeft(-0.0);
    if (l.has_nan()) CombineWithLeft(nan_v<Bits>);

    if (base::erase_if(results, [](float_t v) { return std::isnan(v); }) > 0) {
      special_values |= type_t::kNaN;
    }
    if (base::erase_if(results, [](float_t v) { return IsMinusZero(v); }) > 0) {
      special_values |= type_t::kMinusZero;
    }
    base::sort(results);
    auto it = std::unique(results.begin(), results.end());
    if (std::distance(results.begin(), it) > kSetThreshold)
      return Type::Invalid();
    results.erase(it, results.end());
    if (results.empty()) return type_t::OnlySpecialValues(special_values);
    return Set(std::move(results), special_values, zone);
  }

  static Type Add(type_t l, type_t r, Zone* zone) {
    // Addition can return NaN if either input can be NaN or we try to compute
    // the sum of two infinities of opposite sign.
    if (l.is_only_nan() || r.is_only_nan()) return type_t::NaN();
    bool maybe_nan = l.has_nan() || r.has_nan();

    // Addition can yield minus zero only if both inputs can be minus zero.
    bool maybe_minuszero = true;
    if (l.has_minus_zero()) {
      l = type_t::LeastUpperBound(l, type_t::Constant(0), zone);
    } else {
      maybe_minuszero = false;
    }
    if (r.has_minus_zero()) {
      r = type_t::LeastUpperBound(r, type_t::Constant(0), zone);
    } else {
      maybe_minuszero = false;
    }

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);
    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return a + b; };
    if (l.is_set() && r.is_set()) {
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // Otherwise just construct a range.
    auto [l_min, l_max] = l.minmax();
    auto [r_min, r_max] = r.minmax();

    std::array<float_t, 4> results;
    results[0] = l_min + r_min;
    results[1] = l_min + r_max;
    results[2] = l_max + r_min;
    results[3] = l_max + r_max;

    int nans = 0;
    for (int i = 0; i < 4; ++i) {
      if (std::isnan(results[i])) ++nans;
    }
    if (nans > 0) {
      special_values |= type_t::kNaN;
      if (nans >= 4) {
        // All combinations of inputs produce NaN.
        return type_t::OnlySpecialValues(special_values);
      }
    }
    const float_t result_min = array_min(results);
    const float_t result_max = array_max(results);
    return Range(result_min, result_max, special_values, zone);
  }

  static Type Subtract(type_t l, type_t r, Zone* zone) {
    // Subtraction can return NaN if either input can be NaN or we try to
    // compute the sum of two infinities of opposite sign.
    if (l.is_only_nan() || r.is_only_nan()) return type_t::NaN();
    bool maybe_nan = l.has_nan() || r.has_nan();

    // Subtraction can yield minus zero if {lhs} can be minus zero and {rhs}
    // can be zero.
    bool maybe_minuszero = false;
    if (l.has_minus_zero()) {
      l = type_t::LeastUpperBound(l, type_t::Constant(0), zone);
      maybe_minuszero = r.Contains(0);
    }
    if (r.has_minus_zero()) {
      r = type_t::LeastUpperBound(r, type_t::Constant(0), zone);
    }

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);
    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return a - b; };
    if (l.is_set() && r.is_set()) {
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // Otherwise just construct a range.
    auto [l_min, l_max] = l.minmax();
    auto [r_min, r_max] = r.minmax();

    std::array<float_t, 4> results;
    results[0] = l_min - r_min;
    results[1] = l_min - r_max;
    results[2] = l_max - r_min;
    results[3] = l_max - r_max;

    int nans = 0;
    for (int i = 0; i < 4; ++i) {
      if (std::isnan(results[i])) ++nans;
    }
    if (nans > 0) {
      special_values |= type_t::kNaN;
      if (nans >= 4) {
        // All combinations of inputs produce NaN.
        return type_t::NaN();
      }
    }
    const float_t result_min = array_min(results);
    const float_t result_max = array_max(results);
    return Range(result_min, result_max, special_values, zone);
  }

  static Type Multiply(type_t l, type_t r, Zone* zone) {
    // Multiplication propagates NaN:
    //   NaN * x = NaN         (regardless of sign of x)
    //   0 * Infinity = NaN    (regardless of signs)
    if (l.is_only_nan() || r.is_only_nan()) return type_t::NaN();
    bool maybe_nan = l.has_nan() || r.has_nan() ||
                     (IsZeroish(l) && (r.min() == -inf || r.max() == inf)) ||
                     (IsZeroish(r) && (l.min() == -inf || r.max() == inf));

    // Try to rule out -0.
    bool maybe_minuszero = l.has_minus_zero() || r.has_minus_zero() ||
                           (IsZeroish(l) && r.min() < 0.0) ||
                           (IsZeroish(r) && l.min() < 0.0);
    if (l.has_minus_zero()) {
      l = type_t::LeastUpperBound(l, type_t::Constant(0), zone);
    }
    if (r.has_minus_zero()) {
      r = type_t::LeastUpperBound(r, type_t::Constant(0), zone);
    }

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);
    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return a * b; };
    if (l.is_set() && r.is_set()) {
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // Otherwise just construct a range.
    auto [l_min, l_max] = l.minmax();
    auto [r_min, r_max] = r.minmax();

    std::array<float_t, 4> results;
    results[0] = l_min * r_min;
    results[1] = l_min * r_max;
    results[2] = l_max * r_min;
    results[3] = l_max * r_max;

    for (int i = 0; i < 4; ++i) {
      if (std::isnan(results[i])) {
        return type_t::Any();
      }
    }

    float_t result_min = array_min(results);
    float_t result_max = array_max(results);
    if (result_min <= 0.0 && 0.0 <= result_max &&
        (l_min < 0.0 || r_min < 0.0)) {
      special_values |= type_t::kMinusZero;
      // Remove -0.
      result_min += 0.0;
      result_max += 0.0;
    }
    // 0 * V8_INFINITY is NaN, regardless of sign
    if (((l_min == -inf || l_max == inf) && (r_min <= 0.0 && 0.0 <= r_max)) ||
        ((r_min == -inf || r_max == inf) && (l_min <= 0.0 && 0.0 <= l_max))) {
      special_values |= type_t::kNaN;
    }

    type_t type = Range(result_min, result_max, special_values, zone);
    return type;
  }

  static Type Divide(const type_t& l, const type_t& r, Zone* zone) {
    // Division is tricky, so all we do is try ruling out -0 and NaN.
    if (l.is_only_nan() || r.is_only_nan()) return type_t::NaN();

    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) {
      if V8_UNLIKELY (!std::isfinite(a) && !std::isfinite(b)) {
        return nan_v<Bits>;
      }
      if V8_UNLIKELY (IsMinusZero(b)) {
        // +-0 / -0 ==> NaN
        if (a == 0 || std::isnan(a)) return nan_v<Bits>;
        return a > 0 ? -inf : inf;
      }
      if V8_UNLIKELY (b == 0) {
        // +-0 / 0 ==> NaN
        if (a == 0 || std::isnan(a)) return nan_v<Bits>;
        return a > 0 ? inf : -inf;
      }
      return a / b;
    };
    if (l.is_set() && r.is_set()) {
      auto result = ProductSet(l, r, 0, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    auto [l_min, l_max] = l.minmax();
    auto [r_min, r_max] = r.minmax();

    bool maybe_nan =
        l.has_nan() || IsZeroish(r) ||
        ((l_min == -inf || l_max == inf) && (r_min == -inf || r_max == inf));

    // Try to rule out -0.
    bool maybe_minuszero =
        // -0 / r (r > 0)
        (l.has_minus_zero() && r_max > 0)
        // 0 / r (r < 0)
        || (l.Contains(0) && r_min < 0)
        // -0.0..01 / r (r > 1)
        || (l.Contains(0) && l_min < 0 && r_max > 1)
        // 0.0..01 / r (r < -1)
        || (l.Contains(0) && l_max >= 0 && r_min < -1)
        // l / large (l < 0)
        || (l_max < 0 && detail::is_minus_zero(l_max / r_max))
        // l / -large (l > 0)
        || (l_min > 0 && detail::is_minus_zero(l_min / r_min));

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);

    const bool r_all_positive = r_min >= 0 && !r.has_minus_zero();
    const bool r_all_negative = r_max < 0;

    // If r doesn't span 0, we can try to compute a more precise type.
    if (r_all_positive || r_all_negative) {
      // If r does not contain 0 or -0, we can compute a range.
      if (r_min > 0 && !r.has_minus_zero()) {
        std::array<float_t, 4> results;
        results[0] = l_min / r_min;
        results[1] = l_min / r_max;
        results[2] = l_max / r_min;
        results[3] = l_max / r_max;

        for (float_t r : results) {
          if (std::isnan(r)) return type_t::Any();
        }

        const float_t result_min = array_min(results);
        const float_t result_max = array_max(results);
        return Range(result_min, result_max, special_values, zone);
      }

      // Otherwise we try to check for the sign of the result.
      if (l_max < 0) {
        if (r_all_positive) {
          // All values are negative.
          return Range(-inf, next_smaller(float_t{0}), special_values, zone);
        } else {
          DCHECK(r_all_negative);
          // All values are positive.
          return Range(0, inf, special_values, zone);
        }
      } else if (l_min >= 0 && !l.has_minus_zero()) {
        if (r_all_positive) {
          // All values are positive.
          DCHECK_EQ(special_values & type_t::kMinusZero, 0);
          return Range(0, inf, special_values, zone);
        } else {
          DCHECK(r_all_negative);
          // All values are negative.
          return Range(-inf, next_smaller(float_t{0}), special_values, zone);
        }
      }
    }

    // Otherwise we give up on a precise type.
    return type_t::Any(special_values);
  }

  static Type Modulus(type_t l, type_t r, Zone* zone) {
    // Modulus can yield NaN if either {lhs} or {rhs} are NaN, or
    // {lhs} is not finite, or the {rhs} is a zero value.
    if (l.is_only_nan() || r.is_only_nan()) return type_t::NaN();
    bool maybe_nan =
        l.has_nan() || IsZeroish(r) || l.min() == -inf || l.max() == inf;

    // Deal with -0 inputs, only the signbit of {lhs} matters for the result.
    bool maybe_minuszero = l.min() < 0;
    if (l.has_minus_zero()) {
      maybe_minuszero = true;
      l = type_t::LeastUpperBound(l, type_t::Constant(0), zone);
    }
    if (r.has_minus_zero()) {
      r = type_t::LeastUpperBound(r, type_t::Constant(0), zone);
    }

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);
    // For integer inputs {l} and {r} we can infer a precise type.
    if (IsIntegerSet(l) && IsIntegerSet(r)) {
      auto [l_min, l_max] = l.minmax();
      auto [r_min, r_max] = r.minmax();
      // l % r is:
      // - never greater than abs(l)
      // - never greater than abs(r) - 1
      auto l_abs = std::max(std::abs(l_min), std::abs(l_max));
      auto r_abs = std::max(std::abs(r_min), std::abs(r_max));
      // If rhs is 0, we can only produce NaN.
      if (r_abs == 0) return type_t::NaN();
      r_abs -= 1;
      auto abs = std::min(l_abs, r_abs);
      float_t min = 0.0, max = 0.0;
      if (l_min >= 0.0) {
        // {l} positive.
        max = abs;
      } else if (l_max <= 0.0) {
        // {l} negative.
        min = 0.0 - abs;
      } else {
        // {l} positive or negative.
        min = 0.0 - abs;
        max = abs;
      }
      if (min == max) return Set({min}, special_values, zone);
      return Range(min, max, special_values, zone);
    }

    // Otherwise, we give up.
    return type_t::Any(special_values);
  }

  static Type Min(type_t l, type_t r, Zone* zone) {
    if (l.is_only_nan() || r.is_only_nan()) return type_t::NaN();
    bool maybe_nan = l.has_nan() || r.has_nan();

    // In order to ensure monotonicity of the computation below, we additionally
    // pretend +0 is present (for simplicity on both sides).
    bool maybe_minuszero = false;
    if (l.has_minus_zero() && !(r.max() < 0.0)) {
      maybe_minuszero = true;
      l = type_t::LeastUpperBound(l, type_t::Constant(0), zone);
    }
    if (r.has_minus_zero() && !(l.max() < 0.0)) {
      maybe_minuszero = true;
      r = type_t::LeastUpperBound(r, type_t::Constant(0), zone);
    }

    uint32_t special_values = (maybe_nan ? type_t::kNaN : 0) |
                              (maybe_minuszero ? type_t::kMinusZero : 0);
    // If both sides are decently small sets, we produce the product set.
    auto combine = [](float_t a, float_t b) { return std::min(a, b); };
    if (l.is_set() && r.is_set()) {
      // TODO(nicohartmann@): There is a faster way to compute this set.
      auto result = ProductSet(l, r, special_values, zone, combine);
      if (!result.IsInvalid()) return result;
    }

    // Otherwise just construct a range.
    auto [l_min, l_max] = l.minmax();
    auto [r_min, r_max] = r.minmax();

    auto min = std::min(l_min, r_min);
    auto max = std::min(l_max, r_max);
    return Range(min, max, special_values, zone);
  }

  static Type Max(type_t l, type_t r, Zone* zone) {
    if (l.is_only_nan() || r.is_only_nan()) return type_t::NaN();
    bool maybe_n
"""


```