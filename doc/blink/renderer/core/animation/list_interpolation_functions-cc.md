Response:
Let's break down the thought process to analyze the provided C++ code for `list_interpolation_functions.cc`.

1. **Understand the Core Purpose:** The filename itself gives a huge clue: "list_interpolation_functions". This strongly suggests the file deals with how lists of values are interpolated during animations. Interpolation is the process of calculating intermediate values between a starting and ending point, crucial for smooth animations.

2. **Identify Key Data Structures:**  Skimming the code reveals several important types:
    * `InterpolableList`:  This likely represents a list of values that *can* be interpolated (e.g., numbers, colors).
    * `NonInterpolableList`: This likely represents a list of values that *cannot* be directly interpolated (e.g., keywords like `auto`, `inherit`).
    * `InterpolationValue`:  This seems to be a container holding both `InterpolableList` and `NonInterpolableList`. This makes sense, as a CSS property might have both interpolable and non-interpolable components (e.g., `background-image: linear-gradient(red, blue)` where `linear-gradient` is non-interpolable but the colors are).
    * `UnderlyingValue`:  This seems to represent the current state of an animated value during the animation process.
    * `UnderlyingItemValue`: This looks like a helper class to manage individual items within an `UnderlyingValue` that's a list.
    * `PairwiseInterpolationValue`:  Likely a struct or class to hold the start and end interpolation values for a single step of merging/interpolation.

3. **Analyze Key Functions:** Now, let's go through the major functions and understand their roles:
    * `EqualValues`:  Simple enough. Checks if two `InterpolationValue`s are equal, considering both interpolable and non-interpolable parts. It uses a callback to handle equality of the non-interpolable parts, allowing for custom comparison logic.
    * `MatchLengths`: This function deals with how to handle lists of different lengths during interpolation. It offers strategies like "equal length required," "lowest common multiple" (for repeating patterns), and "pad to the largest length." This is vital for handling cases where, for instance, animating a list of two gradients to a list of three.
    * `MaybeMergeSingles`: This is a complex function and a central piece. It attempts to merge two `InterpolationValue`s (start and end) into a single pair that can be interpolated. It handles cases with empty lists, lists of different lengths (using `MatchLengths`), and uses a callback (`merge_single_item_conversions`) to handle the merging of individual items in the lists. The name "MaybeMergeSingles" suggests it might return null if merging isn't possible.
    * `RepeatToLength`:  Used when the `LengthMatchingStrategy` is `kLowestCommonMultiple`. It takes an `InterpolationValue` and repeats its items to match a target length. This is used for repeating patterns in animations.
    * `PadToSameLength`: Used when `LengthMatchingStrategy` is `kPadToLargest`. It takes a shorter `InterpolationValue` and adds "zeroed" versions of items from the longer `InterpolationValue` to make their lengths match.
    * `InterpolableListsAreCompatible` and `NonInterpolableListsAreCompatible`: These functions check if the *individual items* within two interpolable or non-interpolable lists can be meaningfully interpolated together, considering the length matching strategy.
    * `VerifyNoNonInterpolableValues`: A simple assertion check, likely used in contexts where non-interpolable values aren't expected.
    * `Composite`: This is the core interpolation function. It takes the current `UnderlyingValue`, the interpolation fraction, the target `InterpolationValue`, and various callbacks. It figures out the final length, checks for compatibility, and then iterates through the items, delegating the actual interpolation of individual items to the `composite_item` callback. It handles the different length-matching strategies.
    * `NonInterpolableList::AutoBuilder`: This is a helper class to efficiently update the `NonInterpolableList` within an `UnderlyingValue`. It avoids unnecessary copying by only modifying the list when necessary.

4. **Identify Relationships with Web Technologies:**  Now, consider how this relates to JavaScript, HTML, and CSS:
    * **CSS Animations and Transitions:** The primary link is to CSS animations and transitions. When you define an animation or transition involving lists of values (e.g., multiple background images, multiple box shadows), this code is likely involved in calculating the intermediate values as the animation progresses.
    * **JavaScript's `element.animate()` API:** The `element.animate()` API in JavaScript can trigger these interpolation mechanisms. When you animate properties that take lists as values, this code comes into play.
    * **HTML:** HTML defines the structure of the document, and the elements being styled are part of the HTML. The CSS styles applied to these HTML elements drive the need for this interpolation logic.
    * **CSS Properties with List Values:**  Think of CSS properties like `background-image`, `box-shadow`, `transform-origin`, `clip-path`, etc., where you can specify multiple values. This code is designed to handle the animation of these kinds of properties.

5. **Consider Logic and Edge Cases:**
    * **Length Matching Strategies:**  The different length-matching strategies are crucial for handling various scenarios gracefully. Think about animating from one background image to two. "Pad to largest" would likely duplicate the first image in the starting state. "Lowest common multiple" would repeat the patterns.
    * **Non-Interpolable Values:**  The separation of interpolable and non-interpolable values is important. You can't directly interpolate "red" to "auto." The code needs to handle these cases appropriately (often by keeping the non-interpolable value constant).
    * **Callbacks:** The extensive use of callbacks (`equal_non_interpolable_values`, `merge_single_item_conversions`, `interpolable_values_are_compatible`, `non_interpolable_values_are_compatible`, `composite_item`) makes the code very flexible and allows it to be used with different types of list items.

6. **Think About Potential Errors:**
    * **Incorrect Length Matching:** If the code incorrectly determines the final length of the lists, the animation could be glitchy or incorrect.
    * **Compatibility Issues:** If the individual items within the lists aren't considered "compatible" for interpolation (e.g., trying to interpolate a number with a color), the animation might break down or the browser might fall back to discrete steps.
    * **Memory Issues:** The comment about `kRepeatableListMaxLength` hints at potential memory issues if the "lowest common multiple" strategy leads to extremely long lists. This is a good example of a potential programming error if not handled carefully.
    * **Mismatched List Types:**  If the underlying data structures aren't correctly managed, the code could try to treat an interpolable list as a non-interpolable list, leading to errors.

By following these steps, we can systematically analyze the code and understand its purpose, its relationship to web technologies, and potential areas for errors. The key is to start with the high-level purpose and gradually delve into the details of the data structures and functions.
这个C++文件 `list_interpolation_functions.cc` 属于 Chromium Blink 引擎，负责处理**列表类型的属性在动画过程中的插值计算**。更具体地说，它定义了一系列函数，用于在 CSS 动画或过渡期间，计算具有列表值的属性（例如 `background-image`, `box-shadow`, `transform-origin` 等）在不同状态之间的中间值。

**以下是它的主要功能:**

1. **比较列表值是否相等 (`EqualValues`)**:
   - 该函数用于比较两个 `InterpolationValue`（表示动画中的值，包含可插值部分和不可插值部分）是否相等。
   - 它会比较两个列表中对应位置的可插值部分和不可插值部分。
   - 对于不可插值部分的比较，它使用一个回调函数 `equal_non_interpolable_values`，允许更灵活的比较逻辑。
   - **假设输入:** 两个 `InterpolationValue` 对象，各自包含一个 `InterpolableList` 和一个 `NonInterpolableList`。
   - **假设输出:** `true` 如果两个列表在所有对应位置都相等，否则 `false`。

2. **匹配列表长度 (`MatchLengths`)**:
   - 该函数定义了在两个列表长度不同时如何处理的策略。
   - 它支持三种策略：
     - `kEqual`: 两个列表必须长度相等。
     - `kPadToLargest`: 将较短的列表填充到与较长列表相同的长度。
     - `kLowestCommonMultiple`: 将两个列表的长度扩展到它们的最小公倍数，用于处理重复模式的动画。为了防止内存溢出，有一个最大长度限制 `kRepeatableListMaxLength`。
   - **假设输入:** 两个列表的长度，以及一个长度匹配策略枚举值。
   - **假设输出:** 根据策略计算出的最终长度。

3. **合并单个值 (`MaybeMergeSingles`)**:
   - 该函数尝试将两个 `InterpolationValue` 合并成一个可插值的对。
   - 它处理了列表长度不一致的情况，并使用 `MatchLengths` 来确定最终长度。
   - 如果两个列表长度都为 0，则直接返回。
   - 如果只有一个列表长度为 0，则将另一个列表的对应插值部分克隆并置零作为另一个列表的值。
   - 对于长度不一致的情况，根据 `length_matching_strategy`，它会重复或填充较短的列表。
   - 它使用 `merge_single_item_conversions` 回调函数来处理列表中单个元素的合并。
   - **假设输入:** 两个 `InterpolationValue` 对象，以及一个长度匹配策略枚举值和一个用于合并单个条目的回调函数。
   - **假设输出:** 一个 `PairwiseInterpolationValue` 对象，包含合并后的起始和结束可插值列表，以及不可插值列表，如果无法合并则返回 `nullptr`。

4. **重复列表到指定长度 (`RepeatToLength`)**:
   - 该函数用于将一个 `InterpolationValue` 中的列表重复填充到指定的长度。
   - 它主要用于 `kLowestCommonMultiple` 策略，将较短的列表重复以匹配最小公倍数长度。
   - **假设输入:** 一个 `InterpolationValue` 对象和一个目标长度。
   - **假设输出:**  修改输入的 `InterpolationValue`，使其内部的列表被重复填充到目标长度。

5. **填充列表到相同长度 (`PadToSameLength`)**:
   - 该函数用于将一个 `InterpolationValue` 中的列表填充到与另一个 `InterpolationValue` 中列表相同的长度。
   - 它将较短的列表通过克隆并置零较长列表中对应位置的插值部分来填充。
   - **假设输入:** 两个 `InterpolationValue` 对象，其中一个的列表可能比另一个短。
   - **假设输出:** 修改第一个输入的 `InterpolationValue`，使其内部的列表被填充到与第二个输入列表相同的长度。

6. **检查列表是否兼容 (`InterpolableListsAreCompatible`, `NonInterpolableListsAreCompatible`)**:
   - 这两个函数用于检查两个可插值列表或不可插值列表是否兼容，可以进行插值。
   - 它们会根据长度匹配策略来判断是否所有对应位置的元素都兼容。
   - **假设输入:** 两个可插值列表或不可插值列表，一个最终长度，以及长度匹配策略和兼容性检查回调函数。
   - **假设输出:** `true` 如果列表兼容，否则 `false`。

7. **组合插值值 (`Composite`)**:
   - 这是进行实际插值的核心函数。
   - 它接收当前动画的底层值 (`UnderlyingValueOwner`)，插值进度 (`underlying_fraction`)，目标值 (`InterpolationValue`) 等参数。
   - 它根据长度匹配策略调整列表长度。
   - 它使用回调函数 `composite_item` 来对列表中的每个元素进行插值计算。
   - **假设输入:**  `UnderlyingValueOwner` 对象，插值进度，插值类型，目标 `InterpolationValue`，长度匹配策略，以及多个兼容性和组合回调函数。
   - **假设输出:**  通过 `UnderlyingValueOwner` 修改底层的动画值，使其反映插值后的状态。

8. **`NonInterpolableList::AutoBuilder`**:
   - 这是一个辅助类，用于高效地构建和修改 `NonInterpolableList`。
   - 它允许在修改 `NonInterpolableList` 时避免不必要的拷贝，只有在实际修改了内容时才更新底层的值。

**与 JavaScript, HTML, CSS 的关系:**

这个文件是 Blink 渲染引擎的一部分，直接服务于 CSS 动画和过渡效果。

* **CSS 动画和过渡:** 当你在 CSS 中定义一个动画或过渡，涉及到具有列表值的属性时，这个文件中的函数会被调用来计算动画过程中的中间值。例如，当你动画 `background-image: url(a.png), url(b.png)` 到 `background-image: url(c.png), url(d.png)` 时，这个文件会处理两个 URL 之间的插值（尽管 URL 本身是不可插值的，这里可能涉及到元素的添加或移除，以及可能的属性值的插值）。

* **JavaScript 的 `element.animate()` API:**  JavaScript 的 Web Animations API 允许通过 `element.animate()` 方法创建动画。当动画的属性值是列表时，例如 `element.animate({ boxShadow: ['1px 1px black', '2px 2px red'] }, { duration: 1000 })`，这个文件也会参与到动画值的计算过程中。

* **HTML:** HTML 定义了文档的结构，而 CSS 样式应用于 HTML 元素。这个文件处理的是 CSS 属性值的动画，因此它间接地与 HTML 元素相关联，因为它处理的是应用于这些元素的样式。

**逻辑推理的例子:**

**假设输入:**

* **起始 CSS 样式:** `background-image: url(image1.png), url(image2.png);`
* **结束 CSS 样式:** `background-image: url(image3.png);`
* **插值进度:** 0.5 (动画进行到一半)
* **长度匹配策略:** `kPadToLargest`

**逻辑推理过程:**

1. `MatchLengths` 函数会被调用，传入起始长度 2 和结束长度 1，以及策略 `kPadToLargest`。输出为 2。
2. `MaybeMergeSingles` 函数会被调用，因为长度不一致，会尝试合并这两个列表。
3. 由于长度匹配策略是 `kPadToLargest`，较短的列表（结束状态）会被填充一个“零值”的 `background-image`，可能是 `none` 或一个空的 URL。
4. `Composite` 函数会被调用，针对列表中的每个元素进行插值。
5. 对于第一个 `background-image`，会从 `url(image1.png)` 插值到 `url(image3.png)`（具体如何插值取决于 `composite_item` 回调函数的实现，对于 URL 来说，通常是离散的，不会进行颜色或数值上的插值）。
6. 对于第二个 `background-image`，会从 `url(image2.png)` 插值到一个“零值”的 `background-image`。

**假设输出 (可能的结果):**

在动画进行到一半时，`background-image` 的值可能是：`url(某种过渡后的image), none;`  （具体的过渡效果取决于更底层的图像处理逻辑，这里主要展示列表长度的处理）。

**用户或编程常见的使用错误:**

1. **假设列表长度相等但实际不等:**  如果开发者期望动画的起始和结束状态的列表长度相同，但实际情况并非如此，可能会导致意外的动画效果，具体取决于所使用的长度匹配策略。例如，如果使用 `kEqual` 策略，且长度不一致，动画可能不会发生。

2. **错误地假设不可插值属性会平滑过渡:**  例如，直接动画 `background-image` 的 URL，由于 URL 是不可插值的，浏览器通常会进行离散的切换，而不是平滑的过渡。开发者可能需要使用其他技术，如 `opacity` 或 JavaScript 来实现更复杂的过渡效果。

3. **过度使用 `kLowestCommonMultiple` 导致性能问题:**  如果列表的长度很大，且最小公倍数非常大，使用 `kLowestCommonMultiple` 可能会导致创建非常大的中间列表，消耗大量内存并影响性能。`kRepeatableListMaxLength` 的存在就是为了防止这种情况。

4. **忘记处理不同类型的列表项:**  动画的逻辑需要能够处理列表中不同类型的条目。例如，`box-shadow` 可以包含长度、颜色等不同类型的属性。插值函数需要能够正确处理这些不同类型的值。

总而言之，`list_interpolation_functions.cc` 文件在 Chromium Blink 引擎中扮演着关键角色，负责处理 CSS 动画和过渡中列表类型属性的平滑过渡效果，涉及到多种策略来处理不同长度的列表，并区分可插值和不可插值的部分。理解这个文件的工作原理有助于更好地理解浏览器如何渲染复杂的 CSS 动画。

### 提示词
```
这是目录为blink/renderer/core/animation/list_interpolation_functions.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/animation/list_interpolation_functions.h"

#include <memory>
#include "base/functional/callback.h"
#include "third_party/blink/renderer/core/animation/underlying_value_owner.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"

namespace blink {

DEFINE_NON_INTERPOLABLE_VALUE_TYPE(NonInterpolableList);

const wtf_size_t kRepeatableListMaxLength = 1000;

// An UnderlyingValue used for compositing list items.
//
// When new NonInterpolableValues are set, the NonInterpolableList::AutoBuilder
// is modified at the corresponding index. The NonInterpolableValue of the
// underlying_list is updated when the AutoBuilder goes out of scope (if
// any calls to UnderlyingItemValue::SetNonInterpolableValue were made).
class UnderlyingItemValue : public UnderlyingValue {
  STACK_ALLOCATED();

 public:
  UnderlyingItemValue(UnderlyingValue& underlying_list,
                      NonInterpolableList::AutoBuilder& builder,
                      wtf_size_t index)
      : underlying_list_(underlying_list), builder_(builder), index_(index) {}

  InterpolableValue& MutableInterpolableValue() final {
    return *To<InterpolableList>(underlying_list_.MutableInterpolableValue())
                .GetMutable(index_);
  }
  void SetInterpolableValue(InterpolableValue* interpolable_value) final {
    To<InterpolableList>(underlying_list_.MutableInterpolableValue())
        .Set(index_, std::move(interpolable_value));
  }
  const NonInterpolableValue* GetNonInterpolableValue() const final {
    return To<NonInterpolableList>(*underlying_list_.GetNonInterpolableValue())
        .Get(index_);
  }
  void SetNonInterpolableValue(
      scoped_refptr<const NonInterpolableValue> non_interpolable_value) final {
    builder_.Set(index_, std::move(non_interpolable_value));
  }

 private:
  UnderlyingValue& underlying_list_;
  NonInterpolableList::AutoBuilder& builder_;
  wtf_size_t index_;
};

bool ListInterpolationFunctions::EqualValues(
    const InterpolationValue& a,
    const InterpolationValue& b,
    EqualNonInterpolableValuesCallback equal_non_interpolable_values) {
  if (!a && !b)
    return true;

  if (!a || !b)
    return false;

  const auto& interpolable_list_a = To<InterpolableList>(*a.interpolable_value);
  const auto& interpolable_list_b = To<InterpolableList>(*b.interpolable_value);

  if (interpolable_list_a.length() != interpolable_list_b.length())
    return false;

  wtf_size_t length = interpolable_list_a.length();
  if (length == 0)
    return true;

  const auto& non_interpolable_list_a =
      To<NonInterpolableList>(*a.non_interpolable_value);
  const auto& non_interpolable_list_b =
      To<NonInterpolableList>(*b.non_interpolable_value);

  for (wtf_size_t i = 0; i < length; i++) {
    if (!equal_non_interpolable_values(non_interpolable_list_a.Get(i),
                                       non_interpolable_list_b.Get(i)))
      return false;
  }
  return true;
}

static wtf_size_t MatchLengths(
    wtf_size_t start_length,
    wtf_size_t end_length,
    ListInterpolationFunctions::LengthMatchingStrategy
        length_matching_strategy) {
  if (length_matching_strategy ==
      ListInterpolationFunctions::LengthMatchingStrategy::kEqual) {
    DCHECK_EQ(start_length, end_length);
    return start_length;
  } else if (length_matching_strategy ==
             ListInterpolationFunctions::LengthMatchingStrategy::
                 kLowestCommonMultiple) {
    // Combining the length expansion of lowestCommonMultiple with CSS
    // transitions has the potential to create pathological cases where this
    // algorithm compounds upon itself as the user starts transitions on already
    // animating values multiple times. This maximum limit is to avoid locking
    // up users' systems with memory consumption in the event that this occurs.
    // See crbug.com/739197 for more context.
    return std::min(kRepeatableListMaxLength,
                    static_cast<wtf_size_t>(
                        LowestCommonMultiple(start_length, end_length)));
  }
  DCHECK_EQ(length_matching_strategy,
            ListInterpolationFunctions::LengthMatchingStrategy::kPadToLargest);
  return std::max(start_length, end_length);
}

PairwiseInterpolationValue ListInterpolationFunctions::MaybeMergeSingles(
    InterpolationValue&& start,
    InterpolationValue&& end,
    LengthMatchingStrategy length_matching_strategy,
    MergeSingleItemConversionsCallback merge_single_item_conversions) {
  const wtf_size_t start_length =
      To<InterpolableList>(*start.interpolable_value).length();
  const wtf_size_t end_length =
      To<InterpolableList>(*end.interpolable_value).length();

  if (length_matching_strategy ==
          ListInterpolationFunctions::LengthMatchingStrategy::kEqual &&
      (start_length != end_length)) {
    return nullptr;
  }

  if (start_length == 0 && end_length == 0) {
    return PairwiseInterpolationValue(std::move(start.interpolable_value),
                                      std::move(end.interpolable_value),
                                      nullptr);
  }

  if (start_length == 0) {
    InterpolableValue* start_interpolable_value =
        end.interpolable_value->CloneAndZero();
    return PairwiseInterpolationValue(start_interpolable_value,
                                      std::move(end.interpolable_value),
                                      std::move(end.non_interpolable_value));
  }

  if (end_length == 0) {
    InterpolableValue* end_interpolable_value =
        start.interpolable_value->CloneAndZero();
    return PairwiseInterpolationValue(std::move(start.interpolable_value),
                                      end_interpolable_value,
                                      std::move(start.non_interpolable_value));
  }

  const wtf_size_t final_length =
      MatchLengths(start_length, end_length, length_matching_strategy);
  auto* result_start_interpolable_list =
      MakeGarbageCollected<InterpolableList>(final_length);
  auto* result_end_interpolable_list =
      MakeGarbageCollected<InterpolableList>(final_length);
  Vector<scoped_refptr<const NonInterpolableValue>>
      result_non_interpolable_values(final_length);

  auto& start_interpolable_list =
      To<InterpolableList>(*start.interpolable_value);
  auto& end_interpolable_list = To<InterpolableList>(*end.interpolable_value);
  const auto* start_non_interpolable_list =
      To<NonInterpolableList>(start.non_interpolable_value.get());
  const auto* end_non_interpolable_list =
      To<NonInterpolableList>(end.non_interpolable_value.get());
  const wtf_size_t start_non_interpolable_length =
      start_non_interpolable_list ? start_non_interpolable_list->length() : 0;
  const wtf_size_t end_non_interpolable_length =
      end_non_interpolable_list ? end_non_interpolable_list->length() : 0;
  for (wtf_size_t i = 0; i < final_length; i++) {
    if (length_matching_strategy ==
            LengthMatchingStrategy::kLowestCommonMultiple ||
        (i < start_length && i < end_length)) {
      InterpolationValue start_merge(
          start_interpolable_list.Get(i % start_length)->Clone(),
          start_non_interpolable_list ? start_non_interpolable_list->Get(
                                            i % start_non_interpolable_length)
                                      : nullptr);
      InterpolationValue end_merge(
          end_interpolable_list.Get(i % end_length)->Clone(),
          end_non_interpolable_list
              ? end_non_interpolable_list->Get(i % end_non_interpolable_length)
              : nullptr);
      PairwiseInterpolationValue result = merge_single_item_conversions(
          std::move(start_merge), std::move(end_merge));
      if (!result)
        return nullptr;
      result_start_interpolable_list->Set(
          i, std::move(result.start_interpolable_value));
      result_end_interpolable_list->Set(
          i, std::move(result.end_interpolable_value));
      result_non_interpolable_values[i] =
          std::move(result.non_interpolable_value);
    } else {
      DCHECK_EQ(length_matching_strategy,
                LengthMatchingStrategy::kPadToLargest);
      if (i < start_length) {
        result_start_interpolable_list->Set(
            i, start_interpolable_list.Get(i)->Clone());
        result_end_interpolable_list->Set(
            i, start_interpolable_list.Get(i)->CloneAndZero());
        result_non_interpolable_values[i] =
            (i < start_non_interpolable_length)
                ? start_non_interpolable_list->Get(i)
                : nullptr;
      } else {
        DCHECK_LT(i, end_length);
        result_start_interpolable_list->Set(
            i, end_interpolable_list.Get(i)->CloneAndZero());
        result_end_interpolable_list->Set(
            i, end_interpolable_list.Get(i)->Clone());
        result_non_interpolable_values[i] =
            (i < end_non_interpolable_length)
                ? end_non_interpolable_list->Get(i)
                : nullptr;
      }
    }
  }
  return PairwiseInterpolationValue(
      std::move(result_start_interpolable_list),
      std::move(result_end_interpolable_list),
      NonInterpolableList::Create(std::move(result_non_interpolable_values)));
}

static void RepeatToLength(InterpolationValue& value, wtf_size_t length) {
  auto& interpolable_list = To<InterpolableList>(*value.interpolable_value);
  const auto& non_interpolable_list =
      To<NonInterpolableList>(*value.non_interpolable_value);
  wtf_size_t current_length = interpolable_list.length();
  DCHECK_GT(current_length, 0U);
  if (current_length == length)
    return;
  DCHECK_LT(current_length, length);
  auto* new_interpolable_list = MakeGarbageCollected<InterpolableList>(length);
  Vector<scoped_refptr<const NonInterpolableValue>> new_non_interpolable_values(
      length);
  for (wtf_size_t i = length; i-- > 0;) {
    new_interpolable_list->Set(
        i, i < current_length
               ? std::move(interpolable_list.GetMutable(i).Get())
               : interpolable_list.Get(i % current_length)->Clone());
    new_non_interpolable_values[i] =
        non_interpolable_list.Get(i % current_length);
  }
  value.interpolable_value = std::move(new_interpolable_list);
  value.non_interpolable_value =
      NonInterpolableList::Create(std::move(new_non_interpolable_values));
}

// This helper function makes value the same length as length_value by
// CloneAndZero-ing the additional items from length_value into value.
static void PadToSameLength(InterpolationValue& value,
                            const InterpolationValue& length_value) {
  auto& interpolable_list = To<InterpolableList>(*value.interpolable_value);
  const auto& non_interpolable_list =
      To<NonInterpolableList>(*value.non_interpolable_value);
  const wtf_size_t current_length = interpolable_list.length();
  auto& target_interpolable_list =
      To<InterpolableList>(*length_value.interpolable_value);
  const auto& target_non_interpolable_list =
      To<NonInterpolableList>(*length_value.non_interpolable_value);
  const wtf_size_t target_length = target_interpolable_list.length();
  DCHECK_LT(current_length, target_length);
  auto* new_interpolable_list =
      MakeGarbageCollected<InterpolableList>(target_length);
  Vector<scoped_refptr<const NonInterpolableValue>> new_non_interpolable_values(
      target_length);
  wtf_size_t index = 0;
  for (; index < current_length; index++) {
    new_interpolable_list->Set(index,
                               std::move(interpolable_list.GetMutable(index)));
    new_non_interpolable_values[index] = non_interpolable_list.Get(index);
  }
  for (; index < target_length; index++) {
    new_interpolable_list->Set(
        index, target_interpolable_list.Get(index)->CloneAndZero());
    new_non_interpolable_values[index] =
        target_non_interpolable_list.Get(index);
  }
  value.interpolable_value = std::move(new_interpolable_list);
  value.non_interpolable_value =
      NonInterpolableList::Create(std::move(new_non_interpolable_values));
}

static bool InterpolableListsAreCompatible(
    const InterpolableList& a,
    const InterpolableList& b,
    wtf_size_t length,
    ListInterpolationFunctions::LengthMatchingStrategy length_matching_strategy,
    ListInterpolationFunctions::InterpolableValuesAreCompatibleCallback
        interpolable_values_are_compatible) {
  for (wtf_size_t i = 0; i < length; i++) {
    if (length_matching_strategy ==
            ListInterpolationFunctions::LengthMatchingStrategy::
                kLowestCommonMultiple ||
        (i < a.length() && i < b.length())) {
      if (!interpolable_values_are_compatible(a.Get(i % a.length()),
                                              b.Get(i % b.length()))) {
        return false;
      }
    }
  }
  return true;
}

static bool NonInterpolableListsAreCompatible(
    const NonInterpolableList& a,
    const NonInterpolableList& b,
    wtf_size_t length,
    ListInterpolationFunctions::LengthMatchingStrategy length_matching_strategy,
    ListInterpolationFunctions::NonInterpolableValuesAreCompatibleCallback
        non_interpolable_values_are_compatible) {
  for (wtf_size_t i = 0; i < length; i++) {
    if (length_matching_strategy ==
            ListInterpolationFunctions::LengthMatchingStrategy::
                kLowestCommonMultiple ||
        (i < a.length() && i < b.length())) {
      if (!non_interpolable_values_are_compatible(a.Get(i % a.length()),
                                                  b.Get(i % b.length()))) {
        return false;
      }
    }
  }
  return true;
}

bool ListInterpolationFunctions::VerifyNoNonInterpolableValues(
    const NonInterpolableValue* a,
    const NonInterpolableValue* b) {
  DCHECK(!a && !b);
  return true;
}

void ListInterpolationFunctions::Composite(
    UnderlyingValueOwner& underlying_value_owner,
    double underlying_fraction,
    const InterpolationType& type,
    const InterpolationValue& value,
    LengthMatchingStrategy length_matching_strategy,
    InterpolableValuesAreCompatibleCallback interpolable_values_are_compatible,
    NonInterpolableValuesAreCompatibleCallback
        non_interpolable_values_are_compatible,
    CompositeItemCallback composite_item) {
  const wtf_size_t underlying_length =
      To<InterpolableList>(*underlying_value_owner.Value().interpolable_value)
          .length();

  const auto& interpolable_list =
      To<InterpolableList>(*value.interpolable_value);
  const wtf_size_t value_length = interpolable_list.length();

  if (length_matching_strategy ==
          ListInterpolationFunctions::LengthMatchingStrategy::kEqual &&
      (underlying_length != value_length)) {
    underlying_value_owner.Set(type, value);
    return;
  }

  if (underlying_length == 0) {
    DCHECK(!underlying_value_owner.Value().non_interpolable_value);
    underlying_value_owner.Set(type, value);
    return;
  }

  if (value_length == 0) {
    DCHECK(!value.non_interpolable_value);
    underlying_value_owner.MutableValue().interpolable_value->Scale(
        underlying_fraction);
    return;
  }

  const wtf_size_t final_length =
      MatchLengths(underlying_length, value_length, length_matching_strategy);

  if (!InterpolableListsAreCompatible(
          To<InterpolableList>(
              *underlying_value_owner.Value().interpolable_value),
          interpolable_list, final_length, length_matching_strategy,
          interpolable_values_are_compatible)) {
    underlying_value_owner.Set(type, value);
    return;
  }

  const auto& non_interpolable_list =
      To<NonInterpolableList>(*value.non_interpolable_value);
  if (!NonInterpolableListsAreCompatible(
          To<NonInterpolableList>(
              *underlying_value_owner.Value().non_interpolable_value),
          non_interpolable_list, final_length, length_matching_strategy,
          non_interpolable_values_are_compatible)) {
    underlying_value_owner.Set(type, value);
    return;
  }

  InterpolationValue& underlying_value = underlying_value_owner.MutableValue();
  if (length_matching_strategy ==
      LengthMatchingStrategy::kLowestCommonMultiple) {
    if (underlying_length < final_length) {
      RepeatToLength(underlying_value, final_length);
    }
    NonInterpolableList::AutoBuilder builder(underlying_value_owner);

    for (wtf_size_t i = 0; i < final_length; i++) {
      UnderlyingItemValue underlying_item(underlying_value_owner, builder, i);
      composite_item(underlying_item, underlying_fraction,
                     *interpolable_list.Get(i % value_length),
                     non_interpolable_list.Get(i % value_length));
    }
  } else {
    DCHECK(length_matching_strategy == LengthMatchingStrategy::kPadToLargest ||
           length_matching_strategy == LengthMatchingStrategy::kEqual);
    if (underlying_length < final_length) {
      DCHECK_EQ(length_matching_strategy,
                LengthMatchingStrategy::kPadToLargest);
      DCHECK_EQ(value_length, final_length);
      PadToSameLength(underlying_value, value);
    }
    auto& underlying_interpolable_list =
        To<InterpolableList>(*underlying_value.interpolable_value);

    NonInterpolableList::AutoBuilder builder(underlying_value_owner);

    for (wtf_size_t i = 0; i < value_length; i++) {
      UnderlyingItemValue underlying_item(underlying_value_owner, builder, i);
      composite_item(underlying_item, underlying_fraction,
                     *interpolable_list.Get(i), non_interpolable_list.Get(i));
    }
    for (wtf_size_t i = value_length; i < final_length; i++) {
      underlying_interpolable_list.GetMutable(i)->Scale(underlying_fraction);
    }
  }
}

NonInterpolableList::AutoBuilder::AutoBuilder(UnderlyingValue& underlying_value)
    : underlying_value_(underlying_value) {
  DCHECK(underlying_value.GetNonInterpolableValue());
  DCHECK(IsA<NonInterpolableList>(underlying_value_.GetNonInterpolableValue()));
}

NonInterpolableList::AutoBuilder::~AutoBuilder() {
  // If no call to Set ever happened, there is no need to modify
  // underlying_value_.
  if (!list_.size())
    return;
  const auto& non_interpolable_list =
      To<NonInterpolableList>(*underlying_value_.GetNonInterpolableValue());
  DCHECK_EQ(non_interpolable_list.length(), list_.size());
  underlying_value_.SetNonInterpolableValue(
      NonInterpolableList::Create(std::move(list_)));
}

void NonInterpolableList::AutoBuilder::Set(
    wtf_size_t index,
    scoped_refptr<const NonInterpolableValue> non_interpolable_value) {
  // Copy list on first call to Set.
  if (!list_.size()) {
    const auto& non_interpolable_list =
        To<NonInterpolableList>(*underlying_value_.GetNonInterpolableValue());
    wtf_size_t underlying_length = non_interpolable_list.length();
    for (wtf_size_t i = 0; i < underlying_length; ++i)
      list_.push_back(non_interpolable_list.Get(i));
  }

  DCHECK_LT(index, list_.size());
  list_[index] = non_interpolable_value;
}

}  // namespace blink
```