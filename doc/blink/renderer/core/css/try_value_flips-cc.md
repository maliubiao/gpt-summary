Response:
Let's break down the thought process for analyzing the `try_value_flips.cc` file.

1. **Understand the Goal:** The core goal of this file is to handle CSS property and value transformations based on "flip" directives (like `flip-inline` or `flip-block`). This suggests a mechanism for creating alternative CSS property sets based on these flipping rules.

2. **Identify Key Classes and Functions:** Scan the code for class names and function names. This immediately highlights:
    * `TryValueFlips`: The central class.
    * `FlipSet`: Likely retrieves or creates a set of flipped properties.
    * `CreateFlipSet`: The function responsible for *generating* the flipped property set.
    * `TryTacticTransform`:  A key class related to the flipping logic. The name implies transforming based on some "tactics."
    * `CSSPropertyValueSet`:  Represents a collection of CSS property-value pairs. This makes sense as the output of the flipping process.
    * `CSSFlipRevertValue`: A special value type indicating a reversion to the original property when flipped.
    * Functions like `DeterminePropertyAxis`, `DetermineValueAxis`, `ConvertLeftRightToLogical`, `FlipSelfAlignmentKeyword`, `TransformPhysical`, `TransformLogical`, `TransformPositionAreaKeyword`, `TransformPositionArea`, `FlipValue`. These point towards the detailed logic of how specific properties and values are handled.

3. **Analyze `FlipSet`:**  This function takes a `TryTacticList`. It uses a `TryTacticTransform` to get a `CacheIndex`. It accesses a `cached_flip_sets_` array. The comments mention `kNoTryTactics` and the caching mechanism. This suggests:
    * Flipping configurations are cached for performance.
    * `TryTacticList` represents the specific flipping rules.
    * `TryTacticTransform` translates these rules into a cacheable index.
    * If a flipped set isn't cached, `CreateFlipSet` is called.

4. **Deep Dive into `CreateFlipSet`:** This is where the core flipping logic resides.
    * It creates a `HeapVector<CSSPropertyValue>` to store the flipped declarations.
    * The `add` lambda adds a `CSSFlipRevertValue`. This confirms the "revert to original" idea.
    * The `add_if_flipped` lambda conditionally adds declarations based on whether the property is actually flipped.
    * It uses `TryTacticTransform::LogicalSides` to represent logical property mappings (inline-start, inline-end, block-start, block-end).
    * The code carefully handles `insets`, `margin`, `align-self`, `justify-self`, `position-area`, and size-related properties (`block-size`, `inline-size`, etc.).
    * The comment about `revert_transform = transform.Inverse()` is crucial for understanding how the `CSSFlipRevertValue` is constructed. It needs the *inverse* transformation to know what the original property was.

5. **Examine Transformation Functions:**  The functions below `CreateFlipSet` detail how individual CSS properties and values are transformed.
    * `DeterminePropertyAxis` and `DetermineValueAxis` figure out if a property/value relates to the inline or block axis based on writing direction.
    * `ConvertLeftRightToLogical` translates physical left/right to logical start/end based on writing direction.
    * `FlipSelfAlignmentKeyword` handles flipping keywords like `start` to `end`.
    * `TransformSelfAlignment` applies the flipping to `align-self` and `justify-self` values.
    * `TransformPhysical`, `TransformXY`, and `TransformLogical` deal with transforming groups of related properties (like `left`, `right`, `top`, `bottom`).
    * `TransformPositionAreaKeyword` and `TransformPositionArea` are dedicated to handling the complexities of the `position-area` property and its values.

6. **Connect to HTML, CSS, and JavaScript:**
    * **CSS:** This file directly manipulates CSS properties and values. The "flip" directives are likely CSS features (or under development to be). The concepts of logical properties (inline/block) are core CSS concepts.
    * **HTML:** The flipping of CSS styles will directly affect how HTML elements are rendered.
    * **JavaScript:**  JavaScript could trigger or interact with these flipping mechanisms, potentially through CSSOM manipulation or by setting CSS properties that involve flipping.

7. **Consider User/Programming Errors:**  Think about situations where things might go wrong:
    * Mismatched flip directives.
    * Applying flips to properties that don't have a logical counterpart.
    * Incorrectly understanding how `position-area` values are transformed.

8. **Trace User Operations:** How does a user's action lead to this code being executed?  The key is the "flip" concept. A user (or developer) must somehow specify a flip, likely through CSS. This would trigger the browser's layout engine to process the CSS, which would eventually involve this `try_value_flips.cc` file to generate the alternative property sets.

9. **Structure the Answer:** Organize the findings into logical sections: functionality, relationship to web technologies, logical reasoning, potential errors, and debugging. Use clear examples to illustrate the concepts. Refer back to the code snippets where relevant.

10. **Review and Refine:**  Read through the generated answer. Is it clear? Accurate?  Are the examples helpful?  Could anything be explained better?  For instance, initially, I might have just said "it flips properties," but realizing the `CSSFlipRevertValue` and the concept of *reverting* is crucial adds more depth. Similarly, emphasizing the caching mechanism and the role of `TryTacticTransform` provides a better understanding of the overall design.
`blink/renderer/core/css/try_value_flips.cc` 这个文件是 Chromium Blink 渲染引擎中的一部分，它的主要功能是**根据指定的 "try tactics" (尝试策略) 来生成 CSS 属性值的翻转 (flip) 版本**。  更具体地说，它用于处理 CSS 逻辑属性和值，以便在不同的书写模式（例如从左到右和从右到左）下正确地应用样式。

以下是它的详细功能分解和与 Web 技术的关系：

**功能:**

1. **生成翻转后的 CSS 属性值集合 (`FlipSet`):**
   - 接收一个 `TryTacticList` 作为输入，该列表定义了需要应用的翻转策略，例如 `flip-inline` (翻转内联方向) 或 `flip-block` (翻转块方向)。
   - 内部使用 `TryTacticTransform` 类来表示和操作这些翻转策略。
   - 返回一个 `CSSPropertyValueSet` 对象，其中包含了基于给定策略翻转后的 CSS 属性和值。这些属性值使用了特殊的 `CSSFlipRevertValue`，它表示当实际应用样式时，应该根据当前的上下文翻转回原始值。
   - 为了提高性能，翻转后的属性值集合会被缓存起来。

2. **创建翻转后的属性值集合 (`CreateFlipSet`):**
   - 这是 `FlipSet` 的核心实现。它根据 `TryTacticTransform` 中定义的翻转策略，为可能需要翻转的 CSS 属性创建 `CSSFlipRevertValue`。
   - 它处理各种 CSS 属性，例如 `inset-block-start`，`margin-inline-end`，`align-self`，`justify-self`，以及尺寸属性 `block-size` 和 `inline-size` 等。
   - 对于某些属性，例如 `align-self` 和 `justify-self`，即使属性本身不需要翻转，也可能会添加翻转后的值，因为它们的值可能需要根据翻转策略进行调整。

3. **确定属性和值的轴向 (`DeterminePropertyAxis`, `DetermineValueAxis`):**
   - 这些辅助函数用于判断给定的 CSS 属性或值是与内联轴 (inline axis) 相关还是与块轴 (block axis) 相关。这对于理解如何进行翻转至关重要。例如，`left` 和 `right` 在水平书写模式下是内联轴的属性，但在垂直书写模式下是块轴的属性。

4. **转换 CSS 值 (`ConvertLeftRightToLogical`, `FlipSelfAlignmentKeyword`, `TransformPhysical`, `TransformLogical`, `TransformPositionAreaKeyword`, `TransformPositionArea`, `FlipValue`):**
   - 这些函数负责根据翻转策略和书写模式转换特定的 CSS 值。
   - `ConvertLeftRightToLogical`: 将物理的 `left` 和 `right` 值转换为逻辑的 `start` 和 `end`，根据书写方向 (LTR/RTL)。
   - `FlipSelfAlignmentKeyword`: 翻转 `align-self` 和 `justify-self` 的关键字，例如将 `start` 翻转为 `end`。
   - `TransformPhysical`, `TransformXY`, `TransformLogical`: 处理物理属性（如 `left`, `right`, `top`, `bottom`）、基于坐标的属性（如 `x-start`, `y-end`）和逻辑属性（如 `inline-start`, `block-end`）的翻转。
   - `TransformPositionAreaKeyword`, `TransformPositionArea`: 特别用于处理 `position-area` 属性及其复杂的关键字值，例如 `top left` 或 `inline-start block-end`。
   - `FlipValue`:  根据属性和翻转策略，选择合适的转换函数来翻转 CSS 值。它处理 `CSSMathFunctionValue`（用于锚定定位）、`align-self` 和 `justify-self` 以及 `position-area` 属性。

**与 JavaScript, HTML, CSS 的关系:**

* **CSS:**  此文件直接处理 CSS 属性和值。翻转的概念与 CSS 逻辑属性和值密切相关，例如 `margin-inline-start`，`border-block-end` 等。`try_value_flips.cc` 的目标是实现 CSS 翻转功能，这通常通过 CSS 属性（如 `flip-inline`, `flip-block`）或更底层的渲染机制来触发。

   **举例说明:**
   假设有以下 CSS 规则：
   ```css
   .element {
     inset-inline-start: 10px;
     float: left;
     try-value: flip-inline;
   }
   ```
   当渲染引擎处理这个规则时，如果启用了 `try-value: flip-inline` 功能，`TryValueFlips::FlipSet` 会被调用。对于 `inset-inline-start: 10px;`，它会生成一个翻转后的属性值，大致相当于：
   ```css
   inset-inline-start: -internal-flip-revert(inset-inline-end);
   ```
   当在 RTL (从右到左) 环境中渲染时，`inset-inline-start` 实际上会被解析为 `inset-inline-end` 的值，从而实现翻转效果。对于 `float: left;`，它可能会生成：
   ```css
   float: -internal-flip-revert(right);
   ```
   在 RTL 环境中，`float: left` 会被翻转为 `float: right`。

* **HTML:** HTML 结构定义了元素的布局，而 CSS 样式控制这些元素的呈现。`try_value_flips.cc` 处理 CSS 样式，因此它间接地影响了 HTML 元素的最终显示效果。

   **举例说明:**
   一个包含文本的 `<div>` 元素，其 CSS 应用了 `try-value: flip-inline`，在 LTR 和 RTL 环境下，文本的起始位置和浮动元素的行为可能会因为 `try_value_flips.cc` 生成的翻转后的样式而有所不同。

* **JavaScript:** JavaScript 可以动态地修改元素的 CSS 样式。如果 JavaScript 设置了与翻转相关的 CSS 属性或使用了逻辑属性，那么 `try_value_flips.cc` 的功能会被触发。

   **举例说明:**
   ```javascript
   const element = document.querySelector('.element');
   element.style.setProperty('try-value', 'flip-block');
   ```
   这段 JavaScript 代码设置了 `try-value` 属性，这可能会导致渲染引擎调用 `try_value_flips.cc` 来生成相应的翻转后的样式。

**逻辑推理 (假设输入与输出):**

**假设输入:**

- `tactic_list`: 一个 `TryTacticList` 对象，例如包含 `flip-inline` 策略。
- 当前正在处理的 CSS 属性是 `margin-left: 10px;`。
- 当前的渲染上下文是 RTL (从右到左) 书写模式。

**输出:**

- `TryValueFlips::FlipSet` 可能会返回一个 `CSSPropertyValueSet`，其中包含类似以下的条目：
  ```
  margin-left: -internal-flip-revert(margin-right);
  ```
- 当实际应用样式时，由于是 RTL 环境，`margin-left` 会被解释为 `margin-right` 的值，从而实现翻转。

**用户或编程常见的使用错误:**

1. **错误地应用翻转策略到不支持的属性:** 用户可能会尝试将 `flip-inline` 应用到一个没有内联对应物的属性上，例如 `opacity`。在这种情况下，`try_value_flips.cc` 可能不会生成任何翻转后的值，或者会生成一个空操作。

   **例子:**
   ```css
   .element {
     opacity: 0.5;
     try-value: flip-inline; /* opacity 没有内联对应物 */
   }
   ```

2. **对逻辑属性和物理属性的混淆:** 开发者可能不理解逻辑属性的工作原理，并尝试同时使用逻辑属性和物理属性，导致意外的翻转行为。

   **例子:**
   ```css
   .element {
     margin-inline-start: 10px;
     margin-left: 20px; /* 可能会与 margin-inline-start 冲突 */
     try-value: flip-inline;
   }
   ```

3. **不理解 `position-area` 的翻转规则:** `position-area` 属性的翻转逻辑比较复杂，涉及到多个关键字的转换。开发者可能会错误地期望某些关键字的翻转行为。

   **例子:**
   ```css
   .anchor {
     position-area: top left;
     try-value: flip-inline;
   }
   ```
   在 RTL 环境下，`top left` 应该翻转为 `top right`。如果开发者期望其他结果，那就是使用错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户编写 HTML 和 CSS 代码:** 用户创建包含 CSS 规则的 HTML 文件或外部 CSS 文件，其中使用了 `try-value` 属性或者浏览器默认开启了某些翻转行为。
2. **浏览器加载和解析 HTML 和 CSS:** 当用户在浏览器中打开网页时，浏览器会加载 HTML 文档和相关的 CSS 样式表。
3. **样式计算:** 浏览器的渲染引擎会解析 CSS 规则，构建样式表，并计算每个 HTML 元素的最终样式。
4. **遇到 `try-value` 或需要翻转的属性:** 当渲染引擎遇到像 `try-value: flip-inline` 这样的属性，或者遇到需要根据书写模式进行翻转的逻辑属性时，它会触发相应的处理流程。
5. **调用 `TryValueFlips::FlipSet`:**  渲染引擎会调用 `TryValueFlips::FlipSet` 函数，并传递当前的翻转策略。
6. **创建或检索翻转后的属性值集合:** `FlipSet` 函数会检查缓存，如果不存在对应的翻转后的属性值集合，则会调用 `CreateFlipSet` 来生成。
7. **应用翻转后的样式:** 生成的 `CSSPropertyValueSet` 会被用于后续的布局和绘制阶段，确保在不同的书写模式下，元素的样式能够正确地呈现。

**调试线索:**

- **检查 CSS 规则:** 确认是否使用了 `try-value` 属性或影响翻转的 CSS 逻辑属性。
- **检查渲染上下文:** 确认当前的浏览器书写模式（LTR 或 RTL）。
- **断点调试:** 在 `TryValueFlips::FlipSet` 和 `CreateFlipSet` 等关键函数中设置断点，查看传入的 `tactic_list` 和正在处理的 CSS 属性。
- **查看生成的翻转后的属性值:** 检查 `CreateFlipSet` 生成的 `declarations`，了解哪些属性被添加了 `CSSFlipRevertValue`。
- **分析 `TryTacticTransform`:**  理解 `TryTacticTransform` 如何根据 `tactic_list` 进行转换，可以帮助理解为什么某些属性会被翻转。
- **研究 `DeterminePropertyAxis` 和 `DetermineValueAxis` 的结果:** 确保属性和值的轴向被正确地识别。

总而言之，`blink/renderer/core/css/try_value_flips.cc` 是 Blink 渲染引擎中一个关键的模块，负责根据指定的策略生成 CSS 属性值的翻转版本，以支持多语言环境和不同的书写模式。它深入参与了 CSS 样式的计算和应用过程，直接影响着网页的最终呈现效果。

### 提示词
```
这是目录为blink/renderer/core/css/try_value_flips.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/try_value_flips.h"

#include "third_party/blink/renderer/core/css/css_flip_revert_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_math_expression_node.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/try_tactic_transform.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

const CSSPropertyValueSet* TryValueFlips::FlipSet(
    const TryTacticList& tactic_list) const {
  if (tactic_list == kNoTryTactics) {
    return nullptr;
  }

  TryTacticTransform transform(tactic_list);
  // We don't store the kNoTryTactics/nullptr case explicitly, i.e. the entry
  // at cached_flip_sets_[0] corresponds to CacheIndex()==1.
  unsigned index = transform.CacheIndex() - 1;
  cached_flip_sets_.resize(kCachedFlipSetsSize);
  CHECK_LT(index, cached_flip_sets_.size());
  if (!cached_flip_sets_[index]) {
    cached_flip_sets_[index] = CreateFlipSet(transform);
  }
  return cached_flip_sets_[index];
}

const CSSPropertyValueSet* TryValueFlips::CreateFlipSet(
    const TryTacticTransform& transform) const {
  // The maximum number of declarations that can be added to the flip set.
  constexpr wtf_size_t kMaxDeclarations = 17;
  HeapVector<CSSPropertyValue, kMaxDeclarations> declarations;

  auto add = [&declarations, transform](CSSPropertyID from, CSSPropertyID to) {
    declarations.push_back(CSSPropertyValue(
        CSSPropertyName(from),
        *MakeGarbageCollected<cssvalue::CSSFlipRevertValue>(to, transform)));
  };

  auto add_if_flipped = [&add](CSSPropertyID from, CSSPropertyID to) {
    if (from != to) {
      add(from, to);
    }
  };

  using Properties = TryTacticTransform::LogicalSides<CSSPropertyID>;

  // The value of insets.inline_start (etc) must contain the property
  // we should revert to using CSSFlipRevertValue. This means we need
  // the inverse transform.
  //
  // For example, consider this declaration:
  //
  //  right: anchor(left);
  //
  // If we flip this by "flip-inline flip-start", then we should ultimately
  // end up with:
  //
  //  top: anchor(bottom); /* via -internal-flip-revert(right) */
  //
  // The insets, as transformed by `transform` would look like this:
  //
  //  {
  //   .inline_start = CSSPropertyID::kInsetBlockEnd,   /* L -> B */
  //   .inline_end = CSSPropertyID::kInsetBlockStart,   /* R -> T */
  //   .block_start = CSSPropertyID::kInsetInlineStart, /* T -> L */
  //   .block_end = CSSPropertyID::kInsetInlineEnd,     /* B -> R */
  //  }
  //
  // That shows that a inline-end (right) constraint becomes a block-start
  // (top) constraint, which is correct, but if we generate a flip declaration
  // from that using add_if_flipped(kInsetBlockStart, insets.block_start),
  // we effectively get: top:-internal-flip-revert(left), which is not correct.
  // However, if you read above transformed properties the opposite way
  // (i.e. the inverse), you'll see that we indeed get
  // top:-internal-flip-revert(right).
  TryTacticTransform revert_transform = transform.Inverse();

  Properties insets = revert_transform.Transform(Properties{
      .inline_start = CSSPropertyID::kInsetInlineStart,
      .inline_end = CSSPropertyID::kInsetInlineEnd,
      .block_start = CSSPropertyID::kInsetBlockStart,
      .block_end = CSSPropertyID::kInsetBlockEnd,
  });

  add_if_flipped(CSSPropertyID::kInsetBlockStart, insets.block_start);
  add_if_flipped(CSSPropertyID::kInsetBlockEnd, insets.block_end);
  add_if_flipped(CSSPropertyID::kInsetInlineStart, insets.inline_start);
  add_if_flipped(CSSPropertyID::kInsetInlineEnd, insets.inline_end);

  Properties margin = revert_transform.Transform(Properties{
      .inline_start = CSSPropertyID::kMarginInlineStart,
      .inline_end = CSSPropertyID::kMarginInlineEnd,
      .block_start = CSSPropertyID::kMarginBlockStart,
      .block_end = CSSPropertyID::kMarginBlockEnd,
  });

  add_if_flipped(CSSPropertyID::kMarginBlockStart, margin.block_start);
  add_if_flipped(CSSPropertyID::kMarginBlockEnd, margin.block_end);
  add_if_flipped(CSSPropertyID::kMarginInlineStart, margin.inline_start);
  add_if_flipped(CSSPropertyID::kMarginInlineEnd, margin.inline_end);

  // Unlike the other properties, align-self, justify-self, position-area,
  // and inset-area are always added, because we might need to transform the
  // value without changing the property.
  // (E.g. justify-self:start + flip-inline => justify-self:end).
  add(CSSPropertyID::kAlignSelf, transform.FlippedStart()
                                     ? CSSPropertyID::kJustifySelf
                                     : CSSPropertyID::kAlignSelf);
  add(CSSPropertyID::kJustifySelf, transform.FlippedStart()
                                       ? CSSPropertyID::kAlignSelf
                                       : CSSPropertyID::kJustifySelf);
  add(CSSPropertyID::kPositionArea, CSSPropertyID::kPositionArea);

  if (transform.FlippedStart()) {
    add(CSSPropertyID::kBlockSize, CSSPropertyID::kInlineSize);
    add(CSSPropertyID::kInlineSize, CSSPropertyID::kBlockSize);
    add(CSSPropertyID::kMinBlockSize, CSSPropertyID::kMinInlineSize);
    add(CSSPropertyID::kMinInlineSize, CSSPropertyID::kMinBlockSize);
    add(CSSPropertyID::kMaxBlockSize, CSSPropertyID::kMaxInlineSize);
    add(CSSPropertyID::kMaxInlineSize, CSSPropertyID::kMaxBlockSize);
  }

  // Consider updating `kMaxDeclarations` when new properties are added.

  return ImmutableCSSPropertyValueSet::Create(declarations, kHTMLStandardMode);
}

namespace {

LogicalAxis DeterminePropertyAxis(
    CSSPropertyID property_id,
    const WritingDirectionMode& writing_direction) {
  // We expect physical properties here.
  CHECK(!CSSProperty::Get(property_id).IsSurrogate());

  switch (property_id) {
    case CSSPropertyID::kLeft:
    case CSSPropertyID::kRight:
    case CSSPropertyID::kMarginLeft:
    case CSSPropertyID::kMarginRight:
    case CSSPropertyID::kJustifySelf:
    case CSSPropertyID::kWidth:
    case CSSPropertyID::kMaxWidth:
    case CSSPropertyID::kMinWidth:
      return writing_direction.IsHorizontal() ? LogicalAxis::kInline
                                              : LogicalAxis::kBlock;
    case CSSPropertyID::kTop:
    case CSSPropertyID::kBottom:
    case CSSPropertyID::kMarginTop:
    case CSSPropertyID::kMarginBottom:
    case CSSPropertyID::kAlignSelf:
    case CSSPropertyID::kHeight:
    case CSSPropertyID::kMaxHeight:
    case CSSPropertyID::kMinHeight:
      return writing_direction.IsHorizontal() ? LogicalAxis::kBlock
                                              : LogicalAxis::kInline;
    default:
      break;
  }

  NOTREACHED();
}

std::optional<LogicalAxis> DetermineValueAxis(
    CSSValueID value_id,
    const WritingDirectionMode& writing_direction) {
  switch (value_id) {
    case CSSValueID::kLeft:
    case CSSValueID::kRight:
    case CSSValueID::kSpanLeft:
    case CSSValueID::kSpanRight:
    case CSSValueID::kXStart:
    case CSSValueID::kXEnd:
    case CSSValueID::kSpanXStart:
    case CSSValueID::kSpanXEnd:
    case CSSValueID::kXSelfStart:
    case CSSValueID::kXSelfEnd:
    case CSSValueID::kSpanXSelfStart:
    case CSSValueID::kSpanXSelfEnd:
      return writing_direction.IsHorizontal() ? LogicalAxis::kInline
                                              : LogicalAxis::kBlock;
    case CSSValueID::kTop:
    case CSSValueID::kBottom:
    case CSSValueID::kSpanTop:
    case CSSValueID::kSpanBottom:
    case CSSValueID::kYStart:
    case CSSValueID::kYEnd:
    case CSSValueID::kSpanYStart:
    case CSSValueID::kSpanYEnd:
    case CSSValueID::kYSelfStart:
    case CSSValueID::kYSelfEnd:
    case CSSValueID::kSpanYSelfStart:
    case CSSValueID::kSpanYSelfEnd:
      return writing_direction.IsHorizontal() ? LogicalAxis::kBlock
                                              : LogicalAxis::kInline;
    case CSSValueID::kBlockStart:
    case CSSValueID::kBlockEnd:
    case CSSValueID::kSpanBlockStart:
    case CSSValueID::kSpanBlockEnd:
    case CSSValueID::kSelfBlockStart:
    case CSSValueID::kSelfBlockEnd:
    case CSSValueID::kSpanSelfBlockStart:
    case CSSValueID::kSpanSelfBlockEnd:
      return LogicalAxis::kBlock;
    case CSSValueID::kInlineStart:
    case CSSValueID::kInlineEnd:
    case CSSValueID::kSpanInlineStart:
    case CSSValueID::kSpanInlineEnd:
    case CSSValueID::kSelfInlineStart:
    case CSSValueID::kSelfInlineEnd:
    case CSSValueID::kSpanSelfInlineStart:
    case CSSValueID::kSpanSelfInlineEnd:
      return LogicalAxis::kInline;
    case CSSValueID::kSpanAll:
    case CSSValueID::kCenter:
    case CSSValueID::kStart:
    case CSSValueID::kEnd:
    case CSSValueID::kSpanStart:
    case CSSValueID::kSpanEnd:
    case CSSValueID::kSelfStart:
    case CSSValueID::kSelfEnd:
    case CSSValueID::kSpanSelfStart:
    case CSSValueID::kSpanSelfEnd:
    default:
      return std::nullopt;
  }
}

CSSValueID ConvertLeftRightToLogical(
    CSSValueID value,
    const WritingDirectionMode& writing_direction) {
  if (value == CSSValueID::kLeft) {
    return writing_direction.IsLtr() ? CSSValueID::kSelfStart
                                     : CSSValueID::kSelfEnd;
  }
  if (value == CSSValueID::kRight) {
    return writing_direction.IsLtr() ? CSSValueID::kSelfEnd
                                     : CSSValueID::kSelfStart;
  }
  return value;
}

CSSValueID FlipSelfAlignmentKeyword(CSSValueID value) {
  switch (value) {
    case CSSValueID::kLeft:
      return CSSValueID::kRight;
    case CSSValueID::kRight:
      return CSSValueID::kLeft;
    case CSSValueID::kStart:
      return CSSValueID::kEnd;
    case CSSValueID::kEnd:
      return CSSValueID::kStart;
    case CSSValueID::kSelfStart:
      return CSSValueID::kSelfEnd;
    case CSSValueID::kSelfEnd:
      return CSSValueID::kSelfStart;
    case CSSValueID::kFlexStart:
      return CSSValueID::kFlexEnd;
    case CSSValueID::kFlexEnd:
      return CSSValueID::kFlexStart;
    default:
      return value;
  }
}

const CSSValue* TransformSelfAlignment(
    const CSSValue* value,
    LogicalAxis logical_axis,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) {
  auto* ident = DynamicTo<CSSIdentifierValue>(value);
  auto* pair = DynamicTo<CSSValuePair>(value);
  if (!ident && !pair) {
    return value;
  }
  // Flips start => end, end => start, etc.
  bool flip_side = (logical_axis == LogicalAxis::kInline)
                       ? transform.FlippedInline()
                       : transform.FlippedBlock();

  CSSValueID from = ident ? ident->GetValueID()
                          : To<CSSIdentifierValue>(pair->Second()).GetValueID();
  CSSValueID to = flip_side ? FlipSelfAlignmentKeyword(from) : from;
  // justify-self supports left and right, align-self does not. FlippedStart
  // means align-self may have acquired a left or right value, which needs to be
  // translated to a logical equivalent.
  to = transform.FlippedStart()
           ? ConvertLeftRightToLogical(to, writing_direction)
           : to;
  if (from == to) {
    return value;
  }
  // Return the same type of value that came in.
  if (ident) {
    return CSSIdentifierValue::Create(to);
  }
  return MakeGarbageCollected<CSSValuePair>(
      &pair->First(), CSSIdentifierValue::Create(to),
      pair->KeepIdenticalValues() ? CSSValuePair::kKeepIdenticalValues
                                  : CSSValuePair::kDropIdenticalValues);
}

LogicalToPhysical<CSSValueID> TransformPhysical(
    CSSValueID left,
    CSSValueID right,
    CSSValueID top,
    CSSValueID bottom,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) {
  // The transform is carried out on logical values, so we need to convert
  // to logical first.
  PhysicalToLogical logical(writing_direction, top, right, bottom, left);
  return transform.Transform(
      TryTacticTransform::LogicalSides<CSSValueID>{
          .inline_start = logical.InlineStart(),
          .inline_end = logical.InlineEnd(),
          .block_start = logical.BlockStart(),
          .block_end = logical.BlockEnd()},
      writing_direction);
}

LogicalToPhysical<CSSValueID> TransformXY(
    CSSValueID x_start,
    CSSValueID x_end,
    CSSValueID y_start,
    CSSValueID y_end,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) {
  // We can use TransformPhysical even though x-* and y-* are not fully
  // physical. We might get the start/end in the reverse order when we
  // convert from physical to logical, but it doesn't matter, because
  // we'll then un-reverse the start/end when we convert back to logical.
  return TransformPhysical(x_start, x_end, y_start, y_end, transform,
                           writing_direction);
}

TryTacticTransform::LogicalSides<CSSValueID> TransformLogical(
    CSSValueID inline_start,
    CSSValueID inline_end,
    CSSValueID block_start,
    CSSValueID block_end,
    const TryTacticTransform& transform) {
  return transform.Transform(
      TryTacticTransform::LogicalSides<CSSValueID>{.inline_start = inline_start,
                                                   .inline_end = inline_end,
                                                   .block_start = block_start,
                                                   .block_end = block_end});
}

// Transforms a CSSValueID, specified for the indicated logical axis,
// according to the transform.
CSSValueID TransformPositionAreaKeyword(
    CSSValueID from,
    LogicalAxis logical_axis,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) {
  bool flip_start_end = (logical_axis == LogicalAxis::kInline)
                            ? transform.FlippedInline()
                            : transform.FlippedBlock();

  auto transform_physical = [&transform, &writing_direction] {
    return TransformPhysical(CSSValueID::kLeft, CSSValueID::kRight,
                             CSSValueID::kTop, CSSValueID::kBottom, transform,
                             writing_direction);
  };

  auto transform_physical_span = [&transform, &writing_direction] {
    return TransformPhysical(CSSValueID::kSpanLeft, CSSValueID::kSpanRight,
                             CSSValueID::kSpanTop, CSSValueID::kSpanBottom,
                             transform, writing_direction);
  };

  auto transform_logical = [&transform] {
    return TransformLogical(CSSValueID::kInlineStart, CSSValueID::kInlineEnd,
                            CSSValueID::kBlockStart, CSSValueID::kBlockEnd,
                            transform);
  };

  auto transform_logical_span = [&transform] {
    return TransformLogical(
        CSSValueID::kSpanInlineStart, CSSValueID::kSpanInlineEnd,
        CSSValueID::kSpanBlockStart, CSSValueID::kSpanBlockEnd, transform);
  };

  auto transform_logical_self = [&transform] {
    return TransformLogical(
        CSSValueID::kSelfInlineStart, CSSValueID::kSelfInlineEnd,
        CSSValueID::kSelfBlockStart, CSSValueID::kSelfBlockEnd, transform);
  };

  auto transform_logical_span_self = [&transform] {
    return TransformLogical(CSSValueID::kSpanSelfInlineStart,
                            CSSValueID::kSpanSelfInlineEnd,
                            CSSValueID::kSpanSelfBlockStart,
                            CSSValueID::kSpanSelfBlockEnd, transform);
  };

  auto transform_xy = [&transform, &writing_direction] {
    return TransformXY(CSSValueID::kXStart, CSSValueID::kXEnd,
                       CSSValueID::kYStart, CSSValueID::kYEnd, transform,
                       writing_direction);
  };

  auto transform_xy_span = [&transform, &writing_direction] {
    return TransformXY(CSSValueID::kSpanXStart, CSSValueID::kSpanXEnd,
                       CSSValueID::kSpanYStart, CSSValueID::kSpanYEnd,
                       transform, writing_direction);
  };

  auto transform_xy_self = [&transform, &writing_direction] {
    return TransformXY(CSSValueID::kXSelfStart, CSSValueID::kXSelfEnd,
                       CSSValueID::kYSelfStart, CSSValueID::kYSelfEnd,
                       transform, writing_direction);
  };

  auto transform_xy_span_self = [&transform, &writing_direction] {
    return TransformXY(CSSValueID::kSpanXSelfStart, CSSValueID::kSpanXSelfEnd,
                       CSSValueID::kSpanYSelfStart, CSSValueID::kSpanYSelfEnd,
                       transform, writing_direction);
  };

  switch (from) {
      // Physical:

    case CSSValueID::kLeft:
      return transform_physical().Left();
    case CSSValueID::kRight:
      return transform_physical().Right();
    case CSSValueID::kTop:
      return transform_physical().Top();
    case CSSValueID::kBottom:
      return transform_physical().Bottom();

    case CSSValueID::kSpanLeft:
      return transform_physical_span().Left();
    case CSSValueID::kSpanRight:
      return transform_physical_span().Right();
    case CSSValueID::kSpanTop:
      return transform_physical_span().Top();
    case CSSValueID::kSpanBottom:
      return transform_physical_span().Bottom();

      // XY:

    case CSSValueID::kXStart:
      return transform_xy().Left();
    case CSSValueID::kXEnd:
      return transform_xy().Right();
    case CSSValueID::kYStart:
      return transform_xy().Top();
    case CSSValueID::kYEnd:
      return transform_xy().Bottom();

    case CSSValueID::kSpanXStart:
      return transform_xy_span().Left();
    case CSSValueID::kSpanXEnd:
      return transform_xy_span().Right();
    case CSSValueID::kSpanYStart:
      return transform_xy_span().Top();
    case CSSValueID::kSpanYEnd:
      return transform_xy_span().Bottom();

    case CSSValueID::kXSelfStart:
      return transform_xy_self().Left();
    case CSSValueID::kXSelfEnd:
      return transform_xy_self().Right();
    case CSSValueID::kYSelfStart:
      return transform_xy_self().Top();
    case CSSValueID::kYSelfEnd:
      return transform_xy_self().Bottom();

    case CSSValueID::kSpanXSelfStart:
      return transform_xy_span_self().Left();
    case CSSValueID::kSpanXSelfEnd:
      return transform_xy_span_self().Right();
    case CSSValueID::kSpanYSelfStart:
      return transform_xy_span_self().Top();
    case CSSValueID::kSpanYSelfEnd:
      return transform_xy_span_self().Bottom();

      // Logical:

    case CSSValueID::kInlineStart:
      return transform_logical().inline_start;
    case CSSValueID::kInlineEnd:
      return transform_logical().inline_end;
    case CSSValueID::kBlockStart:
      return transform_logical().block_start;
    case CSSValueID::kBlockEnd:
      return transform_logical().block_end;

    case CSSValueID::kSpanInlineStart:
      return transform_logical_span().inline_start;
    case CSSValueID::kSpanInlineEnd:
      return transform_logical_span().inline_end;
    case CSSValueID::kSpanBlockStart:
      return transform_logical_span().block_start;
    case CSSValueID::kSpanBlockEnd:
      return transform_logical_span().block_end;

    case CSSValueID::kSelfInlineStart:
      return transform_logical_self().inline_start;
    case CSSValueID::kSelfInlineEnd:
      return transform_logical_self().inline_end;
    case CSSValueID::kSelfBlockStart:
      return transform_logical_self().block_start;
    case CSSValueID::kSelfBlockEnd:
      return transform_logical_self().block_end;

    case CSSValueID::kSpanSelfInlineStart:
      return transform_logical_span_self().inline_start;
    case CSSValueID::kSpanSelfInlineEnd:
      return transform_logical_span_self().inline_end;
    case CSSValueID::kSpanSelfBlockStart:
      return transform_logical_span_self().block_start;
    case CSSValueID::kSpanSelfBlockEnd:
      return transform_logical_span_self().block_end;

      // Start/end

    case CSSValueID::kStart:
      return flip_start_end ? CSSValueID::kEnd : CSSValueID::kStart;
    case CSSValueID::kEnd:
      return flip_start_end ? CSSValueID::kStart : CSSValueID::kEnd;

    case CSSValueID::kSpanStart:
      return flip_start_end ? CSSValueID::kSpanEnd : CSSValueID::kSpanStart;
    case CSSValueID::kSpanEnd:
      return flip_start_end ? CSSValueID::kSpanStart : CSSValueID::kSpanEnd;

    case CSSValueID::kSelfStart:
      return flip_start_end ? CSSValueID::kSelfEnd : CSSValueID::kSelfStart;
    case CSSValueID::kSelfEnd:
      return flip_start_end ? CSSValueID::kSelfStart : CSSValueID::kSelfEnd;

    case CSSValueID::kSpanSelfStart:
      return flip_start_end ? CSSValueID::kSpanSelfEnd
                            : CSSValueID::kSpanSelfStart;
    case CSSValueID::kSpanSelfEnd:
      return flip_start_end ? CSSValueID::kSpanSelfStart
                            : CSSValueID::kSpanSelfEnd;

    default:
      return from;
  }
}

const CSSValue* TransformPositionArea(
    const CSSValue* value,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) {
  auto* ident = DynamicTo<CSSIdentifierValue>(value);
  auto* pair = DynamicTo<CSSValuePair>(value);
  if (!ident && !pair) {
    return value;
  }

  CSSValueID first_value = CSSValueID::kNone;
  CSSValueID second_value = CSSValueID::kNone;

  if (ident) {
    first_value = ident->GetValueID();
    second_value = css_parsing_utils::IsRepeatedPositionAreaValue(first_value)
                       ? first_value
                       : CSSValueID::kSpanAll;
  } else {
    first_value = To<CSSIdentifierValue>(pair->First()).GetValueID();
    second_value = To<CSSIdentifierValue>(pair->Second()).GetValueID();
  }

  std::optional<LogicalAxis> first_axis =
      DetermineValueAxis(first_value, writing_direction);
  std::optional<LogicalAxis> second_axis =
      DetermineValueAxis(second_value, writing_direction);

  // If one value is unambiguous about its axis, the other value must refer
  // to the other axis. If both are ambiguous, then the first value represents
  // the block axis.
  //
  // https://drafts.csswg.org/css-anchor-position-1/#resolving-spans
  if (first_axis.has_value()) {
    second_axis = (first_axis.value() == LogicalAxis::kInline)
                      ? LogicalAxis::kBlock
                      : LogicalAxis::kInline;
  } else if (second_axis.has_value()) {
    first_axis = (second_axis.value() == LogicalAxis::kInline)
                     ? LogicalAxis::kBlock
                     : LogicalAxis::kInline;
  } else {
    first_axis = LogicalAxis::kBlock;
    second_axis = LogicalAxis::kInline;
  }

  CSSValueID first_value_transformed = TransformPositionAreaKeyword(
      first_value, first_axis.value(), transform, writing_direction);
  CSSValueID second_value_transformed = TransformPositionAreaKeyword(
      second_value, second_axis.value(), transform, writing_direction);

  // Maintain grammar order after flip-start.
  if (transform.FlippedStart()) {
    std::swap(first_value_transformed, second_value_transformed);
  }

  if (first_value == first_value_transformed &&
      second_value == second_value_transformed) {
    // No transformation needed.
    return value;
  }

  if (first_value_transformed == second_value_transformed) {
    return CSSIdentifierValue::Create(first_value_transformed);
  }

  // Return a value on the canonical form, i.e. represent the value as a single
  // identifier when possible. See the end of the section 3.1.1 [1] for cases
  // where we should return a single identifier.
  // [1] https://drafts.csswg.org/css-anchor-position-1/#resolving-spans

  if (first_value_transformed == CSSValueID::kSpanAll &&
      !css_parsing_utils::IsRepeatedPositionAreaValue(
          second_value_transformed)) {
    return CSSIdentifierValue::Create(second_value_transformed);
  }
  if (second_value_transformed == CSSValueID::kSpanAll &&
      !css_parsing_utils::IsRepeatedPositionAreaValue(
          first_value_transformed)) {
    return CSSIdentifierValue::Create(first_value_transformed);
  }

  return MakeGarbageCollected<CSSValuePair>(
      CSSIdentifierValue::Create(first_value_transformed),
      CSSIdentifierValue::Create(second_value_transformed),
      pair->KeepIdenticalValues() ? CSSValuePair::kKeepIdenticalValues
                                  : CSSValuePair::kDropIdenticalValues);
}

}  // namespace

const CSSValue* TryValueFlips::FlipValue(
    CSSPropertyID from_property,
    const CSSValue* value,
    const TryTacticTransform& transform,
    const WritingDirectionMode& writing_direction) {
  if (const auto* math_value = DynamicTo<CSSMathFunctionValue>(value)) {
    LogicalAxis logical_axis =
        DeterminePropertyAxis(from_property, writing_direction);
    return math_value->TransformAnchors(logical_axis, transform,
                                        writing_direction);
  }
  if (from_property == CSSPropertyID::kAlignSelf ||
      from_property == CSSPropertyID::kJustifySelf) {
    LogicalAxis logical_axis =
        DeterminePropertyAxis(from_property, writing_direction);
    return TransformSelfAlignment(value, logical_axis, transform,
                                  writing_direction);
  }
  if (from_property == CSSPropertyID::kPositionArea) {
    return TransformPositionArea(value, transform, writing_direction);
  }
  return value;
}

void TryValueFlips::Trace(Visitor* visitor) const {
  visitor->Trace(cached_flip_sets_);
}

}  // namespace blink
```