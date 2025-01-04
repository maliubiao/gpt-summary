Response:
Let's break down the thought process to analyze the `css_direction_aware_resolver.cc` file.

**1. Initial Reading and Identifying the Core Purpose:**

The file name itself, `css_direction_aware_resolver.cc`, is highly suggestive. "Direction-aware" points towards handling layout and styling based on text direction (like left-to-right vs. right-to-left). The "resolver" part implies it's about determining the *actual* CSS property to use based on context.

Skimming through the code confirms this. Keywords like "logical", "physical", "writing direction", "inline", "block", "start", and "end" are strong indicators of dealing with logical properties.

**2. Understanding the Key Concepts:**

* **Logical vs. Physical Properties:** This is crucial. Logical properties (e.g., `border-block-start`, `margin-inline-end`) describe placement relative to the flow of content, whereas physical properties (e.g., `border-top`, `margin-right`) are fixed to the viewport edges. The resolver's job is to map between them.
* **Writing Modes:**  The code explicitly mentions `WritingMode` and different values like `horizontal-tb`, `vertical-rl`, etc. This reinforces the idea of handling different text layout orientations.
* **Writing Direction:**  The `WritingDirectionMode` class and the use of `IsLtr()` further highlight the importance of left-to-right and right-to-left contexts.
* **Mappings:** The `LogicalMapping` and `PhysicalMapping` templates are clearly central. They seem to group related CSS properties together.

**3. Analyzing the Code Structure:**

* **Namespaces:** The code is within the `blink` namespace and an anonymous namespace. This is typical Chromium style for organization and avoiding naming conflicts.
* **Helper Functions:** The anonymous namespace contains helper enums (`PhysicalAxis`, `PhysicalBoxCorner`) and constant arrays (`kStartStartMap`, `kStartEndMap`, etc.). These are pre-calculated mappings based on writing mode and direction.
* **`Group` Template:** This template appears to be a basic container for a group of related CSS properties, either from a shorthand or a direct list.
* **Mapping Functions:**  Functions like `LogicalBorderMapping()`, `PhysicalBorderColorMapping()`, etc., return instances of `LogicalMapping` or `PhysicalMapping`, pre-populated with the relevant CSS property pointers. This suggests these functions define the known mappings.
* **`Resolve*` Functions:**  The core logic lies in functions like `ResolveInlineStart()`, `ResolveBlockEnd()`, `ResolveStartStart()`, etc. These take a `WritingDirectionMode` and a `PhysicalMapping` as input and return a specific `CSSProperty` based on the current context.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

* **CSS:** The entire file revolves around CSS properties. The mapping between logical and physical properties *is* a core aspect of modern CSS layout. Examples of logical properties are present in the mapping function names.
* **HTML:** The `dir` attribute on HTML elements is a direct influence on writing direction. The browser parses this attribute and uses it to determine the `WritingDirectionMode`.
* **JavaScript:** JavaScript can manipulate the `dir` attribute of elements, dynamically changing the writing direction and thus influencing which physical CSS properties are ultimately applied. JavaScript could also read computed styles, observing the effects of the direction-aware resolution.

**5. Inferring Logic and Providing Examples:**

* **Hypothetical Input/Output:** Consider the `ResolveInlineStart()` function. If `writing_direction` is LTR, it should return the *left* property. If it's RTL, it should return the *right* property. This is a core behavior of direction-aware resolution. Similar logic applies to `block-start` (top in horizontal, left/right in vertical), etc.
* **`kStartStartMap` Example:**  For LTR and `horizontal-tb`, `kStartStartMap` indicates the top-left corner. For RTL and `horizontal-tb`, it indicates the top-right corner. This directly ties logical concepts to physical box corners.

**6. Identifying Potential User/Programming Errors:**

* **Inconsistent Logical/Physical Usage:**  Mixing logical and physical properties without understanding their interaction can lead to unexpected results, especially when dealing with different writing modes.
* **Incorrect `dir` Attribute:** Setting the `dir` attribute incorrectly or failing to set it when needed can cause layout issues for right-to-left languages.
* **Overriding Logical Properties with Physical Ones:**  Directly setting physical properties can negate the benefits of using logical properties for internationalization.

**7. Tracing User Operations:**

This requires thinking about how the browser processes web pages:

1. **HTML Parsing:** The browser parses the HTML, including the `dir` attribute.
2. **CSS Parsing:** The browser parses the CSS, encountering logical and physical properties.
3. **Style Calculation:** This is where the `css_direction_aware_resolver.cc` comes into play. During style calculation, the browser needs to determine the *final* physical values to apply based on the logical properties and the computed writing direction. The resolver is used to map logical properties to their appropriate physical counterparts.
4. **Layout:** The layout engine uses the resolved physical properties to position and size elements on the page.
5. **Rendering:** The final visual output is rendered based on the layout.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file just maps logical to physical properties."  **Correction:** It's more nuanced. It considers *both* writing direction and writing mode to determine the correct physical property.
* **Initial thought:** "The mapping is simple." **Correction:** The use of lookup tables like `kStartStartMap` shows that the mapping depends on the combination of writing direction and mode, making it more complex.
* **Focusing too much on specific function names:** **Correction:**  It's important to understand the overall purpose and how the different parts work together. The `Resolve*` functions are key, but the mapping data structures are equally important.

By following this structured approach, combining code analysis with knowledge of web technologies and potential pitfalls, a comprehensive understanding of the `css_direction_aware_resolver.cc` file can be achieved.
这个文件是 Chromium Blink 引擎中的 `css_direction_aware_resolver.cc`，它的主要功能是 **解析和处理 CSS 逻辑属性 (Logical Properties)**，并将其映射到相应的 **物理属性 (Physical Properties)**。这个过程会考虑到元素的 **书写模式 (Writing Mode)** 和 **书写方向 (Writing Direction)**，从而实现对不同语言和布局的支持。

**更具体的功能可以列举如下：**

1. **定义逻辑属性到物理属性的映射关系:**  文件中定义了各种 CSS 逻辑属性（如 `border-block-start`, `margin-inline-end`）与对应的物理属性（如 `border-top`, `margin-right`）之间的映射关系。这些映射关系存储在 `LogicalMapping` 和 `PhysicalMapping` 结构体中。

2. **根据书写模式和书写方向进行解析:** 核心功能是根据元素的 `writing-mode` 和 `direction` CSS 属性（或者继承来的值）来决定使用哪个物理属性。例如，对于一个设置了 `writing-mode: horizontal-tb` 和 `direction: rtl` 的元素，`border-block-start` 可能会映射到 `border-top`，而 `border-inline-start` 可能会映射到 `border-right`。

3. **提供便捷的访问接口:**  文件中提供了一系列的 `Resolve*` 函数（如 `ResolveInlineStart`, `ResolveBlockEnd`, `ResolveStartStart`），这些函数接收 `WritingDirectionMode` 对象（包含书写模式和书写方向信息）以及一个 `PhysicalMapping` 对象，并返回最终应该使用的物理属性。

**与 JavaScript, HTML, CSS 的关系以及举例说明：**

* **CSS:**  这个文件直接处理 CSS 属性。
    * **例子:** 当 CSS 中使用了逻辑属性 `margin-inline-start: 10px;` 时，`css_direction_aware_resolver.cc` 会根据元素的 `writing-mode` 和 `direction` 来决定这个样式最终应用到哪个物理属性上。
        * 如果 `direction: ltr` (left-to-right)，则会映射到 `margin-left: 10px;`。
        * 如果 `direction: rtl` (right-to-left)，则会映射到 `margin-right: 10px;`。
        * 如果 `writing-mode` 是垂直方向的，映射可能会更复杂。

* **HTML:** HTML 的 `dir` 属性会影响书写方向。
    * **例子:**  一个 HTML 元素设置了 `<div dir="rtl">...</div>`，这会影响其内部元素的书写方向。当 CSS 中的逻辑属性应用到这个 `div` 或其子元素时，`css_direction_aware_resolver.cc` 会考虑这个 `dir` 属性的值。

* **JavaScript:** JavaScript 可以读取和修改元素的 CSS 样式，包括逻辑属性和影响书写模式和方向的属性。
    * **例子:** JavaScript 可以使用 `element.style.marginInlineStart = '20px';` 来设置逻辑属性。Blink 引擎在处理这个样式时会用到 `css_direction_aware_resolver.cc` 来确定最终的物理属性。
    * **例子:** JavaScript 也可以通过 `element.style.direction = 'rtl';` 来改变元素的书写方向，这会直接影响 `css_direction_aware_resolver.cc` 的解析结果。

**逻辑推理、假设输入与输出：**

假设我们有以下 CSS 和 HTML：

**HTML:**

```html
<!DOCTYPE html>
<html>
<head>
<style>
  .box {
    writing-mode: horizontal-tb; /* 水平方向，从上到下 */
    direction: rtl; /* 从右到左 */
    border-block-start: 5px solid black;
    border-inline-start: 10px solid red;
  }
</style>
</head>
<body>
  <div class="box">这是一个盒子</div>
</body>
</html>
```

**假设输入 (在 `css_direction_aware_resolver.cc` 的上下文中):**

* `writing_direction`: 一个 `WritingDirectionMode` 对象，其内部包含了 `writing-mode: horizontal-tb` 和 `direction: rtl` 的信息。
* 对于 `border-block-start`:  调用 `ResolveBlockStart` 函数，传入 `PhysicalBorderMapping()`。
* 对于 `border-inline-start`: 调用 `ResolveInlineStart` 函数，传入 `PhysicalBorderMapping()`。

**逻辑推理:**

* 对于 `border-block-start`:
    * `writing-mode` 是 `horizontal-tb`，表示块级方向是垂直的。
    * `ResolveBlockStart` 会根据水平书写模式，通常映射到物理属性的顶部。
    * **输出:**  `GetCSSPropertyBorderTop()` (指向 `border-top` 属性的指针)。

* 对于 `border-inline-start`:
    * `writing-mode` 是 `horizontal-tb`，表示内联方向是水平的。
    * `direction` 是 `rtl`，表示内联方向的开始在右边。
    * `ResolveInlineStart` 会根据水平书写模式和 RTL 方向，映射到物理属性的右边。
    * **输出:** `GetCSSPropertyBorderRight()` (指向 `border-right` 属性的指针)。

**用户或编程常见的使用错误：**

1. **混淆逻辑属性和物理属性:**  不理解逻辑属性的含义，错误地认为它们总是对应相同的物理属性，导致在不同的书写模式或方向下出现意外的布局。
    * **例子:** 开发者可能认为 `margin-inline-start` 总是对应 `margin-left`，而忽略了 `direction: rtl` 的情况。

2. **没有正确设置 `writing-mode` 和 `direction`:**  对于需要支持多种语言或布局的网页，没有正确设置这两个属性会导致逻辑属性无法按预期工作。
    * **例子:**  一个阿拉伯语网站没有设置 `direction: rtl`，导致使用逻辑属性定义的边距或边框出现在错误的一侧。

3. **过度使用物理属性而忽略逻辑属性:**  在可以使用逻辑属性的情况下仍然使用物理属性，会降低代码的灵活性和国际化能力。
    * **例子:**  始终使用 `margin-left` 和 `margin-right` 而不使用 `margin-inline-start` 和 `margin-inline-end`。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户访问一个网页:** 用户在浏览器中输入网址或点击链接访问一个网页。

2. **浏览器解析 HTML 和 CSS:** 浏览器开始解析下载的 HTML 和 CSS 文件。

3. **遇到包含逻辑属性的 CSS 规则:**  解析器在 CSS 规则中遇到了逻辑属性，例如 `padding-block-end`。

4. **样式计算 (Style Calculation):**  Blink 引擎开始进行样式计算，确定每个元素最终的样式。在这个阶段，需要将逻辑属性解析为对应的物理属性。

5. **`css_direction_aware_resolver.cc` 被调用:**  当需要解析逻辑属性时，相关的代码会调用 `css_direction_aware_resolver.cc` 中的函数。

6. **获取元素的书写模式和方向:**  `css_direction_aware_resolver.cc` 的代码会检查当前元素的 `writing-mode` 和 `direction` 属性（或者继承来的值）。

7. **查找映射关系:**  根据元素的书写模式和方向，以及要解析的逻辑属性，代码会使用预定义的映射关系 (例如 `LogicalBorderMapping`, `PhysicalPaddingMapping`)。

8. **调用 `Resolve*` 函数:**  相应的 `Resolve*` 函数会被调用，例如 `ResolvePaddingBlockEnd`，传入书写模式/方向信息和物理属性映射组。

9. **确定最终的物理属性:**  `Resolve*` 函数根据书写模式和方向，从物理属性映射组中选择正确的物理属性。

10. **应用物理属性:**  最终，计算出的物理属性值会被应用到元素的样式中，用于后续的布局和渲染。

**调试线索:**

如果开发者在调试涉及到逻辑属性的布局问题，可以关注以下几点：

* **检查元素的 `writing-mode` 和 `direction` 属性:**  使用浏览器的开发者工具查看元素的计算样式，确认这两个属性的值是否符合预期。
* **断点调试 `css_direction_aware_resolver.cc`:**  如果可以构建和调试 Chromium，可以在 `Resolve*` 函数中设置断点，查看在特定的书写模式和方向下，逻辑属性是如何被映射到物理属性的。
* **检查相关的 CSS 规则:**  确认 CSS 规则中逻辑属性的使用是否正确，是否有意外的层叠或覆盖。
* **考虑继承关系:**  书写模式和方向是可以继承的，确保父元素的设置没有意外地影响子元素。

总而言之，`css_direction_aware_resolver.cc` 是 Blink 引擎中处理 CSS 逻辑属性的关键组件，它确保了网页在不同的书写模式和方向下能够正确地显示和布局，是实现国际化和本地化的重要基础。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/css_direction_aware_resolver.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/css/properties/css_direction_aware_resolver.h"

#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/properties/shorthands.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/text/writing_direction_mode.h"
#include "third_party/blink/renderer/platform/wtf/assertions.h"

namespace blink {
namespace {

template <size_t size>
using LogicalMapping = CSSDirectionAwareResolver::LogicalMapping<size>;
template <size_t size>
using PhysicalMapping = CSSDirectionAwareResolver::PhysicalMapping<size>;

enum PhysicalAxis { kPhysicalAxisX, kPhysicalAxisY };
enum PhysicalBoxCorner {
  kTopLeftCorner,
  kTopRightCorner,
  kBottomRightCorner,
  kBottomLeftCorner
};

constexpr size_t kWritingModeSize =
    static_cast<size_t>(WritingMode::kMaxWritingMode) + 1;
// Following four arrays contain values for horizontal-tb, vertical-rl,
// vertical-lr, sideways-rl, and sideways-lr in this order.
constexpr uint8_t kStartStartMap[kWritingModeSize] = {
    kTopLeftCorner, kTopRightCorner, kTopLeftCorner, kTopRightCorner,
    kBottomLeftCorner};
constexpr uint8_t kStartEndMap[kWritingModeSize] = {
    kTopRightCorner, kBottomRightCorner, kBottomLeftCorner, kBottomRightCorner,
    kTopLeftCorner};
constexpr uint8_t kEndStartMap[kWritingModeSize] = {
    kBottomLeftCorner, kTopLeftCorner, kTopRightCorner, kTopLeftCorner,
    kBottomRightCorner};
constexpr uint8_t kEndEndMap[kWritingModeSize] = {
    kBottomRightCorner, kBottomLeftCorner, kBottomRightCorner,
    kBottomLeftCorner, kTopRightCorner};

// Prerequisites for Physical*Mapping().
STATIC_ASSERT_ENUM(PhysicalDirection::kUp, 0);
STATIC_ASSERT_ENUM(PhysicalDirection::kRight, 1);
STATIC_ASSERT_ENUM(PhysicalDirection::kDown, 2);
STATIC_ASSERT_ENUM(PhysicalDirection::kLeft, 3);

}  // namespace

template <size_t size>
CSSDirectionAwareResolver::Group<size>::Group(
    const StylePropertyShorthand& shorthand)
    : properties_(shorthand.properties().data()) {
  DCHECK_EQ(size, shorthand.length());
}

template <size_t size>
CSSDirectionAwareResolver::Group<size>::Group(
    const CSSProperty* (&properties)[size])
    : properties_(properties) {}

template <size_t size>
const CSSProperty& CSSDirectionAwareResolver::Group<size>::GetProperty(
    size_t index) const {
  DCHECK_LT(index, size);
  return *properties_[index];
}

template <size_t size>
bool CSSDirectionAwareResolver::Group<size>::Contains(CSSPropertyID id) const {
  for (size_t i = 0; i < size; ++i) {
    if (properties_[i]->IDEquals(id)) {
      return true;
    }
  }
  return false;
}

template class CSSDirectionAwareResolver::Group<2ul>;
template class CSSDirectionAwareResolver::Group<4ul>;

LogicalMapping<4> CSSDirectionAwareResolver::LogicalBorderMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyBorderBlockStart(), &GetCSSPropertyBorderBlockEnd(),
      &GetCSSPropertyBorderInlineStart(), &GetCSSPropertyBorderInlineEnd()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalBorderMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyBorderTop(), &GetCSSPropertyBorderRight(),
      &GetCSSPropertyBorderBottom(), &GetCSSPropertyBorderLeft()};
  return PhysicalMapping<4>(kProperties);
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalBorderColorMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyBorderBlockStartColor(),
      &GetCSSPropertyBorderBlockEndColor(),
      &GetCSSPropertyBorderInlineStartColor(),
      &GetCSSPropertyBorderInlineEndColor()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalBorderColorMapping() {
  return PhysicalMapping<4>(borderColorShorthand());
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalBorderStyleMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyBorderBlockStartStyle(),
      &GetCSSPropertyBorderBlockEndStyle(),
      &GetCSSPropertyBorderInlineStartStyle(),
      &GetCSSPropertyBorderInlineEndStyle()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalBorderStyleMapping() {
  return PhysicalMapping<4>(borderStyleShorthand());
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalBorderWidthMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyBorderBlockStartWidth(),
      &GetCSSPropertyBorderBlockEndWidth(),
      &GetCSSPropertyBorderInlineStartWidth(),
      &GetCSSPropertyBorderInlineEndWidth()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<2>
CSSDirectionAwareResolver::PhysicalContainIntrinsicSizeMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyContainIntrinsicWidth(),
      &GetCSSPropertyContainIntrinsicHeight()};
  return PhysicalMapping<2>(kProperties);
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalBorderRadiusMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyBorderStartStartRadius(),
      &GetCSSPropertyBorderStartEndRadius(),
      &GetCSSPropertyBorderEndStartRadius(),
      &GetCSSPropertyBorderEndEndRadius()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalBorderRadiusMapping() {
  return PhysicalMapping<4>(borderRadiusShorthand());
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalBorderWidthMapping() {
  return PhysicalMapping<4>(borderWidthShorthand());
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalInsetMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyInsetBlockStart(), &GetCSSPropertyInsetBlockEnd(),
      &GetCSSPropertyInsetInlineStart(), &GetCSSPropertyInsetInlineEnd()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalInsetMapping() {
  return PhysicalMapping<4>(insetShorthand());
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalMarginMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyMarginBlockStart(), &GetCSSPropertyMarginBlockEnd(),
      &GetCSSPropertyMarginInlineStart(), &GetCSSPropertyMarginInlineEnd()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalMarginMapping() {
  return PhysicalMapping<4>(marginShorthand());
}

LogicalMapping<2> CSSDirectionAwareResolver::LogicalMaxSizeMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyMaxBlockSize(),
                                             &GetCSSPropertyMaxInlineSize()};
  return LogicalMapping<2>(kProperties);
}

PhysicalMapping<2> CSSDirectionAwareResolver::PhysicalMaxSizeMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyMaxWidth(),
                                             &GetCSSPropertyMaxHeight()};
  return PhysicalMapping<2>(kProperties);
}

LogicalMapping<2> CSSDirectionAwareResolver::LogicalMinSizeMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyMinBlockSize(),
                                             &GetCSSPropertyMinInlineSize()};
  return LogicalMapping<2>(kProperties);
}

PhysicalMapping<2> CSSDirectionAwareResolver::PhysicalMinSizeMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyMinWidth(),
                                             &GetCSSPropertyMinHeight()};
  return PhysicalMapping<2>(kProperties);
}

LogicalMapping<2> CSSDirectionAwareResolver::LogicalOverflowMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyOverflowBlock(),
                                             &GetCSSPropertyOverflowInline()};
  return LogicalMapping<2>(kProperties);
}

PhysicalMapping<2> CSSDirectionAwareResolver::PhysicalOverflowMapping() {
  return PhysicalMapping<2>(overflowShorthand());
}

LogicalMapping<2>
CSSDirectionAwareResolver::LogicalOverscrollBehaviorMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyOverscrollBehaviorBlock(),
      &GetCSSPropertyOverscrollBehaviorInline()};
  return LogicalMapping<2>(kProperties);
}

PhysicalMapping<2>
CSSDirectionAwareResolver::PhysicalOverscrollBehaviorMapping() {
  return PhysicalMapping<2>(overscrollBehaviorShorthand());
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalPaddingMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyPaddingBlockStart(), &GetCSSPropertyPaddingBlockEnd(),
      &GetCSSPropertyPaddingInlineStart(), &GetCSSPropertyPaddingInlineEnd()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalPaddingMapping() {
  return PhysicalMapping<4>(paddingShorthand());
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalScrollMarginMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyScrollMarginBlockStart(),
      &GetCSSPropertyScrollMarginBlockEnd(),
      &GetCSSPropertyScrollMarginInlineStart(),
      &GetCSSPropertyScrollMarginInlineEnd()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalScrollMarginMapping() {
  return PhysicalMapping<4>(scrollMarginShorthand());
}

LogicalMapping<4> CSSDirectionAwareResolver::LogicalScrollPaddingMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyScrollPaddingBlockStart(),
      &GetCSSPropertyScrollPaddingBlockEnd(),
      &GetCSSPropertyScrollPaddingInlineStart(),
      &GetCSSPropertyScrollPaddingInlineEnd()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4> CSSDirectionAwareResolver::PhysicalScrollPaddingMapping() {
  return PhysicalMapping<4>(scrollPaddingShorthand());
}

LogicalMapping<2> CSSDirectionAwareResolver::LogicalScrollStartMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyScrollStartBlock(), &GetCSSPropertyScrollStartInline()};
  return LogicalMapping<2>(kProperties);
}

PhysicalMapping<2> CSSDirectionAwareResolver::PhysicalScrollStartMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyScrollStartX(),
                                             &GetCSSPropertyScrollStartY()};
  return PhysicalMapping<2>(kProperties);
}

LogicalMapping<2> CSSDirectionAwareResolver::LogicalSizeMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyBlockSize(),
                                             &GetCSSPropertyInlineSize()};
  return LogicalMapping<2>(kProperties);
}

PhysicalMapping<2> CSSDirectionAwareResolver::PhysicalSizeMapping() {
  static const CSSProperty* kProperties[] = {&GetCSSPropertyWidth(),
                                             &GetCSSPropertyHeight()};
  return PhysicalMapping<2>(kProperties);
}

LogicalMapping<4>
CSSDirectionAwareResolver::LogicalVisitedBorderColorMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyInternalVisitedBorderBlockStartColor(),
      &GetCSSPropertyInternalVisitedBorderBlockEndColor(),
      &GetCSSPropertyInternalVisitedBorderInlineStartColor(),
      &GetCSSPropertyInternalVisitedBorderInlineEndColor()};
  return LogicalMapping<4>(kProperties);
}

PhysicalMapping<4>
CSSDirectionAwareResolver::PhysicalVisitedBorderColorMapping() {
  static const CSSProperty* kProperties[] = {
      &GetCSSPropertyInternalVisitedBorderTopColor(),
      &GetCSSPropertyInternalVisitedBorderRightColor(),
      &GetCSSPropertyInternalVisitedBorderBottomColor(),
      &GetCSSPropertyInternalVisitedBorderLeftColor()};
  return PhysicalMapping<4>(kProperties);
}

const CSSProperty& CSSDirectionAwareResolver::ResolveInlineStart(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  return group.GetProperty(
      static_cast<size_t>(writing_direction.InlineStart()));
}

const CSSProperty& CSSDirectionAwareResolver::ResolveInlineEnd(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  return group.GetProperty(static_cast<size_t>(writing_direction.InlineEnd()));
}

const CSSProperty& CSSDirectionAwareResolver::ResolveBlockStart(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  return group.GetProperty(static_cast<size_t>(writing_direction.BlockStart()));
}

const CSSProperty& CSSDirectionAwareResolver::ResolveBlockEnd(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  return group.GetProperty(static_cast<size_t>(writing_direction.BlockEnd()));
}

const CSSProperty& CSSDirectionAwareResolver::ResolveInline(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<2>& group) {
  if (writing_direction.IsHorizontal()) {
    return group.GetProperty(kPhysicalAxisX);
  }
  return group.GetProperty(kPhysicalAxisY);
}

const CSSProperty& CSSDirectionAwareResolver::ResolveBlock(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<2>& group) {
  if (writing_direction.IsHorizontal()) {
    return group.GetProperty(kPhysicalAxisY);
  }
  return group.GetProperty(kPhysicalAxisX);
}

const CSSProperty& CSSDirectionAwareResolver::ResolveStartStart(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  WritingMode writing_mode = writing_direction.GetWritingMode();
  if (writing_direction.IsLtr()) {
    return group.GetProperty(kStartStartMap[static_cast<int>(writing_mode)]);
  }
  return group.GetProperty(kStartEndMap[static_cast<int>(writing_mode)]);
}

const CSSProperty& CSSDirectionAwareResolver::ResolveStartEnd(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  WritingMode writing_mode = writing_direction.GetWritingMode();
  if (writing_direction.IsLtr()) {
    return group.GetProperty(kStartEndMap[static_cast<int>(writing_mode)]);
  }
  return group.GetProperty(kStartStartMap[static_cast<int>(writing_mode)]);
}

const CSSProperty& CSSDirectionAwareResolver::ResolveEndStart(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  WritingMode writing_mode = writing_direction.GetWritingMode();
  if (writing_direction.IsLtr()) {
    return group.GetProperty(kEndStartMap[static_cast<int>(writing_mode)]);
  }
  return group.GetProperty(kEndEndMap[static_cast<int>(writing_mode)]);
}

const CSSProperty& CSSDirectionAwareResolver::ResolveEndEnd(
    WritingDirectionMode writing_direction,
    const PhysicalMapping<4>& group) {
  WritingMode writing_mode = writing_direction.GetWritingMode();
  if (writing_direction.IsLtr()) {
    return group.GetProperty(kEndEndMap[static_cast<int>(writing_mode)]);
  }
  return group.GetProperty(kEndStartMap[static_cast<int>(writing_mode)]);
}

}  // namespace blink

"""

```