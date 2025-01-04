Response:
Let's break down the thought process for analyzing the `list_marker.cc` file.

1. **Understand the Goal:** The request is to analyze the functionality of the `ListMarker` class in Chromium's Blink rendering engine, specifically within the context of list markers. The analysis should include its relationship to web technologies (JavaScript, HTML, CSS), provide examples of logical reasoning (input/output), and point out common usage errors.

2. **Initial Reading and Identification of Key Concepts:**  First, I'd read through the code to get a general understanding. I'd look for keywords and recognizable patterns. Immediately, terms like "list marker," "LayoutObject," "ComputedStyle," "CounterStyle," "list-style-type," and "list-style-image" stand out. This suggests the file is responsible for how list markers are rendered and managed.

3. **Deconstructing the Class Structure:** I'd examine the class definition (`class ListMarker`). I'd note the private member `marker_text_type_`, which seems to track the state of the marker's text content. I'd also observe the static helper functions like `Get(const LayoutObject*)` and `MarkerFromListItem(const LayoutObject*)`, which are likely used to access `ListMarker` instances associated with different layout objects.

4. **Analyzing Key Methods and their Purpose:**  I would then go through each method, trying to understand its specific role:

    * **Constructors/Destructors:** (Implicit default constructor)  No explicit destructor, but the `DestroyLayoutObject` function is important.
    * **`Get()` methods:**  These are clearly for retrieving the `ListMarker` associated with a layout object (either the marker itself or the list item). This hints at a relationship between list items and their markers.
    * **`MarkerFromListItem()` and `ListItem()`:**  These solidify the connection between list items and their markers.
    * **`ListItemValue()`:**  This retrieves the current value of a list item (important for ordered lists).
    * **`ListStyleTypeChanged()`, `CounterStyleChanged()`, `OrdinalValueChanged()`:** These functions handle updates when the styling of the list marker changes, triggering a re-layout. The `marker_text_type_ = kUnresolved;` is a clear indication of needing a refresh.
    * **`GetContentChild()` and `GetTextChild()`:** These are used to access the underlying layout object that represents the marker's content (either text or an image).
    * **`UpdateMarkerText()`:** This method is crucial. It's responsible for generating the actual marker text based on the current style and list item value. The `MarkerText()` method it calls is the core logic.
    * **`MarkerText()`:** This is the heart of the text generation. It uses the `ComputedStyle` and `CounterStyle` to determine what to display (numbers, bullets, custom symbols). The `ListStyleCategory` enum helps categorize the type of marker.
    * **`MarkerTextWithSuffix()`, `MarkerTextWithoutSuffix()`, `TextAlternative()`:** These are variations of getting the marker text, likely for different purposes like accessibility.
    * **`UpdateMarkerContentIfNeeded()`:** This handles the creation or updating of the actual layout object for the marker (either a `LayoutTextFragment` for text or a `LayoutListMarkerImage` for an image).
    * **`SymbolMarkerLayoutText()` and `IsMarkerImage()`:** These are helper methods to check the type of marker.
    * **`WidthOfSymbol()`:** Calculates the default width for certain symbol-based markers.
    * **`InlineMarginsForInside()` and `InlineMarginsForOutside()`:** These methods calculate the margins needed for the marker depending on whether it's inside or outside the list item.
    * **`RelativeSymbolMarkerRect()`:**  Calculates the positioning of symbol markers.
    * **`GetCounterStyle()` and `GetListStyleCategory()`:** Helper functions to retrieve the relevant style information.

5. **Identifying Relationships with Web Technologies:**

    * **CSS:** The code heavily relies on `ComputedStyle`, `CounterStyle`, and properties like `list-style-type`, `list-style-image`, and `content`. The constants like `kCMarkerPaddingPx` and `kCUAMarkerMarginEm` also point to default styling. The mention of `::-webkit-details-marker` and the TODO about moving to `html.css` further reinforces the connection to CSS.
    * **HTML:** The code interacts with `LayoutListItem` and `LayoutInlineListItem`, representing the `<li>` elements in HTML. The concept of list item "value" directly corresponds to the `value` attribute of `<li>`.
    * **JavaScript:** While the C++ code itself doesn't directly interact with JavaScript *execution*, the styles and layout it manages are often manipulated via JavaScript. For example, changing the `list-style-type` using JavaScript would trigger the `ListStyleTypeChanged()` method. Accessibility (AXObjectCache) is also important for how assistive technologies interact with the rendered content, which JavaScript can influence.

6. **Inferring Logical Reasoning and Input/Output:** For methods like `MarkerText()`, it's possible to reason about the output given certain inputs:

    * **Input:** `list-style-type: decimal;` and a list item with `value="3"`.
    * **Output:** The `MarkerText()` method would generate "3." (or potentially with prefixes/suffixes depending on the `CounterStyle`).
    * **Input:** `list-style-image: url('image.png');`.
    * **Output:**  `MarkerText()` would likely return an empty string, and `UpdateMarkerContentIfNeeded()` would create a `LayoutListMarkerImage`.

7. **Identifying Potential Usage Errors:**  Based on the code, potential errors include:

    * **CSS errors:** Incorrectly specifying `list-style-type` or `content` values.
    * **JavaScript errors:** Manipulating list item values in a way that leads to unexpected marker updates.
    * **Accessibility issues:** Although the code handles accessibility to some extent, developers could still create semantically incorrect lists, leading to accessibility problems. The comment about manual removal of AXObjects highlights a potential area for errors if not handled correctly.

8. **Structuring the Analysis:** Finally, I would organize the findings into the requested categories: functionality, relationship to web technologies, logical reasoning, and common errors, providing specific examples for each. The use of code snippets and clear explanations would be essential.

**(Self-Correction during the process):** Initially, I might focus too much on the low-level layout details. I'd need to remind myself to also address the higher-level connections to HTML, CSS, and JavaScript, as requested by the prompt. Also, understanding the subtle differences between the `Get()` methods and when to use them is crucial for a correct analysis. Recognizing the state management done by `marker_text_type_` is also important.
好的，让我们详细分析一下 `blink/renderer/core/layout/list/list_marker.cc` 这个文件。

**文件功能概述：**

`list_marker.cc` 文件定义了 `ListMarker` 类及其相关功能，这个类的主要职责是**负责管理和渲染 HTML 列表项（`<li>`）的标记（marker）**。  这些标记可以是数字、项目符号、自定义符号或者图像，具体取决于 CSS 属性 `list-style-type` 和 `list-style-image` 的设置。

**核心功能点：**

1. **标记内容的生成和更新：**
   - 根据 `list-style-type` 的值（例如 `decimal`, `disc`, `square`, 自定义的 `@counter-style` 等）生成相应的文本或符号作为标记内容。
   - 当 `list-style-type` 或关联的 `@counter-style` 发生变化时，负责更新标记的文本内容。
   - 当列表项的 `value` 属性（用于有序列表）发生变化时，更新标记的数字。

2. **标记内容的布局和渲染：**
   - 创建和管理用于渲染标记内容的 `LayoutObject`，例如 `LayoutTextFragment` (用于文本标记) 或 `LayoutListMarkerImage` (用于图像标记)。
   - 计算标记所需的内边距（padding）和外边距（margin），以便在列表项中正确放置标记。
   - 考虑标记是显示在列表项内部 (`list-style-position: inside`) 还是外部 (`list-style-position: outside`)，并进行相应的布局调整。

3. **与 CSS 属性的关联：**
   - 读取和解析与列表标记相关的 CSS 属性，如 `list-style-type`, `list-style-image`, `list-style-position`, 以及 `@counter-style` 规则。
   - 根据这些 CSS 属性的值来决定标记的类型、内容和样式。

4. **辅助功能（Accessibility）：**
   - 为列表标记生成可访问性信息，例如文本替代（alternative text），以便屏幕阅读器等辅助技术能够理解和传达列表的结构和标记信息。

5. **内部实现细节：**
   - 管理标记的内部状态，例如 `marker_text_type_` 用于跟踪标记文本的类型和是否需要更新。
   - 提供辅助方法来获取与标记关联的列表项、样式信息等。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**
    - `ListMarker` 直接关联到 HTML 的 `<li>` 元素。它负责渲染这些列表项的标记。
    - **例子:** 当浏览器解析到以下 HTML 代码时，`ListMarker` 类会参与渲染项目符号：
      ```html
      <ul>
        <li>Item 1</li>
        <li>Item 2</li>
      </ul>
      ```
      或者渲染数字编号：
      ```html
      <ol>
        <li>Item A</li>
        <li>Item B</li>
      </ol>
      ```
      以及带 `value` 属性的有序列表：
      ```html
      <ol start="5">
        <li value="7">Item X</li>
        <li>Item Y</li>
      </ol>
      ```

* **CSS:**
    - `ListMarker` 类的行为受到多个 CSS 属性的控制：
        - **`list-style-type`:** 决定标记的类型 (例如 `disc`, `circle`, `square`, `decimal`, `lower-roman`, 自定义的 `@counter-style` 名称等)。
          - **例子:**
            ```css
            ul {
              list-style-type: square; /* 使用方块作为项目符号 */
            }
            ol {
              list-style-type: lower-alpha; /* 使用小写字母编号 */
            }
            ```
        - **`list-style-image`:** 允许使用图像作为标记。
          - **例子:**
            ```css
            ul {
              list-style-image: url("bullet.png");
            }
            ```
        - **`list-style-position`:** 决定标记是显示在列表项内部还是外部。
          - **例子:**
            ```css
            li {
              list-style-position: inside; /* 标记显示在列表项文本的内部 */
            }
            ```
        - **`@counter-style`:** 允许定义自定义的计数器样式，`ListMarker` 会解析并使用这些自定义样式来生成标记。
          - **例子:**
            ```css
            @counter-style thumbs {
              system: cyclic;
              symbols: "👍" "👎";
              suffix: " ";
            }
            ol {
              list-style-type: thumbs; /* 使用自定义的 thumbs 计数器样式 */
            }
            ```
        - **`content` (在 `::marker` 伪元素上):**  虽然注释中提到未来可能会支持 `::marker` 伪元素，但目前代码中处理 `content` 属性的方式表明，自定义标记内容可能已经或即将支持。

* **JavaScript:**
    - JavaScript 可以动态地修改与列表标记相关的 CSS 属性，从而间接地影响 `ListMarker` 的行为。
    - JavaScript 可以操作 HTML 结构，添加或删除列表项，`ListMarker` 会相应地创建或销毁标记。
    - JavaScript 可以通过设置 `<li>` 元素的 `value` 属性来改变有序列表的编号，这会触发 `ListMarker` 更新标记。
    - **例子:**
      ```javascript
      // 获取第一个有序列表
      const ol = document.querySelector('ol');
      // 修改其 list-style-type
      ol.style.listStyleType = 'upper-roman';

      // 获取第三个列表项并设置其 value
      const listItem = ol.querySelectorAll('li')[2];
      listItem.setAttribute('value', '10');
      ```
      这些 JavaScript 代码的执行会导致 `ListMarker` 重新生成和渲染列表标记。

**逻辑推理和假设输入与输出：**

假设我们有以下 HTML 和 CSS：

```html
<ol id="myList" style="list-style-type: lower-greek;">
  <li value="1">Alpha</li>
  <li>Beta</li>
  <li value="5">Gamma</li>
</ol>
```

**假设输入：**  浏览器开始渲染 `#myList` 这个有序列表。

**`ListMarker` 的逻辑推理和输出：**

1. **读取样式：** `ListMarker` 会读取 `<ol>` 元素的 `list-style-type: lower-greek;` 样式，以及 `<li>` 元素的 `value` 属性（如果存在）。

2. **处理第一个 `<li>`：**
   - `value` 属性为 "1"。
   - `list-style-type` 为 `lower-greek`。
   - `MarkerText()` 方法会根据 `lower-greek` 规则将值 "1" 转换为希腊小写字母 "α"。
   - **输出：** 标记为 "α."

3. **处理第二个 `<li>`：**
   - 没有 `value` 属性，默认为上一个列表项的值加 1，即 1 + 1 = 2。
   - `list-style-type` 为 `lower-greek`。
   - `MarkerText()` 方法会根据 `lower-greek` 规则将值 "2" 转换为希腊小写字母 "β"。
   - **输出：** 标记为 "β."

4. **处理第三个 `<li>`：**
   - `value` 属性为 "5"。
   - `list-style-type` 为 `lower-greek`。
   - `MarkerText()` 方法会根据 `lower-greek` 规则将值 "5" 转换为希腊小写字母 "ε"。
   - **输出：** 标记为 "ε."

**最终渲染结果：**

```
α. Alpha
β. Beta
ε. Gamma
```

**涉及用户或编程常见的使用错误：**

1. **CSS 属性值错误：**
   - 用户可能会输入无效的 `list-style-type` 值，例如拼写错误或者不存在的关键字。 这会导致浏览器使用默认的标记样式。
   - **例子:** `list-style-type: mispelled-type;`

2. **`@counter-style` 定义错误：**
   - 自定义 `@counter-style` 规则可能存在语法错误或逻辑错误，导致标记无法正确生成。
   - **例子:** `@counter-style my-style { system: invalid-system; symbols: ...; }`

3. **`value` 属性使用不当：**
   - 在有序列表中，错误地使用 `value` 属性可能导致编号不连续或出现意外的编号。
   - **例子:**
     ```html
     <ol>
       <li>Item 1</li>
       <li value="abc">Item 2</li>  <!-- value 应该是数字 -->
       <li>Item 3</li>
     </ol>
     ```
   - 在无序列表中设置 `value` 属性是没有意义的，会被浏览器忽略。

4. **与 `::marker` 伪元素混淆：**
   - 虽然该文件可能在未来支持 `::marker`，但目前直接操作 `::marker` 的样式可能不会产生预期的效果，或者行为与预期不符。 用户可能会尝试使用 `content` 属性在 `::marker` 上设置自定义内容，但如果引擎尚未完全支持，可能会出现问题。

5. **JavaScript 动态修改导致意外行为：**
   - 过度或不小心地使用 JavaScript 动态修改与列表标记相关的样式或属性，可能导致性能问题或者视觉上的不一致。

6. **辅助功能考虑不足：**
   - 虽然 `ListMarker` 提供了生成辅助文本的功能，但如果开发者完全依赖视觉样式而不考虑语义化的 HTML 结构，仍然可能导致辅助技术无法正确理解列表内容。

总而言之，`blink/renderer/core/layout/list/list_marker.cc` 文件是 Chromium Blink 引擎中负责列表标记渲染的核心组件。它深入参与了 HTML 结构的解析、CSS 样式的应用以及最终的页面布局和渲染过程。理解其功能有助于开发者更好地掌握 HTML 列表的渲染机制，并避免常见的错误。

Prompt: 
```
这是目录为blink/renderer/core/layout/list/list_marker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/list/list_marker.h"

#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/counter_style.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/layout/geometry/logical_rect.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/layout_image_resource_style_image.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/layout_text_fragment.h"
#include "third_party/blink/renderer/core/layout/list/layout_inline_list_item.h"
#include "third_party/blink/renderer/core/layout/list/layout_inside_list_marker.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_item.h"
#include "third_party/blink/renderer/core/layout/list/layout_list_marker_image.h"
#include "third_party/blink/renderer/core/layout/list/layout_outside_list_marker.h"
#include "third_party/blink/renderer/core/style/list_style_type_data.h"

namespace blink {

const int kCMarkerPaddingPx = 7;

// TODO(glebl): Move to core/html/resources/html.css after
// Blink starts to support ::marker crbug.com/457718
// Recommended UA margin for list markers.
const int kCUAMarkerMarginEm = 1;

// 'closure-*' have 0.4em margin for compatibility with
// ::-webkit-details-marker.
const float kClosureMarkerMarginEm = 0.4f;

namespace {

LayoutUnit DisclosureSymbolSize(const ComputedStyle& style) {
  return LayoutUnit(style.SpecifiedFontSize() * style.EffectiveZoom() * 0.66);
}

void DestroyLayoutObject(LayoutObject* layout_object) {
  // AXObjects are normally removed from destroyed layout objects in
  // Node::DetachLayoutTree(), but as the list marker implementation manually
  // destroys the layout objects, it must manually remove the accessibility
  // objects for them as well.
  if (auto* cache = layout_object->GetDocument().ExistingAXObjectCache()) {
    cache->RemoveAXObjectsInLayoutSubtree(layout_object);
  }
  layout_object->Destroy();
}

}  // namespace

ListMarker::ListMarker() : marker_text_type_(kNotText) {}

const ListMarker* ListMarker::Get(const LayoutObject* marker) {
  if (auto* ng_outside_marker = DynamicTo<LayoutOutsideListMarker>(marker)) {
    return &ng_outside_marker->Marker();
  }
  if (auto* ng_inside_marker = DynamicTo<LayoutInsideListMarker>(marker)) {
    return &ng_inside_marker->Marker();
  }
  return nullptr;
}

ListMarker* ListMarker::Get(LayoutObject* marker) {
  return const_cast<ListMarker*>(
      ListMarker::Get(static_cast<const LayoutObject*>(marker)));
}

LayoutObject* ListMarker::MarkerFromListItem(const LayoutObject* list_item) {
  if (auto* ng_list_item = DynamicTo<LayoutListItem>(list_item)) {
    return ng_list_item->Marker();
  }
  if (auto* inline_list_item = DynamicTo<LayoutInlineListItem>(list_item)) {
    return inline_list_item->Marker();
  }
  return nullptr;
}

LayoutObject* ListMarker::ListItem(const LayoutObject& marker) const {
  DCHECK_EQ(Get(&marker), this);
  LayoutObject* list_item = marker.GetNode()->parentNode()->GetLayoutObject();
  DCHECK(list_item);
  DCHECK(list_item->IsListItem());
  return list_item;
}

int ListMarker::ListItemValue(const LayoutObject& list_item) const {
  if (auto* ng_list_item = DynamicTo<LayoutListItem>(list_item)) {
    return ng_list_item->Value();
  }
  if (auto* inline_list_item = DynamicTo<LayoutInlineListItem>(list_item)) {
    return inline_list_item->Value();
  }
  NOTREACHED();
}

// If the value of ListStyleType changed, we need to update the marker text.
void ListMarker::ListStyleTypeChanged(LayoutObject& marker) {
  DCHECK_EQ(Get(&marker), this);
  if (marker_text_type_ == kNotText || marker_text_type_ == kUnresolved)
    return;

  marker_text_type_ = kUnresolved;
  marker.SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
      layout_invalidation_reason::kListStyleTypeChange);
}

// If the @counter-style in use has changed, we need to update the marker text.
void ListMarker::CounterStyleChanged(LayoutObject& marker) {
  DCHECK_EQ(Get(&marker), this);
  if (marker_text_type_ == kNotText || marker_text_type_ == kUnresolved)
    return;

  marker_text_type_ = kUnresolved;
  marker.SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
      layout_invalidation_reason::kCounterStyleChange);
}

void ListMarker::OrdinalValueChanged(LayoutObject& marker) {
  DCHECK_EQ(Get(&marker), this);
  if (marker_text_type_ == kOrdinalValue) {
    marker_text_type_ = kUnresolved;
    marker.SetNeedsLayoutAndIntrinsicWidthsRecalcAndFullPaintInvalidation(
        layout_invalidation_reason::kListValueChange);
  }
}

LayoutObject* ListMarker::GetContentChild(const LayoutObject& marker) const {
  DCHECK_EQ(Get(&marker), this);
  LayoutObject* const first_child = marker.SlowFirstChild();
  if (IsA<LayoutTextCombine>(first_child)) {
    return first_child->SlowFirstChild();
  }
  return first_child;
}

LayoutTextFragment& ListMarker::GetTextChild(const LayoutObject& marker) const {
  auto& text = *To<LayoutTextFragment>(GetContentChild(marker));
  // There should be a single text child
  DCHECK(!text.NextSibling());
  return text;
}

void ListMarker::UpdateMarkerText(LayoutObject& marker) {
  DCHECK_EQ(Get(&marker), this);
  auto& text = GetTextChild(marker);
  DCHECK_EQ(marker_text_type_, kUnresolved);
  StringBuilder marker_text_builder;
  marker_text_type_ =
      MarkerText(marker, &marker_text_builder, kWithPrefixSuffix);
  text.SetContentString(marker_text_builder.ToString());
  DCHECK_NE(marker_text_type_, kNotText);
  DCHECK_NE(marker_text_type_, kUnresolved);
}

ListMarker::MarkerTextType ListMarker::MarkerText(
    const LayoutObject& marker,
    StringBuilder* text,
    MarkerTextFormat format) const {
  DCHECK_EQ(Get(&marker), this);
  if (!marker.StyleRef().ContentBehavesAsNormal())
    return kNotText;
  if (IsMarkerImage(marker)) {
    if (format == kWithPrefixSuffix)
      text->Append(' ');
    return kNotText;
  }

  LayoutObject* list_item = ListItem(marker);
  const ComputedStyle& style = list_item->StyleRef();
  switch (GetListStyleCategory(marker.GetDocument(), style)) {
    case ListStyleCategory::kNone:
      return kNotText;
    case ListStyleCategory::kStaticString:
      text->Append(style.ListStyleStringValue());
      return kStatic;
    case ListStyleCategory::kSymbol: {
      const CounterStyle& counter_style =
          GetCounterStyle(marker.GetDocument(), style);
      switch (format) {
        case kWithPrefixSuffix:
          text->Append(
              counter_style.GenerateRepresentationWithPrefixAndSuffix(0));
          break;
        case kWithoutPrefixSuffix:
          text->Append(counter_style.GenerateRepresentation(0));
          break;
        case kAlternativeText:
          text->Append(counter_style.GenerateTextAlternative(0));
      }
      return kSymbolValue;
    }
    case ListStyleCategory::kLanguage: {
      int value = ListItemValue(*list_item);
      const CounterStyle& counter_style =
          GetCounterStyle(marker.GetDocument(), style);
      switch (format) {
        case kWithPrefixSuffix:
          text->Append(
              counter_style.GenerateRepresentationWithPrefixAndSuffix(value));
          break;
        case kWithoutPrefixSuffix:
          text->Append(counter_style.GenerateRepresentation(value));
          break;
        case kAlternativeText:
          text->Append(counter_style.GenerateTextAlternative(value));
      }
      return kOrdinalValue;
    }
  }
  NOTREACHED();
}

String ListMarker::MarkerTextWithSuffix(const LayoutObject& marker) const {
  DCHECK_EQ(Get(&marker), this);
  StringBuilder text;
  MarkerText(marker, &text, kWithPrefixSuffix);
  return text.ToString();
}

String ListMarker::MarkerTextWithoutSuffix(const LayoutObject& marker) const {
  DCHECK_EQ(Get(&marker), this);
  StringBuilder text;
  MarkerText(marker, &text, kWithoutPrefixSuffix);
  return text.ToString();
}

String ListMarker::TextAlternative(const LayoutObject& marker) const {
  DCHECK_EQ(Get(&marker), this);
  DCHECK_NE(marker_text_type_, kUnresolved);
  // For accessibility, return the marker string in the logical order even in
  // RTL, reflecting speech order.
  if (marker_text_type_ == kNotText) {
    String text = MarkerTextWithSuffix(marker);
    if (!text.empty()) {
      return text;
    }

    // Pseudo element list markers may return empty text as their text
    // alternative, so obtain the text from its child as a fallback mechanism.
    auto* text_child = GetContentChild(marker);
    if (text_child && !text_child->NextSibling() &&
        IsA<LayoutTextFragment>(text_child)) {
      return GetTextChild(marker).PlainText();
    }

    // The fallback is not present, so return the original empty text.
    return text;
  }

  if (RuntimeEnabledFeatures::CSSAtRuleCounterStyleSpeakAsDescriptorEnabled()) {
    StringBuilder text;
    MarkerText(marker, &text, kAlternativeText);
    return text.ToString();
  }

  if (marker_text_type_ == kUnresolved) {
    return MarkerTextWithSuffix(marker);
  }

  return GetTextChild(marker).PlainText();
}

void ListMarker::UpdateMarkerContentIfNeeded(LayoutObject& marker) {
  DCHECK_EQ(Get(&marker), this);
  if (!marker.StyleRef().ContentBehavesAsNormal()) {
    marker_text_type_ = kNotText;
    return;
  }

  // There should be at most one child.
  LayoutObject* child = GetContentChild(marker);

  const ComputedStyle& style = ListItem(marker)->StyleRef();
  if (IsMarkerImage(marker)) {
    StyleImage* list_style_image = style.ListStyleImage();
    if (child) {
      // If the url of `list-style-image` changed, create a new LayoutImage.
      if (!child->IsLayoutImage() ||
          To<LayoutImage>(child)->ImageResource()->ImagePtr() !=
              list_style_image->Data()) {
        if (IsA<LayoutTextCombine>(child->Parent())) [[unlikely]] {
          DestroyLayoutObject(child->Parent());
        } else {
          DestroyLayoutObject(child);
        }
        child = nullptr;
      }
    }
    if (!child) {
      LayoutListMarkerImage* image =
          LayoutListMarkerImage::CreateAnonymous(&marker.GetDocument());
      const ComputedStyle* image_style =
          marker.GetDocument()
              .GetStyleResolver()
              .CreateAnonymousStyleWithDisplay(marker.StyleRef(),
                                               EDisplay::kInline);
      image->SetStyle(image_style);
      image->SetImageResource(
          MakeGarbageCollected<LayoutImageResourceStyleImage>(
              list_style_image));
      image->SetIsGeneratedContent();
      marker.AddChild(image);
    }
    marker_text_type_ = kNotText;
    return;
  }

  if (!style.ListStyleType()) {
    marker_text_type_ = kNotText;
    return;
  }

  // |text_style| should be as same as style propagated in
  // |LayoutObject::PropagateStyleToAnonymousChildren()| to avoid unexpected
  // full layout due by style difference. See http://crbug.com/980399
  const auto& style_parent = child ? *child->Parent() : marker;
  const ComputedStyle* text_style =
      marker.GetDocument().GetStyleResolver().CreateAnonymousStyleWithDisplay(
          style_parent.StyleRef(), marker.StyleRef().Display());
  if (IsA<LayoutTextFragment>(child))
    return child->SetStyle(text_style);
  if (child) {
    DestroyLayoutObject(child);
  }

  auto* const new_text = LayoutTextFragment::CreateAnonymous(
      marker.GetDocument(), StringImpl::empty_, 0, 0);
  new_text->SetStyle(std::move(text_style));
  marker.AddChild(new_text);
  marker_text_type_ = kUnresolved;
}

LayoutObject* ListMarker::SymbolMarkerLayoutText(
    const LayoutObject& marker) const {
  DCHECK_EQ(Get(&marker), this);
  if (marker_text_type_ != kSymbolValue)
    return nullptr;
  return GetContentChild(marker);
}

bool ListMarker::IsMarkerImage(const LayoutObject& marker) const {
  DCHECK_EQ(Get(&marker), this);
  return marker.StyleRef().ContentBehavesAsNormal() &&
         ListItem(marker)->StyleRef().GeneratesMarkerImage();
}

LayoutUnit ListMarker::WidthOfSymbol(const ComputedStyle& style,
                                     const AtomicString& list_style) {
  const Font& font = style.GetFont();
  const SimpleFontData* font_data = font.PrimaryFont();
  DCHECK(font_data);
  if (!font_data)
    return LayoutUnit();
  if (style.SpecifiedFontSize() == 0) [[unlikely]] {
    // See http://crbug.com/1228157
    return LayoutUnit();
  }
  if (list_style == keywords::kDisclosureOpen ||
      list_style == keywords::kDisclosureClosed) {
    return DisclosureSymbolSize(style);
  }
  return LayoutUnit((font_data->GetFontMetrics().Ascent() * 2 / 3 + 1) / 2 + 2);
}

std::pair<LayoutUnit, LayoutUnit> ListMarker::InlineMarginsForInside(
    Document& document,
    const ComputedStyleBuilder& marker_style_builder,
    const ComputedStyle& list_item_style) {
  if (!marker_style_builder.GetDisplayStyle().ContentBehavesAsNormal()) {
    return {};
  }
  if (list_item_style.GeneratesMarkerImage())
    return {LayoutUnit(), LayoutUnit(kCMarkerPaddingPx)};
  switch (GetListStyleCategory(document, list_item_style)) {
    case ListStyleCategory::kSymbol: {
      const AtomicString& name =
          list_item_style.ListStyleType()->GetCounterStyleName();
      if (name == keywords::kDisclosureOpen ||
          name == keywords::kDisclosureClosed) {
        return {LayoutUnit(),
                LayoutUnit(
                    kClosureMarkerMarginEm *
                    marker_style_builder.GetFontDescription().SpecifiedSize())};
      }
      return {
          LayoutUnit(-1),
          LayoutUnit(kCUAMarkerMarginEm *
                     marker_style_builder.GetFontDescription().ComputedSize())};
    }
    default:
      break;
  }
  return {};
}

std::pair<LayoutUnit, LayoutUnit> ListMarker::InlineMarginsForOutside(
    Document& document,
    const ComputedStyle& marker_style,
    const ComputedStyle& list_item_style,
    LayoutUnit marker_inline_size) {
  LayoutUnit margin_start;
  LayoutUnit margin_end;
  if (!marker_style.ContentBehavesAsNormal()) {
    margin_start = -marker_inline_size;
  } else if (list_item_style.GeneratesMarkerImage()) {
    margin_start = -marker_inline_size - kCMarkerPaddingPx;
    margin_end = LayoutUnit(kCMarkerPaddingPx);
  } else {
    switch (GetListStyleCategory(document, list_item_style)) {
      case ListStyleCategory::kNone:
        break;
      case ListStyleCategory::kSymbol: {
        const SimpleFontData* font_data = marker_style.GetFont().PrimaryFont();
        DCHECK(font_data);
        if (!font_data)
          return {};
        const FontMetrics& font_metrics = font_data->GetFontMetrics();
        const AtomicString& name =
            list_item_style.ListStyleType()->GetCounterStyleName();
        LayoutUnit offset = (name == keywords::kDisclosureOpen ||
                             name == keywords::kDisclosureClosed)
                                ? DisclosureSymbolSize(marker_style)
                                : LayoutUnit(font_metrics.Ascent() * 2 / 3);
        margin_start = -offset - kCMarkerPaddingPx - 1;
        margin_end = offset + kCMarkerPaddingPx + 1 - marker_inline_size;
        break;
      }
      default:
        margin_start = -marker_inline_size;
    }
  }
  DCHECK_EQ(-margin_start - margin_end, marker_inline_size);
  return {margin_start, margin_end};
}

PhysicalRect ListMarker::RelativeSymbolMarkerRect(
    const ComputedStyle& style,
    const AtomicString& list_style,
    LayoutUnit width) {
  const SimpleFontData* font_data = style.GetFont().PrimaryFont();
  DCHECK(font_data);
  if (!font_data)
    return PhysicalRect();

  LogicalRect relative_rect;
  // TODO(wkorman): Review and clean up/document the calculations below.
  // http://crbug.com/543193
  const FontMetrics& font_metrics = font_data->GetFontMetrics();
  const int ascent = font_metrics.Ascent();
  if (list_style == keywords::kDisclosureOpen ||
      list_style == keywords::kDisclosureClosed) {
    LayoutUnit marker_size = DisclosureSymbolSize(style);
    relative_rect = LogicalRect(LayoutUnit(), ascent - marker_size, marker_size,
                                marker_size);
  } else {
    LayoutUnit bullet_width = LayoutUnit((ascent * 2 / 3 + 1) / 2);
    relative_rect = LogicalRect(LayoutUnit(1),
                                LayoutUnit(3 * (ascent - ascent * 2 / 3) / 2),
                                bullet_width, bullet_width);
  }
  // TextDirection doesn't matter here.  Passing
  // `relative_rect.size.inline_size` to get a correct result in sideways-lr.
  WritingModeConverter converter(
      {ToLineWritingMode(style.GetWritingMode()), TextDirection::kLtr},
      PhysicalSize(width, relative_rect.size.inline_size));
  return converter.ToPhysical(relative_rect);
}

const CounterStyle& ListMarker::GetCounterStyle(Document& document,
                                                const ComputedStyle& style) {
  DCHECK(style.ListStyleType());
  DCHECK(style.ListStyleType()->IsCounterStyle());
  return style.ListStyleType()->GetCounterStyle(document);
}

ListMarker::ListStyleCategory ListMarker::GetListStyleCategory(
    Document& document,
    const ComputedStyle& style) {
  const ListStyleTypeData* list_style = style.ListStyleType();
  if (!list_style)
    return ListStyleCategory::kNone;
  if (list_style->IsString())
    return ListStyleCategory::kStaticString;
  DCHECK(list_style->IsCounterStyle());
  return GetCounterStyle(document, style).IsPredefinedSymbolMarker()
             ? ListStyleCategory::kSymbol
             : ListStyleCategory::kLanguage;
}

}  // namespace blink

"""

```