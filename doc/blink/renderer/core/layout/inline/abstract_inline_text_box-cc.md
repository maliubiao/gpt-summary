Response:
Let's break down the thought process for analyzing the provided C++ code and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `abstract_inline_text_box.cc` within the Chromium Blink rendering engine. The request also asks for connections to web technologies (HTML, CSS, JavaScript), logical reasoning examples, and common usage errors.

**2. Initial Code Scan (High-Level):**

My first pass involves quickly skimming the code to identify key elements:

* **Includes:**  Headers like `<accessibility/ax_object_cache.h>`, `<layout/inline/...>`, `<platform/fonts/...>`, and `<platform/text/...>` strongly suggest this code is related to text layout, rendering, and accessibility.
* **Namespace:**  The code is within the `blink` namespace, specifically under the anonymous namespace and then `blink` again for the main class definition.
* **Class `AbstractInlineTextBox`:** This is the central entity. The name itself suggests an abstraction over the representation of inline text.
* **Methods:**  Names like `GetOrCreate`, `WillDestroy`, `Detach`, `GetTextContent`, `LocalBounds`, `CharacterWidths`, `GetWordBoundaries`, `IsFirst`, `IsLast`, `NextOnLine`, `PreviousOnLine`, `IsLineBreak` provide hints about the class's responsibilities.
* **Helper Class `AbstractInlineTextBoxCache`:**  This immediately suggests an optimization strategy, likely to avoid redundant creation of `AbstractInlineTextBox` objects. The use of a `HeapHashMap` reinforces this idea.
* **`InlineCursor`:** This appears to be a crucial type for navigating and interacting with inline layout structures.
* **`FragmentItem`, `FragmentItems`, `LogicalBoxFragment`:**  These likely represent pieces of the layout tree related to inline content.

**3. Focused Analysis (Method by Method):**

Next, I'd go through the public methods of `AbstractInlineTextBox` and the `AbstractInlineTextBoxCache` in more detail. For each method, I'd ask:

* **What is its purpose?** (Based on the name and code logic)
* **What data does it operate on?** (Class members, parameters)
* **What is its return value?**
* **Are there any side effects?** (e.g., modifying internal state, interacting with other objects)

**Example - Analyzing `GetTextContent()`:**

* **Purpose:** Retrieve the textual content of the inline text box.
* **Data:**  Uses `GetCursor()` to obtain an `InlineCursor`, then accesses text through the `cursor`.
* **Return Value:** A `String`.
* **Side Effects:** None apparent.

**Key Observations During Method Analysis:**

* **Relationship with `InlineCursor`:**  Many methods rely heavily on the `InlineCursor` to locate and access the relevant text fragment.
* **Caching Mechanism:** The `AbstractInlineTextBoxCache` is clearly designed to manage the lifetime of `AbstractInlineTextBox` instances, likely to improve performance by reusing them.
* **Accessibility Integration:**  The inclusion of `<accessibility/ax_object_cache.h>` and methods like `GetWordBoundaries` indicate involvement in making text accessible.
* **Layout Concepts:** Terms like "line," "fragment," and "box" tie this code directly to the layout process.
* **Font Shaping:** The inclusion of `<platform/fonts/shaping/...>` and the `CharacterWidths` method show it's involved in determining the visual representation of characters.

**4. Connecting to Web Technologies:**

With a better understanding of the code's functions, I'd then consider how these relate to HTML, CSS, and JavaScript:

* **HTML:**  The text content manipulated by this class originates from the text nodes within the HTML structure. The layout of these text nodes is what this code manages.
* **CSS:**  CSS properties like `font-family`, `font-size`, `white-space`, and `direction` directly influence how the text is shaped, broken into lines, and rendered. The `AbstractInlineTextBox` needs to be aware of these styles. The first-letter pseudo-class is explicitly mentioned.
* **JavaScript:** While this C++ code isn't directly called by JavaScript, JavaScript can manipulate the DOM (HTML) and CSS, which in turn triggers layout calculations involving `AbstractInlineTextBox`. Accessibility APIs, often accessed via JavaScript, rely on the information provided by this class.

**5. Logical Reasoning Examples:**

To demonstrate logical reasoning, I'd select a method with clear inputs and outputs. `GetTextContent()` is a good candidate:

* **Hypothesis:** If an `AbstractInlineTextBox` represents the text "Hello", then `GetTextContent()` should return "Hello".
* **Input:**  An `AbstractInlineTextBox` object associated with a text node containing "Hello".
* **Output:** The string "Hello".

I'd try to come up with variations and edge cases to further illustrate the logic (e.g., handling of whitespace, generated content).

**6. Common Usage Errors (Conceptual):**

Since this is low-level rendering code, direct "user" errors are unlikely. However, common *programming* errors within the Blink engine that could affect this code might involve:

* **Incorrect `InlineCursor` Management:** If the cursor is not properly initialized or moved, it could lead to accessing incorrect text fragments or causing crashes.
* **Cache Invalidation Issues:** If the `AbstractInlineTextBoxCache` doesn't properly invalidate entries when the underlying layout changes, it could lead to displaying stale or incorrect information.
* **Style Invalidation:**  Failing to update `AbstractInlineTextBox` when relevant CSS styles change would result in rendering inconsistencies.

**7. Structuring the Output:**

Finally, I'd organize the information in a clear and structured way, addressing each part of the original request:

* **Functionality List:**  A bulleted list summarizing the key responsibilities of the class.
* **Relationships to Web Technologies:**  Specific examples showing how the code interacts with HTML, CSS, and JavaScript.
* **Logical Reasoning:**  Clearly stated hypotheses, inputs, and outputs for chosen methods.
* **Common Usage Errors:**  Illustrative examples of potential programming errors.

**Self-Correction/Refinement:**

During the process, I might realize that my initial understanding of a particular method was incomplete or slightly off. For instance, I might initially think `GetWordBoundaries` is solely about accessibility, but then realize it potentially has other internal uses within the rendering engine. I'd then refine my explanation accordingly. I also need to pay attention to details like the handling of soft hyphens or generated content, and ensure my examples are accurate.
好的，让我们来详细分析一下 `blink/renderer/core/layout/inline/abstract_inline_text_box.cc` 这个文件。

**功能列举：**

这个文件定义了 `AbstractInlineTextBox` 类，它是 Blink 渲染引擎中用于表示**内联文本盒子（inline text box）**的抽象基类。  它的主要功能包括：

1. **表示内联文本片段：**  `AbstractInlineTextBox` 对象代表了内联布局中一段连续的文本，这些文本具有相同的样式属性。它可以是 HTML 文本节点的一部分，也可以是由 CSS 生成的内容。
2. **管理文本内容：**  提供方法获取和操作其包含的文本内容，例如 `GetTextContent()` 和 `GetText()`。
3. **确定文本盒子的几何属性：**  提供方法获取文本盒子的边界 (`LocalBounds()`)、长度 (`Len()`) 和方向 (`GetDirection()`)。
4. **处理空格：**  判断文本盒子是否需要尾随空格 (`NeedsTrailingSpace()`)，这在处理 `white-space` 属性时非常重要。
5. **处理字符和单词边界：**  提供方法获取字符宽度 (`CharacterWidths()`) 和单词边界 (`GetWordBoundaries()`)，这对于文本选择、光标定位和辅助功能至关重要。
6. **导航：**  提供方法在同一 `LayoutText` 对象内的下一个或前一个文本盒子 (`NextInlineTextBox()`)，以及在同一行上的下一个或前一个文本盒子 (`NextOnLine()`, `PreviousOnLine()`) 之间进行导航。
7. **与布局对象关联：**  存储与之关联的 `LayoutText` 对象和 `LogicalBoxFragment` 的引用。
8. **支持首字母伪类：**  提供方法获取可能存在的首字母伪元素的 `LayoutText` 对象 (`GetFirstLetterPseudoLayoutText()`)。
9. **与辅助功能集成：**  通过 `AXObjectCache` 与辅助功能树进行交互，提供文本内容和结构信息。
10. **对象生命周期管理：**  使用 `AbstractInlineTextBoxCache` 来管理 `AbstractInlineTextBox` 对象的创建和销毁，以提高性能。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`AbstractInlineTextBox` 在 Blink 渲染引擎中扮演着核心角色，直接关联到 HTML 结构、CSS 样式以及 JavaScript 的交互。

* **HTML:**
    * **功能关系：** `AbstractInlineTextBox` 最终呈现的是 HTML 文本节点的内容。当浏览器解析 HTML 时，文本节点会被创建，并在布局过程中生成相应的 `AbstractInlineTextBox` 对象。
    * **举例说明：**  对于以下 HTML 代码：
      ```html
      <p>This is some <strong>text</strong>.</p>
      ```
      可能会创建多个 `AbstractInlineTextBox` 对象，分别对应 "This is some "， "text" 和 ".". 加粗标签 `<strong>` 可能会导致 "text" 部分的文本盒子具有不同的样式属性。

* **CSS:**
    * **功能关系：** CSS 样式决定了 `AbstractInlineTextBox` 的外观和布局，例如字体、大小、颜色、行高、`white-space` 属性等。这些样式信息会被应用到 `LayoutText` 对象，进而影响到 `AbstractInlineTextBox` 的渲染。
    * **举例说明：**  对于以下 CSS 规则：
      ```css
      p {
        font-size: 16px;
        line-height: 1.5;
      }
      ```
      应用到上述 HTML 的 `<p>` 元素时，其包含的 `AbstractInlineTextBox` 对象会使用 16 像素的字体大小和 1.5 的行高进行渲染。  `white-space: pre-wrap;` 属性会影响 `NeedsTrailingSpace()` 的返回值。

* **JavaScript:**
    * **功能关系：** JavaScript 可以通过 DOM API 操作 HTML 结构和 CSS 样式。当 JavaScript 修改文本内容或样式时，会导致布局的重新计算，进而可能创建、销毁或更新 `AbstractInlineTextBox` 对象。此外，JavaScript 可以通过 Accessibility API (例如 ARIA 属性) 与辅助功能树交互，而 `AbstractInlineTextBox` 提供了辅助功能所需的部分信息。
    * **举例说明：**
      ```javascript
      const p = document.querySelector('p');
      p.textContent = 'New text'; // 修改文本内容
      p.style.color = 'blue';    // 修改样式
      ```
      这些 JavaScript 操作会导致浏览器重新布局，可能创建新的 `AbstractInlineTextBox` 对象来表示 "New text"，并应用蓝色颜色。  辅助功能相关的 JavaScript 代码可能会访问 `AbstractInlineTextBox` 提供的单词边界信息来实现更精细的文本导航。

**逻辑推理 (假设输入与输出):**

假设我们有一个包含以下 HTML 和 CSS 的场景：

**HTML:**

```html
<div id="container">Hello world</div>
```

**CSS:**

```css
#container {
  font-size: 20px;
}
```

**假设输入：**

1. `InlineCursor` 指向 `LayoutText` 对象中 "Hello" 这部分文本的开头。
2. 调用 `AbstractInlineTextBox::GetOrCreate(cursor)` 创建一个 `AbstractInlineTextBox` 对象。

**逻辑推理与输出：**

*   **`GetTextContent()`:**  假设调用新创建的 `AbstractInlineTextBox` 对象的 `GetTextContent()` 方法，输出应该是字符串 `"Hello"`.
*   **`Len()`:**  调用 `Len()` 方法，输出应该是整数 `5`，表示 "Hello" 的长度。
*   **`LocalBounds()`:**  调用 `LocalBounds()` 方法，输出应该是一个 `PhysicalRect` 对象，其值取决于具体的布局计算结果，但会反映 "Hello" 这部分文本在容器中的位置和大小（例如，`x: 0, y: 0, width: 假设为 60px, height: 假设为 25px`）。
*   **`GetWordBoundaries()`:** 调用 `GetWordBoundaries()` 方法，输出应该是一个包含一个 `WordBoundaries` 元素的 `Vector`，该元素的 `start_index` 为 0， `end_index` 为 5， 表示 "Hello" 是一个完整的单词。
*   **`IsFirst()`:** 如果这是 `LayoutText` 对象中的第一个文本盒子，则调用 `IsFirst()` 应该返回 `true`。

**用户或编程常见的使用错误举例说明：**

由于 `AbstractInlineTextBox` 是 Blink 内部使用的类，用户或前端开发者不会直接与其交互。然而，在 Blink 引擎的开发过程中，可能会出现以下编程错误：

1. **`InlineCursor` 使用错误：**  如果传递给 `AbstractInlineTextBox::GetOrCreate()` 的 `InlineCursor` 指向了错误的位置或状态不一致，可能会导致创建错误的文本盒子或程序崩溃。例如，`InlineCursor` 指向了一个非文本的布局对象。
    ```c++
    // 错误示例：cursor 指向一个 block 级别的元素
    InlineCursor cursor(block_layout_object->FirstFragment());
    AbstractInlineTextBox* box = AbstractInlineTextBox::GetOrCreate(cursor); // 可能导致问题
    ```
2. **缓存管理错误：**  `AbstractInlineTextBoxCache` 的逻辑如果出现错误，例如在文本内容或样式发生变化时未能正确地使缓存失效，可能会导致获取到过时的 `AbstractInlineTextBox` 对象，从而渲染出错误的内容。
3. **生命周期管理错误：**  未能正确管理 `AbstractInlineTextBox` 对象的生命周期，例如在对象不再需要时未能及时释放，可能会导致内存泄漏。`WillDestroy` 方法的调用时机至关重要。
4. **假设文本内容不可变：** 在某些计算中假设 `AbstractInlineTextBox` 的文本内容在整个生命周期内保持不变，但实际上文本内容可能因为 DOM 操作而改变。这可能导致缓存失效不及时或计算结果错误。
5. **忽略 `white-space` 属性：** 在处理文本边界或空格时，如果没有充分考虑 CSS 的 `white-space` 属性（例如 `pre`, `nowrap`, `pre-wrap` 等），可能会导致文本渲染或辅助功能信息不正确。例如，在 `white-space: pre;` 的情况下，尾随空格不应被忽略。

总而言之，`AbstractInlineTextBox` 是 Blink 渲染引擎中一个关键的组成部分，负责表示和管理内联文本的各种属性，并与 HTML 结构、CSS 样式以及 JavaScript 交互紧密相关。 理解其功能有助于深入了解浏览器的渲染机制。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/abstract_inline_text_box.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/abstract_inline_text_box.h"

#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_items.h"
#include "third_party/blink/renderer/core/layout/inline/inline_break_token.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/logical_box_fragment.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_buffer.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"

namespace blink {

namespace {

wtf_size_t ItemIndex(const InlineCursor& cursor) {
  return static_cast<wtf_size_t>(cursor.CurrentItem() -
                                 &cursor.Items().front());
}

class AbstractInlineTextBoxCache final {
 public:
  static AbstractInlineTextBox* GetOrCreate(const InlineCursor& cursor) {
    if (!s_instance_)
      s_instance_ = new AbstractInlineTextBoxCache();
    return s_instance_->GetOrCreateInternal(cursor);
  }

  static void WillDestroy(const InlineCursor& cursor) {
    if (!s_instance_)
      return;
    s_instance_->WillDestroyInternal(cursor);
  }

 private:
  AbstractInlineTextBoxCache() : map_(MakeGarbageCollected<MapType>()) {}

  AbstractInlineTextBox* GetOrCreateInternal(const InlineCursor& cursor) {
    DCHECK(cursor.CurrentItem());
    MapKey key = ToMapKey(cursor);
    const auto it = map_->find(key);
    auto* const layout_text =
        To<LayoutText>(cursor.CurrentMutableLayoutObject());
    if (it != map_->end()) {
      CHECK(layout_text->HasAbstractInlineTextBox());
      return it->value.Get();
    }
    auto* obj = MakeGarbageCollected<AbstractInlineTextBox>(cursor);
    map_->Set(key, obj);
    layout_text->SetHasAbstractInlineTextBox();
    return obj;
  }

  void WillDestroyInternal(const InlineCursor& cursor) {
    MapKey key = ToMapKey(cursor);
    const auto it = map_->find(key);
    if (it == map_->end()) {
      return;
    }
    it->value->Detach();
    map_->erase(key);
  }

  // An FragmentItem pointer can't be a key because FragmentItem instances
  // are stored in HeapVector instances, and Oilpan heap compaction changes
  // addresses of FragmentItem instances.
  using MapKey = std::pair<const FragmentItems*, wtf_size_t>;
  MapKey ToMapKey(const InlineCursor& cursor) {
    return MapKey(&cursor.Items(), ItemIndex(cursor));
  }

  static AbstractInlineTextBoxCache* s_instance_;

  using MapType = HeapHashMap<MapKey, Member<AbstractInlineTextBox>>;
  Persistent<MapType> map_;
};

AbstractInlineTextBoxCache* AbstractInlineTextBoxCache::s_instance_ = nullptr;

}  // namespace

AbstractInlineTextBox* AbstractInlineTextBox::GetOrCreate(
    const InlineCursor& cursor) {
  if (!cursor)
    return nullptr;
  return AbstractInlineTextBoxCache::GetOrCreate(cursor);
}

void AbstractInlineTextBox::WillDestroy(const InlineCursor& cursor) {
  if (cursor.CurrentItem()) {
    return AbstractInlineTextBoxCache::WillDestroy(cursor);
  }
  NOTREACHED();
}

AbstractInlineTextBox::AbstractInlineTextBox(const InlineCursor& cursor)
    : fragment_item_index_(ItemIndex(cursor)),
      layout_text_(To<LayoutText>(cursor.Current().GetMutableLayoutObject())),
      root_box_fragment_(&cursor.ContainerFragment()) {
  DCHECK(cursor.CurrentItem()->IsText()) << cursor.CurrentItem();
}

AbstractInlineTextBox::~AbstractInlineTextBox() {
  DCHECK(!fragment_item_index_);
  DCHECK(!root_box_fragment_);
  DCHECK(!layout_text_);
}

void AbstractInlineTextBox::Trace(Visitor* visitor) const {
  visitor->Trace(layout_text_);
  visitor->Trace(root_box_fragment_);
}

void AbstractInlineTextBox::Detach() {
  LayoutObject* prev_layout_object = GetLayoutText();
  AXObjectCache* cache = ExistingAXObjectCache();

  DCHECK(layout_text_);
  if (cache) {
    cache->Remove(this);
  }

  layout_text_ = nullptr;

  fragment_item_index_ = std::nullopt;
  root_box_fragment_ = nullptr;

  if (cache) {
    prev_layout_object->CheckIsNotDestroyed();
    DCHECK(IsA<LayoutText>(prev_layout_object));
    cache->InlineTextBoxesUpdated(prev_layout_object);
  }
}

LayoutText* AbstractInlineTextBox::GetFirstLetterPseudoLayoutText() const {
  // We only want to apply the first letter to the first inline text box
  // for a LayoutObject.
  if (!IsFirst()) {
    return nullptr;
  }

  Node* node = layout_text_->GetNode();
  if (!node) {
    return nullptr;
  }
  if (auto* layout_text = DynamicTo<LayoutText>(node->GetLayoutObject())) {
    return layout_text->GetFirstLetterPart();
  }
  return nullptr;
}

InlineCursor AbstractInlineTextBox::GetCursor() const {
  if (!fragment_item_index_) {
    return InlineCursor();
  }
  InlineCursor cursor(*root_box_fragment_);
  cursor.MoveTo(cursor.Items().Items()[*fragment_item_index_]);
  DCHECK(!cursor.Current().GetLayoutObject()->NeedsLayout());
  return cursor;
}

InlineCursor AbstractInlineTextBox::GetCursorOnLine() const {
  InlineCursor current = GetCursor();
  InlineCursor line_box = current;
  line_box.MoveToContainingLine();
  InlineCursor cursor = line_box.CursorForDescendants();
  cursor.MoveTo(current);
  return cursor;
}

String AbstractInlineTextBox::GetTextContent() const {
  const InlineCursor& cursor = GetCursor();
  if (cursor.Current().IsLayoutGeneratedText())
    return cursor.Current().Text(cursor).ToString();
  return cursor.Items().Text(cursor.Current().UsesFirstLineStyle());
}

bool AbstractInlineTextBox::NeedsTrailingSpace() const {
  const InlineCursor& cursor = GetCursor();
  if (cursor.Current().Style().ShouldPreserveWhiteSpaces()) {
    return false;
  }
  InlineCursor line_box = cursor;
  line_box.MoveToContainingLine();
  if (!line_box.Current().HasSoftWrapToNextLine())
    return false;
  const String text_content = GetTextContent();
  const unsigned end_offset = cursor.Current().TextEndOffset();
  if (end_offset >= text_content.length())
    return false;
  if (text_content[end_offset] != ' ')
    return false;
  const InlineBreakToken* break_token =
      line_box.Current().GetInlineBreakToken();
  // TODO(yosin): We should support OOF fragments between |fragment_| and
  // break token.
  if (break_token && break_token->StartTextOffset() != end_offset + 1) {
    return false;
  }
  // Check a character in text content after |fragment_| comes from same
  // layout text of |fragment_|.
  const LayoutObject* const layout_object = cursor.Current().GetLayoutObject();
  const OffsetMapping* mapping = OffsetMapping::GetFor(layout_object);
  // TODO(kojii): There's not much we can do for dirty-tree. crbug.com/946004
  if (!mapping)
    return false;
  const base::span<const OffsetMappingUnit> mapping_units =
      mapping->GetMappingUnitsForTextContentOffsetRange(end_offset,
                                                        end_offset + 1);
  if (mapping_units.begin() == mapping_units.end())
    return false;
  const OffsetMappingUnit& mapping_unit = mapping_units.front();
  return mapping_unit.GetLayoutObject() == layout_object;
}

AbstractInlineTextBox* AbstractInlineTextBox::NextInlineTextBox() const {
  InlineCursor next = GetCursor();
  if (!next)
    return nullptr;
  next.MoveToNextForSameLayoutObject();
  if (!next)
    return nullptr;
  return GetOrCreate(next);
}

PhysicalRect AbstractInlineTextBox::LocalBounds() const {
  if (const InlineCursor& cursor = GetCursor()) {
    return cursor.Current().RectInContainerFragment();
  }
  return PhysicalRect();
}

unsigned AbstractInlineTextBox::Len() const {
  const InlineCursor& cursor = GetCursor();
  if (!cursor)
    return 0;
  if (NeedsTrailingSpace())
    return cursor.Current().Text(cursor).length() + 1;
  return cursor.Current().Text(cursor).length();
}

unsigned AbstractInlineTextBox::TextOffsetInFormattingContext(
    unsigned offset) const {
  const InlineCursor& cursor = GetCursor();
  if (!cursor)
    return 0;
  return cursor.Current().TextStartOffset() + offset;
}

PhysicalDirection AbstractInlineTextBox::GetDirection() const {
  const InlineCursor& cursor = GetCursor();
  if (!cursor)
    return PhysicalDirection::kRight;
  return WritingDirectionMode(GetLayoutText()->Style()->GetWritingMode(),
                              cursor.Current().ResolvedDirection())
      .InlineEnd();
}

Node* AbstractInlineTextBox::GetNode() const {
  return layout_text_ ? layout_text_->GetNode() : nullptr;
}

AXObjectCache* AbstractInlineTextBox::ExistingAXObjectCache() const {
  return layout_text_ ? layout_text_->GetDocument().ExistingAXObjectCache()
                      : nullptr;
}

void AbstractInlineTextBox::CharacterWidths(Vector<float>& widths) const {
  const InlineCursor& cursor = GetCursor();
  if (!cursor)
    return;
  const ShapeResultView* shape_result_view = cursor.Current().TextShapeResult();
  if (!shape_result_view) {
    // When |fragment_| for BR, we don't have shape result.
    // "aom-computed-boolean-properties.html" reaches here.
    widths.resize(Len());
    return;
  }
  // TODO(layout-dev): Add support for IndividualCharacterRanges to
  // ShapeResultView to avoid the copy below.
  ShapeResult* shape_result = shape_result_view->CreateShapeResult();
  Vector<CharacterRange> ranges;
  shape_result->IndividualCharacterRanges(&ranges);
  widths.reserve(ranges.size());
  widths.resize(0);
  for (const auto& range : ranges)
    widths.push_back(range.Width());
  // The shaper can fail to return glyph metrics for all characters (see
  // crbug.com/613915 and crbug.com/615661) so add empty ranges to ensure all
  // characters have an associated range.
  widths.resize(Len());
}

void AbstractInlineTextBox::GetWordBoundaries(
    Vector<WordBoundaries>& words) const {
  GetWordBoundariesForText(words, GetText());

  // TODO(crbug/1406930): Uncomment the following DCHECK and fix the dozens of
  // failing tests.
  // #if DCHECK_IS_ON()
  //   if (!words.empty()) {
  //     // Validate that our word boundary detection algorithm gives the same
  //     output
  //     // as the one from the Editing layer.
  //     const int initial_offset_in_container =
  //         static_cast<int>(TextOffsetInFormattingContext(0));

  //     // 1. Compare the word offsets to the ones of the Editing algorithm
  //     when
  //     // moving forward.
  //     Position editing_pos(GetNode(), initial_offset_in_container);
  //     int editing_offset =
  //         editing_pos.OffsetInContainerNode() - initial_offset_in_container;
  //     for (WordBoundaries word : words) {
  //       DCHECK_EQ(editing_offset, word.start_index)
  //           << "[Going forward] Word boundaries are different between "
  //              "accessibility and editing in text=\""
  //           << GetText() << "\". Failing at editing text offset \""
  //           << editing_offset << "\" and AX text offset \"" <<
  //           word.start_index
  //           << "\".";
  //       // See comment in `AbstractInlineTextBox::GetWordBoundariesForText`
  //       that
  //       // justify why we only check for kWordSkipSpaces.
  //       editing_pos =
  //           NextWordPosition(editing_pos,
  //           PlatformWordBehavior::kWordSkipSpaces)
  //               .GetPosition();
  //       editing_offset =
  //           editing_pos.OffsetInContainerNode() -
  //           initial_offset_in_container;
  //     }
  //     // Check for the last word boundary.
  //     DCHECK_EQ(editing_offset, words[words.size() - 1].end_index)
  //         << "[Going forward] Word boundaries are different between "
  //            "accessibility and at the end of the inline text box. Text=\""
  //         << GetText() << "\".";

  //     // 2. Compare the word offsets to the ones of the Editing algorithm
  //     when
  //     // moving backwards.
  //     //
  //     // TODO(accessibility): Uncomment the following code to validate our
  //     word
  //     // boundaries also match the ones from the Editing layer when moving
  //     // backward. This is currently failing because of crbug/1406287.
  //     //
  //     // const int last_text_offset =
  //     //     initial_offset_in_container + GetText().length();
  //     // editing_pos = Position(GetNode(), last_text_offset);
  //     // editing_offset = editing_pos.OffsetInContainerNode() -
  //     // initial_offset_in_container;

  //     // // Check for the first word boundary.
  //     // DCHECK_EQ(editing_offset, words[words.size() - 1].end_index)
  //     //     << "[Going backward] Word boundaries are different between "
  //     //        "accessibility and at the end of the inline text box.
  //     Text=\""
  //     //     << GetText() << "\".";
  //     // editing_pos = PreviousWordPosition(editing_pos).GetPosition();
  //     // editing_offset = editing_pos.OffsetInContainerNode() -
  //     // initial_offset_in_container;

  //     // Vector<WordBoundaries> reverse_words(words);
  //     // reverse_words.Reverse();
  //     // for (WordBoundaries word : reverse_words) {
  //     //   DCHECK_EQ(editing_offset, word.start_index)
  //     //       << "[Going backward] Word boundaries are different between "
  //     //          "accessibility and editing in text=\""
  //     //       << GetText() << "\". Failing at editing text offset \""
  //     //       << editing_offset << "\" and AX text offset \"" <<
  //     word.start_index
  //     //       << "\".";
  //     //   editing_pos = PreviousWordPosition(editing_pos).GetPosition();
  //     //   editing_offset = editing_pos.OffsetInContainerNode() -
  //     //   initial_offset_in_container;
  //     // }
  //   }
  // #endif
}

// static
void AbstractInlineTextBox::GetWordBoundariesForText(
    Vector<WordBoundaries>& words,
    const String& text) {
  if (!text.length()) {
    return;
  }

  TextBreakIterator* it = WordBreakIterator(text, 0, text.length());
  if (!it) {
    return;
  }
  std::optional<int> word_start;
  for (int offset = 0;
       offset != kTextBreakDone && offset < static_cast<int>(text.length());
       offset = it->following(offset)) {
    // Unlike in ICU's WordBreakIterator, a word boundary is valid only if it is
    // before, or immediately preceded by a word break as defined by the Editing
    // code (see `IsWordBreak`). We therefore need to filter the boundaries
    // returned by ICU's WordBreakIterator and return a subset of them. For
    // example we should exclude a word boundary that is between two space
    // characters, "Hello | there".
    //
    // IMPORTANT: This algorithm needs to stay in sync with the one used to
    // find the next/previous word boundary in the Editing layer. See
    // `NextWordPositionInternal` in `visible_units_word.cc` for more info.
    //
    // There's one noticeable difference between our implementation and the one
    // in the Editing layer: in the Editing layer, we only skip spaces before
    // word starts when on Windows. However, we skip spaces the accessible word
    // offsets on all platforms because:
    //   1. It doesn't have an impact on the screen reader user (ATs never
    //      announce spaces).
    //   2. The implementation is simpler. Arguably, this is a bad reason, but
    //      the reality is that word offsets computation will sooner or later
    //      move to the browser process where we'll have to reimplement this
    //      algorithm. Another more near-term possibility is that Editing folks
    //      could refactor their word boundary algorithm so that we could simply
    //      reuse it for accessibility. Anyway, we currently do not see a strong
    //      case to justify spending time to match this behavior perfectly.
    if (WTF::unicode::IsPunct(text[offset]) || U16_IS_SURROGATE(text[offset])) {
      // Case 1: A new word should start before and end after a series of
      // punctuation marks, i.e., Consecutive punctuation marks should be
      // accumulated into a single word. For example, "|Hello|+++---|there|".
      // Surrogate pair runs should also be collapsed.
      //
      // At beginning of text, or right after an alphanumeric character or a
      // character that cannot be a word break.
      if (offset == 0 || WTF::unicode::IsAlphanumeric(text[offset - 1]) ||
          !IsWordBreak(text[offset - 1])) {
        if (word_start) {
          words.emplace_back(*word_start, offset);
        }
        word_start = offset;
      } else {
        // Skip to the end of the punctuation/surrogate pair run.
        continue;
      }
    } else if (IsWordBreak(text[offset])) {
      // Case 2: A new word should start if `offset` is before an alphanumeric
      // character, an underscore or a hard line break.
      //
      // We found a new word start or end. Append the previous word (if it
      // exists) to the results, otherwise save this offset as a word start.
      if (word_start) {
        words.emplace_back(*word_start, offset);
      }
      word_start = offset;
    } else if (offset > 0) {
      // Case 3: A word should end if `offset` is proceeded by a word break or
      // a punctuation.
      UChar prev_character = text[offset - 1];
      if (IsWordBreak(prev_character) ||
          WTF::unicode::IsPunct(prev_character) ||
          U16_IS_SURROGATE(prev_character)) {
        if (word_start) {
          words.emplace_back(*word_start, offset);
          word_start = std::nullopt;
        }
      }
    }
  }

  // Case 4: If the character at last `offset` in `text` was a word break, then
  // it would have started a new word. We need to add its corresponding word end
  // boundary which should be at `text`'s length.
  if (word_start) {
    words.emplace_back(*word_start, text.length());
    word_start = std::nullopt;
  }
}

String AbstractInlineTextBox::GetText() const {
  const InlineCursor& cursor = GetCursor();
  if (!cursor)
    return g_empty_string;

  String result = cursor.Current().Text(cursor).ToString();

  // For compatibility with |InlineTextBox|, we should have a space character
  // for soft line break.
  // Following tests require this:
  //  - accessibility/inline-text-change-style.html
  //  - accessibility/inline-text-changes.html
  //  - accessibility/inline-text-word-boundaries.html
  if (NeedsTrailingSpace())
    result = result + " ";

  // When the CSS first-letter pseudoselector is used, the LayoutText for the
  // first letter is excluded from the accessibility tree, so we need to prepend
  // its text here.
  if (LayoutText* first_letter = GetFirstLetterPseudoLayoutText())
    result = first_letter->TransformedText().SimplifyWhiteSpace() + result;

  return result;
}

bool AbstractInlineTextBox::IsFirst() const {
  const InlineCursor& cursor = GetCursor();
  if (!cursor)
    return true;
  InlineCursor first_fragment;
  first_fragment.MoveTo(*cursor.Current().GetLayoutObject());
  return cursor == first_fragment;
}

bool AbstractInlineTextBox::IsLast() const {
  InlineCursor cursor = GetCursor();
  if (!cursor)
    return true;
  cursor.MoveToNextForSameLayoutObject();
  return !cursor;
}

AbstractInlineTextBox* AbstractInlineTextBox::NextOnLine() const {
  InlineCursor cursor = GetCursorOnLine();
  if (!cursor)
    return nullptr;
  for (cursor.MoveToNext(); cursor; cursor.MoveToNext()) {
    if (cursor.Current().GetLayoutObject()->IsText())
      return GetOrCreate(cursor);
  }
  return nullptr;
}

AbstractInlineTextBox* AbstractInlineTextBox::PreviousOnLine() const {
  InlineCursor cursor = GetCursorOnLine();
  if (!cursor)
    return nullptr;
  for (cursor.MoveToPrevious(); cursor; cursor.MoveToPrevious()) {
    if (cursor.Current().GetLayoutObject()->IsText())
      return GetOrCreate(cursor);
  }
  return nullptr;
}

bool AbstractInlineTextBox::IsLineBreak() const {
  const InlineCursor& cursor = GetCursor();
  return cursor && cursor.Current().IsLineBreak();
}

}  // namespace blink
```