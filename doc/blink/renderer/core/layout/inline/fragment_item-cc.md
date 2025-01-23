Response:
The user wants a summary of the functionality of the `fragment_item.cc` file in the Chromium Blink engine. The summary should cover:

1. **Core Functionality:** What does this file do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logic and Data Flow:** If there are logical deductions, describe them with input and output.
4. **Common Usage Errors:** Point out potential mistakes users or developers might make.
5. **Overall Summary:** A concise recap of its purpose.

Let's break down the code to identify these aspects.

**1. Core Functionality:**

The file defines the `FragmentItem` class. Based on the constructors and member variables, `FragmentItem` seems to represent a single visual piece within an inline layout. It can be:

*   A piece of text (`TextItem`).
*   Generated content like bullets or numbering (`GeneratedTextItem`).
*   An entire line box (`LineItem`).
*   A generic box element (`BoxItem`).

It stores information about its:

*   Position and size (`rect_`).
*   Associated layout object (`layout_object_`).
*   Type (`const_type_`, `sub_type_`).
*   Styling variations (`style_variant_`).
*   Visibility (`is_hidden_for_paint_`).
*   Text direction (`text_direction_`).
*   Ink overflow information (`ink_overflow_`).

The file also includes methods for:

*   Determining the type of fragment.
*   Accessing associated layout data.
*   Handling SVG-specific transformations and bounding boxes.
*   Calculating ink overflow.
*   Debugging and string representation.

**2. Relationship to Web Technologies:**

*   **HTML:**  `FragmentItem` directly represents the visual layout of HTML elements. A `<div>`, `<span>`, text nodes, or even list markers can be represented by `FragmentItem` instances.
*   **CSS:** The styling information (e.g., `style_variant_`, used for font and color) and layout properties (like `writing-mode`) from CSS directly influence the creation and properties of `FragmentItem`s. The ink overflow calculations are also tied to CSS `overflow` properties and visual effects like box shadows.
*   **JavaScript:** While `FragmentItem` itself is a C++ class and not directly manipulated by JavaScript, the layout calculations it participates in are crucial for JavaScript APIs that query element positions and sizes (e.g., `getBoundingClientRect()`). When JavaScript modifies the DOM or CSS, it can trigger layout recalculations involving `FragmentItem` creation and manipulation.

**Examples:**

*   **HTML:** `<span>Hello</span>` would likely result in a `FragmentItem` of type `kText`.
*   **CSS:** `div { width: 100px; }`  When this `div` is rendered inline, a `FragmentItem` of type `kBox` would be created, and its `rect_` would have a width of 100px.
*   **CSS:** `li::marker { content: "• "; }` The bullet point would be represented by a `FragmentItem` of type `kGeneratedText`.
*   **CSS:** `svg text { fill: red; }` A `FragmentItem` representing the SVG text would store the color information.
*   **JavaScript:** `element.getBoundingClientRect()` relies on the layout information computed using `FragmentItem`s to return the element's bounding box.

**3. Logic and Data Flow:**

The constructors of `FragmentItem` demonstrate the logic for creating different types of fragments based on the input `InlineItem` or `PhysicalBoxFragment`.

*   **Input:** An `InlineItem` representing a text node with "World", `TextOffsetRange{0, 5}`, and a size of `PhysicalSize(50, 20)`.
*   **Output:** A `FragmentItem` of type `kText` with `text_.text_offset` as `{0, 5}` and `rect_` with size `(50, 20)`.

*   **Input:** A `PhysicalBoxFragment` representing a `<div>` with dimensions `100x30`.
*   **Output:** A `FragmentItem` of type `kBox` with `rect_` having a size of `(100, 30)`.

The SVG-related methods (`ObjectBoundingBox`, `SvgUnscaledQuad`, `BuildSvgTransformForPaint`, etc.) show the logic for applying SVG transformations to text fragments.

**4. Common Usage Errors (from a developer perspective):**

While developers don't directly instantiate `FragmentItem`, understanding its role is important when working on layout-related features in Blink.

*   **Incorrect assumptions about fragment boundaries:**  Assuming a one-to-one mapping between HTML elements and `FragmentItem`s is wrong. A single element can be split into multiple fragments across lines.
*   **Misunderstanding the impact of CSS properties:** Changes in CSS (like `display`, `float`, `writing-mode`) will fundamentally change how `FragmentItem`s are created and arranged.
*   **Ignoring text directionality:** Incorrect handling of bidirectional text can lead to layout issues in how `FragmentItem`s are ordered.
*   **Incorrectly calculating bounding boxes for complex scenarios:**  SVG transformations and complex inline layouts require careful consideration of how `FragmentItem`s are positioned and transformed.

**5. Overall Summary (for Part 1):**

The `fragment_item.cc` file defines the `FragmentItem` class, a fundamental building block for representing individual visual components within Blink's inline layout system. It encapsulates information about text, generated content, lines, and boxes, including their position, size, styling, and associated layout objects. It plays a crucial role in rendering web content defined by HTML and styled by CSS, and its functionality is indirectly relevant to JavaScript's ability to query layout information. The code includes logic for handling various fragment types and SVG-specific rendering.

这是 `blink/renderer/core/layout/inline/fragment_item.cc` 文件的第一部分，主要定义了 `FragmentItem` 类的结构和基本构造函数。`FragmentItem` 是 Blink 渲染引擎中内联布局的关键组成部分，用于表示内联格式化上下文中一个独立的视觉片段。

**功能归纳:**

1. **表示内联布局的视觉单元:** `FragmentItem` 作为一个基类或结构体，用于表示内联布局中的不同类型的视觉元素，例如文本片段、生成的文本内容（如列表标记）、行框和内联盒子。

2. **存储布局和样式信息:**  它存储了与该视觉片段相关的关键信息，包括：
    *   **几何属性:**  `rect_` 存储了片段的物理位置和大小。
    *   **关联的布局对象:** `layout_object_` 指向与该片段关联的 `LayoutObject`，这是 Blink 中表示 DOM 元素的布局对象。
    *   **片段类型和子类型:** `const_type_` 和 `sub_type_` 用于区分不同类型的 `FragmentItem` (例如文本、生成内容、行、盒子)。
    *   **样式变体:** `style_variant_`  可能用于表示不同的样式应用方式。
    *   **绘制时的隐藏状态:** `is_hidden_for_paint_` 指示该片段在绘制时是否被隐藏。
    *   **文本方向:** `text_direction_` 存储文本的书写方向。
    *   **墨水溢出信息:** `ink_overflow_` 用于存储片段的墨水溢出区域信息。
    *   **脏标记:** `is_dirty_` 可能用于标记该片段是否需要重新计算。
    *   **节点末尾标记:** `is_last_for_node_` 指示该片段是否是其关联布局对象的最后一个片段。

3. **支持不同类型的内联元素:**  通过不同的构造函数，`FragmentItem` 可以被创建来表示不同类型的内联元素：
    *   **文本片段:** 通过 `InlineItem` 和文本偏移量创建。
    *   **生成的文本:**  通过 `LayoutObject`、文本类型、样式变体、文本内容等信息创建，用于表示如 `::before` 或 `::after` 生成的内容。
    *   **行框:** 通过 `PhysicalLineBoxFragment` 创建，表示一行中的内容。
    *   **盒子:** 通过 `PhysicalBoxFragment` 创建，表示内联盒子元素。

4. **处理 SVG 文本:** 包含处理 SVG 文本片段的构造函数和成员变量 (`text_.svg_data`)，用于存储 SVG 相关的属性。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **HTML:**  `FragmentItem` 直接对应于 HTML 元素在内联布局中的视觉表示。
    *   **例子:**  `<span>Hello</span>` 中的 "Hello" 文本会被表示为一个或多个 `FragmentItem` (如果跨行)。 `<div>Inline Content</div>` 中的 "Inline Content" 也可能被表示为 `FragmentItem`。

*   **CSS:** CSS 样式会影响 `FragmentItem` 的创建和属性。
    *   **例子:**  `span { color: red; }` 会影响文本 `FragmentItem` 的绘制属性。 `li::marker { content: "•"; }` 生成的 "•" 会被表示为一个 `GeneratedTextItem`。 `div { display: inline-block; width: 50px; }` 创建的内联块元素会被表示为一个 `BoxItem`，其 `rect_` 会包含宽度信息。 `svg text { fill: blue; }`  创建的 `FragmentItem` 会存储与蓝色填充相关的 SVG 数据。

*   **JavaScript:** 虽然 JavaScript 不能直接操作 `FragmentItem` 对象，但 JavaScript 通过 DOM API 和 CSSOM 操作影响布局，从而间接地影响 `FragmentItem` 的创建和属性。
    *   **例子:**  使用 JavaScript 修改元素的 `textContent` 会导致新的文本 `FragmentItem` 被创建。通过 JavaScript 修改元素的 CSS 属性（例如 `element.style.display = 'inline'`) 会改变 `FragmentItem` 的类型。 `element.getBoundingClientRect()`  等方法返回的元素尺寸和位置信息，是基于 `FragmentItem` 等布局计算结果的。

**逻辑推理 (假设输入与输出):**

*   **假设输入:**  一个 `<span>` 元素包含文本 "Example"。
*   **输出:**  会创建一个 `FragmentItem` 对象，其 `const_type_` 为 `kText`，`sub_type_` 可能指示是普通的文本，`layout_object_` 指向该 `<span>` 元素的 `LayoutText` 对象，`text_.text_offset` 会是 `{0, 7}` (文本 "Example" 的长度)，`rect_` 会包含该文本在屏幕上的位置和大小。

*   **假设输入:** 一个 `<li>` 元素。
*   **输出:**  可能会创建两个 `FragmentItem` 对象，一个 `GeneratedTextItem` 表示列表标记（如果存在），另一个 `FragmentItem` (可能是 `kText` 或 `kBox`) 表示列表项的内容。

**用户或编程常见的使用错误 (针对 Blink 开发者):**

*   **假设 `FragmentItem` 和 DOM 元素一一对应:** 这是一个常见的误解。一个 DOM 元素的内容可能因为换行、分段等原因被分割成多个 `FragmentItem`。
*   **直接修改 `FragmentItem` 的属性而不触发布局更新:**  `FragmentItem` 的状态应该与布局树的状态保持一致。不经过正确的布局流程修改 `FragmentItem` 可能会导致渲染错误。
*   **在不合适的时机访问或操作 `FragmentItem`:**  例如，在布局计算完成之前访问 `FragmentItem` 的尺寸信息可能得到错误的结果。
*   **没有正确处理不同类型的 `FragmentItem`:**  代码逻辑需要根据 `FragmentItem` 的 `const_type_` 和 `sub_type_` 来进行不同的处理，例如访问文本片段需要访问 `text_` 成员，而访问盒子需要访问 `box_` 成员。

总而言之，`fragment_item.cc` 的第一部分定义了 `FragmentItem` 类的基本结构和构造方式，为表示和管理内联布局中的视觉片段提供了基础。它是 Blink 渲染引擎连接 HTML 结构、CSS 样式和最终屏幕渲染的关键数据结构之一。

### 提示词
```
这是目录为blink/renderer/core/layout/inline/fragment_item.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"

#include "base/debug/dump_without_crashing.h"
#include "third_party/blink/renderer/core/editing/bidi_adjustment.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/layout/geometry/writing_mode_converter.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_items_builder.h"
#include "third_party/blink/renderer/core/layout/inline/inline_caret_position.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/paint/inline_paint_context.h"
#include "third_party/blink/renderer/platform/fonts/text_fragment_paint_info.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"

namespace blink {

namespace {

struct SameSizeAsFragmentItem {
  union {
    FragmentItem::TextItem text_;
    FragmentItem::GeneratedTextItem generated_text_;
    FragmentItem::LineItem line_;
    FragmentItem::BoxItem box_;
  };
  PhysicalRect rect;
  InkOverflow ink_overflow;
  Member<void*> member;
  wtf_size_t sizes[2];
  unsigned flags;
};

ASSERT_SIZE(FragmentItem, SameSizeAsFragmentItem);

}  // namespace

FragmentItem::FragmentItem(const InlineItem& inline_item,
                           const ShapeResultView* shape_result,
                           const TextOffsetRange& text_offset,
                           const PhysicalSize& size,
                           bool is_hidden_for_paint)
    : text_({shape_result, nullptr, text_offset}),
      rect_({PhysicalOffset(), size}),
      layout_object_(inline_item.GetLayoutObject()),
      const_type_(kText),
      sub_type_(static_cast<unsigned>(inline_item.TextType())),
      style_variant_(static_cast<unsigned>(inline_item.GetStyleVariant())),
      is_hidden_for_paint_(is_hidden_for_paint),
      text_direction_(static_cast<unsigned>(inline_item.Direction())),
      ink_overflow_type_(static_cast<unsigned>(InkOverflow::Type::kNotSet)),
      is_dirty_(false),
      is_last_for_node_(true) {
#if DCHECK_IS_ON()
  if (text_.shape_result) {
    DCHECK_EQ(text_.shape_result->StartIndex(), StartOffset());
    DCHECK_EQ(text_.shape_result->EndIndex(), EndOffset());
  }
#endif
  DCHECK_NE(TextType(), TextItemType::kLayoutGenerated);
  DCHECK(!IsFormattingContextRoot());
}

FragmentItem::FragmentItem(const LayoutObject& layout_object,
                           TextItemType text_type,
                           StyleVariant style_variant,
                           TextDirection direction,
                           const ShapeResultView* shape_result,
                           const String& text_content,
                           const PhysicalSize& size,
                           bool is_hidden_for_paint)
    : generated_text_({shape_result, text_content}),
      rect_({PhysicalOffset(), size}),
      layout_object_(&layout_object),
      const_type_(kGeneratedText),
      sub_type_(static_cast<unsigned>(text_type)),
      style_variant_(static_cast<unsigned>(style_variant)),
      is_hidden_for_paint_(is_hidden_for_paint),
      text_direction_(static_cast<unsigned>(direction)),
      ink_overflow_type_(static_cast<unsigned>(InkOverflow::Type::kNotSet)),
      is_dirty_(false),
      is_last_for_node_(true) {
  DCHECK(layout_object_);
  DCHECK_EQ(TextShapeResult()->StartIndex(), StartOffset());
  DCHECK_EQ(TextShapeResult()->EndIndex(), EndOffset());
  DCHECK(!IsFormattingContextRoot());
}

FragmentItem::FragmentItem(const InlineItem& inline_item,
                           const ShapeResultView* shape_result,
                           const String& text_content,
                           const PhysicalSize& size,
                           bool is_hidden_for_paint)
    : FragmentItem(*inline_item.GetLayoutObject(),
                   inline_item.TextType(),
                   inline_item.GetStyleVariant(),
                   inline_item.Direction(),
                   shape_result,
                   text_content,
                   size,
                   is_hidden_for_paint) {}

FragmentItem::FragmentItem(const PhysicalLineBoxFragment& line)
    : line_({&line, /* descendants_count */ 1}),
      rect_({PhysicalOffset(), line.Size()}),
      layout_object_(line.ContainerLayoutObject()),
      const_type_(kLine),
      sub_type_(static_cast<unsigned>(line.GetLineBoxType())),
      style_variant_(static_cast<unsigned>(line.GetStyleVariant())),
      is_hidden_for_paint_(line.IsHiddenForPaint()),
      text_direction_(static_cast<unsigned>(line.BaseDirection())),
      ink_overflow_type_(static_cast<unsigned>(InkOverflow::Type::kNotSet)),
      is_dirty_(false),
      is_last_for_node_(true) {
  DCHECK(!IsFormattingContextRoot());
}

FragmentItem::FragmentItem(const PhysicalSize& size,
                           const PhysicalLineBoxFragment& base_line)
    : line_({nullptr, /* descendants_count */ 1}),
      rect_({PhysicalOffset(), size}),
      layout_object_(base_line.ContainerLayoutObject()),
      const_type_(kLine),
      sub_type_(
          static_cast<unsigned>(FragmentItem::LineBoxType::kNormalLineBox)),
      style_variant_(static_cast<unsigned>(base_line.GetStyleVariant())),
      is_hidden_for_paint_(false),
      text_direction_(static_cast<unsigned>(base_line.BaseDirection())),
      ink_overflow_type_(static_cast<unsigned>(InkOverflow::Type::kNotSet)),
      is_dirty_(false),
      is_last_for_node_(true) {
  DCHECK(!IsFormattingContextRoot());
}

FragmentItem::FragmentItem(const PhysicalBoxFragment& box,
                           TextDirection resolved_direction)
    : box_(&box, /* descendants_count */ 1),
      rect_({PhysicalOffset(), box.Size()}),
      layout_object_(box.GetLayoutObject()),
      const_type_(kBox),
      style_variant_(static_cast<unsigned>(box.GetStyleVariant())),
      is_hidden_for_paint_(box.IsHiddenForPaint()),
      text_direction_(static_cast<unsigned>(resolved_direction)),
      ink_overflow_type_(static_cast<unsigned>(InkOverflow::Type::kNotSet)),
      is_dirty_(false),
      is_last_for_node_(true) {
  DCHECK_EQ(IsFormattingContextRoot(), box.IsFormattingContextRoot());
}

// |const_type_| will be re-initialized in another constructor called inside
// this one.
FragmentItem::FragmentItem(LogicalLineItem&& line_item,
                           WritingMode writing_mode)
    : const_type_(kInvalid) {
  DCHECK(line_item.CanCreateFragmentItem());

  if (line_item.inline_item) {
    if (line_item.text_content) [[unlikely]] {
      new (this) FragmentItem(
          *line_item.inline_item, std::move(line_item.shape_result),
          line_item.text_content,
          ToPhysicalSize(line_item.MarginSize(), writing_mode),
          line_item.is_hidden_for_paint);
      has_over_annotation_ = line_item.has_over_annotation;
      has_under_annotation_ = line_item.has_under_annotation;
      return;
    }

    new (this)
        FragmentItem(*line_item.inline_item, std::move(line_item.shape_result),
                     line_item.text_offset,
                     ToPhysicalSize(line_item.MarginSize(), writing_mode),
                     line_item.is_hidden_for_paint);
    has_over_annotation_ = line_item.has_over_annotation;
    has_under_annotation_ = line_item.has_under_annotation;
    return;
  }

  if (line_item.layout_result) {
    const auto& box_fragment =
        To<PhysicalBoxFragment>(line_item.layout_result->GetPhysicalFragment());
    new (this) FragmentItem(box_fragment, line_item.ResolvedDirection());
    return;
  }

  if (line_item.layout_object) {
    const TextDirection direction = line_item.shape_result->Direction();
    new (this)
        FragmentItem(*line_item.layout_object, TextItemType::kLayoutGenerated,
                     line_item.style_variant, direction,
                     std::move(line_item.shape_result), line_item.text_content,
                     ToPhysicalSize(line_item.MarginSize(), writing_mode),
                     line_item.is_hidden_for_paint);
    return;
  }

  // CanCreateFragmentItem()
  NOTREACHED();
}

FragmentItem::FragmentItem(const FragmentItem& source)
    : rect_(source.rect_),
      layout_object_(source.layout_object_),
      fragment_id_(source.fragment_id_),
      delta_to_next_for_same_layout_object_(
          source.delta_to_next_for_same_layout_object_),
      const_type_(source.const_type_),
      sub_type_(source.sub_type_),
      style_variant_(source.style_variant_),
      is_hidden_for_paint_(source.is_hidden_for_paint_),
      text_direction_(source.text_direction_),
      has_over_annotation_(source.has_over_annotation_),
      has_under_annotation_(source.has_under_annotation_),
      ink_overflow_type_(static_cast<unsigned>(InkOverflow::Type::kNotSet)),
      is_dirty_(source.is_dirty_),
      is_last_for_node_(source.is_last_for_node_) {
  switch (Type()) {
    case kInvalid:
      NOTREACHED() << "Cannot construct invalid value";
    case kText:
      new (&text_) TextItem(source.text_);
      break;
    case kGeneratedText:
      new (&generated_text_) GeneratedTextItem(source.generated_text_);
      break;
    case kLine:
      new (&line_) LineItem(source.line_);
      break;
    case kBox:
      new (&box_) BoxItem(source.box_);
      break;
  }

  if (source.IsInkOverflowComputed()) {
    ink_overflow_type_ = static_cast<unsigned>(source.InkOverflowType());
    new (&ink_overflow_)
        InkOverflow(source.InkOverflowType(), source.ink_overflow_);
  }
}

FragmentItem::FragmentItem(FragmentItem&& source)
    : rect_(source.rect_),
      ink_overflow_(source.InkOverflowType(), std::move(source.ink_overflow_)),
      layout_object_(source.layout_object_),
      fragment_id_(source.fragment_id_),
      delta_to_next_for_same_layout_object_(
          source.delta_to_next_for_same_layout_object_),
      const_type_(source.const_type_),
      sub_type_(source.sub_type_),
      style_variant_(source.style_variant_),
      is_hidden_for_paint_(source.is_hidden_for_paint_),
      text_direction_(source.text_direction_),
      has_over_annotation_(source.has_over_annotation_),
      has_under_annotation_(source.has_under_annotation_),
      ink_overflow_type_(source.ink_overflow_type_),
      is_dirty_(source.is_dirty_),
      is_last_for_node_(source.is_last_for_node_) {
  switch (Type()) {
    case kInvalid:
      NOTREACHED() << "Cannot construct invalid value";
    case kText:
      new (&text_) TextItem(std::move(source.text_));
      break;
    case kGeneratedText:
      new (&generated_text_)
          GeneratedTextItem(std::move(source.generated_text_));
      break;
    case kLine:
      new (&line_) LineItem(std::move(source.line_));
      break;
    case kBox:
      new (&box_) BoxItem(std::move(source.box_));
      break;
  }
}

FragmentItem::~FragmentItem() {
  switch (Type()) {
    case kInvalid:
      // Slot can be zeroed, do nothing.
      return;
    case kText:
      text_.~TextItem();
      break;
    case kGeneratedText:
      generated_text_.~GeneratedTextItem();
      break;
    case kLine:
      line_.~LineItem();
      break;
    case kBox:
      box_.~BoxItem();
      break;
  }
  ink_overflow_.Reset(InkOverflowType());
}

bool FragmentItem::IsInlineBox() const {
  if (Type() == kBox) {
    if (const PhysicalBoxFragment* box = BoxFragment()) {
      return box->IsInlineBox();
    }
    NOTREACHED();
  }
  return false;
}

bool FragmentItem::IsAtomicInline() const {
  if (Type() != kBox)
    return false;
  if (const PhysicalBoxFragment* box = BoxFragment()) {
    return box->IsAtomicInline();
  }
  return false;
}

bool FragmentItem::IsBlockInInline() const {
  switch (Type()) {
    case kBox:
      if (auto* box = BoxFragment())
        return box->IsBlockInInline();
      return false;
    case kLine:
      if (auto* line_box = LineBoxFragment())
        return line_box->IsBlockInInline();
      return false;
    default:
      return false;
  }
}

bool FragmentItem::IsFloating() const {
  if (const PhysicalBoxFragment* box = BoxFragment()) {
    return box->IsFloating();
  }
  return false;
}

bool FragmentItem::IsEmptyLineBox() const {
  return GetLineBoxType() == LineBoxType::kEmptyLineBox;
}

bool FragmentItem::IsStyleGeneratedText() const {
  if (Type() == kText) {
    return GetLayoutObject()->IsStyleGenerated();
  }
  return false;
}

bool FragmentItem::IsGeneratedText() const {
  return IsLayoutGeneratedText() || IsStyleGeneratedText();
}

bool FragmentItem::IsFormattingContextRoot() const {
  const PhysicalBoxFragment* box = BoxFragment();
  return box && box->IsFormattingContextRoot();
}

bool FragmentItem::IsListMarker() const {
  return layout_object_ && layout_object_->IsLayoutOutsideListMarker();
}

LayoutObject& FragmentItem::BlockInInline() const {
  DCHECK(IsBlockInInline());
  auto* const block = To<LayoutBlockFlow>(GetLayoutObject())->FirstChild();
  DCHECK(block) << this;
  return *block;
}

void FragmentItem::SetSvgFragmentData(const SvgFragmentData* data,
                                      const PhysicalRect& unscaled_rect,
                                      bool is_hidden) {
  DCHECK_EQ(Type(), kText);
  text_.svg_data = data;
  rect_ = unscaled_rect;
  is_hidden_for_paint_ = is_hidden;
}

void FragmentItem::SetSvgLineLocalRect(const PhysicalRect& unscaled_rect) {
  DCHECK_EQ(Type(), kLine);
  rect_ = unscaled_rect;
}

gfx::RectF FragmentItem::ObjectBoundingBox(const FragmentItems& items) const {
  DCHECK(IsSvgText());
  const Font& scaled_font = ScaledFont();
  gfx::RectF ink_bounds = scaled_font.TextInkBounds(TextPaintInfo(items));
  if (const auto* font_data = scaled_font.PrimaryFont())
    ink_bounds.Offset(0.0f, font_data->GetFontMetrics().FloatAscent());
  ink_bounds.Scale(GetSvgFragmentData()->length_adjust_scale, 1.0f);
  const gfx::RectF& scaled_rect = GetSvgFragmentData()->rect;
  // Convert a logical ink_bounds to physical. We don't use WiringModeConverter,
  // which has no ToPhysical() for gfx::RectF.
  switch (GetWritingMode()) {
    case WritingMode::kHorizontalTb:
      break;
    case WritingMode::kVerticalLr:
    case WritingMode::kVerticalRl:
    case WritingMode::kSidewaysRl:
      ink_bounds =
          gfx::RectF(scaled_rect.width() - ink_bounds.bottom(), ink_bounds.x(),
                     ink_bounds.height(), ink_bounds.width());
      break;
    case WritingMode::kSidewaysLr:
      ink_bounds =
          gfx::RectF(ink_bounds.y(), scaled_rect.height() - ink_bounds.right(),
                     ink_bounds.height(), ink_bounds.width());
      break;
  }
  ink_bounds.Offset(scaled_rect.OffsetFromOrigin());
  ink_bounds.Union(scaled_rect);
  if (HasSvgTransformForBoundingBox())
    ink_bounds = BuildSvgTransformForBoundingBox().MapRect(ink_bounds);
  ink_bounds.Scale(1 / SvgScalingFactor());
  return ink_bounds;
}

gfx::QuadF FragmentItem::SvgUnscaledQuad() const {
  DCHECK(IsSvgText());
  gfx::QuadF quad = BuildSvgTransformForBoundingBox().MapQuad(
      gfx::QuadF(GetSvgFragmentData()->rect));
  const float scaling_factor = SvgScalingFactor();
  quad.Scale(1 / scaling_factor, 1 / scaling_factor);
  return quad;
}

PhysicalOffset FragmentItem::MapPointInContainer(
    const PhysicalOffset& point) const {
  if (IsSvgText() && HasSvgTransformForBoundingBox()) {
    const float scaling_factor = SvgScalingFactor();
    return PhysicalOffset::FromPointFRound(gfx::ScalePoint(
        BuildSvgTransformForBoundingBox().Inverse().MapPoint(
            gfx::ScalePoint(gfx::PointF(point), scaling_factor)),
        scaling_factor));
  }
  return point;
}

float FragmentItem::ScaleInlineOffset(LayoutUnit inline_offset) const {
  if (const SvgFragmentData* svg_data = GetSvgFragmentData()) {
    return inline_offset.ToFloat() * SvgScalingFactor() /
           svg_data->length_adjust_scale;
  }
  return inline_offset.ToFloat();
}

bool FragmentItem::InclusiveContains(const gfx::PointF& position) const {
  DCHECK(IsSvgText());
  gfx::PointF scaled_position = gfx::ScalePoint(position, SvgScalingFactor());
  const gfx::RectF& item_rect = GetSvgFragmentData()->rect;
  if (!HasSvgTransformForBoundingBox())
    return item_rect.InclusiveContains(scaled_position);
  return BuildSvgTransformForBoundingBox()
      .MapQuad(gfx::QuadF(item_rect))
      .Contains(scaled_position);
}

bool FragmentItem::HasNonVisibleOverflow() const {
  if (const PhysicalBoxFragment* fragment = BoxFragment()) {
    return fragment->HasNonVisibleOverflow();
  }
  return false;
}

bool FragmentItem::IsScrollContainer() const {
  if (const PhysicalBoxFragment* fragment = BoxFragment()) {
    return fragment->IsScrollContainer();
  }
  return false;
}

bool FragmentItem::HasSelfPaintingLayer() const {
  if (const PhysicalBoxFragment* fragment = BoxFragment()) {
    return fragment->HasSelfPaintingLayer();
  }
  return false;
}

FragmentItem::BoxItem::BoxItem(const PhysicalBoxFragment* box_fragment,
                               wtf_size_t descendants_count)
    : box_fragment(box_fragment), descendants_count(descendants_count) {}

void FragmentItem::BoxItem::Trace(Visitor* visitor) const {
  visitor->Trace(box_fragment);
}

const PhysicalBoxFragment* FragmentItem::BoxItem::PostLayout() const {
  if (box_fragment)
    return box_fragment->PostLayout();
  return nullptr;
}

void FragmentItem::LayoutObjectWillBeDestroyed() const {
  const_cast<FragmentItem*>(this)->layout_object_ = nullptr;
  if (const PhysicalBoxFragment* fragment = BoxFragment()) {
    fragment->LayoutObjectWillBeDestroyed();
  }
}

void FragmentItem::LayoutObjectWillBeMoved() const {
  // When |Layoutobject| is moved out from the current IFC, we should not clear
  // the association with it in |ClearAssociatedFragments|, because the
  // |LayoutObject| may be moved to a different IFC and is already laid out
  // before clearing this IFC. This happens e.g., when split inlines moves
  // inline children into a child anonymous block.
  const_cast<FragmentItem*>(this)->layout_object_ = nullptr;
}

const PhysicalOffset FragmentItem::ContentOffsetInContainerFragment() const {
  PhysicalOffset offset = OffsetInContainerFragment();
  if (const PhysicalBoxFragment* box = BoxFragment()) {
    offset += box->ContentOffset();
  }
  return offset;
}

inline const LayoutBox* FragmentItem::InkOverflowOwnerBox() const {
  if (Type() == kBox)
    return DynamicTo<LayoutBox>(GetLayoutObject());
  return nullptr;
}

inline LayoutBox* FragmentItem::MutableInkOverflowOwnerBox() {
  if (Type() == kBox) {
    return DynamicTo<LayoutBox>(
        const_cast<LayoutObject*>(layout_object_.Get()));
  }
  return nullptr;
}

PhysicalRect FragmentItem::SelfInkOverflowRect() const {
  if (const PhysicalBoxFragment* box_fragment = BoxFragment()) {
    return box_fragment->SelfInkOverflowRect();
  }
  if (!HasInkOverflow())
    return LocalRect();
  return ink_overflow_.Self(InkOverflowType(), Size());
}

PhysicalRect FragmentItem::InkOverflowRect() const {
  if (const PhysicalBoxFragment* box_fragment = BoxFragment()) {
    return box_fragment->InkOverflowRect();
  }
  if (!HasInkOverflow())
    return LocalRect();
  if (!IsContainer() || HasNonVisibleOverflow())
    return ink_overflow_.Self(InkOverflowType(), Size());
  return ink_overflow_.SelfAndContents(InkOverflowType(), Size());
}

const ShapeResultView* FragmentItem::TextShapeResult() const {
  if (Type() == kText)
    return text_.shape_result.Get();
  if (Type() == kGeneratedText)
    return generated_text_.shape_result.Get();
  NOTREACHED();
}

TextOffsetRange FragmentItem::TextOffset() const {
  if (Type() == kText)
    return text_.text_offset;
  if (Type() == kGeneratedText)
    return {0, generated_text_.text.length()};
  NOTREACHED();
}

unsigned FragmentItem::StartOffsetInContainer(
    const InlineCursor& container) const {
  DCHECK_EQ(Type(), kGeneratedText);
  DCHECK(!IsEllipsis());
  // Hyphens don't have the text offset in the container. Find the closest
  // previous text fragment.
  DCHECK_EQ(container.Current().Item(), this);
  InlineCursor cursor(container);
  for (cursor.MoveToPrevious(); cursor; cursor.MoveToPrevious()) {
    const InlineCursorPosition& current = cursor.Current();
    if (current->IsText() && !current->IsLayoutGeneratedText())
      return current->EndOffset();
    // A box doesn't have the offset either.
    if (current->Type() == kBox && !current->IsInlineBox())
      break;
  }
  // No such text fragment.  We don't know how to reproduce this.
  // See crbug.com/372586875.
  return 0;
}

StringView FragmentItem::Text(const FragmentItems& items) const {
  if (Type() == kText) {
    return StringView(items.Text(UsesFirstLineStyle()), text_.text_offset.start,
                      text_.text_offset.Length());
  }
  if (Type() == kGeneratedText)
    return GeneratedText();
  NOTREACHED();
}

TextFragmentPaintInfo FragmentItem::TextPaintInfo(
    const FragmentItems& items) const {
  if (Type() == kText) {
    return {items.Text(UsesFirstLineStyle()), text_.text_offset.start,
            text_.text_offset.end, text_.shape_result.Get()};
  }
  if (Type() == kGeneratedText) {
    return {generated_text_.text, 0, generated_text_.text.length(),
            generated_text_.shape_result.Get()};
  }
  NOTREACHED();
}

TextDirection FragmentItem::BaseDirection() const {
  DCHECK_EQ(Type(), kLine);
  return static_cast<TextDirection>(text_direction_);
}

TextDirection FragmentItem::ResolvedDirection() const {
  DCHECK(IsText() || IsAtomicInline());
  return static_cast<TextDirection>(text_direction_);
}

bool FragmentItem::HasSvgTransformForPaint() const {
  if (const SvgFragmentData* svg_data = GetSvgFragmentData()) {
    return svg_data->length_adjust_scale != 1.0f || svg_data->angle != 0.0f;
  }
  return false;
}

bool FragmentItem::HasSvgTransformForBoundingBox() const {
  if (const SvgFragmentData* svg_data = GetSvgFragmentData()) {
    return svg_data->angle != 0.0f;
  }
  return false;
}

// For non-<textPath>:
//   length-adjust * translate(x, y) * rotate() * translate(-x, -y)
// For <textPath>:
//   translate(x, y) * rotate() * length-adjust * translate(-x, -y)
//
// (x, y) is the center of the rotation.  The center points of a non-<textPath>
// character and a <textPath> character are different.
AffineTransform FragmentItem::BuildSvgTransformForPaint() const {
  DCHECK(IsSvgText());
  if (text_.svg_data->in_text_path) {
    if (text_.svg_data->angle == 0.0f) {
      return BuildSvgTransformForLengthAdjust();
    }
    return BuildSvgTransformForTextPath(BuildSvgTransformForLengthAdjust());
  }
  AffineTransform transform = BuildSvgTransformForBoundingBox();
  AffineTransform length_adjust = BuildSvgTransformForLengthAdjust();
  if (!length_adjust.IsIdentity())
    transform.PostConcat(length_adjust);
  return transform;
}

AffineTransform FragmentItem::BuildSvgTransformForLengthAdjust() const {
  DCHECK(IsSvgText());
  const SvgFragmentData& svg_data = *text_.svg_data;
  const bool is_horizontal = IsHorizontal();
  AffineTransform scale_transform;
  float scale = svg_data.length_adjust_scale;
  if (scale != 1.0f) {
    // Inline offset adjustment is not necessary if this works with textPath
    // rotation.
    const bool with_text_path_transform =
        svg_data.in_text_path && svg_data.angle != 0.0f;
    // We'd like to scale only inline-size without moving inline position.
    if (is_horizontal) {
      float x = svg_data.rect.x();
      scale_transform.SetMatrix(
          scale, 0, 0, 1, with_text_path_transform ? 0 : x - scale * x, 0);
    } else {
      // svg_data.rect is a physical bounding rectangle including lengthAdjust
      // scaling.  So all vertical writing modes including sideways-lr need the
      // same transform.
      float y = svg_data.rect.y();
      scale_transform.SetMatrix(1, 0, 0, scale, 0,
                                with_text_path_transform ? 0 : y - scale * y);
    }
  }
  return scale_transform;
}

AffineTransform FragmentItem::BuildSvgTransformForTextPath(
    const AffineTransform& length_adjust) const {
  DCHECK(IsSvgText());
  const SvgFragmentData& svg_data = *text_.svg_data;
  DCHECK(svg_data.in_text_path);
  DCHECK_NE(svg_data.angle, 0.0f);

  AffineTransform transform;
  transform.Rotate(svg_data.angle);

  const SimpleFontData* font_data = ScaledFont().PrimaryFont();

  // https://svgwg.org/svg2-draft/text.html#TextpathLayoutRules
  // The rotation should be about the center of the baseline.
  const auto font_baseline = Style().GetFontBaseline();
  // |x| in the horizontal writing-mode and |y| in the vertical writing-mode
  // point the center of the baseline.  See |SvgTextLayoutAlgorithm::
  // PositionOnPath()|.
  float x = svg_data.rect.x();
  float y = svg_data.rect.y();
  switch (GetWritingMode()) {
    case WritingMode::kHorizontalTb:
      y += font_data->GetFontMetrics().FixedAscent(font_baseline);
      transform.Translate(-svg_data.rect.width() / 2, svg_data.baseline_shift);
      break;
    case WritingMode::kVerticalLr:
    case WritingMode::kVerticalRl:
    case WritingMode::kSidewaysRl:
      x += font_data->GetFontMetrics().FixedDescent(font_baseline);
      transform.Translate(svg_data.baseline_shift, -svg_data.rect.height() / 2);
      break;
    case WritingMode::kSidewaysLr:
      x += font_data->GetFontMetrics().FixedAscent(font_baseline);
      y = svg_data.rect.bottom();
      transform.Translate(-svg_data.baseline_shift, svg_data.rect.height() / 2);
      break;
  }
  transform.PreConcat(length_adjust);
  transform.SetE(transform.E() + x);
  transform.SetF(transform.F() + y);
  transform.Translate(-x, -y);
  return transform;
}

// This function returns:
//   translate(x, y) * rotate() * translate(-x, -y)
//
// (x, y) is the center of the rotation.  The center points of a non-<textPath>
// character and a <textPath> character are different.
AffineTransform FragmentItem::BuildSvgTransformForBoundingBox() const {
  DCHECK(IsSvgText());
  const SvgFragmentData& svg_data = *text_.svg_data;
  AffineTransform transform;
  if (svg_data.angle == 0.0f)
    return transform;
  if (svg_data.in_text_path)
    return BuildSvgTransformForTextPath(AffineTransform());

  transform.Rotate(svg_data.angle);
  const SimpleFontData* font_data = ScaledFont().PrimaryFont();
  // https://svgwg.org/svg2-draft/text.html#TextElementRotateAttribute
  // > The supplemental rotation, in degrees, about the current text position
  //
  // TODO(crbug.com/1179585): The following code is equivalent to the legacy
  // SVG. That is to say, rotation around the left edge of the baseline.
  // However it doesn't look correct for RTL and vertical text.
  float ascent =
      font_data ? font_data->GetFontMetrics().FixedAscent().ToFloat() : 0.0f;
  float y = svg_data.rect.y() + ascent;
  transform.SetE(transform.E() + svg_data.rect.x());
  transform.SetF(transform.F() + y);
  transform.Translate(-svg_data.rect.x(), -y);
  return transform;
}

float FragmentItem::SvgScalingFactor() const {
  const auto* svg_inline_text =
      DynamicTo<LayoutSVGInlineText>(GetLayoutObject());
  if (!svg_inline_text)
    return 1.0f;
  const float scaling_factor = svg_inline_text->ScalingFactor();
  DCHECK_GT(scaling_factor, 0.0f);
  return scaling_factor;
}

const Font& FragmentItem::ScaledFont() const {
  if (const auto* svg_inline_text =
          DynamicTo<LayoutSVGInlineText>(GetLayoutObject()))
    return svg_inline_text->ScaledFont();
  return Style().GetFont();
}

String FragmentItem::ToString() const {
  StringBuilder name;
  name.Append("FragmentItem");
  if (IsHiddenForPaint()) {
    name.Append(" (hidden)");
  }
  switch (Type()) {
    case FragmentItem::kBox:
      name.Append(" Box ");
      name.Append(layout_object_->DebugName());
      break;
    case FragmentItem::kText: {
      name.Append(" Text ");
      const FragmentItems* fragment_items = nullptr;
      if (const LayoutBlockFlow* block_flow =
              layout_object_->FragmentItemsContainer()) {
        for (unsigned i = 0; i < block_flow->PhysicalFragmentCount(); ++i) {
          const PhysicalBoxFragment* containing_fragment =
              block_flow->GetPhysicalFragment(i);
          fragment_items = containing_fragment->Items();
          if (fragment_items) {
            break;
          }
        }
      }
      if (fragment_items) {
        name.Append(Text(*fragment_items).ToString().EncodeForDebugging());
      } else {
        name.Append("\"(container not found)\"");
      }
      break;
    }
    case FragmentItem::kGeneratedText:
      name.Append(" GeneratedText ");
      name.Append(GeneratedText().EncodeForDebugging());
      name.Append(" ");
      name.Append(layout_object_ ? layout_object_->DebugName() : "null");
      break;
    case FragmentItem::kLine:
      name.Append(" Line");
      break;
    case FragmentItem::kInvalid:
      name.Append(" Invalid");
      break;
  }
  return name.ToString();
}

PhysicalRect FragmentItem::LocalVisualRectFor(
    const LayoutObject& layout_object) {
  DCHECK(layout_object.IsInLayoutNGInlineFormattingContext());

  PhysicalRect visual_rect;
  InlineCursor cursor;
  for (cursor.MoveTo(layout_object); cursor;
       cursor.MoveToNextForSameLayoutObject()) {
    DCHECK(cursor.Current().Item());
    const FragmentItem& item = *cursor.Current().Item();
    if (item.IsHiddenForPaint()) [[unlikely]] {
      continue;
    }
    PhysicalRect child_visual_rect = item.SelfInkOverflowRect();
    child_visual_rect.offset += item.OffsetInContainerFragment();
    visual_rect.Unite(child_visual_rect);
  }
  return visual_rect;
}

void FragmentItem::InvalidateInkOverflow() {
  ink_overflow_type_ =
      static_cast<unsigned>(ink_overflow_.Invalidate(InkOverflowType()));
}

PhysicalRect FragmentItem::RecalcInkOverflowForCursor(
    InlineCursor* cursor,
    InlinePaintContext* inline_context) {
  DCHECK(cursor);
  DCHECK(!cursor->Current() || cursor->IsAtFirst());
  PhysicalRect contents_ink_overflow;
  for (; *cursor; cursor->MoveToNextSkippingChildren()) {
    const FragmentItem* item = cursor->CurrentItem();
    DCHECK(item);
    if (item->IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
      // TODO(crbug.com/1099613): This should not happen, as long as it is
      // layout-clean. It looks like there are cases where the layout is dirty.
      continue;
    }
    if (item->HasSelfPaintingLayer()) [[unlikely]] {
      continue;
    }

    PhysicalRect child_rect;
    item->GetMutableForPainting().RecalcInkOverflow(*cursor, inline_context,
                                                    &child_rect);
    if (!child_rect.IsEmpty()) {
      child_rect.offset += item->OffsetInContainerFragment();
      contents_ink_overflow.Unite(child_rect);
    }
  }
  return contents_ink_overflow;
}

void FragmentItem::RecalcInkOverflow(const InlineCursor& cursor,
                                     InlinePaintContext* inline_context,
                                     PhysicalRect* self_and_contents_rect_out) {
  DCHECK_EQ(this, cursor.CurrentItem());

  if (IsLayoutObjectDestroyedOrMoved()) [[unlikely]] {
    // TODO(crbug.com/1099613): This should not happen, as long as it is really
    // layout-clean. It looks like there are cases where the layout is dirty.
    NOTREACHED();
  }

  if (IsText()) {
    // Re-computing text item is not necessary, because all changes that needs
    // to re-compute ink overflow invalidate layout. Except for box shadows,
    // text decorations and outlines that are invalidated before this point in
    // the code.
    if (IsInkOverflowComputed()) {
      *self_and_contents_rect_out = SelfInkOverflowRect();
      return;
    }

    TextFragmentPaintInfo paint_info = TextPaintInfo(cursor.Items());
    if (paint_info.shape_result) {
      if (const SvgFragmentData* svg_data = GetSvgFragmentData()) {
        ink_overflow_type_ =
            static_cast<unsigned>(ink_overflow_.SetSvgTextInkOverflow(
                InkOverflowType(), cursor, paint_info, Style(), ScaledFont(),
                svg_data->rect, SvgScalingFactor(),
                svg_data->length_adjust_scale,
                BuildSvgTransformForBoundingBox(), self_and_contents_rect_out));
        return;
      }
      // Create |ScopedInlineItem| here because the decoration box is not
```