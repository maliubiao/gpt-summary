Response:
Let's break down the thought process for analyzing the `line_truncator.cc` file.

**1. Initial Understanding of the File Path and Purpose:**

* **Path:** `blink/renderer/core/layout/inline/line_truncator.cc`  This immediately tells us a few things:
    * It's part of the Blink rendering engine (Chrome's rendering engine).
    * It's located within the `core` module, meaning it deals with fundamental layout logic.
    * It's specifically in the `layout/inline` directory, indicating its role in handling inline content layout.
    * The file name `line_truncator.cc` strongly suggests its primary function is to truncate text within a line.

**2. Analyzing the Includes:**

The included header files provide crucial clues about the dependencies and functionality:

* `base/containers/adapters.h`: Likely used for iterating over containers in reverse order (seen later in the code).
* `third_party/blink/renderer/core/layout/inline/inline_box_state.h`, `inline_item_result.h`, `line_info.h`, `logical_line_item.h`: These are all related to the internal representation of inline content and line breaking. They hint at the data structures the `LineTruncator` works with.
* `physical_box_fragment.h`:  Deals with the visual representation of layout objects, indicating the `LineTruncator` interacts with how content is displayed.
* `third_party/blink/renderer/platform/fonts/font_baseline.h`, `shaping/harfbuzz_shaper.h`, `shaping/shape_result_view.h`:  These are font and text shaping related, confirming the focus on text manipulation. HarfBuzz is a known text shaping engine.

**3. Examining the Class Definition (`LineTruncator`):**

* **Constructor:** Takes a `LineInfo` object, suggesting it operates within the context of a specific line of text. It initializes members like `line_style_`, `available_width_`, `line_direction_`, and `use_first_line_style_`.
* **`EllipsisStyle()`:**  Returns the style to use for the ellipsis character. The comment links to the CSS UI specification, connecting this to a web standard.
* **`SetupEllipsis()`:**  Handles the creation and shaping of the ellipsis character ("..."). It uses HarfBuzz for shaping, confirming its role in text rendering.
* **`PlaceEllipsisNextTo()`:**  Determines the position of the ellipsis next to a truncated element, considering text direction (LTR/RTL).
* **`AddTruncatedChild()`:** Creates a new "truncated" line item, representing a portion of text that has been cut off. It uses `ShapeResult::OffsetToFit` to find the truncation point.
* **`TruncateLine()`:** This appears to be the core function for truncating a line. It iterates through line items, determines where to place the ellipsis, and potentially creates a truncated item. The logic handles both LTR and RTL text directions.
* **`TruncateLineInTheMiddle()`:**  A more specialized truncation method, likely for specific cases like `<input type="file">`. It attempts to place the ellipsis in the middle, truncating content on both sides.
* **`HideChild()`:**  Marks a line item as hidden for painting, effectively making it invisible without affecting layout calculations.
* **`EllipsizeChild()`:** Decides whether and how to truncate a specific child element to make space for the ellipsis.
* **`TruncateChild()`:**  Performs the actual truncation of a child element (specifically text).
* **`TruncateText()`:**  Creates a new `LogicalLineItem` representing the truncated portion of text.

**4. Identifying Key Functionality and Relationships:**

Based on the analysis above, the core functionalities emerge:

* **Text Truncation:** The primary goal is to shorten text that doesn't fit within a line's width.
* **Ellipsis Insertion:**  Adding the "..." character to indicate truncation.
* **Text Direction Handling (LTR/RTL):**  Correctly positioning the ellipsis and determining truncation points based on text direction.
* **Inline Layout Integration:** Working with `LogicalLineItems` and other inline layout structures.
* **Font and Text Shaping:** Using HarfBuzz to calculate text widths and glyph positions.

**5. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **CSS:** The code directly relates to the `text-overflow: ellipsis` CSS property. The `EllipsisStyle()` function and the overall truncation logic are implementations of this feature.
* **HTML:**  The truncation applies to the text content of HTML elements. The `<input type="file">` example shows how it might handle specific HTML structures.
* **JavaScript:**  JavaScript can trigger layout changes that might necessitate text truncation. While the `LineTruncator` itself isn't directly called from JS, it's part of the rendering pipeline that responds to JS-driven DOM manipulation and style changes.

**6. Developing Examples (Hypothetical Input/Output, Usage Errors):**

This involves thinking about how the code would behave in different scenarios:

* **Simple Truncation:** A long string within a fixed-width container.
* **RTL Text:** Ensuring the ellipsis appears on the correct side.
* **Atomic Inline Elements:**  How elements like images are handled during truncation.
* **Usage Errors:**  Situations where the developer might expect different behavior or where the code might have limitations.

**7. Refining and Organizing the Information:**

Finally, the information needs to be organized clearly, with distinct sections for functionality, relationships to web technologies, examples, and potential errors. Using bullet points, code snippets (even hypothetical ones), and clear language helps in conveying the information effectively.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it just adds the ellipsis. **Correction:** The code also handles *how* to truncate the text to make space for the ellipsis.
* **Focusing too much on one function:** Realizing that `TruncateLine` and `TruncateLineInTheMiddle` have different purposes and need separate explanations.
* **Not enough concrete examples:**  Adding hypothetical HTML/CSS to illustrate the connection to web technologies.
* **Overlooking potential errors:**  Specifically thinking about what could go wrong from a developer's perspective (e.g., assuming truncation works on all element types).
这个文件 `blink/renderer/core/layout/inline/line_truncator.cc` 的主要功能是**处理行内布局中，当文本内容超出可用宽度时进行截断并添加省略号（ellipsis）**。 它负责实现 CSS 的 `text-overflow: ellipsis;` 属性的效果。

下面分点详细列举其功能，并结合 JavaScript, HTML, CSS 来说明关系，并提供假设输入输出和常见错误示例。

**功能列举:**

1. **计算省略号的尺寸:**  `SetupEllipsis()` 方法会根据当前行的样式（字体、字号等）计算出省略号（"..." 或其他表示）的宽度和高度。

2. **确定省略号的位置:** `PlaceEllipsisNextTo()` 方法根据文本方向 (LTR 或 RTL) 和被截断的元素的位置，计算出放置省略号的最佳位置。

3. **截断文本内容:**  `TruncateLine()` 和 `TruncateLineInTheMiddle()` 是核心方法，它们负责识别需要被截断的文本元素，并根据可用宽度计算出截断点。

4. **创建被截断的文本片段:** `AddTruncatedChild()` 和 `TruncateText()` 方法用于创建一个新的表示被截断文本的内部数据结构 (`LogicalLineItem`)。这个新的数据结构包含了截断后的文本范围和对应的渲染信息。

5. **处理不同类型的行内元素:** `EllipsizeChild()` 方法会判断当前的行内元素是否需要被截断，并处理不同类型的元素，例如文本节点和原子级行内元素 (atomic inline-level elements，例如 `<img>`)。

6. **处理文本方向:**  代码中多次出现对 `line_direction_` (文本方向) 的判断，确保在 RTL (从右到左) 和 LTR (从左到右) 的布局中，省略号的位置和截断逻辑是正确的。

7. **处理 `text-overflow: ellipsis` 属性:** 整个类的设计和功能都是为了实现 `text-overflow: ellipsis` 的 CSS 属性。

8. **处理特殊的截断情况:** `TruncateLineInTheMiddle()` 方法处理一些特殊的截断需求，例如在 `<input type="file">` 元素中将文件名截断并在中间显示省略号。

9. **隐藏被截断的原始元素:** `HideChild()` 方法会将原始的、未截断的元素标记为隐藏，以便在渲染时只显示被截断的部分和省略号。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **CSS (`text-overflow: ellipsis;`)**:  `LineTruncator` 的核心目标是实现 `text-overflow: ellipsis;` 的效果。
    * **HTML:**  考虑以下 HTML 结构：
        ```html
        <div style="width: 100px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
          This is a very long text that will be truncated.
        </div>
        ```
    * **CSS:** 上面的 CSS 样式中，`text-overflow: ellipsis;` 告诉浏览器，当文本超出容器宽度时，应该用省略号来表示截断。
    * **Blink/LineTruncator:** 当 Blink 渲染引擎遇到这样的样式时，`LineTruncator` 类会被调用来执行截断操作。它会计算出在哪个位置截断文本，并在末尾添加省略号。

* **JavaScript (间接关系):** JavaScript 可以动态修改元素的文本内容或样式，从而间接影响 `LineTruncator` 的工作。
    * **例子:**
        ```javascript
        const div = document.querySelector('div');
        div.textContent = 'An even longer text that requires more truncation.';
        ```
        如果 JavaScript 修改了 `div` 的文本内容，使其超出容器宽度，Blink 的布局引擎会重新计算布局，并可能调用 `LineTruncator` 来应用省略号。

* **HTML (文本内容):**  `LineTruncator` 处理的是 HTML 元素中的文本内容。
    * **例子:**  在上面的 HTML 例子中，`LineTruncator` 会处理 `<div>` 标签内的文本 `"This is a very long text that will be truncated."`。

**逻辑推理的假设输入与输出:**

**假设输入:**

* **HTML:**
    ```html
    <div id="test" style="width: 80px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
      VeryLongTextContent
    </div>
    ```
* **CSS:** (已内联在 HTML 中)
* **`LineInfo` 对象:**  包含 `available_width_ = 80px`，`line_direction_ = LTR`，以及文本内容的渲染信息（字体等）。

**输出 (预期):**

* 在渲染后的页面上，`<div>` 元素会显示类似 `"VeryLong..."` 的内容。
* `LineTruncator` 的内部操作会：
    1. 计算省略号的宽度。
    2. 确定在 "VeryLong" 之后需要截断。
    3. 创建一个表示 "VeryLong" 的 `LogicalLineItem`。
    4. 在其后添加表示省略号的元素。
    5. 隐藏原始的完整文本内容。

**用户或编程常见的使用错误举例说明:**

1. **忘记设置 `overflow: hidden;` 或 `overflow: scroll;`:**  `text-overflow: ellipsis;` 只有在元素发生溢出时才会生效。 如果没有设置 `overflow` 属性来限制内容的显示，文本不会被截断，省略号也不会显示。
    ```html
    <div style="width: 100px; text-overflow: ellipsis; white-space: nowrap;">
      This text will not be truncated because overflow is not hidden.
    </div>
    ```

2. **忘记设置 `white-space: nowrap;`:**  `text-overflow: ellipsis;` 通常与 `white-space: nowrap;` 一起使用，以确保文本不会换行，从而触发溢出。 如果文本可以换行，则不会发生单行溢出，省略号也不会显示。
    ```html
    <div style="width: 100px; overflow: hidden; text-overflow: ellipsis;">
      This text might wrap and not trigger ellipsis.
    </div>
    ```

3. **对块级元素使用 `text-overflow: ellipsis;` 但没有限制宽度:**  如果一个块级元素没有明确的宽度限制，它会尽可能地占用可用空间，通常不会发生溢出，因此省略号也不会显示。
    ```html
    <div style="text-overflow: ellipsis; white-space: nowrap;">
      This might not work as expected for block-level elements without width.
    </div>
    ```

4. **期望 `text-overflow: ellipsis;` 可以截断多行文本:** `text-overflow: ellipsis;` 只能处理单行文本的截断。 对于多行文本的截断，需要使用其他技术，例如 `-webkit-line-clamp` (WebKit 浏览器和 Chrome) 或 JavaScript 实现。

总而言之，`blink/renderer/core/layout/inline/line_truncator.cc` 是 Blink 渲染引擎中负责实现 `text-overflow: ellipsis;` 这一重要 CSS 特性的关键组件，它深入处理文本布局和渲染的细节，确保在各种情况下都能正确地截断文本并显示省略号。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/line_truncator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/line_truncator.h"

#include "base/containers/adapters.h"
#include "third_party/blink/renderer/core/layout/inline/inline_box_state.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result.h"
#include "third_party/blink/renderer/core/layout/inline/line_info.h"
#include "third_party/blink/renderer/core/layout/inline/logical_line_item.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/platform/fonts/font_baseline.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"

namespace blink {

namespace {

bool IsLeftMostOffset(const ShapeResult& shape_result, unsigned offset) {
  if (shape_result.IsRtl())
    return offset == shape_result.NumCharacters();
  return offset == 0;
}

bool IsRightMostOffset(const ShapeResult& shape_result, unsigned offset) {
  if (shape_result.IsRtl())
    return offset == 0;
  return offset == shape_result.NumCharacters();
}

}  // namespace

LineTruncator::LineTruncator(const LineInfo& line_info)
    : line_style_(&line_info.LineStyle()),
      available_width_(line_info.AvailableWidth() - line_info.TextIndent()),
      line_direction_(line_info.BaseDirection()),
      use_first_line_style_(line_info.UseFirstLineStyle()) {}

const ComputedStyle& LineTruncator::EllipsisStyle() const {
  // The ellipsis is styled according to the line style.
  // https://drafts.csswg.org/css-ui/#ellipsing-details
  DCHECK(line_style_);
  return *line_style_;
}

void LineTruncator::SetupEllipsis() {
  const Font& font = EllipsisStyle().GetFont();
  ellipsis_font_data_ = font.PrimaryFont();
  DCHECK(ellipsis_font_data_);
  ellipsis_text_ =
      ellipsis_font_data_ && ellipsis_font_data_->GlyphForCharacter(
                                 kHorizontalEllipsisCharacter)
          ? String(base::span_from_ref(kHorizontalEllipsisCharacter))
          : String(u"...");
  HarfBuzzShaper shaper(ellipsis_text_);
  ellipsis_shape_result_ =
      ShapeResultView::Create(shaper.Shape(&font, line_direction_));
  ellipsis_width_ = ellipsis_shape_result_->SnappedWidth();
}

LayoutUnit LineTruncator::PlaceEllipsisNextTo(
    LogicalLineItems* line_box,
    LogicalLineItem* ellipsized_child) {
  // Create the ellipsis, associating it with the ellipsized child.
  DCHECK(ellipsized_child->HasInFlowFragment());
  const LayoutObject* ellipsized_layout_object =
      ellipsized_child->GetMutableLayoutObject();
  DCHECK(ellipsized_layout_object);
  DCHECK(ellipsized_layout_object->IsInline());
  DCHECK(ellipsized_layout_object->IsText() ||
         ellipsized_layout_object->IsAtomicInlineLevel());

  // Now the offset of the ellpisis is determined. Place the ellpisis into the
  // line box.
  LayoutUnit ellipsis_inline_offset =
      IsLtr(line_direction_)
          ? ellipsized_child->InlineOffset() + ellipsized_child->inline_size
          : ellipsized_child->InlineOffset() - ellipsis_width_;
  FontHeight ellipsis_metrics;
  DCHECK(ellipsis_font_data_);
  if (ellipsis_font_data_) {
    ellipsis_metrics = ellipsis_font_data_->GetFontMetrics().GetFontHeight(
        line_style_->GetFontBaseline());
  }

  DCHECK(ellipsis_text_);
  DCHECK(ellipsis_shape_result_);
  line_box->AddChild(
      *ellipsized_layout_object,
      use_first_line_style_ ? StyleVariant::kFirstLineEllipsis
                            : StyleVariant::kStandardEllipsis,
      ellipsis_shape_result_, ellipsis_text_,
      LogicalRect(ellipsis_inline_offset, -ellipsis_metrics.ascent,
                  ellipsis_width_, ellipsis_metrics.LineHeight()),
      /* bidi_level */ 0);
  return ellipsis_inline_offset;
}

wtf_size_t LineTruncator::AddTruncatedChild(
    wtf_size_t source_index,
    bool leave_one_character,
    LayoutUnit position,
    TextDirection edge,
    LogicalLineItems* line_box,
    InlineLayoutStateStack* box_states) {
  LogicalLineItems& line = *line_box;
  const LogicalLineItem& source_item = line[source_index];
  DCHECK(source_item.shape_result);
  const ShapeResult* shape_result =
      source_item.shape_result->CreateShapeResult();
  unsigned text_offset = shape_result->OffsetToFit(position, edge);
  if (IsLtr(edge) ? IsLeftMostOffset(*shape_result, text_offset)
                  : IsRightMostOffset(*shape_result, text_offset)) {
    if (!leave_one_character)
      return kDidNotAddChild;
    text_offset =
        shape_result->OffsetToFit(shape_result->PositionForOffset(
                                      IsRtl(edge) == shape_result->IsRtl()
                                          ? 1
                                          : shape_result->NumCharacters() - 1),
                                  edge);
  }

  const wtf_size_t new_index = line.size();
  line.AddChild(TruncateText(source_item, *shape_result, text_offset, edge));
  box_states->ChildInserted(new_index);
  return new_index;
}

LayoutUnit LineTruncator::TruncateLine(LayoutUnit line_width,
                                       LogicalLineItems* line_box,
                                       InlineLayoutStateStack* box_states) {
  // Shape the ellipsis and compute its inline size.
  SetupEllipsis();

  // Loop children from the logical last to the logical first to determine where
  // to place the ellipsis. Children maybe truncated or moved as part of the
  // process.
  LogicalLineItem* ellipsized_child = nullptr;
  std::optional<LogicalLineItem> truncated_child;
  if (IsLtr(line_direction_)) {
    LogicalLineItem* first_child = line_box->FirstInFlowChild();
    for (auto& child : base::Reversed(*line_box)) {
      if (EllipsizeChild(line_width, ellipsis_width_, &child == first_child,
                         &child, &truncated_child)) {
        ellipsized_child = &child;
        break;
      }
    }
  } else {
    LogicalLineItem* first_child = line_box->LastInFlowChild();
    for (auto& child : *line_box) {
      if (EllipsizeChild(line_width, ellipsis_width_, &child == first_child,
                         &child, &truncated_child)) {
        ellipsized_child = &child;
        break;
      }
    }
  }

  // Abort if ellipsis could not be placed.
  if (!ellipsized_child)
    return line_width;

  // Truncate the text fragment if needed.
  if (truncated_child) {
    // In order to preserve layout information before truncated, hide the
    // original fragment and insert a truncated one.
    unsigned child_index_to_truncate =
        base::checked_cast<unsigned>(ellipsized_child - &*line_box->begin());
    line_box->InsertChild(child_index_to_truncate + 1,
                          std::move(*truncated_child));
    box_states->ChildInserted(child_index_to_truncate + 1);
    LogicalLineItem* child_to_truncate = &(*line_box)[child_index_to_truncate];
    ellipsized_child = std::next(child_to_truncate);

    HideChild(child_to_truncate);
    DCHECK_LE(ellipsized_child->inline_size, child_to_truncate->inline_size);
    if (IsRtl(line_direction_)) [[unlikely]] {
      ellipsized_child->rect.offset.inline_offset +=
          child_to_truncate->inline_size - ellipsized_child->inline_size;
    }
  }

  // Create the ellipsis, associating it with the ellipsized child.
  LayoutUnit ellipsis_inline_offset =
      PlaceEllipsisNextTo(line_box, ellipsized_child);
  return std::max(ellipsis_inline_offset + ellipsis_width_, line_width);
}

// This function was designed to work only with <input type=file>.
// We assume the line box contains:
//     (Optional) children without in-flow fragments
//     Children with in-flow fragments, and
//     (Optional) children without in-flow fragments
// in this order, and the children with in-flow fragments have no padding,
// no border, and no margin.
// Children with IsPlaceholder() can appear anywhere.
LayoutUnit LineTruncator::TruncateLineInTheMiddle(
    LayoutUnit line_width,
    LogicalLineItems* line_box,
    InlineLayoutStateStack* box_states) {
  // Shape the ellipsis and compute its inline size.
  SetupEllipsis();

  LogicalLineItems& line = *line_box;
  wtf_size_t initial_index_left = kNotFound;
  wtf_size_t initial_index_right = kNotFound;
  for (wtf_size_t i = 0; i < line_box->size(); ++i) {
    auto& child = line[i];
    if (child.IsPlaceholder())
      continue;
    if (!child.shape_result) {
      if (initial_index_right != kNotFound)
        break;
      continue;
    }
    // Skip pseudo elements like ::before.
    if (!child.GetNode())
      continue;

    if (initial_index_left == kNotFound)
      initial_index_left = i;
    initial_index_right = i;
  }
  // There are no truncatable children.
  if (initial_index_left == kNotFound)
    return line_width;
  DCHECK_NE(initial_index_right, kNotFound);
  DCHECK(line[initial_index_left].HasInFlowFragment());
  DCHECK(line[initial_index_right].HasInFlowFragment());

  // line[]:
  //     s s s p f f p f f s s
  //             ^       ^
  // initial_index_left  |
  //                     initial_index_right
  //   s: child without in-flow fragment
  //   p: placeholder child
  //   f: child with in-flow fragment

  const LayoutUnit static_width_left = line[initial_index_left].InlineOffset();
  LayoutUnit static_width_right = LayoutUnit(0);
  if (initial_index_right + 1 < line.size()) {
    const LogicalLineItem& item = line[initial_index_right];
    LayoutUnit truncatable_right = item.InlineOffset() + item.inline_size;
    // |line_width| and/or truncatable_right might be saturated.
    if (line_width <= truncatable_right) {
      return line_width;
    }
    // We can do nothing if the right-side static item sticks out to the both
    // sides.
    if (truncatable_right < 0) {
      return line_width;
    }
    static_width_right = line_width - truncatable_right;
  }
  const LayoutUnit available_width =
      available_width_ - static_width_left - static_width_right;
  if (available_width <= ellipsis_width_)
    return line_width;
  LayoutUnit available_width_left = (available_width - ellipsis_width_) / 2;
  LayoutUnit available_width_right = available_width_left;

  // Children for ellipsis and truncated fragments will have index which
  // is >= new_child_start.
  const wtf_size_t new_child_start = line.size();

  wtf_size_t index_left = initial_index_left;
  wtf_size_t index_right = initial_index_right;

  if (IsLtr(line_direction_)) {
    // Find truncation point at the left, truncate, and add an ellipsis.
    while (available_width_left >= line[index_left].inline_size) {
      available_width_left -= line[index_left++].inline_size;
      if (index_left >= line.size()) {
        // We have a logic bug. Do nothing.
        return line_width;
      }
    }
    DCHECK_LE(index_left, index_right);
    DCHECK(!line[index_left].IsPlaceholder());
    wtf_size_t new_index = AddTruncatedChild(
        index_left, index_left == initial_index_left, available_width_left,
        TextDirection::kLtr, line_box, box_states);
    if (new_index == kDidNotAddChild) {
      DCHECK_GT(index_left, initial_index_left);
      DCHECK_GT(index_left, 0u);
      wtf_size_t i = index_left;
      while (!line[--i].HasInFlowFragment())
        DCHECK(line[i].IsPlaceholder());
      PlaceEllipsisNextTo(line_box, &line[i]);
      available_width_right += available_width_left;
    } else {
      PlaceEllipsisNextTo(line_box, &line[new_index]);
      available_width_right +=
          available_width_left -
          line[new_index].inline_size.ClampNegativeToZero();
    }

    // Find truncation point at the right.
    while (available_width_right >= line[index_right].inline_size) {
      available_width_right -= line[index_right].inline_size;
      if (index_right == 0) {
        // We have a logic bug. We proceed anyway because |line| was already
        // modified.
        break;
      }
      --index_right;
    }
    LayoutUnit new_modified_right_offset =
        line[line.size() - 1].InlineOffset() + ellipsis_width_;
    DCHECK_LE(index_left, index_right);
    DCHECK(!line[index_right].IsPlaceholder());
    if (available_width_right > 0) {
      new_index = AddTruncatedChild(
          index_right, false,
          line[index_right].inline_size - available_width_right,
          TextDirection::kRtl, line_box, box_states);
      if (new_index != kDidNotAddChild) {
        line[new_index].rect.offset.inline_offset = new_modified_right_offset;
        new_modified_right_offset += line[new_index].inline_size;
      }
    }
    // Shift unchanged children at the right of the truncated child.
    // It's ok to modify existing children's offsets because they are not
    // web-exposed.
    LayoutUnit offset_diff = line[index_right].InlineOffset() +
                             line[index_right].inline_size -
                             new_modified_right_offset;
    for (wtf_size_t i = index_right + 1; i < new_child_start; ++i)
      line[i].rect.offset.inline_offset -= offset_diff;
    line_width -= offset_diff;

  } else {
    // Find truncation point at the right, truncate, and add an ellipsis.
    while (available_width_right >= line[index_right].inline_size) {
      available_width_right -= line[index_right].inline_size;
      if (index_right == 0) {
        // We have a logic bug. Do nothing.
        return line_width;
      }
      --index_right;
    }
    DCHECK_LE(index_left, index_right);
    DCHECK(!line[index_right].IsPlaceholder());
    wtf_size_t new_index =
        AddTruncatedChild(index_right, index_right == initial_index_right,
                          line[index_right].inline_size - available_width_right,
                          TextDirection::kRtl, line_box, box_states);
    if (new_index == kDidNotAddChild) {
      DCHECK_LT(index_right, initial_index_right);
      wtf_size_t i = index_right;
      while (!line[++i].HasInFlowFragment())
        DCHECK(line[i].IsPlaceholder());
      PlaceEllipsisNextTo(line_box, &line[i]);
      available_width_left += available_width_right;
    } else {
      line[new_index].rect.offset.inline_offset +=
          line[index_right].inline_size - line[new_index].inline_size;
      PlaceEllipsisNextTo(line_box, &line[new_index]);
      available_width_left += available_width_right -
                              line[new_index].inline_size.ClampNegativeToZero();
    }
    LayoutUnit ellipsis_offset = line[line.size() - 1].InlineOffset();

    // Find truncation point at the left.
    while (available_width_left >= line[index_left].inline_size) {
      available_width_left -= line[index_left++].inline_size;
      if (index_left >= line.size()) {
        // We have a logic bug. We proceed anyway because |line| was already
        // modified.
        break;
      }
    }
    DCHECK_LE(index_left, index_right);
    DCHECK(!line[index_left].IsPlaceholder());
    if (available_width_left > 0) {
      new_index = AddTruncatedChild(index_left, false, available_width_left,
                                    TextDirection::kLtr, line_box, box_states);
      if (new_index != kDidNotAddChild) {
        line[new_index].rect.offset.inline_offset =
            ellipsis_offset - line[new_index].inline_size;
      }
    }

    // Shift unchanged children at the left of the truncated child.
    // It's ok to modify existing children's offsets because they are not
    // web-exposed.
    LayoutUnit offset_diff =
        line[line.size() - 1].InlineOffset() - line[index_left].InlineOffset();
    for (wtf_size_t i = index_left; i > 0; --i)
      line[i - 1].rect.offset.inline_offset += offset_diff;
    line_width -= offset_diff;
  }
  // Hide left/right truncated children and children between them.
  for (wtf_size_t i = index_left; i <= index_right; ++i) {
    if (line[i].HasInFlowFragment())
      HideChild(&line[i]);
  }

  return line_width;
}

// Hide this child from being painted. Leaves a hidden fragment so that layout
// queries such as |offsetWidth| work as if it is not truncated.
void LineTruncator::HideChild(LogicalLineItem* child) {
  DCHECK(child->HasInFlowFragment());

  if (const LayoutResult* layout_result = child->layout_result) {
    // Need to propagate OOF descendants in this inline-block child.
    const auto& fragment =
        To<PhysicalBoxFragment>(layout_result->GetPhysicalFragment());
    if (fragment.HasOutOfFlowPositionedDescendants())
      return;

    // Truncate this object. Atomic inline is monolithic.
    DCHECK(fragment.IsMonolithic());
    LayoutObject* layout_object = fragment.GetMutableLayoutObject();
    DCHECK(layout_object);
    DCHECK(layout_object->IsAtomicInlineLevel());
    layout_object->SetIsTruncated(true);
    return;
  }

  if (child->inline_item) {
    child->is_hidden_for_paint = true;
    return;
  }

  NOTREACHED();
}

// Return the offset to place the ellipsis.
//
// This function may truncate or move the child so that the ellipsis can fit.
bool LineTruncator::EllipsizeChild(
    LayoutUnit line_width,
    LayoutUnit ellipsis_width,
    bool is_first_child,
    LogicalLineItem* child,
    std::optional<LogicalLineItem>* truncated_child) {
  DCHECK(truncated_child && !*truncated_child);

  // Leave out-of-flow children as is.
  if (!child->HasInFlowFragment())
    return false;

  // Inline boxes should not be ellipsized. Usually they will be created in the
  // later phase, but empty inline box are already created.
  if (child->IsInlineBox())
    return false;

  // Can't place ellipsis if this child is completely outside of the box.
  LayoutUnit child_inline_offset =
      IsLtr(line_direction_)
          ? child->InlineOffset()
          : line_width - (child->InlineOffset() + child->inline_size);
  LayoutUnit space_for_child = available_width_ - child_inline_offset;
  if (space_for_child <= 0) {
    // This child is outside of the content box, but we still need to hide it.
    // When the box has paddings, this child outside of the content box maybe
    // still inside of the clipping box.
    if (!is_first_child)
      HideChild(child);
    return false;
  }

  // At least part of this child is in the box.
  // If |child| can fit in the space, truncate this line at the end of |child|.
  space_for_child -= ellipsis_width;
  if (space_for_child >= child->inline_size)
    return true;

  // If not all of this child can fit, try to truncate.
  if (TruncateChild(space_for_child, is_first_child, *child, truncated_child))
    return true;

  // This child is partially in the box, but it can't be truncated to fit. It
  // should not be visible because earlier sibling will be truncated.
  if (!is_first_child)
    HideChild(child);
  return false;
}

// Truncate the specified child. Returns true if truncated successfully, false
// otherwise.
//
// Note that this function may return true even if it can't fit the child when
// |is_first_child|, because the spec defines that the first character or atomic
// inline-level element on a line must be clipped rather than ellipsed.
// https://drafts.csswg.org/css-ui/#text-overflow
bool LineTruncator::TruncateChild(
    LayoutUnit space_for_child,
    bool is_first_child,
    const LogicalLineItem& child,
    std::optional<LogicalLineItem>* truncated_child) {
  DCHECK(truncated_child && !*truncated_child);

  // If the space is not enough, try the next child.
  if (space_for_child <= 0 && !is_first_child)
    return false;

  // Only text fragments can be truncated.
  if (!child.shape_result)
    return is_first_child;

  // TODO(layout-dev): Add support for OffsetToFit to ShapeResultView to avoid
  // this copy.
  const ShapeResult* shape_result = child.shape_result->CreateShapeResult();
  DCHECK(shape_result);
  const TextOffsetRange original_offset = child.text_offset;
  // Compute the offset to truncate.
  unsigned offset_to_fit = shape_result->OffsetToFit(
      IsLtr(line_direction_) ? space_for_child
                             : shape_result->Width() - space_for_child,
      line_direction_);
  DCHECK_LE(offset_to_fit, original_offset.Length());
  if (!offset_to_fit || offset_to_fit == original_offset.Length()) {
    if (!is_first_child)
      return false;
    offset_to_fit = !offset_to_fit ? 1 : offset_to_fit - 1;
  }
  *truncated_child =
      TruncateText(child, *shape_result, offset_to_fit, line_direction_);
  return true;
}

LogicalLineItem LineTruncator::TruncateText(const LogicalLineItem& item,
                                            const ShapeResult& shape_result,
                                            unsigned offset_to_fit,
                                            TextDirection direction) {
  const TextOffsetRange new_text_offset =
      direction == shape_result.Direction()
          ? TextOffsetRange(item.StartOffset(),
                            item.StartOffset() + offset_to_fit)
          : TextOffsetRange(item.StartOffset() + offset_to_fit,
                            item.EndOffset());
  const ShapeResultView* new_shape_result = ShapeResultView::Create(
      &shape_result, new_text_offset.start, new_text_offset.end);
  DCHECK(item.inline_item);
  return LogicalLineItem(item, new_shape_result, new_text_offset);
}

}  // namespace blink

"""

```