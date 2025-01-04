Response:
Let's break down the thought process for analyzing the `ruby_utils.cc` file.

1. **Understand the Goal:** The primary goal is to analyze the provided C++ code snippet and explain its functionalities, especially its relation to web technologies (HTML, CSS, JavaScript) and potential issues.

2. **Initial Scan and Keyword Identification:**  First, quickly scan the code for obvious keywords and structures. This helps in forming initial hypotheses about its purpose. Keywords like "ruby," "annotation," "line," "inline," "layout," "font," "style," "overhang," and "align" stand out. The file path `blink/renderer/core/layout/inline/ruby_utils.cc` itself strongly suggests it's related to the layout of ruby annotations within the Blink rendering engine.

3. **Decomposition by Function:**  The next step is to examine the individual functions and their roles. Start with the public functions and then look at the private helper functions they call.

    * **`ParseRubyInInlineItems`:** The name clearly indicates parsing of inline items related to ruby. The input is a `HeapVector<InlineItem>`, which suggests it's processing a sequence of layout items. The logic with `kOpenRubyColumn` and `kCloseRubyColumn` confirms it's identifying ruby structures within the inline flow.

    * **`GetOverhang`:** This function appears to calculate the "overhang" of annotations, meaning how much the annotation extends beyond the base text. It has two overloads, suggesting different ways of calculating this. The logic involving `RubyAlign` and comparisons of widths points to CSS ruby alignment properties.

    * **`CanApplyStartOverhang`:** This function seems to check if a start overhang can be applied, considering factors like the font size of the preceding text.

    * **`CommitPendingEndOverhang`:**  This function looks like it's finalizing the end overhang, potentially adjusting margins of placeholder items.

    * **`ApplyRubyAlign`:**  This function is central to the layout of ruby elements, taking into account available space and CSS `ruby-align` and `text-align` properties. The different cases in the `switch` statement directly correspond to the possible values of `ruby-align`.

    * **`ComputeAnnotationOverflow`:**  This function calculates how much the annotations extend above and below the base text line, considering factors like line height and text emphasis.

    * **`UpdateRubyColumnInlinePositions`:**  This function deals with positioning the ruby columns within the inline flow.

    * **`RubyBlockPositionCalculator`:**  This is a class that seems responsible for the overall block-level positioning of ruby annotations across multiple lines. The methods `GroupLines`, `HandleRubyLine`, `EnsureRubyLine`, `PlaceLines`, and `AddLinesTo` suggest a multi-stage process for arranging the ruby elements vertically.

4. **Connecting to Web Technologies:**  As each function is analyzed, actively think about how it relates to HTML, CSS, and JavaScript.

    * **HTML:**  The `<ruby>`, `<rt>`, and `<rb>` tags are the primary HTML elements for ruby annotations. The functions directly work on the layout of these elements.

    * **CSS:**  CSS properties like `ruby-align`, `text-align`, `font-size`, `line-height`, and `text-emphasis` are clearly influencing the logic within the functions. For example, `ApplyRubyAlign` directly uses the `RubyAlign()` and `TextAlign()` from the `ComputedStyle`.

    * **JavaScript:** While the core layout is handled by the C++ engine, JavaScript can manipulate the DOM (adding or removing ruby elements) and CSS styles, which will then trigger the layout calculations in this code.

5. **Identifying Logic and Assumptions:** Look for logical conditions and calculations. For example, the `GetOverhang` function assumes certain alignment behaviors based on the `ruby-align` property. The `ComputeAnnotationOverflow` function makes assumptions about the baseline and the impact of text emphasis.

6. **Considering Input and Output:** For more complex functions, try to imagine example inputs and the expected output. For instance, for `ParseRubyInInlineItems`, consider an input `InlineItem` vector representing `<ruby><rb>base</rb><rt>anno</rt></ruby>`. The output should be the indices of the start and end of the base and annotation.

7. **Identifying Potential Errors:**  Think about what could go wrong. Common user errors include:

    * Incorrectly nested ruby tags.
    * Conflicting CSS styles that make the ruby layout unpredictable.
    * Using very large font sizes for annotations, causing them to overlap with other content.

    Common programming errors in the engine itself could involve incorrect calculations of overhang or alignment, leading to visual rendering bugs.

8. **Structuring the Explanation:** Organize the findings logically. Start with a general overview, then detail each function, and finally address the connections to web technologies and potential errors. Use clear and concise language. Use examples where possible to illustrate the concepts.

9. **Refinement and Review:**  After drafting the explanation, review it for clarity, accuracy, and completeness. Ensure the examples are relevant and easy to understand. Double-check the connection between the code and the web technologies.

By following this systematic approach, one can effectively analyze a complex code snippet like `ruby_utils.cc` and understand its purpose and implications within the broader context of a web browser engine.
This C++ source code file, `ruby_utils.cc`, located within the Chromium Blink rendering engine, is specifically designed to handle the **layout and positioning of ruby annotations** in web pages. Ruby annotations are small lines of text displayed alongside base text, often used in East Asian typography to provide pronunciation or meaning.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Parsing Ruby Inline Items (`ParseRubyInInlineItems`)**: This function analyzes a sequence of inline layout items to identify the different parts of a ruby structure: the base text and the annotation(s). It takes a vector of `InlineItem` objects and a starting index as input and returns a structure (`RubyItemIndexes`) containing the start and end indices of the ruby column, base text, and annotation.

    * **Logic/Assumption:** It assumes the input `InlineItem` vector represents a valid ruby structure, starting with an `InlineItem::kOpenRubyColumn`. It iterates through the items to find corresponding `kCloseRubyColumn` and `kOpenTag` (for ruby text) items.
    * **Hypothetical Input:** A vector of `InlineItem` objects representing `[OpenRubyColumn, Text("base"), OpenTag(<rt>), Text("anno"), CloseTag, CloseRubyColumn]`.
    * **Hypothetical Output:** `indexes.base_end` would point to the index of "base", `indexes.annotation_start` would point to the index of `<rt>`, and `indexes.column_end` would point to the index of the final `CloseRubyColumn`.

2. **Calculating Annotation Overhang (`GetOverhang`)**: This function determines how much the ruby annotation visually extends beyond the base text. It takes the size of the ruby element and information about the base and annotation lines as input. The calculation depends on the `ruby-align` CSS property.

    * **Relationship to CSS:** The `ERubyAlign` enum and the logic within the function directly correspond to the values of the CSS `ruby-align` property (e.g., `space-between`, `start`, `center`).
    * **Example:** If `ruby-align: start;` and the annotation is wider than the base, the `overhang.end` will be calculated as the difference, indicating the annotation extends to the right (in LTR).

3. **Applying Start Overhang (`CanApplyStartOverhang`)**: This function checks if a start overhang can be applied to a ruby annotation. It considers the font size of the preceding text and the available space.

    * **Relationship to CSS:** This function implicitly relates to CSS by considering font sizes, which are defined via CSS.
    * **User/Programming Error:** If a large start overhang is specified, but the preceding text is very short, this function might prevent the overhang from being applied fully, potentially leading to unexpected layout.

4. **Committing Pending End Overhang (`CommitPendingEndOverhang`)**: This function finalizes the end overhang of a ruby annotation, potentially adjusting margins of placeholder elements. It's called when a text item follows a ruby column.

5. **Applying Ruby Alignment (`ApplyRubyAlign`)**: This function adjusts the inline positioning of ruby elements within a line based on the `ruby-align` and `text-align` CSS properties. It distributes available space according to the specified alignment rules.

    * **Relationship to CSS:** This function directly implements the behavior defined by the CSS `ruby-align` and `text-align` properties.
    * **Example:** If `ruby-align: space-around;`, this function will distribute the extra space around the ruby elements within the line. If `text-align: center;`, it will center the ruby element within the available space.

6. **Computing Annotation Overflow (`ComputeAnnotationOverflow`)**: This function calculates how much the ruby annotations extend above and below the normal line height of the base text. It considers the font sizes and line heights of both the base and annotation text.

    * **Relationship to CSS:**  This function depends on CSS properties like `font-size`, `line-height`, and `text-emphasis`.
    * **Example:** If the annotation has a larger font size or requires more line height than the base text, this function will calculate the overflow needed to accommodate the annotation.

7. **Updating Ruby Column Inline Positions (`UpdateRubyColumnInlinePositions`)**: This function updates the inline offsets of ruby columns within a line. It's used to position the annotations correctly relative to the base text.

8. **`RubyBlockPositionCalculator` Class**: This class manages the block-level positioning of ruby annotations across multiple lines. It groups lines of ruby annotations based on their nesting level and then places them vertically, considering their heights.

    * **`GroupLines`**: Organizes ruby columns into logical lines based on their nesting structure.
    * **`HandleRubyLine`**: Recursively processes ruby lines and their annotations.
    * **`EnsureRubyLine`**: Creates or retrieves a `RubyLine` object for a given nesting level.
    * **`PlaceLines`**: Determines the vertical positions of the ruby annotation lines based on their calculated heights and the base line.
    * **`AddLinesTo`**: Adds the positioned annotation lines to the overall line layout.
    * **Relationship to CSS:** Implicitly related to CSS as the layout and positioning are driven by CSS properties applied to the ruby elements.

**Relationship to JavaScript, HTML, CSS:**

* **HTML:** This code directly deals with the layout of HTML elements related to ruby annotations: `<ruby>`, `<rb>` (ruby base), and `<rt>` (ruby text). When the browser encounters these elements in the HTML, the rendering engine uses this code to determine their visual placement.
* **CSS:** The functionality of this code is heavily influenced by CSS properties specifically designed for ruby annotations, such as:
    * `ruby-align`: Controls the horizontal alignment of the ruby text relative to the base text.
    * `ruby-position`: Specifies where the ruby text should be placed (above or below the base).
    * `text-align`: Affects the alignment of the ruby element within its containing line.
    * `font-size`, `line-height`: Determine the dimensions of the base and annotation text, impacting layout calculations.
    * `text-emphasis`: If text emphasis is applied to the base text, this code considers it when calculating annotation overflow.
* **JavaScript:** While JavaScript doesn't directly interact with this specific C++ code, it can manipulate the DOM (Document Object Model) by adding, removing, or modifying ruby elements and their associated CSS styles. These changes will then trigger the layout calculations performed by this code in the rendering engine.

**Examples:**

* **HTML:**
  ```html
  <ruby>
    漢 <rt> かん </rt>
  </ruby>
  ```
* **CSS:**
  ```css
  ruby { ruby-align: center; }
  rt { font-size: 0.8em; }
  ```
  The `ruby_utils.cc` code would be responsible for:
    * Identifying "漢" as the base and "かん" as the annotation (`ParseRubyInInlineItems`).
    * Centering "かん" above "漢" (`ApplyRubyAlign` based on `ruby-align: center`).
    * Ensuring the font size of "かん" is smaller (`ComputeAnnotationOverflow` and other height calculations).

**Logic Inference (Example with `ApplyRubyAlign`):**

* **Hypothetical Input:**
    * `available_line_size`: 100px
    * `line_info.WidthForAlignment()`: 60px (width of the ruby element)
    * `line_info.LineStyle().RubyAlign()`: `ERubyAlign::kSpaceAround`
    * `line_info.TextAlign()`: `ETextAlign::kStart` (assuming initial value)
    * `line_info.BaseDirection()`: LTR
* **Logic:**
    1. Calculate `space`: 100px - 60px = 40px
    2. `ruby_align` is `kSpaceAround`, so the initial `text_align` is respected.
    3. `text_align` is `kStart` and the base direction is LTR, so `text_align` becomes `ETextAlign::kLeft`.
    4. For `ETextAlign::kLeft`, the function returns `{LayoutUnit(), space}`, which is `{0px, 40px}`.
* **Hypothetical Output:** The ruby element will have 0px of space to its left and 40px of space to its right within the line.

**User or Programming Common Usage Errors:**

1. **Incorrectly Nested Ruby Tags:** If the HTML has invalid nesting of `<ruby>`, `<rb>`, and `<rt>` tags, the `ParseRubyInInlineItems` function might not be able to correctly identify the ruby structure, leading to unexpected layout or rendering issues.

    * **Example:** `<ruby><rt>Annotation</rt>Base</ruby>` (incorrect order).

2. **Conflicting CSS Properties:** Setting conflicting values for ruby-related CSS properties can lead to unpredictable layout.

    * **Example:** Setting both `ruby-align: space-between;` and `text-align: center;` on the same ruby element. The browser will likely have a defined precedence, but it might not be what the author intended.

3. **Overlapping Annotations:** If multiple levels of ruby annotations are used without proper spacing or styling, they might overlap, making the text difficult to read. This could be a result of insufficient handling in `ComputeAnnotationOverflow` or incorrect CSS styling.

4. **Using Very Large Font Sizes for Annotations:** While technically allowed, using extremely large font sizes for annotations can disrupt the line layout and potentially cause the annotations to overlap with other content.

5. **Programming Errors in Blink:**  Bugs within the `ruby_utils.cc` code itself could lead to incorrect calculations of overhang, alignment, or overflow, resulting in visual rendering errors of ruby annotations. These would be internal errors in the browser engine.

In summary, `ruby_utils.cc` plays a crucial role in the layout and rendering of ruby annotations in Chromium. It directly interacts with the internal layout mechanisms of the browser and is heavily influenced by HTML structure and CSS styling related to ruby elements. Understanding its functionality is essential for anyone working on web rendering engines or dealing with complex text layout scenarios involving ruby annotations.

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/ruby_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/ruby_utils.h"

#include <tuple>

#include "third_party/blink/renderer/core/layout/inline/inline_box_state.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result.h"
#include "third_party/blink/renderer/core/layout/inline/inline_item_result_ruby_column.h"
#include "third_party/blink/renderer/core/layout/inline/justification_utils.h"
#include "third_party/blink/renderer/core/layout/inline/line_info.h"
#include "third_party/blink/renderer/core/layout/inline/logical_line_container.h"
#include "third_party/blink/renderer/core/layout/inline/logical_line_item.h"
#include "third_party/blink/renderer/core/layout/layout_object_inlines.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/platform/fonts/font_height.h"
#include "third_party/blink/renderer/platform/heap/collection_support/clear_collection_scope.h"

namespace blink {

namespace {

std::tuple<LayoutUnit, LayoutUnit> AdjustTextOverUnderOffsetsForEmHeight(
    LayoutUnit over,
    LayoutUnit under,
    const ComputedStyle& style,
    const ShapeResultView& shape_view) {
  DCHECK_LE(over, under);
  const SimpleFontData* primary_font_data = style.GetFont().PrimaryFont();
  if (!primary_font_data)
    return std::make_pair(over, under);
  const auto font_baseline = style.GetFontBaseline();
  const LayoutUnit line_height = under - over;
  const LayoutUnit primary_ascent =
      primary_font_data->GetFontMetrics().FixedAscent(font_baseline);
  const LayoutUnit primary_descent = line_height - primary_ascent;

  // We don't use ShapeResultView::FallbackFonts() because we can't know if the
  // primary font is actually used with FallbackFonts().
  HeapVector<ShapeResult::RunFontData> run_fonts;
  ClearCollectionScope clear_scope(&run_fonts);
  shape_view.GetRunFontData(&run_fonts);
  const LayoutUnit kNoDiff = LayoutUnit::Max();
  LayoutUnit over_diff = kNoDiff;
  LayoutUnit under_diff = kNoDiff;
  for (const auto& run_font : run_fonts) {
    const SimpleFontData* font_data = run_font.font_data_;
    if (!font_data)
      continue;
    const FontHeight normalized_height =
        font_data->NormalizedTypoAscentAndDescent(font_baseline);
    // Floor() is better than Round().  We should not subtract pixels larger
    // than |primary_ascent - em_box.ascent|.
    const LayoutUnit current_over_diff(
        (primary_ascent - normalized_height.ascent)
            .ClampNegativeToZero()
            .Floor());
    const LayoutUnit current_under_diff(
        (primary_descent - normalized_height.descent)
            .ClampNegativeToZero()
            .Floor());
    over_diff = std::min(over_diff, current_over_diff);
    under_diff = std::min(under_diff, current_under_diff);
  }
  if (over_diff == kNoDiff)
    over_diff = LayoutUnit();
  if (under_diff == kNoDiff)
    under_diff = LayoutUnit();
  return std::make_tuple(over + over_diff, under - under_diff);
}

FontHeight ComputeEmHeight(const LogicalLineItem& line_item) {
  if (const auto& shape_result_view = line_item.shape_result) {
    const ComputedStyle* style = line_item.Style();
    const SimpleFontData* primary_font_data = style->GetFont().PrimaryFont();
    if (!primary_font_data) {
      return FontHeight();
    }
    const auto font_baseline = style->GetFontBaseline();
    const FontHeight primary_height =
        primary_font_data->GetFontMetrics().GetFloatFontHeight(font_baseline);
    FontHeight result_height;
    // We don't use ShapeResultView::FallbackFonts() because we can't know if
    // the primary font is actually used with FallbackFonts().
    HeapVector<ShapeResult::RunFontData> run_fonts;
    ClearCollectionScope clear_scope(&run_fonts);
    shape_result_view->GetRunFontData(&run_fonts);
    for (const auto& run_font : run_fonts) {
      const SimpleFontData* font_data = run_font.font_data_;
      if (!font_data) {
        continue;
      }
      result_height.Unite(
          font_data->NormalizedTypoAscentAndDescent(font_baseline));
    }
    result_height.ascent = std::min(LayoutUnit(result_height.ascent.Ceil()),
                                    primary_height.ascent);
    result_height.descent = std::min(LayoutUnit(result_height.descent.Ceil()),
                                     primary_height.descent);
    result_height.Move(line_item.rect.offset.block_offset +
                       primary_height.ascent);
    return result_height;
  }
  if (const auto& layout_result = line_item.layout_result) {
    const auto& fragment = layout_result->GetPhysicalFragment();
    const auto& style = fragment.Style();
    LogicalSize logical_size =
        LogicalFragment(style.GetWritingDirection(), fragment).Size();
    const LayoutBox* box = DynamicTo<LayoutBox>(line_item.GetLayoutObject());
    if (logical_size.inline_size && box && box->IsAtomicInlineLevel()) {
      LogicalRect overflow =
          WritingModeConverter(
              {ToLineWritingMode(style.GetWritingMode()), style.Direction()},
              fragment.Size())
              .ToLogical(box->ScrollableOverflowRect());
      // Assume 0 is the baseline.  BlockOffset() is always negative.
      return FontHeight(-overflow.offset.block_offset - line_item.BlockOffset(),
                        overflow.BlockEndOffset() + line_item.BlockOffset());
    }
  }
  return FontHeight();
}

}  // anonymous namespace

RubyItemIndexes ParseRubyInInlineItems(const HeapVector<InlineItem>& items,
                                       wtf_size_t start_item_index) {
  CHECK_LT(start_item_index, items.size());
  CHECK_EQ(items[start_item_index].Type(), InlineItem::kOpenRubyColumn);
  RubyItemIndexes indexes = {start_item_index, WTF::kNotFound, WTF::kNotFound,
                             WTF::kNotFound};
  for (wtf_size_t i = start_item_index + 1; i < items.size(); ++i) {
    const InlineItem& item = items[i];
    if (item.Type() == InlineItem::kCloseRubyColumn) {
      if (indexes.base_end == WTF::kNotFound) {
        DCHECK_EQ(indexes.annotation_start, WTF::kNotFound);
        indexes.base_end = i;
      } else {
        DCHECK_NE(indexes.annotation_start, WTF::kNotFound);
      }
      indexes.column_end = i;
      return indexes;
    }
    if (item.Type() == InlineItem::kOpenTag &&
        item.GetLayoutObject()->IsInlineRubyText()) {
      DCHECK_EQ(indexes.base_end, WTF::kNotFound);
      DCHECK_EQ(indexes.annotation_start, WTF::kNotFound);
      indexes.base_end = i;
      indexes.annotation_start = i;
    } else if (item.Type() == InlineItem::kOpenRubyColumn) {
      RubyItemIndexes sub_indexes = ParseRubyInInlineItems(items, i);
      i = sub_indexes.column_end;
    }
  }
  NOTREACHED();
}

AnnotationOverhang GetOverhang(
    LayoutUnit ruby_size,
    const LineInfo& base_line,
    const HeapVector<LineInfo, 1> annotation_line_list) {
  AnnotationOverhang overhang;
  ERubyAlign ruby_align = base_line.LineStyle().RubyAlign();
  switch (ruby_align) {
    case ERubyAlign::kSpaceBetween:
      return overhang;
    case ERubyAlign::kStart:
    case ERubyAlign::kSpaceAround:
    case ERubyAlign::kCenter:
      break;
  }
  LayoutUnit half_width_of_annotation_font;
  for (const auto& annotation_line : annotation_line_list) {
    if (annotation_line.Width() == ruby_size) {
      half_width_of_annotation_font =
          LayoutUnit(annotation_line.LineStyle().FontSize() / 2);
      break;
    }
  }
  if (half_width_of_annotation_font == LayoutUnit()) {
    return overhang;
  }
  LayoutUnit space = ruby_size - base_line.Width();
  if (space <= LayoutUnit()) {
    return overhang;
  }
  if (ruby_align == ERubyAlign::kStart) {
    overhang.end = std::min(space, half_width_of_annotation_font);
    return overhang;
  }
  std::optional<LayoutUnit> inset = ComputeRubyBaseInset(space, base_line);
  if (!inset) {
    return overhang;
  }
  overhang.start = std::min(*inset, half_width_of_annotation_font);
  overhang.end = overhang.start;
  return overhang;
}

AnnotationOverhang GetOverhang(const InlineItemResult& item) {
  DCHECK(item.IsRubyColumn());
  const InlineItemResultRubyColumn& column = *item.ruby_column;
  return GetOverhang(item.inline_size, column.base_line,
                     column.annotation_line_list);
}

bool CanApplyStartOverhang(const LineInfo& line_info,
                           wtf_size_t ruby_index,
                           const ComputedStyle& ruby_style,
                           LayoutUnit& start_overhang) {
  if (start_overhang <= LayoutUnit())
    return false;
  const InlineItemResults& items = line_info.Results();
  // Requires at least the ruby item and the previous item.
  if (ruby_index < 1) {
    return false;
  }
  // Find a previous item other than kOpenTag/kCloseTag.
  // Searching items in the logical order doesn't work well with bidi
  // reordering. However, it's difficult to compute overhang after bidi
  // reordering because it affects line breaking.
  wtf_size_t previous_index = ruby_index - 1;
  while ((items[previous_index].item->Type() == InlineItem::kOpenTag ||
          items[previous_index].item->Type() == InlineItem::kCloseTag) &&
         previous_index > 0) {
    --previous_index;
  }
  const InlineItemResult& previous_item = items[previous_index];
  if (previous_item.item->Type() != InlineItem::kText) {
    return false;
  }
  if (previous_item.item->Style()->FontSize() > ruby_style.FontSize()) {
    return false;
  }
  start_overhang = std::min(start_overhang, previous_item.inline_size);
  return true;
}

LayoutUnit CommitPendingEndOverhang(const InlineItem& text_item,
                                    LineInfo* line_info) {
  DCHECK(line_info);
  InlineItemResults* items = line_info->MutableResults();
  if (items->size() < 1U) {
    return LayoutUnit();
  }
  if (text_item.Type() == InlineItem::kControl) {
    return LayoutUnit();
  }
  DCHECK_EQ(text_item.Type(), InlineItem::kText);
  wtf_size_t i = items->size() - 1;
  while (!(*items)[i].IsRubyColumn()) {
    const auto type = (*items)[i].item->Type();
    if (type != InlineItem::kOpenTag && type != InlineItem::kCloseTag &&
        type != InlineItem::kCloseRubyColumn &&
        type != InlineItem::kOpenRubyColumn &&
        type != InlineItem::kRubyLinePlaceholder) {
      return LayoutUnit();
    }
    if (i-- == 0) {
      return LayoutUnit();
    }
  }
  InlineItemResult& column_item = (*items)[i];
  if (column_item.pending_end_overhang <= LayoutUnit()) {
    return LayoutUnit();
  }
  if (column_item.ruby_column->base_line.LineStyle().FontSize() <
      text_item.Style()->FontSize()) {
    return LayoutUnit();
  }
  // Ideally we should refer to inline_size of |text_item| instead of the
  // width of the InlineItem's ShapeResult. However it's impossible to compute
  // inline_size of |text_item| before calling BreakText(), and BreakText()
  // requires precise |position_| which takes |end_overhang| into account.
  LayoutUnit end_overhang =
      std::min(column_item.pending_end_overhang,
               LayoutUnit(text_item.TextShapeResult()->Width()));
  InlineItemResult& end_item =
      column_item.ruby_column->base_line.MutableResults()->back();
  DCHECK_EQ(end_item.item->Type(), InlineItem::kRubyLinePlaceholder);
  DCHECK_EQ(end_item.margins.inline_end, LayoutUnit());
  end_item.margins.inline_end = -end_overhang;
  column_item.pending_end_overhang = LayoutUnit();
  return end_overhang;
}

std::pair<LayoutUnit, LayoutUnit> ApplyRubyAlign(LayoutUnit available_line_size,
                                                 bool on_start_edge,
                                                 bool on_end_edge,
                                                 LineInfo& line_info) {
  DCHECK(line_info.IsRubyBase() || line_info.IsRubyText());
  LayoutUnit space = available_line_size - line_info.WidthForAlignment();
  if (space <= LayoutUnit()) {
    return {LayoutUnit(), LayoutUnit()};
  }

  ERubyAlign ruby_align = line_info.LineStyle().RubyAlign();
  ETextAlign text_align = line_info.TextAlign();
  switch (ruby_align) {
    case ERubyAlign::kSpaceAround:
      // We respect to the text-align value as ever if ruby-align is the
      // initial value.
      break;
    case ERubyAlign::kSpaceBetween:
      on_start_edge = true;
      on_end_edge = true;
      text_align = ETextAlign::kJustify;
      break;
    case ERubyAlign::kStart:
      return IsLtr(line_info.BaseDirection())
                 ? std::make_pair(LayoutUnit(), space)
                 : std::make_pair(space, LayoutUnit());
    case ERubyAlign::kCenter:
      return {space / 2, space / 2};
  }

  // Handle `space-around` and `space-between`.
  if (text_align == ETextAlign::kJustify) {
    JustificationTarget target;
    if (on_start_edge && on_end_edge) {
      // Switch to `space-between` if this needs to align both edges.
      target = JustificationTarget::kNormal;
    } else if (line_info.IsRubyBase()) {
      target = JustificationTarget::kRubyBase;
    } else {
      DCHECK(line_info.IsRubyText());
      target = JustificationTarget::kRubyText;
    }
    std::optional<LayoutUnit> inset =
        ApplyJustification(space, target, &line_info);
    // https://drafts.csswg.org/css-ruby/#line-edge
    if (inset) {
      if (on_start_edge && !on_end_edge) {
        return {LayoutUnit(), *inset * 2};
      }
      if (!on_start_edge && on_end_edge) {
        return {*inset * 2, LayoutUnit()};
      }
      return {*inset, *inset};
    }
    if (on_start_edge && !on_end_edge) {
      return {LayoutUnit(), space};
    }
    if (!on_start_edge && on_end_edge) {
      return {space, LayoutUnit()};
    }
    return {space / 2, space / 2};
  }

  bool is_ltr = IsLtr(line_info.BaseDirection());
  if (text_align == ETextAlign::kStart) {
    text_align = is_ltr ? ETextAlign::kLeft : ETextAlign::kRight;
  } else if (text_align == ETextAlign::kEnd) {
    text_align = is_ltr ? ETextAlign::kRight : ETextAlign::kLeft;
  }
  switch (text_align) {
    case ETextAlign::kLeft:
    case ETextAlign::kWebkitLeft:
      return {LayoutUnit(), space};

    case ETextAlign::kRight:
    case ETextAlign::kWebkitRight:
      return {space, LayoutUnit()};

    case ETextAlign::kCenter:
    case ETextAlign::kWebkitCenter:
      return {space / 2, space / 2};

    case ETextAlign::kStart:
    case ETextAlign::kEnd:
    case ETextAlign::kJustify:
      NOTREACHED();
  }
  return {LayoutUnit(), LayoutUnit()};
}

AnnotationMetrics ComputeAnnotationOverflow(
    const LogicalLineItems& logical_line,
    const FontHeight& line_box_metrics,
    const ComputedStyle& line_style,
    std::optional<FontHeight> annotation_metrics) {
  // Min/max position of content and annotations, ignoring line-height.
  // They are distance from the line box top.
  const LayoutUnit line_over;
  LayoutUnit content_over = line_over + line_box_metrics.ascent;
  LayoutUnit content_under = content_over;

  bool has_over_annotation = false;
  bool has_under_annotation = false;

  const LayoutUnit line_under = line_over + line_box_metrics.LineHeight();
  bool has_over_emphasis = false;
  bool has_under_emphasis = false;
  // TODO(crbug.com/324111880): This loop can be replaced with
  // ComputeLogicalLineEmHeight() after enabling RubyLineBreakable flag.
  for (const LogicalLineItem& item : logical_line) {
    if (!item.HasInFlowFragment())
      continue;
    if (item.IsControl() || item.IsRubyLinePlaceholder()) {
      continue;
    }
    LayoutUnit item_over = line_box_metrics.ascent + item.BlockOffset();
    LayoutUnit item_under = line_box_metrics.ascent + item.BlockEndOffset();
    if (item.shape_result) {
      if (const auto* style = item.Style()) {
        std::tie(item_over, item_under) = AdjustTextOverUnderOffsetsForEmHeight(
            item_over, item_under, *style, *item.shape_result);
      }
    } else {
      const LayoutBox* box = DynamicTo<LayoutBox>(item.GetLayoutObject());
      const auto* fragment = item.GetPhysicalFragment();
      if (fragment && box && box->IsAtomicInlineLevel() &&
          !box->IsInitialLetterBox()) {
        item_under = ComputeEmHeight(item).LineHeight();
      } else if (item.IsInlineBox()) {
        continue;
      }
    }
    content_over = std::min(content_over, item_over);
    content_under = std::max(content_under, item_under);

    if (const auto* style = item.Style()) {
      if (style->GetTextEmphasisMark() != TextEmphasisMark::kNone) {
        if (style->GetTextEmphasisLineLogicalSide() == LineLogicalSide::kOver)
          has_over_emphasis = true;
        else
          has_under_emphasis = true;
      }
    }
  }

  if (annotation_metrics) {
    if (annotation_metrics->ascent) {
      LayoutUnit item_over =
          line_box_metrics.ascent - annotation_metrics->ascent;
      content_over = std::min(content_over, item_over);
      has_over_annotation = true;
    }
    if (annotation_metrics->descent) {
      LayoutUnit item_under =
          line_box_metrics.ascent + annotation_metrics->descent;
      content_under = std::max(content_under, item_under);
      has_under_annotation = true;
    }
  }

  // Probably this is an empty line. We should secure font-size space.
  const LayoutUnit font_size(line_style.ComputedFontSize());
  if (content_under - content_over < font_size) {
    LayoutUnit half_leading = (line_box_metrics.LineHeight() - font_size) / 2;
    half_leading = half_leading.ClampNegativeToZero();
    content_over = line_over + half_leading;
    content_under = line_under - half_leading;
  }

  // Don't provide annotation space if text-emphasis exists.
  // TODO(layout-dev): If the text-emphasis is in [line_over, line_under],
  // this line can provide annotation space.
  if (has_over_emphasis)
    content_over = std::min(content_over, line_over);
  if (has_under_emphasis)
    content_under = std::max(content_under, line_under);

  // With some fonts, text fragment sizes can exceed line-height.
  // We'd like to set overflow only if we have annotations.
  // This affects fast/ruby/line-height.html on macOS.
  if (content_over < line_over && !has_over_annotation)
    content_over = line_over;
  if (content_under > line_under && !has_under_annotation)
    content_under = line_under;

  return {(line_over - content_over).ClampNegativeToZero(),
          (content_under - line_under).ClampNegativeToZero(),
          (content_over - line_over).ClampNegativeToZero(),
          (line_under - content_under).ClampNegativeToZero()};
}

// ================================================================

void UpdateRubyColumnInlinePositions(
    const LogicalLineItems& line_items,
    LayoutUnit inline_size,
    HeapVector<Member<LogicalRubyColumn>>& column_list) {
  for (auto& column : column_list) {
    LayoutUnit inline_offset;
    wtf_size_t start_index = column->start_index;
    if (start_index < line_items.size()) {
      inline_offset = line_items[start_index].rect.offset.inline_offset;
    } else if (start_index == line_items.size()) {
      if (line_items.size() > 0) {
        const LogicalLineItem& last_item = line_items[start_index - 1];
        inline_offset = last_item.rect.offset.inline_offset +
                        last_item.rect.InlineEndOffset();
      } else {
        inline_offset = inline_size;
      }
    } else {
      NOTREACHED() << " LogicalLineItems::size()=" << line_items.size()
                   << " LogicalRubyColumn::start_index=" << start_index;
    }
    // TODO(crbug.com/324111880): Handle overhang.
    column->annotation_items->MoveInInlineDirection(inline_offset);
    column->state_stack.MoveBoxDataInInlineDirection(inline_offset);
    UpdateRubyColumnInlinePositions(*column->annotation_items, inline_size,
                                    column->RubyColumnList());
  }
}

// ================================================================

namespace {

FontHeight ComputeLogicalLineEmHeight(const LogicalLineItems& line_items) {
  FontHeight height;
  for (const auto& item : line_items) {
    height.Unite(ComputeEmHeight(item));
  }
  return height;
}

FontHeight ComputeLogicalLineEmHeight(const LogicalLineItems& line_items,
                                      const Vector<wtf_size_t>& index_list) {
  if (index_list.empty()) {
    return ComputeLogicalLineEmHeight(line_items);
  }
  FontHeight height;
  for (const auto index : index_list) {
    height.Unite(ComputeEmHeight(line_items[index]));
  }
  return height;
}

}  // namespace

RubyBlockPositionCalculator::RubyBlockPositionCalculator() = default;

RubyBlockPositionCalculator& RubyBlockPositionCalculator::GroupLines(
    const HeapVector<Member<LogicalRubyColumn>>& column_list) {
  HandleRubyLine(EnsureRubyLine(RubyLevel()), column_list);
  return *this;
}

void RubyBlockPositionCalculator::HandleRubyLine(
    const RubyLine& current_ruby_line,
    const HeapVector<Member<LogicalRubyColumn>>& column_list) {
  if (column_list.empty()) {
    return;
  }

  auto create_level_and_update_depth =
      [](const RubyLevel& current, const AnnotationDepth& current_depth) {
        AnnotationDepth depth = current_depth;
        RubyLevel new_level;
        new_level.reserve(current.size() + 1);
        new_level.AppendVector(current);
        if (depth.column->ruby_position == RubyPosition::kUnder) {
          new_level.push_back(--depth.under_depth);
        } else {
          new_level.push_back(++depth.over_depth);
        }
        return std::make_pair(new_level, depth);
      };

  HeapVector<AnnotationDepth, 1> depth_stack;
  const RubyLevel& current_level = current_ruby_line.Level();
  for (wtf_size_t i = 0; i < column_list.size(); ++i) {
    // Push depth values with zeros.  Actual depths are fixed on closing this
    // ruby column.
    depth_stack.push_back(AnnotationDepth{column_list[i].Get(), 0, 0});

    // Close this ruby column and parent ruby columns which are not parents of
    // the next column.
    auto should_close_column = [=]() {
      const LogicalRubyColumn* column = depth_stack.back().column;
      return i + 1 >= column_list.size() ||
             column->EndIndex() <= column_list[i + 1]->start_index;
    };
    while (!depth_stack.empty() && should_close_column()) {
      const auto [annotation_level, closing_depth] =
          create_level_and_update_depth(current_level, depth_stack.back());
      RubyLine& annotation_line = EnsureRubyLine(annotation_level);
      annotation_line.Append(*closing_depth.column);
      HandleRubyLine(annotation_line, closing_depth.column->RubyColumnList());
      annotation_line.MaybeRecordBaseIndexes(*closing_depth.column);

      depth_stack.pop_back();
      if (!depth_stack.empty()) {
        AnnotationDepth& parent_depth = depth_stack.back();
        parent_depth.over_depth =
            std::max(parent_depth.over_depth, closing_depth.over_depth);
        parent_depth.under_depth =
            std::min(parent_depth.under_depth, closing_depth.under_depth);
      }
    }
  }
  CHECK(depth_stack.empty());
}

RubyBlockPositionCalculator::RubyLine&
RubyBlockPositionCalculator::EnsureRubyLine(const RubyLevel& level) {
  // We do linear search because ruby_lines_ typically has only two items.
  auto it =
      base::ranges::find_if(ruby_lines_, [&](const Member<RubyLine>& line) {
        return base::ranges::equal(line->Level(), level);
      });
  if (it != ruby_lines_.end()) {
    return **it;
  }
  ruby_lines_.push_back(MakeGarbageCollected<RubyLine>(level));
  return *ruby_lines_.back();
}

RubyBlockPositionCalculator& RubyBlockPositionCalculator::PlaceLines(
    const LogicalLineItems& base_line_items,
    const FontHeight& line_box_metrics) {
  DCHECK(!ruby_lines_.empty()) << "This must be called after GroupLines().";
  annotation_metrics_ = FontHeight();

  // Sort `ruby_lines` from the lowest to the highest.
  base::ranges::sort(ruby_lines_, [](const Member<RubyLine>& line1,
                                     const Member<RubyLine>& line2) {
    return *line1 < *line2;
  });

  auto base_iterator = base::ranges::find_if(
      ruby_lines_,
      [](const Member<RubyLine>& line) { return line->Level().empty(); });
  CHECK_NE(base_iterator, ruby_lines_.end());

  // Place "under" annotations from the base level to the lowest one.
  if (base_iterator != ruby_lines_.begin()) {
    auto first_under_iterator = base::ranges::find_if(
        ruby_lines_.begin(), base_iterator,
        [](const Member<RubyLine>& line) { return line->IsFirstUnderLevel(); });
    FontHeight em_height = ComputeLogicalLineEmHeight(
        base_line_items, (**first_under_iterator).BaseIndexList());
    if (!em_height.LineHeight()) {
      em_height = line_box_metrics;
    }
    LayoutUnit offset = em_height.descent;
    auto lines_before_base =
        base::span(ruby_lines_)
            .first(base::checked_cast<size_t>(
                std::distance(ruby_lines_.begin(), base_iterator)));
    for (auto& ruby_line : base::Reversed(lines_before_base)) {
      FontHeight metrics = ruby_line->UpdateMetrics();
      offset += metrics.ascent;
      ruby_line->MoveInBlockDirection(offset);
      offset += metrics.descent;
    }
    annotation_metrics_.descent = offset;
  }

  // Place "over" annotations from the base level to the highest one.
  if (std::next(base_iterator) != ruby_lines_.end()) {
    auto first_over_iterator = base::ranges::find_if(
        base_iterator, ruby_lines_.end(),
        [](const Member<RubyLine>& line) { return line->IsFirstOverLevel(); });
    FontHeight em_height = ComputeLogicalLineEmHeight(
        base_line_items, (**first_over_iterator).BaseIndexList());
    if (!em_height.LineHeight()) {
      em_height = line_box_metrics;
    }
    LayoutUnit offset = -em_height.ascent;
    for (auto& ruby_line :
         base::span(ruby_lines_)
             .last(base::checked_cast<size_t>(
                 std::distance(base_iterator, ruby_lines_.end()) - 1))) {
      FontHeight metrics = ruby_line->UpdateMetrics();
      offset -= metrics.descent;
      ruby_line->MoveInBlockDirection(offset);
      offset -= metrics.ascent;
    }
    annotation_metrics_.ascent = -offset;
  }
  return *this;
}

RubyBlockPositionCalculator& RubyBlockPositionCalculator::AddLinesTo(
    LogicalLineContainer& line_container) {
  DCHECK(!annotation_metrics_.IsEmpty())
      << "This must be called after PlaceLines().";
  for (const auto& ruby_line : ruby_lines_) {
    ruby_line->AddLinesTo(line_container);
  }
  return *this;
}

FontHeight RubyBlockPositionCalculator::AnnotationMetrics() const {
  DCHECK(!annotation_metrics_.IsEmpty())
      << "This must be called after PlaceLines().";
  return annotation_metrics_;
}

// ================================================================

RubyBlockPositionCalculator::RubyLine::RubyLine(const RubyLevel& level)
    : level_(level) {}

void RubyBlockPositionCalculator::RubyLine::Trace(Visitor* visitor) const {
  visitor->Trace(column_list_);
}

bool RubyBlockPositionCalculator::RubyLine::operator<(
    const RubyLine& another) const {
  const RubyLevel& level1 = Level();
  const RubyLevel& level2 = another.Level();
  wtf_size_t i = 0;
  while (i < level1.size() && i < level2.size() && level1[i] == level2[i]) {
    ++i;
  }
  RubyLevel::ValueType value1 = i < level1.size() ? level1[i] : 0;
  RubyLevel::ValueType value2 = i < level2.size() ? level2[i] : 0;
  return value1 < value2;
}

void RubyBlockPositionCalculator::RubyLine::Append(
    LogicalRubyColumn& logical_column) {
  column_list_.push_back(logical_column);
}

void RubyBlockPositionCalculator::RubyLine::MaybeRecordBaseIndexes(
    const LogicalRubyColumn& logical_column) {
  if (IsFirstOverLevel() || IsFirstUnderLevel()) {
    base_index_list_.reserve(base_index_list_.size() + logical_column.size);
    for (wtf_size_t item_index = logical_column.start_index;
         item_index < logical_column.EndIndex(); ++item_index) {
      base_index_list_.push_back(item_index);
    }
  }
}

FontHeight RubyBlockPositionCalculator::RubyLine::UpdateMetrics() {
  DCHECK(metrics_.IsEmpty());
  metrics_ = FontHeight();
  for (auto& column : column_list_) {
    const auto margins = column->state_stack.AnnotationBoxBlockAxisMargins();
    if (!margins.has_value()) {
      metrics_.Unite(ComputeLogicalLineEmHeight(*column->annotation_items));
    } else {
      // A placeholder item is at [0] in LTR, but it's not at [0] in RTL.
      for (const LogicalLineItem& item : *column->annotation_items) {
        if (item.IsPlaceholder()) {
          metrics_.Unite({-item.BlockOffset() + margins->first,
                          item.BlockEndOffset() + margins->second});
          break;
        }
      }
    }
  }
  return metrics_;
}

void RubyBlockPositionCalculator::RubyLine::MoveInBlockDirection(
    LayoutUnit offset) {
  for (auto& column : column_list_) {
    column->annotation_items->MoveInBlockDirection(offset);
    column->state_stack.MoveBoxDataInBlockDirection(offset);
  }
}

void RubyBlockPositionCalculator::RubyLine::AddLinesTo(
    LogicalLineContainer& line_container) const {
  if (IsBaseLevel()) {
    return;
  }
  for (const auto& column : column_list_) {
    line_container.AddAnnotation(metrics_, *column->annotation_items);
  }
}

// ================================================================

void RubyBlockPositionCalculator::AnnotationDepth::Trace(
    Visitor* visitor) const {
  visitor->Trace(column);
}

}  // namespace blink

"""

```