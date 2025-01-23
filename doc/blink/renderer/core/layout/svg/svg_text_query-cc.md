Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Goal:** The request is to understand the functionality of the `svg_text_query.cc` file within the Chromium Blink engine. Specifically, the request asks for its core functions, relationships to web technologies (JavaScript, HTML, CSS), logical reasoning (with input/output examples), and common usage errors.

2. **Initial Code Scan (High-Level):**  Quickly read through the code, looking for keywords and patterns. Observations:
    *  Includes:  Mentions `SVGTextQuery`, `FragmentItem`, `LayoutObject`, `LayoutSVGInlineText`, `LayoutSVGText`. These strongly suggest this code is related to handling SVG `<text>` elements and their layout.
    *  Namespaces: `blink` clearly indicates it's part of the Blink rendering engine.
    *  Functions with names like `NumberOfCharacters`, `SubStringLength`, `StartPositionOfCharacter`, `EndPositionOfCharacter`, `ExtentOfCharacter`, `RotationOfCharacter`, `CharacterNumberAtPosition`. These are strong clues about the kinds of queries this class supports related to SVG text.
    *  Use of `gfx::PointF`, `gfx::RectF`, `StringView`. These suggest interactions with geometry and text manipulation.

3. **Identify Key Data Structures and Classes:** Focus on the core classes and data structures being used:
    * `SvgTextQuery`:  Likely the main class that provides the querying functionality.
    * `LayoutObject`:  A fundamental Blink class representing layout elements. The code explicitly checks for `IsSVGText()`.
    * `LayoutSVGText`, `LayoutSVGInlineText`: Specialized layout objects for SVG text.
    * `FragmentItem`: Represents a fragment of text within the layout. Crucial for understanding how text is broken down.
    * `PhysicalBoxFragment`: Represents a physical fragment of a layout box.
    * `ShapeResultView`:  Related to font shaping and glyph layout.

4. **Analyze Individual Functions:**  Go through each function and try to understand its purpose. This is where the bulk of the analysis happens.

    * **Helper Functions (top of file):**
        * `AdjustCodeUnitStartOffset`, `AdjustCodeUnitEndOffset`:  Handle UTF-16 surrogate pairs correctly, ensuring offsets point to valid code points.
        * `FragmentItemsInVisualOrder`, `FragmentItemsInLogicalOrder`: Key functions for retrieving `FragmentItem`s, the former in the order they appear on the screen, the latter in the order they appear in the source. This is important for SVG text rendering, which can be reordered.
        * `FindFragmentItemForAddressableCodeUnitIndex`:  Maps a character index to the corresponding `FragmentItem` and relevant offsets.
        * `GetCanvasRotation`:  A callback function used during glyph processing to determine rotation.
        * `InlineSize`: Calculates the visual length of a substring within a `FragmentItem`.
        * `ScaledCharacterRectInContainer`:  Gets the bounding box of a character, taking into account transformations.
        * `StartOrEndPosition`:  Calculates the starting or ending position of a character.

    * **`SvgTextQuery` Class Methods:**
        * `NumberOfCharacters`: Returns the total number of characters in the SVG text.
        * `SubStringLength`: Calculates the visual length of a substring.
        * `StartPositionOfCharacter`, `EndPositionOfCharacter`: Return the starting and ending coordinates of a character.
        * `ExtentOfCharacter`: Returns the bounding rectangle of a character.
        * `RotationOfCharacter`:  Returns the rotation angle of a character.
        * `CharacterNumberAtPosition`:  Crucially, this method determines which character (by index) is located at a given point.

5. **Identify Relationships with Web Technologies:**  Connect the C++ code to the browser's behavior and web standards.
    * **JavaScript:** The methods in `SvgTextQuery` directly correspond to methods on SVG DOM elements in JavaScript (e.g., `getExtentOfChar`, `getStartPositionOfChar`, `getNumberOfChars`, `getCharNumAtPosition`).
    * **HTML:** The `<svg>` and `<text>` elements in HTML are the targets of this code. The layout process described handles how these elements are rendered.
    * **CSS:** CSS properties (like `writing-mode`, `text-orientation`, `direction`, `transform`) directly influence the calculations performed in this code.

6. **Logical Reasoning and Examples:**
    * **Input/Output:**  Think about specific scenarios and what the expected input and output of the functions would be. For example, for `SubStringLength`, provide an example with a starting index and length. For `CharacterNumberAtPosition`, provide an example with mouse coordinates.
    * **Assumptions:**  Explicitly state any assumptions made (e.g., the presence of a `<text>` element).

7. **Common Usage Errors:** Think about how developers might misuse the JavaScript APIs that are backed by this C++ code. Examples include:
    * Incorrect indexing (off-by-one errors).
    * Assuming visual order matches logical order.
    * Not considering transformations.

8. **Structure and Refine:** Organize the findings into logical sections (Functionality, Web Technology Relationships, Logical Reasoning, Common Errors). Use clear and concise language.

9. **Review and Iterate:** Read through the analysis to ensure accuracy and completeness. Does it address all parts of the original request?  Is it easy to understand?  For example, initially, I might have just said "handles SVG text layout," but refining that to mention specific SVG elements and layout concepts is more helpful. Also, ensuring clear connections to the corresponding JavaScript methods strengthens the analysis.
好的，让我们来分析一下 `blink/renderer/core/layout/svg/svg_text_query.cc` 文件的功能。

**文件功能概述:**

`svg_text_query.cc` 文件定义了 `SvgTextQuery` 类，该类主要负责**查询 SVG `<text>` 元素及其子元素的布局信息**。它提供了一组方法，可以获取 SVG 文本中字符的位置、长度、旋转角度以及在给定位置的字符索引等信息。这个类是 Blink 渲染引擎处理 SVG 文本相关查询的核心组件。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`SvgTextQuery` 提供的功能直接对应于 SVG DOM 规范中定义的关于文本测量的 JavaScript API。当 JavaScript 代码调用这些 API 时，Blink 引擎会使用 `SvgTextQuery` 类的方法来计算并返回结果。

* **JavaScript:**
    * `getNumberOfChars()`:  对应 `SvgTextQuery::NumberOfCharacters()`，返回 SVG 文本元素中的字符总数。
    * `getExtentOfChar(index)`: 对应 `SvgTextQuery::ExtentOfCharacter(unsigned index)`，返回指定索引字符的边界框（以 `DOMRect` 对象表示）。
    * `getStartPositionOfChar(index)`: 对应 `SvgTextQuery::StartPositionOfCharacter(unsigned index)`，返回指定索引字符的起始位置（以 `DOMPoint` 对象表示）。
    * `getEndPositionOfChar(index)`: 对应 `SvgTextQuery::EndPositionOfCharacter(unsigned index)`，返回指定索引字符的结束位置（以 `DOMPoint` 对象表示）。
    * `getSubStringLength(startIndex, count)`: 对应 `SvgTextQuery::SubStringLength(unsigned start_index, unsigned length)`，返回指定起始索引和长度的子字符串的渲染长度。
    * `getRotationOfChar(index)`: 对应 `SvgTextQuery::RotationOfCharacter(unsigned index)`，返回指定索引字符的旋转角度。
    * `getCharNumAtPosition(point)`: 对应 `SvgTextQuery::CharacterNumberAtPosition(const gfx::PointF& position)`，返回给定屏幕坐标位置下的字符索引。

    **例子：**

    假设 HTML 中有以下 SVG 代码：

    ```html
    <svg width="200" height="100">
      <text id="myText" x="10" y="50">Hello</text>
    </svg>

    <script>
      const textElement = document.getElementById('myText');
      console.log(textElement.getNumberOfChars()); // 输出: 5
      console.log(textElement.getExtentOfChar(0)); // 输出: 包含 'H' 字符边界信息的 DOMRect 对象
      console.log(textElement.getCharNumAtPosition(new DOMPoint(15, 50))); // 如果点击在 'H' 字符附近，可能输出: 0
    </script>
    ```

* **HTML:**  `SvgTextQuery` 处理的是 HTML 中 `<svg>` 标签内的 `<text>` 及其相关子元素（如 `<tspan>`, `<tref>`, `<textPath>`)。这些元素定义了要渲染的文本内容和样式。

* **CSS:** CSS 样式会影响 SVG 文本的渲染，例如 `font-size`、`font-family`、`fill`、`stroke`、`writing-mode`、`text-orientation` 等。`SvgTextQuery` 在计算布局信息时会考虑这些 CSS 属性的影响。例如，`RotationOfCharacter` 方法会根据 `writing-mode` 和 `text-orientation` 来调整字符的旋转角度。

**逻辑推理及假设输入与输出:**

让我们以 `SubStringLength` 方法为例进行逻辑推理。

**假设输入：**

* `query_root_`: 指向 `<text>` 元素的 `LayoutObject`。
* `start_index`:  子字符串的起始字符索引，例如 `1`。
* `length`:  子字符串的长度，例如 `3`。

**处理过程（简化）：**

1. `FragmentItemsInLogicalOrder(query_root_)` 获取 SVG 文本中所有文本片段 (`FragmentItem`)，并按逻辑顺序排序。每个 `FragmentItem` 代表一部分连续的文本。
2. 遍历这些 `FragmentItem`。
3. 对于每个 `FragmentItem`，检查它是否包含目标子字符串的一部分。
4. 如果包含，则调用 `InlineSize` 方法计算该部分子字符串的渲染长度。`InlineSize` 会考虑字体、字号、缩放等因素。
5. 累加所有包含部分的长度。

**假设输出：**

假设 `<text>` 元素的内容是 "Hello"，并且应用了默认样式。调用 `SubStringLength(1, 3)`，对应子字符串 "ell"。  输出将是 "ell" 这三个字符在当前样式下的渲染宽度。这个宽度会受到字体、字号等因素的影响。例如，如果字体是 Arial，字号是 16px，那么输出可能是一个近似的像素值，比如 `25.6px` (这只是一个假设值，实际值需要根据字体渲染的具体情况确定)。

**涉及用户或编程常见的使用错误:**

1. **索引越界:**  当 JavaScript 调用 `getExtentOfChar` 等方法时，如果提供的 `index` 超出了文本字符的范围（小于 0 或大于等于字符总数），可能会导致错误或返回不期望的结果。Blink 引擎在内部可能会进行边界检查，但用户在使用 JavaScript API 时也需要注意。

   **例子：**

   ```javascript
   const textElement = document.getElementById('myText');
   console.log(textElement.getExtentOfChar(10)); // 如果文本只有 5 个字符，这将是一个错误的使用
   ```

2. **混淆视觉顺序和逻辑顺序:** SVG 文本可以通过 `<tspan>` 等元素设置不同的属性，导致文本的视觉渲染顺序与它们在 DOM 结构中的逻辑顺序不同。`SvgTextQuery` 提供了在视觉顺序和逻辑顺序之间处理 `FragmentItem` 的方法，但开发者在理解和操作文本信息时需要注意这种差异，尤其是在处理 `getCharNumAtPosition` 这类与屏幕坐标相关的操作时。`CharacterNumberAtPosition` 方法的注释特别指出，为了与旧版的 SVG `<text>` 行为匹配，它是在**视觉顺序**中进行命中测试的，这与规范中要求的逻辑顺序不同。

3. **未考虑变换 (Transforms):**  SVG 元素可以应用变换 (如 `translate`, `rotate`, `scale`)。虽然 `SvgTextQuery` 的一些方法（如 `ExtentOfCharacter`）会考虑这些变换，但开发者在使用返回的位置信息时，需要理解这些坐标是相对于哪个坐标系的。

   **例子：**

   如果 `<text>` 元素应用了 `transform="translate(50, 20)"`，那么 `getStartPositionOfChar(0)` 返回的坐标将是相对于应用变换后的坐标系。

4. **假设字符宽度一致:**  在计算子字符串长度时，新手可能会错误地假设所有字符的宽度都相同。实际上，不同字符的字形宽度是不同的，而且字距调整等因素也会影响渲染长度。`SvgTextQuery` 的 `SubStringLength` 方法通过精确的布局计算来避免这种错误。

总而言之，`blink/renderer/core/layout/svg/svg_text_query.cc` 文件是 Blink 引擎中处理 SVG 文本布局查询的关键部分，它连接了底层的布局计算和上层的 JavaScript API，使得开发者能够获取 SVG 文本的各种渲染信息。理解其功能有助于更好地理解和使用 SVG 文本相关的 API。

### 提示词
```
这是目录为blink/renderer/core/layout/svg/svg_text_query.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/svg/svg_text_query.h"

#include <unicode/utf16.h>

#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_text.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"

namespace blink {

namespace {

unsigned AdjustCodeUnitStartOffset(StringView string, unsigned offset) {
  return (U16_IS_TRAIL(string[offset]) && offset > 0 &&
          U16_IS_LEAD(string[offset - 1]))
             ? offset - 1
             : offset;
}

unsigned AdjustCodeUnitEndOffset(StringView string, unsigned offset) {
  return (offset < string.length() && U16_IS_TRAIL(string[offset]) &&
          offset > 0 && U16_IS_LEAD(string[offset - 1]))
             ? offset + 1
             : offset;
}

std::tuple<Vector<const FragmentItem*>, const FragmentItems*>
FragmentItemsInVisualOrder(const LayoutObject& query_root) {
  Vector<const FragmentItem*> item_list;
  const FragmentItems* items = nullptr;
  if (query_root.IsSVGText()) {
    DCHECK_LE(To<LayoutBox>(query_root).PhysicalFragmentCount(), 1u);
    for (const auto& fragment : To<LayoutBox>(query_root).PhysicalFragments()) {
      if (!fragment.Items()) {
        continue;
      }
      items = fragment.Items();
      for (const auto& item : fragment.Items()->Items()) {
        if (item.IsSvgText()) {
          item_list.push_back(&item);
        }
      }
    }
  } else {
    DCHECK(query_root.IsInLayoutNGInlineFormattingContext());
    InlineCursor cursor;
    cursor.MoveToIncludingCulledInline(query_root);
    items = &cursor.Items();
    for (; cursor; cursor.MoveToNextForSameLayoutObject()) {
      const FragmentItem& item = *cursor.CurrentItem();
      if (item.IsSvgText()) {
        item_list.push_back(&item);
      } else if (InlineCursor descendants = cursor.CursorForDescendants()) {
        for (; descendants; descendants.MoveToNext()) {
          if (descendants.CurrentItem()->IsSvgText()) {
            item_list.push_back(descendants.CurrentItem());
          }
        }
      }
    }
  }
  return {std::move(item_list), items};
}

std::tuple<Vector<const FragmentItem*>, const FragmentItems*>
FragmentItemsInLogicalOrder(const LayoutObject& query_root) {
  auto items_tuple = FragmentItemsInVisualOrder(query_root);
  auto& item_list = std::get<0>(items_tuple);
  // Sort |item_list| in the logical order.
  std::sort(item_list.begin(), item_list.end(),
            [](const FragmentItem* a, const FragmentItem* b) {
              return a->StartOffset() < b->StartOffset();
            });
  return items_tuple;
}

// Returns a tuple of FragmentItem, Item text, IFC text offset for |index|,
// and the next IFC text offset.
std::tuple<const FragmentItem*, StringView, unsigned, unsigned>
FindFragmentItemForAddressableCodeUnitIndex(const LayoutObject& query_root,
                                            unsigned index) {
  auto [item_list, items] = FragmentItemsInLogicalOrder(query_root);

  unsigned character_index = 0;
  for (const auto* item : item_list) {
    const StringView item_text = item->Text(*items);
    if (character_index + item_text.length() <= index) {
      character_index += item_text.length();
      continue;
    }
    DCHECK_GE(index, character_index);
    DCHECK_LT(index, character_index + item_text.length());
    unsigned i = AdjustCodeUnitStartOffset(item_text, index - character_index);
    return {item, item_text, item->StartOffset() + i,
            item->StartOffset() + item_text.NextCodePointOffset(i)};
  }
  return {nullptr, StringView(), WTF::kNotFound, WTF::kNotFound};
}

void GetCanvasRotation(void* context,
                       unsigned,
                       Glyph,
                       gfx::Vector2dF,
                       float,
                       bool,
                       CanvasRotationInVertical rotation,
                       const SimpleFontData*) {
  auto* canvas_rotation = static_cast<CanvasRotationInVertical*>(context);
  *canvas_rotation = rotation;
}

float InlineSize(const FragmentItem& item,
                 StringView item_text,
                 unsigned start_code_unit_offset,
                 unsigned end_code_unit_offset) {
  unsigned start_ifc_offset =
      item.StartOffset() +
      AdjustCodeUnitStartOffset(item_text, start_code_unit_offset);
  unsigned end_ifc_offset =
      item.StartOffset() +
      AdjustCodeUnitEndOffset(item_text, end_code_unit_offset);
  PhysicalRect r = item.LocalRect(item_text, start_ifc_offset, end_ifc_offset);
  return (item.IsHorizontal() ? r.Width() : r.Height()) *
         item.GetSvgFragmentData()->length_adjust_scale /
         item.SvgScalingFactor();
}

std::tuple<const FragmentItem*, gfx::RectF> ScaledCharacterRectInContainer(
    const LayoutObject& query_root,
    unsigned code_unit_index) {
  auto [item, item_text, start_ifc_offset, end_ifc_offset] =
      FindFragmentItemForAddressableCodeUnitIndex(query_root, code_unit_index);
  DCHECK(item);
  DCHECK(item->IsSvgText());
  if (item->IsHiddenForPaint()) {
    return {item, gfx::RectF()};
  }
  auto char_rect =
      gfx::RectF(item->LocalRect(item_text, start_ifc_offset, end_ifc_offset));
  char_rect.Offset(item->GetSvgFragmentData()->rect.OffsetFromOrigin());
  return {item, char_rect};
}

enum class QueryPosition { kStart, kEnd };
gfx::PointF StartOrEndPosition(const LayoutObject& query_root,
                               unsigned index,
                               QueryPosition pos) {
  auto [item, char_rect] = ScaledCharacterRectInContainer(query_root, index);
  DCHECK(item->IsSvgText());
  if (item->IsHiddenForPaint()) {
    return gfx::PointF();
  }
  const auto& inline_text = *To<LayoutSVGInlineText>(item->GetLayoutObject());
  const SimpleFontData* font = inline_text.ScaledFont().PrimaryFont();
  const float ascent =
      font ? font->GetFontMetrics().FixedAscent(item->Style().GetFontBaseline())
           : 0.0f;
  const bool is_reversed =
      IsLtr(item->ResolvedDirection()) != (pos == QueryPosition::kStart);
  gfx::PointF point;
  switch (item->GetWritingMode()) {
    case WritingMode::kHorizontalTb:
      point = is_reversed ? char_rect.top_right() : char_rect.origin();
      point.Offset(0.0f, ascent);
      break;
    case WritingMode::kVerticalLr:
    case WritingMode::kVerticalRl:
    case WritingMode::kSidewaysRl:
      point = is_reversed ? char_rect.bottom_right() : char_rect.top_right();
      point.Offset(-ascent, 0.0f);
      break;
    case WritingMode::kSidewaysLr:
      point = is_reversed ? char_rect.origin() : char_rect.bottom_left();
      point.Offset(ascent, 0.0f);
      break;
  }
  if (item->HasSvgTransformForPaint()) {
    point = item->BuildSvgTransformForPaint().MapPoint(point);
  }
  const float scaling_factor = inline_text.ScalingFactor();
  point.Scale(1 / scaling_factor, 1 / scaling_factor);
  return point;
}

}  // namespace

unsigned SvgTextQuery::NumberOfCharacters() const {
  auto [item_list, items] = FragmentItemsInLogicalOrder(query_root_);

  unsigned addressable_code_unit_count = 0;
  for (const auto* item : item_list) {
    addressable_code_unit_count += item->Text(*items).length();
  }
  return addressable_code_unit_count;
}

float SvgTextQuery::SubStringLength(unsigned start_index,
                                    unsigned length) const {
  if (length <= 0) {
    return 0.0f;
  }
  auto [item_list, items] = FragmentItemsInLogicalOrder(query_root_);

  float total_length = 0.0f;
  // Starting addressable code unit index for the current FragmentItem.
  unsigned character_index = 0;
  const unsigned end_index = start_index + length;
  for (const auto* item : item_list) {
    if (end_index <= character_index) {
      break;
    }
    StringView item_text = item->Text(*items);
    unsigned next_character_index = character_index + item_text.length();
    if ((character_index <= start_index &&
         start_index < next_character_index) ||
        (character_index < end_index && end_index <= next_character_index) ||
        (start_index < character_index && next_character_index < end_index)) {
      total_length += InlineSize(
          *item, item_text,
          start_index < character_index ? 0 : start_index - character_index,
          std::min(end_index, next_character_index) - character_index);
    }
    character_index = next_character_index;
  }
  return total_length;
}

gfx::PointF SvgTextQuery::StartPositionOfCharacter(unsigned index) const {
  return StartOrEndPosition(query_root_, index, QueryPosition::kStart);
}

gfx::PointF SvgTextQuery::EndPositionOfCharacter(unsigned index) const {
  return StartOrEndPosition(query_root_, index, QueryPosition::kEnd);
}

gfx::RectF SvgTextQuery::ExtentOfCharacter(unsigned index) const {
  auto [item, char_rect] = ScaledCharacterRectInContainer(query_root_, index);
  DCHECK(item->IsSvgText());
  if (item->IsHiddenForPaint()) {
    return gfx::RectF();
  }
  if (item->HasSvgTransformForPaint()) {
    char_rect = item->BuildSvgTransformForPaint().MapRect(char_rect);
  }
  char_rect.Scale(1 / item->SvgScalingFactor());
  return char_rect;
}

float SvgTextQuery::RotationOfCharacter(unsigned index) const {
  auto [item, item_text, start_ifc_offset, end_ifc_offset] =
      FindFragmentItemForAddressableCodeUnitIndex(query_root_, index);
  DCHECK(item);
  DCHECK(item->IsSvgText());
  if (item->IsHiddenForPaint()) {
    return 0.0f;
  }
  float rotation = item->GetSvgFragmentData()->angle;
  switch (item->Style().GetWritingMode()) {
    case WritingMode::kHorizontalTb:
      return rotation;
    case WritingMode::kSidewaysRl:
      return rotation + 90.0f;
    case WritingMode::kSidewaysLr:
      return rotation - 90.0f;
    case WritingMode::kVerticalRl:
    case WritingMode::kVerticalLr:
      break;
  }
  ETextOrientation orientation = item->Style().GetTextOrientation();
  if (orientation == ETextOrientation::kUpright) {
    return rotation;
  }
  if (orientation == ETextOrientation::kSideways) {
    return rotation + 90.0f;
  }
  DCHECK_EQ(orientation, ETextOrientation::kMixed);
  CanvasRotationInVertical canvas_rotation;
  // GetCanvasRotation() is called only once because a pair of
  // start_ifc_offset and end_ifc_offset represents a single glyph.
  item->TextShapeResult()->ForEachGlyph(0, start_ifc_offset, end_ifc_offset, 0,
                                        GetCanvasRotation, &canvas_rotation);
  if (IsCanvasRotationInVerticalUpright(canvas_rotation)) {
    return rotation;
  }
  return rotation + 90.0f;
}

// https://svgwg.org/svg2-draft/text.html#__svg__SVGTextContentElement__getCharNumAtPosition
int SvgTextQuery::CharacterNumberAtPosition(const gfx::PointF& position) const {
  // The specification says we should do hit-testing in logical order.
  // However, this does it in visual order in order to match to the legacy SVG
  // <text> behavior.
  auto [item_list, items] = FragmentItemsInVisualOrder(query_root_);

  const FragmentItem* hit_item = nullptr;
  for (const auto* item : item_list) {
    if (!item->IsHiddenForPaint() && item->InclusiveContains(position)) {
      hit_item = item;
      break;
    }
  }
  if (!hit_item) {
    return -1;
  }

  // Count code units before |hit_item|.
  std::sort(item_list.begin(), item_list.end(),
            [](const FragmentItem* a, const FragmentItem* b) {
              return a->StartOffset() < b->StartOffset();
            });
  unsigned addressable_code_unit_count = 0;
  for (const auto* item : item_list) {
    if (item == hit_item) {
      break;
    }
    addressable_code_unit_count += item->Text(*items).length();
  }

  PhysicalOffset transformed_point =
      hit_item->MapPointInContainer(PhysicalOffset::FromPointFRound(position)) -
      hit_item->OffsetInContainerFragment();
  // FragmentItem::TextOffsetForPoint() is not suitable here because it
  // returns an offset for the nearest glyph edge.
  LayoutUnit inline_offset =
      WritingModeConverter({hit_item->GetWritingMode(), TextDirection::kLtr},
                           hit_item->Size())
          .ToLogical(transformed_point, {})
          .inline_offset;
  unsigned offset_in_item =
      hit_item->TextShapeResult()->CreateShapeResult()->OffsetForPosition(
          hit_item->ScaleInlineOffset(inline_offset), BreakGlyphsOption(true));
  return addressable_code_unit_count + offset_in_item;
}

}  // namespace blink
```