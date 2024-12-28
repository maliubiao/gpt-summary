Response:
The user wants a summary of the functionality of the `svg_text_layout_algorithm.cc` file in the Chromium Blink engine. I need to extract the core responsibilities of this algorithm and relate them to web technologies (JavaScript, HTML, CSS) where applicable. I also need to provide examples of logical reasoning within the code (input/output), and point out potential user/developer errors.

Here's a breakdown of the file's function:

1. **Core Function:**  It lays out the individual characters within SVG `<text>` elements, considering various attributes and constraints.
2. **Relationship to Web Technologies:**  It directly implements how SVG text is rendered, which is a feature of HTML and styled with CSS. JavaScript can dynamically modify SVG text and its attributes, influencing this algorithm.
3. **Logical Reasoning:** The algorithm takes character data, SVG attributes, and styling information as input and produces the final positions and orientations of each character.
4. **Common Errors:** Incorrect or conflicting SVG attributes, especially those related to positioning and length, can lead to unexpected rendering.
这是Chromium Blink引擎中负责SVG文本布局的核心算法实现文件。它的主要功能是计算并确定SVG `<text>` 元素及其子元素中每个字符的最终位置和方向，以便在屏幕上正确渲染SVG文本。

以下是其功能的归纳：

1. **初始化和准备 (Setup):**
    *   接收需要布局的内联节点（`InlineNode`, 实际上是 `LayoutSVGInlineText` 或其子类）和书写模式（`WritingMode`）。
    *   根据文本内容的长度预分配存储字符布局信息的空间 (`result_`, `css_positions_`)。
    *   确定文本的书写方向是水平还是垂直。

2. **设置标志位和初始位置 (SetFlags):**
    *   遍历文本内容中的可寻址字符（addressable characters）。
    *   根据字符在文本流中的位置设置 `anchored_chunk` 标志，用于后续的锚定调整。
    *   从CSS渲染器获取每个字符的初始位置 (`CSS_positions_`)，并考虑书写模式的影响。
    *   存储每个字符的内联尺寸 (`inline_size`)。
    *   处理多字符的字形，将后续字符标记为 `middle`。

3. **调整位置：dx, dy (AdjustPositionsDxDy):**
    *   处理 `<tspan>` 等元素上的 `dx` 和 `dy` 属性，这些属性定义了字符相对于前一个字符的偏移量。
    *   累积 `dx` 和 `dy` 的值，并将其应用到每个字符的初始位置上。
    *   考虑缩放因子 (`ScalingFactorAt`) 对 `dx` 和 `dy` 的影响。
    *   对于 `<textPath>` 中的第一个字符，会重置偏移量。

4. **应用 ‘textLength’ 属性 (ApplyTextLengthAttribute):**
    *   处理 `<text>` 和 `<tspan>` 等元素上的 `textLength` 属性，该属性用于调整文本的整体长度。
    *   调用 `ResolveTextLength` 函数来处理每个具有 `textLength` 属性的元素。

5. **解析 ‘textLength’ 属性 (ResolveTextLength):**
    *   计算具有 `textLength` 属性的文本元素的实际渲染长度。
    *   根据 `lengthAdjust` 属性的值（`spacingAndGlyphs` 或 `spacing`）来调整字符的位置和/或字形大小，以使文本的渲染长度符合 `textLength` 的设定值。
    *   对于 `lengthAdjust="spacing"`,  会在字符间均匀分配额外的或减少的空间。
    *   对于 `lengthAdjust="spacingAndGlyphs"`,  会缩放字符的宽度。
    *   考虑内联元素的嵌套关系，确保 `textLength` 属性的应用范围正确。

6. **调整位置：x, y (AdjustPositionsXY):**
    *   处理 `<tspan>` 等元素上的 `x` 和 `y` 属性，这些属性定义了字符的绝对位置。
    *   计算由于 `x` 和 `y` 属性导致的偏移量，并将其应用到字符的位置上。
    *   需要考虑基线偏移 (`baseline-shift`) 的影响。
    *   对于 `<textPath>` 中的第一个字符，会重置块方向的偏移量。

7. **应用锚定 (ApplyAnchoring):**
    *   处理 `<text>` 元素上的 `text-anchor` CSS 属性（`start`, `middle`, `end`），该属性决定了文本相对于其起始位置的对齐方式。
    *   根据 `text-anchor` 的值调整每个文本块的整体位置。
    *   文本块由 `anchored_chunk` 标记确定。

8. **在路径上定位 (PositionOnPath):**
    *   处理 `<textPath>` 元素，该元素使文本沿着指定的路径渲染。
    *   使用 `PathPositionMapper` 计算每个字符在路径上的位置和切线角度。
    *   考虑 `<textPath>` 元素的 `startOffset` 属性。
    *   根据书写模式和旋转角度调整字符的最终位置。
    *   对于不在路径上的字符，会计算 `path_end` 偏移量。

9. **写回片段项 (WriteBackToFragmentItems):**
    *   将计算出的字符位置和属性信息写回到 `FragmentItemsBuilder::ItemWithOffsetList` 中，以便后续的渲染过程使用。

**与 JavaScript, HTML, CSS 的关系：**

*   **HTML:**  此代码直接处理 HTML 中 `<svg>` 标签内的 `<text>`, `<tspan>`, `<textPath>` 等元素。这些元素定义了 SVG 文本的内容和结构。
    *   **举例:**  当 HTML 中存在 `<svg><text>Hello</text></svg>` 时，该算法负责计算 "H", "e", "l", "l", "o" 这五个字符在 SVG 画布上的具体坐标。
*   **CSS:**  此代码会读取和应用与 SVG 文本相关的 CSS 属性，例如 `text-anchor`, `writing-mode`, `direction` 等。
    *   **举例:**  如果 CSS 设置了 `text-anchor: middle;`，则 `ApplyAnchoring` 函数会根据计算出的文本块宽度，将文本水平居中。
*   **JavaScript:** JavaScript 可以动态地创建、修改 SVG 文本元素及其属性。这些修改会触发 Blink 引擎的重新布局，从而调用此算法。
    *   **举例:**  JavaScript 使用 `setAttribute('x', 10)` 修改 `<tspan>` 元素的 `x` 属性后，`AdjustPositionsXY` 函数会在下次布局时将该 `<tspan>` 内的字符移动到新的 x 坐标。

**逻辑推理的假设输入与输出：**

**假设输入:**

*   一个简单的 SVG `<text>` 元素: `<text x="10" y="20">AB</text>`
*   书写模式为水平从左到右。
*   字符 "A" 和 "B" 的初始 CSS 位置分别为 (0, 0) 和 (width\_of\_A, 0)。
*   没有 `dx` 或 `dy` 属性。
*   没有 `textLength` 属性。
*   `text-anchor` 默认为 `start`。

**逻辑推理过程:**

1. **SetFlags:**  "A" 和 "B" 的 `anchored_chunk` 标志可能都会被设置为 true (如果它们在同一行)。获取 "A" 和 "B" 的初始 CSS 位置。
2. **AdjustPositionsDxDy:** 由于没有 `dx` 和 `dy`，此步骤不会改变字符位置。
3. **ApplyTextLengthAttribute:** 没有 `textLength` 属性，此步骤跳过。
4. **AdjustPositionsXY:**  `x="10"` 会导致 `shift.x = 10 - 0 = 10` 对于 "A"，对于 "B"，由于 `resolve.HasX()` 为真， `shift.x` 会被重置为 `10 - (0 + width_of_A) = 10 - width_of_A`。  `y="20"` 会导致类似的垂直方向的偏移。
5. **ApplyAnchoring:** `text-anchor` 为 `start`，不会进行额外的水平调整。
6. **PositionOnPath:** 没有 `<textPath>`，此步骤跳过。

**预期输出:**

*   字符 "A" 的最终位置接近 (10, 20)。
*   字符 "B" 的最终位置接近 (10 + width\_of\_A, 20)。

**用户或编程常见的使用错误举例：**

1. **`textLength` 与实际文本长度不匹配:**  用户可能设置了一个固定的 `textLength` 值，但实际渲染的文本长度可能因为字体、字号等原因而不同。这可能导致文本被拉伸或压缩，如果 `lengthAdjust` 设置不当，可能会出现意想不到的布局。
    *   **例子:** `<text textLength="50">Long Text</text>`，如果 "Long Text" 的自然宽度超过 50 像素，且 `lengthAdjust` 为 `spacing`，字符之间会被挤压。
2. **错误地使用 `x`, `y`, `dx`, `dy` 属性:**  用户可能混淆这些属性的使用，例如在已经设置了绝对位置 `x` 的情况下，又使用 `dx` 进行偏移，导致位置计算混乱。
    *   **例子:** `<tspan x="10" dx="20">Text</tspan>`，用户可能期望文本的起始位置是 30，但实际效果取决于浏览器如何处理这种组合。
3. **`textPath` 的路径问题:**  如果 `<textPath>` 引用的路径无效或路径太短，文本可能无法完全沿着路径渲染，或者根本不显示。
    *   **例子:** `<text><textPath xlink:href="#invalidPath">Text on Path</textPath></text>`，由于 "#invalidPath" 不存在，文本可能不会渲染。
4. **忽略书写模式和方向:**  在处理垂直或从右到左的书写模式时，如果没有正确理解其对坐标和布局的影响，可能会导致文本显示错乱。
    *   **例子:**  在一个 `writing-mode: vertical-lr;` 的 SVG 中，假设 `x` 和 `y` 代表水平和垂直位置，可能会与水平模式下的理解相反。

总结来说，`svg_text_layout_algorithm.cc` 是 Blink 引擎中至关重要的组成部分，它负责将 SVG 文本元素及其属性转化为最终的视觉呈现，并与 HTML、CSS 和 JavaScript 紧密协作，共同构建动态和丰富的 Web 页面。

Prompt: 
```
这是目录为blink/renderer/core/layout/svg/svg_text_layout_algorithm.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/svg/svg_text_layout_algorithm.h"

#include <algorithm>

#include "base/containers/contains.h"
#include "base/ranges/algorithm.h"
#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_inline_text.h"
#include "third_party/blink/renderer/core/layout/svg/layout_svg_text_path.h"
#include "third_party/blink/renderer/core/layout/svg/resolved_text_layout_attributes_iterator.h"
#include "third_party/blink/renderer/core/layout/svg/svg_inline_node_data.h"
#include "third_party/blink/renderer/core/svg/svg_animated_length.h"
#include "third_party/blink/renderer/core/svg/svg_length_context.h"
#include "third_party/blink/renderer/core/svg/svg_text_content_element.h"
#include "third_party/blink/renderer/platform/wtf/text/code_point_iterator.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "ui/gfx/geometry/rect_conversions.h"

namespace blink {

// See https://svgwg.org/svg2-draft/text.html#TextLayoutAlgorithm

SvgTextLayoutAlgorithm::SvgTextLayoutAlgorithm(InlineNode node,
                                               WritingMode writing_mode)
    : inline_node_(node),
      // 1.5. Let "horizontal" be a flag, true if the writing mode of ‘text’
      // is horizontal, false otherwise.
      horizontal_(IsHorizontalWritingMode(writing_mode)),
      inline_direction_(
          WritingDirectionMode(writing_mode, TextDirection::kLtr).InlineEnd()) {
  DCHECK(node.IsSvgText());
}

PhysicalSize SvgTextLayoutAlgorithm::Layout(
    const String& ifc_text_content,
    FragmentItemsBuilder::ItemWithOffsetList& items) {
  TRACE_EVENT0("blink", "SvgTextLayoutAlgorithm::Layout");
  // https://svgwg.org/svg2-draft/text.html#TextLayoutAlgorithm
  //
  // The major difference from the algorithm in the specification:
  // We handle only addressable characters. The size of "result",
  // "CSS_positions", and "resolved" is the number of addressable characters.

  // 1. Setup
  if (!Setup(ifc_text_content.length())) {
    return PhysicalSize();
  }

  // 2. Set flags and assign initial positions
  SetFlags(ifc_text_content, items);
  if (addressable_count_ == 0) {
    return PhysicalSize();
  }

  // 3. Resolve character positioning
  // This was already done in PrepareLayout() step. See
  // SvgTextLayoutAttributesBuilder.
  // Copy |rotate| and |anchored_chunk| fields.
  ResolvedTextLayoutAttributesIterator iterator(
      inline_node_.SvgCharacterDataList());
  for (wtf_size_t i = 0; i < result_.size(); ++i) {
    const SvgCharacterData& resolve = iterator.AdvanceTo(i);
    if (resolve.HasRotate()) {
      result_[i].rotate = resolve.rotate;
    }
    if (resolve.anchored_chunk) {
      result_[i].anchored_chunk = true;
    }
  }

  // 4. Adjust positions: dx, dy
  AdjustPositionsDxDy(items);

  // 5. Apply ‘textLength’ attribute
  ApplyTextLengthAttribute(items);

  // 6. Adjust positions: x, y
  AdjustPositionsXY(items);

  // 7. Apply anchoring
  ApplyAnchoring(items);

  // 8. Position on path
  PositionOnPath(items);

  return WriteBackToFragmentItems(items);
}

bool SvgTextLayoutAlgorithm::Setup(wtf_size_t approximate_count) {
  // 1.2. Let count be the number of DOM characters within the ‘text’ element's
  // subtree.
  // ==> We don't use |count|. We set |addressable_count_| in the step 2.

  // 1.3. Let result be an array of length count whose entries contain the
  // per-character information described above.
  // ... If result is empty, then return result.
  if (approximate_count == 0) {
    return false;
  }
  // ==> We don't fill |result| here. We do it in the step 2.
  result_.reserve(approximate_count);

  // 1.4. Let CSS_positions be an array of length count whose entries will be
  // filled with the x and y positions of the corresponding typographic
  // character in root. The array entries are initialized to (0, 0).
  // ==> We don't fill |CSS_positions| here. We do it in the step 2.
  css_positions_.reserve(approximate_count);
  return true;
}

// This function updates |result_|.
void SvgTextLayoutAlgorithm::SetFlags(
    const String& ifc_text_content,
    const FragmentItemsBuilder::ItemWithOffsetList& items) {
  // This function collects information per an "addressable" character in DOM
  // order. So we need to access FragmentItems in the logical order.
  Vector<wtf_size_t> sorted_item_indexes;
  sorted_item_indexes.reserve(items.size());
  for (wtf_size_t i = 0; i < items.size(); ++i) {
    if (items[i]->Type() == FragmentItem::kText) {
      sorted_item_indexes.push_back(i);
    }
  }
  if (inline_node_.IsBidiEnabled()) {
    base::ranges::sort(sorted_item_indexes, [&](wtf_size_t a, wtf_size_t b) {
      return items[a]->StartOffset() < items[b]->StartOffset();
    });
  }

  bool found_first_character = false;
  for (wtf_size_t i : sorted_item_indexes) {
    // Zero-length item is not addressable.
    if (items[i]->TextLength() == 0) {
      continue;
    }
    SvgPerCharacterInfo info;
    info.item_index = i;
    // 2.3. If the character at index i corresponds to a typographic
    // character at the beginning of a line, then set the "anchored chunk"
    // flag of result[i] to true.
    if (!found_first_character) {
      found_first_character = true;
      info.anchored_chunk = true;
    }
    // 2.4. If addressable is true and middle is false then set
    // CSS_positions[i] to the position of the corresponding typographic
    // character as determined by the CSS renderer.
    const FragmentItem& item = *items[info.item_index];
    const LogicalOffset logical_offset = items[info.item_index].offset;
    LayoutUnit ascent;
    if (const auto* font_data = item.ScaledFont().PrimaryFont()) {
      ascent = font_data->GetFontMetrics().FixedAscent(
          item.Style().GetFontBaseline());
    }
    gfx::PointF offset;
    if (IsHorizontal()) {
      offset.SetPoint(logical_offset.inline_offset,
                      logical_offset.block_offset + ascent);
    } else if (IsVerticalDownward()) {
      offset.SetPoint(-(logical_offset.block_offset + ascent),
                      logical_offset.inline_offset);
    } else {
      offset.SetPoint(logical_offset.block_offset + ascent,
                      -logical_offset.inline_offset);
    }
    css_positions_.push_back(offset);

    info.inline_size = horizontal_ ? item.Size().width : item.Size().height;
    result_.push_back(info);

    StringView item_string(ifc_text_content, item.StartOffset(),
                           item.TextLength());
    // 2.2. Set middle to true if the character at index i is the second or
    // later character that corresponds to a typographic character.
    WTF::CodePointIterator iterator = item_string.begin();
    const WTF::CodePointIterator end = item_string.end();
    for (++iterator; iterator != end; ++iterator) {
      SvgPerCharacterInfo middle_info;
      middle_info.middle = true;
      middle_info.item_index = info.item_index;
      result_.push_back(middle_info);
      css_positions_.push_back(css_positions_.back());
    }
  }
  addressable_count_ = result_.size();
}

void SvgTextLayoutAlgorithm::AdjustPositionsDxDy(
    const FragmentItemsBuilder::ItemWithOffsetList& items) {
  // 1. Let shift be the cumulative x and y shifts due to ‘x’ and ‘y’
  // attributes, initialized to (0,0).
  // TODO(crbug.com/1179585): Report a specification bug on "'x' and 'y'
  // attributes".
  gfx::PointF shift;
  // 2. For each array element with index i in result:
  ResolvedTextLayoutAttributesIterator iterator(
      inline_node_.SvgCharacterDataList());
  for (wtf_size_t i = 0; i < addressable_count_; ++i) {
    const SvgCharacterData& resolve = iterator.AdvanceTo(i);
    // https://github.com/w3c/svgwg/issues/846
    if (resolve.HasX()) {
      shift.set_x(0.0f);
    }
    if (resolve.HasY()) {
      shift.set_y(0.0f);
    }

    // If this character is the first one in a <textPath>, reset both of x
    // and y.
    if (IsFirstCharacterInTextPath(i)) {
      shift.set_x(0.0f);
      shift.set_y(0.0f);
    }

    // 2.1. If resolve_x[i] is unspecified, set it to 0. If resolve_y[i] is
    // unspecified, set it to 0.
    // https://github.com/w3c/svgwg/issues/271
    // 2.2. Let shift.x = shift.x + resolve_x[i] and
    // shift.y = shift.y + resolve_y[i].
    // https://github.com/w3c/svgwg/issues/271
    shift.Offset(resolve.HasDx() ? resolve.dx : 0.0f,
                 resolve.HasDy() ? resolve.dy : 0.0f);
    // 2.3. Let result[i].x = CSS_positions[i].x + shift.x and
    // result[i].y = CSS_positions[i].y + shift.y.
    const float scaling_factor = ScalingFactorAt(items, i);
    result_[i].x =
        ClampTo<float>(css_positions_[i].x() + shift.x() * scaling_factor);
    result_[i].y =
        ClampTo<float>(css_positions_[i].y() + shift.y() * scaling_factor);
  }
}

void SvgTextLayoutAlgorithm::ApplyTextLengthAttribute(
    const FragmentItemsBuilder::ItemWithOffsetList& items) {
  // Start indexes of the highest textLength elements which were already
  // handled by ResolveTextLength().
  Vector<wtf_size_t> resolved_descendant_node_starts;
  for (const auto& range : inline_node_.SvgTextLengthRangeList()) {
    ResolveTextLength(items, range, resolved_descendant_node_starts);
  }
}

// The implementation of step 2 of "Procedure: resolve text length"
// in "5. Apply 'textLength' attribute".
//
// This function is called for elements with textLength in the order of
// closed tags. e.g.
//     <text textLength="...">
//       <tspan textLength="...">...</tspan>
//       <tspan textLength="...">...</tspan>
//     </text>
//    1. Called for the first <tspan>.
//    2. Called for the second <tspan>.
//    3. Called for the <text>.
void SvgTextLayoutAlgorithm::ResolveTextLength(
    const FragmentItemsBuilder::ItemWithOffsetList& items,
    const SvgTextContentRange& range,
    Vector<wtf_size_t>& resolved_descendant_node_starts) {
  const unsigned i = range.start_index;
  const unsigned j_plus_1 = range.end_index + 1;
  auto* element = To<SVGTextContentElement>(range.layout_object->GetNode());
  const float text_length = ClampTo<float>(
      element->textLength()->CurrentValue()->Value(SVGLengthContext(element)) *
      ScalingFactorAt(items, i));
  const SVGLengthAdjustType length_adjust =
      element->lengthAdjust()->CurrentEnumValue();

  // 2.1. Let a = +Infinity and b = −Infinity.
  float min_position = std::numeric_limits<float>::infinity();
  float max_position = -std::numeric_limits<float>::infinity();

  // 2.2. Let i and j be the global index of the first character and last
  // characters in node, respectively.
  // ==> They are computed in TextLayoutAttributeBuilder.

  // 2.3. For each index k in the range [i, j] where the "addressable" flag of
  // result[k] is true:
  for (wtf_size_t k = i; k < j_plus_1; ++k) {
    // 2.3.1. If the character at k is a linefeed or carriage return, return. No
    // adjustments due to ‘textLength’ are made to a node with a forced line
    // break.
    // ==> We don't support white-space:pre yet. crbug.com/366558.

    // 2.3.2. Let pos = the x coordinate of the position in result[k], if the
    // "horizontal" flag is true, and the y coordinate otherwise.
    float min_char_pos = IsHorizontal()         ? *result_[k].x
                         : IsVerticalDownward() ? *result_[k].y
                                                : -*result_[k].y;

    // 2.3.3. Let advance = the advance of the typographic character
    // corresponding to character k.
    float inline_size = result_[k].inline_size;
    // 2.3.4. Set a = min(a, pos, pos + advance).
    min_position = std::min(min_position, min_char_pos);
    // 2.3.5. Set b = max(b, pos, pos + advance).
    max_position = std::max(max_position, min_char_pos + inline_size);
  }
  // 2.4. If a != +Infinity then:
  if (min_position == std::numeric_limits<float>::infinity()) {
    return;
  }
  // 2.4.1. Find the distance delta = ‘textLength’ computed value − (b − a).
  const float delta = text_length - (max_position - min_position);

  float shift;
  if (length_adjust == kSVGLengthAdjustSpacingAndGlyphs) {
    // If the target range contains no glyphs, we do nothing.
    if (min_position >= max_position) {
      return;
    }
    float length_adjust_scale = text_length / (max_position - min_position);
    for (wtf_size_t k = i; k < j_plus_1; ++k) {
      SvgPerCharacterInfo& info = result_[k];
      float original_x = *info.x;
      float original_y = *info.y;
      if (IsHorizontal()) {
        *info.x = min_position + (*info.x - min_position) * length_adjust_scale;
      } else if (IsVerticalDownward()) {
        *info.y = min_position + (*info.y - min_position) * length_adjust_scale;
      } else {
        *info.y =
            -min_position + (*info.y + min_position) * length_adjust_scale;
      }
      info.text_length_shift_x += *info.x - original_x;
      info.text_length_shift_y += *info.y - original_y;
      if (!info.middle && !info.text_length_resolved) {
        info.length_adjust_scale = length_adjust_scale;
        info.inline_size *= length_adjust_scale;
      }
      info.text_length_resolved = true;
    }
    shift = delta;
  } else {
    // 2.4.2. Find n, the total number of typographic characters in this node
    // including any descendant nodes that are not resolved descendant nodes or
    // within a resolved descendant node.
    auto n = base::ranges::count_if(
        base::span(result_).subspan(i, j_plus_1 - i), [](const auto& info) {
          return !info.middle && !info.text_length_resolved;
        });
    // 2.4.3. Let n = n + number of resolved descendant nodes − 1.
    n += base::ranges::count_if(resolved_descendant_node_starts,
                                [i, j_plus_1](const auto& start_index) {
                                  return i <= start_index &&
                                         start_index < j_plus_1;
                                }) -
         1;
    // 2.4.4. Find the per-character adjustment small-delta = delta/n.
    // character_delta should be 0 if n==0 because it means we have no
    // adjustable characters for this textLength.
    float character_delta = n != 0 ? delta / n : 0;
    // 2.4.5. Let shift = 0.
    shift = 0.0f;
    // 2.4.6. For each index k in the range [i,j]:
    //  ==> This loop should run in visual order.
    Vector<wtf_size_t> visual_indexes;
    visual_indexes.reserve(j_plus_1 - i);
    for (wtf_size_t k = i; k < j_plus_1; ++k) {
      visual_indexes.push_back(k);
    }
    if (inline_node_.IsBidiEnabled()) {
      std::sort(visual_indexes.begin(), visual_indexes.end(),
                [&](wtf_size_t a, wtf_size_t b) {
                  return result_[a].item_index < result_[b].item_index;
                });
    }

    for (wtf_size_t k : visual_indexes) {
      SvgPerCharacterInfo& info = result_[k];
      // 2.4.6.1. Add shift to the x coordinate of the position in result[k], if
      // the "horizontal" flag is true, and to the y coordinate otherwise.
      if (IsHorizontal()) {
        *info.x += shift;
        info.text_length_shift_x += shift;
      } else if (IsVerticalDownward()) {
        *info.y += shift;
        info.text_length_shift_y += shift;
      } else {
        *info.y -= shift;
        info.text_length_shift_y -= shift;
      }
      // 2.4.6.2. If the "middle" flag for result[k] is not true and k is not a
      // character in a resolved descendant node other than the first character
      // then shift = shift + small-delta.
      if (!info.middle && (base::Contains(resolved_descendant_node_starts, k) ||
                           !info.text_length_resolved)) {
        shift += character_delta;
      }
      info.text_length_resolved = true;
    }
  }
  // We should shift characters until the end of this text chunk.
  // Note: This is not defined by the algorithm. But it seems major SVG
  // engines work so.
  for (wtf_size_t k = j_plus_1; k < result_.size(); ++k) {
    if (result_[k].anchored_chunk) {
      break;
    }
    if (IsHorizontal()) {
      *result_[k].x += shift;
    } else if (IsVerticalDownward()) {
      *result_[k].y += shift;
    } else {
      *result_[k].y -= shift;
    }
  }

  // Remove resolved_descendant_node_starts entries for descendant nodes,
  // and register an entry for this node.
  auto new_end =
      std::remove_if(resolved_descendant_node_starts.begin(),
                     resolved_descendant_node_starts.end(),
                     [i, j_plus_1](const auto& start_index) {
                       return i <= start_index && start_index < j_plus_1;
                     });
  resolved_descendant_node_starts.erase(new_end,
                                        resolved_descendant_node_starts.end());
  resolved_descendant_node_starts.push_back(i);
}

void SvgTextLayoutAlgorithm::AdjustPositionsXY(
    const FragmentItemsBuilder::ItemWithOffsetList& items) {
  // This function moves characters to
  //   <position specified by x/y attributes>
  //   + <shift specified by dx/dy attributes>
  //   + <baseline-shift done in the inline layout>
  // css_positions_[i].y() for horizontal_ or css_positions_[i].x() for
  // !horizontal_ represents baseline-shift because the block offsets of the
  // normal baseline is 0.

  // 1. Let shift be the current adjustment due to the ‘x’ and ‘y’ attributes,
  // initialized to (0,0).
  gfx::PointF shift;
  // 2. Set index = 1.
  // 3. While index < count:
  // 3.5. Set index to index + 1.
  ResolvedTextLayoutAttributesIterator iterator(
      inline_node_.SvgCharacterDataList());
  for (wtf_size_t i = 0; i < result_.size(); ++i) {
    const float scaling_factor = ScalingFactorAt(items, i);
    const SvgCharacterData& resolve = iterator.AdvanceTo(i);
    // 3.1. If resolved_x[index] is set, then let
    // shift.x = resolved_x[index] − result.x[index].
    // https://github.com/w3c/svgwg/issues/845
    if (resolve.HasX()) {
      shift.set_x(resolve.x * scaling_factor - css_positions_[i].x() -
                  result_[i].text_length_shift_x);
      // Take into account of baseline-shift.
      if (!horizontal_) {
        shift.set_x(shift.x() + css_positions_[i].x());
      }
      shift.set_x(ClampTo<float>(shift.x()));
    }
    // 3.2. If resolved_y[index] is set, then let
    // shift.y = resolved_y[index] − result.y[index].
    // https://github.com/w3c/svgwg/issues/845
    if (resolve.HasY()) {
      shift.set_y(resolve.y * scaling_factor - css_positions_[i].y() -
                  result_[i].text_length_shift_y);
      // Take into account of baseline-shift.
      if (horizontal_) {
        shift.set_y(shift.y() + css_positions_[i].y());
      }
      shift.set_y(ClampTo<float>(shift.y()));
    }

    // If this character is the first one in a <textPath>, reset the
    // block-direction shift.
    if (IsFirstCharacterInTextPath(i)) {
      if (horizontal_) {
        shift.set_y(0.0f);
      } else {
        shift.set_x(0.0f);
      }
    }

    // 3.3. Let result.x[index] = result.x[index] + shift.x and
    // result.y[index] = result.y[index] + shift.y.
    result_[i].x = *result_[i].x + shift.x();
    result_[i].y = *result_[i].y + shift.y();
    // 3.4. If the "middle" and "anchored chunk" flags of result[index] are
    // both true, then:
    if (result_[i].middle && result_[i].anchored_chunk) {
      // 3.4.1. Set the "anchored chunk" flag of result[index] to false.
      result_[i].anchored_chunk = false;
      // 3.4.2. If index + 1 < count, then set the "anchored chunk" flag of
      // result[index + 1] to true.
      if (i + 1 < result_.size()) {
        result_[i + 1].anchored_chunk = true;
      }
    }
  }
}

void SvgTextLayoutAlgorithm::ApplyAnchoring(
    const FragmentItemsBuilder::ItemWithOffsetList& items) {
  DCHECK_GT(result_.size(), 0u);
  DCHECK(result_[0].anchored_chunk);
  // 1. For each slice result[i..j] (inclusive of both i and j), where:
  //  * the "anchored chunk" flag of result[i] is true,
  //  * the "anchored chunk" flags of result[k] where i < k ≤ j are false, and
  //  * j = count − 1 or the "anchored chunk" flag of result[j + 1] is true;
  wtf_size_t i = 0;
  while (i < result_.size()) {
    const wtf_size_t start_index = i + 1;
    auto result_range = base::span(result_).subspan(start_index);
    auto next_anchor = base::ranges::find_if(
        result_range, [](const auto& info) { return info.anchored_chunk; });
    wtf_size_t j =
        start_index + static_cast<wtf_size_t>(
                          std::distance(result_range.begin(), next_anchor) - 1);

    const auto& text_path_ranges = inline_node_.SvgTextPathRangeList();
    const auto text_path_iter =
        base::ranges::find_if(text_path_ranges, [i](const auto& range) {
          return range.start_index <= i && i <= range.end_index;
        });
    if (text_path_iter != text_path_ranges.end()) {
      // Anchoring should be scoped within the <textPath>.
      // Non-anchored text following <textPath> will be handled in
      // PositionOnPath().
      // This affects the third test in svg/batik/text/textOnPath2.svg.
      j = std::min(j, text_path_iter->end_index);
    }

    // 1.1. Let a = +Infinity and b = −Infinity.
    // ==> 'a' is left/top of characters. 'b' is right/top of characters.
    float min_position = std::numeric_limits<float>::infinity();
    float max_position = -std::numeric_limits<float>::infinity();
    // 1.2. For each index k in the range [i, j] where the "addressable" flag
    // of result[k] is true:
    for (wtf_size_t k = i; k <= j; ++k) {
      // The code in this block is simpler than the specification because
      // min_char_pos is always smaller edge of the character though
      // result[k].x/y in the specification is not.

      // 1.2.1. Let pos = the x coordinate of the position in result[k], if
      // the "horizontal" flag is true, and the y coordinate otherwise.
      const float min_char_pos = IsHorizontal()         ? *result_[k].x
                                 : IsVerticalDownward() ? *result_[k].y
                                                        : -*result_[k].y;
      // 2.2.2. Let advance = the advance of the typographic character
      // corresponding to character k.
      const float inline_size = result_[k].inline_size;
      // 2.2.3. Set a = min(a, pos, pos + advance).
      min_position = std::min(min_position, min_char_pos);
      // 2.2.4. Set b = max(b, pos, pos + advance).
      max_position = std::max(max_position, min_char_pos + inline_size);
    }

    // 1.3. if a != +Infinity, then:
    if (min_position != std::numeric_limits<float>::infinity()) {
      // 1.3.1. Let shift be the x coordinate of result[i], if the "horizontal"
      // flag is true, and the y coordinate otherwise.
      float shift = IsHorizontal()         ? *result_[i].x
                    : IsVerticalDownward() ? *result_[i].y
                                           : -*result_[i].y;

      // 1.3.2. Adjust shift based on the value of text-anchor and direction
      // of the element the character at index i is in:
      //  -> (start, ltr) or (end, rtl)
      //       Set shift = shift − a.
      //  -> (start, rtl) or (end, ltr)
      //       Set shift = shift − b.
      //  -> (middle, ltr) or (middle, rtl)
      //       Set shift = shift − (a + b) / 2.
      const ComputedStyle& style = items[result_[i].item_index]->Style();
      const bool is_ltr = style.IsLeftToRightDirection();
      switch (style.TextAnchor()) {
        default:
          NOTREACHED();
        case ETextAnchor::kStart:
          shift = is_ltr ? shift - min_position : shift - max_position;
          break;
        case ETextAnchor::kEnd:
          shift = is_ltr ? shift - max_position : shift - min_position;
          break;
        case ETextAnchor::kMiddle:
          shift = shift - (min_position + max_position) / 2;
          break;
      }

      // 1.3.3. For each index k in the range [i, j]:
      for (wtf_size_t k = i; k <= j; ++k) {
        // 1.3.3.1. Add shift to the x coordinate of the position in result[k],
        // if the "horizontal" flag is true, and to the y coordinate otherwise.
        if (IsHorizontal()) {
          *result_[k].x += shift;
        } else if (IsVerticalDownward()) {
          *result_[k].y += shift;
        } else {
          *result_[k].y -= shift;
        }
      }
    }
    i = j + 1;
  }
}

void SvgTextLayoutAlgorithm::PositionOnPath(
    const FragmentItemsBuilder::ItemWithOffsetList& items) {
  const auto& ranges = inline_node_.SvgTextPathRangeList();
  if (ranges.empty()) {
    return;
  }

  wtf_size_t range_index = 0;
  wtf_size_t in_path_index = WTF::kNotFound;
  std::unique_ptr<PathPositionMapper> path_mapper;

  // 2. Set the "in path" flag to false.
  bool in_path = false;
  // 3. Set the "after path" flag to false.
  bool after_path = false;
  // 4. Let path_end be an offset for characters that follow a ‘textPath’
  // element. Set path_end to (0,0).
  float path_end_x = 0.0f;
  float path_end_y = 0.0f;
  // 1. Set index = 0.
  // 5. While index < count:
  // 5.3. Set index = index + 1.
  for (unsigned index = 0; index < result_.size(); ++index) {
    auto& info = result_[index];
    // 5.1. If the character at index i is within a ‘textPath’ element and
    // corresponds to a typographic character, then:
    if (range_index < ranges.size() &&
        index >= ranges[range_index].start_index &&
        index <= ranges[range_index].end_index) {
      if (!in_path || in_path_index != range_index) {
        path_mapper =
            To<LayoutSVGTextPath>(ranges[range_index].layout_object.Get())
                ->LayoutPath();
      }
      // 5.1.1. Set "in path" flag to true.
      in_path = true;
      in_path_index = range_index;
      info.in_text_path = true;
      // 5.1.2. If the "middle" flag of result[index] is false, then:
      if (!info.middle) {
        const float scaling_factor = ScalingFactorAt(items, index);
        // 5.1.2.1. Let path be the equivalent path of the basic shape element
        // referenced by the ‘textPath’ element, or an empty path if the
        // reference is invalid.
        if (!path_mapper) {
          info.hidden = true;
        } else {
          // 5.1.2.2. If the ‘side’ attribute of the ‘textPath’ element is
          // 'right', then reverse path.
          // ==> We don't support 'side' attribute yet.

          // 5.1.2.4. Let offset be the value of the ‘textPath’ element's
          // ‘startOffset’ attribute, adjusted due to any ‘pathLength’
          // attribute on the referenced element.
          const float offset = path_mapper->StartOffset();

          // 5.1.2.5. Let advance = the advance of the typographic character
          // corresponding to character k.
          // 5.1.2.6. Let (x, y) and angle be the position and angle in
          // result[index].
          // 5.1.2.7. Let mid be a coordinate value depending on the value of
          // the "horizontal" flag:
          //   -> true
          //      mid is x + advance / 2 + offset
          //   -> false
          //      mid is y + advance / 2 + offset
          const float char_offset = IsHorizontal()         ? *info.x
                                    : IsVerticalDownward() ? *info.y
                                                           : -*info.y;
          const float mid =
              (char_offset + info.inline_size / 2) / scaling_factor + offset;

          // 5.1.2.3. Let length be the length of path.
          // 5.1.2.9. If path is a closed subpath depending on the values of
          // text-anchor and direction of the element the character at index is
          // in:
          //   -> (start, ltr) or (end, rtl)
          //      If mid−offset < 0 or mid−offset > length, set the "hidden"
          //      flag of result[index] to true.
          //   -> (middle, ltr) or (middle, rtl)
          //      If mid−offset < −length/2 or mid−offset > length/2, set the
          //      "hidden" flag of result[index] to true.
          //   -> (start, rtl) or (end, ltr)
          //      If mid−offset < −length or mid−offset > 0, set the "hidden"
          //      flag of result[index] to true.
          //
          // ==> Major browsers don't support the special handling for closed
          //     paths.

          // 5.1.2.10. If the hidden flag is false:
          if (!info.hidden) {
            PointAndTangent point_tangent;
            PathPositionMapper::PositionType position_type =
                path_mapper->PointAndNormalAtLength(mid, point_tangent);
            if (position_type != PathPositionMapper::kOnPath) {
              info.hidden = true;
            }
            point_tangent.tangent_in_degrees += info.rotate.value_or(0.0f);
            if (IsVerticalDownward()) {
              point_tangent.tangent_in_degrees -= 90;
            } else if (IsVerticalUpward()) {
              point_tangent.tangent_in_degrees += 90;
            }
            info.rotate = point_tangent.tangent_in_degrees;
            if (*info.rotate == 0.0f) {
              if (IsHorizontal()) {
                info.x = point_tangent.point.x() * scaling_factor -
                         info.inline_size / 2;
                info.y = point_tangent.point.y() * scaling_factor + *info.y;
              } else if (IsVerticalDownward()) {
                info.x = point_tangent.point.x() * scaling_factor + *info.x;
                info.y = point_tangent.point.y() * scaling_factor -
                         info.inline_size / 2;
              } else {
                info.x = point_tangent.point.x() * scaling_factor + *info.x;
                info.y = point_tangent.point.y() * scaling_factor +
                         info.inline_size / 2;
              }
            } else {
              // Unlike the specification, we just set result[index].x/y to the
              // point along the path. The character is moved by an
              // AffineTransform produced from baseline_shift and inline_size/2.
              // See |FragmentItem::BuildSVGTransformForTextPath()|.
              info.baseline_shift = IsHorizontal()         ? *info.y
                                    : IsVerticalDownward() ? *info.x
                                                           : -*info.x;
              info.x = point_tangent.point.x() * scaling_factor;
              info.y = point_tangent.point.y() * scaling_factor;
            }
            info.x = ClampTo<float>(*info.x);
            info.y = ClampTo<float>(*info.y);
          }
        }
      } else {
        // 5.1.3. Otherwise, the "middle" flag of result[index] is true:
        // 5.1.3.1. Set the position and angle values of result[index] to those
        // in result[index − 1].
        info.x = *result_[index - 1].x;
        info.y = *result_[index - 1].y;
        info.rotate = result_[index - 1].rotate;
      }
    } else {
      // 5.2. If the character at index i is not within a ‘textPath’ element
      // and corresponds to a typographic character, then:
      // 5.2.1. If the "in path" flag is true:
      if (in_path) {
        // 5.2.1.1. Set the "in path" flag to false.
        in_path = false;
        // 5.2.1.2. Set the "after path" flag to true.
        after_path = true;
        // 5.2.1.3. Set path_end equal to the end point of the path referenced
        // by ‘textPath’ − the position of result[index].
        //
        // ==> This is not compatible with the legacy layout, in which text
        // following <textPath> is placed on the end of the last character
        // in the <textPath>. However, the specification asks the new behavior
        // explicitly. See the figure before
        // https://svgwg.org/svg2-draft/text.html#TextRenderingOrder .
        // This affects svg/batik/text/{textOnPath,textOnPath2}.svg.
        if (path_mapper) {
          const float scaling_factor = ScalingFactorAt(items, index);
          PointAndTangent point_tangent;
          path_mapper->PointAndNormalAtLength(path_mapper->length(),
                                              point_tangent);
          path_end_x = ClampTo<float>(point_tangent.point.x() * scaling_factor -
                                      *info.x);
          path_end_y = ClampTo<float>(point_tangent.point.y() * scaling_factor -
                                      *info.y);
        } else {
          // The 'current text position' should be at the next to the last
          // drawn character.
          auto result_range = base::span(result_).subspan(index);
          auto reverse_result_range = base::Reversed(result_range);

"""


```