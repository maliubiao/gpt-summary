Response:
My thinking process to analyze the provided C++ code snippet went through these steps:

1. **Identify the core purpose:** The file name `shape_result.cc` and the namespace `blink::fonts::shaping` strongly suggest that this code is responsible for storing and managing the results of text shaping. Text shaping is the process of converting a sequence of characters into a sequence of glyphs (visual representations of characters) for rendering.

2. **Examine the includes:** The included headers provide valuable clues about the code's functionality:
    * `<hb.h>` (HarfBuzz): Indicates interaction with the HarfBuzz library, a key component for complex text layout.
    * `<algorithm>`, `<limits>`, `<memory>`, `<utility>`: Standard C++ library elements for general-purpose programming.
    * `"base/containers/adapters.h"`, `"base/memory/ptr_util.h"`, `"base/numerics/safe_conversions.h"`:  Chromium base library components, hinting at memory management and safe type conversions.
    *  Headers within the same directory (`glyph_bounds_accumulator.h`, `shape_result_inline_headers.h`, etc.):  Suggest modularity and related functionalities.
    * Platform-specific headers (`character_range.h`, `font.h`):  Indicate interaction with Blink's font handling.
    * `"third_party/blink/renderer/platform/text/text_break_iterator.h"`:  Crucial for understanding text segmentation (e.g., word breaking, grapheme breaking).
    * `"third_party/blink/renderer/platform/wtf/size_assertions.h"`, `"third_party/blink/renderer/platform/wtf/text/string_builder.h"`: WTF (Web Template Framework) utilities, likely for debugging and string manipulation.
    * `"ui/gfx/geometry/skia_conversions.h"`: Interaction with Skia graphics library for geometry calculations.

3. **Analyze the main class `ShapeResult`:**
    * **Member variables:**  The member variables of `ShapeResult` provide direct insight into the data it holds:
        * `width_`: The overall width of the shaped text.
        * `runs_`: A vector of `RunInfo` objects, suggesting that shaped text is broken down into runs (likely based on font, script, or direction).
        * `character_position_`: Information about the position of individual characters.
        * `primary_font_`: The main font used.
        * `start_index_`, `num_characters_`: The range of characters this `ShapeResult` represents.
        * `direction_`: The text direction (LTR or RTL).
        * Flags (`has_vertical_offsets_`, `is_applied_spacing_`).
    * **Nested class `RunInfo`:**  This class likely represents a contiguous segment of text shaped with the same properties. Its members (like `glyph_data_`, `graphemes_`, `start_index_`, `num_characters_`, `direction_`, `font_data_`, `width_`) further clarify the information stored for each run.
    * **Nested struct `HarfBuzzRunGlyphData`:** This represents information about a single glyph within a run: its ID, the corresponding character index, and its advance width.

4. **Examine the methods:** The methods of `ShapeResult` and `RunInfo` reveal the operations that can be performed on the shaped text data:
    * **Methods related to breaking:** `NextSafeToBreakOffset`, `PreviousSafeToBreakOffset`, `IsStartSafeToBreak`, `AddUnsafeToBreak`:  Deal with finding appropriate places to break lines or words.
    * **Methods related to positioning:** `XPositionForOffset`, `XPositionForVisualOffset`, `CharacterIndexForXPosition`, `OffsetForPosition`, `CaretPositionForOffset`: Handle mapping between character offsets and pixel positions, essential for cursor placement and hit testing.
    * **Methods related to graphemes:** `EnsureGraphemes`, `NumGraphemes`, `CountGraphemesInCluster`: Work with grapheme clusters (user-perceived characters), which can consist of multiple code points.
    * **Methods related to glyphs:** `ForEachGlyph`: Allows iterating over the generated glyphs.
    * **Utility methods:** `ByteSize`, `Trace`, constructors, destructor.

5. **Identify connections to web technologies (JavaScript, HTML, CSS):**
    * **HTML:** The shaping process is crucial for rendering text content within HTML elements. The `ShapeResult` stores the necessary information to accurately position glyphs within the layout of a webpage.
    * **CSS:** CSS properties like `font-family`, `font-size`, `direction`, `letter-spacing`, and `word-spacing` directly influence the shaping process and the data stored in `ShapeResult`.
    * **JavaScript:** JavaScript can interact with the rendered text through APIs like `getBoundingClientRect`, which relies on the layout information generated during shaping. Text selection in JavaScript also depends on the mapping between character offsets and visual positions.

6. **Infer logic and potential usage errors:**
    * The code heavily relies on character and glyph indices. Incorrect handling of these indices (e.g., off-by-one errors, using logical vs. visual indices incorrectly) can lead to incorrect positioning and hit testing.
    * The distinction between character offsets and grapheme offsets is important. Functions dealing with visual layout often need to work with graphemes.
    * Assumptions about text direction (LTR vs. RTL) need to be handled correctly throughout the code.
    * The `EnsureGraphemes` function suggests that grapheme information might be computed lazily, potentially leading to performance considerations.

7. **Structure the summary:** Based on the above analysis, I structured the summary to cover the key aspects of the file's functionality:
    * **Core Function:**  Start with the primary purpose.
    * **Key Data Structures:** Describe the main classes and their roles.
    * **Core Functionalities:** List the main operations performed by the code.
    * **Relationship to Web Technologies:** Explain how the code relates to JavaScript, HTML, and CSS, providing specific examples.
    * **Logical Inferences:** Include assumptions about inputs, outputs, and the underlying logic.
    * **Potential Errors:** Highlight common pitfalls for developers using or interacting with this code.
    * **Summary of Part 1:** Briefly reiterate the main role of the code as presented in this first part.

By following these steps, I could systematically dissect the C++ code and extract meaningful information about its purpose and functionality within the Blink rendering engine. The key was to leverage the file name, included headers, class structures, and method names to infer the underlying logic and its role in the broader context of web rendering.
## 功能归纳：blink/renderer/platform/fonts/shaping/shape_result.cc (第1部分)

这个C++源代码文件 `shape_result.cc` (第一部分) 主要定义了 `ShapeResult` 类及其相关的辅助结构体，**用于存储和管理文本 shaping（字形生成）的结果**。 Shaping 是将一段文本（字符序列）转换为一系列可渲染的字形（glyphs）的过程，这个过程会考虑字体、语言、书写方向等因素。

**具体功能可以归纳为:**

1. **数据存储:**  `ShapeResult` 类是核心的数据容器，它存储了文本 shaping 后的各种信息，包括：
    * **文本范围:**  处理的字符起始索引 (`start_index_`) 和字符数量 (`num_characters_`)。
    * **整体属性:**  文本的宽度 (`width_`) 和书写方向 (`direction_`)。
    * **字形信息:**
        *  一个或多个 `RunInfo` 对象，每个 `RunInfo` 代表一段具有相同属性（例如，相同的字体）的连续字形序列。
        *  在 `RunInfo` 中，存储了每个字形的具体信息，例如字形 ID、对应的字符索引、以及字形的排版前进量 (`advance`)。
    * **其他元数据:**  例如，是否包含垂直偏移信息 (`has_vertical_offsets_`)，是否应用了间距 (`is_applied_spacing_`)。
    * **字符位置信息:** `character_position_` 存储了每个字符的额外数据，例如可能的字形边界信息。

2. **辅助数据结构:**  定义了辅助的结构体来组织和存储 shaping 结果的细节：
    * **`RunInfo`:**  存储了一段连续的具有相同属性的字形序列的信息，包括：
        *  字形数据集合 (`glyph_data_`)，包含每个字形的 ID、对应的字符索引和前进量。
        *  字体的指针 (`font_data_`)。
        *  字形边界信息 (`graphemes_`)，用于处理组合字符。
        *  是否安全打断的信息 (`safe_to_break_before`)。
    * **`HarfBuzzRunGlyphData`:**  存储单个字形的详细信息，如字形 ID (`glyph`)、字符索引 (`character_index`) 和排版前进量 (`advance`)。

3. **安全打断点管理:**  `ShapeResult` 和 `RunInfo` 提供了方法来查询和管理文本中的安全打断点。 这些打断点用于确定换行、断句等的合适位置。

4. **字符与像素位置的映射:**  `RunInfo` 提供了方法 (`XPositionForOffset`, `XPositionForVisualOffset`)，用于将字符的偏移量映射到水平像素位置。这对于光标定位、文本选择等功能至关重要。

5. **像素位置与字符的映射:**  `RunInfo` 提供了方法 (`CharacterIndexForXPosition`)，用于将给定的水平像素位置映射回对应的字符索引。这对于点击测试（hit testing）等交互功能非常重要。

6. **Grapheme 簇处理:**  `RunInfo` 提供了方法 (`EnsureGraphemes`, `NumGraphemes`) 来处理 Grapheme 簇（用户感知到的单个字符，可能由多个 Unicode 代码点组成）。这对于正确计算字符数量和进行基于字符的操作非常重要。

**与 JavaScript, HTML, CSS 的关系举例:**

* **HTML:** 当浏览器渲染 HTML 文档中的文本内容时，会进行 shaping 过程。 `ShapeResult` 存储了这段文本 shaping 后的结果，这些结果最终被用于在屏幕上绘制出正确的字形。例如，对于 `<p>This is some text.</p>` 标签内的文本，`ShapeResult` 会存储每个字符对应的字形信息，以及这些字形在段落中的位置。
* **CSS:** CSS 样式，如 `font-family` (字体选择), `font-size` (字体大小), `direction` (文本方向，如 `rtl` 或 `ltr`), `letter-spacing` (字母间距) 等，都会直接影响 shaping 的结果。不同的 CSS 样式会导致生成不同的 `ShapeResult` 对象。例如，如果 CSS 中指定了 `direction: rtl;`，那么 `ShapeResult` 中存储的字形排列顺序和前进方向会与默认的 `ltr` 情况相反。
* **JavaScript:** JavaScript 可以通过 DOM API 获取文本元素的几何信息，例如使用 `getBoundingClientRect()` 方法。这个方法返回的文本元素的边界信息，背后就依赖于 `ShapeResult` 中存储的字形位置等信息。 另外，JavaScript 进行文本选择操作时，也需要依赖字符与像素位置的映射关系，而 `ShapeResult` 提供的相关方法就参与了这个过程。 例如，当用户在网页上拖动鼠标选择文本时，浏览器会使用 `ShapeResult` 的方法来确定鼠标位置对应的字符范围。

**逻辑推理举例 (假设输入与输出):**

**假设输入:**

* 一段字符串: "你好世界"
* 使用的字体: "SimSun"
* CSS 样式: `direction: ltr;`

**逻辑推理过程 (简化):**

1. Shaping 引擎会分析输入字符串，确定每个字符需要使用哪个字形（根据字体 "SimSun"）。
2. 根据字体和 CSS 样式（`ltr`），确定字形的排列方向是从左到右。
3. 计算每个字形的宽度（advance）。

**输出 (存储在 `ShapeResult` 中):**

* `num_characters_`: 4
* `direction_`: `TextDirection::kLtr`
* `runs_`:  可能包含一个 `RunInfo` 对象 (如果所有字符都使用相同的字体)
    * `RunInfo.num_characters_`: 4
    * `RunInfo.glyph_data_`: 包含 4 个 `HarfBuzzRunGlyphData` 对象，分别对应 "你", "好", "世", "界" 这四个字符。
        * 每个 `HarfBuzzRunGlyphData` 对象会包含对应的字形 ID 和 advance 值。 例如，对于 "你"，`glyph` 可能是一个数字，`advance` 可能是 15.0 (像素)。
* `width_`:  所有字形 advance 值的总和，例如 15.0 + 16.0 + 14.5 + 17.0 = 62.5 (像素)。

**用户或编程常见的使用错误举例:**

1. **错误地假设字符和字形一一对应:**  在复杂的文本排版中，一个字符可能对应多个字形（例如，组合字符），或者多个字符可能合并成一个字形（例如，连字）。如果代码直接使用字符索引来访问字形数据，而没有考虑到这种一对多或多对一的关系，就会导致错误。`ShapeResult` 中使用 `RunInfo` 和 `HarfBuzzRunGlyphData` 来正确表示这种映射关系。
2. **忽略文本方向:**  在处理双向文本（既包含从左到右的文本，也包含从右到左的文本）时，如果没有正确处理文本方向，会导致字形排列顺序错误。 `ShapeResult` 中的 `direction_` 属性以及 `RunInfo` 中的相关信息就是为了解决这个问题。
3. **在像素定位时使用字符索引，而不是依赖 `ShapeResult` 的映射方法:**  开发者可能会尝试自己计算字符在屏幕上的位置，而不是使用 `ShapeResult` 提供的 `XPositionForOffset` 等方法。这样做很容易出错，因为 shaping 过程考虑了很多复杂的因素，例如字距调整、连字等，简单的字符宽度累加无法得到正确的结果。

**总结一下它的功能 (针对第 1 部分):**

`blink/renderer/platform/fonts/shaping/shape_result.cc` (第 1 部分) 的主要功能是 **定义了用于存储和组织文本 shaping 结果的数据结构** (`ShapeResult`, `RunInfo`, `HarfBuzzRunGlyphData`)，并提供了一些 **基本的查询和管理方法**，例如获取安全打断点，以及在字符偏移量和像素位置之间进行映射。 它是 Blink 渲染引擎中处理文本显示的关键组件，为后续的文本绘制、光标定位、文本选择等功能提供了基础数据。

### 提示词
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (c) 2012 Google Inc. All rights reserved.
 * Copyright (C) 2013 BlackBerry Limited. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/shaping/shape_result.h"

#include <hb.h>
#include <algorithm>
#include <limits>
#include <memory>
#include <utility>

#include "base/containers/adapters.h"
#include "base/memory/ptr_util.h"
#include "base/numerics/safe_conversions.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/fonts/character_range.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/shaping/glyph_bounds_accumulator.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_inline_headers.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_spacing.h"
#include "third_party/blink/renderer/platform/fonts/shaping/text_auto_space.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

constexpr unsigned HarfBuzzRunGlyphData::kMaxCharacterIndex;
constexpr unsigned HarfBuzzRunGlyphData::kMaxGlyphs;

struct SameSizeAsHarfBuzzRunGlyphData {
  unsigned glyph : 16;
  unsigned char_index_and_bit_field : 16;
  float advance;
};

ASSERT_SIZE(HarfBuzzRunGlyphData, SameSizeAsHarfBuzzRunGlyphData);

struct SameSizeAsRunInfo {
  struct GlyphDataCollection {
    void* pointers[2];
    unsigned integer;
  } glyph_data;
  Member<void*> pointer;
  Vector<int> vector;
  int integers[6];
};

ASSERT_SIZE(ShapeResult::RunInfo, SameSizeAsRunInfo);

struct SameSizeAsShapeResult {
  float width;
  UntracedMember<void*> deprecated_ink_bounds_;
  Vector<int> runs_;
  Vector<int> character_position_;
  UntracedMember<void*> primary_font_;
  unsigned start_index_;
  unsigned num_characters_;
  unsigned bitfields : 32;
};

ASSERT_SIZE(ShapeResult, SameSizeAsShapeResult);

unsigned ShapeResult::RunInfo::NextSafeToBreakOffset(unsigned offset) const {
  DCHECK_LE(offset, num_characters_);
  if (IsLtr()) {
    for (const auto& glyph_data : glyph_data_) {
      if (glyph_data.safe_to_break_before &&
          glyph_data.character_index >= offset)
        return glyph_data.character_index;
    }
  } else {
    for (const auto& glyph_data : base::Reversed(glyph_data_)) {
      if (glyph_data.safe_to_break_before &&
          glyph_data.character_index >= offset)
        return glyph_data.character_index;
    }
  }

  // Next safe break is at the end of the run.
  return num_characters_;
}

unsigned ShapeResult::RunInfo::PreviousSafeToBreakOffset(
    unsigned offset) const {
  if (offset >= num_characters_)
    return num_characters_;
  if (IsLtr()) {
    for (const auto& glyph_data : base::Reversed(glyph_data_)) {
      if (glyph_data.safe_to_break_before &&
          glyph_data.character_index <= offset)
        return glyph_data.character_index;
    }
  } else {
    for (const auto& glyph_data : glyph_data_) {
      if (glyph_data.safe_to_break_before &&
          glyph_data.character_index <= offset)
        return glyph_data.character_index;
    }
  }

  // Next safe break is at the start of the run.
  return 0;
}

float ShapeResult::RunInfo::XPositionForVisualOffset(
    unsigned offset,
    AdjustMidCluster adjust_mid_cluster) const {
  DCHECK_LT(offset, num_characters_);
  if (IsRtl())
    offset = num_characters_ - offset - 1;
  return XPositionForOffset(offset, adjust_mid_cluster);
}

unsigned ShapeResult::RunInfo::NumGraphemes(unsigned start,
                                            unsigned end) const {
  if (graphemes_.size() == 0 || start >= num_characters_)
    return 0;
  CHECK_LT(start, end);
  CHECK_LE(end, num_characters_);
  CHECK_EQ(num_characters_, graphemes_.size());
  return graphemes_[end - 1] - graphemes_[start] + 1;
}

void ShapeResult::EnsureGraphemes(const StringView& text) const {
  CHECK_EQ(NumCharacters(), text.length());

  // Hit-testing, canvas, etc. may still call this function for 0-length text,
  // or glyphs may be missing at all.
  if (runs_.empty())
    return;

  bool is_computed = !runs_.front()->graphemes_.empty();
#if DCHECK_IS_ON()
  for (const auto& run : runs_)
    DCHECK_EQ(is_computed, !run->graphemes_.empty());
#endif
  if (is_computed)
    return;

  unsigned result_start_index = StartIndex();
  for (const Member<RunInfo>& run : runs_) {
    if (!run)
      continue;
    DCHECK_GE(run->start_index_, result_start_index);
    GraphemesClusterList(
        StringView(text, run->start_index_ - result_start_index,
                   run->num_characters_),
        &run->graphemes_);
  }
}

// XPositionForOffset returns the X position (in layout space) from the
// beginning of the run to the beginning of the cluster of glyphs for X
// character.
// For RTL, beginning means the right most side of the cluster.
// Characters may spawn multiple glyphs.
// In the case that multiple characters form a Unicode grapheme cluster, we
// distribute the width of the grapheme cluster among the number of cursor
// positions returned by cursor-based TextBreakIterator.
float ShapeResult::RunInfo::XPositionForOffset(
    unsigned offset,
    AdjustMidCluster adjust_mid_cluster) const {
  DCHECK_LE(offset, num_characters_);
  const unsigned num_glyphs = glyph_data_.size();

  // In this context, a glyph sequence is a sequence of glyphs that shares the
  // same character_index and therefore represent the same interval of source
  // characters. glyph_sequence_start marks the character index at the beginning
  // of the interval of characters for which this glyph sequence was formed as
  // the result of shaping; glyph_sequence_end marks the end of the interval of
  // characters for which this glyph sequence was formed. [glyph_sequence_start,
  // glyph_sequence_end) is inclusive on the start for the range of characters
  // of the current sequence we are visiting.
  unsigned glyph_sequence_start = 0;
  unsigned glyph_sequence_end = num_characters_;
  // the advance of the current glyph sequence.
  InlineLayoutUnit glyph_sequence_advance;
  // the accumulated advance up to the current glyph sequence.
  InlineLayoutUnit accumulated_position;

  if (IsLtr()) {
    for (unsigned i = 0; i < num_glyphs; ++i) {
      unsigned current_glyph_char_index = glyph_data_[i].character_index;
      // If this glyph is still part of the same glyph sequence for the grapheme
      // cluster at character index glyph_sequence_start, add its advance to the
      // glyph_sequence's advance.
      if (glyph_sequence_start == current_glyph_char_index) {
        glyph_sequence_advance += glyph_data_[i].advance;
        continue;
      }

      // We are about to move out of a glyph sequence that contains offset, so
      // the current glyph sequence is the one we are looking for.
      if (glyph_sequence_start <= offset && offset < current_glyph_char_index) {
        glyph_sequence_end = current_glyph_char_index;
        break;
      }

      glyph_sequence_start = current_glyph_char_index;
      // Since we always update glyph_sequence_end when we break, set this to
      // last_character in case this is the final iteration of the loop.
      glyph_sequence_end = num_characters_;
      accumulated_position += glyph_sequence_advance;
      glyph_sequence_advance = glyph_data_[i].advance;
    }

  } else {
    glyph_sequence_start = glyph_sequence_end = num_characters_;

    for (unsigned i = 0; i < num_glyphs; ++i) {
      unsigned current_glyph_char_index = glyph_data_[i].character_index;
      // If this glyph is still part of the same glyph sequence for the grapheme
      // cluster at character index glyph_sequence_start, add its advance to the
      // glyph_sequence's advance.
      if (glyph_sequence_start == current_glyph_char_index) {
        glyph_sequence_advance += glyph_data_[i].advance;
        continue;
      }

      // We are about to move out of a glyph sequence that contains offset, so
      // the current glyph sequence is the one we are looking for.
      if (glyph_sequence_start <= offset && offset < glyph_sequence_end) {
        break;
      }

      glyph_sequence_end = glyph_sequence_start;
      glyph_sequence_start = current_glyph_char_index;
      accumulated_position += glyph_sequence_advance;
      glyph_sequence_advance = glyph_data_[i].advance;
    }
  }

  // Determine if the offset is at the beginning of the current glyph sequence.
  bool is_offset_at_glyph_sequence_start = (offset == glyph_sequence_start);

  // We calculate the number of Unicode grapheme clusters (actually cursor
  // position stops) on the subset of characters. We use this to divide
  // glyph_sequence_advance by the number of unicode grapheme clusters this
  // glyph sequence was shaped for, and thus linearly interpolate the cursor
  // position based on accumulated position and a fraction of
  // glyph_sequence_advance.
  unsigned graphemes = NumGraphemes(glyph_sequence_start, glyph_sequence_end);
  if (graphemes > 1) {
    DCHECK_GE(glyph_sequence_end, glyph_sequence_start);
    unsigned next_offset = offset + (offset == num_characters_ ? 0 : 1);
    unsigned num_graphemes_to_offset =
        NumGraphemes(glyph_sequence_start, next_offset) - 1;
    // |is_offset_at_glyph_sequence_start| bool variable above does not take
    // into account the case of broken glyphs (with multi graphemes) scenarios,
    // so make amend here. Check if the offset is at the beginning of the
    // specific grapheme cluster in the broken glyphs.
    if (offset > 0) {
      is_offset_at_glyph_sequence_start =
          (NumGraphemes(offset - 1, next_offset) != 1);
    }
    glyph_sequence_advance = glyph_sequence_advance / graphemes;
    const unsigned num_graphemes_from_left =
        IsLtr() ? num_graphemes_to_offset
                : graphemes - num_graphemes_to_offset - 1;
    accumulated_position += glyph_sequence_advance * num_graphemes_from_left;
  }

  // Re-adapt based on adjust_mid_cluster. On LTR, if we want AdjustToEnd and
  // offset is not at the beginning, we need to jump to the right side of the
  // grapheme. On RTL, if we want AdjustToStart and offset is not at the end, we
  // need to jump to the left side of the grapheme.
  if (IsLtr() && adjust_mid_cluster == AdjustMidCluster::kToEnd &&
      !is_offset_at_glyph_sequence_start) {
    accumulated_position += glyph_sequence_advance;
  } else if (IsRtl() && adjust_mid_cluster == AdjustMidCluster::kToEnd &&
             !is_offset_at_glyph_sequence_start) {
    accumulated_position -= glyph_sequence_advance;
  }

  if (IsRtl()) {
    // For RTL, we return the right side.
    accumulated_position += glyph_sequence_advance;
  }

  return accumulated_position;
}

// In some ways, CharacterIndexForXPosition is the reverse of
// XPositionForOffset. Given a target pixel distance on screen space, returns a
// character index for the end of the interval that would be included within
// that space. @break_glyphs controls whether we use grapheme information
// to break glyphs into grapheme clusters and return character that are a part
// of a glyph.
void ShapeResult::RunInfo::CharacterIndexForXPosition(
    float target_x,
    BreakGlyphsOption break_glyphs,
    GlyphIndexResult* result) const {
  DCHECK(target_x >= 0 && target_x <= width_);

  result->origin_x = 0;
  unsigned glyph_sequence_start = 0;
  unsigned glyph_sequence_end = num_characters_;
  result->advance = 0.0;

  // on RTL, we start on the last index.
  if (IsRtl()) {
    glyph_sequence_start = glyph_sequence_end = num_characters_;
  }

  for (const HarfBuzzRunGlyphData& glyph_data : glyph_data_) {
    unsigned current_glyph_char_index = glyph_data.character_index;
    // If the glyph is part of the same sequence, we just accumulate the
    // advance.
    if (glyph_sequence_start == current_glyph_char_index) {
      result->advance += glyph_data.advance.ToFloat();
      continue;
    }

    // Since we are about to move to the next sequence of glyphs, check if
    // the target falls inside it, if it does, we found our sequence.
    if (result->origin_x + result->advance > target_x) {
      if (IsLtr()) {
        glyph_sequence_end = current_glyph_char_index;
      }
      break;
    }

    // Move to the next sequence, update accumulated_x.
    if (IsRtl()) {
      // Notice that on RTL, as we move to our next sequence, we already know
      // both bounds. Nonetheless, we still need to move forward so we can
      // capture all glyphs of this sequence.
      glyph_sequence_end = glyph_sequence_start;
    }
    glyph_sequence_start = current_glyph_char_index;
    result->origin_x += result->advance;
    result->advance = glyph_data.advance;
  }

  // At this point, we have [glyph_sequence_start, glyph_sequence_end)
  // representing a sequence of glyphs, of size glyph_sequence_advance. We
  // linearly interpolate how much space each character takes, and reduce the
  // sequence to only match the character size.
  if (break_glyphs && glyph_sequence_end > glyph_sequence_start) {
    int graphemes = NumGraphemes(glyph_sequence_start, glyph_sequence_end);
    if (graphemes > 1) {
      float unit_size = result->advance / graphemes;
      unsigned step = floor((target_x - result->origin_x) / unit_size);
      unsigned glyph_length = glyph_sequence_end - glyph_sequence_start;
      unsigned final_size = floor(glyph_length / graphemes);
      result->origin_x += unit_size * step;
      if (IsLtr()) {
        glyph_sequence_start += step;
        glyph_sequence_end = glyph_sequence_start + final_size;
      } else {
        glyph_sequence_end -= step;
        glyph_sequence_start = glyph_sequence_end - final_size;
      }
      result->advance = unit_size;
    }
  }

  if (IsLtr()) {
    result->left_character_index = glyph_sequence_start;
    result->right_character_index = glyph_sequence_end;
  } else {
    result->left_character_index = glyph_sequence_end;
    result->right_character_index = glyph_sequence_start;
  }
}

ShapeResult::ShapeResult(const SimpleFontData* font_data,
                         unsigned start_index,
                         unsigned num_characters,
                         TextDirection direction)
    : primary_font_(font_data),
      start_index_(start_index),
      num_characters_(num_characters),
      direction_(static_cast<unsigned>(direction)) {}

ShapeResult::ShapeResult(const Font* font,
                         unsigned start_index,
                         unsigned num_characters,
                         TextDirection direction)
    : ShapeResult(font->PrimaryFont(), start_index, num_characters, direction) {
}

ShapeResult::ShapeResult(const ShapeResult& other)
    : width_(other.width_),
      primary_font_(other.primary_font_),
      start_index_(other.start_index_),
      num_characters_(other.num_characters_),
      num_glyphs_(other.num_glyphs_),
      direction_(other.direction_),
      has_vertical_offsets_(other.has_vertical_offsets_),
      is_applied_spacing_(other.is_applied_spacing_) {
  runs_.ReserveInitialCapacity(other.runs_.size());
  for (const auto& run : other.runs_)
    runs_.push_back(MakeGarbageCollected<RunInfo>(*run));
}

ShapeResult::~ShapeResult() = default;

void ShapeResult::Trace(Visitor* visitor) const {
  visitor->Trace(deprecated_ink_bounds_);
  visitor->Trace(runs_);
  visitor->Trace(character_position_);
  visitor->Trace(primary_font_);
}

size_t ShapeResult::ByteSize() const {
  size_t self_byte_size = sizeof(*this);
  for (unsigned i = 0; i < runs_.size(); ++i) {
    self_byte_size += runs_[i]->ByteSize();
  }
  return self_byte_size;
}

const ShapeResultCharacterData& ShapeResult::CharacterData(
    unsigned offset) const {
  DCHECK_GE(offset, StartIndex());
  DCHECK_LT(offset, EndIndex());
  DCHECK(!character_position_.empty());
  return character_position_[offset - StartIndex()];
}

ShapeResultCharacterData& ShapeResult::CharacterData(unsigned offset) {
  DCHECK_GE(offset, StartIndex());
  DCHECK_LT(offset, EndIndex());
  DCHECK(!character_position_.empty());
  return character_position_[offset - StartIndex()];
}

bool ShapeResult::IsStartSafeToBreak() const {
  // Empty is likely a |SubRange| at the middle of a cluster or a ligature.
  if (runs_.empty()) [[unlikely]] {
    return false;
  }
  const RunInfo* run = nullptr;
  const HarfBuzzRunGlyphData* glyph_data = nullptr;
  if (IsLtr()) {
    run = runs_.front().Get();
    glyph_data = &run->glyph_data_.front();
  } else {
    run = runs_.back().Get();
    glyph_data = &run->glyph_data_.back();
  }
  return glyph_data->safe_to_break_before &&
         // If the glyph for the first character is missing, consider not safe.
         StartIndex() == run->start_index_ + glyph_data->character_index;
}

unsigned ShapeResult::NextSafeToBreakOffset(unsigned index) const {
  for (auto it = runs_.begin(); it != runs_.end(); ++it) {
    const auto& run = *it;
    if (!run)
      continue;

    unsigned run_start = run->start_index_;
    if (index >= run_start) {
      unsigned offset = index - run_start;
      if (offset < run->num_characters_) {
        return run->NextSafeToBreakOffset(offset) + run_start;
      }
      if (IsRtl()) {
        if (it == runs_.begin())
          return run_start + run->num_characters_;
        const auto& previous_run = *--it;
        return previous_run->start_index_;
      }
    } else if (IsLtr()) {
      return run_start;
    }
  }

  return EndIndex();
}

unsigned ShapeResult::PreviousSafeToBreakOffset(unsigned index) const {
  for (auto it = runs_.rbegin(); it != runs_.rend(); ++it) {
    const auto& run = *it;
    if (!run)
      continue;

    unsigned run_start = run->start_index_;
    if (index >= run_start) {
      unsigned offset = index - run_start;
      if (offset <= run->num_characters_) {
        return run->PreviousSafeToBreakOffset(offset) + run_start;
      }
      if (IsLtr()) {
        return run_start + run->num_characters_;
      }
    } else if (IsRtl()) {
      if (it == runs_.rbegin())
        return run->start_index_;
      const auto& previous_run = *--it;
      return previous_run->start_index_ + previous_run->num_characters_;
    }
  }

  return StartIndex();
}

template <typename Iterator>
void ShapeResult::AddUnsafeToBreak(Iterator offsets_iter,
                                   const Iterator offsets_end) {
  CHECK(offsets_iter != offsets_end);
#if EXPENSIVE_DCHECKS_ARE_ON()
  DCHECK(character_position_.empty());
  DCHECK(std::is_sorted(
      offsets_iter, offsets_end,
      IsLtr() ? [](unsigned a, unsigned b) { return a < b; }
              : [](unsigned a, unsigned b) { return a > b; }));
  DCHECK_GE(*offsets_iter, StartIndex());
#endif
  unsigned offset = *offsets_iter;
  for (const auto& run : runs_) {
    unsigned run_offset = offset - run->StartIndex();
    if (run_offset >= run->num_characters_) {
      continue;
    }
    for (HarfBuzzRunGlyphData& glyph_data : run->glyph_data_) {
      if (glyph_data.character_index == run_offset) {
        glyph_data.safe_to_break_before = false;
        if (++offsets_iter == offsets_end) {
          return;
        }
        offset = *offsets_iter;
        run_offset = offset - run->StartIndex();
        if (run_offset >= run->num_characters_) {
          break;
        }
      }
    }
  }
}

void ShapeResult::AddUnsafeToBreak(base::span<const unsigned> offsets) {
  if (IsLtr()) {
    AddUnsafeToBreak(offsets.begin(), offsets.end());
  } else {
    AddUnsafeToBreak(offsets.rbegin(), offsets.rend());
  }
}

// If the position is outside of the result, returns the start or the end offset
// depends on the position.
void ShapeResult::OffsetForPosition(float target_x,
                                    BreakGlyphsOption break_glyphs,
                                    GlyphIndexResult* result) const {
  if (target_x <= 0) {
    if (IsRtl()) {
      result->left_character_index = result->right_character_index =
          NumCharacters();
    }
    return;
  }

  unsigned characters_so_far = IsRtl() ? NumCharacters() : 0;
  float current_x = 0;

  for (const Member<RunInfo>& run : runs_) {
    if (!run)
      continue;
    if (IsRtl())
      characters_so_far -= run->num_characters_;
    float next_x = current_x + run->width_;
    float offset_for_run = target_x - current_x;
    if (offset_for_run >= 0 && offset_for_run < run->width_) {
      // The x value in question is within this script run.
      run->CharacterIndexForXPosition(offset_for_run, break_glyphs, result);
      result->characters_on_left_runs = characters_so_far;
      if (IsRtl()) {
        result->left_character_index =
            characters_so_far + result->left_character_index;
        result->right_character_index =
            characters_so_far + result->right_character_index;
        DCHECK_LE(result->left_character_index, NumCharacters() + 1);
        DCHECK_LE(result->right_character_index, NumCharacters());
      } else {
        result->left_character_index += characters_so_far;
        result->right_character_index += characters_so_far;
        DCHECK_LE(result->left_character_index, NumCharacters());
        DCHECK_LE(result->right_character_index, NumCharacters() + 1);
      }
      result->origin_x += current_x;
      return;
    }
    if (IsLtr())
      characters_so_far += run->num_characters_;
    current_x = next_x;
  }

  if (IsRtl()) {
    result->left_character_index = 0;
    result->right_character_index = 0;
  } else {
    result->left_character_index += characters_so_far;
    result->right_character_index += characters_so_far;
  }

  result->characters_on_left_runs = characters_so_far;

  DCHECK_LE(result->left_character_index, NumCharacters());
  DCHECK_LE(result->right_character_index, NumCharacters() + 1);
}

unsigned ShapeResult::OffsetForPosition(float x,
                                        BreakGlyphsOption break_glyphs) const {
  GlyphIndexResult result;
  OffsetForPosition(x, break_glyphs, &result);

  // For LTR, the offset is always the left one.
  if (IsLtr())
    return result.left_character_index;

  // For RTL the offset is the right one, except that the interval is open
  // on other side. So in case we are exactly at the boundary, we return the
  // left index.
  if (x == result.origin_x)
    return result.left_character_index;
  return result.right_character_index;
}

unsigned ShapeResult::CaretOffsetForHitTest(
    float x,
    const StringView& text,
    BreakGlyphsOption break_glyphs_option) const {
  if (break_glyphs_option)
    EnsureGraphemes(text);

  GlyphIndexResult result;
  OffsetForPosition(x, break_glyphs_option, &result);

  if (x - result.origin_x <= result.advance / 2)
    return result.left_character_index;
  return result.right_character_index;
}

unsigned ShapeResult::OffsetToFit(float x, TextDirection line_direction) const {
  GlyphIndexResult result;
  OffsetForPosition(x, BreakGlyphsOption(false), &result);

  if (blink::IsLtr(line_direction))
    return result.left_character_index;

  if (x == result.origin_x)
    return result.left_character_index;
  return result.right_character_index;
}

float ShapeResult::PositionForOffset(
    unsigned absolute_offset,
    AdjustMidCluster adjust_mid_cluster) const {
  float x = 0;

  // The absolute_offset argument represents the offset for the entire
  // ShapeResult while offset counts down the remaining offset as runs are
  // processed.
  unsigned offset = absolute_offset;

  if (IsRtl()) {
    // Convert logical offsets to visual offsets, because results are in
    // logical order while runs are in visual order.
    if (offset < NumCharacters())
      offset = NumCharacters() - offset - 1;
  }

  for (unsigned i = 0; i < runs_.size(); i++) {
    if (!runs_[i])
      continue;
    DCHECK_EQ(IsRtl(), runs_[i]->IsRtl());
    unsigned num_characters = runs_[i]->num_characters_;

    if (offset < num_characters) {
      return runs_[i]->XPositionForVisualOffset(offset, adjust_mid_cluster) + x;
    }

    offset -= num_characters;
    x += runs_[i]->width_;
  }

  // The position in question might be just after the text.
  if (absolute_offset == NumCharacters()) {
    return IsRtl() ? 0 : width_;
  }

  return 0;
}

float ShapeResult::CaretPositionForOffset(
    unsigned offset,
    const StringView& text,
    AdjustMidCluster adjust_mid_cluster) const {
  EnsureGraphemes(text);
  return PositionForOffset(offset, adjust_mid_cluster);
}

bool ShapeResult::HasFallbackFonts(const SimpleFontData* primary_font) const {
  for (const Member<RunInfo>& run : runs_) {
    if (run->font_data_ != primary_font) {
      return true;
    }
  }
  return false;
}

void ShapeResult::GetRunFontData(HeapVector<RunFontData>* font_data) const {
  for (const auto& run : runs_) {
    font_data->push_back(
        RunFontData({run->font_data_.Get(), run->glyph_data_.size()}));
  }
}

template <bool has_non_zero_glyph_offsets>
float ShapeResult::ForEachGlyphImpl(float initial_advance,
                                    GlyphCallback glyph_callback,
                                    void* context,
                                    const RunInfo& run) const {
  auto glyph_offsets = run.glyph_data_.GetOffsets<has_non_zero_glyph_offsets>();
  auto total_advance = InlineLayoutUnit::FromFloatRound(initial_advance);
  bool is_horizontal = HB_DIRECTION_IS_HORIZONTAL(run.direction_);
  for (const auto& glyph_data : run.glyph_data_) {
    glyph_callback(context, run.start_index_ + glyph_data.character_index,
                   glyph_data.glyph, *glyph_offsets, total_advance,
                   is_horizontal, run.canvas_rotation_, run.font_data_.Get());
    total_advance += glyph_data.advance;
    ++glyph_offsets;
  }
  return total_advance;
}

float ShapeResult::ForEachGlyph(float initial_advance,
                                GlyphCallback glyph_callback,
                                void* context) const {
  auto total_advance = initial_advance;
  for (const auto& run : runs_) {
    if (run->glyph_data_.HasNonZeroOffsets()) {
      total_advance =
          ForEachGlyphImpl<true>(total_advance, glyph_callback, context, *run);
    } else {
      total_advance =
          ForEachGlyphImpl<false>(total_advance, glyph_callback, context, *run);
    }
  }
  return total_advance;
}

template <bool has_non_zero_glyph_offsets>
float ShapeResult::ForEachGlyphImpl(float initial_advance,
                                    unsigned from,
                                    unsigned to,
                                    unsigned index_offset,
                                    GlyphCallback glyph_callback,
                                    void* context,
                                    const RunInfo& run) const {
  auto glyph_offsets = run.glyph_data_.GetOffsets<has_non_zero_glyph_offsets>();
  auto total_advance = InlineLayoutUnit::FromFloatRound(initial_advance);
  unsigned run_start = run.start_index_ + index_offset;
  bool is_horizontal = HB_DIRECTION_IS_HORIZONTAL(run.direction_);
  const SimpleFontData* font_data = run.font_data_.Get();

  if (run.IsLtr()) {  // Left-to-right
    for (const auto& glyph_data : run.glyph_data_) {
      const unsigned character_index = run_start + glyph_data.character_index;
      if (character_index >= to)
        break;
      if (character_index >= from) {
        glyph_callback(context, character_index, glyph_data.glyph,
                       *glyph_offsets, total_advance, is_horizontal,
                       run.canvas_rotation_, font_data);
      }
      total_advance += glyph_data.advance;
      ++glyph_offsets;
    }
  } else {  // Right-to-left
    for (const auto& glyph_data : run.glyph_data_) {
      const unsigned character_index = run_start + glyph_data.character_index;
      if (character_index < from)
        break;
      if (character_index < to) {
        glyph_callback(context, character_index, glyph_data.glyph,
                       *glyph_offsets, total_advance, is_horizontal,
                       run.canvas_rotation_, font_data);
      }
      total_advance += glyph_data.advance;
      ++glyph_offsets;
    }
  }
  return total_advance;
}

float ShapeResult::ForEachGlyph(float initial_advance,
                                unsigned from,
                                unsigned to,
                                unsigned index_offset,
                                GlyphCallback glyph_callback,
                                void* context) const {
  auto total_advance = initial_advance;
  for (const auto& run : runs_) {
    if (run->glyph_data_.HasNonZeroOffsets()) {
      total_advance = ForEachGlyphImpl<true>(
          total_advance, from, to, index_offset, glyph_callback, context, *run);
    } else {
      total_advance = ForEachGlyphImpl<false>(
          total_advance, from, to, index_offset, glyph_callback, context, *run);
    }
  }
  return total_advance;
}

unsigned ShapeResult::CountGraphemesInCluster(base::span<const UChar> str,
                                              uint16_t start_index,
                                              uint16_t end_index) {
  if (start_index > end_index)
    std::swap(start_index, end_index);
  uint16_t length = end_index - start_index;
  TextBreakIterator* cursor_pos_iterator =
      CursorMovementIterator(str.subspan(start_index, length));
  if (!cursor_pos_iterator)
    return 0;

  int cursor_pos = cursor_pos_iterator->current();
  int num_graphemes = -1;
  while (0 <= cursor_pos) {
    cursor_pos = cursor_pos_iterator->next();
    num_graphemes++;
  }
  return std::max(0, num_graphemes);
}

float ShapeResult::ForEachGraphemeClusters(const StringView& text,
                                           float initial_advance,
                                           unsigned from,
                                           unsigned to,
                                           unsigned index_offset,
                                           GraphemeClusterCallback callback,
                                           void* context) const {
  unsigned run_offset = index_offset;
  InlineLayoutUnit advance_so_far =
      InlineLayoutUnit::FromFloatRound(initial_advance);
  for (const auto& run : runs_) {
    unsigned graphemes_in_cluster = 1;
    InlineLayoutUnit cluster_advance;

    // FIXME: should this be run->direction_?
    bool rtl = Direction() == TextDirection::kRtl;

    // A "cluster" in this context means a cluster as it is used by HarfBuzz:
    // The minimal group of characters and corresponding glyphs, that cannot be
    // broken down further from a text shaping point of view.  A cluster can
    // contain multiple glyphs and grapheme clusters, with mutually overlapping
    // boundaries.
    uint16_t cluster_start = static_cast<uint16_t>(
        rtl ? run->start_index_ + run->num_characters_ + run_offset
            : run->GlyphToCharacterIndex(0) + run_offset);

    const unsigned num_glyphs = run->glyph_data_.size();
    for (unsigned i = 0; i
```