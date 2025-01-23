Response:
The user wants me to analyze a C++ source code file related to text shaping in the Chromium browser engine. Specifically, they're asking about the functionality of `blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc`.

Here's a plan to address the request:

1. **Identify Core Functionality:** Scan the code for key classes, methods, and data structures to understand the primary purpose of the file. Look for interactions with HarfBuzz and other Blink components.
2. **Explain Functionality:**  Describe the role of `HarfBuzzShaper` in the text rendering pipeline. Focus on how it uses HarfBuzz to perform shaping.
3. **Relate to Web Technologies:** Explain how the shaping process implemented in this file is relevant to JavaScript, HTML, and CSS. Provide concrete examples.
4. **Demonstrate Logic with Examples:** Create scenarios with hypothetical input (text, font) and describe the expected output (shaped glyphs, positions).
5. **Highlight Common Usage Errors:**  Think about how developers or the system might misuse the text shaping functionality and provide illustrative examples.
6. **Summarize Functionality:**  Provide a concise summary of the file's purpose based on the analysis.
```cpp
void CapsFeatureSetting
```

这是目录为 `blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc` 的 chromium blink 引擎源代码文件的第一部分。根据代码内容，我们可以归纳出以下功能：

**主要功能：使用 HarfBuzz 库进行文本 shaping（字形组合和定位）。**

*   **Shaping 核心:** 该文件实现了 `HarfBuzzShaper` 类，该类利用 HarfBuzz 库将文本和字体信息转换为最终用于渲染的字形及其位置信息。这包括：
    *   将字符序列转换为字形序列。
    *   根据字体特性（OpenType features 等）调整字形。
    *   确定每个字形的水平和垂直位置。
*   **字体回退处理:**  代码处理字体回退逻辑。当当前字体无法渲染某些字符时，它会尝试使用备用字体。这个过程可能需要多次尝试不同的字体。
*   **处理不同文字方向:** 支持从左到右 (LTR) 和从右到左 (RTL) 的文本方向。
*   **处理垂直排版:**  支持垂直排版，并根据需要旋转画布。
*   **处理 Emoji:**  包含检测和处理 emoji 的逻辑，尤其关注在字体回退过程中 emoji 是否被正确渲染（是否拆分成多个字形）。
*   **处理 OpenType 特性:**  支持应用 OpenType 字体特性，例如小型大写字母、连字等。
*   **处理大小写映射:**  包含使用 `CaseMappingHarfbuzzBufferFiller` 进行大小写转换的逻辑。
*   **处理韩文 Kerning:** 包含对韩文进行字距调整的逻辑 (`HanKerning`)。
*   **与 Blink 引擎集成:**  该代码与 Blink 引擎的字体系统紧密集成，使用了 `Font`、`FontDescription`、`FontFallbackIterator` 等 Blink 内部的类。
*   **性能优化:**  使用了诸如 `STACK_ALLOCATED` 等技术来优化内存分配。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**  JavaScript 可以通过 DOM API 操作文本内容和样式，这些操作最终会触发 Blink 引擎的渲染流程，其中就包括使用 `HarfBuzzShaper` 进行文本 shaping。例如，当 JavaScript 修改一个包含复杂文字排版的元素的 `textContent` 时，引擎会调用此代码进行 shaping。
*   **HTML:** HTML 定义了网页的结构和内容，文本内容是 HTML 的核心组成部分。`HarfBuzzShaper` 负责将 HTML 中包含的文本内容转换为可渲染的字形。例如，在 `<p>` 标签中的文本需要经过 shaping 才能在浏览器中正确显示。
*   **CSS:** CSS 用于控制网页的样式，包括字体、字号、文字方向、行高等。这些 CSS 属性会影响 `HarfBuzzShaper` 的行为。
    *   **`font-family`:** CSS 的 `font-family` 属性决定了使用的字体。如果指定的字体无法渲染某些字符，`HarfBuzzShaper` 会根据字体回退机制尝试其他字体。
    *   **`font-size`:** CSS 的 `font-size` 属性会影响 HarfBuzz 如何缩放字形。
    *   **`direction`:** CSS 的 `direction` 属性（`ltr` 或 `rtl`）会直接影响 `HarfBuzzShaper` 的文本 shaping 方向。
    *   **`font-variant-caps`:** CSS 的 `font-variant-caps` 属性（例如 `small-caps`）会影响 `HarfBuzzShaper` 应用哪些 OpenType 特性。代码中可以看到对 `FontDescription::FontVariantCaps` 的处理。
    *   **`writing-mode`:** CSS 的 `writing-mode` 属性（例如 `vertical-rl`）会影响 `HarfBuzzShaper` 是否进行垂直排版。
    *   **`font-variant-emoji`:** CSS 的 `font-variant-emoji` 属性会影响在字体回退时优先选择 emoji 字体还是普通文本字体。

**逻辑推理的假设输入与输出：**

**假设输入：**

*   **文本:** "你好世界" (简体中文)
*   **字体:**  一个支持中文的字体，例如 "思源黑体"
*   **CSS 样式:** `font-family: "思源黑体"; direction: ltr;`

**预期输出：**

*   `HarfBuzzShaper` 会使用 HarfBuzz 库将 "你好世界" 这四个字符转换为对应的字形。
*   由于 "思源黑体" 支持中文，应该会找到这四个字符的对应字形。
*   输出的 `ShapeResult` 会包含这四个字形的 ID 和它们在水平方向上的位置信息，以从左到右排列。

**假设输入（回退情况）：**

*   **文本:** "😀👍" (Emoji)
*   **主要字体:**  一个不支持彩色 emoji 的字体，例如 "Arial"
*   **备用字体:**  一个支持彩色 emoji 的字体，例如 "Noto Color Emoji"
*   **CSS 样式:** `font-family: "Arial", "Noto Color Emoji";`

**预期输出：**

*   `HarfBuzzShaper` 首先尝试使用 "Arial" 进行 shaping，但 "Arial" 没有彩色 emoji 字形。
*   `HarfBuzzShaper` 会检测到缺失的字形 (可能输出 .notdef 字形)。
*   根据字体回退机制，`HarfBuzzShaper` 会尝试使用备用字体 "Noto Color Emoji"。
*   "Noto Color Emoji" 包含 "😀" 和 "👍" 的彩色字形。
*   输出的 `ShapeResult` 会包含这两个彩色 emoji 字形的 ID 和位置信息。

**用户或编程常见的使用错误举例：**

*   **字体缺失或未正确安装：** 如果 CSS 中指定的字体未安装在用户的系统中，或者字体文件损坏，`HarfBuzzShaper` 会尝试字体回退，但最终可能显示为占位符或乱码。
    *   **例子:** CSS 中使用了 `font-family: "MyCustomFont";` 但该字体文件不存在或浏览器无法访问。
*   **字符编码问题：**  如果文本的编码与浏览器的预期不一致，可能导致 `HarfBuzzShaper` 无法正确识别字符，从而导致 shaping 失败或显示错误的字形。
    *   **例子:**  HTML 文件使用了错误的字符集声明 (`<meta charset="...">`)，导致文本被错误解析。
*   **OpenType 特性使用不当：**  错误地使用或组合 OpenType 特性可能导致意外的字形显示。
    *   **例子:**  CSS 中同时启用了互斥的连字特性。
*   **字体回退顺序不合理：**  如果字体回退列表的顺序不合理，可能导致本应由首选字体渲染的字符被备用字体渲染，从而影响视觉效果。
    *   **例子:**  `font-family: "EmojiFont", "RegularTextFont";`  如果 "RegularTextFont" 也包含一些 emoji 字形，可能会优先使用 "RegularTextFont" 的单色 emoji 而不是 "EmojiFont" 的彩色 emoji。

**总结该部分功能：**

这部分代码定义了 `HarfBuzzShaper` 类，它是 Blink 引擎中使用 HarfBuzz 库进行文本 shaping 的核心组件。它负责将文本、字体信息和样式信息转换为可用于渲染的字形及其位置，并处理字体回退、文本方向、垂直排版、Emoji 以及 OpenType 特性等复杂情况。它与 JavaScript、HTML 和 CSS 紧密关联，是浏览器正确渲染网页文本的关键组成部分。

### 提示词
```
这是目录为blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
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

#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_shaper.h"

#include <hb.h>
#include <unicode/uchar.h>
#include <unicode/uscript.h>

#include <algorithm>
#include <hb-cplusplus.hh>
#include <memory>
#include <utility>

#include "base/check_op.h"
#include "base/logging.h"
#include "base/memory/ptr_util.h"
#include "base/notreached.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/font_description.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_iterator.h"
#include "third_party/blink/renderer/platform/fonts/font_fallback_priority.h"
#include "third_party/blink/renderer/platform/fonts/font_variant_emoji.h"
#include "third_party/blink/renderer/platform/fonts/opentype/open_type_caps_support.h"
#include "third_party/blink/renderer/platform/fonts/shaping/case_mapping_harfbuzz_buffer_filler.h"
#include "third_party/blink/renderer/platform/fonts/shaping/font_features.h"
#include "third_party/blink/renderer/platform/fonts/shaping/han_kerning.h"
#include "third_party/blink/renderer/platform/fonts/shaping/harfbuzz_face.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_inline_headers.h"
#include "third_party/blink/renderer/platform/fonts/small_caps_iterator.h"
#include "third_party/blink/renderer/platform/fonts/utf16_text_iterator.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"
#include "third_party/blink/renderer/platform/wtf/math_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

namespace {

constexpr hb_feature_t CreateFeature(char c1,
                                     char c2,
                                     char c3,
                                     char c4,
                                     uint32_t value = 0) {
  return {HB_TAG(c1, c2, c3, c4), value, 0 /* start */,
          static_cast<unsigned>(-1) /* end */};
}

#if EXPENSIVE_DCHECKS_ARE_ON()
// Check if the ShapeResult has the specified range.
// |text| and |font| are only for logging.
void CheckShapeResultRange(const ShapeResult* result,
                           unsigned start,
                           unsigned end,
                           const String& text,
                           const Font* font) {
  if (!result) {
    return;
  }
  DCHECK_LE(start, end);
  unsigned length = end - start;
  if (length == result->NumCharacters() &&
      (!length ||
       (start == result->StartIndex() && end == result->EndIndex()))) {
    return;
  }

  // Log font-family/size as specified.
  StringBuilder log;
  log.Append("Font='");
  const FontDescription& font_description = font->GetFontDescription();
  log.Append(font_description.Family().ToString());
  log.AppendFormat("', %f", font_description.ComputedSize());

  // Log the primary font with its family name in the font file.
  const SimpleFontData* font_data = font->PrimaryFont();
  if (font_data) {
    const SkTypeface* typeface = font_data->PlatformData().Typeface();
    SkString family_name;
    typeface->getFamilyName(&family_name);
    log.Append(", primary=");
    log.Append(family_name.c_str());
  }

  // Log the text to shape.
  log.AppendFormat(": %u-%u -> %u-%u:", start, end, result->StartIndex(),
                   result->EndIndex());
  for (unsigned i = start; i < end; ++i) {
    log.AppendFormat(" %02X", text[i]);
  }

  log.Append(", result=");
  result->ToString(&log);

  NOTREACHED() << log.ToString();
}
#endif

struct TrackEmoji {
  bool is_start;
  unsigned tracked_cluster_index;
  bool cluster_broken;

  unsigned num_broken_clusters;
  unsigned num_clusters;
};

// The algorithm is relying on the following assumption: If an emoji is shaped
// correctly it will present as only one glyph. This definitely holds for
// NotoColorEmoji. So if one sequence (which HarfBuzz groups as a cluster)
// presents as multiple glyphs, it means an emoji is rendered as sequence that
// the font did not understand and did not shape into only one glyph. If it
// renders as only one glyph but that glyph is .notdef/Tofu, it also means it's
// broken.  Due to the way flags work (pairs of regional indicators), broken
// flags cannot be correctly identified with this method - as each regional
// indicator will display as one emoji with Noto Color Emoji.
void IdentifyBrokenEmoji(void* context,
                         unsigned character_index,
                         Glyph glyph,
                         gfx::Vector2dF,
                         float,
                         bool,
                         CanvasRotationInVertical,
                         const SimpleFontData*) {
  DCHECK(context);
  TrackEmoji* track_emoji = reinterpret_cast<TrackEmoji*>(context);

  if (character_index != track_emoji->tracked_cluster_index ||
      track_emoji->is_start) {
    // We have reached the next cluster and can decide for the previous cluster
    // whether it was broken or not.
    track_emoji->num_clusters++;
    track_emoji->is_start = false;
    track_emoji->tracked_cluster_index = character_index;
    if (track_emoji->cluster_broken) {
      track_emoji->num_broken_clusters++;
    }
    track_emoji->cluster_broken = glyph == 0;
  } else {
    // We have reached an additional glyph for the same cluster, which means the
    // sequence was not identified by the font and is showing as multiple
    // glyphs.
    track_emoji->cluster_broken = true;
  }
}

struct EmojiCorrectness {
  unsigned num_clusters = 0;
  unsigned num_broken_clusters = 0;
};

EmojiCorrectness ComputeBrokenEmojiPercentage(ShapeResult* shape_result,
                                              unsigned start_index,
                                              unsigned end_index) {
  TrackEmoji track_emoji = {true, 0, false, 0, 0};
  shape_result->ForEachGlyph(0.f, start_index, end_index, 0 /* index_offset */,
                             IdentifyBrokenEmoji, &track_emoji);
  track_emoji.num_broken_clusters += track_emoji.cluster_broken ? 1 : 0;
  return {track_emoji.num_clusters, track_emoji.num_broken_clusters};
}

FontFallbackPriority ApplyFontVariantEmojiOnFallbackPriority(
    FontFallbackPriority curr_font_fallback_priority,
    FontVariantEmoji font_variant_emoji) {
  // font-variant-emoji property should not override emoji variation selectors,
  // see https://www.w3.org/TR/css-fonts-4/#font-variant-emoji-prop.
  if (RuntimeEnabledFeatures::FontVariantEmojiEnabled() &&
      !HasVSFallbackPriority(curr_font_fallback_priority)) {
    if (font_variant_emoji == kEmojiVariantEmoji) {
      return FontFallbackPriority::kEmojiEmoji;
    }
    if (font_variant_emoji == kTextVariantEmoji) {
      return FontFallbackPriority::kText;
    }
  }
  return curr_font_fallback_priority;
}

}  // namespace

enum ReshapeQueueItemAction {
  kReshapeQueueNextFont,
  kReshapeQueueRange,
  kReshapeQueueReset
};

struct ReshapeQueueItem {
  DISALLOW_NEW();
  ReshapeQueueItemAction action_;
  unsigned start_index_;
  unsigned num_characters_;
  ReshapeQueueItem(ReshapeQueueItemAction action, unsigned start, unsigned num)
      : action_(action), start_index_(start), num_characters_(num) {}
};

//
// Represents a context while shaping a range.
//
// Input-only data and objects whose pointers don't change are marked as
// `const`.
//
struct RangeContext {
  STACK_ALLOCATED();

 public:
  RangeContext(const Font* font,
               TextDirection direction,
               unsigned start,
               unsigned end,
               ShapeOptions options = ShapeOptions())
      : font(font),
        text_direction(direction),
        start(start),
        end(end),
        buffer(hb_buffer_create()),
        options(options) {
    DCHECK_GE(end, start);
    font_features.Initialize(font->GetFontDescription());
  }

  const Font* const font;
  const TextDirection text_direction;
  const unsigned start;
  const unsigned end;
  const hb::unique_ptr<hb_buffer_t> buffer;
  FontFeatures font_features;
  Deque<ReshapeQueueItem> reshape_queue;
  const ShapeOptions options;

  hb_direction_t HarfBuzzDirection(CanvasRotationInVertical canvas_rotation) {
    FontOrientation orientation = font->GetFontDescription().Orientation();
    hb_direction_t direction =
        IsVerticalAnyUpright(orientation) &&
                IsCanvasRotationInVerticalUpright(canvas_rotation)
            ? HB_DIRECTION_TTB
            : HB_DIRECTION_LTR;
    return text_direction == TextDirection::kRtl
               ? HB_DIRECTION_REVERSE(direction)
               : direction;
  }
};

struct BufferSlice {
  unsigned start_character_index;
  unsigned num_characters;
  unsigned start_glyph_index;
  unsigned num_glyphs;
};

namespace {

// A port of hb_icu_script_to_script because harfbuzz on CrOS is built
// without hb-icu. See http://crbug.com/356929
static inline hb_script_t ICUScriptToHBScript(UScriptCode script) {
  if (script == USCRIPT_INVALID_CODE) [[unlikely]] {
    return HB_SCRIPT_INVALID;
  }

  return hb_script_from_string(uscript_getShortName(script), -1);
}

inline float HarfBuzzPositionToFloat(hb_position_t value) {
  return static_cast<float>(value) / (1 << 16);
}

void RoundHarfBuzzPosition(hb_position_t* value) {
  if ((*value) & 0xFFFF) {
    // There is a non-zero fractional part in the 16.16 value.
    *value = static_cast<hb_position_t>(
                 round(static_cast<float>(*value) / (1 << 16)))
             << 16;
  }
}

void RoundHarfBuzzBufferPositions(hb_buffer_t* buffer) {
  unsigned int len;
  hb_glyph_position_t* glyph_positions =
      hb_buffer_get_glyph_positions(buffer, &len);
  for (unsigned int i = 0; i < len; i++) {
    hb_glyph_position_t* pos = &glyph_positions[i];
    RoundHarfBuzzPosition(&pos->x_offset);
    RoundHarfBuzzPosition(&pos->y_offset);
    RoundHarfBuzzPosition(&pos->x_advance);
    RoundHarfBuzzPosition(&pos->y_advance);
  }
}

inline bool ShapeRange(hb_buffer_t* buffer,
                       const FontFeatures& font_features,
                       const SimpleFontData* current_font,
                       const UnicodeRangeSet* current_font_range_set,
                       UScriptCode current_run_script,
                       hb_direction_t direction,
                       hb_language_t language,
                       float specified_size) {
  const FontPlatformData* platform_data = &(current_font->PlatformData());
  HarfBuzzFace* face = platform_data->GetHarfBuzzFace();
  if (!face) {
    DLOG(ERROR) << "Could not create HarfBuzzFace from FontPlatformData.";
    return false;
  }

  FontFeatures variant_features;
  if (!platform_data->ResolvedFeatures().empty()) {
    const ResolvedFontFeatures& resolved_features =
        platform_data->ResolvedFeatures();
    for (const std::pair<uint32_t, uint32_t>& feature : resolved_features) {
      variant_features.Append({feature.first, feature.second, 0 /* start */,
                               static_cast<unsigned>(-1) /* end */});
    }
  }

  bool needs_feature_merge = variant_features.size();
  if (needs_feature_merge) {
    for (wtf_size_t i = 0; i < font_features.size(); ++i) {
      variant_features.Append(font_features.data()[i]);
    }
  }
  const FontFeatures& argument_features =
      needs_feature_merge ? variant_features : font_features;

  hb_buffer_set_language(buffer, language);
  hb_buffer_set_script(buffer, ICUScriptToHBScript(current_run_script));
  hb_buffer_set_direction(buffer, direction);

  hb_font_t* hb_font =
      face->GetScaledFont(current_font_range_set,
                          HB_DIRECTION_IS_VERTICAL(direction)
                              ? HarfBuzzFace::kPrepareForVerticalLayout
                              : HarfBuzzFace::kNoVerticalLayout,
                          specified_size);
  hb_shape(hb_font, buffer, argument_features.data(), argument_features.size());
  if (!face->ShouldSubpixelPosition()) {
    RoundHarfBuzzBufferPositions(buffer);
  }

  return true;
}

BufferSlice ComputeSlice(RangeContext* range_data,
                         const ReshapeQueueItem& current_queue_item,
                         const hb_glyph_info_t* glyph_info,
                         unsigned num_glyphs,
                         unsigned old_glyph_index,
                         unsigned new_glyph_index) {
  // Compute the range indices of consecutive shaped or .notdef glyphs.
  // Cluster information for RTL runs becomes reversed, e.g. glyph 0
  // has cluster index 5 in a run of 6 characters.
  BufferSlice result;
  result.start_glyph_index = old_glyph_index;
  result.num_glyphs = new_glyph_index - old_glyph_index;

  if (HB_DIRECTION_IS_FORWARD(hb_buffer_get_direction(range_data->buffer))) {
    result.start_character_index = glyph_info[old_glyph_index].cluster;
    if (new_glyph_index == num_glyphs) {
      // Clamp the end offsets of the queue item to the offsets representing
      // the shaping window.
      unsigned shape_end =
          std::min(range_data->end, current_queue_item.start_index_ +
                                        current_queue_item.num_characters_);
      result.num_characters = shape_end - result.start_character_index;
    } else {
      result.num_characters =
          glyph_info[new_glyph_index].cluster - result.start_character_index;
    }
  } else {
    // Direction Backwards
    result.start_character_index = glyph_info[new_glyph_index - 1].cluster;
    if (old_glyph_index == 0) {
      // Clamp the end offsets of the queue item to the offsets representing
      // the shaping window.
      unsigned shape_end =
          std::min(range_data->end, current_queue_item.start_index_ +
                                        current_queue_item.num_characters_);
      result.num_characters = shape_end - result.start_character_index;
    } else {
      result.num_characters = glyph_info[old_glyph_index - 1].cluster -
                              glyph_info[new_glyph_index - 1].cluster;
    }
  }

  return result;
}

bool IsLastFontToShape(HarfBuzzShaper::FallbackFontStage fallback_stage) {
  return fallback_stage == HarfBuzzShaper::kLast ||
         fallback_stage == HarfBuzzShaper::kLastIgnoreVS;
}

bool StageNeedsQueueReset(HarfBuzzShaper::FallbackFontStage fallback_stage) {
  return fallback_stage == HarfBuzzShaper::kLastWithVS;
}

HarfBuzzShaper::FallbackFontStage ChangeStageToLast(
    HarfBuzzShaper::FallbackFontStage fallback_stage) {
  switch (fallback_stage) {
    case HarfBuzzShaper::kIntermediate:
      return HarfBuzzShaper::kLast;
    case HarfBuzzShaper::kIntermediateWithVS:
      DCHECK(RuntimeEnabledFeatures::FontVariationSequencesEnabled());
      return HarfBuzzShaper::kLastWithVS;
    case HarfBuzzShaper::kIntermediateIgnoreVS:
      DCHECK(RuntimeEnabledFeatures::FontVariationSequencesEnabled());
      return HarfBuzzShaper::kLastIgnoreVS;
    default:
      return fallback_stage;
  }
}

HarfBuzzShaper::FallbackFontStage ChangeStageToVS(
    HarfBuzzShaper::FallbackFontStage fallback_stage) {
  DCHECK(RuntimeEnabledFeatures::FontVariationSequencesEnabled());
  switch (fallback_stage) {
    case HarfBuzzShaper::kIntermediate:
      return HarfBuzzShaper::kIntermediateWithVS;
    case HarfBuzzShaper::kLast:
      return HarfBuzzShaper::kLastWithVS;
    case HarfBuzzShaper::kIntermediateWithVS:
    case HarfBuzzShaper::kLastWithVS:
      return fallback_stage;
    default:
      // We should not call this function on the second fallback pass.
      NOTREACHED();
  }
}

void QueueCharacters(RangeContext* range_data,
                     const SimpleFontData* current_font,
                     bool& font_cycle_queued,
                     const BufferSlice& slice,
                     HarfBuzzShaper::FallbackFontStage font_stage) {
  if (!font_cycle_queued) {
    if (StageNeedsQueueReset(font_stage)) {
      DCHECK(RuntimeEnabledFeatures::FontVariationSequencesEnabled());
      range_data->reshape_queue.push_back(
          ReshapeQueueItem(kReshapeQueueReset, 0, 0));
    } else {
      range_data->reshape_queue.push_back(
          ReshapeQueueItem(kReshapeQueueNextFont, 0, 0));
    }
    font_cycle_queued = true;
  }

  DCHECK(slice.num_characters);
  range_data->reshape_queue.push_back(ReshapeQueueItem(
      kReshapeQueueRange, slice.start_character_index, slice.num_characters));
}

CanvasRotationInVertical CanvasRotationForRun(
    FontOrientation font_orientation,
    OrientationIterator::RenderOrientation render_orientation,
    const FontDescription& font_description) {
  if (font_orientation == FontOrientation::kVerticalUpright) {
    return font_description.IsSyntheticOblique()
               ? CanvasRotationInVertical::kRotateCanvasUprightOblique
               : CanvasRotationInVertical::kRotateCanvasUpright;
  }

  if (font_orientation == FontOrientation::kVerticalMixed) {
    if (render_orientation == OrientationIterator::kOrientationKeep) {
      return font_description.IsSyntheticOblique()
                 ? CanvasRotationInVertical::kRotateCanvasUprightOblique
                 : CanvasRotationInVertical::kRotateCanvasUpright;
    }
    return font_description.IsSyntheticOblique()
               ? CanvasRotationInVertical::kOblique
               : CanvasRotationInVertical::kRegular;
  }

  return CanvasRotationInVertical::kRegular;
}

}  // namespace

inline void HarfBuzzShaper::CheckTextLen(unsigned start,
                                         unsigned length) const {
  CHECK_LE(start, text_.length());
  CHECK_LE(length, text_.length() - start);
}

inline void HarfBuzzShaper::CheckTextEnd(unsigned start, unsigned end) const {
  CHECK_LE(start, end);
  CHECK_LE(start, text_.length());
  CHECK_LE(end, text_.length());
}

void HarfBuzzShaper::CommitGlyphs(RangeContext* range_data,
                                  const SimpleFontData* current_font,
                                  UScriptCode current_run_script,
                                  CanvasRotationInVertical canvas_rotation,
                                  FallbackFontStage fallback_stage,
                                  const BufferSlice& slice,
                                  ShapeResult* shape_result) const {
  hb_direction_t direction = range_data->HarfBuzzDirection(canvas_rotation);
  hb_script_t script = ICUScriptToHBScript(current_run_script);
  // Here we need to specify glyph positions.
  BufferSlice next_slice;
  unsigned run_start_index = slice.start_character_index;
  for (const BufferSlice* current_slice = &slice;;) {
    auto* run = MakeGarbageCollected<ShapeResult::RunInfo>(
        current_font, direction, canvas_rotation, script, run_start_index,
        current_slice->num_glyphs, current_slice->num_characters);
    unsigned next_start_glyph;
    shape_result->InsertRun(run, current_slice->start_glyph_index,
                            current_slice->num_glyphs, &next_start_glyph,
                            range_data->buffer);
    DCHECK_GE(current_slice->start_glyph_index + current_slice->num_glyphs,
              next_start_glyph);
    unsigned next_num_glyphs =
        current_slice->num_glyphs -
        (next_start_glyph - current_slice->start_glyph_index);
    if (!next_num_glyphs) {
      break;
    }

    // If the slice exceeds the limit a RunInfo can store, create another
    // RunInfo for the rest of the slice.
    DCHECK_GT(current_slice->num_characters, run->num_characters_);
    next_slice = {current_slice->start_character_index + run->num_characters_,
                  current_slice->num_characters - run->num_characters_,
                  next_start_glyph, next_num_glyphs};
    current_slice = &next_slice;

    // The |InsertRun| has truncated the right end. In LTR, advance the
    // |run_start_index| because the end characters are truncated. In RTL, keep
    // the same |run_start_index| because the start characters are truncated.
    if (HB_DIRECTION_IS_FORWARD(direction)) {
      run_start_index = next_slice.start_character_index;
    }
  }
  if (IsLastFontToShape(fallback_stage)) {
    range_data->font->ReportNotDefGlyph();
  }
}

void HarfBuzzShaper::ExtractShapeResults(
    RangeContext* range_data,
    bool& font_cycle_queued,
    const ReshapeQueueItem& current_queue_item,
    const SimpleFontData* current_font,
    UScriptCode current_run_script,
    CanvasRotationInVertical canvas_rotation,
    FallbackFontStage& fallback_stage,
    ShapeResult* shape_result) const {
  enum ClusterResult { kShaped, kNotDef, kUnknown };
  ClusterResult current_cluster_result = kUnknown;
  ClusterResult previous_cluster_result = kUnknown;
  unsigned previous_cluster = 0;
  unsigned current_cluster = 0;

  // Find first notdef glyph in buffer.
  unsigned num_glyphs = hb_buffer_get_length(range_data->buffer);
  hb_glyph_info_t* glyph_info =
      hb_buffer_get_glyph_infos(range_data->buffer, nullptr);

  unsigned last_change_glyph_index = 0;
  unsigned previous_cluster_start_glyph_index = 0;

  if (!num_glyphs) {
    return;
  }

  const Glyph space_glyph = current_font->SpaceGlyph();
  for (unsigned glyph_index = 0; glyph_index < num_glyphs; ++glyph_index) {
    // We proceed by full clusters and determine a shaping result - either
    // kShaped or kNotDef for each cluster.
    const hb_glyph_info_t& glyph = glyph_info[glyph_index];
    previous_cluster = current_cluster;
    current_cluster = glyph.cluster;
    const hb_codepoint_t glyph_id = glyph.codepoint;
    ClusterResult glyph_result;
    if (glyph_id == 0) {
      // Glyph 0 must be assigned to a .notdef glyph.
      // https://docs.microsoft.com/en-us/typography/opentype/spec/recom#glyph-0-the-notdef-glyph
      glyph_result = kNotDef;
    } else if (glyph_id == space_glyph && !IsLastFontToShape(fallback_stage) &&
               text_[current_cluster] == kIdeographicSpaceCharacter) {
      // HarfBuzz synthesizes U+3000 IDEOGRAPHIC SPACE using the space glyph.
      // This is not desired for run-splitting, applying features, and for
      // computing `line-height`. crbug.com/1193282
      // We revisit when HarfBuzz decides how to solve this more generally.
      // https://github.com/harfbuzz/harfbuzz/issues/2889
      glyph_result = kNotDef;
    } else if (glyph_id == kUnmatchedVSGlyphId) {
      fallback_stage = ChangeStageToVS(fallback_stage);
      glyph_result = kNotDef;
    } else {
      glyph_result = kShaped;
    }

    if (current_cluster != previous_cluster) {
      // We are transitioning to a new cluster (whose shaping result state we
      // have not looked at yet). This means the cluster we just looked at is
      // completely analysed and we can determine whether it was fully shaped
      // and whether that means a state change to the cluster before that one.
      if ((previous_cluster_result != current_cluster_result) &&
          previous_cluster_result != kUnknown) {
        BufferSlice slice = ComputeSlice(
            range_data, current_queue_item, glyph_info, num_glyphs,
            last_change_glyph_index, previous_cluster_start_glyph_index);
        // If the most recent cluster is shaped and there is a state change,
        // it means the previous ones were unshaped, so we queue them, unless
        // we're using the last resort font.
        if (current_cluster_result == kShaped &&
            !IsLastFontToShape(fallback_stage)) {
          QueueCharacters(range_data, current_font, font_cycle_queued, slice,
                          fallback_stage);
        } else {
          // If the most recent cluster is unshaped and there is a state
          // change, it means the previous one(s) were shaped, so we commit
          // the glyphs. We also commit when we've reached the last resort
          // font.
          CommitGlyphs(range_data, current_font, current_run_script,
                       canvas_rotation, fallback_stage, slice, shape_result);
        }
        last_change_glyph_index = previous_cluster_start_glyph_index;
      }

      // No state change happened, continue.
      previous_cluster_result = current_cluster_result;
      previous_cluster_start_glyph_index = glyph_index;
      // Reset current cluster result.
      current_cluster_result = glyph_result;
    } else {
      // Update and merge current cluster result.
      current_cluster_result =
          glyph_result == kShaped && (current_cluster_result == kShaped ||
                                      current_cluster_result == kUnknown)
              ? kShaped
              : kNotDef;
    }
  }

  // End of the run.
  if (current_cluster_result != previous_cluster_result &&
      previous_cluster_result != kUnknown &&
      !IsLastFontToShape(fallback_stage)) {
    // The last cluster in the run still had shaping status different from
    // the cluster(s) before it, we need to submit one shaped and one
    // unshaped segment.
    if (current_cluster_result == kShaped) {
      BufferSlice slice = ComputeSlice(
          range_data, current_queue_item, glyph_info, num_glyphs,
          last_change_glyph_index, previous_cluster_start_glyph_index);
      QueueCharacters(range_data, current_font, font_cycle_queued, slice,
                      fallback_stage);
      slice =
          ComputeSlice(range_data, current_queue_item, glyph_info, num_glyphs,
                       previous_cluster_start_glyph_index, num_glyphs);
      CommitGlyphs(range_data, current_font, current_run_script,
                   canvas_rotation, fallback_stage, slice, shape_result);
    } else {
      BufferSlice slice = ComputeSlice(
          range_data, current_queue_item, glyph_info, num_glyphs,
          last_change_glyph_index, previous_cluster_start_glyph_index);
      CommitGlyphs(range_data, current_font, current_run_script,
                   canvas_rotation, fallback_stage, slice, shape_result);
      slice =
          ComputeSlice(range_data, current_queue_item, glyph_info, num_glyphs,
                       previous_cluster_start_glyph_index, num_glyphs);
      QueueCharacters(range_data, current_font, font_cycle_queued, slice,
                      fallback_stage);
    }
  } else {
    // There hasn't been a state change for the last cluster, so we can just
    // either commit or queue what we have up until here.
    BufferSlice slice =
        ComputeSlice(range_data, current_queue_item, glyph_info, num_glyphs,
                     last_change_glyph_index, num_glyphs);
    if (current_cluster_result == kNotDef &&
        !IsLastFontToShape(fallback_stage)) {
      QueueCharacters(range_data, current_font, font_cycle_queued, slice,
                      fallback_stage);
    } else {
      CommitGlyphs(range_data, current_font, current_run_script,
                   canvas_rotation, fallback_stage, slice, shape_result);
    }
  }
}

bool HarfBuzzShaper::CollectFallbackHintChars(
    const Deque<ReshapeQueueItem>& reshape_queue,
    bool needs_hint_list,
    HintCharList& hint) const {
  if (reshape_queue.empty()) {
    return false;
  }

  // Clear without releasing the capacity to avoid reallocations.
  hint.resize(0);

  size_t num_chars_added = 0;
  for (auto it = reshape_queue.begin(); it != reshape_queue.end(); ++it) {
    if (it->action_ == kReshapeQueueNextFont) {
      break;
    }

    CheckTextLen(it->start_index_, it->num_characters_);
    if (text_.Is8Bit()) {
      for (unsigned i = 0; i < it->num_characters_; i++) {
        const UChar hint_char = text_[it->start_index_ + i];
        hint.push_back(hint_char);
        num_chars_added++;
        // Determine if we can take a shortcut and not fill the hint list
        // further: We can do that if we do not need a hint list, and we have
        // managed to find a character with a definite script since
        // FontFallbackIterator needs a character with a determined script to
        // perform meaningful system fallback.
        if (!needs_hint_list && Character::HasDefiniteScript(hint_char)) {
          return true;
        }
      }
      continue;
    }

    // !text_.Is8Bit()...
    UChar32 hint_char;
    UTF16TextIterator iterator(
        text_.Span16().subspan(it->start_index_, it->num_characters_));
    while (iterator.Consume(hint_char)) {
      hint.push_back(hint_char);
      num_chars_added++;
      // Determine if we can take a shortcut and not fill the hint list
      // further: We can do that if we do not need a hint list, and we have
      // managed to find a character with a definite script since
      // FontFallbackIterator needs a character with a determined script to
      // perform meaningful system fallback.
      if (!needs_hint_list && Character::HasDefiniteScript(hint_char)) {
        return true;
      }
      iterator.Advance();
    }
  }
  return num_chars_added > 0;
}

namespace {

void SplitUntilNextCaseChange(
    const String& text,
    Deque<blink::ReshapeQueueItem>* queue,
    blink::ReshapeQueueItem& current_queue_item,
    SmallCapsIterator::SmallCapsBehavior& small_caps_behavior) {
  // TODO(layout-dev): Add support for latin-1 to SmallCapsIterator.
  base::span<const UChar> normalized_buffer;
  std::optional<String> utf16_text;
  if (text.Is8Bit()) {
    utf16_text.emplace(text);
    utf16_text->Ensure16Bit();
    normalized_buffer = utf16_text->Span16();
  } else {
    normalized_buffer = text.Span16();
  }

  unsigned num_characters_until_case_change = 0;
  SmallCapsIterator small_caps_iterator(normalized_buffer.subspan(
      current_queue_item.start_index_, current_queue_item.num_characters_));
  small_caps_iterator.Consume(&num_characters_until_case_change,
                              &small_caps_behavior);
  if (num_characters_until_case_change > 0 &&
      num_characters_until_case_change < current_queue_item.num_characters_) {
    queue->push_front(blink::ReshapeQueueItem(
        blink::ReshapeQueueItemAction::kReshapeQueueRange,
        current_queue_item.start_index_ + num_characters_until_case_change,
        current_queue_item.num_characters_ - num_characters_until_case_change));
    current_queue_item.num_characters_ = num_characters_until_case_change;
  }
}

class CapsFeatureSettingsScopedOverlay final {
  STACK_ALLOCATED();

 public:
  CapsFeatureSettingsScopedOverlay(FontFeatures*,
                                   FontDescription::FontVariantCaps);
  CapsFeatureSettingsScopedOverlay() = delete;
  ~CapsFeatureSettingsScopedOverlay();

 private:
  void OverlayCapsFeatures(FontDescription::FontVariantCaps);
  void PrependCounting(const hb_feature_t&);
  FontFeatures* features_;
  wtf_size_t count_features_;
};

CapsFeatureSettingsScopedOverlay::CapsFeatureSettingsScopedOverlay(
    FontFeatures* features,
    FontDescription::FontVariantCaps variant_caps)
    : features_(features), count_features_(0) {
  OverlayCapsFeatures(variant_caps);
}

void CapsFeatureSetting
```