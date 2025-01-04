Response:
Let's break down the thought process for analyzing the `ShapeResultBloberizer.cc` file and generating the response.

1. **Understand the Core Purpose:** The filename itself, `shape_result_bloberizer.cc`, strongly suggests its function: taking shaping results (the output of text shaping, which determines glyphs and their positions) and "bloberizing" them. "Bloberizing" likely means grouping and preparing this data for efficient rendering. The presence of `ShapeResult` and `FontDescription` in the constructor reinforces this.

2. **Identify Key Data Structures:**  Look for member variables that hold important data. The most prominent are:
    * `blobs_`:  This is clearly the output, a collection of "blobs." The `BlobBuffer` type confirms this.
    * `builder_`:  This seems to be a helper class for constructing the blobs. The methods like `allocRunTextPos`, `make` are strong indicators.
    * `pending_glyphs_`, `pending_offsets_`: These likely hold glyph and offset data before they are committed to a blob. The "pending" prefix is a big clue.
    * `pending_utf8_`, `pending_utf8_character_indexes_`: These handle the conversion and storage of the text into UTF-8. This is necessary for rendering APIs that often work with UTF-8.
    * `current_text_`, `current_character_indexes_`:  These seem to manage the current segment of text being processed.
    * `font_description_`:  The font being used is crucial for shaping.

3. **Trace the Data Flow:**  Try to follow how data moves through the class.
    * `SetText`:  Sets the current text being processed.
    * `CommitText`: Converts the current text to UTF-8 and associates it with the pending glyphs.
    * `Add`: Adds a single glyph and its offset.
    * `CommitPendingRun`: Groups the pending glyphs and offsets into a "run" within a blob. It also handles UTF-8 data association.
    * `CommitPendingBlob`: Finalizes a blob.
    * `Blobs`:  The main entry point to retrieve the finished blobs.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Consider how the functionality relates to what web developers do:
    * **HTML:** The text content itself comes from HTML. The `StringView` hints at this.
    * **CSS:**  Font properties (family, size, weight, style) are defined in CSS. The `FontDescription` directly reflects this. Text decoration (`text-decoration-skip-ink`) is explicitly mentioned in the `IsSkipInkException` function. Text emphasis is also handled.
    * **JavaScript:**  While this code doesn't directly interact with JavaScript, JavaScript manipulation of the DOM can lead to changes in text content and styles, which eventually reach this part of the rendering pipeline.

5. **Look for Specific Functionalities and Logic:**
    * **Glyph Positioning:** The core task is to determine the position of each glyph. The `glyph_offset`, `advance` parameters in the `Add` methods are key. The handling of horizontal and vertical layouts is important.
    * **Text Segmentation (Clusters):** The code handles text segmentation into grapheme clusters. This is essential for correctly handling complex scripts and combining characters. The `cluster_starts` logic is relevant here.
    * **UTF-8 Conversion:** The conversion of text to UTF-8 is explicit. Understand *why* this is necessary (for Skia, the underlying graphics library).
    * **Emphasis Marks:** The dedicated functions for adding emphasis marks demonstrate a specific feature related to text styling.
    * **Fast Path Optimization:**  The `CanUseFastPath` functions and `FillFastHorizontalGlyphs` indicate an optimization for common cases. Understand the conditions for using the fast path.
    * **Canvas Rotation:** The handling of `CanvasRotationInVertical` suggests support for vertical text layout.

6. **Consider Potential Errors/Edge Cases:**
    * **Mismatched Data:** The `DCHECK` statements are crucial for identifying potential inconsistencies (e.g., between glyphs and offsets).
    * **Incorrect Input:**  Although not explicitly handled by error messages in this code,  incorrect font data or invalid shaping results could lead to problems.
    * **Performance Issues:**  Inefficient bloberization could impact rendering performance. The fast path is an attempt to mitigate this.

7. **Structure the Response:** Organize the findings into logical categories:
    * **Core Functionality:** Start with the main purpose of the class.
    * **Relationship to Web Technologies:** Explain the connections to HTML, CSS, and JavaScript with examples.
    * **Logic and Algorithms:** Describe the key steps and processes involved (glyph addition, UTF-8 conversion, etc.). Use illustrative input/output examples (even if simplified).
    * **Potential Errors:**  Highlight common usage mistakes or potential issues.

8. **Refine and Elaborate:**  Review the generated response for clarity, accuracy, and completeness. Add more detail or examples where needed. For instance, explicitly mention Skia in the UTF-8 conversion explanation. Explain *why* clustering is important.

By following these steps, we can systematically analyze the code and produce a comprehensive and informative explanation of its functionality and context. The key is to understand the "what," "why," and "how" of the code within the broader context of a web browser's rendering engine.
这个文件 `shape_result_bloberizer.cc` 的主要功能是将文本塑形（shaping）的结果转换成可以用于绘制的“blob”数据结构。这个过程被称为“bloberizing”。  更具体地说，它将一系列的字形（glyphs）及其位置信息，以及相关的文本信息组织起来，方便后续的图形渲染引擎（例如 Skia）高效地绘制文本。

以下是其功能的详细列表：

1. **组织字形数据:**  它接收由文本塑形器（shaper）生成的字形、偏移量、以及相关的字体信息，并将它们存储起来。

2. **处理水平和垂直排版:**  它能区分并处理水平和垂直排版的字形数据，根据需要存储不同的偏移量信息 (仅水平偏移或水平和垂直偏移)。

3. **管理文本内容:** 它存储了原始文本的 UTF-8 编码表示以及每个字形对应的文本字符索引。这使得渲染器能够将绘制的字形与原始文本关联起来。

4. **分批处理字形（Runs 和 Blobs）:**
    * **Runs:**  它将具有相同字体和旋转角度的连续字形分组到一个“run”中。
    * **Blobs:** 它将具有相同旋转角度的多个“runs”组合成一个“blob”。这有助于优化渲染过程，因为可以对同一旋转角度的文本进行批处理。

5. **优化渲染性能:** 通过将字形数据组织成 blob，可以减少渲染引擎需要处理的绘制调用次数，从而提高渲染性能。

6. **处理文本强调 (Emphasis Marks):**  它包含添加文本强调标记（例如，中文的着重号）的功能。

7. **提供快速路径优化:**  对于一些简单的场景（例如，单行、水平、无垂直偏移的文本），它提供了一个优化的快速路径来处理字形数据。

**与 JavaScript, HTML, CSS 的关系:**

`ShapeResultBloberizer` 位于 Blink 渲染引擎的底层，它负责将浏览器从 HTML、CSS 中解析出来的文本和样式信息转换成最终在屏幕上显示的像素。

* **HTML:** HTML 提供了文本内容。 `ShapeResultBloberizer` 接收来自 HTML 的文本字符串，例如 `<p>This is some text.</p>` 中的 "This is some text."。

* **CSS:** CSS 定义了文本的样式，包括字体、大小、颜色、排版方向、以及是否需要强调等。
    * **字体 (font-family, font-size, font-weight, font-style):** `ShapeResultBloberizer` 的构造函数接收 `FontDescription` 对象，该对象包含了从 CSS 解析出的字体信息。这些信息用于选择合适的字形和计算字形的位置。
    * **文本方向 (direction, unicode-bidi):** CSS 的文本方向属性影响文本的塑形和 `ShapeResultBloberizer` 处理字形的顺序。 例如，对于 `direction: rtl;` 的文本，字形的排列顺序是相反的。
    * **文本强调 (text-emphasis):** CSS 的 `text-emphasis` 属性会触发 `ShapeResultBloberizer` 中的 `AddEmphasisMark` 功能，将强调标记的字形添加到 blob 中。

* **JavaScript:** JavaScript 可以动态地修改 HTML 内容和 CSS 样式。当 JavaScript 修改文本内容或样式时，渲染引擎会重新进行文本塑形，并调用 `ShapeResultBloberizer` 来生成新的 blob 数据。

**举例说明:**

假设有以下的 HTML 和 CSS：

```html
<!DOCTYPE html>
<html>
<head>
<style>
  .emphasized {
    font-family: "SimSun";
    font-size: 16px;
    text-emphasis: filled sesame red;
  }
  .rtl-text {
    direction: rtl;
  }
</style>
</head>
<body>
  <p class="emphasized">这是一个带强调的文本。</p>
  <p class="rtl-text">שלום עולם</p>
</body>
</html>
```

1. **带强调的文本:**
   - **输入 (假设):** 文本 "这是一个带强调的文本。", 字体 "SimSun", 字号 16px，需要红色实心芝麻点强调。
   - **逻辑推理:**  文本塑形器会先对文本进行塑形，生成每个字符对应的字形和位置信息。然后，`ShapeResultBloberizer` 会识别到 `text-emphasis` 属性，调用 `AddEmphasisMark` 为每个需要强调的字符添加相应的强调标记字形，并将其添加到 blob 数据中。
   - **输出 (假设):**  生成的 blob 数据将包含原始文本的字形以及每个需要强调的字符上方的红色芝麻点字形，以及它们的偏移量信息。

2. **从右到左的文本:**
   - **输入 (假设):** 文本 "שלום עולם" (希伯来语)，文本方向为 RTL。
   - **逻辑推理:** 文本塑形器会按照从右到左的顺序生成字形。 `ShapeResultBloberizer` 会根据文本方向 (RTL) 相应的处理字形的顺序和偏移量。
   - **输出 (假设):** 生成的 blob 数据中，字形的顺序会反映出从右到左的排列，并且偏移量也会相应调整。

**逻辑推理的假设输入与输出:**

假设我们有以下简单的文本和字体信息：

**输入:**
* **文本:** "ab"
* **字体:**  假设已加载名为 "MyFont" 的字体
* **字形信息 (假设文本塑形器已生成):**
    * 'a' 的字形 ID: 10, 水平偏移: 0, 高级宽度: 10
    * 'b' 的字形 ID: 20, 水平偏移: 10, 高级宽度: 12

**逻辑推理过程 (简化):**

1. `SetText` 被调用，传入文本 "ab"。
2. 文本塑形器生成 'a' 和 'b' 的字形信息。
3. `Add` 方法被调用两次：
   - 第一次添加 'a' 的字形，偏移量为 0。
   - 第二次添加 'b' 的字形，偏移量根据 'a' 的高级宽度调整，为 10。
4. `CommitText` 将文本 "ab" 转换为 UTF-8 并记录字符索引。
5. `CommitPendingRun` 将字形和偏移量信息添加到当前 run 中。
6. `CommitPendingBlob` 将当前的 run 添加到 blob 列表中。
7. `Blobs` 返回生成的 blob 数据。

**输出 (简化后的 blob 数据结构):**

```
Blob {
  rotation: Regular, // 假设没有旋转
  runs: [
    Run {
      font: MyFont,
      glyphs: [10, 20],
      offsets: [0, 10],
      utf8_text: "ab",
      utf8_cluster_starts: [0, 1]
    }
  ]
}
```

**用户或编程常见的使用错误:**

由于 `ShapeResultBloberizer` 是 Blink 渲染引擎的内部组件，一般的 Web 开发者不会直接与其交互。但是，一些底层编程错误或不当的引擎配置可能会导致问题：

1. **字体加载失败或字体数据损坏:** 如果指定的字体无法加载或字体数据损坏，文本塑形器可能无法正确生成字形信息，导致 `ShapeResultBloberizer` 无法正常工作，最终可能导致文本显示异常或崩溃。

   **例子:**  如果在 CSS 中指定了一个不存在的字体 `font-family: "NonExistentFont";`，或者字体文件被损坏，可能会导致渲染错误。

2. **文本塑形器返回无效数据:** 如果文本塑形器本身存在 bug，可能会返回错误的字形 ID 或偏移量，`ShapeResultBloberizer` 会接收这些错误的数据并生成错误的 blob，导致渲染结果不正确。

   **例子:**  某些复杂的 Unicode 字符组合可能导致文本塑形器出现错误，从而影响 `ShapeResultBloberizer` 的输出。

3. **在高频率下进行大量的文本更新:**  如果 JavaScript 代码频繁地修改包含大量文本的 DOM 节点，会导致渲染引擎不断地进行文本塑形和 bloberizing 操作，可能会影响性能。

   **例子:**  一个实时更新的大型日志显示界面，如果没有进行适当的优化，可能会导致性能问题。

总而言之，`ShapeResultBloberizer` 是 Blink 渲染引擎中一个关键的组件，它负责将文本塑形的结果转换成可用于高效绘制的数据结构，是连接文本内容、样式和最终屏幕显示的重要桥梁。 虽然 Web 开发者通常不会直接操作它，但了解其功能有助于理解浏览器渲染文本的底层过程。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result_bloberizer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_bloberizer.h"

#include <hb.h>

#include "base/logging.h"
#include "base/ranges/algorithm.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/shaping/caching_word_shaper.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"
#include "third_party/blink/renderer/platform/fonts/text_run_paint_info.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/text/text_run.h"

namespace blink {

ShapeResultBloberizer::ShapeResultBloberizer(
    const FontDescription& font_description,
    Type type)
    : font_description_(font_description), type_(type) {}

bool ShapeResultBloberizer::HasPendingVerticalOffsets() const {
  // We exclusively store either horizontal/x-only offsets -- in which case
  // m_offsets.size == size, or vertical/xy offsets -- in which case
  // m_offsets.size == size * 2.
  DCHECK(pending_glyphs_.size() == pending_offsets_.size() ||
         pending_glyphs_.size() * 2 == pending_offsets_.size());
  return pending_glyphs_.size() != pending_offsets_.size();
}

void ShapeResultBloberizer::SetText(const StringView& text,
                                    unsigned from,
                                    unsigned to,
                                    base::span<const unsigned> cluster_starts) {
  if (current_text_.IsNull())
    CommitPendingRun();

  // Any outstanding 'current' state should have been moved to 'pending'.
  DCHECK(current_character_indexes_.empty());

  DVLOG(4) << "   SetText from: " << from << " to: " << to;

  // cluster_ends_ must be at least the size of the source run length,
  // but the run length may be negative (in which case no glyphs will be added).
  if (from < to) {
    DVLOG(4) << "   SetText text: "
             << StringView(text, from, to - from).ToString();
    cluster_ends_.resize(to - from);
    for (size_t i = 0; i < cluster_starts.size() - 1; ++i) {
      cluster_ends_[cluster_starts[i] - from] = cluster_starts[i + 1];
    }
  } else {
    cluster_ends_.Shrink(0);
  }

  DVLOG(4) << "   Cluster ends: " << base::make_span(cluster_ends_);

  cluster_ends_offset_ = from;
  current_text_ = text;
}

void ShapeResultBloberizer::CommitText() {
  if (current_character_indexes_.empty())
    return;

  unsigned from = current_character_indexes_[0];
  unsigned to = current_character_indexes_[0];
  for (unsigned character_index : current_character_indexes_) {
    unsigned character_index_end =
        cluster_ends_[character_index - cluster_ends_offset_];
    from = std::min(from, character_index);
    to = std::max(to, character_index_end);
  }

  DCHECK(!current_text_.IsNull());

  DVLOG(4) << "   CommitText from: " << from << " to: " << to;
  DVLOG(4) << "   CommitText glyphs: "
           << base::make_span(
                  pending_glyphs_.end() - current_character_indexes_.size(),
                  pending_glyphs_.end());
  DVLOG(4) << "   CommitText cluster starts: "
           << base::make_span(current_character_indexes_);

  wtf_size_t pending_utf8_original_size = pending_utf8_.size();
  wtf_size_t pending_utf8_character_indexes_original_size =
      pending_utf8_character_indexes_.size();

  // Do the UTF-8 conversion here.
  // For each input code point track the location of output UTF-8 code point.

  unsigned current_text_length = current_text_.length();
  DCHECK_LE(to, current_text_length);

  unsigned size = to - from;
  Vector<uint32_t, 256> pending_utf8_character_index_from_character_index(size);
  if (current_text_.Is8Bit()) {
    const LChar* latin1 = current_text_.Characters8();
    wtf_size_t utf8_size = pending_utf8_.size();
    for (unsigned i = from; i < to;) {
      pending_utf8_character_index_from_character_index[i - from] = utf8_size;

      LChar cp = latin1[i++];
      pending_utf8_.Grow(utf8_size + U8_LENGTH(cp));
      U8_APPEND_UNSAFE(pending_utf8_.begin(), utf8_size, cp);
    }
  } else {
    const UChar* utf16 = current_text_.Characters16();
    wtf_size_t utf8_size = pending_utf8_.size();
    for (unsigned i = from; i < to;) {
      pending_utf8_character_index_from_character_index[i - from] = utf8_size;

      UChar32 cp;
      U16_NEXT_OR_FFFD(utf16, i, current_text_length, cp);
      pending_utf8_.Grow(utf8_size + U8_LENGTH(cp));
      U8_APPEND_UNSAFE(pending_utf8_.begin(), utf8_size, cp);
    }
  }

  for (unsigned character_index : current_character_indexes_) {
    unsigned index = character_index - from;
    pending_utf8_character_indexes_.push_back(
        pending_utf8_character_index_from_character_index[index]);
  }

  current_character_indexes_.Shrink(0);

  DVLOG(4) << "  CommitText appended UTF-8: \""
           << std::string(&pending_utf8_[pending_utf8_original_size],
                          pending_utf8_.data() + pending_utf8_.size())
           << "\"";
  DVLOG(4) << "  CommitText UTF-8 indexes: "
           << base::span(pending_utf8_character_indexes_)
                  .subspan(pending_utf8_character_indexes_original_size);
}

void ShapeResultBloberizer::CommitPendingRun() {
  if (pending_glyphs_.empty())
    return;

  if (pending_canvas_rotation_ != builder_rotation_) {
    // The pending run rotation doesn't match the current blob; start a new
    // blob.
    CommitPendingBlob();
    builder_rotation_ = pending_canvas_rotation_;
  }

  if (!current_character_indexes_.empty()) [[unlikely]] {
    CommitText();
  }

  SkFont run_font =
      pending_font_data_->PlatformData().CreateSkFont(&font_description_);

  const auto run_size = pending_glyphs_.size();
  const auto text_size = pending_utf8_.size();
  const auto& buffer = [&]() {
    if (HasPendingVerticalOffsets()) {
      if (text_size)
        return builder_.allocRunTextPos(run_font, run_size, text_size);
      else
        return builder_.allocRunPos(run_font, run_size);
    } else {
      if (text_size)
        return builder_.allocRunTextPosH(run_font, run_size, 0, text_size);
      else
        return builder_.allocRunPosH(run_font, run_size, 0);
    }
  }();
  builder_run_count_ += 1;

  if (text_size) {
    DVLOG(4) << "  CommitPendingRun text: \""
             << std::string(pending_utf8_.begin(), pending_utf8_.end()) << "\"";
    DVLOG(4) << "  CommitPendingRun glyphs: "
             << base::make_span(pending_glyphs_);
    DVLOG(4) << "  CommitPendingRun indexes: "
             << base::make_span(pending_utf8_character_indexes_);
    DCHECK_EQ(pending_utf8_character_indexes_.size(), run_size);
    base::ranges::copy(pending_utf8_character_indexes_, buffer.clusters);
    base::ranges::copy(pending_utf8_, buffer.utf8text);

    pending_utf8_.Shrink(0);
    pending_utf8_character_indexes_.Shrink(0);
  }

  base::ranges::copy(pending_glyphs_, buffer.glyphs);
  base::ranges::copy(pending_offsets_, buffer.pos);
  pending_glyphs_.Shrink(0);
  pending_offsets_.Shrink(0);
}

void ShapeResultBloberizer::CommitPendingBlob() {
  if (!builder_run_count_)
    return;

  blobs_.emplace_back(builder_.make(), builder_rotation_);
  builder_run_count_ = 0;
}

const ShapeResultBloberizer::BlobBuffer& ShapeResultBloberizer::Blobs() {
  CommitPendingRun();
  CommitPendingBlob();
  DCHECK(pending_glyphs_.empty());
  DCHECK_EQ(builder_run_count_, 0u);

  return blobs_;
}

inline bool ShapeResultBloberizer::IsSkipInkException(
    const StringView& text,
    unsigned character_index) {
  // We want to skip descenders in general, but it is undesirable renderings for
  // CJK characters.
  return type_ == ShapeResultBloberizer::Type::kTextIntercepts &&
         !Character::CanTextDecorationSkipInk(
             text.CodepointAt(character_index));
}

inline void ShapeResultBloberizer::AddEmphasisMark(
    const GlyphData& emphasis_data,
    CanvasRotationInVertical canvas_rotation,
    gfx::PointF glyph_center,
    float mid_glyph_offset) {
  const SimpleFontData* emphasis_font_data = emphasis_data.font_data;
  DCHECK(emphasis_font_data);

  bool is_vertical =
      emphasis_font_data->PlatformData().IsVerticalAnyUpright() &&
      IsCanvasRotationInVerticalUpright(emphasis_data.canvas_rotation);

  if (!is_vertical) {
    Add(emphasis_data.glyph, emphasis_font_data,
        CanvasRotationInVertical::kRegular, mid_glyph_offset - glyph_center.x(),
        0);
  } else {
    Add(emphasis_data.glyph, emphasis_font_data, emphasis_data.canvas_rotation,
        gfx::Vector2dF(-glyph_center.x(), mid_glyph_offset - glyph_center.y()),
        0);
  }
}

namespace {
class GlyphCallbackContext {
  STACK_ALLOCATED();

 public:
  GlyphCallbackContext(ShapeResultBloberizer* bloberizer,
                       const StringView& text)
      : bloberizer(bloberizer), text(text) {}
  GlyphCallbackContext(const GlyphCallbackContext&) = delete;
  GlyphCallbackContext& operator=(const GlyphCallbackContext&) = delete;

  ShapeResultBloberizer* bloberizer;
  const StringView& text;
};
}  // namespace

/*static*/ void ShapeResultBloberizer::AddGlyphToBloberizer(
    void* context,
    unsigned character_index,
    Glyph glyph,
    gfx::Vector2dF glyph_offset,
    float advance,
    bool is_horizontal,
    CanvasRotationInVertical rotation,
    const SimpleFontData* font_data) {
  GlyphCallbackContext* parsed_context =
      static_cast<GlyphCallbackContext*>(context);
  ShapeResultBloberizer* bloberizer = parsed_context->bloberizer;
  const StringView& text = parsed_context->text;

  if (bloberizer->IsSkipInkException(text, character_index))
    return;
  gfx::Vector2dF start_offset =
      is_horizontal ? gfx::Vector2dF(advance, 0) : gfx::Vector2dF(0, advance);
  bloberizer->Add(glyph, font_data, rotation, start_offset + glyph_offset,
                  character_index);
}

/*static*/ void ShapeResultBloberizer::AddFastHorizontalGlyphToBloberizer(
    void* context,
    unsigned character_index,
    Glyph glyph,
    gfx::Vector2dF glyph_offset,
    float advance,
    bool is_horizontal,
    CanvasRotationInVertical canvas_rotation,
    const SimpleFontData* font_data) {
  ShapeResultBloberizer* bloberizer =
      static_cast<ShapeResultBloberizer*>(context);
  DCHECK(!glyph_offset.y());
  DCHECK(is_horizontal);
  bloberizer->Add(glyph, font_data, canvas_rotation, advance + glyph_offset.x(),
                  character_index);
}

float ShapeResultBloberizer::FillGlyphsForResult(const ShapeResult* result,
                                                 const StringView& text,
                                                 unsigned from,
                                                 unsigned to,
                                                 float initial_advance,
                                                 unsigned run_offset) {
  GlyphCallbackContext context = {this, text};
  return result->ForEachGlyph(initial_advance, from, to, run_offset,
                              AddGlyphToBloberizer,
                              static_cast<void*>(&context));
}

namespace {
class ClusterCallbackContext {
  STACK_ALLOCATED();

 public:
  ClusterCallbackContext(ShapeResultBloberizer* bloberizer,
                         const StringView& text,
                         const GlyphData& emphasis_data,
                         gfx::PointF glyph_center)
      : bloberizer(bloberizer),
        text(text),
        emphasis_data(emphasis_data),
        glyph_center(std::move(glyph_center)) {}
  ClusterCallbackContext(const ClusterCallbackContext&) = delete;
  ClusterCallbackContext& operator=(const ClusterCallbackContext&) = delete;

  ShapeResultBloberizer* bloberizer;
  const StringView& text;
  const GlyphData& emphasis_data;
  gfx::PointF glyph_center;
};
}  // namespace

/*static*/ void ShapeResultBloberizer::AddEmphasisMarkToBloberizer(
    void* context,
    unsigned character_index,
    float advance_so_far,
    unsigned graphemes_in_cluster,
    float cluster_advance,
    CanvasRotationInVertical canvas_rotation) {
  ClusterCallbackContext* parsed_context =
      static_cast<ClusterCallbackContext*>(context);
  ShapeResultBloberizer* bloberizer = parsed_context->bloberizer;
  const StringView& text = parsed_context->text;
  const GlyphData& emphasis_data = parsed_context->emphasis_data;
  gfx::PointF glyph_center = parsed_context->glyph_center;

  if (text.Is8Bit()) {
    if (Character::CanReceiveTextEmphasis(text[character_index])) {
      bloberizer->AddEmphasisMark(emphasis_data, canvas_rotation, glyph_center,
                                  advance_so_far + cluster_advance / 2);
    }
  } else {
    float glyph_advance_x = cluster_advance / graphemes_in_cluster;
    for (unsigned j = 0; j < graphemes_in_cluster; ++j) {
      // Do not put emphasis marks on space, separator, and control
      // characters.
      if (Character::CanReceiveTextEmphasis(
              text.CodepointAt(character_index))) {
        bloberizer->AddEmphasisMark(emphasis_data, canvas_rotation,
                                    glyph_center,
                                    advance_so_far + glyph_advance_x / 2);
      }
      advance_so_far += glyph_advance_x;
    }
  }
}

namespace {
class ClusterStarts {
  STACK_ALLOCATED();

 public:
  ClusterStarts() = default;
  ClusterStarts(const ClusterStarts&) = delete;
  ClusterStarts& operator=(const ClusterStarts&) = delete;

  static void Accumulate(void* context,
                         unsigned character_index,
                         Glyph,
                         gfx::Vector2dF,
                         float,
                         bool,
                         CanvasRotationInVertical,
                         const SimpleFontData*) {
    ClusterStarts* self = static_cast<ClusterStarts*>(context);

    if (self->cluster_starts_.empty() ||
        self->last_seen_character_index_ != character_index) {
      self->cluster_starts_.push_back(character_index);
      self->last_seen_character_index_ = character_index;
    }
  }

  void Finish(unsigned from, unsigned to) {
    std::sort(cluster_starts_.begin(), cluster_starts_.end());
    DCHECK_EQ(base::ranges::adjacent_find(cluster_starts_),
              cluster_starts_.end());
    DVLOG(4) << "  Cluster starts: " << base::make_span(cluster_starts_);
    if (!cluster_starts_.empty()) {
      // 'from' may point inside a cluster; the least seen index may be larger.
      DCHECK_LE(from, *cluster_starts_.begin());
      DCHECK_LT(*(cluster_starts_.end() - 1), to);
    }
    cluster_starts_.push_back(to);
  }

  base::span<const unsigned> Data() { return cluster_starts_; }

 private:
  Vector<unsigned, 256> cluster_starts_;
  unsigned last_seen_character_index_ = 0;
};
}  // namespace

ShapeResultBloberizer::FillGlyphs::FillGlyphs(
    const FontDescription& font_description,
    const TextRunPaintInfo& run_info,
    const ShapeResultBuffer& result_buffer,
    const Type type)
    : ShapeResultBloberizer(font_description, type) {
  if (CanUseFastPath(run_info.from, run_info.to, run_info.run.length(),
                     result_buffer.HasVerticalOffsets())) {
    DVLOG(4) << "FillGlyphs fast path";
    DCHECK(!result_buffer.HasVerticalOffsets());
    DCHECK_NE(type_, ShapeResultBloberizer::Type::kTextIntercepts);
    DCHECK_NE(type_, ShapeResultBloberizer::Type::kEmitText);
    advance_ =
        FillFastHorizontalGlyphs(result_buffer, run_info.run.Direction());
    return;
  }

  DVLOG(4) << "FillGlyphs slow path";

  float advance = 0;
  auto results = result_buffer.results_;

  if (type_ == Type::kEmitText) [[unlikely]] {
    unsigned word_offset = 0;
    ClusterStarts cluster_starts;
    for (const auto& word_result : results) {
      word_result->ForEachGlyph(advance, run_info.from, run_info.to,
                                word_offset, ClusterStarts::Accumulate,
                                static_cast<void*>(&cluster_starts));
      word_offset += word_result->NumCharacters();
    }
    cluster_starts.Finish(run_info.from, run_info.to);
    SetText(run_info.run.ToStringView(), run_info.from, run_info.to,
            cluster_starts.Data());
  }

  if (run_info.run.Rtl()) {
    unsigned word_offset = run_info.run.length();
    for (unsigned j = 0; j < results.size(); j++) {
      unsigned resolved_index = results.size() - 1 - j;
      const Member<const ShapeResult>& word_result = results[resolved_index];
      unsigned word_characters = word_result->NumCharacters();
      word_offset -= word_characters;
      DVLOG(4) << " FillGlyphs RTL run from: " << run_info.from
               << " to: " << run_info.to << " offset: " << word_offset
               << " length: " << word_characters;
      advance =
          FillGlyphsForResult(word_result.Get(), run_info.run.ToStringView(),
                              run_info.from, run_info.to, advance, word_offset);
    }
  } else {
    unsigned word_offset = 0;
    for (const auto& word_result : results) {
      unsigned word_characters = word_result->NumCharacters();
      DVLOG(4) << " FillGlyphs LTR run from: " << run_info.from
               << " to: " << run_info.to << " offset: " << word_offset
               << " length: " << word_characters;
      advance =
          FillGlyphsForResult(word_result.Get(), run_info.run.ToStringView(),
                              run_info.from, run_info.to, advance, word_offset);
      word_offset += word_characters;
    }
  }

  if (type_ == Type::kEmitText) [[unlikely]] {
    CommitText();
  }

  advance_ = advance;
}

ShapeResultBloberizer::FillGlyphsNG::FillGlyphsNG(
    const FontDescription& font_description,
    const StringView& text,
    unsigned from,
    unsigned to,
    const ShapeResultView* result,
    const Type type)
    : ShapeResultBloberizer(font_description, type) {
  DCHECK(result);
  DCHECK(to <= text.length());
  float initial_advance = 0;
  if (CanUseFastPath(from, to, result)) {
    DVLOG(4) << "FillGlyphsNG fast path";
    DCHECK(!result->HasVerticalOffsets());
    DCHECK_NE(type_, ShapeResultBloberizer::Type::kTextIntercepts);
    DCHECK_NE(type_, ShapeResultBloberizer::Type::kEmitText);
    advance_ = result->ForEachGlyph(initial_advance,
                                    &AddFastHorizontalGlyphToBloberizer,
                                    static_cast<void*>(this));
    return;
  }

  DVLOG(4) << "FillGlyphsNG slow path";
  unsigned run_offset = 0;
  if (type_ == Type::kEmitText) [[unlikely]] {
    ClusterStarts cluster_starts;
    result->ForEachGlyph(initial_advance, from, to, run_offset,
                         ClusterStarts::Accumulate,
                         static_cast<void*>(&cluster_starts));
    cluster_starts.Finish(from, to);
    SetText(text, from, to, cluster_starts.Data());
  }

  GlyphCallbackContext context = {this, text};
  advance_ =
      result->ForEachGlyph(initial_advance, from, to, run_offset,
                           AddGlyphToBloberizer, static_cast<void*>(&context));

  if (type_ == Type::kEmitText) [[unlikely]] {
    CommitText();
  }
}

ShapeResultBloberizer::FillTextEmphasisGlyphs::FillTextEmphasisGlyphs(
    const FontDescription& font_description,
    const TextRunPaintInfo& run_info,
    const ShapeResultBuffer& result_buffer,
    const GlyphData& emphasis)
    : ShapeResultBloberizer(font_description, Type::kNormal) {
  gfx::PointF glyph_center =
      emphasis.font_data->BoundsForGlyph(emphasis.glyph).CenterPoint();

  float advance = 0;
  auto results = result_buffer.results_;

  if (run_info.run.Rtl()) {
    unsigned word_offset = run_info.run.length();
    for (unsigned j = 0; j < results.size(); j++) {
      unsigned resolved_index = results.size() - 1 - j;
      const Member<const ShapeResult>& word_result = results[resolved_index];
      word_offset -= word_result->NumCharacters();
      StringView text = run_info.run.ToStringView();
      ClusterCallbackContext context = {this, text, emphasis, glyph_center};
      advance = word_result->ForEachGraphemeClusters(
          text, advance, run_info.from, run_info.to, word_offset,
          AddEmphasisMarkToBloberizer, static_cast<void*>(&context));
    }
  } else {  // Left-to-right.
    unsigned word_offset = 0;
    for (const auto& word_result : results) {
      StringView text = run_info.run.ToStringView();
      ClusterCallbackContext context = {this, text, emphasis, glyph_center};
      advance = word_result->ForEachGraphemeClusters(
          text, advance, run_info.from, run_info.to, word_offset,
          AddEmphasisMarkToBloberizer, static_cast<void*>(&context));
      word_offset += word_result->NumCharacters();
    }
  }

  advance_ = advance;
}

ShapeResultBloberizer::FillTextEmphasisGlyphsNG::FillTextEmphasisGlyphsNG(
    const FontDescription& font_description,
    const StringView& text,
    unsigned from,
    unsigned to,
    const ShapeResultView* result,
    const GlyphData& emphasis)
    : ShapeResultBloberizer(font_description, Type::kNormal) {
  gfx::PointF glyph_center =
      emphasis.font_data->BoundsForGlyph(emphasis.glyph).CenterPoint();
  ClusterCallbackContext context = {this, text, emphasis, glyph_center};
  float initial_advance = 0;
  unsigned index_offset = 0;
  advance_ = result->ForEachGraphemeClusters(
      text, initial_advance, from, to, index_offset,
      AddEmphasisMarkToBloberizer, static_cast<void*>(&context));
}

bool ShapeResultBloberizer::CanUseFastPath(unsigned from,
                                           unsigned to,
                                           unsigned length,
                                           bool has_vertical_offsets) {
  return !from && to == length && !has_vertical_offsets &&
         type_ != ShapeResultBloberizer::Type::kTextIntercepts &&
         type_ != ShapeResultBloberizer::Type::kEmitText;
}

bool ShapeResultBloberizer::CanUseFastPath(
    unsigned from,
    unsigned to,
    const ShapeResultView* shape_result) {
  return from <= shape_result->StartIndex() && to >= shape_result->EndIndex() &&
         !shape_result->HasVerticalOffsets() &&
         type_ != ShapeResultBloberizer::Type::kTextIntercepts &&
         type_ != ShapeResultBloberizer::Type::kEmitText;
}

float ShapeResultBloberizer::FillFastHorizontalGlyphs(
    const ShapeResultBuffer& result_buffer,
    TextDirection text_direction) {
  DCHECK(!result_buffer.HasVerticalOffsets());
  DCHECK_NE(type_, ShapeResultBloberizer::Type::kTextIntercepts);

  float advance = 0;
  auto results = result_buffer.results_;

  for (unsigned i = 0; i < results.size(); ++i) {
    const auto& word_result =
        IsLtr(text_direction) ? results[i] : results[results.size() - 1 - i];
    advance = FillFastHorizontalGlyphs(word_result.Get(), advance);
  }

  return advance;
}

float ShapeResultBloberizer::FillFastHorizontalGlyphs(const ShapeResult* result,
                                                      float initial_advance) {
  DCHECK(!result->HasVerticalOffsets());
  DCHECK_NE(type_, ShapeResultBloberizer::Type::kTextIntercepts);

  return result->ForEachGlyph(initial_advance,
                              &AddFastHorizontalGlyphToBloberizer,
                              static_cast<void*>(this));
}

}  // namespace blink

"""

```