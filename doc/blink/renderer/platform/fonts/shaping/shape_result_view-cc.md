Response:
Let's break down the thought process for analyzing this `shape_result_view.cc` file.

1. **Understand the Purpose:** The filename itself, `shape_result_view.cc`, strongly suggests it's a view or representation of some shaping result. Coupled with the directory `blink/renderer/platform/fonts/shaping/`, it's clearly related to font rendering and text shaping within the Blink rendering engine.

2. **Identify Key Classes and Structures:**  Scanning the code reveals central classes and structs:
    * `ShapeResultView`: The primary class, likely responsible for holding and managing shaped text data.
    * `RunInfoPart`:  Seems to represent a segment or "run" of shaped text with specific properties.
    * `ShapeResult`:  While not fully defined in this file, it's clearly the source of the data for `ShapeResultView`.
    * `Segment`:  Used when creating `ShapeResultView` from multiple sources.
    * `InitData`: A helper struct for initializing `ShapeResultView`.

3. **Analyze `ShapeResultView`'s Members:**  Looking at the member variables of `ShapeResultView` provides insights into what data it stores:
    * `primary_font_`: The main font used.
    * `start_index_`:  The starting character index in the original text.
    * `num_glyphs_`: The number of glyphs (visual representations of characters).
    * `direction_`:  Text direction (LTR or RTL).
    * `has_vertical_offsets_`: Whether glyphs have vertical positioning.
    * `char_index_offset_`: An offset for character indices.
    * `parts_`: A collection of `RunInfoPart` objects.
    * `width_`: The total width of the shaped text.

4. **Analyze `RunInfoPart`'s Members:**  Similarly, examining `RunInfoPart`'s members clarifies its role:
    * `run_`: A pointer to a `ShapeResult::RunInfo`, which likely contains lower-level shaping data.
    * `range_`: A range of glyph data within the run.
    * `start_index_`: The starting character index of this part.
    * `offset_`: An offset within the run.
    * `num_characters_`: The number of characters in this part.
    * `width_`: The width of this part.

5. **Examine Key Methods and their Functionality:**  The methods reveal the core operations `ShapeResultView` performs:
    * **Constructors (`ShapeResultView::ShapeResultView`, `ShapeResultView::Create`):** How `ShapeResultView` instances are created, often taking `ShapeResult` or other `ShapeResultView` instances as input. The `Create` methods with `Segment` arrays indicate handling of text split across multiple shaping results.
    * **`CreateShapeResult()`:**  The reverse operation – converting a `ShapeResultView` back into a `ShapeResult`.
    * **`PopulateRunInfoParts()`:** How `ShapeResultView` populates its `parts_` from `ShapeResult` or other `ShapeResultView` instances.
    * **`PreviousSafeToBreakOffset()`:**  Determining the last safe place to break a line before a given character index. This is crucial for text wrapping.
    * **`ForEachGlyph()` and `ForEachGraphemeClusters()`:**  Iterating over glyphs and grapheme clusters, providing information about their position, appearance, and the characters they represent. These are core methods for rendering text.
    * **`ComputeInkBounds()`:** Calculating the bounding box that encloses all the rendered glyphs.
    * **`ExpandRangeToIncludePartialGlyphs()`:** Adjusting character ranges to encompass partially rendered glyphs.

6. **Infer Relationships to Web Technologies:** Based on the functionality:
    * **JavaScript:**  JavaScript can manipulate text content and styles, which ultimately affect the input to the shaping process. The output of `ShapeResultView` is used to render text, which is part of what JavaScript might control.
    * **HTML:** HTML defines the structure and content of web pages, including the text to be rendered. The text content in HTML is the source data for shaping.
    * **CSS:** CSS controls the visual presentation of HTML elements, including font properties (family, size, weight, style), text direction, and line breaking behavior. These CSS properties directly influence the shaping process and the information stored in `ShapeResultView`.

7. **Consider Logical Reasoning and Examples:**
    * **Line Breaking:** The `PreviousSafeToBreakOffset()` method is a clear example of a logical process. Given a character index, it needs to find the preceding valid break point based on the script and language rules. Thinking about different scripts (Latin, CJK) and how line breaks work in those contexts helps understand the complexity.
    * **Glyph Iteration:**  The `ForEachGlyph()` method takes a callback. Imagine a scenario where you want to highlight specific words in a text. You'd use `ForEachGlyph()` to get the bounding boxes of the glyphs corresponding to those words.
    * **Text Direction:** The code explicitly handles LTR and RTL text. Consider how the iteration order and break point calculation would differ between these directions.

8. **Think about Potential User/Programming Errors:**
    * **Incorrect Input Ranges:**  Methods like `Create` with start and end indices are prone to errors if the provided indices are out of bounds or reversed.
    * **Mismatched `ShapeResult` and Text:**  If the `ShapeResultView` is created with a `ShapeResult` that doesn't correspond to the actual text being rendered, the glyph information will be incorrect.
    * **Incorrect Use of Offsets:** The various offset parameters (`start_index_`, `char_index_offset_`, offsets within `RunInfoPart`) need careful management. Errors in calculating or applying these offsets can lead to misaligned or incorrectly rendered text.

9. **Structure the Explanation:** Finally, organize the findings into a coherent explanation, covering the core functionality, relationships to web technologies with examples, logical reasoning with input/output examples, and common usage errors. Use clear and concise language.

By following these steps, we can systematically analyze the code and understand its purpose, functionalities, and implications within the larger context of the Blink rendering engine.
这个文件 `shape_result_view.cc` 是 Chromium Blink 引擎中负责 **查看和操作文本塑形（shaping）结果** 的一个核心组件。它提供了一种更方便、更高效的方式来访问和处理 `ShapeResult` 中存储的文本布局信息。

**主要功能：**

1. **提供对文本塑形结果的只读视图 (Read-only View):**  `ShapeResultView` 不拥有底层的 `ShapeResult` 数据，而是提供一个视图，允许访问其内容，例如字形（glyphs）、字形偏移、前进宽度（advance）、以及与每个字形对应的字符索引等信息。这避免了在只需要读取数据时进行昂贵的拷贝操作。

2. **支持处理分段 (Segments) 的塑形结果:**  它可以将多个 `ShapeResult` 或 `ShapeResultView` 的片段组合成一个单一的逻辑视图。这在处理例如带有 `<br>` 标签的多行文本时非常有用，每个 `<br>` 可能会产生独立的 `ShapeResult`。

3. **提供高效的字形迭代方法:**  它提供了 `ForEachGlyph` 和 `ForEachGraphemeClusters` 等方法，允许以不同的粒度遍历文本中的字形和字素簇（grapheme clusters）。这些方法通常接受一个回调函数，对每个字形或字素簇执行自定义操作。

4. **计算文本的墨水边界 (Ink Bounds):** `ComputeInkBounds` 方法可以计算出文本中所有字形实际绘制区域的边界矩形。这对于布局、碰撞检测等操作至关重要。

5. **查找安全换行点:** `PreviousSafeToBreakOffset` 方法允许查找给定字符索引之前的安全换行点。这对于实现正确的文本换行逻辑至关重要。

6. **创建新的 `ShapeResult`:**  `CreateShapeResult` 方法可以将 `ShapeResultView` 中包含的信息重新打包成一个新的 `ShapeResult` 对象。这在需要对塑形结果进行修改或传递给其他需要 `ShapeResult` 对象的功能时很有用。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`ShapeResultView` 本身并不直接与 JavaScript, HTML, CSS 交互，它处于 Blink 引擎的更底层，负责处理文本布局的核心逻辑。然而，它的功能是支撑这些 Web 技术的基础。

* **HTML:** HTML 定义了网页的结构和内容，包括文本内容。`ShapeResultView` 处理的就是这些 HTML 文本的塑形结果。例如，当浏览器渲染 `<p>Hello World!</p>` 时，会先将 "Hello World!" 进行塑形，`ShapeResultView` 就提供了访问这个塑形结果的途径。

* **CSS:** CSS 决定了文本的样式，例如字体、字号、颜色、文字方向等。这些 CSS 属性会影响文本的塑形过程，从而影响 `ShapeResult` 的内容，最终也影响 `ShapeResultView` 中可见的信息。例如：
    * **`font-family`:**  不同的字体会导致不同的字形形状和尺寸。
    * **`font-size`:**  字号会直接影响字形的大小和文本的整体宽度。
    * **`direction: rtl;`:**  CSS 的 `direction` 属性会影响文本的排列方向，`ShapeResultView` 需要正确处理从右到左的文本。

* **JavaScript:** JavaScript 可以动态地操作 HTML 结构和 CSS 样式，也可以获取和操作文本内容。虽然 JavaScript 通常不直接操作 `ShapeResultView`，但浏览器内部会使用其功能来辅助实现 JavaScript 相关的文本操作，例如：
    * **`element.offsetWidth` 和 `element.offsetHeight`:**  计算元素的尺寸时，需要知道文本的渲染宽度和高度，这会涉及到 `ShapeResultView` 计算的墨水边界。
    * **`Selection API`:**  实现文本选择功能时，需要精确地定位字符和字形的位置，`ShapeResultView` 提供的字形迭代方法可以帮助实现。
    * **自定义渲染逻辑:**  在一些高级的 JavaScript 文本渲染场景中，开发者可能需要获取底层的字形信息，虽然不能直接访问 `ShapeResultView`，但其提供的数据是实现这些功能的必要基础。

**逻辑推理与假设输入/输出：**

假设我们有以下输入文本和样式：

**输入文本:** "你好 世界"
**CSS:** `font-family: "SimSun"; font-size: 16px;`

Blink 引擎会首先进行文本塑形，生成一个 `ShapeResult` 对象。然后，我们可以创建一个 `ShapeResultView` 来查看这个结果。

**假设 `ShapeResult` 包含以下信息（简化表示）：**

* **字形数据:**
    * 字形 1 (你):  glyph_id=100, advance=10, character_index=0
    * 字形 2 (好):  glyph_id=101, advance=12, character_index=1
    * 字形 3 ( ):   glyph_id=102, advance=5,  character_index=2
    * 字形 4 (世):  glyph_id=103, advance=11, character_index=3
    * 字形 5 (界):  glyph_id=104, advance=13, character_index=4
* **文本方向:** LTR

**使用 `ShapeResultView` 的一些可能输出：**

* **`ForEachGlyph` 迭代 (假设回调函数只是打印字形信息):**
    ```
    Glyph: 100, Advance: 10, Character Index: 0
    Glyph: 101, Advance: 12, Character Index: 1
    Glyph: 102, Advance: 5,  Character Index: 2
    Glyph: 103, Advance: 11, Character Index: 3
    Glyph: 104, Advance: 13, Character Index: 4
    ```

* **`ComputeInkBounds` 输出 (假设字形都是从基线开始绘制):**
    `RectF(0, 0, 10 + 12 + 5 + 11 + 13, 字形高度)`  （实际高度取决于字体）

* **`PreviousSafeToBreakOffset(3)` 输出:**  会返回 `2` (空格的位置)，因为空格通常是一个安全的换行点。

**用户或编程常见的使用错误：**

1. **传递不匹配的索引范围:** 在使用 `Create` 方法创建 `ShapeResultView` 的子集时，如果传递的 `start_index` 和 `end_index` 超出了原始 `ShapeResult` 的范围，或者 `start_index` 大于 `end_index`，会导致错误或未定义的行为。

   **例子:** 假设一个 `ShapeResult` 对应 "ABCDE"，索引范围是 0-4。
   * 错误 1: `ShapeResultView::Create(result, -1, 3);` // 负索引
   * 错误 2: `ShapeResultView::Create(result, 2, 6);` // 结束索引超出范围
   * 错误 3: `ShapeResultView::Create(result, 3, 1);` // 开始索引大于结束索引

2. **在修改 `ShapeResult` 后未更新 `ShapeResultView`:** `ShapeResultView` 是对 `ShapeResult` 的一个视图，如果直接修改了底层的 `ShapeResult` 对象，`ShapeResultView` 并不会自动更新。这会导致 `ShapeResultView` 中的数据与实际的塑形结果不一致。

   **例子:**
   ```c++
   ShapeResult* result = ...;
   ShapeResultView* view = ShapeResultView::Create(result);

   // 修改 result 中的一些字形数据
   result->runs_[0]->glyph_data_[0].advance = 20;

   // 此时 view 中的信息可能仍然是修改前的
   view->ForEachGlyph(...); // 输出的 advance 可能仍然是旧的值
   ```
   要解决这个问题，需要创建一个新的 `ShapeResultView`。

3. **错误地假设 `ShapeResultView` 拥有数据:**  开发者可能会错误地尝试修改 `ShapeResultView` 中的数据，例如 `parts_` 成员。由于 `ShapeResultView` 只是一个视图，这样做是无效的，并且可能导致程序崩溃或产生难以调试的错误。

4. **在多线程环境下并发访问和修改底层的 `ShapeResult`:**  如果多个线程同时访问同一个 `ShapeResultView`，并且其中一个线程修改了底层的 `ShapeResult`，可能会导致数据竞争和不一致性。需要进行适当的同步控制。

总而言之，`shape_result_view.cc` 文件定义了一个关键的组件，它提供了一个方便和高效的方式来访问和操作文本塑形的结果，是 Blink 引擎中处理文本布局的核心组成部分，并间接地支撑着 JavaScript, HTML 和 CSS 相关的文本渲染和操作功能。理解其功能和使用方法对于理解浏览器如何渲染文本至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result_view.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_view.h"

#include <iterator>
#include <numeric>

#include "base/containers/adapters.h"
#include "base/ranges/algorithm.h"
#include "build/build_config.h"
#include "third_party/blink/renderer/platform/fonts/font.h"
#include "third_party/blink/renderer/platform/fonts/shaping/glyph_bounds_accumulator.h"
#include "third_party/blink/renderer/platform/fonts/shaping/shape_result_inline_headers.h"
#include "ui/gfx/geometry/skia_conversions.h"

namespace blink {

ShapeResultView::RunInfoPart::RunInfoPart(const ShapeResult::RunInfo* run,
                                          GlyphDataRange range,
                                          unsigned start_index,
                                          unsigned offset,
                                          unsigned num_characters,
                                          float width)
    : run_(run),
      range_(range),
      start_index_(start_index),
      offset_(offset),
      num_characters_(num_characters),
      width_(width) {
  static_assert(std::is_trivially_destructible<RunInfoPart>::value, "");
}

void ShapeResultView::RunInfoPart::Trace(Visitor* visitor) const {
  visitor->Trace(run_);
}

unsigned ShapeResultView::RunInfoPart::PreviousSafeToBreakOffset(
    unsigned offset) const {
  if (offset >= NumCharacters())
    return NumCharacters();
  offset += offset_;
  if (run_->IsLtr()) {
    for (const auto& glyph : base::Reversed(*this)) {
      if (glyph.safe_to_break_before && glyph.character_index <= offset)
        return glyph.character_index - offset_;
    }
  } else {
    for (const auto& glyph : *this) {
      if (glyph.safe_to_break_before && glyph.character_index <= offset)
        return glyph.character_index - offset_;
    }
  }

  // Next safe break is at the start of the run.
  return 0;
}

GlyphDataRange ShapeResultView::RunInfoPart::FindGlyphDataRange(
    unsigned start_character_index,
    unsigned end_character_index) const {
  return GetGlyphDataRange().FindGlyphDataRange(
      run_->IsRtl(), start_character_index, end_character_index);
}

// The offset to add to |HarfBuzzRunGlyphData.character_index| to compute the
// character index of the source string.
unsigned ShapeResultView::CharacterIndexOffsetForGlyphData(
    const RunInfoPart& part) const {
  return part.start_index_ + char_index_offset_ - part.offset_;
}

// |InitData| provides values of const member variables of |ShapeResultView|
// for constructor.
struct ShapeResultView::InitData {
  STACK_ALLOCATED();

 public:
  const SimpleFontData* primary_font = nullptr;
  unsigned start_index = 0;
  unsigned char_index_offset = 0;
  TextDirection direction = TextDirection::kLtr;
  bool has_vertical_offsets = false;
  wtf_size_t num_parts = 0;

  // Uses for fast path of constructing |ShapeResultView| from |ShapeResult|.
  void Populate(const ShapeResult& result) {
    PopulateFromShapeResult(result);
    has_vertical_offsets = result.has_vertical_offsets_;
    num_parts = result.RunsOrParts().size();
  }

  // Uses for constructing |ShapeResultView| from |Segments|.
  void Populate(base::span<const Segment> segments) {
    const Segment& first_segment = segments.front();

    if (first_segment.result) {
      DCHECK(!first_segment.view);
      PopulateFromShapeResult(*first_segment.result);
    } else if (first_segment.view) {
      DCHECK(!first_segment.result);
      PopulateFromShapeResult(*first_segment.view);
    } else {
      NOTREACHED();
    }

    // Compute start index offset for the overall run. This is added to the
    // start index of each glyph to ensure consistency with
    // |ShapeResult::SubRange|.
    if (IsLtr()) {
      DCHECK_EQ(start_index, 0u);
      char_index_offset =
          std::max(char_index_offset, first_segment.start_index);
    } else {
      DCHECK(IsRtl());
      start_index = std::max(start_index, first_segment.start_index);
      DCHECK_EQ(char_index_offset, 0u);
    }

    // Accumulates |num_parts| and |has_vertical_offsets|.
    DCHECK_EQ(num_parts, 0u);
    // Iterate |segment| in logical order, because of |ProcessShapeResult()|
    // doesn't case logical/visual order. See |ShapeResult::Create()|.
    for (auto& segment : segments) {
      if (segment.result) {
        DCHECK(!segment.view);
        ProcessShapeResult(*segment.result, segment);
      } else if (segment.view) {
        DCHECK(!segment.result);
        ProcessShapeResult(*segment.view, segment);
      } else {
        NOTREACHED();
      }
    }
  }

 private:
  TextDirection Direction() const { return direction; }
  bool IsLtr() const { return blink::IsLtr(Direction()); }
  bool IsRtl() const { return blink::IsRtl(Direction()); }

  template <typename ShapeResultType>
  void PopulateFromShapeResult(const ShapeResultType& result) {
    primary_font = result.primary_font_;
    direction = result.Direction();
    if (IsLtr()) {
      DCHECK_EQ(start_index, 0u);
      char_index_offset = result.StartIndex();
    } else {
      DCHECK(IsRtl());
      start_index = result.StartIndex();
      DCHECK_EQ(char_index_offset, 0u);
    }
  }

  template <typename ShapeResultType>
  void ProcessShapeResult(const ShapeResultType& result,
                          const Segment& segment) {
    DCHECK_EQ(result.Direction(), Direction());
    has_vertical_offsets |= result.has_vertical_offsets_;
    num_parts += CountRunInfoParts(result, segment);
  }

  template <typename ShapeResultType>
  static unsigned CountRunInfoParts(const ShapeResultType& result,
                                    const Segment& segment) {
    return static_cast<unsigned>(base::ranges::count_if(
        result.RunsOrParts(), [&result, &segment](const auto& run_or_part) {
          return !!RunInfoPart::ComputeStartEnd(*run_or_part.Get(), result,
                                                segment);
        }));
  }
};

ShapeResultView::ShapeResultView(const InitData& data)
    : primary_font_(data.primary_font),
      start_index_(data.start_index),
      num_glyphs_(0),
      direction_(static_cast<unsigned>(data.direction)),
      has_vertical_offsets_(data.has_vertical_offsets),
      char_index_offset_(data.char_index_offset) {}

ShapeResult* ShapeResultView::CreateShapeResult() const {
  ShapeResult* new_result = MakeGarbageCollected<ShapeResult>(
      primary_font_, start_index_ + char_index_offset_, num_characters_,
      Direction());
  new_result->runs_.ReserveInitialCapacity(parts_.size());
  for (const auto& part : RunsOrParts()) {
    auto* new_run = MakeGarbageCollected<ShapeResult::RunInfo>(
        part.run_->font_data_.Get(), part.run_->direction_,
        part.run_->canvas_rotation_, part.run_->script_, part.start_index_,
        part.NumGlyphs(), part.num_characters_);
    new_run->glyph_data_.CopyFromRange(part.range_);
    for (HarfBuzzRunGlyphData& glyph_data : new_run->glyph_data_) {
      DCHECK_GE(glyph_data.character_index, part.offset_);
      glyph_data.character_index -= part.offset_;
      DCHECK_LT(glyph_data.character_index, part.num_characters_);
    }

    new_run->start_index_ += char_index_offset_;
    new_run->width_ = part.width_;
    new_run->num_characters_ = part.num_characters_;
    new_run->CheckConsistency();
    new_result->runs_.push_back(new_run);
  }

  new_result->num_glyphs_ = num_glyphs_;
  new_result->has_vertical_offsets_ = has_vertical_offsets_;
  new_result->width_ = width_;

  return new_result;
}

template <class ShapeResultType>
void ShapeResultView::PopulateRunInfoParts(const ShapeResultType& other,
                                           const Segment& segment) {
  // Compute the diff of index and the number of characters from the source
  // ShapeResult and given offsets, because computing them from runs/parts can
  // be inaccurate when all characters in a run/part are missing.
  const int index_diff = start_index_ + num_characters_ -
                         std::max(segment.start_index, other.StartIndex());

  // |num_characters_| is accumulated for computing |index_diff|.
  num_characters_ += std::min(segment.end_index, other.EndIndex()) -
                     std::max(segment.start_index, other.StartIndex());

  for (const auto& run_or_part : other.RunsOrParts()) {
    const auto* const run = run_or_part.Get();
    const auto part_start_end =
        RunInfoPart::ComputeStartEnd(*run, other, segment);
    if (!part_start_end)
      continue;

    // Adjust start/end to the character index of |RunInfo|. The start index
    // of |RunInfo| could be different from |part_start| for
    // ShapeResultView.
    const unsigned part_start = part_start_end.value().first;
    const unsigned part_end = part_start_end.value().second;
    DCHECK_GE(part_start, run->OffsetToRunStartIndex());
    const unsigned run_start = part_start - run->OffsetToRunStartIndex();
    const unsigned range_start =
        segment.start_index > run_start
            ? std::max(segment.start_index, part_start) - run_start
            : 0;
    const unsigned range_end =
        std::min(segment.end_index, part_end) - run_start;
    DCHECK_GT(range_end, range_start);
    const unsigned part_characters = range_end - range_start;

    // Avoid O(log n) find operation if the entire run is in range.
    GlyphDataRange range;
    float part_width;
    if (part_start >= segment.start_index && part_end <= segment.end_index) {
      range = run->GetGlyphDataRange();
      part_width = run->width_;
    } else {
      range = run->FindGlyphDataRange(range_start, range_end);
      part_width = std::accumulate(
          range.begin, range.end, InlineLayoutUnit(),
          [](InlineLayoutUnit sum, const auto& glyph) {
            return sum + glyph.advance.template To<InlineLayoutUnit>();
          });
    }

    // Adjust start_index for runs to be continuous.
    const unsigned part_start_index = run_start + range_start + index_diff;
    const unsigned part_offset = range_start;
    parts_.emplace_back(run->GetRunInfo(), range, part_start_index, part_offset,
                        part_characters, part_width);

    num_glyphs_ += range.end - range.begin;
    width_ += part_width;
  }
}

void ShapeResultView::PopulateRunInfoParts(const Segment& segment) {
  if (segment.result) {
    DCHECK(!segment.view);
    PopulateRunInfoParts(*segment.result, segment);
  } else if (segment.view) {
    DCHECK(!segment.result);
    PopulateRunInfoParts(*segment.view, segment);
  } else {
    NOTREACHED();
  }
}

ShapeResultView* ShapeResultView::Create(base::span<const Segment> segments) {
  DCHECK(!segments.empty());
  InitData data;
  data.Populate(segments);

  ShapeResultView* out = MakeGarbageCollected<ShapeResultView>(data);
  DCHECK_EQ(out->num_characters_, 0u);
  DCHECK_EQ(out->num_glyphs_, 0u);
  DCHECK_EQ(out->width_, 0);
  out->parts_.ReserveInitialCapacity(data.num_parts);

  // Segments are in logical order, runs and parts are in visual order.
  // Iterate over segments back-to-front for RTL.
  if (out->IsLtr()) {
    for (auto& segment : segments)
      out->PopulateRunInfoParts(segment);
  } else {
    for (auto& segment : base::Reversed(segments))
      out->PopulateRunInfoParts(segment);
  }
  DCHECK_EQ(data.num_parts, out->parts_.size());
  return out;
}

ShapeResultView* ShapeResultView::Create(const ShapeResult* result,
                                         unsigned start_index,
                                         unsigned end_index) {
  const Segment segments[] = {{result, start_index, end_index}};
  return Create(segments);
}

ShapeResultView* ShapeResultView::Create(const ShapeResultView* result,
                                         unsigned start_index,
                                         unsigned end_index) {
  const Segment segments[] = {{result, start_index, end_index}};
  return Create(segments);
}

ShapeResultView* ShapeResultView::Create(const ShapeResult* result) {
  // This specialization is an optimization to allow the bounding box to be
  // re-used.
  InitData data;
  data.Populate(*result);

  ShapeResultView* out = MakeGarbageCollected<ShapeResultView>(data);
  DCHECK_EQ(out->num_characters_, 0u);
  DCHECK_EQ(out->num_glyphs_, 0u);
  DCHECK_EQ(out->width_, 0);
  out->parts_.ReserveInitialCapacity(data.num_parts);

  const Segment segment = {result, 0, std::numeric_limits<unsigned>::max()};
  out->PopulateRunInfoParts(segment);
  DCHECK_EQ(data.num_parts, out->parts_.size());
  return out;
}

unsigned ShapeResultView::PreviousSafeToBreakOffset(unsigned index) const {
  for (auto it = RunsOrParts().rbegin(); it != RunsOrParts().rend(); ++it) {
    const auto& part = *it;
    unsigned run_start = part.start_index_ + char_index_offset_;
    if (index >= run_start) {
      unsigned offset = index - run_start;
      if (offset <= part.num_characters_) {
        return part.PreviousSafeToBreakOffset(offset) + run_start;
      }
      if (IsLtr()) {
        return run_start + part.num_characters_;
      }
    } else if (IsRtl()) {
      if (it == RunsOrParts().rbegin())
        return part.start_index_;
      const auto& previous_run = *--it;
      return previous_run.start_index_ + previous_run.num_characters_;
    }
  }

  return StartIndex();
}

void ShapeResultView::GetRunFontData(
    HeapVector<ShapeResult::RunFontData>* font_data) const {
  for (const auto& part : RunsOrParts()) {
    font_data->push_back(ShapeResult::RunFontData(
        {part.run_->font_data_.Get(),
         static_cast<wtf_size_t>(part.end() - part.begin())}));
  }
}

HeapHashSet<Member<const SimpleFontData>> ShapeResultView::UsedFonts() const {
  HeapHashSet<Member<const SimpleFontData>> used_fonts;
  for (const auto& part : RunsOrParts()) {
    if (part.run_->font_data_) {
      used_fonts.insert(part.run_->font_data_.Get());
    }
  }
  return used_fonts;
}

template <bool has_non_zero_glyph_offsets>
float ShapeResultView::ForEachGlyphImpl(float initial_advance,
                                        GlyphCallback glyph_callback,
                                        void* context,
                                        const RunInfoPart& part) const {
  auto glyph_offsets = part.GetGlyphOffsets<has_non_zero_glyph_offsets>();
  const auto& run = part.run_;
  auto total_advance = InlineLayoutUnit::FromFloatRound(initial_advance);
  bool is_horizontal = HB_DIRECTION_IS_HORIZONTAL(run->direction_);
  const SimpleFontData* font_data = run->font_data_.Get();
  const unsigned character_index_offset_for_glyph_data =
      CharacterIndexOffsetForGlyphData(part);
  for (const auto& glyph_data : part) {
    unsigned character_index =
        glyph_data.character_index + character_index_offset_for_glyph_data;
    glyph_callback(context, character_index, glyph_data.glyph, *glyph_offsets,
                   total_advance, is_horizontal, run->canvas_rotation_,
                   font_data);
    total_advance += glyph_data.advance;
    ++glyph_offsets;
  }
  return total_advance;
}

float ShapeResultView::ForEachGlyph(float initial_advance,
                                    GlyphCallback glyph_callback,
                                    void* context) const {
  auto total_advance = initial_advance;
  for (const auto& part : RunsOrParts()) {
    if (part.HasGlyphOffsets()) {
      total_advance =
          ForEachGlyphImpl<true>(total_advance, glyph_callback, context, part);
    } else {
      total_advance =
          ForEachGlyphImpl<false>(total_advance, glyph_callback, context, part);
    }
  }
  return total_advance;
}

template <bool has_non_zero_glyph_offsets>
float ShapeResultView::ForEachGlyphImpl(float initial_advance,
                                        unsigned from,
                                        unsigned to,
                                        unsigned index_offset,
                                        GlyphCallback glyph_callback,
                                        void* context,
                                        const RunInfoPart& part) const {
  auto glyph_offsets = part.GetGlyphOffsets<has_non_zero_glyph_offsets>();
  auto total_advance = InlineLayoutUnit::FromFloatRound(initial_advance);
  const auto& run = part.run_;
  bool is_horizontal = HB_DIRECTION_IS_HORIZONTAL(run->direction_);
  const SimpleFontData* font_data = run->font_data_.Get();
  const unsigned character_index_offset_for_glyph_data =
      CharacterIndexOffsetForGlyphData(part);
  if (run->IsLtr()) {  // Left-to-right
    for (const auto& glyph_data : part) {
      unsigned character_index =
          glyph_data.character_index + character_index_offset_for_glyph_data;
      if (character_index >= to)
        break;
      if (character_index >= from) {
        glyph_callback(context, character_index, glyph_data.glyph,
                       *glyph_offsets, total_advance, is_horizontal,
                       run->canvas_rotation_, font_data);
      }
      total_advance += glyph_data.advance;
      ++glyph_offsets;
    }

  } else {  // Right-to-left
    for (const auto& glyph_data : part) {
      unsigned character_index =
          glyph_data.character_index + character_index_offset_for_glyph_data;
      if (character_index < from)
        break;
      if (character_index < to) {
        glyph_callback(context, character_index, glyph_data.glyph,
                       *glyph_offsets, total_advance, is_horizontal,
                       run->canvas_rotation_, font_data);
      }
      total_advance += glyph_data.advance;
      ++glyph_offsets;
    }
  }
  return total_advance;
}

float ShapeResultView::ForEachGlyph(float initial_advance,
                                    unsigned from,
                                    unsigned to,
                                    unsigned index_offset,
                                    GlyphCallback glyph_callback,
                                    void* context) const {
  auto total_advance = initial_advance;

  for (const auto& part : parts_) {
    if (part.HasGlyphOffsets()) {
      total_advance = ForEachGlyphImpl<true>(
          total_advance, from, to, index_offset, glyph_callback, context, part);
    } else {
      total_advance = ForEachGlyphImpl<false>(
          total_advance, from, to, index_offset, glyph_callback, context, part);
    }
  }
  return total_advance;
}

float ShapeResultView::ForEachGraphemeClusters(const StringView& text,
                                               float initial_advance,
                                               unsigned from,
                                               unsigned to,
                                               unsigned index_offset,
                                               GraphemeClusterCallback callback,
                                               void* context) const {
  unsigned run_offset = index_offset;
  float advance_so_far = initial_advance;

  for (const auto& part : RunsOrParts()) {
    if (!part.NumGlyphs())
      continue;

    const auto& run = part.run_;
    unsigned graphemes_in_cluster = 1;
    float cluster_advance = 0;
    bool rtl = Direction() == TextDirection::kRtl;

    // A "cluster" in this context means a cluster as it is used by HarfBuzz:
    // The minimal group of characters and corresponding glyphs, that cannot be
    // broken down further from a text shaping point of view.  A cluster can
    // contain multiple glyphs and grapheme clusters, with mutually overlapping
    // boundaries.
    const unsigned character_index_offset_for_glyph_data =
        CharacterIndexOffsetForGlyphData(part) + run_offset;
    uint16_t cluster_start =
        static_cast<uint16_t>(rtl ? part.CharacterIndexOfEndGlyph() +
                                        character_index_offset_for_glyph_data
                                  : part.GlyphAt(0).character_index +
                                        character_index_offset_for_glyph_data);

    const unsigned num_glyphs = part.NumGlyphs();
    for (unsigned i = 0; i < num_glyphs; ++i) {
      const HarfBuzzRunGlyphData& glyph_data = part.GlyphAt(i);
      uint16_t current_character_index =
          glyph_data.character_index + character_index_offset_for_glyph_data;

      bool is_run_end = (i + 1 == num_glyphs);
      bool is_cluster_end =
          is_run_end || (part.GlyphAt(i + 1).character_index +
                             character_index_offset_for_glyph_data !=
                         current_character_index);

      if ((rtl && current_character_index >= to) ||
          (!rtl && current_character_index < from)) {
        advance_so_far += glyph_data.advance.ToFloat();
        rtl ? --cluster_start : ++cluster_start;
        continue;
      }

      cluster_advance += glyph_data.advance.ToFloat();

      if (text.Is8Bit()) {
        callback(context, current_character_index, advance_so_far, 1,
                 glyph_data.advance, run->canvas_rotation_);

        advance_so_far += glyph_data.advance.ToFloat();
      } else if (is_cluster_end) {
        uint16_t cluster_end;
        if (rtl) {
          cluster_end = current_character_index;
        } else {
          cluster_end = static_cast<uint16_t>(
              is_run_end ? part.CharacterIndexOfEndGlyph() +
                               character_index_offset_for_glyph_data
                         : part.GlyphAt(i + 1).character_index +
                               character_index_offset_for_glyph_data);
        }
        graphemes_in_cluster = ShapeResult::CountGraphemesInCluster(
            text.Span16(), cluster_start, cluster_end);
        if (!graphemes_in_cluster || !cluster_advance)
          continue;

        callback(context, current_character_index, advance_so_far,
                 graphemes_in_cluster, cluster_advance, run->canvas_rotation_);
        advance_so_far += cluster_advance;

        cluster_start = cluster_end;
        cluster_advance = 0;
      }
    }
  }
  return advance_so_far;
}

template <bool is_horizontal_run, bool has_non_zero_glyph_offsets>
void ShapeResultView::ComputePartInkBounds(
    const ShapeResultView::RunInfoPart& part,
    float run_advance,
    gfx::RectF* ink_bounds) const {
  // Get glyph bounds from Skia. It's a lot faster if we give it list of glyph
  // IDs rather than calling it for each glyph.
  // TODO(kojii): MacOS does not benefit from batching the Skia request due to
  // https://bugs.chromium.org/p/skia/issues/detail?id=5328, and the cost to
  // prepare batching, which is normally much less than the benefit of
  // batching, is not ignorable unfortunately.
  auto glyph_offsets = part.GetGlyphOffsets<has_non_zero_glyph_offsets>();
  const SimpleFontData& current_font_data = *part.run_->font_data_;
  unsigned num_glyphs = part.NumGlyphs();
#if !BUILDFLAG(IS_APPLE)
  Vector<Glyph, 256> glyphs(num_glyphs);
  unsigned i = 0;
  for (const auto& glyph_data : part)
    glyphs[i++] = glyph_data.glyph;
  Vector<SkRect, 256> bounds_list(num_glyphs);
  current_font_data.BoundsForGlyphs(glyphs, &bounds_list);
#endif

  GlyphBoundsAccumulator<is_horizontal_run> bounds;
  InlineLayoutUnit origin = InlineLayoutUnit::FromFloatCeil(run_advance);
  for (unsigned j = 0; j < num_glyphs; ++j) {
    const HarfBuzzRunGlyphData& glyph_data = part.GlyphAt(j);
#if BUILDFLAG(IS_APPLE)
    gfx::RectF glyph_bounds =
        current_font_data.BoundsForGlyph(glyph_data.glyph);
#else
    gfx::RectF glyph_bounds = gfx::SkRectToRectF(bounds_list[j]);
#endif
    bounds.Unite(glyph_bounds, origin, *glyph_offsets);
    origin += glyph_data.advance;
    ++glyph_offsets;
  }

  if (!is_horizontal_run)
    bounds.ConvertVerticalRunToLogical(current_font_data.GetFontMetrics());
  ink_bounds->Union(bounds.Bounds());
}

gfx::RectF ShapeResultView::ComputeInkBounds() const {
  gfx::RectF ink_bounds;

  float run_advance = 0.0f;
  for (const auto& part : parts_) {
    if (part.HasGlyphOffsets()) {
      if (part.run_->IsHorizontal()) {
        ComputePartInkBounds<true, true>(part, run_advance, &ink_bounds);
      } else {
        ComputePartInkBounds<false, true>(part, run_advance, &ink_bounds);
      }
    } else {
      if (part.run_->IsHorizontal()) {
        ComputePartInkBounds<true, false>(part, run_advance, &ink_bounds);
      } else {
        ComputePartInkBounds<false, false>(part, run_advance, &ink_bounds);
      }
    }
    run_advance += part.Width();
  }

  return ink_bounds;
}

void ShapeResultView::ExpandRangeToIncludePartialGlyphs(unsigned* from,
                                                        unsigned* to) const {
  for (const auto& part : parts_) {
    unsigned part_offset =
        char_index_offset_ + part.start_index_ - part.offset_;
    part.run_->ExpandRangeToIncludePartialGlyphs(
        part_offset, reinterpret_cast<int*>(from), reinterpret_cast<int*>(to));
  }
}

}  // namespace blink

"""

```