Response:
The user wants to understand the functionality of the `shape_result.cc` file in the Chromium Blink engine. I need to analyze the provided C++ code and:

1. **Summarize its purpose:** What is the core responsibility of this file?
2. **Identify connections to web technologies:**  Does it interact with JavaScript, HTML, or CSS? If so, provide examples.
3. **Illustrate logic with examples:**  For specific functions, create hypothetical inputs and outputs to demonstrate their behavior.
4. **Point out potential errors:** Are there common mistakes users or developers might make when working with this kind of code or its concepts?
5. **Provide a final summary:**  Condense the overall functionality of the file.

Let's break down the code section by section:

*   **`MoveShapeResult`:** This function seems to adjust the starting index of the shape result.
*   **`CheckConsistency`:** This function performs internal checks to ensure the integrity of the `ShapeResult` data.
*   **`CreateForTabulationCharacters`:** This function creates a `ShapeResult` specifically for tab characters. It calculates the advance (width) of each tab based on font and tab size.
*   **`CreateForSpaces`:** Similar to the tab function, this creates a `ShapeResult` for space characters.
*   **`CreateForStretchyMathOperator` (two versions):** These functions handle the layout of stretchy mathematical symbols, either by using a single glyph and scaling it or by assembling it from multiple parts.
*   **`ToString` (and the `<<` operator overload):** These functions provide a way to represent the `ShapeResult` as a string for debugging or logging.
*   **`ComputePositionData`:** This function calculates the visual position of each character within the shaped text. It considers the text direction (LTR or RTL).
*   **`EnsurePositionData` and `RecalcCharacterPositions`:** These manage the calculation and caching of character positions.
*   **`CachedOffsetForPosition`:** This function takes a horizontal position and returns the character offset at that position. It performs a binary search for efficiency.
*   **`CachedPositionForOffset`:** This function takes a character offset and returns the horizontal position of that character.
*   **`CachedWidth`:**  Calculates the width of a substring given start and end offsets.
*   **`CachedNextSafeToBreakOffset` and `CachedPreviousSafeToBreakOffset`:**  These functions help in line breaking by finding the next or previous safe place to break the text.
*   **`IndividualCharacterRanges`:** This function calculates the bounding boxes for individual characters.
*   **`ComputeRunInkBounds`:** This function calculates the tight bounding box (ink bounds) of a single "run" of glyphs, taking into account glyph offsets.
*   **`ComputeInkBounds`:** This function calculates the overall ink bounds of the entire `ShapeResult` by combining the ink bounds of its individual runs.

Based on this analysis, I can now formulate the answer.
好的，让我们归纳一下 `blink/renderer/platform/fonts/shaping/shape_result.cc` 文件的功能。

**功能归纳:**

`shape_result.cc` 文件是 Chromium Blink 引擎中负责 **文本塑形 (text shaping)** 结果表示的核心组件。它的主要功能是：

1. **存储和管理文本塑形的结果:**  它包含了一个文本片段（由 `Font`、文本方向、起始索引和长度定义）经过塑形后得到的字形 (glyph) 信息。这些信息包括：
    *   字形本身 (`Glyph`)
    *   字形对应的字符索引 (`character_index`)
    *   字形的排布信息（例如，字形前进宽度 `advance`）
    *   字形是否可以安全地在此之前断行 (`safe_to_break_before`)
    *   字形的偏移量 (`GlyphOffset`)
2. **组织字形信息到“Run”:**  为了高效地管理，字形信息被组织成 `RunInfo` 对象，每个 `RunInfo` 代表具有相同属性（例如，字体、书写方向）的连续字形序列。
3. **提供访问和查询塑形结果的接口:**  它提供了多种方法来查询和访问塑形后的信息，例如：
    *   获取字形数量 (`num_glyphs_`) 和字符数量 (`num_characters_`)
    *   获取整个塑形结果的宽度 (`width_`)
    *   判断文本方向 (`IsLtr`, `IsRtl`)
    *   遍历所有的字形 run
    *   获取指定字符偏移量的水平位置 (`CachedPositionForOffset`)
    *   获取指定水平位置的字符偏移量 (`CachedOffsetForPosition`)
    *   获取指定字符范围的宽度 (`CachedWidth`)
    *   查找下一个或上一个安全断行位置 (`CachedNextSafeToBreakOffset`, `CachedPreviousSafeToBreakOffset`)
    *   计算每个字符的范围 (`IndividualCharacterRanges`)
    *   计算字形的墨水边界 (`ComputeInkBounds`)
4. **支持不同类型的文本塑形结果:** 它包含创建特定类型 `ShapeResult` 的静态方法，例如：
    *   用于制表符 (`CreateForTabulationCharacters`)
    *   用于空格 (`CreateForSpaces`)
    *   用于可伸缩的数学运算符 (`CreateForStretchyMathOperator`)
5. **进行内部一致性检查:**  在调试模式下，`CheckConsistency` 方法会验证 `ShapeResult` 对象内部数据的一致性。

**与 JavaScript, HTML, CSS 的关系举例:**

`ShapeResult` 对象本身并不直接与 JavaScript、HTML 或 CSS 交互。它是在 Blink 渲染引擎内部，在处理文本渲染流程中生成的中间数据结构。然而，它的功能是支持这些 Web 技术的文本显示：

*   **HTML:** 当浏览器解析 HTML 文档，遇到文本内容时，会利用 `ShapeResult` 来确定如何在屏幕上排列这些文本。例如，考虑以下 HTML 代码：

    ```html
    <p style="font-family: sans-serif; direction: rtl;">مرحبا بالعالم</p>
    ```

    当渲染这段文本时，Blink 会：
    1. 确定文本的字体 (`sans-serif`) 和方向 (`rtl` - 从右到左)。
    2. 使用文本塑形算法（通常涉及 HarfBuzz 库）来生成 `ShapeResult` 对象。这个对象会包含每个字符对应的字形、它们的顺序以及它们之间的间距。
    3. 然后，渲染引擎会根据 `ShapeResult` 中提供的信息，将字形绘制到屏幕上。

*   **CSS:** CSS 样式会影响文本塑形的过程。例如：
    *   `font-family`:  不同的字体会有不同的字形和排布规则。`ShapeResult` 会根据指定的字体进行塑形。
    *   `font-size`: 字体大小会影响字形的尺寸和间距。
    *   `direction`:  `ShapeResult` 会根据 `direction: ltr` 或 `direction: rtl` 来排列字形。
    *   `letter-spacing`, `word-spacing`: 这些 CSS 属性会影响字形之间的额外间距，虽然 `ShapeResult` 主要处理基本的字形排布，但这些间距通常在后续的布局阶段应用。
    *   `white-space`: 不同的 `white-space` 属性值会影响空格和换行符的处理，从而影响 `ShapeResult` 的生成，例如 `ShapeResult::CreateForSpaces` 就是处理空格的情况。

*   **JavaScript:** JavaScript 可以通过 DOM API 获取和操作文本内容，最终这些文本会被渲染，并依赖 `ShapeResult` 进行塑形。虽然 JavaScript 不会直接操作 `ShapeResult` 对象，但它影响着需要被塑形的文本内容。例如：

    ```javascript
    let paragraph = document.createElement('p');
    paragraph.textContent = 'Hello';
    document.body.appendChild(paragraph);
    ```

    当浏览器渲染这个新创建的段落时，会为 "Hello" 这个文本生成 `ShapeResult`。

**逻辑推理、假设输入与输出:**

让我们以 `ShapeResult::CachedPositionForOffset` 函数为例进行逻辑推理：

**假设输入:**

*   一个已经生成的 `ShapeResult` 对象，表示文本 "ABC"。
*   文本方向为从左到右 (LTR)。
*   每个字符的宽度都为 10 个像素。
*   调用 `CachedPositionForOffset(1)`，即请求索引为 1 的字符（'B'）的水平位置。

**逻辑推理:**

1. `CachedPositionForOffset` 函数会检查文本方向，这里是 LTR。
2. 对于 LTR 文本，字符的水平位置通常是其左边缘的位置。
3. 索引为 0 的字符 'A' 的位置应该是 0。
4. 索引为 1 的字符 'B' 的位置应该是字符 'A' 的位置加上字符 'A' 的宽度，即 0 + 10 = 10。

**预期输出:**

函数应该返回 `LayoutUnit(10)`。

**用户或编程常见的使用错误举例:**

虽然开发者通常不会直接创建或操作 `ShapeResult` 对象，但理解其背后的概念对于理解文本渲染至关重要。一些可能相关的错误包括：

1. **假设字符和字形一一对应:**  在复杂的文本渲染中，一个字符可能对应多个字形（例如，组合字符），或者多个字符可能组合成一个字形（例如，连字）。开发者不应该假设字符索引和字形索引总是相同的。`ShapeResult` 明确地存储了字符索引和字形之间的映射关系。
2. **忽略文本方向性:**  对于双向文本（包含从左到右和从右到左的文本），简单地从左到右处理字符位置可能会导致显示错误。`ShapeResult` 考虑了文本方向，并提供了基于视觉顺序的位置信息。
3. **在断行逻辑中错误地使用字符偏移:**  在实现自定义的文本断行逻辑时，应该使用 `ShapeResult` 提供的 `CachedNextSafeToBreakOffset` 和 `CachedPreviousSafeToBreakOffset` 等方法，而不是简单地根据字符数量进行分割，以避免在不应该断行的地方断行。
4. **不理解缓存机制的影响:** `ShapeResult` 中使用了一些缓存（例如，字符位置）。如果底层的字体或文本内容发生变化，需要确保这些缓存能够被正确地更新，否则可能会导致显示不一致。

**总结功能 (第 3 部分):**

根据您提供的代码片段，我们可以进一步归纳其功能：

*   **`MoveShapeResult`:** 这个函数允许创建一个新的 `ShapeResult` 对象，该对象共享原始 `ShapeResult` 的数据，但具有不同的起始索引。这在处理文本布局的子片段时很有用，例如，在处理文本行的过程中。它通过调整 `run` 内部的起始索引来实现，避免了数据的复制。
*   **`CheckConsistency` (结尾部分):**  这部分代码进一步完善了 `ShapeResult` 的内部一致性检查，确保字符和字形的数量、起始和结束索引等信息是匹配的。它针对从左到右 (LTR) 和从右到左 (RTL) 的文本方向进行了不同的检查逻辑，并考虑了某些平台上的特殊情况（例如，Mac 上的 RTL 文本可能不会为所有字符都有独立的 run）。

总而言之，`shape_result.cc` 定义了 Blink 渲染引擎中用于表示和操作文本塑形结果的关键数据结构和方法。它连接了文本内容、字体信息和最终的屏幕渲染，是实现正确和高效文本显示的基础。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
  for (auto& run : result->runs_) {
      DCHECK(run->start_index_ >= delta);
      run->start_index_ -= delta;
    }
  }

  result->start_index_ = start_index;
  return result;
}

#if DCHECK_IS_ON()
void ShapeResult::CheckConsistency() const {
  if (runs_.empty()) {
    DCHECK_EQ(0u, num_characters_);
    DCHECK_EQ(0u, num_glyphs_);
    return;
  }

  for (const auto& run : runs_)
    run->CheckConsistency();

  const unsigned start_index = StartIndex();
  unsigned index = start_index;
  unsigned num_glyphs = 0;
  if (IsLtr()) {
    for (const auto& run : runs_) {
      // Characters maybe missing, but must be in increasing order.
      DCHECK_GE(run->start_index_, index);
      index = run->start_index_ + run->num_characters_;
      num_glyphs += run->glyph_data_.size();
    }
  } else {
    // RTL on Mac may not have runs for the all characters. crbug.com/774034
    index = runs_.back()->start_index_;
    for (const auto& run : base::Reversed(runs_)) {
      DCHECK_GE(run->start_index_, index);
      index = run->start_index_ + run->num_characters_;
      num_glyphs += run->glyph_data_.size();
    }
  }
  const unsigned end_index = EndIndex();
  DCHECK_LE(index, end_index);
  DCHECK_EQ(end_index - start_index, num_characters_);
  DCHECK_EQ(num_glyphs, num_glyphs_);
}
#endif

const ShapeResult* ShapeResult::CreateForTabulationCharacters(
    const Font* font,
    TextDirection direction,
    const TabSize& tab_size,
    float position,
    unsigned start_index,
    unsigned length) {
  DCHECK_GT(length, 0u);
  const SimpleFontData* font_data = font->PrimaryFont();
  DCHECK(font_data);
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(font, start_index, length, direction);
  result->num_glyphs_ = length;
  DCHECK_EQ(result->num_glyphs_, length);  // no overflow
  result->has_vertical_offsets_ =
      font_data->PlatformData().IsVerticalAnyUpright();
  // Tab characters are always LTR or RTL, not TTB, even when
  // isVerticalAnyUpright().
  hb_direction_t hb_direction =
      blink::IsLtr(direction) ? HB_DIRECTION_LTR : HB_DIRECTION_RTL;
  // Only the advance of the first tab is affected by |position|.
  TextRunLayoutUnit advance = TextRunLayoutUnit::FromFloatRound(
      font->TabWidth(font_data, tab_size, position));
  do {
    unsigned run_length = std::min(length, HarfBuzzRunGlyphData::kMaxGlyphs);
    RunInfo* run = MakeGarbageCollected<RunInfo>(
        font_data, hb_direction, CanvasRotationInVertical::kRegular,
        HB_SCRIPT_COMMON, start_index, run_length, run_length);
    InlineLayoutUnit run_width;
    for (unsigned i = 0; i < run_length; i++) {
      // 2nd and following tabs have the base width, without using |position|.
      if (i == 1) {
        advance = TextRunLayoutUnit::FromFloatRound(
            font->TabWidth(font_data, tab_size));
      }
      const unsigned index = blink::IsLtr(direction) ? i : length - 1 - i;
      run->glyph_data_[i] = {font_data->SpaceGlyph(), index, true, advance};
      run_width += advance;
    }
    run->width_ = run_width;
    result->width_ += run->width_;
    result->runs_.push_back(run);
    DCHECK_GE(length, run_length);
    length -= run_length;
    start_index += run_length;
  } while (length);
  return result;
}

const ShapeResult* ShapeResult::CreateForSpaces(const Font* font,
                                                TextDirection direction,
                                                unsigned start_index,
                                                unsigned length,
                                                float width) {
  DCHECK_GT(length, 0u);
  const SimpleFontData* font_data = font->PrimaryFont();
  DCHECK(font_data);
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(font, start_index, length, direction);
  result->num_glyphs_ = length;
  DCHECK_EQ(result->num_glyphs_, length);  // no overflow
  result->has_vertical_offsets_ =
      font_data->PlatformData().IsVerticalAnyUpright();
  hb_direction_t hb_direction =
      blink::IsLtr(direction) ? HB_DIRECTION_LTR : HB_DIRECTION_RTL;
  RunInfo* run = MakeGarbageCollected<RunInfo>(
      font_data, hb_direction, CanvasRotationInVertical::kRegular,
      HB_SCRIPT_COMMON, start_index, length, length);
  result->width_ = run->width_ = width;
  length = run->NumGlyphs();
  TextRunLayoutUnit glyph_width = TextRunLayoutUnit::FromFloatRound(width);
  for (unsigned i = 0; i < length; i++) {
    const unsigned index = blink::IsLtr(direction) ? i : length - 1 - i;
    run->glyph_data_[i] = {font_data->SpaceGlyph(), index, true, glyph_width};
    glyph_width = TextRunLayoutUnit();
  }
  result->runs_.push_back(run);
  return result;
}

const ShapeResult* ShapeResult::CreateForStretchyMathOperator(
    const Font* font,
    TextDirection direction,
    Glyph glyph_variant,
    float stretch_size) {
  unsigned start_index = 0;
  unsigned num_characters = 1;
  ShapeResult* result = MakeGarbageCollected<ShapeResult>(
      font, start_index, num_characters, direction);

  hb_direction_t hb_direction = HB_DIRECTION_LTR;
  unsigned glyph_index = 0;
  RunInfo* run = MakeGarbageCollected<RunInfo>(
      font->PrimaryFont(), hb_direction, CanvasRotationInVertical::kRegular,
      HB_SCRIPT_COMMON, start_index, 1 /* num_glyph */, num_characters);
  run->glyph_data_[glyph_index] = {
      glyph_variant, 0 /* character index */, true /* IsSafeToBreakBefore */,
      TextRunLayoutUnit::FromFloatRound(stretch_size)};
  run->width_ = std::max(0.0f, stretch_size);

  result->width_ = run->width_;
  result->num_glyphs_ = run->NumGlyphs();
  result->runs_.push_back(run);

  return result;
}

const ShapeResult* ShapeResult::CreateForStretchyMathOperator(
    const Font* font,
    TextDirection direction,
    OpenTypeMathStretchData::StretchAxis stretch_axis,
    const OpenTypeMathStretchData::AssemblyParameters& assembly_parameters) {
  DCHECK(!assembly_parameters.parts.empty());
  DCHECK_LE(assembly_parameters.glyph_count, HarfBuzzRunGlyphData::kMaxGlyphs);

  bool is_horizontal_assembly =
      stretch_axis == OpenTypeMathStretchData::StretchAxis::Horizontal;
  unsigned start_index = 0;
  unsigned num_characters = 1;
  ShapeResult* result = MakeGarbageCollected<ShapeResult>(
      font, start_index, num_characters, direction);

  hb_direction_t hb_direction =
      is_horizontal_assembly ? HB_DIRECTION_LTR : HB_DIRECTION_TTB;
  RunInfo* run = MakeGarbageCollected<RunInfo>(
      font->PrimaryFont(), hb_direction, CanvasRotationInVertical::kRegular,
      HB_SCRIPT_COMMON, start_index, assembly_parameters.glyph_count,
      num_characters);

  float overlap = assembly_parameters.connector_overlap;
  unsigned part_index = 0;
  for (const auto& part : assembly_parameters.parts) {
    unsigned repetition_count =
        part.is_extender ? assembly_parameters.repetition_count : 1;
    if (!repetition_count)
      continue;
    DCHECK(part_index < assembly_parameters.glyph_count);
    float glyph_ink_ascent;
    if (!is_horizontal_assembly) {
      glyph_ink_ascent = -font->PrimaryFont()->BoundsForGlyph(part.glyph).y();
    }
    for (unsigned repetition_index = 0; repetition_index < repetition_count;
         repetition_index++) {
      unsigned glyph_index =
          is_horizontal_assembly
              ? part_index
              : assembly_parameters.glyph_count - 1 - part_index;
      float full_advance = glyph_index == assembly_parameters.glyph_count - 1
                               ? part.full_advance
                               : part.full_advance - overlap;
      run->glyph_data_[glyph_index] = {
          part.glyph, 0 /* character index */,
          !glyph_index /* IsSafeToBreakBefore */,
          TextRunLayoutUnit::FromFloatRound(full_advance)};
      if (!is_horizontal_assembly) {
        GlyphOffset glyph_offset(
            0, -assembly_parameters.stretch_size + glyph_ink_ascent);
        run->glyph_data_.SetOffsetAt(glyph_index, glyph_offset);
        result->has_vertical_offsets_ |= (glyph_offset.y() != 0);
      }
      part_index++;
    }
  }
  run->width_ = std::max(0.0f, assembly_parameters.stretch_size);

  result->width_ = run->width_;
  result->num_glyphs_ = run->NumGlyphs();
  result->runs_.push_back(run);
  return result;
}

void ShapeResult::ToString(StringBuilder* output) const {
  output->Append("#chars=");
  output->AppendNumber(num_characters_);
  output->Append(", #glyphs=");
  output->AppendNumber(num_glyphs_);
  output->Append(", dir=");
  output->AppendNumber(direction_);
  output->Append(", runs[");
  output->AppendNumber(runs_.size());
  output->Append("]{");
  for (unsigned run_index = 0; run_index < runs_.size(); run_index++) {
    output->AppendNumber(run_index);
    const auto& run = *runs_[run_index];
    output->Append(":{start=");
    output->AppendNumber(run.start_index_);
    output->Append(", #chars=");
    output->AppendNumber(run.num_characters_);
    output->Append(", dir=");
    output->AppendNumber(static_cast<uint32_t>(run.direction_));
    output->Append(", glyphs[");
    output->AppendNumber(run.glyph_data_.size());
    output->Append("]{");
    for (unsigned glyph_index = 0; glyph_index < run.glyph_data_.size();
         glyph_index++) {
      output->AppendNumber(glyph_index);
      const auto& glyph_data = run.glyph_data_[glyph_index];
      output->Append(":{char=");
      output->AppendNumber(glyph_data.character_index);
      output->Append(", glyph=");
      output->AppendNumber(glyph_data.glyph);
      output->Append("}");
    }
    output->Append("}}");
  }
  output->Append("}");
}

String ShapeResult::ToString() const {
  StringBuilder output;
  ToString(&output);
  return output.ToString();
}

std::ostream& operator<<(std::ostream& ostream,
                         const ShapeResult& shape_result) {
  return ostream << shape_result.ToString();
}

template <bool rtl>
void ShapeResult::ComputePositionData() const {
  unsigned next_character_index = 0;
  InlineLayoutUnit total_advance;
  InlineLayoutUnit last_x_position;

  // Iterate runs/glyphs in the visual order; i.e., from the left edge
  // regardless of the directionality, so that |x_position| is always in
  // ascending order.
  // TODO(kojii): It does not work when large negative letter-/word-
  // spacing is applied.
  for (const auto& run : runs_) {
    if (!run)
      continue;

    // Assumes all runs have the same directionality as the ShapeResult so that
    // |x_position| is in ascending order.
    DCHECK_EQ(IsRtl(), run->IsRtl());

    for (const auto& glyph_data : run->glyph_data_) {
      DCHECK_GE(run->start_index_, start_index_);
      const unsigned logical_index =
          run->start_index_ + glyph_data.character_index - start_index_;

      // Make |character_index| to the visual offset.
      DCHECK_LT(logical_index, num_characters_);
      const unsigned character_index =
          rtl ? num_characters_ - logical_index - 1 : logical_index;

      // If this glyph is the first glyph of a new cluster, set the data.
      // Otherwise, |character_position_[character_index]| is already set.
      // Do not overwrite.
      if (character_index >= num_characters_) {
        // We are not sure why we reach here. See http://crbug.com/1286882
        NOTREACHED();
      }
      if (next_character_index <= character_index) {
        if (next_character_index < character_index) {
          // Multiple glyphs may have the same character index and not all
          // character indices may have glyphs. For character indices without
          // glyphs set the x-position to that of the nearest preceding glyph in
          // the logical order; i.e., the last position for LTR or this position
          // for RTL.
          const LayoutUnit x_position =
              (!rtl ? last_x_position : total_advance).ToCeil<LayoutUnit>();
          for (unsigned i = next_character_index; i < character_index; i++) {
            DCHECK_LT(i, num_characters_);
            character_position_[i].SetCachedData(x_position, false, false);
          }
        }

        const LayoutUnit x_position = total_advance.ToCeil<LayoutUnit>();
        character_position_[character_index].SetCachedData(
            x_position, true, glyph_data.safe_to_break_before);
        last_x_position = total_advance;
      }

      total_advance += glyph_data.advance;
      next_character_index = character_index + 1;
    }
  }

  // Fill |x_position| for the rest of characters, when they don't have
  // corresponding glyphs.
  if (next_character_index < num_characters_) {
    const LayoutUnit x_position =
        (!rtl ? last_x_position : total_advance).ToCeil<LayoutUnit>();
    for (unsigned i = next_character_index; i < num_characters_; i++) {
      character_position_[i].SetCachedData(x_position, false, false);
    }
  }

  width_ = total_advance;
}

void ShapeResult::EnsurePositionData() const {
  if (!character_position_.empty()) {
    return;
  }

  character_position_ = HeapVector<ShapeResultCharacterData>(num_characters_);
  RecalcCharacterPositions();
}

void ShapeResult::RecalcCharacterPositions() const {
  DCHECK(!character_position_.empty());

  if (IsLtr()) {
    ComputePositionData<false>();
  } else {
    ComputePositionData<true>();
  }
}

// TODO(eae): Might be worth trying to set midpoint to ~50% more than the number
// of characters in the previous line for the first try. Would cut the number
// of tries in the majority of cases for long strings.
unsigned ShapeResult::CachedOffsetForPosition(LayoutUnit x) const {
  DCHECK(!character_position_.empty());

  // At or before start, return offset *of* the first character.
  // At or beyond the end, return offset *after* the last character.
  const bool rtl = IsRtl();
  const unsigned length = character_position_.size();
  if (x <= 0)
    return !rtl ? 0 : length;
  if (x >= width_)
    return !rtl ? length : 0;

  // Do a binary search to find the largest x-position that is less than or
  // equal to the supplied x value.
  unsigned low = 0;
  unsigned high = length - 1;
  while (low <= high) {
    unsigned midpoint = low + (high - low) / 2;
    const LayoutUnit x_position = character_position_[midpoint].x_position;
    if (x_position <= x && (midpoint + 1 == length ||
                            character_position_[midpoint + 1].x_position > x)) {
      if (!rtl)
        return midpoint;
      // The border belongs to the logical next character.
      return x_position == x ? length - midpoint : length - midpoint - 1;
    }
    if (x < x_position) {
      high = midpoint - 1;
    } else {
      low = midpoint + 1;
    }
  }

  return 0;
}

LayoutUnit ShapeResult::CachedPositionForOffset(unsigned offset) const {
  DCHECK_GE(offset, 0u);
  DCHECK_LE(offset, num_characters_);
  DCHECK(!character_position_.empty());

  const bool rtl = IsRtl();
  const unsigned length = character_position_.size();
  if (!rtl) {
    if (offset < length) {
      return character_position_[offset].x_position;
    }
  } else {
    if (offset >= length) {
      return LayoutUnit();
    }
    // Return the left edge of the next character because in RTL, the position
    // is the right edge of the character.
    for (unsigned visual_offset = length - offset - 1; visual_offset < length;
         visual_offset++) {
      if (character_position_[visual_offset].is_cluster_base) {
        return visual_offset + 1 < length
                   ? character_position_[visual_offset + 1].x_position
                   : LayoutUnit::FromFloatCeil(width_);
      }
    }
  }
  return LayoutUnit::FromFloatCeil(width_);
}

LayoutUnit ShapeResult::CachedWidth(unsigned start_offset,
                                    unsigned end_offset) const {
  const unsigned offset_adjust = StartIndex();
  const LayoutUnit start_position =
      CachedPositionForOffset(start_offset - offset_adjust);
  const LayoutUnit end_position =
      CachedPositionForOffset(end_offset - offset_adjust);
  return IsLtr() ? end_position - start_position
                 : start_position - end_position;
}

unsigned ShapeResult::CachedNextSafeToBreakOffset(unsigned offset) const {
  if (IsRtl()) {
    return NextSafeToBreakOffset(offset);
  }

  DCHECK(!character_position_.empty());
  DCHECK_LE(start_index_, offset);

  const unsigned adjusted_offset = offset - start_index_;
  const unsigned length = character_position_.size();
  DCHECK_LT(adjusted_offset, length);

  for (unsigned i = adjusted_offset; i < length; i++) {
    if (character_position_[i].safe_to_break_before) {
      return start_index_ + i;
    }
  }

  // Next safe break is at the end of the run.
  return start_index_ + length;
}

unsigned ShapeResult::CachedPreviousSafeToBreakOffset(unsigned offset) const {
  if (IsRtl()) {
    return PreviousSafeToBreakOffset(offset);
  }

  DCHECK(!character_position_.empty());
  DCHECK_LE(start_index_, offset);

  const unsigned adjusted_offset = offset - start_index_;
  const unsigned length = character_position_.size();
  DCHECK_LE(adjusted_offset, length);

  // Assume it is always safe to break at the end of the run.
  if (adjusted_offset >= length) {
    return start_index_ + length;
  }

  for (unsigned i = adjusted_offset + 1; i > 0; i--) {
    if (character_position_[i - 1].safe_to_break_before) {
      return start_index_ + (i - 1);
    }
  }

  // Previous safe break is at the start of the run.
  return RuntimeEnabledFeatures::
                 ShapeResultCachedPreviousSafeToBreakOffsetEnabled()
             ? start_index_
             : 0;
}

namespace {

void AddRunInfoRanges(const ShapeResult::RunInfo& run_info,
                      float offset,
                      Vector<CharacterRange>* ranges) {
  Vector<float> character_widths(run_info.num_characters_);
  for (const auto& glyph : run_info.glyph_data_) {
    // TODO(crbug.com/1147011): This should not happen, but crash logs indicate
    // that this is happening.
    if (glyph.character_index >= character_widths.size()) [[unlikely]] {
      NOTREACHED();
    }
    character_widths[glyph.character_index] += glyph.advance.ToFloat();
  }

  if (run_info.IsRtl())
    offset += run_info.width_;

  for (unsigned character_index = 0; character_index < character_widths.size();
       character_index++) {
    float start = offset;
    offset += character_widths[character_index] * (run_info.IsRtl() ? -1 : 1);
    float end = offset;

    // To match getCharacterRange we flip ranges to ensure start <= end.
    if (end < start)
      ranges->push_back(CharacterRange(end, start, 0, 0));
    else
      ranges->push_back(CharacterRange(start, end, 0, 0));
  }
}

}  // anonymous namespace

float ShapeResult::IndividualCharacterRanges(Vector<CharacterRange>* ranges,
                                             float start_x) const {
  DCHECK(ranges);
  float current_x = start_x;

  if (IsRtl()) {
    unsigned run_count = runs_.size();
    for (int index = run_count - 1; index >= 0; index--) {
      current_x -= runs_[index]->width_;
      AddRunInfoRanges(*runs_[index], current_x, ranges);
    }
  } else {
    for (const auto& run : runs_) {
      AddRunInfoRanges(*run, current_x, ranges);
      current_x += run->width_;
    }
  }

  return current_x;
}

template <bool is_horizontal_run, bool has_non_zero_glyph_offsets>
void ShapeResult::ComputeRunInkBounds(const ShapeResult::RunInfo& run,
                                      float run_advance,
                                      gfx::RectF* ink_bounds) const {
  // Get glyph bounds from Skia. It's a lot faster if we give it list of glyph
  // IDs rather than calling it for each glyph.
  // TODO(kojii): MacOS does not benefit from batching the Skia request due to
  // https://bugs.chromium.org/p/skia/issues/detail?id=5328, and the cost to
  // prepare batching, which is normally much less than the benefit of
  // batching, is not ignorable unfortunately.
  auto glyph_offsets = run.glyph_data_.GetOffsets<has_non_zero_glyph_offsets>();
  const SimpleFontData& current_font_data = *run.font_data_;
  unsigned num_glyphs = run.glyph_data_.size();
#if !BUILDFLAG(IS_APPLE)
  Vector<Glyph, 256> glyphs(num_glyphs);
  unsigned i = 0;
  for (const auto& glyph_data : run.glyph_data_)
    glyphs[i++] = glyph_data.glyph;
  Vector<SkRect, 256> bounds_list(num_glyphs);
  current_font_data.BoundsForGlyphs(glyphs, &bounds_list);
#endif

  GlyphBoundsAccumulator<is_horizontal_run> bounds;
  InlineLayoutUnit origin = InlineLayoutUnit::FromFloatCeil(run_advance);
  for (unsigned j = 0; j < num_glyphs; ++j) {
    const HarfBuzzRunGlyphData& glyph_data = run.glyph_data_[j];
#if BUILDFLAG(IS_APPLE)
    gfx::RectF glyph_bounds =
        current_font_data.BoundsForGlyph(glyph_data.glyph);
#else
    gfx::RectF glyph_bounds = gfx::SkRectToRectF(bounds_list[j]);
#endif
    bounds.Unite(glyph_bounds, origin, *glyph_offsets);
    ++glyph_offsets;
    origin += glyph_data.advance;
  }

  if (!is_horizontal_run)
    bounds.ConvertVerticalRunToLogical(current_font_data.GetFontMetrics());
  ink_bounds->Union(bounds.Bounds());
}

gfx::RectF ShapeResult::ComputeInkBounds() const {
  gfx::RectF ink_bounds;
  float run_advance = 0.0f;
  for (const auto& run : runs_) {
    if (run->glyph_data_.HasNonZeroOffsets()) {
      if (run->IsHorizontal())
        ComputeRunInkBounds<true, true>(*run, run_advance, &ink_bounds);
      else
        ComputeRunInkBounds<false, true>(*run, run_advance, &ink_bounds);
    } else {
      if (run->IsHorizontal())
        ComputeRunInkBounds<true, false>(*run, run_advance, &ink_bounds);
      else
        ComputeRunInkBounds<false, false>(*run, run_advance, &ink_bounds);
    }
    run_advance += run->width_;
  }

  return ink_bounds;
}

}  // namespace blink

"""


```