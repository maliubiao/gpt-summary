Response:
The user wants a summary of the functionality of the provided C++ code snippet from `shape_result.cc`. The snippet appears to be part of a text shaping engine, likely involved in rendering text in a web browser. I need to identify the key operations performed by this code and explain their purpose in the context of text layout and rendering.

Specifically, I should focus on:

1. **Iterating over glyphs and clusters:** The first part of the code iterates through glyphs within "runs" of text, processing each glyph and potentially grouping them into clusters.
2. **Applying spacing:** The `ApplySpacingImpl` function modifies glyph advances based on some spacing parameters.
3. **Applying leading/trailing expansion:**  Functions like `ApplyLeadingExpansion` and `ApplyTrailingExpansion` adjust the spacing at the beginning or end of text.
4. **Handling auto-spacing:** The `ApplyTextAutoSpacing` and related functions seem to deal with automatic spacing adjustments based on context.
5. **Breaking considerations:** The code mentions "safe to break" which hints at line breaking logic.
6. **Run management:** Functions like `InsertRun` and `CopyRange` indicate the code manages segments of shaped text ("runs").

I will go through the code section by section and synthesize a concise summary of its functions.
这是对 `blink/renderer/platform/fonts/shaping/shape_result.cc` 文件代码片段的功能归纳：

这段代码主要负责处理文本的 **字形（glyph）布局和间距调整**。它遍历已成形的文本运行（runs），对每个字形进行处理，并根据需要应用各种间距调整。

以下是其主要功能点的总结：

1. **字形遍历和信息提取:**
   - 遍历文本运行中的每个字形 (`for (wtf_size_t i = 0; i < num_glyphs; ++i)`)。
   - 获取字形的元数据，例如字符索引 (`glyph_data.character_index`) 和预先计算的宽度 (`glyph_data.advance`)。
   - 判断是否为文本簇（cluster）的结尾 (`is_cluster_end`)。

2. **基于字形的 Callback 执行:**
   - 对于每个字形或文本簇，执行一个回调函数 (`callback`)。
   - 回调函数接收上下文信息 (`context`)，当前字符索引 (`current_character_index`)，到目前为止的累积宽度 (`advance_so_far`)，文本簇中的字形数量 (`graphemes_in_cluster`)，文本簇的宽度 (`cluster_advance`) 和画布旋转信息 (`run->canvas_rotation_`)。
   - 这段逻辑主要用于遍历字形并提供字形级别的布局信息。

3. **应用间距调整 (`ApplySpacingImpl`)**:
   - 遍历文本运行 (`for (auto& run : runs_)`)。
   - 遍历每个运行中的字形 (`for (wtf_size_t i = 0; i < run->glyph_data_.size(); i++)`)。
   - 跳过非文本簇边界的字形。
   - 调用 `spacing.ComputeSpacing` 计算要应用的间距。
   - 将计算出的间距 (`space`) 添加到字形的宽度 (`glyph_data.AddAdvance(space)`)。
   - 根据文本方向（水平或垂直）将间距应用为字形的偏移 (`glyph_data_.AddOffsetWidthAt` 或 `glyph_data_.AddOffsetHeightAt`)。
   - 更新运行的总宽度 (`run->width_`) 和整个 `ShapeResult` 的宽度 (`width_`)。

4. **应用前导和尾随扩展 (`ApplyLeadingExpansion`, `ApplyTrailingExpansion`)**:
   - 在文本的开头或结尾添加额外的间距。
   - 遍历文本运行（对于 `ApplyTrailingExpansion` 是反向遍历）。
   - 找到第一个或最后一个包含字形的运行。
   - 将扩展量添加到运行中第一个或最后一个字形的宽度和偏移。
   - 更新运行和 `ShapeResult` 的总宽度。

5. **应用文本自动间距 (`ApplyTextAutoSpacing`, `ApplyTextAutoSpacingCore`)**:
   - 根据预定义的偏移量列表 (`offsets_with_spacing`)，在特定字符后添加自动间距。
   - 遍历文本运行，找到需要添加间距的位置。
   - 将间距添加到相应字形的宽度中，并更新 `ShapeResultCharacterData` 标记该位置已添加自动间距。

6. **移除自动间距 (`UnapplyAutoSpacing`)**:
   - 从指定范围的最后一个字形中移除自动添加的间距。
   - 创建一个子范围的 `ShapeResult`。
   - 从子范围的最后一个字形中减去间距。

7. **调整偏移以考虑自动间距 (`AdjustOffsetForAutoSpacing`)**:
   -  根据自动间距的存在，调整给定的偏移量。
   -  如果下一个字符在应用自动间距后仍然在给定的位置内，则将偏移量向前移动。

8. **限制字形数量 (`RunInfo::LimitNumGlyphs`)**:
   - 限制单个文本运行中字形的数量，以避免超出内存限制或性能问题。
   - 考虑字符索引的范围 (`kMaxCharacterIndex`) 和最大字形数量 (`kMaxGlyphs`)。
   - 如果字形数量超出限制，则截断字形，并确保截断发生在文本簇的边界。

9. **计算字形位置 (`ComputeGlyphPositions`)**:
   - 根据 HarfBuzz 库提供的字形信息和位置信息，计算每个字形的最终位置。
   - 设置字形的宽度 (`advance`) 和偏移 (`offset`)。
   - 确定是否需要垂直偏移。

10. **插入文本运行 (`InsertRun`)**:
    - 将新的文本运行添加到 `ShapeResult` 中。
    - 保持文本运行在 `ShapeResult` 中按照视觉顺序排列（对于从左到右的文本，按照字符起始索引升序排列；对于从右到左的文本，按照字符起始索引降序排列）。

11. **重新排序从右到左的文本运行 (`ReorderRtlRuns`)**:
    - 对于从右到左的文本，由于新添加的运行可能在逻辑上位于前面，但需要在视觉上排在前面，因此需要重新排序运行。

12. **复制指定范围的字形信息 (`CopyRange`, `CopyRanges`, `CopyRangeInternal`)**:
    - 从当前的 `ShapeResult` 中复制指定范围的字形信息到目标 `ShapeResult`。
    - 处理多个范围复制的情况。
    - 确保复制后的字形信息的字符索引是连续的。

13. **创建子范围 (`SubRange`)**:
    - 创建一个新的 `ShapeResult` 对象，包含当前 `ShapeResult` 中指定范围的字形信息。

**与 JavaScript, HTML, CSS 的关系举例：**

- **JavaScript:**  JavaScript 可以动态修改文本内容或样式，这些修改可能导致需要重新进行文本成形。例如，当 JavaScript 修改元素的 `textContent` 时，浏览器需要重新计算文本的布局，包括调用 `ShapeResult` 相关的功能来确定字形的位置和间距。
- **HTML:** HTML 定义了文本内容和结构。例如，`<span>` 或 `<p>` 标签包含的文本内容会被传递给文本成形引擎进行处理。HTML 的文本方向属性（例如 `dir="rtl"`）会影响文本成形的处理方向。
- **CSS:** CSS 提供了控制文本外观的样式，例如 `font-family`，`font-size`，`letter-spacing`，`word-spacing`，`text-align`，`direction` 等。
    - `letter-spacing` 和 `word-spacing` 的值会影响 `ApplySpacingImpl` 函数计算出的间距。
    - `direction: rtl` 会影响文本运行的排序和处理方向，例如在 `ReorderRtlRuns` 中体现。
    - `text-align: justify` 可能会触发更复杂的间距调整逻辑，可能与 `ApplySpacingImpl` 中的一些条件判断相关。

**逻辑推理的假设输入与输出：**

假设输入一个包含 "Hello World" 字符串的 `ShapeResult` 对象，并且 CSS 样式中设置了 `letter-spacing: 2px;`。

- **假设输入:**
    - `ShapeResult` 对象，包含 "Hello World" 的字形信息，初始字形宽度未应用 `letter-spacing`。
    - `ShapeResultSpacing` 对象，指示需要应用 2px 的字母间距。
- **输出:**
    - 调用 `ApplySpacingImpl` 后，`ShapeResult` 对象中每个字母字形的 `advance` 值会增加 2px。
    - `ShapeResult` 的总宽度 (`width_`) 会相应增加。

**用户或编程常见的使用错误举例：**

- **在已经应用间距的 `ShapeResult` 上再次应用间距:** 代码中的 `DCHECK(!is_applied_spacing_)`  表明，重复应用间距可能会导致错误。开发者可能错误地在同一个 `ShapeResult` 对象上多次调用 `ApplySpacing` 相关方法。
- **传递错误的偏移量给自动间距相关的函数:** 例如，传递的偏移量超出了文本的范围，或者偏移量列表不是有序的，这会导致断言失败或逻辑错误。

总而言之，这段代码是 Chromium Blink 引擎中处理文本布局的核心部分，它负责将抽象的文本内容转换为可在屏幕上绘制的字形序列，并精确地控制字形之间的间距，以实现正确的文本渲染效果。

### 提示词
```
这是目录为blink/renderer/platform/fonts/shaping/shape_result.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
< num_glyphs; ++i) {
      const HarfBuzzRunGlyphData& glyph_data = run->glyph_data_[i];
      uint16_t current_character_index =
          run->start_index_ + glyph_data.character_index + run_offset;
      bool is_run_end = (i + 1 == num_glyphs);
      bool is_cluster_end =
          is_run_end || (run->GlyphToCharacterIndex(i + 1) + run_offset !=
                         current_character_index);

      if ((rtl && current_character_index >= to) ||
          (!rtl && current_character_index < from)) {
        advance_so_far += glyph_data.advance;
        rtl ? --cluster_start : ++cluster_start;
        continue;
      }

      cluster_advance += glyph_data.advance;

      if (text.Is8Bit()) {
        callback(context, current_character_index, advance_so_far, 1,
                 glyph_data.advance, run->canvas_rotation_);

        advance_so_far += glyph_data.advance;
      } else if (is_cluster_end) {
        uint16_t cluster_end;
        if (rtl) {
          cluster_end = current_character_index;
        } else {
          cluster_end = static_cast<uint16_t>(
              is_run_end ? run->start_index_ + run->num_characters_ + run_offset
                         : run->GlyphToCharacterIndex(i + 1) + run_offset);
        }
        graphemes_in_cluster =
            CountGraphemesInCluster(text.Span16(), cluster_start, cluster_end);
        if (!graphemes_in_cluster || !cluster_advance)
          continue;

        callback(context, current_character_index, advance_so_far,
                 graphemes_in_cluster, cluster_advance, run->canvas_rotation_);
        advance_so_far += cluster_advance;

        cluster_start = cluster_end;
        cluster_advance = InlineLayoutUnit();
      }
    }
  }
  return advance_so_far;
}

// TODO(kojii): VC2015 fails to explicit instantiation of a member function.
// Typed functions + this private function are to instantiate instances.
template <typename TextContainerType>
float ShapeResult::ApplySpacingImpl(
    ShapeResultSpacing<TextContainerType>& spacing,
    int text_start_offset) {
  float offset = 0;
  float total_advance = 0;
  TextRunLayoutUnit space;
  for (auto& run : runs_) {
    if (!run)
      continue;
    unsigned run_start_index = run->start_index_ + text_start_offset;
    InlineLayoutUnit total_advance_for_run;
    for (wtf_size_t i = 0; i < run->glyph_data_.size(); i++) {
      HarfBuzzRunGlyphData& glyph_data = run->glyph_data_[i];

      // Skip if it's not a grapheme cluster boundary.
      if (i + 1 < run->glyph_data_.size() &&
          glyph_data.character_index ==
              run->glyph_data_[i + 1].character_index) {
        total_advance_for_run += glyph_data.advance;
        continue;
      }

      typename ShapeResultSpacing<TextContainerType>::ComputeSpacingParameters
          parameters{.index = run_start_index + glyph_data.character_index,
                     .original_advance = glyph_data.advance};
      space = spacing.ComputeSpacing(parameters, offset);
      glyph_data.AddAdvance(space);
      total_advance_for_run += glyph_data.advance;

      // |offset| is non-zero only when justifying CJK characters that follow
      // non-CJK characters.
      if (offset) [[unlikely]] {
        if (run->IsHorizontal()) {
          run->glyph_data_.AddOffsetWidthAt(i, offset);
        } else {
          run->glyph_data_.AddOffsetHeightAt(i, offset);
          has_vertical_offsets_ = true;
        }
        offset = 0;
      }
    }
    run->width_ = total_advance_for_run;
    total_advance += run->width_;
  }
  width_ = total_advance;
  return space;
}

float ShapeResult::ApplySpacing(ShapeResultSpacing<String>& spacing,
                                int text_start_offset) {
  // For simplicity, we apply spacing once only. If you want to do multiple
  // time, please get rid of below |DCHECK()|.
  DCHECK(!is_applied_spacing_) << this;
  is_applied_spacing_ = true;
  return ApplySpacingImpl(spacing, text_start_offset);
}

ShapeResult* ShapeResult::ApplySpacingToCopy(
    ShapeResultSpacing<TextRun>& spacing,
    const TextRun& run) const {
  unsigned index_of_sub_run = spacing.Text().IndexOfSubRun(run);
  DCHECK_NE(std::numeric_limits<unsigned>::max(), index_of_sub_run);
  ShapeResult* result = MakeGarbageCollected<ShapeResult>(*this);
  if (index_of_sub_run != std::numeric_limits<unsigned>::max())
    result->ApplySpacingImpl(spacing, index_of_sub_run);
  return result;
}

void ShapeResult::ApplyLeadingExpansion(LayoutUnit expansion) {
  if (expansion <= LayoutUnit()) {
    return;
  }
  for (auto& run : runs_) {
    if (!run) {
      continue;
    }
    for (wtf_size_t i = 0; i < run->glyph_data_.size(); i++) {
      HarfBuzzRunGlyphData& glyph_data = run->glyph_data_[i];

      // Skip if it's not a grapheme cluster boundary.
      if (i + 1 < run->glyph_data_.size() &&
          glyph_data.character_index ==
              run->glyph_data_[i + 1].character_index) {
        continue;
      }

      const TextRunLayoutUnit advance = expansion.To<TextRunLayoutUnit>();
      glyph_data.AddAdvance(advance);
      const float expansion_as_float = advance.ToFloat();
      run->width_ += expansion_as_float;
      width_ += expansion_as_float;

      if (run->IsHorizontal()) {
        run->glyph_data_.AddOffsetWidthAt(i, expansion_as_float);
      } else {
        run->glyph_data_.AddOffsetHeightAt(i, expansion_as_float);
        has_vertical_offsets_ = true;
      }
      return;
    }
  }
  // No glyphs.
  NOTREACHED();
}

void ShapeResult::ApplyTrailingExpansion(LayoutUnit expansion) {
  if (expansion <= LayoutUnit()) {
    return;
  }
  for (auto& run : base::Reversed(runs_)) {
    if (!run) {
      continue;
    }
    if (run->glyph_data_.IsEmpty()) {
      continue;
    }
    HarfBuzzRunGlyphData& glyph_data = run->glyph_data_.back();
    const TextRunLayoutUnit advance = expansion.To<TextRunLayoutUnit>();
    glyph_data.AddAdvance(advance);
    const float expansion_as_float = advance.ToFloat();
    run->width_ += expansion_as_float;
    width_ += expansion_as_float;
    return;
  }
  // No glyphs.
  NOTREACHED();
}

bool ShapeResult::HasAutoSpacingAfter(unsigned offset) const {
  if (!character_position_.empty() && offset >= StartIndex() &&
      offset < EndIndex()) {
    return CharacterData(offset).has_auto_spacing_after;
  }
  return false;
}

bool ShapeResult::HasAutoSpacingBefore(unsigned offset) const {
  return HasAutoSpacingAfter(offset - 1);
}

void ShapeResult::ApplyTextAutoSpacing(
    const Vector<OffsetWithSpacing, 16>& offsets_with_spacing) {
  // `offsets_with_spacing` must be non-empty, ascending list without the same
  // offsets.
  DCHECK(!offsets_with_spacing.empty());
#if EXPENSIVE_DCHECKS_ARE_ON()
  DCHECK(std::is_sorted(
      offsets_with_spacing.begin(), offsets_with_spacing.end(),
      [](const OffsetWithSpacing& lhs, const OffsetWithSpacing& rhs) {
        return lhs.offset <= rhs.offset;
      }));
  DCHECK_GE(offsets_with_spacing.front().offset, StartIndex());
  DCHECK_LE(offsets_with_spacing.back().offset, EndIndex());
#endif

  EnsurePositionData();
  if (IsLtr()) [[likely]] {
    ApplyTextAutoSpacingCore<TextDirection::kLtr>(offsets_with_spacing.begin(),
                                                  offsets_with_spacing.end());
  } else {
    ApplyTextAutoSpacingCore<TextDirection::kRtl>(offsets_with_spacing.rbegin(),
                                                  offsets_with_spacing.rend());
  }
  RecalcCharacterPositions();
}

template <TextDirection direction, class Iterator>
void ShapeResult::ApplyTextAutoSpacingCore(Iterator offset_begin,
                                           Iterator offset_end) {
  DCHECK(offset_begin != offset_end);
  Iterator current_offset = offset_begin;
  if (current_offset->offset == StartIndex()) [[unlikely]] {
    // Enter this branch if the previous item's direction is RTL and current
    // item's direction is LTR. In this case, spacing cannot be added to the
    // advance of the previous run, otherwise it might be a wrong position after
    // line break. Instead, the spacing is added to the offset of the first run.
    if (Direction() == TextDirection::kRtl) {
      // TODO(https://crbug.com/1463890): Here should be item's direction !=
      // base direction .
      current_offset++;
    } else {
      for (auto& run : runs_) {
        if (!run) [[unlikely]] {
          continue;
        }
        DCHECK_EQ(run->start_index_, current_offset->offset);
        wtf_size_t last_glyph_of_first_char = 0;
        float uni_dim_offset = current_offset->spacing;
        // It is unfortunate to set glyph_data_'s offsets, but it should be
        // super rare to reach there, so it would not hurt memory usage.
        GlyphOffset glyph_offset = run->IsHorizontal()
                                       ? GlyphOffset(uni_dim_offset, 0)
                                       : GlyphOffset(0, uni_dim_offset);
        for (wtf_size_t i = 0; i < run->NumGlyphs(); i++) {
          if (run->glyph_data_[i].character_index != 0) {
            break;
          }
          run->glyph_data_.SetOffsetAt(i, glyph_offset);
          last_glyph_of_first_char = i;
        }
        run->glyph_data_[last_glyph_of_first_char].AddAdvance(uni_dim_offset);
        has_vertical_offsets_ |= (glyph_offset.y() != 0);
        run->width_ += uni_dim_offset;
        current_offset++;
        break;
      }
    }
  }

  for (auto& run : runs_) {
    if (!run) [[unlikely]] {
      continue;
    }
    if (current_offset == offset_end) {
      break;
    }
    wtf_size_t offset = current_offset->offset;
    DCHECK_GE(offset, run->start_index_);
    wtf_size_t offset_in_run = offset - run->start_index_;
    if (offset_in_run > run->num_characters_) {
      continue;
    }

    float total_space_for_run = 0;
    for (wtf_size_t i = 0; i < run->NumGlyphs(); i++) {
      // `character_index` may repeat or skip. Add the spacing to the glyph
      // before the first one that is equal to or greater than `offset_in_run`.
      wtf_size_t next_character_index;
      if (i + 1 < run->glyph_data_.size()) {
        next_character_index = run->glyph_data_[i + 1].character_index;
      } else {
        next_character_index = run->num_characters_;
      }
      bool should_add_spacing;
      if (blink::IsLtr(direction)) {
        // In the following example, add the spacing to the glyph 2 if the
        // `offset_in_run` is 1, 2, or 3.
        //   Glyph|0|1|2|3|4|5|
        //   Char |0|0|0|3|3|4|
        should_add_spacing = next_character_index >= offset_in_run;
      } else {
        // TODO(crbug.com/1463890): RTL might need more considerations, both
        // the protocol and the logic.
        // In the following example, add the spacing to the glyph 2 if the
        // `offset_in_run` is 1, 2, or 3.
        //   Glyph|0|1|2|3|4|5|
        //   Char |4|3|3|0|0|0|
        if (offset_in_run == run->num_characters_) {
          // Except when adding to the end of the run. In that case, add to the
          // last glyph.
          should_add_spacing = i == run->NumGlyphs() - 1;
        } else {
          should_add_spacing = next_character_index < offset_in_run;
        }
      }
      if (should_add_spacing) {
        HarfBuzzRunGlyphData& glyph_data = run->glyph_data_[i];
        glyph_data.AddAdvance(current_offset->spacing);
        total_space_for_run += current_offset->spacing;

        ShapeResultCharacterData& data = CharacterData(offset - 1);
        DCHECK(!data.has_auto_spacing_after);
        data.has_auto_spacing_after = true;

        if (++current_offset == offset_end) {
          break;
        }
        offset = current_offset->offset;
        DCHECK_GE(offset, run->start_index_);
        offset_in_run = offset - run->start_index_;
      }
    }
    run->width_ += total_space_for_run;
  }
#if 0
  // TODO(crbug.com/333698368): Disable the DCHECK for now to unblock VS test.
  DCHECK(current_offset == offset_end);  // Check if all offsets are consumed.
#endif
  // `width_` will be updated in `RecalcCharacterPositions()`.
}

const ShapeResult* ShapeResult::UnapplyAutoSpacing(
    float spacing_width,
    unsigned start_offset,
    unsigned break_offset) const {
  DCHECK_GE(start_offset, StartIndex());
  DCHECK_GT(break_offset, start_offset);
  DCHECK_LE(break_offset, EndIndex());
  DCHECK(HasAutoSpacingBefore(break_offset));

  // Create a `ShapeResult` for the character before `break_offset`.
  ShapeResult* sub_range = SubRange(start_offset, break_offset);

  // Remove the auto-spacing from the last glyph.
  for (const Member<RunInfo>& run : base::Reversed(sub_range->runs_)) {
    if (!run->NumGlyphs()) [[unlikely]] {
      continue;
    }
    HarfBuzzRunGlyphData& last_glyph = run->glyph_data_.back();
    DCHECK_GE(last_glyph.advance.ToFloat(), spacing_width);
    last_glyph.AddAdvance(-spacing_width);
    run->width_ -= spacing_width;
    sub_range->width_ -= spacing_width;
    break;
  }
  return sub_range;
}

unsigned ShapeResult::AdjustOffsetForAutoSpacing(float spacing_width,
                                                 unsigned offset,
                                                 float position) const {
  DCHECK(!character_position_.empty());
  DCHECK(HasAutoSpacingAfter(offset));
  DCHECK_GE(offset, StartIndex());
  offset -= StartIndex();
  DCHECK_LT(offset, NumCharacters());
  // If the next character fits in `position + spacing_width`, then advance
  // the break offset. The auto-spacing at line edges will be removed by
  // `UnapplyAutoSpacing`.
  if (IsLtr()) {
    position += spacing_width;
    if (offset + 1 < NumCharacters()) {
      const ShapeResultCharacterData& data = character_position_[offset + 1];
      if (data.x_position <= position) {
        ++offset;
      }
    } else {
      if (Width() <= position) {
        offset = NumCharacters();
      }
    }
  } else {
    position -= spacing_width;
    if (offset + 1 < NumCharacters()) {
      const ShapeResultCharacterData& data = character_position_[offset + 1];
      if (data.x_position >= position) {
        ++offset;
      }
    } else {
      if (Width() <= -position) {
        offset = NumCharacters();
      }
    }
  }
  return offset + StartIndex();
}

namespace {

float HarfBuzzPositionToFloat(hb_position_t value) {
  return static_cast<float>(value) / (1 << 16);
}

inline TextRunLayoutUnit HarfBuzzPositionToTextLayoutUnit(hb_position_t value) {
  return TextRunLayoutUnit::FromFixed<16>(value);
}

// Checks whether it's safe to break without reshaping before the given glyph.
bool IsSafeToBreakBefore(const hb_glyph_info_t* glyph_infos,
                         unsigned i,
                         unsigned num_glyph,
                         TextDirection direction) {
  if (direction == TextDirection::kLtr) {
    // Before the first glyph is safe to break.
    if (!i)
      return true;

    // Not at a cluster boundary.
    if (glyph_infos[i].cluster == glyph_infos[i - 1].cluster)
      return false;
  } else {
    DCHECK_EQ(direction, TextDirection::kRtl);
    // Before the first glyph is safe to break.
    if (i == num_glyph - 1)
      return true;

    // Not at a cluster boundary.
    if (glyph_infos[i].cluster == glyph_infos[i + 1].cluster)
      return false;
  }

  // The HB_GLYPH_FLAG_UNSAFE_TO_BREAK flag is set for all glyphs in a
  // given cluster so we only need to check the last one.
  hb_glyph_flags_t flags = hb_glyph_info_get_glyph_flags(glyph_infos + i);
  return (flags & HB_GLYPH_FLAG_UNSAFE_TO_BREAK) == 0;
}

}  // anonymous namespace

// This function computes the number of glyphs and characters that can fit into
// this RunInfo.
//
// HarfBuzzRunGlyphData has a limit kMaxCharacterIndex for the character index
// in order to packsave memory. Also, RunInfo has kMaxGlyphs to make the number
// of glyphs predictable and to minimize the buffer reallocations.
void ShapeResult::RunInfo::LimitNumGlyphs(unsigned start_glyph,
                                          unsigned* num_glyphs_in_out,
                                          unsigned* num_glyphs_removed_out,
                                          const bool is_ltr,
                                          const hb_glyph_info_t* glyph_infos) {
  unsigned num_glyphs = *num_glyphs_in_out;
  CHECK_GT(num_glyphs, 0u);

  // If there were larger character indexes than kMaxCharacterIndex, reduce
  // num_glyphs so that all character indexes can fit to kMaxCharacterIndex.
  // Because code points and glyphs are not always 1:1, we need to check the
  // first and the last cluster.
  const hb_glyph_info_t* left_glyph_info = &glyph_infos[start_glyph];
  const hb_glyph_info_t* right_glyph_info = &left_glyph_info[num_glyphs - 1];
  unsigned start_cluster;
  if (is_ltr) {
    start_cluster = left_glyph_info->cluster;
    unsigned last_cluster = right_glyph_info->cluster;
    unsigned max_cluster =
        start_cluster + HarfBuzzRunGlyphData::kMaxCharacterIndex;
    if (last_cluster > max_cluster) [[unlikely]] {
      // Limit at |max_cluster| in LTR. If |max_cluster| is 100:
      //   0 1 2 ... 98 99 99 101 101 103 ...
      //                     ^ limit here.
      // Find |glyph_info| where |cluster| <= |max_cluster|.
      const hb_glyph_info_t* limit_glyph_info = std::upper_bound(
          left_glyph_info, right_glyph_info + 1, max_cluster,
          [](unsigned cluster, const hb_glyph_info_t& glyph_info) {
            return cluster < glyph_info.cluster;
          });
      --limit_glyph_info;
      CHECK_GT(limit_glyph_info, left_glyph_info);
      CHECK_LT(limit_glyph_info, right_glyph_info);
      DCHECK_LE(limit_glyph_info->cluster, max_cluster);
      // Adjust |right_glyph_info| and recompute dependent variables.
      right_glyph_info = limit_glyph_info;
      num_glyphs =
          base::checked_cast<unsigned>(right_glyph_info - left_glyph_info + 1);
      num_characters_ = right_glyph_info[1].cluster - start_cluster;
    }
  } else {
    start_cluster = right_glyph_info->cluster;
    unsigned last_cluster = left_glyph_info->cluster;
    unsigned max_cluster =
        start_cluster + HarfBuzzRunGlyphData::kMaxCharacterIndex;
    if (last_cluster > max_cluster) [[unlikely]] {
      // Limit the right edge, which is in the reverse order in RTL.
      // If |min_cluster| is 3:
      //   103 102 ... 4 4 2 2 ...
      //                  ^ limit here.
      // Find |glyph_info| where |cluster| >= |min_cluster|.
      unsigned min_cluster =
          last_cluster - HarfBuzzRunGlyphData::kMaxCharacterIndex;
      DCHECK_LT(start_cluster, min_cluster);
      const hb_glyph_info_t* limit_glyph_info = std::upper_bound(
          left_glyph_info, right_glyph_info + 1, min_cluster,
          [](unsigned cluster, const hb_glyph_info_t& glyph_info) {
            return cluster > glyph_info.cluster;
          });
      --limit_glyph_info;
      CHECK_GT(limit_glyph_info, left_glyph_info);
      CHECK_LT(limit_glyph_info, right_glyph_info);
      DCHECK_GE(limit_glyph_info->cluster, min_cluster);
      // Adjust |right_glyph_info| and recompute dependent variables.
      right_glyph_info = limit_glyph_info;
      start_cluster = right_glyph_info->cluster;
      num_glyphs =
          base::checked_cast<unsigned>(right_glyph_info - left_glyph_info + 1);
      start_index_ = start_cluster;
      num_characters_ = last_cluster - right_glyph_info[1].cluster;
    }
  }

  // num_glyphs maybe still larger than kMaxGlyphs after it was reduced to fit
  // to kMaxCharacterIndex. Reduce to kMaxGlyphs if so.
  *num_glyphs_removed_out = 0;
  if (num_glyphs > HarfBuzzRunGlyphData::kMaxGlyphs) [[unlikely]] {
    const unsigned old_num_glyphs = num_glyphs;
    num_glyphs = HarfBuzzRunGlyphData::kMaxGlyphs;

    // If kMaxGlyphs is not a cluster boundary, reduce further until the last
    // boundary.
    const unsigned end_cluster = glyph_infos[start_glyph + num_glyphs].cluster;
    for (; num_glyphs; num_glyphs--) {
      if (glyph_infos[start_glyph + num_glyphs - 1].cluster != end_cluster)
        break;
    }

    if (!num_glyphs) {
      // Extreme edge case when kMaxGlyphs is one grapheme cluster. We don't
      // have much choices, just cut at kMaxGlyphs.
      num_glyphs = HarfBuzzRunGlyphData::kMaxGlyphs;
      *num_glyphs_removed_out = old_num_glyphs - num_glyphs;
    } else if (is_ltr) {
      num_characters_ = end_cluster - start_cluster;
      DCHECK(num_characters_);
    } else {
      num_characters_ = glyph_infos[start_glyph].cluster - end_cluster;
      // Cutting the right end glyphs means cutting the start characters.
      start_index_ = glyph_infos[start_glyph + num_glyphs - 1].cluster;
      DCHECK(num_characters_);
    }
  }
  DCHECK_LE(num_glyphs, HarfBuzzRunGlyphData::kMaxGlyphs);

  if (num_glyphs == *num_glyphs_in_out)
    return;
  glyph_data_.Shrink(num_glyphs);
  *num_glyphs_in_out = num_glyphs;
}

// Computes glyph positions, sets advance and offset of each glyph to RunInfo.
template <bool is_horizontal_run>
void ShapeResult::ComputeGlyphPositions(ShapeResult::RunInfo* run,
                                        unsigned start_glyph,
                                        unsigned num_glyphs,
                                        hb_buffer_t* harfbuzz_buffer) {
  DCHECK_EQ(is_horizontal_run, run->IsHorizontal());
  const unsigned start_cluster = run->StartIndex();
  const hb_glyph_info_t* glyph_infos =
      hb_buffer_get_glyph_infos(harfbuzz_buffer, nullptr);
  const hb_glyph_position_t* glyph_positions =
      hb_buffer_get_glyph_positions(harfbuzz_buffer, nullptr);

  DCHECK_LE(num_glyphs, HarfBuzzRunGlyphData::kMaxGlyphs);

  // Compute glyph_origin in physical, since offsets of glyphs are in physical.
  // It's the caller's responsibility to convert to logical.
  InlineLayoutUnit total_advance;
  bool has_vertical_offsets = !is_horizontal_run;

  // HarfBuzz returns result in visual order, no need to flip for RTL.
  for (unsigned i = 0; i < num_glyphs; ++i) {
    const hb_glyph_info_t glyph = glyph_infos[start_glyph + i];
    const hb_glyph_position_t& pos = glyph_positions[start_glyph + i];

    // One out of x_advance and y_advance is zero, depending on
    // whether the buffer direction is horizontal or vertical.
    // Convert to float and negate to avoid integer-overflow for ULONG_MAX.
    const TextRunLayoutUnit advance =
        is_horizontal_run ? HarfBuzzPositionToTextLayoutUnit(pos.x_advance)
                          : -HarfBuzzPositionToTextLayoutUnit(pos.y_advance);

    DCHECK_GE(glyph.cluster, start_cluster);
    const uint16_t character_index = glyph.cluster - start_cluster;
    DCHECK_LE(character_index, HarfBuzzRunGlyphData::kMaxCharacterIndex);
    DCHECK_LT(character_index, run->num_characters_);
    run->glyph_data_[i] = {glyph.codepoint, character_index,
                           IsSafeToBreakBefore(glyph_infos + start_glyph, i,
                                               num_glyphs, Direction()),
                           advance};

    // Offset is primarily used when painting glyphs. Keep it in physical.
    if (pos.x_offset || pos.y_offset) [[unlikely]] {
      has_vertical_offsets |= (pos.y_offset != 0);
      const GlyphOffset offset(HarfBuzzPositionToFloat(pos.x_offset),
                               -HarfBuzzPositionToFloat(pos.y_offset));
      run->glyph_data_.SetOffsetAt(i, offset);
    }

    total_advance += advance;
  }

  run->width_ = total_advance.ClampNegativeToZero().ToFloat();
  has_vertical_offsets_ |= has_vertical_offsets;
  run->CheckConsistency();
}

void ShapeResult::InsertRun(ShapeResult::RunInfo* run,
                            unsigned start_glyph,
                            unsigned num_glyphs,
                            unsigned* next_start_glyph,
                            hb_buffer_t* harfbuzz_buffer) {
  DCHECK_GT(num_glyphs, 0u);

  const hb_glyph_info_t* glyph_infos =
      hb_buffer_get_glyph_infos(harfbuzz_buffer, nullptr);
  const bool is_ltr =
      HB_DIRECTION_IS_FORWARD(hb_buffer_get_direction(harfbuzz_buffer));
  // num_glyphs_removed will be non-zero if the first grapheme cluster of |run|
  // is too big to fit in a single run, in which case it is truncated and the
  // truncated glyphs won't be inserted into any run.
  unsigned num_glyphs_removed = 0;
  run->LimitNumGlyphs(start_glyph, &num_glyphs, &num_glyphs_removed, is_ltr,
                      glyph_infos);
  *next_start_glyph = start_glyph + run->NumGlyphs() + num_glyphs_removed;

  if (run->IsHorizontal()) {
    // Inserting a horizontal run into a horizontal or vertical result.
    ComputeGlyphPositions<true>(run, start_glyph, num_glyphs, harfbuzz_buffer);
  } else {
    // Inserting a vertical run to a vertical result.
    ComputeGlyphPositions<false>(run, start_glyph, num_glyphs, harfbuzz_buffer);
  }
  width_ += run->width_;
  num_glyphs_ += run->NumGlyphs();
  DCHECK_GE(num_glyphs_, run->NumGlyphs());

  InsertRun(run);
}

void ShapeResult::InsertRun(ShapeResult::RunInfo* run) {
  // The runs are stored in result->m_runs in visual order. For LTR, we place
  // the run to be inserted before the next run with a bigger character start
  // index.
  const auto ltr_comparer = [](Member<RunInfo>& run, unsigned start_index) {
    return run->start_index_ < start_index;
  };

  // For RTL, we place the run before the next run with a lower character
  // index. Otherwise, for both directions, at the end.
  const auto rtl_comparer = [](Member<RunInfo>& run, unsigned start_index) {
    return run->start_index_ > start_index;
  };

  auto it = std::lower_bound(
      runs_.begin(), runs_.end(), run->start_index_,
      HB_DIRECTION_IS_FORWARD(run->direction_) ? ltr_comparer : rtl_comparer);
  if (it != runs_.end()) {
    runs_.insert(static_cast<wtf_size_t>(it - runs_.begin()), run);
  } else {
    // If we didn't find an existing slot to place it, append.
    runs_.push_back(run);
  }
}

ShapeResult::RunInfo* ShapeResult::InsertRunForTesting(
    unsigned start_index,
    unsigned num_characters,
    TextDirection direction,
    Vector<uint16_t> safe_break_offsets) {
  auto* run = MakeGarbageCollected<RunInfo>(
      nullptr, blink::IsLtr(direction) ? HB_DIRECTION_LTR : HB_DIRECTION_RTL,
      CanvasRotationInVertical::kRegular, HB_SCRIPT_COMMON, start_index,
      num_characters, num_characters);
  for (unsigned i = 0; i < run->glyph_data_.size(); i++) {
    run->glyph_data_[i] = {0, i, false, TextRunLayoutUnit()};
  }
  for (uint16_t offset : safe_break_offsets)
    run->glyph_data_[offset].safe_to_break_before = true;
  // RTL runs have glyphs in the descending order of character_index.
  if (IsRtl())
    run->glyph_data_.Reverse();
  num_glyphs_ += run->NumGlyphs();
  InsertRun(run);
  return run;
}

// Moves runs at (run_size_before, end) to the front of |runs_|.
//
// Runs in RTL result are in visual order, and that new runs should be
// prepended. This function adjusts the run order after runs were appended.
void ShapeResult::ReorderRtlRuns(unsigned run_size_before) {
  DCHECK(IsRtl());
  DCHECK_GT(runs_.size(), run_size_before);
  if (runs_.size() == run_size_before + 1) {
    if (!run_size_before)
      return;
    RunInfo* new_run = runs_.back();
    runs_.pop_back();
    runs_.push_front(new_run);
    return;
  }

  // |push_front| is O(n) that we should not call it multiple times.
  // Create a new list in the correct order and swap it.
  HeapVector<Member<RunInfo>> new_runs;
  new_runs.ReserveInitialCapacity(runs_.size());
  for (unsigned i = run_size_before; i < runs_.size(); i++)
    new_runs.push_back(runs_[i]);

  // Then append existing runs.
  for (unsigned i = 0; i < run_size_before; i++)
    new_runs.push_back(runs_[i]);
  runs_.swap(new_runs);
}

void ShapeResult::CopyRange(unsigned start_offset,
                            unsigned end_offset,
                            ShapeResult* target) const {
  unsigned run_index = 0;
  CopyRangeInternal(run_index, start_offset, end_offset, target);
}

void ShapeResult::CopyRanges(const ShapeRange* ranges,
                             unsigned num_ranges) const {
  DCHECK_GT(num_ranges, 0u);

  // Ranges are in logical order so for RTL the ranges are proccessed back to
  // front to ensure that they're in a sequential visual order with regards to
  // the runs.
  if (IsRtl()) {
    unsigned run_index = 0;
    unsigned last_range = num_ranges - 1;
    for (unsigned i = 0; i < num_ranges; i++) {
      const ShapeRange& range = ranges[last_range - i];
#if DCHECK_IS_ON()
      DCHECK_GE(range.end, range.start);
      if (i != last_range)
        DCHECK_GE(range.start, ranges[last_range - (i + 1)].end);
#endif
      run_index =
          CopyRangeInternal(run_index, range.start, range.end, range.target);
    }
    return;
  }

  unsigned run_index = 0;
  for (unsigned i = 0; i < num_ranges; i++) {
    const ShapeRange& range = ranges[i];
#if DCHECK_IS_ON()
    DCHECK_GE(range.end, range.start);
    if (i)
      DCHECK_GE(range.start, ranges[i - 1].end);
#endif
    run_index =
        CopyRangeInternal(run_index, range.start, range.end, range.target);
  }
}

unsigned ShapeResult::CopyRangeInternal(unsigned run_index,
                                        unsigned start_offset,
                                        unsigned end_offset,
                                        ShapeResult* target) const {
#if DCHECK_IS_ON()
  unsigned target_num_characters_before = target->num_characters_;
#endif

  target->is_applied_spacing_ |= is_applied_spacing_;

  // When |target| is empty, its character indexes are the specified sub range
  // of |this|. Otherwise the character indexes are renumbered to be continuous.
  //
  // Compute the diff of index and the number of characters from the source
  // ShapeResult and given offsets, because computing them from runs/parts can
  // be inaccurate when all characters in a run/part are missing.
  int index_diff;
  if (!target->num_characters_) {
    index_diff = 0;
    target->start_index_ = start_offset;
  } else {
    index_diff = target->EndIndex() - std::max(start_offset, StartIndex());
  }
  target->num_characters_ +=
      std::min(end_offset, EndIndex()) - std::max(start_offset, StartIndex());

  unsigned target_run_size_before = target->runs_.size();
  bool should_merge = !target->runs_.empty();
  for (; run_index < runs_.size(); run_index++) {
    const auto& run = runs_[run_index];
    unsigned run_start = run->start_index_;
    unsigned run_end = run_start + run->num_characters_;

    if (start_offset < run_end && end_offset > run_start) {
      unsigned start = start_offset > run_start ? start_offset - run_start : 0;
      unsigned end = std::min(end_offset, run_end) - run_start;
      DCHECK(end > start);

      if (RunInfo* sub_run = run->CreateSubRun(start, end)) {
        sub_run->start_index_ += index_diff;
        target->width_ += sub_run->width_;
        target->num_glyphs_ += sub_run->glyph_data_.size();
        if (auto* merged_run =
                should_merge ? target->runs_.back()->MergeIfPossible(*sub_run)
                             : nullptr) {
          target->runs_.back() = merged_run;
        } else {
          target->runs_.push_back(sub_run);
        }
      }
      should_merge = false;

      // No need to process runs after the end of the range.
      if ((IsLtr() && end_offset <= run_end) ||
          (IsRtl() && start_offset >= run_start)) {
        break;
      }
    }
  }

  if (!target->num_glyphs_) {
    return run_index;
  }

  // Runs in RTL result are in visual order, and that new runs should be
  // prepended. Reorder appended runs.
  DCHECK_EQ(IsRtl(), target->IsRtl());
  if (IsRtl() && target->runs_.size() != target_run_size_before) [[unlikely]] {
    target->ReorderRtlRuns(target_run_size_before);
  }

  target->has_vertical_offsets_ |= has_vertical_offsets_;

#if DCHECK_IS_ON()
  DCHECK_EQ(
      target->num_characters_ - target_num_characters_before,
      std::min(end_offset, EndIndex()) - std::max(start_offset, StartIndex()));
  target->CheckConsistency();
#endif

  return run_index;
}

ShapeResult* ShapeResult::SubRange(unsigned start_offset,
                                   unsigned end_offset) const {
  ShapeResult* sub_range =
      MakeGarbageCollected<ShapeResult>(primary_font_.Get(), 0, 0, Direction());
  CopyRange(start_offset, end_offset, sub_range);
  return sub_range;
}

const ShapeResult* ShapeResult::CopyAdjustedOffset(unsigned start_index) const {
  ShapeResult* result = MakeGarbageCollected<ShapeResult>(*this);

  if (start_index > result->StartIndex()) {
    unsigned delta = start_index - result->StartIndex();
    for (auto& run : result->runs_)
      run->start_index_ += delta;
  } else {
    unsigned delta = result->StartIndex() - start_index;
```