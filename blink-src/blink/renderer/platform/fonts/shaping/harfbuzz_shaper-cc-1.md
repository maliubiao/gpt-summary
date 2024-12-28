Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of the Chromium Blink rendering engine and specifically deals with HarfBuzz shaping. I need to explain what this code does, its relationship to web technologies (JavaScript, HTML, CSS), provide examples of its behavior, point out potential user or programming errors, and finally, summarize its overall purpose.

**Plan:**

1. **Analyze `CapsFeatureSettingsScopedOverlay`:** Understand how it manages OpenType font features related to capitalization.
2. **Analyze `HarfBuzzShaper::ShapeSegment`:** This is the core shaping logic. I need to break down its steps:
    - Initialization and fallback handling.
    - Handling of capitalization features.
    - Interaction with HarfBuzz for actual shaping.
    - Extracting results.
3. **Analyze the various `HarfBuzzShaper::Shape` overloads:**  Understand how they initiate the shaping process with different input parameters.
4. **Analyze `HarfBuzzShaper::GetGlyphData`:**  Understand how it retrieves glyph information for a given font and text.
5. **Connect to web technologies:** Identify how font features, text shaping, and glyph rendering relate to CSS properties and how JavaScript might trigger these processes.
6. **Provide examples:** Illustrate with hypothetical inputs and outputs for key functions.
7. **Identify common errors:**  Consider scenarios where incorrect font settings or text input might lead to unexpected results.
8. **Summarize:**  Concisely describe the overall function of the code.
这是 `blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc` 文件的第二部分代码，主要负责使用 HarfBuzz 库对文本进行整形（shaping），这是将字符转换成字形（glyphs）并确定它们在屏幕上位置的关键过程。

**功能归纳:**

这部分代码的核心功能是定义了 `HarfBuzzShaper` 类中的 `ShapeSegment` 方法以及多个 `Shape` 方法的重载，这些方法共同实现了使用 HarfBuzz 库对文本段落进行整形的功能。 具体来说，它完成了以下任务：

1. **处理 OpenType 字体特性 (OpenType Features):**  `CapsFeatureSettingsScopedOverlay` 类及其相关逻辑用于管理与大写字母相关的 OpenType 特性，例如小型大写字母 (small caps)、Petite Caps、Unicase 和 Titling Caps。它根据 `FontDescription` 中指定的 `variant_caps` 来启用或禁用相应的字体特性。

2. **字体回退 (Font Fallback):**  `ShapeSegment` 方法使用了 `FontFallbackIterator` 来处理当当前字体不包含所有需要渲染的字符时的情况。它会尝试从回退字体列表中查找合适的字形。

3. **分段整形 (Segment Shaping):** `ShapeSegment` 函数是执行实际整形操作的核心。它接收一个文本段落 (`segment`)，并使用 HarfBuzz 库将其转换为字形序列。

4. **处理大小写 (Case Handling):**  代码考虑了字体描述中的大小写变体 (`variant_caps`)，并使用 `OpenTypeCapsSupport` 来判断是否需要进行大小写转换或应用合成字体（例如，合成小型大写字母）。

5. **HarfBuzz Buffer 的管理:** 代码使用 `hb_buffer_t` 来存储需要整形的文本，并设置其语言、脚本和方向等属性。

6. **应用 OpenType 特性:**  在调用 HarfBuzz 的整形函数之前，代码会将根据字体描述和大小写设置选择的 OpenType 特性应用到 HarfBuzz buffer 中。

7. **处理 Canvas 旋转:** 代码考虑了文本在垂直书写模式下的旋转 (`CanvasRotationInVertical`)。

8. **汉字避头尾 (Han Kerning):**  代码包含处理汉字避头尾距的逻辑 (`HanKerning`)，这是一种调整汉字字符间距以改善排版美观性的技术。

9. **提取整形结果 (Extract Shape Results):**  整形完成后，`ExtractShapeResults` 函数会将 HarfBuzz buffer 中的字形信息提取到 `ShapeResult` 对象中。

10. **处理 Emoji:**  代码还包含了对 Emoji 表情的特殊处理，包括检查 Emoji 是否正确渲染。

11. **提供多种整形入口:**  `Shape` 方法提供了多种重载，允许调用者以不同的方式指定要整形的文本范围和选项。

12. **获取字形数据 (GetGlyphData):** `GetGlyphData` 方法允许获取指定字体和文本的字形数据，这对于某些底层的渲染操作很有用。

**与 JavaScript, HTML, CSS 的关系:**

这些 C++ 代码是 Blink 渲染引擎的一部分，直接影响着网页上文本的显示效果。

* **CSS:**
    * **`font-family`:**  CSS 的 `font-family` 属性决定了使用的字体。如果指定的字体不包含某些字符，字体回退机制就会被触发，`ShapeSegment` 中的 `FontFallbackIterator` 会发挥作用。
    * **`font-variant-caps`:** CSS 的 `font-variant-caps` 属性（例如 `small-caps`, `all-small-caps`, `petite-caps`, `all-petite-caps`, `unicase`, `titling-caps`）直接对应了 `FontDescription::FontVariantCaps` 枚举，并控制着 `CapsFeatureSettingsScopedOverlay` 中应用的 OpenType 特性。
        * **例子:** 当 CSS 中设置了 `font-variant-caps: small-caps;` 时，`sScopedOverlay::OverlayCapsFeatures` 函数会将 `smcp` 特性添加到 HarfBuzz buffer 中，指示 HarfBuzz 使用小型大写字母的字形（如果字体支持）。
    * **`font-style: italic` 和 `font-weight: bold`:** 虽然这部分代码没有直接展示，但 Blink 引擎会根据这些 CSS 属性选择不同的字体变体，而 `HarfBuzzShaper` 会处理这些变体的整形。
    * **`text-orientation: upright` 和 `writing-mode: vertical-lr/rl`:** 这些 CSS 属性影响文本的渲染方向。`ShapeSegment` 中会根据这些属性以及字体本身的特性来确定 HarfBuzz 的排版方向 (`hb_direction_t`)。
    * **`unicode-range`:**  CSS 的 `@font-face` 规则中的 `unicode-range` 描述了字体支持的 Unicode 范围，这会影响字体回退的选择。

* **HTML:** HTML 提供了文本内容，这些内容最终会被传递给 `HarfBuzzShaper` 进行整形。

* **JavaScript:** JavaScript 可以动态地修改 HTML 内容和 CSS 样式，从而间接地影响 `HarfBuzzShaper` 的行为。例如：
    * **动态修改文本内容:**  通过 JavaScript 改变页面上的文本，会导致浏览器重新进行布局和渲染，包括调用 `HarfBuzzShaper` 对新的文本进行整形。
    * **动态修改 CSS 样式:**  JavaScript 可以修改元素的 `style` 属性或添加/移除 CSS 类，从而改变字体相关的 CSS 属性，进而影响 `HarfBuzzShaper` 的行为。

**逻辑推理示例:**

**假设输入:**

* **文本:** "Example Text"
* **字体:**  一个支持小型大写字母的 OpenType 字体 "MyFont"
* **CSS:**  `font-family: "MyFont"; font-variant-caps: small-caps;`

**输出:**

1. `sScopedOverlay::OverlayCapsFeatures` 会根据 `font-variant-caps: small-caps;` 的设置，将 `smcp` 特性添加到 HarfBuzz buffer 中。
2. `HarfBuzzShaper::ShapeSegment` 在使用 HarfBuzz 进行整形时，会考虑 `smcp` 特性。
3. 最终渲染结果中，"EXAMPLE TEXT" 这部分字符会使用 "MyFont" 字体中的小型大写字母字形进行显示。

**用户或编程常见的使用错误示例:**

1. **用户错误:**
    * **指定的字体不包含所需的字形:**  如果 CSS 中指定的字体没有某个字符的字形，并且没有合适的字体回退，那么该字符可能显示为方框或其他替代符号。
    * **`font-variant-caps` 设置不当:**  用户可能错误地设置了 `font-variant-caps`，导致文本没有按照预期的方式显示（例如，期望显示小型大写字母但没有设置该属性）。

2. **编程错误:**
    * **Blink 引擎内部错误:** 虽然用户不太可能直接遇到，但 Blink 引擎的开发者可能会在处理字体回退或 OpenType 特性时出现逻辑错误，导致整形结果不正确。
    * **HarfBuzzShaper 的调用者传递了错误的参数:** 例如，传递了错误的文本范围或字体信息。

**总结:**

这段代码是 Chromium Blink 引擎中负责文本整形的关键部分，它利用 HarfBuzz 库将字符转换为可渲染的字形，并考虑了复杂的字体特性、字体回退、大小写处理和排版规则。它的正确运行对于在网页上准确且美观地显示文本至关重要，并且直接受到 HTML 结构和 CSS 样式的控制，也可能受到 JavaScript 动态修改的影响。

Prompt: 
```
这是目录为blink/renderer/platform/fonts/shaping/harfbuzz_shaper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
sScopedOverlay::OverlayCapsFeatures(
    FontDescription::FontVariantCaps variant_caps) {
  static constexpr hb_feature_t smcp = CreateFeature('s', 'm', 'c', 'p', 1);
  static constexpr hb_feature_t pcap = CreateFeature('p', 'c', 'a', 'p', 1);
  static constexpr hb_feature_t c2sc = CreateFeature('c', '2', 's', 'c', 1);
  static constexpr hb_feature_t c2pc = CreateFeature('c', '2', 'p', 'c', 1);
  static constexpr hb_feature_t unic = CreateFeature('u', 'n', 'i', 'c', 1);
  static constexpr hb_feature_t titl = CreateFeature('t', 'i', 't', 'l', 1);
  if (variant_caps == FontDescription::kSmallCaps ||
      variant_caps == FontDescription::kAllSmallCaps) {
    PrependCounting(smcp);
    if (variant_caps == FontDescription::kAllSmallCaps) {
      PrependCounting(c2sc);
    }
  }
  if (variant_caps == FontDescription::kPetiteCaps ||
      variant_caps == FontDescription::kAllPetiteCaps) {
    PrependCounting(pcap);
    if (variant_caps == FontDescription::kAllPetiteCaps) {
      PrependCounting(c2pc);
    }
  }
  if (variant_caps == FontDescription::kUnicase) {
    PrependCounting(unic);
  }
  if (variant_caps == FontDescription::kTitlingCaps) {
    PrependCounting(titl);
  }
}

void CapsFeatureSettingsScopedOverlay::PrependCounting(
    const hb_feature_t& feature) {
  features_->Insert(feature);
  count_features_++;
}

CapsFeatureSettingsScopedOverlay::~CapsFeatureSettingsScopedOverlay() {
  features_->EraseAt(0, count_features_);
}

}  // namespace

void HarfBuzzShaper::ShapeSegment(
    RangeContext* range_data,
    const RunSegmenter::RunSegmenterRange& segment,
    ShapeResult* result) const {
  DCHECK(result);
  DCHECK(range_data->buffer);
  const Font* font = range_data->font;
  const FontDescription& font_description = font->GetFontDescription();
  const LayoutLocale& locale = font_description.LocaleOrDefault();
  const hb_language_t language = locale.HarfbuzzLanguage();
  bool needs_caps_handling =
      font_description.VariantCaps() != FontDescription::kCapsNormal;
  OpenTypeCapsSupport caps_support;

  FontFallbackIterator fallback_iterator(
      font->CreateFontFallbackIterator(ApplyFontVariantEmojiOnFallbackPriority(
          segment.font_fallback_priority, font_description.VariantEmoji())));

  range_data->reshape_queue.push_back(
      ReshapeQueueItem(kReshapeQueueNextFont, 0, 0));
  range_data->reshape_queue.push_back(ReshapeQueueItem(
      kReshapeQueueRange, segment.start, segment.end - segment.start));

  bool font_cycle_queued = false;
  HintCharList fallback_chars_hint;
  // Reserve sufficient capacity to avoid multiple reallocations, only when a
  // full hint list is needed.
  if (fallback_iterator.NeedsHintList()) {
    fallback_chars_hint.ReserveInitialCapacity(range_data->end -
                                               range_data->start);
  }
  FontDataForRangeSet* current_font_data_for_range_set = nullptr;
  FallbackFontStage fallback_stage = kIntermediate;
  // Variation selector mode should be always set to default at the
  // beginning of the segment shaping run.
  DCHECK(HarfBuzzFace::GetVariationSelectorMode() ==
         kUseSpecifiedVariationSelector);
  if (RuntimeEnabledFeatures::FontVariantEmojiEnabled() &&
      font_description.VariantEmoji() != kNormalVariantEmoji) {
    HarfBuzzFace::SetVariationSelectorMode(
        GetVariationSelectorModeFromFontVariantEmoji(
            font_description.VariantEmoji()));
  }
  while (!range_data->reshape_queue.empty()) {
    ReshapeQueueItem current_queue_item = range_data->reshape_queue.TakeFirst();

    if (current_queue_item.action_ != kReshapeQueueRange) {
      if (current_queue_item.action_ == kReshapeQueueReset) {
        // We reached last font in the list, some of the variation sequences
        // are not shaped yet and there is a fonts in the list that has glyphs
        // for the base codepoint of unshaped variation sequences, so we need to
        // restart the fallback queue and set the variation selector mode to
        // `kIgnoreVariationSelector`.
        DCHECK(RuntimeEnabledFeatures::FontVariationSequencesEnabled());
        DCHECK_EQ(fallback_stage, kLastWithVS);
        fallback_iterator.Reset();
        fallback_stage = kIntermediateIgnoreVS;
        HarfBuzzFace::SetVariationSelectorMode(kIgnoreVariationSelector);
      }

      if (!CollectFallbackHintChars(range_data->reshape_queue,
                                    fallback_iterator.NeedsHintList(),
                                    fallback_chars_hint)) {
        // Give up shaping since we cannot retrieve a font fallback
        // font without a hintlist.
        range_data->reshape_queue.clear();
        break;
      }

      current_font_data_for_range_set =
          fallback_iterator.Next(fallback_chars_hint);
      if (!current_font_data_for_range_set->FontData()) {
        DCHECK(range_data->reshape_queue.empty());
        break;
      }
      font_cycle_queued = false;
      continue;
    }

    if (!fallback_iterator.HasNext()) {
      fallback_stage = ChangeStageToLast(fallback_stage);
    }

    const SimpleFontData* font_data =
        current_font_data_for_range_set->FontData();
    SmallCapsIterator::SmallCapsBehavior small_caps_behavior =
        SmallCapsIterator::kSmallCapsSameCase;
    if (needs_caps_handling) {
      caps_support =
          OpenTypeCapsSupport(font_data->PlatformData().GetHarfBuzzFace(),
                              font_description.VariantCaps(),
                              font_description.GetFontSynthesisSmallCaps(),
                              ICUScriptToHBScript(segment.script));
      if (caps_support.NeedsRunCaseSplitting()) {
        SplitUntilNextCaseChange(text_, &range_data->reshape_queue,
                                 current_queue_item, small_caps_behavior);
        // Skip queue items generated by SplitUntilNextCaseChange that do not
        // contribute to the shape result if the range_data restricts shaping to
        // a substring.
        if (range_data->start >= current_queue_item.start_index_ +
                                     current_queue_item.num_characters_ ||
            range_data->end <= current_queue_item.start_index_) {
          continue;
        }
      }
    }

    DCHECK(current_queue_item.num_characters_);
    const SimpleFontData* adjusted_font = font_data;

    // Clamp the start and end offsets of the queue item to the offsets
    // representing the shaping window.
    const unsigned shape_start =
        std::max(range_data->start, current_queue_item.start_index_);
    const unsigned shape_end =
        std::min(range_data->end, current_queue_item.start_index_ +
                                      current_queue_item.num_characters_);
    DCHECK_GT(shape_end, shape_start);
    CheckTextEnd(shape_start, shape_end);

    CaseMapIntend case_map_intend = CaseMapIntend::kKeepSameCase;
    if (needs_caps_handling) {
      case_map_intend = caps_support.NeedsCaseChange(small_caps_behavior);
      if (caps_support.NeedsSyntheticFont(small_caps_behavior)) {
        adjusted_font = font_data->SmallCapsFontData(font_description);
      }
    }

    CaseMappingHarfBuzzBufferFiller(
        case_map_intend, font_description.LocaleOrDefault(), range_data->buffer,
        text_, shape_start, shape_end - shape_start);

    CanvasRotationInVertical canvas_rotation =
        CanvasRotationForRun(adjusted_font->PlatformData().Orientation(),
                             segment.render_orientation, font_description);

    CapsFeatureSettingsScopedOverlay caps_overlay(
        &range_data->font_features,
        caps_support.FontFeatureToUse(small_caps_behavior));
    hb_direction_t direction = range_data->HarfBuzzDirection(canvas_rotation);
    HanKerning han_kerning(
        text_, shape_start, shape_end, *adjusted_font, font_description,
        {.is_horizontal = HB_DIRECTION_IS_HORIZONTAL(direction),
         .is_line_start = range_data->options.is_line_start &&
                          range_data->start == shape_start,
         .apply_start = range_data->options.han_kerning_start &&
                        range_data->start == shape_start,
         .apply_end = range_data->options.han_kerning_end &&
                      range_data->end == shape_end},
        &range_data->font_features);

    if (!ShapeRange(range_data->buffer, range_data->font_features,
                    adjusted_font, current_font_data_for_range_set->Ranges(),
                    segment.script, direction, language,
                    font_description.SpecifiedSize())) {
      DLOG(ERROR) << "Shaping range failed.";
    }

    ExtractShapeResults(range_data, font_cycle_queued, current_queue_item,
                        adjusted_font, segment.script, canvas_rotation,
                        fallback_stage, result);

    if (!han_kerning.UnsafeToBreakBefore().empty()) [[unlikely]] {
      result->AddUnsafeToBreak(han_kerning.UnsafeToBreakBefore());
    }

    hb_buffer_reset(range_data->buffer);
  }

  // Ignore variation selectors flag should be only changed when the
  // FontVariationSequences runtime flag is enabled.
  DCHECK(
      RuntimeEnabledFeatures::FontVariationSequencesEnabled() ||
      !ShouldIgnoreVariationSelector(HarfBuzzFace::GetVariationSelectorMode()));

  if (RuntimeEnabledFeatures::FontVariationSequencesEnabled()) {
    // Set variation selector mode to the default state.
    HarfBuzzFace::SetVariationSelectorMode(kUseSpecifiedVariationSelector);
  }

  if (IsEmojiPresentationEmoji(segment.font_fallback_priority)) {
    EmojiCorrectness emoji_correctness =
        ComputeBrokenEmojiPercentage(result, segment.start, segment.end);
    if (emoji_metrics_reporter_for_testing_) {
      emoji_metrics_reporter_for_testing_.Run(
          emoji_correctness.num_clusters,
          emoji_correctness.num_broken_clusters);
    } else {
      range_data->font->ReportEmojiSegmentGlyphCoverage(
          emoji_correctness.num_clusters,
          emoji_correctness.num_broken_clusters);
    }
  }
}

ShapeResult* HarfBuzzShaper::Shape(const Font* font,
                                   TextDirection direction,
                                   unsigned start,
                                   unsigned end) const {
  DCHECK_GE(end, start);
  DCHECK_LE(end, text_.length());

  const unsigned length = end - start;
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(font, start, length, direction);
  RangeContext range_data(font, direction, start, end);
  if (text_.Is8Bit()) {
    // 8-bit text is guaranteed to be horizontal latin-1.
    RunSegmenter::RunSegmenterRange segment_range = {
        start, end, USCRIPT_LATIN, OrientationIterator::kOrientationKeep,
        FontFallbackPriority::kText};
    ShapeSegment(&range_data, segment_range, result);

  } else {
    // Run segmentation needs to operate on the entire string, regardless of the
    // shaping window (defined by the start and end parameters).
    DCHECK(!text_.Is8Bit());
    RunSegmenter run_segmenter(text_.Span16(),
                               font->GetFontDescription().Orientation());
    RunSegmenter::RunSegmenterRange segment_range;
    while (run_segmenter.Consume(&segment_range)) {
      // Only shape segments overlapping with the range indicated by start and
      // end. Not only those strictly within.
      if (start < segment_range.end && end > segment_range.start) {
        ShapeSegment(&range_data, segment_range, result);
      }

      // Break if beyond the requested range. Because RunSegmenter is
      // incremental, further ranges are not needed. This also allows reusing
      // the segmenter state for next incremental calls.
      if (segment_range.end >= end) {
        break;
      }
    }
  }

#if EXPENSIVE_DCHECKS_ARE_ON()
  CheckShapeResultRange(result, start, end, text_, font);
#endif
  return result;
}

ShapeResult* HarfBuzzShaper::Shape(
    const Font* font,
    TextDirection direction,
    unsigned start,
    unsigned end,
    const Vector<RunSegmenter::RunSegmenterRange>& ranges,
    ShapeOptions options) const {
  DCHECK_GE(end, start);
  DCHECK_LE(end, text_.length());
  DCHECK_GT(ranges.size(), 0u);
  DCHECK_EQ(start, ranges[0].start);
  DCHECK_EQ(end, ranges[ranges.size() - 1].end);

  const unsigned length = end - start;
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(font, start, length, direction);
  RangeContext range_data(font, direction, start, end, options);
  for (const RunSegmenter::RunSegmenterRange& segmented_range : ranges) {
    DCHECK_GE(segmented_range.end, segmented_range.start);
    DCHECK_GE(segmented_range.start, start);
    DCHECK_LE(segmented_range.end, end);
    ShapeSegment(&range_data, segmented_range, result);
  }

#if EXPENSIVE_DCHECKS_ARE_ON()
  CheckShapeResultRange(result, start, end, text_, font);
#endif
  return result;
}

ShapeResult* HarfBuzzShaper::Shape(
    const Font* font,
    TextDirection direction,
    unsigned start,
    unsigned end,
    const RunSegmenter::RunSegmenterRange pre_segmented,
    ShapeOptions options) const {
  DCHECK_GE(end, start);
  DCHECK_LE(end, text_.length());
  DCHECK_GE(start, pre_segmented.start);
  DCHECK_LE(end, pre_segmented.end);

  const unsigned length = end - start;
  ShapeResult* result =
      MakeGarbageCollected<ShapeResult>(font, start, length, direction);
  RangeContext range_data(font, direction, start, end, options);
  ShapeSegment(&range_data, pre_segmented, result);

#if EXPENSIVE_DCHECKS_ARE_ON()
  CheckShapeResultRange(result, start, end, text_, font);
#endif
  return result;
}

ShapeResult* HarfBuzzShaper::Shape(const Font* font,
                                   TextDirection direction) const {
  return Shape(font, direction, 0, text_.length());
}

void HarfBuzzShaper::GetGlyphData(const SimpleFontData& font_data,
                                  const LayoutLocale& locale,
                                  UScriptCode script,
                                  bool is_horizontal,
                                  GlyphDataList& glyphs) {
  hb::unique_ptr<hb_buffer_t> hb_buffer(hb_buffer_create());
  hb_buffer_set_language(hb_buffer, locale.HarfbuzzLanguage());
  hb_buffer_set_script(hb_buffer, ICUScriptToHBScript(script));
  hb_buffer_set_direction(hb_buffer,
                          is_horizontal ? HB_DIRECTION_LTR : HB_DIRECTION_TTB);
  CHECK(!text_.Is8Bit());
  static_assert(sizeof(uint16_t) == sizeof(UChar));
  hb_buffer_add_utf16(hb_buffer,
                      reinterpret_cast<const uint16_t*>(text_.Characters16()),
                      text_.length(), 0, text_.length());

  const FontPlatformData& platform_data = font_data.PlatformData();
  HarfBuzzFace* const hb_face = platform_data.GetHarfBuzzFace();
  DCHECK(hb_face);
  hb_font_t* const hb_font = hb_face->GetScaledFont(
      nullptr,
      is_horizontal ? HarfBuzzFace::kNoVerticalLayout
                    : HarfBuzzFace::kPrepareForVerticalLayout,
      platform_data.size());
  DCHECK(hb_font);
  hb_shape(hb_font, hb_buffer, nullptr, 0);

  // Create `GlyphDataList` from `hb_buffer`.
  unsigned num_glyphs;
  hb_glyph_info_t* glyph_info =
      hb_buffer_get_glyph_infos(hb_buffer, &num_glyphs);
  hb_glyph_position_t* glyph_position =
      hb_buffer_get_glyph_positions(hb_buffer, nullptr);
  glyphs.reserve(num_glyphs);
  for (; num_glyphs; --num_glyphs, ++glyph_info, ++glyph_position) {
    glyphs.push_back(GlyphData{
        .cluster = glyph_info->cluster,
        .glyph = static_cast<Glyph>(glyph_info->codepoint),
        .advance = {HarfBuzzPositionToFloat(glyph_position->x_advance),
                    -HarfBuzzPositionToFloat(glyph_position->y_advance)},
        .offset = {HarfBuzzPositionToFloat(glyph_position->x_offset),
                   -HarfBuzzPositionToFloat(glyph_position->y_offset)}});
  }
}

}  // namespace blink

"""


```