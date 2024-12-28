Response:
The user wants to understand the functionality of the `computed_style.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and:

1. **List the functionalities:** Identify the key actions and calculations performed within the code.
2. **Relate to web technologies (JavaScript, HTML, CSS):**  Explain how the code interacts with these technologies, providing examples.
3. **Logical Reasoning (Input/Output):**  For functions that perform calculations or transformations, provide example inputs and their expected outputs.
4. **Common User/Programming Errors:**  Highlight potential mistakes users or developers might make related to the functionalities.
5. **Summarize the functionality:**  Provide a concise overview of the code's purpose, as this is part 3 of a 4-part analysis.

**Breakdown of the Code Snippet:**

The provided code snippet focuses on various aspects of computed style in Blink:

* **Offset Path:** Calculating the position and rotation of an element based on a defined path (either a basic shape or an SVG path). This relates to CSS `offset-path`, `offset-position`, and `offset-rotate` properties.
* **Border Image:** Checking if a border image can be rendered. This relates to the CSS `border-image` property.
* **Counters:**  Managing CSS counters, which are used for numbering elements. This relates to CSS `counter-reset`, `counter-increment`, and `content` with `counter()` or `counters()`.
* **Hyphenation:** Handling automatic hyphenation of text. This relates to the CSS `hyphens` property.
* **Text Alignment:** Determining the effective text alignment, including the `text-align-last` property.
* **Text Transformation:** Applying transformations like `uppercase`, `lowercase`, and `capitalize`. This relates to the CSS `text-transform` property.
* **Text Emphasis:**  Handling text emphasis marks. This relates to the CSS `text-emphasis` properties.
* **Font Baselines and Heights:**  Calculating font metrics.
* **Text Decoration:**  Managing and applying text decorations like underlines and strikethroughs. This relates to the CSS `text-decoration` properties.
* **CSS Variables:**  Handling custom CSS properties (variables). This relates to CSS custom properties (`--*`).
* **Scrollbars:** Determining the styling of scrollbars, including custom scrollbar styling. This relates to CSS pseudo-elements like `::-webkit-scrollbar` and standard scrollbar properties.
* **Line Height:** Calculating the computed line height. This relates to the CSS `line-height` property.
* **Decoration Color:** Determining the color of text decorations.
* **Background:** Checking if an element has a visible background. This relates to the CSS `background-color` and `background-image` properties.
* **Visited Link Styles:**  Handling styles for visited links. This relates to the `:visited` pseudo-class.
* **Column Rules:**  Checking for equality of column rule styles. This relates to the CSS `column-rule` properties.
* **Image Outsets:** Calculating the outsets of border images.
* **Border Obscurity:** Determining if borders completely hide the background.
* **Box Decoration Outsets:** Calculating the total visual outsets of a box (including shadows, borders, etc.).
* **Border Edges:**  Extracting information about the individual borders.
* **Current Color:** Resolving the value of the `currentColor` keyword.
* **List Style Markers:** Determining if a list marker should be inside or outside the list item. This relates to the CSS `list-style-position` property.
```cpp
ightRadius());
      inset->SetBottomRightRadius(style.BorderBottomRightRadius());
      inset->SetBottomLeftRadius(style.BorderBottomLeftRadius());
      const gfx::RectF reference_box = GetReferenceBox(box, coord_box);
      const gfx::PointF offset_from_reference_box =
          GetOffsetFromContainingBlock(box) - reference_box.OffsetFromOrigin();
      const gfx::SizeF& reference_box_size = reference_box.size();
      const gfx::PointF starting_point = GetStartingPointOfThePath(
          offset_from_reference_box, position, reference_box_size);
      path_position = CalculatePointAndTangentOnBasicShape(
          *inset, starting_point, reference_box_size);
      // `path_position.point` is now relative to the containing block.
      // Make it relative to the box.
      path_position.point -= offset_from_reference_box.OffsetFromOrigin();
    }
  } else {
    const auto* url_operation =
        DynamicTo<ReferenceOffsetPathOperation>(offset_path);
    if (!url_operation->Resource()) {
      return;
    }
    const auto* target =
        DynamicTo<SVGGeometryElement>(url_operation->Resource()->Target());
    Path path;
    if (!target || !target->GetComputedStyle()) {
      // Failure to find a shape should be equivalent to a "m0,0" path.
      path.MoveTo({0, 0});
    } else {
      path = target->AsPath();
    }
    path_position = CalculatePointAndTangentOnPath(path);
  }

  if (rotate.type == OffsetRotationType::kFixed) {
    path_position.tangent_in_degrees = 0;
  }

  transform.Translate(path_position.point.x() - origin_x,
                      path_position.point.y() - origin_y);
  transform.Rotate(path_position.tangent_in_degrees + rotate.angle);

  const LengthPoint& anchor = OffsetAnchor();
  if (!anchor.X().IsAuto()) {
    gfx::PointF anchor_point = PointForLengthPoint(anchor, bounding_box.size());
    anchor_point += bounding_box.OffsetFromOrigin();

    // Shift the origin back to transform-origin and then move it based on the
    // anchor.
    transform.Translate(origin_x - anchor_point.x(),
                        origin_y - anchor_point.y());
  }
}

bool ComputedStyle::CanRenderBorderImage() const {
  const StyleImage* border_image = BorderImage().GetImage();
  return border_image && border_image->CanRender() && border_image->IsLoaded();
}

const CounterDirectiveMap* ComputedStyle::GetCounterDirectives() const {
  return CounterDirectivesInternal().get();
}

const CounterDirectives ComputedStyle::GetCounterDirectives(
    const AtomicString& identifier) const {
  if (GetCounterDirectives()) {
    auto it = GetCounterDirectives()->find(identifier);
    if (it != GetCounterDirectives()->end()) {
      return it->value;
    }
  }
  return CounterDirectives();
}

Hyphenation* ComputedStyle::GetHyphenation() const {
  if (GetHyphens() != Hyphens::kAuto) {
    return nullptr;
  }
  if (const LayoutLocale* locale = GetFontDescription().Locale()) {
    return locale->GetHyphenation();
  }
  return nullptr;
}

Hyphenation* ComputedStyle::GetHyphenationWithLimits() const {
  if (Hyphenation* hyphenation = GetHyphenation()) {
    const StyleHyphenateLimitChars& limits = HyphenateLimitChars();
    hyphenation->SetLimits(limits.MinBeforeChars(), limits.MinAfterChars(),
                           limits.MinWordChars());
    return hyphenation;
  }
  return nullptr;
}

const AtomicString& ComputedStyle::HyphenString() const {
  const AtomicString& hyphenation_string = HyphenationString();
  if (!hyphenation_string.IsNull()) {
    return hyphenation_string;
  }

  // FIXME: This should depend on locale.
  DEFINE_STATIC_LOCAL(AtomicString, hyphen_minus_string,
                      (base::span_from_ref(kHyphenMinusCharacter)));
  DEFINE_STATIC_LOCAL(AtomicString, hyphen_string,
                      (base::span_from_ref(kHyphenCharacter)));
  const SimpleFontData* primary_font = GetFont().PrimaryFont();
  DCHECK(primary_font);
  return primary_font && primary_font->GlyphForCharacter(kHyphenCharacter)
             ? hyphen_string
             : hyphen_minus_string;
}

ETextAlign ComputedStyle::GetTextAlign(bool is_last_line) const {
  if (!is_last_line) {
    return GetTextAlign();
  }

  // When this is the last line of a block, or the line ends with a forced line
  // break.
  // https://drafts.csswg.org/css-text-3/#propdef-text-align-last
  switch (TextAlignLast()) {
    case ETextAlignLast::kStart:
      return ETextAlign::kStart;
    case ETextAlignLast::kEnd:
      return ETextAlign::kEnd;
    case ETextAlignLast::kLeft:
      return ETextAlign::kLeft;
    case ETextAlignLast::kRight:
      return ETextAlign::kRight;
    case ETextAlignLast::kCenter:
      return ETextAlign::kCenter;
    case ETextAlignLast::kJustify:
      return ETextAlign::kJustify;
    case ETextAlignLast::kAuto:
      ETextAlign text_align = GetTextAlign();
      if (text_align == ETextAlign::kJustify) {
        return ETextAlign::kStart;
      }
      return text_align;
  }
  NOTREACHED();
}

// Unicode 11 introduced Georgian capital letters (U+1C90 - U+1CBA,
// U+1CB[D-F]), but virtually no font covers them. For now map them back
// to their lowercase counterparts (U+10D0 - U+10FA, U+10F[D-F]).
// https://www.unicode.org/charts/PDF/U10A0.pdf
// https://www.unicode.org/charts/PDF/U1C90.pdf
// See https://crbug.com/865427 .
// TODO(jshin): Make this platform-dependent. For instance, turn this
// off when CrOS gets new Georgian fonts covering capital letters.
// ( https://crbug.com/880144 ).
static String DisableNewGeorgianCapitalLetters(const String& text) {
  if (text.IsNull() || text.Is8Bit()) {
    return text;
  }
  unsigned length = text.length();
  const StringImpl& input = *(text.Impl());
  StringBuilder result;
  result.ReserveCapacity(length);
  // |input| must be well-formed UTF-16 so that there's no worry
  // about surrogate handling.
  for (unsigned i = 0; i < length; ++i) {
    UChar character = input[i];
    if (Character::IsModernGeorgianUppercase(character)) {
      result.Append(Character::LowercaseModernGeorgianUppercase(character));
    } else {
      result.Append(character);
    }
  }
  return result.ToString();
}

namespace {

String ApplyMathAutoTransform(const String& text, TextOffsetMap* offset_map) {
  if (text.length() != 1) {
    return text;
  }
  UChar character = text[0];
  UChar32 transformed_char = ItalicMathVariant(text[0]);
  if (transformed_char == static_cast<UChar32>(character)) {
    return text;
  }

  Vector<UChar> transformed_text(U16_LENGTH(transformed_char));
  int i = 0;
  U16_APPEND_UNSAFE(transformed_text, i, transformed_char);
  String transformed_string = String(transformed_text);
  if (offset_map) {
    offset_map->Append(text.length(), transformed_string.length());
  }
  return transformed_string;
}

}  // namespace

String ComputedStyle::ApplyTextTransform(const String& text,
                                         UChar previous_character,
                                         TextOffsetMap* offset_map) const {
  switch (TextTransform()) {
    case ETextTransform::kNone:
      return text;
    case ETextTransform::kCapitalize:
      return Capitalize(text, previous_character);
    case ETextTransform::kUppercase: {
      const LayoutLocale* locale = GetFontDescription().Locale();
      CaseMap case_map(locale ? locale->CaseMapLocale() : CaseMap::Locale());
      return DisableNewGeorgianCapitalLetters(
          case_map.ToUpper(text, offset_map));
    }
    case ETextTransform::kLowercase: {
      const LayoutLocale* locale = GetFontDescription().Locale();
      CaseMap case_map(locale ? locale->CaseMapLocale() : CaseMap::Locale());
      return case_map.ToLower(text, offset_map);
    }
    case ETextTransform::kMathAuto:
      return ApplyMathAutoTransform(text, offset_map);
  }
  NOTREACHED();
}

const AtomicString& ComputedStyle::TextEmphasisMarkString() const {
  switch (GetTextEmphasisMark()) {
    case TextEmphasisMark::kNone:
      return g_null_atom;
    case TextEmphasisMark::kCustom:
      return TextEmphasisCustomMark();
    case TextEmphasisMark::kDot: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_dot_string,
                          (base::span_from_ref(kBulletCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_dot_string,
                          (base::span_from_ref(kWhiteBulletCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_dot_string
                 : open_dot_string;
    }
    case TextEmphasisMark::kCircle: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_circle_string,
                          (base::span_from_ref(kBlackCircleCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_circle_string,
                          (base::span_from_ref(kWhiteCircleCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_circle_string
                 : open_circle_string;
    }
    case TextEmphasisMark::kDoubleCircle: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_double_circle_string,
                          (base::span_from_ref(kFisheyeCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_double_circle_string,
                          (base::span_from_ref(kBullseyeCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_double_circle_string
                 : open_double_circle_string;
    }
    case TextEmphasisMark::kTriangle: {
      DEFINE_STATIC_LOCAL(
          AtomicString, filled_triangle_string,
          (base::span_from_ref(kBlackUpPointingTriangleCharacter)));
      DEFINE_STATIC_LOCAL(
          AtomicString, open_triangle_string,
          (base::span_from_ref(kWhiteUpPointingTriangleCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_triangle_string
                 : open_triangle_string;
    }
    case TextEmphasisMark::kSesame: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_sesame_string,
                          (base::span_from_ref(kSesameDotCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_sesame_string,
                          (base::span_from_ref(kWhiteSesameDotCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_sesame_string
                 : open_sesame_string;
    }
    case TextEmphasisMark::kAuto:
      NOTREACHED();
  }

  NOTREACHED();
}

LineLogicalSide ComputedStyle::GetTextEmphasisLineLogicalSide() const {
  TextEmphasisPosition position = GetTextEmphasisPosition();
  if (IsHorizontalWritingMode()) {
    return IsOver(position) ? LineLogicalSide::kOver : LineLogicalSide::kUnder;
  }
  if (GetWritingMode() != WritingMode::kSidewaysLr) {
    return IsRight(position) ? LineLogicalSide::kOver : LineLogicalSide::kUnder;
  }
  return IsLeft(position) ? LineLogicalSide::kOver : LineLogicalSide::kUnder;
}

FontBaseline ComputedStyle::GetFontBaseline() const {
  // CssDominantBaseline() always returns kAuto for non-SVG elements,
  // and never returns kUseScript, kNoChange, and kResetSize.
  // See StyleAdjuster::AdjustComputedStyle().
  switch (CssDominantBaseline()) {
    case EDominantBaseline::kAuto:
      break;
    case EDominantBaseline::kMiddle:
      return kXMiddleBaseline;
    case EDominantBaseline::kAlphabetic:
      return kAlphabeticBaseline;
    case EDominantBaseline::kHanging:
      return kHangingBaseline;
    case EDominantBaseline::kCentral:
      return kCentralBaseline;
    case EDominantBaseline::kTextBeforeEdge:
      return kTextOverBaseline;
    case EDominantBaseline::kTextAfterEdge:
      return kTextUnderBaseline;
    case EDominantBaseline::kIdeographic:
      return kIdeographicUnderBaseline;
    case EDominantBaseline::kMathematical:
      return kMathBaseline;

    case EDominantBaseline::kUseScript:
    case EDominantBaseline::kNoChange:
    case EDominantBaseline::kResetSize:
      NOTREACHED();
  }

  // Vertical flow (except 'text-orientation: sideways') uses ideographic
  // central baseline.
  // https://drafts.csswg.org/css-writing-modes-3/#text-baselines
  return !GetFontDescription().IsVerticalAnyUpright() ? kAlphabeticBaseline
                                                      : kCentralBaseline;
}

FontHeight ComputedStyle::GetFontHeight(FontBaseline baseline) const {
  if (const SimpleFontData* font_data = GetFont().PrimaryFont()) {
    return font_data->GetFontMetrics().GetFontHeight(baseline);
  }
  return FontHeight();
}

bool ComputedStyle::TextDecorationVisualOverflowChanged(
    const ComputedStyle& o) const {
  const Vector<AppliedTextDecoration, 1>& applied_with_this =
      AppliedTextDecorations();
  const Vector<AppliedTextDecoration, 1>& applied_with_other =
      o.AppliedTextDecorations();
  if (applied_with_this.size() != applied_with_other.size()) {
    return true;
  }
  for (auto decoration_index = 0u; decoration_index < applied_with_this.size();
       ++decoration_index) {
    const AppliedTextDecoration& decoration_from_this =
        applied_with_this[decoration_index];
    const AppliedTextDecoration& decoration_from_other =
        applied_with_other[decoration_index];
    if (decoration_from_this.Thickness() != decoration_from_other.Thickness() ||
        decoration_from_this.UnderlineOffset() !=
            decoration_from_other.UnderlineOffset() ||
        decoration_from_this.Style() != decoration_from_other.Style() ||
        decoration_from_this.Lines() != decoration_from_other.Lines()) {
      return true;
    }
  }
  if (GetTextUnderlinePosition() != o.GetTextUnderlinePosition()) {
    return true;
  }

  return false;
}

TextDecorationLine ComputedStyle::TextDecorationsInEffect() const {
  TextDecorationLine decorations = GetTextDecorationLine();
  if (const auto& base_decorations = BaseTextDecorationDataInternal()) {
    for (const AppliedTextDecoration& decoration : base_decorations->data) {
      decorations |= decoration.Lines();
    }
  }
  return decorations;
}

base::RefCountedData<Vector<AppliedTextDecoration, 1>>*
ComputedStyle::EnsureAppliedTextDecorationsCache() const {
  DCHECK(IsDecoratingBox());

  if (!cached_data_ || !cached_data_->applied_text_decorations_) {
    using DecorationsVector = Vector<AppliedTextDecoration, 1>;
    DecorationsVector decorations;
    if (const auto& base_decorations = BaseTextDecorationDataInternal()) {
      decorations.ReserveInitialCapacity(base_decorations->data.size() + 1u);
      decorations = base_decorations->data;
    }
    decorations.emplace_back(
        GetTextDecorationLine(), TextDecorationStyle(),
        VisitedDependentColor(GetCSSPropertyTextDecorationColor()),
        GetTextDecorationThickness(), TextUnderlineOffset());
    EnsureCachedData().applied_text_decorations_ =
        base::MakeRefCounted<base::RefCountedData<DecorationsVector>>(
            std::move(decorations));
  }

  return cached_data_->applied_text_decorations_.get();
}

const Vector<AppliedTextDecoration, 1>& ComputedStyle::AppliedTextDecorations()
    const {
  if (!HasAppliedTextDecorations()) {
    using DecorationsVector = Vector<AppliedTextDecoration, 1>;
    DEFINE_STATIC_LOCAL(DecorationsVector, empty, ());
    return empty;
  }

  if (!IsDecoratingBox()) {
    const auto& base_decorations = BaseTextDecorationDataInternal();
    DCHECK(base_decorations);
    DCHECK_GE(base_decorations->data.size(), 1u);
    return base_decorations->data;
  }

  return EnsureAppliedTextDecorationsCache()->data;
}

static bool HasInitialVariables(const StyleInitialData* initial_data) {
  return initial_data && initial_data->HasInitialVariables();
}

bool ComputedStyle::HasVariables() const {
  return InheritedVariables() || NonInheritedVariables() ||
         HasInitialVariables(InitialData());
}

wtf_size_t ComputedStyle::GetVariableNamesCount() const {
  if (!HasVariables()) {
    return 0;
  }
  return GetVariableNames().size();
}

const Vector<AtomicString>& ComputedStyle::GetVariableNames() const {
  if (auto* cache = GetVariableNamesCache()) {
    return *cache;
  }

  Vector<AtomicString>& cache = EnsureVariableNamesCache();

  HashSet<AtomicString> names;
  if (auto* initial_data = InitialData()) {
    initial_data->CollectVariableNames(names);
  }
  if (auto* inherited_variables = InheritedVariables()) {
    inherited_variables->CollectNames(names);
  }
  if (auto* non_inherited_variables = NonInheritedVariables()) {
    non_inherited_variables->CollectNames(names);
  }
  cache.assign(names);

  return cache;
}

const StyleInheritedVariables* ComputedStyle::InheritedVariables() const {
  return InheritedVariablesInternal().Get();
}

const StyleNonInheritedVariables* ComputedStyle::NonInheritedVariables() const {
  return NonInheritedVariablesInternal().Get();
}

namespace {

template <typename T>
CSSVariableData* GetVariableData(
    const T& style_or_builder,
    const AtomicString& name,
    std::optional<bool> inherited_hint = std::nullopt) {
  if (inherited_hint.value_or(true) && style_or_builder.InheritedVariables()) {
    if (auto data = style_or_builder.InheritedVariables()->GetData(name)) {
      return *data;
    }
  }
  if (!inherited_hint.value_or(false) &&
      style_or_builder.NonInheritedVariables()) {
    if (auto data = style_or_builder.NonInheritedVariables()->GetData(name)) {
      return *data;
    }
  }
  if (StyleInitialData* initial_data = style_or_builder.InitialData()) {
    return initial_data->GetVariableData(name);
  }
  return nullptr;
}

template <typename T>
const CSSValue* GetVariableValue(
    const T& style_or_builder,
    const AtomicString& name,
    std::optional<bool> inherited_hint = std::nullopt) {
  if (inherited_hint.value_or(true) && style_or_builder.InheritedVariables()) {
    if (auto data = style_or_builder.InheritedVariables()->GetValue(name)) {
      return *data;
    }
  }
  if (!inherited_hint.value_or(false) &&
      style_or_builder.NonInheritedVariables()) {
    if (auto data = style_or_builder.NonInheritedVariables()->GetValue(name)) {
      return *data;
    }
  }
  if (StyleInitialData* initial_data = style_or_builder.InitialData()) {
    return initial_data->GetVariableValue(name);
  }
  return nullptr;
}

}  // namespace

CSSVariableData* ComputedStyle::GetVariableData(
    const AtomicString& name) const {
  return blink::GetVariableData(*this, name);
}

CSSVariableData* ComputedStyle::GetVariableData(
    const AtomicString& name,
    bool is_inherited_property) const {
  return blink::GetVariableData(*this, name, is_inherited_property);
}

const CSSValue* ComputedStyle::GetVariableValue(
    const AtomicString& name) const {
  return blink::GetVariableValue(*this, name);
}

const CSSValue* ComputedStyle::GetVariableValue(
    const AtomicString& name,
    bool is_inherited_property) const {
  return blink::GetVariableValue(*this, name, is_inherited_property);
}

bool ComputedStyle::HasCustomScrollbarStyle(Element* element) const {
  if (!element) {
    return false;
  }

  // Ignore ::-webkit-scrollbar when the web setting to prefer default scrollbar
  // styling is true. The exception to this case is when 'display' is set to
  // 'none'.
  if (RuntimeEnabledFeatures::PreferDefaultScrollbarStylesEnabled() &&
      PrefersDefaultScrollbarStyles() && element &&
      !ScrollbarIsHiddenByCustomStyle(element)) {
    return false;
  }

  // Ignore non-standard ::-webkit-scrollbar when standard properties are in
  // use.
  return HasPseudoElementStyle(kPseudoIdScrollbar) &&
         !UsesStandardScrollbarStyle();
}

EScrollbarWidth ComputedStyle::UsedScrollbarWidth() const {
  if (PrefersDefaultScrollbarStyles() &&
      ScrollbarWidth() != EScrollbarWidth::kNone) {
    return EScrollbarWidth::kAuto;
  }

  return ScrollbarWidth();
}

StyleScrollbarColor* ComputedStyle::UsedScrollbarColor() const {
  if (PrefersDefaultScrollbarStyles()) {
    return nullptr;
  }

  return ScrollbarColor();
}

Length ComputedStyle::LineHeight() const {
  const Length& lh = LineHeightInternal();
  // Unlike getFontDescription().computedSize() and hence fontSize(), this is
  // recalculated on demand as we only store the specified line height.
  // FIXME: Should consider scaling the fixed part of any calc expressions
  // too, though this involves messily poking into CalcExpressionLength.
  if (lh.IsFixed()) {
    float multiplier = TextAutosizingMultiplier();
    return Length::Fixed(TextAutosizer::ComputeAutosizedFontSize(
        lh.Value(), multiplier, EffectiveZoom()));
  }

  return lh;
}

float ComputedStyle::ComputedLineHeight(const Length& lh, const Font& font) {
  // For "normal" line-height use the font's built-in spacing if available.
  if (lh.IsAuto()) {
    if (font.PrimaryFont()) {
      return font.PrimaryFont()->GetFontMetrics().LineSpacing();
    }
    return 0.0f;
  }

  if (lh.HasPercent()) {
    return MinimumValueForLength(
        lh, LayoutUnit(font.GetFontDescription().ComputedSize()));
  }

  return lh.Value();
}

float ComputedStyle::ComputedLineHeight() const {
  return ComputedLineHeight(LineHeight(), GetFont());
}

LayoutUnit ComputedStyle::ComputedLineHeightAsFixed(const Font& font) const {
  const Length& lh = LineHeight();

  // For "normal" line-height use the font's built-in spacing if available.
  if (lh.IsAuto()) {
    if (font.PrimaryFont()) {
      return font.PrimaryFont()->GetFontMetrics().FixedLineSpacing();
    }
    return LayoutUnit();
  }

  if (lh.HasPercent()) {
    return MinimumValueForLength(lh, ComputedFontSizeAsFixed(font));
  }

  return LayoutUnit::FromFloatRound(lh.Value());
}

LayoutUnit ComputedStyle::ComputedLineHeightAsFixed() const {
  return ComputedLineHeightAsFixed(GetFont());
}

StyleColor ComputedStyle::DecorationColorIncludingFallback(
    bool visited_link) const {
  StyleColor style_color = visited_link ? InternalVisitedTextDecorationColor()
                                        : TextDecorationColor();

  if (!style_color.IsCurrentColor()) {
    return style_color;
  }

  if (TextStrokeWidth()) {
    // Prefer stroke color if possible, but not if it's fully transparent.
    StyleColor text_stroke_style_color =
        visited_link ? InternalVisitedTextStrokeColor() : TextStrokeColor();
    if (!text_stroke_style_color.IsCurrentColor() &&
        !text_stroke_style_color.Resolve(blink::Color(), UsedColorScheme())
             .IsFullyTransparent()) {
      return text_stroke_style_color;
    }
  }

  return visited_link ? InternalVisitedTextFillColor() : TextFillColor();
}

bool ComputedStyle::HasBackground() const {
  // Ostensibly, we should call VisitedDependentColor() here,
  // but visited does not affect alpha (see VisitedDependentColor()
  // implementation).
  blink::Color color = GetCSSPropertyBackgroundColor().ColorIncludingFallback(
      false, *this,
      /*is_current_color=*/nullptr);
  if (!color.IsFullyTransparent()) {
    return true;
  }
  // When background color animation is running on the compositor thread, we
  // need to trigger repaint even if the background is transparent to collect
  // artifacts in order to run the animation on the compositor.
  if (RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled() &&
      HasCurrentBackgroundColorAnimation()) {
    return true;
  }
  return HasBackgroundImage();
}

Color ComputedStyle::VisitedDependentColor(const Longhand& color_property,
                                           bool* is_current_color) const {
  DCHECK(!color_property.IsVisited());

  blink::Color unvisited_color =
      color_property.ColorIncludingFallback(false, *this, is_current_color);
  if (InsideLink() != EInsideLink::kInsideVisitedLink) {
    return unvisited_color;
  }

  // Properties that provide a GetVisitedProperty() must use the
  // ColorIncludingFallback function on that property.
  //
  // TODO(andruud): Simplify this when all properties support
  // GetVisitedProperty.
  const CSSProperty* visited_property = &color_property;
  if (const CSSProperty* visited = color_property.GetVisitedProperty()) {
    visited_property = visited;
  }

  // Overwrite is_current_color based on the visited color.
  blink::Color visited_color =
      To<Longhand>(*visited_property)
          .ColorIncludingFallback(true, *this, is_current_color);

  // Take the alpha from the unvisited color, but get the RGB values from the
  // visited color.
  //
  // Ideally we would set the |is_current_color| flag to true if the unvisited
  // color is ‘currentColor’, because the result depends on the unvisited alpha,
  // to tell the highlight painter to resolve the color again with a different
  // current color, but that’s not possible with the current interface.
  //
  // In reality, the highlight painter just throws away the whole color and
  // falls back to the layer or next layer or originating ‘color’, so setting
  // the flag when the unvisited color is ‘currentColor’ would break tests like
  // css/css-pseudo/selection-link-001 and css/css-pseudo/target-text-008.
  // TODO(dazabani@igalia.com) improve behaviour where unvisited is currentColor
  return Color::FromColorSpace(visited_color.GetColorSpace(),
                               visited_color.Param0(), visited_color.Param1(),
                               visited_color.Param2(), unvisited_color.Alpha());
}

blink::Color ComputedStyle::VisitedDependentContextFill(
    const SVGPaint& context_paint,
    const ComputedStyle& context_style) const {
  return VisitedDependentContextPaint(context_paint,
                                      context_style.InternalVisitedFillPaint());
}

blink::Color ComputedStyle::VisitedDependentContextStroke(
    const SVGPaint& context_paint,
    const ComputedStyle& context_style) const {
  return VisitedDependentContextPaint(
      context_paint, context_style.InternalVisitedStrokePaint());
}

blink::Color ComputedStyle::VisitedDependentContextPaint(
    const SVGPaint& context_paint,
    const SVGPaint& context_visited_paint) const {
  blink::Color unvisited_color =
      ShouldForceColor(context_paint.GetColor())
          ? GetInternalForcedCurrentColor(nullptr)
          : context_paint.GetColor().Resolve(GetCurrentColor(),
                                             UsedColorScheme(), nullptr);
  if (InsideLink() != EInsideLink::kInsideVisitedLink) {
    return unvisited_color;
  }

  if (!context_visited_paint.HasColor()) {
    return unvisited_color;
  }
  if (ShouldForceColor(context_visited_paint.GetColor())) {
    return GetInternalForcedVisitedCurrentColor(nullptr);
  }
  return context_visited_paint.GetColor().Resolve(
      GetInternalVisitedCurrentColor(), UsedColorScheme(), nullptr);
}

blink::Color ComputedStyle::ResolvedColor(const StyleColor& color,
                                          bool* is_current_color) const {
  bool visited_link = (InsideLink() == EInsideLink::kInsideVisitedLink);
  blink::Color current_color =
      visited_link ? GetInternalVisitedCurrentColor() : GetCurrentColor();
  return color.Resolve(current_color, UsedColorScheme(), is_current_color);
}

bool ComputedStyle::ColumnRuleEquivalent(
    const ComputedStyle& other_style) const {
  return ColumnRuleStyle() == other_style.ColumnRuleStyle() &&
         ColumnRuleWidth() == other_style.Column
Prompt: 
```
这是目录为blink/renderer/core/style/computed_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
ightRadius());
      inset->SetBottomRightRadius(style.BorderBottomRightRadius());
      inset->SetBottomLeftRadius(style.BorderBottomLeftRadius());
      const gfx::RectF reference_box = GetReferenceBox(box, coord_box);
      const gfx::PointF offset_from_reference_box =
          GetOffsetFromContainingBlock(box) - reference_box.OffsetFromOrigin();
      const gfx::SizeF& reference_box_size = reference_box.size();
      const gfx::PointF starting_point = GetStartingPointOfThePath(
          offset_from_reference_box, position, reference_box_size);
      path_position = CalculatePointAndTangentOnBasicShape(
          *inset, starting_point, reference_box_size);
      // `path_position.point` is now relative to the containing block.
      // Make it relative to the box.
      path_position.point -= offset_from_reference_box.OffsetFromOrigin();
    }
  } else {
    const auto* url_operation =
        DynamicTo<ReferenceOffsetPathOperation>(offset_path);
    if (!url_operation->Resource()) {
      return;
    }
    const auto* target =
        DynamicTo<SVGGeometryElement>(url_operation->Resource()->Target());
    Path path;
    if (!target || !target->GetComputedStyle()) {
      // Failure to find a shape should be equivalent to a "m0,0" path.
      path.MoveTo({0, 0});
    } else {
      path = target->AsPath();
    }
    path_position = CalculatePointAndTangentOnPath(path);
  }

  if (rotate.type == OffsetRotationType::kFixed) {
    path_position.tangent_in_degrees = 0;
  }

  transform.Translate(path_position.point.x() - origin_x,
                      path_position.point.y() - origin_y);
  transform.Rotate(path_position.tangent_in_degrees + rotate.angle);

  const LengthPoint& anchor = OffsetAnchor();
  if (!anchor.X().IsAuto()) {
    gfx::PointF anchor_point = PointForLengthPoint(anchor, bounding_box.size());
    anchor_point += bounding_box.OffsetFromOrigin();

    // Shift the origin back to transform-origin and then move it based on the
    // anchor.
    transform.Translate(origin_x - anchor_point.x(),
                        origin_y - anchor_point.y());
  }
}

bool ComputedStyle::CanRenderBorderImage() const {
  const StyleImage* border_image = BorderImage().GetImage();
  return border_image && border_image->CanRender() && border_image->IsLoaded();
}

const CounterDirectiveMap* ComputedStyle::GetCounterDirectives() const {
  return CounterDirectivesInternal().get();
}

const CounterDirectives ComputedStyle::GetCounterDirectives(
    const AtomicString& identifier) const {
  if (GetCounterDirectives()) {
    auto it = GetCounterDirectives()->find(identifier);
    if (it != GetCounterDirectives()->end()) {
      return it->value;
    }
  }
  return CounterDirectives();
}

Hyphenation* ComputedStyle::GetHyphenation() const {
  if (GetHyphens() != Hyphens::kAuto) {
    return nullptr;
  }
  if (const LayoutLocale* locale = GetFontDescription().Locale()) {
    return locale->GetHyphenation();
  }
  return nullptr;
}

Hyphenation* ComputedStyle::GetHyphenationWithLimits() const {
  if (Hyphenation* hyphenation = GetHyphenation()) {
    const StyleHyphenateLimitChars& limits = HyphenateLimitChars();
    hyphenation->SetLimits(limits.MinBeforeChars(), limits.MinAfterChars(),
                           limits.MinWordChars());
    return hyphenation;
  }
  return nullptr;
}

const AtomicString& ComputedStyle::HyphenString() const {
  const AtomicString& hyphenation_string = HyphenationString();
  if (!hyphenation_string.IsNull()) {
    return hyphenation_string;
  }

  // FIXME: This should depend on locale.
  DEFINE_STATIC_LOCAL(AtomicString, hyphen_minus_string,
                      (base::span_from_ref(kHyphenMinusCharacter)));
  DEFINE_STATIC_LOCAL(AtomicString, hyphen_string,
                      (base::span_from_ref(kHyphenCharacter)));
  const SimpleFontData* primary_font = GetFont().PrimaryFont();
  DCHECK(primary_font);
  return primary_font && primary_font->GlyphForCharacter(kHyphenCharacter)
             ? hyphen_string
             : hyphen_minus_string;
}

ETextAlign ComputedStyle::GetTextAlign(bool is_last_line) const {
  if (!is_last_line) {
    return GetTextAlign();
  }

  // When this is the last line of a block, or the line ends with a forced line
  // break.
  // https://drafts.csswg.org/css-text-3/#propdef-text-align-last
  switch (TextAlignLast()) {
    case ETextAlignLast::kStart:
      return ETextAlign::kStart;
    case ETextAlignLast::kEnd:
      return ETextAlign::kEnd;
    case ETextAlignLast::kLeft:
      return ETextAlign::kLeft;
    case ETextAlignLast::kRight:
      return ETextAlign::kRight;
    case ETextAlignLast::kCenter:
      return ETextAlign::kCenter;
    case ETextAlignLast::kJustify:
      return ETextAlign::kJustify;
    case ETextAlignLast::kAuto:
      ETextAlign text_align = GetTextAlign();
      if (text_align == ETextAlign::kJustify) {
        return ETextAlign::kStart;
      }
      return text_align;
  }
  NOTREACHED();
}

// Unicode 11 introduced Georgian capital letters (U+1C90 - U+1CBA,
// U+1CB[D-F]), but virtually no font covers them. For now map them back
// to their lowercase counterparts (U+10D0 - U+10FA, U+10F[D-F]).
// https://www.unicode.org/charts/PDF/U10A0.pdf
// https://www.unicode.org/charts/PDF/U1C90.pdf
// See https://crbug.com/865427 .
// TODO(jshin): Make this platform-dependent. For instance, turn this
// off when CrOS gets new Georgian fonts covering capital letters.
// ( https://crbug.com/880144 ).
static String DisableNewGeorgianCapitalLetters(const String& text) {
  if (text.IsNull() || text.Is8Bit()) {
    return text;
  }
  unsigned length = text.length();
  const StringImpl& input = *(text.Impl());
  StringBuilder result;
  result.ReserveCapacity(length);
  // |input| must be well-formed UTF-16 so that there's no worry
  // about surrogate handling.
  for (unsigned i = 0; i < length; ++i) {
    UChar character = input[i];
    if (Character::IsModernGeorgianUppercase(character)) {
      result.Append(Character::LowercaseModernGeorgianUppercase(character));
    } else {
      result.Append(character);
    }
  }
  return result.ToString();
}

namespace {

String ApplyMathAutoTransform(const String& text, TextOffsetMap* offset_map) {
  if (text.length() != 1) {
    return text;
  }
  UChar character = text[0];
  UChar32 transformed_char = ItalicMathVariant(text[0]);
  if (transformed_char == static_cast<UChar32>(character)) {
    return text;
  }

  Vector<UChar> transformed_text(U16_LENGTH(transformed_char));
  int i = 0;
  U16_APPEND_UNSAFE(transformed_text, i, transformed_char);
  String transformed_string = String(transformed_text);
  if (offset_map) {
    offset_map->Append(text.length(), transformed_string.length());
  }
  return transformed_string;
}

}  // namespace

String ComputedStyle::ApplyTextTransform(const String& text,
                                         UChar previous_character,
                                         TextOffsetMap* offset_map) const {
  switch (TextTransform()) {
    case ETextTransform::kNone:
      return text;
    case ETextTransform::kCapitalize:
      return Capitalize(text, previous_character);
    case ETextTransform::kUppercase: {
      const LayoutLocale* locale = GetFontDescription().Locale();
      CaseMap case_map(locale ? locale->CaseMapLocale() : CaseMap::Locale());
      return DisableNewGeorgianCapitalLetters(
          case_map.ToUpper(text, offset_map));
    }
    case ETextTransform::kLowercase: {
      const LayoutLocale* locale = GetFontDescription().Locale();
      CaseMap case_map(locale ? locale->CaseMapLocale() : CaseMap::Locale());
      return case_map.ToLower(text, offset_map);
    }
    case ETextTransform::kMathAuto:
      return ApplyMathAutoTransform(text, offset_map);
  }
  NOTREACHED();
}

const AtomicString& ComputedStyle::TextEmphasisMarkString() const {
  switch (GetTextEmphasisMark()) {
    case TextEmphasisMark::kNone:
      return g_null_atom;
    case TextEmphasisMark::kCustom:
      return TextEmphasisCustomMark();
    case TextEmphasisMark::kDot: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_dot_string,
                          (base::span_from_ref(kBulletCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_dot_string,
                          (base::span_from_ref(kWhiteBulletCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_dot_string
                 : open_dot_string;
    }
    case TextEmphasisMark::kCircle: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_circle_string,
                          (base::span_from_ref(kBlackCircleCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_circle_string,
                          (base::span_from_ref(kWhiteCircleCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_circle_string
                 : open_circle_string;
    }
    case TextEmphasisMark::kDoubleCircle: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_double_circle_string,
                          (base::span_from_ref(kFisheyeCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_double_circle_string,
                          (base::span_from_ref(kBullseyeCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_double_circle_string
                 : open_double_circle_string;
    }
    case TextEmphasisMark::kTriangle: {
      DEFINE_STATIC_LOCAL(
          AtomicString, filled_triangle_string,
          (base::span_from_ref(kBlackUpPointingTriangleCharacter)));
      DEFINE_STATIC_LOCAL(
          AtomicString, open_triangle_string,
          (base::span_from_ref(kWhiteUpPointingTriangleCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_triangle_string
                 : open_triangle_string;
    }
    case TextEmphasisMark::kSesame: {
      DEFINE_STATIC_LOCAL(AtomicString, filled_sesame_string,
                          (base::span_from_ref(kSesameDotCharacter)));
      DEFINE_STATIC_LOCAL(AtomicString, open_sesame_string,
                          (base::span_from_ref(kWhiteSesameDotCharacter)));
      return GetTextEmphasisFill() == TextEmphasisFill::kFilled
                 ? filled_sesame_string
                 : open_sesame_string;
    }
    case TextEmphasisMark::kAuto:
      NOTREACHED();
  }

  NOTREACHED();
}

LineLogicalSide ComputedStyle::GetTextEmphasisLineLogicalSide() const {
  TextEmphasisPosition position = GetTextEmphasisPosition();
  if (IsHorizontalWritingMode()) {
    return IsOver(position) ? LineLogicalSide::kOver : LineLogicalSide::kUnder;
  }
  if (GetWritingMode() != WritingMode::kSidewaysLr) {
    return IsRight(position) ? LineLogicalSide::kOver : LineLogicalSide::kUnder;
  }
  return IsLeft(position) ? LineLogicalSide::kOver : LineLogicalSide::kUnder;
}

FontBaseline ComputedStyle::GetFontBaseline() const {
  // CssDominantBaseline() always returns kAuto for non-SVG elements,
  // and never returns kUseScript, kNoChange, and kResetSize.
  // See StyleAdjuster::AdjustComputedStyle().
  switch (CssDominantBaseline()) {
    case EDominantBaseline::kAuto:
      break;
    case EDominantBaseline::kMiddle:
      return kXMiddleBaseline;
    case EDominantBaseline::kAlphabetic:
      return kAlphabeticBaseline;
    case EDominantBaseline::kHanging:
      return kHangingBaseline;
    case EDominantBaseline::kCentral:
      return kCentralBaseline;
    case EDominantBaseline::kTextBeforeEdge:
      return kTextOverBaseline;
    case EDominantBaseline::kTextAfterEdge:
      return kTextUnderBaseline;
    case EDominantBaseline::kIdeographic:
      return kIdeographicUnderBaseline;
    case EDominantBaseline::kMathematical:
      return kMathBaseline;

    case EDominantBaseline::kUseScript:
    case EDominantBaseline::kNoChange:
    case EDominantBaseline::kResetSize:
      NOTREACHED();
  }

  // Vertical flow (except 'text-orientation: sideways') uses ideographic
  // central baseline.
  // https://drafts.csswg.org/css-writing-modes-3/#text-baselines
  return !GetFontDescription().IsVerticalAnyUpright() ? kAlphabeticBaseline
                                                      : kCentralBaseline;
}

FontHeight ComputedStyle::GetFontHeight(FontBaseline baseline) const {
  if (const SimpleFontData* font_data = GetFont().PrimaryFont()) {
    return font_data->GetFontMetrics().GetFontHeight(baseline);
  }
  return FontHeight();
}

bool ComputedStyle::TextDecorationVisualOverflowChanged(
    const ComputedStyle& o) const {
  const Vector<AppliedTextDecoration, 1>& applied_with_this =
      AppliedTextDecorations();
  const Vector<AppliedTextDecoration, 1>& applied_with_other =
      o.AppliedTextDecorations();
  if (applied_with_this.size() != applied_with_other.size()) {
    return true;
  }
  for (auto decoration_index = 0u; decoration_index < applied_with_this.size();
       ++decoration_index) {
    const AppliedTextDecoration& decoration_from_this =
        applied_with_this[decoration_index];
    const AppliedTextDecoration& decoration_from_other =
        applied_with_other[decoration_index];
    if (decoration_from_this.Thickness() != decoration_from_other.Thickness() ||
        decoration_from_this.UnderlineOffset() !=
            decoration_from_other.UnderlineOffset() ||
        decoration_from_this.Style() != decoration_from_other.Style() ||
        decoration_from_this.Lines() != decoration_from_other.Lines()) {
      return true;
    }
  }
  if (GetTextUnderlinePosition() != o.GetTextUnderlinePosition()) {
    return true;
  }

  return false;
}

TextDecorationLine ComputedStyle::TextDecorationsInEffect() const {
  TextDecorationLine decorations = GetTextDecorationLine();
  if (const auto& base_decorations = BaseTextDecorationDataInternal()) {
    for (const AppliedTextDecoration& decoration : base_decorations->data) {
      decorations |= decoration.Lines();
    }
  }
  return decorations;
}

base::RefCountedData<Vector<AppliedTextDecoration, 1>>*
ComputedStyle::EnsureAppliedTextDecorationsCache() const {
  DCHECK(IsDecoratingBox());

  if (!cached_data_ || !cached_data_->applied_text_decorations_) {
    using DecorationsVector = Vector<AppliedTextDecoration, 1>;
    DecorationsVector decorations;
    if (const auto& base_decorations = BaseTextDecorationDataInternal()) {
      decorations.ReserveInitialCapacity(base_decorations->data.size() + 1u);
      decorations = base_decorations->data;
    }
    decorations.emplace_back(
        GetTextDecorationLine(), TextDecorationStyle(),
        VisitedDependentColor(GetCSSPropertyTextDecorationColor()),
        GetTextDecorationThickness(), TextUnderlineOffset());
    EnsureCachedData().applied_text_decorations_ =
        base::MakeRefCounted<base::RefCountedData<DecorationsVector>>(
            std::move(decorations));
  }

  return cached_data_->applied_text_decorations_.get();
}

const Vector<AppliedTextDecoration, 1>& ComputedStyle::AppliedTextDecorations()
    const {
  if (!HasAppliedTextDecorations()) {
    using DecorationsVector = Vector<AppliedTextDecoration, 1>;
    DEFINE_STATIC_LOCAL(DecorationsVector, empty, ());
    return empty;
  }

  if (!IsDecoratingBox()) {
    const auto& base_decorations = BaseTextDecorationDataInternal();
    DCHECK(base_decorations);
    DCHECK_GE(base_decorations->data.size(), 1u);
    return base_decorations->data;
  }

  return EnsureAppliedTextDecorationsCache()->data;
}

static bool HasInitialVariables(const StyleInitialData* initial_data) {
  return initial_data && initial_data->HasInitialVariables();
}

bool ComputedStyle::HasVariables() const {
  return InheritedVariables() || NonInheritedVariables() ||
         HasInitialVariables(InitialData());
}

wtf_size_t ComputedStyle::GetVariableNamesCount() const {
  if (!HasVariables()) {
    return 0;
  }
  return GetVariableNames().size();
}

const Vector<AtomicString>& ComputedStyle::GetVariableNames() const {
  if (auto* cache = GetVariableNamesCache()) {
    return *cache;
  }

  Vector<AtomicString>& cache = EnsureVariableNamesCache();

  HashSet<AtomicString> names;
  if (auto* initial_data = InitialData()) {
    initial_data->CollectVariableNames(names);
  }
  if (auto* inherited_variables = InheritedVariables()) {
    inherited_variables->CollectNames(names);
  }
  if (auto* non_inherited_variables = NonInheritedVariables()) {
    non_inherited_variables->CollectNames(names);
  }
  cache.assign(names);

  return cache;
}

const StyleInheritedVariables* ComputedStyle::InheritedVariables() const {
  return InheritedVariablesInternal().Get();
}

const StyleNonInheritedVariables* ComputedStyle::NonInheritedVariables() const {
  return NonInheritedVariablesInternal().Get();
}

namespace {

template <typename T>
CSSVariableData* GetVariableData(
    const T& style_or_builder,
    const AtomicString& name,
    std::optional<bool> inherited_hint = std::nullopt) {
  if (inherited_hint.value_or(true) && style_or_builder.InheritedVariables()) {
    if (auto data = style_or_builder.InheritedVariables()->GetData(name)) {
      return *data;
    }
  }
  if (!inherited_hint.value_or(false) &&
      style_or_builder.NonInheritedVariables()) {
    if (auto data = style_or_builder.NonInheritedVariables()->GetData(name)) {
      return *data;
    }
  }
  if (StyleInitialData* initial_data = style_or_builder.InitialData()) {
    return initial_data->GetVariableData(name);
  }
  return nullptr;
}

template <typename T>
const CSSValue* GetVariableValue(
    const T& style_or_builder,
    const AtomicString& name,
    std::optional<bool> inherited_hint = std::nullopt) {
  if (inherited_hint.value_or(true) && style_or_builder.InheritedVariables()) {
    if (auto data = style_or_builder.InheritedVariables()->GetValue(name)) {
      return *data;
    }
  }
  if (!inherited_hint.value_or(false) &&
      style_or_builder.NonInheritedVariables()) {
    if (auto data = style_or_builder.NonInheritedVariables()->GetValue(name)) {
      return *data;
    }
  }
  if (StyleInitialData* initial_data = style_or_builder.InitialData()) {
    return initial_data->GetVariableValue(name);
  }
  return nullptr;
}

}  // namespace

CSSVariableData* ComputedStyle::GetVariableData(
    const AtomicString& name) const {
  return blink::GetVariableData(*this, name);
}

CSSVariableData* ComputedStyle::GetVariableData(
    const AtomicString& name,
    bool is_inherited_property) const {
  return blink::GetVariableData(*this, name, is_inherited_property);
}

const CSSValue* ComputedStyle::GetVariableValue(
    const AtomicString& name) const {
  return blink::GetVariableValue(*this, name);
}

const CSSValue* ComputedStyle::GetVariableValue(
    const AtomicString& name,
    bool is_inherited_property) const {
  return blink::GetVariableValue(*this, name, is_inherited_property);
}

bool ComputedStyle::HasCustomScrollbarStyle(Element* element) const {
  if (!element) {
    return false;
  }

  // Ignore ::-webkit-scrollbar when the web setting to prefer default scrollbar
  // styling is true. The exception to this case is when 'display' is set to
  // 'none'.
  if (RuntimeEnabledFeatures::PreferDefaultScrollbarStylesEnabled() &&
      PrefersDefaultScrollbarStyles() && element &&
      !ScrollbarIsHiddenByCustomStyle(element)) {
    return false;
  }

  // Ignore non-standard ::-webkit-scrollbar when standard properties are in
  // use.
  return HasPseudoElementStyle(kPseudoIdScrollbar) &&
         !UsesStandardScrollbarStyle();
}

EScrollbarWidth ComputedStyle::UsedScrollbarWidth() const {
  if (PrefersDefaultScrollbarStyles() &&
      ScrollbarWidth() != EScrollbarWidth::kNone) {
    return EScrollbarWidth::kAuto;
  }

  return ScrollbarWidth();
}

StyleScrollbarColor* ComputedStyle::UsedScrollbarColor() const {
  if (PrefersDefaultScrollbarStyles()) {
    return nullptr;
  }

  return ScrollbarColor();
}

Length ComputedStyle::LineHeight() const {
  const Length& lh = LineHeightInternal();
  // Unlike getFontDescription().computedSize() and hence fontSize(), this is
  // recalculated on demand as we only store the specified line height.
  // FIXME: Should consider scaling the fixed part of any calc expressions
  // too, though this involves messily poking into CalcExpressionLength.
  if (lh.IsFixed()) {
    float multiplier = TextAutosizingMultiplier();
    return Length::Fixed(TextAutosizer::ComputeAutosizedFontSize(
        lh.Value(), multiplier, EffectiveZoom()));
  }

  return lh;
}

float ComputedStyle::ComputedLineHeight(const Length& lh, const Font& font) {
  // For "normal" line-height use the font's built-in spacing if available.
  if (lh.IsAuto()) {
    if (font.PrimaryFont()) {
      return font.PrimaryFont()->GetFontMetrics().LineSpacing();
    }
    return 0.0f;
  }

  if (lh.HasPercent()) {
    return MinimumValueForLength(
        lh, LayoutUnit(font.GetFontDescription().ComputedSize()));
  }

  return lh.Value();
}

float ComputedStyle::ComputedLineHeight() const {
  return ComputedLineHeight(LineHeight(), GetFont());
}

LayoutUnit ComputedStyle::ComputedLineHeightAsFixed(const Font& font) const {
  const Length& lh = LineHeight();

  // For "normal" line-height use the font's built-in spacing if available.
  if (lh.IsAuto()) {
    if (font.PrimaryFont()) {
      return font.PrimaryFont()->GetFontMetrics().FixedLineSpacing();
    }
    return LayoutUnit();
  }

  if (lh.HasPercent()) {
    return MinimumValueForLength(lh, ComputedFontSizeAsFixed(font));
  }

  return LayoutUnit::FromFloatRound(lh.Value());
}

LayoutUnit ComputedStyle::ComputedLineHeightAsFixed() const {
  return ComputedLineHeightAsFixed(GetFont());
}

StyleColor ComputedStyle::DecorationColorIncludingFallback(
    bool visited_link) const {
  StyleColor style_color = visited_link ? InternalVisitedTextDecorationColor()
                                        : TextDecorationColor();

  if (!style_color.IsCurrentColor()) {
    return style_color;
  }

  if (TextStrokeWidth()) {
    // Prefer stroke color if possible, but not if it's fully transparent.
    StyleColor text_stroke_style_color =
        visited_link ? InternalVisitedTextStrokeColor() : TextStrokeColor();
    if (!text_stroke_style_color.IsCurrentColor() &&
        !text_stroke_style_color.Resolve(blink::Color(), UsedColorScheme())
             .IsFullyTransparent()) {
      return text_stroke_style_color;
    }
  }

  return visited_link ? InternalVisitedTextFillColor() : TextFillColor();
}

bool ComputedStyle::HasBackground() const {
  // Ostensibly, we should call VisitedDependentColor() here,
  // but visited does not affect alpha (see VisitedDependentColor()
  // implementation).
  blink::Color color = GetCSSPropertyBackgroundColor().ColorIncludingFallback(
      false, *this,
      /*is_current_color=*/nullptr);
  if (!color.IsFullyTransparent()) {
    return true;
  }
  // When background color animation is running on the compositor thread, we
  // need to trigger repaint even if the background is transparent to collect
  // artifacts in order to run the animation on the compositor.
  if (RuntimeEnabledFeatures::CompositeBGColorAnimationEnabled() &&
      HasCurrentBackgroundColorAnimation()) {
    return true;
  }
  return HasBackgroundImage();
}

Color ComputedStyle::VisitedDependentColor(const Longhand& color_property,
                                           bool* is_current_color) const {
  DCHECK(!color_property.IsVisited());

  blink::Color unvisited_color =
      color_property.ColorIncludingFallback(false, *this, is_current_color);
  if (InsideLink() != EInsideLink::kInsideVisitedLink) {
    return unvisited_color;
  }

  // Properties that provide a GetVisitedProperty() must use the
  // ColorIncludingFallback function on that property.
  //
  // TODO(andruud): Simplify this when all properties support
  // GetVisitedProperty.
  const CSSProperty* visited_property = &color_property;
  if (const CSSProperty* visited = color_property.GetVisitedProperty()) {
    visited_property = visited;
  }

  // Overwrite is_current_color based on the visited color.
  blink::Color visited_color =
      To<Longhand>(*visited_property)
          .ColorIncludingFallback(true, *this, is_current_color);

  // Take the alpha from the unvisited color, but get the RGB values from the
  // visited color.
  //
  // Ideally we would set the |is_current_color| flag to true if the unvisited
  // color is ‘currentColor’, because the result depends on the unvisited alpha,
  // to tell the highlight painter to resolve the color again with a different
  // current color, but that’s not possible with the current interface.
  //
  // In reality, the highlight painter just throws away the whole color and
  // falls back to the layer or next layer or originating ‘color’, so setting
  // the flag when the unvisited color is ‘currentColor’ would break tests like
  // css/css-pseudo/selection-link-001 and css/css-pseudo/target-text-008.
  // TODO(dazabani@igalia.com) improve behaviour where unvisited is currentColor
  return Color::FromColorSpace(visited_color.GetColorSpace(),
                               visited_color.Param0(), visited_color.Param1(),
                               visited_color.Param2(), unvisited_color.Alpha());
}

blink::Color ComputedStyle::VisitedDependentContextFill(
    const SVGPaint& context_paint,
    const ComputedStyle& context_style) const {
  return VisitedDependentContextPaint(context_paint,
                                      context_style.InternalVisitedFillPaint());
}

blink::Color ComputedStyle::VisitedDependentContextStroke(
    const SVGPaint& context_paint,
    const ComputedStyle& context_style) const {
  return VisitedDependentContextPaint(
      context_paint, context_style.InternalVisitedStrokePaint());
}

blink::Color ComputedStyle::VisitedDependentContextPaint(
    const SVGPaint& context_paint,
    const SVGPaint& context_visited_paint) const {
  blink::Color unvisited_color =
      ShouldForceColor(context_paint.GetColor())
          ? GetInternalForcedCurrentColor(nullptr)
          : context_paint.GetColor().Resolve(GetCurrentColor(),
                                             UsedColorScheme(), nullptr);
  if (InsideLink() != EInsideLink::kInsideVisitedLink) {
    return unvisited_color;
  }

  if (!context_visited_paint.HasColor()) {
    return unvisited_color;
  }
  if (ShouldForceColor(context_visited_paint.GetColor())) {
    return GetInternalForcedVisitedCurrentColor(nullptr);
  }
  return context_visited_paint.GetColor().Resolve(
      GetInternalVisitedCurrentColor(), UsedColorScheme(), nullptr);
}

blink::Color ComputedStyle::ResolvedColor(const StyleColor& color,
                                          bool* is_current_color) const {
  bool visited_link = (InsideLink() == EInsideLink::kInsideVisitedLink);
  blink::Color current_color =
      visited_link ? GetInternalVisitedCurrentColor() : GetCurrentColor();
  return color.Resolve(current_color, UsedColorScheme(), is_current_color);
}

bool ComputedStyle::ColumnRuleEquivalent(
    const ComputedStyle& other_style) const {
  return ColumnRuleStyle() == other_style.ColumnRuleStyle() &&
         ColumnRuleWidth() == other_style.ColumnRuleWidth() &&
         VisitedDependentColor(GetCSSPropertyColumnRuleColor()) ==
             other_style.VisitedDependentColor(GetCSSPropertyColumnRuleColor());
}

TextEmphasisMark ComputedStyle::GetTextEmphasisMark() const {
  TextEmphasisMark mark = TextEmphasisMarkInternal();
  if (mark != TextEmphasisMark::kAuto) {
    return mark;
  }

  // https://drafts.csswg.org/css-text-decor/#propdef-text-emphasis-style
  // If only `filled` or `open` is specified, the shape keyword computes to
  // `circle` in horizontal typographic modes and `sesame` in vertical
  // typographic modes.
  if (IsHorizontalTypographicMode()) {
    return TextEmphasisMark::kDot;
  }

  return TextEmphasisMark::kSesame;
}

PhysicalBoxStrut ComputedStyle::ImageOutsets(
    const NinePieceImage& image) const {
  return {
      NinePieceImage::ComputeOutset(image.Outset().Top(), BorderTopWidth()),
      NinePieceImage::ComputeOutset(image.Outset().Right(), BorderRightWidth()),
      NinePieceImage::ComputeOutset(image.Outset().Bottom(),
                                    BorderBottomWidth()),
      NinePieceImage::ComputeOutset(image.Outset().Left(), BorderLeftWidth())};
}

bool ComputedStyle::BorderObscuresBackground() const {
  if (!HasBorder()) {
    return false;
  }

  // Bail if we have any border-image for now. We could look at the image alpha
  // to improve this.
  if (BorderImage().GetImage()) {
    return false;
  }

  BorderEdgeArray edges;
  GetBorderEdgeInfo(edges);

  for (unsigned int i = static_cast<unsigned>(BoxSide::kTop);
       i <= static_cast<unsigned>(BoxSide::kLeft); ++i) {
    const BorderEdge& curr_edge = edges[i];
    if (!curr_edge.ObscuresBackground()) {
      return false;
    }
  }

  return true;
}

PhysicalBoxStrut ComputedStyle::BoxDecorationOutsets() const {
  DCHECK(HasVisualOverflowingEffect());
  PhysicalBoxStrut outsets;

  if (const ShadowList* box_shadow = BoxShadow()) {
    outsets =
        PhysicalBoxStrut::Enclosing(box_shadow->RectOutsetsIncludingOriginal());
  }

  if (HasBorderImageOutsets()) {
    outsets.Unite(BorderImageOutsets());
  }

  if (HasMaskBoxImageOutsets()) {
    outsets.Unite(MaskBoxImageOutsets());
  }

  return outsets;
}

void ComputedStyle::GetBorderEdgeInfo(BorderEdgeArray& edges,
                                      PhysicalBoxSides sides_to_include) const {
  edges[static_cast<unsigned>(BoxSide::kTop)] = BorderEdge(
      BorderTopWidth(), VisitedDependentColor(GetCSSPropertyBorderTopColor()),
      BorderTopStyle(), sides_to_include.top);

  edges[static_cast<unsigned>(BoxSide::kRight)] =
      BorderEdge(BorderRightWidth(),
                 VisitedDependentColor(GetCSSPropertyBorderRightColor()),
                 BorderRightStyle(), sides_to_include.right);

  edges[static_cast<unsigned>(BoxSide::kBottom)] =
      BorderEdge(BorderBottomWidth(),
                 VisitedDependentColor(GetCSSPropertyBorderBottomColor()),
                 BorderBottomStyle(), sides_to_include.bottom);

  edges[static_cast<unsigned>(BoxSide::kLeft)] = BorderEdge(
      BorderLeftWidth(), VisitedDependentColor(GetCSSPropertyBorderLeftColor()),
      BorderLeftStyle(), sides_to_include.left);
}

void ComputedStyle::CopyChildDependentFlagsFrom(
    const ComputedStyle& other) const {
  if (other.ChildHasExplicitInheritance()) {
    SetChildHasExplicitInheritance();
  }
}

blink::Color ComputedStyle::GetCurrentColor(bool* is_current_color) const {
  DCHECK(!Color().IsCurrentColor());
  if (is_current_color) {
    *is_current_color = ColorIsCurrentColor();
  }
  return Color().Resolve(blink::Color(), UsedColorScheme());
}

blink::Color ComputedStyle::GetInternalVisitedCurrentColor(
    bool* is_current_color) const {
  DCHECK(!InternalVisitedColor().IsCurrentColor());
  if (is_current_color) {
    *is_current_color = InternalVisitedColorIsCurrentColor();
  }
  return InternalVisitedColor().Resolve(blink::Color(), UsedColorScheme());
}

blink::Color ComputedStyle::GetInternalForcedCurrentColor(
    bool* is_current_color) const {
  DCHECK(!InternalForcedColor().IsCurrentColor());
  if (Color().IsSystemColorIncludingDeprecated()) {
    return GetCurrentColor(is_current_color);
  }
  return InternalForcedColor().Resolve(blink::Color(), UsedColorScheme(),
                                       is_current_color);
}

blink::Color ComputedStyle::GetInternalForcedVisitedCurrentColor(
    bool* is_current_color) const {
  DCHECK(!InternalForcedVisitedColor().IsCurrentColor());
  if (InternalVisitedColor().IsSystemColorIncludingDeprecated()) {
    return GetInternalVisitedCurrentColor(is_current_color);
  }
  return InternalForcedVisitedColor().Resolve(blink::Color(), UsedColorScheme(),
                                              is_current_color);
}

bool ComputedStyle::ShadowListHasCurrentColor(const ShadowList* shadow_list) {
  return shadow_list &&
         base::ranges::any_of(shadow_list->Shadows(),
                              [](const ShadowData& shadow) {
                                return shadow.GetColor().IsCurrentColor();
                              });
}

const AtomicString& ComputedStyle::ListStyleStringValue() const {
  if (!ListStyleType() || !ListStyleType()->IsString()) {
    return g_null_atom;
  }
  return ListStyleType()->GetStringValue();
}

bool ComputedStyle::MarkerShouldBeInside(
    const Element& parent,
    const DisplayStyle& marker_style) const {
  // https://w3c.github.io/csswg-drafts/css-lists/#list-style-position-outside
  // > If the list item is an inline box: this value is equivalent to insid
"""


```