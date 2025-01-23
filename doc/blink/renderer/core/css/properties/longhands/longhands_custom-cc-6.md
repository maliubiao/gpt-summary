Response:
The user is asking for a summary of the functionality of the provided C++ code snippet. This file seems to define how different CSS properties are parsed, applied, and converted to CSS values within the Blink rendering engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file `longhands_custom.cc` deals with the implementation of individual CSS properties. The "longhands" part suggests it handles the fully expanded form of properties (e.g., `margin-top` instead of the `margin` shorthand).

2. **Analyze the functions within each property's definition:** For each CSS property, the code defines functions like `ParseSingleValue`, `ApplyInitial`, `ApplyInherit`, `ApplyValue`, `CSSValueFromComputedStyleInternal`, and `ColorIncludingFallback`. Understanding the role of each function is key.

3. **Relate to CSS concepts:** Connect the functions and logic to how CSS properties work in general. For example, parsing involves understanding the syntax, applying involves setting the internal style representation, and converting to a CSS value is needed for things like `getComputedStyle`.

4. **Look for connections to JavaScript, HTML:**  CSS directly styles HTML. JavaScript interacts with CSS via the DOM (e.g., `element.style`, `getComputedStyle`). Identify where these interactions might occur implicitly. For instance, when a CSS property affects layout, JavaScript might trigger layout recalculations.

5. **Infer logic and provide examples:** Based on the code, especially the `ApplyValue` and `ParseSingleValue` functions,  deduce the expected behavior for different input values. Create simple examples demonstrating this.

6. **Identify potential user errors:** Consider how a developer might misuse these properties or provide invalid input. The parsing functions often have error handling, and the `ApplyValue` functions might have checks.

7. **Trace user actions (debugging):**  Think about the sequence of steps a user might take in a browser that would lead to this code being executed. This usually starts with loading a web page with specific CSS rules.

8. **Address the "part 7 of 13" instruction:**  Recognize that this is part of a larger system and focus on the specific functionality within this file, while acknowledging it fits into the bigger picture of CSS processing.

**Pre-computation/Pre-analysis (Mental Walkthrough of the Code):**

* **Color Properties (e.g., `InternalForcedColor`, `InternalForcedOutlineColor`, `InternalForcedVisitedColor`, `LightingColor`):**  These deal with parsing color values, handling `currentcolor`, visited link states, and forced colors (high contrast modes).
* **Layout Properties (e.g., `Left`, `Margin*`, `MaxHeight`):** These involve parsing length units, percentages, and potentially `auto`. Some are marked as `IsLayoutDependent`, indicating they influence the rendering layout.
* **Text Properties (e.g., `LetterSpacing`, `LineBreak`, `LineClamp`, `LineHeight`):** These handle spacing, line wrapping, and limiting the number of lines.
* **List Properties (e.g., `ListStyleImage`, `ListStylePosition`, `ListStyleType`):** These are for styling list markers, including images and custom counters.
* **Grid/Flexbox Properties (e.g., `JustifyContent`, `JustifyItems`, `JustifySelf`):** These control the alignment of items in grid and flexbox layouts.
* **SVG Marker Properties (e.g., `MarkerEnd`, `MarkerMid`, `MarkerStart`):** These allow attaching SVG elements as markers to lines or shapes.
* **Masonry Properties (e.g., `MasonrySlack`, `MasonryTemplateTracks`, `MasonryTrack*`):** These relate to the masonry layout algorithm.
* **Math Properties (e.g., `MathShift`, `MathStyle`, `MathDepth`):** These are specific to the styling of mathematical formulas.
* **Generic Properties (e.g., `Interactivity`, `InterpolateSize`, `Isolation`, `MaskType`):** These cover other CSS features.

By grouping properties with similar functionality, the analysis becomes more manageable. The presence of `ParseSingleValue`, `ApplyValue`, and `CSSValueFromComputedStyleInternal` is a common pattern across many properties, reinforcing the idea that this file is about the lifecycle of CSS property handling.
这是Blink渲染引擎的源代码文件，专门负责处理各种CSS长属性（longhand properties），特别是那些需要自定义逻辑处理的属性。 这是第7部分，表明这个文件是处理CSS属性定义的一个模块化部分。

**核心功能归纳:**

这个文件的核心功能是**定义和实现各种CSS长属性的解析、应用和计算值的获取逻辑**。  它为每一个特定的CSS属性（例如 `internal-forced-color`, `margin-top`, `line-height` 等）提供了以下能力：

1. **解析 (Parsing):**  定义如何从CSS样式表中的文本值（token stream）解析出对应属性的值。  例如，`ParseSingleValue` 函数负责完成此项任务。
2. **应用 (Applying):** 定义如何将解析出的值应用到元素的样式计算过程中，更新元素的 `ComputedStyle` 对象。 例如， `ApplyInitial`, `ApplyInherit`, 和 `ApplyValue` 函数负责处理初始值、继承值和指定值。
3. **计算值获取 (Getting Computed Value):** 定义如何从元素的 `ComputedStyle` 对象中获取该属性的最终计算值，并将其转换为 `CSSValue` 对象，以便在例如 JavaScript 中通过 `getComputedStyle` 获取。 例如，`CSSValueFromComputedStyleInternal` 函数负责此项任务。
4. **颜色处理 (Color Handling):** 对于颜色相关的属性，还定义了如何处理颜色回退、`currentcolor` 关键字以及访问过的链接状态下的颜色 (`ColorIncludingFallback`)。
5. **布局依赖性判断 (Layout Dependency):** 某些属性（例如 `margin` 和 `left`）的计算值依赖于元素的布局信息。  `IsLayoutDependent` 函数用于判断属性是否具有布局依赖性。

**与 Javascript, HTML, CSS 的关系及举例说明:**

* **CSS:** 这个文件直接实现了 CSS 属性的行为。它定义了浏览器如何理解和应用 CSS 样式规则。
    * **举例:**  `MarginTop::ParseSingleValue` 函数定义了浏览器如何解析 `margin-top: 10px;` 或 `margin-top: auto;` 这样的 CSS 声明。
* **HTML:** CSS 样式最终会应用到 HTML 元素上。这个文件中的逻辑决定了当某个 HTML 元素具有特定的 CSS 属性时，其渲染效果会如何。
    * **举例:** 当一个 `<div>` 元素的 CSS 中设置了 `line-height: 1.5;`，`LineHeight::ParseSingleValue` 和相关的 `ApplyValue` 函数会确保浏览器正确解析并应用这个行高值。
* **JavaScript:** JavaScript 可以通过 DOM API (例如 `element.style` 和 `getComputedStyle`) 来读取和修改元素的 CSS 样式。 这个文件中的 `CSSValueFromComputedStyleInternal` 函数负责将计算后的样式值转换为 JavaScript 可以理解的 `CSSValue` 对象。
    * **举例:**  如果 JavaScript 代码执行了 `getComputedStyle(element).marginTop;`，那么 `MarginTop::CSSValueFromComputedStyleInternal` 函数会被调用，返回一个表示 `margin-top` 计算值的 `CSSValue` 对象，最终会被转换为 JavaScript 可以使用的字符串形式 (例如 "10px")。

**逻辑推理及假设输入与输出:**

**假设输入 (针对 `LineHeight` 属性):**

* **CSS 样式:** `line-height: 1.5;`
* **当前元素的 `font-size` 计算值为:** `16px`

**逻辑推理:**

1. `LineHeight::ParseSingleValue` 函数会被调用，解析出 `1.5` 这个无单位的值。
2. `LineHeight::ApplyValue` 函数（可能在其他文件中）会根据这个值更新元素的 `ComputedStyle`。
3. 当需要获取 `line-height` 的计算值时（例如，渲染引擎需要知道每行的高度），`LineHeight::CSSValueFromComputedStyleInternal` 函数会被调用。
4. 由于输入的是一个无单位的值，计算值会是 `font-size` 的倍数，即 `1.5 * 16px = 24px`。

**假设输出:**

* `LineHeight::CSSValueFromComputedStyleInternal` 函数会返回一个表示 `24px` 的 `CSSValue` 对象。

**用户或编程常见的使用错误及举例说明:**

* **拼写错误或无效值:** 用户在编写 CSS 时可能会拼写错误属性名或提供无效的属性值。
    * **举例:**  用户可能会写 `margin-top: 10 px;` (多了空格) 或者 `line-height: abc;` (无效的值)。  解析函数 (`ParseSingleValue`) 会尝试处理这些错误，但如果完全无法解析，可能会忽略该声明或使用默认值。
* **类型不匹配:**  某些属性只接受特定类型的值。
    * **举例:** `line-clamp` 属性通常接受一个整数值。 如果用户尝试设置 `line-clamp: auto;` 但上下文不支持 `auto` (取决于浏览器版本和规范)，可能会导致解析错误或应用默认值。
* **遗漏单位:**  某些需要单位的属性，用户可能会忘记添加单位。
    * **举例:**  `margin-left: 10;`  解析器可能会根据上下文进行处理，但通常需要明确指定单位 (例如 `10px`, `10em`)。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户在 HTML 文件中编写 CSS 样式。** 例如，用户在 `<style>` 标签内或通过外部 CSS 文件添加了 `margin-top: 20px;` 这样的规则。
2. **浏览器加载 HTML 文件并解析 CSS。** 当浏览器解析到 `margin-top: 20px;` 时，会调用 `blink/renderer/core/css/parser/CSSParser.cc` 等文件中的 CSS 解析器。
3. **CSS 解析器识别出 `margin-top` 属性。**
4. **根据属性名，解析器会找到对应的长属性处理类 `MarginTop`。**
5. **`MarginTop::ParseSingleValue` 函数被调用，解析 `20px` 这个值。** 这会创建一个表示 `20px` 的 `CSSValue` 对象。
6. **在样式层叠和继承的过程中，`MarginTop::ApplyValue` (或相关的应用函数) 会被调用。**  这个函数会将解析出的值应用到当前元素的 `ComputedStyle` 对象中。
7. **当浏览器需要渲染该元素时，布局引擎会访问元素的 `ComputedStyle`。**
8. **如果需要获取 `margin-top` 的计算值 (例如，用于布局计算或通过 JavaScript 查询)，`MarginTop::CSSValueFromComputedStyleInternal` 函数会被调用。**

**功能归纳 (作为第7部分):**

作为 CSS 属性处理流程的第7部分，这个文件专注于**细粒度的CSS长属性的解析和应用逻辑**。 它负责将 CSS 文本值转换为内部表示，并将其应用于元素的样式计算中。  这个文件定义了各种独立 CSS 属性的具体行为，是构建浏览器样式系统的重要组成部分。 前面的部分可能涉及 CSS 语法解析、选择器匹配等，而后面的部分可能涉及样式的应用、布局计算和渲染等。

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
e &&
      identifier_value->GetValueID() == CSSValueID::kCurrentcolor) {
    ApplyInherit(state);
    return;
  }
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (value.IsInitialColorValue()) {
    DCHECK_EQ(state.GetElement(), state.GetDocument().documentElement());
    builder.SetInternalForcedColor(
        ComputedStyleInitialValues::InitialInternalForcedColor());
    return;
  }
  builder.SetInternalForcedColor(
      StyleBuilderConverter::ConvertStyleColor(state, value));
}

const blink::Color InternalForcedColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(!visited_link);
  return style.GetInternalForcedCurrentColor(is_current_color);
}

const CSSValue* InternalForcedColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return cssvalue::CSSColor::Create(
      allow_visited_style ? style.VisitedDependentColor(*this)
                          : style.GetInternalForcedCurrentColor());
}

const CSSValue* InternalForcedColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

const blink::Color InternalForcedOutlineColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  // No is_current_color here because we might not be current_color
  blink::Color current_color =
      visited_link ? style.GetInternalForcedVisitedCurrentColor()
                   : style.GetInternalForcedCurrentColor();

  return style.InternalForcedOutlineColor().Resolve(
      current_color, style.UsedColorScheme(), is_current_color);
}

const CSSValue* InternalForcedOutlineColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  bool visited_link = allow_visited_style &&
                      style.InsideLink() == EInsideLink::kInsideVisitedLink;
  return cssvalue::CSSColor::Create(
      ColorIncludingFallback(visited_link, style));
}

const CSSValue* InternalForcedOutlineColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

void InternalForcedVisitedColor::ApplyInitial(StyleResolverState& state) const {
  state.StyleBuilder().SetInternalForcedVisitedColor(
      ComputedStyleInitialValues::InitialInternalForcedVisitedColor());
}

void InternalForcedVisitedColor::ApplyInherit(StyleResolverState& state) const {
  auto color = state.ParentStyle()->InternalForcedVisitedColor();
  state.StyleBuilder().SetInternalForcedVisitedColor(color);
}

void InternalForcedVisitedColor::ApplyValue(StyleResolverState& state,
                                            const CSSValue& value,
                                            ValueMode) const {
  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  if (identifier_value &&
      identifier_value->GetValueID() == CSSValueID::kCurrentcolor) {
    ApplyInherit(state);
    return;
  }
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (value.IsInitialColorValue()) {
    DCHECK_EQ(state.GetElement(), state.GetDocument().documentElement());
    builder.SetInternalForcedVisitedColor(
        ComputedStyleInitialValues::InitialInternalForcedVisitedColor());
    return;
  }
  builder.SetInternalForcedVisitedColor(
      StyleBuilderConverter::ConvertStyleColor(state, value, true));
}

const blink::Color InternalForcedVisitedColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  DCHECK(visited_link);
  return style.GetInternalForcedVisitedCurrentColor(is_current_color);
}

const CSSValue* InternalForcedVisitedColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

const CSSValue* Interactivity::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Interactivity());
}

const CSSValue* InterpolateSize::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.InterpolateSize());
}

const CSSValue* Isolation::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.Isolation());
}

const CSSValue* JustifyContent::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // justify-content property does not allow the <baseline-position> values.
  if (css_parsing_utils::IdentMatches<CSSValueID::kFirst, CSSValueID::kLast,
                                      CSSValueID::kBaseline>(
          stream.Peek().Id())) {
    return nullptr;
  }
  return css_parsing_utils::ConsumeContentDistributionOverflowPosition(
      stream, css_parsing_utils::IsContentPositionOrLeftOrRightKeyword);
}

const CSSValue* JustifyContent::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::
      ValueForContentPositionAndDistributionWithOverflowAlignment(
          style.JustifyContent());
}

const CSSValue* JustifyItems::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSParserTokenStream::State savepoint = stream.Save();
  // justify-items property does not allow the 'auto' value.
  if (css_parsing_utils::IdentMatches<CSSValueID::kAuto>(stream.Peek().Id())) {
    return nullptr;
  }
  CSSIdentifierValue* legacy =
      css_parsing_utils::ConsumeIdent<CSSValueID::kLegacy>(stream);
  CSSIdentifierValue* position_keyword =
      css_parsing_utils::ConsumeIdent<CSSValueID::kCenter, CSSValueID::kLeft,
                                      CSSValueID::kRight>(stream);
  if (!legacy) {
    legacy = css_parsing_utils::ConsumeIdent<CSSValueID::kLegacy>(stream);
  }
  if (!legacy) {
    stream.Restore(savepoint);
  }
  if (legacy) {
    if (position_keyword) {
      context.Count(WebFeature::kCSSLegacyAlignment);
      return MakeGarbageCollected<CSSValuePair>(
          legacy, position_keyword, CSSValuePair::kDropIdenticalValues);
    }
    return legacy;
  }

  return css_parsing_utils::ConsumeSelfPositionOverflowPosition(
      stream, css_parsing_utils::IsSelfPositionOrLeftOrRightKeyword);
}

const CSSValue* JustifyItems::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForItemPositionWithOverflowAlignment(
      style.JustifyItems().GetPosition() == ItemPosition::kAuto
          ? ComputedStyleInitialValues::InitialDefaultAlignment()
          : style.JustifyItems());
}

const CSSValue* JustifySelf::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSelfPositionOverflowPosition(
      stream, css_parsing_utils::IsSelfPositionOrLeftOrRightKeyword);
}

const CSSValue* JustifySelf::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForItemPositionWithOverflowAlignment(
      style.JustifySelf());
}

const CSSValue* Left::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? kCSSAnchorQueryTypesAll
          : static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchor);
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context,
      css_parsing_utils::UnitlessUnlessShorthand(local_context), anchor_types);
}

bool Left::IsLayoutDependent(const ComputedStyle* style,
                             LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* Left::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForPositionOffset(style, *this,
                                                    layout_object);
}

const CSSValue* LetterSpacing::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ParseSpacing(stream, context);
}

const CSSValue* LetterSpacing::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.LetterSpacing()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }
  return ZoomAdjustedPixelValue(style.LetterSpacing(), style);
}

const CSSValue* LightingColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColor(stream, context);
}

const blink::Color LightingColor::ColorIncludingFallback(
    bool visited_link,
    const ComputedStyle& style,
    bool* is_current_color) const {
  const StyleColor& lighting_color = style.LightingColor();
  if (style.ShouldForceColor(lighting_color)) {
    return style.GetInternalForcedCurrentColor(is_current_color);
  }
  return style.ResolvedColor(lighting_color, is_current_color);
}

const CSSValue* LightingColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::CurrentColorOrValidColor(
      style, style.LightingColor(), value_phase);
}

const CSSValue* LineBreak::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.GetLineBreak());
}

void LineClamp::ApplyInitial(StyleResolverState& state) const {
  // initial needs to be customized so it doesn't default to `auto`.
  state.StyleBuilder().SetStandardLineClamp(0);
}

const CSSValue* LineClamp::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone ||
      stream.Peek().Id() == CSSValueID::kAuto) {
    return css_parsing_utils::ConsumeIdent(stream);
  } else {
    return css_parsing_utils::ConsumePositiveInteger(stream, context);
  }
}

const CSSValue* LineClamp::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.HasAutoStandardLineClamp()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (style.StandardLineClamp() == 0) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  return CSSNumericLiteralValue::Create(style.StandardLineClamp(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

const CSSValue* LineHeight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeLineHeight(stream, context);
}

const CSSValue* LineHeight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (value_phase == CSSValuePhase::kComputedValue) {
    return ComputedStyleUtils::ComputedValueForLineHeight(style);
  }
  return ComputedStyleUtils::ValueForLineHeight(style);
}

const CSSValue* ListStyleImage::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeImageOrNone(stream, context);
}

const CSSValue* ListStyleImage::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (style.ListStyleImage()) {
    return style.ListStyleImage()->ComputedCSSValue(style, allow_visited_style,
                                                    value_phase);
  }
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

void ListStyleImage::ApplyValue(StyleResolverState& state,
                                const CSSValue& value,
                                ValueMode) const {
  state.StyleBuilder().SetListStyleImage(
      state.GetStyleImage(CSSPropertyID::kListStyleImage, value));
}

const CSSValue* ListStylePosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.ListStylePosition());
}

const CSSValue* ListStyleType::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (auto* none = css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream)) {
    return none;
  }

  if (auto* counter_style_name =
          css_parsing_utils::ConsumeCounterStyleName(stream, context)) {
    return counter_style_name;
  }

  return css_parsing_utils::ConsumeString(stream);
}

const CSSValue* ListStyleType::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.ListStyleType()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  const ListStyleTypeData& list_style_type = *style.ListStyleType();
  if (list_style_type.IsString()) {
    return MakeGarbageCollected<CSSStringValue>(
        list_style_type.GetStringValue());
  }
  return &MakeGarbageCollected<CSSCustomIdentValue>(
              list_style_type.GetCounterStyleName())
              ->PopulateWithTreeScope(list_style_type.GetTreeScope());
}

void ListStyleType::ApplyValue(StyleResolverState& state,
                               const CSSValue& value,
                               ValueMode) const {
  DCHECK(value.IsScopedValue());
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK_EQ(CSSValueID::kNone, identifier_value->GetValueID());
    builder.SetListStyleType(nullptr);
    return;
  }

  if (const auto* string_value = DynamicTo<CSSStringValue>(value)) {
    builder.SetListStyleType(
        ListStyleTypeData::CreateString(AtomicString(string_value->Value())));
    return;
  }

  DCHECK(value.IsCustomIdentValue());
  const auto& custom_ident_value = To<CSSCustomIdentValue>(value);
  // “The non-overridable counter-style names are the keywords decimal,
  // disc, square, circle, disclosure-open, and disclosure-closed.”
  //
  // NOTE: Keep in sync with ConsumeCounterStyleNameInPrelude().
  //
  // https://drafts.csswg.org/css-counter-styles/#the-counter-style-rule
  if (custom_ident_value.Value() != keywords::kDecimal &&
      custom_ident_value.Value() != keywords::kDisc &&
      custom_ident_value.Value() != keywords::kSquare &&
      custom_ident_value.Value() != keywords::kCircle &&
      custom_ident_value.Value() != keywords::kDisclosureOpen &&
      custom_ident_value.Value() != keywords::kDisclosureClosed) {
    state.SetHasTreeScopedReference();
  }
  builder.SetListStyleType(ListStyleTypeData::CreateCounterStyle(
      custom_ident_value.Value(), custom_ident_value.GetTreeScope()));
}

bool MarginBlockEnd::IsLayoutDependent(const ComputedStyle* style,
                                       LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* MarginBlockEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

bool MarginBlockStart::IsLayoutDependent(const ComputedStyle* style,
                                         LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* MarginBlockStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

const CSSValue* MarginBottom::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow, anchor_types);
}

bool MarginBottom::IsLayoutDependent(const ComputedStyle* style,
                                     LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* MarginBottom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (const LayoutBox* box = DynamicTo<LayoutBox>(layout_object)) {
    if (!style.MarginBottom().IsFixed()) {
      return ZoomAdjustedPixelValue(box->MarginBottom(), style);
    }
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.MarginBottom(), style);
}

bool MarginInlineEnd::IsLayoutDependent(const ComputedStyle* style,
                                        LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* MarginInlineEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

bool MarginInlineStart::IsLayoutDependent(const ComputedStyle* style,
                                          LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox();
}

const CSSValue* MarginInlineStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kForbid, anchor_types);
}

const CSSValue* MarginLeft::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow, anchor_types);
}

bool MarginLeft::IsLayoutDependent(const ComputedStyle* style,
                                   LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->MarginLeft().IsFixed());
}

const CSSValue* MarginLeft::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (const LayoutBox* box = DynamicTo<LayoutBox>(layout_object)) {
    if (!style.MarginLeft().IsFixed()) {
      return ZoomAdjustedPixelValue(box->MarginLeft(), style);
    }
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.MarginLeft(),
                                                             style);
}

const CSSValue* MarginRight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow, anchor_types);
}

bool MarginRight::IsLayoutDependent(const ComputedStyle* style,
                                    LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->MarginRight().IsFixed());
}

const CSSValue* MarginRight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (const LayoutBox* box = DynamicTo<LayoutBox>(layout_object)) {
    if (!style.MarginRight().IsFixed()) {
      return ZoomAdjustedPixelValue(box->MarginRight(), style);
    }
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
      style.MarginRight(), style);
}

const CSSValue* MarginTop::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  CSSAnchorQueryTypes anchor_types =
      RuntimeEnabledFeatures::CSSAnchorSizeInsetsMarginsEnabled()
          ? static_cast<CSSAnchorQueryTypes>(CSSAnchorQueryType::kAnchorSize)
          : kCSSAnchorQueryTypesNone;
  return css_parsing_utils::ConsumeMarginOrOffset(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow, anchor_types);
}

bool MarginTop::IsLayoutDependent(const ComputedStyle* style,
                                  LayoutObject* layout_object) const {
  return layout_object && layout_object->IsBox() &&
         (!style || !style->MarginTop().IsFixed());
}

const CSSValue* MarginTop::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (const LayoutBox* box = DynamicTo<LayoutBox>(layout_object)) {
    if (!style.MarginTop().IsFixed()) {
      return ZoomAdjustedPixelValue(box->MarginTop(), style);
    }
  }
  return ComputedStyleUtils::ZoomAdjustedPixelValueForLength(style.MarginTop(),
                                                             style);
}

const CSSValue* MarkerEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeUrl(stream, context);
}

const CSSValue* MarkerEnd::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForSVGResource(style.MarkerEndResource());
}

void MarkerEnd::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  state.StyleBuilder().SetMarkerEndResource(
      StyleBuilderConverter::ConvertElementReference(state, value,
                                                     PropertyID()));
}

const CSSValue* MarkerMid::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeUrl(stream, context);
}

const CSSValue* MarkerMid::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForSVGResource(style.MarkerMidResource());
}

void MarkerMid::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  state.StyleBuilder().SetMarkerMidResource(
      StyleBuilderConverter::ConvertElementReference(state, value,
                                                     PropertyID()));
}

const CSSValue* MarkerStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return css_parsing_utils::ConsumeIdent(stream);
  }
  return css_parsing_utils::ConsumeUrl(stream, context);
}

const CSSValue* MarkerStart::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForSVGResource(style.MarkerStartResource());
}

void MarkerStart::ApplyValue(StyleResolverState& state,
                             const CSSValue& value,
                             ValueMode) const {
  state.StyleBuilder().SetMarkerStartResource(
      StyleBuilderConverter::ConvertElementReference(state, value,
                                                     PropertyID()));
}

const CSSValue* MaskType::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.MaskType());
}

const CSSValue* MasonrySlack::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeMasonrySlack(stream, context);
}

const CSSValue* MasonrySlack::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForMasonrySlack(style.MasonrySlack(), style);
}

const CSSValue* MasonryTemplateTracks::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridTemplatesRowsOrColumns(stream, context);
}

bool MasonryTemplateTracks::IsLayoutDependent(
    const ComputedStyle* style,
    LayoutObject* layout_object) const {
  return layout_object && layout_object->IsLayoutMasonry();
}

const CSSValue* MasonryTemplateTracks::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForMasonryTrackList(layout_object, style);
}

const CSSValue* MasonryTemplateTracks::InitialValue() const {
  auto* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
  return list;
}

const CSSValue* MasonryTrackEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridLine(stream, context);
}

const CSSValue* MasonryTrackEnd::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridPosition(style.MasonryTrackEnd());
}

const CSSValue* MasonryTrackStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeGridLine(stream, context);
}

const CSSValue* MasonryTrackStart::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForGridPosition(style.MasonryTrackStart());
}

const CSSValue* MathShift::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.MathShift());
}

const CSSValue* MathStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.MathStyle());
}

const CSSValue* MathDepth::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeMathDepth(stream, context);
}

const CSSValue* MathDepth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSNumericLiteralValue::Create(style.MathDepth(),
                                        CSSPrimitiveValue::UnitType::kNumber);
}

void MathDepth::ApplyValue(StyleResolverState& state,
                           const CSSValue& value,
                           ValueMode) const {
  ComputedStyleBuilder& builder = state.StyleBuilder();
  if (const auto* list = DynamicTo<CSSValueList>(value)) {
    DCHECK_EQ(list->length(), 1U);
    const auto& relative_value = To<CSSPrimitiveValue>(list->Item(0));
    builder.SetMathDepth(base::ClampAdd(
        state.ParentStyle()->MathDepth(),
        relative_value.ComputeInteger(state.CssToLengthConversionData())));
  } else if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    DCHECK(identifier_value->GetValueID() == CSSValueID::kAutoAdd);
    int16_t depth = 0;
    if (state.ParentStyle()->MathStyle() == EMathStyle::kCompact) {
      depth += 1;
    }
    builder.SetMathDepth(
        base::ClampAdd(state.ParentStyle()->MathDepth(), depth));
  } else if (DynamicTo<CSSPrimitiveValue>(value)) {
    builder.SetMathDepth(
        ClampTo<int16_t>(To<CSSPrimitiveValue>(value).ComputeInteger(
            state.CssToLengthConversionData())));
  }
}

const CSSValue* MaxBlockSize::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeMaxWidthOrHeight(stream, context);
}

const CSSValue* MaxHeight::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeMaxWidthOrHeight(
      stream, context, css_parsing_utils::UnitlessQuirk::kAllow);
}

const CSSValue* MaxHeight::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const
```