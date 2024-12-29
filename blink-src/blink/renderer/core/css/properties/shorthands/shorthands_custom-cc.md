Response:
The user wants to understand the functionality of the `shorthands_custom.cc` file in the Chromium Blink rendering engine. This file seems to be responsible for implementing the parsing and computed style value generation for CSS shorthand properties that require custom logic beyond the automatically generated implementations.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename and the `#include` directives strongly suggest this file deals with CSS shorthand properties. The "custom" part implies that these shorthands need special handling beyond the default parsing and computation.

2. **Scan for key function types:**  Look for functions that indicate the main actions performed by this code. The presence of `ParseShorthand` and `CSSValueFromComputedStyleInternal` is a strong indicator of parsing and computed value generation.

3. **Analyze `ParseShorthand` functions:** Examine the implementations of these functions. They take a token stream, parser context, and a vector to store parsed properties. They call helper functions like `css_parsing_utils::Consume...` to parse specific CSS values. This confirms their role in parsing shorthand syntax into individual longhand properties.

4. **Analyze `CSSValueFromComputedStyleInternal` functions:** These functions take a `ComputedStyle` object and potentially a `LayoutObject`. They return a `CSSValue`. This confirms their role in generating the CSS value representation of a shorthand property based on the computed styles of the element. They often call helper functions like `ComputedStyleUtils::ValuesFor...`.

5. **Relate to CSS functionality:** Connect the functions and included headers to core CSS concepts. The file deals with parsing CSS syntax (`CSSParserTokenStream`), understanding CSS contexts (`CSSParserContext`), and manipulating CSS values (`CSSValue`, `CSSValueList`). The generated values are used in the computed style of elements, directly affecting how elements are rendered.

6. **Find relationships with JavaScript and HTML:** CSS is directly linked to HTML through the `<style>` tag and the `style` attribute. JavaScript can manipulate CSS properties via the DOM's `style` object or the CSSOM. The code in this file is part of the engine that makes these interactions possible.

7. **Construct examples:**  Based on the identified functionalities, create concrete examples of how these shorthands are used in HTML and how the parsing logic in this file would handle them.

8. **Consider error scenarios:** Think about common mistakes developers make when using CSS shorthands and how the parsing logic might handle them (e.g., invalid values, missing components).

9. **Trace user interaction:** Imagine how a user's action in a browser leads to this code being executed. Typing CSS in the developer tools or loading a webpage with CSS are obvious entry points.

10. **Synthesize the summary:** Condense the findings into a concise summary that captures the main purpose of the file.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  The file just parses shorthands.
* **Correction:**  Realized it also generates computed style values, which is crucial for the rendering process.
* **Initial thought:**  Focus on individual shorthands in isolation.
* **Refinement:**  Recognized the common patterns and the role of `css_parsing_utils` and `ComputedStyleUtils`.
* **Initial thought:**  Examples are obvious.
* **Refinement:**  Made the examples more specific and illustrative of the parsing process.

By following these steps, the detailed and accurate explanation of the file's functionality can be generated, addressing all the user's specific requests.
这个`shorthands_custom.cc`文件的功能是为Chromium Blink引擎中的**自定义CSS简写属性**提供**解析**和**计算样式值**的功能。

更具体地说，它做了以下事情：

1. **解析CSS简写语法:**  它包含了各种CSS简写属性的`ParseShorthand`方法的实现。这些方法接收CSS解析器生成的token流，并将其解析成对应的多个CSS长属性的值。
2. **生成计算后的CSS值:**  它包含了各种CSS简写属性的`CSSValueFromComputedStyleInternal`方法的实现。这些方法根据元素的计算样式（`ComputedStyle`）以及可能的布局对象（`LayoutObject`），生成该简写属性对应的`CSSValue`。这用于在浏览器渲染时确定元素的最终样式。

**与JavaScript, HTML, CSS的功能关系及举例说明:**

* **CSS:**  这是直接相关的。该文件处理的是CSS简写属性。
    * **示例:**  考虑CSS简写属性 `animation`。
        * HTML: `<div style="animation: slide 1s ease-in-out;"></div>`
        * CSS:
          ```css
          .my-element {
            animation: slide 1s ease-in-out;
          }
          ```
        * `ParseShorthand` 功能会解析字符串 `"slide 1s ease-in-out"`，并将其分解为 `animation-name: slide; animation-duration: 1s; animation-timing-function: ease-in-out;` 等长属性的值。
        * `CSSValueFromComputedStyleInternal` 功能会根据计算出的 `animation-name`, `animation-duration` 等长属性的值，重新构建 `animation` 简写属性的 `CSSValue` 表示。

* **HTML:**  HTML中通过 `<style>` 标签或元素的 `style` 属性来应用CSS样式，最终这些样式会传递给Blink引擎进行解析和渲染。
    * **示例:** 上面的HTML示例直接使用了 `animation` 简写属性。浏览器加载这个HTML时，Blink引擎会调用 `ParseShorthand` 来解析 `animation` 属性。

* **JavaScript:** JavaScript 可以通过 DOM API 来操作元素的样式，包括设置和获取CSS简写属性的值。
    * **示例:**
      ```javascript
      const element = document.querySelector('div');
      element.style.animation = 'fade 2s linear'; // 设置简写属性
      const animationValue = getComputedStyle(element).animation; // 获取简写属性的计算值
      console.log(animationValue); // 输出类似 "fade 2s linear 0s ease 0s 1 normal forwards running"
      ```
      当JavaScript设置 `element.style.animation` 时，Blink引擎会调用相应的 `ParseShorthand` 方法。当 JavaScript 调用 `getComputedStyle` 获取 `animation` 属性时，Blink引擎会调用 `CSSValueFromComputedStyleInternal` 方法来生成计算后的值。

**逻辑推理，假设输入与输出:**

假设输入一段CSS样式字符串，包含 `border-block` 简写属性：

**假设输入:**  `"border-block: 1px solid red;"`

**`ParseShorthand` 功能的输出 (简化):**

* 会解析出三个长属性及其值:
    * `CSSPropertyID::kBorderBlockWidth`:  表示 `1px` 的 `CSSValue` 对象
    * `CSSPropertyID::kBorderBlockStyle`: 表示 `solid` 的 `CSSValue` 对象
    * `CSSPropertyID::kBorderBlockColor`: 表示 `red` 的 `CSSValue` 对象

**`CSSValueFromComputedStyleInternal` 功能的假设输入和输出:**

**假设输入:** 一个 `ComputedStyle` 对象，其中 `border-block-start-width`, `border-block-start-style`, `border-block-start-color` 的计算值分别为 1px, solid, red，并且 `border-block-end-*` 的值与之相同。

**输出:**  一个表示 `"1px solid red"` 的 `CSSValue` 对象。如果 `border-block-start` 和 `border-block-end` 的值不一致，则该方法可能会返回 `nullptr`，因为简写属性无法完全表示这种情况。

**涉及用户或者编程常见的使用错误，举例说明:**

* **错误的简写属性值顺序:**  例如，对于 `border` 属性，用户可能会错误地写成 `border: red solid 1px;`  而不是 `border: 1px solid red;`。 `ParseShorthand` 方法需要能够正确处理或拒绝这种错误的顺序。
* **缺少必要的组成部分:** 例如，对于 `animation` 属性，只写 `animation: 2s;` 缺少了 `animation-name`。`ParseShorthand` 方法需要处理这种情况，通常会使用默认值或者报告解析错误。
* **提供了过多的值:**  例如，对于 `margin` 属性，如果提供了五个值而不是四个、三个、两个或一个，`ParseShorthand` 需要能够识别并处理这种错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在HTML文件中编写CSS样式:**  例如，在 `<style>` 标签内或元素的 `style` 属性中使用了 `animation: slide 1s ease-in-out;`。
2. **浏览器加载HTML文件并解析:**  当浏览器加载到包含这段CSS的HTML时，渲染引擎（Blink）的CSS解析器开始工作。
3. **CSS解析器遇到简写属性:**  解析器识别出 `animation` 是一个简写属性。
4. **查找对应的 `ParseShorthand` 方法:**  Blink引擎会查找 `blink/renderer/core/css/properties/shorthands/shorthands_custom.cc` 文件中 `Animation::ParseShorthand` 方法。
5. **调用 `ParseShorthand` 进行解析:**  解析器将CSS属性值（例如 `"slide 1s ease-in-out"`)作为token流传递给 `ParseShorthand` 方法。
6. **`ParseShorthand` 解析并创建长属性值:**  该方法内部会调用 `css_parsing_utils::ConsumeAnimationShorthand` 等工具函数，将简写值分解为 `animation-name`, `animation-duration` 等长属性对应的 `CSSValue` 对象，并将这些值添加到 `properties` 向量中。
7. **计算样式:**  在布局阶段或JavaScript请求计算样式时，如果需要获取 `animation` 属性的计算值，Blink引擎会调用 `Animation::CSSValueFromComputedStyleInternal` 方法。
8. **`CSSValueFromComputedStyleInternal` 根据长属性值生成简写值:**  该方法会读取 `ComputedStyle` 中 `animation-*` 长属性的值，并将它们组合成 `animation` 简写属性的 `CSSValue` 表示。

**归纳一下它的功能 (第1部分):**

这个文件的主要功能是为一部分自定义的CSS简写属性提供**解析CSS语法**的功能，将简写属性的值分解为对应的长属性值，以便Blink引擎理解和应用这些样式。它负责将用户在CSS中书写的简写形式转换为引擎内部更容易处理的多个长属性表示。

Prompt: 
```
这是目录为blink/renderer/core/css/properties/shorthands/shorthands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/animation/timeline_offset.h"
#include "third_party/blink/renderer/core/css/css_content_distribution_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_initial_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_pending_system_font_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_property_value.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_fast_paths.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_save_point.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_alternates_parser.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_east_asian_parser.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_ligatures_parser.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_numeric_parser.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhand.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/properties/shorthands.h"
#include "third_party/blink/renderer/core/css/zoom_adjusted_pixel_value.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"

// Implementations of methods in Shorthand subclasses that aren't generated.

namespace blink {
namespace css_shorthand {

namespace {

// New animation-* properties are  "reset only":
// https://github.com/w3c/csswg-drafts/issues/6946#issuecomment-1233190360
bool IsResetOnlyAnimationProperty(CSSPropertyID property) {
  switch (property) {
    case CSSPropertyID::kAnimationTimeline:
    case CSSPropertyID::kAnimationRangeStart:
    case CSSPropertyID::kAnimationRangeEnd:
      return true;
    default:
      return false;
  }
}

// Legacy parsing allows <string>s for animation-name.
CSSValue* ConsumeAnimationValue(CSSPropertyID property,
                                CSSParserTokenStream& stream,
                                const CSSParserContext& context,
                                bool use_legacy_parsing) {
  switch (property) {
    case CSSPropertyID::kAnimationDelay:
      return css_parsing_utils::ConsumeTime(
          stream, context, CSSPrimitiveValue::ValueRange::kAll);
    case CSSPropertyID::kAnimationDirection:
      return css_parsing_utils::ConsumeIdent<
          CSSValueID::kNormal, CSSValueID::kAlternate, CSSValueID::kReverse,
          CSSValueID::kAlternateReverse>(stream);
    case CSSPropertyID::kAnimationDuration:
      return css_parsing_utils::ConsumeAnimationDuration(stream, context);
    case CSSPropertyID::kAnimationFillMode:
      return css_parsing_utils::ConsumeIdent<
          CSSValueID::kNone, CSSValueID::kForwards, CSSValueID::kBackwards,
          CSSValueID::kBoth>(stream);
    case CSSPropertyID::kAnimationIterationCount:
      return css_parsing_utils::ConsumeAnimationIterationCount(stream, context);
    case CSSPropertyID::kAnimationName:
      return css_parsing_utils::ConsumeAnimationName(stream, context,
                                                     use_legacy_parsing);
    case CSSPropertyID::kAnimationPlayState:
      return css_parsing_utils::ConsumeIdent<CSSValueID::kRunning,
                                             CSSValueID::kPaused>(stream);
    case CSSPropertyID::kAnimationTimingFunction:
      return css_parsing_utils::ConsumeAnimationTimingFunction(stream, context);
    case CSSPropertyID::kAnimationTimeline:
    case CSSPropertyID::kAnimationRangeStart:
    case CSSPropertyID::kAnimationRangeEnd:
      // New animation-* properties are  "reset only", see
      // IsResetOnlyAnimationProperty.
      DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());
      return nullptr;
    default:
      NOTREACHED();
  }
}

bool ParseAnimationShorthand(const StylePropertyShorthand& shorthand,
                             bool important,
                             CSSParserTokenStream& stream,
                             const CSSParserContext& context,
                             const CSSParserLocalContext& local_context,
                             HeapVector<CSSPropertyValue, 64>& properties) {
  const unsigned longhand_count = shorthand.length();

  HeapVector<Member<CSSValueList>, css_parsing_utils::kMaxNumAnimationLonghands>
      longhands(longhand_count);
  if (!css_parsing_utils::ConsumeAnimationShorthand(
          shorthand, longhands, ConsumeAnimationValue,
          IsResetOnlyAnimationProperty, stream, context,
          local_context.UseAliasParsing())) {
    return false;
  }

  for (unsigned i = 0; i < longhand_count; ++i) {
    css_parsing_utils::AddProperty(
        shorthand.properties()[i]->PropertyID(), shorthand.id(), *longhands[i],
        important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
        properties);
  }
  return true;
}

const CSSValue* CSSValueFromComputedAnimation(
    const StylePropertyShorthand& shorthand,
    const CSSAnimationData* animation_data) {
  if (animation_data) {
    // The shorthand can not represent the following properties if they have
    // non-initial values. This is because they are always reset to their
    // initial value by the shorthand.
    if (!animation_data->HasSingleInitialTimeline() ||
        !animation_data->HasSingleInitialDelayEnd() ||
        !animation_data->HasSingleInitialRangeStart() ||
        !animation_data->HasSingleInitialRangeEnd()) {
      return nullptr;
    }

    CSSValueList* animations_list = CSSValueList::CreateCommaSeparated();
    for (wtf_size_t i = 0; i < animation_data->NameList().size(); ++i) {
      CSSValueList* list = CSSValueList::CreateSpaceSeparated();
      list->Append(*ComputedStyleUtils::ValueForAnimationDuration(
          CSSTimingData::GetRepeated(animation_data->DurationList(), i),
          /* resolve_auto_to_zero */ true));
      list->Append(*ComputedStyleUtils::ValueForAnimationTimingFunction(
          CSSTimingData::GetRepeated(animation_data->TimingFunctionList(), i)));
      list->Append(*ComputedStyleUtils::ValueForAnimationDelay(
          CSSTimingData::GetRepeated(animation_data->DelayStartList(), i)));
      list->Append(*ComputedStyleUtils::ValueForAnimationIterationCount(
          CSSTimingData::GetRepeated(animation_data->IterationCountList(), i)));
      list->Append(*ComputedStyleUtils::ValueForAnimationDirection(
          CSSTimingData::GetRepeated(animation_data->DirectionList(), i)));
      list->Append(*ComputedStyleUtils::ValueForAnimationFillMode(
          CSSTimingData::GetRepeated(animation_data->FillModeList(), i)));
      list->Append(*ComputedStyleUtils::ValueForAnimationPlayState(
          CSSTimingData::GetRepeated(animation_data->PlayStateList(), i)));
      list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(
          animation_data->NameList()[i]));
      animations_list->Append(*list);
    }
    return animations_list;
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  // animation-name default value.
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
  list->Append(*ComputedStyleUtils::ValueForAnimationDuration(
      CSSAnimationData::InitialDuration(),
      /* resolve_auto_to_zero */ true));
  list->Append(*ComputedStyleUtils::ValueForAnimationTimingFunction(
      CSSAnimationData::InitialTimingFunction()));
  list->Append(*ComputedStyleUtils::ValueForAnimationDelay(
      CSSAnimationData::InitialDelayStart()));
  list->Append(*ComputedStyleUtils::ValueForAnimationIterationCount(
      CSSAnimationData::InitialIterationCount()));
  list->Append(*ComputedStyleUtils::ValueForAnimationDirection(
      CSSAnimationData::InitialDirection()));
  list->Append(*ComputedStyleUtils::ValueForAnimationFillMode(
      CSSAnimationData::InitialFillMode()));
  list->Append(*ComputedStyleUtils::ValueForAnimationPlayState(
      CSSAnimationData::InitialPlayState()));
  return list;
}

bool ParseBackgroundOrMaskPosition(
    const StylePropertyShorthand& shorthand,
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    std::optional<WebFeature> three_value_position,
    HeapVector<CSSPropertyValue, 64>& properties) {
  const CSSValue* result_x = nullptr;
  const CSSValue* result_y = nullptr;
  if (!css_parsing_utils::ConsumeBackgroundPosition(
          stream, context, css_parsing_utils::UnitlessQuirk::kAllow,
          three_value_position, result_x, result_y)) {
    return false;
  }
  const StylePropertyShorthand::Properties& longhands = shorthand.properties();
  DCHECK_EQ(2u, longhands.size());
  css_parsing_utils::AddProperty(
      longhands[0]->PropertyID(), shorthand.id(), *result_x, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  css_parsing_utils::AddProperty(
      longhands[1]->PropertyID(), shorthand.id(), *result_y, important,
      css_parsing_utils::IsImplicitProperty::kNotImplicit, properties);
  return true;
}

}  // namespace

bool Animation::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return ParseAnimationShorthand(animationShorthand(), important, stream,
                                 context, local_context, properties);
}

const CSSValue* Animation::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSValueFromComputedAnimation(animationShorthand(),
                                       style.Animations());
}

bool AlternativeAnimationWithTimeline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return ParseAnimationShorthand(alternativeAnimationWithTimelineShorthand(),
                                 important, stream, context, local_context,
                                 properties);
}

const CSSValue*
AlternativeAnimationWithTimeline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSValueFromComputedAnimation(
      alternativeAnimationWithTimelineShorthand(), style.Animations());
}

namespace {

// Consume a single <animation-range-start> and a single
// <animation-range-end>, and append the result to `start_list` and
// `end_list` respectively.
bool ConsumeAnimationRangeItemInto(CSSParserTokenStream& stream,
                                   const CSSParserContext& context,
                                   CSSValueList* start_list,
                                   CSSValueList* end_list) {
  using css_parsing_utils::ConsumeAnimationRange;
  using css_parsing_utils::ConsumeTimelineRangeName;

  const CSSValue* start_range =
      ConsumeAnimationRange(stream, context, /* default_offset_percent */ 0.0);
  const CSSValue* end_range = ConsumeAnimationRange(
      stream, context, /* default_offset_percent */ 100.0);

  // The form 'name X' must expand to 'name X name 100%'.
  //
  // https://github.com/w3c/csswg-drafts/issues/8438
  if (start_range && start_range->IsValueList() && !end_range) {
    CSSValueList* implied_end = CSSValueList::CreateSpaceSeparated();
    const CSSValue& name = To<CSSValueList>(start_range)->First();
    if (name.IsIdentifierValue()) {
      implied_end->Append(name);
      end_range = implied_end;
    }
  }

  if (!start_range) {
    return false;
  }
  if (!end_range) {
    end_range = CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  DCHECK(start_range);
  DCHECK(end_range);

  start_list->Append(*start_range);
  end_list->Append(*end_range);

  return true;
}

}  // namespace

bool AnimationRange::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());

  using css_parsing_utils::AddProperty;
  using css_parsing_utils::ConsumeCommaIncludingWhitespace;
  using css_parsing_utils::IsImplicitProperty;

  const StylePropertyShorthand shorthand = animationRangeShorthand();
  DCHECK_EQ(2u, shorthand.length());
  DCHECK_EQ(&GetCSSPropertyAnimationRangeStart(), shorthand.properties()[0]);
  DCHECK_EQ(&GetCSSPropertyAnimationRangeEnd(), shorthand.properties()[1]);

  CSSValueList* start_list = CSSValueList::CreateCommaSeparated();
  CSSValueList* end_list = CSSValueList::CreateCommaSeparated();

  do {
    if (!ConsumeAnimationRangeItemInto(stream, context, start_list, end_list)) {
      return false;
    }
  } while (ConsumeCommaIncludingWhitespace(stream));

  DCHECK(start_list->length());
  DCHECK(end_list->length());
  DCHECK_EQ(start_list->length(), end_list->length());

  AddProperty(CSSPropertyID::kAnimationRangeStart,
              CSSPropertyID::kAnimationRange, *start_list, important,
              IsImplicitProperty::kNotImplicit, properties);
  AddProperty(CSSPropertyID::kAnimationRangeEnd, CSSPropertyID::kAnimationRange,
              *end_list, important, IsImplicitProperty::kNotImplicit,
              properties);

  return true;
}

const CSSValue* AnimationRange::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const Vector<std::optional<TimelineOffset>>& range_start_list =
      style.Animations() ? style.Animations()->RangeStartList()
                         : Vector<std::optional<TimelineOffset>>{
                               CSSAnimationData::InitialRangeStart()};
  const Vector<std::optional<TimelineOffset>>& range_end_list =
      style.Animations() ? style.Animations()->RangeEndList()
                         : Vector<std::optional<TimelineOffset>>{
                               CSSAnimationData::InitialRangeEnd()};

  if (range_start_list.size() != range_end_list.size()) {
    return nullptr;
  }

  TimelineOffset default_start(TimelineOffset::NamedRange::kNone,
                               Length::Percent(0));
  TimelineOffset default_end(TimelineOffset::NamedRange::kNone,
                             Length::Percent(100));

  auto* outer_list = CSSValueList::CreateCommaSeparated();

  for (wtf_size_t i = 0; i < range_start_list.size(); ++i) {
    const std::optional<TimelineOffset>& start = range_start_list[i];
    const std::optional<TimelineOffset>& end = range_end_list[i];

    auto* inner_list = CSSValueList::CreateSpaceSeparated();
    inner_list->Append(
        *ComputedStyleUtils::ValueForAnimationRangeStart(start, style));

    // The form "name X name 100%" must contract to "name X".
    //
    // https://github.com/w3c/csswg-drafts/issues/8438
    TimelineOffset omittable_end(start.value_or(default_start).name,
                                 Length::Percent(100));
    if (end.value_or(default_end) != omittable_end) {
      inner_list->Append(
          *ComputedStyleUtils::ValueForAnimationRangeEnd(end, style));
    }
    outer_list->Append(*inner_list);
  }

  return outer_list;
}

bool Background::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ParseBackgroundOrMask(important, stream, context,
                                                  local_context, properties);
}

const CSSValue* Background::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForBackgroundShorthand(
      style, layout_object, allow_visited_style, value_phase);
}

bool BackgroundPosition::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return ParseBackgroundOrMaskPosition(
      backgroundPositionShorthand(), important, stream, context,
      WebFeature::kThreeValuedPositionBackground, properties);
}

const CSSValue* BackgroundPosition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::BackgroundPositionOrMaskPosition(
      *this, style, &style.BackgroundLayers());
}

bool BorderBlockColor::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      borderBlockColorShorthand(), important, context, stream, properties);
}

const CSSValue* BorderBlockColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      borderBlockColorShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderBlock::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* width = nullptr;
  const CSSValue* style = nullptr;
  const CSSValue* color = nullptr;

  if (!css_parsing_utils::ConsumeBorderShorthand(stream, context, local_context,
                                                 width, style, color)) {
    return false;
  };

  css_parsing_utils::AddExpandedPropertyForValue(
      CSSPropertyID::kBorderBlockWidth, *width, important, properties);
  css_parsing_utils::AddExpandedPropertyForValue(
      CSSPropertyID::kBorderBlockStyle, *style, important, properties);
  css_parsing_utils::AddExpandedPropertyForValue(
      CSSPropertyID::kBorderBlockColor, *color, important, properties);

  return true;
}

const CSSValue* BorderBlock::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const CSSValue* value_start =
      GetCSSPropertyBorderBlockStart().CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* value_end =
      GetCSSPropertyBorderBlockEnd().CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  if (!base::ValuesEquivalent(value_start, value_end)) {
    return nullptr;
  }
  return value_start;
}

bool BorderBlockEnd::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderBlockEndShorthand(), important, context, stream, properties);
}

bool BorderBlockStart::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderBlockStartShorthand(), important, context, stream, properties);
}

bool BorderBlockStyle::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      borderBlockStyleShorthand(), important, context, stream, properties);
}

const CSSValue* BorderBlockStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      borderBlockStyleShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderBlockWidth::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      borderBlockWidthShorthand(), important, context, stream, properties);
}

const CSSValue* BorderBlockWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      borderBlockWidthShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderBottom::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderBottomShorthand(), important, context, stream, properties);
}

const CSSValue* BorderBottom::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForShorthandProperty(
      borderBottomShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderColor::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia4Longhands(
      borderColorShorthand(), important, context, stream, properties);
}

const CSSValue* BorderColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForSidesShorthand(
      borderColorShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool Border::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* width = nullptr;
  const CSSValue* style = nullptr;
  const CSSValue* color = nullptr;

  if (!css_parsing_utils::ConsumeBorderShorthand(stream, context, local_context,
                                                 width, style, color)) {
    return false;
  };

  css_parsing_utils::AddExpandedPropertyForValue(CSSPropertyID::kBorderWidth,
                                                 *width, important, properties);
  css_parsing_utils::AddExpandedPropertyForValue(CSSPropertyID::kBorderStyle,
                                                 *style, important, properties);
  css_parsing_utils::AddExpandedPropertyForValue(CSSPropertyID::kBorderColor,
                                                 *color, important, properties);
  css_parsing_utils::AddExpandedPropertyForValue(CSSPropertyID::kBorderImage,
                                                 *CSSInitialValue::Create(),
                                                 important, properties);

  return true;
}

const CSSValue* Border::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const CSSValue* value = GetCSSPropertyBorderTop().CSSValueFromComputedStyle(
      style, layout_object, allow_visited_style, value_phase);
  static const std::array<const CSSProperty*, 3> kProperties = {
      &GetCSSPropertyBorderRight(), &GetCSSPropertyBorderBottom(),
      &GetCSSPropertyBorderLeft()};
  for (size_t i = 0; i < std::size(kProperties); ++i) {
    const CSSValue* value_for_side = kProperties[i]->CSSValueFromComputedStyle(
        style, layout_object, allow_visited_style, value_phase);
    if (!base::ValuesEquivalent(value, value_for_side)) {
      return nullptr;
    }
  }
  return value;
}

bool BorderImage::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  CSSValue* source = nullptr;
  CSSValue* slice = nullptr;
  CSSValue* width = nullptr;
  CSSValue* outset = nullptr;
  CSSValue* repeat = nullptr;

  if (!css_parsing_utils::ConsumeBorderImageComponents(
          stream, context, source, slice, width, outset, repeat,
          css_parsing_utils::DefaultFill::kNoFill)) {
    return false;
  }

  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderImageSource, CSSPropertyID::kBorderImage,
      source ? *source : *GetCSSPropertyBorderImageSource().InitialValue(),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderImageSlice, CSSPropertyID::kBorderImage,
      slice ? *slice : *GetCSSPropertyBorderImageSlice().InitialValue(),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderImageWidth, CSSPropertyID::kBorderImage,
      width ? *width : *GetCSSPropertyBorderImageWidth().InitialValue(),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderImageOutset, CSSPropertyID::kBorderImage,
      outset ? *outset : *GetCSSPropertyBorderImageOutset().InitialValue(),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);
  css_parsing_utils::AddProperty(
      CSSPropertyID::kBorderImageRepeat, CSSPropertyID::kBorderImage,
      repeat ? *repeat : *GetCSSPropertyBorderImageRepeat().InitialValue(),
      important, css_parsing_utils::IsImplicitProperty::kNotImplicit,
      properties);

  return true;
}

const CSSValue* BorderImage::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForNinePieceImage(
      style.BorderImage(), style, allow_visited_style, value_phase);
}

bool BorderInlineColor::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      borderInlineColorShorthand(), important, context, stream, properties);
}

const CSSValue* BorderInlineColor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      borderInlineColorShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderInline::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  const CSSValue* width = nullptr;
  const CSSValue* style = nullptr;
  const CSSValue* color = nullptr;

  if (!css_parsing_utils::ConsumeBorderShorthand(stream, context, local_context,
                                                 width, style, color)) {
    return false;
  };

  css_parsing_utils::AddExpandedPropertyForValue(
      CSSPropertyID::kBorderInlineWidth, *width, important, properties);
  css_parsing_utils::AddExpandedPropertyForValue(
      CSSPropertyID::kBorderInlineStyle, *style, important, properties);
  css_parsing_utils::AddExpandedPropertyForValue(
      CSSPropertyID::kBorderInlineColor, *color, important, properties);

  return true;
}

const CSSValue* BorderInline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const CSSValue* value_start =
      GetCSSPropertyBorderInlineStart().CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  const CSSValue* value_end =
      GetCSSPropertyBorderInlineEnd().CSSValueFromComputedStyle(
          style, layout_object, allow_visited_style, value_phase);
  if (!base::ValuesEquivalent(value_start, value_end)) {
    return nullptr;
  }
  return value_start;
}

bool BorderInlineEnd::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderInlineEndShorthand(), important, context, stream, properties);
}

bool BorderInlineStart::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandGreedilyViaLonghands(
      borderInlineStartShorthand(), important, context, stream, properties);
}

bool BorderInlineStyle::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      borderInlineStyleShorthand(), important, context, stream, properties);
}

const CSSValue* BorderInlineStyle::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      borderInlineStyleShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderInlineWidth::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&,
    HeapVector<CSSPropertyValue, 64>& properties) const {
  return css_parsing_utils::ConsumeShorthandVia2Longhands(
      borderInlineWidthShorthand(), important, context, stream, properties);
}

const CSSValue* BorderInlineWidth::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValuesForInlineBlockShorthand(
      borderInlineWidthShorthand(), style, layout_object, allow_visited_style,
      value_phase);
}

bool BorderLeft::ParseShorthand(
    bool important,
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    
"""


```