Response:
The user is asking for a summary of the functionality of the provided C++ source code file. The file appears to be part of the Chromium Blink rendering engine and deals with parsing and managing CSS properties.

Here's a plan to address the request:

1. **Identify the core purpose of the file:** Based on the filename and included headers, the file seems to be responsible for parsing and converting CSS longhand properties into internal representations used by the rendering engine. The "custom" suffix suggests it handles properties that might not have straightforward, generated implementations.

2. **Analyze the included headers:** The headers provide clues about the functionalities handled. Look for categories of CSS features like colors, fonts, layout, animations, backgrounds, etc.

3. **Examine the implemented methods:** The provided snippet contains implementations for the `ParseSingleValue` and `CSSValueFromComputedStyleInternal` methods for various CSS properties. These methods are key to understanding how CSS text is converted into internal data structures and how those structures are represented as CSS values.

4. **Connect to Javascript, HTML, and CSS:**  Relate the parsed properties to their direct usage in CSS and how Javascript can interact with them (e.g., through the CSSOM). Explain how these CSS properties style HTML elements.

5. **Illustrate with examples:** Provide concrete examples of CSS syntax that this code would parse.

6. **Consider potential user errors:** Think about common mistakes developers make when using these CSS properties.

7. **Trace user actions:** Imagine the steps a user takes in a web browser that would lead to this code being executed.

8. **Focus on the provided snippet:** Since this is "part 1", limit the analysis to the code provided and avoid speculating too much about the rest of the file.
这是 `blink/renderer/core/css/properties/longhands/longhands_custom.cc` 文件的第一部分，其主要功能是**实现对部分 CSS 属性的解析和计算值到 CSS 值的转换**。 这些属性在 Blink 渲染引擎中被定义为“longhand”（详细属性），意味着它们不是其他简写属性的组成部分。 由于某些属性的解析逻辑或计算值到 CSS 值的转换逻辑较为复杂或特殊，无法通过代码自动生成，因此需要在此文件中进行手动实现。

**功能归纳:**

* **CSS 属性解析:**  为特定的 CSS 属性提供 `ParseSingleValue` 方法的实现。这个方法负责接收 CSS 语法解析器提供的 token 流，并将其转换为 Blink 内部的 CSS 值表示。
* **计算值到 CSS 值转换:** 为特定的 CSS 属性提供 `CSSValueFromComputedStyleInternal` 方法的实现。这个方法负责将渲染引擎计算出的属性值（存储在 `ComputedStyle` 对象中）转换回对应的 CSS 值表示形式，以便例如在开发者工具中显示或进行样式查询。
* **初始值、继承处理:**  对于某些属性，可能还包含 `ApplyInitial` 和 `ApplyInherit` 方法的实现，分别用于设置属性的初始值和处理属性的继承。
* **应用解析值:** 对于某些属性，可能包含 `ApplyValue` 方法，用于将解析后的 CSS 值应用到 `StyleResolverState` 中，为后续的样式计算做准备。

**与 Javascript, HTML, CSS 的关系及举例说明:**

这个文件直接参与了浏览器如何理解和应用 CSS 样式，因此与 Javascript、HTML 和 CSS 都有着密切的关系。

* **CSS:** 文件中定义的每个类都对应一个 CSS 属性，例如 `AlignContent` 对应 CSS 的 `align-content` 属性。 代码负责解析 CSS 文本中的属性值，并将其转换为内部表示。
    * **举例:**  当浏览器解析到 CSS 规则 `align-content: center;` 时，`AlignContent::ParseSingleValue` 方法会被调用来解析 `center` 关键字，并创建一个表示该值的内部对象。

* **HTML:**  CSS 样式最终会应用到 HTML 元素上，从而影响元素的渲染效果。 这个文件解析的 CSS 属性值将决定元素的布局、外观等特性。
    * **举例:** HTML 中有一个 `<div>` 元素，CSS 中设置了 `align-items: flex-start;`，那么 `AlignItems::ParseSingleValue` 会解析 `flex-start`，最终会影响 `<div>` 内部 flex 项目的对齐方式。

* **Javascript:** Javascript 可以通过 CSSOM (CSS Object Model) 操作 CSS 样式。 例如，可以使用 `element.style.alignContent = 'space-between';` 来修改元素的 `align-content` 属性。 浏览器内部会调用相应的解析代码来处理这个新的属性值。 同样，通过 `getComputedStyle` 获取到的样式值，其内部也依赖于 `CSSValueFromComputedStyleInternal` 将计算后的值转换为 CSS 值格式。
    * **举例:** Javascript 代码 `element.style.positionAnchor = 'my-anchor';` 会触发 `PositionAnchor::ParseSingleValue` 来解析自定义标识符 `'my-anchor'`。
    * **举例:** Javascript 代码 `getComputedStyle(element).alignItems;` 会调用 `AlignItems::CSSValueFromComputedStyleInternal` 将计算后的 `align-items` 值转换为 CSS 字符串（如 "flex-start"）。

**逻辑推理的假设输入与输出:**

假设我们以 `AlignItems::ParseSingleValue` 为例：

* **假设输入 (CSS Parser Token Stream):**  一个包含标识符 "center" 的 token 流。
* **预期输出 (CSSValue*):**  一个指向 `CSSIdentifierValue` 对象的指针，该对象表示 `CSSValueID::kCenter`。

假设我们以 `AlignItems::CSSValueFromComputedStyleInternal` 为例：

* **假设输入 (ComputedStyle):** 一个 `ComputedStyle` 对象，其 `align-items` 属性的值为 `EItemPosition::kCenter`。
* **预期输出 (CSSValue*):** 一个指向 `CSSIdentifierValue` 对象的指针，该对象表示 `CSSValueID::kCenter`。

**用户或编程常见的使用错误举例:**

* **拼写错误:** 用户在 CSS 中输入了错误的属性值，例如 `algin-items: center;` (拼写错误)。 这会导致解析失败，相关的 `ParseSingleValue` 方法会返回 `nullptr`。
* **使用了不合法的属性值:**  用户为某个属性设置了不被允许的值。 例如，`align-items` 属性不允许使用 `auto` 关键字，如果用户设置了 `align-items: auto;`，`AlignItems::ParseSingleValue` 会返回 `nullptr`。
* **Javascript 操作错误:**  在 Javascript 中尝试设置不合法的 CSS 值，例如 `element.style.animationComposition = 'invalid-value';`。 这同样会导致解析失败。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户在 HTML 文件中编写 CSS 样式:**  例如，用户在 `<style>` 标签或外部 CSS 文件中添加了 `align-items: center;` 这样的规则。
2. **浏览器加载 HTML 文件并开始解析:**  当浏览器解析到 CSS 规则时，会调用 CSS 解析器。
3. **CSS 解析器识别到 `align-items` 属性:**  解析器会查找与该属性对应的 longhand 类，即 `AlignItems`。
4. **调用 `AlignItems::ParseSingleValue`:**  解析器将属性值 "center" 转换为 token 流，并将其传递给 `ParseSingleValue` 方法进行解析。
5. **如果解析成功:**  `ParseSingleValue` 会创建一个表示该值的内部 `CSSValue` 对象。
6. **后续的样式计算和应用:**  解析后的 CSS 值会被用于计算元素的最终样式，并影响元素的布局和渲染。

**调试线索:** 如果开发者在调试过程中发现某个 CSS 属性没有生效，或者计算值不正确，可以断点调试 `longhands_custom.cc` 中对应属性的 `ParseSingleValue` 或 `CSSValueFromComputedStyleInternal` 方法，查看解析过程是否正确，以及计算值到 CSS 值的转换是否符合预期。 检查传入的 token 流和 `ComputedStyle` 对象可以帮助定位问题。

**总结第 1 部分的功能:**

总而言之，`longhands_custom.cc` 文件的第一部分主要负责处理部分 CSS 属性的解析和计算值到 CSS 值的转换，确保浏览器能够正确理解和应用开发者编写的 CSS 样式，并将内部的计算结果以合适的 CSS 值形式暴露出来。 它连接了 CSS 语法和 Blink 渲染引擎的内部表示，是浏览器渲染流程中至关重要的一部分。

### 提示词
```
这是目录为blink/renderer/core/css/properties/longhands/longhands_custom.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共13部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/numerics/clamped_math.h"
#include "third_party/blink/renderer/core/css/basic_shape_functions.h"
#include "third_party/blink/renderer/core/css/css_anchor_query_enums.h"
#include "third_party/blink/renderer/core/css/css_axis_value.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_content_distribution_value.h"
#include "third_party/blink/renderer/core/css/css_counter_value.h"
#include "third_party/blink/renderer/core/css/css_cursor_image_value.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_dynamic_range_limit_mix_value.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_font_variation_value.h"
#include "third_party/blink/renderer/core/css/css_function_value.h"
#include "third_party/blink/renderer/core/css/css_grid_auto_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_template_areas_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_initial_color_value.h"
#include "third_party/blink/renderer/core/css/css_layout_function_value.h"
#include "third_party/blink/renderer/core/css/css_light_dark_value_pair.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_quad_value.h"
#include "third_party/blink/renderer/core/css/css_ratio_value.h"
#include "third_party/blink/renderer/core/css/css_reflect_value.h"
#include "third_party/blink/renderer/core/css/css_resolution_units.h"
#include "third_party/blink/renderer/core/css/css_scoped_keyword_value.h"
#include "third_party/blink/renderer/core/css/css_string_value.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_fast_paths.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_mode.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_save_point.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_alternates_parser.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_east_asian_parser.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_ligatures_parser.h"
#include "third_party/blink/renderer/core/css/parser/font_variant_numeric_parser.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/resolver/style_builder_converter.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver_state.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/zoom_adjusted_pixel_value.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/coord_box_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/geometry_box_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/grid_area.h"
#include "third_party/blink/renderer/core/style/paint_order_array.h"
#include "third_party/blink/renderer/core/style/reference_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/reference_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/shape_clip_path_operation.h"
#include "third_party/blink/renderer/core/style/shape_offset_path_operation.h"
#include "third_party/blink/renderer/core/style/style_overflow_clip_margin.h"
#include "third_party/blink/renderer/core/style/style_svg_resource.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_style_tracker.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/geometry/length.h"
#include "third_party/blink/renderer/platform/graphics/color.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/quotes_data.h"

// Implementations of methods in Longhand subclasses that aren't generated.

namespace blink {

namespace {

void AppendIntegerOrAutoIfZero(unsigned value, CSSValueList* list) {
  if (!value) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
    return;
  }
  list->Append(*CSSNumericLiteralValue::Create(
      value, CSSPrimitiveValue::UnitType::kInteger));
}

CSSCustomIdentValue* ConsumeCustomIdentExcludingNone(
    CSSParserTokenStream& stream,
    const CSSParserContext& context) {
  if (stream.Peek().Id() == CSSValueID::kNone) {
    return nullptr;
  }
  return css_parsing_utils::ConsumeCustomIdent(stream, context);
}

}  // namespace

namespace css_longhand {

const CSSValue* AlignContent::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeContentDistributionOverflowPosition(
      stream, css_parsing_utils::IsContentPositionKeyword);
}

const CSSValue* AlignContent::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::
      ValueForContentPositionAndDistributionWithOverflowAlignment(
          style.AlignContent());
}

const CSSValue* AlignItems::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // align-items property does not allow the 'auto' value.
  if (css_parsing_utils::IdentMatches<CSSValueID::kAuto>(stream.Peek().Id())) {
    return nullptr;
  }
  return css_parsing_utils::ConsumeSelfPositionOverflowPosition(
      stream, css_parsing_utils::IsSelfPositionKeyword);
}

const CSSValue* AlignItems::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForItemPositionWithOverflowAlignment(
      style.AlignItems());
}

const CSSValue* AlignSelf::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeSelfPositionOverflowPosition(
      stream, css_parsing_utils::IsSelfPositionKeyword);
}

const CSSValue* AlignSelf::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForItemPositionWithOverflowAlignment(
      style.AlignSelf());
}
const CSSValue* AlignmentBaseline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(style.AlignmentBaseline());
}

const CSSValue* PositionAnchor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (CSSValue* value =
          css_parsing_utils::ConsumeIdent<CSSValueID::kAuto>(stream)) {
    return value;
  }
  return css_parsing_utils::ConsumeDashedIdent(stream, context);
}
const CSSValue* PositionAnchor::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.PositionAnchor()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return MakeGarbageCollected<CSSCustomIdentValue>(*style.PositionAnchor());
}

void PositionAnchor::ApplyInitial(StyleResolverState& state) const {
  state.SetPositionAnchor(ComputedStyleInitialValues::InitialPositionAnchor());
}

void PositionAnchor::ApplyInherit(StyleResolverState& state) const {
  state.SetPositionAnchor(state.ParentStyle()->PositionAnchor());
}

void PositionAnchor::ApplyValue(StyleResolverState& state,
                                const CSSValue& value,
                                ValueMode) const {
  state.SetPositionAnchor(
      StyleBuilderConverter::ConvertPositionAnchor(state, value));
}

// https://drafts.csswg.org/css-anchor-position-1/#position-visibility
// position-visibility:
//   always | [ anchors-valid | anchors-visible ] || no-overflow
// TODO(crbug.com/332933527): Support anchors-valid. For now,
// we only support the modified grammar:
//   position-visibility: always | anchors-visible || no-overflow
const CSSValue* PositionVisibility::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (stream.Peek().Id() == CSSValueID::kAlways) {
    return css_parsing_utils::ConsumeIdent(stream);
  }

  CSSIdentifierValue* anchors_visible =
      css_parsing_utils::ConsumeIdent<CSSValueID::kAnchorsVisible>(stream);
  CSSIdentifierValue* no_overflow =
      css_parsing_utils::ConsumeIdent<CSSValueID::kNoOverflow>(stream);
  if (!anchors_visible) {
    anchors_visible =
        css_parsing_utils::ConsumeIdent<CSSValueID::kAnchorsVisible>(stream);
  }

  if (!anchors_visible && !no_overflow) {
    return nullptr;
  }
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (anchors_visible) {
    list->Append(*anchors_visible);
  }
  if (no_overflow) {
    list->Append(*no_overflow);
  }
  return list;
}

const CSSValue* PositionVisibility::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  blink::PositionVisibility position_visibility = style.GetPositionVisibility();
  if (position_visibility == blink::PositionVisibility::kAlways) {
    return CSSIdentifierValue::Create(CSSValueID::kAlways);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (EnumHasFlags(position_visibility,
                   blink::PositionVisibility::kAnchorsVisible)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kAnchorsVisible));
  }
  if (EnumHasFlags(position_visibility,
                   blink::PositionVisibility::kNoOverflow)) {
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kNoOverflow));
  }
  return list;
}

// anchor-name: none | <dashed-ident>#
const CSSValue* AnchorName::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (CSSValue* value =
          css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream)) {
    return value;
  }
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeDashedIdent, stream, context);
}
const CSSValue* AnchorName::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.AnchorName()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const Member<const ScopedCSSName>& name :
       style.AnchorName()->GetNames()) {
    list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(*name));
  }
  return list;
}

const CSSValue* AnchorScope::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  if (CSSValue* value =
          css_parsing_utils::ConsumeIdent<CSSValueID::kNone>(stream)) {
    return value;
  }
  if (CSSValue* value =
          css_parsing_utils::ConsumeScopedKeywordValue<CSSValueID::kAll>(
              stream)) {
    return value;
  }
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeDashedIdent, stream, context);
}

const CSSValue* AnchorScope::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  const StyleAnchorScope& anchor_scope = style.AnchorScope();
  if (anchor_scope.IsNone()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }
  if (anchor_scope.IsAll()) {
    return CSSIdentifierValue::Create(CSSValueID::kAll);
  }
  CHECK(anchor_scope.Names());
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const Member<const ScopedCSSName>& name :
       anchor_scope.Names()->GetNames()) {
    list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(*name));
  }
  return list;
}

const CSSValue* AnimationComposition::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList<CSSIdentifierValue*(
      CSSParserTokenStream&)>(
      css_parsing_utils::ConsumeIdent<CSSValueID::kReplace, CSSValueID::kAdd,
                                      CSSValueID::kAccumulate>,
      stream);
}

const CSSValue* AnimationComposition::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  if (!style.Animations()) {
    return InitialValue();
  }
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const auto& composition_list = style.Animations()->CompositionList();
  for (const auto& composition : composition_list) {
    list->Append(*CSSIdentifierValue::Create(composition));
  }
  return list;
}

const CSSValue* AnimationComposition::InitialValue() const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kReplace));
  return list;
}

const CSSValue* AnimationDelay::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      static_cast<CSSPrimitiveValue* (*)(CSSParserTokenStream&,
                                         const CSSParserContext&,
                                         CSSPrimitiveValue::ValueRange)>(
          css_parsing_utils::ConsumeTime),
      stream, context, CSSPrimitiveValue::ValueRange::kAll);
}

const CSSValue* AnimationDelay::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationDelayList(style.Animations());
}

const CSSValue* AnimationDelay::InitialValue() const {
  DEFINE_STATIC_LOCAL(const Persistent<CSSValue>, value,
                      (ComputedStyleUtils::ValueForAnimationDelay(
                          CSSTimingData::InitialDelayStart())));
  return value;
}

const CSSValue* AnimationDirection::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList<CSSIdentifierValue*(
      CSSParserTokenStream&)>(
      css_parsing_utils::ConsumeIdent<
          CSSValueID::kNormal, CSSValueID::kAlternate, CSSValueID::kReverse,
          CSSValueID::kAlternateReverse>,
      stream);
}

const CSSValue* AnimationDirection::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationDirectionList(style.Animations());
}

const CSSValue* AnimationDirection::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNormal);
}

const CSSValue* AnimationDuration::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationDuration, stream, context);
}

const CSSValue* AnimationDuration::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationDurationList(style.Animations(),
                                                           value_phase);
}

const CSSValue* AnimationDuration::InitialValue() const {
  return ComputedStyleUtils::ValueForAnimationDuration(
      CSSAnimationData::InitialDuration(), /* resolve_auto_to_zero */ false);
}

const CSSValue* AnimationFillMode::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList<CSSIdentifierValue*(
      CSSParserTokenStream&)>(
      css_parsing_utils::ConsumeIdent<CSSValueID::kNone, CSSValueID::kForwards,
                                      CSSValueID::kBackwards,
                                      CSSValueID::kBoth>,
      stream);
}

const CSSValue* AnimationFillMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationFillModeList(style.Animations());
}

const CSSValue* AnimationFillMode::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* AnimationIterationCount::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationIterationCount, stream, context);
}

const CSSValue* AnimationIterationCount::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationIterationCountList(
      style.Animations());
}

const CSSValue* AnimationIterationCount::InitialValue() const {
  DEFINE_STATIC_LOCAL(
      const Persistent<CSSValue>, value,
      (CSSNumericLiteralValue::Create(CSSAnimationData::InitialIterationCount(),
                                      CSSPrimitiveValue::UnitType::kNumber)));
  return value;
}

const CSSValue* AnimationName::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  // Allow quoted name if this is an alias property.
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationName, stream, context,
      local_context.UseAliasParsing());
}

const CSSValue* AnimationName::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const CSSAnimationData* animation_data = style.Animations();
  if (animation_data) {
    for (wtf_size_t i = 0; i < animation_data->NameList().size(); ++i) {
      list->Append(*MakeGarbageCollected<CSSCustomIdentValue>(
          animation_data->NameList()[i]));
    }
  } else {
    list->Append(*InitialValue());
  }
  return list;
}

const CSSValue* AnimationName::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNone);
}

const CSSValue* AnimationPlayState::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList<CSSIdentifierValue*(
      CSSParserTokenStream&)>(
      css_parsing_utils::ConsumeIdent<CSSValueID::kRunning,
                                      CSSValueID::kPaused>,
      stream);
}

const CSSValue* AnimationPlayState::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationPlayStateList(style.Animations());
}

const CSSValue* AnimationPlayState::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kRunning);
}

const CSSValue* AnimationRangeStart::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationRange, stream, context,
      /* default_offset_percent */ 0.0);
}

const CSSValue* AnimationRangeStart::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationRangeStartList(style.Animations(),
                                                             style);
}

const CSSValue* AnimationRangeStart::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNormal);
}

const CSSValue* AnimationRangeEnd::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  DCHECK(RuntimeEnabledFeatures::ScrollTimelineEnabled());
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationRange, stream, context,
      /* default_offset_percent */ 100.0);
}

const CSSValue* AnimationRangeEnd::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationRangeEndList(style.Animations(),
                                                           style);
}

const CSSValue* AnimationRangeEnd::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kNormal);
}

const CSSValue* AnimationTimeline::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext& local_context) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationTimeline, stream, context);
}

const CSSValue* AnimationTimeline::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationTimelineList(style.Animations());
}

const CSSValue* AnimationTimeline::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kAuto);
}

const CSSValue* AnimationTimingFunction::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeAnimationTimingFunction, stream, context);
}

const CSSValue* AnimationTimingFunction::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForAnimationTimingFunctionList(
      style.Animations());
}

const CSSValue* AnimationTimingFunction::InitialValue() const {
  return CSSIdentifierValue::Create(CSSValueID::kEase);
}

const CSSValue* AspectRatio::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  // Syntax: auto | auto 1/2 | 1/2 auto | 1/2
  CSSValue* auto_value = nullptr;
  if (stream.Peek().Id() == CSSValueID::kAuto) {
    auto_value = css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValue* ratio = css_parsing_utils::ConsumeRatio(stream, context);
  if (!ratio) {
    return auto_value;  // Either auto alone, or failure.
  }

  if (!auto_value && stream.Peek().Id() == CSSValueID::kAuto) {
    auto_value = css_parsing_utils::ConsumeIdent(stream);
  }

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (auto_value) {
    list->Append(*auto_value);
  }
  list->Append(*ratio);
  return list;
}

const CSSValue* AspectRatio::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  auto& ratio = style.AspectRatio();
  if (ratio.GetTypeForComputedStyle() == EAspectRatioType::kAuto) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }

  auto* ratio_value = MakeGarbageCollected<cssvalue::CSSRatioValue>(
      *CSSNumericLiteralValue::Create(ratio.GetRatio().width(),
                                      CSSPrimitiveValue::UnitType::kNumber),
      *CSSNumericLiteralValue::Create(ratio.GetRatio().height(),
                                      CSSPrimitiveValue::UnitType::kNumber));

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  if (ratio.GetTypeForComputedStyle() != EAspectRatioType::kRatio) {
    DCHECK_EQ(ratio.GetTypeForComputedStyle(), EAspectRatioType::kAutoAndRatio);
    list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
  }

  list->Append(*ratio_value);
  return list;
}

const CSSValue* BackdropFilter::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeFilterFunctionList(stream, context);
}

const CSSValue* BackdropFilter::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return ComputedStyleUtils::ValueForFilter(style, style.BackdropFilter());
}

void BackdropFilter::ApplyValue(StyleResolverState& state,
                                const CSSValue& value,
                                ValueMode) const {
  state.StyleBuilder().SetBackdropFilter(
      StyleBuilderConverter::ConvertFilterOperations(state, value,
                                                     PropertyID()));
}

const CSSValue* BackfaceVisibility::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  return CSSIdentifierValue::Create(
      (style.BackfaceVisibility() == EBackfaceVisibility::kHidden)
          ? CSSValueID::kHidden
          : CSSValueID::kVisible);
}

const CSSValue* BackgroundAttachment::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeBackgroundAttachment, stream);
}

const CSSValue* BackgroundAttachment::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const FillLayer* curr_layer = &style.BackgroundLayers(); curr_layer;
       curr_layer = curr_layer->Next()) {
    list->Append(*CSSIdentifierValue::Create(curr_layer->Attachment()));
  }
  return list;
}

const CSSValue* BackgroundBlendMode::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeCommaSeparatedList(
      css_parsing_utils::ConsumeBackgroundBlendMode, stream);
}

const CSSValue* BackgroundBlendMode::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (const FillLayer* curr_layer = &style.BackgroundLayers(); curr_layer;
       curr_layer = curr_layer->Next()) {
    list->Append(*CSSIdentifierValue::Create(curr_layer->GetBlendMode()));
  }
  return list;
}

const CSSValue* BackgroundClip::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext&,
    const CSSParserLocalContext& local_context) const {
  if (RuntimeEnabledFeatures::CSSBackgroundClipUnprefixEnabled()) {
    return css_parsing_utils::ConsumeCommaSeparatedList(
        css_parsing_utils::ConsumeBackgroundBoxOrText, stream);
  } else {
    return css_parsing_utils::ParseBackgroundBox(
        stream, local_context, css_parsing_utils::AllowTextValue::kAllow);
  }
}

const CSSValue* BackgroundClip::CSSValueFromComputedStyleInternal(
    const ComputedStyle& style,
    const LayoutObject*,
    bool allow_visited_style,
    CSSValuePhase value_phase) const {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &style.BackgroundLayers();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    EFillBox box = curr_layer->Clip();
    list->Append(*CSSIdentifierValue::Create(box));
  }
  return list;
}

void UseCountBackgroundClip(Document& document, const CSSValue& value) {
  if (const auto* identifier_value = DynamicTo<CSSIdentifierValue>(value)) {
    switch (identifier_value->GetValueID()) {
      case CSSValueID::kBorder:
        UseCounter::Count(document, WebFeature::kCSSBackgroundClipBorder);
        break;
      case CSSValueID::kContent:
        UseCounter::Count(document, WebFeature::kCSSBackgroundClipContent);
        break;
      case CSSValueID::kPadding:
        UseCounter::Count(document, WebFeature::kCSSBackgroundClipPadding);
        break;
      default:
        break;
    }
  }
}

// TODO(crbug.com/1339290): Revert to use the generated implementation once the
// use counters are no longer needed. Also remove UseCountBackgroundClip above.
void BackgroundClip::ApplyValue(StyleResolverState& state,
                                const CSSValue& value,
                                ValueMode) const {
  Document& document = state.GetDocument();
  FillLayer* curr_child = &state.StyleBuilder().AccessBackgroundLayers();
  FillLayer* prev_child = nullptr;
  const auto* value_list = DynamicTo<CSSValueList>(value);
  if (value_list && !value.IsImageSetValue()) {
    // Walk each value and put it into a layer, creating new layers as needed.
    // As per https://w3c.github.io/csswg-drafts/css-backgrounds/#layering
    while (curr_child) {
      for (auto curr_val : *value_list) {
        if (!curr_child) {
          curr_child = prev_child->EnsureNext();
        }
        CSSToStyleMap::MapFillClip(state, curr_child, *curr_val);
        UseCountBackgroundClip(document, *curr_val);
        prev_child = curr_child;
        curr_child = curr_child->Next();
      }
    }
  } else {
    while (curr_child) {
      CSSToStyleMap::MapFillClip(state, curr_child, value);
      curr_child = curr_child->Next();
    }
  }
}

const CSSValue* BackgroundColor::ParseSingleValue(
    CSSParserTokenStream& stream,
    const CSSParserContext& context,
    const CSSParserLocalContext&) const {
  return css_parsing_utils::ConsumeColorMaybeQuirky(stream, context);
}

const blink::Color Backg
```