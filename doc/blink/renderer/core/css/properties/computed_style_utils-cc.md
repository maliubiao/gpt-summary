Response:
The user wants a summary of the functionality of the provided C++ code snippet.
This file appears to be responsible for converting internal representations of CSS properties into CSS values that can be exposed to JavaScript and other parts of the rendering engine.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The filename and included headers strongly suggest this file deals with converting computed style data into CSS values. The presence of functions like `ZoomAdjustedPixelValueForLength`, `ValueForPosition`, `ValueForColor`, etc., confirms this.

2. **Categorize the functionality:**  The functions handle different CSS property types. Group them by what they are converting (lengths, colors, images, backgrounds, etc.). This provides a structured overview.

3. **Relate to web technologies:**  Explicitly connect the C++ code to CSS, HTML, and JavaScript. Explain how the conversions impact these technologies. For example, how a C++ representation of a color becomes a string in CSS or a value accessible via JavaScript's `getComputedStyle`.

4. **Consider logic and data flow:**  While the provided snippet doesn't have complex algorithms, it does perform conversions and conditional logic. Think about what inputs a function might take and what output it produces. This leads to examples with assumed inputs and outputs.

5. **Identify potential user errors:**  Think about how incorrect CSS or JavaScript usage might lead to the execution of code within this file. For instance, specifying invalid color values or incorrect units.

6. **Trace the execution path:**  Consider the user actions that would trigger the need to compute and expose CSS styles. This often starts with loading a webpage, interacting with it, or inspecting its styles.

7. **Address the "Part 1 of 6" instruction:**  Focus only on the functionality visible in the current snippet and avoid speculating about the content of the remaining parts.

8. **Structure the summary:** Organize the findings into clear sections based on the prompt's requirements: Functionality, Relationship with Web Technologies, Logical Reasoning, User Errors, Debugging Clues, and Overall Summary.
```
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"

#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/css/basic_shape_functions.h"
#include "third_party/blink/renderer/core/css/css_alternate_value.h"
#include "third_party/blink/renderer/core/css/css_border_image.h"
#include "third_party/blink/renderer/core/css/css_border_image_slice_value.h"
#include "third_party/blink/renderer/core/css/css_bracketed_value_list.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_color_mix_value.h"
#include "third_party/blink/renderer/core/css/css_content_distribution_value.h"
#include "third_party/blink/renderer/core/css/css_counter_value.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_feature_value.h"
#include "third_party/blink/renderer/core/css/css_font_style_range_value.h"
#third_party/blink/renderer/core/css/css_font_variation_value.h"
#include "third_party/blink/renderer/core/css/css_function_value.h"
#include "third_party/blink/renderer/core/css/css_grid_auto_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_integer_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_template_areas_value.h"
#include "third_party/blink/renderer/core/css/css_initial_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_quad_value.h"
#include "third_party/blink/renderer/core/css/css_reflect_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_scroll_value.h"
#include "third_party/blink/renderer/core/css/css_shadow_value.h"
#include "third_party/blink/renderer/core/css/css_string_value.h"
#include "third_party/blink/renderer/core/css/css_timing_function_value.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/css_view_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_color_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_keyword_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_unit_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_unparsed_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_unsupported_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_keyword_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unparsed_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unsupported_color.h"
#include "third_party/blink/renderer/core/css/cssom_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/properties/shorthands.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/grid/layout_grid.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/svg/transform_helper.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/position_area.h"
#include "third_party/blink/renderer/core/style/style_intrinsic_length.h"
#include "third_party/blink/renderer/core/style/style_svg_resource.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_rect_element.h"
#include "third_party/blink/renderer/core/svg_element_type_helpers.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"
#include "third_party/blink/renderer/platform/fonts/font_optical_sizing.h"
#include "third_party/blink/renderer/platform/fonts/font_palette.h"
#include "third_party/blink/renderer/platform/fonts/font_variant_emoji.h"
#include "third_party/blink/renderer/platform/fonts/opentype/font_settings.h"
#include "third_party/blink/renderer/platform/transforms/matrix_3d_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/matrix_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/perspective_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/skew_transform_operation.h"

namespace blink {

namespace {

const double kFinalStatePercentage = 100.0;
const double kMiddleStatePercentage = 50.0;

CSSValue* ConvertFontPaletteToCSSValue(const blink::FontPalette* palette) {
  switch (palette->GetPaletteNameKind()) {
    case blink::FontPalette::kNormalPalette:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case blink::FontPalette::kLightPalette:
      return CSSIdentifierValue::Create(CSSValueID::kLight);
    case blink::FontPalette::kDarkPalette:
      return CSSIdentifierValue::Create(CSSValueID::kDark);
    case blink::FontPalette::kCustomPalette:
      return MakeGarbageCollected<CSSCustomIdentValue>(
          palette->GetPaletteValuesName());
    case blink::FontPalette::kInterpolablePalette: {
      // TODO(crbug.com/1400620): Change the serialization of palette-mix()
      // function to match color-mix(), i.e.: palette-mix() =
      // palette-mix(<color-interpolation-method> , [ [normal | light | dark |
      // <palette-identifier> | <palette-mix()> ] && <percentage [0,100]>?
      // ]#{2})
      CSSFunctionValue* result =
          MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kPaletteMix);

      CSSValueList* color_space_css_value_list =
          CSSValueList::CreateSpaceSeparated();
      color_space_css_value_list->Append(
          *MakeGarbageCollected<CSSCustomIdentValue>(AtomicString("in")));
      if (palette->GetHueInterpolationMethod().has_value()) {
        color_space_css_value_list->Append(
            *MakeGarbageCollected<CSSCustomIdentValue>(
                AtomicString(Color::SerializeInterpolationSpace(
                    palette->GetColorInterpolationSpace(),
                    *palette->GetHueInterpolationMethod()))));
      } else {
        color_space_css_value_list->Append(
            *MakeGarbageCollected<CSSCustomIdentValue>(
                AtomicString(Color::SerializeInterpolationSpace(
                    palette->GetColorInterpolationSpace()))));
      }
      result->Append(*color_space_css_value_list);

      double start_percentage_ = palette->GetStartPercentage();
      double end_percentage_ = palette->GetEndPercentage();

      CSSValueList* start_palette_with_percentage =
          CSSValueList::CreateSpaceSeparated();
      CSSValue* start = ConvertFontPaletteToCSSValue(palette->GetStart().get());
      start_palette_with_percentage->Append(*start);
      // Percentages in the palette-mix() function should be serialized the same
      // way they are serialized in color-mix() function. If the first
      // percentage is equal 50% and the two specified percentages add to 100%,
      // we should skip the first percentage in the serialization. Second
      // percentage should be skipped if it equals to 50%, or the two specified
      // percentages add to 100%. Compare:
      // https://drafts.csswg.org/css-color-5/#serial-color-mix.
      if (start_percentage_ + end_percentage_ != kFinalStatePercentage ||
          start_percentage_ != kMiddleStatePercentage) {
        CSSValue* param = CSSNumericLiteralValue::Create(
            start_percentage_, CSSPrimitiveValue::UnitType::kPercentage);
        start_palette_with_percentage->Append(*param);
      }
      result->Append(*start_palette_with_percentage);

      CSSValueList* end_palette_with_percentage =
          CSSValueList::CreateSpaceSeparated();
      CSSValue* end = ConvertFontPaletteToCSSValue(palette->GetEnd().get());
      if (*start == *end) {
        return start;
      }
      end_palette_with_percentage->Append(*end);
      if (start_percentage_ + end_percentage_ != kFinalStatePercentage) {
        CSSValue* param = CSSNumericLiteralValue::Create(
            end_percentage_, CSSPrimitiveValue::UnitType::kPercentage);
        end_palette_with_percentage->Append(*param);
      }
      result->Append(*end_palette_with_percentage);

      return result;
    }
    default:
      NOTREACHED();
  }
}

}  // namespace

static Length Negate(const Length& length) {
  if (length.IsCalculated()) {
    NOTREACHED();
  }

  Length ret = Length(-length.GetFloatValue(), length.GetType());
  ret.SetQuirk(length.Quirk());
  return ret;
}

// TODO(rjwright): make this const
CSSValue* ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
    const Length& length,
    const ComputedStyle& style) {
  if (length.IsFixed()) {
    return ZoomAdjustedPixelValue(length.Value(), style);
  }
  return CSSValue::Create(length, style.EffectiveZoom());
}

CSSValue* ComputedStyleUtils::ValueForPosition(const LengthPoint& position,
                                               const ComputedStyle& style) {
  if (position.X().IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (position.X().IsNone()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  return MakeGarbageCollected<CSSValuePair>(
      ZoomAdjustedPixelValueForLength(position.X(), style),
      ZoomAdjustedPixelValueForLength(position.Y(), style),
      CSSValuePair::kKeepIdenticalValues);
}

CSSValue* ComputedStyleUtils::ValueForOffset(const ComputedStyle& style,
                                             const LayoutObject* layout_object,
                                             bool allow_visited_style,
                                             CSSValuePhase value_phase) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  CSSValue* position = ValueForPosition(style.OffsetPosition(), style);
  auto* position_identifier_value = DynamicTo<CSSIdentifierValue>(position);
  if (!position_identifier_value ||
      position_identifier_value->GetValueID() == CSSValueID::kAuto) {
    list->Append(*position);
  } else {
    DCHECK_EQ(position_identifier_value->GetValueID(), CSSValueID::kNormal);
  }

  static const CSSProperty* longhands[3] = {&GetCSSPropertyOffsetPath(),
                                            &GetCSSPropertyOffsetDistance(),
                                            &GetCSSPropertyOffsetRotate()};
  for (const CSSProperty* longhand : longhands) {
    const CSSValue* value = longhand->CSSValueFromComputedStyle(
        style, layout_object, allow_visited_style, value_phase);
    DCHECK(value);
    list->Append(*value);
  }

  CSSValue* anchor = ValueForPosition(style.OffsetAnchor(), style);
  auto* anchor_identifier_value = DynamicTo<CSSIdentifierValue>(anchor);
  if (!anchor_identifier_value) {
    // Add a slash before anchor.
    CSSValueList* result = CSSValueList::CreateSlashSeparated();
    result->Append(*list);
    result->Append(*anchor);
    return result;
  }
  DCHECK_EQ(anchor_identifier_value->GetValueID(), CSSValueID::kAuto);
  return list;
}

const CSSValue* ComputedStyleUtils::ValueForColor(
    const StyleColor& style_color,
    const ComputedStyle& style,
    const Color* override_current_color,
    CSSValuePhase value_phase) {
  const Color current_color = override_current_color ? *override_current_color
                                                     : style.GetCurrentColor();
  return cssvalue::CSSColor::Create(
      style_color.Resolve(current_color, style.UsedColorScheme()));
}

const CSSValue* ComputedStyleUtils::CurrentColorOrValidColor(
    const ComputedStyle& style,
    const StyleColor& color,
    CSSValuePhase value_phase) {
  return ValueForColor(color, style, nullptr, value_phase);
}

const blink::Color ComputedStyleUtils::BorderSideColor(
    const ComputedStyle& style,
    const StyleColor& color,
    EBorderStyle border_style,
    bool visited_link,
    bool* is_current_color) {
  Color current_color;
  if (visited_link) {
    current_color = style.GetInternalVisitedCurrentColor();
  } else if (border_style == EBorderStyle::kInset ||
             border_style == EBorderStyle::kOutset ||
             border_style == EBorderStyle::kRidge ||
             border_style == EBorderStyle::kGroove) {
    // FIXME: Treating styled borders with initial color differently causes
    // problems, see crbug.com/316559, crbug.com/276231
    current_color = blink::Color(238, 238, 238);
  } else {
    current_color = style.GetCurrentColor();
  }
  return color.Resolve(current_color, style.UsedColorScheme(),
                       is_current_color);
}

const CSSValue* ComputedStyleUtils::BackgroundImageOrMaskImage(
    const ComputedStyle& style,
    bool allow_visited_style,
    const FillLayer& fill_layer,
    CSSValuePhase value_phase) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &fill_layer;
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    if (curr_layer->GetImage()) {
      list->Append(*curr_layer->GetImage()->ComputedCSSValue(
          style, allow_visited_style, value_phase));
    } else {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
    }
  }
  return list;
}

const CSSValue* ComputedStyleUtils::ValueForFillSize(
    const FillSize& fill_size,
    const ComputedStyle& style) {
  if (fill_size.type == EFillSizeType::kContain) {
    return CSSIdentifierValue::Create(CSSValueID::kContain);
  }

  if (fill_size.type == EFillSizeType::kCover) {
    return CSSIdentifierValue::Create(CSSValueID::kCover);
  }

  if (fill_size.size.Height().IsAuto()) {
    return ZoomAdjustedPixelValueForLength(fill_size.size.Width(), style);
  }

  return MakeGarbageCollected<CSSValuePair>(
      ZoomAdjustedPixelValueForLength(fill_size.size.Width(), style),
      ZoomAdjustedPixelValueForLength(fill_size.size.Height(), style),
      CSSValuePair::kKeepIdenticalValues);
}

const CSSValue* ComputedStyleUtils::BackgroundImageOrMaskSize(
    const ComputedStyle& style,
    const FillLayer& fill_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &fill_layer;
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(*ValueForFillSize(curr_layer->Size(), style));
  }
  return list;
}

const CSSValueList* ComputedStyleUtils::CreatePositionListForLayer(
    const CSSProperty& property,
    const FillLayer& layer,
    const ComputedStyle& style) {
  CSSValueList* position_list = CSSValueList::CreateSpaceSeparated();
  if (layer.IsBackgroundXOriginSet()) {
    DCHECK(property.IDEquals(CSSPropertyID::kBackgroundPosition) ||
           property.IDEquals(CSSPropertyID::kMaskPosition));
    position_list->Append(
        *CSSIdentifierValue::Create(layer.BackgroundXOrigin()));
  }
  position_list->Append(
      *ZoomAdjustedPixelValueForLength(layer.PositionX(), style));
  if (layer.IsBackgroundYOriginSet()) {
    DCHECK(property.IDEquals(CSSPropertyID::kBackgroundPosition) ||
           property.IDEquals(CSSPropertyID::kMaskPosition));
    position_list->Append(
        *CSSIdentifierValue::Create(layer.BackgroundYOrigin()));
  }
  position_list->Append(
      *ZoomAdjustedPixelValueForLength(layer.PositionY(), style));
  return position_list;
}

const CSSValue* ComputedStyleUtils::ValueForFillRepeat(
    const FillLayer* curr_layer) {
  const auto& fill_repeat = curr_layer->Repeat();

  return MakeGarbageCollected<CSSRepeatStyleValue>(
      CSSIdentifierValue::Create(fill_repeat.x),
      CSSIdentifierValue::Create(fill_repeat.y));
}

const CSSValue* ComputedStyleUtils::RepeatStyle(const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();

  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(*ValueForFillRepeat(curr_layer));
  }

  return list;
}

const CSSValue* ComputedStyleUtils::MaskMode(const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(*CSSIdentifierValue::Create(curr_layer->MaskMode()));
  }
  return list;
}

const CSSValueList* ComputedStyleUtils::ValuesForBackgroundShorthand(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  CSSValueList* result = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &style.BackgroundLayers();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    CSSValueList* list = CSSValueList::CreateSlashSeparated();
    CSSValueList* before_slash = CSSValueList::CreateSpaceSeparated();
    if (!curr_layer->Next()) {  // color only for final layer
      const CSSValue* value =
          GetCSSPropertyBackgroundColor().CSSValueFromComputedStyle(
              style, layout_object, allow_visited_style, value_phase);
      DCHECK(value);
      before_slash->Append(*value);
    }
    before_slash->Append(curr_layer->GetImage()
                             ? *curr_layer->GetImage()->ComputedCSSValue(
                                   style, allow_visited_style, value_phase)
                             : *CSSIdentifierValue::Create(CSSValueID::kNone));
    before_slash->Append(*ValueForFillRepeat(curr_layer));
    before_slash->Append(*CSSIdentifierValue::Create(curr_layer->Attachment()));
    before_slash->Append(*CreatePositionListForLayer(
        GetCSSPropertyBackgroundPosition(), *curr_layer, style));
    list->Append(*before_slash);
    CSSValueList* after_slash = CSSValueList::CreateSpaceSeparated();
    after_slash->Append(*ValueForFillSize(curr_layer->Size(), style));
    after_slash->Append(*CSSIdentifierValue::Create(curr_layer->Origin()));
    after_slash->Append(*CSSIdentifierValue::Create(curr_layer->Clip()));
    list->Append(*after_slash);
    result->Append(*list);
  }
  return result;
}

namespace {

// Append clip and origin vals (https://drafts.fxtf.org/css-masking/#the-mask):
// * If one <geometry-box> value and the no-clip keyword are present then
//   <geometry-box> sets mask-origin and no-clip sets mask-clip to that value.
// * If one <geometry-box> value and no no-clip keyword are present then
//   <geometry-box> sets both mask-origin and mask-clip to that value.
// * If two <geometry-box> values are present, then the first sets mask-origin
//   and the second mask-clip.
// Additionally, simplifies when possible.
void AppendValuesForMaskClipAndOrigin(CSSValueList* result_list,
                                      EFillBox origin,
                                      EFillBox clip) {
  if (origin == clip) {
    // If both values are border-box, omit everything as it is the default.
    if (origin == EFillBox::kBorder) {
      return;
    }
    // If the values are the same, only emit one value. Note that mask-origin
    // does not support no-clip, so there is no need to consider no-clip
    // special cases.
    result_list->Append(*CSSIdentifierValue::Create(origin));
  } else if (origin == EFillBox::kBorder && clip == EFillBox::kNoClip) {
    // Mask-origin does not support no-clip, so mask-origin can be omitted if it
    // is the default.
    result_list->Append(*CSSIdentifierValue::Create(clip));
  } else {
    result_list->Append(*CSSIdentifierValue::Create(origin));
    result_list->Append(*CSSIdentifierValue::Create(clip));
  }
}

}  // namespace

const CSSValueList* ComputedStyleUtils::ValuesForMaskShorthand(
    const StylePropertyShorthand&,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  // Canonical order (https://drafts.fxtf.org/css-masking/#typedef-mask-layer):
  //   <mask-reference>              ||
  //   <position> [ / <bg-size> ]?   ||
  //   <repeat-style>                ||
  //   <geometry-box>                ||
  //   [ <geometry-box> | no-clip ]  ||
  //   <compositing-operator>        ||
  //   <masking-mode>
  // The logic below omits initial values due to the following spec:
  // https://drafts.csswg.org/cssom/#serialize-a-css-value
  // "If component values can be omitted or replaced with a shorter
  // representation without changing the meaning of the value, omit/replace
  // them".
  CSSValueList* result = CSSValueList::CreateCommaSeparated();
  const FillLayer* layer = &style.MaskLayers();
  for (; layer; layer = layer->Next()) {
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    // <mask-reference>
    if (layer->GetImage()) {
      list->Append(*layer->GetImage()->ComputedCSSValue(
          style, allow_visited_style, value_phase));
    }
    // <position> [ / <bg-size> ]?
    if (layer->PositionX() !=
            FillLayer::InitialFillPositionX(EFillLayerType::kMask) ||
        layer->PositionY() !=
            FillLayer::InitialFillPositionY(EFillLayerType::kMask) ||
        layer->Size() != FillLayer::InitialFillSize(EFillLayerType::kMask)) {
      CSSValueList* position_size_list = CSSValueList::CreateSlashSeparated();
      position_size_list->Append(*CreatePositionListForLayer(
          GetCSSPropertyMaskPosition(), *layer, style));
      if (layer->Size() != FillLayer::InitialFillSize(EFillLayerType::kMask)) {
        position_size_list->Append(*ValueForFillSize(layer->Size(), style));
      }
      list->Append(*position_size_list);
    }
    // <repeat-style>
    if (layer->Repeat() !=
        FillLayer::InitialFillRepeat(EFillLayerType::kMask)) {
      list->Append(*ValueForFillRepeat(layer));
    }
    // <geometry-box>
    // [ <geometry-box> | no-clip ]
    AppendValuesForMaskClipAndOrigin(list, layer->Origin(), layer->Clip());
    // <compositing-operator>
    if (layer->CompositingOperator() !=
        FillLayer::InitialFillCompositingOperator(EFillLayerType::kMask)) {
      list->Append(*CSSIdentifierValue::Create(layer->CompositingOperator()));
    }
    // <masking-mode>
    if (layer->MaskMode() !=
        FillLayer::InitialFillMaskMode(EFillLayerType::kMask)) {
      list->Append(*CSSIdentifierValue::Create(layer->MaskMode()));
    }

    if (list->length()) {
      result->Append(*list);
    } else {
      result->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
    }
  }
  return result;
}

const CSSValue* ComputedStyleUtils::BackgroundPositionOrMaskPosition(
    const CSSProperty& resolved_property,
    const ComputedStyle& style,
    const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(
        *CreatePositionListForLayer(resolved_property, *curr_layer, style));
  }
  return list;
}

const CSSValue* ComputedStyleUtils::BackgroundPositionXOrWebkitMaskPositionX(
    const ComputedStyle& style,
    const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    const Length& from_edge = curr_layer->PositionX();
    if (curr_layer->BackgroundXOrigin() == BackgroundEdgeOrigin::kRight) {
      // TODO(crbug.com/610627): This should use two-value syntax once the
      // parser accepts it.
      list->Append(*ZoomAdjustedPixelValueForLength(
          from_edge.SubtractFromOneHundredPercent(), style));
    } else {
      list->Append(*ZoomAdjustedPixelValueForLength(from_edge, style));
    }
  }
  return list;
}

const CSSValue* ComputedStyleUtils::BackgroundPositionYOrWebkitMaskPositionY(
    const ComputedStyle& style,
    const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    const Length& from_edge = curr_layer->PositionY();
    if (curr_layer->BackgroundYOrigin() == BackgroundEdgeOrigin::kBottom) {
      // TODO(crbug.com/610627): This should use two-value syntax once the
      // parser accepts it.
      list->Append(*ZoomAdjustedPixelValueForLength(
          from_edge.SubtractFromOneHundredPercent(), style));
    } else {
      list->Append(*ZoomAdjustedPixelValueForLength(from_edge, style));
    }
  }
  return list;
}

static CSSNumericLiteralValue* ValueForImageSlice(const Length& slice) {
  CHECK(slice.IsPercent() || slice.IsFixed());
  return CSSNumericLiteralValue::Create(
      slice.Value(), slice.IsPercent()
                         ? CSSPrimitiveValue::UnitType::kPercentage
                         : CSSPrimitiveValue::UnitType::kNumber);
}

cssvalue::CSSBorderImageSliceValue*
ComputedStyleUtils::ValueForNinePieceImageSlice(const NinePieceImage& image) {
  const LengthBox& slices = image.ImageSlices();

  // Create the slices.
  CSSPrimitiveValue* top = ValueForImageSlice(slices.Top());

  CSSPrimitiveValue* right = nullptr;
  CSSPrimitiveValue* bottom = nullptr;
  CSSPrimitiveValue* left = nullptr;
  if (slices.Right() == slices.Top() && slices.Bottom() == slices.Top() &&
      slices.Left() == slices.Top()) {
    right = top;
    bottom = top;
    left = top;
  } else {
    right = ValueForImageSlice(slices.Right());

    if (slices.Bottom() == slices.Top() && slices.Right() == slices.Left()) {
      bottom = top;
      left = right;
    } else {
      bottom = ValueForImageSlice(slices.Bottom());

      if (slices.Left() == slices.Right()) {
        left = right;
      } else {
        left = ValueForImageSlice(slices.Left());
      }
    }
  }

  return MakeGarbageCollected<cssvalue::CSSBorderImageSliceValue>(
      MakeGarbageCollected<CSSQuadValue>(top, right, bottom, left,
                                         CSSQuadValue::kSerializeAsQuad),
      image.Fill());
}

CSSValue* ValueForBorderImageLength(
    const BorderImageLength& border_image_length,
    const ComputedStyle& style) {
  if (border_image_length.IsNumber()) {
    return CSSNumericLiteralValue::Create(border_image_length.Number(),
                                          CSSPrimitiveValue::UnitType::kNumber);

### 提示词
```
这是目录为blink/renderer/core/css/properties/computed_style_utils.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"

#include "base/memory/values_equivalent.h"
#include "third_party/blink/renderer/core/css/basic_shape_functions.h"
#include "third_party/blink/renderer/core/css/css_alternate_value.h"
#include "third_party/blink/renderer/core/css/css_border_image.h"
#include "third_party/blink/renderer/core/css/css_border_image_slice_value.h"
#include "third_party/blink/renderer/core/css/css_bracketed_value_list.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_color_mix_value.h"
#include "third_party/blink/renderer/core/css/css_content_distribution_value.h"
#include "third_party/blink/renderer/core/css/css_counter_value.h"
#include "third_party/blink/renderer/core/css/css_custom_ident_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_feature_value.h"
#include "third_party/blink/renderer/core/css/css_font_style_range_value.h"
#include "third_party/blink/renderer/core/css/css_font_variation_value.h"
#include "third_party/blink/renderer/core/css/css_function_value.h"
#include "third_party/blink/renderer/core/css/css_grid_auto_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_integer_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_grid_template_areas_value.h"
#include "third_party/blink/renderer/core/css/css_initial_value.h"
#include "third_party/blink/renderer/core/css/css_math_function_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_quad_value.h"
#include "third_party/blink/renderer/core/css/css_reflect_value.h"
#include "third_party/blink/renderer/core/css/css_repeat_value.h"
#include "third_party/blink/renderer/core/css/css_scroll_value.h"
#include "third_party/blink/renderer/core/css/css_shadow_value.h"
#include "third_party/blink/renderer/core/css/css_string_value.h"
#include "third_party/blink/renderer/core/css/css_timing_function_value.h"
#include "third_party/blink/renderer/core/css/css_uri_value.h"
#include "third_party/blink/renderer/core/css/css_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/css_view_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_color_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_keyword_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_unit_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_unparsed_value.h"
#include "third_party/blink/renderer/core/css/cssom/cross_thread_unsupported_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_keyword_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unit_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unparsed_value.h"
#include "third_party/blink/renderer/core/css/cssom/css_unsupported_color.h"
#include "third_party/blink/renderer/core/css/cssom_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/properties/shorthands.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/grid/layout_grid.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/svg/transform_helper.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/style/position_area.h"
#include "third_party/blink/renderer/core/style/style_intrinsic_length.h"
#include "third_party/blink/renderer/core/style/style_svg_resource.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/core/svg/svg_rect_element.h"
#include "third_party/blink/renderer/core/svg_element_type_helpers.h"
#include "third_party/blink/renderer/platform/animation/timing_function.h"
#include "third_party/blink/renderer/platform/fonts/font_optical_sizing.h"
#include "third_party/blink/renderer/platform/fonts/font_palette.h"
#include "third_party/blink/renderer/platform/fonts/font_variant_emoji.h"
#include "third_party/blink/renderer/platform/fonts/opentype/font_settings.h"
#include "third_party/blink/renderer/platform/transforms/matrix_3d_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/matrix_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/perspective_transform_operation.h"
#include "third_party/blink/renderer/platform/transforms/skew_transform_operation.h"

namespace blink {

namespace {

const double kFinalStatePercentage = 100.0;
const double kMiddleStatePercentage = 50.0;

CSSValue* ConvertFontPaletteToCSSValue(const blink::FontPalette* palette) {
  switch (palette->GetPaletteNameKind()) {
    case blink::FontPalette::kNormalPalette:
      return CSSIdentifierValue::Create(CSSValueID::kNormal);
    case blink::FontPalette::kLightPalette:
      return CSSIdentifierValue::Create(CSSValueID::kLight);
    case blink::FontPalette::kDarkPalette:
      return CSSIdentifierValue::Create(CSSValueID::kDark);
    case blink::FontPalette::kCustomPalette:
      return MakeGarbageCollected<CSSCustomIdentValue>(
          palette->GetPaletteValuesName());
    case blink::FontPalette::kInterpolablePalette: {
      // TODO(crbug.com/1400620): Change the serialization of palette-mix()
      // function to match color-mix(), i.e.: palette-mix() =
      // palette-mix(<color-interpolation-method> , [ [normal | light | dark |
      // <palette-identifier> | <palette-mix()> ] && <percentage [0,100]>?
      // ]#{2})
      CSSFunctionValue* result =
          MakeGarbageCollected<CSSFunctionValue>(CSSValueID::kPaletteMix);

      CSSValueList* color_space_css_value_list =
          CSSValueList::CreateSpaceSeparated();
      color_space_css_value_list->Append(
          *MakeGarbageCollected<CSSCustomIdentValue>(AtomicString("in")));
      if (palette->GetHueInterpolationMethod().has_value()) {
        color_space_css_value_list->Append(
            *MakeGarbageCollected<CSSCustomIdentValue>(
                AtomicString(Color::SerializeInterpolationSpace(
                    palette->GetColorInterpolationSpace(),
                    *palette->GetHueInterpolationMethod()))));
      } else {
        color_space_css_value_list->Append(
            *MakeGarbageCollected<CSSCustomIdentValue>(
                AtomicString(Color::SerializeInterpolationSpace(
                    palette->GetColorInterpolationSpace()))));
      }
      result->Append(*color_space_css_value_list);

      double start_percentage_ = palette->GetStartPercentage();
      double end_percentage_ = palette->GetEndPercentage();

      CSSValueList* start_palette_with_percentage =
          CSSValueList::CreateSpaceSeparated();
      CSSValue* start = ConvertFontPaletteToCSSValue(palette->GetStart().get());
      start_palette_with_percentage->Append(*start);
      // Percentages in the palette-mix() function should be serialized the same
      // way they are serialized in color-mix() function. If the first
      // percentage is equal 50% and the two specified percentages add to 100%,
      // we should skip the first percentage in the serialization. Second
      // percentage should be skipped if it equals to 50%, or the two specified
      // percentages add to 100%. Compare:
      // https://drafts.csswg.org/css-color-5/#serial-color-mix.
      if (start_percentage_ + end_percentage_ != kFinalStatePercentage ||
          start_percentage_ != kMiddleStatePercentage) {
        CSSValue* param = CSSNumericLiteralValue::Create(
            start_percentage_, CSSPrimitiveValue::UnitType::kPercentage);
        start_palette_with_percentage->Append(*param);
      }
      result->Append(*start_palette_with_percentage);

      CSSValueList* end_palette_with_percentage =
          CSSValueList::CreateSpaceSeparated();
      CSSValue* end = ConvertFontPaletteToCSSValue(palette->GetEnd().get());
      if (*start == *end) {
        return start;
      }
      end_palette_with_percentage->Append(*end);
      if (start_percentage_ + end_percentage_ != kFinalStatePercentage) {
        CSSValue* param = CSSNumericLiteralValue::Create(
            end_percentage_, CSSPrimitiveValue::UnitType::kPercentage);
        end_palette_with_percentage->Append(*param);
      }
      result->Append(*end_palette_with_percentage);

      return result;
    }
    default:
      NOTREACHED();
  }
}

}  // namespace

static Length Negate(const Length& length) {
  if (length.IsCalculated()) {
    NOTREACHED();
  }

  Length ret = Length(-length.GetFloatValue(), length.GetType());
  ret.SetQuirk(length.Quirk());
  return ret;
}

// TODO(rjwright): make this const
CSSValue* ComputedStyleUtils::ZoomAdjustedPixelValueForLength(
    const Length& length,
    const ComputedStyle& style) {
  if (length.IsFixed()) {
    return ZoomAdjustedPixelValue(length.Value(), style);
  }
  return CSSValue::Create(length, style.EffectiveZoom());
}

CSSValue* ComputedStyleUtils::ValueForPosition(const LengthPoint& position,
                                               const ComputedStyle& style) {
  if (position.X().IsAuto()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  if (position.X().IsNone()) {
    return CSSIdentifierValue::Create(CSSValueID::kNormal);
  }

  return MakeGarbageCollected<CSSValuePair>(
      ZoomAdjustedPixelValueForLength(position.X(), style),
      ZoomAdjustedPixelValueForLength(position.Y(), style),
      CSSValuePair::kKeepIdenticalValues);
}

CSSValue* ComputedStyleUtils::ValueForOffset(const ComputedStyle& style,
                                             const LayoutObject* layout_object,
                                             bool allow_visited_style,
                                             CSSValuePhase value_phase) {
  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  CSSValue* position = ValueForPosition(style.OffsetPosition(), style);
  auto* position_identifier_value = DynamicTo<CSSIdentifierValue>(position);
  if (!position_identifier_value ||
      position_identifier_value->GetValueID() == CSSValueID::kAuto) {
    list->Append(*position);
  } else {
    DCHECK_EQ(position_identifier_value->GetValueID(), CSSValueID::kNormal);
  }

  static const CSSProperty* longhands[3] = {&GetCSSPropertyOffsetPath(),
                                            &GetCSSPropertyOffsetDistance(),
                                            &GetCSSPropertyOffsetRotate()};
  for (const CSSProperty* longhand : longhands) {
    const CSSValue* value = longhand->CSSValueFromComputedStyle(
        style, layout_object, allow_visited_style, value_phase);
    DCHECK(value);
    list->Append(*value);
  }

  CSSValue* anchor = ValueForPosition(style.OffsetAnchor(), style);
  auto* anchor_identifier_value = DynamicTo<CSSIdentifierValue>(anchor);
  if (!anchor_identifier_value) {
    // Add a slash before anchor.
    CSSValueList* result = CSSValueList::CreateSlashSeparated();
    result->Append(*list);
    result->Append(*anchor);
    return result;
  }
  DCHECK_EQ(anchor_identifier_value->GetValueID(), CSSValueID::kAuto);
  return list;
}

const CSSValue* ComputedStyleUtils::ValueForColor(
    const StyleColor& style_color,
    const ComputedStyle& style,
    const Color* override_current_color,
    CSSValuePhase value_phase) {
  const Color current_color = override_current_color ? *override_current_color
                                                     : style.GetCurrentColor();
  return cssvalue::CSSColor::Create(
      style_color.Resolve(current_color, style.UsedColorScheme()));
}

const CSSValue* ComputedStyleUtils::CurrentColorOrValidColor(
    const ComputedStyle& style,
    const StyleColor& color,
    CSSValuePhase value_phase) {
  return ValueForColor(color, style, nullptr, value_phase);
}

const blink::Color ComputedStyleUtils::BorderSideColor(
    const ComputedStyle& style,
    const StyleColor& color,
    EBorderStyle border_style,
    bool visited_link,
    bool* is_current_color) {
  Color current_color;
  if (visited_link) {
    current_color = style.GetInternalVisitedCurrentColor();
  } else if (border_style == EBorderStyle::kInset ||
             border_style == EBorderStyle::kOutset ||
             border_style == EBorderStyle::kRidge ||
             border_style == EBorderStyle::kGroove) {
    // FIXME: Treating styled borders with initial color differently causes
    // problems, see crbug.com/316559, crbug.com/276231
    current_color = blink::Color(238, 238, 238);
  } else {
    current_color = style.GetCurrentColor();
  }
  return color.Resolve(current_color, style.UsedColorScheme(),
                       is_current_color);
}

const CSSValue* ComputedStyleUtils::BackgroundImageOrMaskImage(
    const ComputedStyle& style,
    bool allow_visited_style,
    const FillLayer& fill_layer,
    CSSValuePhase value_phase) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &fill_layer;
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    if (curr_layer->GetImage()) {
      list->Append(*curr_layer->GetImage()->ComputedCSSValue(
          style, allow_visited_style, value_phase));
    } else {
      list->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
    }
  }
  return list;
}

const CSSValue* ComputedStyleUtils::ValueForFillSize(
    const FillSize& fill_size,
    const ComputedStyle& style) {
  if (fill_size.type == EFillSizeType::kContain) {
    return CSSIdentifierValue::Create(CSSValueID::kContain);
  }

  if (fill_size.type == EFillSizeType::kCover) {
    return CSSIdentifierValue::Create(CSSValueID::kCover);
  }

  if (fill_size.size.Height().IsAuto()) {
    return ZoomAdjustedPixelValueForLength(fill_size.size.Width(), style);
  }

  return MakeGarbageCollected<CSSValuePair>(
      ZoomAdjustedPixelValueForLength(fill_size.size.Width(), style),
      ZoomAdjustedPixelValueForLength(fill_size.size.Height(), style),
      CSSValuePair::kKeepIdenticalValues);
}

const CSSValue* ComputedStyleUtils::BackgroundImageOrMaskSize(
    const ComputedStyle& style,
    const FillLayer& fill_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &fill_layer;
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(*ValueForFillSize(curr_layer->Size(), style));
  }
  return list;
}

const CSSValueList* ComputedStyleUtils::CreatePositionListForLayer(
    const CSSProperty& property,
    const FillLayer& layer,
    const ComputedStyle& style) {
  CSSValueList* position_list = CSSValueList::CreateSpaceSeparated();
  if (layer.IsBackgroundXOriginSet()) {
    DCHECK(property.IDEquals(CSSPropertyID::kBackgroundPosition) ||
           property.IDEquals(CSSPropertyID::kMaskPosition));
    position_list->Append(
        *CSSIdentifierValue::Create(layer.BackgroundXOrigin()));
  }
  position_list->Append(
      *ZoomAdjustedPixelValueForLength(layer.PositionX(), style));
  if (layer.IsBackgroundYOriginSet()) {
    DCHECK(property.IDEquals(CSSPropertyID::kBackgroundPosition) ||
           property.IDEquals(CSSPropertyID::kMaskPosition));
    position_list->Append(
        *CSSIdentifierValue::Create(layer.BackgroundYOrigin()));
  }
  position_list->Append(
      *ZoomAdjustedPixelValueForLength(layer.PositionY(), style));
  return position_list;
}

const CSSValue* ComputedStyleUtils::ValueForFillRepeat(
    const FillLayer* curr_layer) {
  const auto& fill_repeat = curr_layer->Repeat();

  return MakeGarbageCollected<CSSRepeatStyleValue>(
      CSSIdentifierValue::Create(fill_repeat.x),
      CSSIdentifierValue::Create(fill_repeat.y));
}

const CSSValue* ComputedStyleUtils::RepeatStyle(const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();

  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(*ValueForFillRepeat(curr_layer));
  }

  return list;
}

const CSSValue* ComputedStyleUtils::MaskMode(const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(*CSSIdentifierValue::Create(curr_layer->MaskMode()));
  }
  return list;
}

const CSSValueList* ComputedStyleUtils::ValuesForBackgroundShorthand(
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  CSSValueList* result = CSSValueList::CreateCommaSeparated();
  const FillLayer* curr_layer = &style.BackgroundLayers();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    CSSValueList* list = CSSValueList::CreateSlashSeparated();
    CSSValueList* before_slash = CSSValueList::CreateSpaceSeparated();
    if (!curr_layer->Next()) {  // color only for final layer
      const CSSValue* value =
          GetCSSPropertyBackgroundColor().CSSValueFromComputedStyle(
              style, layout_object, allow_visited_style, value_phase);
      DCHECK(value);
      before_slash->Append(*value);
    }
    before_slash->Append(curr_layer->GetImage()
                             ? *curr_layer->GetImage()->ComputedCSSValue(
                                   style, allow_visited_style, value_phase)
                             : *CSSIdentifierValue::Create(CSSValueID::kNone));
    before_slash->Append(*ValueForFillRepeat(curr_layer));
    before_slash->Append(*CSSIdentifierValue::Create(curr_layer->Attachment()));
    before_slash->Append(*CreatePositionListForLayer(
        GetCSSPropertyBackgroundPosition(), *curr_layer, style));
    list->Append(*before_slash);
    CSSValueList* after_slash = CSSValueList::CreateSpaceSeparated();
    after_slash->Append(*ValueForFillSize(curr_layer->Size(), style));
    after_slash->Append(*CSSIdentifierValue::Create(curr_layer->Origin()));
    after_slash->Append(*CSSIdentifierValue::Create(curr_layer->Clip()));
    list->Append(*after_slash);
    result->Append(*list);
  }
  return result;
}

namespace {

// Append clip and origin vals (https://drafts.fxtf.org/css-masking/#the-mask):
// * If one <geometry-box> value and the no-clip keyword are present then
//   <geometry-box> sets mask-origin and no-clip sets mask-clip to that value.
// * If one <geometry-box> value and no no-clip keyword are present then
//   <geometry-box> sets both mask-origin and mask-clip to that value.
// * If two <geometry-box> values are present, then the first sets mask-origin
//   and the second mask-clip.
// Additionally, simplifies when possible.
void AppendValuesForMaskClipAndOrigin(CSSValueList* result_list,
                                      EFillBox origin,
                                      EFillBox clip) {
  if (origin == clip) {
    // If both values are border-box, omit everything as it is the default.
    if (origin == EFillBox::kBorder) {
      return;
    }
    // If the values are the same, only emit one value. Note that mask-origin
    // does not support no-clip, so there is no need to consider no-clip
    // special cases.
    result_list->Append(*CSSIdentifierValue::Create(origin));
  } else if (origin == EFillBox::kBorder && clip == EFillBox::kNoClip) {
    // Mask-origin does not support no-clip, so mask-origin can be omitted if it
    // is the default.
    result_list->Append(*CSSIdentifierValue::Create(clip));
  } else {
    result_list->Append(*CSSIdentifierValue::Create(origin));
    result_list->Append(*CSSIdentifierValue::Create(clip));
  }
}

}  // namespace

const CSSValueList* ComputedStyleUtils::ValuesForMaskShorthand(
    const StylePropertyShorthand&,
    const ComputedStyle& style,
    const LayoutObject* layout_object,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  // Canonical order (https://drafts.fxtf.org/css-masking/#typedef-mask-layer):
  //   <mask-reference>              ||
  //   <position> [ / <bg-size> ]?   ||
  //   <repeat-style>                ||
  //   <geometry-box>                ||
  //   [ <geometry-box> | no-clip ]  ||
  //   <compositing-operator>        ||
  //   <masking-mode>
  // The logic below omits initial values due to the following spec:
  // https://drafts.csswg.org/cssom/#serialize-a-css-value
  // "If component values can be omitted or replaced with a shorter
  // representation without changing the meaning of the value, omit/replace
  // them".
  CSSValueList* result = CSSValueList::CreateCommaSeparated();
  const FillLayer* layer = &style.MaskLayers();
  for (; layer; layer = layer->Next()) {
    CSSValueList* list = CSSValueList::CreateSpaceSeparated();
    // <mask-reference>
    if (layer->GetImage()) {
      list->Append(*layer->GetImage()->ComputedCSSValue(
          style, allow_visited_style, value_phase));
    }
    // <position> [ / <bg-size> ]?
    if (layer->PositionX() !=
            FillLayer::InitialFillPositionX(EFillLayerType::kMask) ||
        layer->PositionY() !=
            FillLayer::InitialFillPositionY(EFillLayerType::kMask) ||
        layer->Size() != FillLayer::InitialFillSize(EFillLayerType::kMask)) {
      CSSValueList* position_size_list = CSSValueList::CreateSlashSeparated();
      position_size_list->Append(*CreatePositionListForLayer(
          GetCSSPropertyMaskPosition(), *layer, style));
      if (layer->Size() != FillLayer::InitialFillSize(EFillLayerType::kMask)) {
        position_size_list->Append(*ValueForFillSize(layer->Size(), style));
      }
      list->Append(*position_size_list);
    }
    // <repeat-style>
    if (layer->Repeat() !=
        FillLayer::InitialFillRepeat(EFillLayerType::kMask)) {
      list->Append(*ValueForFillRepeat(layer));
    }
    // <geometry-box>
    // [ <geometry-box> | no-clip ]
    AppendValuesForMaskClipAndOrigin(list, layer->Origin(), layer->Clip());
    // <compositing-operator>
    if (layer->CompositingOperator() !=
        FillLayer::InitialFillCompositingOperator(EFillLayerType::kMask)) {
      list->Append(*CSSIdentifierValue::Create(layer->CompositingOperator()));
    }
    // <masking-mode>
    if (layer->MaskMode() !=
        FillLayer::InitialFillMaskMode(EFillLayerType::kMask)) {
      list->Append(*CSSIdentifierValue::Create(layer->MaskMode()));
    }

    if (list->length()) {
      result->Append(*list);
    } else {
      result->Append(*CSSIdentifierValue::Create(CSSValueID::kNone));
    }
  }
  return result;
}

const CSSValue* ComputedStyleUtils::BackgroundPositionOrMaskPosition(
    const CSSProperty& resolved_property,
    const ComputedStyle& style,
    const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    list->Append(
        *CreatePositionListForLayer(resolved_property, *curr_layer, style));
  }
  return list;
}

const CSSValue* ComputedStyleUtils::BackgroundPositionXOrWebkitMaskPositionX(
    const ComputedStyle& style,
    const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    const Length& from_edge = curr_layer->PositionX();
    if (curr_layer->BackgroundXOrigin() == BackgroundEdgeOrigin::kRight) {
      // TODO(crbug.com/610627): This should use two-value syntax once the
      // parser accepts it.
      list->Append(*ZoomAdjustedPixelValueForLength(
          from_edge.SubtractFromOneHundredPercent(), style));
    } else {
      list->Append(*ZoomAdjustedPixelValueForLength(from_edge, style));
    }
  }
  return list;
}

const CSSValue* ComputedStyleUtils::BackgroundPositionYOrWebkitMaskPositionY(
    const ComputedStyle& style,
    const FillLayer* curr_layer) {
  CSSValueList* list = CSSValueList::CreateCommaSeparated();
  for (; curr_layer; curr_layer = curr_layer->Next()) {
    const Length& from_edge = curr_layer->PositionY();
    if (curr_layer->BackgroundYOrigin() == BackgroundEdgeOrigin::kBottom) {
      // TODO(crbug.com/610627): This should use two-value syntax once the
      // parser accepts it.
      list->Append(*ZoomAdjustedPixelValueForLength(
          from_edge.SubtractFromOneHundredPercent(), style));
    } else {
      list->Append(*ZoomAdjustedPixelValueForLength(from_edge, style));
    }
  }
  return list;
}

static CSSNumericLiteralValue* ValueForImageSlice(const Length& slice) {
  CHECK(slice.IsPercent() || slice.IsFixed());
  return CSSNumericLiteralValue::Create(
      slice.Value(), slice.IsPercent()
                         ? CSSPrimitiveValue::UnitType::kPercentage
                         : CSSPrimitiveValue::UnitType::kNumber);
}

cssvalue::CSSBorderImageSliceValue*
ComputedStyleUtils::ValueForNinePieceImageSlice(const NinePieceImage& image) {
  const LengthBox& slices = image.ImageSlices();

  // Create the slices.
  CSSPrimitiveValue* top = ValueForImageSlice(slices.Top());

  CSSPrimitiveValue* right = nullptr;
  CSSPrimitiveValue* bottom = nullptr;
  CSSPrimitiveValue* left = nullptr;
  if (slices.Right() == slices.Top() && slices.Bottom() == slices.Top() &&
      slices.Left() == slices.Top()) {
    right = top;
    bottom = top;
    left = top;
  } else {
    right = ValueForImageSlice(slices.Right());

    if (slices.Bottom() == slices.Top() && slices.Right() == slices.Left()) {
      bottom = top;
      left = right;
    } else {
      bottom = ValueForImageSlice(slices.Bottom());

      if (slices.Left() == slices.Right()) {
        left = right;
      } else {
        left = ValueForImageSlice(slices.Left());
      }
    }
  }

  return MakeGarbageCollected<cssvalue::CSSBorderImageSliceValue>(
      MakeGarbageCollected<CSSQuadValue>(top, right, bottom, left,
                                         CSSQuadValue::kSerializeAsQuad),
      image.Fill());
}

CSSValue* ValueForBorderImageLength(
    const BorderImageLength& border_image_length,
    const ComputedStyle& style) {
  if (border_image_length.IsNumber()) {
    return CSSNumericLiteralValue::Create(border_image_length.Number(),
                                          CSSPrimitiveValue::UnitType::kNumber);
  }
  return CSSValue::Create(border_image_length.length(), style.EffectiveZoom());
}

CSSQuadValue* ComputedStyleUtils::ValueForNinePieceImageQuad(
    const BorderImageLengthBox& box,
    const ComputedStyle& style) {
  // Create the slices.
  CSSValue* top = nullptr;
  CSSValue* right = nullptr;
  CSSValue* bottom = nullptr;
  CSSValue* left = nullptr;

  top = ValueForBorderImageLength(box.Top(), style);

  if (box.Right() == box.Top() && box.Bottom() == box.Top() &&
      box.Left() == box.Top()) {
    right = top;
    bottom = top;
    left = top;
  } else {
    right = ValueForBorderImageLength(box.Right(), style);

    if (box.Bottom() == box.Top() && box.Right() == box.Left()) {
      bottom = top;
      left = right;
    } else {
      bottom = ValueForBorderImageLength(box.Bottom(), style);

      if (box.Left() == box.Right()) {
        left = right;
      } else {
        left = ValueForBorderImageLength(box.Left(), style);
      }
    }
  }
  return MakeGarbageCollected<CSSQuadValue>(top, right, bottom, left,
                                            CSSQuadValue::kSerializeAsQuad);
}

CSSValueID ValueForRepeatRule(int rule) {
  switch (rule) {
    case kRepeatImageRule:
      return CSSValueID::kRepeat;
    case kRoundImageRule:
      return CSSValueID::kRound;
    case kSpaceImageRule:
      return CSSValueID::kSpace;
    default:
      return CSSValueID::kStretch;
  }
}

CSSValue* ComputedStyleUtils::ValueForNinePieceImageRepeat(
    const NinePieceImage& image) {
  CSSIdentifierValue* horizontal_repeat = nullptr;
  CSSIdentifierValue* vertical_repeat = nullptr;

  horizontal_repeat =
      CSSIdentifierValue::Create(ValueForRepeatRule(image.HorizontalRule()));
  if (image.HorizontalRule() == image.VerticalRule()) {
    vertical_repeat = horizontal_repeat;
  } else {
    vertical_repeat =
        CSSIdentifierValue::Create(ValueForRepeatRule(image.VerticalRule()));
  }
  return MakeGarbageCollected<CSSValuePair>(horizontal_repeat, vertical_repeat,
                                            CSSValuePair::kDropIdenticalValues);
}

CSSValue* ComputedStyleUtils::ValueForNinePieceImage(
    const NinePieceImage& image,
    const ComputedStyle& style,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  if (!image.HasImage()) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  // Image first.
  CSSValue* image_value = nullptr;
  if (image.GetImage()) {
    image_value = image.GetImage()->ComputedCSSValue(style, allow_visited_style,
                                                     value_phase);
  }

  // Create the image slice.
  cssvalue::CSSBorderImageSliceValue* image_slices =
      ValueForNinePieceImageSlice(image);

  // Create the border area slices.
  CSSValue* border_slices =
      ValueForNinePieceImageQuad(image.BorderSlices(), style);

  // Create the border outset.
  CSSValue* outset = ValueForNinePieceImageQuad(image.Outset(), style);

  // Create the repeat rules.
  CSSValue* repeat = ValueForNinePieceImageRepeat(image);

  return CreateBorderImageValue(image_value, image_slices, border_slices,
                                outset, repeat);
}

CSSValue* ComputedStyleUtils::ValueForReflection(
    const StyleReflection* reflection,
    const ComputedStyle& style,
    bool allow_visited_style,
    CSSValuePhase value_phase) {
  if (!reflection) {
    return CSSIdentifierValue::Create(CSSValueID::kNone);
  }

  auto* direction = CSSIdentifierValue::Create(reflection->Direction());
  auto* offset = CSSPrimitiveValue::CreateFromLength(reflection->Offset(),
                                                     style.EffectiveZoom());
  return MakeGarbageCollected<cssvalue::CSSReflectValue>(
      direction, offset,
      ValueForNinePieceImage(reflection->Mask(), style, allow_visited_style,
                             value_phase));
}

CSSValue* ComputedStyleUtils::MinWidthOrMinHeightAuto(
    const ComputedStyle& style) {
  if (style.IsFlexOrGridOrCustomItem() && !style.IsEnsuredInDisplayNone()) {
    return CSSIdentifierValue::Create(CSSValueID::kAuto);
  }
  return ZoomAdjustedPixelValue(0, style);
}

CSSValue* ComputedStyleUtils::ValueForPositionOffset(
    const ComputedStyle& style,
    const CSSProperty& property,
    const LayoutObject* layout_object) {
  std::pair<const Length*, const Length*> positions;
  bool is_horizontal_property;
  switch (property.PropertyID()) {
    case CSSPropertyID::kLeft:
      positions = std::make_pair(&style.Left(), &style.Right());
      is_horizontal_property = true;
      break;
    case CSSPropertyID::kRight:
      positions = std::make_pair(&style.Right(), &style.Left());
      is_horizontal_property = true;
      break;
    case CSSPropertyID::kTop:
      positions = std::make_pair(&style.Top(), &style.Bottom());
      is_horizontal_property = false;
      break;
    case CSSPropertyID::kBottom:
      positions = std::make_pair(&style.Bottom(), &style.Top());
      is_horizontal_property = false;
      break;
    default:
      NOTREACHED();
  }
  DCHECK(positions.first && positions.second);

  const Length& offset = *positions.first;
  const Length& opposite = *positions.second;
  const auto* box = DynamicTo<LayoutBox>(layout_object);

  // In this case, the used value is the computed value, so we resolve directly.
  if (offset.IsFixed()) {
    return ZoomAdjustedPixelValueForLength(offset, style);
  }

  if (box && box->IsOutOfFlowPositioned()) {
    // LayoutBox::OutOfFlowInsetsForGetComputedStyle() are relative to the
    // container's writing direction. Convert it to physical.
    const PhysicalBoxStrut& insets =
        box->OutOfFlowInsetsForGetComputedStyle().ConvertToPhysical(
            box->ContainingBlock()->StyleRef().GetWritingDirection());
    LayoutUnit inset;
    switch (property.PropertyID()) {
      case CSSPropertyID::kLeft:
        inset = insets.left;
        break;
      case CSSPropertyID::kTop:
        inset = insets.top;
        break;
      case CSSPropertyID::kRight:
```