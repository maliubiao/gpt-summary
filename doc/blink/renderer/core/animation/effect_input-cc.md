Response:
The user wants to understand the functionality of the `effect_input.cc` file in the Chromium Blink rendering engine.

Here's a plan to address the request:

1. **Identify the core purpose:** Analyze the included headers and the overall structure to determine the main responsibilities of the file. It seems related to processing and converting input data for animations.
2. **Break down functionalities:** Examine the individual functions and code blocks to pinpoint specific tasks. Keywords like `Parse`, `Convert`, `Set` suggest data transformation and setting properties.
3. **Relate to web technologies:** Connect the functionalities to JavaScript, HTML, and CSS concepts, providing examples of how the code interacts with these technologies.
4. **Illustrate with logical reasoning:**  Where applicable, create hypothetical scenarios to demonstrate how inputs are transformed into outputs.
5. **Highlight common errors:** Identify potential pitfalls or incorrect usage patterns that developers might encounter.
6. **Summarize the overall function:** Provide a concise overview of the file's purpose based on the analysis.

**Detailed Analysis of the Code Snippet:**

* **Includes:**  The included headers suggest the file deals with:
    * Binding JavaScript objects to C++ (`renderer/bindings/core/v8/*`)
    * Animation concepts (`renderer/core/animation/*`)
    * CSS parsing and manipulation (`renderer/core/css/*`)
    * DOM elements and documents (`renderer/core/dom/*`)
    * Error handling and logging (`renderer/core/frame/FrameConsole`, `renderer/core/inspector/ConsoleMessage`)
    * Generic utilities (`renderer/platform/heap/*`, `renderer/platform/wtf/*`)
* **Namespaces:** The code resides within the `blink` namespace, indicating it's part of the Blink rendering engine.
* **Helper Functions:** The code defines several static helper functions:
    * `ParseCompositeProperty`:  Handles parsing the `composite` property of keyframes.
    * `ParseOffsetFromTimelineRangeOffset`, `ParseOffsetFromCssText`, `ParseOffset`: Functions for parsing different offset formats for keyframes.
    * `SetKeyframeOffset`:  Sets the offset value on a `Keyframe` object.
    * `ExtractPropertyIndexedKeyframeOffsets`: Extracts multiple offsets from a property-indexed keyframe.
    * `SetKeyframeValue`:  Sets the CSS property value on a `StringKeyframe`.
    * `IsAnimatableKeyframeAttribute`: Checks if a given attribute is animatable.
    * `AddPropertyValuePairsForKeyframe`: Extracts animatable properties and their values from a JavaScript keyframe object.
    * `ConvertArrayForm`: Handles conversion of keyframes provided as an array.
    * `GetPropertyIndexedKeyframeValues`: Extracts values for a specific property from a keyframe object.
    * `ConvertObjectForm`: Handles conversion of keyframes provided as an object.

Based on this analysis, the primary function of this code seems to be **processing and converting various input formats (from JavaScript) representing animation keyframes into internal Blink representations.** This involves parsing offsets, easing functions, composite operations, and property values, while also performing validation and error handling.
这是`blink/renderer/core/animation/effect_input.cc`文件的第一部分，其主要功能是**处理和解析来自JavaScript的动画效果输入，并将其转换为Blink内部使用的表示形式，特别是针对关键帧动画。**

更具体地说，它负责：

**1. 解析关键帧数据：**

*   **支持不同的关键帧格式：**  该文件处理两种主要的关键帧定义方式：
    *   **数组形式 (Array Form):**  关键帧以JavaScript数组的形式提供，数组中的每个元素都是一个包含属性及其值的对象。
    *   **对象形式 (Object Form):** 关键帧以一个JavaScript对象的形式提供，对象的键是CSS属性名，值是包含该属性在不同时间点的取值的数组或单个值。
*   **解析关键帧的各个属性：**  它能够解析关键帧对象中的 `offset` (偏移量), `easing` (缓动函数), `composite` (合成操作) 以及其他CSS属性值。
*   **处理不同类型的偏移量：**  支持数字、百分比以及基于命名时间轴范围的偏移量定义。
*   **类型转换和验证：**  将JavaScript中的字符串、数字等类型转换为Blink内部使用的类型，并对输入进行验证，例如偏移量是否在有效范围内。

**2. 与JavaScript, HTML, CSS 的关系：**

*   **JavaScript:** 该文件直接处理来自JavaScript的输入，例如通过 `Animation()` 构造函数或者 `Element.animate()` 方法传递的 `keyframes` 参数。它使用了V8 JavaScript引擎的绑定来与JavaScript对象交互（例如 `v8::Local<v8::Object>`, `NativeValueTraits`）。
    *   **举例：**  JavaScript代码可能如下所示：
        ```javascript
        const element = document.getElementById('myElement');
        element.animate([
          { opacity: 0, offset: 0 },
          { opacity: 1, offset: 1 }
        ], { duration: 1000 });
        ```
        `effect_input.cc` 中的代码会解析这个传递给 `animate` 方法的关键帧数组。
*   **HTML:** 该文件处理的动画通常会应用于HTML元素。虽然文件本身不直接操作HTML结构，但它解析的动画数据会影响HTML元素的样式和渲染。
    *   **举例：** 上述 JavaScript 代码操作了 `myElement` 这个 HTML 元素的 `opacity` 属性。`effect_input.cc` 会解析 `opacity: 0` 和 `opacity: 1` 这两个关键帧值。
*   **CSS:** 该文件大量涉及到CSS属性的解析和处理。它使用Blink的CSS解析器 (`CSSParser`) 和相关工具来理解关键帧中定义的CSS属性和值。
    *   **举例：**  代码中可以看到对 `CSSPropertyID` 的使用，例如 `AnimationInputHelpers::KeyframeAttributeToCSSProperty(property, document)` 用于将JavaScript中的属性名映射到CSS属性ID。`SetKeyframeValue` 函数会根据CSS属性的类型进行相应的处理。

**3. 逻辑推理与假设输入输出：**

假设有以下 JavaScript 输入（数组形式）：

**假设输入:**

```javascript
[
  { transform: 'translateX(0px)', offset: 0 },
  { transform: 'translateX(100px)', offset: 0.5, easing: 'ease-in' },
  { transform: 'translateX(200px)', offset: 1 }
]
```

**逻辑推理:**

`ConvertArrayForm` 函数会被调用。它会遍历数组中的每个对象：

1. 对于第一个对象 `{ transform: 'translateX(0px)', offset: 0 }`:
    *   解析 `offset: 0` 为数字 `0`。
    *   解析 `transform: 'translateX(0px)'`。`KeyframeAttributeToCSSProperty` 会将 `transform` 映射到 `CSSPropertyID::kTransform`。`SetKeyframeValue` 会将 `translateX(0px)` 作为字符串存储在 `StringKeyframe` 对象的 `transform` 属性中。
2. 对于第二个对象 `{ transform: 'translateX(100px)', offset: 0.5, easing: 'ease-in' }`:
    *   解析 `offset: 0.5` 为数字 `0.5`。
    *   解析 `easing: 'ease-in'` 并创建对应的 `TimingFunction` 对象。
    *   解析 `transform: 'translateX(100px)'`。
3. 对于第三个对象 `{ transform: 'translateX(200px)', offset: 1 }`:
    *   解析 `offset: 1` 为数字 `1`。
    *   解析 `transform: 'translateX(200px)'`。

**假设输出:**

`ConvertArrayForm` 函数会返回一个 `StringKeyframeVector`，其中包含三个 `StringKeyframe` 对象，每个对象都包含了对应的 `offset`, `easing` (如果存在), 和 `transform` 属性的值。

**4. 用户或编程常见的使用错误：**

*   **无效的偏移量:**  提供了小于0或大于1的数字偏移量，或者提供了无法解析为数字或百分比的偏移量字符串。
    *   **举例：**  `{ offset: 1.5 }` 或 `{ offset: 'abc' }`
*   **非单调递增的偏移量 (数组形式):**  在数组形式的关键帧中，偏移量不是按升序排列的。
    *   **举例：** `[{ offset: 1 }, { offset: 0 }]`
*   **拼写错误的属性名:**  使用了浏览器无法识别的CSS属性名。
    *   **举例：** `{ backgroudColor: 'red' }` (正确的拼写是 `backgroundColor`)。虽然代码会尝试处理，但可能会导致样式不生效或控制台警告。
*   **无效的属性值:**  为某个CSS属性提供了无效的值。
    *   **举例：** `{ width: 'abc' }`
*   **对象形式中，属性值数组长度不一致:** 在对象形式的关键帧中，如果不同属性的值数组长度不一致，逻辑会比较复杂，可能会循环使用较短的数组值，但理解不当可能导致预期外的动画效果。
*   **尝试动画非动画属性:** 尝试在关键帧中设置无法动画的CSS属性或HTML属性。代码中 `IsAnimatableKeyframeAttribute` 会进行检查，但错误使用仍然可能存在。

**5. 功能归纳 (针对第一部分):**

总而言之，`blink/renderer/core/animation/effect_input.cc` 的第一部分专注于 **将 JavaScript 中定义的关键帧动画数据转换成 Blink 引擎可以理解和处理的内部数据结构**。 它负责解析关键帧的各种属性，处理不同的输入格式，并进行基本的验证。 这为后续的动画计算、合成和渲染奠定了基础。

### 提示词
```
这是目录为blink/renderer/core/animation/effect_input.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *     * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/animation/effect_input.h"

#include "third_party/blink/renderer/bindings/core/v8/dictionary.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/native_value_traits_impl.h"
#include "third_party/blink/renderer/bindings/core/v8/script_iterator.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_base_keyframe.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_base_property_indexed_keyframe.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_timeline_range.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_timeline_range_offset.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_compositeoperationorauto_compositeoperationorautosequence.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_double_doubleorstringortimelinerangeoffsetornullsequence_string_timelinerangeoffset_null.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_double_string_timelinerangeoffset.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_stringsequence.h"
#include "third_party/blink/renderer/core/animation/animation_input_helpers.h"
#include "third_party/blink/renderer/core/animation/compositor_animations.h"
#include "third_party/blink/renderer/core/animation/css/css_animations.h"
#include "third_party/blink/renderer/core/animation/keyframe_effect_model.h"
#include "third_party/blink/renderer/core/animation/string_keyframe.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_value_id_mappings_generated.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/properties/computed_style_utils.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/resolver/element_resolve_context.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/frame_console.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_map.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/hash_map.h"
#include "third_party/blink/renderer/platform/wtf/text/ascii_ctype.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "v8/include/v8.h"

namespace blink {

namespace {

// Names of classes autogenerated from IDL get very long.
// Create shorter aliases.
using BaseKeyframeOffset = V8UnionDoubleOrStringOrTimelineRangeOffset;
using BasePropertyIndexedKeyframeOffset =
    V8UnionDoubleOrDoubleOrStringOrTimelineRangeOffsetOrNullSequenceOrStringOrTimelineRangeOffsetOrNull;

// Converts the composite property of a BasePropertyIndexedKeyframe into a
// vector of std::optional<EffectModel::CompositeOperation> enums.
Vector<std::optional<EffectModel::CompositeOperation>> ParseCompositeProperty(
    const BasePropertyIndexedKeyframe* keyframe) {
  const auto* composite = keyframe->composite();
  switch (composite->GetContentType()) {
    case V8UnionCompositeOperationOrAutoOrCompositeOperationOrAutoSequence::
        ContentType::kCompositeOperationOrAuto:
      return {EffectModel::EnumToCompositeOperation(
          composite->GetAsCompositeOperationOrAuto().AsEnum())};
    case V8UnionCompositeOperationOrAutoOrCompositeOperationOrAutoSequence::
        ContentType::kCompositeOperationOrAutoSequence: {
      Vector<std::optional<EffectModel::CompositeOperation>> result;
      for (const auto& composite_operation :
           composite->GetAsCompositeOperationOrAutoSequence()) {
        result.push_back(EffectModel::EnumToCompositeOperation(
            composite_operation.AsEnum()));
      }
      return result;
    }
  }
  NOTREACHED();
}

struct ParsedOffset {
  TimelineOffset::NamedRange range;
  double relative_offset;
};

std::optional<ParsedOffset> ParseOffsetFromTimelineRangeOffset(
    TimelineRangeOffset* timeline_range_offset,
    ExceptionState& exception_state) {
  ParsedOffset result;
  result.range = timeline_range_offset->hasRangeName()
                     ? timeline_range_offset->rangeName().AsEnum()
                     : TimelineOffset::NamedRange::kNone;
  if (timeline_range_offset->hasOffset()) {
    CSSNumericValue* numeric_value = timeline_range_offset->offset();
    const CSSPrimitiveValue* css_value =
        DynamicTo<CSSPrimitiveValue>(numeric_value->ToCSSValue());

    if (!css_value || !css_value->IsPercentage()) {
      exception_state.ThrowTypeError(
          "CSSNumericValue must be a percentage for a keyframe offset");
      return std::nullopt;
    }
    result.relative_offset = css_value->GetDoubleValue() / 100;
  } else {
    exception_state.ThrowTypeError(
        "timeline offset must be a range offset pair.  Missing the offset.");
    return std::nullopt;
  }
  return result;
}

std::optional<ParsedOffset> ParseOffsetFromCssText(
    Document& document,
    String css_text,
    ExceptionState& exception_state) {
  const CSSParserContext* context =
      document.ElementSheet().Contents()->ParserContext();
  CSSParserTokenStream stream(css_text);
  stream.ConsumeWhitespace();

  // <number>
  {
    CSSParserTokenStream::State savepoint = stream.Save();
    const CSSPrimitiveValue* primitive = css_parsing_utils::ConsumeNumber(
        stream, *context, CSSPrimitiveValue::ValueRange::kAll);
    if (primitive && stream.AtEnd()) {
      return ParsedOffset(
          {TimelineOffset::NamedRange::kNone, primitive->GetValue<double>()});
    }
    stream.Restore(savepoint);
  }

  // <percent>
  {
    CSSParserTokenStream::State savepoint = stream.Save();
    const CSSPrimitiveValue* primitive = css_parsing_utils::ConsumePercent(
        stream, *context, CSSPrimitiveValue::ValueRange::kAll);
    if (primitive && stream.AtEnd()) {
      return ParsedOffset({TimelineOffset::NamedRange::kNone,
                           primitive->GetValue<double>() / 100});
    }
    stream.Restore(savepoint);
  }

  // <range-name> <percent>
  auto* range_name_percent = To<CSSValueList>(
      css_parsing_utils::ConsumeTimelineRangeNameAndPercent(stream, *context));
  if (!range_name_percent || !stream.AtEnd()) {
    exception_state.ThrowTypeError(
        "timeline offset must be of the form [timeline-range-name] "
        "<percentage>");
    return std::nullopt;
  }
  TimelineOffset::NamedRange range =
      To<CSSIdentifierValue>(range_name_percent->Item(0))
          .ConvertTo<TimelineOffset::NamedRange>();
  double relative_offset =
      To<CSSPrimitiveValue>(range_name_percent->Item(1)).GetFloatValue() / 100;

  return ParsedOffset({range, relative_offset});
}

template <typename T>
std::optional<ParsedOffset> ParseOffset(Document& document,
                                        T* keyframe_offset,
                                        ExceptionState& exception_state) {
  if (!keyframe_offset) {
    return std::nullopt;
  }

  if (keyframe_offset->IsDouble()) {
    return ParsedOffset(
        {TimelineOffset::NamedRange::kNone, keyframe_offset->GetAsDouble()});
  }

  if (keyframe_offset->IsTimelineRangeOffset()) {
    return ParseOffsetFromTimelineRangeOffset(
        keyframe_offset->GetAsTimelineRangeOffset(), exception_state);
  }

  if (keyframe_offset->IsString()) {
    return ParseOffsetFromCssText(document, keyframe_offset->GetAsString(),
                                  exception_state);
  }

  // If calling using a PropertyIndexKeyframe, we must already have handled
  // sequences.
  NOTREACHED();
}

void SetKeyframeOffset(Keyframe& keyframe, ParsedOffset& offset) {
  if (offset.range == V8TimelineRange::Enum::kNone) {
    keyframe.SetOffset(offset.relative_offset);
  } else {
    TimelineOffset timeline_offset(
        offset.range, Length::Percent(100 * offset.relative_offset));
    keyframe.SetTimelineOffset(timeline_offset);
  }
}

Vector<std::optional<ParsedOffset>> ExtractPropertyIndexedKeyframeOffsets(
    Document& document,
    BasePropertyIndexedKeyframe& base_property_indexed_keyframe,
    ExceptionState& exception_state) {
  Vector<std::optional<ParsedOffset>> offsets;

  if (!base_property_indexed_keyframe.hasOffset()) {
    return offsets;
  }

  BasePropertyIndexedKeyframeOffset* keyframe_offset =
      base_property_indexed_keyframe.offset();

  if (keyframe_offset->IsNull()) {
    return offsets;
  }

  if (keyframe_offset->IsDoubleOrStringOrTimelineRangeOffsetOrNullSequence()) {
    // iterate through all offsets in the list.
    const HeapVector<Member<BaseKeyframeOffset>>& list =
        keyframe_offset
            ->GetAsDoubleOrStringOrTimelineRangeOffsetOrNullSequence();
    for (BaseKeyframeOffset* base_keyframe_offset : list) {
      std::optional<ParsedOffset> parsed_offset =
          ParseOffset(document, base_keyframe_offset, exception_state);
      offsets.push_back(parsed_offset);
    }
    return offsets;
  }

  std::optional<ParsedOffset> parsed_offset =
      ParseOffset(document, keyframe_offset, exception_state);
  offsets.push_back(parsed_offset);
  return offsets;
}

void SetKeyframeValue(Element* element,
                      Document& document,
                      StringKeyframe& keyframe,
                      const String& property,
                      const String& value,
                      ExecutionContext* execution_context) {
  StyleSheetContents* style_sheet_contents = document.ElementSheet().Contents();
  CSSPropertyID css_property =
      AnimationInputHelpers::KeyframeAttributeToCSSProperty(property, document);
  SecureContextMode secure_context_mode =
      document.GetExecutionContext()
          ? document.GetExecutionContext()->GetSecureContextMode()
          : SecureContextMode::kInsecureContext;
  if (css_property != CSSPropertyID::kInvalid) {
    MutableCSSPropertyValueSet::SetResult set_result =
        css_property == CSSPropertyID::kVariable
            ? keyframe.SetCSSPropertyValue(AtomicString(property), value,
                                           secure_context_mode,
                                           style_sheet_contents)
            : keyframe.SetCSSPropertyValue(css_property, value,
                                           secure_context_mode,
                                           style_sheet_contents);
    if (set_result == MutableCSSPropertyValueSet::kParseError &&
        execution_context) {
      if (document.GetFrame()) {
        document.GetFrame()->Console().AddMessage(
            MakeGarbageCollected<ConsoleMessage>(
                mojom::ConsoleMessageSource::kJavaScript,
                mojom::ConsoleMessageLevel::kWarning,
                "Invalid keyframe value for property " + property + ": " +
                    value));
      }
    }
    return;
  }
  css_property =
      AnimationInputHelpers::KeyframeAttributeToPresentationAttribute(property,
                                                                      element);
  if (css_property != CSSPropertyID::kInvalid) {
    keyframe.SetPresentationAttributeValue(CSSProperty::Get(css_property),
                                           value, secure_context_mode,
                                           style_sheet_contents);
    return;
  }
  const QualifiedName* svg_attribute =
      AnimationInputHelpers::KeyframeAttributeToSVGAttribute(property, element);
  if (svg_attribute)
    keyframe.SetSVGAttributeValue(*svg_attribute, value);
}

bool IsAnimatableKeyframeAttribute(const String& property,
                                   Element* element,
                                   const Document& document) {
  CSSPropertyID css_property =
      AnimationInputHelpers::KeyframeAttributeToCSSProperty(property, document);
  if (css_property != CSSPropertyID::kInvalid) {
    return !CSSAnimations::IsAnimationAffectingProperty(
        CSSProperty::Get(css_property));
  }

  css_property =
      AnimationInputHelpers::KeyframeAttributeToPresentationAttribute(property,
                                                                      element);
  if (css_property != CSSPropertyID::kInvalid)
    return true;

  return !!AnimationInputHelpers::KeyframeAttributeToSVGAttribute(property,
                                                                  element);
}

void AddPropertyValuePairsForKeyframe(
    v8::Isolate* isolate,
    v8::Local<v8::Object> keyframe_obj,
    Element* element,
    const Document& document,
    Vector<std::pair<String, String>>& property_value_pairs,
    ExceptionState& exception_state) {
  Vector<String> keyframe_properties =
      GetOwnPropertyNames(isolate, keyframe_obj, exception_state);
  if (exception_state.HadException())
    return;

  // By spec, we must sort the properties in "ascending order by the Unicode
  // codepoints that define each property name."
  std::sort(keyframe_properties.begin(), keyframe_properties.end(),
            WTF::CodeUnitCompareLessThan);

  TryRethrowScope rethrow_scope(isolate, exception_state);
  for (const auto& property : keyframe_properties) {
    if (property == "offset" || property == "float" ||
        property == "composite" || property == "easing") {
      continue;
    }

    // By spec, we are not allowed to access any non-animatable property.
    if (!IsAnimatableKeyframeAttribute(property, element, document))
      continue;

    // By spec, we are only allowed to access a given (property, value) pair
    // once. This is observable by the web client, so we take care to adhere
    // to that.
    v8::Local<v8::Value> v8_value;
    if (!keyframe_obj
             ->Get(isolate->GetCurrentContext(), V8String(isolate, property))
             .ToLocal(&v8_value)) {
      return;
    }

    if (v8_value->IsArray()) {
      // Since allow-lists is false, array values should be ignored.
      continue;
    }

    String string_value = NativeValueTraits<IDLString>::NativeValue(
        isolate, v8_value, exception_state);
    if (exception_state.HadException())
      return;
    property_value_pairs.push_back(std::make_pair(property, string_value));
  }
}

StringKeyframeVector ConvertArrayForm(Element* element,
                                      Document& document,
                                      ScriptIterator iterator,
                                      ScriptState* script_state,
                                      ExceptionState& exception_state) {
  v8::Isolate* isolate = script_state->GetIsolate();

  // https://www.w3.org/TR/web-animations-1/#processing-a-keyframes-argument
  // This implementation relaxes steps 6 and 7, which require the keyframes to
  // be loosely sorted and bounded between 0 and 1.  The sorting and bounds
  // only apply to keyframes without timeline offsets.

  // This loop captures step 5 of the procedure to process a keyframes argument,
  // in the case where the argument is iterable.
  HeapVector<Member<const BaseKeyframe>> processed_base_keyframes;
  Vector<Vector<std::pair<String, String>>> processed_properties;
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  while (iterator.Next(execution_context, exception_state)) {
    CHECK(!exception_state.HadException());

    // The value should already be non-empty, as guaranteed by the call to Next
    // and the exception_state check above.
    v8::Local<v8::Value> keyframe = iterator.GetValue().ToLocalChecked();

    if (!keyframe->IsObject() && !keyframe->IsNullOrUndefined()) {
      exception_state.ThrowTypeError(
          "Keyframes must be objects, or null or undefined");
      return {};
    }

    BaseKeyframe* base_keyframe = NativeValueTraits<BaseKeyframe>::NativeValue(
        isolate, keyframe, exception_state);
    Vector<std::pair<String, String>> property_value_pairs;
    if (exception_state.HadException())
      return {};

    if (!keyframe->IsNullOrUndefined()) {
      AddPropertyValuePairsForKeyframe(
          isolate, v8::Local<v8::Object>::Cast(keyframe), element, document,
          property_value_pairs, exception_state);
      if (exception_state.HadException())
        return {};
    }

    processed_base_keyframes.push_back(base_keyframe);
    processed_properties.push_back(property_value_pairs);
  }
  // If the very first call to next() throws the above loop will never be
  // entered, so we have to catch that here.
  if (exception_state.HadException())
    return {};

  // 6. If processed keyframes is not loosely sorted by offset, throw a
  //    TypeError and abort these steps.
  double previous_offset = -std::numeric_limits<double>::infinity();
  Vector<std::optional<ParsedOffset>> offsets;
  const wtf_size_t num_processed_keyframes = processed_base_keyframes.size();
  for (wtf_size_t i = 0; i < num_processed_keyframes; ++i) {
    const BaseKeyframe* base_keyframe = processed_base_keyframes[i];
    std::optional<ParsedOffset> offset =
        ParseOffset(document, base_keyframe->offset(), exception_state);
    if (exception_state.HadException()) {
      return {};
    }
    offsets.push_back(offset);

    if (!offset || offset->range != TimelineOffset::NamedRange::kNone) {
      continue;
    }

    double numeric_offset = offset->relative_offset;
    if (numeric_offset < previous_offset) {
      exception_state.ThrowTypeError(
          "Offsets must be monotonically non-decreasing.");
      return {};
    }
    previous_offset = numeric_offset;
  }

  // 7. If there exist any keyframe in processed keyframes whose keyframe
  //    offset is non-null and less than zero or greater than one, throw a
  //    TypeError and abort these steps.
  for (wtf_size_t i = 0; i < num_processed_keyframes; ++i) {
    std::optional<ParsedOffset> offset = offsets[i];
    if (!offset || offset->range != TimelineOffset::NamedRange::kNone) {
      continue;
    }

    double numeric_offset = offset->relative_offset;
    if (numeric_offset < 0 || numeric_offset > 1) {
      exception_state.ThrowTypeError(
          "Offsets must be null or in the range [0,1].");
      return {};
    }
  }

  StringKeyframeVector keyframes;
  for (wtf_size_t i = 0; i < num_processed_keyframes; ++i) {
    // Now we create the actual Keyframe object. We start by assigning the
    // offset and composite values; conceptually these were actually added in
    // step 5 above but we didn't have a keyframe object then.
    auto* keyframe = MakeGarbageCollected<StringKeyframe>();
    if (offsets[i]) {
      SetKeyframeOffset(*keyframe, offsets[i].value());
    }

    // 8.1. For each property-value pair in frame, parse the property value
    // using the syntax specified for that property.
    const BaseKeyframe* base_keyframe = processed_base_keyframes[i];
    for (const auto& pair : processed_properties[i]) {
      // TODO(crbug.com/777971): Make parsing of property values spec-compliant.
      SetKeyframeValue(element, document, *keyframe, pair.first, pair.second,
                       execution_context);
    }

    std::optional<EffectModel::CompositeOperation> composite =
        EffectModel::EnumToCompositeOperation(
            base_keyframe->composite().AsEnum());
    if (composite) {
      keyframe->SetComposite(composite.value());
    }

    // 8.2. Let the timing function of frame be the result of parsing the
    // “easing” property on frame using the CSS syntax defined for the easing
    // property of the AnimationEffectTimingReadOnly interface.
    //
    // If parsing the “easing” property fails, throw a TypeError and abort this
    // procedure.
    scoped_refptr<TimingFunction> timing_function =
        AnimationInputHelpers::ParseTimingFunction(base_keyframe->easing(),
                                                   &document, exception_state);
    if (!timing_function)
      return {};
    keyframe->SetEasing(timing_function);

    keyframes.push_back(keyframe);
  }

  DCHECK(!exception_state.HadException());
  return keyframes;
}

// Extracts the values for a given property in the input keyframes. As per the
// spec property values for the object-notation form have type (DOMString or
// sequence<DOMString>).
bool GetPropertyIndexedKeyframeValues(const v8::Local<v8::Object>& keyframe,
                                      const String& property,
                                      ScriptState* script_state,
                                      ExceptionState& exception_state,
                                      Vector<String>& result) {
  DCHECK(result.empty());

  // By spec, we are only allowed to access a given (property, value) pair once.
  // This is observable by the web client, so we take care to adhere to that.
  v8::Local<v8::Value> v8_value;
  v8::Local<v8::Context> context = script_state->GetContext();
  v8::Isolate* isolate = script_state->GetIsolate();
  TryRethrowScope rethrow_scope(isolate, exception_state);
  if (!keyframe->Get(context, V8String(isolate, property)).ToLocal(&v8_value)) {
    return {};
  }

  auto* string_or_string_sequence =
      V8UnionStringOrStringSequence::Create(isolate, v8_value, exception_state);
  if (exception_state.HadException())
    return false;

  switch (string_or_string_sequence->GetContentType()) {
    case V8UnionStringOrStringSequence::ContentType::kString:
      result.push_back(string_or_string_sequence->GetAsString());
      break;
    case V8UnionStringOrStringSequence::ContentType::kStringSequence:
      result = string_or_string_sequence->GetAsStringSequence();
      break;
  }

  return true;
}

// Implements the procedure to "process a keyframes argument" from the
// web-animations spec for an object form keyframes argument.
//
// See https://w3.org/TR/web-animations-1/#processing-a-keyframes-argument
StringKeyframeVector ConvertObjectForm(Element* element,
                                       Document& document,
                                       const v8::Local<v8::Object>& v8_keyframe,
                                       ScriptState* script_state,
                                       ExceptionState& exception_state) {
  // We implement much of this procedure out of order from the way the spec is
  // written, to avoid repeatedly going over the list of keyframes.
  // The web-observable behavior should be the same as the spec.

  // Extract the offset, easing, and composite as per step 1 of the 'procedure
  // to process a keyframe-like object'.
  BasePropertyIndexedKeyframe* property_indexed_keyframe =
      NativeValueTraits<BasePropertyIndexedKeyframe>::NativeValue(
          script_state->GetIsolate(), v8_keyframe, exception_state);
  if (exception_state.HadException())
    return {};

  Vector<std::optional<ParsedOffset>> offsets =
      ExtractPropertyIndexedKeyframeOffsets(
          document, *property_indexed_keyframe, exception_state);
  if (exception_state.HadException()) {
    return {};
  }

  // The web-animations spec explicitly states that easings should be kept as
  // DOMStrings here and not parsed into timing functions until later.
  Vector<String> easings;
  if (property_indexed_keyframe->easing()->IsString())
    easings.push_back(property_indexed_keyframe->easing()->GetAsString());
  else
    easings = property_indexed_keyframe->easing()->GetAsStringSequence();

  Vector<std::optional<EffectModel::CompositeOperation>> composite_operations =
      ParseCompositeProperty(property_indexed_keyframe);

  // Next extract all animatable properties from the input argument and iterate
  // through them, processing each as a list of values for that property. This
  // implements both steps 2-7 of the 'procedure to process a keyframe-like
  // object' and step 5.2 of the 'procedure to process a keyframes argument'.

  Vector<String> keyframe_properties = GetOwnPropertyNames(
      script_state->GetIsolate(), v8_keyframe, exception_state);
  if (exception_state.HadException())
    return {};

  // Steps 5.2 - 5.4 state that the user agent is to:
  //
  //   * Create sets of 'property keyframes' with no offset.
  //   * Calculate computed offsets for each set of keyframes individually.
  //   * Join the sets together and merge those with identical computed offsets.
  //
  // This is equivalent to just keeping a hashmap from computed offset to a
  // single keyframe, which simplifies the parsing logic.
  HeapHashMap<double, Member<StringKeyframe>> keyframes;

  // By spec, we must sort the properties in "ascending order by the Unicode
  // codepoints that define each property name."
  std::sort(keyframe_properties.begin(), keyframe_properties.end(),
            WTF::CodeUnitCompareLessThan);

  for (const auto& property : keyframe_properties) {
    if (property == "offset" || property == "float" ||
        property == "composite" || property == "easing") {
      continue;
    }

    // By spec, we are not allowed to access any non-animatable property.
    if (!IsAnimatableKeyframeAttribute(property, element, document))
      continue;

    Vector<String> values;
    if (!GetPropertyIndexedKeyframeValues(v8_keyframe, property, script_state,
                                          exception_state, values)) {
      return {};
    }

    // Now create a keyframe (or retrieve and augment an existing one) for each
    // value this property maps to. As explained above, this loop performs both
    // the initial creation and merging mentioned in the spec.
    wtf_size_t num_keyframes = values.size();
    ExecutionContext* execution_context = ExecutionContext::From(script_state);
    for (wtf_size_t i = 0; i < num_keyframes; ++i) {
      // As all offsets are null for these 'property keyframes', the computed
      // offset is just the fractional position of each keyframe in the array.
      //
      // The only special case is that when there is only one keyframe the sole
      // computed offset is defined as 1.
      double computed_offset =
          (num_keyframes == 1) ? 1 : i / double(num_keyframes - 1);

      auto result = keyframes.insert(computed_offset, nullptr);
      if (result.is_new_entry)
        result.stored_value->value = MakeGarbageCollected<StringKeyframe>();

      SetKeyframeValue(element, document, *result.stored_value->value, property,
                       values[i], execution_context);
    }
  }

  // 5.3 Sort processed keyframes by the computed keyframe offset of each
  // keyframe in increasing order.
  Vector<double> keys;
  WTF::CopyKeysToVector(keyframes, keys);
  std::sort(keys.begin(), keys.end());

  // Steps 5.5 - 5.12 deal with assigning the user-specified offset, easing, and
  // composite properties to the keyframes.
  //
  // This loop also implements steps 6, 7, and 8 of the spec. Because nothing is
  // user-observable at this point, we can operate out of order. Note that this
  // may result in us throwing a different order of TypeErrors than other user
  // agents[1], but as all exceptions are TypeErrors this is not observable by
  // the web client.
  //
  // [1] E.g. if the offsets are [2, 0] we will throw due to the first offset
  //     being > 1 before we throw due to the offsets not being loosely ordered.
  StringKeyframeVector results;
  double previous_offset = 0.0;
  for (wtf_size_t i = 0; i < keys.size(); i++) {
    auto* keyframe = keyframes.at(keys[i]);

    if (i < offsets.size()) {
      std::optional<ParsedOffset> parsed_offset = offsets[i];
      std::optional<double> numeric_offset;
      if (parsed_offset.has_value() &&
          parsed_offset.value().range == TimelineOffset::NamedRange::kNone) {
        numeric_offset = parsed_offset.value().relative_offset;
      }

      // 6. If processed keyframes is not loosely sorted by offset, throw a
      // TypeError and abort these steps.
      if (numeric_offset.has_value()) {
        if (numeric_offset.value() < previous_offset) {
          exception_state.ThrowTypeError(
              "Offsets must be monotonically non-decreasing.");
          return {};
        }
        previous_offset = numeric_offset.value();
      }

      // 7. If there exist any keyframe in processed keyframes whose keyframe
      // offset is non-null and less than zero or greater than one, throw a
      // TypeError and abort these steps.
      if (numeric_offset.has_value() &&
          (numeric_offset.value() < 0 || numeric_offset.value() > 1)) {
        exception_state.ThrowTypeError(
            "Offsets must be null or in the range [0,1].");
        return {};
      }
      if (parsed_offset) {
        SetKeyframeOffset(*keyframe, parsed_offset.value());
      }
    }

    // At this point in the code we have read all the properties we will read
    // from the input object, so it is safe to parse the easing strings. See the
    // note on step 8.2.
    if (!easings.empty()) {
      // 5.9 If easings has fewer items than property keyframes, repeat the
      // elements in easings successively starting from the beginning of the
      // list until easings has as many items as property keyframes.
      const String& easing = easings[i % easings.size()];

      // 8.2 Let the timing function of frame be the result of parsing the
      // "easing" property on frame using the CSS syntax defined for the easing
      // property of the AnimationEffectTimingReadOnly interface.
      //
      // If parsing the “easing” property fails, throw a TypeError and abort
      // this procedure.
      scoped_refptr<TimingFunction> timing_function =
          AnimationInputHelpers::ParseTimingFunction(easing, &document,
                                                     exception_state);
      if (!timing_function)
        return {};

      keyframe->SetEasing(timing_function);
    }

    if (!composite_operations.empty()) {
      // 5.12.2 As with easings, if composite modes has fewer items than
      // property keyframes, repeat the elements in composite modes successively
      // starting from the beginning of the list until composite modes has as
      // many items as property keyframes.
      std::optional<EffectModel::CompositeOperation> composite =
          composite_operations[i % composite_operations.size()];
      if (composite) {
        keyframe->SetComposite(composite.value());
      }
    }

    results.push_back(keyframe);
  }

  // Step 8 of the spec is done above (or will be): parsing property values
  // according to syntax for the property (discarding with console warning on
  // fail) and parsing each easing property.
  // TODO(crbug.com/777971): Fix parsing of property values to adhere to spec.

  // 9. Parse each of the values in unused easings using the CSS syntax defined
```