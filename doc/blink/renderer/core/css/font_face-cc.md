Response:
The user is asking for a summary of the functionality of the `font_face.cc` file in the Chromium Blink rendering engine. I need to analyze the provided C++ code and identify its core purpose, its relationships to web technologies (JavaScript, HTML, CSS), provide examples of how it's used, consider potential user errors, explain how a user action might lead to this code being executed, and then summarize the file's function.

Here's a breakdown of the steps:

1. **Identify the Core Purpose:** The file name `font_face.cc` strongly suggests that it deals with the `@font-face` CSS at-rule. The included headers confirm this, particularly those related to CSS font objects and parsing.

2. **Analyze Functionality:**  Go through the code, focusing on:
    * **Class Definition:** The `FontFace` class is central. Identify its members and methods.
    * **Creation Methods:**  Look for `Create` methods. How are `FontFace` objects instantiated?  Notice the different overloads for handling string sources and binary data.
    * **Property Setters/Getters:** Examine the methods for setting and getting font properties like `style`, `weight`, `stretch`, etc. Pay attention to how these properties are parsed and stored.
    * **Loading and Error Handling:**  Analyze the `status_`, `SetLoadStatus`, `SetError`, `FontStatusPromise`, and `load` methods. These indicate how font loading is managed.
    * **Callbacks:**  Understand how loading callbacks are used to notify when a font is loaded or fails.
    * **Font Selection Capabilities:**  Examine the `GetFontSelectionCapabilities` method. This seems crucial for matching the font face to specific text styles.

3. **Relate to Web Technologies:**
    * **CSS:** The file directly implements the functionality of the `@font-face` rule, allowing web developers to specify custom fonts. Provide examples of `@font-face` syntax and how its properties map to the `FontFace` class members.
    * **JavaScript:**  The presence of `ScriptPromise` and methods like `load` indicates that JavaScript can interact with `FontFace` objects. Explain how the Font Loading API (specifically the `FontFace` interface) relates to this code.
    * **HTML:**  While not directly involved, HTML elements using CSS that references `@font-face` rules will indirectly trigger this code.

4. **Provide Examples (Input/Output & Usage Errors):**
    * **Input/Output:** For a function like `ParseCSSValue`, provide an example of a CSS string input and what kind of CSSValue object it would produce.
    * **Usage Errors:** Think about common mistakes developers make with `@font-face`, such as incorrect syntax, invalid font URLs, or missing `src` declarations.

5. **Explain User Operation as a Debugging Clue:**  Describe the user actions that would lead the browser to process `@font-face` rules, such as visiting a webpage with such rules in its CSS.

6. **Summarize Functionality (Part 1):**  Focus on the aspects covered in the first part of the file. This will likely revolve around creating `FontFace` objects, setting their properties, and initiating the loading process.

**Pre-computation/Analysis during the thought process:**

* **Header Files:**  Note the included headers and what subsystems they represent (bindings, CSS, DOM, platform). This gives a high-level understanding of the file's dependencies.
* **`FontFaceDescriptors`:** Recognize this structure is used to pass initial property values when creating `FontFace` objects programmatically via JavaScript.
* **`CSSFontFace`:** Understand that `FontFace` is a higher-level abstraction, and `CSSFontFace` is likely the underlying object that handles the actual font loading and management within the CSS engine.
* **Enum `LoadStatusType`:** Pay attention to the different states a font face can be in (unloaded, loading, loaded, error).
* **`ScriptPromise` and Callbacks:**  Distinguish between the promise-based API for JavaScript and the callback mechanism used internally.

By following these steps, I can generate a comprehensive and accurate description of the `font_face.cc` file's functionality, addressing all the user's requirements.
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

#include "third_party/blink/renderer/core/css/font_face.h"

#include "base/metrics/histogram_macros.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_descriptors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_load_status.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_string.h"
#include "third_party/blink/renderer/core/css/binary_data_font_face_source.h"
#include "third_party/blink/renderer/core/css/css_font_face.h"
#include "third_party/blink/renderer/core/css/css_font_face_src_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_font_style_range_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_unicode_range_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/local_font_face_source.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/media_values_dynamic.h"
#include "third_party/blink/renderer/core/css/offscreen_font_selector.h"
#include "third_party/blink/renderer/core/css/parser/at_rule_descriptor_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/remote_font_face_source.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/font_family_names.h"
#include "third_party/blink/renderer/platform/fonts/font_metrics_override.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

namespace {

const CSSValue* ParseCSSValue(const ExecutionContext* context,
                              const String& value,
                              AtRuleDescriptorID descriptor_id) {
  auto* window = DynamicTo<LocalDOMWindow>(context);
  CSSParserContext* parser_context =
      window ? MakeGarbageCollected<CSSParserContext>(*window->document())
             : MakeGarbageCollected<CSSParserContext>(*context);
  return AtRuleDescriptorParser::ParseFontFaceDescriptor(descriptor_id, value,
                                                         *parser_context);
}

CSSFontFace* CreateCSSFontFace(FontFace* font_face,
                               const CSSValue* unicode_range) {
  HeapVector<UnicodeRange> ranges;
  if (const auto* range_list = To<CSSValueList>(unicode_range)) {
    unsigned num_ranges = range_list->length();
    for (unsigned i = 0; i < num_ranges; i++) {
      const auto& range =
          To<cssvalue::CSSUnicodeRangeValue>(range_list->Item(i));
      ranges.push_back(UnicodeRange(range.From(), range.To()));
    }
  }

  return MakeGarbageCollected<CSSFontFace>(font_face, std::move(ranges));
}

const CSSValue* ConvertFontMetricOverrideValue(const CSSValue* parsed_value) {
  if (parsed_value && parsed_value->IsIdentifierValue()) {
    // We store the "normal" keyword value as nullptr
    DCHECK_EQ(CSSValueID::kNormal,
              To<CSSIdentifierValue>(parsed_value)->GetValueID());
    return nullptr;
  }
  return parsed_value;
}

const CSSValue* ConvertSizeAdjustValue(const CSSValue* parsed_value) {
  // We store the initial value 100% as nullptr
  if (parsed_value && To<CSSPrimitiveValue>(parsed_value)->IsHundred() ==
                          CSSPrimitiveValue::BoolStatus::kTrue) {
    return nullptr;
  }
  return parsed_value;
}

}  // namespace

FontFace* FontFace::Create(
    ExecutionContext* execution_context,
    const AtomicString& family,
    const V8UnionArrayBufferOrArrayBufferViewOrString* source,
    const FontFaceDescriptors* descriptors) {
  DCHECK(source);

  switch (source->GetContentType()) {
    case V8UnionArrayBufferOrArrayBufferViewOrString::ContentType::kArrayBuffer:
      return Create(execution_context, family,
                    source->GetAsArrayBuffer()->ByteSpan(), descriptors);
    case V8UnionArrayBufferOrArrayBufferViewOrString::ContentType::
        kArrayBufferView:
      return Create(execution_context, family,
                    source->GetAsArrayBufferView()->ByteSpan(), descriptors);
    case V8UnionArrayBufferOrArrayBufferViewOrString::ContentType::kString:
      return Create(execution_context, family, source->GetAsString(),
                    descriptors);
  }

  NOTREACHED();
}

FontFace* FontFace::Create(ExecutionContext* context,
                           const AtomicString& family,
                           const String& source,
                           const FontFaceDescriptors* descriptors) {
  FontFace* font_face =
      MakeGarbageCollected<FontFace>(context, family, descriptors);

  const CSSValue* src = ParseCSSValue(context, source, AtRuleDescriptorID::Src);
  if (!src || !src->IsValueList()) {
    font_face->SetError(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSyntaxError,
        "The source provided ('" + source +
            "') could not be parsed as a value list."));
  }

  font_face->InitCSSFontFace(context, *src);
  return font_face;
}

FontFace* FontFace::Create(ExecutionContext* context,
                           const AtomicString& family,
                           base::span<const uint8_t> data,
                           const FontFaceDescriptors* descriptors) {
  FontFace* font_face =
      MakeGarbageCollected<FontFace>(context, family, descriptors);
  font_face->InitCSSFontFace(context, data);
  return font_face;
}

FontFace* FontFace::Create(Document* document,
                           const StyleRuleFontFace* font_face_rule,
                           bool is_user_style) {
  const CSSPropertyValueSet& properties = font_face_rule->Properties();

  // Obtain the font-family property and the src property. Both must be defined.
  auto* family = DynamicTo<CSSFontFamilyValue>(
      properties.GetPropertyCSSValue(AtRuleDescriptorID::FontFamily));
  if (!family) {
    return nullptr;
  }
  const CSSValue* src = properties.GetPropertyCSSValue(AtRuleDescriptorID::Src);
  if (!src || !src->IsValueList()) {
    return nullptr;
  }

  FontFace* font_face = MakeGarbageCollected<FontFace>(
      document->GetExecutionContext(), font_face_rule, is_user_style);
  font_face->SetFamilyValue(*family);

  if (font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontStyle) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontWeight) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontStretch) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::UnicodeRange) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontVariant) &&
      font_face->SetPropertyFromStyle(
          properties, AtRuleDescriptorID::FontFeatureSettings) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontDisplay) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::AscentOverride) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::DescentOverride) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::LineGapOverride) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::SizeAdjust) &&
      font_face->GetFontSelectionCapabilities().IsValid()) {
    font_face->InitCSSFontFace(document->GetExecutionContext(), *src);
    return font_face;
  }
  return nullptr;
}

FontFace::FontFace(ExecutionContext* context,
                   const StyleRuleFontFace* style_rule,
                   bool is_user_style)
    : ActiveScriptWrappable<FontFace>({}),
      ExecutionContextClient(context),
      style_rule_(style_rule),
      status_(kUnloaded),
      is_user_style_(is_user_style) {}

FontFace::FontFace(ExecutionContext* context,
                   const AtomicString& family,
                   const FontFaceDescriptors* descriptors)
    : ActiveScriptWrappable<FontFace>({}),
      ExecutionContextClient(context),
      family_(family),
      status_(kUnloaded) {
  SetPropertyFromString(context, descriptors->style(),
                        AtRuleDescriptorID::FontStyle);
  SetPropertyFromString(context, descriptors->weight(),
                        AtRuleDescriptorID::FontWeight);
  SetPropertyFromString(context, descriptors->stretch(),
                        AtRuleDescriptorID::FontStretch);
  SetPropertyFromString(context, descriptors->unicodeRange(),
                        AtRuleDescriptorID::UnicodeRange);
  SetPropertyFromString(context, descriptors->variant(),
                        AtRuleDescriptorID::FontVariant);
  SetPropertyFromString(context, descriptors->featureSettings(),
                        AtRuleDescriptorID::FontFeatureSettings);
  SetPropertyFromString(context, descriptors->display(),
                        AtRuleDescriptorID::FontDisplay);
  SetPropertyFromString(context, descriptors->ascentOverride(),
                        AtRuleDescriptorID::AscentOverride);
  SetPropertyFromString(context, descriptors->descentOverride(),
                        AtRuleDescriptorID::DescentOverride);
  SetPropertyFromString(context, descriptors->lineGapOverride(),
                        AtRuleDescriptorID::LineGapOverride);
  SetPropertyFromString(context, descriptors->sizeAdjust(),
                        AtRuleDescriptorID::SizeAdjust);
}

FontFace::~FontFace() = default;

String FontFace::style() const {
  return style_ ? style_->CssText() : "normal";
}

String FontFace::weight() const {
  return weight_ ? weight_->CssText() : "normal";
}

String FontFace::stretch() const {
  return stretch_ ? stretch_->CssText() : "normal";
}

String FontFace::unicodeRange() const {
  return unicode_range_ ? unicode_range_->CssText() : "U+0-10FFFF";
}

String FontFace::variant() const {
  return variant_ ? variant_->CssText() : "normal";
}

String FontFace::featureSettings() const {
  return feature_settings_ ? feature_settings_->CssText() : "normal";
}

String FontFace::display() const {
  return display_ ? display_->CssText() : "auto";
}

String FontFace::ascentOverride() const {
  return ascent_override_ ? ascent_override_->CssText() : "normal";
}

String FontFace::descentOverride() const {
  return descent_override_ ? descent_override_->CssText() : "normal";
}

String FontFace::lineGapOverride() const {
  return line_gap_override_ ? line_gap_override_->CssText() : "normal";
}

String FontFace::sizeAdjust() const {
  return size_adjust_ ? size_adjust_->CssText() : "100%";
}

void FontFace::setStyle(ExecutionContext* context,
                        const String& s,
                        ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontStyle,
                        &exception_state);
}

void FontFace::setWeight(ExecutionContext* context,
                         const String& s,
                         ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontWeight,
                        &exception_state);
}

void FontFace::setStretch(ExecutionContext* context,
                          const String& s,
                          ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontStretch,
                        &exception_state);
}

void FontFace::setUnicodeRange(ExecutionContext* context,
                               const String& s,
                               ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::UnicodeRange,
                        &exception_state);
}

void FontFace::setVariant(ExecutionContext* context,
                          const String& s,
                          ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontVariant,
                        &exception_state);
}

void FontFace::setFeatureSettings(ExecutionContext* context,
                                  const String& s,
                                  ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontFeatureSettings,
                        &exception_state);
}

void FontFace::setDisplay(ExecutionContext* context,
                          const String& s,
                          ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontDisplay,
                        &exception_state);
}

void FontFace::setAscentOverride(ExecutionContext* context,
                                 const String& s,
                                 ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::AscentOverride,
                        &exception_state);
}

void FontFace::setDescentOverride(ExecutionContext* context,
                                  const String& s,
                                  ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::DescentOverride,
                        &exception_state);
}

void FontFace::setLineGapOverride(ExecutionContext* context,
                                  const String& s,
                                  ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::LineGapOverride,
                        &exception_state);
}

void FontFace::setSizeAdjust(ExecutionContext* context,
                             const String& s,
                             ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::SizeAdjust,
                        &exception_state);
}

void FontFace::SetPropertyFromString(const ExecutionContext* context,
                                     const String& s,
                                     AtRuleDescriptorID descriptor_id,
                                     ExceptionState* exception_state) {
  const CSSValue* value = ParseCSSValue(context, s, descriptor_id);
  if (value && SetPropertyValue(value, descriptor_id)) {
    return;
  }

  String message = "Failed to set '" + s + "' as a property value.";
  if (exception_state) {
    exception_state->ThrowDOMException(DOMExceptionCode::kSyntaxError, message);
  } else {
    SetError(MakeGarbageCollected<DOMException>(DOMExceptionCode::kSyntaxError,
                                                message));
  }
}

bool FontFace::SetPropertyFromStyle(const CSSPropertyValueSet& properties,
                                    AtRuleDescriptorID property_id) {
  return SetPropertyValue(properties.GetPropertyCSSValue(property_id),
                          property_id);
}

bool FontFace::SetPropertyValue(const CSSValue* value,
                                AtRuleDescriptorID descriptor_id) {
  switch (descriptor_id) {
    case AtRuleDescriptorID::FontStyle:
      style_ = value;
      break;
    case AtRuleDescriptorID::FontWeight:
      weight_ = value;
      break;
    case AtRuleDescriptorID::FontStretch:
      stretch_ = value;
      break;
    case AtRuleDescriptorID::UnicodeRange:
      if (value && !value->IsValueList()) {
        return false;
      }
      unicode_range_ = value;
      break;
    case AtRuleDescriptorID::FontVariant:
      variant_ = value;
      break;
    case AtRuleDescriptorID::FontFeatureSettings:
      feature_settings_ = value;
      break;
    case AtRuleDescriptorID::FontDisplay:
      display_ = value;
      if (css_font_face_) {
        css_font_face_->SetDisplay(CSSValueToFontDisplay(display_.Get()));
      }
      break;
    case AtRuleDescriptorID::AscentOverride:
      ascent_override_ = ConvertFontMetricOverrideValue(value);
      break;
    case AtRuleDescriptorID::DescentOverride:
      descent_override_ = ConvertFontMetricOverrideValue(value);
      break;
    case AtRuleDescriptorID::LineGapOverride:
      line_gap_override_ = ConvertFontMetricOverrideValue(value);
      break;
    case AtRuleDescriptorID::SizeAdjust:
      size_adjust_ = ConvertSizeAdjustValue(value);
      break;
    default:
      NOTREACHED();
  }
  return true;
}

void FontFace::SetFamilyValue(const CSSFontFamilyValue& family_value) {
  family_ = family_value.Value();
}

V8FontFaceLoadStatus FontFace::status() const {
  switch (status_) {
    case kUnloaded:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kUnloaded);
    case kLoading:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kLoading);
    case kLoaded:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kLoaded);
    case kError:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kError);
  }
  NOTREACHED();
}

void FontFace::SetLoadStatus(LoadStatusType status) {
  status_ = status;
  DCHECK(status_ != kError || error_);

  if (!GetExecutionContext()) {
    return;
  }

  if (status_ == kLoaded || status_ == kError) {
    if (loaded_property_) {
      if (status_ == kLoaded) {
        GetExecutionContext()
            ->GetTaskRunner(TaskType::kDOMManipulation)
            ->PostTask(FROM_HERE,
                       WTF::BindOnce(&LoadedProperty::Resolve<FontFace*>,
                                     WrapPersistent(loaded_property_.Get()),
                                     WrapPersistent(this)));
      } else {
        GetExecutionContext()
            ->GetTaskRunner(TaskType::kDOMManipulation)
            ->PostTask(FROM_HERE,
                       WTF::BindOnce(&LoadedProperty::Reject<DOMException*>,
                                     WrapPersistent(loaded_property_.Get()),
                                     WrapPersistent(error_.Get())));
      }
    }

    GetExecutionContext()
        ->GetTaskRunner(TaskType::kDOMManipulation)
        ->PostTask(FROM_HERE, WTF::BindOnce(&FontFace::RunCallbacks,
                                            WrapPersistent(this)));
  }
}

void FontFace::RunCallbacks() {
  HeapVector<Member<LoadFontCallback>> callbacks;
  callbacks_.swap(callbacks);
  for (wtf_size_t i = 0; i < callbacks.size(); ++i) {
    if (status_ == kLoaded) {
      callbacks[i]->NotifyLoaded(this);
    } else {
      callbacks[i]->NotifyError(this);
    }
  }
}

void FontFace::SetError(DOMException* error) {
  if (!error_) {
    error_ = error ? error
                   : MakeGarbageCollected<DOMException>(
                         DOMExceptionCode::kNetworkError);
  }
  SetLoadStatus(kError);
}

ScriptPromise<FontFace> FontFace::FontStatusPromise(ScriptState* script_state) {
  if (!loaded_property_) {
    loaded_property_ = MakeGarbageCollected<LoadedProperty>(
        ExecutionContext::From(script_state));
    if (status_ == kLoaded) {
      loaded_property_->Resolve(this);
    } else if (status_ == kError) {
      loaded_property_->Reject(error_.Get());
    }
  }
  return loaded_property_->Promise(script_state->World());
}

ScriptPromise<FontFace> FontFace::load(ScriptState* script_state) {
  if (status_ == kUnloaded) {
    css_font_face_->Load();
  }
  DidBeginImperativeLoad();
  return FontStatusPromise(script_state);
}

void FontFace::LoadWithCallback(LoadFontCallback* callback) {
  if (status_ == kUnloaded) {
    css_font_face_->Load();
  }
  AddCallback(callback);
}

void FontFace::AddCallback(LoadFontCallback* callback) {
  if (status_ == kLoaded) {
    callback->NotifyLoaded(this);
  } else if (status_ == kError) {
    callback->NotifyError(this);
  } else {
    callbacks_.push_back(callback);
  }
}

FontSelectionCapabilities FontFace::GetFontSelectionCapabilities() const {
  // FontSelectionCapabilities represents a range of available width, slope and
  // weight values. The first value of each pair is the minimum value, the
  // second is the maximum value.
  FontSelectionCapabilities normal_capabilities(
      {kNormalWidthValue, kNormalWidthValue},
      {kNormalSlopeValue, kNormalSlopeValue},
      {kNormalWeightValue, kNormalWeightValue});
  FontSelectionCapabilities capabilities(normal_capabilities);

  if (stretch_) {
    if (auto* stretch_identifier_value =
            DynamicTo<CSSIdentifierValue>(stretch_.Get())) {
      switch (stretch_identifier_value->GetValueID()) {
        case CSSValueID::kUltraCondensed:
          capabilities.width = {kUltraCondensedWidthValue,
                                kUltraCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kExtraCondensed:
          capabilities.width = {kExtraCondensedWidthValue,
                                kExtraCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kCondensed:
          capabilities.width = {kCondensedWidthValue, kCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kSemiCondensed:
          capabilities.width = {kSemiCondensedWidthValue,
                                kSemiCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kSemiExpanded:
          capabilities.width = {kSemiExpandedWidthValue,
                                kSemiExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kExpanded:
          capabilities.width = {kExpandedWidthValue, kExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kExtraExpanded:
          capabilities.width = {kExtraExpandedWidthValue,
                                kExtraExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kUltraExpanded:
          capabilities.width = {kUltraExpandedWidthValue,
                                kUltraExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kAuto:
          capabilities.width = {kNormalWidthValue, kNormalWidthValue,
                                FontSelectionRange::RangeType::kSetFromAuto};
          break;
        default:
          break;
      }
    } else if (const auto* stretch_list =
                   DynamicTo<CSSValueList>(stretch_.Get())) {
      // Transition FontFace interpretation of parsed values from
      // CSSIdentifierValue to CSSValueList or CSSPrimitiveValue.
      // TODO(drott) crbug.com/739139: Update the parser to only produce
      // CSSPrimitiveValue or CSSValueList.
      if (stretch_list->length() != 2) {
        return normal_capabilities;
      }
      const auto* stretch_from =
          DynamicTo<CSSPrimitiveValue>(&stretch_list->Item(0));
      const auto* stretch_to =
          DynamicTo<CSSPrimitiveValue>(&stretch_list->Item(1));
      if (!stretch_from || !stretch_to) {
        return normal_capabilities;
      }
      if (!stretch_from->IsPercentage() || !stretch_to->IsPercentage()) {
        return normal_capabilities;
      }
      // https://drafts.csswg.org/css-fonts/#font-prop-desc
      // "User agents must swap the computed value of the startpoint and
      // endpoint of the range in order to forbid decreasing ranges."
      if (stretch_from->ComputeValueInCanonicalUnit(EnsureLengthResolver()) <
          stretch_to->ComputeValueInCanonicalUnit(EnsureLengthResolver())) {
        capabilities.width = {
            FontSelectionValue(stretch_from->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionValue(stretch_to->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionRange::RangeType::kSetExplicitly};
      } else {
        capabilities.width = {
            FontSelectionValue(stretch_to->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionValue(stretch_from->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionRange::RangeType::kSetExplicitly};
      }
    } else if (auto* stretch_primitive_value =
                   DynamicTo<CSSPrimitiveValue>(stretch_.Get())) {
      float stretch_value =
          stretch_primitive_value->ComputeValueInCanonicalUnit(
              EnsureLengthResolver());
      capabilities.width = {FontSelectionValue(stretch_value),
                            FontSelectionValue(stretch_value),
                            FontSelectionRange::RangeType::kSetExplicitly};
    } else {
      NOTREACHED();
    }
  }

  if (style_) {
    if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(style_.Get())) {
      switch (identifier_value->GetValueID()) {
        case CSSValueID::kNormal:
          capabilities.slope = {kNormalSlopeValue, kNormalSlopeValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kOblique:
          capabilities.slope = {kItalicSlopeValue, kItalicSlopeValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kItalic:
          capabilities.slope = {kItalicSlopeValue, kItalicSlopeValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kAuto:
          capabilities.slope = {kNormalSlopeValue, kNormalSlopeValue,
                                FontSelectionRange::RangeType::kSetFromAuto};
          break;
        default:
          break;
      }
    } else
### 提示词
```
这是目录为blink/renderer/core/css/font_face.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
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

#include "third_party/blink/renderer/core/css/font_face.h"

#include "base/metrics/histogram_macros.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_descriptors.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_font_face_load_status.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_arraybuffer_arraybufferview_string.h"
#include "third_party/blink/renderer/core/css/binary_data_font_face_source.h"
#include "third_party/blink/renderer/core/css/css_font_face.h"
#include "third_party/blink/renderer/core/css/css_font_face_src_value.h"
#include "third_party/blink/renderer/core/css/css_font_family_value.h"
#include "third_party/blink/renderer/core/css/css_font_selector.h"
#include "third_party/blink/renderer/core/css/css_font_style_range_value.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_unicode_range_value.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/css_value_pair.h"
#include "third_party/blink/renderer/core/css/local_font_face_source.h"
#include "third_party/blink/renderer/core/css/media_values.h"
#include "third_party/blink/renderer/core/css/media_values_cached.h"
#include "third_party/blink/renderer/core/css/media_values_dynamic.h"
#include "third_party/blink/renderer/core/css/offscreen_font_selector.h"
#include "third_party/blink/renderer/core/css/parser/at_rule_descriptor_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/remote_font_face_source.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css_value_keywords.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_exception.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer.h"
#include "third_party/blink/renderer/core/typed_arrays/dom_array_buffer_view.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_state.h"
#include "third_party/blink/renderer/platform/font_family_names.h"
#include "third_party/blink/renderer/platform/fonts/font_metrics_override.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"

namespace blink {

namespace {

const CSSValue* ParseCSSValue(const ExecutionContext* context,
                              const String& value,
                              AtRuleDescriptorID descriptor_id) {
  auto* window = DynamicTo<LocalDOMWindow>(context);
  CSSParserContext* parser_context =
      window ? MakeGarbageCollected<CSSParserContext>(*window->document())
             : MakeGarbageCollected<CSSParserContext>(*context);
  return AtRuleDescriptorParser::ParseFontFaceDescriptor(descriptor_id, value,
                                                         *parser_context);
}

CSSFontFace* CreateCSSFontFace(FontFace* font_face,
                               const CSSValue* unicode_range) {
  HeapVector<UnicodeRange> ranges;
  if (const auto* range_list = To<CSSValueList>(unicode_range)) {
    unsigned num_ranges = range_list->length();
    for (unsigned i = 0; i < num_ranges; i++) {
      const auto& range =
          To<cssvalue::CSSUnicodeRangeValue>(range_list->Item(i));
      ranges.push_back(UnicodeRange(range.From(), range.To()));
    }
  }

  return MakeGarbageCollected<CSSFontFace>(font_face, std::move(ranges));
}

const CSSValue* ConvertFontMetricOverrideValue(const CSSValue* parsed_value) {
  if (parsed_value && parsed_value->IsIdentifierValue()) {
    // We store the "normal" keyword value as nullptr
    DCHECK_EQ(CSSValueID::kNormal,
              To<CSSIdentifierValue>(parsed_value)->GetValueID());
    return nullptr;
  }
  return parsed_value;
}

const CSSValue* ConvertSizeAdjustValue(const CSSValue* parsed_value) {
  // We store the initial value 100% as nullptr
  if (parsed_value && To<CSSPrimitiveValue>(parsed_value)->IsHundred() ==
                          CSSPrimitiveValue::BoolStatus::kTrue) {
    return nullptr;
  }
  return parsed_value;
}

}  // namespace

FontFace* FontFace::Create(
    ExecutionContext* execution_context,
    const AtomicString& family,
    const V8UnionArrayBufferOrArrayBufferViewOrString* source,
    const FontFaceDescriptors* descriptors) {
  DCHECK(source);

  switch (source->GetContentType()) {
    case V8UnionArrayBufferOrArrayBufferViewOrString::ContentType::kArrayBuffer:
      return Create(execution_context, family,
                    source->GetAsArrayBuffer()->ByteSpan(), descriptors);
    case V8UnionArrayBufferOrArrayBufferViewOrString::ContentType::
        kArrayBufferView:
      return Create(execution_context, family,
                    source->GetAsArrayBufferView()->ByteSpan(), descriptors);
    case V8UnionArrayBufferOrArrayBufferViewOrString::ContentType::kString:
      return Create(execution_context, family, source->GetAsString(),
                    descriptors);
  }

  NOTREACHED();
}

FontFace* FontFace::Create(ExecutionContext* context,
                           const AtomicString& family,
                           const String& source,
                           const FontFaceDescriptors* descriptors) {
  FontFace* font_face =
      MakeGarbageCollected<FontFace>(context, family, descriptors);

  const CSSValue* src = ParseCSSValue(context, source, AtRuleDescriptorID::Src);
  if (!src || !src->IsValueList()) {
    font_face->SetError(MakeGarbageCollected<DOMException>(
        DOMExceptionCode::kSyntaxError,
        "The source provided ('" + source +
            "') could not be parsed as a value list."));
  }

  font_face->InitCSSFontFace(context, *src);
  return font_face;
}

FontFace* FontFace::Create(ExecutionContext* context,
                           const AtomicString& family,
                           base::span<const uint8_t> data,
                           const FontFaceDescriptors* descriptors) {
  FontFace* font_face =
      MakeGarbageCollected<FontFace>(context, family, descriptors);
  font_face->InitCSSFontFace(context, data);
  return font_face;
}

FontFace* FontFace::Create(Document* document,
                           const StyleRuleFontFace* font_face_rule,
                           bool is_user_style) {
  const CSSPropertyValueSet& properties = font_face_rule->Properties();

  // Obtain the font-family property and the src property. Both must be defined.
  auto* family = DynamicTo<CSSFontFamilyValue>(
      properties.GetPropertyCSSValue(AtRuleDescriptorID::FontFamily));
  if (!family) {
    return nullptr;
  }
  const CSSValue* src = properties.GetPropertyCSSValue(AtRuleDescriptorID::Src);
  if (!src || !src->IsValueList()) {
    return nullptr;
  }

  FontFace* font_face = MakeGarbageCollected<FontFace>(
      document->GetExecutionContext(), font_face_rule, is_user_style);
  font_face->SetFamilyValue(*family);

  if (font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontStyle) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontWeight) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontStretch) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::UnicodeRange) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontVariant) &&
      font_face->SetPropertyFromStyle(
          properties, AtRuleDescriptorID::FontFeatureSettings) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::FontDisplay) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::AscentOverride) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::DescentOverride) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::LineGapOverride) &&
      font_face->SetPropertyFromStyle(properties,
                                      AtRuleDescriptorID::SizeAdjust) &&
      font_face->GetFontSelectionCapabilities().IsValid()) {
    font_face->InitCSSFontFace(document->GetExecutionContext(), *src);
    return font_face;
  }
  return nullptr;
}

FontFace::FontFace(ExecutionContext* context,
                   const StyleRuleFontFace* style_rule,
                   bool is_user_style)
    : ActiveScriptWrappable<FontFace>({}),
      ExecutionContextClient(context),
      style_rule_(style_rule),
      status_(kUnloaded),
      is_user_style_(is_user_style) {}

FontFace::FontFace(ExecutionContext* context,
                   const AtomicString& family,
                   const FontFaceDescriptors* descriptors)
    : ActiveScriptWrappable<FontFace>({}),
      ExecutionContextClient(context),
      family_(family),
      status_(kUnloaded) {
  SetPropertyFromString(context, descriptors->style(),
                        AtRuleDescriptorID::FontStyle);
  SetPropertyFromString(context, descriptors->weight(),
                        AtRuleDescriptorID::FontWeight);
  SetPropertyFromString(context, descriptors->stretch(),
                        AtRuleDescriptorID::FontStretch);
  SetPropertyFromString(context, descriptors->unicodeRange(),
                        AtRuleDescriptorID::UnicodeRange);
  SetPropertyFromString(context, descriptors->variant(),
                        AtRuleDescriptorID::FontVariant);
  SetPropertyFromString(context, descriptors->featureSettings(),
                        AtRuleDescriptorID::FontFeatureSettings);
  SetPropertyFromString(context, descriptors->display(),
                        AtRuleDescriptorID::FontDisplay);
  SetPropertyFromString(context, descriptors->ascentOverride(),
                        AtRuleDescriptorID::AscentOverride);
  SetPropertyFromString(context, descriptors->descentOverride(),
                        AtRuleDescriptorID::DescentOverride);
  SetPropertyFromString(context, descriptors->lineGapOverride(),
                        AtRuleDescriptorID::LineGapOverride);
  SetPropertyFromString(context, descriptors->sizeAdjust(),
                        AtRuleDescriptorID::SizeAdjust);
}

FontFace::~FontFace() = default;

String FontFace::style() const {
  return style_ ? style_->CssText() : "normal";
}

String FontFace::weight() const {
  return weight_ ? weight_->CssText() : "normal";
}

String FontFace::stretch() const {
  return stretch_ ? stretch_->CssText() : "normal";
}

String FontFace::unicodeRange() const {
  return unicode_range_ ? unicode_range_->CssText() : "U+0-10FFFF";
}

String FontFace::variant() const {
  return variant_ ? variant_->CssText() : "normal";
}

String FontFace::featureSettings() const {
  return feature_settings_ ? feature_settings_->CssText() : "normal";
}

String FontFace::display() const {
  return display_ ? display_->CssText() : "auto";
}

String FontFace::ascentOverride() const {
  return ascent_override_ ? ascent_override_->CssText() : "normal";
}

String FontFace::descentOverride() const {
  return descent_override_ ? descent_override_->CssText() : "normal";
}

String FontFace::lineGapOverride() const {
  return line_gap_override_ ? line_gap_override_->CssText() : "normal";
}

String FontFace::sizeAdjust() const {
  return size_adjust_ ? size_adjust_->CssText() : "100%";
}

void FontFace::setStyle(ExecutionContext* context,
                        const String& s,
                        ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontStyle,
                        &exception_state);
}

void FontFace::setWeight(ExecutionContext* context,
                         const String& s,
                         ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontWeight,
                        &exception_state);
}

void FontFace::setStretch(ExecutionContext* context,
                          const String& s,
                          ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontStretch,
                        &exception_state);
}

void FontFace::setUnicodeRange(ExecutionContext* context,
                               const String& s,
                               ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::UnicodeRange,
                        &exception_state);
}

void FontFace::setVariant(ExecutionContext* context,
                          const String& s,
                          ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontVariant,
                        &exception_state);
}

void FontFace::setFeatureSettings(ExecutionContext* context,
                                  const String& s,
                                  ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontFeatureSettings,
                        &exception_state);
}

void FontFace::setDisplay(ExecutionContext* context,
                          const String& s,
                          ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::FontDisplay,
                        &exception_state);
}

void FontFace::setAscentOverride(ExecutionContext* context,
                                 const String& s,
                                 ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::AscentOverride,
                        &exception_state);
}

void FontFace::setDescentOverride(ExecutionContext* context,
                                  const String& s,
                                  ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::DescentOverride,
                        &exception_state);
}

void FontFace::setLineGapOverride(ExecutionContext* context,
                                  const String& s,
                                  ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::LineGapOverride,
                        &exception_state);
}

void FontFace::setSizeAdjust(ExecutionContext* context,
                             const String& s,
                             ExceptionState& exception_state) {
  SetPropertyFromString(context, s, AtRuleDescriptorID::SizeAdjust,
                        &exception_state);
}

void FontFace::SetPropertyFromString(const ExecutionContext* context,
                                     const String& s,
                                     AtRuleDescriptorID descriptor_id,
                                     ExceptionState* exception_state) {
  const CSSValue* value = ParseCSSValue(context, s, descriptor_id);
  if (value && SetPropertyValue(value, descriptor_id)) {
    return;
  }

  String message = "Failed to set '" + s + "' as a property value.";
  if (exception_state) {
    exception_state->ThrowDOMException(DOMExceptionCode::kSyntaxError, message);
  } else {
    SetError(MakeGarbageCollected<DOMException>(DOMExceptionCode::kSyntaxError,
                                                message));
  }
}

bool FontFace::SetPropertyFromStyle(const CSSPropertyValueSet& properties,
                                    AtRuleDescriptorID property_id) {
  return SetPropertyValue(properties.GetPropertyCSSValue(property_id),
                          property_id);
}

bool FontFace::SetPropertyValue(const CSSValue* value,
                                AtRuleDescriptorID descriptor_id) {
  switch (descriptor_id) {
    case AtRuleDescriptorID::FontStyle:
      style_ = value;
      break;
    case AtRuleDescriptorID::FontWeight:
      weight_ = value;
      break;
    case AtRuleDescriptorID::FontStretch:
      stretch_ = value;
      break;
    case AtRuleDescriptorID::UnicodeRange:
      if (value && !value->IsValueList()) {
        return false;
      }
      unicode_range_ = value;
      break;
    case AtRuleDescriptorID::FontVariant:
      variant_ = value;
      break;
    case AtRuleDescriptorID::FontFeatureSettings:
      feature_settings_ = value;
      break;
    case AtRuleDescriptorID::FontDisplay:
      display_ = value;
      if (css_font_face_) {
        css_font_face_->SetDisplay(CSSValueToFontDisplay(display_.Get()));
      }
      break;
    case AtRuleDescriptorID::AscentOverride:
      ascent_override_ = ConvertFontMetricOverrideValue(value);
      break;
    case AtRuleDescriptorID::DescentOverride:
      descent_override_ = ConvertFontMetricOverrideValue(value);
      break;
    case AtRuleDescriptorID::LineGapOverride:
      line_gap_override_ = ConvertFontMetricOverrideValue(value);
      break;
    case AtRuleDescriptorID::SizeAdjust:
      size_adjust_ = ConvertSizeAdjustValue(value);
      break;
    default:
      NOTREACHED();
  }
  return true;
}

void FontFace::SetFamilyValue(const CSSFontFamilyValue& family_value) {
  family_ = family_value.Value();
}

V8FontFaceLoadStatus FontFace::status() const {
  switch (status_) {
    case kUnloaded:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kUnloaded);
    case kLoading:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kLoading);
    case kLoaded:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kLoaded);
    case kError:
      return V8FontFaceLoadStatus(V8FontFaceLoadStatus::Enum::kError);
  }
  NOTREACHED();
}

void FontFace::SetLoadStatus(LoadStatusType status) {
  status_ = status;
  DCHECK(status_ != kError || error_);

  if (!GetExecutionContext()) {
    return;
  }

  if (status_ == kLoaded || status_ == kError) {
    if (loaded_property_) {
      if (status_ == kLoaded) {
        GetExecutionContext()
            ->GetTaskRunner(TaskType::kDOMManipulation)
            ->PostTask(FROM_HERE,
                       WTF::BindOnce(&LoadedProperty::Resolve<FontFace*>,
                                     WrapPersistent(loaded_property_.Get()),
                                     WrapPersistent(this)));
      } else {
        GetExecutionContext()
            ->GetTaskRunner(TaskType::kDOMManipulation)
            ->PostTask(FROM_HERE,
                       WTF::BindOnce(&LoadedProperty::Reject<DOMException*>,
                                     WrapPersistent(loaded_property_.Get()),
                                     WrapPersistent(error_.Get())));
      }
    }

    GetExecutionContext()
        ->GetTaskRunner(TaskType::kDOMManipulation)
        ->PostTask(FROM_HERE, WTF::BindOnce(&FontFace::RunCallbacks,
                                            WrapPersistent(this)));
  }
}

void FontFace::RunCallbacks() {
  HeapVector<Member<LoadFontCallback>> callbacks;
  callbacks_.swap(callbacks);
  for (wtf_size_t i = 0; i < callbacks.size(); ++i) {
    if (status_ == kLoaded) {
      callbacks[i]->NotifyLoaded(this);
    } else {
      callbacks[i]->NotifyError(this);
    }
  }
}

void FontFace::SetError(DOMException* error) {
  if (!error_) {
    error_ = error ? error
                   : MakeGarbageCollected<DOMException>(
                         DOMExceptionCode::kNetworkError);
  }
  SetLoadStatus(kError);
}

ScriptPromise<FontFace> FontFace::FontStatusPromise(ScriptState* script_state) {
  if (!loaded_property_) {
    loaded_property_ = MakeGarbageCollected<LoadedProperty>(
        ExecutionContext::From(script_state));
    if (status_ == kLoaded) {
      loaded_property_->Resolve(this);
    } else if (status_ == kError) {
      loaded_property_->Reject(error_.Get());
    }
  }
  return loaded_property_->Promise(script_state->World());
}

ScriptPromise<FontFace> FontFace::load(ScriptState* script_state) {
  if (status_ == kUnloaded) {
    css_font_face_->Load();
  }
  DidBeginImperativeLoad();
  return FontStatusPromise(script_state);
}

void FontFace::LoadWithCallback(LoadFontCallback* callback) {
  if (status_ == kUnloaded) {
    css_font_face_->Load();
  }
  AddCallback(callback);
}

void FontFace::AddCallback(LoadFontCallback* callback) {
  if (status_ == kLoaded) {
    callback->NotifyLoaded(this);
  } else if (status_ == kError) {
    callback->NotifyError(this);
  } else {
    callbacks_.push_back(callback);
  }
}

FontSelectionCapabilities FontFace::GetFontSelectionCapabilities() const {
  // FontSelectionCapabilities represents a range of available width, slope and
  // weight values. The first value of each pair is the minimum value, the
  // second is the maximum value.
  FontSelectionCapabilities normal_capabilities(
      {kNormalWidthValue, kNormalWidthValue},
      {kNormalSlopeValue, kNormalSlopeValue},
      {kNormalWeightValue, kNormalWeightValue});
  FontSelectionCapabilities capabilities(normal_capabilities);

  if (stretch_) {
    if (auto* stretch_identifier_value =
            DynamicTo<CSSIdentifierValue>(stretch_.Get())) {
      switch (stretch_identifier_value->GetValueID()) {
        case CSSValueID::kUltraCondensed:
          capabilities.width = {kUltraCondensedWidthValue,
                                kUltraCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kExtraCondensed:
          capabilities.width = {kExtraCondensedWidthValue,
                                kExtraCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kCondensed:
          capabilities.width = {kCondensedWidthValue, kCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kSemiCondensed:
          capabilities.width = {kSemiCondensedWidthValue,
                                kSemiCondensedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kSemiExpanded:
          capabilities.width = {kSemiExpandedWidthValue,
                                kSemiExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kExpanded:
          capabilities.width = {kExpandedWidthValue, kExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kExtraExpanded:
          capabilities.width = {kExtraExpandedWidthValue,
                                kExtraExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kUltraExpanded:
          capabilities.width = {kUltraExpandedWidthValue,
                                kUltraExpandedWidthValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kAuto:
          capabilities.width = {kNormalWidthValue, kNormalWidthValue,
                                FontSelectionRange::RangeType::kSetFromAuto};
          break;
        default:
          break;
      }
    } else if (const auto* stretch_list =
                   DynamicTo<CSSValueList>(stretch_.Get())) {
      // Transition FontFace interpretation of parsed values from
      // CSSIdentifierValue to CSSValueList or CSSPrimitiveValue.
      // TODO(drott) crbug.com/739139: Update the parser to only produce
      // CSSPrimitiveValue or CSSValueList.
      if (stretch_list->length() != 2) {
        return normal_capabilities;
      }
      const auto* stretch_from =
          DynamicTo<CSSPrimitiveValue>(&stretch_list->Item(0));
      const auto* stretch_to =
          DynamicTo<CSSPrimitiveValue>(&stretch_list->Item(1));
      if (!stretch_from || !stretch_to) {
        return normal_capabilities;
      }
      if (!stretch_from->IsPercentage() || !stretch_to->IsPercentage()) {
        return normal_capabilities;
      }
      // https://drafts.csswg.org/css-fonts/#font-prop-desc
      // "User agents must swap the computed value of the startpoint and
      // endpoint of the range in order to forbid decreasing ranges."
      if (stretch_from->ComputeValueInCanonicalUnit(EnsureLengthResolver()) <
          stretch_to->ComputeValueInCanonicalUnit(EnsureLengthResolver())) {
        capabilities.width = {
            FontSelectionValue(stretch_from->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionValue(stretch_to->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionRange::RangeType::kSetExplicitly};
      } else {
        capabilities.width = {
            FontSelectionValue(stretch_to->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionValue(stretch_from->ComputeValueInCanonicalUnit(
                EnsureLengthResolver())),
            FontSelectionRange::RangeType::kSetExplicitly};
      }
    } else if (auto* stretch_primitive_value =
                   DynamicTo<CSSPrimitiveValue>(stretch_.Get())) {
      float stretch_value =
          stretch_primitive_value->ComputeValueInCanonicalUnit(
              EnsureLengthResolver());
      capabilities.width = {FontSelectionValue(stretch_value),
                            FontSelectionValue(stretch_value),
                            FontSelectionRange::RangeType::kSetExplicitly};
    } else {
      NOTREACHED();
    }
  }

  if (style_) {
    if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(style_.Get())) {
      switch (identifier_value->GetValueID()) {
        case CSSValueID::kNormal:
          capabilities.slope = {kNormalSlopeValue, kNormalSlopeValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kOblique:
          capabilities.slope = {kItalicSlopeValue, kItalicSlopeValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kItalic:
          capabilities.slope = {kItalicSlopeValue, kItalicSlopeValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kAuto:
          capabilities.slope = {kNormalSlopeValue, kNormalSlopeValue,
                                FontSelectionRange::RangeType::kSetFromAuto};
          break;
        default:
          break;
      }
    } else if (const auto* range_value =
                   DynamicTo<cssvalue::CSSFontStyleRangeValue>(style_.Get())) {
      if (range_value->GetFontStyleValue()->IsIdentifierValue()) {
        CSSValueID font_style_id =
            range_value->GetFontStyleValue()->GetValueID();
        if (!range_value->GetObliqueValues()) {
          if (font_style_id == CSSValueID::kNormal) {
            capabilities.slope = {
                kNormalSlopeValue, kNormalSlopeValue,
                FontSelectionRange::RangeType::kSetExplicitly};
          }
          DCHECK(font_style_id == CSSValueID::kItalic ||
                 font_style_id == CSSValueID::kOblique);
          capabilities.slope = {kItalicSlopeValue, kItalicSlopeValue,
                                FontSelectionRange::RangeType::kSetExplicitly};
        } else {
          DCHECK(font_style_id == CSSValueID::kOblique);
          size_t oblique_values_size =
              range_value->GetObliqueValues()->length();
          if (oblique_values_size == 1) {
            const auto& range_start =
                To<CSSPrimitiveValue>(range_value->GetObliqueValues()->Item(0));
            FontSelectionValue oblique_range(
                range_start.ComputeValueInCanonicalUnit(
                    EnsureLengthResolver()));
            capabilities.slope = {
                oblique_range, oblique_range,
                FontSelectionRange::RangeType::kSetExplicitly};
          } else {
            DCHECK_EQ(oblique_values_size, 2u);
            const auto& range_start =
                To<CSSPrimitiveValue>(range_value->GetObliqueValues()->Item(0));
            const auto& range_end =
                To<CSSPrimitiveValue>(range_value->GetObliqueValues()->Item(1));
            // https://drafts.csswg.org/css-fonts/#font-prop-desc
            // "User agents must swap the computed value of the startpoint and
            // endpoint of the range in order to forbid decreasing ranges."
            if (range_start.ComputeValueInCanonicalUnit(
                    EnsureLengthResolver()) <
                range_end.ComputeValueInCanonicalUnit(EnsureLengthResolver())) {
              capabilities.slope = {
                  FontSelectionValue(range_start.ComputeValueInCanonicalUnit(
                      EnsureLengthResolver())),
                  FontSelectionValue(range_end.ComputeValueInCanonicalUnit(
                      EnsureLengthResolver())),
                  FontSelectionRange::RangeType::kSetExplicitly};
            } else {
              capabilities.slope = {
                  FontSelectionValue(range_end.ComputeValueInCanonicalUnit(
                      EnsureLengthResolver())),
                  FontSelectionValue(range_start.ComputeValueInCanonicalUnit(
                      EnsureLengthResolver())),
                  FontSelectionRange::RangeType::kSetExplicitly};
            }
          }
        }
      }
    } else {
      NOTREACHED();
    }
  }

  if (weight_) {
    if (auto* identifier_value = DynamicTo<CSSIdentifierValue>(weight_.Get())) {
      switch (identifier_value->GetValueID()) {
        case CSSValueID::kNormal:
          capabilities.weight = {kNormalWeightValue, kNormalWeightValue,
                                 FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kBold:
          capabilities.weight = {kBoldWeightValue, kBoldWeightValue,
                                 FontSelectionRange::RangeType::kSetExplicitly};
          break;
        case CSSValueID::kAuto:
          capabilities.weight = {kNormalWeightValue, kNormalWeightValue,
```