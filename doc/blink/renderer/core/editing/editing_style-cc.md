Response:

Prompt: 
```
这是目录为blink/renderer/core/editing/editing_style.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2007, 2008, 2009 Apple Computer, Inc.
 * Copyright (C) 2010, 2011 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include "third_party/blink/renderer/core/editing/editing_style.h"

#include "base/memory/values_equivalent.h"
#include "base/stl_util.h"
#include "mojo/public/mojom/base/text_direction.mojom-blink.h"
#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_computed_style_declaration.h"
#include "third_party/blink/renderer/core/css/css_identifier_value.h"
#include "third_party/blink/renderer/core/css/css_numeric_literal_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value.h"
#include "third_party/blink/renderer/core/css/css_primitive_value_mappings.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_value_list.h"
#include "third_party/blink/renderer/core/css/font_size_functions.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_property.h"
#include "third_party/blink/renderer/core/css/properties/longhands.h"
#include "third_party/blink/renderer/core/css/properties/shorthands.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/editing/commands/apply_style_command.h"
#include "third_party/blink/renderer/core/editing/editing_style_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_tri_state.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/serializers/html_interchange.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_font_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style_property_shorthand.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"

namespace blink {

// Editing style properties must be preserved during editing operation.
// e.g. when a user inserts a new paragraph, all properties listed here must be
// copied to the new paragraph.
// NOTE: Use either allEditingProperties() or inheritableEditingProperties() to
// respect runtime enabling of properties.
static const CSSPropertyID kStaticEditingProperties[] = {
    CSSPropertyID::kBackgroundColor,
    CSSPropertyID::kColor,
    CSSPropertyID::kFontFamily,
    CSSPropertyID::kFontSize,
    CSSPropertyID::kFontStyle,
    CSSPropertyID::kFontVariantLigatures,
    CSSPropertyID::kFontVariantCaps,
    CSSPropertyID::kFontWeight,
    CSSPropertyID::kLetterSpacing,
    CSSPropertyID::kOrphans,
    CSSPropertyID::kTextAlign,
    CSSPropertyID::kTextDecorationLine,
    CSSPropertyID::kTextIndent,
    CSSPropertyID::kTextTransform,
    CSSPropertyID::kWidows,
    CSSPropertyID::kWordSpacing,
    CSSPropertyID::kWebkitTextDecorationsInEffect,
    CSSPropertyID::kWebkitTextFillColor,
    CSSPropertyID::kWebkitTextStrokeColor,
    CSSPropertyID::kWebkitTextStrokeWidth,
    CSSPropertyID::kCaretColor,
    CSSPropertyID::kTextWrapMode,
    CSSPropertyID::kWhiteSpaceCollapse,
};

enum EditingPropertiesType {
  kOnlyInheritableEditingProperties,
  kAllEditingProperties
};

static const Vector<const CSSProperty*>& AllEditingProperties(
    const ExecutionContext* execution_context) {
  DEFINE_STATIC_LOCAL(Vector<const CSSProperty*>, properties, ());
  if (properties.empty()) {
    properties.ReserveInitialCapacity(std::size(kStaticEditingProperties) + 2);
    CSSProperty::FilterWebExposedCSSPropertiesIntoVector(
        execution_context, kStaticEditingProperties,
        std::size(kStaticEditingProperties), properties);
  }
  return properties;
}

static const Vector<const CSSProperty*>& InheritableEditingProperties(
    const ExecutionContext* execution_context) {
  DEFINE_STATIC_LOCAL(Vector<const CSSProperty*>, properties, ());
  if (properties.empty()) {
    const Vector<const CSSProperty*>& all =
        AllEditingProperties(execution_context);
    properties.ReserveInitialCapacity(all.size());
    for (const CSSProperty* property : all) {
      if (property->IsInherited()) {
        properties.push_back(property);
      }
    }
  }
  return properties;
}

template <class StyleDeclarationType>
static MutableCSSPropertyValueSet* CopyEditingProperties(
    const ExecutionContext* execution_context,
    StyleDeclarationType* style,
    EditingPropertiesType type = kOnlyInheritableEditingProperties) {
  if (type == kAllEditingProperties)
    return style->CopyPropertiesInSet(AllEditingProperties(execution_context));
  return style->CopyPropertiesInSet(
      InheritableEditingProperties(execution_context));
}

static inline bool IsEditingProperty(ExecutionContext* execution_context,
                                     CSSPropertyID id) {
  static const Vector<const CSSProperty*>& properties =
      AllEditingProperties(execution_context);
  for (wtf_size_t index = 0; index < properties.size(); index++) {
    if (properties[index]->IDEquals(id))
      return true;
  }
  return false;
}

static MutableCSSPropertyValueSet* GetPropertiesNotIn(
    CSSPropertyValueSet* style_with_redundant_properties,
    Node*,
    CSSStyleDeclaration* base_style,
    SecureContextMode);
enum LegacyFontSizeMode {
  kAlwaysUseLegacyFontSize,
  kUseLegacyFontSizeOnlyIfPixelValuesMatch
};
static int LegacyFontSizeFromCSSValue(Document*,
                                      const CSSValue*,
                                      bool,
                                      LegacyFontSizeMode);

class HTMLElementEquivalent : public GarbageCollected<HTMLElementEquivalent> {
 public:
  HTMLElementEquivalent(CSSPropertyID);
  HTMLElementEquivalent(CSSPropertyID, const HTMLQualifiedName& tag_name);
  HTMLElementEquivalent(CSSPropertyID,
                        CSSValueID primitive_value,
                        const HTMLQualifiedName& tag_name);

  virtual bool Matches(const Element* element) const {
    return !tag_name_ || element->HasTagName(*tag_name_);
  }
  virtual bool HasAttribute() const { return false; }
  virtual bool PropertyExistsInStyle(const CSSPropertyValueSet* style) const {
    return style->GetPropertyCSSValue(property_id_);
  }
  virtual bool ValueIsPresentInStyle(HTMLElement*, CSSPropertyValueSet*) const;
  virtual void AddToStyle(Element*, EditingStyle*) const;

  virtual void Trace(Visitor* visitor) const {
    visitor->Trace(identifier_value_);
  }

 protected:
  const CSSPropertyID property_id_;
  const Member<CSSIdentifierValue> identifier_value_;
  // We can store a pointer because HTML tag names are const global.
  const HTMLQualifiedName* tag_name_;
};

HTMLElementEquivalent::HTMLElementEquivalent(CSSPropertyID id)
    : property_id_(id), tag_name_(nullptr) {}

HTMLElementEquivalent::HTMLElementEquivalent(CSSPropertyID id,
                                             const HTMLQualifiedName& tag_name)
    : property_id_(id), tag_name_(&tag_name) {}

HTMLElementEquivalent::HTMLElementEquivalent(CSSPropertyID id,
                                             CSSValueID value_id,
                                             const HTMLQualifiedName& tag_name)
    : property_id_(id),
      identifier_value_(CSSIdentifierValue::Create(value_id)),
      tag_name_(&tag_name) {
  DCHECK(IsValidCSSValueID(value_id));
}

bool HTMLElementEquivalent::ValueIsPresentInStyle(
    HTMLElement* element,
    CSSPropertyValueSet* style) const {
  const CSSValue* value = style->GetPropertyCSSValue(property_id_);

  // TODO: Does this work on style or computed style? The code here, but we
  // might need to do something here to match CSSPrimitiveValues. if
  // (property_id_ == CSSPropertyID::kFontWeight &&
  //     identifier_value_->GetValueID() == CSSValueID::kBold) {
  //   auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value);
  //   if (primitive_value &&
  //       primitive_value->GetFloatValue() >= BoldThreshold()) {
  //     LOG(INFO) << "weight match in HTMLElementEquivalent for primitive
  //     value"; return true;
  //   } else {
  //     LOG(INFO) << "weight match in HTMLElementEquivalent for identifier
  //     value";
  //   }
  // }

  if (!Matches(element))
    return false;

  auto* identifier_value = DynamicTo<CSSIdentifierValue>(value);
  return identifier_value &&
         identifier_value->GetValueID() == identifier_value_->GetValueID();
}

void HTMLElementEquivalent::AddToStyle(Element* element,
                                       EditingStyle* style) const {
  style->SetProperty(property_id_, identifier_value_->CssText(),
                     /* important */ false,
                     element->GetExecutionContext()->GetSecureContextMode());
}

class HTMLTextDecorationEquivalent final : public HTMLElementEquivalent {
 public:
  static HTMLElementEquivalent* Create(CSSValueID primitive_value,
                                       const HTMLQualifiedName& tag_name) {
    return MakeGarbageCollected<HTMLTextDecorationEquivalent>(primitive_value,
                                                              tag_name);
  }

  HTMLTextDecorationEquivalent(CSSValueID primitive_value,
                               const HTMLQualifiedName& tag_name);

  bool PropertyExistsInStyle(const CSSPropertyValueSet*) const override;
  bool ValueIsPresentInStyle(HTMLElement*, CSSPropertyValueSet*) const override;

  void Trace(Visitor* visitor) const override {
    HTMLElementEquivalent::Trace(visitor);
  }
};

HTMLTextDecorationEquivalent::HTMLTextDecorationEquivalent(
    CSSValueID primitive_value,
    const HTMLQualifiedName& tag_name)
    : HTMLElementEquivalent(CSSPropertyID::kTextDecorationLine,
                            primitive_value,
                            tag_name)
// CSSPropertyID::kTextDecorationLine is used in
// HTMLElementEquivalent::AddToStyle
{}

bool HTMLTextDecorationEquivalent::PropertyExistsInStyle(
    const CSSPropertyValueSet* style) const {
  return style->GetPropertyCSSValue(
             CSSPropertyID::kWebkitTextDecorationsInEffect) ||
         style->GetPropertyCSSValue(CSSPropertyID::kTextDecorationLine);
}

bool HTMLTextDecorationEquivalent::ValueIsPresentInStyle(
    HTMLElement* element,
    CSSPropertyValueSet* style) const {
  const CSSValue* style_value =
      style->GetPropertyCSSValue(CSSPropertyID::kWebkitTextDecorationsInEffect);
  if (!style_value) {
    style_value =
        style->GetPropertyCSSValue(CSSPropertyID::kTextDecorationLine);
  }
  if (!Matches(element))
    return false;
  auto* style_value_list = DynamicTo<CSSValueList>(style_value);
  return style_value_list && style_value_list->HasValue(*identifier_value_);
}

class HTMLAttributeEquivalent : public HTMLElementEquivalent {
 public:
  HTMLAttributeEquivalent(CSSPropertyID,
                          const HTMLQualifiedName& tag_name,
                          const QualifiedName& attr_name);
  HTMLAttributeEquivalent(CSSPropertyID, const QualifiedName& attr_name);

  bool Matches(const Element* element) const override {
    return HTMLElementEquivalent::Matches(element) &&
           element->hasAttribute(attr_name_);
  }
  bool HasAttribute() const override { return true; }
  bool ValueIsPresentInStyle(HTMLElement*, CSSPropertyValueSet*) const override;
  void AddToStyle(Element*, EditingStyle*) const override;
  virtual const CSSValue* AttributeValueAsCSSValue(Element*) const;
  inline const QualifiedName& AttributeName() const { return attr_name_; }

  void Trace(Visitor* visitor) const override {
    HTMLElementEquivalent::Trace(visitor);
  }

 protected:
  // We can store a reference because HTML attribute names are const global.
  const QualifiedName& attr_name_;
};

HTMLAttributeEquivalent::HTMLAttributeEquivalent(
    CSSPropertyID id,
    const HTMLQualifiedName& tag_name,
    const QualifiedName& attr_name)
    : HTMLElementEquivalent(id, tag_name), attr_name_(attr_name) {}

HTMLAttributeEquivalent::HTMLAttributeEquivalent(CSSPropertyID id,
                                                 const QualifiedName& attr_name)
    : HTMLElementEquivalent(id), attr_name_(attr_name) {}

bool HTMLAttributeEquivalent::ValueIsPresentInStyle(
    HTMLElement* element,
    CSSPropertyValueSet* style) const {
  const CSSValue* value = AttributeValueAsCSSValue(element);
  const CSSValue* style_value = style->GetPropertyCSSValue(property_id_);

  return base::ValuesEquivalent(value, style_value);
}

void HTMLAttributeEquivalent::AddToStyle(Element* element,
                                         EditingStyle* style) const {
  if (const CSSValue* value = AttributeValueAsCSSValue(element)) {
    style->SetProperty(property_id_, value->CssText(), /* important */ false,
                       element->GetExecutionContext()->GetSecureContextMode());
  }
}

const CSSValue* HTMLAttributeEquivalent::AttributeValueAsCSSValue(
    Element* element) const {
  DCHECK(element);
  const AtomicString& value = element->getAttribute(attr_name_);
  if (value.IsNull())
    return nullptr;

  auto* dummy_style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  dummy_style->ParseAndSetProperty(
      property_id_, value, /* important */ false,
      element->GetExecutionContext()->GetSecureContextMode());
  return dummy_style->GetPropertyCSSValue(property_id_);
}

class HTMLFontSizeEquivalent final : public HTMLAttributeEquivalent {
 public:
  static HTMLFontSizeEquivalent* Create() {
    return MakeGarbageCollected<HTMLFontSizeEquivalent>();
  }

  HTMLFontSizeEquivalent();

  const CSSValue* AttributeValueAsCSSValue(Element*) const override;

  void Trace(Visitor* visitor) const override {
    HTMLAttributeEquivalent::Trace(visitor);
  }
};

HTMLFontSizeEquivalent::HTMLFontSizeEquivalent()
    : HTMLAttributeEquivalent(CSSPropertyID::kFontSize,
                              html_names::kFontTag,
                              html_names::kSizeAttr) {}

const CSSValue* HTMLFontSizeEquivalent::AttributeValueAsCSSValue(
    Element* element) const {
  DCHECK(element);
  const AtomicString& value = element->getAttribute(attr_name_);
  if (value.IsNull())
    return nullptr;
  CSSValueID size;
  if (!HTMLFontElement::CssValueFromFontSizeNumber(value, size))
    return nullptr;
  return CSSIdentifierValue::Create(size);
}

EditingStyle::EditingStyle(Element* element,
                           PropertiesToInclude properties_to_include) {
  Init(element, properties_to_include);
}

EditingStyle::EditingStyle(const Position& position,
                           PropertiesToInclude properties_to_include) {
  Init(position.AnchorNode(), properties_to_include);
}

EditingStyle::EditingStyle(const CSSPropertyValueSet* style)
    : mutable_style_(style ? style->MutableCopy() : nullptr) {
  ExtractFontSizeDelta();
}

EditingStyle::EditingStyle(CSSPropertyID property_id,
                           const String& value,
                           SecureContextMode secure_context_mode)
    : mutable_style_(nullptr) {
  SetProperty(property_id, value, /* important */ false, secure_context_mode);
  is_vertical_align_ = property_id == CSSPropertyID::kVerticalAlign &&
                       (value == "sub" || value == "super");
}

static Color CssValueToColor(const CSSValue* value) {
  if (!value)
    return Color::kTransparent;

  auto* color_value = DynamicTo<cssvalue::CSSColor>(value);
  if (!color_value && !value->IsPrimitiveValue() && !value->IsIdentifierValue())
    return Color::kTransparent;

  if (color_value)
    return color_value->Value();

  Color color = Color::kTransparent;
  // FIXME: Why ignore the return value?
  CSSParser::ParseColor(color, value->CssText());
  return color;
}

static inline Color GetFontColor(CSSStyleDeclaration* style) {
  return CssValueToColor(
      style->GetPropertyCSSValueInternal(CSSPropertyID::kColor));
}

static inline Color GetFontColor(CSSPropertyValueSet* style) {
  return CssValueToColor(style->GetPropertyCSSValue(CSSPropertyID::kColor));
}

static inline Color GetBackgroundColor(CSSStyleDeclaration* style) {
  return CssValueToColor(
      style->GetPropertyCSSValueInternal(CSSPropertyID::kBackgroundColor));
}

static inline Color GetBackgroundColor(CSSPropertyValueSet* style) {
  return CssValueToColor(
      style->GetPropertyCSSValue(CSSPropertyID::kBackgroundColor));
}

static inline Color BackgroundColorInEffect(Node* node) {
  return CssValueToColor(
      EditingStyleUtilities::BackgroundColorValueInEffect(node));
}

static CSSValueID NormalizeTextAlign(CSSValueID text_align) {
  switch (text_align) {
    case CSSValueID::kCenter:
    case CSSValueID::kWebkitCenter:
      return CSSValueID::kCenter;
    case CSSValueID::kJustify:
      return CSSValueID::kJustify;
    case CSSValueID::kLeft:
    case CSSValueID::kWebkitLeft:
      return CSSValueID::kLeft;
    case CSSValueID::kRight:
    case CSSValueID::kWebkitRight:
      return CSSValueID::kRight;
    case CSSValueID::kStart:
    case CSSValueID::kEnd:
      return text_align;
    default:
      return CSSValueID::kInvalid;
  }
}
static CSSValueID TextAlignResolvingStartAndEnd(CSSValueID text_align,
                                                TextDirection direction) {
  const CSSValueID normalized = NormalizeTextAlign(text_align);
  switch (normalized) {
    case CSSValueID::kStart:
      return IsLtr(direction) ? CSSValueID::kLeft : CSSValueID::kRight;
    case CSSValueID::kEnd:
      return IsLtr(direction) ? CSSValueID::kRight : CSSValueID::kLeft;
    default:
      return normalized;
  }
}

// Returns true "text-align" property of |style| is redundant when applying
// |style| inheriting from |base_style| to |node|.
// Note: direction for "text-align:start" and "text-align:end" are taken
// from |node|.
template <typename T>
static bool IsRedundantTextAlign(MutableCSSPropertyValueSet* style,
                                 T* base_style,
                                 Node* node) {
  DCHECK(node);
  const CSSValueID base_text_align = NormalizeTextAlign(
      GetIdentifierValue(base_style, CSSPropertyID::kTextAlign));
  if (base_text_align == CSSValueID::kInvalid)
    return false;
  const CSSValueID text_align =
      NormalizeTextAlign(GetIdentifierValue(style, CSSPropertyID::kTextAlign));
  if (text_align == CSSValueID::kInvalid)
    return false;
  if (text_align == base_text_align)
    return true;
  const ComputedStyle* node_style =
      node->GetComputedStyleForElementOrLayoutObject();
  if (!node_style) {
    return true;
  }
  TextDirection node_direction = node_style->Direction();
  if (base_text_align == CSSValueID::kStart ||
      base_text_align == CSSValueID::kEnd) {
    // Returns true for "text-align:left" of <p>
    //   <div style="text-align:start"><p dir="ltr" style="text-align:left">
    // because meaning of "text-align:start" in <p> is identical to
    // "text-align:left".
    //
    // Returns false for "text-align:left" of <p>
    //   <div style="text-align:start"><p dir="rtl" style="text-align:left">
    // because meaning of "text-align:start" in <p> is identical to
    // "text-align:right".
    return TextAlignResolvingStartAndEnd(base_text_align, node_direction) ==
           text_align;
  }
  if (text_align == CSSValueID::kStart || text_align == CSSValueID::kEnd) {
    // Returns true for "text-align:start" of <p>
    //  <div style="text-align:left"><p dir="ltr" style="text-align:start">
    //  <div style="text-align:right"><p dir="rtl" style="text-align:start">
    // Returns false for "text-align:start" of <p>
    //  <div style="text-align:left"><p dir="rtl" style="text-align:start">
    //  <div style="text-align:right"><p dir="ltr" style="text-align:start">
    return TextAlignResolvingStartAndEnd(text_align, node_direction) ==
           base_text_align;
  }
  return false;
}

namespace {

Element* ElementFromStyledNode(Node* node) {
  if (Element* element = DynamicTo<Element>(node)) {
    return element;
  }
  if (node) {
    // This should probably be FlatTreeTraversal::ParentElement() instead, but
    // it breaks tests.
    return node->ParentOrShadowHostElement();
  }
  return nullptr;
}

}  // namespace

void EditingStyle::Init(Node* node, PropertiesToInclude properties_to_include) {
  if (IsTabHTMLSpanElementTextNode(node))
    node = TabSpanElement(node)->parentNode();
  else if (IsTabHTMLSpanElement(node))
    node = node->parentNode();
  node_ = node;
  auto* computed_style_at_position =
      MakeGarbageCollected<CSSComputedStyleDeclaration>(
          ElementFromStyledNode(node));
  mutable_style_ =
      properties_to_include == kAllProperties && computed_style_at_position
          ? computed_style_at_position->CopyProperties()
          : CopyEditingProperties(node ? node->GetExecutionContext() : nullptr,
                                  computed_style_at_position);

  if (properties_to_include == kEditingPropertiesInEffect) {
    if (const CSSValue* value =
            EditingStyleUtilities::BackgroundColorValueInEffect(node)) {
      mutable_style_->ParseAndSetProperty(
          CSSPropertyID::kBackgroundColor, value->CssText(),
          /* important */ false,
          node->GetExecutionContext()->GetSecureContextMode());
    }
    if (const CSSValue* value = computed_style_at_position->GetPropertyCSSValue(
            CSSPropertyID::kWebkitTextDecorationsInEffect)) {
      mutable_style_->ParseAndSetProperty(
          CSSPropertyID::kTextDecoration, value->CssText(),
          /* important */ false,
          node->GetExecutionContext()->GetSecureContextMode());
    }
  }

  const ComputedStyle* computed_style =
      node ? node->GetComputedStyleForElementOrLayoutObject() : nullptr;
  if (computed_style) {
    // Fix for crbug.com/768261: due to text-autosizing, reading the current
    // computed font size and re-writing it to an element may actually cause the
    // font size to become larger (since the autosizer will run again on the new
    // computed size). The fix is to toss out the computed size property here
    // and use ComputedStyle::SpecifiedFontSize().
    if (computed_style->ComputedFontSize() !=
        computed_style->SpecifiedFontSize()) {
      // ReplaceSelectionCommandTest_TextAutosizingDoesntInflateText gets here.
      mutable_style_->ParseAndSetProperty(
          CSSPropertyID::kFontSize,
          CSSNumericLiteralValue::Create(computed_style->SpecifiedFontSize(),
                                         CSSPrimitiveValue::UnitType::kPixels)
              ->CssText(),
          /* important */ false,
          node->GetExecutionContext()->GetSecureContextMode());
    }
    RemoveForcedColorsIfNeeded(computed_style);
    RemoveInheritedColorsIfNeeded(computed_style);
    ReplaceFontSizeByKeywordIfPossible(
        computed_style, node->GetExecutionContext()->GetSecureContextMode(),
        computed_style_at_position);
  }

  is_monospace_font_ = computed_style_at_position->IsMonospaceFont();
  ExtractFontSizeDelta();
}

void EditingStyle::RemoveForcedColorsIfNeeded(
    const ComputedStyle* computed_style) {
  if (!computed_style->InForcedColorsMode()) {
    return;
  }
  mutable_style_->RemoveProperty(CSSPropertyID::kColor);
  mutable_style_->RemoveProperty(CSSPropertyID::kBackgroundColor);
  mutable_style_->RemoveProperty(CSSPropertyID::kTextDecorationColor);
}

void EditingStyle::RemoveInheritedColorsIfNeeded(
    const ComputedStyle* computed_style) {
  // If a node's text fill color is currentColor, then its children use
  // their font-color as their text fill color (they don't
  // inherit it).  Likewise for stroke color.
  // Similar thing happens for caret-color if it's auto or currentColor.
  if (computed_style->TextFillColor().IsCurrentColor())
    mutable_style_->RemoveProperty(CSSPropertyID::kWebkitTextFillColor);
  if (computed_style->TextStrokeColor().IsCurrentColor())
    mutable_style_->RemoveProperty(CSSPropertyID::kWebkitTextStrokeColor);
  if (computed_style->CaretColor().IsAutoColor() ||
      computed_style->CaretColor().IsCurrentColor())
    mutable_style_->RemoveProperty(CSSPropertyID::kCaretColor);
}

CSSValueID EditingStyle::GetProperty(CSSPropertyID property_id) const {
  return GetIdentifierValue(mutable_style_.Get(), property_id);
}

void EditingStyle::SetProperty(CSSPropertyID property_id,
                               const String& value,
                               bool important,
                               SecureContextMode secure_context_mode) {
  if (!mutable_style_) {
    mutable_style_ =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  }

  mutable_style_->ParseAndSetProperty(property_id, value, important,
                                      secure_context_mode);
}

void EditingStyle::ReplaceFontSizeByKeywordIfPossible(
    const ComputedStyle* computed_style,
    SecureContextMode secure_context_mode,
    CSSComputedStyleDeclaration* css_computed_style) {
  DCHECK(computed_style);
  if (computed_style->GetFontDescription().KeywordSize()) {
    if (const CSSValue* keyword =
            css_computed_style->GetFontSizeCSSValuePreferringKeyword()) {
      mutable_style_->ParseAndSetProperty(
          CSSPropertyID::kFontSize, keyword->CssText(),
          /* important */ false, secure_context_mode);
    }
  }
}

void EditingStyle::ExtractFontSizeDelta() {
  if (!mutable_style_)
    return;

  if (mutable_style_->GetPropertyCSSValue(CSSPropertyID::kFontSize)) {
    // Explicit font size overrides any delta.
    mutable_style_->RemoveProperty(CSSPropertyID::kInternalFontSizeDelta);
    return;
  }

  // Get the adjustment amount out of the style.
  const CSSValue* value = mutable_style_->GetPropertyCSSValue(
      CSSPropertyID::kInternalFontSizeDelta);
  const auto* primitive_value = DynamicTo<CSSPrimitiveValue>(value);
  if (!primitive_value)
    return;

  // Only PX handled now. If we handle more types in the future, perhaps
  // a switch statement here would be more appropriate.
  if (!primitive_value->IsPx())
    return;

  font_size_delta_ = primitive_value->GetFloatValue();
  mutable_style_->RemoveProperty(CSSPropertyID::kInternalFontSizeDelta);
}

bool EditingStyle::IsEmpty() const {
  return (!mutable_style_ || mutable_style_->IsEmpty()) &&
         font_size_delta_ == kNoFontDelta;
}

bool EditingStyle::GetTextDirection(
    mojo_base::mojom::blink::TextDirection& writing_direction) const {
  if (!mutable_style_)
    return false;

  const CSSValue* unicode_bidi =
      mutable_style_->GetPropertyCSSValue(CSSPropertyID::kUnicodeBidi);
  auto* unicode_bidi_identifier_value =
      DynamicTo<CSSIdentifierValue>(unicode_bidi);
  if (!unicode_bidi_identifier_value)
    return false;

  CSSValueID unicode_bidi_value = unicode_bidi_identifier_value->GetValueID();
  if (EditingStyleUtilities::IsEmbedOrIsolate(unicode_bidi_value)) {
    const CSSValue* direction =
        mutable_style_->GetPropertyCSSValue(CSSPropertyID::kDirection);
    auto* direction_identifier_value = DynamicTo<CSSIdentifierValue>(direction);
    if (!direction_identifier_value)
      return false;

    writing_direction =
        direction_identifier_value->GetValueID() == CSSValueID::kLtr
            ? mojo_base::mojom::blink::TextDirection::LEFT_TO_RIGHT
            : mojo_base::mojom::blink::TextDirection::RIGHT_TO_LEFT;

    return true;
  }

  if (unicode_bidi_value == CSSValueID::kNormal) {
    writing_direction =
        mojo_base::mojom::blink::TextDirection::UNKNOWN_DIRECTION;
    return true;
  }

  return false;
}

void EditingStyle::OverrideWithStyle(const CSSPropertyValueSet* style) {
  if (!style || style->IsEmpty())
    return;
  if (!mutable_style_) {
    mutable_style_ =
        MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLQuirksMode);
  }
  mutable_style_->MergeAndOverrideOnConflict(style);
  ExtractFontSizeDelta();
}

void EditingStyle::Clear() {
  mutable_style_.Clear();
  is_monospace_font_ = false;
  font_size_delta_ = kNoFontDelta;
}

EditingStyle* EditingStyle::Copy() const {
  EditingStyle* copy = MakeGarbageCollected<EditingStyle>();
  if (mutable_style_)
    copy->mutable_style_ = mutable_style_->MutableCopy();
  copy->is_monospace_font_ = is_monospace_font_;
  copy->font_size_delta_ = font_size_delta_;
  return copy;
}

// This is the list of CSS properties that apply specially to block-level
// elements.
static const CSSPropertyID kStaticBlockProperties[] = {
    CSSPropertyID::kBreakAfter, CSSPropertyID::kBreakBefore,
    CSSPropertyID::kBreakInside, CSSPropertyID::kOrphans,
    CSSPropertyID::kOverflow,  // This can be also be applied to replaced
                               // elements
    CSSPropertyID::kColumnCount, CSSPropertyID::kColumnGap,
    CSSPropertyID::kColumnRuleColor, CSSPropertyID::kColumnRuleStyle,
    CSSPropertyID::kColumnRuleWidth, CSSPropertyID::kWebkitColumnBreakBefore,
    CSSPropertyID::kWebkitColumnBreakAfter,
    CSSPropertyID::kWebkitColumnBreakInside, CSSPropertyID::kColumnWidth,
    CSSPropertyID::kPageBreakAfter, CSSPropertyID::kPageBreakBefore,
    CSSPropertyID::kPageBreakInside, CSSPropertyID::kTextAlign,
    CSSPropertyID::kTextAlignLast, CSSPropertyID::kTextIndent,
    CSSPropertyID::kWidows};

static const Vector<const CSSProperty*>& BlockPropertiesVector(
    const ExecutionContext* execution_context) {
  DEFINE_STATIC_LOCAL(Vector<const CSSProperty*>, properties, ());
  if (properties.empty()) {
    CSSProperty::FilterWebExposedCSSPropertiesIntoVector(
        execution_context, kStaticBlockProperties,
        std::size(kStaticBlockProperties), properties);
  }
  return properties;
}

EditingStyle* EditingStyle::ExtractAndRemoveBlockProperties(
    const ExecutionContext* execution_context) {
  EditingStyle* block_properties = MakeGarbageCollected<EditingStyle>();
  if (!mutable_style_)
    return block_properties;

  block_properties->mutable_style_ = mutable_style_->CopyPropertiesInSet(
      BlockPropertiesVector(execution_context));
  RemoveBlockProperties(execution_context);

  return block_properties;
}

EditingStyle* EditingStyle::ExtractAndRemoveTextDirection(
    SecureContextMode secure_context_mode) {
  EditingStyle* text_dir
"""


```