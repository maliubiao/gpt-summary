Response:
The user wants a summary of the functionality of the provided C++ code snippet from the `inspector_style_sheet.cc` file in the Chromium Blink engine. Specifically, they want to understand its relationship to JavaScript, HTML, and CSS, including examples, logical reasoning with input/output, and common user errors.

This is the second part of a three-part request, so I need to focus on the functionality within this specific snippet and avoid repeating information from the previous parts (if any were provided) or anticipating the content of the next part.

The code snippet primarily deals with the `InspectorStyleSheet` class and related functions, focusing on:

1. **Retrieving and manipulating CSS property values:** The `ShorthandValue` function retrieves the value of a CSS shorthand property.
2. **Expanding CSS shorthand properties:** The `LonghandProperties` function takes a shorthand property and returns its constituent longhand properties.
3. **Tracing objects for debugging:** The `Trace` functions are for internal debugging and memory management.
4. **Managing stylesheet text and line endings:** The `InspectorStyleSheetBase` class handles basic operations related to stylesheet text, like tracking line endings.
5. **Modifying CSS rules within a stylesheet:**  The `InspectorStyleSheet` class provides methods to set selectors, property names, keyframe keys, style text, and media/container/supports/scope rule texts.
6. **Inserting and deleting CSS rules:** Functions like `InsertCSSOMRuleInStyleSheet`, `InsertCSSOMRuleInMediaRule`, `AddRule`, and `DeleteRule` allow modifying the structure of the stylesheet.
7. **Collecting class names:** The `CollectClassNames` function extracts all unique class names used in the stylesheet.
8. **Replacing text within the stylesheet:** The `ReplaceText` function allows for direct text manipulation.
9. **Parsing stylesheet text:** The `ParseText` function takes CSS text and parses it to build an internal representation.
10. **Merging CSSOM rules with text:** The `MergeCSSOMRulesWithText` function attempts to reconcile the potentially out-of-sync in-memory representation of the stylesheet with the source text.
11. **Setting the stylesheet text:** The `InnerSetText` function updates the internal representation of the stylesheet with new text.
这是 `blink/renderer/core/inspector/inspector_style_sheet.cc` 文件的一部分，主要负责以下功能：

**1. 获取 CSS 简写属性的展开值:**

   - **功能:** `ShorthandValue(const String& shorthand_property)` 函数接收一个 CSS 简写属性名作为输入，并返回该简写属性的计算值。如果该简写属性本身有值，则直接返回；否则，它会遍历该样式中所有相关的长写属性，并将它们的值组合起来。
   - **与 CSS 的关系:** 直接操作 CSS 属性和值。
   - **举例说明:**
     - **假设输入:**  一个元素的 `style_` 对象中，`shorthand_property` 为 "margin"。
     - **可能输出 1 (简写属性有值):** 如果 `style_->getPropertyValue("margin")` 返回 "10px 20px", 则 `ShorthandValue("margin")` 返回 "10px 20px"。
     - **可能输出 2 (简写属性无值，但有长写属性):** 如果 `style_->getPropertyValue("margin")` 为空，但 `style_` 中有 `margin-top: 10px; margin-left: 20px;`，则 `ShorthandValue("margin")` 返回 "10px 20px"。
     - **逻辑推理:** 函数会根据 CSS 规则，将相关的长写属性值按正确的顺序组合成简写属性的值。
   - **用户或编程常见的使用错误:**
     - 调用该函数时传入一个非简写属性名，可能导致返回空值或只返回该属性本身的值。

**2. 获取 CSS 简写属性对应的长写属性列表:**

   - **功能:** `LonghandProperties(const CSSPropertySourceData& property_entry)` 函数接收一个 CSS 属性的源数据信息（包含属性名、值、是否重要等），如果该属性是一个简写属性，则解析其值，并返回一个包含所有对应长写属性及其值的 `protocol::CSS::CSSProperty` 数组。
   - **与 CSS 的关系:** 深入解析 CSS 简写属性的结构。
   - **举例说明:**
     - **假设输入:** `property_entry` 的 `name` 为 "margin"， `value` 为 "10px 20px !important"， `important` 为 true。
     - **可能输出:**  一个包含两个 `protocol::CSS::CSSProperty` 对象的数组，分别表示 `margin-top: 10px !important` 和 `margin-left: 20px !important`。
     - **逻辑推理:** 该函数利用 CSS 解析器来拆解简写属性的值，并生成对应的长写属性对象。
   - **用户或编程常见的使用错误:**
     - 传入的 `property_entry` 对应的属性不是简写属性，则该函数会返回 `nullptr`。

**3. 构建 CSS 样式对象的协议表示 (Protocol Representation):**

   - **功能:** `BuildObjectForStyle` 函数 (在 `InspectorStyle` 类中，此部分未完全展示，但在上下文中有提及)  接收一个 `CSSStyleDeclaration` 对象，并将其转换为用于 Chrome DevTools 协议 (CDP) 的 `protocol::CSS::CSSStyle` 对象。这通常涉及到提取样式中的属性和值。
   - **与 JavaScript, HTML, CSS 的关系:**
     - **CSS:**  直接处理 CSS 样式信息。
     - **JavaScript:**  生成的协议对象会被发送到前端 DevTools，前端 JavaScript 代码可以解析和使用这些信息。
     - **HTML:**  样式信息通常与 HTML 元素关联。
   - **举例说明:**
     - **假设输入:** 一个 HTML 元素的 `style` 属性被解析后生成的 `CSSStyleDeclaration` 对象，其中包含 `color: red; font-size: 16px;`。
     - **可能输出:** 一个 `protocol::CSS::CSSStyle` 对象，其 `cssProperties` 属性包含两个 `protocol::CSS::CSSProperty` 对象，分别表示 `name: "color", value: "red"` 和 `name: "font-size", value: "16px"`。

**4. 获取和管理样式表的文本内容和行尾符:**

   - **功能:** `InspectorStyleSheetBase` 类中的 `GetLineEndings` 和 `ResetLineEndings`  用于获取和重置样式表文本的行尾符信息，这对于处理源代码位置信息至关重要。`OnStyleSheetTextChanged` 会在样式表文本改变时更新行尾符信息。
   - **与 CSS 的关系:**  处理 CSS 源代码的结构。
   - **逻辑推理:**  行尾符用于将字符偏移量转换为行号和列号，方便在 DevTools 中定位 CSS 代码。

**5. 将行号和列号转换为字符偏移量:**

   - **功能:** `LineNumberAndColumnToOffset(unsigned line_number, unsigned column_number, unsigned* offset)` 函数接收行号和列号作为输入，并计算出对应的字符偏移量。
   - **与 CSS 的关系:**  用于在 CSS 源代码中精确定位位置。
   - **假设输入:**  `line_number = 2`, `column_number = 5`，并且已知第二行之前有 20 个字符（包括行尾符）。
   - **可能输出:** `offset` 被设置为 `20 + 5 - 1 = 24` (假设列号从 1 开始计数)。
   - **逻辑推理:**  该函数利用预先计算的行尾符信息来计算偏移量。

**6. 修改样式表中的 CSS 规则 (Selector, Property Name, Keyframe Key, Style Text, Media Rule Text, 等等):**

   - **功能:** `InspectorStyleSheet` 类中提供了 `SetRuleSelector`, `SetPropertyName`, `SetKeyframeKey`, `SetStyleText`, `SetMediaRuleText`, `SetContainerRuleText`, `SetSupportsRuleText`, `SetScopeRuleText` 等一系列函数，用于修改样式表中特定 CSS 规则的各个部分。这些函数会验证输入文本的合法性，更新内部的 CSSOM (CSS Object Model) 结构，并更新源代码文本。
   - **与 CSS 的关系:**  核心功能是编辑和修改 CSS 代码。
   - **举例说明:**
     - **假设输入:**  `SetRuleSelector` 函数接收一个表示 CSS 选择器位置的 `SourceRange`，以及新的选择器文本。
     - **操作:**  函数会找到该 `SourceRange` 对应的 CSS 规则，修改其选择器，并更新样式表的源代码。
   - **用户或编程常见的使用错误:**
     - 提供的 `SourceRange` 不存在或不匹配任何 CSS 规则。
     - 提供的新文本不符合 CSS 语法，例如选择器中包含非法字符。

**7. 插入和删除 CSS 规则:**

   - **功能:** `InsertCSSOMRuleInStyleSheet`, `InsertCSSOMRuleInMediaRule`, `AddRule`, `DeleteRule` 等函数允许在样式表中插入新的 CSS 规则或删除现有的规则。
   - **与 CSS 的关系:**  修改 CSS 代码的结构。
   - **举例说明:**
     - `AddRule` 函数可以在指定的位置插入一条新的 CSS 样式规则。
     - `DeleteRule` 函数可以删除指定范围内的 CSS 规则。
   - **用户或编程常见的使用错误:**
     - 尝试在只读样式表中插入或删除规则。
     - 插入的规则文本不符合 CSS 语法。
     - 删除的 `SourceRange` 不精确，导致删除了错误的规则或部分规则。

**8. 收集样式表中的所有类名:**

   - **功能:** `CollectClassNames()` 函数遍历样式表中的所有样式规则，提取出其中使用的
Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_style_sheet.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
SS::CSSStyle> result =
      protocol::CSS::CSSStyle::create()
          .setCssProperties(std::move(properties_object))
          .setShorthandEntries(std::move(shorthand_entries))
          .build();
  return result;
}

String InspectorStyle::ShorthandValue(const String& shorthand_property) {
  StringBuilder builder;
  String value = style_->getPropertyValue(shorthand_property);
  if (value.empty()) {
    for (unsigned i = 0; i < style_->length(); ++i) {
      String individual_property = style_->item(i);
      if (style_->GetPropertyShorthand(individual_property) !=
          shorthand_property)
        continue;
      if (style_->IsPropertyImplicit(individual_property))
        continue;
      String individual_value = style_->getPropertyValue(individual_property);
      if (individual_value == "initial")
        continue;
      if (!builder.empty())
        builder.Append(' ');
      builder.Append(individual_value);
    }
  } else {
    builder.Append(value);
  }

  if (!style_->getPropertyPriority(shorthand_property).empty())
    builder.Append(" !important");

  return builder.ToString();
}

std::unique_ptr<protocol::Array<protocol::CSS::CSSProperty>>
InspectorStyle::LonghandProperties(
    const CSSPropertySourceData& property_entry) {
  String property_value = property_entry.value;
  if (property_entry.important) {
    property_value = property_value.Substring(
        0, property_value.length() - 10 /* length of "!important" */);
  }
  CSSParserTokenStream stream(property_value);
  stream.EnsureLookAhead();  // Several parsers expect this.
  CSSPropertyID property_id =
      CssPropertyID(style_->GetExecutionContext(), property_entry.name);
  if (property_id == CSSPropertyID::kInvalid ||
      property_id == CSSPropertyID::kVariable)
    return nullptr;
  const CSSProperty& property =
      CSSProperty::Get(ResolveCSSPropertyID(property_id));
  if (!property.IsProperty() || !property.IsShorthand())
    return nullptr;
  const auto local_context =
      CSSParserLocalContext().WithCurrentShorthand(property_id);
  HeapVector<CSSPropertyValue, 64> longhand_properties;
  if (To<Shorthand>(property).ParseShorthand(
          property_entry.important, stream,
          *ParserContextForDocument(parent_style_sheet_->GetDocument()),
          local_context, longhand_properties)) {
    auto result =
        std::make_unique<protocol::Array<protocol::CSS::CSSProperty>>();
    for (auto longhand_property : longhand_properties) {
      String value = longhand_property.Value()->CssText();
      std::unique_ptr<protocol::CSS::CSSProperty> longhand =
          protocol::CSS::CSSProperty::create()
              .setName(longhand_property.Name().ToAtomicString())
              .setValue(value)
              .build();
      if (property_entry.important) {
        longhand->setValue(value + " !important");
        longhand->setImportant(true);
      }
      result->emplace_back(std::move(longhand));
    }
    return result;
  }
  return nullptr;
}

void InspectorStyle::Trace(Visitor* visitor) const {
  visitor->Trace(style_);
  visitor->Trace(parent_style_sheet_);
  visitor->Trace(source_data_);
}

InspectorStyleSheetBase::InspectorStyleSheetBase(Listener* listener, String id)
    : id_(id),
      listener_(listener),
      line_endings_(std::make_unique<LineEndings>()) {}

void InspectorStyleSheetBase::OnStyleSheetTextChanged() {
  line_endings_ = std::make_unique<LineEndings>();
  if (GetListener())
    GetListener()->StyleSheetChanged(this);
}

std::unique_ptr<protocol::CSS::CSSStyle>
InspectorStyleSheetBase::BuildObjectForStyle(
    CSSStyleDeclaration* style,
    Element* element,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  return GetInspectorStyle(style)->BuildObjectForStyle(element, pseudo_id,
                                                       pseudo_argument);
}

const LineEndings* InspectorStyleSheetBase::GetLineEndings() {
  if (line_endings_->size() > 0)
    return line_endings_.get();
  String text;
  if (GetText(&text))
    line_endings_ = WTF::GetLineEndings(text);
  return line_endings_.get();
}

void InspectorStyleSheetBase::ResetLineEndings() {
  line_endings_ = std::make_unique<LineEndings>();
}

bool InspectorStyleSheetBase::LineNumberAndColumnToOffset(
    unsigned line_number,
    unsigned column_number,
    unsigned* offset) {
  const LineEndings* endings = GetLineEndings();
  if (line_number >= endings->size())
    return false;
  unsigned characters_in_line =
      line_number > 0
          ? endings->at(line_number) - endings->at(line_number - 1) - 1
          : endings->at(0);
  if (column_number > characters_in_line)
    return false;
  TextPosition position(OrdinalNumber::FromZeroBasedInt(line_number),
                        OrdinalNumber::FromZeroBasedInt(column_number));
  *offset = position.ToOffset(*endings).ZeroBasedInt();
  return true;
}

InspectorStyleSheet::InspectorStyleSheet(
    InspectorNetworkAgent* network_agent,
    CSSStyleSheet* page_style_sheet,
    const String& origin,
    const String& document_url,
    InspectorStyleSheetBase::Listener* listener,
    InspectorResourceContainer* resource_container)
    : InspectorStyleSheetBase(
          listener,
          IdentifiersFactory::IdForCSSStyleSheet(page_style_sheet)),
      resource_container_(resource_container),
      network_agent_(network_agent),
      page_style_sheet_(page_style_sheet),
      origin_(origin),
      document_url_(document_url) {
  UpdateText();
}

InspectorStyleSheet::~InspectorStyleSheet() = default;

void InspectorStyleSheet::Trace(Visitor* visitor) const {
  visitor->Trace(resource_container_);
  visitor->Trace(network_agent_);
  visitor->Trace(page_style_sheet_);
  visitor->Trace(cssom_flat_rules_);
  visitor->Trace(parsed_flat_rules_);
  visitor->Trace(source_data_);
  InspectorStyleSheetBase::Trace(visitor);
}

static String StyleSheetURL(CSSStyleSheet* page_style_sheet) {
  if (page_style_sheet && !page_style_sheet->Contents()->BaseURL().IsEmpty())
    return page_style_sheet->Contents()->BaseURL().GetString();
  return g_empty_string;
}

String InspectorStyleSheet::FinalURL() {
  String url = StyleSheetURL(page_style_sheet_.Get());
  return url.empty() ? document_url_ : url;
}

bool InspectorStyleSheet::SetText(const String& text,
                                  ExceptionState& exception_state) {
  page_style_sheet_->SetText(text, CSSImportRules::kAllow);
  InnerSetText(text, true);
  OnStyleSheetTextChanged();
  return true;
}

void InspectorStyleSheet::CSSOMStyleSheetTextReplaced(const String& text) {
  InnerSetText(text, false);
}

CSSStyleRule* InspectorStyleSheet::SetRuleSelector(
    const SourceRange& range,
    const String& text,
    SourceRange* new_range,
    String* old_text,
    ExceptionState& exception_state) {
  if (!VerifySelectorText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Selector or media text is not valid.");
    return nullptr;
  }

  CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasProperties()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing source range");
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->GetType() != CSSRule::kStyleRule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  CSSStyleRule* style_rule = InspectorCSSAgent::AsCSSStyleRule(rule);
  style_rule->setSelectorText(
      page_style_sheet_->OwnerDocument()->GetExecutionContext(), text);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return style_rule;
}

CSSPropertyRule* InspectorStyleSheet::SetPropertyName(
    const SourceRange& range,
    const String& text,
    SourceRange* new_range,
    String* old_text,
    ExceptionState& exception_state) {
  if (!VerifyPropertyNameText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Property name text is not valid.");
    return nullptr;
  }

  CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasProperties()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing source range");
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->GetType() != CSSRule::kPropertyRule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  CSSPropertyRule* property_rule = To<CSSPropertyRule>(rule);
  if (!property_rule->SetNameText(
          page_style_sheet_->OwnerDocument()->GetExecutionContext(), text)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The property name '" + text + "' is invalid and cannot be parsed");
    return nullptr;
  }

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return property_rule;
}

CSSKeyframeRule* InspectorStyleSheet::SetKeyframeKey(
    const SourceRange& range,
    const String& text,
    SourceRange* new_range,
    String* old_text,
    ExceptionState& exception_state) {
  if (!VerifyKeyframeKeyText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Keyframe key text is not valid.");
    return nullptr;
  }

  CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasProperties()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing source range");
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->GetType() != CSSRule::kKeyframeRule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  CSSKeyframeRule* keyframe_rule = To<CSSKeyframeRule>(rule);
  keyframe_rule->setKeyText(
      page_style_sheet_->OwnerDocument()->GetExecutionContext(), text,
      exception_state);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return keyframe_rule;
}

CSSRule* InspectorStyleSheet::SetStyleText(const SourceRange& range,
                                           const String& text,
                                           SourceRange* new_range,
                                           String* old_text,
                                           ExceptionState& exception_state) {
  CSSRuleSourceData* source_data = FindRuleByDeclarationsRange(range);
  if (!source_data || !source_data->HasProperties()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  if (!VerifyStyleText(page_style_sheet_->OwnerDocument(), text,
                       source_data->type)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Style text is not valid.");
    return nullptr;
  }

  if (source_data->type == StyleRule::RuleType::kStyle &&
      source_data->rule_header_range.length() == 0u &&
      !VerifyNestedDeclarations(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Style text would cause rule to disappear");
    // TODO(crbug.com/361116768): This should work, but we're not yet
    // equipped to handle rules that disappear.
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      (!IsA<CSSStyleRule>(rule) && !IsA<CSSKeyframeRule>(rule) &&
       !IsA<CSSPropertyRule>(rule) && !IsA<CSSFontPaletteValuesRule>(rule) &&
       !IsA<CSSPositionTryRule>(rule))) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  CSSStyleDeclaration* style = nullptr;
  if (auto* style_rule = DynamicTo<CSSStyleRule>(rule)) {
    style = style_rule->style();
  } else if (auto* property_rule = DynamicTo<CSSPropertyRule>(rule)) {
    style = property_rule->Style();
  } else if (auto* font_palette_values_rule =
                 DynamicTo<CSSFontPaletteValuesRule>(rule)) {
    style = font_palette_values_rule->Style();
  } else if (auto* position_try_rule = DynamicTo<CSSPositionTryRule>(rule)) {
    style = position_try_rule->style();
  } else {
    style = To<CSSKeyframeRule>(rule)->style();
  }

  Document* owner_document = page_style_sheet_->OwnerDocument();
  ExecutionContext* execution_context =
      owner_document ? owner_document->GetExecutionContext() : nullptr;

  style->setCSSText(execution_context, text, exception_state);

  ReplaceText(source_data->rule_declarations_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return rule;
}

CSSMediaRule* InspectorStyleSheet::SetMediaRuleText(
    const SourceRange& range,
    const String& text,
    SourceRange* new_range,
    String* old_text,
    ExceptionState& exception_state) {
  if (!VerifyMediaText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Selector or media text is not valid.");
    return nullptr;
  }

  CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasMedia()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing source range");
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->GetType() != CSSRule::kMediaRule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing style source range");
    return nullptr;
  }

  CSSMediaRule* media_rule = InspectorCSSAgent::AsCSSMediaRule(rule);
  media_rule->media()->setMediaText(
      page_style_sheet_->OwnerDocument()->GetExecutionContext(), text);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return media_rule;
}

CSSContainerRule* InspectorStyleSheet::SetContainerRuleText(
    const SourceRange& range,
    const String& text,
    SourceRange* new_range,
    String* old_text,
    ExceptionState& exception_state) {
  if (!VerifyContainerQueryText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Selector or container query text is not valid.");
    return nullptr;
  }

  CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasContainer()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing source range");
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->GetType() != CSSRule::kContainerRule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "CQ Source range didn't match existing style source range");
    return nullptr;
  }

  CSSContainerRule* container_rule =
      InspectorCSSAgent::AsCSSContainerRule(rule);
  container_rule->SetConditionText(
      page_style_sheet_->OwnerDocument()->GetExecutionContext(), text);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return container_rule;
}

CSSSupportsRule* InspectorStyleSheet::SetSupportsRuleText(
    const SourceRange& range,
    const String& text,
    SourceRange* new_range,
    String* old_text,
    ExceptionState& exception_state) {
  if (!VerifySupportsText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Selector or supports rule text is not valid.");
    return nullptr;
  }

  CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasSupports()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing source range");
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->GetType() != CSSRule::kSupportsRule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Supports source range didn't match existing source range");
    return nullptr;
  }

  CSSSupportsRule* supports_rule = InspectorCSSAgent::AsCSSSupportsRule(rule);
  supports_rule->SetConditionText(
      page_style_sheet_->OwnerDocument()->GetExecutionContext(), text);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return supports_rule;
}

CSSScopeRule* InspectorStyleSheet::SetScopeRuleText(
    const SourceRange& range,
    const String& text,
    SourceRange* new_range,
    String* old_text,
    ExceptionState& exception_state) {
  if (!VerifyScopeText(page_style_sheet_->OwnerDocument(), text)) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "Selector or scope rule text is not valid.");
    return nullptr;
  }

  CSSRuleSourceData* source_data = FindRuleByHeaderRange(range);
  if (!source_data || !source_data->HasScope()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Source range didn't match existing source range");
    return nullptr;
  }

  CSSRule* rule = RuleForSourceData(source_data);
  if (!rule || !rule->parentStyleSheet() ||
      rule->GetType() != CSSRule::kScopeRule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "Scope source range didn't match existing source range");
    return nullptr;
  }

  CSSScopeRule* scope_rule = InspectorCSSAgent::AsCSSScopeRule(rule);
  scope_rule->SetPreludeText(
      page_style_sheet_->OwnerDocument()->GetExecutionContext(), text);

  ReplaceText(source_data->rule_header_range, text, new_range, old_text);
  OnStyleSheetTextChanged();

  return scope_rule;
}

CSSRuleSourceData* InspectorStyleSheet::RuleSourceDataAfterSourceRange(
    const SourceRange& source_range) {
  DCHECK(source_data_);
  unsigned index = 0;
  for (; index < source_data_->size(); ++index) {
    CSSRuleSourceData* sd = source_data_->at(index).Get();
    if (sd->rule_header_range.start >= source_range.end)
      break;
  }
  return index < source_data_->size() ? source_data_->at(index).Get() : nullptr;
}

CSSStyleRule* InspectorStyleSheet::InsertCSSOMRuleInStyleSheet(
    CSSRule* insert_before,
    const String& rule_text,
    ExceptionState& exception_state) {
  unsigned index = 0;
  for (; index < page_style_sheet_->length(); ++index) {
    CSSRule* rule = page_style_sheet_->ItemInternal(index);
    if (rule == insert_before)
      break;
  }

  page_style_sheet_->insertRule(rule_text, index, exception_state);
  CSSRule* rule = page_style_sheet_->ItemInternal(index);
  CSSStyleRule* style_rule = InspectorCSSAgent::AsCSSStyleRule(rule);
  if (!style_rule) {
    page_style_sheet_->deleteRule(index, ASSERT_NO_EXCEPTION);
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The rule '" + rule_text + "' could not be added in style sheet.");
    return nullptr;
  }
  return style_rule;
}

CSSStyleRule* InspectorStyleSheet::InsertCSSOMRuleInMediaRule(
    CSSMediaRule* media_rule,
    CSSRule* insert_before,
    const String& rule_text,
    ExceptionState& exception_state) {
  unsigned index = 0;
  for (; index < media_rule->length(); ++index) {
    CSSRule* rule = media_rule->ItemInternal(index);
    if (rule == insert_before)
      break;
  }

  media_rule->insertRule(
      page_style_sheet_->OwnerDocument()->GetExecutionContext(), rule_text,
      index, exception_state);
  CSSRule* rule = media_rule->ItemInternal(index);
  CSSStyleRule* style_rule = InspectorCSSAgent::AsCSSStyleRule(rule);
  if (!style_rule) {
    media_rule->deleteRule(index, ASSERT_NO_EXCEPTION);
    exception_state.ThrowDOMException(
        DOMExceptionCode::kSyntaxError,
        "The rule '" + rule_text + "' could not be added in media rule.");
    return nullptr;
  }
  return style_rule;
}

CSSStyleRule* InspectorStyleSheet::InsertCSSOMRuleBySourceRange(
    const SourceRange& source_range,
    const String& rule_text,
    ExceptionState& exception_state) {
  DCHECK(source_data_);

  CSSRuleSourceData* containing_rule_source_data = nullptr;
  for (wtf_size_t i = 0; i < source_data_->size(); ++i) {
    CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    if (rule_source_data->rule_header_range.start < source_range.start &&
        source_range.start < rule_source_data->rule_body_range.start) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotFoundError,
          "Cannot insert rule inside rule selector.");
      return nullptr;
    }
    if (source_range.start < rule_source_data->rule_body_range.start ||
        rule_source_data->rule_body_range.end < source_range.start)
      continue;
    if (!containing_rule_source_data ||
        containing_rule_source_data->rule_body_range.length() >
            rule_source_data->rule_body_range.length())
      containing_rule_source_data = rule_source_data;
  }

  CSSRuleSourceData* insert_before =
      RuleSourceDataAfterSourceRange(source_range);
  CSSRule* insert_before_rule = RuleForSourceData(insert_before);

  if (!containing_rule_source_data)
    return InsertCSSOMRuleInStyleSheet(insert_before_rule, rule_text,
                                       exception_state);

  CSSRule* rule = RuleForSourceData(containing_rule_source_data);
  if (!rule || rule->GetType() != CSSRule::kMediaRule) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "Cannot insert rule in non-media rule.");
    return nullptr;
  }

  return InsertCSSOMRuleInMediaRule(To<CSSMediaRule>(rule), insert_before_rule,
                                    rule_text, exception_state);
}

CSSStyleRule* InspectorStyleSheet::AddRule(const String& rule_text,
                                           const SourceRange& location,
                                           SourceRange* added_range,
                                           ExceptionState& exception_state) {
  if (location.start != location.end) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "Source range must be collapsed.");
    return nullptr;
  }

  if (!VerifyRuleText(page_style_sheet_->OwnerDocument(), rule_text)) {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "Rule text is not valid.");
    return nullptr;
  }

  if (!source_data_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "Style is read-only.");
    return nullptr;
  }

  CSSStyleRule* style_rule =
      InsertCSSOMRuleBySourceRange(location, rule_text, exception_state);
  if (exception_state.HadException())
    return nullptr;

  ReplaceText(location, rule_text, added_range, nullptr);
  OnStyleSheetTextChanged();
  return style_rule;
}

bool InspectorStyleSheet::DeleteRule(const SourceRange& range,
                                     ExceptionState& exception_state) {
  if (!source_data_) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "Style is read-only.");
    return false;
  }

  // Find index of CSSRule that entirely belongs to the range.
  CSSRuleSourceData* found_data = nullptr;

  for (wtf_size_t i = 0; i < source_data_->size(); ++i) {
    CSSRuleSourceData* rule_source_data = source_data_->at(i).Get();
    unsigned rule_start = rule_source_data->rule_header_range.start;
    unsigned rule_end = rule_source_data->rule_body_range.end + 1;
    bool start_belongs = rule_start >= range.start && rule_start < range.end;
    bool end_belongs = rule_end > range.start && rule_end <= range.end;

    if (start_belongs != end_belongs)
      break;
    if (!start_belongs)
      continue;
    if (!found_data || found_data->rule_body_range.length() >
                           rule_source_data->rule_body_range.length())
      found_data = rule_source_data;
  }
  CSSRule* rule = RuleForSourceData(found_data);
  if (!rule) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "No style rule could be found in given range.");
    return false;
  }
  CSSStyleSheet* style_sheet = rule->parentStyleSheet();
  if (!style_sheet) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "No parent stylesheet could be found.");
    return false;
  }
  CSSRule* parent_rule = rule->parentRule();
  if (parent_rule) {
    if (parent_rule->GetType() != CSSRule::kMediaRule) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kNotFoundError,
          "Cannot remove rule from non-media rule.");
      return false;
    }
    CSSMediaRule* parent_media_rule = To<CSSMediaRule>(parent_rule);
    wtf_size_t index = 0;
    while (index < parent_media_rule->length() &&
           parent_media_rule->ItemInternal(index) != rule) {
      ++index;
    }
    DCHECK_LT(index, parent_media_rule->length());
    parent_media_rule->deleteRule(index, exception_state);
  } else {
    wtf_size_t index = 0;
    while (index < style_sheet->length() &&
           style_sheet->ItemInternal(index) != rule) {
      ++index;
    }
    DCHECK_LT(index, style_sheet->length());
    style_sheet->deleteRule(index, exception_state);
  }
  // |rule| MAY NOT be addressed after this line!

  if (exception_state.HadException())
    return false;

  ReplaceText(range, "", nullptr, nullptr);
  OnStyleSheetTextChanged();
  return true;
}

std::unique_ptr<protocol::Array<String>>
InspectorStyleSheet::CollectClassNames() {
  HashSet<String> unique_names;
  auto result = std::make_unique<protocol::Array<String>>();

  for (wtf_size_t i = 0; i < parsed_flat_rules_.size(); ++i) {
    if (auto* style_rule =
            DynamicTo<CSSStyleRule>(parsed_flat_rules_.at(i).Get()))
      GetClassNamesFromRule(style_rule, unique_names);
  }
  for (const String& class_name : unique_names)
    result->emplace_back(class_name);
  return result;
}

void InspectorStyleSheet::ReplaceText(const SourceRange& range,
                                      const String& text,
                                      SourceRange* new_range,
                                      String* old_text) {
  String sheet_text = text_;
  if (old_text)
    *old_text = sheet_text.Substring(range.start, range.length());
  sheet_text.replace(range.start, range.length(), text);
  if (new_range)
    *new_range = SourceRange(range.start, range.start + text.length());
  InnerSetText(sheet_text, true);
}

void InspectorStyleSheet::ParseText(const String& text) {
  CSSRuleSourceDataList* rule_tree =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      page_style_sheet_->Contents()->ParserContext());
  Document* owner_document = page_style_sheet_->OwnerDocument();
  InspectorCSSParserObserver observer(
      text, owner_document, rule_tree,
      InspectorCSSParserObserver::IssueReportingContext{
          page_style_sheet_->BaseURL(),
          page_style_sheet_->StartPositionInSource()});
  CSSParser::ParseSheetForInspector(
      page_style_sheet_->Contents()->ParserContext(), style_sheet, text,
      observer);
  CSSStyleSheet* source_data_sheet = nullptr;
  if (auto* import_rule =
          DynamicTo<CSSImportRule>(page_style_sheet_->ownerRule())) {
    source_data_sheet =
        MakeGarbageCollected<CSSStyleSheet>(style_sheet, import_rule);
  } else {
    if (page_style_sheet_->ownerNode()) {
      source_data_sheet = MakeGarbageCollected<CSSStyleSheet>(
          style_sheet, *page_style_sheet_->ownerNode());
    } else {
      source_data_sheet = MakeGarbageCollected<CSSStyleSheet>(style_sheet);
    }
  }

  parsed_flat_rules_.clear();
  CollectFlatRules(source_data_sheet, &parsed_flat_rules_);

  source_data_ = MakeGarbageCollected<CSSRuleSourceDataList>();
  FlattenSourceData(*rule_tree, source_data_.Get());

  // The number of rules parsed should be equal to the number of source data
  // entries:
  DCHECK_EQ(parsed_flat_rules_.size(), source_data_->size());

  if (owner_document) {
    const auto* property_registry = owner_document->GetPropertyRegistry();

    if (property_registry) {
      for (const auto& rule_source_data : *source_data_) {
        for (auto& property_source_data : rule_source_data->property_data) {
          if (!property_source_data.name.StartsWith("--") ||
              !property_source_data.parsed_ok) {
            continue;
          }

          // The defaulting keywords are always allowed
          if (css_parsing_utils::IsCSSWideKeyword(property_source_data.value)) {
            continue;
          }

          const auto* registration = property_registry->Registration(
              AtomicString(property_source_data.name));
          if (!registration) {
            continue;
          }
          if (!registration->Syntax().Parse(property_source_data.value,
                                            *style_sheet->ParserContext(),
                                            false)) {
            property_source_data.parsed_ok = false;
          }
        }
      }
    }
  }
}

// The stylesheet text might be out of sync with `page_style_sheet_` rules.
// This method checks if a rule is present in the source text using
// `SourceDataForRule` and produces a new text with all rules merged into the
// original text. For example, if the source text is
//
//   /* comment */ .rule1 {} .rule3 {}
//
// and the page_style_sheet_ contains
//
//   .rule0 {} .rule1 {} .rule2 {} .rule3 {} .rule4 {}
//
// The result should be
//
//   .rule0 {} /* comment */ .rule1 {} .rule2 {} .rule3 {} .rule4 {}
//
// Note that page_style_sheet_ does not maintain comments and original
// formatting.
String InspectorStyleSheet::MergeCSSOMRulesWithText(const String& text) {
  String merged_text = text;
  unsigned original_insert_pos = 0;
  unsigned inserted_count = 0;
  for (unsigned i = 0; i < page_style_sheet_->length(); i++) {
    CSSRuleSourceData* source_data =
        SourceDataForRule(page_style_sheet_->ItemInternal(i));
    if (source_data) {
      original_insert_pos = source_data->rule_body_range.end + 1;
      continue;
    }
    String rule_text = page_style_sheet_->ItemInternal(i)->cssText();
    merged_text.replace(original_insert_pos + inserted_count, 0, rule_text);
    inserted_count += rule_text.length();
  }
  rule_to_source_data_.clear();
  source_data_to_rule_.clear();
  cssom_flat_rules_.clear();
  return merged_text;
}

void InspectorStyleSheet::InnerSetText(const String& text,
                                       bool mark_as_locally_modified) {
  marked_for_sync_ = false;
  ParseText(text);

  text_ = text;

  if (mark_as_locally_modified) {
    Element* element = OwnerStyleElement();
    if (element) {
      resource_container_->StoreStyleElementContent(element->GetDomNodeId(),
                                                    text);
    } else if (origin_ == protocol::CSS::StyleSheetOriginEnum::Inspector) {
      resource_container_->StoreStyleElementContent(
          page_style_sheet_->OwnerDocument()->GetDomNodeId(), text);
    } else {
      resource_container_->StoreStyleSheetContent(FinalURL(), text);
    }
  }
}

namespace {

TextPosition TextPositionFromOffsetAndLineEndingsRelativeToStartPosition(
    unsigned offset,
    const Vector<unsigned>& line_endings,
    const TextPositi
"""


```