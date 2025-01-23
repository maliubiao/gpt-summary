Response:
My thought process for analyzing the provided code snippet and generating the summary went something like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided C++ code, highlighting its relationship with web technologies (JavaScript, HTML, CSS), common errors, and any logical inferences. It's the second part of a larger file analysis.

2. **Initial Scan for Keywords and Patterns:** I quickly scanned the code for recurring keywords and patterns. The most obvious and frequent terms were:
    * `aria-`:  Clearly related to accessibility attributes.
    * `html_names::k...Attr`:  Indicates the code is dealing with HTML attributes.
    * `WebFeature::k...Attribute`: Suggests tracking the usage of specific attributes.
    * `attribute_triggers`:  A key data structure mapping attributes to actions.
    * `HTMLElement::`:  Confirms this code is part of the `HTMLElement` class in Blink.
    * `AttributeChanged`, `ParseAttribute`:  These are important lifecycle methods for handling attribute modifications.
    * `blur()`: A function related to focus management.

3. **Identify the Core Functionality (Based on the first part):** The initial part of the file (not shown, but implied by "Part 2") likely established the basic structure of `HTMLElement` and how attributes are handled generally. This section seems to be adding *specific* handling for a defined set of attributes.

4. **Focus on the Provided Data Structure (`attribute_triggers`):** This is the heart of the provided code. Each entry in the `attribute_triggers` array defines:
    * An HTML attribute name (`html_names::k...Attr`).
    * A corresponding `WebFeature` enum value (for tracking usage).
    * An event name (`kNoEvent` in this snippet, suggesting these specific attributes don't directly trigger events at this stage).
    * A function pointer (`nullptr` here, implying no specialized function handling for these attributes *during parsing*).

5. **Infer the Purpose of `attribute_triggers`:**  Given the structure, I inferred that this array serves as a lookup table. It allows the browser engine to quickly determine if a particular attribute is one of the "special" attributes being handled in this section. The `AttributeToTriggerIndexMap` confirms this, as it's a hash map for efficient lookup.

6. **Relate to Web Technologies:**
    * **HTML:** The attributes listed are directly from HTML (specifically ARIA attributes and `autocapitalize`).
    * **JavaScript:** The `SetAttributeEventListener` function (though not used for these specific attributes *yet*) hints at a connection to JavaScript event handlers. The comment about namespaced attributes falling back to a general handler also suggests a potential interaction when JavaScript manipulates such attributes.
    * **CSS:** While these attributes don't directly *style* elements, ARIA attributes are used by assistive technologies and can influence how elements are rendered or interpreted. The `blur()` call on `hidden` attribute changes hints at managing visual focus, which is related to rendering.

7. **Identify Potential Logical Inferences and Assumptions:**
    * **Assumption:** The code assumes that the `html_names` namespace and `WebFeature` enum are defined elsewhere.
    * **Inference:** The absence of specific event handlers or functions in the `attribute_triggers` for this section implies that these attributes are likely processed in a more general way by the `HTMLElement` class after being identified.

8. **Consider User/Programming Errors:**  While this specific snippet doesn't show explicit error handling for *invalid* attribute values, the overall design suggests that:
    * **Typos in attribute names:** The lookup table approach makes the system robust against typos, as misspelled attributes will simply not be found in the table and likely handled as standard attributes.
    * **Incorrect usage of ARIA attributes:**  While the code tracks usage, it doesn't enforce correctness. Incorrect ARIA attribute values would likely be caught by accessibility validators or lead to unexpected behavior in assistive technologies.

9. **Formulate Examples:** Based on the identified functionalities, I crafted examples demonstrating how these attributes are used in HTML and how JavaScript might interact with them.

10. **Synthesize the Summary (for Part 2):**  Focus on the key contribution of this section. It's about providing specific handling for a defined set of HTML attributes, primarily ARIA attributes and `autocapitalize`, by creating a lookup table. It sets the stage for further processing of these attributes within the `HTMLElement` lifecycle.

11. **Review and Refine:** I reviewed the summary to ensure it was clear, concise, and accurately reflected the functionality of the provided code snippet, while also addressing the specific requirements of the prompt (JavaScript, HTML, CSS relations, errors, inferences). I also made sure to explicitly state that this is a summary of *this specific part* of the file.
```
功能归纳（第2部分）:

这部分代码主要定义和初始化了一个**静态的属性触发器查找表 (attribute_triggers)**，用于将特定的HTML属性名称映射到一些预定义的操作或信息。  具体来说，这部分专注于列出和注册 **ARIA (Accessible Rich Internet Applications)** 属性以及 `autocapitalize` 属性。

**功能详细说明:**

1. **定义属性触发器结构体 (`AttributeTriggers`)**:  尽管结构体的完整定义没有在此处显示，但从代码中可以推断出它至少包含以下字段：
    * `attribute`:  一个 `QualifiedName` 对象，表示 HTML 属性的名称（包含命名空间，虽然这里大部分是空命名空间）。
    * `web_feature`: 一个 `WebFeature` 枚举值，用于追踪特定属性的使用情况 (通过 `UseCounter`)。
    * `event`: 一个 `AtomicString` 对象，表示当属性被设置时可能触发的事件名称 (这里大部分是 `kNoEvent`，意味着这些属性的改变不会直接触发特定的事件，而是通过其他机制处理)。
    * `function`: 一个函数指针，指向当属性被解析时需要调用的特定处理函数 (这里全部是 `nullptr`，表示这些属性没有特别的解析逻辑，而是由 `HTMLElement` 的通用属性解析机制处理)。

2. **初始化静态查找表 (`attribute_triggers`)**:  这是一个静态的数组，包含了大量的 `AttributeTriggers` 结构体实例。每个实例都对应一个特定的 HTML 属性。  这部分代码罗列了几乎所有的标准 ARIA 属性，例如：
    * `aria-busy`
    * `aria-checked`
    * `aria-controls`
    * `aria-hidden`
    * `aria-label`
    * ... 以及许多其他的 ARIA 属性。
    * 最后还包含了 `autocapitalize` 属性。

3. **创建属性到索引的映射 (`attribute_to_trigger_index_map`)**:  为了提高查找效率，代码创建了一个静态的哈希映射 (`HashMap`)，将属性名称 (`QualifiedName`) 映射到其在 `attribute_triggers` 数组中的索引。  这样可以通过属性名快速找到对应的 `AttributeTriggers` 信息。

4. **提供查找函数 (`TriggersForAttributeName`)**:  这是一个静态函数，接收一个 `QualifiedName` 类型的属性名作为输入，并在 `attribute_to_trigger_index_map` 中查找对应的索引，然后返回 `attribute_triggers` 数组中相应的 `AttributeTriggers` 结构体的指针。如果找不到匹配的属性，则返回 `nullptr`。

5. **提供获取事件名称的函数 (`EventNameForAttributeName`)**:  这是一个静态函数，接收一个 `QualifiedName` 类型的属性名，调用 `TriggersForAttributeName` 获取对应的 `AttributeTriggers`，并返回其 `event` 字段的值。 如果找不到对应的属性，则返回一个空字符串 (`g_null_atom`)。

**与 JavaScript, HTML, CSS 的关系：**

* **HTML:** 这部分代码直接对应了 HTML 规范中定义的 ARIA 属性和 `autocapitalize` 属性。它确保了 Blink 引擎能够识别和处理这些属性。
    * **例子:**  在 HTML 中使用 `aria-label="关闭菜单"`  ，Blink 引擎会通过这里的查找表识别 `aria-label` 属性，并记录其使用情况 (通过 `WebFeature::kARIALabelAttribute`)。虽然这里没有直接关联的事件或特殊处理函数，但 Blink 的其他部分会利用这些信息来提供更好的可访问性支持。

* **JavaScript:**  虽然这部分代码本身没有直接的 JavaScript 交互，但它为 JavaScript 操作这些属性奠定了基础。 JavaScript 可以通过 DOM API (例如 `element.getAttribute('aria-hidden')`, `element.setAttribute('aria-expanded', 'true')`) 来读取和设置这些属性。 Blink 引擎会使用这里定义的查找表来识别这些属性。
    * **例子:**  JavaScript 代码 `document.getElementById('myButton').setAttribute('aria-pressed', 'true');`  执行时，Blink 引擎会识别 `aria-pressed` 属性。

* **CSS:**  ARIA 属性本身不直接影响元素的样式，但 CSS 可以使用属性选择器来根据 ARIA 属性的值来应用样式。
    * **例子:** CSS 规则 `button[aria-pressed="true"] { font-weight: bold; }`  会选择所有 `aria-pressed` 属性值为 "true" 的 button 元素，并将它们的字体加粗。  Blink 引擎需要能够正确识别 `aria-pressed` 属性才能使这个 CSS 规则生效。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  `attr_name` 为 `html_names::kAriaLabelAttr`。
* **输出:** `TriggersForAttributeName(attr_name)` 将返回指向 `attribute_triggers` 数组中对应 `aria-label` 条目的 `AttributeTriggers` 结构体的指针。 该结构体中的 `web_feature` 将是 `WebFeature::kARIALabelAttribute`， `event` 将是 `kNoEvent`， `function` 将是 `nullptr`。
* **假设输入:** `attr_name` 为 `QualifiedName::FromQualifiedName("non-existent-attribute")`。
* **输出:** `TriggersForAttributeName(attr_name)` 将返回 `nullptr`，因为该属性不在查找表中。
* **假设输入:** `attr_name` 为 `html_names::kAriaHiddenAttr`。
* **输出:** `EventNameForAttributeName(attr_name)` 将返回 `kNoEvent`。

**用户或编程常见的使用错误举例:**

虽然这部分代码本身不直接处理用户输入或容易出错的逻辑，但它涉及的属性在实际使用中容易出现错误：

* **拼写错误:** 开发者可能会拼错 ARIA 属性的名称，例如 `aria-lbel` 而不是 `aria-label`。  由于查找表是精确匹配，拼写错误的属性将不会被识别为 ARIA 属性。
* **使用错误的 ARIA 属性:**  开发者可能在不合适的元素上使用了不相关的 ARIA 属性，导致可访问性问题。  例如，在一个非交互元素上使用 `aria-pressed`。  这部分代码虽然会记录这些属性的使用，但不会阻止这种错误的使用。
* **ARIA 属性值不合法:** 某些 ARIA 属性有特定的值域要求。  例如，`aria-live` 只能取 `off`, `polite`, 或 `assertive`。  提供其他值是错误的。  这部分代码不会校验属性值是否合法。
* **忘记使用 ARIA 属性:**  开发者可能忘记为需要可访问性的元素添加必要的 ARIA 属性，导致屏幕阅读器等辅助技术无法正确理解页面的结构和交互。

**总结:**

这部分代码的核心功能是构建了一个高效的查找机制，用于识别和记录特定的 HTML 属性，尤其是 ARIA 属性和 `autocapitalize` 属性。 它为 Blink 引擎处理这些属性奠定了基础，虽然自身不包含复杂的逻辑，但对于正确支持 Web 标准和提供可访问性至关重要。 它通过将属性名称映射到 `WebFeature` 枚举值来支持属性使用情况的统计，以便 Chrome 团队了解 Web 平台的采用情况。  对于这里列出的属性，目前没有定义特定的事件触发或解析函数，意味着这些属性的通用处理逻辑在 `HTMLElement` 类的其他部分实现。
```
### 提示词
```
这是目录为blink/renderer/core/html/html_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
{html_names::kAriaBusyAttr, WebFeature::kARIABusyAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaCheckedAttr, WebFeature::kARIACheckedAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaColcountAttr, WebFeature::kARIAColCountAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaColindexAttr, WebFeature::kARIAColIndexAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaColindextextAttr,
       WebFeature::kARIAColIndexTextAttribute, kNoEvent, nullptr},
      {html_names::kAriaColspanAttr, WebFeature::kARIAColSpanAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaControlsAttr, WebFeature::kARIAControlsAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaCurrentAttr, WebFeature::kARIACurrentAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaDescribedbyAttr, WebFeature::kARIADescribedByAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaDescriptionAttr, WebFeature::kARIADescriptionAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaDetailsAttr, WebFeature::kARIADetailsAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaDisabledAttr, WebFeature::kARIADisabledAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaErrormessageAttr,
       WebFeature::kARIAErrorMessageAttribute, kNoEvent, nullptr},
      {html_names::kAriaExpandedAttr, WebFeature::kARIAExpandedAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaFlowtoAttr, WebFeature::kARIAFlowToAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaHaspopupAttr, WebFeature::kARIAHasPopupAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaHiddenAttr, WebFeature::kARIAHiddenAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaInvalidAttr, WebFeature::kARIAInvalidAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaKeyshortcutsAttr,
       WebFeature::kARIAKeyShortcutsAttribute, kNoEvent, nullptr},
      {html_names::kAriaLabelAttr, WebFeature::kARIALabelAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaLabeledbyAttr, WebFeature::kARIALabeledByAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaLabelledbyAttr, WebFeature::kARIALabelledByAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaLevelAttr, WebFeature::kARIALevelAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaLiveAttr, WebFeature::kARIALiveAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaModalAttr, WebFeature::kARIAModalAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaMultilineAttr, WebFeature::kARIAMultilineAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaMultiselectableAttr,
       WebFeature::kARIAMultiselectableAttribute, kNoEvent, nullptr},
      {html_names::kAriaOrientationAttr, WebFeature::kARIAOrientationAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaOwnsAttr, WebFeature::kARIAOwnsAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaPlaceholderAttr, WebFeature::kARIAPlaceholderAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaPosinsetAttr, WebFeature::kARIAPosInSetAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaPressedAttr, WebFeature::kARIAPressedAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaReadonlyAttr, WebFeature::kARIAReadOnlyAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaRelevantAttr, WebFeature::kARIARelevantAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaRequiredAttr, WebFeature::kARIARequiredAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaRoledescriptionAttr,
       WebFeature::kARIARoleDescriptionAttribute, kNoEvent, nullptr},
      {html_names::kAriaRowcountAttr, WebFeature::kARIARowCountAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaRowindexAttr, WebFeature::kARIARowIndexAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaRowindextextAttr,
       WebFeature::kARIARowIndexTextAttribute, kNoEvent, nullptr},
      {html_names::kAriaRowspanAttr, WebFeature::kARIARowSpanAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaSelectedAttr, WebFeature::kARIASelectedAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaSetsizeAttr, WebFeature::kARIASetSizeAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaSortAttr, WebFeature::kARIASortAttribute, kNoEvent,
       nullptr},
      {html_names::kAriaValuemaxAttr, WebFeature::kARIAValueMaxAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaValueminAttr, WebFeature::kARIAValueMinAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaValuenowAttr, WebFeature::kARIAValueNowAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaValuetextAttr, WebFeature::kARIAValueTextAttribute,
       kNoEvent, nullptr},
      {html_names::kAriaVirtualcontentAttr,
       WebFeature::kARIAVirtualcontentAttribute, kNoEvent, nullptr},
      // End ARIA attributes.

      {html_names::kAutocapitalizeAttr, WebFeature::kAutocapitalizeAttribute,
       kNoEvent, nullptr},
  };

  using AttributeToTriggerIndexMap = HashMap<QualifiedName, uint32_t>;
  DEFINE_STATIC_LOCAL(AttributeToTriggerIndexMap,
                      attribute_to_trigger_index_map, ());
  if (!attribute_to_trigger_index_map.size()) {
    for (uint32_t i = 0; i < std::size(attribute_triggers); ++i) {
      DCHECK(attribute_triggers[i].attribute.NamespaceURI().IsNull())
          << "Lookup table does not work for namespaced attributes because "
             "they would not match for different prefixes";
      attribute_to_trigger_index_map.insert(attribute_triggers[i].attribute, i);
    }
  }

  auto iter = attribute_to_trigger_index_map.find(attr_name);
  if (iter != attribute_to_trigger_index_map.end())
    return &attribute_triggers[iter->value];
  return nullptr;
}

// static
const AtomicString& HTMLElement::EventNameForAttributeName(
    const QualifiedName& attr_name) {
  AttributeTriggers* triggers = TriggersForAttributeName(attr_name);
  if (triggers)
    return triggers->event;
  return g_null_atom;
}

void HTMLElement::AttributeChanged(const AttributeModificationParams& params) {
  Element::AttributeChanged(params);
  if (params.name == html_names::kDisabledAttr &&
      IsFormAssociatedCustomElement() &&
      params.old_value.IsNull() != params.new_value.IsNull()) {
    EnsureElementInternals().DisabledAttributeChanged();
    if (params.reason == AttributeModificationReason::kDirectly &&
        IsDisabledFormControl() && AdjustedFocusedElementInTreeScope() == this)
      blur();
    return;
  }
  if (params.name == html_names::kReadonlyAttr &&
      IsFormAssociatedCustomElement() &&
      params.old_value.IsNull() != params.new_value.IsNull()) {
    EnsureElementInternals().ReadonlyAttributeChanged();
    return;
  }

  if (params.reason != AttributeModificationReason::kDirectly)
    return;
  // adjustedFocusedElementInTreeScope() is not trivial. We should check
  // attribute names, then call adjustedFocusedElementInTreeScope().
  if (params.name == html_names::kHiddenAttr && !params.new_value.IsNull()) {
    if (AdjustedFocusedElementInTreeScope() == this)
      blur();
  } else if (params.name == html_names::kSpellcheckAttr) {
    if (GetDocument().GetFrame()) {
      GetDocument().GetFrame()->GetSpellChecker().RespondToChangedEnablement(
          *this, IsSpellCheckingEnabled());
    }
  } else if (params.name == html_names::kContenteditableAttr) {
    if (GetDocument().GetFrame()) {
      GetDocument()
          .GetFrame()
          ->GetSpellChecker()
          .RemoveSpellingAndGrammarMarkers(
              *this, SpellChecker::ElementsType::kOnlyNonEditable);
    }
    if (AdjustedFocusedElementInTreeScope() != this)
      return;
    // The attribute change may cause IsFocusable() to return false
    // for the element which had focus.
    //
    // TODO(tkent): We should avoid updating style.  We'd like to check only
    // DOM-level focusability here.
    GetDocument().UpdateStyleAndLayoutTreeForElement(
        this, DocumentUpdateReason::kFocus);
    if (!IsFocusable()) {
      blur();
    }
  }
}

void HTMLElement::ParseAttribute(const AttributeModificationParams& params) {
  AttributeTriggers* triggers = TriggersForAttributeName(params.name);
  if (!triggers) {
    if (!params.name.NamespaceURI().IsNull()) {
      // AttributeTriggers lookup table does not support namespaced attributes.
      // Fall back to Element implementation for attributes like xml:lang.
      Element::ParseAttribute(params);
    }
    return;
  }

  if (triggers->event != g_null_atom) {
    SetAttributeEventListener(
        triggers->event,
        JSEventHandlerForContentAttribute::Create(
            GetExecutionContext(), params.name, params.new_value));
  }

  if (triggers->web_feature != kNoWebFeature) {
    // Count usage of attributes but ignore attributes in user agent shadow DOM.
    if (!IsInUserAgentShadowRoot())
      UseCounter::Count(GetDocument(), triggers->web_feature);
  }
  if (triggers->function)
    ((*this).*(triggers->function))(params);
}

DocumentFragment* HTMLElement::TextToFragment(const String& text,
                                              ExceptionState& exception_state) {
  DocumentFragment* fragment = DocumentFragment::Create(GetDocument());
  unsigned i, length = text.length();
  UChar c = 0;
  for (unsigned start = 0; start < length;) {
    // Find next line break.
    for (i = start; i < length; i++) {
      c = text[i];
      if (c == '\r' || c == '\n')
        break;
    }

    if (i > start) {
      fragment->AppendChild(
          Text::Create(GetDocument(), text.Substring(start, i - start)),
          exception_state);
      if (exception_state.HadException())
        return nullptr;
    }

    if (i == length)
      break;

    fragment->AppendChild(MakeGarbageCollected<HTMLBRElement>(GetDocument()),
                          exception_state);
    if (exception_state.HadException())
      return nullptr;

    // Make sure \r\n doesn't result in two line breaks.
    if (c == '\r' && i + 1 < length && text[i + 1] == '\n')
      i++;

    start = i + 1;  // Character after line break.
  }

  return fragment;
}

V8UnionStringLegacyNullToEmptyStringOrTrustedScript*
HTMLElement::innerTextForBinding() {
  return MakeGarbageCollected<
      V8UnionStringLegacyNullToEmptyStringOrTrustedScript>(innerText());
}

void HTMLElement::setInnerTextForBinding(
    const V8UnionStringLegacyNullToEmptyStringOrTrustedScript*
        string_or_trusted_script,
    ExceptionState& exception_state) {
  String value;
  switch (string_or_trusted_script->GetContentType()) {
    case V8UnionStringLegacyNullToEmptyStringOrTrustedScript::ContentType::
        kStringLegacyNullToEmptyString:
      value = string_or_trusted_script->GetAsStringLegacyNullToEmptyString();
      break;
    case V8UnionStringLegacyNullToEmptyStringOrTrustedScript::ContentType::
        kTrustedScript:
      value = string_or_trusted_script->GetAsTrustedScript()->toString();
      break;
  }
  setInnerText(value);
}

void HTMLElement::setInnerText(const String& text) {
  // FIXME: This doesn't take whitespace collapsing into account at all.

  // The usage of ASSERT_NO_EXCEPTION in this function is subject to mutation
  // events being fired while removing elements. By delaying them to the end of
  // the function, we can guarantee that no exceptions will be thrown.
  EventQueueScope delay_mutation_events;

  if (!text.Contains('\n') && !text.Contains('\r')) {
    if (text.empty()) {
      RemoveChildren();
      return;
    }
    ReplaceChildrenWithText(this, text, ASSERT_NO_EXCEPTION);
    return;
  }

  // Add text nodes and <br> elements.
  DocumentFragment* fragment = TextToFragment(text, ASSERT_NO_EXCEPTION);
  ReplaceChildrenWithFragment(this, fragment, ASSERT_NO_EXCEPTION);
}

void HTMLElement::setOuterText(const String& text,
                               ExceptionState& exception_state) {
  ContainerNode* parent = parentNode();
  if (!parent) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNoModificationAllowedError,
        "The element has no parent.");
    return;
  }

  Node* prev = previousSibling();
  Node* next = nextSibling();
  Node* new_child = nullptr;

  // Convert text to fragment with <br> tags instead of linebreaks if needed.
  if (text.Contains('\r') || text.Contains('\n'))
    new_child = TextToFragment(text, exception_state);
  else
    new_child = Text::Create(GetDocument(), text);

  if (exception_state.HadException())
    return;

  parent->ReplaceChild(new_child, this, exception_state);

  Node* node = next ? next->previousSibling() : nullptr;
  auto* next_text_node = DynamicTo<Text>(node);
  if (!exception_state.HadException() && next_text_node)
    MergeWithNextTextNode(next_text_node, exception_state);

  auto* prev_text_node = DynamicTo<Text>(prev);
  if (!exception_state.HadException() && prev && prev->IsTextNode())
    MergeWithNextTextNode(prev_text_node, exception_state);
}

void HTMLElement::ApplyAspectRatioToStyle(const AtomicString& width,
                                          const AtomicString& height,
                                          MutableCSSPropertyValueSet* style) {
  HTMLDimension width_dim;
  if (!ParseDimensionValue(width, width_dim) || !width_dim.IsAbsolute())
    return;
  HTMLDimension height_dim;
  if (!ParseDimensionValue(height, height_dim) || !height_dim.IsAbsolute())
    return;
  ApplyAspectRatioToStyle(width_dim.Value(), height_dim.Value(), style);
}

void HTMLElement::ApplyIntegerAspectRatioToStyle(
    const AtomicString& width,
    const AtomicString& height,
    MutableCSSPropertyValueSet* style) {
  unsigned width_val = 0;
  if (!ParseHTMLNonNegativeInteger(width, width_val))
    return;
  unsigned height_val = 0;
  if (!ParseHTMLNonNegativeInteger(height, height_val))
    return;
  ApplyAspectRatioToStyle(width_val, height_val, style);
}

void HTMLElement::ApplyAspectRatioToStyle(double width,
                                          double height,
                                          MutableCSSPropertyValueSet* style) {
  auto* width_val = CSSNumericLiteralValue::Create(
      width, CSSPrimitiveValue::UnitType::kNumber);
  auto* height_val = CSSNumericLiteralValue::Create(
      height, CSSPrimitiveValue::UnitType::kNumber);
  auto* ratio_value =
      MakeGarbageCollected<cssvalue::CSSRatioValue>(*width_val, *height_val);

  CSSValueList* list = CSSValueList::CreateSpaceSeparated();
  list->Append(*CSSIdentifierValue::Create(CSSValueID::kAuto));
  list->Append(*ratio_value);

  style->SetProperty(CSSPropertyID::kAspectRatio, *list);
}

void HTMLElement::ApplyAlignmentAttributeToStyle(
    const AtomicString& alignment,
    MutableCSSPropertyValueSet* style) {
  // Vertical alignment with respect to the current baseline of the text
  // right or left means floating images.
  CSSValueID float_value = CSSValueID::kInvalid;
  CSSValueID vertical_align_value = CSSValueID::kInvalid;

  if (EqualIgnoringASCIICase(alignment, "absmiddle") ||
      EqualIgnoringASCIICase(alignment, "abscenter")) {
    vertical_align_value = CSSValueID::kMiddle;
  } else if (EqualIgnoringASCIICase(alignment, "absbottom")) {
    vertical_align_value = CSSValueID::kBottom;
  } else if (EqualIgnoringASCIICase(alignment, "left")) {
    float_value = CSSValueID::kLeft;
    vertical_align_value = CSSValueID::kTop;
  } else if (EqualIgnoringASCIICase(alignment, "right")) {
    float_value = CSSValueID::kRight;
    vertical_align_value = CSSValueID::kTop;
  } else if (EqualIgnoringASCIICase(alignment, "top")) {
    vertical_align_value = CSSValueID::kTop;
  } else if (EqualIgnoringASCIICase(alignment, "middle")) {
    vertical_align_value = CSSValueID::kWebkitBaselineMiddle;
  } else if (EqualIgnoringASCIICase(alignment, "center")) {
    vertical_align_value = CSSValueID::kMiddle;
  } else if (EqualIgnoringASCIICase(alignment, "bottom")) {
    vertical_align_value = CSSValueID::kBaseline;
  } else if (EqualIgnoringASCIICase(alignment, "texttop")) {
    vertical_align_value = CSSValueID::kTextTop;
  }

  if (IsValidCSSValueID(float_value)) {
    AddPropertyToPresentationAttributeStyle(style, CSSPropertyID::kFloat,
                                            float_value);
  }

  if (IsValidCSSValueID(vertical_align_value)) {
    AddPropertyToPresentationAttributeStyle(
        style, CSSPropertyID::kVerticalAlign, vertical_align_value);
  }
}

bool HTMLElement::HasCustomFocusLogic() const {
  return false;
}

ContentEditableType HTMLElement::contentEditableNormalized() const {
  AtomicString value =
      FastGetAttribute(html_names::kContenteditableAttr).LowerASCII();

  if (value.IsNull())
    return ContentEditableType::kInherit;
  if (value.empty() || value == keywords::kTrue) {
    return ContentEditableType::kContentEditable;
  }
  if (value == keywords::kFalse) {
    return ContentEditableType::kNotContentEditable;
  }
  if (value == keywords::kPlaintextOnly) {
    return ContentEditableType::kPlaintextOnly;
  }

  return ContentEditableType::kInherit;
}

String HTMLElement::contentEditable() const {
  switch (contentEditableNormalized()) {
    case ContentEditableType::kInherit:
      return keywords::kInherit;
    case ContentEditableType::kContentEditable:
      return keywords::kTrue;
    case ContentEditableType::kNotContentEditable:
      return keywords::kFalse;
    case ContentEditableType::kPlaintextOnly:
      return keywords::kPlaintextOnly;
  }
}

void HTMLElement::setContentEditable(const String& enabled,
                                     ExceptionState& exception_state) {
  String lower_value = enabled.LowerASCII();
  if (lower_value == keywords::kTrue) {
    setAttribute(html_names::kContenteditableAttr, keywords::kTrue);
  } else if (lower_value == keywords::kFalse) {
    setAttribute(html_names::kContenteditableAttr, keywords::kFalse);
  } else if (lower_value == keywords::kPlaintextOnly) {
    setAttribute(html_names::kContenteditableAttr, keywords::kPlaintextOnly);
  } else if (lower_value == keywords::kInherit) {
    removeAttribute(html_names::kContenteditableAttr);
  } else {
    exception_state.ThrowDOMException(DOMExceptionCode::kSyntaxError,
                                      "The value provided ('" + enabled +
                                          "') is not one of 'true', 'false', "
                                          "'plaintext-only', or 'inherit'.");
  }
}

V8UnionBooleanOrStringOrUnrestrictedDouble* HTMLElement::hidden() const {
  const AtomicString& attribute = FastGetAttribute(html_names::kHiddenAttr);

  if (attribute == g_null_atom) {
    return MakeGarbageCollected<V8UnionBooleanOrStringOrUnrestrictedDouble>(
        false);
  }
  if (attribute == "until-found") {
    return MakeGarbageCollected<V8UnionBooleanOrStringOrUnrestrictedDouble>(
        String("until-found"));
  }
  return MakeGarbageCollected<V8UnionBooleanOrStringOrUnrestrictedDouble>(true);
}

void HTMLElement::setHidden(
    const V8UnionBooleanOrStringOrUnrestrictedDouble* value) {
  if (!value) {
    removeAttribute(html_names::kHiddenAttr);
    return;
  }
  switch (value->GetContentType()) {
    case V8UnionBooleanOrStringOrUnrestrictedDouble::ContentType::kBoolean:
      if (value->GetAsBoolean()) {
        setAttribute(html_names::kHiddenAttr, g_empty_atom);
      } else {
        removeAttribute(html_names::kHiddenAttr);
      }
      break;
    case V8UnionBooleanOrStringOrUnrestrictedDouble::ContentType::kString:
      if (EqualIgnoringASCIICase(value->GetAsString(), "until-found")) {
        setAttribute(html_names::kHiddenAttr, AtomicString("until-found"));
      } else if (value->GetAsString() == "") {
        removeAttribute(html_names::kHiddenAttr);
      } else {
        setAttribute(html_names::kHiddenAttr, g_empty_atom);
      }
      break;
    case V8UnionBooleanOrStringOrUnrestrictedDouble::ContentType::
        kUnrestrictedDouble:
      double double_value = value->GetAsUnrestrictedDouble();
      if (double_value && !std::isnan(double_value)) {
        setAttribute(html_names::kHiddenAttr, g_empty_atom);
      } else {
        removeAttribute(html_names::kHiddenAttr);
      }
      break;
  }
}

namespace {

PopoverValueType GetPopoverTypeFromAttributeValue(const AtomicString& value) {
  AtomicString lower_value = value.LowerASCII();
  if (lower_value == keywords::kAuto || (!value.IsNull() && value.empty())) {
    return PopoverValueType::kAuto;
  } else if (lower_value == keywords::kHint &&
             RuntimeEnabledFeatures::HTMLPopoverHintEnabled()) {
    return PopoverValueType::kHint;
  } else if (lower_value == keywords::kManual) {
    return PopoverValueType::kManual;
  } else if (!value.IsNull()) {
    // Invalid values default to popover=manual.
    return PopoverValueType::kManual;
  }
  return PopoverValueType::kNone;
}
}  // namespace

void HTMLElement::UpdatePopoverAttribute(const AtomicString& value) {
  PopoverValueType type = GetPopoverTypeFromAttributeValue(value);
  if (type == PopoverValueType::kManual &&
      !EqualIgnoringASCIICase(value, keywords::kManual)) {
    AddConsoleMessage(mojom::blink::ConsoleMessageSource::kOther,
                      mojom::blink::ConsoleMessageLevel::kWarning,
                      "Found a 'popover' attribute with an invalid value.");
    UseCounter::Count(GetDocument(), WebFeature::kPopoverTypeInvalid);
  }
  if (HasPopoverAttribute()) {
    if (PopoverType() == type)
      return;
    String original_type = FastGetAttribute(html_names::kPopoverAttr);
    // If the popover type is changing, hide it.
    if (popoverOpen()) {
      HidePopoverInternal(
          HidePopoverFocusBehavior::kFocusPreviousElement,
          HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
          /*exception_state=*/nullptr);
      // Event handlers could have changed the popover, including by removing
      // the popover attribute, or changing its value. If that happened, we need
      // to make sure that PopoverData's copy of the popover attribute stays in
      // sync.
      type = GetPopoverTypeFromAttributeValue(
          FastGetAttribute(html_names::kPopoverAttr));
    }
  }
  if (type == PopoverValueType::kNone) {
    if (HasPopoverAttribute()) {
      if (RuntimeEnabledFeatures::CustomizableSelectEnabled() &&
          !RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled()) {
        // CustomizableSelect allows the implicit anchor to be set but only for
        // the UA ::picker(select) popover, which will never have its popover
        // attribute removed and therefore never hit this code path.
        DCHECK_EQ(implicitAnchor(), nullptr);
      }
      if (RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled()) {
        SetImplicitAnchor(nullptr);
      }
      // If the popover attribute is being removed, remove the PopoverData.
      RemovePopoverData();
    }
    return;
  }
  UseCounter::Count(GetDocument(), WebFeature::kValidPopoverAttribute);
  switch (type) {
    case PopoverValueType::kAuto:
      UseCounter::Count(GetDocument(), WebFeature::kPopoverTypeAuto);
      break;
    case PopoverValueType::kHint:
      UseCounter::Count(GetDocument(), WebFeature::kPopoverTypeHint);
      break;
    case PopoverValueType::kManual:
      UseCounter::Count(GetDocument(), WebFeature::kPopoverTypeManual);
      break;
    case PopoverValueType::kNone:
      NOTREACHED();
  }
  CHECK_EQ(type, GetPopoverTypeFromAttributeValue(
                     FastGetAttribute(html_names::kPopoverAttr)));
  EnsurePopoverData()->setType(type);
}

bool HTMLElement::HasPopoverAttribute() const {
  return GetPopoverData();
}

AtomicString HTMLElement::popover() const {
  auto attribute_value =
      FastGetAttribute(html_names::kPopoverAttr).LowerASCII();
  if (attribute_value.IsNull()) {
    return attribute_value;  // Nullable
  } else if (attribute_value.empty()) {
    return keywords::kAuto;  // ReflectEmpty = "auto"
  } else if (attribute_value == keywords::kAuto ||
             attribute_value == keywords::kManual) {
    return attribute_value;  // ReflectOnly
  } else if (attribute_value == keywords::kHint &&
             RuntimeEnabledFeatures::HTMLPopoverHintEnabled()) {
    return attribute_value;  // ReflectOnly (with HTMLPopoverHint enabled)
  } else {
    return keywords::kManual;  // ReflectInvalid = "manual"
  }
}
void HTMLElement::setPopover(const AtomicString& value) {
  setAttribute(html_names::kPopoverAttr, value);
}

PopoverValueType HTMLElement::PopoverType() const {
  return GetPopoverData() ? GetPopoverData()->type() : PopoverValueType::kNone;
}

// This should be true when `:popover-open` should match.
bool HTMLElement::popoverOpen() const {
  if (auto* popover_data = GetPopoverData())
    return popover_data->visibilityState() == PopoverVisibilityState::kShowing;
  return false;
}

bool HTMLElement::IsPopoverReady(PopoverTriggerAction action,
                                 ExceptionState* exception_state,
                                 bool include_event_handler_text,
                                 Document* expected_document) const {
  CHECK_NE(action, PopoverTriggerAction::kNone);

  auto maybe_throw_exception = [&exception_state, &include_event_handler_text](
                                   DOMExceptionCode code, const char* msg) {
    if (exception_state) {
      String error_message =
          String(msg) +
          (include_event_handler_text
               ? " This might have been the result of the \"beforetoggle\" "
                 "event handler changing the state of this popover."
               : "");
      exception_state->ThrowDOMException(code, error_message);
    }
  };

  if (!HasPopoverAttribute()) {
    maybe_throw_exception(DOMExceptionCode::kNotSupportedError,
                          "Not supported on elements that do not have a valid "
                          "value for the 'popover' attribute.");
    return false;
  }
  if (!GetDocument().IsActive() &&
      RuntimeEnabledFeatures::TopLayerInactiveDocumentExceptionsEnabled()) {
    maybe_throw_exception(
        DOMExceptionCode::kInvalidStateError,
        "Invalid for popovers within documents that are not fully active.");
    return false;
  }
  if (action == PopoverTriggerAction::kShow &&
      GetPopoverData()->visibilityState() != PopoverVisibilityState::kHidden) {
    return false;
  }
  if (action == PopoverTriggerAction::kHide &&
      GetPopoverData()->visibilityState() != PopoverVisibilityState::kShowing) {
    // Important to check that visibility is not kShowing (rather than
    // popoverOpen()), because a hide transition might have been started on this
    // popover already, and we don't want to allow a double-hide.
    return false;
  }
  if (!isConnected()) {
    maybe_throw_exception(DOMExceptionCode::kInvalidStateError,
                          "Invalid on disconnected popover elements.");
    return false;
  }
  if (expected_document && &GetDocument() != expected_document) {
    maybe_throw_exception(DOMExceptionCode::kInvalidStateError,
                          "Invalid when the document changes while showing or "
                          "hiding a popover element.");
    return false;
  }
  if (auto* dialog = DynamicTo<HTMLDialogElement>(this)) {
    if (action == PopoverTriggerAction::kShow && dialog->IsModal()) {
      maybe_throw_exception(DOMExceptionCode::kInvalidStateError,
                            "The dialog is already open as a dialog, and "
                            "therefore cannot be opened as a popover.");
      return false;
    }
  }
  if (action == PopoverTriggerAction::kShow &&
      Fullscreen::IsFullscreenElement(*this)) {
    maybe_throw_exception(
        DOMExceptionCode::kInvalidStateError,
        "This element is already in fullscreen mode, and therefore cannot be "
        "opened as a popover.");
    return false;
  }
  return true;
}

namespace {
// We have to mark *all* invokers for the given popover dirty in the
// ax tree, since they all should now have an updated expanded state.
void MarkPopoverInvokersDirty(const HTMLElement& popover) {
  CHECK(popover.HasPopoverAttribute());
  auto& document = popover.GetDocument();
  AXObjectCache* cache = document.ExistingAXObjectCache();
  if (!cache) {
    return;
  }
  for (auto* invoker_candidate :
       *popover.GetTreeScope().RootNode().PopoverInvokers()) {
    auto* invoker = To<HTMLFormControlElement>(invoker_candidate);
    if (popover == invoker->popoverTargetElement().popover) {
      cache->MarkElementDirty(invoker);
    }
  }
}
}  // namespace

bool HTMLElement::togglePopover(ExceptionState& exception_state) {
  return togglePopover(nullptr, exception_state);
}

// The `force` parameter to `togglePopover()` is specified here:
// https://html.spec.whatwg.org/multipage/popover.html#dom-togglepopover
// and is roughly:
//  - If `force` is provided, and true, then ensure the popover is *shown*.
//    So if the popover is already showing, do nothing.
//  - If `force` is provided, and false, then ensure the popover is *hidden*.
//    So if the popover is already hidden, do nothing.
//  - If `force` is not provided, just toggle the popover's current state.
bool HTMLElement::togglePopover(
    V8UnionBooleanOrTogglePopoverOptions* options_or_force,
    ExceptionState& exception_state) {
  bool popover_was_open = popoverOpen();
  bool force = !popover_was_open;
  Element* invoker;
  if (options_or_force && options_or_force->IsBoolean()) {
    force = options_or_force->GetAsBoolean();
    invoker = nullptr;
  } else {
    TogglePopoverOptions* options =
        (options_or_force &&
         RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled())
            ? options_or_force->GetAsTogglePopoverOptions()
            : nullptr;
    if (options && options->hasForce()) {
      force = options->force();
    }
    invoker = (options && options->hasSource()) ? options->source() : nullptr;
  }
  if (!force && popover_was_open) {
    hidePopover(exception_state);
  } else if (force && !popover_was_open) {
    ShowPopoverInternal(invoker, &exception_state);
  } else {
    // We had `force`, and the state already lined up. Just make sure to still
    // throw exceptions in other cases, e.g. disconnected element or no popover
    // attribute.
    IsPopoverReady(PopoverTriggerAction::kToggle, &exception_state,
                   /*include_event_handler_text=*/false,
                   /*document=*/nullptr);
  }
  return GetPopoverData() && GetPopoverData()->visibilityState() ==
                                 PopoverVisibilityState::kShowing;
}

void HTMLElement::showPopover(ExceptionState& exception_state) {
  return showPopover(nullptr, exception_state);
}
void HTMLElement::showPopover(ShowPopoverOptions* options,
                              ExceptionState& exception_state) {
  if (!RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled()) {
    options = nullptr;
  }
  Element* invoker =
      options && options->hasSource() ? options->source() : nullptr;
  ShowPopoverInternal(invoker, &exception_state);
}

void HTMLElement::ShowPopoverInternal(Element* invoker,
                                      ExceptionState* exception_state) {
  if (!IsPopoverReady(PopoverTriggerAction::kShow, exception_state,
                      /*include_event_handler_text=*/false, /*document=*/nullptr)) {
    CHECK(exception_state)
        << " Callers which aren't supposed to throw exceptions should not call "
           "ShowPopoverInternal when the Popover isn't in a valid state to be "
           "shown.";
    return;
  }

  CHECK(!GetPopoverData() || !GetPopoverData()->invoker());

  // Fire events by default, unless we're recursively showing this popover.
  PopoverData::ScopedStartShowingOrHiding scoped_was_showing_or_hiding(*this);
  auto transition_behavior =
      scoped_was_showing_or_hiding
          ? HidePopoverTransitionBehavior::kNoEventsNoWaiting
          : HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions;

  auto& original_document = GetDocument();

  // Fire the "opening" beforetoggle event.
  auto* event = ToggleEvent::Create(
      event_type_names::kBeforetoggle, Event::Cancelable::kYes,
      /*old_state*/ "closed", /*new_state*/ "open");
  CHECK(!event->bubbles());
  CHECK(event->cancelable());
  CHECK_EQ(event->oldState(), "closed");
  CHECK_EQ(event->newState(), "open");
  event->SetTarget(this);
  if (DispatchEvent(*event) != DispatchEventResult::kNotCanceled)
    return;

  // The 'beforetoggle' event handler could have changed this popover, e.g. by
  // changing its type, removing it from the document, moving it to another
  // document, or calling showPopover().
  if (!IsPopoverReady(PopoverTriggerAction
```