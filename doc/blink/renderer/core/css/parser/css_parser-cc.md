Response:
My thinking process to analyze the `css_parser.cc` file and address the prompt's requirements would go something like this:

1. **Understand the Core Function:** The file name `css_parser.cc` and the `#include` directives (like `css_parser_impl.h`, `css_tokenizer.h`, `css_selector_parser.h`) immediately tell me this file is about parsing CSS. The `blink::CSSParser` namespace confirms this is part of the Blink rendering engine.

2. **Identify Key Responsibilities:**  I'd scan the public methods within the `blink::CSSParser` namespace. The names of these methods are highly descriptive:
    * `ParseDeclarationList`:  Parsing a list of CSS declarations (property-value pairs).
    * `ParseNestedDeclarationsRule`: Parsing declarations within nested at-rules.
    * `ParseSelector`: Parsing CSS selectors.
    * `ParsePageSelector`: Parsing selectors specifically for `@page` rules.
    * `ParseMarginRule`: Parsing rules within `@page` margin boxes.
    * `ParseRule`: A more general rule parsing function.
    * `ParseSheet`: Parsing an entire CSS stylesheet.
    * `ParseValue`: Parsing individual CSS property values.
    * `ParseValueForCustomProperty`:  Specifically for parsing CSS custom properties (variables).
    * `ParseSingleValue`: Parsing a single value for a given property.
    * `ParseInlineStyleDeclaration`: Parsing the `style` attribute of HTML elements.
    * `ParseKeyframeKeyList`: Parsing the list of keyframe offsets in an `@keyframes` rule.
    * `ParseKeyframeRule`: Parsing an individual `@keyframes` rule.
    * `ParseCustomPropertyName`: Parsing the name of a custom property.
    * `ParseSupportsCondition`: Parsing the condition within a `@supports` rule.
    * `ParseColor`: Parsing color values.
    * `ParseSystemColor`: Parsing system color keywords.
    * `ParseFontFaceDescriptor`: Parsing descriptors within an `@font-face` rule.
    * `ParseLengthPercentage`: Parsing length or percentage values.
    * `ParseFont`: Parsing the shorthand `font` property.

3. **Categorize Functionality:** I'd group these methods into logical categories:
    * **General Parsing:** `ParseDeclarationList`, `ParseRule`, `ParseSheet`, `ParseValue`, `ParseSingleValue`.
    * **Selector Parsing:** `ParseSelector`, `ParsePageSelector`.
    * **At-Rule Specific Parsing:** `ParseNestedDeclarationsRule`, `ParseMarginRule`, `ParseKeyframeRule`, `ParseSupportsCondition`, `ParseFontFaceDescriptor`.
    * **Inline Styles:** `ParseInlineStyleDeclaration`.
    * **Value Parsing (Specific Types):** `ParseColor`, `ParseSystemColor`, `ParseLengthPercentage`, `ParseFont`, `ParseKeyframeKeyList`, `ParseCustomPropertyName`, `ParseValueForCustomProperty`.
    * **Inspector Support:**  Methods with `ForInspector` in their name.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **CSS:** This is the most direct relationship. The entire file is about parsing CSS syntax. Every function listed directly deals with interpreting CSS.
    * **HTML:**  `ParseInlineStyleDeclaration` is a key connection. When the browser encounters a `style` attribute in HTML, this function is used to interpret the CSS within it. Also, the parsing context can be tied to the document associated with the HTML.
    * **JavaScript:** The `@supports` rule parsing (`ParseSupportsCondition`) is directly related to the `CSS.supports()` JavaScript API. JavaScript can use this API to check if the browser supports certain CSS features. The Inspector-related functions are also used by DevTools, which often involves JavaScript interaction.

5. **Provide Examples:** For each relationship, I'd construct simple, clear examples:
    * **CSS:** A basic CSS rule like `p { color: red; }`.
    * **HTML:** An HTML element with a `style` attribute: `<div style="background-color: blue;">`.
    * **JavaScript:** Using `CSS.supports('display: grid')`.

6. **Consider Logic and Input/Output:**  While the code itself isn't presented as a series of if/else statements that are easy to trace for input/output, I can infer the basic logic:
    * **Input:** A string representing CSS syntax (declaration, selector, rule, sheet, value, etc.). Also, a `CSSParserContext` providing context (quirks mode, secure context, etc.).
    * **Processing:** Tokenization (breaking the string into meaningful units), parsing (building a structured representation of the CSS), and validation.
    * **Output:**  Data structures representing the parsed CSS, such as `MutableCSSPropertyValueSet`, `CSSSelectorList`, `StyleRuleBase`, `CSSValue`. Or a boolean indicating success/failure (`ParseSupportsCondition`, `ParseColor`).

7. **Identify Potential User/Programming Errors:**  Based on the function names and CSS syntax rules, I can infer common errors:
    * **Syntax Errors:** Incorrect property names, missing semicolons, invalid values.
    * **Type Mismatches:**  Providing a value of the wrong type for a property (e.g., a string where a number is expected).
    * **Case Sensitivity:** While CSS property names are generally case-insensitive, certain values might be case-sensitive.
    * **Vendor Prefixes:** Using outdated or incorrect vendor prefixes.
    * **Invalid Custom Property Names:**  Not starting with `--`.

8. **Explain User Steps to Reach the Code (Debugging Context):** I'd think about how the browser processes CSS:
    * **Loading External Stylesheets:**  The browser fetches `.css` files, and their content is parsed by `ParseSheet`.
    * **Parsing `<style>` Tags:** The content of `<style>` tags in HTML is also parsed using `ParseSheet`.
    * **Processing Inline Styles:**  As mentioned before, `ParseInlineStyleDeclaration` handles `style` attributes.
    * **JavaScript Interaction:**  When JavaScript manipulates the `style` property of an element or uses the CSS Object Model (CSSOM) APIs, the parser might be involved to interpret the new CSS.
    * **Developer Tools:**  When inspecting elements or editing styles in the browser's DevTools, the parsing functions are used to interpret the input and update the styles.

9. **Structure the Response:**  I would organize my findings logically, starting with the main functions, then relating them to other web technologies, providing examples, explaining the logic and potential errors, and finally describing the debugging context. Using headings and bullet points makes the information easier to read and understand.

By following these steps, I can comprehensively analyze the `css_parser.cc` file and address all the requirements of the prompt, even without having the full Chromium codebase available. The key is to leverage the information present in the file itself (function names, included headers) and my knowledge of web technologies and browser behavior.
This C++ source file, `css_parser.cc`, located within the Blink rendering engine of Chromium, is a central component responsible for **parsing CSS (Cascading Style Sheets)**. It acts as an entry point and orchestrator for various CSS parsing functionalities.

Here's a breakdown of its key functions:

**Core Functionalities:**

* **Parsing Declaration Lists:**
    * `ParseDeclarationList`: Parses a string containing a list of CSS declarations (property-value pairs) and populates a `MutableCSSPropertyValueSet`. This is fundamental for processing the content within CSS rules.
    * `ParseDeclarationListForInspector`: Similar to the above, but also notifies a `CSSParserObserver`, likely used by developer tools for tracking parsing events.
    * `ParseNestedDeclarationsRule`: Parses declarations within nested at-rules (like `@media`, `@supports`, etc.).

* **Parsing Selectors:**
    * `ParseSelector`:  Parses a CSS selector string and creates a `CSSSelector` object (or a list of them). This is crucial for determining which HTML elements a CSS rule applies to.
    * `ParsePageSelector`: Specifically parses selectors used within `@page` at-rules.

* **Parsing Rules:**
    * `ParseRule`: A general function for parsing various types of CSS rules (e.g., style rules, at-rules like `@media`, `@keyframes`, `@import`). It dispatches to more specific parsing logic based on the rule type.
    * `ParseMarginRule`:  Specifically parses rules within `@page` margin boxes.
    * `ParseKeyframeRule`: Parses rules within `@keyframes` at-rules.

* **Parsing Entire Stylesheets:**
    * `ParseSheet`: Parses an entire CSS stylesheet (a string containing multiple rules and declarations) and populates a `StyleSheetContents` object.
    * `ParseSheetForInspector`: Similar to `ParseSheet`, but also notifies a `CSSParserObserver`.

* **Parsing Property Values:**
    * `ParseValue`: Parses a string representing the value of a CSS property and sets it on a `MutableCSSPropertyValueSet`. This is a core function for interpreting the meaning of CSS declarations. It has several overloads to handle different contexts.
    * `ParseValueForCustomProperty`: Specifically parses values for CSS custom properties (variables).
    * `ParseSingleValue`: Parses a single CSS value for a given property ID.
    * `ParseFontFaceDescriptor`: Parses descriptors within an `@font-face` rule.
    * `ParseLengthPercentage`: Parses strings representing length or percentage values.

* **Parsing Inline Styles:**
    * `ParseInlineStyleDeclaration`: Parses the CSS found within the `style` attribute of an HTML element.

* **Parsing Keyframe Lists:**
    * `ParseKeyframeKeyList`: Parses the list of keyframe offsets (e.g., "0%", "50%", "to") in an `@keyframes` rule.

* **Parsing Custom Property Names:**
    * `ParseCustomPropertyName`: Parses the name of a CSS custom property (ensuring it starts with `--`).

* **Parsing `@supports` Conditions:**
    * `ParseSupportsCondition`: Parses the condition within a `@supports` at-rule, which is used for conditional CSS based on browser capabilities.

* **Parsing Colors:**
    * `ParseColor`: Parses a string representing a color value.
    * `ParseSystemColor`: Parses system color keywords.

* **Parsing the `font` Shorthand:**
    * `ParseFont`: Parses the complex `font` shorthand property.

**Relationship with JavaScript, HTML, and CSS:**

This file is **fundamentally about CSS**. It's the engine's way of understanding the styling rules written in CSS. However, it directly interacts with HTML and indirectly with JavaScript:

* **HTML:**
    * **Inline Styles:**  The `ParseInlineStyleDeclaration` function is directly invoked when the browser encounters a `style` attribute in HTML.
        * **Example:** When the HTML parser encounters `<div style="color: blue; font-size: 16px;">`, the string `"color: blue; font-size: 16px;"` is passed to `ParseInlineStyleDeclaration`. This function then uses other functions within `css_parser.cc` (like `ParseDeclarationList` and `ParseValue`) to interpret the CSS and apply the styles to the `div` element.
    * **`<style>` Tags and External Stylesheets:** When the browser parses a `<style>` tag or loads an external `.css` file, the content is passed to functions like `ParseSheet` to build the internal representation of the stylesheet.

* **JavaScript:**
    * **CSSOM (CSS Object Model):** JavaScript can interact with CSS through the CSSOM. When JavaScript modifies the `style` property of an element or manipulates CSS rules, the parsing logic in `css_parser.cc` might be involved to interpret the new CSS.
        * **Example:**  If JavaScript code executes `document.getElementById('myDiv').style.backgroundColor = 'red'`, the string `'red'` might be passed to `ParseValue` (or a similar function) to ensure it's a valid color value before applying the style.
    * **`CSS.supports()`:** The `ParseSupportsCondition` function is directly related to the `CSS.supports()` JavaScript API. This API allows JavaScript to check if the browser supports a specific CSS feature.
        * **Example:**  When JavaScript calls `CSS.supports('display: grid')`, the string `'display: grid'` (wrapped in parentheses internally) is passed to `ParseSupportsCondition` to determine if the browser understands the `grid` value for the `display` property.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `ParseValue` function with a simplified example:

**Hypothetical Input:**

* `declaration`: An empty `MutableCSSPropertyValueSet`.
* `unresolved_property`: `CSSPropertyID::kColor` (representing the `color` property).
* `string`: `"green"`.
* `important`: `false`.
* `context`: A valid `CSSParserContext`.

**Logical Reasoning:**

1. The `ParseValue` function is called with the property `color` and the value `"green"`.
2. It might first check for fast-path parsing for common values (though "green" might not have a specific fast path).
3. It would likely tokenize the string `"green"`.
4. It would then try to match the tokenized value to known color keywords or color functions.
5. Upon recognizing "green" as a valid color keyword, it would create a `CSSValue` representing the color green.
6. Finally, it would add this `CSSValue` to the `declaration` (the `MutableCSSPropertyValueSet`) associated with the `color` property.

**Hypothetical Output:**

The `declaration` `MutableCSSPropertyValueSet` would now contain a property-value pair: `color: green;`.

**User or Programming Common Usage Errors:**

* **Syntax Errors in CSS:**  Users might write invalid CSS syntax, leading to parsing errors.
    * **Example:**  Writing `color: rood;` instead of `color: red;` would cause a parsing error when `ParseValue` attempts to interpret `"rood"`.
* **Incorrect Property Names:** Using misspelled or non-existent CSS property names.
    * **Example:**  `backgroud-color: blue;` instead of `background-color: blue;` would likely result in the parser ignoring the declaration.
* **Providing Invalid Values:**  Using values that are not valid for a specific property.
    * **Example:**  `width: abc;` where a length or percentage is expected, would cause `ParseValue` to fail.
* **Missing Semicolons:** Forgetting to terminate declarations with semicolons (especially in inline styles).
    * **Example:** `<div style="color: blue font-size: 16px;">` would be parsed incorrectly because of the missing semicolon after `blue`.
* **Case Sensitivity (in some contexts):** While CSS property names are generally case-insensitive, certain values (like keywords or URLs) might be case-sensitive depending on the context.

**User Steps to Reach This Code (Debugging Clues):**

A user's actions that eventually lead to the execution of code within `css_parser.cc` are typically related to the browser rendering web pages:

1. **Opening a Web Page:** The most common way to trigger CSS parsing. When the browser loads an HTML page, it encounters `<link>` tags referencing external stylesheets or `<style>` tags containing inline CSS.
2. **Browser Fetches CSS Files:** If the HTML references external stylesheets, the browser makes requests to fetch those files.
3. **HTML Parser Encounters CSS:** The HTML parser identifies `<style>` tags and `style` attributes.
4. **CSS Tokenization:** The content of stylesheets and inline styles is first broken down into tokens by the CSS tokenizer.
5. **Calling CSS Parser Functions:** Based on the context (e.g., parsing a stylesheet, an inline style, a specific rule), the appropriate functions in `css_parser.cc` are called.
    * For external stylesheets or `<style>` tags: `CSSParser::ParseSheet` is a likely entry point.
    * For inline styles: `CSSParser::ParseInlineStyleDeclaration` is called.
    * For individual declarations within a rule: `CSSParser::ParseDeclarationList` and `CSSParser::ParseValue` are used.
    * For selectors: `CSSParser::ParseSelector` is used.
6. **JavaScript Manipulation of Styles:** If JavaScript code modifies the styling of elements (e.g., using `element.style.color = 'red'`), this can also trigger parsing functions within `css_parser.cc` to validate and apply the changes.
7. **Developer Tools Interaction:** When a developer uses the browser's developer tools to inspect elements, view and edit styles, the parsing logic in this file is actively used to interpret and update the CSS. Editing CSS in the "Styles" pane would directly involve these parsing functions.

**Debugging Clues:**

If you're debugging an issue related to CSS, and suspect `css_parser.cc` is involved, you might look for:

* **Error Messages in the Console:** The browser's developer console might show warnings or errors related to CSS parsing failures.
* **Incorrect Styling:** If elements are not styled as expected, it could indicate a problem during the parsing of the relevant CSS rules.
* **Performance Issues:**  Complex or poorly written CSS can lead to performance bottlenecks during parsing. Profiling tools might point to the CSS parsing stages.
* **Breakpoints in `css_parser.cc`:** Developers can set breakpoints in this file to step through the parsing process and understand how CSS is being interpreted.

In summary, `css_parser.cc` is a critical file in the Chromium Blink rendering engine that forms the foundation for understanding and applying CSS styles to web pages. It bridges the gap between the textual representation of CSS and the internal data structures used by the browser to render web content.

### 提示词
```
这是目录为blink/renderer/core/css/parser/css_parser.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/css/parser/css_parser.h"

#include <memory>

#include "third_party/blink/renderer/core/css/css_color.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_fast_paths.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_impl.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_token_stream.h"
#include "third_party/blink/renderer/core/css/parser/css_property_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_selector_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_supports_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_tokenizer.h"
#include "third_party/blink/renderer/core/css/parser/css_variable_parser.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/style_color.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"

namespace blink {

bool CSSParser::ParseDeclarationList(const CSSParserContext* context,
                                     MutableCSSPropertyValueSet* property_set,
                                     const String& declaration) {
  return CSSParserImpl::ParseDeclarationList(property_set, declaration,
                                             context);
}

StyleRuleBase* CSSParser::ParseNestedDeclarationsRule(
    const CSSParserContext* context,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    StringView text) {
  return CSSParserImpl::ParseNestedDeclarationsRule(
      context, nesting_type, parent_rule_for_nesting, is_within_scope, text);
}

void CSSParser::ParseDeclarationListForInspector(
    const CSSParserContext* context,
    const String& declaration,
    CSSParserObserver& observer) {
  CSSParserImpl::ParseDeclarationListForInspector(declaration, context,
                                                  observer);
}

base::span<CSSSelector> CSSParser::ParseSelector(
    const CSSParserContext* context,
    CSSNestingType nesting_type,
    StyleRule* parent_rule_for_nesting,
    bool is_within_scope,
    StyleSheetContents* style_sheet_contents,
    const String& selector,
    HeapVector<CSSSelector>& arena) {
  CSSParserTokenStream stream(selector);
  return CSSSelectorParser::ParseSelector(
      stream, context, nesting_type, parent_rule_for_nesting, is_within_scope,
      /* semicolon_aborts_nested_selector */ false, style_sheet_contents,
      arena);
}

CSSSelectorList* CSSParser::ParsePageSelector(
    const CSSParserContext& context,
    StyleSheetContents* style_sheet_contents,
    const String& selector) {
  CSSParserTokenStream stream(selector);
  CSSSelectorList* selector_list =
      CSSParserImpl::ParsePageSelector(stream, style_sheet_contents, context);
  if (!stream.AtEnd()) {
    // Extra tokens at end of selector.
    return nullptr;
  }
  return selector_list;
}

StyleRuleBase* CSSParser::ParseMarginRule(const CSSParserContext* context,
                                          StyleSheetContents* style_sheet,
                                          const String& rule) {
  return CSSParserImpl::ParseRule(rule, context, CSSNestingType::kNone,
                                  /*parent_rule_for_nesting=*/nullptr,
                                  /*is_within_scope=*/false, style_sheet,
                                  CSSParserImpl::kPageMarginRules);
}

StyleRuleBase* CSSParser::ParseRule(const CSSParserContext* context,
                                    StyleSheetContents* style_sheet,
                                    CSSNestingType nesting_type,
                                    StyleRule* parent_rule_for_nesting,
                                    bool is_within_scope,
                                    const String& rule) {
  return CSSParserImpl::ParseRule(
      rule, context, nesting_type, parent_rule_for_nesting, is_within_scope,
      style_sheet, CSSParserImpl::kAllowImportRules);
}

ParseSheetResult CSSParser::ParseSheet(
    const CSSParserContext* context,
    StyleSheetContents* style_sheet,
    const String& text,
    CSSDeferPropertyParsing defer_property_parsing,
    bool allow_import_rules) {
  return CSSParserImpl::ParseStyleSheet(
      text, context, style_sheet, defer_property_parsing, allow_import_rules);
}

void CSSParser::ParseSheetForInspector(const CSSParserContext* context,
                                       StyleSheetContents* style_sheet,
                                       const String& text,
                                       CSSParserObserver& observer) {
  return CSSParserImpl::ParseStyleSheetForInspector(text, context, style_sheet,
                                                    observer);
}

MutableCSSPropertyValueSet::SetResult CSSParser::ParseValue(
    MutableCSSPropertyValueSet* declaration,
    CSSPropertyID unresolved_property,
    StringView string,
    bool important,
    const ExecutionContext* execution_context) {
  return ParseValue(
      declaration, unresolved_property, string, important,
      execution_context ? execution_context->GetSecureContextMode()
                        : SecureContextMode::kInsecureContext,
      static_cast<StyleSheetContents*>(nullptr), execution_context);
}

static inline const CSSParserContext* GetParserContext(
    SecureContextMode secure_context_mode,
    StyleSheetContents* style_sheet,
    const ExecutionContext* execution_context,
    CSSParserMode parser_mode) {
  if (style_sheet) {
    if (style_sheet->ParserContext()->GetMode() == parser_mode) {
      // We can reuse this, to save on the construction.
      return style_sheet->ParserContext();
    } else {
      // This can happen when parsing e.g. SVG attributes in the context of
      // an HTML document.
      CSSParserContext* mutable_context =
          MakeGarbageCollected<CSSParserContext>(style_sheet->ParserContext());
      mutable_context->SetMode(parser_mode);
      return mutable_context;
    }
  } else if (IsA<LocalDOMWindow>(execution_context)) {
    // Create parser context using document if it exists so it can check for
    // origin trial enabled property/value.
    CSSParserContext* mutable_context = MakeGarbageCollected<CSSParserContext>(
        *To<LocalDOMWindow>(execution_context)->document());
    mutable_context->SetMode(parser_mode);
    return mutable_context;
  } else {
    return MakeGarbageCollected<CSSParserContext>(parser_mode,
                                                  secure_context_mode);
  }
}

MutableCSSPropertyValueSet::SetResult CSSParser::ParseValue(
    MutableCSSPropertyValueSet* declaration,
    CSSPropertyID unresolved_property,
    StringView string,
    bool important,
    SecureContextMode secure_context_mode,
    StyleSheetContents* style_sheet,
    const ExecutionContext* execution_context) {
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  if (string.empty()) {
    return MutableCSSPropertyValueSet::kParseError;
  }

  CSSPropertyID resolved_property = ResolveCSSPropertyID(unresolved_property);
  CSSParserMode parser_mode = declaration->CssParserMode();
  const CSSParserContext* context = GetParserContext(
      secure_context_mode, style_sheet, execution_context, parser_mode);

  // See if this property has a specific fast-path parser.
  const CSSValue* value =
      CSSParserFastPaths::MaybeParseValue(resolved_property, string, context);
  if (value) {
    return declaration->SetLonghandProperty(CSSPropertyValue(
        CSSPropertyName(resolved_property), *value, important));
  }

  // OK, that didn't work (either the property doesn't have a fast path,
  // or the string is on some form that the fast-path parser doesn't support,
  // e.g. a parse error). See if the value we are looking for is a longhand;
  // if so, we can use a faster parsing function. In particular, we don't need
  // to set up a vector for the results, since there will be only one.
  //
  // We only allow this path in standards mode, which rules out situations
  // like @font-face parsing etc. (which have their own rules).
  const CSSProperty& property = CSSProperty::Get(resolved_property);
  if (parser_mode == kHTMLStandardMode && property.IsProperty() &&
      !property.IsShorthand()) {
    CSSParserTokenStream stream(string);
    value =
        CSSPropertyParser::ParseSingleValue(resolved_property, stream, context);
    if (value != nullptr) {
      return declaration->SetLonghandProperty(CSSPropertyValue(
          CSSPropertyName(resolved_property), *value, important));
    }
  }

  // OK, that didn't work either, so we'll need the full-blown parser.
  return ParseValue(declaration, unresolved_property, string, important,
                    context);
}

MutableCSSPropertyValueSet::SetResult CSSParser::ParseValueForCustomProperty(
    MutableCSSPropertyValueSet* declaration,
    const AtomicString& property_name,
    StringView value,
    bool important,
    SecureContextMode secure_context_mode,
    StyleSheetContents* style_sheet,
    bool is_animation_tainted) {
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  DCHECK(CSSVariableParser::IsValidVariableName(property_name));
  if (value.empty()) {
    return MutableCSSPropertyValueSet::kParseError;
  }
  CSSParserMode parser_mode = declaration->CssParserMode();
  CSSParserContext* context;
  if (style_sheet) {
    context =
        MakeGarbageCollected<CSSParserContext>(style_sheet->ParserContext());
    context->SetMode(parser_mode);
  } else {
    context = MakeGarbageCollected<CSSParserContext>(parser_mode,
                                                     secure_context_mode);
  }
  return CSSParserImpl::ParseVariableValue(declaration, property_name, value,
                                           important, context,
                                           is_animation_tainted);
}

MutableCSSPropertyValueSet::SetResult CSSParser::ParseValue(
    MutableCSSPropertyValueSet* declaration,
    CSSPropertyID unresolved_property,
    StringView string,
    bool important,
    const CSSParserContext* context) {
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  return CSSParserImpl::ParseValue(declaration, unresolved_property, string,
                                   important, context);
}

const CSSValue* CSSParser::ParseSingleValue(CSSPropertyID property_id,
                                            const String& string,
                                            const CSSParserContext* context) {
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  if (string.empty()) {
    return nullptr;
  }
  if (CSSValue* value =
          CSSParserFastPaths::MaybeParseValue(property_id, string, context)) {
    return value;
  }
  CSSParserTokenStream stream(string);
  return CSSPropertyParser::ParseSingleValue(property_id, stream, context);
}

ImmutableCSSPropertyValueSet* CSSParser::ParseInlineStyleDeclaration(
    const String& style_string,
    Element* element) {
  return CSSParserImpl::ParseInlineStyleDeclaration(style_string, element);
}

ImmutableCSSPropertyValueSet* CSSParser::ParseInlineStyleDeclaration(
    const String& style_string,
    CSSParserMode parser_mode,
    SecureContextMode secure_context_mode,
    const Document* document) {
  return CSSParserImpl::ParseInlineStyleDeclaration(
      style_string, parser_mode, secure_context_mode, document);
}

std::unique_ptr<Vector<KeyframeOffset>> CSSParser::ParseKeyframeKeyList(
    const CSSParserContext* context,
    const String& key_list) {
  return CSSParserImpl::ParseKeyframeKeyList(context, key_list);
}

StyleRuleKeyframe* CSSParser::ParseKeyframeRule(const CSSParserContext* context,
                                                const String& rule) {
  StyleRuleBase* keyframe = CSSParserImpl::ParseRule(
      rule, context, CSSNestingType::kNone, /*parent_rule_for_nesting=*/nullptr,
      /*is_within_scope=*/false, nullptr, CSSParserImpl::kKeyframeRules);
  return To<StyleRuleKeyframe>(keyframe);
}

String CSSParser::ParseCustomPropertyName(const String& name_text) {
  return CSSParserImpl::ParseCustomPropertyName(name_text);
}

bool CSSParser::ParseSupportsCondition(
    const String& condition,
    const ExecutionContext* execution_context) {
  // window.CSS.supports requires to parse as-if it was wrapped in parenthesis.
  String wrapped_condition = "(" + condition + ")";
  CSSParserTokenStream stream(wrapped_condition);
  DCHECK(execution_context);
  // Create parser context using document so it can check for origin trial
  // enabled property/value.
  CSSParserContext* context = MakeGarbageCollected<CSSParserContext>(
      *To<LocalDOMWindow>(execution_context)->document());
  // Override the parser mode interpreted from the document as the spec
  // https://quirks.spec.whatwg.org/#css requires quirky values and colors
  // must not be supported in CSS.supports() method.
  context->SetMode(kHTMLStandardMode);
  CSSParserImpl parser(context);
  CSSSupportsParser::Result result =
      CSSSupportsParser::ConsumeSupportsCondition(stream, parser);
  if (!stream.AtEnd()) {
    result = CSSSupportsParser::Result::kParseFailure;
  }

  return result == CSSSupportsParser::Result::kSupported;
}

bool CSSParser::ParseColor(Color& color, const String& string, bool strict) {
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  if (string.empty()) {
    return false;
  }

  // The regular color parsers don't resolve named colors, so explicitly
  // handle these first.
  Color named_color;
  if (named_color.SetNamedColor(string)) {
    color = named_color;
    return true;
  }

  switch (CSSParserFastPaths::ParseColor(
      string, strict ? kHTMLStandardMode : kHTMLQuirksMode, color)) {
    case ParseColorResult::kFailure:
      break;
    case ParseColorResult::kKeyword:
      return false;
    case ParseColorResult::kColor:
      return true;
  }

  // TODO(timloh): Why is this always strict mode?
  // NOTE(ikilpatrick): We will always parse color value in the insecure
  // context mode. If a function/unit/etc will require a secure context check
  // in the future, plumbing will need to be added.
  const CSSValue* value = ParseSingleValue(
      CSSPropertyID::kColor, string,
      StrictCSSParserContext(SecureContextMode::kInsecureContext));
  auto* color_value = DynamicTo<cssvalue::CSSColor>(value);
  if (!color_value) {
    return false;
  }

  color = color_value->Value();
  return true;
}

bool CSSParser::ParseSystemColor(Color& color,
                                 const String& color_string,
                                 mojom::blink::ColorScheme color_scheme,
                                 const ui::ColorProvider* color_provider,
                                 bool is_in_web_app_scope) {
  CSSValueID id = CssValueKeywordID(color_string);
  if (!StyleColor::IsSystemColorIncludingDeprecated(id)) {
    return false;
  }

  color = LayoutTheme::GetTheme().SystemColor(id, color_scheme, color_provider,
                                              is_in_web_app_scope);
  return true;
}

const CSSValue* CSSParser::ParseFontFaceDescriptor(
    CSSPropertyID property_id,
    const String& property_value,
    const CSSParserContext* context) {
  auto* style =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kCSSFontFaceRuleMode);
  CSSParser::ParseValue(style, property_id, property_value, true, context);
  const CSSValue* value = style->GetPropertyCSSValue(property_id);

  return value;
}

CSSPrimitiveValue* CSSParser::ParseLengthPercentage(
    const String& string,
    const CSSParserContext* context,
    CSSPrimitiveValue::ValueRange value_range) {
  if (string.empty() || !context) {
    return nullptr;
  }
  CSSParserTokenStream stream(string);
  // Trim whitespace from the string. It's only necessary to consume leading
  // whitespaces, since ConsumeLengthOrPercent always consumes trailing ones.
  stream.ConsumeWhitespace();
  CSSPrimitiveValue* parsed_value =
      css_parsing_utils::ConsumeLengthOrPercent(stream, *context, value_range);
  return stream.AtEnd() ? parsed_value : nullptr;
}

MutableCSSPropertyValueSet* CSSParser::ParseFont(
    const String& string,
    const ExecutionContext* execution_context) {
  DCHECK(ThreadState::Current()->IsAllocationAllowed());
  auto* set =
      MakeGarbageCollected<MutableCSSPropertyValueSet>(kHTMLStandardMode);
  ParseValue(set, CSSPropertyID::kFont, string, true /* important */,
             execution_context);
  if (set->IsEmpty()) {
    return nullptr;
  }
  const CSSValue* font_size =
      set->GetPropertyCSSValue(CSSPropertyID::kFontSize);
  if (!font_size || font_size->IsCSSWideKeyword()) {
    return nullptr;
  }
  if (font_size->IsPendingSubstitutionValue()) {
    return nullptr;
  }
  return set;
}

}  // namespace blink
```