Response:
The user is asking for a summary of the functionality of the `inspector_style_sheet.cc` file in the Chromium Blink engine, based on the provided source code snippet.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The filename itself, "inspector_style_sheet.cc", strongly suggests that this file is responsible for handling CSS stylesheets within the context of the browser's developer tools (Inspector).

2. **Scan for key data structures and classes:**  Look for classes and data structures defined or used in the code that are related to CSS and the Inspector. The presence of classes like `InspectorStyleSheetBase`, `InspectorStyle`, `CSSStyleRule`, `CSSStyleSheet`, `CSSRuleSourceDataList`, and `protocol::CSS::*`  confirms the initial hypothesis.

3. **Analyze included headers:**  The included headers provide valuable context about the file's dependencies and interactions with other parts of the Blink engine. Headers related to CSS parsing (`css_parser.h`, `css_parser_local_context.h`, `css_parser_observer.h`), CSS rules (`css_style_rule.h`, `css_media_rule.h`, etc.), DOM (`document.h`, `element.h`), and the Inspector protocol (`protocol/css.h`, `inspector_css_agent.h`) are particularly relevant.

4. **Examine key functions and their logic:** Look at the functions defined in the provided snippet. Functions like `BuildSourceRangeObject`, `BuildObjectForStyle`, `StyleText`, `TextForRange`, `PopulateAllProperties`, `StyleWithProperties`, and the `Verify...` functions offer insights into the file's operations.

5. **Identify connections to web technologies (JavaScript, HTML, CSS):**  The file heavily deals with CSS concepts like rules, selectors, properties, and stylesheets. It's also part of the Inspector, which interacts with the browser's rendering engine and provides information about the HTML structure and applied styles. The presence of `protocol::CSS::*`  clearly indicates communication with the frontend (likely JavaScript-based) through the DevTools protocol.

6. **Look for error handling and validation:** The `Verify...` functions strongly suggest a role in validating CSS syntax and structure. This is crucial for providing accurate information and debugging capabilities in the Inspector.

7. **Infer logical reasoning:** The `Verify...` functions take CSS snippets as input and return boolean values indicating whether the snippets are valid according to the CSS parser. This demonstrates a form of logical reasoning or validation.

8. **Consider potential user errors:** If the code validates CSS, then a common user error would be providing invalid CSS syntax.

9. **Synthesize the findings:** Based on the above analysis, formulate a concise summary of the file's functions.

10. **Structure the answer:** Organize the information into logical sections addressing each part of the user's request (general functionality, relation to web technologies, logical reasoning, user errors, and overall summary). Use clear and understandable language.

**Self-Correction/Refinement during the process:**

* Initially, I might focus too much on specific data structures. Realizing that the user wants a functional overview, I would shift the focus to the actions performed by the file.
* The presence of `Verify...` functions is a strong indicator of validation. I would ensure to highlight this aspect and connect it to potential user errors.
*  The connection to the Inspector is paramount. Emphasize that this file is about *inspecting* and *representing* CSS, not necessarily *applying* it (though it interacts with the components that do).
*  The use of the DevTools protocol (`protocol::CSS::*`) is a critical point that links the backend (Blink) with the frontend (DevTools UI).

By following these steps, I can create a comprehensive and accurate summary of the `inspector_style_sheet.cc` file's functionality.
基于提供的部分代码，我们可以归纳出 `blink/renderer/core/inspector/inspector_style_sheet.cc` 文件的一些核心功能：

**核心功能归纳：**

1. **表示和管理 CSS 样式表信息，用于开发者工具 (Inspector)：**  该文件中的类和函数主要负责从 Blink 引擎内部的 CSS 样式表对象中提取信息，并将其转换为 Inspector 前端可以理解和展示的数据格式（通常是基于 Chrome DevTools Protocol 的）。

2. **提供 CSS 规则和属性的详细信息：**  它能够解析和表示各种 CSS 规则（例如，样式规则、媒体查询、@keyframes、@supports 等）以及规则中的属性，包括属性名、值、重要性、是否被禁用等。

3. **支持 CSS 源代码映射和位置信息：**  该文件能够记录 CSS 规则和属性在源文件中的位置（行号、列号），使得 Inspector 能够将用户在界面上的操作（例如，编辑样式）映射回源代码。

4. **提供 CSS 编辑和验证的基础设施：**  代码中包含了一些 `Verify...` 函数，这些函数用于验证用户输入的 CSS 代码片段（例如，属性值、选择器、媒体查询等）是否有效。这为 Inspector 提供实时的 CSS 编辑和错误提示功能提供了基础。

**与 JavaScript, HTML, CSS 的关系：**

* **CSS:**  这是该文件直接操作的对象。它负责解析、提取和表示 CSS 样式表的结构和内容。例如：
    *  读取 `CSSStyleRule` 对象，提取选择器和声明块。
    *  读取 `CSSMediaRule` 对象，提取媒体查询条件和包含的样式规则。
    *  读取 `CSSPropertySourceData` 对象，提取属性名、值、范围等。

* **HTML:**  该文件间接地与 HTML 相关联。CSS 样式最终会被应用到 HTML 元素上。Inspector 通过这个文件展示应用于特定 HTML 元素的样式信息。例如：
    *  通过 `Document` 对象获取 CSS 样式表。
    *  在 `InspectorStyle::BuildObjectForStyle` 函数中，可能需要 `Element` 对象来获取计算后的样式信息，以处理 `var()` 函数等。

* **JavaScript:**  Inspector 的前端通常使用 JavaScript 开发。这个 `.cc` 文件中的代码负责生成可以被 Inspector 前端 JavaScript 代码消费的数据结构。例如：
    *  使用 `protocol::CSS::*` 命名空间下的类来构建符合 Chrome DevTools Protocol 的 JSON 对象，这些对象会被发送到前端。
    *  `InspectorStyle::StyleWithProperties` 函数构建 `protocol::CSS::CSSStyle` 对象，其中包含了属性信息。

**逻辑推理示例：**

假设输入一个 CSS 样式规则的字符串："`.my-class { color: red; font-size: 16px; }`"

**假设输入：**  一个包含上述 CSS 规则的字符串。

**可能进行的逻辑推理：**

1. **解析规则:**  使用 CSS 解析器将字符串解析成 `CSSStyleRule` 对象。
2. **提取选择器:** 从 `CSSStyleRule` 对象中提取选择器 `.my-class`。
3. **提取属性:** 遍历 `CSSStyleRule` 的声明块，提取 `color: red;` 和 `font-size: 16px;` 这两个属性及其值。
4. **构建 Inspector 数据:**  创建 `protocol::CSS::CSSStyle` 对象，并为每个属性创建 `protocol::CSS::CSSProperty` 对象，设置其 `name` 为 "color" 和 "font-size"，`value` 分别为 "red" 和 "16px"。
5. **输出:**  返回构建好的 `protocol::CSS::CSSStyle` 对象，它可以被序列化成 JSON 数据发送到 Inspector 前端。

**涉及的用户或编程常见的使用错误示例：**

* **输入无效的 CSS 语法：**  例如，`VerifyStyleText` 函数会验证用户输入的属性值是否有效。如果用户输入 `color: re;` (拼写错误)，该函数可能会返回 `false`。Inspector 前端可以根据这个结果提示用户语法错误。
    * **假设输入 (给 `VerifyStyleText`):** `"re;"`
    * **预期输出:** `false`

* **尝试编辑只读的样式表：**  某些样式表（例如，浏览器默认样式）可能是只读的。如果用户尝试在 Inspector 中编辑这些样式表，相关的功能可能会拒绝操作，因为底层的 `CSSStyleSheet` 对象不允许修改。虽然这段代码本身没有直接处理编辑逻辑，但它负责提供样式表的信息，这间接影响了编辑功能。

**总结（针对第 1 部分）：**

这部分 `inspector_style_sheet.cc` 文件的主要功能是 **作为 Blink 引擎和 Inspector 之间关于 CSS 样式表信息的桥梁**。它负责从 Blink 内部的 CSS 对象中提取数据，并将其转换为 Inspector 前端可以理解的格式。同时，它也提供了一些基础的 CSS 验证功能，为 Inspector 的实时编辑和错误提示提供了支持。

### 提示词
```
这是目录为blink/renderer/core/inspector/inspector_style_sheet.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE INC. AND ITS CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE INC. OR ITS CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "third_party/blink/renderer/core/inspector/inspector_style_sheet.h"

#include <algorithm>
#include <memory>

#include "third_party/blink/renderer/core/css/css_container_rule.h"
#include "third_party/blink/renderer/core/css/css_font_palette_values_rule.h"
#include "third_party/blink/renderer/core/css/css_grouping_rule.h"
#include "third_party/blink/renderer/core/css/css_import_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframe_rule.h"
#include "third_party/blink/renderer/core/css/css_keyframes_rule.h"
#include "third_party/blink/renderer/core/css/css_layer_block_rule.h"
#include "third_party/blink/renderer/core/css/css_media_rule.h"
#include "third_party/blink/renderer/core/css/css_nested_declarations_rule.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/css/css_property_rule.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_rule_list.h"
#include "third_party/blink/renderer/core/css/css_scope_rule.h"
#include "third_party/blink/renderer/core/css/css_style_rule.h"
#include "third_party/blink/renderer/core/css/css_style_sheet.h"
#include "third_party/blink/renderer/core/css/css_supports_rule.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_local_context.h"
#include "third_party/blink/renderer/core/css/parser/css_parser_observer.h"
#include "third_party/blink/renderer/core/css/properties/css_parsing_utils.h"
#include "third_party/blink/renderer/core/css/properties/longhands/custom_property.h"
#include "third_party/blink/renderer/core/css/properties/shorthand.h"
#include "third_party/blink/renderer/core/css/property_registry.h"
#include "third_party/blink/renderer/core/css/resolver/style_cascade.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/css/style_sheet_contents.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_css_parser_observer.h"
#include "third_party/blink/renderer/core/inspector/inspector_network_agent.h"
#include "third_party/blink/renderer/core/inspector/inspector_resource_container.h"
#include "third_party/blink/renderer/core/inspector/inspector_style_resolver.h"
#include "third_party/blink/renderer/core/inspector/protocol/css.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/wtf/allocator/allocator.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/text_position.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

using blink::protocol::Array;

namespace blink {

namespace {

static const CSSParserContext* ParserContextForDocument(
    const Document* document) {
  // Fallback to an insecure context parser if no document is present.
  return document ? MakeGarbageCollected<CSSParserContext>(*document)
                  : StrictCSSParserContext(SecureContextMode::kInsecureContext);
}

String FindMagicComment(const String& content, const String& name) {
  DCHECK(name.Find("=") == kNotFound);

  wtf_size_t length = content.length();
  wtf_size_t name_length = name.length();
  const bool kMultiline = true;

  wtf_size_t pos = length;
  wtf_size_t equal_sign_pos = 0;
  wtf_size_t closing_comment_pos = 0;
  while (true) {
    pos = content.ReverseFind(name, pos);
    if (pos == kNotFound)
      return g_empty_string;

    // Check for a /\/[\/*][@#][ \t]/ regexp (length of 4) before found name.
    if (pos < 4)
      return g_empty_string;
    pos -= 4;
    if (content[pos] != '/')
      continue;
    if ((content[pos + 1] != '/' || kMultiline) &&
        (content[pos + 1] != '*' || !kMultiline))
      continue;
    if (content[pos + 2] != '#' && content[pos + 2] != '@')
      continue;
    if (content[pos + 3] != ' ' && content[pos + 3] != '\t')
      continue;
    equal_sign_pos = pos + 4 + name_length;
    if (equal_sign_pos < length && content[equal_sign_pos] != '=')
      continue;
    if (kMultiline) {
      closing_comment_pos = content.Find("*/", equal_sign_pos + 1);
      if (closing_comment_pos == kNotFound)
        return g_empty_string;
    }

    break;
  }

  DCHECK(equal_sign_pos);
  DCHECK(!kMultiline || closing_comment_pos);
  wtf_size_t url_pos = equal_sign_pos + 1;
  String match = kMultiline
                     ? content.Substring(url_pos, closing_comment_pos - url_pos)
                     : content.Substring(url_pos);

  wtf_size_t new_line = match.Find("\n");
  if (new_line != kNotFound)
    match = match.Substring(0, new_line);
  match = match.StripWhiteSpace();

  String disallowed_chars("\"' \t");
  for (uint32_t i = 0; i < match.length(); ++i) {
    if (disallowed_chars.find(match[i]) != kNotFound)
      return g_empty_string;
  }

  return match;
}

void GetClassNamesFromRule(CSSStyleRule* rule, HashSet<String>& unique_names) {
  for (const CSSSelector* sub_selector = rule->GetStyleRule()->FirstSelector();
       sub_selector; sub_selector = CSSSelectorList::Next(*sub_selector)) {
    const CSSSelector* simple_selector = sub_selector;
    while (simple_selector) {
      if (simple_selector->Match() == CSSSelector::kClass)
        unique_names.insert(simple_selector->Value());
      simple_selector = simple_selector->NextSimpleSelector();
    }
  }
}

bool VerifyRuleText(Document* document, const String& rule_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text = rule_text + " div { " + bogus_property_name + ": none; }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);
  unsigned rule_count = source_data->size();

  // Exactly two rules should be parsed.
  if (rule_count != 2)
    return false;

  // Added rule must be style rule.
  if (!source_data->at(0)->HasProperties())
    return false;

  Vector<CSSPropertySourceData>& property_data =
      source_data->at(1)->property_data;
  unsigned property_count = property_data.size();

  // Exactly one property should be in rule.
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

bool VerifyStyleText(Document* document,
                     const String& text,
                     StyleRule::RuleType rule_type = StyleRule::kStyle) {
  if (rule_type == StyleRule::kProperty) {
    return VerifyRuleText(document, "@property --property {" + text + "}");
  }
  return VerifyRuleText(document, "div {" + text + "}");
}

bool VerifyNestedDeclarations(Document* document, const String& rule_text) {
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text = ".a { .b {} " + rule_text + " }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kStyle) {
    return false;
  }
  const CSSRuleSourceData& rule_data = *source_data->front();
  if (rule_data.child_rules.size() != 2) {
    return false;
  }
  // It is not allowed to create a CSSNestedDeclarations rule without
  // any valid properties.
  // TODO(crbug.com/363985597): List this restriction.
  auto is_valid = [](const CSSPropertySourceData& data) {
    return data.parsed_ok && !data.disabled;
  };
  if (!base::ranges::any_of(rule_data.child_rules[1]->property_data,
                            is_valid)) {
    return false;
  }
  return true;
}

bool VerifyPropertyNameText(Document* document, const String& name_text) {
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text =
      "@property " + name_text + " { syntax: \"*\"; inherits: false; }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kProperty)
    return false;

  const CSSRuleSourceData& property_data = *source_data->at(0);
  if (property_data.property_data.size() != 2)
    return false;

  return true;
}

bool VerifyKeyframeKeyText(Document* document, const String& key_text) {
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text = "@keyframes boguzAnim { " + key_text +
                " { -webkit-boguz-propertee : none; } }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  // Exactly one should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kKeyframes)
    return false;

  const CSSRuleSourceData& keyframe_data = *source_data->at(0);
  if (keyframe_data.child_rules.size() != 1 ||
      keyframe_data.child_rules.at(0)->type != StyleRule::kKeyframe)
    return false;

  // Exactly one property should be in keyframe rule.
  const unsigned property_count =
      keyframe_data.child_rules.at(0)->property_data.size();
  if (property_count != 1)
    return false;

  return true;
}

bool VerifySelectorText(Document* document, const String& selector_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text = selector_text + " { " + bogus_property_name + ": none; }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  // Exactly one rule should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kStyle)
    return false;

  // Exactly one property should be in style rule.
  Vector<CSSPropertySourceData>& property_data =
      source_data->at(0)->property_data;
  unsigned property_count = property_data.size();
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

bool VerifyMediaText(Document* document, const String& media_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text = "@media " + media_text + " { div { " + bogus_property_name +
                ": none; } }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  // Exactly one media rule should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kMedia)
    return false;

  // Media rule should have exactly one style rule child.
  CSSRuleSourceDataList& child_source_data = source_data->at(0)->child_rules;
  rule_count = child_source_data.size();
  if (rule_count != 1 || !child_source_data.at(0)->HasProperties())
    return false;

  // Exactly one property should be in style rule.
  Vector<CSSPropertySourceData>& property_data =
      child_source_data.at(0)->property_data;
  unsigned property_count = property_data.size();
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

bool VerifyContainerQueryText(Document* document,
                              const String& container_query_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text = "@container " + container_query_text + " { div { " +
                bogus_property_name + ": none; } }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  // TODO(crbug.com/1146422): for now these checks are identical to
  // those for media queries. We should enforce container-query-specific
  // checks once the spec is finalized.
  // Exactly one container rule should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kContainer)
    return false;

  // Container rule should have exactly one style rule child.
  CSSRuleSourceDataList& child_source_data = source_data->at(0)->child_rules;
  rule_count = child_source_data.size();
  if (rule_count != 1 || !child_source_data.at(0)->HasProperties())
    return false;

  // Exactly one property should be in style rule.
  Vector<CSSPropertySourceData>& property_data =
      child_source_data.at(0)->property_data;
  unsigned property_count = property_data.size();
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

bool VerifySupportsText(Document* document, const String& supports_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text = "@supports " + supports_text + " { div { " +
                bogus_property_name + ": none; } }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  // Exactly one supports rule should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kSupports)
    return false;

  // Supports rule should have exactly one style rule child.
  CSSRuleSourceDataList& child_source_data = source_data->at(0)->child_rules;
  rule_count = child_source_data.size();
  if (rule_count != 1 || !child_source_data.at(0)->HasProperties())
    return false;

  // Exactly one property should be in style rule.
  Vector<CSSPropertySourceData>& property_data =
      child_source_data.at(0)->property_data;
  unsigned property_count = property_data.size();
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

bool VerifyScopeText(Document* document, const String& scope_text) {
  DEFINE_STATIC_LOCAL(String, bogus_property_name, ("-webkit-boguz-propertee"));
  auto* style_sheet = MakeGarbageCollected<StyleSheetContents>(
      ParserContextForDocument(document));
  CSSRuleSourceDataList* source_data =
      MakeGarbageCollected<CSSRuleSourceDataList>();
  String text =
      "@scope " + scope_text + " { " + bogus_property_name + ": none; }";
  InspectorCSSParserObserver observer(text, document, source_data);
  CSSParser::ParseSheetForInspector(ParserContextForDocument(document),
                                    style_sheet, text, observer);

  // Exactly one scope rule should be parsed.
  unsigned rule_count = source_data->size();
  if (rule_count != 1 || source_data->at(0)->type != StyleRule::kScope)
    return false;

  // Scope rule should have exactly one CSSNestedDeclarationsRule child.
  CSSRuleSourceDataList& child_source_data = source_data->at(0)->child_rules;
  rule_count = child_source_data.size();
  if (rule_count != 1 || !child_source_data.at(0)->HasProperties())
    return false;

  // Exactly one property should be in the CSSNestedDeclarationsRule.
  Vector<CSSPropertySourceData>& property_data =
      child_source_data.at(0)->property_data;
  unsigned property_count = property_data.size();
  if (property_count != 1)
    return false;

  // Check for the property name.
  if (property_data.at(0).name != bogus_property_name)
    return false;

  return true;
}

void FlattenSourceData(const CSSRuleSourceDataList& data_list,
                       CSSRuleSourceDataList* result) {
  for (CSSRuleSourceData* data : data_list) {
    // The result->append()'ed types should be exactly the same as in
    // collectFlatRules().
    switch (data->type) {
      case StyleRule::kImport:
      case StyleRule::kFontFace:
      case StyleRule::kKeyframe:
      case StyleRule::kFontFeature:
      case StyleRule::kPositionTry:
      case StyleRule::kViewTransition:
      case StyleRule::kFontPaletteValues:
        result->push_back(data);
        break;
      case StyleRule::kStyle:
      case StyleRule::kMedia:
      case StyleRule::kScope:
      case StyleRule::kSupports:
      case StyleRule::kKeyframes:
      case StyleRule::kContainer:
      case StyleRule::kLayerBlock:
      case StyleRule::kFontFeatureValues:
      case StyleRule::kProperty:
      case StyleRule::kStartingStyle:
        result->push_back(data);
        FlattenSourceData(data->child_rules, result);
        break;
      default:
        break;
    }
  }
}

CSSRuleList* AsCSSRuleList(CSSRule* rule) {
  if (!rule)
    return nullptr;

  if (auto* style_rule = DynamicTo<CSSStyleRule>(rule)) {
    return style_rule->cssRules();
  }

  if (auto* media_rule = DynamicTo<CSSMediaRule>(rule))
    return media_rule->cssRules();

  if (auto* starting_style_rule = DynamicTo<CSSStartingStyleRule>(rule)) {
    return starting_style_rule->cssRules();
  }

  if (auto* scope_rule = DynamicTo<CSSScopeRule>(rule))
    return scope_rule->cssRules();

  if (auto* supports_rule = DynamicTo<CSSSupportsRule>(rule))
    return supports_rule->cssRules();

  if (auto* keyframes_rule = DynamicTo<CSSKeyframesRule>(rule))
    return keyframes_rule->cssRules();

  if (auto* container_rule = DynamicTo<CSSContainerRule>(rule))
    return container_rule->cssRules();

  if (auto* layer_rule = DynamicTo<CSSLayerBlockRule>(rule))
    return layer_rule->cssRules();

  if (auto* property_rule = DynamicTo<CSSPropertyRule>(rule))
    return property_rule->cssRules();

  if (auto* font_palette_values_rule =
          DynamicTo<CSSFontPaletteValuesRule>(rule))
    return font_palette_values_rule->cssRules();

  return nullptr;
}

template <typename RuleList>
void CollectFlatRules(RuleList rule_list, CSSRuleVector* result) {
  if (!rule_list)
    return;

  for (unsigned i = 0, size = rule_list->length(); i < size; ++i) {
    CSSRule* rule = rule_list->ItemInternal(i);

    // The result->append()'ed types should be exactly the same as in
    // flattenSourceData().
    switch (rule->GetType()) {
      case CSSRule::kImportRule:
      case CSSRule::kFontFaceRule:
      case CSSRule::kKeyframeRule:
      case CSSRule::kFontFeatureRule:
      case CSSRule::kPositionTryRule:
      case CSSRule::kViewTransitionRule:
      case CSSRule::kFontPaletteValuesRule:
        result->push_back(rule);
        break;
      case CSSRule::kStyleRule:
      case CSSRule::kMediaRule:
      case CSSRule::kScopeRule:
      case CSSRule::kSupportsRule:
      case CSSRule::kKeyframesRule:
      case CSSRule::kContainerRule:
      case CSSRule::kLayerBlockRule:
      case CSSRule::kFontFeatureValuesRule:
      case CSSRule::kPropertyRule:
      case CSSRule::kStartingStyleRule:
        result->push_back(rule);
        CollectFlatRules(AsCSSRuleList(rule), result);
        break;
      case CSSRule::kNestedDeclarationsRule:
        result->push_back(
            To<CSSNestedDeclarationsRule>(*rule).InnerCSSStyleRule());
        break;
      default:
        break;
    }
  }
}

// Warning: it does not always produce valid CSS.
// Use the rule's cssText method if you need to expose CSS externally.
String CanonicalCSSText(CSSRule* rule) {
  auto* style_rule = DynamicTo<CSSStyleRule>(rule);
  if (!style_rule)
    return rule->cssText();

  Vector<std::pair<unsigned, String>> properties;
  CSSStyleDeclaration* style = style_rule->style();
  for (unsigned i = 0; i < style->length(); ++i)
    properties.emplace_back(i, style->item(i));

  std::sort(properties.begin(), properties.end(),
            [](const auto& a, const auto& b) -> bool {
              return WTF::CodeUnitCompareLessThan(a.second, b.second);
            });

  StringBuilder builder;
  builder.Append(style_rule->selectorText());
  builder.Append('{');
  for (const auto& [index, name] : properties) {
    builder.Append(' ');
    builder.Append(name);
    builder.Append(':');
    builder.Append(style->GetPropertyValueWithHint(name, index));
    String priority = style->GetPropertyPriorityWithHint(name, index);
    if (!priority.empty()) {
      builder.Append(' ');
      builder.Append(priority);
    }
    builder.Append(';');
  }
  builder.Append('}');

  return builder.ToString();
}

}  // namespace

enum MediaListSource {
  kMediaListSourceLinkedSheet,
  kMediaListSourceInlineSheet,
  kMediaListSourceMediaRule,
  kMediaListSourceImportRule
};

std::unique_ptr<protocol::CSS::SourceRange>
InspectorStyleSheetBase::BuildSourceRangeObject(const SourceRange& range) {
  const LineEndings* line_endings = GetLineEndings();
  if (!line_endings)
    return nullptr;
  TextPosition start =
      TextPosition::FromOffsetAndLineEndings(range.start, *line_endings);
  TextPosition end =
      TextPosition::FromOffsetAndLineEndings(range.end, *line_endings);

  std::unique_ptr<protocol::CSS::SourceRange> result =
      protocol::CSS::SourceRange::create()
          .setStartLine(start.line_.ZeroBasedInt())
          .setStartColumn(start.column_.ZeroBasedInt())
          .setEndLine(end.line_.ZeroBasedInt())
          .setEndColumn(end.column_.ZeroBasedInt())
          .build();
  return result;
}

InspectorStyle::InspectorStyle(CSSStyleDeclaration* style,
                               CSSRuleSourceData* source_data,
                               InspectorStyleSheetBase* parent_style_sheet)
    : style_(style),
      source_data_(source_data),
      parent_style_sheet_(parent_style_sheet) {
  DCHECK(style_);
}

std::unique_ptr<protocol::CSS::CSSStyle> InspectorStyle::BuildObjectForStyle(
    Element* element,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  std::unique_ptr<protocol::CSS::CSSStyle> result =
      StyleWithProperties(element, pseudo_id, pseudo_argument);
  if (source_data_) {
    if (parent_style_sheet_ && !parent_style_sheet_->Id().empty())
      result->setStyleSheetId(parent_style_sheet_->Id());
    result->setRange(parent_style_sheet_->BuildSourceRangeObject(
        source_data_->rule_declarations_range));
    String sheet_text;
    bool success = parent_style_sheet_->GetText(&sheet_text);
    if (success) {
      const SourceRange& declarations_range =
          source_data_->rule_declarations_range;
      result->setCssText(sheet_text.Substring(
          declarations_range.start,
          declarations_range.end - declarations_range.start));
    }
  }

  return result;
}

bool InspectorStyle::StyleText(String* result) {
  if (!source_data_)
    return false;

  return TextForRange(source_data_->rule_declarations_range, result);
}

bool InspectorStyle::TextForRange(const SourceRange& range, String* result) {
  String style_sheet_text;
  bool success = parent_style_sheet_->GetText(&style_sheet_text);
  if (!success)
    return false;

  DCHECK(0 <= range.start);
  DCHECK_LE(range.start, range.end);
  DCHECK_LE(range.end, style_sheet_text.length());
  *result = style_sheet_text.Substring(range.start, range.end - range.start);
  return true;
}

void InspectorStyle::PopulateAllProperties(
    Vector<CSSPropertySourceData>& result) {
  if (source_data_ && source_data_->HasProperties()) {
    Vector<CSSPropertySourceData>& source_property_data =
        source_data_->property_data;
    for (const auto& data : source_property_data)
      result.push_back(data);
  }

  for (int i = 0, size = style_->length(); i < size; ++i) {
    String name = style_->item(i);
    if (!IsValidCSSPropertyID(
            CssPropertyID(style_->GetExecutionContext(), name)))
      continue;

    String value = style_->GetPropertyValueWithHint(name, i);
    bool important = !style_->GetPropertyPriorityWithHint(name, i).empty();
    if (important)
      value = value + " !important";
    result.push_back(CSSPropertySourceData(name, value, important, false, true,
                                           SourceRange()));
  }
}

bool InspectorStyle::CheckRegisteredPropertySyntaxWithVarSubstitution(
    Element* element,
    const CSSPropertySourceData& property,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) const {
  if (!element) {
    return false;
  }
  const Document* document = parent_style_sheet_->GetDocument();
  if (!document) {
    return false;
  }
  if (!property.name.StartsWith("--")) {
    return false;
  }
  const PropertyRegistry* registry = document->GetPropertyRegistry();
  if (!registry) {
    return false;
  }
  AtomicString atomic_name(property.name);
  const PropertyRegistration* registration =
      registry->Registration(atomic_name);
  if (!registration) {
    return false;
  }

  const ComputedStyle* style =
      element->EnsureComputedStyle(pseudo_id, pseudo_argument);
  if (!style) {
    return false;
  }

  PropertyRegistry* empty_registry = MakeGarbageCollected<PropertyRegistry>();
  CustomProperty p(atomic_name, empty_registry);

  const CSSParserContext* parser_context = ParserContextForDocument(document);
  const CSSValue* result = p.Parse(property.value, *parser_context, {});
  if (!result) {
    return false;
  }

  CSSPropertyName property_name(atomic_name);
  // Substitute var()s in the property value from element's computed style.
  const auto* computed_value =
      StyleResolver::ResolveValue(*element, *style, property_name, *result);
  if (!computed_value) {
    return false;
  }

  // Now check the substitution result against the registered syntax.
  if (!registration->Syntax().Parse(computed_value->CssText(), *parser_context,
                                    false)) {
    return false;
  }
  return true;
}

std::unique_ptr<protocol::CSS::CSSStyle> InspectorStyle::StyleWithProperties(
    Element* element,
    PseudoId pseudo_id,
    const AtomicString& pseudo_argument) {
  auto properties_object =
      std::make_unique<protocol::Array<protocol::CSS::CSSProperty>>();
  auto shorthand_entries =
      std::make_unique<protocol::Array<protocol::CSS::ShorthandEntry>>();
  HashSet<String> found_shorthands;

  Vector<CSSPropertySourceData> properties;
  PopulateAllProperties(properties);

  for (auto& style_property : properties) {
    const CSSPropertySourceData& property_entry = style_property;
    const String& name = property_entry.name;

    std::unique_ptr<protocol::CSS::CSSProperty> property =
        protocol::CSS::CSSProperty::create()
            .setName(name)
            .setValue(property_entry.value)
            .build();

    // Default "parsedOk" == true.
    if (!property_entry.parsed_ok) {
      property->setParsedOk(CheckRegisteredPropertySyntaxWithVarSubstitution(
          element, property_entry, pseudo_id, pseudo_argument));
    }

    String text;
    if (style_property.range.length() &&
        TextForRange(style_property.range, &text))
      property->setText(text);
    if (property_entry.important)
      property->setImportant(true);
    if (style_property.range.length()) {
      property->setRange(parent_style_sheet_
                             ? parent_style_sheet_->BuildSourceRangeObject(
                                   property_entry.range)
                             : nullptr);
      if (!property_entry.disabled) {
        property->setImplicit(false);
      }
      property->setDisabled(property_entry.disabled);
    } else if (!property_entry.disabled) {
      bool implicit = style_->IsPropertyImplicit(name);
      // Default "implicit" == false.
      if (implicit)
        property->setImplicit(true);

      String shorthand = style_->GetPropertyShorthand(name);
      if (!shorthand.empty()) {
        if (found_shorthands.insert(shorthand).is_new_entry) {
          std::unique_ptr<protocol::CSS::ShorthandEntry> entry =
              protocol::CSS::ShorthandEntry::create()
                  .setName(shorthand)
                  .setValue(ShorthandValue(shorthand))
                  .build();
          if (!style_->getPropertyPriority(name).empty())
            entry->setImportant(true);
          shorthand_entries->emplace_back(std::move(entry));
        }
      }
    }

    if (auto longhandProperties = LonghandProperties(property_entry))
      property->setLonghandProperties(std::move(longhandProperties));

    properties_object->emplace_back(std::move(property));
  }

  std::unique_ptr<protocol::C
```