Response:
Let's break down the thought process for analyzing the provided C++ code for `speculation_rule_set.cc`.

1. **Understand the Goal:** The request asks for the file's functionalities, its relationship with web technologies (JavaScript, HTML, CSS), logical reasoning examples, common user errors, and debugging context.

2. **Initial Skim and Keyword Identification:** Quickly read through the code, looking for keywords and patterns. Keywords like "speculation rules," "parse," "JSON," "prefetch," "prerender," "target_hint," "referrer_policy," "eagerness," and "console message" stand out. These give a high-level overview of the file's purpose.

3. **Identify Core Functionality:** The filename and the prominent keywords strongly suggest this file is responsible for *processing and managing speculation rules*. Speculation rules, as suggested by "prefetch" and "prerender," likely aim to optimize page loading by proactively fetching or rendering resources.

4. **Deconstruct the Code into Logical Blocks:**  Start examining the code section by section. Pay attention to classes, functions, and namespaces.

    * **Includes:**  The `#include` directives reveal dependencies on other Blink components (`core/css/style_rule.h`, `core/dom/document.h`, etc.) and platform utilities (`platform/json/json_parser.h`). This confirms interaction with the broader rendering engine. The inclusion of `public/mojom/speculation_rules/speculation_rules.mojom-shared.h` indicates the use of Mojo interfaces, a common way for Chromium components to communicate.

    * **Anonymous Namespace:** The anonymous namespace contains helper functions. Analyze these:
        * `AddConsoleMessageForSpeculationRuleSetValidation`: Clearly, this handles logging errors and warnings to the browser's developer console.
        * `IsValidContextName`, `IsValidBrowsingContextNameOrKeyword`: These validate the `target_hint` attribute, linking to HTML concepts of browsing contexts.
        * `SetParseErrorMessage`: A utility for error handling during parsing.
        * `ParseSpeculationRule`: This is the core parsing function, taking JSON input and converting it into a `SpeculationRule` object. It handles various attributes like `source`, `urls`, `where`, `target_hint`, etc. This is where much of the logic resides.

    * **`SpeculationRuleSet::Source`:** This nested class encapsulates the origin of the speculation rules (inline script, fetched resource, browser-injected). It stores the source text and relevant metadata.

    * **`SpeculationRuleSet`:** This is the main class.
        * Constructor: Takes a `Source` object.
        * `SetError`, `AddWarnings`: Methods for reporting parsing issues.
        * `Parse`: The static method responsible for the overall parsing process. It orchestrates the parsing of different rule types ("prefetch," "prerender"). It uses `ParseSpeculationRule` for individual rule parsing.
        * Helper methods like `HasError`, `HasWarnings`, and `ShouldReportUMAForError`.
        * `SpeculationTargetHintFromString`: Converts the string representation of the target hint into an enum.
        * `AddConsoleMessageForValidation`: Public interface to trigger console message logging.

5. **Relate to Web Technologies:** Based on the code analysis, establish connections to JavaScript, HTML, and CSS:

    * **JavaScript:** Speculation rules are often defined within `<script>` tags using JSON. The `Parse` function processes this JSON. The `Source::FromInlineScript` method indicates parsing rules directly from scripts.
    * **HTML:** The `<script type="speculationrules">` tag is the primary way to embed these rules. The validation of `target_hint` directly relates to HTML's browsing context names.
    * **CSS:** The `DocumentRulePredicate` and its `GetStyleRules` method suggest that CSS selectors can be used to target specific elements for applying speculation rules. The `where` clause in the JSON structure likely ties into CSS selectors.

6. **Construct Examples:** Create illustrative examples to demonstrate the functionality and relationships:

    * **JavaScript/HTML Example:** Show a `<script>` tag with a JSON structure containing prefetch and prerender rules. Highlight the different attributes and their possible values.
    * **CSS Relationship:** Explain how the `where` clause uses CSS selectors to define conditions for applying rules. Give an example of a rule that only applies to links within a specific div.
    * **Logical Reasoning:** Devise scenarios with specific JSON inputs and predict the output (parsed rules, errors, warnings). This tests understanding of the parsing logic.

7. **Identify Common User Errors:** Think about typical mistakes developers might make when working with speculation rules:

    * **Invalid JSON:**  Syntax errors, missing commas, etc.
    * **Incorrect Keys:** Using unknown or misspelled keys.
    * **Invalid Values:** Providing non-string values for attributes that require strings.
    * **Type Mismatches:** Providing an object where an array is expected.
    * **Conflicting Attributes:** Using `urls` and `where` in the same rule without a `source`.
    * **Invalid `target_hint`:** Using a value that isn't a valid browsing context name or keyword.
    * **Invalid `referrer_policy`:**  Using an unsupported or misspelled referrer policy string.
    * **Invalid `eagerness`:** Using an unrecognized eagerness value.

8. **Trace User Operations (Debugging Context):**  Consider how a user's actions lead to this code being executed:

    * **Page Load:** The browser encounters a `<script type="speculationrules">` tag or fetches a speculation rules JSON file.
    * **Parsing:** The Blink engine identifies the script or resource as containing speculation rules.
    * **`SpeculationRuleSet::Parse`:** This function is called to process the rules.
    * **Error Handling:** If there are errors, `AddConsoleMessageForSpeculationRuleSetValidation` logs messages to the console.

9. **Structure the Answer:** Organize the findings into clear sections as requested: Functionalities, Relationships, Logical Reasoning, User Errors, and Debugging Context. Use clear language and code examples where appropriate.

10. **Review and Refine:** Read through the answer to ensure accuracy, clarity, and completeness. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have only focused on the parsing of URLs. A closer look reveals the importance of the "where" clause and its connection to CSS selectors. Similarly, the different `Source` types and their implications for error reporting are important to highlight.
好的，我们来详细分析一下 `blink/renderer/core/speculation_rules/speculation_rule_set.cc` 这个文件的功能。

**文件功能概览:**

`speculation_rule_set.cc` 文件是 Chromium Blink 引擎中负责解析、验证和管理推测规则（Speculation Rules）的核心组件。推测规则是一种允许网页开发者向浏览器提供关于未来可能导航的目标 URL 和相关配置信息的机制，以便浏览器可以提前进行预取（prefetch）或预渲染（prerender），从而提升页面加载速度和用户体验。

该文件主要负责：

1. **解析推测规则 JSON:**  从 `<script type="speculationrules">` 标签内的 JSON 数据或通过链接的 JSON 文件中读取推测规则。
2. **验证规则的有效性:**  检查 JSON 结构是否符合规范，例如是否存在未知的键、键的类型是否正确、URL 是否有效、`target_hint`、`referrer_policy`、`eagerness` 等属性的值是否合法。
3. **创建 `SpeculationRule` 对象:** 将解析和验证后的规则信息转化为 `SpeculationRule` 对象，这些对象包含了具体的预取或预渲染目标、触发条件、以及其他配置信息。
4. **管理规则集合:**  `SpeculationRuleSet` 类用于存储和管理一组相关的推测规则。
5. **生成控制台消息:**  在解析过程中，如果遇到错误或警告，会将相应的消息输出到浏览器的开发者控制台，帮助开发者调试和修正规则。
6. **处理不同来源的规则:**  支持来自内联脚本、外部资源文件以及浏览器注入的推测规则。
7. **支持文档规则 (Document Rules):**  解析并处理基于 CSS 选择器的文档规则，允许根据页面元素的状态动态应用推测规则。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:**
    * **定义推测规则:**  推测规则通常以 JSON 格式写在 `<script type="speculationrules">` 标签内，JavaScript 可以动态生成或修改这些规则。
    ```html
    <script type="speculationrules">
    {
      "prefetch": [
        {"urls": ["/next-page"]}
      ]
    }
    </script>
    ```
    * **动态注入规则:** JavaScript 可以通过 DOM 操作创建和插入包含推测规则的 `<script>` 标签。

* **HTML:**
    * **嵌入推测规则:**  通过 `<script type="speculationrules">` 标签将推测规则嵌入到 HTML 文档中。
    * **链接外部规则文件:**  可以使用 `<link rel="speculationrules" href="rules.json">` 标签链接到包含推测规则的外部 JSON 文件。
    * **`target_hint` 属性:**  规则中的 `target_hint` 属性与 HTML 的 `target` 属性的概念相关，用于指定预渲染的目标页面的打开方式（例如 `_blank`, `_self`）。

* **CSS:**
    * **文档规则 (Document Rules) 中的 CSS 选择器:**  推测规则可以包含 `where` 子句，该子句使用 CSS 选择器来指定规则生效的条件。例如，只有当用户鼠标悬停在特定链接上时才进行预取。
    ```json
    {
      "prefetch": [
        {
          "source": "document",
          "where": {
            "href_matches": "products/.*",
            "and": [
              {"selector": ".product-link:hover"}
            ]
          }
        }
      ]
    }
    ```
    在这个例子中，只有当链接的 `href` 匹配 `products/.*` 并且鼠标悬停在 class 为 `product-link` 的元素上时，才会预取匹配的 URL。

**逻辑推理及假设输入与输出:**

假设有以下推测规则 JSON 数据：

**输入 (JSON):**

```json
{
  "prefetch": [
    { "urls": ["/page1", "/page2"] },
    {
      "source": "document",
      "where": { "selector": "#buy-button" }
    }
  ],
  "prerender": [
    { "urls": ["/expensive-page"], "target_hint": "_blank" }
  ]
}
```

**解析过程中的逻辑推理:**

1. **解析 "prefetch" 规则:**
   - 第一个规则是列表规则（`source` 默认为 "list"），包含两个 URL `/page1` 和 `/page2`，会被解析为两个独立的预取目标。
   - 第二个规则是文档规则，当页面上存在 ID 为 `buy-button` 的元素时，会预取所有匹配到的链接。

2. **解析 "prerender" 规则:**
   -  包含一个 URL `/expensive-page`，并且指定了 `target_hint` 为 `_blank`，意味着预渲染的页面可能会在新标签页中打开。

**输出 (内部 `SpeculationRule` 对象，简化表示):**

```
SpeculationRuleSet {
  prefetch_rules: [
    SpeculationRule { urls: ["/page1"] },
    SpeculationRule { urls: ["/page2"] },
    SpeculationRule { document_rule_predicate: { selector: "#buy-button" } }
  ],
  prerender_rules: [
    SpeculationRule { urls: ["/expensive-page"], target_hint: kBlank }
  ]
}
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **JSON 格式错误:**  忘记逗号、引号不匹配、括号不匹配等。
   ```json
   {
     "prefetch": [
       { "urls": ["/page1"  "/page2"] } // 错误：缺少逗号
     ]
   }
   ```
   **控制台警告:** "While parsing speculation rules: Parsed JSON must be an object." (具体的错误信息可能会更详细)

2. **使用未知的键:**  在 JSON 中使用了规范未定义的键。
   ```json
   {
     "prefetch": [
       { "invalid_key": "/page1" }
     ]
   }
   ```
   **控制台警告:** "While parsing speculation rules: A rule contains an unknown key: "invalid_key"."

3. **键的值类型错误:**  例如，`urls` 应该是一个字符串数组，但提供了一个字符串。
   ```json
   {
     "prefetch": [
       { "urls": "/page1" } // 错误：urls 应该是数组
     ]
   }
   ```
   **控制台警告:** "While parsing speculation rules: A rule must have a "urls" array."

4. **`target_hint` 的值无效:**  使用了不是 `_blank`, `_self`, `_parent`, `_top` 等有效值。
   ```json
   {
     "prerender": [
       { "urls": ["/page"], "target_hint": "invalid" }
     ]
   }
   ```
   **控制台警告:** "While parsing speculation rules: A rule has an invalid "target_hint": "invalid"."

5. **在列表规则中使用了 `where` 子句:**  列表规则默认基于提供的 URL 列表进行推测，不应包含文档规则的匹配条件。
   ```json
   {
     "prefetch": [
       { "urls": ["/page"], "where": { "selector": ".link" } }
     ]
   }
   ```
   **控制台警告:** "While parsing speculation rules: A list rule may not have document rule matchers."

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者在 HTML 中添加 `<script type="speculationrules">` 标签或 `<link rel="speculationrules">` 标签。** 这是触发推测规则解析的起点。
2. **浏览器加载 HTML 文档并解析。** 当解析器遇到 `<script type="speculationrules">` 标签时，会提取其内容。如果遇到 `<link rel="speculationrules">` 标签，则会发起对链接资源的请求。
3. **如果规则来自 `<script>` 标签，则 `HTMLScriptElement::ProcessScript` 方法会被调用。**  在这个过程中，会识别出 `type="speculationrules"`，并触发相关的处理逻辑。
4. **如果规则来自外部资源，则会发起网络请求。**  当资源加载完成后，其 MIME 类型会被检查，如果匹配 `application/speculationrules+json`，则会被视为推测规则。
5. **`SpeculationRuleSet::Parse` 静态方法被调用。**  无论是内联脚本还是外部资源，最终都会调用这个方法来解析 JSON 数据。
6. **在 `SpeculationRuleSet::Parse` 内部，会使用 JSON 解析器（例如 `JSONParser::Parse`）将字符串解析为 JSON 对象。**
7. **`ParseSpeculationRule` 函数会被多次调用，用于解析 JSON 对象中的每个规则。**
8. **在解析和验证过程中，如果发现错误，`SpeculationRuleSet::SetError` 或 `SpeculationRuleSet::AddWarnings` 会被调用。**
9. **`AddConsoleMessageForSpeculationRuleSetValidation` 函数会被调用，将错误或警告信息添加到浏览器的控制台。**  这个函数会获取当前文档和相关的脚本元素或资源对象，以便在控制台中提供更精确的错误位置信息。

**作为调试线索:**

* **查看控制台消息:**  开发者应该首先检查浏览器的开发者控制台，查看是否有与推测规则相关的错误或警告信息。这些消息通常会指出具体的错误类型和位置。
* **检查 `<script>` 标签或外部 JSON 文件的内容:**  仔细检查 JSON 语法是否正确，键名是否拼写正确，值类型是否符合预期。
* **使用浏览器的 "Network" 面板:**  如果推测规则来自外部文件，可以使用浏览器的网络面板检查资源是否成功加载，以及响应的 Content-Type 是否正确。
* **断点调试:**  对于更复杂的场景，开发者可以在 `speculation_rule_set.cc` 文件中的关键函数（例如 `SpeculationRuleSet::Parse`，`ParseSpeculationRule`）设置断点，逐步跟踪代码执行过程，查看解析过程中的变量值和状态，从而更深入地理解问题所在。

总而言之，`speculation_rule_set.cc` 文件在 Chromium Blink 引擎中扮演着至关重要的角色，它负责将开发者定义的推测规则转化为浏览器可以理解和执行的内部数据结构，并负责在解析过程中进行严格的验证，确保规则的有效性，从而为网页的性能优化奠定基础。

### 提示词
```
这是目录为blink/renderer/core/speculation_rules/speculation_rule_set.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/speculation_rules/speculation_rule_set.h"

#include "base/containers/contains.h"
#include "base/not_fatal_until.h"
#include "services/network/public/mojom/no_vary_search.mojom-shared.h"
#include "services/network/public/mojom/referrer_policy.mojom-shared.h"
#include "third_party/blink/public/mojom/speculation_rules/speculation_rules.mojom-shared.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/inspector/identifiers_factory.h"
#include "third_party/blink/renderer/core/loader/resource/speculation_rules_resource.h"
#include "third_party/blink/renderer/core/script/script_element_base.h"
#include "third_party/blink/renderer/core/speculation_rules/document_rule_predicate.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rules_metrics.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_parser.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/network/http_parsers.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/weborigin/security_policy.h"
#include "third_party/blink/renderer/platform/wtf/text/string_view.h"

namespace blink {

namespace {

void AddConsoleMessageForSpeculationRuleSetValidation(
    SpeculationRuleSet& speculation_rule_set,
    Document& element_document,
    ScriptElementBase* script_element,
    SpeculationRulesResource* resource) {
  // `script_element` and `resource` are mutually exclusive.
  CHECK(script_element || resource);
  CHECK(!script_element || !resource);

  if (speculation_rule_set.HasError()) {
    String error_message;
    if (script_element) {
      error_message = "While parsing speculation rules: " +
                      speculation_rule_set.error_message();
    } else {
      error_message = "While parsing speculation rules fetched from \"" +
                      resource->GetResourceRequest().Url().ElidedString() +
                      "\": " + speculation_rule_set.error_message() + "\".";
    }
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning, error_message);
    if (script_element) {
      console_message->SetNodes(element_document.GetFrame(),
                                {script_element->GetDOMNodeId()});
    }
    element_document.AddConsoleMessage(console_message);
  }
  if (speculation_rule_set.HasWarnings()) {
    // Only add the first warning message to console.
    String warning_message;
    if (script_element) {
      warning_message = "While parsing speculation rules: " +
                        speculation_rule_set.warning_messages()[0];
    } else {
      warning_message = "While parsing speculation rules fetched from \"" +
                        resource->GetResourceRequest().Url().ElidedString() +
                        "\": " + speculation_rule_set.warning_messages()[0] +
                        "\".";
    }
    auto* console_message = MakeGarbageCollected<ConsoleMessage>(
        mojom::blink::ConsoleMessageSource::kOther,
        mojom::blink::ConsoleMessageLevel::kWarning, warning_message);
    if (script_element) {
      console_message->SetNodes(element_document.GetFrame(),
                                {script_element->GetDOMNodeId()});
    }
    element_document.AddConsoleMessage(console_message);
  }
}

// https://html.spec.whatwg.org/C/#valid-browsing-context-name
bool IsValidContextName(const String& name_or_keyword) {
  // "A valid browsing context name is any string with at least one character
  // that does not start with a U+005F LOW LINE character. (Names starting with
  // an underscore are reserved for special keywords.)"
  if (name_or_keyword.empty())
    return false;
  if (name_or_keyword.StartsWith("_"))
    return false;
  return true;
}

// https://html.spec.whatwg.org/C/#valid-browsing-context-name-or-keyword
bool IsValidBrowsingContextNameOrKeyword(const String& name_or_keyword) {
  // "A valid browsing context name or keyword is any string that is either a
  // valid browsing context name or that is an ASCII case-insensitive match for
  // one of: _blank, _self, _parent, or _top."
  if (IsValidContextName(name_or_keyword) ||
      EqualIgnoringASCIICase(name_or_keyword, "_blank") ||
      EqualIgnoringASCIICase(name_or_keyword, "_self") ||
      EqualIgnoringASCIICase(name_or_keyword, "_parent") ||
      EqualIgnoringASCIICase(name_or_keyword, "_top")) {
    return true;
  }
  return false;
}

// If `out_error` is provided and hasn't already had a message set, sets it to
// `message`.
void SetParseErrorMessage(String* out_error, String message) {
  if (out_error && out_error->IsNull()) {
    *out_error = message;
  }
}

SpeculationRule* ParseSpeculationRule(JSONObject* input,
                                      const KURL& base_url,
                                      ExecutionContext* context,
                                      bool is_browser_injected,
                                      String* out_error,
                                      Vector<String>& out_warnings) {
  // https://wicg.github.io/nav-speculation/speculation-rules.html#parse-a-speculation-rule

  // If input has any key other than "source", "urls", "where", "requires",
  // "target_hint", "referrer_policy", "relative_to", "eagerness" and
  // "expects_no_vary_search", then return null.
  const char* const kKnownKeys[] = {
      "source",      "urls",        "where",
      "requires",    "target_hint", "referrer_policy",
      "relative_to", "eagerness",   "expects_no_vary_search"};
  for (wtf_size_t i = 0; i < input->size(); ++i) {
    const String& input_key = input->at(i).first;
    if (!base::Contains(kKnownKeys, input_key)) {
      SetParseErrorMessage(
          out_error, "A rule contains an unknown key: \"" + input_key + "\".");
      return nullptr;
    }
  }

  // Let source be null.
  // If input["source"] exists, then set source to input["source"].
  JSONValue* source_value = input->Get("source");
  String source;
  if (source_value) {
    if (!source_value->AsString(&source)) {
      SetParseErrorMessage(out_error,
                           "The value of the \"source\" key must be a string.");
      return nullptr;
    }
  } else {
    // Otherwise, if input["urls"] exists and input["where"] does not exist,
    // then set source to "list".
    //
    // Otherwise, if input["where"] exists and input["urls"] does not exist,
    // then set source to "document".
    const bool has_urls = input->Get("urls");
    const bool has_where = input->Get("where");
    if (has_urls && !has_where) {
      source = "list";
    } else if (!has_urls && has_where) {
      source = "document";
    } else if (has_urls && has_where) {
      SetParseErrorMessage(out_error,
                           "A rule with no explicit \"source\" must specify "
                           "\"urls\" or a \"where\" condition, but not both.");
      return nullptr;
    } else {
      SetParseErrorMessage(out_error,
                           "A rule with no explicit \"source\" must specify "
                           "one of \"urls\" or \"where\".");
      return nullptr;
    }
  }

  if (source != "list" && source != "document") {
    SetParseErrorMessage(out_error,
                         "A rule has an unknown source: \"" + source + "\".");
    return nullptr;
  }

  Vector<KURL> urls;
  if (source == "list") {
    // If input["where"] exists, then return null.
    if (input->Get("where")) {
      SetParseErrorMessage(out_error,
                           "A list rule may not have document rule matchers.");
      return nullptr;
    }

    // For now, use the given base URL to construct the list rules.
    KURL base_url_to_parse = base_url;
    //  If input["relative_to"] exists:
    if (JSONValue* relative_to = input->Get("relative_to")) {
      const char* const kKnownRelativeToValues[] = {"ruleset", "document"};
      String value;
      // If relativeTo is neither the string "ruleset" nor the string
      // "document", then return null.
      if (!relative_to->AsString(&value) ||
          !base::Contains(kKnownRelativeToValues, value)) {
        SetParseErrorMessage(out_error,
                             "A rule has an unknown \"relative_to\" value.");
        return nullptr;
      }
      // If relativeTo is "document", then set baseURL to the document's
      // document base URL.
      if (value == "document") {
        base_url_to_parse = context->BaseURL();
      }
    }

    // Let urls be an empty list.
    // If input["urls"] does not exist, is not a list, or has any element which
    // is not a string, then return null.
    JSONArray* input_urls = input->GetArray("urls");
    if (!input_urls) {
      SetParseErrorMessage(out_error,
                           "A list rule must have a \"urls\" array.");
      return nullptr;
    }

    // For each urlString of input["urls"]...
    urls.ReserveInitialCapacity(input_urls->size());
    for (wtf_size_t i = 0; i < input_urls->size(); ++i) {
      String url_string;
      if (!input_urls->at(i)->AsString(&url_string)) {
        SetParseErrorMessage(out_error, "URLs must be given as strings.");
        return nullptr;
      }

      // Let parsedURL be the result of parsing urlString with baseURL.
      // If parsedURL is failure, then continue.
      KURL parsed_url(base_url_to_parse, url_string);
      if (!parsed_url.IsValid() || !parsed_url.ProtocolIsInHTTPFamily())
        continue;

      urls.push_back(std::move(parsed_url));
    }
  }

  DocumentRulePredicate* document_rule_predicate = nullptr;
  if (source == "document") {
    // If input["urls"] exists, then return null.
    if (input->Get("urls")) {
      SetParseErrorMessage(out_error,
                           "A document rule cannot have a \"urls\" key.");
      return nullptr;
    }

    // "relative_to" outside the "href_matches" clause is not allowed for
    // document rules.
    if (input->Get("relative_to")) {
      SetParseErrorMessage(out_error,
                           "A document rule cannot have \"relative_to\" "
                           "outside the \"where\" clause.");
      return nullptr;
    }

    // If input["where"] does not exist, then set predicate to a document rule
    // conjunction whose clauses is an empty list.
    if (!input->Get("where")) {
      document_rule_predicate = DocumentRulePredicate::MakeDefaultPredicate();
    } else {
      // Otherwise, set predicate to the result of parsing a document rule
      // predicate given input["where"] and baseURL.
      document_rule_predicate = DocumentRulePredicate::Parse(
          input->GetJSONObject("where"), base_url, context,
          IGNORE_EXCEPTION_FOR_TESTING, out_error);
    }
    if (!document_rule_predicate)
      return nullptr;
  }

  // Let requirements be an empty ordered set.
  // If input["requires"] exists, but is not a list, then return null.
  JSONValue* requirements = input->Get("requires");
  if (requirements && requirements->GetType() != JSONValue::kTypeArray) {
    SetParseErrorMessage(out_error, "\"requires\" must be an array.");
    return nullptr;
  }

  // For each requirement of input["requires"]...
  SpeculationRule::RequiresAnonymousClientIPWhenCrossOrigin
      requires_anonymous_client_ip(false);
  if (JSONArray* requirements_array = JSONArray::Cast(requirements)) {
    for (wtf_size_t i = 0; i < requirements_array->size(); ++i) {
      String requirement;
      if (!requirements_array->at(i)->AsString(&requirement)) {
        SetParseErrorMessage(out_error, "Requirements must be strings.");
        return nullptr;
      }

      if (requirement == "anonymous-client-ip-when-cross-origin") {
        requires_anonymous_client_ip =
            SpeculationRule::RequiresAnonymousClientIPWhenCrossOrigin(true);
      } else {
        SetParseErrorMessage(
            out_error,
            "A rule has an unknown requirement: \"" + requirement + "\".");
        return nullptr;
      }
    }
  }

  // Let targetHint be null.
  std::optional<mojom::blink::SpeculationTargetHint> target_hint;

  // If input["target_hint"] exists:
  JSONValue* target_hint_value = input->Get("target_hint");
  if (target_hint_value) {
    // If input["target_hint"] is not a valid browsing context name or keyword,
    // then return null.
    // Set targetHint to input["target_hint"].
    String target_hint_str;
    if (!target_hint_value->AsString(&target_hint_str)) {
      SetParseErrorMessage(out_error, "\"target_hint\" must be a string.");
      return nullptr;
    }
    if (!IsValidBrowsingContextNameOrKeyword(target_hint_str)) {
      SetParseErrorMessage(out_error,
                           "A rule has an invalid \"target_hint\": \"" +
                               target_hint_str + "\".");
      return nullptr;
    }
    target_hint =
        SpeculationRuleSet::SpeculationTargetHintFromString(target_hint_str);
  }

  // Let referrerPolicy be the empty string.
  std::optional<network::mojom::ReferrerPolicy> referrer_policy;
  // If input["referrer_policy"] exists:
  JSONValue* referrer_policy_value = input->Get("referrer_policy");
  if (referrer_policy_value) {
    // If input["referrer_policy"] is not a referrer policy, then return null.
    String referrer_policy_str;
    if (!referrer_policy_value->AsString(&referrer_policy_str)) {
      SetParseErrorMessage(out_error, "A referrer policy must be a string.");
      return nullptr;
    }

    if (!referrer_policy_str.empty()) {
      network::mojom::ReferrerPolicy referrer_policy_out =
          network::mojom::ReferrerPolicy::kDefault;
      if (!SecurityPolicy::ReferrerPolicyFromString(
              referrer_policy_str, kDoNotSupportReferrerPolicyLegacyKeywords,
              &referrer_policy_out)) {
        SetParseErrorMessage(out_error,
                             "A rule has an invalid referrer policy: \"" +
                                 referrer_policy_str + "\".");
        return nullptr;
      }
      DCHECK_NE(referrer_policy_out, network::mojom::ReferrerPolicy::kDefault);
      // Set referrerPolicy to input["referrer_policy"].
      referrer_policy = referrer_policy_out;
      UseCounter::Count(context,
                        WebFeature::kSpeculationRulesExplicitReferrerPolicy);
    }
  }

  mojom::blink::SpeculationEagerness eagerness;
  if (JSONValue* eagerness_value = input->Get("eagerness")) {
    String eagerness_str;
    if (!eagerness_value->AsString(&eagerness_str)) {
      SetParseErrorMessage(out_error, "Eagerness value must be a string.");
      return nullptr;
    }

    if (eagerness_str == "eager" || eagerness_str == "immediate") {
      eagerness = mojom::blink::SpeculationEagerness::kEager;
    } else if (eagerness_str == "moderate") {
      eagerness = mojom::blink::SpeculationEagerness::kModerate;
    } else if (eagerness_str == "conservative") {
      eagerness = mojom::blink::SpeculationEagerness::kConservative;
    } else {
      SetParseErrorMessage(
          out_error, "Eagerness value: \"" + eagerness_str + "\" is invalid.");
      return nullptr;
    }

    UseCounter::Count(context, WebFeature::kSpeculationRulesExplicitEagerness);
  } else {
    eagerness = source == "list"
                    ? mojom::blink::SpeculationEagerness::kEager
                    : mojom::blink::SpeculationEagerness::kConservative;
  }

  network::mojom::blink::NoVarySearchPtr no_vary_search = nullptr;
  if (JSONValue* no_vary_search_value = input->Get("expects_no_vary_search");
      no_vary_search_value) {
    String no_vary_search_str;
    if (!no_vary_search_value->AsString(&no_vary_search_str)) {
      SetParseErrorMessage(out_error,
                           "expects_no_vary_search's value must be a string.");
      return nullptr;
    }
    // Parse No-Vary-Search hint value.
    auto no_vary_search_hint = blink::ParseNoVarySearch(no_vary_search_str);
    CHECK(no_vary_search_hint);
    if (no_vary_search_hint->is_parse_error()) {
      const auto& parse_error = no_vary_search_hint->get_parse_error();
      CHECK_NE(parse_error, network::mojom::NoVarySearchParseError::kOk);
      if (parse_error !=
          network::mojom::NoVarySearchParseError::kDefaultValue) {
        out_warnings.push_back(GetNoVarySearchHintConsoleMessage(parse_error));
      }
    } else {
      UseCounter::Count(context, WebFeature::kSpeculationRulesNoVarySearchHint);
      no_vary_search = std::move(no_vary_search_hint->get_no_vary_search());
    }
  }

  auto injection_type = mojom::blink::SpeculationInjectionType::kNone;
  if (is_browser_injected) {
    injection_type =
        mojom::blink::SpeculationInjectionType::kAutoSpeculationRules;
  } else if (auto* world = context->GetCurrentWorld()) {
    if (world->IsMainWorld()) {
      injection_type = mojom::blink::SpeculationInjectionType::kMainWorldScript;
    } else {
      injection_type =
          mojom::blink::SpeculationInjectionType::kIsolatedWorldScript;
    }
  }

  return MakeGarbageCollected<SpeculationRule>(
      std::move(urls), document_rule_predicate, requires_anonymous_client_ip,
      target_hint, referrer_policy, eagerness, std::move(no_vary_search),
      injection_type);
}

}  // namespace

// ---- SpeculationRuleSet::Source implementation ----

SpeculationRuleSet::Source::Source(base::PassKey<SpeculationRuleSet::Source>,
                                   const String& source_text,
                                   Document* document,
                                   std::optional<DOMNodeId> node_id,
                                   std::optional<KURL> base_url,
                                   std::optional<uint64_t> request_id,
                                   bool ignore_opt_out)
    : source_text_(source_text),
      document_(document),
      node_id_(node_id),
      base_url_(base_url),
      request_id_(request_id),
      ignore_opt_out_(ignore_opt_out) {}

SpeculationRuleSet::Source* SpeculationRuleSet::Source::FromInlineScript(
    const String& source_text,
    Document& document,
    DOMNodeId node_id) {
  return MakeGarbageCollected<Source>(base::PassKey<Source>(), source_text,
                                      &document, node_id, std::nullopt,
                                      std::nullopt, false);
}

SpeculationRuleSet::Source* SpeculationRuleSet::Source::FromRequest(
    const String& source_text,
    const KURL& base_url,
    uint64_t request_id) {
  return MakeGarbageCollected<Source>(base::PassKey<Source>(), source_text,
                                      nullptr, std::nullopt, base_url,
                                      request_id, false);
}

SpeculationRuleSet::Source* SpeculationRuleSet::Source::FromBrowserInjected(
    const String& source_text,
    const KURL& base_url,
    BrowserInjectedSpeculationRuleOptOut opt_out) {
  const bool ignore_opt_out =
      opt_out == BrowserInjectedSpeculationRuleOptOut::kIgnore;

  return MakeGarbageCollected<Source>(base::PassKey<Source>(), source_text,
                                      nullptr, std::nullopt, base_url,
                                      std::nullopt, ignore_opt_out);
}

bool SpeculationRuleSet::Source::IsFromInlineScript() const {
  return node_id_.has_value();
}

bool SpeculationRuleSet::Source::IsFromRequest() const {
  return request_id_.has_value();
}

bool SpeculationRuleSet::Source::IsFromBrowserInjected() const {
  return !IsFromInlineScript() && !IsFromRequest();
}

bool SpeculationRuleSet::Source::IsFromBrowserInjectedAndRespectsOptOut()
    const {
  return IsFromBrowserInjected() && !ignore_opt_out_;
}

const String& SpeculationRuleSet::Source::GetSourceText() const {
  return source_text_;
}

const std::optional<DOMNodeId>& SpeculationRuleSet::Source::GetNodeId() const {
  return node_id_;
}

const std::optional<KURL> SpeculationRuleSet::Source::GetSourceURL() const {
  if (IsFromRequest()) {
    CHECK(base_url_.has_value());
    return base_url_;
  }
  return std::nullopt;
}

const std::optional<uint64_t>& SpeculationRuleSet::Source::GetRequestId()
    const {
  return request_id_;
}

KURL SpeculationRuleSet::Source::GetBaseURL() const {
  if (base_url_) {
    DCHECK(!document_);
    return base_url_.value();
  }
  DCHECK(document_);
  return document_->BaseURL();
}

void SpeculationRuleSet::Source::Trace(Visitor* visitor) const {
  visitor->Trace(document_);
}

// ---- SpeculationRuleSet implementation ----

SpeculationRuleSet::SpeculationRuleSet(base::PassKey<SpeculationRuleSet>,
                                       Source* source)
    : inspector_id_(IdentifiersFactory::CreateIdentifier()), source_(source) {}

void SpeculationRuleSet::SetError(SpeculationRuleSetErrorType error_type,
                                  String error_message) {
  // Only the first error will be reported.
  if (error_type_ != SpeculationRuleSetErrorType::kNoError) {
    return;
  }

  error_type_ = error_type;
  error_message_ = error_message;
}

void SpeculationRuleSet::AddWarnings(
    base::span<const String> warning_messages) {
  warning_messages_.AppendSpan(warning_messages);
}

// static
SpeculationRuleSet* SpeculationRuleSet::Parse(Source* source,
                                              ExecutionContext* context) {
  CHECK(context, base::NotFatalUntil::M131);
  // https://wicg.github.io/nav-speculation/speculation-rules.html#parse-speculation-rules

  const String& source_text = source->GetSourceText();
  const KURL& base_url = source->GetBaseURL();

  // Let result be an empty speculation rule set.
  SpeculationRuleSet* result = MakeGarbageCollected<SpeculationRuleSet>(
      base::PassKey<SpeculationRuleSet>(), source);

  // Let parsed be the result of parsing a JSON string to an Infra value given
  // input.
  JSONParseError parse_error;
  auto parsed = JSONObject::From(ParseJSON(source_text, &parse_error));

  // If parsed is not a map, then return an empty rule sets.
  if (!parsed) {
    result->SetError(SpeculationRuleSetErrorType::kSourceIsNotJsonObject,
                     parse_error.type != JSONParseErrorType::kNoError
                         ? parse_error.message
                         : "Parsed JSON must be an object.");
    return result;
  }

  if (!parse_error.duplicate_keys.empty()) {
    String duplicate_key_warning;
    if (parse_error.duplicate_keys.size() == 1) {
      String key = parse_error.duplicate_keys[0];
      duplicate_key_warning =
          "An object contained more than one key named " +
          key.EncodeForDebugging() + ". All but the last are ignored." +
          ((key == "prefetch" || key == "prerender")
               ? " It is likely that either one of them was intended to be "
                 "another action, or that their rules should be merged into a "
                 "single array."
               : String());
    } else {
      StringBuilder builder;
      builder.Append(
          "The following keys were duplicated on one or more objects: ");
      for (wtf_size_t i = 0; i < parse_error.duplicate_keys.size(); i++) {
        if (i != 0) {
          builder.Append(", ");
        }
        builder.Append(parse_error.duplicate_keys[i].EncodeForDebugging());
      }
      builder.Append(". All but the last value for each key are ignored.");
      duplicate_key_warning = builder.ReleaseString();
    }
    result->AddWarnings(base::span_from_ref(duplicate_key_warning));
  }

  const auto parse_for_action =
      [&](const char* key, HeapVector<Member<SpeculationRule>>& destination,
          bool allow_target_hint,
          bool allow_requires_anonymous_client_ip_when_cross_origin) {
        // If key doesn't exist, it is not an error and is nop.
        JSONValue* value = parsed->Get(key);
        if (!value) {
          return;
        }

        JSONArray* array = JSONArray::Cast(value);
        if (!array) {
          result->SetError(SpeculationRuleSetErrorType::kInvalidRulesSkipped,
                           "A rule set for a key must be an array: path = [\"" +
                               String(key) + "\"]");
          return;
        }

        Vector<String> warning_messages;
        for (wtf_size_t i = 0; i < array->size(); ++i) {
          // If prefetch/prerenderRule is not a map, then continue.
          JSONObject* input_rule = JSONObject::Cast(array->at(i));
          if (!input_rule) {
            result->SetError(SpeculationRuleSetErrorType::kInvalidRulesSkipped,
                             "A rule must be an object: path = [\"" +
                                 String(key) + "\"][" + String::Number(i) +
                                 "]");
            continue;
          }

          // Let rule be the result of parsing a speculation rule given
          // prefetch/prerenderRule and baseURL.
          //
          // TODO(https://crbug.com/1410709): Refactor
          // ParseSpeculationRule to return
          // `std::tuple<SpeculationRule*, String, Vector<String>>`.
          String error_message;
          SpeculationRule* rule = ParseSpeculationRule(
              input_rule, base_url, context, source->IsFromBrowserInjected(),
              &error_message, warning_messages);

          // If parse failed for a rule, then ignore it and continue.
          if (!rule) {
            result->SetError(SpeculationRuleSetErrorType::kInvalidRulesSkipped,
                             error_message);
            continue;
          }

          // Rejects if "target_hint" is set but not allowed.
          if (!allow_target_hint &&
              rule->target_browsing_context_name_hint().has_value()) {
            result->SetError(SpeculationRuleSetErrorType::kInvalidRulesSkipped,
                             "\"target_hint\" may not be set for " +
                                 String(key) + " rules.");
            continue;
          }

          // Rejects if "anonymous-client-ip-when-cross-origin" is required but
          // not allowed.
          if (!allow_requires_anonymous_client_ip_when_cross_origin &&
              rule->requires_anonymous_client_ip_when_cross_origin()) {
            result->SetError(
                SpeculationRuleSetErrorType::kInvalidRulesSkipped,
                "requirement \"anonymous-client-ip-when-cross-origin\" for \"" +
                    String(key) + "\" is not supported.");
            continue;
          }

          // Add the warnings and continue
          result->AddWarnings(warning_messages);
          warning_messages.clear();

          if (rule->predicate()) {
            result->has_document_rule_ = true;
            result->selectors_.AppendVector(rule->predicate()->GetStyleRules());
          }

          if (rule->eagerness() != mojom::blink::SpeculationEagerness::kEager) {
            result->requires_unfiltered_input_ = true;
          }

          // Append rule to result's prefetch/prerender rules.
          destination.push_back(rule);
        }
      };

  // If parsed["prefetch"] exists and is a list, then for each...
  parse_for_action(
      "prefetch", result->prefetch_rules_,
      /*allow_target_hint=*/false,
      /*allow_requires_anonymous_client_ip_when_cross_origin=*/true);

  // If parsed["prefetch_with_subresources"] exists and is a list, then for
  // each...
  parse_for_action(
      "prefetch_with_subresources", result->prefetch_with_subresources_rules_,
      /*allow_target_hint=*/false,
      /*allow_requires_anonymous_client_ip_when_cross_origin=*/false);

  // If parsed["prerender"] exists and is a list, then for each...
  parse_for_action(
      "prerender", result->prerender_rules_,
      /*allow_target_hint=*/true,
      /*allow_requires_anonymous_client_ip_when_cross_origin=*/false);

  return result;
}

bool SpeculationRuleSet::HasError() const {
  return error_type_ != SpeculationRuleSetErrorType::kNoError;
}

bool SpeculationRuleSet::HasWarnings() const {
  return !warning_messages_.empty();
}

bool SpeculationRuleSet::ShouldReportUMAForError() const {
  // We report UMAs only if entire parse failed.
  switch (error_type_) {
    case SpeculationRuleSetErrorType::kSourceIsNotJsonObject:
      return true;
    case SpeculationRuleSetErrorType::kNoError:
    case SpeculationRuleSetErrorType::kInvalidRulesSkipped:
      return false;
  }
}

// static
mojom::blink::SpeculationTargetHint
SpeculationRuleSet::SpeculationTargetHintFromString(
    const StringView& target_hint_str) {
  // Currently only "_blank" and "_self" are supported.
  // TODO(https://crbug.com/1354049): Support more browsing context names and
  // keywords.
  if (EqualIgnoringASCIICase(target_hint_str, "_blank")) {
    return mojom::blink::SpeculationTargetHint::kBlank;
  } else if (EqualIgnoringASCIICase(target_hint_str, "_self")) {
    return mojom::blink::SpeculationTargetHint::kSelf;
  } else {
    return mojom::blink::SpeculationTargetHint::kNoHint;
  }
}

void SpeculationRuleSet::Trace(Visitor* visitor) const {
  visitor->Trace(prefetch_rules_);
  visitor->Trace(prefetch_with_subresources_rules_);
  visitor->Trace(prerender_rules_);
  visitor->Trace(source_);
  visitor->Trace(selectors_);
}

void SpeculationRuleSet::AddConsoleMessageForValidation(
    ScriptElementBase& script_element) {
  AddConsoleMessageForSpeculationRuleSetValidation(
      *this, script_element.GetDocument(), &script_element, nullptr);
}

void SpeculationRuleSet::AddConsoleMessageForValidation(
    Document& document,
    SpeculationRulesResource& resource) {
  AddConsoleMessageForSpeculationRuleSetValidation(*this, document, nullptr,
                                                   &resource);
}

}  // namespace blink
```