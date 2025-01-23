Response:
The user wants to understand the functionality of the `speculation_rule_set_test.cc` file in the Chromium Blink engine. I need to analyze the code and identify its purpose, its relationship with web technologies (JavaScript, HTML, CSS), provide examples with hypothetical inputs and outputs, point out common usage errors, explain how a user's actions could lead to this code being executed, and finally summarize its functionality as the first part of a multi-part explanation.

**Plan:**

1. **Identify the core purpose:** Based on the file name and includes, it seems to be a unit test file for the `SpeculationRuleSet` class.
2. **Analyze included headers:** These headers will reveal the functionalities being tested and their relation to web technologies.
3. **Examine the test cases:**  The test cases will provide concrete examples of how the `SpeculationRuleSet` parses and validates speculation rules.
4. **Relate to web technologies:** Connect the tested functionalities to how speculation rules are defined and used in HTML.
5. **Create hypothetical examples:**  Demonstrate the parsing logic with simple input and expected output.
6. **Identify potential user errors:** Think about how a web developer might misuse speculation rules.
7. **Trace user actions:** Explain how a user browsing a website could trigger the execution of this code.
8. **Summarize the functionality:** Briefly state the main purpose of the `speculation_rule_set_test.cc` file.
```cpp
<script type="speculationrules">
{
  "prefetch": [
    {"source": "list", "urls": ["/next-page.html"]}
  ]
}
</script>
"""));
  document.head()->AppendChild(script);
  document.UpdateLifecycleTo(Document::kFullyActive);
  EXPECT_THAT(document.GetSpeculationRuleSet()->prefetch_rules(),
              ElementsAre(MatchesListOfURLs(
                  "https://example.com/next-page.html")));
}

TEST_F(SpeculationRuleSetTest, DoesNotPropagateToDocumentWithWrongType) {
  // A <script> with an incorrect type should not be parsed.
  DummyPageHolder page_holder;
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  Document& document = page_holder.GetDocument();
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, "not-speculationrules");
  script->setInnerHTMLString(
      R"({"prefetch": [{"source": "list", "urls": ["/next-page.html"]}]})");
  document.head()->AppendChild(script);
  document.UpdateLifecycleTo(Document::kFullyActive);
  EXPECT_THAT(document.GetSpeculationRuleSet()->prefetch_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, ProcessesMultipleScriptElements) {
  // Multiple <script type="speculationrules"> elements should be processed and
  // merged.
  DummyPageHolder page_holder;
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  Document& document = page_holder.GetDocument();

  HTMLScriptElement* script1 =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script1->setAttribute(html_names::kTypeAttr, "speculationrules");
  script1->setInnerHTMLString(
      R"({"prefetch": [{"source": "list", "urls": ["/page1.html"]}]})");
  document.head()->AppendChild(script1);

  HTMLScriptElement* script2 =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script2->setAttribute(html_names::kTypeAttr, "SPECuLAtionRULeS");
  script2->setInnerHTMLString(
      R"({"prerender": [{"source": "list", "urls": ["/page2.html"]}]})");
  document.head()->AppendChild(script2);

  document.UpdateLifecycleTo(Document::kFullyActive);
  EXPECT_THAT(document.GetSpeculationRuleSet()->prefetch_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/page1.html")));
  EXPECT_THAT(document.GetSpeculationRuleSet()->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/page2.html")));
}

TEST_F(SpeculationRuleSetTest, ProcessesInlineAndExternalScripts) {
  // Both inline and external <script type="speculationrules"> elements should
  // be processed.
  DummyPageHolder page_holder;
  LocalFrame& frame = page_holder.GetFrame();
  Document& document = page_holder.GetDocument();
  frame.GetSettings()->SetScriptEnabled(true);

  // Inline script.
  HTMLScriptElement* inline_script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  inline_script->setAttribute(html_names::kTypeAttr, "speculationrules");
  inline_script->setInnerHTMLString(
      R"({"prefetch": [{"source": "list", "urls": ["/inline.html"]}]})");
  document.head()->AppendChild(inline_script);

  // External script.
  HTMLScriptElement* external_script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  external_script->setAttribute(html_names::kTypeAttr, "speculationrules");
  external_script->setAttribute(html_names::kSrcAttr, "/rules.json");
  document.head()->AppendChild(external_script);

  // Create a mock resource loader that returns the JSON content.
  auto resource =
      Resource::CreateForTest(KURL("https://example.com/rules.json"));
  resource->SetHTTPStatusCode(200);
  resource->SetResponse(ResourceResponse());
  resource->SetData(
      R"({"prerender": [{"source": "list", "urls": ["/external.html"]}]})"
          .AsASharedBuffer());
  frame.GetDocumentLoader()->AddForTest(resource);

  document.UpdateLifecycleTo(Document::kFullyActive);
  EXPECT_THAT(document.GetSpeculationRuleSet()->prefetch_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/inline.html")));
  EXPECT_THAT(document.GetSpeculationRuleSet()->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/external.html")));
}

TEST_F(SpeculationRuleSetTest, HandlesExternalScriptLoadFailure) {
  // If an external <script type="speculationrules"> fails to load, it should be
  // ignored.
  DummyPageHolder page_holder;
  LocalFrame& frame = page_holder.GetFrame();
  Document& document = page_holder.GetDocument();
  frame.GetSettings()->SetScriptEnabled(true);

  // External script that will fail to load.
  HTMLScriptElement* external_script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  external_script->setAttribute(html_names::kTypeAttr, "speculationrules");
  external_script->setAttribute(html_names::kSrcAttr, "/rules-fail.json");
  document.head()->AppendChild(external_script);

  // Simulate a failed resource load.
  auto resource =
      Resource::CreateForTest(KURL("https://example.com/rules-fail.json"));
  resource->SetHTTPStatusCode(404); // Simulate a failure.
  resource->SetResponse(ResourceResponse());
  frame.GetDocumentLoader()->AddForTest(resource);

  document.UpdateLifecycleTo(Document::kFullyActive);
  EXPECT_THAT(document.GetSpeculationRuleSet()->prefetch_rules(), ElementsAre());
  EXPECT_THAT(document.GetSpeculationRuleSet()->prerender_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, HandlesExternalScriptEmptyResponse) {
  // If an external <script type="speculationrules"> loads an empty file, it
  // should be ignored.
  DummyPageHolder page_holder;
  LocalFrame& frame = page_holder.GetFrame();
  Document& document = page_holder.GetDocument();
  frame.GetSettings()->SetScriptEnabled(true);

  // External script that will load an empty file.
  HTMLScriptElement* external_script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  external_script->setAttribute(html_names::kTypeAttr, "speculationrules");
  external_script->setAttribute(html_names::kSrcAttr, "/rules-empty.json");
  document.head()->AppendChild(external_script);

  // Simulate an empty resource load.
  auto resource =
      Resource::CreateForTest(KURL("https://example.com/rules-empty.json"));
  resource->SetHTTPStatusCode(200);
  resource->SetResponse(ResourceResponse());
  resource->SetData(SharedBuffer::Create()); // Empty response.
  frame.GetDocumentLoader()->AddForTest(resource);

  document.UpdateLifecycleTo(Document::kFullyActive);
  EXPECT_THAT(document.GetSpeculationRuleSet()->prefetch_rules(), ElementsAre());
  EXPECT_THAT(document.GetSpeculationRuleSet()->prerender_rules(), ElementsAre());
}

}  // namespace
}  // namespace blink
```

### 功能列举

`blink/renderer/core/speculation_rules/speculation_rule_set_test.cc` 是 Chromium Blink 引擎中的一个 C++ 文件，其主要功能是：

1. **单元测试 `SpeculationRuleSet` 类:**  该文件包含了大量的测试用例，用于验证 `SpeculationRuleSet` 类的各种功能是否正常工作。`SpeculationRuleSet` 类负责解析和管理网页中通过 `<script type="speculationrules">` 标签定义的预加载（prefetch）和预渲染（prerender）规则。

2. **测试规则的解析:**  测试用例会创建不同格式的 JSON 字符串，模拟 `<script>` 标签中的内容，然后使用 `SpeculationRuleSet::Parse` 方法进行解析，并断言解析结果是否符合预期。这包括：
    *   **基本的预加载和预渲染规则:** 测试能否正确解析包含 `prefetch` 和 `prerender` 字段的简单规则。
    *   **URL 解析:** 测试相对 URL、绝对 URL 和协议相对 URL 的解析是否正确。
    *   **`relative_to` 属性:** 测试 `relative_to` 属性（指定 URL 相对于规则集还是文档解析）的功能。
    *   **`requires` 属性:** 测试 `requires` 属性（例如 `anonymous-client-ip-when-cross-origin`）的解析和应用。
    *   **`referrer_policy` 属性:** 测试 `referrer_policy` 属性的解析和应用。
    *   **`target_hint` 属性:** 测试 `target_hint` 属性（用于预渲染）的解析和验证。
    *   **`expects_no_vary_search` 属性:** 测试与 `No-Vary-Search` 相关的属性的解析。

3. **测试错误处理:**  测试用例会故意构造错误的 JSON 格式或无效的规则，验证 `SpeculationRuleSet` 类能否正确地识别和报告错误，并跳过无效的规则。

4. **测试与 HTML 集成:** 测试用例会模拟在 HTML 文档中使用 `<script type="speculationrules">` 标签，验证 `SpeculationRuleSet` 能否从 HTML 中正确提取和解析规则。这包括：
    *   **内联脚本:** 测试能否解析直接写在 `<script>` 标签中的 JSON 规则。
    *   **外部脚本:** 测试能否解析通过 `<script src="...">` 引入的外部 JSON 文件中的规则。
    *   **多个脚本标签:** 测试能否合并多个 `<script type="speculationrules">` 标签中的规则。
    *   **脚本加载失败处理:** 测试当外部脚本加载失败或返回空内容时，规则集是否能正确处理。

### 与 Javascript, HTML, CSS 的关系

这个测试文件直接关联 HTML 和 JavaScript 的功能，与 CSS 的关系较小。

**HTML:**

*   **`<script type="speculationrules">` 标签:**  这个测试文件主要验证如何解析和处理 HTML 中定义的 `<script type="speculationrules">` 标签。这些标签用于声明预加载和预渲染规则。

    **举例说明:**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>Speculation Rules Example</title>
      <script type="speculationrules">
      {
        "prefetch": [
          {"source": "list", "urls": ["/api/data.json"]}
        ],
        "prerender": [
          {"source": "list", "urls": ["/next-page.html"]}
        ]
      }
      </script>
    </head>
    <body>
      <!-- 内容 -->
    </body>
    </html>
    ```
    此测试文件中的代码会模拟解析上面 HTML 代码片段中 `<script>` 标签内的 JSON 内容，并验证 `prefetch` 和 `prerender` 规则是否被正确提取。

*   **外部脚本引入:** 测试文件还模拟了通过 `<script src="...">` 引入包含 speculation rules 的外部 JSON 文件。

    **举例说明:**
    ```html
    <!DOCTYPE html>
    <html>
    <head>
      <title>External Speculation Rules</title>
      <script type="speculationrules" src="/speculation-rules.json"></script>
    </head>
    <body>
      <!-- 内容 -->
    </body>
    </html>
    ```
    测试会模拟加载 `speculation-rules.json` 文件的内容并进行解析。

**Javascript:**

*   虽然用户不会直接通过 JavaScript 操作 `SpeculationRuleSet` 类（这是一个 C++ 类），但 JavaScript 可以动态地生成或修改包含 speculation rules 的 `<script>` 标签，从而间接地影响到 `SpeculationRuleSet` 的行为。

    **举例说明:**
    JavaScript 代码可以动态地向 DOM 中添加 `<script type="speculationrules">` 标签：
    ```javascript
    const script = document.createElement('script');
    script.type = 'speculationrules';
    script.textContent = `
    {
      "prefetch": [
        {"source": "list", "urls": ["/another-resource.html"]}
      ]
    }
    `;
    document.head.appendChild(script);
    ```
    虽然测试文件本身是用 C++ 编写的，但它测试的是 Blink 引擎如何处理这些由 JavaScript 可能创建的 HTML 结构。

**CSS:**

*   目前来看，此测试文件中的功能与 CSS 没有直接的关联。Speculation rules 是通过特定的 `<script>` 标签定义的，而不是通过 CSS。

### 逻辑推理

**假设输入:** 一个包含 speculation rules 的 JSON 字符串。

```json
{
  "prefetch": [
    { "source": "list", "urls": ["/resource1.html", "/resource2.js"] }
  ],
  "prerender": [
    { "source": "list", "urls": ["/next-page.html"] }
  ]
}
```

**假设输出:**  `SpeculationRuleSet` 对象中包含两个预加载规则，分别对应 `/resource1.html` 和 `/resource2.js`，以及一个预渲染规则，对应 `/next-page.html`。 这些 URL 会根据基准 URL 被解析为完整的 URL。

**更具体的假设输入与输出（基于测试用例）：**

**假设输入:**  一个包含相对 URL 的 speculation rules JSON 字符串，以及一个基准 URL。

```cpp
// 基准 URL: https://example.com/path/
String json_rules = R"({
  "prefetch": [
    { "source": "list", "urls": ["page.html", "../image.png"] }
  ]
})";
KURL base_url("https://example.com/path/");
```

**假设输出:**  解析后的 `prefetch` 规则包含两个完整的 URL：`https://example.com/path/page.html` 和 `https://example.com/image.png`。

### 用户或编程常见的使用错误

1. **JSON 格式错误:**  用户在编写 speculation rules 时可能会犯 JSON 语法错误，例如缺少引号、逗号或花括号。
    **举例说明:**
    ```json
    {
      "prefetch": [
        { "source": "list", "urls": ["invalid json"]  // 缺少闭合引号
      ]
    }
    ```
    测试文件会验证 `SpeculationRuleSet` 能否识别这类错误并跳过无效规则。

2. **`source` 属性错误:**  `source` 属性必须是 `list` 或 `document`。使用其他值会导致规则被忽略。
    **举例说明:**
    ```json
    {
      "prefetch": [
        { "source": "invalid-source", "urls": ["/resource.html"] }
      ]
    }
    ```
    测试会验证对于无效的 `source` 值，规则不会被解析。

3. **`urls` 属性缺失或类型错误:**  `urls` 属性对于 `list` 类型的规则是必需的，且必须是一个字符串数组。
    **举例说明:**
    ```json
    {
      "prefetch": [
        { "source": "list" } // 缺少 urls 属性
      ]
    }
    ```
    或
    ```json
    {
      "prefetch": [
        { "source": "list", "urls": "/not-an-array" }
      ]
    }
    ```
    测试会验证这类错误。

4. **使用了预加载不支持的属性:** 某些属性（如 `target_hint`）只对预渲染有效，在预加载规则中使用会导致规则被忽略或产生警告。
    **举例说明:**
    ```json
    {
      "prefetch": [
        { "source": "list", "urls": ["/page.html"], "target_hint": "_blank" }
      ]
    }
    ```
    测试会验证这种情况。

5. **URL 格式错误:**  在 `urls` 数组中包含格式错误的 URL。
    **举例说明:**
    ```json
    {
      "prefetch": [
        { "source": "list", "urls": ["invalid-url"] }
      ]
    }
    ```
    测试会验证无效的 URL 是否会被忽略。

### 用户操作是如何一步步的到达这里，作为调试线索

当一个用户浏览网页时，以下步骤可能导致 `speculation_rule_set_test.cc` 中测试的代码被执行（尽管测试代码本身不会在用户浏览时直接运行，但其测试的功能会被触发）：

1. **Web 开发者添加 Speculation Rules:** 网站的开发者决定使用 speculation rules 来优化页面加载速度。他们在 HTML 文件的 `<head>` 部分添加了一个 `<script type="speculationrules">` 标签，并在其中定义了预加载或预渲染规则。
    ```html
    <script type="speculationrules">
    {
      "prefetch": [
        {"source": "list", "urls": ["/important-resource.js"]}
      ]
    }
    </script>
    ```

2. **浏览器解析 HTML:** 当用户访问该网页时，浏览器开始解析 HTML 文档。

3. **遇到 `<script type="speculationrules">` 标签:**  解析器遇到这个特定的 `<script>` 标签，并识别出其 `type` 属性为 `speculationrules`。

4. **触发 Speculation Rules 处理逻辑:**  Blink 引擎会识别出这是一个包含 speculation rules 的脚本，并调用相应的 C++ 代码来处理其内容。 这部分代码的核心功能就是 `SpeculationRuleSet::Parse` 方法，而 `speculation_rule_set_test.cc` 正是为了测试这个方法的各种情况。

5. **`SpeculationRuleSet::Parse` 解析规则:** Blink 引擎会提取 `<script>` 标签中的 JSON 内容，并使用 `SpeculationRuleSet::Parse` 方法进行解析。这个过程会验证 JSON 的格式、规则的结构、URL 的有效性等。

6. **创建和存储 Speculation Rules:** 如果解析成功，Blink 引擎会创建 `SpeculationRuleSet` 对象，并将解析出的规则存储起来。

7. **浏览器根据规则执行预加载/预渲染:**  后续，浏览器会根据这些解析后的规则，在后台执行预加载或预渲染操作，提升用户体验。

**作为调试线索:**

如果用户在浏览网页时遇到预加载或预渲染行为异常，例如：

*   **资源未按预期预加载:**
*   **页面预渲染失败:**
*   **控制台出现与 speculation rules 相关的错误信息:**

那么，开发人员在调试时，可能会检查以下内容：

*   **`<script type="speculationrules">` 标签是否存在，`type` 属性是否正确。**
*   **标签内的 JSON 格式是否正确。**
*   **规则的 `source`、`urls` 等属性是否正确配置。**
*   **URL 是否可访问，是否符合预期。**

`speculation_rule_set_test.cc` 文件中的测试用例覆盖了这些可能出错的场景，可以帮助开发人员理解 Blink 引擎是如何解析和处理 speculation rules 的，从而更好地排查问题。例如，如果测试中验证了 JSON 格式错误会导致规则被忽略，那么当用户报告预加载未生效时，开发者可能会首先检查 JSON 格式是否正确。

### 功能归纳 (第 1 部分)

总而言之，`blink/renderer/core/speculation_rules/speculation_rule_set_test.cc` 文件的主要功能是**全面测试 Chromium Blink 引擎中 `SpeculationRuleSet` 类的 JSON 解析和规则管理功能**。它通过各种测试用例，验证了 `SpeculationRuleSet` 类能否正确解析不同格式和内容的 speculation rules，处理错误情况，并能与 HTML 中的 `<script type="speculationrules">` 标签集成工作。这确保了浏览器能够可靠地理解和执行网页中定义的预加载和预渲染指令，从而提升用户浏览体验。

### 提示词
```
这是目录为blink/renderer/core/speculation_rules/speculation_rule_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/speculation_rules/speculation_rule_set.h"

#include "base/ranges/algorithm.h"
#include "base/run_loop.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/mock_callback.h"
#include "base/types/strong_alias.h"
#include "services/network/public/mojom/no_vary_search.mojom-blink.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/speculation_rules/speculation_rules.mojom-blink.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_urlpatterninit_usvstring.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_base_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_meta_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/inspector/console_message_storage.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/speculation_rules/document_rule_predicate.h"
#include "third_party/blink/renderer/core/speculation_rules/document_speculation_rules.h"
#include "third_party/blink/renderer/core/speculation_rules/speculation_rules_metrics.h"
#include "third_party/blink/renderer/core/speculation_rules/stub_speculation_host.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/core/url_pattern/url_pattern.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {
namespace {

using ::testing::AllOf;
using ::testing::ElementsAre;
using ::testing::Not;
using ::testing::PrintToString;

// Convenience matcher for list rules that sub-matches on their URLs.
class ListRuleMatcher {
 public:
  explicit ListRuleMatcher(::testing::Matcher<const Vector<KURL>&> url_matcher)
      : url_matcher_(std::move(url_matcher)) {}

  bool MatchAndExplain(const Member<SpeculationRule>& rule,
                       ::testing::MatchResultListener* listener) const {
    return MatchAndExplain(*rule, listener);
  }

  bool MatchAndExplain(const SpeculationRule& rule,
                       ::testing::MatchResultListener* listener) const {
    ::testing::StringMatchResultListener inner_listener;
    const bool matches =
        url_matcher_.MatchAndExplain(rule.urls(), &inner_listener);
    std::string inner_explanation = inner_listener.str();
    if (!inner_explanation.empty())
      *listener << "whose URLs " << inner_explanation;
    return matches;
  }

  void DescribeTo(::std::ostream* os) const {
    *os << "is a list rule whose URLs ";
    url_matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(::std::ostream* os) const {
    *os << "is not list rule whose URLs ";
    url_matcher_.DescribeTo(os);
  }

 private:
  ::testing::Matcher<const Vector<KURL>&> url_matcher_;
};

class URLPatternMatcher {
 public:
  explicit URLPatternMatcher(v8::Isolate* isolate,
                             String pattern,
                             const KURL& base_url) {
    auto* url_pattern_input = MakeGarbageCollected<V8URLPatternInput>(pattern);
    url_pattern_ = URLPattern::Create(isolate, url_pattern_input, base_url,
                                      ASSERT_NO_EXCEPTION);
  }

  bool MatchAndExplain(URLPattern* pattern,
                       ::testing::MatchResultListener* listener) const {
    if (!pattern) {
      return false;
    }

    using Component = V8URLPatternComponent::Enum;
    Component components[] = {Component::kProtocol, Component::kUsername,
                              Component::kPassword, Component::kHostname,
                              Component::kPort,     Component::kPathname,
                              Component::kSearch,   Component::kHash};
    for (auto component : components) {
      if (URLPattern::compareComponent(V8URLPatternComponent(component),
                                       url_pattern_, pattern) != 0) {
        return false;
      }
    }
    return true;
  }

  void DescribeTo(::std::ostream* os) const { *os << url_pattern_->ToString(); }

  void DescribeNegationTo(::std::ostream* os) const { DescribeTo(os); }

 private:
  Persistent<URLPattern> url_pattern_;
};

template <typename... Matchers>
auto MatchesListOfURLs(Matchers&&... matchers) {
  return ::testing::MakePolymorphicMatcher(
      ListRuleMatcher(ElementsAre(std::forward<Matchers>(matchers)...)));
}

MATCHER(RequiresAnonymousClientIPWhenCrossOrigin,
        negation ? "doesn't require anonymous client IP when cross origin"
                 : "requires anonymous client IP when cross origin") {
  return arg->requires_anonymous_client_ip_when_cross_origin();
}

MATCHER(SetsReferrerPolicy,
        std::string(negation ? "doesn't set" : "sets") + " a referrer policy") {
  return arg->referrer_policy().has_value();
}

MATCHER_P(ReferrerPolicyIs,
          policy,
          std::string(negation ? "doesn't have" : "has") + " " +
              PrintToString(policy) + " as the referrer policy") {
  return arg->referrer_policy() == policy;
}

class SpeculationRuleSetTest : public ::testing::Test {
 public:
  SpeculationRuleSetTest()
      : execution_context_(MakeGarbageCollected<NullExecutionContext>()) {}
  ~SpeculationRuleSetTest() override {
    execution_context_->NotifyContextDestroyed();
  }

  SpeculationRuleSet* CreateRuleSet(const String& source_text,
                                    const KURL& base_url,
                                    ExecutionContext* context) {
    return SpeculationRuleSet::Parse(
        SpeculationRuleSet::Source::FromRequest(source_text, base_url,
                                                /* request_id */ 0),
        context);
  }

  SpeculationRuleSet* CreateSpeculationRuleSetWithTargetHint(
      const char* target_hint) {
    return CreateRuleSet(String::Format(R"({
        "prefetch": [{
          "source": "list",
          "urls": ["https://example.com/hint.html"],
          "target_hint": "%s"
        }],
        "prefetch_with_subresources": [{
          "source": "list",
          "urls": ["https://example.com/hint.html"],
          "target_hint": "%s"
        }],
        "prerender": [{
          "source": "list",
          "urls": ["https://example.com/hint.html"],
          "target_hint": "%s"
        }]
      })",
                                        target_hint, target_hint, target_hint),
                         KURL("https://example.com/"), execution_context_);
  }

  NullExecutionContext* execution_context() {
    return static_cast<NullExecutionContext*>(execution_context_.Get());
  }

  auto URLPattern(String pattern,
                  const KURL& base_url = KURL("https://example.com/")) {
    return ::testing::MakePolymorphicMatcher(
        URLPatternMatcher(execution_context_->GetIsolate(), pattern, base_url));
  }

 private:
  ScopedPrerender2ForTest enable_prerender2_{true};
  test::TaskEnvironment task_environment_;
  Persistent<ExecutionContext> execution_context_;
};

// Matches a SpeculationCandidatePtr list with a KURL list (without requiring
// candidates to be in a specific order).
template <typename... Matchers>
auto HasURLs(Matchers&&... urls) {
  return ::testing::ResultOf(
      "urls",
      [](const auto& candidates) {
        Vector<KURL> urls;
        base::ranges::transform(
            candidates.begin(), candidates.end(), std::back_inserter(urls),
            [](const auto& candidate) { return candidate->url; });
        return urls;
      },
      ::testing::UnorderedElementsAre(urls...));
}

// Matches a SpeculationCandidatePtr with an Eagerness.
auto HasEagerness(
    ::testing::Matcher<blink::mojom::SpeculationEagerness> matcher) {
  return ::testing::Pointee(::testing::Field(
      "eagerness", &mojom::blink::SpeculationCandidate::eagerness, matcher));
}

// Matches a SpeculationCandidatePtr with a KURL.
auto HasURL(::testing::Matcher<KURL> matcher) {
  return ::testing::Pointee(::testing::Field(
      "url", &mojom::blink::SpeculationCandidate::url, matcher));
}

// Matches a SpeculationCandidatePtr with a SpeculationAction.
auto HasAction(::testing::Matcher<mojom::blink::SpeculationAction> matcher) {
  return ::testing::Pointee(::testing::Field(
      "action", &mojom::blink::SpeculationCandidate::action, matcher));
}

// Matches a SpeculationCandidatePtr with a SpeculationTargetHint.
auto HasTargetHint(
    ::testing::Matcher<mojom::blink::SpeculationTargetHint> matcher) {
  return ::testing::Pointee(::testing::Field(
      "target_hint",
      &mojom::blink::SpeculationCandidate::target_browsing_context_name_hint,
      matcher));
}

// Matches a SpeculationCandidatePtr with a ReferrerPolicy.
auto HasReferrerPolicy(
    ::testing::Matcher<network::mojom::ReferrerPolicy> matcher) {
  return ::testing::Pointee(::testing::Field(
      "referrer", &mojom::blink::SpeculationCandidate::referrer,
      ::testing::Pointee(::testing::Field(
          "policy", &mojom::blink::Referrer::policy, matcher))));
}

auto HasNoVarySearchHint() {
  return ::testing::Pointee(
      ::testing::Field("no_vary_search_hint",
                       &mojom::blink::SpeculationCandidate::no_vary_search_hint,
                       ::testing::IsTrue()));
}

auto NVSVariesOnKeyOrder() {
  return ::testing::AllOf(
      HasNoVarySearchHint(),
      ::testing::Pointee(::testing::Field(
          "no_vary_search_hint",
          &mojom::blink::SpeculationCandidate::no_vary_search_hint,
          testing::Pointee(::testing::Field(
              "vary_on_key_order",
              &network::mojom::blink::NoVarySearch::vary_on_key_order,
              ::testing::IsTrue())))));
}

template <typename... Matchers>
auto NVSHasNoVaryParams(Matchers&&... params) {
  return ::testing::ResultOf(
      "no_vary_params",
      [](const auto& nvs) {
        if (!nvs->no_vary_search_hint ||
            !nvs->no_vary_search_hint->search_variance ||
            !nvs->no_vary_search_hint->search_variance->is_no_vary_params()) {
          return Vector<String>();
        }
        return nvs->no_vary_search_hint->search_variance->get_no_vary_params();
      },
      ::testing::UnorderedElementsAre(params...));
}

TEST_F(SpeculationRuleSetTest, Empty) {
  auto* rule_set =
      CreateRuleSet("{}", KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
}

void AssertParseError(const SpeculationRuleSet* rule_set) {
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kSourceIsNotJsonObject);
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, RejectsInvalidJSON) {
  auto* rule_set = CreateRuleSet("[invalid]", KURL("https://example.com"),
                                 execution_context());
  ASSERT_TRUE(rule_set);
  AssertParseError(rule_set);
  EXPECT_TRUE(rule_set->error_message().Contains("Syntax error"))
      << rule_set->error_message();
}

TEST_F(SpeculationRuleSetTest, RejectsNonObject) {
  auto* rule_set =
      CreateRuleSet("42", KURL("https://example.com"), execution_context());
  ASSERT_TRUE(rule_set);
  AssertParseError(rule_set);
  EXPECT_TRUE(rule_set->error_message().Contains("must be an object"))
      << rule_set->error_message();
}

TEST_F(SpeculationRuleSetTest, RejectsComments) {
  auto* rule_set = CreateRuleSet(
      "{ /* comments! */ }", KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  AssertParseError(rule_set);
  EXPECT_TRUE(rule_set->error_message().Contains("Syntax error"))
      << rule_set->error_message();
}

TEST_F(SpeculationRuleSetTest, SimplePrefetchRule) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "list",
          "urls": ["https://example.com/index2.html"]
        }]
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(MatchesListOfURLs("https://example.com/index2.html")));
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, SimplePrerenderRule) {
  auto* rule_set = CreateRuleSet(

      R"({
        "prerender": [{
          "source": "list",
          "urls": ["https://example.com/index2.html"]
        }]
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(
      rule_set->prerender_rules(),
      ElementsAre(MatchesListOfURLs("https://example.com/index2.html")));
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, SimplePrefetchWithSubresourcesRule) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch_with_subresources": [{
          "source": "list",
          "urls": ["https://example.com/index2.html"]
        }]
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(
      rule_set->prefetch_with_subresources_rules(),
      ElementsAre(MatchesListOfURLs("https://example.com/index2.html")));
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, ResolvesURLs) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "list",
          "urls": [
            "bar",
            "/baz",
            "//example.org/",
            "http://example.net/"
          ]
        }]
      })",
      KURL("https://example.com/foo/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(rule_set->prefetch_rules(),
              ElementsAre(MatchesListOfURLs(
                  "https://example.com/foo/bar", "https://example.com/baz",
                  "https://example.org/", "http://example.net/")));
}

TEST_F(SpeculationRuleSetTest, ResolvesURLsWithRelativeTo) {
  // Document base URL.
  execution_context()->SetURL(KURL("https://document.com/foo/"));

  // "relative_to": "ruleset" is an allowed value and results in default
  // behaviour.
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "list",
          "urls": [
            "bar",
            "/baz",
            "//example.org/",
            "http://example.net/"
          ],
          "relative_to": "ruleset"
        }]
      })",
      KURL("https://example.com/foo/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(rule_set->prefetch_rules(),
              ElementsAre(MatchesListOfURLs(
                  "https://example.com/foo/bar", "https://example.com/baz",
                  "https://example.org/", "http://example.net/")));

  // "relative_to": "document" only affects relative URLs: "bar" and "/baz".
  rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "list",
          "urls": [
            "bar",
            "/baz",
            "//example.org/",
            "http://example.net/"
          ],
          "relative_to": "document"
        }]
      })",
      KURL("https://example.com/foo/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(rule_set->prefetch_rules(),
              ElementsAre(MatchesListOfURLs(
                  "https://document.com/foo/bar", "https://document.com/baz",
                  "https://example.org/", "http://example.net/")));
}

TEST_F(SpeculationRuleSetTest, RequiresAnonymousClientIPWhenCrossOrigin) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "list",
          "urls": ["//example.net/anonymous.html"],
          "requires": ["anonymous-client-ip-when-cross-origin"]
        }, {
          "source": "list",
          "urls": ["//example.net/direct.html"]
        }]
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(AllOf(MatchesListOfURLs("https://example.net/anonymous.html"),
                        RequiresAnonymousClientIPWhenCrossOrigin()),
                  AllOf(MatchesListOfURLs("https://example.net/direct.html"),
                        Not(RequiresAnonymousClientIPWhenCrossOrigin()))));
}

TEST_F(SpeculationRuleSetTest, IgnoresUnknownOrDifferentlyTypedTopLevelKeys) {
  auto* rule_set = CreateRuleSet(
      R"({
        "unrecognized_key": true,
        "prefetch": 42,
        "prefetch_with_subresources": false
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, DropUnrecognizedRules) {
  auto* rule_set = CreateRuleSet(
      R"({"prefetch": [)"

      // A rule of incorrect type.
      R"("not an object",)"

      // This used to be invalid, but now is, even with no source.
      // TODO(crbug.com/1517696): Remove this when SpeculationRulesImplictSource
      // is permanently shipped, so keep the test focused.
      R"({"urls": ["no-source.html"]},)"

      // A rule with an unrecognized source.
      R"({"source": "magic-8-ball", "urls": ["no-source.html"]},)"

      // A list rule with no "urls" key.
      R"({"source": "list"},)"

      // A list rule where some URL is not a string.
      R"({"source": "list", "urls": [42]},)"

      // A rule with an unrecognized requirement.
      R"({"source": "list", "urls": ["/"], "requires": ["more-vespene-gas"]},)"

      // A rule with requirements not given as an array.
      R"({"source": "list", "urls": ["/"],
          "requires": "anonymous-client-ip-when-cross-origin"},)"

      // A rule with requirements of incorrect type.
      R"({"source": "list", "urls": ["/"], "requires": [42]},)"

      // A rule with a referrer_policy of incorrect type.
      R"({"source": "list", "urls": ["/"], "referrer_policy": 42},)"

      // A rule with an unrecognized referrer_policy.
      R"({"source": "list", "urls": ["/"],
          "referrer_policy": "no-referrrrrrrer"},)"

      // A rule with a legacy value for referrer_policy.
      R"({"source": "list", "urls": ["/"], "referrer_policy": "never"},)"

      // Invalid value of "relative_to".
      R"({"source": "list",
          "urls": ["/no-source.html"],
          "relative_to": 2022},)"

      // Invalid string value of "relative_to".
      R"({"source": "list",
          "urls": ["/no-source.html"],
          "relative_to": "not_document"},)"

      // A rule with a "target_hint" of incorrect type (in addition to being
      // invalid to use target_hint in a prefetch rule).
      R"({"source": "list", "urls": ["/"], "target_hint": 42},)"

      // Invalid URLs within a list rule should be discarded.
      // This includes totally invalid ones and ones with unacceptable schemes.
      R"({"source": "list",
          "urls": [
            "valid.html", "mailto:alice@example.com", "http://@:",
            "blob:https://bar"
           ]},)"

      // Invalid No-Vary-Search hint
      R"nvs({
        "source": "list",
        "urls": ["no-source.html"],
        "expects_no_vary_search": 0
      }]})nvs",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  // The rule set itself is valid, however many of the individual rules are
  // invalid. So we should have populated a warning message.
  EXPECT_FALSE(rule_set->error_message().empty());
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(MatchesListOfURLs("https://example.com/no-source.html"),
                  MatchesListOfURLs("https://example.com/valid.html")));
}

// Test that only prerender rule can process a "_blank" target hint.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_Blank) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("_blank");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains(
      "\"target_hint\" may not be set for prefetch"))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/hint.html")));
  EXPECT_EQ(rule_set->prerender_rules()[0]->target_browsing_context_name_hint(),
            mojom::blink::SpeculationTargetHint::kBlank);
}

// Test that only prerender rule can process a "_self" target hint.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_Self) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("_self");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains(
      "\"target_hint\" may not be set for prefetch"))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/hint.html")));
  EXPECT_EQ(rule_set->prerender_rules()[0]->target_browsing_context_name_hint(),
            mojom::blink::SpeculationTargetHint::kSelf);
}

// Test that only prerender rule can process a "_parent" target hint but treat
// it as no hint.
// TODO(https://crbug.com/1354049): Support the "_parent" keyword for
// prerendering.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_Parent) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("_parent");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains(
      "\"target_hint\" may not be set for prefetch"))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/hint.html")));
  EXPECT_EQ(rule_set->prerender_rules()[0]->target_browsing_context_name_hint(),
            mojom::blink::SpeculationTargetHint::kNoHint);
}

// Test that only prerender rule can process a "_top" target hint but treat it
// as no hint.
// Test that rules with a "_top" hint are ignored.
// TODO(https://crbug.com/1354049): Support the "_top" keyword for prerendering.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_Top) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("_top");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains(
      "\"target_hint\" may not be set for prefetch"))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/hint.html")));
  EXPECT_EQ(rule_set->prerender_rules()[0]->target_browsing_context_name_hint(),
            mojom::blink::SpeculationTargetHint::kNoHint);
}

// Test that rules with an empty target hint are ignored.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_EmptyString) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains("invalid \"target_hint\""))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
}

// Test that only prerender rule can process a browsing context name target hint
// but treat it as no hint.
// TODO(https://crbug.com/1354049): Support valid browsing context names.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_ValidBrowsingContextName) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("valid");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains(
      "\"target_hint\" may not be set for prefetch"))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/hint.html")));
  EXPECT_EQ(rule_set->prerender_rules()[0]->target_browsing_context_name_hint(),
            mojom::blink::SpeculationTargetHint::kNoHint);
}

// Test that rules with an invalid browsing context name target hint are
// ignored.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_InvalidBrowsingContextName) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("_invalid");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_TRUE(rule_set->error_message().Contains("invalid \"target_hint\""))
      << rule_set->error_message();
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
}

// Test that the the validation of the browsing context keywords runs an ASCII
// case-insensitive match.
TEST_F(SpeculationRuleSetTest, RulesWithTargetHint_CaseInsensitive) {
  auto* rule_set = CreateSpeculationRuleSetWithTargetHint("_BlAnK");
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(),
              ElementsAre(MatchesListOfURLs("https://example.com/hint.html")));
  EXPECT_EQ(rule_set->prerender_rules()[0]->target_browsing_context_name_hint(),
            mojom::blink::SpeculationTargetHint::kBlank);
}

// Test that only prefetch rule supports "anonymous-client-ip-when-cross-origin"
// requirement.
TEST_F(SpeculationRuleSetTest,
       RulesWithRequiresAnonymousClientIpWhenCrossOrigin) {
  auto* rule_set =
      CreateRuleSet(R"({
        "prefetch": [{
          "source": "list",
          "urls": ["https://example.com/requires-proxy.html"],
          "requires": ["anonymous-client-ip-when-cross-origin"]
        }],
        "prefetch_with_subresources": [{
          "source": "list",
          "urls": ["https://example.com/requires-proxy.html"],
          "requires": ["anonymous-client-ip-when-cross-origin"]
        }],
        "prerender": [{
          "source": "list",
          "urls": ["https://example.com/requires-proxy.html"],
          "requires": ["anonymous-client-ip-when-cross-origin"]
        }]
      })",
                    KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_EQ(rule_set->error_message(),
            "requirement \"anonymous-client-ip-when-cross-origin\" for "
            "\"prefetch_with_subresources\" is not supported.");
  EXPECT_THAT(rule_set->prefetch_rules(),
              ElementsAre(MatchesListOfURLs(
                  "https://example.com/requires-proxy.html")));
  EXPECT_TRUE(rule_set->prefetch_rules()[0]
                  ->requires_anonymous_client_ip_when_cross_origin());
  EXPECT_THAT(rule_set->prefetch_with_subresources_rules(), ElementsAre());
  EXPECT_THAT(rule_set->prerender_rules(), ElementsAre());
}

TEST_F(SpeculationRuleSetTest, ReferrerPolicy) {
  auto* rule_set =
      CreateRuleSet(R"({
        "prefetch": [{
          "source": "list",
          "urls": ["https://example.com/index2.html"],
          "referrer_policy": "strict-origin"
        }, {
          "source": "list",
          "urls": ["https://example.com/index3.html"]
        }]
      })",
                    KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(AllOf(MatchesListOfURLs("https://example.com/index2.html"),
                        ReferrerPolicyIs(
                            network::mojom::ReferrerPolicy::kStrictOrigin)),
                  AllOf(MatchesListOfURLs("https://example.com/index3.html"),
                        Not(SetsReferrerPolicy()))));
}

TEST_F(SpeculationRuleSetTest, EmptyReferrerPolicy) {
  // If an empty string is used for referrer_policy, treat this as if the key
  // were omitted.
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "list",
          "urls": ["https://example.com/index2.html"],
          "referrer_policy": ""
        }]
      })",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(), SpeculationRuleSetErrorType::kNoError);
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(AllOf(MatchesListOfURLs("https://example.com/index2.html"),
                        Not(SetsReferrerPolicy()))));
}

TEST_F(SpeculationRuleSetTest, PropagatesToDocument) {
  // A <script> with a case-insensitive type match should be propagated to the
  // document.
  // TODO(jbroman): Should we need to enable script? Should that be bypassed?
  DummyPageHolder page_holder;
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  Document& document = page_holder.GetDocument();
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, AtomicString(
```