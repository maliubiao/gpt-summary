Response:
Let's break down the thought process for analyzing this code and generating the detailed explanation.

1. **Understand the Goal:** The primary goal is to explain the functionality of the `document_rule_predicate.cc` file in the Chromium Blink engine, particularly its relation to JavaScript, HTML, CSS, and potential debugging scenarios.

2. **Initial Scan and Keyword Recognition:**  Start by quickly scanning the code for recognizable keywords and structures. Keywords like `Copyright`, `include`, `namespace blink`, class definitions (`Conjunction`, `Disjunction`, `Negation`, `URLPatternPredicate`, `CSSSelectorPredicate`), and comments referencing specifications (`wicg.github.io/nav-speculation`) are good starting points. The file name itself, "speculation_rules," is a strong indicator of its purpose.

3. **Identify Core Classes:** Notice the distinct classes derived from `DocumentRulePredicate`. These likely represent different types of conditions or predicates used in speculation rules. Focus on understanding the purpose of each class.

4. **Analyze Class Functionality:**  For each class:
    * **Constructor:** Understand what data each class holds (member variables).
    * **`Matches()` method:** This is likely the core logic. How does each predicate determine if a given `HTMLAnchorElementBase` (an anchor tag) matches its criteria?
    * **`GetStyleRules()` method:** Why is this here, and what does it return? It seems related to CSS selectors.
    * **`ToString()` method:**  This is for debugging and logging, providing a string representation of the predicate.
    * **`GetTypeForTesting()` and `GetSubPredicatesForTesting()`:** These are for internal testing and introspection of the predicate structure.
    * **Trace method:** This is for Blink's garbage collection mechanism.

5. **Connect to Speculation Rules:** The comments and the file name point to the "Navigation Speculation Rules" specification. The class names (`Conjunction`, `Disjunction`, `Negation`) map directly to logical operators used in constructing complex rules. `URLPatternPredicate` and `CSSSelectorPredicate` clearly represent filtering based on URL patterns and CSS selectors.

6. **Identify Input Sources (Parsing):** Look for static methods responsible for creating `DocumentRulePredicate` objects. The `Parse()` method is crucial. Analyze how it processes JSON input to create different predicate types. Pay attention to the different JSON keys it handles (`and`, `or`, `not`, `href_matches`, `selector_matches`). This is where the connection to HTML (through the `href` attribute and CSS selectors) is evident.

7. **Connect to Web Technologies:**
    * **HTML:** The `Matches()` methods operate on `HTMLAnchorElementBase`, which represents `<a>` tags. The `href_matches` predicate directly relates to the `href` attribute.
    * **CSS:** The `CSSSelectorPredicate` directly uses CSS selectors to match elements. The `GetStyleRules()` method, present in all predicate types (though potentially empty), hints at the association with CSS rules.
    * **JavaScript:** While the C++ code doesn't directly *execute* JavaScript, it *interprets* data likely derived from `<script>` tags containing JSON for speculation rules. The parsing of URL patterns uses V8 types, indicating interaction with the JavaScript engine.

8. **Illustrate with Examples:** Create concrete examples to demonstrate how each predicate type works and how they relate to HTML, CSS, and potential JSON input. This makes the explanation much clearer.

9. **Consider User Errors and Debugging:** Think about how a developer might misuse speculation rules and how this code would be involved in debugging. Focus on parsing errors (invalid JSON, incorrect keys, invalid selectors/URLs) as common problems. The `out_error` parameter in the `Parse()` method is a key indicator of error handling.

10. **Trace User Actions:**  Outline the steps a user would take to trigger the processing of speculation rules, leading to this code. This helps understand the context and how this file fits into the larger browser workflow.

11. **Structure the Explanation:** Organize the information logically:
    * Start with a general overview of the file's purpose.
    * Explain each class and its functionality.
    * Detail the parsing process and its connection to web technologies.
    * Provide illustrative examples.
    * Discuss user errors and debugging.
    * Describe the user actions leading to this code.

12. **Refine and Review:** Review the explanation for clarity, accuracy, and completeness. Ensure that technical terms are explained or are clear from the context. Make sure the examples are easy to understand. Double-check the connections to JavaScript, HTML, and CSS.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file seems to handle some kind of matching logic."  **Refinement:** "It's specifically about matching anchor elements based on rules defined in JSON, likely for prefetching or prerendering."
* **Initial thought:** "The `GetStyleRules()` seems out of place." **Refinement:** "It's used to store the CSS selectors associated with the predicate, which are derived from the parsed JSON."
* **Initial thought:** "The parsing logic is complex." **Refinement:** "Focus on the different types of predicates and how the JSON structure maps to these types. The error handling (`out_error`) is important."
* **Initial thought:** "How does this relate to user actions?" **Refinement:** "Users don't directly interact with this C++ code, but their actions trigger the browser to parse and apply speculation rules."

By following these steps and engaging in a process of analysis, connection, and refinement, one can create a comprehensive and accurate explanation of the functionality of the given code file.
好的，这是对 `blink/renderer/core/speculation_rules/document_rule_predicate.cc` 文件的功能进行详细的分析：

**文件功能概述:**

`document_rule_predicate.cc` 文件定义了用于表示和解析“文档规则谓词”（Document Rule Predicate）的 C++ 类。这些谓词是“导航推测规则”（Navigation Speculation Rules）机制的核心组成部分，用于确定页面上的哪些链接符合预加载或预渲染的条件。

简单来说，这个文件负责：

1. **定义谓词的抽象接口：**  `DocumentRulePredicate` 是一个抽象基类，定义了所有具体谓词类型需要实现的基本功能，例如判断一个链接是否匹配 (`Matches`)，获取相关的 CSS 样式规则 (`GetStyleRules`)，以及用于调试和测试的方法。

2. **实现不同类型的谓词：**  文件中实现了多种具体的谓词类型，每种类型都基于不同的匹配条件：
   * **`Conjunction` (逻辑与):**  只有当所有子谓词都匹配时，该谓词才匹配。
   * **`Disjunction` (逻辑或):** 只要其中一个子谓词匹配，该谓词就匹配。
   * **`Negation` (逻辑非):**  当其子谓词不匹配时，该谓词才匹配。
   * **`URLPatternPredicate` (URL 模式匹配):**  根据指定的 URL 模式（可以使用通配符等）匹配链接的 `href` 属性。
   * **`CSSSelectorPredicate` (CSS 选择器匹配):**  根据指定的 CSS 选择器匹配链接元素。

3. **解析 JSON 格式的谓词定义：**  文件中包含 `Parse` 静态方法，用于将包含谓词定义的 JSON 对象解析成对应的 `DocumentRulePredicate` 对象。

**与 JavaScript, HTML, CSS 的关系和举例说明:**

这个文件虽然是用 C++ 编写的，但它与 Web 前端技术（JavaScript, HTML, CSS）紧密相关，因为导航推测规则通常在 HTML 中通过 `<script>` 标签以 JSON 格式定义，并利用 CSS 选择器来指定目标链接。

* **HTML:**
    * **关联:**  谓词最终作用于 HTML 中的链接元素 (`<a>` 标签）。`Matches` 方法接收 `HTMLAnchorElementBase` 类型的参数。
    * **举例:**  一个推测规则可能会指定预加载所有 `class="prefetch"` 的链接。 `CSSSelectorPredicate` 就能用于实现这种规则，它会检查 `<a>` 标签是否拥有指定的 class。

* **CSS:**
    * **关联:** `CSSSelectorPredicate` 直接使用 CSS 选择器来匹配元素。`GetStyleRules` 方法也与 CSS 样式规则相关，尽管在这个文件中它的直接用途主要是存储和传递与选择器相关的规则。
    * **举例:**
        ```html
        <a href="/page1" id="link1">Page 1</a>
        <a href="/page2" class="prefetch">Page 2</a>
        ```
        如果推测规则中定义了一个 `CSSSelectorPredicate`，其选择器为 `.prefetch`，那么它将匹配到 "Page 2" 的链接。

* **JavaScript:**
    * **关联:**  导航推测规则通常以 JSON 格式嵌入在 HTML 页面的 `<script type="speculationrules">` 标签中。  `DocumentRulePredicate::Parse` 方法负责解析这些 JSON 数据。
    * **举例:**  一个包含谓词定义的 JSON 可能如下所示：
        ```json
        {
          "where": {
            "or": [
              { "href_matches": "/products/*" },
              { "selector_matches": ".featured-link" }
            ]
          },
          "speculate": {
            "prerender": true
          }
        }
        ```
        `DocumentRulePredicate::Parse` 会将这个 JSON 结构解析成一个 `Disjunction` 谓词，它包含一个 `URLPatternPredicate`（匹配 `/products/*`）和一个 `CSSSelectorPredicate`（匹配 `.featured-link`）。

**逻辑推理的假设输入与输出:**

假设我们有以下 JSON 格式的谓词定义：

**输入 (JSON):**

```json
{
  "where": {
    "and": [
      { "href_matches": "*.example.com" },
      { "not": { "href_matches": "https://old.example.com/*" } }
    ]
  }
}
```

**逻辑推理:**

1. `Parse` 方法会识别顶层的 "and"，创建一个 `Conjunction` 对象。
2. `Conjunction` 对象包含两个子谓词。
3. 第一个子谓词是 `URLPatternPredicate`，它匹配所有 `href` 属性包含 `*.example.com` 的链接。
4. 第二个子谓词是 `Negation`，它包含一个 `URLPatternPredicate`，该谓词匹配所有 `href` 属性以 `https://old.example.com/` 开头的链接。`Negation` 会反转这个结果。

**假设输入 (HTML 链接) 与输出 (匹配结果):**

| HTML 链接 (`href`)             | 匹配结果 | 原因                                                                                                                               |
| ------------------------------- | -------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `https://www.example.com/page` | 是       | 满足第一个条件 (`*.example.com`) 且不满足第二个条件 (`https://old.example.com/*`)。                                                      |
| `https://old.example.com/page` | 否       | 满足第一个条件 (`*.example.com`) 但也满足第二个条件的否定条件（所以最终不匹配）。                                                              |
| `https://other.com/page`       | 否       | 不满足第一个条件 (`*.example.com`)。                                                                                                  |

**用户或编程常见的使用错误及其举例说明:**

1. **JSON 格式错误:**  在 `<script type="speculationrules">` 中编写的 JSON 可能存在语法错误，导致解析失败。
   * **例子:**  缺少逗号、引号不匹配等。Chrome 的开发者工具控制台通常会显示 JSON 解析错误。

2. **谓词类型拼写错误或使用了无效的类型:** `Parse` 方法会检查 JSON 中指定的谓词类型 (`and`, `or`, `not`, `href_matches`, `selector_matches`)，如果拼写错误或使用了不支持的类型，解析会失败。
   * **例子:**  将 `"href_matches"` 错误地拼写为 `"href-match"`。

3. **`href_matches` 的值不是字符串、对象或字符串/对象数组:**  `ParseRawPattern` 函数会检查 `href_matches` 的值类型是否正确。
   * **例子:**  将 `href_matches` 的值设置为一个数字 `{"href_matches": 123}`。

4. **`selector_matches` 的值不是字符串或字符串数组:** `Parse` 方法会检查 `selector_matches` 的值类型。
   * **例子:**  将 `selector_matches` 的值设置为一个布尔值 `{"selector_matches": true}`。

5. **无效的 URL 模式或 CSS 选择器:**  提供的 URL 模式或 CSS 选择器可能无法被 Blink 的解析器识别。
   * **例子 (URL):**  使用了无效的正则表达式语法。
   * **例子 (CSS):**  使用了浏览器不支持的 CSS 伪类或伪元素。解析器会返回错误，导致谓词创建失败。

6. **逻辑组合错误:**  `and`, `or`, `not` 的嵌套使用可能导致意想不到的结果，或者规则变得过于复杂难以理解和维护。
   * **例子:**  创建一个过于复杂的嵌套 `and` 和 `or` 的谓词，使得难以判断哪些链接会被匹配。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者在 HTML 页面中添加 `<script type="speculationrules">` 标签:**  这是用户定义导航推测规则的入口。
2. **在 `<script>` 标签中编写 JSON 格式的推测规则:**  这个 JSON 包含了 `where` 字段，其中定义了文档规则谓词。
3. **浏览器加载并解析 HTML 页面:**  Blink 引擎会解析这个 `<script>` 标签。
4. **识别出 `type="speculationrules"`:**  Blink 会知道这是一个导航推测规则的定义。
5. **解析 JSON 数据:**  `third_party/blink/renderer/platform/json/json_parse.cc` 等文件会将 JSON 字符串解析成 `JSONObject` 等数据结构。
6. **调用 `DocumentRulePredicate::Parse`:**  Blink 会调用这个静态方法来将 JSON 对象转换为 `DocumentRulePredicate` 对象。
7. **`Parse` 方法根据 JSON 结构创建具体的谓词对象:**  例如，如果 JSON 中有 `"and"` 字段，就会创建 `Conjunction` 对象。
8. **当页面上有链接并且推测机制被触发时:**  例如，当鼠标悬停在一个符合条件的链接上时。
9. **Blink 会遍历定义的推测规则和谓词:**  对于每个链接，会调用谓词的 `Matches` 方法来判断是否应该对该链接进行预加载或预渲染。
10. **`Matches` 方法根据具体的谓词类型执行匹配逻辑:** 例如，`URLPatternPredicate::Matches` 会检查链接的 `href` 是否匹配定义的 URL 模式。
11. **如果谓词匹配成功，并且满足其他条件，则执行推测操作。**

**调试线索:**

* **查看开发者工具的 "Network" 面板:**  可以观察到哪些资源被预加载或预渲染，从而推断哪些规则和谓词生效了。
* **使用 "Application" 面板的 "Speculation Rules" 部分 (如果 Chrome 提供了相关工具):**  可以查看已解析的推测规则和谓词的结构。
* **在 `DocumentRulePredicate::Parse` 方法中设置断点:**  可以跟踪 JSON 是如何被解析成谓词对象的，检查中间状态和变量值，排查解析错误。
* **在各个谓词的 `Matches` 方法中设置断点:**  可以了解特定链接是如何被匹配或不被匹配的，检查 `href` 属性、CSS 样式等信息。
* **检查控制台输出的错误信息:**  Blink 通常会在控制台输出 JSON 解析错误或无效的 URL 模式/CSS 选择器等信息。

总而言之，`document_rule_predicate.cc` 是 Blink 引擎中处理导航推测规则中链接匹配逻辑的关键部分，它负责将 JSON 定义的规则转换为 C++ 对象，并根据定义的条件判断页面上的链接是否符合推测的条件。理解这个文件的工作原理对于调试和优化基于推测规则的性能提升至关重要。

Prompt: 
```
这是目录为blink/renderer/core/speculation_rules/document_rule_predicate.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/speculation_rules/document_rule_predicate.h"

#include "base/containers/contains.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_urlpatterninit_usvstring.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_url_pattern_init.h"
#include "third_party/blink/renderer/core/css/parser/css_parser.h"
#include "third_party/blink/renderer/core/css/style_rule.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/url_pattern/url_pattern.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/json/json_values.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// Represents a document rule conjunction:
// https://wicg.github.io/nav-speculation/speculation-rules.html#document-rule-conjunction.
class Conjunction : public DocumentRulePredicate {
 public:
  explicit Conjunction(HeapVector<Member<DocumentRulePredicate>> clauses)
      : clauses_(std::move(clauses)) {}
  ~Conjunction() override = default;

  bool Matches(const HTMLAnchorElementBase& el) const override {
    return base::ranges::all_of(clauses_, [&](DocumentRulePredicate* clause) {
      return clause->Matches(el);
    });
  }

  HeapVector<Member<StyleRule>> GetStyleRules() const override {
    HeapVector<Member<StyleRule>> rules;
    for (DocumentRulePredicate* clause : clauses_) {
      rules.AppendVector(clause->GetStyleRules());
    }
    return rules;
  }

  String ToString() const override {
    StringBuilder builder;
    builder.Append("And(");
    for (wtf_size_t i = 0; i < clauses_.size(); i++) {
      builder.Append(clauses_[i]->ToString());
      if (i != clauses_.size() - 1)
        builder.Append(", ");
    }
    builder.Append(")");
    return builder.ReleaseString();
  }

  Type GetTypeForTesting() const override { return Type::kAnd; }

  HeapVector<Member<DocumentRulePredicate>> GetSubPredicatesForTesting()
      const override {
    return clauses_;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(clauses_);
    DocumentRulePredicate::Trace(visitor);
  }

 private:
  HeapVector<Member<DocumentRulePredicate>> clauses_;
};

// Represents a document rule disjunction:
// https://wicg.github.io/nav-speculation/speculation-rules.html#document-rule-disjunction.
class Disjunction : public DocumentRulePredicate {
 public:
  explicit Disjunction(HeapVector<Member<DocumentRulePredicate>> clauses)
      : clauses_(std::move(clauses)) {}
  ~Disjunction() override = default;

  bool Matches(const HTMLAnchorElementBase& el) const override {
    return base::ranges::any_of(clauses_, [&](DocumentRulePredicate* clause) {
      return clause->Matches(el);
    });
  }

  HeapVector<Member<StyleRule>> GetStyleRules() const override {
    HeapVector<Member<StyleRule>> rules;
    for (DocumentRulePredicate* clause : clauses_) {
      rules.AppendVector(clause->GetStyleRules());
    }
    return rules;
  }

  String ToString() const override {
    StringBuilder builder;
    builder.Append("Or(");
    for (wtf_size_t i = 0; i < clauses_.size(); i++) {
      builder.Append(clauses_[i]->ToString());
      if (i != clauses_.size() - 1)
        builder.Append(", ");
    }
    builder.Append(")");
    return builder.ReleaseString();
  }

  Type GetTypeForTesting() const override { return Type::kOr; }

  HeapVector<Member<DocumentRulePredicate>> GetSubPredicatesForTesting()
      const override {
    return clauses_;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(clauses_);
    DocumentRulePredicate::Trace(visitor);
  }

 private:
  HeapVector<Member<DocumentRulePredicate>> clauses_;
};

// Represents a document rule negation:
// https://wicg.github.io/nav-speculation/speculation-rules.html#document-rule-negation.
class Negation : public DocumentRulePredicate {
 public:
  explicit Negation(DocumentRulePredicate* clause) : clause_(clause) {}
  ~Negation() override = default;

  bool Matches(const HTMLAnchorElementBase& el) const override {
    return !clause_->Matches(el);
  }

  HeapVector<Member<StyleRule>> GetStyleRules() const override {
    return clause_->GetStyleRules();
  }

  String ToString() const override {
    StringBuilder builder;
    builder.Append("Not(");
    builder.Append(clause_->ToString());
    builder.Append(")");
    return builder.ReleaseString();
  }

  Type GetTypeForTesting() const override { return Type::kNot; }

  HeapVector<Member<DocumentRulePredicate>> GetSubPredicatesForTesting()
      const override {
    HeapVector<Member<DocumentRulePredicate>> result;
    result.push_back(clause_);
    return result;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(clause_);
    DocumentRulePredicate::Trace(visitor);
  }

 private:
  Member<DocumentRulePredicate> clause_;
};

}  // namespace

// Represents a document rule URL pattern predicate:
// https://wicg.github.io/nav-speculation/speculation-rules.html#document-rule-url-pattern-predicate
class URLPatternPredicate : public DocumentRulePredicate {
 public:
  explicit URLPatternPredicate(HeapVector<Member<URLPattern>> patterns,
                               ExecutionContext* execution_context)
      : patterns_(std::move(patterns)), execution_context_(execution_context) {}
  ~URLPatternPredicate() override = default;

  bool Matches(const HTMLAnchorElementBase& el) const override {
    // Let href be the result of running el’s href getter steps.
    const KURL href = el.HrefURL();
    // For each pattern of predicate’s patterns:
    for (const auto& pattern : patterns_) {
      // Match given pattern and href. If the result is not null, return true.
      if (pattern->test(ToScriptStateForMainWorld(execution_context_),
                        MakeGarbageCollected<V8URLPatternInput>(href),
                        ASSERT_NO_EXCEPTION)) {
        return true;
      }
    }
    return false;
  }

  HeapVector<Member<StyleRule>> GetStyleRules() const override { return {}; }

  String ToString() const override {
    StringBuilder builder;
    builder.Append("Href([");
    for (wtf_size_t i = 0; i < patterns_.size(); i++) {
      builder.Append(patterns_[i]->ToString());
      if (i != patterns_.size() - 1)
        builder.Append(", ");
    }
    builder.Append("])");
    return builder.ReleaseString();
  }

  Type GetTypeForTesting() const override { return Type::kURLPatterns; }

  HeapVector<Member<URLPattern>> GetURLPatternsForTesting() const override {
    return patterns_;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(patterns_);
    visitor->Trace(execution_context_);
    DocumentRulePredicate::Trace(visitor);
  }

 private:
  HeapVector<Member<URLPattern>> patterns_;
  Member<ExecutionContext> execution_context_;
};

// Represents a document rule CSS selector predicate:
// https://wicg.github.io/nav-speculation/speculation-rules.html#document-rule-css-selector-predicate
class CSSSelectorPredicate : public DocumentRulePredicate {
 public:
  explicit CSSSelectorPredicate(HeapVector<Member<StyleRule>> style_rules)
      : style_rules_(std::move(style_rules)) {}

  bool Matches(const HTMLAnchorElementBase& link) const override {
    DCHECK(!link.GetDocument().NeedsLayoutTreeUpdate());
    const ComputedStyle* computed_style = link.GetComputedStyle();
    DCHECK(computed_style);
    DCHECK(!DisplayLockUtilities::LockedAncestorPreventingStyle(link));
    const Persistent<HeapHashSet<WeakMember<StyleRule>>>& matched_selectors =
        computed_style->DocumentRulesSelectors();
    if (!matched_selectors) {
      return false;
    }

    for (StyleRule* style_rule : style_rules_) {
      if (matched_selectors->Contains(style_rule)) {
        return true;
      }
    }
    return false;
  }

  HeapVector<Member<StyleRule>> GetStyleRules() const override {
    return style_rules_;
  }

  String ToString() const override {
    StringBuilder builder;
    builder.Append("Selector([");
    for (wtf_size_t i = 0; i < style_rules_.size(); i++) {
      builder.Append(style_rules_[i]->SelectorsText());
      if (i != style_rules_.size() - 1) {
        builder.Append(", ");
      }
    }
    builder.Append("])");
    return builder.ReleaseString();
  }

  Type GetTypeForTesting() const override { return Type::kCSSSelectors; }

  HeapVector<Member<StyleRule>> GetStyleRulesForTesting() const override {
    return style_rules_;
  }

  void Trace(Visitor* visitor) const override {
    visitor->Trace(style_rules_);
    DocumentRulePredicate::Trace(visitor);
  }

 private:
  HeapVector<Member<StyleRule>> style_rules_;
};

namespace {
// If `out_error` is provided and hasn't already had a message set, sets it to
// `message`.
void SetParseErrorMessage(String* out_error, String message) {
  if (out_error && out_error->IsNull()) {
    *out_error = message;
  }
}

URLPattern* ParseRawPattern(v8::Isolate* isolate,
                            JSONValue* raw_pattern,
                            const KURL& base_url,
                            ExceptionState& exception_state,
                            String* out_error) {
  // If rawPattern is a string, then:
  if (String raw_string; raw_pattern->AsString(&raw_string)) {
    // Set pattern to the result of constructing a URLPattern using the
    // URLPattern(input, baseURL) constructor steps given rawPattern and
    // serializedBaseURL.
    V8URLPatternInput* url_pattern_input =
        MakeGarbageCollected<V8URLPatternInput>(raw_string);
    return URLPattern::Create(isolate, url_pattern_input, base_url,
                              exception_state);
  }
  // Otherwise, if rawPattern is a map
  if (JSONObject* pattern_object = JSONObject::Cast(raw_pattern)) {
    // Let init be «[ "baseURL" → serializedBaseURL ]», representing a
    // dictionary of type URLPatternInit.
    URLPatternInit* init = URLPatternInit::Create();
    init->setBaseURL(base_url);

    // For each key -> value of rawPattern:
    for (wtf_size_t i = 0; i < pattern_object->size(); i++) {
      JSONObject::Entry entry = pattern_object->at(i);
      String key = entry.first;
      String value;
      // If value is not a string
      if (!entry.second->AsString(&value)) {
        SetParseErrorMessage(
            out_error, "Values for a URL pattern object must be strings.");
        return nullptr;
      }

      // Set init[key] to value.
      if (key == "protocol") {
        init->setProtocol(value);
      } else if (key == "username") {
        init->setUsername(value);
      } else if (key == "password") {
        init->setPassword(value);
      } else if (key == "hostname") {
        init->setHostname(value);
      } else if (key == "port") {
        init->setPort(value);
      } else if (key == "pathname") {
        init->setPathname(value);
      } else if (key == "search") {
        init->setSearch(value);
      } else if (key == "hash") {
        init->setHash(value);
      } else if (key == "baseURL") {
        init->setBaseURL(value);
      } else {
        SetParseErrorMessage(
            out_error,
            String::Format("Invalid key \"%s\" for a URL pattern object found.",
                           key.Latin1().c_str()));
        return nullptr;
      }
    }

    // Set pattern to the result of constructing a URLPattern using the
    // URLPattern(input, baseURL) constructor steps given init.
    V8URLPatternInput* url_pattern_input =
        MakeGarbageCollected<V8URLPatternInput>(init);
    return URLPattern::Create(isolate, url_pattern_input, exception_state);
  }
  SetParseErrorMessage(out_error,
                       "Value for \"href_matches\" should either be a "
                       "string, an object, or a list of strings and objects.");
  return nullptr;
}

String GetPredicateType(JSONObject* input, String* out_error) {
  String predicate_type;
  constexpr const char* kValidTypes[] = {"and", "or", "not", "href_matches",
                                         "selector_matches"};
  for (String type : kValidTypes) {
    if (input->Get(type)) {
      // If we'd already found one, then this is ambiguous.
      if (!predicate_type.IsNull()) {
        SetParseErrorMessage(
            out_error,
            String::Format("Document rule predicate type is ambiguous, "
                           "two types found: \"%s\" and \"%s\".",
                           predicate_type.Latin1().c_str(),
                           type.Latin1().c_str()));
        return String();
      }

      // Otherwise, this is the predicate type.
      predicate_type = std::move(type);
    }
  }
  if (predicate_type.IsNull()) {
    SetParseErrorMessage(out_error,
                         "Could not infer type of document rule predicate, no "
                         "valid type specified.");
  }
  return predicate_type;
}
}  // namespace

// static
DocumentRulePredicate* DocumentRulePredicate::Parse(
    JSONObject* input,
    const KURL& ruleset_base_url,
    ExecutionContext* execution_context,
    ExceptionState& exception_state,
    String* out_error) {
  // If input is not a map, then return null.
  if (!input) {
    SetParseErrorMessage(out_error,
                         "Document rule predicate must be an object.");
    return nullptr;
  }

  // If we can't get a valid predicate type, return null.
  String predicate_type = GetPredicateType(input, out_error);
  if (predicate_type.IsNull())
    return nullptr;

  // If predicateType is "and" or "or"
  if (predicate_type == "and" || predicate_type == "or") {
    // "and" and "or" cannot be paired with any other keys.
    if (input->size() != 1) {
      SetParseErrorMessage(
          out_error,
          String::Format(
              "Document rule predicate with \"%s\" key cannot have other keys.",
              predicate_type.Latin1().c_str()));
      return nullptr;
    }
    // Let rawClauses be the input[predicateType].
    blink::JSONArray* raw_clauses = input->GetArray(predicate_type);

    // If rawClauses is not a list, then return null.
    if (!raw_clauses) {
      SetParseErrorMessage(
          out_error, String::Format("\"%s\" key should have a list value.",
                                    predicate_type.Latin1().c_str()));
      return nullptr;
    }

    // Let clauses be an empty list.
    HeapVector<Member<DocumentRulePredicate>> clauses;
    clauses.ReserveInitialCapacity(raw_clauses->size());
    // For each rawClause of rawClauses:
    for (wtf_size_t i = 0; i < raw_clauses->size(); i++) {
      JSONObject* raw_clause = JSONObject::Cast(raw_clauses->at(i));
      // Let clause be the result of parsing a document rule predicate given
      // rawClause and baseURL.
      DocumentRulePredicate* clause =
          Parse(raw_clause, ruleset_base_url, execution_context,
                exception_state, out_error);
      // If clause is null, then return null.
      if (!clause)
        return nullptr;
      // Append clause to clauses.
      clauses.push_back(clause);
    }

    // If predicateType is "and", then return a document rule conjunction whose
    // clauses is clauses.
    if (predicate_type == "and")
      return MakeGarbageCollected<Conjunction>(std::move(clauses));
    // If predicateType is "or", then return a document rule disjunction whose
    // clauses is clauses.
    if (predicate_type == "or")
      return MakeGarbageCollected<Disjunction>(std::move(clauses));
  }

  // If predicateType is "not"
  if (predicate_type == "not") {
    // "not" cannot be paired with any other keys.
    if (input->size() != 1) {
      SetParseErrorMessage(
          out_error,
          "Document rule predicate with \"not\" key cannot have other keys.");
      return nullptr;
    }
    // Let rawClause be the input[predicateType].
    JSONObject* raw_clause = input->GetJSONObject(predicate_type);

    // Let clause be the result of parsing a document rule predicate given
    // rawClause and baseURL.
    DocumentRulePredicate* clause =
        Parse(raw_clause, ruleset_base_url, execution_context, exception_state,
              out_error);

    // If clause is null, then return null.
    if (!clause)
      return nullptr;

    // Return a document rule negation whose clause is clause.
    return MakeGarbageCollected<Negation>(clause);
  }

  // If predicateType is "href_matches"
  if (predicate_type == "href_matches") {
    // Explainer:
    // https://github.com/WICG/nav-speculation/blob/main/triggers.md#using-the-documents-base-url-for-external-speculation-rule-sets

    // For now, use the ruleset's base URL to construct the predicates.
    KURL base_url = ruleset_base_url;

    for (wtf_size_t i = 0; i < input->size(); ++i) {
      const String key = input->at(i).first;
      if (key == "href_matches") {
        // This is always expected.
      } else if (key == "relative_to") {
        const char* const kKnownRelativeToValues[] = {"ruleset", "document"};
        // If relativeTo is neither the string "ruleset" nor the string
        // "document", then return null.
        String relative_to;
        if (!input->GetString("relative_to", &relative_to) ||
            !base::Contains(kKnownRelativeToValues, relative_to)) {
          SetParseErrorMessage(
              out_error,
              String::Format(
                  "Unrecognized \"relative_to\" value: %s.",
                  input->Get("relative_to")->ToJSONString().Latin1().c_str()));
          return nullptr;
        }
        // If relativeTo is "document", set baseURL to the document's
        // document base URL.
        if (relative_to == "document") {
          base_url = execution_context->BaseURL();
        }
      } else {
        // Otherwise, this is an unrecognized key. The predicate is invalid.
        SetParseErrorMessage(out_error,
                             String::Format("Unrecognized key found: \"%s\".",
                                            key.Latin1().c_str()));
        return nullptr;
      }
    }

    // Let rawPatterns be input["href_matches"].
    Vector<JSONValue*> raw_patterns;
    JSONArray* href_matches = input->GetArray("href_matches");
    if (href_matches) {
      for (wtf_size_t i = 0; i < href_matches->size(); i++) {
        raw_patterns.push_back(href_matches->at(i));
      }
    } else {
      // If rawPatterns is not a list, then set rawPatterns to « rawPatterns ».
      raw_patterns.push_back(input->Get("href_matches"));
    }
    // Let patterns be an empty list.
    HeapVector<Member<URLPattern>> patterns;
    // For each rawPattern of rawPatterns:
    for (JSONValue* raw_pattern : raw_patterns) {
      URLPattern* pattern =
          ParseRawPattern(execution_context->GetIsolate(), raw_pattern,
                          base_url, IGNORE_EXCEPTION, out_error);
      // If those steps throw, `pattern` will be null. Ignore the exception and
      // return null.
      if (!pattern) {
        SetParseErrorMessage(
            out_error,
            String::Format(
                "URL Pattern for \"href_matches\" could not be parsed: %s.",
                raw_pattern->ToJSONString().Latin1().c_str()));
        return nullptr;
      }
      // Append pattern to patterns.
      patterns.push_back(pattern);
    }
    // Return a document rule URL pattern predicate whose patterns is patterns.
    return MakeGarbageCollected<URLPatternPredicate>(std::move(patterns),
                                                     execution_context);
  }

  // If predicateType is "selector_matches"
  if (predicate_type == "selector_matches" && input->size() == 1) {
    // Let rawSelectors be input["selector_matches"].
    Vector<JSONValue*> raw_selectors;
    JSONArray* selector_matches = input->GetArray("selector_matches");
    if (selector_matches) {
      for (wtf_size_t i = 0; i < selector_matches->size(); i++) {
        raw_selectors.push_back(selector_matches->at(i));
      }
    } else {
      // If rawSelectors is not a list, then set rawSelectors to « rawSelectors
      // ».
      raw_selectors.push_back(input->Get("selector_matches"));
    }
    // Let selectors be an empty list.
    HeapVector<Member<StyleRule>> selectors;
    HeapVector<CSSSelector> arena;
    CSSPropertyValueSet* empty_properties =
        ImmutableCSSPropertyValueSet::Create(base::span<CSSPropertyValue>(),
                                             kUASheetMode);
    CSSParserContext* css_parser_context =
        MakeGarbageCollected<CSSParserContext>(*execution_context);
    for (auto* raw_selector : raw_selectors) {
      String raw_selector_string;
      // If rawSelector is not a string, then return null.
      if (!raw_selector->AsString(&raw_selector_string)) {
        SetParseErrorMessage(out_error,
                             "Value for \"selector_matches\" must be a string "
                             "or a list of strings.");
        return nullptr;
      }

      // Parse a selector from rawSelector. If the result is failure, then
      // return null. Otherwise, let selector be the result.
      base::span<CSSSelector> selector_vector = CSSParser::ParseSelector(
          css_parser_context, CSSNestingType::kNone,
          /*parent_rule_for_nesting=*/nullptr, /*is_within_scope=*/false,
          nullptr, raw_selector_string, arena);
      if (selector_vector.empty()) {
        SetParseErrorMessage(
            out_error, String::Format("\"%s\" is not a valid selector.",
                                      raw_selector_string.Latin1().c_str()));
        return nullptr;
      }
      StyleRule* selector =
          StyleRule::Create(selector_vector, empty_properties);
      // Append selector to selectors.
      selectors.push_back(std::move(selector));
    }
    UseCounter::Count(execution_context,
                      WebFeature::kSpeculationRulesSelectorMatches);
    return MakeGarbageCollected<CSSSelectorPredicate>(std::move(selectors));
  }

  return nullptr;
}

// static
DocumentRulePredicate* DocumentRulePredicate::MakeDefaultPredicate() {
  return MakeGarbageCollected<Conjunction>(
      HeapVector<Member<DocumentRulePredicate>>());
}

HeapVector<Member<DocumentRulePredicate>>
DocumentRulePredicate::GetSubPredicatesForTesting() const {
  NOTREACHED();
}

HeapVector<Member<URLPattern>> DocumentRulePredicate::GetURLPatternsForTesting()
    const {
  NOTREACHED();
}

HeapVector<Member<StyleRule>> DocumentRulePredicate::GetStyleRulesForTesting()
    const {
  NOTREACHED();
}

void DocumentRulePredicate::Trace(Visitor*) const {}

}  // namespace blink

"""

```