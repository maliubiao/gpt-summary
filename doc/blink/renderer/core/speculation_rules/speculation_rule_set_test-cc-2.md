Response:
The user wants a summary of the functionality of the provided C++ code. The code is a test file for the `SpeculationRuleSet` class in the Chromium Blink engine. I need to identify the features being tested. These tests seem to focus on:

1. **Parsing Speculation Rules:**  How the engine parses JSON-like rule sets. This includes testing valid and invalid syntax, and how errors are handled (skipped rules, console warnings).
2. **Matching Rules to Elements:** Specifically testing the `href_matches` and `selector_matches` predicates to determine if a link or element matches a rule. This involves different ways of specifying URLs and selectors, including relative URLs and base URLs.
3. **Generating Speculation Candidates:** How the engine identifies URLs to prefetch or prerender based on the rules and the links/elements in the document. This includes testing scenarios where links are added, removed, or modified after the rules are loaded. It also includes links in shadow DOM.
4. **Combining Rules:** Testing how different types of rules (document and list) interact.
5. **Specifying Extra Parameters:** Testing how attributes like `expects_no_vary_search` and `requires` are handled.
6. **Handling Different Link Types:** Testing with both `<a>` and `<area>` elements.

Now I need to structure this into a concise summary for the user, specifically for the *third* part of a six-part response. This means focusing on the functionality covered in the provided code snippet, not the overall scope of speculation rules.

Based on the code provided, the key functionalities demonstrated are:

* **Testing `href_matches` with different base URL scenarios.**
* **Testing the handling of invalid rules and ensuring they are dropped.**
* **Testing console warnings for invalid rules.**
* **Testing specific error messages for invalid rule syntax.**
* **Testing the evaluation of logical operators (`and`, `or`, `not`) in predicates.**
* **Testing the evaluation of the `href_matches` predicate.**
* **Testing how document rules identify initial speculation candidates based on existing links.**
* **Testing how document rules update speculation candidates when links are modified.**
这是对 blink 引擎中 `SpeculationRuleSet` 类的测试文件的一部分，主要关注以下功能：

**核心功能归纳（针对提供的代码片段）：**

* **测试 `href_matches` 谓词的各种用法和解析：**
    * 验证 `href_matches` 可以匹配绝对 URL 和相对 URL。
    * 测试 `baseURL` 和 `relative_to` 属性如何影响 `href_matches` 的匹配行为。
    * 覆盖了基于文档自身 URL 和规则集 URL 解析相对路径的情况。
* **测试无效规则的丢弃和错误处理：**
    * 验证各种格式错误的 speculation rule 会被正确地识别并丢弃，而不会导致程序崩溃。
    * 测试了各种 JSON 格式错误、键值错误、类型错误以及逻辑错误的规则。
* **测试针对无效规则的控制台警告：**
    * 验证当遇到格式错误的 rule 时，会在控制台输出相应的警告信息。
* **测试文档规则的解析错误：**
    * 验证了特定于文档规则的错误，例如在顶级包含 `relative_to` 或 `urls` 键的情况。
* **测试文档规则谓词的解析错误：**
    * 验证了各种格式错误的谓词，例如类型不明确、缺少必要键、键值类型错误、URL 格式错误、选择器格式错误等。
* **测试默认谓词：**
    * 验证当文档规则没有 `where` 子句时，会使用默认的 “匹配所有” 谓词。
* **测试组合谓词的求值：**
    * 验证 `and`、`or` 和 `not` 逻辑组合符在谓词求值中的行为。
* **测试 `href_matches` 谓词的求值：**
    * 验证 `href_matches` 可以匹配单个或多个 URL 模式。
* **测试在初始化后报告推测候选项：**
    * 验证在页面加载后，如果添加了包含 `source: "document"` 的推测规则，会根据现有的链接生成推测候选项。
    * 包含对 `expects_no_vary_search` 的测试，确保推测候选项能够携带 No-Vary-Search 提示。
* **测试在链接修改后更新推测候选项：**
    * 验证当页面上的链接的 `href` 属性发生改变时，推测候选项列表会相应地更新。
* **测试在规则集改变后更新推测候选项：**
    * 验证添加或移除 speculation rules `<script>` 标签时，推测候选项列表会动态更新。

**与 JavaScript, HTML, CSS 的关系：**

* **JavaScript:**  Speculation Rules 通常通过 `<script type="speculationrules">` 标签嵌入到 HTML 中，其内容是 JSON 格式的规则。这段测试代码模拟了 JavaScript 生成和插入这些规则的过程，并测试引擎解析这些规则的能力。
* **HTML:** 测试代码模拟了 HTML 结构，特别是 `<a>` 标签（链接）的存在和属性变化。`href_matches` 谓词会根据 HTML 中 `<a>` 标签的 `href` 属性进行匹配。
* **CSS:** `selector_matches` 谓词（虽然在此部分代码中没有重点测试，但在 `DropInvalidRules` 测试中有涉及）会使用 CSS 选择器来匹配 HTML 元素。

**逻辑推理、假设输入与输出：**

* **假设输入（针对 `HrefMatchesWithBaseURL` 测试）：**
    * 当前页面的 URL 为 `http://foo.com`。
    * Speculation Rule 定义了 `href_matches: "hello"`，没有指定 `baseURL`。
* **预期输出：**  `href_matches` 会相对于当前页面的 URL 进行匹配，因此匹配 `http://foo.com/hello`。

* **假设输入（针对 `HrefMatchesWithBaseURLAndRelativeTo` 测试）：**
    * 当前页面的 URL 为 `http://bar.com`。
    * Speculation Rule 定义了 `href_matches: "/hello"` 和 `relative_to: "document"`。
* **预期输出：** `href_matches` 会相对于当前文档的 URL（即 `http://bar.com`）进行匹配，因此匹配 `http://bar.com/hello`。

**用户或编程常见的使用错误举例：**

* **JSON 格式错误：** 用户在编写 speculation rules 时，JSON 格式不正确，例如缺少引号、逗号错误等。测试中的 `DropInvalidRules` 就覆盖了很多这类情况。
    ```json
    // 错误示例：缺少引号
    { "prefetch": [ { source: "document" } ] }
    ```
* **错误的谓词结构：**  用户定义的 `where` 子句不符合规范，例如同时使用了 `and` 和 `or` 键，或者键的值类型错误。`DropInvalidRules` 和 `DocumentRulePredicateParseErrors` 测试了这些情况。
    ```json
    // 错误示例：同时使用 "and" 和 "or"
    { "prefetch": [ { "source": "document", "where": { "and": [], "or": [] } } ] }
    ```
* **错误的 URL 模式：**  在 `href_matches` 中使用了无法解析的 URL 模式。
    ```json
    // 错误示例：无效的 URL 格式
    { "prefetch": [ { "source": "document", "where": { "href_matches": "https//:" } } ] }
    ```
* **错误的 CSS 选择器：** 在 `selector_matches` 中使用了无效的 CSS 选择器。
    ```json
    // 错误示例：无效的 CSS 选择器
    { "prefetch": [ { "source": "document", "where": { "selector_matches": "#invalid#" } } ] }
    ```

**用户操作到达此处的调试线索：**

1. **开发者在 HTML 中添加了 `<script type="speculationrules">` 标签。**
2. **该标签包含了 JSON 格式的 speculation rules。**
3. **浏览器解析 HTML，遇到了这个 `<script>` 标签。**
4. **Blink 引擎的 SpeculationRuleSet 相关代码开始解析这些规则。**
5. **如果在解析过程中遇到错误，例如 `DropInvalidRules` 测试覆盖的情况，引擎会尝试跳过这些错误的规则并可能在控制台输出警告。**
6. **如果规则解析成功，引擎会根据 `source: "document"` 的规则，遍历当前文档中的链接 (`<a>` 和 `<area>` 标签)。**
7. **引擎会根据规则中的 `where` 子句（例如 `href_matches`），判断哪些链接符合条件，并将符合条件的链接添加到推测候选项列表中。**
8. **当页面上的链接被添加、删除或修改时，引擎会重新评估规则，并更新推测候选项列表。**
9. **开发者可以通过浏览器的开发者工具（Console）查看可能的错误警告，或者通过 Network 面板观察预加载/预渲染的请求来判断 speculation rules 是否生效。**
10. **如果怀疑 speculation rules 没有按预期工作，开发者可能会查看 Blink 引擎的源代码或者相关的测试用例（例如这个文件）来理解其内部逻辑和可能出现的问题。**

总而言之，这个测试文件专注于验证 Blink 引擎正确解析和应用 speculation rules 中 `href_matches` 相关的谓词，并能妥善处理各种格式错误的情况，以及在页面动态变化时如何更新推测候选项。

Prompt: 
```
这是目录为blink/renderer/core/speculation_rules/speculation_rule_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
)", KURL("http://foo.com"));
  EXPECT_THAT(without_base_specified,
              Href({URLPattern("http://foo.com/hello")}));
  auto* with_base_specified = CreatePredicate(
      R"("href_matches": {"pathname": "hello", "baseURL": "http://bar.com"})",
      KURL("http://foo.com"));
  EXPECT_THAT(with_base_specified, Href({URLPattern("http://bar.com/hello")}));
}

// Testing on http://bar.com requesting a ruleset from http://foo.com.
TEST_F(DocumentRulesTest, HrefMatchesWithBaseURLAndRelativeTo) {
  execution_context()->SetURL(KURL{"http://bar.com"});

  auto* with_relative_to = CreatePredicate(
      R"(
        "href_matches": "/hello",
        "relative_to": "document"
      )",
      KURL("http://foo.com"));
  EXPECT_THAT(with_relative_to, Href({URLPattern("http://bar.com/hello")}));

  auto* relative_to_no_effect = CreatePredicate(
      R"(
        "href_matches": {"pathname": "/hello", "baseURL": "http://buz.com"},
        "relative_to": "document"
      )",
      KURL("http://foo.com"));
  EXPECT_THAT(relative_to_no_effect,
              Href({URLPattern("http://buz.com/hello")}));

  auto* nested_relative_to = CreatePredicate(
      R"(
        "or": [
          {
            "href_matches": {"pathname": "/hello"},
            "relative_to": "document"
          },
          {"not": {"href_matches": "/world"}}
        ]
      )",
      KURL("http://foo.com/"));

  EXPECT_THAT(nested_relative_to,
              Or({Href({URLPattern("http://bar.com/hello")}),
                  Neg(Href({URLPattern("http://foo.com/world")}))}));

  auto* relative_to_ruleset = CreatePredicate(R"(
        "href_matches": {"pathname": "/hello"},
        "relative_to": "ruleset"
      )",
                                              KURL("http://foo.com"));
  EXPECT_THAT(relative_to_ruleset, Href({URLPattern("http://foo.com/hello")}));
}

TEST_F(DocumentRulesTest, DropInvalidRules) {
  auto* rule_set = CreateRuleSet(
      R"({"prefetch": [)"

      // A rule that doesn't elaborate on its source (previously disallowed).
      // TODO(crbug.com/1517696): Remove this when SpeculationRulesImplictSource
      // is permanently shipped, so keep the test focused.
      R"({"where": {"and": []}},)"

      // A rule with an unrecognized source.
      R"({"source": "magic-8-ball", "where": {"and": []}},)"

      // A list rule with a "where" key.
      R"({"source": "list", "where": {"and": []}},)"

      // A document rule with a "urls" key.
      R"({"source": "document", "urls": ["foo.html"]},)"

      // "where" clause is not a map.
      R"({"source": "document", "where": [{"and": []}]},)"

      // "where" clause does not contain one of "and", "or", "not",
      // "href_matches" and "selector_matches"
      R"({"source": "document", "where": {"foo": "bar"}},)"

      // "where" clause has both "and" and "or" as keys
      R"({"source": "document", "where": {"and": [], "or": []}},)"

      // "and" key has object value.
      R"({"source": "document", "where": {"and": {}}},)"

      // "or" key has object value.
      R"({"source": "document", "where": {"or": {}}},)"

      // "and" key has invalid list value.
      R"({"source": "document", "where": {"and": ["foo"]}},)"

      // "not" key has list value.
      R"({"source": "document", "where": {"not": [{"and": []}]}},)"

      // "not" key has empty object value.
      R"({"source": "document", "where": {"not": {}}},)"

      // "not" key has invalid object value.
      R"({"source": "document", "where": {"not": {"foo": "bar"}}},)"

      // pattern is not a string or map value.
      R"({"source": "document", "where": {"href_matches": false}},)"

      // pattern string is invalid.
      R"({"source": "document", "where": {"href_matches": "::"}},)"

      // pattern object has invalid key.
      R"({"source": "document", "where": {"href_matches": {"foo": "bar"}}},)"

      // pattern object has invalid value.
      R"({"source": "document",
          "where": {"href_matches": {"protocol": "::"}}},)"

      // Invalid key pairs.
      R"({
          "source": "document",
          "where": {"href_matches": "/hello.html",
                    "invalid_key": "invalid_val"}
        },)"

      // Invalid values of "relative_to".
      R"({
          "source": "document",
          "where": {"href_matches": "/hello.html",
                    "relative_to": 2022}
        },)"
      R"({
          "source": "document",
          "where": {"href_matches": "/hello.html",
                    "relative_to": "not_document"}
        },)"

      // "relative_to" appears at speculation rule level instead of the
      // "href_matches" clause.
      R"({
          "source": "document",
          "where": {"href_matches": "/hello"},
          "relative_to": "document"
        },)"

      // Currently the spec does not allow three keys.
      R"({"source": "document",
          "where":{"href_matches": "/hello.html",
                   "relative_to": "document",
                   "world-cup": "2022"}},)"

      // "selector_matches" paired with another key.
      R"({"source": "document",
          "where": {"selector_matches": ".valid", "second": "value"}
        },)"

      // "selector_matches" with an object value.
      R"({"source": "document",
          "where": {"selector_matches": {"selector": ".valid"}}
        },)"

      // "selector_matches" with an invalid CSS selector.
      R"({"source": "document",
          "where": {"selector_matches": "#invalid#"}
        },)"

      // "selector_matches" with a list with an object.
      R"({"source": "document",
          "where": {"selector_matches": [{"selector": ".valid"}]}
        },)"

      // "selector_matches" with a list with one valid and one invalid CSS
      // selector.
      R"({"source": "document",
        "where": {"selector_matches": [".valid", "#invalid#"]}
        },)"

      // Invalid no-vary-search hint value.
      R"({"source": "list",
        "urls": ["/prefetch/list/page1.html"],
        "expects_no_vary_search": 0
        },)"

      // Both "where" and "urls" with implicit source.
      R"({"urls": ["/"], "where": {"selector_matches": "*"}},)"

      // Neither "where" nor "urls" with implicit source.
      R"({},)"

      // valid document rule.
      R"({"source": "document",
        "where": {"and": [
          {"or": [{"href_matches": "/hello.html"},
                  {"selector_matches": ".valid"}]},
          {"not": {"and": [{"href_matches": {"hostname": "world.com"}}]}}
        ]}
    }]})",
      KURL("https://example.com/"), execution_context());
  ASSERT_TRUE(rule_set);
  EXPECT_EQ(rule_set->error_type(),
            SpeculationRuleSetErrorType::kInvalidRulesSkipped);
  EXPECT_THAT(
      rule_set->prefetch_rules(),
      ElementsAre(
          MatchesPredicate(And({})),
          MatchesPredicate(
              And({Or({Href({URLPattern("/hello.html")}),
                       Selector({StyleRuleWithSelectorText(".valid")})}),
                   Neg(And({Href({URLPattern("https://world.com:*")})}))}))));
}

// Tests that errors of individual rules which cause them to be ignored are
// logged to the console.
TEST_F(DocumentRulesTest, ConsoleWarningForInvalidRule) {
  auto* chrome_client = MakeGarbageCollected<ConsoleCapturingChromeClient>();
  DummyPageHolder page_holder(/*initial_view_size=*/{}, chrome_client);
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);

  Document& document = page_holder.GetDocument();
  HTMLScriptElement* script =
      MakeGarbageCollected<HTMLScriptElement>(document, CreateElementFlags());
  script->setAttribute(html_names::kTypeAttr, AtomicString("speculationrules"));
  script->setText(
      R"({
        "prefetch": [{
          "source": "document",
          "where": {"and": [], "or": []}
        }]
      })");
  document.head()->appendChild(script);

  EXPECT_TRUE(base::ranges::any_of(
      chrome_client->ConsoleMessages(), [](const String& message) {
        return message.Contains("Document rule predicate type is ambiguous");
      }));
}

TEST_F(DocumentRulesTest, DocumentRuleParseErrors) {
  auto* rule_set1 =
      CreateRuleSet(R"({"prefetch": [{
    "source": "document", "relative_to": "document"
  }]})",
                    KURL("https://example.com"), execution_context());
  EXPECT_THAT(
      rule_set1->error_message().Utf8(),
      ::testing::HasSubstr("A document rule cannot have \"relative_to\" "
                           "outside the \"where\" clause"));

  auto* rule_set2 =
      CreateRuleSet(R"({"prefetch": [{
    "source": "document",
    "urls": ["/one",  "/two"]
  }]})",
                    KURL("https://example.com"), execution_context());
  EXPECT_THAT(
      rule_set2->error_message().Utf8(),
      ::testing::HasSubstr("A document rule cannot have a \"urls\" key"));
}

TEST_F(DocumentRulesTest, DocumentRulePredicateParseErrors) {
  String parse_error;

  parse_error = CreateInvalidPredicate(R"("and": [], "not": {})");
  EXPECT_THAT(
      parse_error.Utf8(),
      ::testing::HasSubstr(
          "Document rule predicate type is ambiguous, two types found"));

  parse_error = CreateInvalidPredicate(R"()");
  EXPECT_THAT(parse_error.Utf8(),
              ::testing::HasSubstr("Could not infer type of document rule "
                                   "predicate, no valid type specified"));

  parse_error =
      CreateInvalidPredicate(R"("not": [{"href_matches": "foo.com"}])");
  EXPECT_THAT(
      parse_error.Utf8(),
      ::testing::HasSubstr("Document rule predicate must be an object"));

  parse_error =
      CreateInvalidPredicate(R"("and": [], "relative_to": "document")");
  EXPECT_THAT(
      parse_error.Utf8(),
      ::testing::HasSubstr(
          "Document rule predicate with \"and\" key cannot have other keys."));

  parse_error = CreateInvalidPredicate(R"("or": {})");
  EXPECT_THAT(parse_error.Utf8(),
              ::testing::HasSubstr("\"or\" key should have a list value"));

  parse_error = CreateInvalidPredicate(R"("href_matches": {"port": 1234})");
  EXPECT_THAT(
      parse_error.Utf8(),
      ::testing::HasSubstr("Values for a URL pattern object must be strings"));

  parse_error =
      CreateInvalidPredicate(R"("href_matches": {"path_name": "foo"})");
  EXPECT_THAT(parse_error.Utf8(),
              ::testing::HasSubstr("Invalid key \"path_name\" for a URL "
                                   "pattern object found"));

  parse_error =
      CreateInvalidPredicate(R"("href_matches": [["bar.com/foo.html"]])");
  EXPECT_THAT(parse_error.Utf8(),
              ::testing::HasSubstr("Value for \"href_matches\" should "
                                   "either be a string"));

  parse_error = CreateInvalidPredicate(
      R"("href_matches": "/home", "relative_to": "window")");
  EXPECT_THAT(
      parse_error.Utf8(),
      ::testing::HasSubstr("Unrecognized \"relative_to\" value: \"window\""));

  parse_error = CreateInvalidPredicate(
      R"("href_matches": "/home", "relativeto": "document")");
  EXPECT_THAT(parse_error.Utf8(),
              ::testing::HasSubstr("Unrecognized key found: \"relativeto\""));

  parse_error = CreateInvalidPredicate(R"("href_matches": "https//:")");
  EXPECT_THAT(parse_error.Utf8(),
              ::testing::HasSubstr("URL Pattern for \"href_matches\" could not "
                                   "be parsed: \"https//:\""));

  parse_error = CreateInvalidPredicate(R"("selector_matches": {})");
  EXPECT_THAT(
      parse_error.Utf8(),
      ::testing::HasSubstr("Value for \"selector_matches\" must be a string"));

  parse_error =
      CreateInvalidPredicate(R"("selector_matches": "##bad_selector")");
  EXPECT_THAT(
      parse_error.Utf8(),
      ::testing::HasSubstr("\"##bad_selector\" is not a valid selector"));
}

TEST_F(DocumentRulesTest, DefaultPredicate) {
  auto* rule_set = CreateRuleSet(
      R"({
        "prefetch": [{
          "source": "document"
        }]
      })",
      KURL("https://example.com/"), execution_context());
  EXPECT_THAT(rule_set->prefetch_rules(), ElementsAre(MatchesPredicate(And())));
}

TEST_F(DocumentRulesTest, EvaluateCombinators) {
  DummyPageHolder page_holder;
  Document& document = page_holder.GetDocument();
  HTMLAnchorElement* link = MakeGarbageCollected<HTMLAnchorElement>(document);

  auto* empty_and = CreatePredicate(R"("and": [])");
  EXPECT_THAT(empty_and, And());
  EXPECT_TRUE(empty_and->Matches(*link));

  auto* empty_or = CreatePredicate(R"("or": [])");
  EXPECT_THAT(empty_or, Or());
  EXPECT_FALSE(empty_or->Matches(*link));

  auto* and_false_false_false =
      CreatePredicate(R"("and": [{"or": []}, {"or": []}, {"or": []}])");
  EXPECT_THAT(and_false_false_false, And({Or(), Or(), Or()}));
  EXPECT_FALSE(and_false_false_false->Matches(*link));

  auto* and_false_true_false =
      CreatePredicate(R"("and": [{"or": []}, {"and": []}, {"or": []}])");
  EXPECT_THAT(and_false_true_false, And({Or(), And(), Or()}));
  EXPECT_FALSE(and_false_true_false->Matches(*link));

  auto* and_true_true_true =
      CreatePredicate(R"("and": [{"and": []}, {"and": []}, {"and": []}])");
  EXPECT_THAT(and_true_true_true, And({And(), And(), And()}));
  EXPECT_TRUE(and_true_true_true->Matches(*link));

  auto* or_false_false_false =
      CreatePredicate(R"("or": [{"or": []}, {"or": []}, {"or": []}])");
  EXPECT_THAT(or_false_false_false, Or({Or(), Or(), Or()}));
  EXPECT_FALSE(or_false_false_false->Matches(*link));

  auto* or_false_true_false =
      CreatePredicate(R"("or": [{"or": []}, {"and": []}, {"or": []}])");
  EXPECT_THAT(or_false_true_false, Or({Or(), And(), Or()}));
  EXPECT_TRUE(or_false_true_false->Matches(*link));

  auto* or_true_true_true =
      CreatePredicate(R"("or": [{"and": []}, {"and": []}, {"and": []}])");
  EXPECT_THAT(or_true_true_true, Or({And(), And(), And()}));
  EXPECT_TRUE(or_true_true_true->Matches(*link));

  auto* not_true = CreatePredicate(R"("not": {"and": []})");
  EXPECT_THAT(not_true, Neg(And()));
  EXPECT_FALSE(not_true->Matches(*link));

  auto* not_false = CreatePredicate(R"("not": {"or": []})");
  EXPECT_THAT(not_false, Neg(Or()));
  EXPECT_TRUE(not_false->Matches(*link));
}

TEST_F(DocumentRulesTest, EvaluateHrefMatches) {
  DummyPageHolder page_holder;
  Document& document = page_holder.GetDocument();
  HTMLAnchorElement* link = MakeGarbageCollected<HTMLAnchorElement>(document);
  link->setHref("https://foo.com/bar.html?fizz=buzz");

  // No patterns specified, will not match any link.
  auto* empty = CreatePredicate(R"("href_matches": [])");
  EXPECT_FALSE(empty->Matches(*link));

  // Single pattern (should match).
  auto* single =
      CreatePredicate(R"("href_matches": "https://foo.com/bar.html?*")");
  EXPECT_TRUE(single->Matches(*link));

  // Two patterns which don't match.
  auto* double_fail = CreatePredicate(
      R"("href_matches": ["http://foo.com/*", "https://bar.com/*"])");
  EXPECT_FALSE(double_fail->Matches(*link));

  // One pattern that matches, one that doesn't - should still pass due to
  // an implicit or between patterns in a href_matches list.
  auto* pass_fail = CreatePredicate(
      R"("href_matches": ["https://foo.com/bar.html?*", "https://bar.com/*"])");
  EXPECT_TRUE(pass_fail->Matches(*link));
}

HTMLAnchorElement* AddAnchor(ContainerNode& parent, const String& href) {
  HTMLAnchorElement* link =
      MakeGarbageCollected<HTMLAnchorElement>(parent.GetDocument());
  link->setHref(href);
  parent.appendChild(link);
  return link;
}

HTMLAreaElement* AddAreaElement(ContainerNode& parent, const String& href) {
  HTMLAreaElement* area =
      MakeGarbageCollected<HTMLAreaElement>(parent.GetDocument());
  area->setHref(href);
  parent.appendChild(area);
  return area;
}

// Tests that speculation candidates based of existing links are reported after
// a document rule is inserted.
TEST_F(DocumentRulesTest, SpeculationCandidatesReportedAfterInitialization) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  AddAnchor(*document.body(), "https://foo.com/doc.html");
  AddAnchor(*document.body(), "https://bar.com/doc.html");
  AddAnchor(*document.body(), "https://foo.com/doc2.html");

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);

  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/doc.html"),
                                  KURL("https://foo.com/doc2.html")));
}

// Tests that speculation candidates based of existing links are reported after
// a document rule is inserted. Test that the speculation candidates include
// No-Vary-Search hint.
TEST_F(DocumentRulesTest,
       SpeculationCandidatesReportedAfterInitializationWithNVS) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  AddAnchor(*document.body(), "https://foo.com/doc.html");
  AddAnchor(*document.body(), "https://bar.com/doc.html");
  AddAnchor(*document.body(), "https://foo.com/doc2.html");

  String speculation_script = R"nvs(
    {"prefetch": [{
      "source": "document",
      "where": {"href_matches": "https://foo.com/*"},
      "expects_no_vary_search": "params=(\"a\")"
    }]}
  )nvs";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);

  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/doc.html"),
                                  KURL("https://foo.com/doc2.html")));
  //  Check that the candidates have the correct No-Vary-Search hint.
  EXPECT_THAT(candidates, ::testing::Each(::testing::AllOf(
                              HasNoVarySearchHint(), NVSVariesOnKeyOrder(),
                              NVSHasNoVaryParams("a"))));
}

// Tests that a new speculation candidate is reported after different
// modifications to a link.
TEST_F(DocumentRulesTest, SpeculationCandidatesUpdatedAfterLinkModifications) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  ASSERT_TRUE(candidates.empty());
  HTMLAnchorElement* link = nullptr;

  // Add link with href that matches.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link = AddAnchor(*document.body(), "https://foo.com/action.html");
  });
  ASSERT_EQ(candidates.size(), 1u);
  EXPECT_EQ(candidates[0]->url, KURL("https://foo.com/action.html"));

  // Update link href to URL that doesn't match.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link->setHref("https://bar.com/document.html");
  });
  EXPECT_TRUE(candidates.empty());

  // Update link href to URL that matches.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link->setHref("https://foo.com/document.html");
  });
  ASSERT_EQ(candidates.size(), 1u);
  EXPECT_EQ(candidates[0]->url, KURL("https://foo.com/document.html"));

  // Remove link.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { link->remove(); });
  EXPECT_TRUE(candidates.empty());
}

// Tests that a new list of speculation candidates is reported after a rule set
// is added/removed.
TEST_F(DocumentRulesTest, SpeculationCandidatesUpdatedAfterRuleSetsChanged) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  KURL url_1 = KURL("https://foo.com/abc");
  KURL url_2 = KURL("https://foo.com/xyz");
  AddAnchor(*document.body(), url_1);
  AddAnchor(*document.body(), url_2);

  String speculation_script_1 = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script_1);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(url_1, url_2));

  // Add a new rule set; the number of candidates should double.
  String speculation_script_2 = R"(
    {"prerender": [
      {"source": "document", "where": {"not":
        {"href_matches": {"protocol": "https", "hostname": "bar.com"}}
      }}
    ]}
  )";
  HTMLScriptElement* script_el = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    script_el = InsertSpeculationRules(document, speculation_script_2);
  });
  EXPECT_THAT(candidates, HasURLs(url_1, url_1, url_2, url_2));
  EXPECT_THAT(candidates, ::testing::UnorderedElementsAre(
                              HasAction(mojom::SpeculationAction::kPrefetch),
                              HasAction(mojom::SpeculationAction::kPrefetch),
                              HasAction(mojom::SpeculationAction::kPrerender),
                              HasAction(mojom::SpeculationAction::kPrerender)));

  // Remove the recently added rule set, the number of candidates should be
  // halved.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { script_el->remove(); });
  ASSERT_EQ(candidates.size(), 2u);
  EXPECT_THAT(candidates, HasURLs(url_1, url_2));
  EXPECT_THAT(candidates,
              ::testing::Each(HasAction(mojom::SpeculationAction::kPrefetch)));
}

// Tests that list and document speculation rules work in combination correctly.
TEST_F(DocumentRulesTest, ListRuleCombinedWithDocumentRule) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  AddAnchor(*document.body(), "https://foo.com/bar");
  String speculation_script = R"(
    {"prefetch": [
      {"source": "document"},
      {"source": "list", "urls": ["https://bar.com/foo"]}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar"),
                                  KURL("https://bar.com/foo")));
}

// Tests that candidates created for document rules are correct when
// "anonymous-client-ip-when-cross-origin" is specified.
TEST_F(DocumentRulesTest, RequiresAnonymousClientIPWhenCrossOrigin) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  AddAnchor(*document.body(), "https://foo.com/bar");
  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "requires": ["anonymous-client-ip-when-cross-origin"]
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  ASSERT_EQ(candidates.size(), 1u);
  EXPECT_TRUE(candidates[0]->requires_anonymous_client_ip_when_cross_origin);
}

// Tests that a link inside a shadow tree is included when creating
// document-rule based speculation candidates. Also tests that an "unslotted"
// link (link inside shadow host that isn't assigned to a slot) is not included.
TEST_F(DocumentRulesTest, LinkInShadowTreeIncluded) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  Document& document = page_holder.GetDocument();
  ShadowRoot& shadow_root =
      document.body()->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  auto* shadow_tree_link = AddAnchor(shadow_root, "https://foo.com/bar.html");
  AddAnchor(*document.body(), "https://foo.com/unslotted");

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar.html")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    shadow_tree_link->setHref("https://not-foo.com/");
  });
  EXPECT_TRUE(candidates.empty());

  HTMLAnchorElement* shadow_tree_link_2 = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    shadow_tree_link_2 = AddAnchor(shadow_root, "https://foo.com/buzz");
  });
  ASSERT_EQ(candidates.size(), 1u);
  EXPECT_EQ(candidates[0]->url, KURL("https://foo.com/buzz"));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { shadow_tree_link_2->remove(); });
  EXPECT_TRUE(candidates.empty());
}

// Tests that an anchor element with no href attribute is handled correctly.
TEST_F(DocumentRulesTest, LinkWithNoHrefAttribute) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* link = MakeGarbageCollected<HTMLAnchorElement>(document);
  document.body()->appendChild(link);
  ASSERT_FALSE(link->FastHasAttribute(html_names::kHrefAttr));

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  ASSERT_TRUE(candidates.empty());

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link->setHref("https://foo.com/bar");
  });
  ASSERT_EQ(candidates.size(), 1u);
  ASSERT_EQ(candidates[0]->url, "https://foo.com/bar");

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link->removeAttribute(html_names::kHrefAttr);
  });
  ASSERT_TRUE(candidates.empty());

  // Just to test that no DCHECKs are hit.
  link->remove();
}

// Tests that links with non-HTTP(s) urls are ignored.
TEST_F(DocumentRulesTest, LinkWithNonHttpHref) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* link = AddAnchor(*document.body(), "mailto:abc@xyz.com");
  String speculation_script = R"({"prefetch": [{"source": "document"}]})";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  ASSERT_TRUE(candidates.empty());

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    link->setHref("https://foo.com/bar");
  });
  EXPECT_THAT(candidates, HasURLs("https://foo.com/bar"));
}

// Tests a couple of edge cases:
// 1) Removing a link that doesn't match any rules
// 2) Adding and removing a link before running microtasks (i.e. before calling
// UpdateSpeculationCandidates).
TEST_F(DocumentRulesTest, RemovingUnmatchedAndPendingLinks) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* unmatched_link = AddAnchor(*document.body(), "https://bar.com/foo");
  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_TRUE(candidates.empty());

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    auto* pending_link = AddAnchor(*document.body(), "https://foo.com/bar");
    unmatched_link->remove();
    pending_link->remove();
  });
  EXPECT_TRUE(candidates.empty());
}

// Tests if things still work if we use <area> instead of <a>.
TEST_F(DocumentRulesTest, AreaElement) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();
  HTMLAreaElement* area =
      AddAreaElement(*document.body(), "https://foo.com/action.html");

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  ASSERT_EQ(candidates.size(), 1u);
  EXPECT_EQ(candidates[0]->url, KURL("https://foo.com/action.html"));

  // Update area href to URL that doesn't match.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    area->setHref("https://bar.com/document.html");
  });
  EXPECT_TRUE(candidates.empty());

  // Update area href to URL that matches.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    area->setHref("https://foo.com/document.html");
  });
  ASSERT_EQ(candidates.size(), 1u);
  EXPECT_EQ(candidates[0]->url, KURL("https://foo.com/document.html"));

  // Remove area.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { area->remove(); });
  EXPECT_TRUE(candidates.empty());
}

// Test that adding a link to an element that isn't connected doesn't DCHECK.
TEST_F(DocumentRulesTest, DisconnectedLink) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  ASSERT_TRUE(candidates.empty());

  HTMLDivElement* div = nullptr;
  HTMLAnchorElement* link = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    div = MakeGarbageCollected<HTMLDivElement>(document);
    link = AddAnchor(*div, "https://foo.com/blah.html");
    document.body()->AppendChild(div);
  });
  EXPECT_EQ(candidates.size(), 1u);

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    div->remove();
    link->remove();
  });
  EXPECT_TRUE(candidates.empty());
}

// Similar to test above, but now inside a shadow tree.
TEST_F(DocumentRulesTest, DisconnectedLinkInShadowTree) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  String speculation_script = R"(
    {"prefetch": [
      {"source": "document", "where": {"href_matches": "https://foo.com/*"}}
    ]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  ASSERT_TRUE(candidates.empty());

  HTMLDivElement* div = nullptr;
  HTMLAnchorElement* link = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    div = MakeGarbageCollected<HTMLDivElement>(document);
    ShadowRoot& shadow_root =
        div->AttachShadowRootForTesting(ShadowRootMode::kOpen);
    link = AddAnchor(shadow_root, "https://foo.com/blah.html");
    document.body()->AppendChild(div);
  });
  EXPECT_EQ(candidates.size(), 1u);

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    div->remove();
    link->remove();
  });
  EXPECT_TRUE(candidates.empty());
}

// Tests that a document rule's specified referrer policy is used.
TEST_F(DocumentRulesTest, ReferrerPolicy) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  auto* link_with_referrer = AddAnchor(*document.body(), "https://foo.com/abc");
  link_with_referrer->setAttribute(html_names::kReferrerpolicyAttr,
                                   AtomicString("same-origin"));
  auto* link_with_rel_no_referrer =
      AddAnchor(*document.body(), "https://foo.com/def");
  link_with_rel_no_referrer->setAttribute(html_names::kRelAttr,
                                          AtomicString("nore
"""


```