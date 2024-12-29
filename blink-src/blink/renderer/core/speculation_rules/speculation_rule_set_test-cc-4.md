Response:
The user wants me to summarize the functionality of the provided C++ code snippet from a Chromium file. I need to explain what it does, how it relates to web technologies like JavaScript, HTML, and CSS, provide examples, discuss potential user errors, and outline how a user action might lead to this code being executed.

**Plan:**

1. **Identify the Core Functionality:** The code seems to be testing the behavior of speculation rules, particularly how they interact with changes in the DOM and CSS styles.
2. **Relate to Web Technologies:**
    - **JavaScript:** The speculation rules are often defined in `<script type="speculationrules">` tags, which are part of HTML but processed by JavaScript.
    - **HTML:** The tests manipulate HTML elements (divs, anchors, etc.) and their attributes.
    - **CSS:** The tests focus on how CSS properties like `display` and `content-visibility` affect speculation rule matching.
3. **Provide Examples:** I'll use the test cases themselves as examples, explaining the setup, action, and expected outcome.
4. **Discuss User Errors:** I'll think about scenarios where users might write incorrect speculation rules or unintentionally trigger updates.
5. **Explain User Interaction:** I'll outline a simplified user flow that could lead to speculation rules being evaluated.
6. **Summarize the Functionality:**  I'll condense the core purpose of the code based on the above points.
这是对`blink/renderer/core/speculation_rules/speculation_rule_set_test.cc` 文件部分代码的分析。 这部分代码主要关注**推测规则（Speculation Rules）在文档中元素样式发生变化时的行为**，特别是与元素的可见性相关的样式属性。

**功能归纳:**

这部分测试代码主要验证了以下功能：

1. **根据CSS选择器匹配链接并进行预取/预渲染:** 测试了当HTML中存在符合推测规则中CSS选择器 (`selector_matches`) 的链接时，这些链接会被识别为推测候选对象。
    * **示例:** 当HTML中存在 `<div id="important-section"><a href="https://foo.com/bar"></a></div>`， 并且推测规则为 `{"prefetch": [{"source": "document", "where": {"selector_matches": "#important-section a"}}]}`,  测试会验证 `https://foo.com/bar` 是否被添加为预取候选对象。

2. **当链接的容器ID改变时，推测候选列表不会立即更新:** 测试了当包含链接的元素的ID属性发生变化时，推测规则不会立即重新评估，只有在后续的样式更新后才会生效。
    * **假设输入:** 一个包含链接的div元素，推测规则匹配这个div元素内的链接。
    * **操作:** 通过JavaScript改变这个div元素的ID。
    * **输出:** 在没有强制样式更新的情况下，推测候选列表不会立即改变。
    * **用户操作:** 用户可以通过JavaScript代码来动态修改元素的ID，例如响应用户的点击事件。

3. **当链接或其祖先元素的 `display` 属性改变时，推测候选列表会更新:**  测试了当链接或其父元素的 `display` 属性被设置为 `none` 或移除时，推测规则会重新评估，从而将不可见的链接从候选列表中移除或添加。
    * **示例:** 当一个链接的父元素 `important_section` 的 `display` 属性被设置为 `none`，原本匹配该链接的推测规则将不再认为该链接是候选对象。
    * **用户操作:** 用户可以通过CSS或JavaScript来改变元素的 `display` 属性，例如通过切换类名或直接修改 style 属性。

4. **根据链接的 `href` 属性匹配链接并处理 `display` 变化:** 测试了使用 `href_matches`  匹配链接时，当链接的 `display` 属性改变时，推测候选列表也会相应更新。
    * **示例:** 推测规则为 `{"prefetch": [{"source": "document", "where": {"href_matches": "https://foo.com/*"}}]}`,  当页面中一个 `href` 为 `https://foo.com/bar` 的链接的 `display` 属性变为 `none` 时，该链接将从候选列表中移除。

5. **当链接包含在 `content-visibility: hidden` 的元素中时，推测候选列表会更新:** 测试了当链接的祖先元素设置了 `content-visibility: hidden` 时，即使元素仍然存在于DOM中，但由于其内容被跳过渲染，推测规则也会将其从候选列表中移除。反之，当移除 `content-visibility: hidden` 时，如果链接仍然匹配规则，则会重新添加到候选列表。
    * **用户操作:** 网站可以使用 `content-visibility: hidden` 来延迟渲染屏幕外的元素，从而提高初始加载性能。

6. **处理嵌套的 `content-visibility: hidden` 元素:** 测试了嵌套的 `content-visibility: hidden` 元素对推测规则的影响，验证了在不同锁定/解锁顺序下，推测候选列表的正确更新。

7. **直接在链接上设置 `content-visibility: hidden` 不会立即触发更新:**  测试了直接在链接元素上设置 `content-visibility: hidden` 并不会像在容器元素上设置那样立即触发推测规则的重新评估，可能需要后续的样式更新才能生效。

8. **向 `content-visibility: hidden` 的容器中添加链接不会立即添加为候选对象:** 测试了当一个链接被添加到 `content-visibility: hidden` 的容器中时，它不会立即被识别为推测候选对象。

9. **跟踪 `content-visibility: hidden` 容器的状态变化:** 测试了当包含链接的元素被设置为 `content-visibility: hidden` 时，即使链接的 `href` 发生变化，也不会被添加到候选列表中。只有当容器的 `content-visibility` 变为 `visible` 时，才会根据最新的 `href` 进行评估。

10. **移除推测规则时强制进行样式更新:** 测试了当一个包含推测规则的 `<script>` 标签被移除时，会强制进行样式更新，以便及时更新推测候选列表。这与JavaScript的微任务调度有关。
    * **假设输入:** 页面中存在多个包含推测规则的 `<script>` 标签，并且页面中有符合这些规则的链接。
    * **操作:** 通过JavaScript移除其中一个 `<script>` 标签，并可能同时添加新的推测规则或修改DOM结构。
    * **输出:** 推测候选列表会因为规则的移除和潜在的DOM/样式变化而更新。

11. **在等待样式更新时移除推测规则的处理:**  测试了一种竞争条件，即在推测候选列表正在等待样式更新完成时，一个推测规则被移除。代码验证了在这种情况下，能够正确处理，避免重复更新。

12. **通配符选择器的测试:**  测试了使用通配符 `*` 作为 CSS 选择器时，推测规则的正常工作。

13. **`eagerness` 属性的测试:**  测试了推测规则中 `eagerness` 属性的不同取值 (`conservative`, `eager`, `moderate`, `immediate`) 如何影响推测候选对象的优先级。
    * **示例:**  对于相同的 URL，如果一个规则的 `eagerness` 是 `eager`，另一个是 `conservative`，那么 `eager` 的规则生成的候选对象可能会被优先处理。

14. **无效的 `eagerness` 属性值的处理:** 测试了当 `eagerness` 属性值无效时，推测规则能够正确忽略该属性。

15. **`expects_no_vary_search` 属性的测试:** 测试了推测规则中 `expects_no_vary_search` 属性的解析和使用，用于指定预取请求可以忽略某些URL参数的变化。
    * **示例:**  `"expects_no_vary_search": "params=(\"a\") "` 表示预取 `https://example.com/prefetch/list/page1.html` 时，可以忽略 `a` 参数的变化。

16. **无效的 `expects_no_vary_search` 属性值的处理:** 测试了当 `expects_no_vary_search` 属性值无效时，推测规则会生成不包含 No-Vary-Search hint 的候选对象。

17. **空的和默认的 `expects_no_vary_search` 属性值的处理:** 测试了空字符串和默认值对 `expects_no_vary_search` 的影响。

18. **无效的 `expects_no_vary_search` 值导致控制台警告:** 测试了当 `expects_no_vary_search` 的值不是字符串时，会在控制台输出警告信息。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript:**
    * 通过 JavaScript 动态插入或删除包含推测规则的 `<script type="speculationrules">` 标签。
    * 使用 JavaScript 修改 DOM 结构，例如添加、删除或修改元素的属性（如 `id`、`class`、`href`）。
    * 通过 JavaScript 修改元素的 style 属性，例如设置 `display: none` 或 `content-visibility: hidden`。
* **HTML:**
    * 推测规则本身通常写在 HTML 的 `<script type="speculationrules">` 标签中。
    * 测试代码中创建和操作各种 HTML 元素，如 `<div>` 和 `<a>`，来模拟不同的页面结构。
* **CSS:**
    * 测试代码关注 CSS 属性对推测规则的影响，特别是控制元素可见性的属性 `display` 和 `content-visibility`。
    * 推测规则中的 `where.selector_matches` 选项使用了 CSS 选择器来定位目标链接。

**逻辑推理的假设输入与输出:**

很多测试用例都遵循类似的模式：

* **假设输入:**
    * 一段包含特定 HTML 结构的字符串。
    * 一段包含推测规则的 JSON 字符串。
* **操作:**
    * 将 HTML 结构添加到文档中。
    * 将推测规则添加到文档中。
    * 可能进行一些 DOM 或样式修改操作。
    * 触发推测规则的评估。
* **输出:**
    * 推测候选列表 (`speculation_host.candidates()`) 中包含或不包含特定的 URL。
    * 可以通过 `EXPECT_THAT` 宏来断言候选列表中 URL 的存在或缺失，以及其他属性（如 `eagerness`）。

**涉及用户或编程常见的使用错误举例:**

* **拼写错误或语法错误的推测规则 JSON:** 用户可能会在编写推测规则时犯语法错误，例如缺少引号、括号不匹配等，导致规则无法被正确解析。这在测试中没有直接体现，但在实际使用中是常见错误。
* **CSS 选择器写错:**  用户可能编写了错误的 CSS 选择器，导致推测规则无法匹配到预期的链接。例如，选择器 `#important-section  a` （注意中间的空格）会匹配 `important-section` 后代的所有 `a` 标签，而 `#important-section a` 则只会匹配 `important-section` 的直接子元素的 `a` 标签。
* **不理解 `content-visibility` 的影响:** 用户可能不清楚 `content-visibility: hidden` 会导致元素被跳过渲染，从而影响推测规则的匹配。他们可能会认为只要元素存在于 DOM 中，即使设置了 `content-visibility: hidden`，推测规则仍然会生效。
* **对微任务和样式更新时机的误解:** 用户可能不清楚 DOM 或样式的修改何时会触发推测规则的重新评估。例如，他们可能认为修改一个元素的 ID 会立即更新推测候选列表，而实际上这可能需要等待下一次样式更新。
* **`expects_no_vary_search` 值的错误使用:** 用户可能会不理解 `expects_no_vary_search` 的语法或含义，导致预取请求无法正确忽略某些 URL 参数的变化。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **网页的 HTML 源代码中包含了 `<script type="speculationrules">` 标签。** 这些标签中定义了预取或预渲染的推测规则。
3. **浏览器解析 HTML 并加载这些推测规则。** `blink/renderer/core/speculation_rules/speculation_rule_set.cc` 中的代码负责解析和管理这些规则。
4. **用户与网页进行交互，例如鼠标悬停在链接上，或者页面上的 JavaScript 代码动态修改 DOM 结构或元素样式。**
5. **当 DOM 结构或元素样式发生变化，并且这些变化可能影响到推测规则的匹配时，`speculation_rule_set_test.cc` 中测试的逻辑会被触发。** 例如，如果一个链接被添加到页面中，或者一个元素的 `display` 属性被修改。
6. **浏览器会重新评估推测规则，并更新预取或预渲染的候选列表。** 这部分逻辑涉及到 `SpeculationRuleSet` 类的实现以及与样式系统和布局系统的交互。
7. **如果开发者在本地修改了 `blink` 引擎的代码，并希望测试推测规则在样式变化时的行为，他们会运行 `speculation_rule_set_test.cc` 中的相关测试用例。** 这些测试用例模拟了各种 DOM 和样式变化场景，以确保推测规则的正确性。

**总结:**

这部分代码是 `blink` 引擎中关于推测规则功能的一组测试用例，专门用于验证当页面元素的 CSS 样式（特别是与可见性相关的样式）发生变化时，推测规则能否正确地识别和更新预取/预渲染的候选对象。这些测试覆盖了各种场景，包括修改元素的 `display` 和 `content-visibility` 属性，以及在不同的时间点添加、删除推测规则。通过这些测试，可以确保浏览器在处理推测规则时能够考虑到动态的页面变化，从而提供更智能的预加载策略。

Prompt: 
```
这是目录为blink/renderer/core/speculation_rules/speculation_rule_set_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
tant_section =
      document.getElementById(AtomicString("important-section"));
  AddAnchor(*important_section, "https://foo.com/bar");
  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // Changing the link's container's ID will not queue a microtask on its own.
  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host,
      [&]() {
        important_section->SetIdAttribute(AtomicString("unimportant-section"));
      },
      IncludesStyleUpdate{false}));
  // After style updates, we should update the list of speculation candidates.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, []() {});
  EXPECT_THAT(candidates, HasURLs());
}

TEST_F(DocumentRulesTest, LinksWithoutComputedStyle) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  AddAnchor(*important_section, "https://foo.com/bar");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    InsertSpeculationRules(document, speculation_script);
  });
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // Changing a link's ancestor to display:none should trigger an update and
  // remove it from the candidate list.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetInlineStyleProperty(CSSPropertyID::kDisplay,
                                              CSSValueID::kNone);
  });
  EXPECT_THAT(candidates, HasURLs());

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->RemoveInlineStyleProperty(CSSPropertyID::kDisplay);
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // Adding a shadow root will remove the anchor from the flat tree, and it will
  // stop being rendered. It should trigger an update and be removed from
  // the candidate list.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  });
  EXPECT_THAT(candidates, HasURLs());
}

TEST_F(DocumentRulesTest, LinksWithoutComputedStyle_HrefMatches) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* anchor = AddAnchor(*important_section, "https://foo.com/bar");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"href_matches": "https://foo.com/*"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    InsertSpeculationRules(document, speculation_script);
  });
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    anchor->SetInlineStyleProperty(CSSPropertyID::kDisplay, CSSValueID::kNone);
  });
  EXPECT_THAT(candidates, HasURLs());
}

TEST_F(DocumentRulesTest, LinkInsideDisplayLockedElement) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  AddAnchor(*important_section, "https://foo.com/bar");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                              CSSValueID::kHidden);
  });
  EXPECT_THAT(candidates, HasURLs());

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->RemoveInlineStyleProperty(
        CSSPropertyID::kContentVisibility);
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));
}

TEST_F(DocumentRulesTest, LinkInsideNestedDisplayLockedElement) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section">
      <div id="links"></div>
    </div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* links = document.getElementById(AtomicString("links"));
  AddAnchor(*links, "https://foo.com/bar");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // Scenario 1: Lock links, lock important-section, unlock important-section,
  // unlock links.

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    links->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                  CSSValueID::kHidden);
  });
  EXPECT_THAT(candidates, HasURLs());

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        important_section->SetInlineStyleProperty(
            CSSPropertyID::kContentVisibility, CSSValueID::kHidden);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        important_section->RemoveInlineStyleProperty(
            CSSPropertyID::kContentVisibility);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    links->RemoveInlineStyleProperty(CSSPropertyID::kContentVisibility);
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // Scenario 2: Lock links, lock important-section, unlock links, unlock
  // important-section.

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    links->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                  CSSValueID::kHidden);
  });
  EXPECT_THAT(candidates, HasURLs());

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        important_section->SetInlineStyleProperty(
            CSSPropertyID::kContentVisibility, CSSValueID::kHidden);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        links->RemoveInlineStyleProperty(CSSPropertyID::kContentVisibility);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->RemoveInlineStyleProperty(
        CSSPropertyID::kContentVisibility);
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  // Scenario 3: Lock important-section, lock links, unlock important-section,
  // unlock links.

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                              CSSValueID::kHidden);
  });
  EXPECT_THAT(candidates, HasURLs());

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        links->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                      CSSValueID::kHidden);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        important_section->RemoveInlineStyleProperty(
            CSSPropertyID::kContentVisibility);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    links->RemoveInlineStyleProperty(CSSPropertyID::kContentVisibility);
  });

  // Scenario 4: Lock links and important-section together, unlock links and
  // important-section together.

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                              CSSValueID::kHidden);
    links->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                  CSSValueID::kHidden);
  });
  EXPECT_THAT(candidates, HasURLs());

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->RemoveInlineStyleProperty(
        CSSPropertyID::kContentVisibility);
    links->RemoveInlineStyleProperty(CSSPropertyID::kContentVisibility);
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));
}

TEST_F(DocumentRulesTest, DisplayLockedLink) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* anchor = AddAnchor(*important_section, "https://foo.com/bar");
  anchor->setInnerText("Bar");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        anchor->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                       CSSValueID::kHidden);
      }));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        anchor->RemoveInlineStyleProperty(CSSPropertyID::kContentVisibility);
      }));
}

TEST_F(DocumentRulesTest, AddLinkToDisplayLockedContainer) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section">
    </div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"selector_matches": "#important-section a"}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs());

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        important_section->SetInlineStyleProperty(
            CSSPropertyID::kContentVisibility, CSSValueID::kHidden);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  HTMLAnchorElement* anchor = nullptr;
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    anchor = AddAnchor(*important_section, "https://foo.com/bar");
  });
  EXPECT_THAT(candidates, HasURLs());

  // Tests removing a display-locked container with links.
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      [&]() { important_section->remove(); });
  EXPECT_THAT(candidates, HasURLs());
}

TEST_F(DocumentRulesTest, DisplayLockedContainerTracking) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  document.body()->setInnerHTML(R"HTML(
    <div id="important-section"></div>
    <div id="irrelevant-section"><span></span></div>
  )HTML");
  auto* important_section =
      document.getElementById(AtomicString("important-section"));
  auto* irrelevant_section =
      document.getElementById(AtomicString("irrelevant-section"));
  auto* anchor_1 = AddAnchor(*important_section, "https://foo.com/bar");
  AddAnchor(*important_section, "https://foo.com/logout");
  AddAnchor(*document.body(), "https://foo.com/logout");

  String speculation_script = R"(
    {"prefetch": [{
      "source": "document",
      "where": {"and": [{
        "selector_matches": "#important-section a"
      }, {
        "not": {"href_matches": "https://*/logout"}
      }]}
    }]}
  )";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/bar")));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                              CSSValueID::kHidden);
    anchor_1->SetHref(AtomicString("https://foo.com/fizz.html"));
  });
  EXPECT_THAT(candidates, HasURLs());

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        // Changing style of the display-locked container should not cause an
        // update.
        important_section->SetInlineStyleProperty(CSSPropertyID::kColor,
                                                  CSSValueID::kDarkviolet);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host, [&]() {
    important_section->SetInlineStyleProperty(CSSPropertyID::kContentVisibility,
                                              CSSValueID::kVisible);
  });
  EXPECT_THAT(candidates, HasURLs(KURL("https://foo.com/fizz.html")));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        // Changing style of the display-locked container should not cause an
        // update.
        important_section->SetInlineStyleProperty(CSSPropertyID::kColor,
                                                  CSSValueID::kDeepskyblue);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        irrelevant_section->SetInlineStyleProperty(
            CSSPropertyID::kContentVisibility, CSSValueID::kHidden);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));

  ASSERT_TRUE(NoRulesPropagatedToStubSpeculationHost(
      page_holder, speculation_host, [&]() {
        irrelevant_section->RemoveInlineStyleProperty(
            CSSPropertyID::kContentVisibility);
        page_holder.GetFrameView().UpdateAllLifecyclePhasesForTest();
      }));
}

// Similar to SpeculationRulesTest.RemoveInMicrotask, but with relevant changes
// to style/layout which necessitate forcing a style update after removal.
TEST_F(DocumentRulesTest, RemoveForcesStyleUpdate) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  base::RunLoop run_loop;
  base::MockCallback<base::RepeatingCallback<void(
      const Vector<mojom::blink::SpeculationCandidatePtr>&)>>
      mock_callback;
  {
    ::testing::InSequence sequence;
    EXPECT_CALL(mock_callback, Run(::testing::SizeIs(2)));
    EXPECT_CALL(mock_callback, Run(::testing::SizeIs(3)))
        .WillOnce(::testing::Invoke([&]() { run_loop.Quit(); }));
  }
  speculation_host.SetCandidatesUpdatedCallback(mock_callback.Get());

  LocalFrame& frame = page_holder.GetFrame();
  Document& doc = page_holder.GetDocument();
  frame.GetSettings()->SetScriptEnabled(true);
  auto& broker = frame.DomWindow()->GetBrowserInterfaceBroker();
  broker.SetBinderForTesting(
      mojom::blink::SpeculationHost::Name_,
      WTF::BindRepeating(&StubSpeculationHost::BindUnsafe,
                         WTF::Unretained(&speculation_host)));

  for (StringView path : {"/baz", "/quux"}) {
    AddAnchor(*doc.body(), "https://example.com" + path);
  }

  // First simulated task adds the rule sets.
  InsertSpeculationRules(doc,
                         R"({"prefetch": [
           {"source": "list", "urls": ["https://example.com/foo"]}]})");
  HTMLScriptElement* to_remove = InsertSpeculationRules(doc,
                                                        R"({"prefetch": [
             {"source": "list", "urls": ["https://example.com/bar"]}]})");
  scoped_refptr<scheduler::EventLoop> event_loop =
      frame.DomWindow()->GetAgent()->event_loop();
  event_loop->PerformMicrotaskCheckpoint();
  frame.View()->UpdateAllLifecyclePhasesForTest();

  // Second simulated task removes a rule set, then adds a new rule set which
  // will match some newly added links. Since we are forced to update to handle
  // the removal, these will be discovered during that microtask.
  //
  // There's some extra subtlety here -- the speculation rules update needs to
  // propagate the new invalidation sets for this selector before the
  // setAttribute call occurs. Otherwise this test fails because the change goes
  // unnoticed.
  to_remove->remove();
  InsertSpeculationRules(doc,
                         R"({"prefetch": [{"source": "document",
                        "where": {"selector_matches": ".magic *"}}]})");
  doc.body()->setAttribute(html_names::kClassAttr, AtomicString("magic"));

  event_loop->PerformMicrotaskCheckpoint();

  run_loop.Run();
  broker.SetBinderForTesting(mojom::blink::SpeculationHost::Name_, {});
}

// Checks a subtle case, wherein a ruleset is removed while speculation
// candidate update is waiting for clean style. In this case there is a race
// between the style update and the new microtask. In the case where the
// microtask wins, care is needed to avoid re-entrantly updating speculation
// candidates once it forces style clean.
TEST_F(DocumentRulesTest, RemoveWhileWaitingForStyle) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  base::RunLoop run_loop;
  ::testing::StrictMock<base::MockCallback<base::RepeatingCallback<void(
      const Vector<mojom::blink::SpeculationCandidatePtr>&)>>>
      mock_callback;
  EXPECT_CALL(mock_callback, Run(::testing::SizeIs(1)))
      .WillOnce(::testing::Invoke([&]() { run_loop.Quit(); }));
  speculation_host.SetCandidatesUpdatedCallback(mock_callback.Get());

  LocalFrame& frame = page_holder.GetFrame();
  Document& doc = page_holder.GetDocument();
  frame.GetSettings()->SetScriptEnabled(true);
  auto& broker = frame.DomWindow()->GetBrowserInterfaceBroker();
  broker.SetBinderForTesting(
      mojom::blink::SpeculationHost::Name_,
      WTF::BindRepeating(&StubSpeculationHost::BindUnsafe,
                         WTF::Unretained(&speculation_host)));
  auto event_loop = frame.DomWindow()->GetAgent()->event_loop();

  // First, add the rule set and matching links. Style is not yet clean for the
  // newly added links, even after the microtask. We also add a rule set with a
  // fixed URL to avoid any optimizations that skip empty updates.
  for (StringView path : {"/baz", "/quux"}) {
    AddAnchor(*doc.body(), "https://example.com" + path);
  }
  HTMLScriptElement* to_remove = InsertSpeculationRules(doc,
                                                        R"({"prefetch": [
           {"source": "document", "where": {"selector_matches": "*"}}]})");
  InsertSpeculationRules(doc,
                         R"({"prefetch": [
           {"source": "list", "urls": ["https://example.com/keep"]}]})");
  event_loop->PerformMicrotaskCheckpoint();
  EXPECT_TRUE(doc.NeedsLayoutTreeUpdate());

  // Then, the rule set is removed, and we run another microtask checkpoint.
  to_remove->remove();
  event_loop->PerformMicrotaskCheckpoint();

  // At this point, style should have been forced clean, and we should have
  // received the mock update above.
  EXPECT_FALSE(doc.NeedsLayoutTreeUpdate());

  run_loop.Run();
  broker.SetBinderForTesting(mojom::blink::SpeculationHost::Name_, {});
}

// Regression test, since the universal select sets rule set flags indicating
// that the rule set potentially invalidates all elements.
TEST_F(DocumentRulesTest, UniversalSelector) {
  DummyPageHolder page_holder;
  page_holder.GetFrame().GetSettings()->SetScriptEnabled(true);
  StubSpeculationHost speculation_host;
  InsertSpeculationRules(
      page_holder.GetDocument(),
      R"({"prefetch": [{"source":"document", "where":{"selector_matches":"*"}}]})");
}

TEST_F(SpeculationRuleSetTest, Eagerness) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;
  Document& document = page_holder.GetDocument();

  const KURL kUrl1{"https://example.com/prefetch/list/page1.html"};
  const KURL kUrl2{"https://example.com/prefetch/document/page1.html"};
  const KURL kUrl3{"https://example.com/prerender/list/page1.html"};
  const KURL kUrl4{"https://example.com/prerender/document/page1.html"};
  const KURL kUrl5{"https://example.com/prefetch/list/page2.html"};
  const KURL kUrl6{"https://example.com/prefetch/document/page2.html"};
  const KURL kUrl7{"https://example.com/prerender/list/page2.html"};
  const KURL kUrl8{"https://example.com/prerender/document/page2.html"};
  const KURL kUrl9{"https://example.com/prefetch/list/page3.html"};

  AddAnchor(*document.body(), kUrl2.GetString());
  AddAnchor(*document.body(), kUrl4.GetString());
  AddAnchor(*document.body(), kUrl6.GetString());
  AddAnchor(*document.body(), kUrl8.GetString());

  String speculation_script = R"({
        "prefetch": [
          {
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page1.html"],
            "eagerness": "conservative"
          },
          {
            "source": "document",
            "eagerness": "eager",
            "where": {"href_matches": "https://example.com/prefetch/document/page1.html"}
          },
          {
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page2.html"]
          },
          {
            "source": "document",
            "where": {"href_matches": "https://example.com/prefetch/document/page2.html"}
          },
          {
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page3.html"],
            "eagerness": "immediate"
          }
        ],
        "prerender": [
          {
            "eagerness": "moderate",
            "source": "list",
            "urls": ["https://example.com/prerender/list/page1.html"]
          },
          {
            "source": "document",
            "where": {"href_matches": "https://example.com/prerender/document/page1.html"},
            "eagerness": "eager"
          },
          {
            "source": "list",
            "urls": ["https://example.com/prerender/list/page2.html"]
          },
          {
            "source": "document",
            "where": {"href_matches": "https://example.com/prerender/document/page2.html"}
          }
        ]
      })";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_THAT(
      candidates,
      UnorderedElementsAre(
          AllOf(
              HasURL(kUrl1),
              HasEagerness(blink::mojom::SpeculationEagerness::kConservative)),
          AllOf(HasURL(kUrl2),
                HasEagerness(blink::mojom::SpeculationEagerness::kEager)),
          AllOf(HasURL(kUrl3),
                HasEagerness(blink::mojom::SpeculationEagerness::kModerate)),
          AllOf(HasURL(kUrl4),
                HasEagerness(blink::mojom::SpeculationEagerness::kEager)),
          AllOf(HasURL(kUrl5),
                HasEagerness(blink::mojom::SpeculationEagerness::kEager)),
          AllOf(
              HasURL(kUrl6),
              HasEagerness(blink::mojom::SpeculationEagerness::kConservative)),
          AllOf(HasURL(kUrl7),
                HasEagerness(blink::mojom::SpeculationEagerness::kEager)),
          AllOf(
              HasURL(kUrl8),
              HasEagerness(blink::mojom::SpeculationEagerness::kConservative)),
          AllOf(HasURL(kUrl9),
                HasEagerness(blink::mojom::SpeculationEagerness::kEager))));
}

TEST_F(SpeculationRuleSetTest, InvalidUseOfEagerness1) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  const char* kUrl1 = "https://example.com/prefetch/list/page1.html";

  String speculation_script = R"({
        "eagerness": "conservative",
        "prefetch": [
          {
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page1.html"]
          }
        ]
      })";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  // It should just ignore the "eagerness" key
  EXPECT_THAT(candidates, HasURLs(KURL(kUrl1)));
}

TEST_F(SpeculationRuleSetTest, InvalidUseOfEagerness2) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  const char* kUrl1 = "https://example.com/prefetch/list/page1.html";

  String speculation_script = R"({
        "prefetch": [
          "eagerness",
          {
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page1.html"]
          }
        ]
      })";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  // It should just ignore the "eagerness" key
  EXPECT_THAT(candidates, HasURLs(KURL(kUrl1)));
}

TEST_F(SpeculationRuleSetTest, InvalidEagernessValue) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  String speculation_script = R"({
        "prefetch": [
          {
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page1.html"],
            "eagerness": 0
          },
          {
            "eagerness": 1.0,
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page2.html"]
          },
          {
            "source": "list",
            "eagerness": true,
            "urls": ["https://example.com/prefetch/list/page3.html"]
          },
          {
            "source": "list",
            "urls": ["https://example.com/prefetch/list/page4.html"],
            "eagerness": "xyz"
          }
        ]
      })";
  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_TRUE(candidates.empty());
}

// Test that a valid No-Vary-Search hint will generate a speculation
// candidate.
TEST_F(SpeculationRuleSetTest, ValidNoVarySearchHintValueGeneratesCandidate) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  String speculation_script = R"({
    "prefetch": [{
        "source": "list",
        "urls": ["https://example.com/prefetch/list/page1.html"],
        "expects_no_vary_search": "params=(\"a\") "
      }]
    })";

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_EQ(candidates.size(), 1u);

  // Check that the candidate has the correct No-Vary-Search hint.
  EXPECT_THAT(candidates, ElementsAre(::testing::AllOf(
                              HasNoVarySearchHint(), NVSVariesOnKeyOrder(),
                              NVSHasNoVaryParams("a"))));
}

TEST_F(SpeculationRuleSetTest, InvalidNoVarySearchHintValueGeneratesCandidate) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  String speculation_script = R"({
    "prefetch": [{
        "source": "list",
        "urls": ["https://example.com/prefetch/list/page1.html"],
        "expects_no_vary_search": "params=(a) "
      }]
    })";

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_EQ(candidates.size(), 1u);

  // Check that the candidate doesn't have No-Vary-Search hint.
  EXPECT_THAT(candidates, ElementsAre(Not(HasNoVarySearchHint())));
}

// Test that an empty but valid No-Vary-Search hint will generate a speculation
// candidate.
TEST_F(SpeculationRuleSetTest, EmptyNoVarySearchHintValueGeneratesCandidate) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  String speculation_script = R"({
    "prefetch": [{
        "source": "list",
        "urls": ["https://example.com/prefetch/list/page1.html"],
        "expects_no_vary_search": ""
      }]
    })";

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_EQ(candidates.size(), 1u);

  // Check that the candidate has the correct No-Vary-Search hint.
  EXPECT_THAT(candidates[0], Not(HasNoVarySearchHint()));
}

// Test that a No-Vary-Search hint equivalent to the default
// will generate a speculation candidate.
TEST_F(SpeculationRuleSetTest, DefaultNoVarySearchHintValueGeneratesCandidate) {
  DummyPageHolder page_holder;
  StubSpeculationHost speculation_host;

  String speculation_script = R"({
    "prefetch": [{
        "source": "list",
        "urls": ["https://example.com/prefetch/list/page1.html"],
        "expects_no_vary_search": "key-order=?0"
      }]
    })";

  PropagateRulesToStubSpeculationHost(page_holder, speculation_host,
                                      speculation_script);
  const auto& candidates = speculation_host.candidates();
  EXPECT_EQ(candidates.size(), 1u);

  // Check that the candidate has the correct No-Vary-Search hint.
  EXPECT_THAT(candidates[0], Not(HasNoVarySearchHint()));
}

// Tests that No-Vary-Search errors that cause the speculation rules to be
// skipped are logged to the console.
TEST_F(SpeculationRuleSetTest, ConsoleWarningForNoVarySearchHintNotAString) {
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
        "source": "list",
        "urls": ["https://example.com/prefetch/list/page1.html"],
        "expects_no_vary_search": 0
      }]
    })");
  document.head()->appendChild(script);

  EXPECT_TRUE(base::ranges::any_of(
      chrome_client->ConsoleMessages(), [](const String& me
"""


```