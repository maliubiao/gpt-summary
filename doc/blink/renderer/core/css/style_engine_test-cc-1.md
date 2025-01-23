Response:
The user wants a summary of the functionality of the provided C++ code snippet. This is the second part of an eight-part file, so the summary should focus on the tests included in this specific section.

The code snippet contains various tests for the `StyleEngine` in the Chromium Blink engine. These tests examine different aspects of CSS styling, including:

1. **CSSStyleSheet caching**:  Verifies that `StyleEngine` reuses cached `StyleSheetContents` when creating identical stylesheets.
2. **Rule set invalidation**: Tests how changes to CSS rules affect the style of elements based on various selectors (type, custom pseudo-classes, `:host`, `::slotted`, `:host-context`).
3. **Viewport dependent media queries**: Checks if the engine correctly identifies documents with viewport-dependent media queries.
4. **`media` attribute changes on `<style>` tags**: Tests how modifications to the `media` attribute of a `<style>` tag trigger style updates.
5. **`MatchedPropertiesCache` invalidation**: Ensures that the cache is cleared when CSS rules are modified programmatically.
6. **`Visited` pseudo-class and inheritance**: Tests the interaction of `:visited` styles with explicit inheritance and caching.
7. **Style invalidation scheduling**: Examines how style recalculation is scheduled after subtree modifications.
8. **`<meta http-equiv="default-style">`**: Checks the behavior of this meta tag in triggering style updates.
9. **Retrieving stylesheets**: Tests the functionality of getting stylesheets associated with a document or shadow root.
10. **Viewport description**: Verifies how the viewport description is affected by device scale factor.
11. **`MediaQueryAffectingValueChanged`**: Checks if changes in media query values trigger style updates based on the `<style>` tag's `media` attribute.
12. **`:empty` pseudo-class**: Tests how adding or removing content from elements affects the `:empty` pseudo-class and style invalidation.
13. **Media query changes based on user preferences**: Tests how changes in default font size, color scheme (`prefers-color-scheme`), and contrast (`prefers-contrast`) trigger style updates based on media queries.

Therefore, the main function of this part of the `style_engine_test.cc` file is to **test the core functionalities of the `StyleEngine` related to CSS parsing, caching, invalidation, and application, particularly in response to various changes in the document and user preferences.**
这是 `blink/renderer/core/css/style_engine_test.cc` 文件的第二部分，主要功能是 **测试 Blink 渲染引擎中 `StyleEngine` 的各项功能**。具体而言，这部分代码集中测试了以下几个方面：

**1. CSS 样式表缓存 (CSS StyleSheet Caching):**

* **功能:** 测试 `StyleEngine` 是否会缓存相同的 CSS 样式表内容，并在后续创建相同样式表时重用缓存，以提高性能。
* **与 CSS 的关系:** 直接关联，测试了 `StyleEngine` 如何处理和优化 CSS 样式表的创建和存储。
* **假设输入与输出:**
    * **假设输入:** 两个具有相同 CSS 内容的字符串 `sheet_text`。
    * **预期输出:**  第二次调用 `CreateSheet` 时，返回的 `CSSStyleSheet` 对象的 `Contents()` 指针与第一次调用时相同，并且 `IsUsedFromTextCache()` 返回 `true`。在垃圾回收后，再次创建相同的样式表，`IsUsedFromTextCache()` 返回 `false`。
* **用户或编程常见错误:**  没有利用缓存机制可能导致不必要的性能损耗，尤其是在有大量重复样式表的情况下。
* **用户操作到达方式:** 浏览器解析到 `<style>` 标签或通过 JavaScript 动态创建样式表时，会调用 `StyleEngine` 的 `CreateSheet` 方法。

**2. 规则集失效 (Rule Set Invalidation):**

* **功能:** 测试当通过 `ApplyRuleSetInvalidation` 方法添加新的 CSS 规则时，`StyleEngine` 能否正确地识别受影响的元素并重新计算它们的样式。涵盖了不同类型的选择器，包括类型选择器、后代选择器、ID 选择器、自定义伪类、`:host` 伪类、`::slotted` 伪元素和 `:host-context` 伪类。
* **与 HTML, CSS 的关系:** 紧密相关。测试了 CSS 规则的改变如何影响 HTML 元素的样式。
* **假设输入与输出:**
    * **假设输入:** 一段 HTML 字符串，以及要应用的 CSS 规则字符串。
    * **预期输出:** 在应用规则前后，`GetStyleEngine().StyleForElementCount()` 的差值等于受新规则影响的元素数量。
* **用户或编程常见错误:**  编写过于宽泛的 CSS 规则可能导致不必要的样式重计算，影响性能。
* **用户操作到达方式:**  通过 JavaScript 动态添加 `<style>` 标签或者修改现有 `<style>` 标签的内容，或者使用 CSSOM API (如 `insertRule`) 修改样式表规则。

**3. 视口相关媒体查询 (Viewport Dependent Media Queries):**

* **功能:** 测试 `StyleEngine` 是否能正确判断文档中是否存在依赖于视口大小的媒体查询。
* **与 CSS 的关系:**  测试了 `StyleEngine` 如何处理包含 `min-width`, `max-width` 等媒体特性的 CSS 规则。
* **假设输入与输出:**
    * **假设输入:** 包含或不包含视口相关媒体查询的 HTML 字符串。
    * **预期输出:**  `GetStyleEngine().HasViewportDependentMediaQueries()` 返回 `true` 或 `false`。
* **用户操作到达方式:**  在 HTML 中添加包含视口相关媒体查询的 `<style>` 标签。

**4. `style` 标签的 `media` 属性变化:**

* **功能:** 测试当修改 `<style>` 标签的 `media` 属性时，`StyleEngine` 是否会根据新的媒体查询条件重新计算元素的样式。
* **与 HTML, CSS 的关系:**  测试了 HTML 属性的修改如何触发 CSS 样式的更新。
* **假设输入与输出:**
    * **假设输入:** 包含 `<style>` 标签的 HTML 字符串，以及修改后的 `media` 属性值。
    * **预期输出:** 当 `media` 属性的变化导致样式生效或失效时，`GetStyleEngine().StyleForElementCount()` 会增加或减少，元素的计算样式也会相应改变。
* **用户或编程常见错误:**  频繁修改 `media` 属性可能导致频繁的样式重计算，影响性能。
* **用户操作到达方式:**  通过 JavaScript 修改 `<style>` 元素的 `media` 属性。

**5. `MatchedPropertiesCache` 缓存失效:**

* **功能:** 测试当通过 CSSOM API 修改 `CSSStyleRule` 的样式时，`StyleEngine` 的 `MatchedPropertiesCache` 是否会正确失效，确保后续获取的计算样式是最新的。
* **与 CSS 的关系:**  测试了通过 JavaScript 操作 CSSOM API 对样式缓存的影响。
* **假设输入与输出:**
    * **假设输入:** 包含一个 `<style>` 标签和一个元素的 HTML 字符串。通过 CSSOM API 修改样式规则的颜色属性。
    * **预期输出:**  在每次修改颜色属性后，元素的计算颜色都会更新。
* **用户操作到达方式:**  通过 JavaScript 获取样式表对象和样式规则对象，然后调用 `setProperty` 等方法修改样式。

**6. `:visited` 伪类和继承:**

* **功能:** 测试 `:visited` 伪类在显式继承情况下的行为以及 `MatchedPropertiesCache` 的工作方式。
* **与 CSS 的关系:**  测试了特定伪类和 CSS 继承的交互。
* **假设输入与输出:** 包含 `:visited` 规则和显式继承的 HTML 结构，验证样式是否正确应用。

**7. 子树重新计算后调度失效:**

* **功能:** 测试在子树样式重新计算后，是否会正确调度样式失效。
* **与 HTML, CSS 的关系:**  测试了样式系统内部的失效机制。
* **用户操作到达方式:** 触发需要样式重计算的操作，例如修改类名、禁用/启用样式表等。

**8. 空的 `http-equiv="default-style"`:**

* **功能:** 测试 `<meta http-equiv="default-style">` 标签在内容为空时是否会触发样式更新。
* **与 HTML 的关系:**  测试了特定 `<meta>` 标签对样式系统的影响。

**9. 获取样式表列表:**

* **功能:** 测试 `StyleEngine` 获取与文档或 ShadowRoot 关联的样式表列表的功能。
* **与 HTML, CSS 的关系:**  测试了如何获取当前文档或 ShadowRoot 中应用的样式表。

**10. 视口描述 (Viewport Description):**

* **功能:** 测试 `StyleEngine` 如何获取和处理视口描述信息，并受到设备像素比的影响。
* **与 HTML 的关系:**  与 `<meta name="viewport">` 标签相关。

**11. `MediaQueryAffectingValueChanged`:**

* **功能:** 测试当媒体查询相关的值改变时 (例如，屏幕方向改变)，`StyleEngine` 是否会触发必要的样式更新。
* **与 CSS 的关系:**  测试了媒体查询变化对样式更新的影响。

**12. `:empty` 伪类:**

* **功能:** 测试当元素内容为空或不为空时，`:empty` 伪类是否能正确匹配，并触发相应的样式更新。涵盖了移除子节点、插入子节点和修改文本节点数据等情况。
* **与 HTML, CSS 的关系:**  测试了基于元素内容变化的 CSS 伪类的行为。

**13. 媒体查询影响默认字体大小和颜色主题:**

* **功能:** 测试当默认字体大小或颜色主题（通过 `prefers-color-scheme` 媒体特性）发生变化时，媒体查询是否会重新评估并应用相应的样式。
* **与 CSS 的关系:**  测试了用户偏好和浏览器设置如何影响 CSS 样式的应用。

**14. 媒体查询影响 `prefers-contrast`:**

* **功能:** 测试当用户偏好的对比度（通过 `prefers-contrast` 媒体特性）发生变化时，媒体查询是否会重新评估并应用相应的样式。
* **与 CSS 的关系:**  测试了用户偏好如何影响 CSS 样式的应用，特别是与可访问性相关的特性。

**总结来说，这部分 `style_engine_test.cc` 代码主要负责验证 Blink 引擎的 `StyleEngine` 在处理 CSS 样式表、规则、媒体查询以及响应各种文档和用户环境变化时的正确性和效率。** 它通过大量的单元测试，覆盖了 `StyleEngine` 的核心功能，确保了样式系统的稳定性和可靠性。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
iv {}");
  TextPosition min_pos = TextPosition::MinimumPosition();

  CSSStyleSheet* sheet1 = GetStyleEngine().CreateSheet(
      *element, sheet_text, min_pos, PendingSheetType::kNonBlocking,
      RenderBlockingBehavior::kNonBlocking);

  // Check that the first sheet is not using a cached StyleSheetContents.
  EXPECT_FALSE(sheet1->Contents()->IsUsedFromTextCache());

  CSSStyleSheet* sheet2 = GetStyleEngine().CreateSheet(
      *element, sheet_text, min_pos, PendingSheetType::kNonBlocking,
      RenderBlockingBehavior::kNonBlocking);

  // Check that the second sheet uses the cached StyleSheetContents for the
  // first.
  EXPECT_EQ(sheet1->Contents(), sheet2->Contents());
  EXPECT_TRUE(sheet2->Contents()->IsUsedFromTextCache());

  sheet1 = nullptr;
  sheet2 = nullptr;
  element = nullptr;

  // Garbage collection should clear the weak reference in the
  // StyleSheetContents cache.
  ThreadState::Current()->CollectAllGarbageForTesting();

  element = MakeGarbageCollected<HTMLStyleElement>(GetDocument());
  sheet1 = GetStyleEngine().CreateSheet(*element, sheet_text, min_pos,
                                        PendingSheetType::kNonBlocking,
                                        RenderBlockingBehavior::kNonBlocking);

  // Check that we did not use a cached StyleSheetContents after the garbage
  // collection.
  EXPECT_FALSE(sheet1->Contents()->IsUsedFromTextCache());
}

TEST_F(StyleEngineTest, RuleSetInvalidationTypeSelectors) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div>
      <span></span>
      <div></div>
    </div>
    <b></b><b></b><b></b><b></b>
    <i id=i>
      <i>
        <b></b>
      </i>
    </i>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned before_count = GetStyleEngine().StyleForElementCount();
  ApplyRuleSetInvalidation(GetDocument(), "span { background: green}");
  UpdateAllLifecyclePhases();
  unsigned after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(GetDocument(), "body div { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(2u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(GetDocument(), "div * { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(2u, after_count - before_count);

  before_count = GetStyleEngine().StyleForElementCount();
  ApplyRuleSetInvalidation(GetDocument(), "#i b { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);
}

TEST_F(StyleEngineTest, RuleSetInvalidationCustomPseudo) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>progress { -webkit-appearance:none }</style>
    <progress></progress>
    <div></div><div></div><div></div><div></div><div></div><div></div>
  )HTML");

  UpdateAllLifecyclePhases();

  unsigned before_count = GetStyleEngine().StyleForElementCount();
  ApplyRuleSetInvalidation(GetDocument(),
                           "::-webkit-progress-bar { background: green }");
  UpdateAllLifecyclePhases();
  unsigned after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);
}

TEST_F(StyleEngineTest, RuleSetInvalidationHost) {
  GetDocument().body()->setInnerHTML(
      "<div id=nohost></div><div id=host></div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  shadow_root.setInnerHTML("<div></div><div></div><div></div>");
  UpdateAllLifecyclePhases();

  unsigned before_count = GetStyleEngine().StyleForElementCount();
  ApplyRuleSetInvalidation(shadow_root,
                           ":host(#nohost), #nohost { background: green}");
  UpdateAllLifecyclePhases();
  unsigned after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(0u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(shadow_root, ":host(#host) { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(shadow_root, ":host(div) { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(shadow_root, ":host(*) { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(shadow_root, ":host(*) :hover { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(3u, after_count - before_count);
}

TEST_F(StyleEngineTest, RuleSetInvalidationSlotted) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id=host>
      <span slot=other class=s1></span>
      <span class=s2></span>
      <span class=s1></span>
      <span></span>
    </div>
  )HTML");

  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  shadow_root.setInnerHTML("<slot name=other></slot><slot></slot>");
  UpdateAllLifecyclePhases();

  unsigned before_count = GetStyleEngine().StyleForElementCount();
  ApplyRuleSetInvalidation(shadow_root, "::slotted(.s1) { background: green}");
  UpdateAllLifecyclePhases();
  unsigned after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(4u, after_count - before_count);

  before_count = GetStyleEngine().StyleForElementCount();
  ApplyRuleSetInvalidation(shadow_root, "::slotted(*) { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(4u, after_count - before_count);
}

TEST_F(StyleEngineTest, RuleSetInvalidationHostContext) {
  GetDocument().body()->setInnerHTML(
      "<div class=match><div id=host></div></div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  shadow_root.setInnerHTML("<div></div><div class=a></div><div></div>");
  UpdateAllLifecyclePhases();

  unsigned before_count = GetStyleEngine().StyleForElementCount();
  ApplyRuleSetInvalidation(shadow_root,
                           ":host-context(.nomatch) .a { background: green}");
  UpdateAllLifecyclePhases();
  unsigned after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(0u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(shadow_root,
                           ":host-context(.match) .a { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(shadow_root,
                           ":host-context(:hover) { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);

  before_count = after_count;
  ApplyRuleSetInvalidation(shadow_root,
                           ":host-context(#host) { background: green}");
  UpdateAllLifecyclePhases();
  after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);
}

TEST_F(StyleEngineTest, HasViewportDependentMediaQueries) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>div {}</style>
    <style id='sheet' media='(min-width: 200px)'>
      div {}
    </style>
  )HTML");

  Element* style_element = GetDocument().getElementById(AtomicString("sheet"));

  for (unsigned i = 0; i < 10; i++) {
    GetDocument().body()->RemoveChild(style_element);
    UpdateAllLifecyclePhases();
    GetDocument().body()->AppendChild(style_element);
    UpdateAllLifecyclePhases();
  }

  EXPECT_TRUE(GetStyleEngine().HasViewportDependentMediaQueries());

  GetDocument().body()->RemoveChild(style_element);
  UpdateAllLifecyclePhases();

  EXPECT_FALSE(GetStyleEngine().HasViewportDependentMediaQueries());
}

TEST_F(StyleEngineTest, StyleMediaAttributeStyleChange) {
  GetDocument().body()->setInnerHTML(
      "<style id='s1' media='(max-width: 1px)'>#t1 { color: green }</style>"
      "<div id='t1'>Green</div><div></div>");
  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  ASSERT_TRUE(t1);
  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  unsigned before_count = GetStyleEngine().StyleForElementCount();

  Element* s1 = GetDocument().getElementById(AtomicString("s1"));
  s1->setAttribute(blink::html_names::kMediaAttr,
                   AtomicString("(max-width: 2000px)"));
  UpdateAllLifecyclePhases();

  unsigned after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(1u, after_count - before_count);

  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, StyleMediaAttributeNoStyleChange) {
  GetDocument().body()->setInnerHTML(
      "<style id='s1' media='(max-width: 1000px)'>#t1 { color: green }</style>"
      "<div id='t1'>Green</div><div></div>");
  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  ASSERT_TRUE(t1);
  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  unsigned before_count = GetStyleEngine().StyleForElementCount();

  Element* s1 = GetDocument().getElementById(AtomicString("s1"));
  s1->setAttribute(blink::html_names::kMediaAttr,
                   AtomicString("(max-width: 2000px)"));
  UpdateAllLifecyclePhases();

  unsigned after_count = GetStyleEngine().StyleForElementCount();
  EXPECT_EQ(0u, after_count - before_count);

  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, ModifyStyleRuleMatchedPropertiesCache) {
  // Test that the MatchedPropertiesCache is cleared when a StyleRule is
  // modified. The MatchedPropertiesCache caches results based on
  // CSSPropertyValueSet pointers. When a mutable CSSPropertyValueSet is
  // modified, the pointer doesn't change, yet the declarations do.

  GetDocument().body()->setInnerHTML(
      "<style id='s1'>#t1 { color: blue }</style>"
      "<div id='t1'>Green</div>");
  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  ASSERT_TRUE(t1);
  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 0, 255),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  auto* sheet = To<CSSStyleSheet>(GetDocument().StyleSheets().item(0));
  ASSERT_TRUE(sheet);
  DummyExceptionStateForTesting exception_state;
  ASSERT_TRUE(sheet->cssRules(exception_state));
  CSSStyleRule* style_rule =
      To<CSSStyleRule>(sheet->cssRules(exception_state)->item(0));
  ASSERT_FALSE(exception_state.HadException());
  ASSERT_TRUE(style_rule);
  ASSERT_TRUE(style_rule->style());

  // Modify the CSSPropertyValueSet once to make it a mutable set. Subsequent
  // modifications will not change the CSSPropertyValueSet pointer and cache
  // hash value will be the same.
  style_rule->style()->setProperty(GetDocument().GetExecutionContext(), "color",
                                   "red", "", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhases();

  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  style_rule->style()->setProperty(GetDocument().GetExecutionContext(), "color",
                                   "green", "", ASSERT_NO_EXCEPTION);
  UpdateAllLifecyclePhases();

  ASSERT_TRUE(t1->GetComputedStyle());
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      t1->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, VisitedExplicitInheritanceMatchedPropertiesCache) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      :visited { overflow: inherit }
    </style>
    <span id="span"><a href></a></span>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* span = GetDocument().getElementById(AtomicString("span"));
  const ComputedStyle* style = span->GetComputedStyle();
  EXPECT_FALSE(style->ChildHasExplicitInheritance());

  style = span->firstElementChild()->GetComputedStyle();

  ComputedStyleBuilder builder(*style);
  EXPECT_TRUE(MatchedPropertiesCache::IsStyleCacheable(builder));

  span->SetInlineStyleProperty(CSSPropertyID::kColor, "blue");

  // Should not DCHECK on applying overflow:inherit on cached matched properties
  UpdateAllLifecyclePhases();
}

TEST_F(StyleEngineTest, ScheduleInvalidationAfterSubtreeRecalc) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style id='s1'>
      .t1 span { color: green }
      .t2 span { color: green }
    </style>
    <style id='s2'>div { background: lime }</style>
    <div id='t1'></div>
    <div id='t2'></div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  ASSERT_TRUE(t1);
  ASSERT_TRUE(t2);

  UpdateAllLifecyclePhases();

  // PlatformColorsChanged() triggers SubtreeStyleChange on document(). If that
  // for some reason should change, this test will start failing and the
  // SubtreeStyleChange must be set another way.
  // Calling setNeedsStyleRecalc() explicitly with an arbitrary reason instead
  // requires us to CORE_EXPORT the reason strings.
  GetStyleEngine().PlatformColorsChanged();

  // Check that no invalidations sets are scheduled when the document node is
  // already SubtreeStyleChange.
  t2->setAttribute(blink::html_names::kClassAttr, AtomicString("t2"));
  EXPECT_FALSE(GetDocument().NeedsStyleRecalc());
  EXPECT_FALSE(GetDocument().ChildNeedsStyleRecalc());
  UpdateAllLifecyclePhases();  // Mark everything as clean.

  // Toggling the s2 style sheet should normally touch t1 and t2...
  auto* s2 =
      To<HTMLStyleElement>(GetDocument().getElementById(AtomicString("s2")));
  ASSERT_TRUE(s2);
  s2->setDisabled(true);
  GetStyleEngine().UpdateActiveStyle();
  EXPECT_TRUE(GetDocument().documentElement()->ChildNeedsStyleRecalc());
  EXPECT_TRUE(t1->NeedsStyleRecalc());
  EXPECT_TRUE(t2->NeedsStyleRecalc());
  UpdateAllLifecyclePhases();  // Mark everything as clean.

  // ...but if the root is marked as kSubtreeRecalc, it should not visit them,
  // and thus not mark them for recalc.
  GetStyleEngine().PlatformColorsChanged();
  s2->setDisabled(false);
  GetStyleEngine().UpdateActiveStyle();
  EXPECT_FALSE(GetDocument().documentElement()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(t1->NeedsStyleRecalc());
  EXPECT_FALSE(t2->NeedsStyleRecalc());
  UpdateAllLifecyclePhases();  // Mark everything as clean.

  // Toggling the s1 stylesheet shouldn't touch either, since it matches
  // nothing.
  auto* s1 =
      To<HTMLStyleElement>(GetDocument().getElementById(AtomicString("s1")));
  ASSERT_TRUE(s1);
  s1->setDisabled(true);
  GetStyleEngine().UpdateActiveStyle();
  EXPECT_FALSE(GetDocument().documentElement()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(t1->NeedsStyleRecalc());
  EXPECT_FALSE(t2->NeedsStyleRecalc());
  UpdateAllLifecyclePhases();  // Mark everything as clean.

  // And thus, kSubtreeRecalc on the root shouldn't make any difference.
  GetStyleEngine().PlatformColorsChanged();
  s1->setDisabled(false);
  GetStyleEngine().UpdateActiveStyle();
  EXPECT_FALSE(GetDocument().documentElement()->ChildNeedsStyleRecalc());
  EXPECT_FALSE(t1->NeedsStyleRecalc());
  EXPECT_FALSE(t2->NeedsStyleRecalc());
}

TEST_F(StyleEngineTest, EmptyHttpEquivDefaultStyle) {
  GetDocument().body()->setInnerHTML(
      "<style>div { color:pink }</style><div id=container></div>");
  UpdateAllLifecyclePhases();

  EXPECT_FALSE(GetStyleEngine().NeedsActiveStyleUpdate());

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  container->setInnerHTML("<meta http-equiv='default-style' content=''>");
  EXPECT_FALSE(GetStyleEngine().NeedsActiveStyleUpdate());

  container->setInnerHTML(
      "<meta http-equiv='default-style' content='preferred'>");
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest, StyleSheetsForStyleSheetList_Document) {
  GetDocument().body()->setInnerHTML("<style>span { color: green }</style>");
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());

  const auto& sheet_list =
      GetStyleEngine().StyleSheetsForStyleSheetList(GetDocument());
  EXPECT_EQ(1u, sheet_list.size());
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());

  GetDocument().body()->setInnerHTML(
      "<style>span { color: green }</style><style>div { color: pink }</style>");
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());

  const auto& second_sheet_list =
      GetStyleEngine().StyleSheetsForStyleSheetList(GetDocument());
  EXPECT_EQ(2u, second_sheet_list.size());
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest, StyleSheetsForStyleSheetList_ShadowRoot) {
  GetDocument().body()->setInnerHTML("<div id='host'></div>");
  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);

  UpdateAllLifecyclePhases();
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);

  shadow_root.setInnerHTML("<style>span { color: green }</style>");
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());

  const auto& sheet_list =
      GetStyleEngine().StyleSheetsForStyleSheetList(shadow_root);
  EXPECT_EQ(1u, sheet_list.size());
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());

  shadow_root.setInnerHTML(
      "<style>span { color: green }</style><style>div { color: pink }</style>");
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());

  const auto& second_sheet_list =
      GetStyleEngine().StyleSheetsForStyleSheetList(shadow_root);
  EXPECT_EQ(2u, second_sheet_list.size());
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest, ViewportDescription) {
  ScopedTestingPlatformSupport<TestingPlatformSupport> platform;
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.Initialize();
  web_view_impl->MainFrameWidget()->SetDeviceScaleFactorForTesting(1.f);
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();

  auto desc = document->GetViewportData().GetViewportDescription();
  float min_width = desc.min_width.GetFloatValue();
  float max_width = desc.max_width.GetFloatValue();
  float min_height = desc.min_height.GetFloatValue();
  float max_height = desc.max_height.GetFloatValue();

  const float device_scale = 3.5f;
  web_view_impl->MainFrameWidget()->SetDeviceScaleFactorForTesting(
      device_scale);
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  desc = document->GetViewportData().GetViewportDescription();
  EXPECT_FLOAT_EQ(device_scale * min_width, desc.min_width.GetFloatValue());
  EXPECT_FLOAT_EQ(device_scale * max_width, desc.max_width.GetFloatValue());
  EXPECT_FLOAT_EQ(device_scale * min_height, desc.min_height.GetFloatValue());
  EXPECT_FLOAT_EQ(device_scale * max_height, desc.max_height.GetFloatValue());
}

TEST_F(StyleEngineTest, MediaQueryAffectingValueChanged_StyleElementNoMedia) {
  GetDocument().body()->setInnerHTML("<style>div{color:pink}</style>");
  UpdateAllLifecyclePhases();
  GetStyleEngine().MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  EXPECT_FALSE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest,
       MediaQueryAffectingValueChanged_StyleElementMediaNoValue) {
  GetDocument().body()->setInnerHTML("<style media>div{color:pink}</style>");
  UpdateAllLifecyclePhases();
  GetStyleEngine().MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  EXPECT_FALSE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest,
       MediaQueryAffectingValueChanged_StyleElementMediaEmpty) {
  GetDocument().body()->setInnerHTML("<style media=''>div{color:pink}</style>");
  UpdateAllLifecyclePhases();
  GetStyleEngine().MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  EXPECT_FALSE(GetStyleEngine().NeedsActiveStyleUpdate());
}

// TODO(futhark@chromium.org): The test cases below where all queries are either
// "all" or "not all", we could have detected those and not trigger an active
// stylesheet update for those cases.

TEST_F(StyleEngineTest,
       MediaQueryAffectingValueChanged_StyleElementMediaNoValid) {
  GetDocument().body()->setInnerHTML(
      "<style media=',,'>div{color:pink}</style>");
  UpdateAllLifecyclePhases();
  GetStyleEngine().MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest, MediaQueryAffectingValueChanged_StyleElementMediaAll) {
  GetDocument().body()->setInnerHTML(
      "<style media='all'>div{color:pink}</style>");
  UpdateAllLifecyclePhases();
  GetStyleEngine().MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest,
       MediaQueryAffectingValueChanged_StyleElementMediaNotAll) {
  GetDocument().body()->setInnerHTML(
      "<style media='not all'>div{color:pink}</style>");
  UpdateAllLifecyclePhases();
  GetStyleEngine().MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest, MediaQueryAffectingValueChanged_StyleElementMediaType) {
  GetDocument().body()->setInnerHTML(
      "<style media='print'>div{color:pink}</style>");
  UpdateAllLifecyclePhases();
  GetStyleEngine().MediaQueryAffectingValueChanged(MediaValueChange::kOther);
  EXPECT_TRUE(GetStyleEngine().NeedsActiveStyleUpdate());
}

TEST_F(StyleEngineTest, EmptyPseudo_RemoveLast) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .empty:empty + span { color: purple }
    </style>
    <div id=t1 class=empty>Text</div>
    <span></span>
    <div id=t2 class=empty><span></span></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  t1->firstChild()->remove();
  EXPECT_TRUE(t1->NeedsStyleInvalidation());

  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  t2->firstChild()->remove();
  EXPECT_TRUE(t2->NeedsStyleInvalidation());
}

TEST_F(StyleEngineTest, EmptyPseudo_RemoveNotLast) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .empty:empty + span { color: purple }
    </style>
    <div id=t1 class=empty>Text<span></span></div>
    <span></span>
    <div id=t2 class=empty><span></span><span></span></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  t1->firstChild()->remove();
  EXPECT_FALSE(t1->NeedsStyleInvalidation());

  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  t2->firstChild()->remove();
  EXPECT_FALSE(t2->NeedsStyleInvalidation());
}

TEST_F(StyleEngineTest, EmptyPseudo_InsertFirst) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .empty:empty + span { color: purple }
    </style>
    <div id=t1 class=empty></div>
    <span></span>
    <div id=t2 class=empty></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  t1->appendChild(Text::Create(GetDocument(), "Text"));
  EXPECT_TRUE(t1->NeedsStyleInvalidation());

  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  t2->appendChild(MakeGarbageCollected<HTMLSpanElement>(GetDocument()));
  EXPECT_TRUE(t2->NeedsStyleInvalidation());
}

TEST_F(StyleEngineTest, EmptyPseudo_InsertNotFirst) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .empty:empty + span { color: purple }
    </style>
    <div id=t1 class=empty>Text</div>
    <span></span>
    <div id=t2 class=empty><span></span></div>
    <span></span>
  )HTML");

  UpdateAllLifecyclePhases();

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  t1->appendChild(Text::Create(GetDocument(), "Text"));
  EXPECT_FALSE(t1->NeedsStyleInvalidation());

  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  t2->appendChild(MakeGarbageCollected<HTMLSpanElement>(GetDocument()));
  EXPECT_FALSE(t2->NeedsStyleInvalidation());
}

TEST_F(StyleEngineTest, EmptyPseudo_ModifyTextData_SingleNode) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .empty:empty + span { color: purple }
    </style>
    <div id=t1 class=empty>Text</div>
    <span></span>
    <div id=t2 class=empty></div>
    <span></span>
    <div id=t3 class=empty>Text</div>
    <span></span>
  )HTML");

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  Element* t3 = GetDocument().getElementById(AtomicString("t3"));

  t2->appendChild(Text::Create(GetDocument(), ""));

  UpdateAllLifecyclePhases();

  To<Text>(t1->firstChild())->setData("");
  EXPECT_TRUE(t1->NeedsStyleInvalidation());

  To<Text>(t2->firstChild())->setData("Text");
  EXPECT_TRUE(t2->NeedsStyleInvalidation());

  // This is not optimal. We do not detect that we change text to/from
  // non-empty string.
  To<Text>(t3->firstChild())->setData("NewText");
  EXPECT_TRUE(t3->NeedsStyleInvalidation());
}

TEST_F(StyleEngineTest, EmptyPseudo_ModifyTextData_HasSiblings) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .empty:empty + span { color: purple }
    </style>
    <div id=t1 class=empty>Text<span></span></div>
    <span></span>
    <div id=t2 class=empty><span></span></div>
    <span></span>
    <div id=t3 class=empty>Text<span></span></div>
    <span></span>
  )HTML");

  Element* t1 = GetDocument().getElementById(AtomicString("t1"));
  Element* t2 = GetDocument().getElementById(AtomicString("t2"));
  Element* t3 = GetDocument().getElementById(AtomicString("t3"));

  t2->appendChild(Text::Create(GetDocument(), ""));

  UpdateAllLifecyclePhases();

  To<Text>(t1->firstChild())->setData("");
  EXPECT_FALSE(t1->NeedsStyleInvalidation());

  To<Text>(t2->lastChild())->setData("Text");
  EXPECT_FALSE(t2->NeedsStyleInvalidation());

  To<Text>(t3->firstChild())->setData("NewText");
  EXPECT_FALSE(t3->NeedsStyleInvalidation());
}

TEST_F(StyleEngineTest, MediaQueriesChangeDefaultFontSize) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (max-width: 40em) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  GetDocument().GetSettings()->SetDefaultFontSize(40);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangeColorScheme) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red }
      @media (prefers-color-scheme: dark) {
        body { color: green }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangeColorSchemeForcedDarkMode) {
  GetDocument().GetSettings()->SetForceDarkModeEnabled(true);
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @media (prefers-color-scheme: dark) {
        body { color: green }
      }
      @media (prefers-color-scheme: light) {
        body { color: red }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangePrefersContrast) {
  ScopedForcedColorsForTest forced_scoped_feature(true);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kNoPreference);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red; forced-color-adjust: none; }
      @media (prefers-contrast: no-preference) {
        body { color: green }
      }
      @media (prefers-contrast) {
        body { color: blue }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kMore);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kLess);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kCustom);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, MediaQueriesChangeSpecificPrefersContrast) {
  ScopedForcedColorsForTest forced_scoped_feature(true);

  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kNoPreference);

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { color: red; forced-color-adjust: none; }
      @media (prefers-contrast: more) {
        body { color: blue }
      }
      @media (prefers-contrast: less) {
        body { color: orange }
      }
      @media (prefers-contrast: custom) {
        body { color: yellow }
      }
    </style>
    <body></body>
  )HTML");

  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kMore);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  color_scheme_helper.SetPreferredContrast(
      mojom::blink::PreferredContrast::kLess);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 165, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyCo
```