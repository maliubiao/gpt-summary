Response:
The user wants to understand the functionality of the `style_engine_test.cc` file in the Chromium Blink engine. They've provided a snippet of the file and want me to:

1. **List the file's functions.**  This will involve analyzing the test cases present in the code.
2. **Explain its relationship to Javascript, HTML, and CSS.** This requires connecting the test scenarios to core web technologies.
3. **Provide examples with input/output for logical deductions.**  This means identifying tests that simulate a change and verify the expected outcome.
4. **Illustrate common user/programming errors.** This involves thinking about how developers might misuse the features being tested.
5. **Describe how a user might reach this code during debugging.**  This requires imagining the steps a developer would take when investigating style-related issues.
6. **Summarize the file's functionality (as the 6th part of 8).** This requires synthesizing the previous points into a concise overview.

Let's break down the provided code snippet:

* **Test Fixture:** The code uses `StyleEngineTest` which suggests it's testing the `StyleEngine` class.
* **Test Cases:** Each `TEST_F(StyleEngineTest, ...)` block represents an individual test case. The names of these test cases are indicative of the specific functionality being tested. I'll need to analyze these names carefully.
* **HTML Setup:** Each test case starts by setting up an HTML structure using `GetDocument().documentElement()->setInnerHTML(...)` or similar.
* **CSS Styling:**  Many test cases include `<style>` blocks within the HTML to define CSS rules.
* **DOM Manipulation:**  Some tests manipulate the DOM (e.g., adding classes, appending/removing elements).
* **Style Recalculation and Layout:**  Functions like `UpdateAllLifecyclePhases()`, `GetDocument().UpdateStyleAndLayoutTree()`, and `GetStyleEngine().RecalcStyle()` are used to trigger style and layout updates.
* **Assertions:** `EXPECT_...` and `ASSERT_...` macros are used to verify the expected state of the document and style engine after the test actions. These are crucial for understanding the intended behavior.
* **Specific CSS Features:** Some test names and CSS code snippets hint at specific CSS features being tested (e.g., container queries, anchor positioning, cascade layers, nesting).
* **Use Counters:** Some tests interact with use counters (`IsUseCounted`, `ClearUseCounter`), indicating they are testing the tracking of CSS feature usage.
* **Shadow DOM:**  Several tests involve Shadow DOM (`AttachShadowRootForTesting`).

**Plan:**

1. **Categorize the test cases:**  Group them based on the CSS feature or aspect of the style engine they are testing (e.g., container queries, anchor positioning, cascade layers, performance optimizations).
2. **For each category:**
    * Briefly explain the feature/aspect.
    * Show how the test case relates to HTML, CSS, and potentially JavaScript.
    * Provide a simplified input/output example if a logical deduction is being made.
    * Consider potential user errors related to the feature.
3. **Think about the debugging scenario:** Imagine a developer encountering a style-related bug in one of these areas and how they might end up examining the `style_engine_test.cc` file.
4. **Summarize:** Combine the findings into a concise description of the file's purpose.
这是目录为 `blink/renderer/core/css/style_engine_test.cc` 的 Chromium Blink 引擎源代码文件的第 6 部分，共 8 部分。基于提供的代码片段，我们可以归纳一下它的功能，并结合其与 JavaScript、HTML、CSS 的关系进行说明。

**归纳功能:**

这部分 `style_engine_test.cc` 的主要功能是**测试 Blink 引擎中 CSS 样式计算和应用的相关逻辑，特别是针对一些新的或复杂的 CSS 特性**。它通过创建各种 HTML 结构和 CSS 样式，然后模拟不同的场景（例如 DOM 变更、触发布局等），来验证样式引擎的行为是否符合预期。测试的重点包括：

* **容器查询 (Container Queries):** 测试了在 `display: none` 的元素位于容器查询容器内时，样式更新和布局的影响。
* **锚点定位 (Anchor Positioning):** 测试了 `anchor()` 和 `anchor-size()` 函数的计算和应用，包括在 DOM 变化后样式更新和布局的触发。
* **样式拒绝优化 (Style Reject):** 测试了样式引擎在进行样式计算时，如何快速拒绝不匹配的 CSS 规则，例如针对视频控件、Shadow DOM 的 `::slotted()` 选择器、CSS 嵌套以及复杂的 `:is()` 选择器。
* **伪元素匹配 (Pseudo-element Matching):** 测试了像 `::-webkit-scrollbar-button` 这样的滚动条伪元素是否会错误地匹配到普通元素。
* **用户代理样式 (User-Agent Styles):** 测试了用户代理样式是否按命名空间正确应用，例如 `<audio>` 标签的默认 `display: none` 样式不应应用到非 HTML 命名空间的元素。
* **CSS 特性使用计数 (Use Counters):** 测试了各种 CSS 特性的使用情况是否被正确统计，例如 `::target-text`、`@counter-style`、`@container`、样式容器查询、CSS 嵌套和级联层。
* **样式重计算根节点 (Style Recalc Root):** 测试了在 DOM 结构变化时，样式重计算的根节点是否正确。
* **级联层 (Cascade Layers):** 测试了级联层在不同作用域（用户代理、文档、Shadow DOM）中的管理和排序，以及在多个样式表存在时的合并规则。
* **非 slotted 元素的样式更新 (Non-Slotted Style Dirty):** 测试了在 Shadow DOM 中，非 slotted 子元素的样式更新和重计算逻辑。

**与 JavaScript, HTML, CSS 的关系举例说明:**

1. **容器查询 (CSS & HTML & JavaScript):**
   * **CSS:**  测试了形如 `@container (width > 0px) { ... }` 的 CSS 规则，以及依赖于容器大小的样式变化。
   * **HTML:**  创建了包含容器元素和被容器查询影响的元素的 HTML 结构。
   * **JavaScript (模拟):**  通过 `container->classList().Add(AtomicString("toggle"))` 模拟 JavaScript 修改了容器元素的 class，从而触发容器查询的条件变化。
   * **假设输入与输出:**
     * **输入 HTML:** `<div id="container"><div id="a"></div></div><style>@container #container (min-width: 100px) { #a { display: block; } }</style>`
     * **初始状态:** `container` 宽度小于 100px，`a` 可能默认是 `display: none;` 或其他。
     * **JavaScript 操作:** `document.getElementById('container').style.width = '150px';`
     * **预期输出:** 样式引擎重新计算样式后，`a` 的 `display` 属性变为 `block`。

2. **锚点定位 (CSS & HTML):**
   * **CSS:** 测试了 `anchor(--a left)` 和 `anchor-size(--a width)` 这样的 CSS 函数，用于根据锚点元素的位置和尺寸来定位或设置元素的大小。
   * **HTML:** 创建了包含锚点元素（例如 `#anchor` 设置了 `anchor-name: --a;`）和被锚定元素（例如 `#anchored` 使用了 `anchor()` 函数）的 HTML 结构。
   * **假设输入与输出:**
     * **输入 HTML:** `<div id="anchor" style="position: absolute; left: 100px; top: 200px; width: 50px;"></div><div id="anchored" style="position: absolute; left: anchor(--anchor-element left);"></div>`
     * **预期输出:** 样式引擎计算后，`anchored` 元素的 `left` 值将为 `100px`（与 `anchor` 元素的 `left` 值相同）。

3. **样式拒绝优化 (CSS & HTML):**
   * **CSS:**  测试了各种 CSS 选择器，例如 `.notfound span`，并验证当页面中不存在匹配这些选择器的元素时，样式引擎是否能快速跳过这些规则。
   * **HTML:**  创建了相应的 HTML 结构，有时故意不包含与某些 CSS 规则匹配的元素。
   * **用户使用错误:**  开发者可能会编写大量冗余或不必要的 CSS 规则，例如针对永远不会出现的 class 或元素编写样式。样式拒绝优化可以提高性能，避免对这些规则进行不必要的计算。

4. **级联层 (CSS & HTML):**
   * **CSS:** 测试了 `@layer` 规则，用于显式地控制 CSS 规则的层叠顺序。
   * **HTML:**  创建包含多个 `<style>` 标签的 HTML，并在其中定义不同的级联层顺序。
   * **用户使用错误:**  开发者可能不理解级联层的概念，导致样式优先级混乱，或者在多个样式表中定义冲突的级联层顺序，导致意想不到的结果。

**用户操作如何一步步的到达这里，作为调试线索:**

假设开发者在开发过程中遇到以下问题：

1. **问题:** 某个元素的样式在满足容器查询条件时没有正确更新。
2. **调试步骤:**
   * 开发者会检查 CSS 规则，确认容器查询的条件和目标元素的样式是否正确。
   * 他们可能会使用浏览器的开发者工具查看元素的 computed style，确认样式是否被应用。
   * 如果怀疑是容器查询的逻辑问题，他们可能会尝试修改容器的尺寸或条件，观察样式是否变化。
   * 如果仍然无法解决，他们可能会搜索 Blink 引擎的源代码，特别是与容器查询相关的部分。
   * **到达 `style_engine_test.cc`:** 开发者可能会搜索包含 "container query" 关键字的测试文件，找到 `style_engine_test.cc`，并查看其中 `UpdateStyleAndLayoutTreeWithContainerQueryForHiddenElement` 等测试用例，以了解 Blink 引擎是如何测试和处理这种情况的。他们可以阅读测试代码，理解样式引擎的预期行为，并对比自己的代码和测试用例的场景，找到可能的问题所在。

**总结:**

这部分 `style_engine_test.cc` 通过大量的单元测试，细致地检验了 Blink 引擎在处理复杂 CSS 特性时的正确性和效率。它覆盖了容器查询、锚点定位、样式拒绝优化、级联层等多个关键领域，确保了样式引擎能够准确、高效地解析和应用 CSS 规则，从而保证网页的渲染效果符合预期。开发者可以通过阅读这些测试用例，深入理解 Blink 引擎的内部工作原理，并借鉴其测试方法来验证自己的代码。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
le {
        --x:1;
      }
      #a {
        display: none;
      }
      /* Intentionally no @container rule. */
    </style>
    <main id=container>
      <div id=a></div>
    </main>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());
  EXPECT_FALSE(GetStyleEngine().StyleAffectedByLayout());

  Element* container = GetDocument().getElementById(AtomicString("container"));
  Element* a = GetDocument().getElementById(AtomicString("a"));
  ASSERT_TRUE(container);
  ASSERT_TRUE(a);

  EXPECT_FALSE(GetDocument().View()->NeedsLayout());
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdateForNode(*a));
  EXPECT_FALSE(GetStyleEngine().StyleAffectedByLayout());

  // Mutate DOM to invalidate style recalc.
  container->classList().Add(AtomicString("toggle"));
  EXPECT_EQ(Document::StyleAndLayoutTreeUpdate::kAnalyzed,
            GetDocument().CalculateStyleAndLayoutTreeUpdate());

  // Pretend something needs layout.
  GetDocument().View()->SetNeedsLayout();
  EXPECT_TRUE(GetDocument().View()->NeedsLayout());
  EXPECT_TRUE(GetDocument().NeedsLayoutTreeUpdateForNode(*a));

  // Even though style doesn't depend on layout in this case, we still need to
  // do a layout upgrade for elements that are 1) in display:none, and 2)
  // inside a container query container.
  //
  // See implementation of `ElementLayoutUpgrade::ShouldUpgrade` for more
  // information.
  GetDocument().UpdateStyleAndLayoutTreeForElement(a,
                                                   DocumentUpdateReason::kTest);
  EXPECT_FALSE(GetStyleEngine().StyleAffectedByLayout());
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdateForNode(*a));
}

TEST_F(StyleEngineTest, UpdateStyleAndLayoutTreeWithAnchorQuery) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #anchored {
        position: absolute;
        left: anchor(--a left, 42px);
      }
      #anchored.toggle {
        left: anchor(--a left, 84px);
      }

      #inner { left: inherit; }
    </style>
    <main id=anchored>
      <div id=inner></div>
    </main>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());

  Element* anchored = GetDocument().getElementById(AtomicString("anchored"));
  ASSERT_TRUE(anchored);
  anchored->classList().Add(AtomicString("toggle"));

  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout())
      << "Layout should happen as part of UpdateStyleAndLayoutTree";

  Element* inner = GetDocument().getElementById(AtomicString("inner"));
  ASSERT_TRUE(inner);
  EXPECT_EQ("84px", ComputedValue(inner, "left")->CssText());
}

TEST_F(StyleEngineTest, UpdateStyleAndLayoutTreeForElementWithAnchorQuery) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #anchored {
        position: absolute;
        left: anchor(--a left, 42px);
      }
      #anchored.toggle {
        left: anchor(--a left, 84px);
      }

      #inner { left: inherit; }
    </style>
    <main id=anchored>
      <div id=inner></div>
    </main>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());

  Element* anchored = GetDocument().getElementById(AtomicString("anchored"));
  ASSERT_TRUE(anchored);
  anchored->classList().Add(AtomicString("toggle"));

  Element* inner = GetDocument().getElementById(AtomicString("inner"));
  ASSERT_TRUE(inner);

  GetDocument().UpdateStyleAndLayoutTreeForElement(inner,
                                                   DocumentUpdateReason::kTest);
  EXPECT_FALSE(GetDocument().View()->NeedsLayout())
      << "Layout should happen as part of UpdateStyleAndLayoutTreeForElement";

  EXPECT_EQ("84px", ComputedValue(inner, "left")->CssText());
}

TEST_F(StyleEngineTest, AnchorQueryComputed) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #anchor {
        anchor-name: --a;
        position: absolute;
        width: 100px;
        height: 100px;
        left: 200px;
        top: 300px;
      }
      #anchored {
        position: absolute;
        width: anchor-size(--a width);
        height: anchor-size(--unknown height, 42px);
        left: anchor(--a right);
        top: anchor(--a bottom);
      }
    </style>
    <div id=anchor>Anchor</div>
    <div id=anchored>Anchored</div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* anchored = GetDocument().getElementById(AtomicString("anchored"));
  ASSERT_TRUE(anchored);

  EXPECT_EQ("300px", ComputedValue(anchored, "left")->CssText());
  EXPECT_EQ("400px", ComputedValue(anchored, "top")->CssText());
  EXPECT_EQ("100px", ComputedValue(anchored, "width")->CssText());
  EXPECT_EQ("42px", ComputedValue(anchored, "height")->CssText());
}

TEST_F(StyleEngineTest, AnchorQueryComputedChild) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #anchor {
        anchor-name: --a;
        position: absolute;
        width: 100px;
        height: 100px;
        left: 200px;
        top: 300px;
      }
      #anchored {
        position: absolute;
        width: anchor-size(--a width);
        height: width: anchor-size(--a height);
      }
      #child {
        width: anchor-size(--a width, 42px);
        height: inherit;
      }
    </style>
    <div id=anchor>Anchor</div>
    <div id=anchored>
      <div id=child>Child</div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* child = GetDocument().getElementById(AtomicString("child"));
  ASSERT_TRUE(child);

  // Non-absolutely positioned child may not evaluate queries.
  EXPECT_EQ("42px", ComputedValue(child, "width")->CssText());
}

TEST_F(StyleEngineTest, VideoControlsReject) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <video controls></video>
    <div id="target"></div>
  )HTML");
  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_fast_rejected);
  EXPECT_EQ(0u, stats->rules_rejected);

  Element* target = GetDocument().getElementById(AtomicString("target"));
  ASSERT_TRUE(target);
  target->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // There should be no UA rules for a div to reject
  EXPECT_EQ(0u, stats->rules_fast_rejected);
  EXPECT_EQ(0u, stats->rules_rejected);
}

TEST_F(StyleEngineTest, FastRejectForHostChild) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .notfound span {
        color: pink;
      }
    </style>
    <div id="host">
      <span id="slotted"></span>
    </div>
  )HTML");

  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(R"HTML(
    <slot></slot>
  )HTML");
  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_fast_rejected);

  Element* span = GetDocument().getElementById(AtomicString("slotted"));
  ASSERT_TRUE(span);
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // Should fast reject ".notfound span"
  EXPECT_EQ(1u, stats->rules_fast_rejected);
}

TEST_F(StyleEngineTest, RejectSlottedSelector) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="host">
      <span id="slotted"></span>
    </div>
  )HTML");

  Element* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(R"HTML(
    <style>
      .notfound ::slotted(span) {
        color: pink;
      }
    </style>
    <slot></slot>
  )HTML");
  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_fast_rejected);

  Element* span = GetDocument().getElementById(AtomicString("slotted"));
  ASSERT_TRUE(span);
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // Should fast reject ".notfound ::slotted(span)"
  EXPECT_EQ(1u, stats->rules_fast_rejected);
}

TEST_F(StyleEngineTest, FastRejectForNesting) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .notfound {
        & span {
          color: pink;
        }
      }
    </style>
    <div>
      <span id="child">not pink</span>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_fast_rejected);

  Element* span = GetDocument().getElementById(AtomicString("child"));
  ASSERT_TRUE(span);
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // Should fast reject "& span"
  EXPECT_EQ(1u, stats->rules_fast_rejected);
}

TEST_F(StyleEngineTest, FastRejectForComplexSingleIs) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      :is(#parent .notfound) > span {
        color: pink;
      }
    </style>
    <div id="parent">
      <span id="child">not pink</span>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_fast_rejected);

  Element* span = GetDocument().getElementById(AtomicString("child"));
  ASSERT_TRUE(span);
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // Should fast reject ":is(#parent .notfound) > span", even though it is not
  // the same as "#parent .notfound > span".
  EXPECT_EQ(1u, stats->rules_fast_rejected);
}

TEST_F(StyleEngineTest, NoFastRejectForMultipleIs) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      :is(#foo, #bar) span {
        color: pink;
      }
    </style>
    <div id="parent">
      <span id="child">not pink</span>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_fast_rejected);

  Element* span = GetDocument().getElementById(AtomicString("child"));
  ASSERT_TRUE(span);
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // Should not try to fast reject due to the (multiple-element) selector list.
  EXPECT_EQ(0u, stats->rules_fast_rejected);
}

TEST_F(StyleEngineTest, ScrollbarPartPseudoDoesNotMatchElement) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .parent ::-webkit-scrollbar-button { background-color: red; }
      .parent ::-webkit-scrollbar-corner { background-color: red; }
      .parent ::-webkit-scrollbar-thumb { background-color: red; }
      .parent ::-webkit-scrollbar-track { background-color: red; }
      .parent ::-webkit-scrollbar-track-piece { background-color: red; }
    </style>
    <div class="parent">
      <div class="child"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  StyleEngine& engine = GetStyleEngine();
  // Even if the Stats() were already enabled, the following resets it to 0.
  engine.SetStatsEnabled(true);

  StyleResolverStats* stats = engine.Stats();
  ASSERT_TRUE(stats);
  EXPECT_EQ(0u, stats->rules_matched);

  Element* div = GetDocument().QuerySelector(AtomicString(".child"));
  ASSERT_TRUE(div);
  div->SetInlineStyleProperty(CSSPropertyID::kColor, "green");

  GetDocument().Lifecycle().AdvanceTo(DocumentLifecycle::kInStyleRecalc);
  GetStyleEngine().RecalcStyle();

  // We have two UA rule for <div> that match:
  //  div { display: block; }
  //  div { unicode-bidi: isolate; }
  EXPECT_EQ(stats->rules_matched, 2u);
}

TEST_F(StyleEngineTest, AudioUAStyleNameSpace) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <audio id="html-audio"></audio>
  )HTML");
  Element* html_audio =
      GetDocument().getElementById(AtomicString("html-audio"));
  Element* audio =
      GetDocument().createElementNS(AtomicString("http://dummyns"),
                                    AtomicString("audio"), ASSERT_NO_EXCEPTION);
  GetDocument().body()->appendChild(audio);
  UpdateAllLifecyclePhases();

  // display:none UA rule for audio element should not apply outside html.
  EXPECT_TRUE(audio->GetComputedStyle());
  EXPECT_FALSE(html_audio->GetComputedStyle());

  gfx::SizeF page_size(400, 400);
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size));

  // Also for printing.
  EXPECT_TRUE(audio->GetComputedStyle());
  EXPECT_FALSE(html_audio->GetComputedStyle());
}

TEST_F(StyleEngineTest, TargetTextUseCount) {
  ClearUseCounter(WebFeature::kCSSSelectorTargetText);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #nevermatch::target-text { background-color: pink }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSSelectorTargetText));
  ClearUseCounter(WebFeature::kCSSSelectorTargetText);

  // Count ::target-text if we would have matched if the page was loaded with a
  // text fragment url.
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      div::target-text { background-color: pink }
    </style>
    <div></div>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSSelectorTargetText));
  ClearUseCounter(WebFeature::kCSSSelectorTargetText);
}

TEST_F(StyleEngineTest, NonDirtyStyleRecalcRoot) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <div id="host">
      <span id="slotted"></span>
    </div>
  )HTML");

  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto* slotted = GetDocument().getElementById(AtomicString("slotted"));

  ShadowRoot& shadow_root =
      host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML("<slot></slot>");
  UpdateAllLifecyclePhases();

  slotted->remove();
  GetDocument().body()->appendChild(slotted);
  host->remove();
  auto* recalc_root = GetStyleRecalcRoot();
  EXPECT_EQ(recalc_root, &GetDocument());
  EXPECT_TRUE(GetDocument().documentElement()->ChildNeedsStyleRecalc());
}

TEST_F(StyleEngineTest, AtCounterStyleUseCounter) {
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSAtRuleCounterStyle));

  GetDocument().body()->setInnerHTML("<style>@counter-style foo {}</style>");
  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSAtRuleCounterStyle));
}

TEST_F(StyleEngineTest, AtContainerUseCount) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { --x: No @container rule here; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleContainer));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @container (width > 0px) {
        body { --x: Hello world; }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleContainer));
}

TEST_F(StyleEngineTest, StyleQueryUseCount) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @container (width = 200px) {
        body { background: red; }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleContainer));
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSStyleContainerQuery));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @container ((width > 0px) and style(--foo: bar)) {
        body { background: lime; }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleContainer));
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSStyleContainerQuery));
}

TEST_F(StyleEngineTest, NestingUseCount) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { --x: No @nest or & rule here; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        & .foo { color: fuchsia; }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, NestingUseCountUnsupportedDeclaration) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { unsupported: 100px; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, NestingUseCountSupportedDeclaration) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { width: 100px; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, NestingUseCountDimensionToken) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { 500px: 300px; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, NestingUseCountInvalidSelector) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { & !!! { color: fuchsia; } }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, NestingUseCountUnknownAtRule) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        @unsupported {
          color: fuchsia;
        }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, NestingUseCountAtRule) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        @media {
          color: fuchsia;
        }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, NestingUseCountNotStartingWithAmpersand) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { --x: No @nest rule or & here; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        .foo & { color: lemonchiffon; }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSNesting));
}

TEST_F(StyleEngineTest, SystemFontsObeyDefaultFontSize) {
  // <input> get assigned "font: -webkit-small-control" in the UA sheet.
  Element* body = GetDocument().body();
  body->setInnerHTML("<input>");
  Element* input = GetDocument().QuerySelector(AtomicString("input"));

  // Test the standard font sizes that can be chosen in chrome://settings/
  for (int fontSize : {9, 12, 16, 20, 24}) {
    GetDocument().GetSettings()->SetDefaultFontSize(fontSize);
    UpdateAllLifecyclePhases();
    EXPECT_EQ(fontSize, body->GetComputedStyle()->FontSize());
    EXPECT_EQ(fontSize - 3, input->GetComputedStyle()->FontSize());
  }

  // Now test degenerate cases
  GetDocument().GetSettings()->SetDefaultFontSize(-1);
  GetDocument().GetStyleResolver().InvalidateMatchedPropertiesCache();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(1, body->GetComputedStyle()->FontSize());
  EXPECT_EQ(1, input->GetComputedStyle()->FontSize());

  GetDocument().GetSettings()->SetDefaultFontSize(0);
  GetDocument().GetStyleResolver().InvalidateMatchedPropertiesCache();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(1, body->GetComputedStyle()->FontSize());
  EXPECT_EQ(13, input->GetComputedStyle()->FontSize());

  GetDocument().GetSettings()->SetDefaultFontSize(1);
  GetDocument().GetStyleResolver().InvalidateMatchedPropertiesCache();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(1, body->GetComputedStyle()->FontSize());
  EXPECT_EQ(1, input->GetComputedStyle()->FontSize());

  GetDocument().GetSettings()->SetDefaultFontSize(2);
  GetDocument().GetStyleResolver().InvalidateMatchedPropertiesCache();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(2, body->GetComputedStyle()->FontSize());
  EXPECT_EQ(2, input->GetComputedStyle()->FontSize());

  GetDocument().GetSettings()->SetDefaultFontSize(3);
  GetDocument().GetStyleResolver().InvalidateMatchedPropertiesCache();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(3, body->GetComputedStyle()->FontSize());
  EXPECT_EQ(0, input->GetComputedStyle()->FontSize());

  GetDocument().GetSettings()->SetDefaultFontSize(12345);
  GetDocument().GetStyleResolver().InvalidateMatchedPropertiesCache();
  UpdateAllLifecyclePhases();
  EXPECT_EQ(10000, body->GetComputedStyle()->FontSize());
  EXPECT_EQ(10000, input->GetComputedStyle()->FontSize());
}

TEST_F(StyleEngineTest, CascadeLayersInOriginsAndTreeScopes) {
  // Verifies that user layers and author layers in each tree scope are managed
  // separately. Each have their own layer ordering.

  auto* user_sheet = MakeGarbageCollected<StyleSheetContents>(
      MakeGarbageCollected<CSSParserContext>(GetDocument()));
  user_sheet->ParseString("@layer foo, bar;");
  StyleSheetKey user_key("user_layers");
  GetStyleEngine().InjectSheet(user_key, user_sheet, WebCssOrigin::kUser);

  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <style>
      @layer bar, foo;
    </style>
    <div id="host">
      <template shadowrootmode="open">
        <style>
          @layer foo, bar, foo.baz;
        </style>
      </template>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  // User layer order: foo, bar, (implicit outer layer)
  auto* user_layer_map = GetStyleEngine().GetUserCascadeLayerMap();
  ASSERT_TRUE(user_layer_map);

  const CascadeLayer& user_outer_layer =
      user_sheet->GetRuleSet().CascadeLayers();
  EXPECT_EQ("", user_outer_layer.GetName());
  EXPECT_EQ(CascadeLayerMap::kImplicitOuterLayerOrder,
            user_layer_map->GetLayerOrder(user_outer_layer));

  const CascadeLayer& user_foo = *user_outer_layer.GetDirectSubLayers()[0];
  EXPECT_EQ("foo", user_foo.GetName());
  EXPECT_EQ(0u, user_layer_map->GetLayerOrder(user_foo));

  const CascadeLayer& user_bar = *user_outer_layer.GetDirectSubLayers()[1];
  EXPECT_EQ("bar", user_bar.GetName());
  EXPECT_EQ(1u, user_layer_map->GetLayerOrder(user_bar));

  // Document scope author layer order: bar, foo, (implicit outer layer)
  auto* document_layer_map =
      GetDocument().GetScopedStyleResolver()->GetCascadeLayerMap();
  ASSERT_TRUE(document_layer_map);

  const CascadeLayer& document_outer_layer =
      To<HTMLStyleElement>(GetDocument().QuerySelector(AtomicString("style")))
          ->sheet()
          ->Contents()
          ->GetRuleSet()
          .CascadeLayers();
  EXPECT_EQ("", document_outer_layer.GetName());
  EXPECT_EQ(CascadeLayerMap::kImplicitOuterLayerOrder,
            document_layer_map->GetLayerOrder(document_outer_layer));

  const CascadeLayer& document_bar =
      *document_outer_layer.GetDirectSubLayers()[0];
  EXPECT_EQ("bar", document_bar.GetName());
  EXPECT_EQ(0u, document_layer_map->GetLayerOrder(document_bar));

  const CascadeLayer& document_foo =
      *document_outer_layer.GetDirectSubLayers()[1];
  EXPECT_EQ("foo", document_foo.GetName());
  EXPECT_EQ(1u, document_layer_map->GetLayerOrder(document_foo));

  // Shadow scope author layer order: foo.baz, foo, bar, (implicit outer layer)
  ShadowRoot* shadow =
      GetDocument().getElementById(AtomicString("host"))->GetShadowRoot();
  auto* shadow_layer_map =
      shadow->GetScopedStyleResolver()->GetCascadeLayerMap();
  ASSERT_TRUE(shadow_layer_map);

  const CascadeLayer& shadow_outer_layer =
      To<HTMLStyleElement>(shadow->QuerySelector(AtomicString("style")))
          ->sheet()
          ->Contents()
          ->GetRuleSet()
          .CascadeLayers();
  EXPECT_EQ("", shadow_outer_layer.GetName());
  EXPECT_EQ(CascadeLayerMap::kImplicitOuterLayerOrder,
            shadow_layer_map->GetLayerOrder(shadow_outer_layer));

  const CascadeLayer& shadow_foo = *shadow_outer_layer.GetDirectSubLayers()[0];
  EXPECT_EQ("foo", shadow_foo.GetName());
  EXPECT_EQ(1u, shadow_layer_map->GetLayerOrder(shadow_foo));

  const CascadeLayer& shadow_foo_baz = *shadow_foo.GetDirectSubLayers()[0];
  EXPECT_EQ("baz", shadow_foo_baz.GetName());
  EXPECT_EQ(0u, shadow_layer_map->GetLayerOrder(shadow_foo_baz));

  const CascadeLayer& shadow_bar = *shadow_outer_layer.GetDirectSubLayers()[1];
  EXPECT_EQ("bar", shadow_bar.GetName());
  EXPECT_EQ(2u, shadow_layer_map->GetLayerOrder(shadow_bar));
}

TEST_F(StyleEngineTest, CascadeLayersFromMultipleSheets) {
  // The layer ordering in sheet2 is different from the final ordering.
  GetDocument().body()->setInnerHTML(R"HTML(
    <style id="sheet1">
      @layer foo, bar;
    </style>
    <style id="sheet2">
      @layer baz, bar.qux, foo.quux;
    </style>
  )HTML");

  UpdateAllLifecyclePhases();

  // Final layer ordering:
  // foo.quux, foo, bar.qux, bar, baz, (implicit outer layer)
  auto* layer_map =
      GetDocument().GetScopedStyleResolver()->GetCascadeLayerMap();
  ASSERT_TRUE(layer_map);

  const CascadeLayer& sheet1_outer_layer =
      To<HTMLStyleElement>(GetDocument().getElementById(AtomicString("sheet1")))
          ->sheet()
          ->Contents()
          ->GetRuleSet()
          .CascadeLayers();
  EXPECT_EQ("", sheet1_outer_layer.GetName());
  EXPECT_EQ(CascadeLayerMap::kImplicitOuterLayerOrder,
            layer_map->GetLayerOrder(sheet1_outer_layer));

  const CascadeLayer& sheet1_foo = *sheet1_outer_layer.GetDirectSubLayers()[0];
  EXPECT_EQ("foo", sheet1_foo.GetName());
  EXPECT_EQ(1u, layer_map->GetLayerOrder(sheet1_foo));

  const CascadeLayer& sheet1_bar = *sheet1_outer_layer.GetDirectSubLayers()[1];
  EXPECT_EQ("bar", sheet1_bar.GetName());
  EXPECT_EQ(3u, layer_map->GetLayerOrder(sheet1_bar));

  const CascadeLayer& sheet2_outer_layer =
      To<HTMLStyleElement>(GetDocument().getElementById(AtomicString("sheet2")))
          ->sheet()
          ->Contents()
          ->GetRuleSet()
          .CascadeLayers();
  EXPECT_EQ("", sheet2_outer_layer.GetName());
  EXPECT_EQ(CascadeLayerMap::kImplicitOuterLayerOrder,
            layer_map->GetLayerOrder(sheet2_outer_layer));

  const CascadeLayer& sheet2_baz = *sheet2_outer_layer.GetDirectSubLayers()[0];
  EXPECT_EQ("baz", sheet2_baz.GetName());
  EXPECT_EQ(4u, layer_map->GetLayerOrder(sheet2_baz));

  const CascadeLayer& sheet2_bar = *sheet2_outer_layer.GetDirectSubLayers()[1];
  EXPECT_EQ("bar", sheet2_bar.GetName());
  EXPECT_EQ(3u, layer_map->GetLayerOrder(sheet2_bar));

  const CascadeLayer& sheet2_bar_qux = *sheet2_bar.GetDirectSubLayers()[0];
  EXPECT_EQ("qux", sheet2_bar_qux.GetName());
  EXPECT_EQ(2u, layer_map->GetLayerOrder(sheet2_bar_qux));

  const CascadeLayer& sheet2_foo = *sheet2_outer_layer.GetDirectSubLayers()[2];
  EXPECT_EQ("foo", sheet2_foo.GetName());
  EXPECT_EQ(1u, layer_map->GetLayerOrder(sheet2_foo));

  const CascadeLayer& sheet2_foo_quux = *sheet2_foo.GetDirectSubLayers()[0];
  EXPECT_EQ("quux", sheet2_foo_quux.GetName());
  EXPECT_EQ(0u, layer_map->GetLayerOrder(sheet2_foo_quux));
}

TEST_F(StyleEngineTest, CascadeLayersNotExplicitlyDeclared) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #no-layers { }
    </style>
  )HTML");

  UpdateAllLifecyclePhases();

  // We don't create CascadeLayerMap if no layers are explicitly declared.
  ASSERT_TRUE(GetDocument().GetScopedStyleResolver());
  ASSERT_FALSE(GetDocument().GetScopedStyleResolver()->GetCascadeLayerMap());
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSCascadeLayers));
}

TEST_F(StyleEngineTest, CascadeLayersSheetsRemoved) {
  GetDocument().body()->setHTMLUnsafe(R"HTML(
    <style>
      @layer bar, foo;
    </style>
    <div id="host">
      <template shadowrootmode="open">
        <style>
          @layer foo, bar, foo.baz;
        </style>
      </template>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  ASSERT_TRUE(GetDocument().GetScopedStyleResolver());
  ASSERT_TRUE(GetDocument().GetScopedStyleResolver()->GetCascadeLayerMap());

  ShadowRoot* shadow =
      GetDocument().getElementById(AtomicString("host"))->GetShadowRoot();
  ASSERT_TRUE(shadow->GetScopedStyleResolver());
  ASSERT_TRUE(shadow->GetScopedStyleResolver()->GetCascadeLayerMap());

  GetDocument().QuerySelector(AtomicString("style"))->remove();
  shadow->QuerySelector(AtomicString("style"))->remove();
  UpdateAllLifecyclePhases();

  // When all sheets are removed, document ScopedStyleResolver is not cleared
  // but the CascadeLayerMap should be cleared.
  ASSERT_TRUE(GetDocument().GetScopedStyleResolver());
  ASSERT_FALSE(GetDocument().GetScopedStyleResolver()->GetCascadeLayerMap());

  // When all sheets are removed, shadow tree ScopedStyleResolver is cleared.
  ASSERT_FALSE(shadow->GetScopedStyleResolver());
}

TEST_F(StyleEngineTest, NonSlottedStyleDirty) {
  GetDocument().body()->setInnerHTML("<div id=host></div>");
  auto* host = GetDocument().getElementById(AtomicString("host"));
  ASSERT_TRUE(host);
  host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  UpdateAllLifecyclePhases();

  // Add a child element to a shadow host with no slots. The inserted element is
  // not marked for style recalc because the GetStyleRecalcParent() returns
  // nullptr.
  auto* span = MakeGarbageCollected<HTMLSpanElement>(GetDocument());
  host->appendChild(span);
  EXPECT_FALSE(host->ChildNeedsStyleRecalc());
  EXPECT_FALSE(span->NeedsStyleRecalc());

  UpdateAllLifecyclePhases();

  // Set a style on the inserted child outside the flat tree.
  // GetStyleRecalcParent() still returns nullptr, and the ComputedStyle of the
  // child outside the flat tree is still null. No need to mark dirty.
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "red");
  EXPECT_FALSE(host->ChildNeedsStyleRecalc());
  EXPECT_FALSE(span->NeedsStyleRecalc());

  // Ensure the ComputedStyle for the child and then change the style.
  // GetStyleRecalcParent() is still null, which means the host is not marked
  // with ChildNeedsStyleRecalc(), but the child needs to be marked dirty to
  // make sure the next EnsureComputedStyle updates the style to reflect the
  // changes.
  const ComputedStyle* old_style = span->EnsureComputedStyle();
  span->SetInlineStyleProperty(CSSPropertyID::kColor, "green");
  EXPECT_FALSE(host->ChildNeedsStyleRecalc());
  EXPECT_TRUE(span->NeedsStyleRecalc());
  UpdateAllLifecyclePhases();

  EXPECT_EQ(span->GetComputedStyle(), old_style);
  const ComputedStyle* new_style = span->EnsureComputedStyle();
  EXPECT_NE(new_style, old_style);

  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            old_style->VisitedDependentColor(GetCSSPropertyColor()));
  EXPECT_EQ(Color::FromRGB(0, 128, 0),
            new_style->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, CascadeLayerUseCount) {
  {
    ASSERT_FALSE(IsUseCounted(WebFeature::kCSSCascadeLayers));
    GetDocument().body()->setInnerHTML("<style>@layer foo;</style>");
    EXPECT_TRUE(IsUseCounted(WebFeature::kCSSCascadeLayers));
    ClearUseCounter(WebFeature::kCSSCascadeLayers);
  }

  {
    ASSERT_FALSE(IsUseCounted(WebFeature::kCSSCascadeLayers));
    GetDocument().body()->setInnerHTML("<style>@layer foo { }</style>");
    EXPECT_TRUE(IsUseCounted(WebFeature::kCSSCascadeLayers));
    ClearUseCount
```