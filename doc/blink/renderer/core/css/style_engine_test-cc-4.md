Response:
My thinking process to arrive at the summary of the provided code snippet goes through these stages:

1. **Understand the Context:** The initial prompt states this is part 5 of 8 of the `style_engine_test.cc` file in Chromium's Blink rendering engine. This immediately tells me the file is about testing the styling engine and its interactions with various CSS features and browser functionalities.

2. **Scan for Keywords and Patterns:** I quickly scan the code for recurring patterns and keywords. I notice:
    * `TEST_F(StyleEngineTest, ...)` and `TEST_F(StyleEngineSimTest, ...)` and `TEST_F(StyleEngineContainerQueryTest, ...)`: This is the standard Google Test framework syntax, indicating individual test cases. The prefixes `StyleEngineTest`, `StyleEngineSimTest`, and `StyleEngineContainerQueryTest` group related tests.
    * `GetDocument()`, `GetFrame()`, `GetDocument().body()`, `GetComputedStyle()`: These are common Blink API calls for accessing document structure, frames, and computed styles of elements.
    * `setInnerHTML()`, `setAttribute()`: Methods for manipulating the HTML structure.
    * `EXPECT_EQ()`, `EXPECT_TRUE()`, `EXPECT_FALSE()`: Google Test assertions to check for expected outcomes.
    * CSS property names (e.g., `kBackgroundColor`, `kColor`, `--x`, `display`, `width`, `z-index`): These indicate the tests are examining how CSS properties are applied and behave.
    * Media queries (e.g., `@media (scripting)`, `@media (prefers-color-scheme)`, `@media (display-state)`, `@media (resizable)`, `@media (min-width: ...)`, `@container ...`):  A significant portion of the tests involves media queries and container queries.
    * Printing related calls (`StartPrinting`, `EndPrinting`): Tests related to print styling.
    * Viewport units (`vw`, `vh`, `dvw`, `dvh`, etc.): Tests related to different types of viewport units.
    * `@property`, `@scope`: Tests for custom CSS properties and the `@scope` at-rule.
    * `ForceDarkMode`, `UsedColorScheme`: Properties related to dark mode and color scheme.
    * SimTest related keywords (`SimRequest`, `LoadURL`, `Complete`, `Write`, `Finish`):  These indicate tests that simulate network requests and loading scenarios.
    * Container query specific terms (`container-type`, `UpdateStyleAndLayoutTreeForContainer`): Focus on container query functionality.

3. **Group Tests by Functionality:** Based on the keywords and patterns, I start grouping the tests into logical categories:
    * **Printing:** Tests related to how styles are applied during printing, including dark mode and scripting.
    * **Media Queries:** A broad category including tests for scripting, preferred color scheme, display state, resizable state, and interactions with viewport units.
    * **Custom Properties and At-Rules:** Tests for `@property` and `@scope` at-rules.
    * **Forced Colors:** Tests for internal properties related to forced colors mode.
    * **Viewport Units:** Tests for static and dynamic viewport units and how changes in viewport size affect styling.
    * **Simulated Loading Scenarios (SimTest):** Tests that simulate network requests to examine how styles are applied during different loading stages, focusing on color schemes.
    * **Container Queries:** Tests specifically designed to verify container query behavior, including recalculation, containment, and interactions with layout.

4. **Summarize Each Group:** For each group, I write a concise summary of the functionality being tested:
    * What CSS feature or browser behavior is being examined?
    * What are the key aspects being verified (e.g., correct color application, event triggering, style updates)?

5. **Identify Relationships to Web Technologies:** I explicitly link the tested features to JavaScript, HTML, and CSS:
    * **JavaScript:**  Mentioned in the context of the `@media (scripting)` query and the ability to execute scripts.
    * **HTML:** The tests manipulate HTML elements, their attributes, and inline styles.
    * **CSS:** The core of the tests, covering various CSS properties, media queries, container queries, at-rules, and viewport units.

6. **Consider Logic and Examples:**  For tests that involve logical conditions (like media queries), I think about potential input and output. For instance, with the `PrintVisitedDependentColor` test, the input is the document state before and during printing, and the output is the expected color of the visited link.

7. **Identify Potential User Errors:** I consider common mistakes developers might make when using the tested features, such as:
    * Incorrectly assuming styles apply during printing in the same way as on screen.
    * Misunderstanding how different viewport units behave.
    * Not knowing the precedence of author vs. user stylesheets for custom properties.

8. **Trace User Operations:** I try to imagine the user actions that would lead to the code being executed, focusing on the features being tested (e.g., navigating to a page, printing, resizing the window, enabling/disabling JavaScript).

9. **Synthesize the Overall Function:** Finally, I synthesize the individual summaries into a cohesive description of the file's purpose, emphasizing its role in verifying the correctness of Blink's style engine.

10. **Review and Refine:** I reread my summary and the code snippet to ensure accuracy, clarity, and completeness. I check if I've addressed all aspects of the prompt. I also make sure the language is precise and avoids jargon where possible. This iterative process helps to catch any oversights or ambiguities.
```
功能归纳 (第5部分):

本部分主要集中在 **样式引擎在特定场景下的行为测试**，特别关注以下几个方面：

1. **打印相关的样式处理:**
   - 测试打印状态下 `:visited` 伪类的颜色计算是否正确。
   - 测试打印状态下是否会强制禁用 Dark Mode。
   - 测试打印状态下 `@media (scripting)` 媒体查询的生效情况。

2. **媒体查询 (Media Queries) 的动态变化:**
   - 测试 JavaScript 启用/禁用时，`@media (scripting)` 媒体查询的激活和样式更新。
   - 测试修改 `<style>` 标签的 `media` 属性是否会触发字体缓存的更新。
   - 测试动态视口单位 (Dynamic Viewport Units, 如 `dvh`) 的变化如何影响媒体查询的匹配。
   - 测试窗口显示状态 (`display-state`) 和可调整大小状态 (`resizable`) 的变化如何影响相应的媒体查询。

3. **CSS @规则的计数:**
   - 测试 `@property` 和 `@scope` 这两个 CSS At 规则是否被正确计数 (用于统计特性使用情况)。

4. **用户样式表与作者样式表的优先级:**
   - 测试 `@property` 规则在用户样式表和作者样式表中的优先级。

5. **内部强制属性 (Internal Forced Properties):**
   - 测试 `-internal-forced-*` 这些内部属性只能在 UA 样式表中使用，不能在普通的 CSS 中使用。

6. **视口单位 (Viewport Units) 的处理:**
   - 测试元素是否使用了静态视口单位 (`vw`, `vh` 等) 或动态视口单位 (`dvw`, `dvh` 等)。
   - 测试动态视口单位变化时，样式引擎是否会正确地标记需要重新计算样式的元素。
   - 测试在媒体查询中使用动态视口单位时，视口变化是否会触发活动样式更新。

7. **仿真测试 (SimTest):**
   - 测试 `color-scheme` 属性在 iframe 中的继承和影响。
   - 测试在渲染阻塞的情况下，`<meta name="color-scheme">` 对背景色的影响。
   - 测试 iframe 如何继承父文档的 `prefers-color-scheme` 设置。

8. **容器查询 (Container Queries):**
   - 测试 `UpdateStyleAndLayoutTreeForContainer` 方法是否能正确地更新容器及其后代的样式和布局树。
   - 测试容器查询在特定情况下 (如 `display: contents`) 的 containment 不生效的情况。
   - 测试容器查询如何影响伪元素的样式计算。
   - 测试容器查询的重新计算是否会正确地标记需要重新计算样式的元素，即使涉及到输入框的内部元素。
   - 测试在没有布局依赖的样式变化时，`UpdateStyleAndLayoutTree` 是否会避免不必要的布局。
   - 测试在有布局依赖的容器查询触发样式变化时，`UpdateStyleAndLayoutTree` 是否会触发布局。
   - 涉及在 `display: none` 的元素上添加类名触发容器查询的情况。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    - `TEST_F(StyleEngineTest, PrintScriptingEnabled)` 和 `TEST_F(StyleEngineTest, MediaQueriesChangeScripting)` 测试了当 JavaScript 启用或禁用时，CSS 中 `@media (scripting)` 媒体查询的行为。这直接关联了 JavaScript 的状态如何影响 CSS 样式的应用。
    - **假设输入:** 一个 HTML 页面，包含一个 `@media (scripting)` 规则，并在 JavaScript 禁用时设置不同的颜色。
    - **输出:** 当 JavaScript 启用时，元素应用 `@media (scripting)` 内的样式；当禁用时，应用 `@media (scripting: none)` 内的样式。

* **HTML:**
    - 所有的测试都基于 HTML 结构，通过 `GetDocument().body()->setInnerHTML()` 设置 HTML 内容，并通过 `GetDocument().getElementById()` 获取 HTML 元素。
    - `TEST_F(StyleEngineTest, MediaAttributeChangeUpdatesFontCacheVersion)` 测试了修改 `<style>` 标签的 `media` 属性，这是一个直接的 HTML 属性操作。
    - **假设输入:** 一个包含 `<style id="target">` 标签的 HTML 结构。
    - **输出:** 修改 `target` 元素的 `media` 属性会触发样式引擎的更新。

* **CSS:**
    - 本部分的大量测试都围绕着各种 CSS 特性，例如 `:visited` 伪类、Dark Mode 相关的 CSS 属性、各种媒体查询 (包括标准媒体查询和容器查询)、CSS At 规则 (`@property`, `@scope`) 和视口单位。
    - `TEST_F(StyleEngineTest, AtPropertyUseCount)` 测试了 `@property` 规则的使用情况，这是一个 CSS 新特性。
    - **假设输入:** 一个包含 `@property --x { ... }` 的 CSS 样式。
    - **输出:** 样式引擎会识别并计数 `@property` 规则的使用。

**逻辑推理的假设输入与输出:**

* **`TEST_F(StyleEngineTest, PrintVisitedDependentColor)`:**
    - **假设输入:** 一个包含链接的 HTML 页面，链接的颜色在 `:visited` 状态下有不同的定义。
    - **输出:** 在打印开始前和结束后，`:visited` 链接的颜色会根据是否处于打印状态而变化。

* **`TEST_F(StyleEngineTest, MediaQueriesChangeScripting)`:**
    - **假设输入:** 一个包含 `@media (scripting)` 和 `@media (scripting: none)` 规则的 HTML 页面。
    - **输出:** 当 JavaScript 启用时，应用 `@media (scripting)` 的样式；当 JavaScript 禁用时，应用 `@media (scripting: none)` 的样式。

**涉及用户或编程常见的使用错误举例说明:**

* **打印样式与屏幕样式的混淆:** 用户可能会期望在屏幕上看到的 `:visited` 链接颜色在打印时也相同，但测试 `PrintVisitedDependentColor` 表明，打印状态下可能存在不同的样式。开发者需要注意使用 `@media print` 来定义特定的打印样式。

* **对动态视口单位行为的误解:** 开发者可能不清楚 `vw`/`vh` 和 `dvw`/`dvh` 的区别，以及它们在视口大小变化时的更新机制。`DynamicViewportUnitInvalidation` 测试就展示了这一点，`dvh` 的变化不会影响到 `svh`。

* **不了解用户样式表的优先级:** 开发者可能会惊讶于用户样式表中的 `@property` 规则在某些情况下会被作者样式表覆盖，`AtPropertyInUserOrigin` 测试了这种情况。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户访问一个包含特定 CSS 特性的网页:** 例如，页面使用了 `@property` 规则、容器查询、或者针对打印定义了特殊样式。
2. **用户执行触发特定场景的操作:**
   - **打印:** 用户点击浏览器的打印按钮或使用快捷键触发打印功能。
   - **调整窗口大小:** 用户拖动浏览器窗口的边缘来改变窗口大小，这会影响视口单位。
   - **启用/禁用 JavaScript:** 用户可能通过浏览器设置或开发者工具来切换 JavaScript 的启用状态。
   - **切换 Dark Mode:** 用户可能通过操作系统或浏览器设置来切换 Dark Mode。
3. **浏览器渲染引擎开始解析和应用样式:** 当上述用户操作发生时，Blink 渲染引擎会重新计算样式以响应这些变化。
4. **`style_engine_test.cc` 中的测试覆盖了这些场景:**  开发者编写的测试用例模拟了这些用户操作和浏览器行为，以确保样式引擎在各种情况下都能正确工作。

例如，如果开发者发现用户在打印网页时 `:visited` 链接的颜色显示不正确，他们可以参考 `PrintVisitedDependentColor` 测试，并通过调试相关的代码路径，例如 `ComputedStyle::VisitedDependentColor` 的计算逻辑，来定位问题。

**本部分功能归纳:**

总而言之，本部分 `style_engine_test.cc` 的功能是 **系统性地测试 Blink 样式引擎在各种特定场景下的行为和正确性**，包括打印、媒体查询的动态响应、CSS 新特性的处理、不同来源样式表的优先级、视口单位的计算和更新、以及容器查询的复杂场景。这些测试覆盖了与 JavaScript、HTML 和 CSS 的深度集成，并帮助开发者发现和修复潜在的渲染错误，确保用户在各种情况下都能获得一致且符合预期的网页呈现效果。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
body->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  gfx::SizeF page_size(400, 400);
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size));
  EXPECT_EQ(Color::kBlack, root->GetComputedStyle()->VisitedDependentColor(
                               GetCSSPropertyColor()));
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            root->GetComputedStyle()->UsedColorScheme());
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      body->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(Color::kWhite, root->GetComputedStyle()->VisitedDependentColor(
                               GetCSSPropertyColor()));
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            root->GetComputedStyle()->UsedColorScheme());
  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      body->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, PrintNoForceDarkMode) {
  auto* frame_view = GetDocument().View();
  GetDocument().documentElement()->SetInlineStyleProperty(
      CSSPropertyID::kBackgroundColor, "white");
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(frame_view->DocumentBackgroundColor(), Color::kWhite);
  EXPECT_EQ(GetDocument().documentElement()->GetComputedStyle()->ForceDark(),
            false);

  GetDocument().GetSettings()->SetForceDarkModeEnabled(true);
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(frame_view->DocumentBackgroundColor(), Color(18, 18, 18));
  EXPECT_EQ(GetDocument().documentElement()->GetComputedStyle()->ForceDark(),
            true);

  gfx::SizeF page_size(400, 400);
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size));
  EXPECT_EQ(frame_view->DocumentBackgroundColor(), Color::kWhite);
  EXPECT_EQ(GetDocument().documentElement()->GetComputedStyle()->ForceDark(),
            false);

  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(frame_view->DocumentBackgroundColor(), Color(18, 18, 18));
  EXPECT_EQ(GetDocument().documentElement()->GetComputedStyle()->ForceDark(),
            true);
}

TEST_F(StyleEngineTest, PrintScriptingEnabled) {
  GetDocument().body()->setInnerHTML(R"HTML(
      <style>
        @media (scripting) {
          body { color: green; }
        }
        @media (scripting: none) {
          body { color: red; }
        }
      </style>
    )HTML");
  GetFrame().GetSettings()->SetScriptEnabled(true);
  UpdateAllLifecyclePhases();
  Element* body = GetDocument().body();

  EXPECT_EQ(true,
            GetDocument().GetExecutionContext()->CanExecuteScripts(
                ReasonForCallingCanExecuteScripts::kNotAboutToExecuteScript));

  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      body->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  gfx::SizeF page_size(400, 400);
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size));
  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      body->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetDocument().GetFrame()->EndPrinting();
}

TEST_F(StyleEngineTest, MediaQueriesChangeScripting) {
  GetDocument().body()->setInnerHTML(R"HTML(
        <style>
          @media (scripting) {
            body { color: green; }
          }
          @media (scripting: none) {
            body { color: red; }
          }
        </style>
      )HTML");
  GetFrame().GetSettings()->SetScriptEnabled(true);
  UpdateAllLifecyclePhases();
  Element* body = GetDocument().body();

  EXPECT_EQ(true,
            GetDocument().GetExecutionContext()->CanExecuteScripts(
                ReasonForCallingCanExecuteScripts::kNotAboutToExecuteScript));

  EXPECT_EQ(
      Color::FromRGB(0, 128, 0),
      body->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  GetFrame().GetSettings()->SetScriptEnabled(false);
  UpdateAllLifecyclePhases();

  EXPECT_EQ(false,
            GetDocument().GetExecutionContext()->CanExecuteScripts(
                ReasonForCallingCanExecuteScripts::kNotAboutToExecuteScript));

  EXPECT_EQ(
      Color::FromRGB(255, 0, 0),
      body->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, AtPropertyUseCount) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { --x: No @property rule here; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleProperty));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @property --x {
        syntax: "<length>";
        inherits: false;
        initial-value: 0px;
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleProperty));
}

TEST_F(StyleEngineTest, AtScopeUseCount) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body { --x: No @scope rule here; }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleScope));

  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @scope (.a) {
        body { --x:true; }
      }
    </style>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_TRUE(GetDocument().IsUseCounted(WebFeature::kCSSAtRuleScope));
}

TEST_F(StyleEngineTest, RemoveDeclaredPropertiesEmptyRegistry) {
  EXPECT_FALSE(GetDocument().GetPropertyRegistry());
  PropertyRegistration::RemoveDeclaredProperties(GetDocument());
  EXPECT_FALSE(GetDocument().GetPropertyRegistry());
}

TEST_F(StyleEngineTest, AtPropertyInUserOrigin) {
  // @property in the user origin:
  InjectSheet("user1", WebCssOrigin::kUser, R"CSS(
    @property --x {
      syntax: "<length>";
      inherits: false;
      initial-value: 10px;
    }
  )CSS");
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(ComputedValue(GetDocument().body(), "--x"));
  EXPECT_EQ("10px", ComputedValue(GetDocument().body(), "--x")->CssText());

  // @property in the author origin (should win over user origin)
  InjectSheet("author", WebCssOrigin::kAuthor, R"CSS(
    @property --x {
      syntax: "<length>";
      inherits: false;
      initial-value: 20px;
    }
  )CSS");
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(ComputedValue(GetDocument().body(), "--x"));
  EXPECT_EQ("20px", ComputedValue(GetDocument().body(), "--x")->CssText());

  // An additional @property in the user origin:
  InjectSheet("user2", WebCssOrigin::kUser, R"CSS(
    @property --y {
      syntax: "<length>";
      inherits: false;
      initial-value: 30px;
    }
  )CSS");
  UpdateAllLifecyclePhases();
  ASSERT_TRUE(ComputedValue(GetDocument().body(), "--x"));
  ASSERT_TRUE(ComputedValue(GetDocument().body(), "--y"));
  EXPECT_EQ("20px", ComputedValue(GetDocument().body(), "--x")->CssText());
  EXPECT_EQ("30px", ComputedValue(GetDocument().body(), "--y")->CssText());
}

// https://crbug.com/1050564
TEST_F(StyleEngineTest, MediaAttributeChangeUpdatesFontCacheVersion) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      @font-face { font-family: custom-font; src: url(fake-font.woff); }
    </style>
    <style id=target>
      .display-none { display: none; }
    </style>
    <div style="font-family: custom-font">foo</div>
    <div class="display-none">bar</div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* target = GetDocument().getElementById(AtomicString("target"));
  target->setAttribute(html_names::kMediaAttr, AtomicString("print"));

  // Shouldn't crash.
  UpdateAllLifecyclePhases();
}

// Properties stored for forced colors mode should only be usable by the UA.
TEST_F(StyleEngineTest, InternalForcedProperties) {
  String properties_to_test[] = {
      "-internal-forced-background-color", "-internal-forced-border-color",
      "-internal-forced-color", "-internal-forced-outline-color",
      "-internal-forced-visited-color"};
  for (auto property : properties_to_test) {
    String declaration = property + ":red";
    ASSERT_TRUE(
        css_test_helpers::ParseDeclarationBlock(declaration, kHTMLStandardMode)
            ->IsEmpty());
    ASSERT_TRUE(
        !css_test_helpers::ParseDeclarationBlock(declaration, kUASheetMode)
             ->IsEmpty());
  }
}

TEST_F(StyleEngineTest, HasViewportUnitFlags) {
  struct {
    const char* value;
    bool has_static;
    bool has_dynamic;
  } test_data[] = {
      {"1px", false, false},
      {"1em", false, false},
      {"1rem", false, false},

      {"1vw", true, false},
      {"1vh", true, false},
      {"1vi", true, false},
      {"1vb", true, false},
      {"1vmin", true, false},
      {"1vmax", true, false},

      {"1svw", true, false},
      {"1svh", true, false},
      {"1svi", true, false},
      {"1svb", true, false},
      {"1svmin", true, false},
      {"1svmax", true, false},

      {"1lvw", true, false},
      {"1lvh", true, false},
      {"1lvi", true, false},
      {"1lvb", true, false},
      {"1lvmin", true, false},
      {"1lvmax", true, false},

      {"1dvw", false, true},
      {"1dvh", false, true},
      {"1dvi", false, true},
      {"1dvb", false, true},
      {"1dvmin", false, true},
      {"1dvmax", false, true},

      {"calc(1vh)", true, false},
      {"calc(1dvh)", false, true},
      {"calc(1vh + 1dvh)", true, true},
  };

  for (const auto& data : test_data) {
    SCOPED_TRACE(data.value);
    auto holder = std::make_unique<DummyPageHolder>(gfx::Size(800, 600));
    Document& document = holder->GetDocument();
    document.body()->setInnerHTML(String::Format(R"HTML(
      <style>
        div { width: %s; }
      </style>
      <div id=target></div>
    )HTML",
                                                 data.value));
    document.View()->UpdateAllLifecyclePhasesForTest();

    Element* target = document.getElementById(AtomicString("target"));
    ASSERT_TRUE(target);

    EXPECT_EQ(data.has_static,
              target->GetComputedStyle()->HasStaticViewportUnits());
    EXPECT_EQ(data.has_dynamic,
              target->GetComputedStyle()->HasDynamicViewportUnits());
    EXPECT_EQ(data.has_static, document.HasStaticViewportUnits());
    EXPECT_EQ(data.has_dynamic, document.HasDynamicViewportUnits());
  }
}

TEST_F(StyleEngineTest, DynamicViewportUnitInvalidation) {
  GetDocument().body()->setInnerHTML(R"HTML(
  <style>
    #target_px { width: 1px; }
    #target_svh { width: 1svh; }
    #target_dvh { width: 1dvh; }
  </style>
  <div id=target_px></div>
  <div id=target_svh></div>
  <div id=target_dvh></div>
  )HTML");
  UpdateAllLifecyclePhases();

  Element* target_px = GetDocument().getElementById(AtomicString("target_px"));
  Element* target_svh =
      GetDocument().getElementById(AtomicString("target_svh"));
  Element* target_dvh =
      GetDocument().getElementById(AtomicString("target_dvh"));
  ASSERT_TRUE(target_px);
  ASSERT_TRUE(target_svh);
  ASSERT_TRUE(target_dvh);

  EXPECT_FALSE(target_px->NeedsStyleRecalc());
  EXPECT_FALSE(target_svh->NeedsStyleRecalc());
  EXPECT_FALSE(target_dvh->NeedsStyleRecalc());

  // Only dvh should be affected:
  GetDocument().DynamicViewportUnitsChanged();
  GetStyleEngine().InvalidateViewportUnitStylesIfNeeded();
  EXPECT_FALSE(target_px->NeedsStyleRecalc());
  EXPECT_FALSE(target_svh->NeedsStyleRecalc());
  EXPECT_TRUE(target_dvh->NeedsStyleRecalc());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(target_px->NeedsStyleRecalc());
  EXPECT_FALSE(target_svh->NeedsStyleRecalc());
  EXPECT_FALSE(target_dvh->NeedsStyleRecalc());

  //  svh/dvh should be affected:
  GetDocument().LayoutViewportWasResized();
  GetStyleEngine().InvalidateViewportUnitStylesIfNeeded();
  EXPECT_FALSE(target_px->NeedsStyleRecalc());
  EXPECT_TRUE(target_svh->NeedsStyleRecalc());
  EXPECT_TRUE(target_dvh->NeedsStyleRecalc());
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(target_px->NeedsStyleRecalc());
  EXPECT_FALSE(target_svh->NeedsStyleRecalc());
  EXPECT_FALSE(target_dvh->NeedsStyleRecalc());
}

TEST_F(StyleEngineTest, DynamicViewportUnitsInMediaQuery) {
  // Changes in the dynamic viewport should not affect NeedsActiveStyleUpdate
  // when we don't use dynamic viewport units.
  {
    auto holder = DummyPageHolderWithHTML(R"HTML(
        <style>
          @media (min-width: 50vh) {
            :root { color: green; }
          }
        </style>
      )HTML");
    Document& document = holder->GetDocument();

    EXPECT_FALSE(document.GetStyleEngine().NeedsActiveStyleUpdate());
    document.DynamicViewportUnitsChanged();
    EXPECT_FALSE(document.GetStyleEngine().NeedsActiveStyleUpdate());
  }

  // NeedsActiveStyleUpdate should be set when dv* units are used.
  {
    auto holder = DummyPageHolderWithHTML(R"HTML(
        <style>
          @media (min-width: 50dvh) {
            :root { color: green; }
          }
        </style>
      )HTML");
    Document& document = holder->GetDocument();

    EXPECT_FALSE(document.GetStyleEngine().NeedsActiveStyleUpdate());
    document.DynamicViewportUnitsChanged();
    EXPECT_TRUE(document.GetStyleEngine().NeedsActiveStyleUpdate());
  }

  // Same as the first test, but with media attribute.
  {
    auto holder = DummyPageHolderWithHTML(R"HTML(
        <style media="(min-width: 50vh)">
          :root { color: green; }
        </style>
      )HTML");
    Document& document = holder->GetDocument();

    EXPECT_FALSE(document.GetStyleEngine().NeedsActiveStyleUpdate());
    document.DynamicViewportUnitsChanged();
    EXPECT_FALSE(document.GetStyleEngine().NeedsActiveStyleUpdate());
  }

  // // Same as the second test, but with media attribute.
  {
    auto holder = DummyPageHolderWithHTML(R"HTML(
      <style media="(min-width: 50dvh)">
        :root { color: green; }
      </style>
    )HTML");
    Document& document = holder->GetDocument();

    EXPECT_FALSE(document.GetStyleEngine().NeedsActiveStyleUpdate());
    document.DynamicViewportUnitsChanged();
    EXPECT_TRUE(document.GetStyleEngine().NeedsActiveStyleUpdate());
  }
}

TEST_F(StyleEngineTest, MediaQueriesChangeDisplayState) {
  ScopedDesktopPWAsAdditionalWindowingControlsForTest scoped_feature(true);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        background-color: white;
      }
      @media (display-state: normal) {
        body {
          background-color: yellow;
        }
      }
      @media (display-state: minimized) {
        body {
          background-color: cyan;
        }
      }
      @media (display-state: maximized) {
        body {
          background-color: red;
        }
      }
      @media (display-state: fullscreen) {
        body {
          background-color: blue;
        }
      }
    </style>
    <body></body>
  )HTML");

  // display-state: normal
  // Default is set in /third_party/blink/renderer/core/frame/settings.json5.
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(/*yellow*/ 255, 255, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyBackgroundColor()));

  WTF::Vector<std::pair<ui::mojom::blink::WindowShowState, Color>> test_cases =
      {{ui::mojom::blink::WindowShowState::kMinimized,
        Color::FromRGB(/*cyan*/ 0, 255, 255)},
       {ui::mojom::blink::WindowShowState::kMaximized,
        Color::FromRGB(/*red*/ 255, 0, 0)},
       {ui::mojom::blink::WindowShowState::kFullscreen,
        Color::FromRGB(/*blue*/ 0, 0, 255)}};

  for (const auto& [show_state, color] : test_cases) {
    GetFrame().GetSettings()->SetWindowShowState(show_state);
    UpdateAllLifecyclePhases();
    EXPECT_EQ(color,
              GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                  GetCSSPropertyBackgroundColor()));
  }
}

TEST_F(StyleEngineTest, MediaQueriesChangeResizable) {
  ScopedDesktopPWAsAdditionalWindowingControlsForTest scoped_feature(true);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      body {
        background-color: white;
      }
      @media (resizable: true) {
        body {
          background-color: yellow;
        }
      }
      @media (resizable: false) {
        body {
          background-color: cyan;
        }
      }
    </style>
    <body></body>
  )HTML");

  // resizable: true
  // Default is set in /third_party/blink/renderer/core/frame/settings.json5.
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(/*yellow*/ 255, 255, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyBackgroundColor()));

  // resizable: false
  GetFrame().GetSettings()->SetResizable(false);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(/*cyan*/ 0, 255, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyBackgroundColor()));
}

namespace {

class TestMediaQueryListListener : public MediaQueryListListener {
 public:
  void NotifyMediaQueryChanged() override { notified = true; }
  bool notified = false;
};

}  // namespace

TEST_F(StyleEngineTest, DynamicViewportUnitsInMediaQueryMatcher) {
  auto& matcher = GetDocument().GetMediaQueryMatcher();
  auto* listener = MakeGarbageCollected<TestMediaQueryListListener>();
  matcher.AddViewportListener(listener);

  // Note: SimulateFrame is responsible for eventually causing dispatch of
  // pending events to MediaQueryListListener.
  // See step 10.8 (call to CallMediaQueryListListeners) in
  // ScriptedAnimationController::ServiceScriptedAnimations.

  MediaQuerySet* mq_static = MediaQuerySet::Create(
      "(min-width: 50vh)", GetDocument().GetExecutionContext());
  ASSERT_TRUE(mq_static);
  matcher.Evaluate(mq_static);
  GetDocument().DynamicViewportUnitsChanged();
  SimulateFrame();
  EXPECT_FALSE(listener->notified);

  // Evaluating a media query with dv* units will mark the MediaQueryMatcher
  // as dependent on such units, hence we should see events when calling
  // DynamicViewportUnitsChanged after that.
  MediaQuerySet* mq_dynamic = MediaQuerySet::Create(
      "(min-width: 50dvh)", GetDocument().GetExecutionContext());
  ASSERT_TRUE(mq_dynamic);
  matcher.Evaluate(mq_dynamic);
  GetDocument().DynamicViewportUnitsChanged();
  SimulateFrame();
  EXPECT_TRUE(listener->notified);
}

class StyleEngineSimTest : public SimTest {};

TEST_F(StyleEngineSimTest, OwnerColorScheme) {
  SimRequest main_resource("https://example.com", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com");

  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      iframe { color-scheme: dark }
    </style>
    <iframe id="frame" src="https://example.com/frame.html"></iframe>
  )HTML");

  frame_resource.Complete(R"HTML(
    <!doctype html>
    <p>Frame</p>
  )HTML");

  test::RunPendingTasks();
  Compositor().BeginFrame();

  auto* frame_element = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("frame")));
  auto* frame_document = frame_element->contentDocument();
  ASSERT_TRUE(frame_document);
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            frame_document->GetStyleEngine().GetOwnerColorScheme());

  frame_element->SetInlineStyleProperty(CSSPropertyID::kColorScheme, "light");

  test::RunPendingTasks();
  Compositor().BeginFrame();
  EXPECT_EQ(mojom::blink::ColorScheme::kLight,
            frame_document->GetStyleEngine().GetOwnerColorScheme());
}

TEST_F(StyleEngineSimTest, OwnerColorSchemeBaseBackground) {
  SimRequest main_resource("https://example.com", "text/html");
  SimRequest dark_frame_resource("https://example.com/dark.html", "text/html");
  SimRequest light_frame_resource("https://example.com/light.html",
                                  "text/html");

  LoadURL("https://example.com");

  main_resource.Complete(R"HTML(
    <style>
      .dark { color-scheme: dark }
    </style>
    <iframe id="dark-frame" src="dark.html"></iframe>
    <iframe id="light-frame" src="light.html"></iframe>
  )HTML");

  dark_frame_resource.Complete(R"HTML(
    <!doctype html>
    <meta name=color-scheme content="dark">
    <p>Frame</p>
  )HTML");

  light_frame_resource.Complete(R"HTML(
    <!doctype html>
    <p>Frame</p>
  )HTML");

  test::RunPendingTasks();
  Compositor().BeginFrame();

  auto* dark_document = To<HTMLIFrameElement>(GetDocument().getElementById(
                                                  AtomicString("dark-frame")))
                            ->contentDocument();
  auto* light_document = To<HTMLIFrameElement>(GetDocument().getElementById(
                                                   AtomicString("light-frame")))
                             ->contentDocument();
  ASSERT_TRUE(dark_document);
  ASSERT_TRUE(light_document);

  EXPECT_TRUE(dark_document->View()->ShouldPaintBaseBackgroundColor());
  EXPECT_EQ(Color(0x12, 0x12, 0x12),
            dark_document->View()->BaseBackgroundColor());
  EXPECT_FALSE(light_document->View()->ShouldPaintBaseBackgroundColor());

  GetDocument().documentElement()->setAttribute(blink::html_names::kClassAttr,
                                                AtomicString("dark"));

  test::RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_FALSE(dark_document->View()->ShouldPaintBaseBackgroundColor());
  EXPECT_TRUE(light_document->View()->ShouldPaintBaseBackgroundColor());
  EXPECT_EQ(Color::kWhite, light_document->View()->BaseBackgroundColor());
}

TEST_F(StyleEngineSimTest, ColorSchemeBaseBackgroundWhileRenderBlocking) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest css_resource("https://example.com/slow.css",
                                     "text/css");

  LoadURL("https://example.com");

  main_resource.Write(R"HTML(
    <!doctype html>
    <meta name="color-scheme" content="dark">
    <link rel="stylesheet" href="slow.css">
    Some content
  )HTML");

  css_resource.Start();
  test::RunPendingTasks();

  // No rendering updates should have happened yet.
  ASSERT_TRUE(GetDocument().documentElement());
  ASSERT_FALSE(GetDocument().documentElement()->GetComputedStyle());
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // The dark color-scheme meta should affect the canvas color.
  EXPECT_EQ(Color(0x12, 0x12, 0x12),
            GetDocument().View()->BaseBackgroundColor());

  main_resource.Finish();
  css_resource.Finish();
}

TEST_F(StyleEngineSimTest, IFramePreferredColorScheme) {
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kLight);

  SimRequest main_resource("https://example.com", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");

  LoadURL("https://example.com");

  main_resource.Complete(R"HTML(
    <!doctype html>
    <iframe id="frame" src="https://example.com/frame.html"></iframe>
  )HTML");

  frame_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      @media (prefers-color-scheme: light) {
        body { background: lime; }
      }
      @media (prefers-color-scheme: dark) {
        body { background: green; }
      }
    </style>
  )HTML");

  test::RunPendingTasks();
  Compositor().BeginFrame();

  auto* frame_element = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("frame")));
  auto* frame_document = frame_element->contentDocument();
  ASSERT_TRUE(frame_document);
  EXPECT_EQ(mojom::blink::PreferredColorScheme::kLight,
            GetDocument().GetStyleEngine().GetPreferredColorScheme());
  EXPECT_EQ(mojom::blink::PreferredColorScheme::kLight,
            frame_document->GetStyleEngine().GetPreferredColorScheme());

  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);
  test::RunPendingTasks();
  Compositor().BeginFrame();

  EXPECT_EQ(mojom::blink::PreferredColorScheme::kDark,
            GetDocument().GetStyleEngine().GetPreferredColorScheme());
  EXPECT_EQ(mojom::blink::PreferredColorScheme::kDark,
            frame_document->GetStyleEngine().GetPreferredColorScheme());
}

TEST_F(StyleEngineContainerQueryTest, UpdateStyleAndLayoutTreeForContainer) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .container {
        container-type: size;
        width: 100px;
        height: 100px;
      }
      @container (min-width: 200px) {
        .affected { background-color: green; }
      }
    </style>
    <div id="container1" class="container">
      <span class="affected"></span>
      <div id="container2" class="container affected">
        <span class="affected"></span>
        <span></span>
        <span class="affected"></span>
        <span><span class="affected"></span></span>
        <span class="affected"></span>
        <div style="display:none" class="affected">
          <span class="affected"></span>
        </div>
        <div style="display:none">
          <span class="affected"></span>
          <span class="affected"></span>
        </div>
      </div>
      <span></span>
      <div class="container">
        <span class="affected"></span>
        <span class="affected"></span>
      </div>
      <span class="container" style="display:inline-block">
        <span class="affected"></span>
      </span>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  auto* container1 = GetDocument().getElementById(AtomicString("container1"));
  auto* container2 = GetDocument().getElementById(AtomicString("container2"));
  ASSERT_TRUE(container1);
  ASSERT_TRUE(container2);

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
      *container1, LogicalSize(200, 100), kLogicalAxesBoth);

  // The first span.affected child and #container2
  EXPECT_EQ(2u, GetStyleEngine().StyleForElementCount() - start_count);

  start_count = GetStyleEngine().StyleForElementCount();
  GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
      *container2, LogicalSize(200, 100), kLogicalAxesBoth);

  // Three direct span.affected children, and the two display:none elements.
  EXPECT_EQ(6u, GetStyleEngine().StyleForElementCount() - start_count);
}

TEST_F(StyleEngineContainerQueryTest, ContainerQueriesContainmentNotApplying) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      .container {
        container-type: size;
        width: 100px;
        height: 100px;
      }
      @container (min-width: 200px) {
        .toggle { background-color: green; }
      }
    </style>
    <div id="container" class="container">

      <!-- None of the following should be affected by a change in the
           size of #container. -->
      <div class="container" style="display:contents">
        <span class="toggle"></span>
      </div>
      <span class="container">
        <span class="toggle"></span>
      </span>
      <rt class="container">
        <span class="toggle"></span>
      </rt>
      <div class="container" style="display:table">
        <span class="toggle"></span>
      </div>
      <div class="container" style="display:table-cell">
        <span class="toggle"></span>
      </div>
      <div class="container" style="display:table-row">
        <span class="toggle"></span>
      </div>
      <div class="container" style="display:table-row-group">
        <span class="toggle"></span>
      </div>

      <!-- This should be affected, however. -->
      <div class="toggle">Affected</div>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  auto* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);

  unsigned start_count = GetStyleEngine().StyleForElementCount();

  GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
      *container, LogicalSize(200, 100), kLogicalAxesBoth);

  // Even though none of the inner containers are eligible for containment,
  // they are still containers for the purposes of evaluating container
  // queries. Hence, they should not be affected when the outer container
  // changes its size.
  EXPECT_EQ(1u, GetStyleEngine().StyleForElementCount() - start_count);
}

TEST_F(StyleEngineContainerQueryTest, PseudoElementContainerQueryRecalc) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #container {
        container-type: size;
        width: 100px;
        height: 100px;
      }
      @container (min-width: 200px) {
        #container::before { content: " " }
        span::before { content: " " }
      }
    </style>
    <div id="container">
      <span id="span"></span>
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* span = GetDocument().getElementById(AtomicString("span"));
  ASSERT_TRUE(container);
  ASSERT_TRUE(span);

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
      *container, LogicalSize(200, 100), kLogicalAxesBoth);

  // The two ::before elements + #span.
  EXPECT_EQ(3u, GetStyleEngine().StyleForElementCount() - start_count);
}

TEST_F(StyleEngineContainerQueryTest, MarkStyleDirtyFromContainerRecalc) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #container {
        container-type: size;
        width: 100px;
        height: 100px;
      }
      @container (min-width: 200px) {
        #input { background-color: green; }
      }
    </style>
    <div id="container">
      <input id="input" type="text">
    </div>
  )HTML");

  UpdateAllLifecyclePhases();

  auto* container = GetDocument().getElementById(AtomicString("container"));
  auto* input = GetDocument().getElementById(AtomicString("input"));
  ASSERT_TRUE(container);
  ASSERT_TRUE(input);
  auto* inner_editor = DynamicTo<HTMLInputElement>(input)->InnerEditorElement();
  ASSERT_TRUE(inner_editor);

  const ComputedStyle* old_inner_style = inner_editor->GetComputedStyle();
  EXPECT_TRUE(old_inner_style);

  unsigned start_count = GetStyleEngine().StyleForElementCount();
  GetStyleEngine().UpdateStyleAndLayoutTreeForContainer(
      *container, LogicalSize(200, 100), kLogicalAxesBoth);

  // Input elements mark their InnerEditorElement() style-dirty when they are
  // recalculated. That means the UpdateStyleAndLayoutTreeForContainer() call
  // above will involve marking ChildNeedsStyleRecalc all the way up to the
  // documentElement. Check that we don't leave anything dirty.
  EXPECT_FALSE(GetDocument().NeedsLayoutTreeUpdate());
  EXPECT_FALSE(GetDocument().documentElement()->ChildNeedsStyleRecalc());

  // The input element is recalculated. The inner editor element isn't counted
  // because we don't do normal style resolution to create the ComputedStyle for
  // it, but check that we have a new ComputedStyle object for it.
  EXPECT_EQ(1u, GetStyleEngine().StyleForElementCount() - start_count);

  const ComputedStyle* new_inner_style = inner_editor->GetComputedStyle();
  EXPECT_TRUE(new_inner_style);
  EXPECT_NE(old_inner_style, new_inner_style);
}

TEST_F(StyleEngineContainerQueryTest,
       UpdateStyleAndLayoutTreeWithoutLayoutDependency) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      .toggle { width: 200px; }
    </style>
    <div id=a></div>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());

  Element* a = GetDocument().getElementById(AtomicString("a"));
  ASSERT_TRUE(a);
  a->classList().Add(AtomicString("toggle"));

  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(GetDocument().View()->NeedsLayout())
      << "No layout if style does not depend on layout";
}

TEST_F(StyleEngineContainerQueryTest,
       UpdateStyleAndLayoutTreeWithLayoutDependency) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #container {
        container-type: inline-size;
      }
      #container.toggle {
        width: 200px;
      }

      @container (min-width: 200px) {
        #a { z-index: 2; }
      }
    </style>
    <main id=container>
      <div id=a></div>
    </main>
  )HTML");
  UpdateAllLifecyclePhases();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());

  Element* container = GetDocument().getElementById(AtomicString("container"));
  ASSERT_TRUE(container);
  container->classList().Add(AtomicString("toggle"));

  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout())
      << "Layout should happen as part of UpdateStyleAndLayoutTree";

  Element* a = GetDocument().getElementById(AtomicString("a"));
  ASSERT_TRUE(a);
  EXPECT_EQ(2, a->ComputedStyleRef().ZIndex());
}

// https://crbug.com/1343570
TEST_F(StyleEngineContainerQueryTest,
       UpdateStyleAndLayoutTreeWithUpgradeInDisplayNone) {
  GetDocument().documentElement()->setInnerHTML(R"HTML(
    <style>
      #container {
        container-type: inline-size;
      }
      #container.togg
```