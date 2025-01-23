Response:
The user wants to understand the functionality of the `style_engine_test.cc` file in the Chromium Blink rendering engine. They are particularly interested in its relationship with JavaScript, HTML, and CSS. I need to go through each test case in the provided code and summarize its purpose. I should also look for connections to the core web technologies and provide concrete examples. Finally, I need to summarize the overall function of the file as the 8th part of an 8-part explanation.

Here's a breakdown of the individual tests and their functionalities:

*   **VisitedDependentColorInvalidation:** Tests that the computed style for visited links is correctly invalidated when the visited state changes, ensuring that the link color updates.
*   **StyleElementTypeAttrChange:**  Verifies that the `<style>` element is only effective when it has a valid `type` attribute set to `text/css`.
*   **SVGURIValueCacheClipPath/Fill:** Checks the caching mechanism for SVG `clip-path` and `fill` attributes that use `url()` references. It ensures the cache size is correctly updated when these references are used.
*   **BorderWidthsAreRecalculatedWhenZoomChanges:** Confirms that border widths are recalculated accurately when the page zoom level or device scale factor changes.
*   **AnimationShorthandFlags:** Examines how the `animation` shorthand CSS property is parsed, specifically whether it includes properties related to scroll timelines when the feature is enabled.
*   **InitialStyle_Recalc:** Tests the behavior of `@starting-style` when an element already has inline styles. It verifies that `@starting-style` is not applied in subsequent style recalculations.
*   **InitialStyle_FromDisplayNone:** Checks how `@starting-style` interacts with elements that initially have `display: none`. It ensures a double style recalculation occurs when the element is displayed to apply the starting styles.
*   **InitialStyleCount_EnsureComputedStyle:** Verifies that calling `EnsureComputedStyle` on an element with `display: none` doesn't trigger the `@starting-style` pass.
*   **UseCountCSSAnchorPositioning:**  Checks the usage counting mechanism for CSS anchor positioning features (like `anchor()`, `anchor-size()`, and `@position-try`).
*   **EnsureAppRegionTriggersRelayout:** Tests that changes to the `app-region` CSS property trigger a relayout of the page to update draggable regions.
*   **ForcedColorsLightDark:**  Examines the behavior of the `light-dark()` CSS color function within forced colors mode, especially when a specific color scheme is declared.
*   **UseCountMediaQueryRangeSyntax:** Tracks the usage of the media query range syntax (e.g., `width < 1px`).

Based on these individual functionalities, the overall purpose of the file is to test the correctness of the Blink style engine in various scenarios involving CSS parsing, style application, invalidation, and interactions with browser features like zoom and forced colors. It also verifies usage counting for specific CSS features.
这个文件 `style_engine_test.cc` 是 Chromium Blink 引擎中用于测试样式引擎（Style Engine）功能的单元测试文件。它包含了多个独立的测试用例（以 `TEST_F` 开头），每个用例都针对样式引擎的特定行为或特性进行验证。

**主要功能归纳:**

1. **验证 CSS 属性的计算和应用:** 测试各种 CSS 属性在不同场景下的计算结果是否符合预期，例如颜色、边框、动画等。
2. **测试 CSS 选择器的匹配和优先级:**  虽然这个文件中没有直接体现，但样式引擎测试通常会包含对不同 CSS 选择器（如 ID 选择器、类选择器、属性选择器等）的匹配规则以及优先级规则的验证。
3. **测试样式层叠和继承:** 验证样式如何从不同的来源（如用户代理样式、作者样式、内联样式）层叠并被继承到元素上。
4. **测试特定 CSS 特性的行为:**  例如，测试 `:visited` 伪类的行为、`<style>` 标签的属性变化、SVG 相关的样式处理、`@starting-style` 规则、`app-region` 属性、`light-dark()` 函数、媒体查询的范围语法等。
5. **测试浏览器特性对样式的影响:**  例如，测试页面缩放和设备像素比变化如何影响边框宽度等。
6. **测试性能相关的优化:**  例如，测试 SVG URI 值的缓存机制。
7. **测试特定 Web 平台特性的使用计数:** 统计某些 CSS 特性的使用情况，例如 CSS 锚点定位和媒体查询的范围语法。
8. **测试样式计算生命周期中的不同阶段:**  例如，在元素从 `display: none` 变为可见时，样式重新计算的行为。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

*   **CSS:**  这个测试文件的核心就是验证 CSS 相关的各种功能。
    *   **举例:** `TEST_F(StyleEngineTest, BorderWidthsAreRecalculatedWhenZoomChanges)` 测试了当页面缩放时，CSS 的 `border-width` 属性是否会重新计算并应用。 这直接关系到 CSS 的布局和渲染。
    *   **举例:** `TEST_F(StyleEngineTest, AnimationShorthandFlags)` 测试了 CSS 的 `animation` 简写属性是否正确解析，并将各个子属性（如 `animation-duration`、`animation-timing-function` 等）提取出来。
    *   **举例:** `TEST_F(StyleEngineTest, ForcedColorsLightDark)` 测试了 CSS 的 `light-dark()` 函数在强制颜色模式下的行为，这涉及到 CSS 颜色值的处理。

*   **HTML:** 测试用例通常会创建或操作 HTML 元素来模拟不同的场景，并验证这些元素应用 CSS 后的样式。
    *   **举例:** 多个测试用例都使用 `GetDocument().body()->setInnerHTML()` 来设置 HTML 内容，例如在 `TEST_F(StyleEngineTest, VisitedDependentColorInvalidation)` 中创建了带有链接的 HTML 结构。
    *   **举例:** `TEST_F(StyleEngineTest, StyleElementTypeAttrChange)` 测试了 `<style>` 元素上的 `type` 属性如何影响其中 CSS 规则的生效，这涉及到 HTML 元素和 CSS 的关联。

*   **JavaScript:** 虽然这个文件主要是 C++ 代码，用于测试 Blink 引擎的内部逻辑，但它测试的功能最终会影响到 JavaScript 如何与样式交互。
    *   **间接关系:** JavaScript 可以通过 DOM API 获取元素的计算样式 (`getComputedStyle`)，这个测试文件保证了样式引擎计算出的样式是正确的，从而确保 JavaScript 获取到的样式也是准确的。
    *   **举例:**  虽然代码中没有直接的 JavaScript 代码，但测试 `TEST_F(StyleEngineTest, StyleElementTypeAttrChange)` 验证了当通过 JavaScript 动态修改 `<style>` 标签的 `type` 属性时，样式引擎是否会正确更新样式。

**逻辑推理、假设输入与输出:**

*   **`TEST_F(StyleEngineTest, VisitedDependentColorInvalidation)`**
    *   **假设输入:**
        *   HTML 中包含一个 `<a>` 标签，并设置了访问前和访问后的颜色。
        *   通过测试框架模拟链接的访问状态变化。
    *   **输出:**
        *   在访问状态变化后，通过 `GetComputedStyle()->VisitedDependentColor()` 获取到的链接颜色与预期的访问后颜色一致。

*   **`TEST_F(StyleEngineTest, StyleElementTypeAttrChange)`**
    *   **假设输入:**
        *   创建一个 `<style>` 元素，初始 `type` 属性为 `invalid`，包含设置 `body` 颜色的 CSS 规则。
        *   将 `<style>` 元素添加到文档中。
        *   更新文档生命周期。
        *   将 `<style>` 元素的 `type` 属性更改为 `text/css`。
        *   再次更新文档生命周期。
    *   **输出:**
        *   第一次更新后，`body` 的计算颜色是默认值 (黑色)。
        *   第二次更新后，`body` 的计算颜色是 `<style>` 中设置的颜色 (红色)。

**用户或编程常见的使用错误举例:**

*   **在 `<style>` 标签中使用错误的 `type` 属性值:**  用户可能会错误地将 `<style>` 标签的 `type` 属性设置为其他值，导致其中定义的 CSS 规则不生效。`TEST_F(StyleEngineTest, StyleElementTypeAttrChange)` 就是为了防止这种情况下的错误，并确保引擎能正确处理。
*   **依赖 `:visited` 伪类进行非样式相关的操作:** 用户可能会尝试使用 JavaScript 基于 `:visited` 伪类来判断用户是否访问过某个链接，这存在隐私风险，并且浏览器的行为可能会有所限制。 `TEST_F(StyleEngineTest, VisitedDependentColorInvalidation)` 确保了 `:visited` 的样式更新是正确的，但开发者应该注意其适用场景。
*   **不理解页面缩放对布局和元素尺寸的影响:**  开发者可能没有考虑到页面缩放会导致元素尺寸（例如边框宽度）的变化，从而导致布局问题。`TEST_F(StyleEngineTest, BorderWidthsAreRecalculatedWhenZoomChanges)` 验证了引擎在缩放时会重新计算边框宽度，开发者也应该理解这一点。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. **用户加载一个包含 CSS 样式的网页。**
2. **浏览器解析 HTML 结构，构建 DOM 树。**
3. **浏览器解析 CSS 规则，构建 CSSOM 树。**
4. **样式引擎将 DOM 树和 CSSOM 树结合起来，计算出每个元素的最终样式（Computed Style）。**  `style_engine_test.cc` 中的测试用例模拟了各种 CSS 规则和 HTML 结构，用于验证这个计算过程的正确性。
5. **布局引擎根据计算出的样式信息进行布局，确定元素的位置和大小。**
6. **渲染引擎将布局结果绘制到屏幕上。**

当用户遇到与样式相关的 Bug 时，例如样式没有生效、样式计算错误、页面缩放导致布局错乱等，开发者可能会需要调试 Blink 引擎的源代码。`style_engine_test.cc` 中的测试用例可以帮助开发者理解样式引擎的工作原理，并定位 Bug 发生的具体环节。例如，如果用户反馈 `:visited` 伪类颜色没有正确更新，开发者可以查看 `TEST_F(StyleEngineTest, VisitedDependentColorInvalidation)`  相关的代码，了解引擎是如何处理 `:visited` 状态变化的。

**作为第 8 部分，共 8 部分的功能归纳:**

作为整个样式引擎测试套件的最后一部分，`style_engine_test.cc`  **涵盖了样式引擎中一些较为独立或特定的功能点的测试**。它不像之前的测试文件可能侧重于基础的属性计算或选择器匹配，而是 **深入到一些更细致的 CSS 特性、浏览器行为和性能优化方面**。 这部分测试确保了样式引擎在处理这些边缘情况和特定场景时仍然能够正确可靠地工作，保证了 Web 平台的兼容性和稳定性。它可能也包含了一些在开发过程中后期加入的特性或修复的 Bug 相关的测试。

总而言之，`style_engine_test.cc` 是 Blink 引擎中至关重要的组成部分，它通过大量的单元测试用例，系统地验证了样式引擎的各种功能，确保了浏览器能够正确地解析和应用 CSS 样式，从而为用户提供一致且符合预期的网页浏览体验。

### 提示词
```
这是目录为blink/renderer/core/css/style_engine_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第8部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
econd);
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      second->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  third = GetDocument().getElementById(AtomicString("third"));
  EXPECT_TRUE(third);
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      third->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));

  Element* fourth = GetDocument().getElementById(AtomicString("fourth"));
  EXPECT_TRUE(fourth);
  EXPECT_EQ(
      Color::FromRGB(0, 0, 0),
      fourth->GetComputedStyle()->VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, StyleElementTypeAttrChange) {
  Element* style = GetDocument().CreateElementForBinding(AtomicString("style"));
  style->setAttribute(html_names::kTypeAttr, AtomicString("invalid"));
  style->setInnerHTML("body { color: red }");
  GetDocument().body()->appendChild(style);

  // <style> has no effect due to invalid type attribute value
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(0, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));

  // <style> should now be effective with a valid type attribute value
  style->setAttribute(html_names::kTypeAttr, AtomicString("text/css"));
  UpdateAllLifecyclePhases();
  EXPECT_EQ(Color::FromRGB(255, 0, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, SVGURIValueCacheClipPath) {
  Element* body = GetDocument().body();
  body->setInnerHTML(R"HTML(
    <svg><text clip-path="inset(10px)">CLIPPED</text><svg>
  )HTML");
  UpdateAllLifecyclePhases();

  EXPECT_EQ(FillOrClipPathCacheSize(), 0u);

  body->setInnerHTML(R"HTML(
    <svg><text clip-path="url(#clipped)">CLIPPED</text><svg>
  )HTML");
  UpdateAllLifecyclePhases();

  EXPECT_EQ(FillOrClipPathCacheSize(), 1u);
}

TEST_F(StyleEngineTest, SVGURIValueCacheFill) {
  Element* body = GetDocument().body();
  body->setInnerHTML(R"HTML(
    <svg><rect fill="red">FILLED</rect><svg>
  )HTML");
  UpdateAllLifecyclePhases();

  EXPECT_EQ(FillOrClipPathCacheSize(), 0u);

  body->setInnerHTML(R"HTML(
    <svg><rect fill="url(#fill)">FILLED</rect><svg>
  )HTML");
  UpdateAllLifecyclePhases();

  EXPECT_EQ(FillOrClipPathCacheSize(), 1u);
}

TEST_F(StyleEngineTest, BorderWidthsAreRecalculatedWhenZoomChanges) {
  // Tests that Border Widths are recalculated as expected
  // when Zoom and Device Scale Factor are changed.

  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.Initialize();

  WebFrameWidget* mainFrameWidget = web_view_impl->MainFrameWidget();

  const auto setZoom{[&](const float zoomFactor) {
    mainFrameWidget->SetZoomLevelForTesting(ZoomFactorToZoomLevel(zoomFactor));

    mainFrameWidget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  }};

  auto resetZoom{[&]() { setZoom(1.0f); }};

  const auto setDeviceScaleFactor{[&](const float deviceScaleFactor) {
    mainFrameWidget->SetDeviceScaleFactorForTesting(deviceScaleFactor);

    mainFrameWidget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  }};

  auto resetDeviceScaleFactor{[&]() { setDeviceScaleFactor(1.0f); }};

  auto reset{[&]() {
    resetZoom();
    resetDeviceScaleFactor();
  }};

  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();

  document->body()->setInnerHTML(R"HTML(
    <style>
    #square {
      height: 100px;
      width: 100px;
      border: 1.5px solid gray;
    }
    </style>
    <div id='square'></div>
  )HTML");

  mainFrameWidget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);

  const Element* square = document->getElementById(AtomicString("square"));
  ASSERT_NE(square, nullptr);

  const auto checkBorderWidth{[&](const float expected) {
    const ComputedStyle* computedStyle = square->GetComputedStyle();
    ASSERT_NE(computedStyle, nullptr);

    EXPECT_FLOAT_EQ(expected, computedStyle->BorderTopWidth());
  }};

  // Check initial border width.
  reset();
  checkBorderWidth(1.0f);

  // Check border width with zoom factors.
  setZoom(0.33f);
  checkBorderWidth(1.0f);

  setZoom(1.75f);
  checkBorderWidth(2.0f);

  setZoom(2.0f);
  checkBorderWidth(3.0f);

  // Check border width after zoom is reset.
  resetZoom();
  checkBorderWidth(1.0f);

  // Check border width with device scale factors.
  setDeviceScaleFactor(2.0f);
  checkBorderWidth(3.0f);

  setDeviceScaleFactor(3.0f);
  checkBorderWidth(4.0f);

  // Check border width after device scale factor is reset.
  resetDeviceScaleFactor();
  checkBorderWidth(1.0f);

  // Check border width with a combination
  // of zoom and device scale factors.
  setZoom(2.0f);
  setDeviceScaleFactor(2.0f);
  checkBorderWidth(6.0f);

  setZoom(1.5f);
  checkBorderWidth(4.0f);

  setDeviceScaleFactor(2.6f);
  checkBorderWidth(5.0f);

  setZoom(0.33f);
  checkBorderWidth(1.0f);

  // Check border width after resetting both
  // zoom and device scale factor is reset.
  reset();
  checkBorderWidth(1.0f);
}

TEST_F(StyleEngineTest, AnimationShorthandFlags) {
  String css = "animation: foo 1s";
  {
    ScopedScrollTimelineForTest scroll_timeline_enabled(false);
    ScopedScrollTimelineCurrentTimeForTest current_time_enabled(false);
    const CSSPropertyValueSet* set =
        css_test_helpers::ParseDeclarationBlock(css);
    ASSERT_TRUE(set);
    EXPECT_EQ(8u, set->PropertyCount());
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationDuration));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationTimingFunction));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationDelay));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationIterationCount));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationDirection));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationFillMode));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationPlayState));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationName));
  }
  {
    ScopedScrollTimelineForTest scroll_timeline_enabled(true);
    const CSSPropertyValueSet* set =
        css_test_helpers::ParseDeclarationBlock(css);
    ASSERT_TRUE(set);
    EXPECT_EQ(11u, set->PropertyCount());
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationDuration));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationTimingFunction));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationDelay));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationIterationCount));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationDirection));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationFillMode));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationPlayState));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationName));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationTimeline));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationRangeStart));
    EXPECT_TRUE(set->HasProperty(CSSPropertyID::kAnimationRangeEnd));
  }
}

TEST_F(StyleEngineTest, InitialStyle_Recalc) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #target {
        background-color: green;
        @starting-style { background-color: red; }
      }
    </style>
    <div id="target"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  constexpr Color green = Color::FromRGB(0, 128, 0);
  constexpr Color lime = Color::FromRGB(0, 255, 0);

  Element* target = GetDocument().getElementById(AtomicString("target"));
  unsigned before_count = GetStyleEngine().StyleForElementCount();

  target->SetInlineStyleProperty(CSSPropertyID::kColor, "lime");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(GetStyleEngine().StyleForElementCount() - before_count, 1u)
      << "The style recalc should not do a separate @starting-style pass since "
         "the element already has a style";
  EXPECT_EQ(target->ComputedStyleRef().VisitedDependentColor(
                GetCSSPropertyBackgroundColor()),
            green)
      << "Make sure @starting-style rules do not apply for the second pass";
  EXPECT_EQ(
      target->ComputedStyleRef().VisitedDependentColor(GetCSSPropertyColor()),
      lime)
      << "Check that the color changed to lime";
}

TEST_F(StyleEngineTest, InitialStyle_FromDisplayNone) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #target {
        background-color: green;
        @starting-style { background-color: red; }
      }
    </style>
    <div id="target" style="display:none"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  constexpr Color green = Color::FromRGB(0, 128, 0);

  Element* target = GetDocument().getElementById(AtomicString("target"));
  unsigned before_count = GetStyleEngine().StyleForElementCount();

  target->SetInlineStyleProperty(CSSPropertyID::kDisplay, "block");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(GetStyleEngine().StyleForElementCount() - before_count, 2u)
      << "The style recalc needs to do two passes because the element was "
         "display:none and @starting-style styles are matching";
  EXPECT_EQ(target->ComputedStyleRef().VisitedDependentColor(
                GetCSSPropertyBackgroundColor()),
            green)
      << "Make sure @starting-style do not apply for the second pass";
}

TEST_F(StyleEngineTest, InitialStyleCount_EnsureComputedStyle) {
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      #target {
        background-color: green;
        transition: background-color 100s step-end;
        @starting-style { background-color: red; }
      }
    </style>
    <div id="target" style="display:none"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  constexpr Color green = Color::FromRGB(0, 128, 0);

  Element* target = GetDocument().getElementById(AtomicString("target"));
  unsigned before_count = GetStyleEngine().StyleForElementCount();

  ASSERT_FALSE(target->GetComputedStyle())
      << "Initially no ComputedStyle on display:none element";

  const ComputedStyle* none_style = target->EnsureComputedStyle();
  ASSERT_TRUE(none_style);

  EXPECT_EQ(GetStyleEngine().StyleForElementCount() - before_count, 1u)
      << "No @starting-style pass for EnsureComputedStyle";

  EXPECT_EQ(target->ComputedStyleRef().VisitedDependentColor(
                GetCSSPropertyBackgroundColor()),
            green)
      << "Transitions are not started and @starting-style does not apply in "
         "display:none";
}

TEST_F(StyleEngineTest, UseCountCSSAnchorPositioning) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kCSSAnchorPositioning));

  SetBodyInnerHTML("<style>#foo { top: anchor(top); }");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSAnchorPositioning));

  ClearUseCounter(WebFeature::kCSSAnchorPositioning);
  SetBodyInnerHTML("<style>#foo { width: anchor-size(width); }");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSAnchorPositioning));

  ClearUseCounter(WebFeature::kCSSAnchorPositioning);
  SetBodyInnerHTML("<style>@position-try --pf {}</style>");
  EXPECT_TRUE(IsUseCounted(WebFeature::kCSSAnchorPositioning));
}

TEST_F(StyleEngineTest, EnsureAppRegionTriggersRelayout) {
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.Initialize();
  web_view_impl->SetSupportsDraggableRegions(true);
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  Document* document =
      To<LocalFrame>(web_view_impl->GetPage()->MainFrame())->GetDocument();
  document->body()->setInnerHTML(R"HTML(
    <head>
    <style>
      .drag {
        app-region: drag
      }
      .no-drag {
        app-region: no-drag
      }
    </style>
    </head>
    <body>
       <div id="drag-region"></div>
    </body>
  )HTML");

  Element* drag_element = document->getElementById(AtomicString("drag-region"));

  auto regions = document->DraggableRegions();
  auto it =
      std::find_if(regions.begin(), regions.end(),
                   [](blink::DraggableRegionValue s) { return s.draggable; });
  EXPECT_EQ(it, regions.end()) << "There should be no drag regions";

  drag_element->classList().Add(AtomicString("drag"));
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  regions = document->DraggableRegions();
  it = std::find_if(regions.begin(), regions.end(),
                    [](blink::DraggableRegionValue s) { return s.draggable; });
  EXPECT_NE(it, regions.end()) << "There should be one drag region";

  drag_element->classList().Add(AtomicString("no-drag"));
  web_view_impl->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);

  regions = document->DraggableRegions();
  it = std::find_if(regions.begin(), regions.end(),
                    [](blink::DraggableRegionValue s) { return s.draggable; });

  EXPECT_EQ(it, regions.end()) << "There should be no drag regions";
}

TEST_F(StyleEngineTest, ForcedColorsLightDark) {
  ScopedForcedColorsForTest scoped_feature(true);
  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetInForcedColors(GetDocument(),
                                        /*in_forced_colors=*/true);
  GetDocument().body()->setInnerHTML(R"HTML(
    <style>
      :root { color-scheme: light only; }
      #light-dark {
        color: light-dark(GrayText, red);
      }
      #reference {
        color: GrayText;
      }
    </style>
    <div id="light-dark"></div>
    <div id="reference"></div>
  )HTML");
  UpdateAllLifecyclePhases();

  const ComputedStyle& light_dark =
      GetDocument()
          .getElementById(AtomicString("light-dark"))
          ->ComputedStyleRef();
  const ComputedStyle& reference =
      GetDocument()
          .getElementById(AtomicString("reference"))
          ->ComputedStyleRef();

  EXPECT_EQ(light_dark.VisitedDependentColor(GetCSSPropertyColor()),
            reference.VisitedDependentColor(GetCSSPropertyColor()));
}

TEST_F(StyleEngineTest, UseCountMediaQueryRangeSyntax) {
  EXPECT_FALSE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));

  ClearUseCounter(WebFeature::kMediaQueryRangeSyntax);
  SetBodyInnerHTML("<style>@media (width: 1px){}</style>");
  EXPECT_FALSE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));

  ClearUseCounter(WebFeature::kMediaQueryRangeSyntax);
  SetBodyInnerHTML("<style>@media (width = 1px){}</style>");
  EXPECT_TRUE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));

  ClearUseCounter(WebFeature::kMediaQueryRangeSyntax);
  SetBodyInnerHTML("<style>@media ((width: 1px) and (height: 1px)){}</style>");
  EXPECT_FALSE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));

  ClearUseCounter(WebFeature::kMediaQueryRangeSyntax);
  SetBodyInnerHTML("<style>@media (width){}</style>");
  EXPECT_FALSE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));

  ClearUseCounter(WebFeature::kMediaQueryRangeSyntax);
  SetBodyInnerHTML("<style>@media (width < 1px){}</style>");
  EXPECT_TRUE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));

  ClearUseCounter(WebFeature::kMediaQueryRangeSyntax);
  SetBodyInnerHTML("<style>@media (1px < width){}</style>");
  EXPECT_TRUE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));

  ClearUseCounter(WebFeature::kMediaQueryRangeSyntax);
  SetBodyInnerHTML("<style>@media (1px < width < 2px){}</style>");
  EXPECT_TRUE(IsUseCounted(WebFeature::kMediaQueryRangeSyntax));
}

}  // namespace blink
```