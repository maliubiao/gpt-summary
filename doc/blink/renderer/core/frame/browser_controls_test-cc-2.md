Response:
The user wants a summary of the functionalities implemented in the `browser_controls_test.cc` file, focusing on its relation with web technologies (JavaScript, HTML, CSS), providing examples with hypothetical inputs and outputs, and highlighting potential user or programming errors.

The file appears to contain various unit tests for the browser controls functionality in the Blink rendering engine. These tests cover how browser controls (like the address bar or toolbar) interact with web page layout and viewport units (vh, vw, dvh, dvw).

Here's a breakdown of the functionalities based on the test names and code snippets:

1. **Interaction with Viewport Units (vh, vw, dvh, dvw):**  Many tests focus on how the presence or absence of browser controls affects the calculation of viewport units.
2. **Dynamic Viewport Units (dvh, dvw):** Tests ensure that these units dynamically adjust based on the visibility of browser controls.
3. **Legacy Pages and Minimum Scale:** Some tests deal with how viewport units are calculated on pages with a non-1 minimum scale, considering the browser controls.
4. **Minimum Height for Browser Controls:** Tests verify the behavior when minimum heights are set for top or bottom browser controls.
5. **Viewport Anchoring:**  One test checks if the viewport remains anchored when browser controls are shown while the document is fully scrolled.
6. **Locked Browser Controls:** Tests cover scenarios where browser controls are in a locked state (always shown or hidden).
7. **Size Adjustment for Viewport:**  Tests examine how the size adjustment due to browser controls is reported to the viewport.
8. **Keeping Top Controls Hidden:** A test verifies that increasing the height of hidden top controls doesn't inadvertently show them.
9. **Raster Invalidation:** One test checks if hiding browser controls triggers raster invalidation of the composited layer.
10. **Scrolling with Minimum Height:** Tests ensure correct browser control behavior during scrolling when minimum heights are set.
11. **Mixing Animated and Non-Animated Updates:** A test addresses a specific bug where mixing animated and non-animated browser control updates could cause issues.
12. **Animated Hiding of Browser Controls:** A test (which is cut off) likely focuses on verifying that the hiding of browser controls is animated when requested.

Let's structure the answer according to the user's requirements.
这是 `blink/renderer/core/frame/browser_controls_test.cc` 文件功能的一个总结，它主要负责测试 Blink 引擎中浏览器控件（例如地址栏、工具栏等）与网页布局、特别是与各种视口单位（viewport units）的交互行为。

**功能归纳:**

这个文件包含了针对浏览器控件行为的各种单元测试，主要集中在以下几个方面：

1. **视口单位 (Viewport Units) 的计算和表现：** 验证 `vh`, `vw`, `dvh`, `dvw` 等视口单位在浏览器控件显示和隐藏时的计算是否正确。特别是 `dvh` 和 `dvw` 这种动态视口单位是否能根据浏览器控件的状态动态调整。
2. **传统页面 (Legacy Pages) 的视口单位处理：** 测试在具有非 1 最小缩放比例的传统页面上，视口单位如何正确计算，并考虑浏览器控件的影响。
3. **浏览器控件的最小高度限制：** 验证当设置了顶部或底部浏览器控件的最小高度时，视口单位的计算以及滚动行为是否符合预期。
4. **视口锚定 (Viewport Anchoring)：**  测试在页面完全滚动到底部时，显示浏览器控件是否会保持视口位置不变，防止出现不必要的跳动。
5. **锁定状态的浏览器控件：**  测试当浏览器控件处于锁定显示或锁定隐藏状态时，视口单位的计算是否正确。
6. **视口大小调整 (Viewport Size Adjustment)：** 验证由于浏览器控件的显示或隐藏而引起的视口大小调整是否被正确报告。
7. **保持顶部控件隐藏 (Keeping Top Controls Hidden)：** 测试在顶部控件处于隐藏状态时，即使调整其高度，也不会意外地显示出来。
8. **合成图层失效 (Composited Layer Invalidation)：**  测试隐藏浏览器控件是否会正确地使相关的合成图层失效，触发重绘。
9. **带有最小高度的滚动行为：** 测试在设置了浏览器控件的最小高度后，滚动操作是否能正确地隐藏或显示浏览器控件，并遵守最小高度的限制。
10. **动画和非动画状态更新的混合处理：**  测试同时发送动画和非动画的浏览器控件状态更新时，是否会发生冲突或导致状态错误。
11. **浏览器控件的动画隐藏效果：** (根据未完成的代码推断) 测试请求动画隐藏浏览器控件时，是否真的会产生动画效果，而不是立即隐藏。

**与 JavaScript, HTML, CSS 的关系举例说明:**

这些测试直接关系到开发者在使用 JavaScript, HTML, CSS 构建网页时的体验，特别是涉及到布局和响应式设计时。

*   **CSS 视口单位 (`vh`, `vw`, `dvh`, `dvw`)：** 这些测试确保了 CSS 中定义的视口单位能够按照规范工作。例如，如果一个 `div` 的高度设置为 `100vh`，那么它应该占据视口的高度（可能会受到浏览器控件的影响，特别是对于 `dvh`）。
    ```html
    <div style="height: 100vh;"></div>
    ```
    如果浏览器控件隐藏，这个 `div` 应该占据整个屏幕高度。如果浏览器控件显示，`vh` 通常会包含浏览器控件的高度，而 `dvh` 则会根据实际可用的视口高度进行调整。

    **假设输入与输出 (对于 `dvh`):**
    *   **假设输入 (HTML):**
        ```html
        <div id="test" style="height: 100dvh;"></div>
        ```
    *   **假设输入 (场景):** 浏览器控件完全显示，占据 100px 高度，视口总高度为 800px。
    *   **预期输出:**  JavaScript 获取 `#test` 元素的 `getBoundingClientRect().height` 应该接近 700px。
    *   **假设输入 (场景):** 浏览器控件完全隐藏，视口总高度为 800px。
    *   **预期输出:** JavaScript 获取 `#test` 元素的 `getBoundingClientRect().height` 应该接近 800px。

*   **JavaScript 获取元素尺寸：**  测试中大量使用了 `GetElementById` 和 `GetBoundingClientRect` 等方法，模拟了 JavaScript 代码获取页面元素尺寸的情况。这些测试验证了在浏览器控件状态变化时，JavaScript 获取的元素尺寸是否准确。
    ```javascript
    const element = document.getElementById('myElement');
    const height = element.getBoundingClientRect().height;
    ```

*   **HTML 结构和 Meta 标签：** 测试中使用了不同的 HTML 文件，例如 `v-size.html`, `dv-size.html` 等，这些文件可能包含不同的布局结构和视口 meta 标签 (`<meta name="viewport" ...>`)，以模拟不同的网页场景。测试确保了在这些不同场景下，浏览器控件的行为是一致且正确的。

**用户或编程常见的使用错误举例说明:**

*   **错误地假设 `vh` 总是等于设备屏幕高度：** 用户可能会错误地认为 `100vh` 始终等于设备的物理屏幕高度，而忽略了浏览器控件的存在。这会导致在某些设备上，元素的实际高度会超出可见区域。开发者应该理解 `vh` 的行为，并考虑使用 `dvh` 来获得动态的视口高度。
    ```css
    /* 错误的做法，可能会导致内容被浏览器控件遮挡 */
    .full-height {
      height: 100vh;
    }
    /* 更好的做法，使用 dvh */
    .dynamic-full-height {
      height: 100dvh;
    }
    ```

*   **在 JavaScript 中没有考虑浏览器控件的影响就计算元素位置：** 开发者可能会在 JavaScript 中直接使用 `window.innerHeight` 来计算视口高度，而没有考虑到浏览器控件的存在。这会导致在浏览器控件显示时，计算出的位置不准确。
    ```javascript
    // 错误的做法
    const viewportHeight = window.innerHeight;
    const elementTop = viewportHeight - elementHeight;

    // 应该考虑浏览器控件的影响，或者使用更精确的方法
    const elementRect = element.getBoundingClientRect();
    ```

*   **在传统页面上错误地使用视口单位：** 在具有非 1 最小缩放比例的传统页面上，视口单位的计算可能会更加复杂。开发者如果没有充分理解其行为，可能会导致布局错乱。测试 `DontAffectVHUnitsWithScale` 和 `DontAffectVHUnitsUseLayoutSize` 就是为了验证这种情况下的正确性。

**本部分的总结:**

这段代码主要测试了在滚动条消失的情况下，视口单位 `dvw` 的表现是否符合预期，即宽度不应该发生变化。它创建了包含绝对定位和固定定位元素的 HTML 结构，并通过移除一个占据宽度的 `spacer` 元素来模拟滚动条消失的场景。测试验证了在滚动条消失前后，绝对定位和固定定位元素的宽度是否保持不变。这确保了动态视口宽度单位在滚动条出现/消失时行为的稳定性。

Prompt: 
```
这是目录为blink/renderer/core/frame/browser_controls_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
ts should not change when scrollbar disappears.
  EXPECT_FLOAT_EQ(param.width, abs_pos->GetBoundingClientRect()->width());
  EXPECT_FLOAT_EQ(param.width, fixed_pos->GetBoundingClientRect()->width());
  Element* spacer = GetElementById(WebString::FromUTF8("spacer"));
  ASSERT_TRUE(spacer);
  spacer->remove();
  UpdateAllLifecyclePhases();
  EXPECT_FLOAT_EQ(param.width, abs_pos->GetBoundingClientRect()->width());
  EXPECT_FLOAT_EQ(param.width, fixed_pos->GetBoundingClientRect()->width());
}

static ViewportUnitTestCase viewport_unit_test_cases[] = {
    {"v-size.html", 200.f, 200.f},
    {"lv-size.html", 200.f, 200.f},
    {"sv-size.html", 200.f, 150.f},
};

INSTANTIATE_TEST_SUITE_P(All,
                         BrowserControlsViewportUnitTest,
                         testing::ValuesIn(viewport_unit_test_cases));

// Ensure that browser controls *do* affect dvh units.
TEST_F(BrowserControlsTest, MAYBE(DoAffectDVHUnits)) {
  // Initialize with the browser controls showing.
  WebViewImpl* web_view = Initialize("dv-size.html");
  web_view->GetPage()->GetChromeClient().SetBrowserControlsState(100.0f, 0.0f,
                                                                 true);
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  ASSERT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // 'dvh' units should respond according to the current state of the controls.
  Element* abs_pos = GetElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos = GetElementById(WebString::FromUTF8("fixed"));
  EXPECT_FLOAT_EQ(150.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(150.f, fixed_pos->GetBoundingClientRect()->height());

  // The size used for viewport units should not be reduced by the top
  // controls.
  EXPECT_EQ(300,
            GetFrame()->View()->DynamicViewportSizeForViewportUnits().height());

  // Hide the browser controls.
  VerticalScroll(-100.f);
  web_view->GetPage()->GetChromeClient().SetBrowserControlsState(100.0f, 0.0f,
                                                                 false);
  UpdateAllLifecyclePhases();

  ASSERT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  // dvh units should be dynamic with respect to the browser controls so both
  // <div>s should change size as a result of the browser controls hiding.
  EXPECT_FLOAT_EQ(200.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->height());

  // The viewport size used for dvh units should change as a result of top
  // controls hiding.
  EXPECT_EQ(400,
            GetFrame()->View()->DynamicViewportSizeForViewportUnits().height());

  // The viewport size used for dvh units should not change as a result of top
  // controls partially showing.
  ApplyViewportChangesArgs args;
  args.page_scale_delta = 1.f;
  args.is_pinch_gesture_active = false;
  args.top_controls_delta = 0.5f;
  args.bottom_controls_delta = 0.f;
  args.browser_controls_constraint = cc::BrowserControlsState::kBoth;
  args.scroll_gesture_did_end = false;
  web_view->ApplyViewportChanges(args);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(400,
            GetFrame()->View()->DynamicViewportSizeForViewportUnits().height());

  // dvw units should not change when scrollbar disappears.
  EXPECT_FLOAT_EQ(200.f, abs_pos->GetBoundingClientRect()->width());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->width());
  Element* spacer = GetElementById(WebString::FromUTF8("spacer"));
  ASSERT_TRUE(spacer);
  spacer->remove();
  UpdateAllLifecyclePhases();
  EXPECT_FLOAT_EQ(200.f, abs_pos->GetBoundingClientRect()->width());
  EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->width());
}

// Ensure that on a legacy page (there's a non-1 minimum scale) 100vh units fill
// the viewport, with browser controls hidden, when the viewport encompasses the
// layout width.
TEST_F(BrowserControlsTest, MAYBE(DontAffectVHUnitsWithScale)) {
  // Initialize with the browser controls showing.
  WebViewImpl* web_view = Initialize("vh-height-width-800.html");
  web_view->ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  ASSERT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // Device viewport is 400px but the page is width=800 so minimum-scale
  // should be 0.5. This is also the scale at which the viewport fills the
  // layout width.
  ASSERT_EQ(0.5f, web_view->MinimumPageScaleFactor());

  // We should size vh units so that 100vh fills the viewport at min-scale so
  // we have to account for the minimum page scale factor. Since both boxes
  // are 50vh, and layout scale = 0.5, we have a vh viewport of 400 / 0.5 = 800
  // so we expect 50vh to be 400px.
  Element* abs_pos = GetElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos = GetElementById(WebString::FromUTF8("fixed"));
  EXPECT_FLOAT_EQ(400.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(400.f, fixed_pos->GetBoundingClientRect()->height());

  // The size used for viewport units should not be reduced by the top
  // controls.
  EXPECT_EQ(800,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());

  // Hide the browser controls.
  VerticalScroll(-100.f);
  web_view->ResizeWithBrowserControls(gfx::Size(400, 400), 100.f, 0, false);
  UpdateAllLifecyclePhases();

  ASSERT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  // vh units should be static with respect to the browser controls so neighter
  // <div> should change size are a result of the browser controls hiding.
  EXPECT_FLOAT_EQ(400.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(400.f, fixed_pos->GetBoundingClientRect()->height());

  // The viewport size used for vh units should not change as a result of top
  // controls hiding.
  EXPECT_EQ(800,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());
}

// Ensure that on a legacy page (there's a non-1 minimum scale) whose viewport
// at minimum-scale is larger than the layout size, 100vh units fill the
// viewport, with browser controls hidden, when the viewport is scaled such that
// its width equals the layout width.
TEST_F(BrowserControlsTest, MAYBE(DontAffectVHUnitsUseLayoutSize)) {
  // Initialize with the browser controls showing.
  WebViewImpl* web_view = Initialize("vh-height-width-800-extra-wide.html");
  web_view->ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  UpdateAllLifecyclePhases();

  ASSERT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // Device viewport is 400px and page is width=800 but there's an element
  // that's 1600px wide so the minimum scale is 0.25 to encompass that.
  ASSERT_EQ(0.25f, web_view->MinimumPageScaleFactor());

  // The viewport will match the layout width at scale=0.5 so the height used
  // for vh should be (300 / 0.5) for the layout height + (100 / 0.5) for top
  // controls = 800.
  EXPECT_EQ(800,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());
}

// Ensure that vh units are correctly calculated when a top controls min-height
// is set.
TEST_F(BrowserControlsTest, MAYBE(VHUnitsWithTopMinHeight)) {
  // Initialize with the browser controls showing.
  // Top controls height: 100, top controls min-height: 20.
  WebViewImpl* web_view = Initialize("v-size.html");
  web_view->ResizeWithBrowserControls(gfx::Size(400, 300), gfx::Size(400, 300),
                                      {100, 20, 0, 0, false, true});
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  EXPECT_FLOAT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // 'vh' units should be based on the viewport when the browser controls are
  // hidden. However, the viewport height will be limited by the min-height
  // since the top controls can't completely hide.
  Element* abs_pos = GetElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos = GetElementById(WebString::FromUTF8("fixed"));
  float div_height = 0.5f * (300 + (100 - 20));
  EXPECT_FLOAT_EQ(div_height, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(div_height, fixed_pos->GetBoundingClientRect()->height());

  // The size used for viewport units should be reduced by the top controls
  // min-height.
  EXPECT_EQ(380,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());

  // Scroll the top controls to hide. They won't scroll past the min-height.
  VerticalScroll(-100.f);
  web_view->ResizeWithBrowserControls(gfx::Size(400, 380), gfx::Size(400, 380),
                                      {100, 20, 0, 0, false, false});
  UpdateAllLifecyclePhases();

  EXPECT_FLOAT_EQ(20.f, web_view->GetBrowserControls().ContentOffset());

  // vh units should be static with respect to the browser controls so neither
  // <div> should change size are a result of the browser controls hiding.
  EXPECT_FLOAT_EQ(190.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(190.f, fixed_pos->GetBoundingClientRect()->height());

  // The viewport size used for vh units should not change as a result of top
  // controls hiding.
  ASSERT_EQ(380,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());
}

// Ensure that vh units are correctly calculated when a bottom controls
// min-height is set.
TEST_F(BrowserControlsTest, MAYBE(VHUnitsWithBottomMinHeight)) {
  // Initialize with the browser controls showing.
  // Top controls height: 100, top controls min-height: 20.
  // Bottom controls height: 50, bottom controls min-height: 10.
  WebViewImpl* web_view = Initialize("v-size.html");
  web_view->ResizeWithBrowserControls(gfx::Size(400, 250), gfx::Size(400, 250),
                                      {100, 20, 50, 10, false, true});
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  CompositeForTest();

  EXPECT_FLOAT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // 'vh' units should be based on the viewport when the browser controls are
  // hidden. However, the viewport height will be limited by the min-height
  // since the top and bottom controls can't completely hide.
  Element* abs_pos = GetElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos = GetElementById(WebString::FromUTF8("fixed"));
  float div_height = 0.5f * (250 + (100 - 20) + (50 - 10));
  EXPECT_FLOAT_EQ(div_height, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(div_height, fixed_pos->GetBoundingClientRect()->height());

  // The size used for viewport units should be reduced by the top/bottom
  // controls min-height.
  EXPECT_EQ(370,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());

  // Scroll the controls to hide. They won't scroll past the min-height.
  VerticalScroll(-100.f);
  web_view->ResizeWithBrowserControls(gfx::Size(400, 370), gfx::Size(400, 370),
                                      {100, 20, 50, 10, false, false});
  UpdateAllLifecyclePhases();

  EXPECT_FLOAT_EQ(20.f, web_view->GetBrowserControls().ContentOffset());
  EXPECT_FLOAT_EQ(10.f, web_view->GetBrowserControls().BottomContentOffset());

  // vh units should be static with respect to the browser controls so neither
  // <div> should change size are a result of the browser controls hiding.
  EXPECT_FLOAT_EQ(185.f, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(185.f, fixed_pos->GetBoundingClientRect()->height());

  // The viewport size used for vh units should not change as a result of the
  // controls hiding.
  ASSERT_EQ(370,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());
}

// Ensure that vh units are correctly calculated with changing min-heights.
TEST_F(BrowserControlsTest, MAYBE(VHUnitsWithMinHeightsChanging)) {
  // Initialize with the browser controls showing.
  // Top controls height: 100, top controls min-height: 20.
  // Bottom controls height: 50, bottom controls min-height: 10.
  WebViewImpl* web_view = Initialize("v-size.html");
  web_view->ResizeWithBrowserControls(gfx::Size(400, 250), gfx::Size(400, 250),
                                      {100, 20, 50, 10, false, true});
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  UpdateAllLifecyclePhases();

  EXPECT_FLOAT_EQ(100.f, web_view->GetBrowserControls().ContentOffset());

  // 'vh' units should be based on the viewport when the browser controls are
  // hidden. However, the viewport height will be limited by the min-height
  // since the top and bottom controls can't completely hide.
  Element* abs_pos = GetElementById(WebString::FromUTF8("abs"));
  Element* fixed_pos = GetElementById(WebString::FromUTF8("fixed"));
  float div_height = 0.5f * (250 + (100 - 20) + (50 - 10));
  EXPECT_FLOAT_EQ(div_height, abs_pos->GetBoundingClientRect()->height());
  EXPECT_FLOAT_EQ(div_height, fixed_pos->GetBoundingClientRect()->height());

  // The size used for viewport units should be reduced by the top/bottom
  // controls min-height.
  EXPECT_EQ(370,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());

  // Make the min-heights 0.
  web_view->ResizeWithBrowserControls(gfx::Size(400, 250), gfx::Size(400, 250),
                                      {100, 0, 50, 0, false, true});
  UpdateAllLifecyclePhases();

  // The viewport size used for vh units should be updated to reflect the change
  // to the min-heights.
  float height = 250 + (100 - 0) + (50 - 0);
  ASSERT_EQ(height,
            GetFrame()->View()->LargeViewportSizeForViewportUnits().height());
}

// This tests that the viewport remains anchored when browser controls are
// brought in while the document is fully scrolled. This normally causes
// clamping of the visual viewport to keep it bounded by the layout viewport
// so we're testing that the viewport anchoring logic is working to keep the
// view unchanged.
TEST_F(BrowserControlsTest,
       MAYBE(AnchorViewportDuringBrowserControlsAdjustment)) {
  int content_height = 1016;
  int layout_viewport_height = 500;
  int visual_viewport_height = 500;
  int browser_controls_height = 100;
  int page_scale = 2;
  int min_scale = 1;

  // Initialize with the browser controls showing.
  WebViewImpl* web_view = Initialize("large-div.html");
  GetWebView()->SetDefaultPageScaleLimits(min_scale, 5);
  web_view->ResizeWithBrowserControls(gfx::Size(800, layout_viewport_height),
                                      browser_controls_height, 0, true);
  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  UpdateAllLifecyclePhases();

  LocalFrameView* view = GetFrame()->View();
  ScrollableArea* root_viewport = GetFrame()->View()->GetScrollableArea();

  int expected_visual_offset =
      ((layout_viewport_height + browser_controls_height / min_scale) *
           page_scale -
       (visual_viewport_height + browser_controls_height)) /
      page_scale;
  int expected_layout_offset =
      content_height -
      (layout_viewport_height + browser_controls_height / min_scale);
  int expected_root_offset = expected_visual_offset + expected_layout_offset;

  // Zoom in to 2X and fully scroll both viewports.
  web_view->SetPageScaleFactor(page_scale);
  CompositeForTest();
  {
    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -10000));
    CompositeForTest();

    ASSERT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

    EXPECT_EQ(expected_visual_offset,
              GetVisualViewport().GetScrollOffset().y());
    EXPECT_EQ(expected_layout_offset,
              view->LayoutViewport()->GetScrollOffset().y());
    EXPECT_EQ(expected_root_offset, root_viewport->GetScrollOffset().y());

    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  }

  // Commit the browser controls resize so that the browser controls do not
  // shrink the layout size. This should not have moved any of the viewports.
  web_view->ResizeWithBrowserControls(
      gfx::Size(800, layout_viewport_height + browser_controls_height),
      browser_controls_height, 0, false);
  UpdateAllLifecyclePhases();
  ASSERT_EQ(expected_visual_offset, GetVisualViewport().GetScrollOffset().y());
  ASSERT_EQ(expected_layout_offset,
            view->LayoutViewport()->GetScrollOffset().y());
  ASSERT_EQ(expected_root_offset, root_viewport->GetScrollOffset().y());

  // Now scroll back up just enough to show the browser controls. The browser
  // controls should shrink both viewports but the layout viewport by a greater
  // amount. This means the visual viewport's offset must be clamped to keep it
  // within the layout viewport. Make sure we adjust the scroll position to
  // account for this and keep the visual viewport at the same location relative
  // to the document (i.e. the user shouldn't see a movement).
  {
    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 80));
    CompositeForTest();

    GetVisualViewport().ClampToBoundaries();
    view->LayoutViewport()->SetScrollOffset(
        view->LayoutViewport()->GetScrollOffset(),
        mojom::blink::ScrollType::kProgrammatic);

    ASSERT_EQ(80.f, web_view->GetBrowserControls().ContentOffset());
    EXPECT_EQ(expected_root_offset, root_viewport->GetScrollOffset().y());

    GetWebFrameWidget()->DispatchThroughCcInputHandler(
        GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  }
}

// Ensure that vh units are correct when browser controls are in a locked
// state. That is, normally we need to add the browser controls height to vh
// units since 100vh includes the browser controls even if they're hidden while
// the ICB height does not. When the controls are locked hidden, the ICB size
// is the full viewport height so there's no need to add the browser controls
// height.  crbug.com/688738.
TEST_F(BrowserControlsSimTest, MAYBE(ViewportUnitsWhenControlsLocked)) {
  // Initialize with the browser controls showing.
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
            <style>
              #abs {
                position: absolute;
                left: 0px;
                top: 0px;
                width: 100px;
                height: 50vh;
              }

              #fixed {
                position: fixed;
                right: 0px;
                top: 0px;
                width: 100px;
                height: 50vh;
              }

              #spacer {
                height: 1000px;
              }
            </style>
            <div id="abs"></div>
            <div id="fixed"></div>
            <div id="spacer"></div>
      )HTML");
  WebView().ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kBoth, cc::BrowserControlsState::kShown, false,
      std::nullopt);
  Compositor().BeginFrame();

  ASSERT_EQ(1.f, WebView().GetBrowserControls().TopShownRatio());
  ASSERT_EQ(100.f, WebView().GetBrowserControls().ContentOffset());
  ASSERT_EQ(300, GetDocument().View()->GetLayoutSize().height());

  Element* abs_pos = GetDocument().getElementById(AtomicString("abs"));
  Element* fixed_pos = GetDocument().getElementById(AtomicString("fixed"));

  // Lock the browser controls to hidden.
  {
    Compositor().LayerTreeHost()->UpdateBrowserControlsState(
        cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kHidden,
        false, std::nullopt);
    WebView().ResizeWithBrowserControls(gfx::Size(400, 400), 100.f, 0, false);
    Compositor().BeginFrame();

    ASSERT_EQ(0.f, WebView().GetBrowserControls().ContentOffset());
    ASSERT_EQ(400, GetDocument().View()->GetLayoutSize().height());

    // Make sure we're not adding the browser controls height to the vh units
    // as when they're locked to hidden, the ICB fills the entire viewport
    // already.
    EXPECT_FLOAT_EQ(200.f, abs_pos->GetBoundingClientRect()->height());
    EXPECT_FLOAT_EQ(200.f, fixed_pos->GetBoundingClientRect()->height());
    EXPECT_EQ(
        400,
        GetDocument().View()->LargeViewportSizeForViewportUnits().height());
  }

  // Lock the browser controls to shown. This should cause the vh units to
  // behave as usual by including the browser controls region in 100vh.
  {
    Compositor().LayerTreeHost()->UpdateBrowserControlsState(
        cc::BrowserControlsState::kShown, cc::BrowserControlsState::kShown,
        false, std::nullopt);
    WebView().ResizeWithBrowserControls(gfx::Size(400, 300), 100.f, 0, true);
    Compositor().BeginFrame();

    ASSERT_EQ(100.f, WebView().GetBrowserControls().ContentOffset());
    ASSERT_EQ(300, GetDocument().View()->GetLayoutSize().height());

    // Make sure we're not adding the browser controls height to the vh units as
    // when they're locked to shown, the ICB fills the entire viewport already.
    EXPECT_FLOAT_EQ(150.f, abs_pos->GetBoundingClientRect()->height());
    EXPECT_FLOAT_EQ(150.f, fixed_pos->GetBoundingClientRect()->height());
    EXPECT_EQ(
        400,
        GetDocument().View()->LargeViewportSizeForViewportUnits().height());
  }
}

// Test the size adjustment sent to the viewport when top controls exist.
TEST_F(BrowserControlsTest, MAYBE(TopControlsSizeAdjustment)) {
  WebViewImpl* web_view = Initialize();
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, 0, false);
  web_view->GetBrowserControls().SetShownRatio(1, 0.0);
  EXPECT_FLOAT_EQ(-50.f,
                  web_view->GetBrowserControls().UnreportedSizeAdjustment());

  web_view->GetBrowserControls().SetShownRatio(0.5, 0.0);
  EXPECT_FLOAT_EQ(-25.f,
                  web_view->GetBrowserControls().UnreportedSizeAdjustment());

  web_view->GetBrowserControls().SetShownRatio(0.0, 0.0);
  EXPECT_FLOAT_EQ(0.f,
                  web_view->GetBrowserControls().UnreportedSizeAdjustment());
}

// Test the size adjustment sent to the viewport when bottom controls exist.
// There should never be an adjustment since the bottom controls do not change
// the content offset.
TEST_F(BrowserControlsTest, MAYBE(BottomControlsSizeAdjustment)) {
  WebViewImpl* web_view = Initialize();
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      0, 50.f, false);
  web_view->GetBrowserControls().SetShownRatio(0.0, 1);
  EXPECT_FLOAT_EQ(0.f,
                  web_view->GetBrowserControls().UnreportedSizeAdjustment());

  web_view->GetBrowserControls().SetShownRatio(0.0, 0.5);
  EXPECT_FLOAT_EQ(0.f,
                  web_view->GetBrowserControls().UnreportedSizeAdjustment());

  web_view->GetBrowserControls().SetShownRatio(0.0, 0.0);
  EXPECT_FLOAT_EQ(0.f,
                  web_view->GetBrowserControls().UnreportedSizeAdjustment());
}

TEST_F(BrowserControlsTest, MAYBE(GrowingHeightKeepsTopControlsHidden)) {
  WebViewImpl* web_view = Initialize();
  float bottom_height = web_view->GetBrowserControls().BottomHeight();
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      1.f, bottom_height, false);

  web_view->GetBrowserControls().UpdateConstraintsAndState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kHidden);

  // As we expand the top controls height while hidden, the content offset
  // shouldn't change.
  EXPECT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      50.f, bottom_height, false);
  EXPECT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());

  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      100.f, bottom_height, false);
  EXPECT_EQ(0.f, web_view->GetBrowserControls().ContentOffset());
}

TEST_F(BrowserControlsTest,
       MAYBE(HidingBrowserControlsInvalidatesCompositedLayer)) {
  // Initialize with the browser controls showing.
  WebViewImpl* web_view = Initialize("95-vh.html");
  web_view->ResizeWithBrowserControls(gfx::Size(412, 604), 56.f, 0, true);
  web_view->GetBrowserControls().SetShownRatio(1, 1);
  UpdateAllLifecyclePhases();

  GetFrame()->View()->SetTracksRasterInvalidations(true);

  // Hide the browser controls.
  VerticalScroll(-100.f);
  web_view->ResizeWithBrowserControls(gfx::Size(412, 660), 56.f, 0, false);
  UpdateAllLifecyclePhases();

  // Ensure there is a raster invalidation of the bottom of the layer.
  const auto& raster_invalidations =
      GetRasterInvalidationTracking(*GetFrame()->View())->Invalidations();
  EXPECT_EQ(1u, raster_invalidations.size());
  EXPECT_EQ(gfx::Rect(0, 643, 412, 17), raster_invalidations[0].rect);
  EXPECT_EQ(PaintInvalidationReason::kIncremental,
            raster_invalidations[0].reason);

  GetFrame()->View()->SetTracksRasterInvalidations(false);
}

// Test that the browser controls have different shown ratios when scrolled with
// a minimum height set for only top controls.
TEST_F(BrowserControlsTest, MAYBE(ScrollWithMinHeightSetForTopControlsOnly)) {
  WebViewImpl* web_view = Initialize();
  float top_height = 56;
  float bottom_height = 50;
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      top_height, bottom_height, false);
  web_view->GetBrowserControls().SetShownRatio(1.f, 1.f);
  web_view->GetBrowserControls().SetParams(
      {top_height, 20, bottom_height, 0, false, true});
  CompositeForTest();
  // Scroll down to hide the controls.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -100));
  CompositeForTest();

  // The bottom controls should be completely hidden while the top controls are
  // at the minimum height.
  EXPECT_EQ(0.f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_GT(web_view->GetBrowserControls().TopShownRatio(), 0);
  EXPECT_EQ(20, web_view->GetBrowserControls().ContentOffset());

  // Scrolling back up should bring the browser controls shown ratios back to 1.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 100));
  CompositeForTest();
  EXPECT_EQ(1.f, web_view->GetBrowserControls().BottomShownRatio());
  EXPECT_EQ(1.f, web_view->GetBrowserControls().TopShownRatio());
  EXPECT_EQ(top_height, web_view->GetBrowserControls().ContentOffset());
}

// Test that the browser controls don't scroll off when a minimum height is set.
TEST_F(BrowserControlsTest, MAYBE(ScrollWithMinHeightSet)) {
  WebViewImpl* web_view = Initialize();
  float top_height = 56;
  float bottom_height = 50;
  web_view->ResizeWithBrowserControls(web_view->MainFrameViewWidget()->Size(),
                                      top_height, bottom_height, false);
  web_view->GetBrowserControls().SetShownRatio(1.f, 1.f);
  web_view->GetBrowserControls().SetParams(
      {top_height, 20, bottom_height, 10, false, true});
  CompositeForTest();

  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -100));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();

  // Browser controls don't scroll off completely, and stop scrolling at the min
  // height.
  EXPECT_FLOAT_EQ(20, web_view->GetBrowserControls().ContentOffset());
  EXPECT_FLOAT_EQ(10, web_view->GetBrowserControls().BottomContentOffset());

  // Ending the scroll then scrolling again shouldn't make any difference.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, -50));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollEnd));
  CompositeForTest();
  EXPECT_FLOAT_EQ(20, web_view->GetBrowserControls().ContentOffset());
  EXPECT_FLOAT_EQ(10, web_view->GetBrowserControls().BottomContentOffset());

  // Finally, scroll back up to show the controls completely.
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollBegin));
  GetWebFrameWidget()->DispatchThroughCcInputHandler(
      GenerateEvent(WebInputEvent::Type::kGestureScrollUpdate, 0, 100));
  CompositeForTest();
  EXPECT_FLOAT_EQ(top_height, web_view->GetBrowserControls().ContentOffset());
  EXPECT_FLOAT_EQ(bottom_height,
                  web_view->GetBrowserControls().BottomContentOffset());
}

#undef MAYBE

// Test that sending both an animated and non-animated browser control update
// doesn't cause the animated one to squash the non-animated.
// https://crbug.com/861618.
TEST_F(BrowserControlsSimTest, MixAnimatedAndNonAnimatedUpdateState) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
          <!DOCTYPE html>
          <meta name="viewport" content="width=device-width">
          <style>
            body {
              height: 2000px;
            }
          </style>
      )HTML");
  Compositor().BeginFrame();

  ASSERT_EQ(1.f, WebView().GetBrowserControls().TopShownRatio());

  // Kick off a non-animated clamp to hide the top controls.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kBoth,
      false /* animated */, std::nullopt);

  // Now kick off an animated one to do the same thing.
  Compositor().LayerTreeHost()->UpdateBrowserControlsState(
      cc::BrowserControlsState::kHidden, cc::BrowserControlsState::kBoth,
      true /* animated */, std::nullopt);

  // Advance time. In https://crbug.com/861618, the animation didn't realize
  // yet we're already at 0, so it would play the compositor-side up to 80ms,
  // somewhere mid-way hidden. Later on in this BeginFrame the changes from the
  // main thread are committed so the top controls shown ratio will set to 0.
  Compositor().BeginFrame(0.080);

  EXPECT_EQ(0.f, WebView().GetBrowserControls().TopShownRatio());

  // Tick the animation again. The animation should have been stopped. In
  // https://crbug.com/861618, the animation would continue to play since it
  // was kicked off after the non-animated call as far as the compositor could
  // see. This means this animation tick would set the delta to some non-0 value
  // again. This value will be committed to the main thread causing the controls
  // to show.
  Compositor().BeginFrame();

  EXPECT_EQ(0.f, WebView().GetBrowserControls().TopShownRatio());
}

// Test that requesting an animated hide on the top controls actually
// animates rather than happening instantly.
TEST_F(BrowserControlsSimTest, HideAnimated) {
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Comple
"""


```