Response:
The user wants a summary of the functionality of the provided C++ code snippet from `web_frame_test.cc`. I need to identify the key features being tested and their relationship to web technologies like JavaScript, HTML, and CSS. For tests involving logic or assumptions, I should provide example inputs and outputs. If the code hints at common user or programming errors, I need to illustrate them. Finally, I must remember that this is part 4 of a 19-part series and keep the summary concise to this section.

Here's a breakdown of the tests in this snippet:

1. **Permanent Initial Page Scale Factor:** Tests how setting an initial page scale affects the actual page scale, especially when a "quirk" is enabled.
2. **Permanent Initial Page Scale Factor Affects Layout Width:** Checks if the initial page scale correctly influences the layout width.
3. **DocumentElementClientHeightWorksWithWrapContentMode:**  Verifies that `documentElement.clientHeight` and `clientWidth` return the viewport dimensions when `ForceZeroLayoutHeight` is enabled (simulating "wrap content").
4. **SetForceZeroLayoutHeightWorksWithWrapContentMode:** Tests how `SetForceZeroLayoutHeight` interacts with resizing and ensures that layout size is correctly managed even when the height is initially zero.
5. **SetForceZeroLayoutHeight:** Confirms that `SetForceZeroLayoutHeight` prevents the frame from resizing vertically based on content.
6. **ToggleViewportMetaOnOff:** Checks if toggling the `ViewportMetaEnabled` setting correctly updates the viewport type.
7. **SetForceZeroLayoutHeightWorksWithRelayoutsWhenHeightChanged:** Addresses a scenario where setting zero height initially and then resizing might cause issues with event handling.
8. **FrameOwnerPropertiesMargin:** Verifies that margin properties set on a frame owner are correctly applied to the child frame's body element.
9. **FrameOwnerPropertiesScrolling:** Checks if the `scrollbar_mode` property on a frame owner correctly disables scrollbars in the child frame.
10. **SetForceZeroLayoutHeightWorksAcrossNavigations:** Ensures that the `ForceZeroLayoutHeight` setting persists across page navigations.
11. **SetForceZeroLayoutHeightWithWideViewportQuirk:** Tests the interaction between `ForceZeroLayoutHeight` and the wide viewport quirk.
12. **WideViewportQuirkClobbersHeight:** Checks a specific quirk where setting the wide viewport quirk can override the specified viewport height.
13. **OverflowHiddenDisablesScrolling:** Verifies that setting `overflow: hidden` on the body disables scrolling.
14. **OverflowHiddenDisablesScrollingWithSetCanHaveScrollbars:** Confirms that `overflow: hidden` still disables scrolling even if `SetCanHaveScrollbars` is called.
15. **IgnoreOverflowHiddenQuirk:** Tests the setting that allows ignoring the `overflow: hidden` style on the main frame.
16. **NonZeroValuesNoQuirk:** Examines the behavior when viewport meta tags have non-zero values and the wide viewport quirk is enabled.
17. **setPageScaleFactorDoesNotLayout:** Ensures that manually setting the page scale factor doesn't trigger a full layout.
18. **setPageScaleFactorWithOverlayScrollbarsDoesNotLayout:** Similar to the previous test but specifically for scenarios with overlay scrollbars.
19. **pageScaleFactorWrittenToHistoryItem:** Checks if the manually set page scale factor is saved in the browser's history.
20. **initialScaleWrittenToHistoryItem:** Verifies that the initial scale calculated from the viewport meta tag is stored in the history.
21. **pageScaleFactorDoesntShrinkFrameView:** Confirms that changing the page scale factor doesn't alter the frame's intrinsic size.
22. **pageScaleFactorDoesNotApplyCssTransform:** Checks that the page scale factor is not applied as a CSS transform.
23. **targetDensityDpiHigh:** Tests how the `target-densitydpi=high` viewport meta tag affects layout and page scale at different device scale factors.
24. **targetDensityDpiDevice:** Verifies the behavior of `target-densitydpi=device` with varying device scale factors.
25. **targetDensityDpiDeviceAndFixedWidth:** Checks the interaction of `target-densitydpi=device` with a fixed viewport width.
26. **NoWideViewportAndScaleLessThanOne:** Tests the scenario where the wide viewport is disabled, and the initial scale is less than 1.
27. **NoWideViewportAndScaleLessThanOneWithDeviceWidth:** Similar to the previous test but with the `width=device-width` viewport setting.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的第 4 部分，主要涵盖了以下功能测试：

**核心功能:**

* **测试页面缩放 (Page Scale Factor):**
    * **设置固定的初始页面缩放比例 (Permanent Initial Page Scale Factor):**  验证了可以强制设置一个初始的页面缩放比例，并且在启用特定 quirk 模式时，会按照 quirk 模式的逻辑来应用缩放。
    * **固定的初始页面缩放比例影响布局宽度 (Permanent Initial Page Scale Factor Affects Layout Width):**  确认了设置固定的初始页面缩放比例后，页面的布局宽度会相应地被调整。
    * **手动设置页面缩放比例不触发布局 (setPageScaleFactorDoesNotLayout, setPageScaleFactorWithOverlayScrollbarsDoesNotLayout):**  验证了通过 `SetPageScaleFactor` 方法手动设置页面缩放比例时，不会触发完整的布局过程，从而提高性能。
    * **页面缩放比例写入历史记录 (pageScaleFactorWrittenToHistoryItem):**  测试了通过 `SetPageScaleFactor` 设置的页面缩放比例会被保存到浏览历史记录中。
    * **初始缩放比例写入历史记录 (initialScaleWrittenToHistoryItem):** 验证了解析 `<meta name="viewport" content="initial-scale=...">` 后计算出的初始缩放比例会被保存到浏览历史记录中。
    * **页面缩放比例不缩小 FrameView (pageScaleFactorDoesntShrinkFrameView):**  确认了修改页面缩放比例不会影响 `FrameView` 的实际大小（逻辑像素），只会影响内容的显示比例。
    * **页面缩放比例不作为 CSS 变换应用 (pageScaleFactorDoesNotApplyCssTransform):**  验证了页面缩放不是通过 CSS 变换实现的，而是浏览器底层的缩放机制。

* **测试视口 (Viewport) 相关特性:**
    * **documentElement 的 clientHeight 在 wrap content 模式下工作正常 (DocumentElementClientHeightWorksWithWrapContentMode):** 测试了在 `SetForceZeroLayoutHeight(true)` 模式下，`document.documentElement.clientHeight` 和 `clientWidth` 能否正确返回视口的高度和宽度。
    * **SetForceZeroLayoutHeight 在 wrap content 模式下工作正常 (SetForceZeroLayoutHeightWorksWithWrapContentMode):** 验证了 `SetForceZeroLayoutHeight(true)` 可以使页面的布局高度为 0，并且后续的 resize 操作会按预期工作。
    * **SetForceZeroLayoutHeight 功能测试 (SetForceZeroLayoutHeight):**  测试了 `SetForceZeroLayoutHeight(true)` 可以强制将页面的布局高度设置为 0，并且后续的 resize 操作不会改变布局高度，直到设置为 `false`。
    * **切换 Viewport Meta 开关 (ToggleViewportMetaOnOff):** 测试了动态开启和关闭 `ViewportMetaEnabled` 设置对视口类型的影响。
    * **SetForceZeroLayoutHeight 在高度变化时触发重新布局 (SetForceZeroLayoutHeightWorksWithRelayoutsWhenHeightChanged):**  测试了在设置 `ForceZeroLayoutHeight(true)` 后，如果内容加载导致高度变化，能否正确触发重新布局，以保证 touch 事件能够正确命中元素。
    * **Frame Owner 属性 - margin (FrameOwnerPropertiesMargin):** 测试了通过 `WebFrameOwnerProperties` 设置的 `marginwidth` 和 `marginheight` 属性能够正确应用到子 frame 的 `<body>` 元素上。
    * **Frame Owner 属性 - scrolling (FrameOwnerPropertiesScrolling):** 测试了通过 `WebFrameOwnerProperties` 设置的 `scrollbar_mode` 属性能够正确控制子 frame 的滚动条显示。
    * **SetForceZeroLayoutHeight 跨导航生效 (SetForceZeroLayoutHeightWorksAcrossNavigations):** 验证了 `SetForceZeroLayoutHeight(true)` 的设置在页面导航后仍然有效。
    * **SetForceZeroLayoutHeight 与 WideViewportQuirk 的交互 (SetForceZeroLayoutHeightWithWideViewportQuirk):** 测试了 `SetForceZeroLayoutHeight` 和 `WideViewportQuirkEnabled` 同时启用时的行为。
    * **WideViewportQuirk 覆盖高度 (WideViewportQuirkClobbersHeight):**  测试了启用 `WideViewportQuirkEnabled` 在某些情况下会覆盖通过 `<meta>` 标签设置的视口高度。
    * **overflow: hidden 禁用滚动 (OverflowHiddenDisablesScrolling, OverflowHiddenDisablesScrollingWithSetCanHaveScrollbars):** 测试了 CSS 属性 `overflow: hidden` 可以禁用页面的滚动，即使调用了 `SetCanHaveScrollbars(true)`。
    * **忽略 overflow: hidden 的 quirk (IgnoreOverflowHiddenQuirk):** 测试了设置 `IgnoreMainFrameOverflowHiddenQuirk(true)` 可以忽略主 frame 上 `overflow: hidden` 的效果。
    * **非零值不启用 quirk (NonZeroValuesNoQuirk):** 测试了当 viewport meta 标签包含非零值时，在启用 `ViewportMetaZeroValuesQuirk` 和 `WideViewportQuirkEnabled` 的情况下页面的行为。

* **测试 target-densitydpi (已废弃) (targetDensityDpiHigh, targetDensityDpiDevice, targetDensityDpiDeviceAndFixedWidth):**
    * 验证了已废弃的 `target-densitydpi` viewport meta 标签在不同设备像素比下的行为，包括 `high` 和 `device` 值的处理，以及与固定宽度视口的交互。

* **测试禁用 WideViewport 时的缩放行为 (NoWideViewportAndScaleLessThanOne, NoWideViewportAndScaleLessThanOneWithDeviceWidth):**
    * 测试了当禁用 WideViewport 且设置了小于 1 的 `initial-scale` 时，页面的布局和缩放行为，包括与 `width=device-width` 的结合使用。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:**
    * `Document* document = frame->GetDocument(); EXPECT_EQ(viewport_height, document->documentElement()->clientHeight());` 这段代码测试了通过 JavaScript DOM API 获取的 `documentElement.clientHeight` 属性值是否符合预期。
    * `Element* element = document->getElementById(AtomicString("tap_button"));`  在 `SetForceZeroLayoutHeightWorksWithRelayoutsWhenHeightChanged` 测试中，通过 JavaScript 获取 DOM 元素，并断言其 `innerText` 属性在模拟 touch 事件后发生了改变。
* **HTML:**
    * 很多测试都涉及到加载不同的 HTML 文件，例如 `0-by-0.html`, `200-by-300.html`, `viewport-device-width.html` 等，这些 HTML 文件中可能包含不同的 `<meta>` 标签来控制视口和缩放。例如：`RegisterMockedHttpURLLoad("viewport-initial-scale-less-than-1.html");`  这个测试加载的 HTML 文件可能包含 `<meta name="viewport" content="initial-scale=0.5">` 这样的标签。
    * `EXPECT_EQ(11, child_document->FirstBodyElement()->GetIntegralAttribute(html_names::kMarginwidthAttr));` 这个测试检查了 HTML 元素的属性值，例如 `<body>` 标签的 `marginwidth` 属性。
* **CSS:**
    * `RegisterMockedHttpURLLoad("body-overflow-hidden.html");` 这个测试加载的 HTML 文件可能包含 `<style>body { overflow: hidden; }</style>` 这样的 CSS 代码，用于测试 `overflow: hidden` 属性的效果。

**逻辑推理的假设输入与输出举例:**

* **测试: Permanent Initial Page Scale Factor**
    * **假设输入:**  `enforced_page_scale_factor = 0.5`,  `page_scale_factors = {1.0f, 2.0f}`，启用 quirk 模式。
    * **预期输出:**  在 quirk 模式下，前两次迭代的 `web_view_helper.GetWebView()->PageScaleFactor()` 应该分别为 1.0f 和 2.0f，之后为 0.5f。
* **测试: Permanent Initial Page Scale Factor Affects Layout Width**
    * **假设输入:** `viewport_width = 640`, `enforced_page_scale_factor = 0.5`
    * **预期输出:** `web_view_helper.GetWebView()->MainFrameImpl()->GetFrameView()->Size().width()` 应该等于 1280。

**涉及用户或者编程常见的使用错误举例:**

* **设置了 `SetForceZeroLayoutHeight(true)` 后，没有预期到页面高度会一直是 0，导致后续依赖页面高度的操作出现问题。** 例如，在 `SetForceZeroLayoutHeightWorksWithRelayoutsWhenHeightChanged` 测试中，如果先设置了零高度，然后加载内容，开发者可能会误以为页面会自动根据内容调整高度，从而导致 touch 事件无法正确命中内容。
* **错误地认为手动设置 `SetPageScaleFactor` 会触发页面的重新布局。**  这些测试明确指出 `SetPageScaleFactor` 是一个轻量级的操作，不会触发完整的布局，如果开发者依赖布局来更新某些 UI 或逻辑，可能会导致不一致的状态。
* **不理解 `WideViewportQuirk` 的行为，导致在某些特定网站上视口表现异常。** 例如，`WideViewportQuirkClobbersHeight` 测试就揭示了一个 quirk，可能会覆盖开发者通过 `<meta>` 标签设置的视口高度，这可能会让开发者感到困惑。

**归纳一下它的功能 (第 4 部分):**

这部分代码主要集中在测试 Blink 引擎中关于 **页面缩放 (Page Scale Factor)** 和 **视口 (Viewport)** 相关的核心功能。 它涵盖了初始页面缩放的设置、手动调整页面缩放、`ForceZeroLayoutHeight` 的各种使用场景、`ViewportMetaEnabled` 的动态切换、Frame Owner 属性的设置，以及一些历史遗留的、已废弃的 `target-densitydpi` 特性的测试。 此外，还涉及到了 `overflow: hidden` 对滚动条的影响以及相关的 quirk 模式。 这些测试共同确保了 Blink 引擎在处理不同视口配置和缩放场景下的行为符合预期，并且与 HTML、CSS 和 JavaScript 能够正确交互。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共19部分，请归纳一下它的功能

"""
iew()->SetInitialPageScaleOverride(
          enforced_page_scale_factor);
      web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

      float expected_page_scale_factor =
          quirk_enabled && i < std::size(page_scale_factors)
              ? page_scale_factors[i]
              : enforced_page_scale_factor;
      EXPECT_EQ(expected_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
    }
  }
}

TEST_F(WebFrameTest, PermanentInitialPageScaleFactorAffectsLayoutWidth) {
  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 0.5;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", nullptr, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.GetWebView()->GetSettings()->SetLoadWithOverviewMode(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width / enforced_page_scale_factor,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->Size()
                .width());
  EXPECT_EQ(enforced_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, DocumentElementClientHeightWorksWithWrapContentMode) {
  RegisterMockedHttpURLLoad("0-by-0.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "0-by-0.html", nullptr, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  LocalFrame* frame = web_view_helper.LocalMainFrame()->GetFrame();
  Document* document = frame->GetDocument();
  EXPECT_EQ(viewport_height, document->documentElement()->clientHeight());
  EXPECT_EQ(viewport_width, document->documentElement()->clientWidth());
}

TEST_F(WebFrameTest, SetForceZeroLayoutHeightWorksWithWrapContentMode) {
  RegisterMockedHttpURLLoad("0-by-0.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "0-by-0.html", nullptr, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  LocalFrameView* frame_view =
      web_view_helper.GetWebView()->MainFrameImpl()->GetFrameView();

  EXPECT_EQ(gfx::Size(), frame_view->GetLayoutSize());
  web_view_helper.Resize(gfx::Size(viewport_width, 0));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(gfx::Size(viewport_width, 0), frame_view->GetLayoutSize());

  // The flag ForceZeroLayoutHeight will cause the following resize of viewport
  // height to be ignored by the outer viewport (the container layer of
  // LayerCompositor). The height of the visualViewport, however, is not
  // affected.
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  EXPECT_FALSE(frame_view->NeedsLayout());
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(gfx::Size(viewport_width, 0), frame_view->GetLayoutSize());

  LocalFrame* frame = web_view_helper.LocalMainFrame()->GetFrame();
  VisualViewport& visual_viewport = frame->GetPage()->GetVisualViewport();
  auto* scroll_node = visual_viewport.GetScrollTranslationNode()->ScrollNode();
  EXPECT_EQ(gfx::Rect(viewport_width, viewport_height),
            scroll_node->ContainerRect());
  EXPECT_EQ(gfx::Rect(viewport_width, viewport_height),
            scroll_node->ContentsRect());
}

TEST_F(WebFrameTest, SetForceZeroLayoutHeight) {
  RegisterMockedHttpURLLoad("200-by-300.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "200-by-300.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_LE(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->GetLayoutSize()
                                 .height());
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  EXPECT_TRUE(web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->NeedsLayout());

  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .height());

  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height * 2));
  EXPECT_FALSE(web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->NeedsLayout());
  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .height());

  web_view_helper.Resize(gfx::Size(viewport_width * 2, viewport_height));
  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .height());

  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(false);
  EXPECT_LE(viewport_height, web_view_helper.GetWebView()
                                 ->MainFrameImpl()
                                 ->GetFrameView()
                                 ->GetLayoutSize()
                                 .height());
}

TEST_F(WebFrameTest, ToggleViewportMetaOnOff) {
  RegisterMockedHttpURLLoad("viewport-device-width.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport-device-width.html",
                                    nullptr, nullptr);
  WebSettings* settings = web_view_helper.GetWebView()->GetSettings();
  settings->SetViewportMetaEnabled(false);
  settings->SetViewportEnabled(true);
  settings->SetMainFrameResizesAreOrientationChanges(true);
  settings->SetShrinksViewportContentToFit(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  ViewportData& viewport =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame())
          ->GetDocument()
          ->GetViewportData();
  EXPECT_FALSE(viewport.GetViewportDescription().IsLegacyViewportType());

  settings->SetViewportMetaEnabled(true);
  EXPECT_TRUE(viewport.GetViewportDescription().IsLegacyViewportType());

  settings->SetViewportMetaEnabled(false);
  EXPECT_FALSE(viewport.GetViewportDescription().IsLegacyViewportType());
}

TEST_F(WebFrameTest,
       SetForceZeroLayoutHeightWorksWithRelayoutsWhenHeightChanged) {
  // this unit test is an attempt to target a real world case where an app could
  // 1. call resize(width, 0) and setForceZeroLayoutHeight(true)
  // 2. load content (hoping that the viewport height would increase
  // as more content is added)
  // 3. fail to register touch events aimed at the loaded content
  // because the layout is only updated if either width or height is changed
  RegisterMockedHttpURLLoad("button.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "button.html", nullptr, nullptr,
                                    ConfigureAndroid);
  // set view height to zero so that if the height of the view is not
  // successfully updated during later resizes touch events will fail
  // (as in not hit content included in the view)
  web_view_helper.Resize(gfx::Size(viewport_width, 0));

  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  gfx::PointF hit_point = gfx::PointF(30, 30);  // button size is 100x100

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  Document* document = frame->GetFrame()->GetDocument();
  Element* element = document->getElementById(AtomicString("tap_button"));

  ASSERT_NE(nullptr, element);
  EXPECT_EQ(String("oldValue"), element->innerText());

  WebGestureEvent gesture_event(WebInputEvent::Type::kGestureTap,
                                WebInputEvent::kNoModifiers,
                                WebInputEvent::GetStaticTimeStampForTests(),
                                WebGestureDevice::kTouchscreen);
  gesture_event.SetFrameScale(1);
  gesture_event.SetPositionInWidget(hit_point);
  gesture_event.SetPositionInScreen(hit_point);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->GetFrame()
      ->GetEventHandler()
      .HandleGestureEvent(gesture_event);
  // when pressed, the button changes its own text to "updatedValue"
  EXPECT_EQ(String("updatedValue"), element->innerText());
}

TEST_F(WebFrameTest, FrameOwnerPropertiesMargin) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebFrameOwnerProperties properties;
  properties.margin_width = 11;
  properties.margin_height = 22;
  WebLocalFrameImpl* local_frame = helper.CreateLocalChild(
      *helper.RemoteMainFrame(), "frameName", properties);

  RegisterMockedHttpURLLoad("frame_owner_properties.html");
  frame_test_helpers::LoadFrame(local_frame,
                                base_url_ + "frame_owner_properties.html");

  // Check if the LocalFrame has seen the marginwidth and marginheight
  // properties.
  Document* child_document = local_frame->GetFrame()->GetDocument();
  EXPECT_EQ(11, child_document->FirstBodyElement()->GetIntegralAttribute(
                    html_names::kMarginwidthAttr));
  EXPECT_EQ(22, child_document->FirstBodyElement()->GetIntegralAttribute(
                    html_names::kMarginheightAttr));

  LocalFrameView* frame_view = local_frame->GetFrameView();
  frame_view->Resize(800, 600);
  frame_view->SetNeedsLayout();
  frame_view->UpdateAllLifecyclePhasesForTest();
  // Expect scrollbars to be enabled by default.
  EXPECT_NE(nullptr, frame_view->LayoutViewport()->HorizontalScrollbar());
  EXPECT_NE(nullptr, frame_view->LayoutViewport()->VerticalScrollbar());
}

TEST_F(WebFrameTest, FrameOwnerPropertiesScrolling) {
  frame_test_helpers::WebViewHelper helper;
  helper.InitializeRemote();

  WebFrameOwnerProperties properties;
  // Turn off scrolling in the subframe.
  properties.scrollbar_mode = mojom::blink::ScrollbarMode::kAlwaysOff;
  WebLocalFrameImpl* local_frame = helper.CreateLocalChild(
      *helper.RemoteMainFrame(), "frameName", properties);

  RegisterMockedHttpURLLoad("frame_owner_properties.html");
  frame_test_helpers::LoadFrame(local_frame,
                                base_url_ + "frame_owner_properties.html");

  Document* child_document = local_frame->GetFrame()->GetDocument();
  EXPECT_EQ(0, child_document->FirstBodyElement()->GetIntegralAttribute(
                   html_names::kMarginwidthAttr));
  EXPECT_EQ(0, child_document->FirstBodyElement()->GetIntegralAttribute(
                   html_names::kMarginheightAttr));

  LocalFrameView* frame_view = local_frame->GetFrameView();
  EXPECT_EQ(nullptr, frame_view->LayoutViewport()->HorizontalScrollbar());
  EXPECT_EQ(nullptr, frame_view->LayoutViewport()->VerticalScrollbar());
}

TEST_F(WebFrameTest, SetForceZeroLayoutHeightWorksAcrossNavigations) {
  RegisterMockedHttpURLLoad("200-by-300.html");
  RegisterMockedHttpURLLoad("large-div.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "200-by-300.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "large-div.html");
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .height());
}

TEST_F(WebFrameTest, SetForceZeroLayoutHeightWithWideViewportQuirk) {
  RegisterMockedHttpURLLoad("200-by-300.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "200-by-300.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  web_view_helper.GetWebView()->GetSettings()->SetForceZeroLayoutHeight(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(0, web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->GetLayoutSize()
                   .height());
}

TEST_F(WebFrameTest, WideViewportQuirkClobbersHeight) {
  RegisterMockedHttpURLLoad("viewport-height-1000.html");

  int viewport_width = 600;
  int viewport_height = 800;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank", nullptr, nullptr,
                                    ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "viewport-height-1000.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(800, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->GetLayoutSize()
                     .height());
  EXPECT_EQ(1, web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, OverflowHiddenDisablesScrolling) {
  RegisterMockedHttpURLLoad("body-overflow-hidden.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "body-overflow-hidden.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_FALSE(view->LayoutViewport()->UserInputScrollable(kVerticalScrollbar));
  EXPECT_FALSE(
      view->LayoutViewport()->UserInputScrollable(kHorizontalScrollbar));
}

TEST_F(WebFrameTest, OverflowHiddenDisablesScrollingWithSetCanHaveScrollbars) {
  RegisterMockedHttpURLLoad("body-overflow-hidden-short.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "body-overflow-hidden-short.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_FALSE(view->LayoutViewport()->UserInputScrollable(kVerticalScrollbar));
  EXPECT_FALSE(
      view->LayoutViewport()->UserInputScrollable(kHorizontalScrollbar));

  web_view_helper.LocalMainFrame()->GetFrameView()->SetCanHaveScrollbars(true);
  EXPECT_FALSE(view->LayoutViewport()->UserInputScrollable(kVerticalScrollbar));
  EXPECT_FALSE(
      view->LayoutViewport()->UserInputScrollable(kHorizontalScrollbar));
}

TEST_F(WebFrameTest, IgnoreOverflowHiddenQuirk) {
  RegisterMockedHttpURLLoad("body-overflow-hidden.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetIgnoreMainFrameOverflowHiddenQuirk(true);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "body-overflow-hidden.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  EXPECT_TRUE(view->LayoutViewport()->UserInputScrollable(kVerticalScrollbar));
}

TEST_F(WebFrameTest, NonZeroValuesNoQuirk) {
  RegisterMockedHttpURLLoad("viewport-nonzero-values.html");

  int viewport_width = 640;
  int viewport_height = 480;
  float expected_page_scale_factor = 0.5f;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->GetSettings()->SetViewportMetaZeroValuesQuirk(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "viewport-nonzero-values.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(viewport_width / expected_page_scale_factor,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->GetLayoutSize()
                .width());
  EXPECT_EQ(expected_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());

  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(viewport_width / expected_page_scale_factor,
            web_view_helper.GetWebView()
                ->MainFrameImpl()
                ->GetFrameView()
                ->GetLayoutSize()
                .width());
  EXPECT_EQ(expected_page_scale_factor,
            web_view_helper.GetWebView()->PageScaleFactor());
}

TEST_F(WebFrameTest, setPageScaleFactorDoesNotLayout) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  // Small viewport to ensure there are always scrollbars.
  int viewport_width = 64;
  int viewport_height = 48;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  unsigned prev_layout_count =
      web_view_helper.LocalMainFrame()->GetFrameView()->LayoutCountForTesting();
  web_view_helper.GetWebView()->SetPageScaleFactor(3);
  EXPECT_FALSE(web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->NeedsLayout());
  EXPECT_EQ(prev_layout_count, web_view_helper.GetWebView()
                                   ->MainFrameImpl()
                                   ->GetFrameView()
                                   ->LayoutCountForTesting());
}

TEST_F(WebFrameTest, setPageScaleFactorWithOverlayScrollbarsDoesNotLayout) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  unsigned prev_layout_count =
      web_view_helper.LocalMainFrame()->GetFrameView()->LayoutCountForTesting();
  web_view_helper.GetWebView()->SetPageScaleFactor(30);
  EXPECT_FALSE(web_view_helper.GetWebView()
                   ->MainFrameImpl()
                   ->GetFrameView()
                   ->NeedsLayout());
  EXPECT_EQ(prev_layout_count, web_view_helper.GetWebView()
                                   ->MainFrameImpl()
                                   ->GetFrameView()
                                   ->LayoutCountForTesting());
}

TEST_F(WebFrameTest, pageScaleFactorWrittenToHistoryItem) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  web_view_helper.GetWebView()->SetPageScaleFactor(3);
  EXPECT_EQ(3,
            To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame())
                ->Loader()
                .GetDocumentLoader()
                ->GetHistoryItem()
                ->GetViewState()
                ->page_scale_factor_);
}

TEST_F(WebFrameTest, initialScaleWrittenToHistoryItem) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "fixed_layout.html");
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  int default_fixed_layout_width = 980;
  float minimum_page_scale_factor =
      viewport_width / (float)default_fixed_layout_width;
  EXPECT_EQ(minimum_page_scale_factor,
            To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame())
                ->Loader()
                .GetDocumentLoader()
                ->GetHistoryItem()
                ->GetViewState()
                ->page_scale_factor_);
}

TEST_F(WebFrameTest, pageScaleFactorDoesntShrinkFrameView) {
  RegisterMockedHttpURLLoad("large-div.html");

  // Small viewport to ensure there are always scrollbars.
  int viewport_width = 64;
  int viewport_height = 48;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "large-div.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  int viewport_width_minus_scrollbar = viewport_width;
  int viewport_height_minus_scrollbar = viewport_height;

  if (view->LayoutViewport()->VerticalScrollbar() &&
      !view->LayoutViewport()->VerticalScrollbar()->IsOverlayScrollbar())
    viewport_width_minus_scrollbar -= 15;

  if (view->LayoutViewport()->HorizontalScrollbar() &&
      !view->LayoutViewport()->HorizontalScrollbar()->IsOverlayScrollbar())
    viewport_height_minus_scrollbar -= 15;

  web_view_helper.GetWebView()->SetPageScaleFactor(2);

  gfx::Size unscaled_size = view->Size();
  EXPECT_EQ(viewport_width, unscaled_size.width());
  EXPECT_EQ(viewport_height, unscaled_size.height());

  gfx::Size unscaled_size_minus_scrollbar = view->Size();
  EXPECT_EQ(viewport_width_minus_scrollbar,
            unscaled_size_minus_scrollbar.width());
  EXPECT_EQ(viewport_height_minus_scrollbar,
            unscaled_size_minus_scrollbar.height());

  gfx::Size frame_view_size = view->Size();
  EXPECT_EQ(viewport_width_minus_scrollbar, frame_view_size.width());
  EXPECT_EQ(viewport_height_minus_scrollbar, frame_view_size.height());
}

TEST_F(WebFrameTest, pageScaleFactorDoesNotApplyCssTransform) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  web_view_helper.GetWebView()->SetPageScaleFactor(2);

  EXPECT_EQ(980,
            To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame())
                ->ContentLayoutObject()
                ->DocumentRect()
                .Width());
  EXPECT_EQ(980, web_view_helper.GetWebView()
                     ->MainFrameImpl()
                     ->GetFrameView()
                     ->LayoutViewport()
                     ->ContentsSize()
                     .width());
}

TEST_F(WebFrameTest, targetDensityDpiHigh) {
  RegisterMockedHttpURLLoad("viewport-target-densitydpi-high.html");

  // high-dpi = 240
  float target_dpi = 240.0f;
  std::array<float, 3> device_scale_factors = {1.0f, 4.0f / 3.0f, 2.0f};
  int viewport_width = 640;
  int viewport_height = 480;

  for (size_t i = 0; i < std::size(device_scale_factors); ++i) {
    float device_scale_factor = device_scale_factors[i];
    float device_dpi = device_scale_factor * 160.0f;

    frame_test_helpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(
        base_url_ + "viewport-target-densitydpi-high.html", nullptr, nullptr,
        ConfigureAndroid);
    web_view_helper.GetWebView()
        ->MainFrameWidget()
        ->SetDeviceScaleFactorForTesting(device_scale_factor);
    web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
        true);
    web_view_helper.GetWebView()
        ->GetSettings()
        ->SetSupportDeprecatedTargetDensityDPI(true);
    web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

    // We need to account for the fact that logical pixels are unconditionally
    // multiplied by deviceScaleFactor to produce physical pixels.
    float density_dpi_scale_ratio =
        device_scale_factor * target_dpi / device_dpi;
    EXPECT_NEAR(viewport_width * density_dpi_scale_ratio,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .width(),
                1.0f);
    EXPECT_NEAR(viewport_height * density_dpi_scale_ratio,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .height(),
                1.0f);
    EXPECT_NEAR(1.0f / density_dpi_scale_ratio,
                web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  }
}

TEST_F(WebFrameTest, targetDensityDpiDevice) {
  RegisterMockedHttpURLLoad("viewport-target-densitydpi-device.html");

  std::array<float, 3> device_scale_factors = {1.0f, 4.0f / 3.0f, 2.0f};

  int viewport_width = 640;
  int viewport_height = 480;

  for (size_t i = 0; i < std::size(device_scale_factors); ++i) {
    frame_test_helpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(
        base_url_ + "viewport-target-densitydpi-device.html", nullptr, nullptr,
        ConfigureAndroid);
    web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
    web_view_helper.GetWebView()
        ->MainFrameWidget()
        ->SetDeviceScaleFactorForTesting(device_scale_factors[i]);
    web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
        true);
    web_view_helper.GetWebView()
        ->GetSettings()
        ->SetSupportDeprecatedTargetDensityDPI(true);

    EXPECT_NEAR(viewport_width * device_scale_factors[i],
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .width(),
                1.0f);
    EXPECT_NEAR(viewport_height * device_scale_factors[i],
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .height(),
                1.0f);
    EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
    auto* frame =
        To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
    DCHECK(frame);
    EXPECT_EQ(device_scale_factors[i], frame->DevicePixelRatio());
  }
}

TEST_F(WebFrameTest, targetDensityDpiDeviceAndFixedWidth) {
  RegisterMockedHttpURLLoad(
      "viewport-target-densitydpi-device-and-fixed-width.html");

  std::array<float, 3> device_scale_factors = {1.0f, 4.0f / 3.0f, 2.0f};

  int viewport_width = 640;
  int viewport_height = 480;

  for (size_t i = 0; i < std::size(device_scale_factors); ++i) {
    frame_test_helpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(
        base_url_ + "viewport-target-densitydpi-device-and-fixed-width.html",
        nullptr, nullptr, ConfigureAndroid);
    web_view_helper.GetWebView()
        ->MainFrameWidget()
        ->SetDeviceScaleFactorForTesting(device_scale_factors[i]);
    web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
        true);
    web_view_helper.GetWebView()
        ->GetSettings()
        ->SetSupportDeprecatedTargetDensityDPI(true);
    web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(true);
    web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

    EXPECT_NEAR(viewport_width,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .width(),
                1.0f);
    EXPECT_NEAR(viewport_height,
                web_view_helper.GetWebView()
                    ->MainFrameImpl()
                    ->GetFrameView()
                    ->GetLayoutSize()
                    .height(),
                1.0f);
    EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  }
}

TEST_F(WebFrameTest, NoWideViewportAndScaleLessThanOne) {
  RegisterMockedHttpURLLoad("viewport-initial-scale-less-than-1.html");

  float device_scale_factor = 1.33f;
  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-less-than-1.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->SetDeviceScaleFactorForTesting(device_scale_factor);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetSupportDeprecatedTargetDensityDPI(true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);

  EXPECT_NEAR(viewport_width * device_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .width(),
              1.0f);
  EXPECT_NEAR(viewport_height * device_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .height(),
              1.0f);

  EXPECT_NEAR(0.25f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  DCHECK(frame);
  EXPECT_EQ(device_scale_factor, frame->DevicePixelRatio());
}

TEST_F(WebFrameTest, NoWideViewportAndScaleLessThanOneWithDeviceWidth) {
  RegisterMockedHttpURLLoad(
      "viewport-initial-scale-less-than-1-device-width.html");

  float device_scale_factor = 1.33f;
  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-less-than-1-device-width.html",
      nullptr, nullptr, ConfigureAndroid);
  web_view_helpe
"""


```