Response:
The user wants a summary of the functionalities present in the provided C++ code snippet from `web_frame_test.cc`. I need to identify the core purpose of each test case and highlight its relation to web technologies like JavaScript, HTML, and CSS. For tests involving logical deductions, I'll create hypothetical inputs and outputs. I should also point out any common user or programming errors that these tests might be preventing. Since this is part 5 of 19, the summary should focus on the functionalities covered in this specific section.

**Plan:**

1. **Iterate through each `TEST_F` function:**  Each `TEST_F` represents a distinct test case.
2. **Identify the tested functionality:** Analyze the actions performed within each test.
3. **Relate to web technologies:** Determine if the test involves concepts like viewport, scaling, or layout, which are directly related to HTML, CSS, and how JavaScript can manipulate these aspects.
4. **Logical deductions (if any):** For tests involving calculations or comparisons, create a simple input scenario and predict the expected output based on the code.
5. **User/programming errors:** Consider what mistakes developers might make that these tests are designed to catch. This often relates to misunderstanding how viewport settings or scaling factors interact.
6. **Synthesize a concise summary:** Combine the identified functionalities into a paragraph that encapsulates the purpose of this code section.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的一部分，主要功能是**测试 `WebFrame` 类在处理页面缩放、视口（viewport）以及相关的各种设置和用户交互时的行为是否符合预期**。

具体来说，这部分代码主要关注以下几个方面，并提供了相应的测试用例：

**1. 视口元标签 (Viewport Meta Tag) 和页面缩放 (Page Scale Factor) 的交互：**

*   **功能：** 测试当没有设置 `wide viewport` 并且没有通过 `initial-scale` 或其他方式覆盖初始页面缩放时，页面如何基于视口大小和设备像素比进行布局和缩放。
*   **JavaScript/HTML/CSS 关系：**  这直接关系到 HTML 中的 `<meta name="viewport">` 标签，以及 CSS 如何根据视口大小进行渲染。JavaScript 可以通过 `window.innerWidth`, `window.innerHeight`, `window.devicePixelRatio` 等属性获取相关信息，并可能通过编程方式调整缩放。
*   **假设输入与输出：**
    *   **假设输入：**  一个没有明确设置 `initial-scale` 的 HTML 页面，视口宽度为 640，高度为 480，设备像素比为 2.0。
    *   **预期输出：**  `LayoutSize` 的宽度应接近 `640 * 2.0 / 0.25 = 5120`，高度应接近 `480 * 2.0 / 0.25 = 3840`，页面缩放因子应接近 `0.25`，`DevicePixelRatio` 应为 `2.0`。
*   **用户/编程常见的使用错误：**  开发者可能错误地认为在没有 `initial-scale` 的情况下，页面会以 1.0 的缩放因子显示，而忽略了设备像素比的影响。

**2. 覆盖初始页面缩放 (Initial Page Scale Override)：**

*   **功能：** 测试当显式设置了初始页面缩放覆盖值时，页面如何进行布局和缩放，即使没有设置 `wide viewport`。
*   **JavaScript/HTML/CSS 关系：**  这与通过 API 或特定设置强制覆盖页面初始缩放有关，可能会影响 HTML 页面最初的渲染状态和 CSS 的计算方式。
*   **假设输入与输出：**
    *   **假设输入：** 一个简单的 HTML 页面，视口宽度为 640，高度为 480，强制初始页面缩放因子为 5.0。
    *   **预期输出：** `LayoutSize` 的宽度应接近 `640 / 5.0 = 128`，高度应接近 `480 / 5.0 = 96`，页面缩放因子应接近 `5.0`。
*   **用户/编程常见的使用错误：**  开发者可能错误地认为只有通过 `<meta>` 标签才能控制初始缩放，而忽略了 API 覆盖的可能性。

**3. `user-scalable=no` Quirk 的影响：**

*   **功能：** 测试在启用 `ViewportMetaNonUserScalableQuirk` 时，`user-scalable=no` 是否会忽略视口设置中的缩放值。分别测试了有无 `wide viewport` 的情况。
*   **JavaScript/HTML/CSS 关系：**  这直接关系到 HTML 视口元标签中的 `user-scalable` 属性。CSS 的媒体查询可能会受到缩放因子的影响。
*   **假设输入与输出：**
    *   **假设输入：**  一个包含 `<meta name="viewport" content="initial-scale=2.0, user-scalable=no">` 的 HTML 页面，视口宽度为 640，高度为 480。
    *   **预期输出：** 在启用 `ViewportMetaNonUserScalableQuirk` 的情况下，即使设置了 `initial-scale=2.0`，`LayoutSize` 的宽度和高度都应接近视口尺寸（640 和 480），页面缩放因子应接近 1.0。
*   **用户/编程常见的使用错误：** 开发者可能不理解 `ViewportMetaNonUserScalableQuirk` 的作用，或者误以为设置了 `user-scalable=no` 就完全阻止了缩放，而忽略了某些 Quirks 可能会修改其行为。

**4. 禁用 `wide viewport` 对桌面页面的影响：**

*   **功能：** 测试当禁用 `wide viewport` 时，即使是桌面页面（没有视口标签），仍然可以进行放大。
*   **JavaScript/HTML/CSS 关系：** 这影响了浏览器如何处理没有明确视口设置的页面，以及用户是否可以通过手势或操作进行缩放。
*   **假设输入与输出：**
    *   **假设输入：**  一个没有视口元标签的 HTML 页面，视口宽度为 640，高度为 480，设置了最小和最大页面缩放限制。
    *   **预期输出：**  页面缩放因子应为 1.0，最小缩放因子为 0.25，最大缩放因子为 5.0。
*   **用户/编程常见的使用错误：** 开发者可能认为没有视口标签的页面就不能被缩放，或者不理解 `wide viewport` 设置对这类页面的影响。

**5. 调整窗口大小 (Resize) 对滚动和缩放的影响 (通过 `WebFrameResizeTest` 类进行测试)：**

*   **功能：**  测试在调整浏览器窗口大小时，页面的滚动位置和缩放因子如何变化。涵盖了设置了 `width=device-width`、`minimum-scale`、固定宽度以及固定布局的页面。
*   **JavaScript/HTML/CSS 关系：**  这与响应式设计密切相关，涉及到 CSS 媒体查询、`width=device-width` 的特殊含义，以及 JavaScript 如何处理窗口大小变化。
*   **假设输入与输出：**  （以 `ResizeYieldsCorrectScrollAndScaleForWidthEqualsDeviceWidth` 为例）
    *   **假设输入：**  一个设置了 `width=device-width` 的 HTML 页面，初始页面缩放因子为 1，初始滚动偏移为 (0, 50)，初始视口大小为 120x160。然后将视口大小调整为 160x120。
    *   **预期输出：**  页面缩放因子应保持不变（接近 1），滚动偏移应重置为 (0, 0)。
*   **用户/编程常见的使用错误：**  开发者可能错误地认为调整窗口大小会简单地按比例缩放页面，而忽略了 `width=device-width` 等设置的影响。

**6. 页面缩放因子更新滚动条 (Scrollbars)：**

*   **功能：** 测试当通过 `SetPageScaleFactor` 修改页面缩放因子时，滚动条的大小是否会相应更新。
*   **JavaScript/HTML/CSS 关系：**  滚动条是浏览器渲染的一部分，其大小取决于页面的实际内容大小和当前的缩放级别。
*   **假设输入与输出：**
    *   **假设输入：**  一个固定布局的 HTML 页面，初始视口大小为 640x480，然后设置页面缩放因子为 10。
    *   **预期输出：**  滚动条的大小会根据新的缩放因子进行调整。

**7. 覆盖缩放限制 (Scale Limits)：**

*   **功能：** 测试是否可以通过 `SetIgnoreViewportTagScaleLimits` 忽略 HTML 视口标签中设置的缩放限制。
*   **JavaScript/HTML/CSS 关系：**  这涉及到如何通过 API 或设置来覆盖 HTML 中 `<meta>` 标签定义的行为。
*   **假设输入与输出：**
    *   **假设输入：** 一个设置了 `minimum-scale=2.0, maximum-scale=2.0` 的 HTML 页面，初始设置的默认缩放限制为 0.25 和 5。
    *   **预期输出：** 初始状态下，最小和最大缩放因子为 2.0。调用 `SetIgnoreViewportTagScaleLimits(true)` 后，最小和最大缩放因子变为 1.0 和 5.0。再次调用 `SetIgnoreViewportTagScaleLimits(false)` 后，恢复为 2.0。
*   **用户/编程常见的使用错误：**  开发者可能不清楚浏览器对视口标签的缩放限制的处理顺序，或者不知道可以通过 API 来覆盖这些限制。

**归纳一下这部分的功能：**

这部分 `web_frame_test.cc` 代码主要集中于测试 `WebFrame` 类在处理**页面缩放和视口配置**相关的各种场景。它验证了浏览器引擎在解析和应用视口元标签、设备像素比、初始缩放因子以及用户缩放行为时的逻辑是否正确。这些测试覆盖了不同类型的网页配置，包括有无视口标签、是否允许用户缩放、是否启用 `wide viewport` 等，并验证了在调整窗口大小时页面缩放和滚动行为的正确性。 这些测试对于确保 Chromium 浏览器正确渲染和缩放网页至关重要，尤其是在不同的设备和屏幕尺寸下。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
r.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->SetDeviceScaleFactorForTesting(device_scale_factor);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetSupportDeprecatedTargetDensityDPI(true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);

  // We use 4.0f in EXPECT_NEAR to account for a rounding error.
  const float kPageZoom = 0.25f;
  EXPECT_NEAR(viewport_width * device_scale_factor / kPageZoom,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .width(),
              4.0f);
  EXPECT_NEAR(viewport_height * device_scale_factor / kPageZoom,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .height(),
              4.0f);

  EXPECT_NEAR(kPageZoom, web_view_helper.GetWebView()->PageScaleFactor(),
              0.01f);
  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  DCHECK(frame);
  EXPECT_EQ(device_scale_factor, frame->DevicePixelRatio());
}

TEST_F(WebFrameTest, NoWideViewportAndNoViewportWithInitialPageScaleOverride) {
  RegisterMockedHttpURLLoad("large-div.html");

  int viewport_width = 640;
  int viewport_height = 480;
  float enforced_page_scale_factor = 5.0f;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "large-div.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.GetWebView()->SetInitialPageScaleOverride(
      enforced_page_scale_factor);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_NEAR(viewport_width / enforced_page_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .width(),
              1.0f);
  EXPECT_NEAR(viewport_height / enforced_page_scale_factor,
              web_view_helper.GetWebView()
                  ->MainFrameImpl()
                  ->GetFrameView()
                  ->GetLayoutSize()
                  .height(),
              1.0f);
  EXPECT_NEAR(enforced_page_scale_factor,
              web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
}

TEST_F(WebFrameTest, NoUserScalableQuirkIgnoresViewportScale) {
  RegisterMockedHttpURLLoad("viewport-initial-scale-and-user-scalable-no.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-and-user-scalable-no.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetViewportMetaNonUserScalableQuirk(true);
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

TEST_F(WebFrameTest,
       NoUserScalableQuirkIgnoresViewportScaleForNonWideViewport) {
  RegisterMockedHttpURLLoad("viewport-initial-scale-and-user-scalable-no.html");

  float device_scale_factor = 1.33f;
  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-initial-scale-and-user-scalable-no.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->SetDeviceScaleFactorForTesting(device_scale_factor);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetSupportDeprecatedTargetDensityDPI(true);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetViewportMetaNonUserScalableQuirk(true);
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

  EXPECT_NEAR(2.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  auto* frame =
      To<LocalFrame>(web_view_helper.GetWebView()->GetPage()->MainFrame());
  DCHECK(frame);
  EXPECT_EQ(device_scale_factor, frame->DevicePixelRatio());
}

TEST_F(WebFrameTest, NoUserScalableQuirkIgnoresViewportScaleForWideViewport) {
  RegisterMockedHttpURLLoad("viewport-2x-initial-scale-non-user-scalable.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "viewport-2x-initial-scale-non-user-scalable.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetViewportMetaNonUserScalableQuirk(true);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
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

TEST_F(WebFrameTest, DesktopPageCanBeZoomedInWhenWideViewportIsTurnedOff) {
  RegisterMockedHttpURLLoad("no_viewport_tag.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_viewport_tag.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  web_view_helper.GetWebView()->GetSettings()->SetWideViewportQuirkEnabled(
      true);
  web_view_helper.GetWebView()->GetSettings()->SetUseWideViewport(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->PageScaleFactor(), 0.01f);
  EXPECT_NEAR(1.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor(),
              0.01f);
  EXPECT_NEAR(5.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor(),
              0.01f);
}

class WebFrameResizeTest : public WebFrameTest {
 protected:
  void TestResizeYieldsCorrectScrollAndScale(
      const char* url,
      const float initial_page_scale_factor,
      const gfx::PointF& scroll_offset,
      const gfx::Size& viewport_size,
      const bool should_scale_relative_to_viewport_width) {
    RegisterMockedHttpURLLoad(url);

    const float aspect_ratio =
        static_cast<float>(viewport_size.width()) / viewport_size.height();

    frame_test_helpers::WebViewHelper web_view_helper;
    web_view_helper.InitializeAndLoad(base_url_ + url, nullptr, nullptr,
                                      ConfigureAndroid);
    web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);

    // Origin scrollOffsets preserved under resize.
    {
      web_view_helper.Resize(viewport_size);
      web_view_helper.GetWebView()->SetPageScaleFactor(
          initial_page_scale_factor);
      ASSERT_EQ(gfx::Size(viewport_size),
                web_view_helper.GetWebView()->MainFrameWidget()->Size());
      ASSERT_EQ(initial_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
      web_view_helper.Resize(
          gfx::Size(viewport_size.height(), viewport_size.width()));
      float expected_page_scale_factor =
          initial_page_scale_factor *
          (should_scale_relative_to_viewport_width ? 1 / aspect_ratio : 1);
      EXPECT_NEAR(expected_page_scale_factor,
                  web_view_helper.GetWebView()->PageScaleFactor(), 0.05f);
      EXPECT_EQ(gfx::PointF(),
                web_view_helper.LocalMainFrame()->GetScrollOffset());
    }

    // Resizing just the height should not affect pageScaleFactor or
    // scrollOffset.
    {
      web_view_helper.Resize(viewport_size);
      web_view_helper.GetWebView()->SetPageScaleFactor(
          initial_page_scale_factor);
      web_view_helper.LocalMainFrame()->SetScrollOffset(scroll_offset);
      UpdateAllLifecyclePhases(web_view_helper.GetWebView());
      const gfx::PointF expected_scroll_offset =
          web_view_helper.LocalMainFrame()->GetScrollOffset();
      web_view_helper.Resize(
          gfx::Size(viewport_size.width(), viewport_size.height() * 0.8f));
      EXPECT_EQ(initial_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
      EXPECT_EQ(expected_scroll_offset,
                web_view_helper.LocalMainFrame()->GetScrollOffset());
      web_view_helper.Resize(
          gfx::Size(viewport_size.width(), viewport_size.height() * 0.8f));
      EXPECT_EQ(initial_page_scale_factor,
                web_view_helper.GetWebView()->PageScaleFactor());
      EXPECT_EQ(expected_scroll_offset,
                web_view_helper.LocalMainFrame()->GetScrollOffset());
    }
  }
};

TEST_F(WebFrameResizeTest,
       ResizeYieldsCorrectScrollAndScaleForWidthEqualsDeviceWidth) {
  // With width=device-width, pageScaleFactor is preserved across resizes as
  // long as the content adjusts according to the device-width.
  const char* url = "resize_scroll_mobile.html";
  const float kInitialPageScaleFactor = 1;
  const gfx::PointF scroll_offset(0, 50);
  const gfx::Size viewport_size(120, 160);
  const bool kShouldScaleRelativeToViewportWidth = true;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_F(WebFrameResizeTest, ResizeYieldsCorrectScrollAndScaleForMinimumScale) {
  // This tests a scenario where minimum-scale is set to 1.0, but some element
  // on the page is slightly larger than the portrait width, so our "natural"
  // minimum-scale would be lower. In that case, we should stick to 1.0 scale
  // on rotation and not do anything strange.
  const char* url = "resize_scroll_minimum_scale.html";
  const float kInitialPageScaleFactor = 1;
  const gfx::PointF scroll_offset(0, 0);
  const gfx::Size viewport_size(240, 320);
  const bool kShouldScaleRelativeToViewportWidth = false;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_F(WebFrameResizeTest, ResizeYieldsCorrectScrollAndScaleForFixedWidth) {
  // With a fixed width, pageScaleFactor scales by the relative change in
  // viewport width.
  const char* url = "resize_scroll_fixed_width.html";
  const float kInitialPageScaleFactor = 2;
  const gfx::PointF scroll_offset(0, 200);
  const gfx::Size viewport_size(240, 320);
  const bool kShouldScaleRelativeToViewportWidth = true;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_F(WebFrameResizeTest, ResizeYieldsCorrectScrollAndScaleForFixedLayout) {
  // With a fixed layout, pageScaleFactor scales by the relative change in
  // viewport width.
  const char* url = "resize_scroll_fixed_layout.html";
  const float kInitialPageScaleFactor = 2;
  const gfx::PointF scroll_offset(200, 400);
  const gfx::Size viewport_size(320, 240);
  const bool kShouldScaleRelativeToViewportWidth = true;

  TestResizeYieldsCorrectScrollAndScale(url, kInitialPageScaleFactor,
                                        scroll_offset, viewport_size,
                                        kShouldScaleRelativeToViewportWidth);
}

TEST_F(WebFrameTest, pageScaleFactorUpdatesScrollbars) {
  RegisterMockedHttpURLLoad("fixed_layout.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "fixed_layout.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  LocalFrameView* view = web_view_helper.LocalMainFrame()->GetFrameView();
  ScrollableArea* scrollable_area = view->LayoutViewport();
  EXPECT_EQ(scrollable_area->ScrollSize(kHorizontalScrollbar),
            scrollable_area->ContentsSize().width() - view->Width());
  EXPECT_EQ(scrollable_area->ScrollSize(kVerticalScrollbar),
            scrollable_area->ContentsSize().height() - view->Height());

  web_view_helper.GetWebView()->SetPageScaleFactor(10);

  EXPECT_EQ(scrollable_area->ScrollSize(kHorizontalScrollbar),
            scrollable_area->ContentsSize().width() - view->Width());
  EXPECT_EQ(scrollable_area->ScrollSize(kVerticalScrollbar),
            scrollable_area->ContentsSize().height() - view->Height());
}

TEST_F(WebFrameTest, CanOverrideScaleLimits) {
  RegisterMockedHttpURLLoad("no_scale_for_you.html");

  int viewport_width = 640;
  int viewport_height = 480;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "no_scale_for_you.html",
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 5);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor());
  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor());

  web_view_helper.GetWebView()->SetIgnoreViewportTagScaleLimits(true);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  EXPECT_EQ(1.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor());
  EXPECT_EQ(5.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor());

  web_view_helper.GetWebView()->SetIgnoreViewportTagScaleLimits(false);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MinimumPageScaleFactor());
  EXPECT_EQ(2.0f, web_view_helper.GetWebView()->MaximumPageScaleFactor());
}

// Android doesn't have scrollbars on the main LocalFrameView
#if BUILDFLAG(IS_ANDROID)
TEST_F(WebFrameTest, DISABLED_updateOverlayScrollbarLayers)
#else
TEST_F(WebFrameTest, updateOverlayScrollbarLayers)
#endif
{
  RegisterMockedHttpURLLoad("large-div.html");

  int view_width = 500;
  int view_height = 500;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetPreferCompositingToLCDTextForTesting(true);

  web_view_helper.Resize(gfx::Size(view_width, view_height));
  frame_test_helpers::LoadFrame(web_view_helper.GetWebView()->MainFrameImpl(),
                                base_url_ + "large-div.html");

  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  const cc::Layer* root_layer =
      web_view_helper.GetLayerTreeHost()->root_layer();
  EXPECT_EQ(1u, CcLayersByName(root_layer, "HorizontalScrollbar").size());
  EXPECT_EQ(1u, CcLayersByName(root_layer, "VerticalScrollbar").size());

  web_view_helper.Resize(gfx::Size(view_width * 10, view_height * 10));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  EXPECT_EQ(0u, CcLayersByName(root_layer, "HorizontalScrollbar").size());
  EXPECT_EQ(0u, CcLayersByName(root_layer, "VerticalScrollbar").size());
}

void SetScaleAndScrollAndLayout(WebViewImpl* web_view,
                                const gfx::Point& scroll,
                                float scale) {
  web_view->SetPageScaleFactor(scale);
  web_view->MainFrameImpl()->SetScrollOffset(gfx::PointF(scroll));
  web_view->MainFrameWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
}

void SimulatePageScale(WebViewImpl* web_view_impl, float& scale) {
  float scale_delta =
      web_view_impl->FakePageScaleAnimationPageScaleForTesting() /
      web_view_impl->PageScaleFactor();
  web_view_impl->MainFrameWidget()->ApplyViewportChangesForTesting(
      {gfx::Vector2dF(), gfx::Vector2dF(), scale_delta, false, 0, 0,
       cc::BrowserControlsState::kBoth});
  scale = web_view_impl->PageScaleFactor();
}

gfx::Rect ComputeBlockBoundHelper(WebViewImpl* web_view_impl,
                                  const gfx::Point& point,
                                  bool ignore_clipping) {
  DCHECK(web_view_impl->MainFrameImpl());
  WebFrameWidgetImpl* widget =
      web_view_impl->MainFrameImpl()->FrameWidgetImpl();
  DCHECK(widget);
  return widget->ComputeBlockBound(point, ignore_clipping);
}

void SimulateDoubleTap(WebViewImpl* web_view_impl,
                       gfx::Point& point,
                       float& scale) {
  web_view_impl->AnimateDoubleTapZoom(
      point, ComputeBlockBoundHelper(web_view_impl, point, false));
  EXPECT_TRUE(web_view_impl->FakeDoubleTapAnimationPendingForTesting());
  SimulatePageScale(web_view_impl, scale);
}

TEST_F(WebFrameTest, DivAutoZoomParamsTest) {
  RegisterMockedHttpURLLoad("get_scale_for_auto_zoom_into_div_test.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_auto_zoom_into_div_test.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.01f, 4);
  web_view_helper.GetWebView()->SetPageScaleFactor(0.5f);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  gfx::Rect wide_div(200, 100, 400, 150);
  gfx::Rect tall_div(200, 300, 400, 800);
  gfx::Point double_tap_point_wide(wide_div.x() + 50, wide_div.y() + 50);
  gfx::Point double_tap_point_tall(tall_div.x() + 50, tall_div.y() + 50);
  float scale;
  gfx::Point scroll;

  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;

  // Test double-tap zooming into wide div.
  gfx::Rect wide_block_bound = ComputeBlockBoundHelper(
      web_view_helper.GetWebView(), double_tap_point_wide, false);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      double_tap_point_wide, wide_block_bound, kTouchPointPadding,
      double_tap_zoom_already_legible_scale, scale, scroll);
  // The div should horizontally fill the screen (modulo margins), and
  // vertically centered (modulo integer rounding).
  EXPECT_NEAR(viewport_width / (float)wide_div.width(), scale, 0.1);
  EXPECT_NEAR(wide_div.x(), scroll.x(), 20);
  EXPECT_EQ(0, scroll.y());

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), scroll, scale);

  // Test zoom out back to minimum scale.
  wide_block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                             double_tap_point_wide, false);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      double_tap_point_wide, wide_block_bound, kTouchPointPadding,
      double_tap_zoom_already_legible_scale, scale, scroll);
  // FIXME: Looks like we are missing EXPECTs here.

  scale = web_view_helper.GetWebView()->MinimumPageScaleFactor();
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(), scale);

  // Test double-tap zooming into tall div.
  gfx::Rect tall_block_bound = ComputeBlockBoundHelper(
      web_view_helper.GetWebView(), double_tap_point_tall, false);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      double_tap_point_tall, tall_block_bound, kTouchPointPadding,
      double_tap_zoom_already_legible_scale, scale, scroll);
  // The div should start at the top left of the viewport.
  EXPECT_NEAR(viewport_width / (float)tall_div.width(), scale, 0.1);
  EXPECT_NEAR(tall_div.x(), scroll.x(), 20);
  EXPECT_NEAR(tall_div.y(), scroll.y(), 20);
}

TEST_F(WebFrameTest, DivAutoZoomWideDivTest) {
  RegisterMockedHttpURLLoad("get_wide_div_for_auto_zoom_test.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_wide_div_for_auto_zoom_test.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetZoomFactorForDeviceScaleFactor(
      kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetPageScaleFactor(1.0f);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;

  gfx::Rect div(0, 100, viewport_width, 150);
  gfx::Point point(div.x() + 50, div.y() + 50);
  float scale;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);

  SimulateDoubleTap(web_view_helper.GetWebView(), point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
}

TEST_F(WebFrameTest, DivAutoZoomVeryTallTest) {
  // When a block is taller than the viewport and a zoom targets a lower part
  // of it, then we should keep the target point onscreen instead of snapping
  // back up the top of the block.
  RegisterMockedHttpURLLoad("very_tall_div.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "very_tall_div.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetZoomFactorForDeviceScaleFactor(
      kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetPageScaleFactor(1.0f);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  gfx::Rect div(200, 300, 400, 5000);
  gfx::Point point(div.x() + 50, div.y() + 3000);
  float scale;
  gfx::Point scroll;

  gfx::Rect block_bound =
      ComputeBlockBoundHelper(web_view_helper.GetWebView(), point, true);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForBlockRect(
      point, block_bound, 0, 1.0f, scale, scroll);
  EXPECT_EQ(scale, 1.0f);
  EXPECT_EQ(scroll.y(), 2660);
}

TEST_F(WebFrameTest, DivAutoZoomMultipleDivsTest) {
  RegisterMockedHttpURLLoad("get_multiple_divs_for_auto_zoom_test.html");

  const float kDeviceScaleFactor = 2.0f;
  int viewport_width = 640 / kDeviceScaleFactor;
  int viewport_height = 1280 / kDeviceScaleFactor;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_multiple_divs_for_auto_zoom_test.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  web_view_helper.GetWebView()->SetPageScaleFactor(0.5f);
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  gfx::Rect top_div(200, 100, 200, 150);
  gfx::Rect bottom_div(200, 300, 200, 150);
  gfx::Point top_point(top_div.x() + 50, top_div.y() + 50);
  gfx::Point bottom_point(bottom_div.x() + 50, bottom_div.y() + 50);
  float scale;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);

  // Test double tap on two different divs.  After first zoom, we should go back
  // to minimum page scale with a second double tap.
  SimulateDoubleTap(web_view_helper.GetWebView(), top_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);

  // If the user pinch zooms after double tap, a second double tap should zoom
  // back to the div.
  SimulateDoubleTap(web_view_helper.GetWebView(), top_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        0.6f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);

  // If we didn't yet get an auto-zoom update and a second double-tap arrives,
  // should go back to minimum scale.
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.1f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});

  gfx::Rect block_bounds =
      ComputeBlockBoundHelper(web_view_helper.GetWebView(), top_point, false);
  web_view_helper.GetWebView()->AnimateDoubleTapZoom(top_point, block_bounds);
  EXPECT_TRUE(
      web_view_helper.GetWebView()->FakeDoubleTapAnimationPendingForTesting());
  SimulateDoubleTap(web_view_helper.GetWebView(), bottom_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
}

TEST_F(WebFrameTest, DivAutoZoomScaleBoundsTest) {
  RegisterMockedHttpURLLoad("get_scale_bounds_check_for_auto_zoom_test.html");

  int viewport_width = 320;
  int viewport_height = 480;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_bounds_check_for_auto_zoom_test.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  gfx::Rect div(200, 100, 200, 150);
  gfx::Point double_tap_point(div.x() + 50, div.y() + 50);
  float scale;

  // Test double tap scale bounds.
  // minimumPageScale < doubleTapZoomAlreadyLegibleScale < 1
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(1, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(1, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.1f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  // 1 < minimumPageScale < doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1.1f, 4);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.1f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  // minimumPageScale < 1 < doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.95f, 4);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(double_tap_zoom_already_legible_scale, scale);
}

TEST_F(WebFrameTest, DivAutoZoomScaleLegibleScaleTest) {
  RegisterMockedHttpURLLoad("get_scale_bounds_check_for_auto_zoom_test.html");

  int viewport_width = 320;
  int viewport_height = 480;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  float maximum_legible_scale_factor = 1.13f;
  frame_test_h
```