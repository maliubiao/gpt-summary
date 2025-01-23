Response:
The user wants a summary of the functionality of the provided C++ code snippet from the `web_frame_test.cc` file in the Chromium Blink engine.

The code snippet contains several test cases within the `WebFrameTest` class. These tests seem to focus on the behavior of web frames in response to various events and configurations, particularly related to:

1. **Page scaling and zooming:** Double-tap gestures, maximum legible scale, text autosizing, and accessibility font scaling.
2. **Block bounds:** Determining the boundaries of block-level elements.
3. **Auto-zoom on focus:** Preventing or allowing auto-zoom based on `touch-action` CSS property.
4. **Scrolling into editable elements:** Ensuring correct scrolling and scaling when focusing on text input fields, considering factors like viewport size, caret position, and device scale factor.
5. **Character range rectangles:** Retrieving the position and size of character ranges within text nodes, especially when pinch zoom is active.
6. **Frame reloading:** Verifying that reloads are not incorrectly identified as client-side redirects.

For each test, I need to:
- Identify the core functionality being tested.
- Explain its relation to JavaScript, HTML, and CSS if applicable.
- Provide examples of inputs and expected outputs if the test involves logical reasoning.
- Illustrate common usage errors or misunderstandings related to the tested functionality.
这是 `blink/renderer/core/frame/web_frame_test.cc` 文件的第 6 部分，主要包含以下功能测试，这些测试用例验证了 `WebFrame` 类在处理页面缩放、双击缩放、焦点元素滚动以及字符范围计算等方面的行为。

**1. 双击缩放相关的测试 (DivAutoZoomScaleMaximumLegibleScaleFactorTest, DivAutoZoomScaleFontScaleFactorTest):**

* **功能:** 这两个测试用例主要验证了在启用文本自动调整大小功能（Text Autosizing）时，双击页面上的元素（例如 `div` 元素）时的缩放行为。它们测试了双击缩放的目标缩放级别如何受到 `maximumLegibleScaleFactor`（最大可读缩放因子）和 `accessibilityFontScaleFactor`（辅助功能字体缩放因子）的影响。
* **与 JavaScript, HTML, CSS 的关系:**
    * **HTML:** 测试用例加载了一个 HTML 文件 (`get_scale_bounds_check_for_auto_zoom_test.html`)，该文件包含一个 `div` 元素，用于模拟双击操作。
    * **CSS:** CSS 可以影响元素的布局和大小，这会间接影响双击缩放的效果。例如，`div` 元素的尺寸会影响双击后缩放的程度。
    * **JavaScript:**  虽然这段代码没有直接展示 JavaScript 的交互，但在实际的浏览器行为中，双击事件的监听和缩放逻辑可能涉及到 JavaScript。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**
        * HTML 页面包含一个位于 (200, 100) 坐标，大小为 200x150 的 `div` 元素。
        * 设置了不同的 `maximumLegibleScaleFactor` 或 `accessibilityFontScaleFactor` 的值，以及不同的最小页面缩放比例。
        * 模拟在 `div` 元素内的点 (250, 150) 进行双击操作。
    * **输出:** `scale` 变量会根据不同的缩放因子设置而具有不同的预期值。测试用例使用 `EXPECT_FLOAT_EQ` 来断言实际的缩放值是否与预期值相等。例如，当 `maximumLegibleScaleFactor` 大于 1 且当前缩放比例小于 1 时，第一次双击的预期 `scale` 可能是 `maximumLegibleScaleFactor`。
* **用户或编程常见的使用错误:**
    * **错误设置缩放限制:** 开发者可能会错误地设置 `maximumLegibleScale` 或最小页面缩放比例，导致用户在双击时无法获得预期的缩放效果。例如，将 `maximumLegibleScale` 设置为小于 1 的值可能会阻止双击放大页面到更易读的程度。
    * **忘记启用文本自动调整大小:** 如果没有启用文本自动调整大小，这些测试中的双击缩放行为可能不会按照预期发生。

**2. 计算块级元素的边界 (BlockBoundTest):**

* **功能:** 此测试用例验证了 `ComputeBlockBoundHelper` 函数能够正确计算出给定屏幕坐标点所在的块级元素的边界矩形。
* **与 JavaScript, HTML, CSS 的关系:**
    * **HTML:** 测试加载了 `block_bound.html`，该文件定义了不同的块级元素（例如 `div`），并设置了它们的布局。
    * **CSS:** CSS 样式决定了哪些元素是块级元素，以及它们的尺寸和位置。`ComputeBlockBoundHelper` 函数依赖于渲染树中元素的布局信息，而这些信息受到 CSS 的影响。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** HTML 中定义了多个矩形区域，例如一个背景矩形 `rect_back` 和两个内部矩形 `rect_left_top` 和 `rect_right_bottom`。模拟在不同的坐标点进行点击。
    * **输出:** 根据点击的坐标，`ComputeBlockBoundHelper` 应该返回包含该点的最内层块级元素的边界矩形。例如，点击 (10, 10) 应该返回 `rect_left_top` 的边界。
* **用户或编程常见的使用错误:**
    * **误解块级元素的行为:** 开发者可能不清楚哪些 HTML 元素是块级元素，或者不理解 CSS 如何影响元素的布局，从而导致对 `ComputeBlockBoundHelper` 的预期结果产生误判。例如，内联元素（如 `span`）不会被视为块级元素。

**3. 触摸操作区域内焦点元素的缩放控制 (DontZoomInOnFocusedInTouchAction):**

* **功能:** 此测试用例检查了当焦点元素（例如文本框）位于具有特定 `touch-action` CSS 属性的祖先元素内时，是否会触发自动缩放。`touch-action: pan-x` 会禁用捏合缩放，而 `touch-action: manipulation` 则允许。
* **与 JavaScript, HTML, CSS 的关系:**
    * **HTML:** 测试加载了 `textbox_in_touch_action.html`，该文件包含多个文本框，它们分别位于具有不同 `touch-action` 属性的 `div` 元素内。
    * **CSS:** `touch-action` 属性是关键，它控制了触摸事件的行为，包括是否允许捏合缩放。
    * **JavaScript:** JavaScript 用于将焦点设置到不同的文本框，并模拟滚动操作。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** HTML 中有三个文本框，第一个位于 `touch-action: pan-x` 的容器中，第二个位于 `touch-action: manipulation` 的容器中，第三个位于 `touch-action: pan-x` 的容器中，但中间隔了一个 `overflow:scroll` 的元素。
    * **输出:** 当焦点移动到第一个文本框时，由于 `pan-x` 禁用了捏合缩放，`FakePageScaleAnimationPageScaleForTesting()` 应该返回 0 或接近初始比例的值，表示没有自动缩放。当焦点移动到第二个和第三个文本框时，由于允许捏合缩放或中间有 `overflow:scroll` 元素隔离，应该会触发自动缩放，`FakePageScaleAnimationPageScaleForTesting()` 返回的值应该大于初始比例。
* **用户或编程常见的使用错误:**
    * **错误地使用 `touch-action`:** 开发者可能错误地使用 `touch-action` 属性，导致在不需要缩放时触发了自动缩放，或者在需要缩放时禁用了缩放。例如，在包含可编辑文本的区域使用 `touch-action: none` 会完全禁用触摸交互。

**4. 将焦点元素滚动到可见区域 (DivScrollIntoEditableTest, DivScrollIntoEditablePreservePageScaleTest, DivScrollIntoEditableTestZoomToLegibleScaleDisabled, DivScrollIntoEditableTestWithDeviceScaleFactor):**

* **功能:** 这些测试用例验证了当焦点移动到可编辑元素（如文本框）时，浏览器是否能够正确地滚动页面，使其完全或部分可见。它们还测试了是否会进行自动缩放以使文本更易读，以及在不同场景下（例如，设置了设备像素比）的滚动和缩放行为。
* **与 JavaScript, HTML, CSS 的关系:**
    * **HTML:** 测试加载了 `get_scale_for_zoom_into_editable_test.html`，其中包含多个文本输入框。
    * **CSS:** CSS 影响文本框的位置和大小，这会影响滚动和缩放的计算。
    * **JavaScript:** JavaScript 用于将焦点设置到不同的文本框，并设置选区范围。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** HTML 中有多个文本框，视口大小不同，初始缩放比例不同。将焦点设置到不同的文本框。
    * **输出:** 测试用例验证了焦点元素是否被滚动到可见区域，以及是否进行了自动缩放。例如，如果文本框初始时部分不可见，焦点移动后，页面应该会滚动，使得文本框可见。如果启用了自动缩放，并且文本框太小，页面可能会放大以使其更易读。`ComputeScaleAndScrollForEditableElementRects` 函数用于计算所需的缩放和滚动值。
* **用户或编程常见的使用错误:**
    * **假设元素总是可见:** 开发者可能没有考虑到焦点元素可能在视口之外，需要滚动才能看到。
    * **不理解自动缩放的触发条件:** 开发者可能不清楚在哪些情况下浏览器会自动缩放以提高可读性。

**5. 获取字符范围的矩形 (FirstRectForCharacterRangeWithPinchZoom):**

* **功能:** 此测试用例验证了 `FirstRectForCharacterRange` 函数在捏合缩放（pinch zoom）活动时，能够正确计算出给定字符范围的屏幕坐标矩形。
* **与 JavaScript, HTML, CSS 的关系:**
    * **HTML:** 测试加载了 `textbox.html`，其中包含一个文本框。
    * **CSS:** CSS 影响文本的渲染，例如字体大小和行高，这些会影响字符范围的矩形。
    * **JavaScript:** JavaScript 用于设置文本框的选区范围，这与获取字符范围相关。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 加载一个包含文本框的页面，并使用 JavaScript 选中了文本框中的一部分文本（例如前 5 个字符）。初始状态下获取选区的矩形 `old_rect`。然后，设置页面缩放比例为 2，并设置视口偏移。
    * **输出:** 再次调用 `FirstRectForCharacterRange` 获取相同字符范围的矩形 `rect`。`rect` 的坐标和尺寸应该等于 `old_rect` 的坐标和尺寸乘以缩放比例，并减去视口偏移的影响。
* **用户或编程常见的使用错误:**
    * **未考虑缩放和偏移:** 开发者可能在计算元素在屏幕上的位置时，没有考虑到页面的缩放比例和视口偏移，导致位置计算错误。

**6. 重新加载帧时不应设置为重定向 (ReloadDoesntSetRedirect):**

* **功能:** 此测试用例验证了在快速重新加载一个帧时，`BeginNavigation` 方法不会错误地将这次导航标记为客户端重定向。
* **与 JavaScript, HTML 的关系:**
    * **HTML:** 测试加载了 `form.html`，尽管具体内容在此测试中并不重要，重要的是触发了帧的重新加载。
    * **JavaScript:** 可以使用 JavaScript 来触发帧的重新加载，例如 `window.location.reload()`。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 加载一个页面，然后快速连续地调用两次帧的重新加载操作（通过 `StartReload` 和 `ReloadFrameBypassingCache`）。
    * **输出:** `TestReloadDoesntRedirectWebFrameClient` 监听 `BeginNavigation` 事件，并断言 `info->is_client_redirect` 为 `false`，即使是快速连续的重新加载也不应被误认为是客户端重定向。
* **用户或编程常见的使用错误:**
    * **对重定向的误解:** 开发者可能不清楚什么是客户端重定向，以及浏览器如何区分普通的页面加载和重定向。

**总结第 6 部分的功能:**

这部分代码主要针对 `WebFrame` 类的各种功能进行了详细的单元测试，特别是围绕用户交互（如双击）、页面缩放、焦点管理和内容呈现等方面。它确保了 Blink 引擎在处理这些场景时的行为符合预期，并且能够正确地响应用户操作和页面配置。这些测试覆盖了与 HTML 结构、CSS 样式以及可能的 JavaScript 交互相关的多个方面，旨在提高渲染引擎的稳定性和用户体验。

### 提示词
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第6部分，共19部分，请归纳一下它的功能
```

### 源代码
```cpp
elpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_bounds_check_for_auto_zoom_test.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetMaximumLegibleScale(
      maximum_legible_scale_factor);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(true);

  gfx::Rect div(200, 100, 200, 150);
  gfx::Point double_tap_point(div.x() + 50, div.y() + 50);
  float scale;

  // Test double tap scale bounds.
  // minimumPageScale < doubleTapZoomAlreadyLegibleScale < 1 <
  //     maximumLegibleScaleFactor
  float legible_scale = maximum_legible_scale_factor;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.1f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  // 1 < maximumLegibleScaleFactor < minimumPageScale <
  //     doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1.0f, 4);
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
  // minimumPageScale < 1 < maximumLegibleScaleFactor <
  //     doubleTapZoomAlreadyLegibleScale
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

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.1f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  // minimumPageScale < 1 < doubleTapZoomAlreadyLegibleScale <
  //     maximumLegibleScaleFactor
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.9f, 4);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
}

TEST_F(WebFrameTest, DivAutoZoomScaleFontScaleFactorTest) {
  RegisterMockedHttpURLLoad("get_scale_bounds_check_for_auto_zoom_test.html");

  int viewport_width = 320;
  int viewport_height = 480;
  float double_tap_zoom_already_legible_ratio = 1.2f;
  float accessibility_font_scale_factor = 1.13f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_bounds_check_for_auto_zoom_test.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetMaximumLegibleScale(1.f);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetAccessibilityFontScaleFactor(accessibility_font_scale_factor);

  gfx::Rect div(200, 100, 200, 150);
  gfx::Point double_tap_point(div.x() + 50, div.y() + 50);
  float scale;

  // Test double tap scale bounds.
  // minimumPageScale < doubleTapZoomAlreadyLegibleScale < 1 <
  //     accessibilityFontScaleFactor
  float legible_scale = accessibility_font_scale_factor;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  float double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.5f, 4);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.1f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  // 1 < accessibilityFontScaleFactor < minimumPageScale <
  //     doubleTapZoomAlreadyLegibleScale
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(1.0f, 4);
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
  // minimumPageScale < 1 < accessibilityFontScaleFactor <
  //     doubleTapZoomAlreadyLegibleScale
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

  // Zoom in to reset double_tap_zoom_in_effect flag.
  web_view_helper.GetWebView()
      ->MainFrameWidget()
      ->ApplyViewportChangesForTesting({gfx::Vector2dF(), gfx::Vector2dF(),
                                        1.1f, false, 0, 0,
                                        cc::BrowserControlsState::kBoth});
  // minimumPageScale < 1 < doubleTapZoomAlreadyLegibleScale <
  //     accessibilityFontScaleFactor
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.9f, 4);
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  double_tap_zoom_already_legible_scale =
      web_view_helper.GetWebView()->MinimumPageScaleFactor() *
      double_tap_zoom_already_legible_ratio;
  SetScaleAndScrollAndLayout(
      web_view_helper.GetWebView(), gfx::Point(),
      (web_view_helper.GetWebView()->MinimumPageScaleFactor()) *
          (1 + double_tap_zoom_already_legible_ratio) / 2);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(web_view_helper.GetWebView()->MinimumPageScaleFactor(),
                  scale);
  SimulateDoubleTap(web_view_helper.GetWebView(), double_tap_point, scale);
  EXPECT_FLOAT_EQ(legible_scale, scale);
}

TEST_F(WebFrameTest, BlockBoundTest) {
  RegisterMockedHttpURLLoad("block_bound.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "block_bound.html", nullptr,
                                    nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(300, 300));

  gfx::Rect rect_back(0, 0, 200, 200);
  gfx::Rect rect_left_top(10, 10, 80, 80);
  gfx::Rect rect_right_bottom(110, 110, 80, 80);
  gfx::Rect block_bound;

  block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                        gfx::Point(9, 9), true);
  EXPECT_EQ(rect_back, block_bound);

  block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                        gfx::Point(10, 10), true);
  EXPECT_EQ(rect_left_top, block_bound);

  block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                        gfx::Point(50, 50), true);
  EXPECT_EQ(rect_left_top, block_bound);

  block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                        gfx::Point(89, 89), true);
  EXPECT_EQ(rect_left_top, block_bound);

  block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                        gfx::Point(90, 90), true);
  EXPECT_EQ(rect_back, block_bound);

  block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                        gfx::Point(109, 109), true);
  EXPECT_EQ(rect_back, block_bound);

  block_bound = ComputeBlockBoundHelper(web_view_helper.GetWebView(),
                                        gfx::Point(110, 110), true);
  EXPECT_EQ(rect_right_bottom, block_bound);
}

TEST_F(WebFrameTest, DontZoomInOnFocusedInTouchAction) {
  RegisterMockedHttpURLLoad("textbox_in_touch_action.html");

  int viewport_width = 600;
  int viewport_height = 1000;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "textbox_in_touch_action.html");
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 4);
  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.GetWebView()
      ->GetSettings()
      ->SetAutoZoomFocusedEditableToLegibleScale(true);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));

  float initial_scale = web_view_helper.GetWebView()->PageScaleFactor();

  // Focus the first textbox that's in a touch-action: pan-x ancestor, this
  // shouldn't cause an autozoom since pan-x disables pinch-zoom.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  EXPECT_EQ(
      web_view_helper.GetWebView()->FakePageScaleAnimationPageScaleForTesting(),
      0);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             initial_scale);
  ASSERT_EQ(initial_scale, web_view_helper.GetWebView()->PageScaleFactor());

  // Focus the second textbox that's in a touch-action: manipulation ancestor,
  // this should cause an autozoom since it allows pinch-zoom.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  EXPECT_GT(
      web_view_helper.GetWebView()->FakePageScaleAnimationPageScaleForTesting(),
      initial_scale);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             initial_scale);
  ASSERT_EQ(initial_scale, web_view_helper.GetWebView()->PageScaleFactor());

  // Focus the third textbox that has a touch-action: pan-x ancestor, this
  // should cause an autozoom since it's seperated from the node with the
  // touch-action by an overflow:scroll element.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->FrameWidget()
      ->ScrollFocusedEditableElementIntoView();
  EXPECT_GT(
      web_view_helper.GetWebView()->FakePageScaleAnimationPageScaleForTesting(),
      initial_scale);
}

TEST_F(WebFrameTest, DivScrollIntoEditableTest) {
  RegisterMockedHttpURLLoad("Ahem.ttf");
  RegisterMockedHttpURLLoad("get_scale_for_zoom_into_editable_test.html");

  const bool kAutoZoomToLegibleScale = true;
  int viewport_width = 450;
  int viewport_height = 300;
  float left_box_ratio = 0.3f;
  int caret_padding = 10;
  float min_readable_caret_height = 16.0f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_zoom_into_editable_test.html");
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 4);

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  gfx::Rect edit_box_with_text(200, 200, 250, 20);
  gfx::Rect edit_box_with_no_text(200, 250, 250, 20);

  // Test scrolling the focused node
  // The edit box is shorter and narrower than the viewport when legible.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  // Set the caret to the end of the input box.
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->GetDocument()
      .GetElementById("EditBoxWithText")
      .To<WebInputElement>()
      .SetSelectionRange(1000, 1000);
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(), 1);
  gfx::Rect rect, caret;
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      caret, rect);

  // Set the page scale to be smaller than the minimal readable scale.
  float initial_scale = min_readable_caret_height / caret.height() * 0.5f;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             initial_scale);

  float scale;
  gfx::Point scroll;
  bool need_animation;
  gfx::Rect element_bounds, caret_bounds;
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // The edit box should be left aligned with a margin for possible label.
  int h_scroll =
      edit_box_with_text.x() - left_box_ratio * viewport_width / scale;
  EXPECT_NEAR(h_scroll, scroll.x(), 2);
  int v_scroll = edit_box_with_text.y() -
                 (viewport_height / scale - edit_box_with_text.height()) / 2;
  EXPECT_NEAR(v_scroll, scroll.y(), 2);
  EXPECT_NEAR(min_readable_caret_height / caret.height(), scale, 0.1);

  // The edit box is wider than the viewport when legible.
  viewport_width = 200;
  viewport_height = 150;
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             initial_scale);
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // The caret should be right aligned since the caret would be offscreen when
  // the edit box is left aligned.
  h_scroll = caret.x() + caret.width() + caret_padding - viewport_width / scale;
  EXPECT_NEAR(h_scroll, scroll.x(), 2);
  EXPECT_NEAR(min_readable_caret_height / caret.height(), scale, 0.1);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             initial_scale);
  // Move focus to edit box with text.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // The edit box should be left aligned.
  h_scroll = edit_box_with_no_text.x();
  EXPECT_NEAR(h_scroll, scroll.x(), 2);
  v_scroll = edit_box_with_no_text.y() -
             (viewport_height / scale - edit_box_with_no_text.height()) / 2;
  EXPECT_NEAR(v_scroll, scroll.y(), 2);
  EXPECT_NEAR(min_readable_caret_height / caret.height(), scale, 0.1);

  // Move focus back to the first edit box.
  web_view_helper.GetWebView()->AdvanceFocus(true);
  // Zoom out slightly.
  const float within_tolerance_scale = scale * 0.9f;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), scroll,
                             within_tolerance_scale);
  // Move focus back to the second edit box.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  // The scale should not be adjusted as the zoomed out scale was sufficiently
  // close to the previously focused scale.
  EXPECT_FALSE(need_animation);
}

TEST_F(WebFrameTest, DivScrollIntoEditablePreservePageScaleTest) {
  RegisterMockedHttpURLLoad("get_scale_for_zoom_into_editable_test.html");

  const bool kAutoZoomToLegibleScale = true;
  const int kViewportWidth = 450;
  const int kViewportHeight = 300;
  const float kMinReadableCaretHeight = 16.0f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_zoom_into_editable_test.html");
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.Resize(gfx::Size(kViewportWidth, kViewportHeight));
  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  const gfx::Rect edit_box_with_text(200, 200, 250, 20);

  web_view_helper.GetWebView()->AdvanceFocus(false);
  // Set the caret to the begining of the input box.
  web_view_helper.GetWebView()
      ->MainFrameImpl()
      ->GetDocument()
      .GetElementById("EditBoxWithText")
      .To<WebInputElement>()
      .SetSelectionRange(0, 0);
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(), 1);
  gfx::Rect rect, caret;
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      caret, rect);

  // Set the page scale to be twice as large as the minimal readable scale.
  float new_scale = kMinReadableCaretHeight / caret.height() * 2.0;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             new_scale);

  float scale;
  gfx::Point scroll;
  bool need_animation;
  gfx::Rect element_bounds, caret_bounds;
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // Edit box and caret should be left alinged
  int h_scroll = edit_box_with_text.x();
  EXPECT_NEAR(h_scroll, scroll.x(), 1);
  int v_scroll = edit_box_with_text.y() -
                 (kViewportHeight / scale - edit_box_with_text.height()) / 2;
  EXPECT_NEAR(v_scroll, scroll.y(), 1);
  // Page scale have to be unchanged
  EXPECT_EQ(new_scale, scale);

  // Set page scale and scroll such that edit box will be under the screen
  new_scale = 3.0;
  h_scroll = 200;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(),
                             gfx::Point(h_scroll, 0), new_scale);
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // Horizontal scroll have to be the same
  EXPECT_NEAR(h_scroll, scroll.x(), 1);
  v_scroll = edit_box_with_text.y() -
             (kViewportHeight / scale - edit_box_with_text.height()) / 2;
  EXPECT_NEAR(v_scroll, scroll.y(), 1);
  // Page scale have to be unchanged
  EXPECT_EQ(new_scale, scale);
}

// Tests the scroll into view functionality when
// autoZoomeFocusedNodeToLegibleScale set to false. i.e. The path non-Android
// platforms take.
TEST_F(WebFrameTest, DivScrollIntoEditableTestZoomToLegibleScaleDisabled) {
  RegisterMockedHttpURLLoad("get_scale_for_zoom_into_editable_test.html");

  const bool kAutoZoomToLegibleScale = false;
  int viewport_width = 100;
  int viewport_height = 100;
  float left_box_ratio = 0.3f;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_zoom_into_editable_test.html");
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 4);

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  gfx::Rect edit_box_with_no_text(200, 250, 250, 20);

  // Test scrolling the focused node
  // Since we're zoomed out, the caret is considered too small to be legible and
  // so we'd normally zoom in. Make sure we don't change scale since the
  // auto-zoom setting is off.

  // Focus the second empty textbox.
  web_view_helper.GetWebView()->AdvanceFocus(false);
  web_view_helper.GetWebView()->AdvanceFocus(false);

  // Set the page scale to be smaller than the minimal readable scale.
  float initial_scale = 0.25f;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             initial_scale);

  float scale;
  gfx::Point scroll;
  bool need_animation;
  gfx::Rect element_bounds, caret_bounds;
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);

  // There should be no change in page scale.
  EXPECT_EQ(initial_scale, scale);
  // The edit box should be left aligned with a margin for possible label.
  EXPECT_TRUE(need_animation);
  int h_scroll =
      edit_box_with_no_text.x() - left_box_ratio * viewport_width / scale;
  EXPECT_NEAR(h_scroll, scroll.x(), 2);
  int v_scroll = edit_box_with_no_text.y() -
                 (viewport_height / scale - edit_box_with_no_text.height()) / 2;
  EXPECT_NEAR(v_scroll, scroll.y(), 2);

  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), scroll, scale);

  // Select the first textbox.
  web_view_helper.GetWebView()->AdvanceFocus(true);
  gfx::Rect rect, caret;
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      caret, rect);
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);

  // There should be no change at all since the textbox is fully visible
  // already.
  EXPECT_EQ(initial_scale, scale);
  EXPECT_FALSE(need_animation);
}

// Tests zoom into editable zoom and scroll correctly when zoom-for-dsf enabled.
TEST_F(WebFrameTest, DivScrollIntoEditableTestWithDeviceScaleFactor) {
  RegisterMockedHttpURLLoad("get_scale_for_zoom_into_editable_test.html");

  bool kAutoZoomToLegibleScale = true;
  const float kDeviceScaleFactor = 2.f;
  int viewport_width = 200 * kDeviceScaleFactor;
  int viewport_height = 150 * kDeviceScaleFactor;
  float min_readable_caret_height = 16.0f * kDeviceScaleFactor;

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(
      base_url_ + "get_scale_for_zoom_into_editable_test.html", nullptr,
      nullptr, ConfigureAndroid);
  web_view_helper.GetWebView()
      ->GetPage()
      ->GetSettings()
      .SetTextAutosizingEnabled(false);
  web_view_helper.Resize(gfx::Size(viewport_width, viewport_height));
  web_view_helper.GetWebView()->SetZoomFactorForDeviceScaleFactor(
      kDeviceScaleFactor);
  web_view_helper.GetWebView()->SetDefaultPageScaleLimits(0.25f, 4);

  web_view_helper.GetWebView()->EnableFakePageScaleAnimationForTesting(true);

  gfx::Rect edit_box_with_text(
      200 * kDeviceScaleFactor, 200 * kDeviceScaleFactor,
      250 * kDeviceScaleFactor, 20 * kDeviceScaleFactor);
  web_view_helper.GetWebView()->AdvanceFocus(false);

  // Set the page scale to be smaller than the minimal readable scale.
  float initial_scale = 0.5f;
  SetScaleAndScrollAndLayout(web_view_helper.GetWebView(), gfx::Point(),
                             initial_scale);
  ASSERT_EQ(web_view_helper.GetWebView()->PageScaleFactor(), initial_scale);

  float scale;
  gfx::Point scroll;
  bool need_animation;
  gfx::Rect element_bounds, caret_bounds;
  GetElementAndCaretBoundsForFocusedEditableElement(
      web_view_helper, element_bounds, caret_bounds);
  web_view_helper.GetWebView()->ComputeScaleAndScrollForEditableElementRects(
      element_bounds, caret_bounds, kAutoZoomToLegibleScale, scale, scroll,
      need_animation);
  EXPECT_TRUE(need_animation);
  // The edit box wider than the viewport when legible should be left aligned.
  int h_scroll = edit_box_with_text.x();
  EXPECT_NEAR(h_scroll, scroll.x(), 2);
  int v_scroll = edit_box_with_text.y() -
                 (viewport_height / scale - edit_box_with_text.height()) / 2;
  EXPECT_NEAR(v_scroll, scroll.y(), 2);
  EXPECT_NEAR(min_readable_caret_height / caret_bounds.height(), scale, 0.1);
}

TEST_F(WebFrameTest, FirstRectForCharacterRangeWithPinchZoom) {
  RegisterMockedHttpURLLoad("textbox.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "textbox.html");
  web_view_helper.Resize(gfx::Size(640, 480));

  WebLocalFrame* main_frame = web_view_helper.LocalMainFrame();
  main_frame->ExecuteScript(WebScriptSource("selectRange();"));

  gfx::Rect old_rect;
  main_frame->FirstRectForCharacterRange(0, 5, old_rect);

  gfx::PointF visual_offset(100, 130);
  float scale = 2;
  web_view_helper.GetWebView()->SetPageScaleFactor(scale);
  web_view_helper.GetWebView()->SetVisualViewportOffset(visual_offset);

  gfx::Rect rect;
  main_frame->FirstRectForCharacterRange(0, 5, rect);

  EXPECT_EQ((old_rect.x() - visual_offset.x()) * scale, rect.x());
  EXPECT_EQ((old_rect.y() - visual_offset.y()) * scale, rect.y());
  EXPECT_EQ(old_rect.width() * scale, rect.width());
  EXPECT_EQ(old_rect.height() * scale, rect.height());
}
class TestReloadDoesntRedirectWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestReloadDoesntRedirectWebFrameClient() = default;
  ~TestReloadDoesntRedirectWebFrameClient() override = default;

  // frame_test_helpers::TestWebFrameClient:
  void BeginNavigation(std::unique_ptr<WebNavigationInfo> info) override {
    EXPECT_FALSE(info->is_client_redirect);
    TestWebFrameClient::BeginNavigation(std::move(info));
  }
};

TEST_F(WebFrameTest, ReloadDoesntSetRedirect) {
  // Test for case in http://crbug.com/73104. Reloading a frame very quickly
  // would sometimes call BeginNavigation with isRedirect=true
  RegisterMockedHttpURLLoad("form.html");

  TestReloadDoesntRedirectWebFrameClient web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "form.html", &web_frame_client);

  web_view_helper.GetWebView()->MainFrameImpl()->StartReload(
      WebFrameLoadType::kReloadBypassingCache);
  // start another reload before request is delivered.
  frame_test_helpers::ReloadFrameBypassingCache(
      web_view_helper.GetWebView()->MainFrameImpl());
}

class ClearScrollStateOnCommitWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  ClearScrollStateOnCommitWebFrameClient() = default;
  ~ClearScrollStateOnComm
```