Response:
The user wants to understand the functionality of the provided C++ code snippet from `web_view_test.cc`. This file is part of the Chromium Blink rendering engine and contains unit tests for the `WebView` class.

Here's a breakdown of how to address each point in the request:

1. **List the functionality:**  The code contains multiple test cases (using `TEST_F`) for various features related to `WebView`. I need to identify the purpose of each test case.

2. **Relationship with JavaScript, HTML, CSS:**  Since `WebView` is responsible for rendering web content, the tests likely interact with HTML elements and their styling (CSS). I need to look for examples where the tests manipulate or inspect the state of these elements.

3. **Logical Reasoning (Assumptions, Inputs, Outputs):** Each `TEST_F` function performs a specific action or series of actions and then uses `EXPECT_*` assertions to verify the outcome. I need to analyze the setup (e.g., loading a specific HTML file), the actions performed on the `WebView` object, and the expected results.

4. **Common Usage Errors:**  Unit tests often expose potential issues or incorrect usage. I should look for cases where the tests are verifying expected behavior in scenarios that could lead to errors if not handled correctly.

5. **User Operation to Reach Here (Debugging Clues):** To understand how a user's action might lead to this code being executed, I need to think about the features being tested. For example, tests related to hit-testing are likely triggered by mouse clicks or touch events.

6. **File and Part Information:** The user provided the file name and indicated this is part 2 of 9. This is helpful for context but doesn't directly affect the functional analysis of this specific snippet. The summary should acknowledge that it's part of a larger test file.

**Plan:**

1. Iterate through each `TEST_F` block in the provided code.
2. For each test:
   - Identify the feature being tested (e.g., device emulation, active state, hit testing, auto-resize, text input).
   - Analyze how the test interacts with the `WebView` object and potentially HTML elements.
   - Determine if the test relates to JavaScript, HTML, or CSS. Provide examples.
   - Formulate the assumptions, inputs (e.g., loaded HTML, simulated events), and expected outputs (based on `EXPECT_*`).
   - Consider potential user errors the test might be guarding against.
   - Infer the user actions that could trigger the tested functionality.
3. Summarize the overall functionality of the provided code snippet.
这是`blink/renderer/core/exported/web_view_test.cc`文件的第二部分，主要包含以下功能相关的单元测试：

**核心功能概括:** 这部分代码主要测试了 `WebView` 及其相关组件在以下方面的行为：

* **设备仿真 (Device Emulation):** 测试启用和禁用设备仿真对页面元素样式的影响，特别是焦点环的颜色。
* **激活状态 (Active State):** 测试设置和获取 `WebView` 的激活状态。
* **命中测试 (Hit Testing):** 测试在不同的页面缩放和偏移情况下，如何准确地找到点击位置对应的页面元素。
* **自动调整大小 (Auto Resize):** 测试 `WebView` 如何根据设置的最小和最大尺寸以及页面内容自动调整自身大小。
* **文本输入类型 (Text Input Type):** 测试 `WebView` 如何根据 HTML 输入元素的类型（如 `text`, `password`, `email` 等）识别并报告相应的文本输入类型。
* **文本输入模式 (Input Mode):** 测试 `WebView` 如何根据 HTML 输入元素的 `inputmode` 属性识别并报告相应的文本输入模式。
* **文本输入动作 (Input Action):** 测试 `WebView` 如何根据 HTML 输入元素的 `enterkeyhint` 属性识别并报告相应的文本输入动作。
* **文本输入信息 (Text Input Info):** 测试 `WebView` 如何获取和设置文本输入框的相关信息，包括文本内容、选区范围和输入法组合状态。
* **输入法组合 (IME Composition):** 测试 `WebView` 如何处理输入法的组合文本，包括设置、完成以及光标位置的调整。
* **长按事件 (Long Press):** 测试在输入框外部长按时，不会错误地选中输入框的占位符文本。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:** 所有的测试都依赖于加载不同的 HTML 文件来设置测试场景。例如：
    * `specify_size.html`: 用于测试自动调整大小，HTML 内容会定义页面的宽度和高度。
    * `input_field_default.html`, `input_field_password.html` 等: 用于测试文本输入类型，HTML 内容包含不同类型的 `<input>` 元素。
    * `hit_test.html`: 用于测试命中测试，HTML 内容包含可以被点击的元素（例如 `<img>`）。
* **CSS:** 设备仿真测试直接关系到 CSS 样式。
    * **举例:**  `TEST_F(WebViewTest, DeviceEmulationOutlineColor)` 测试了启用设备仿真后，`LayoutTheme::GetTheme().SetCustomFocusRingColor()` 设置的自定义焦点环颜色是否正确应用到 `<span>` 元素上。这涉及到 CSS 的 `outline-color` 属性。
* **JavaScript:** 虽然这部分代码没有直接展示与 JavaScript 的交互，但 `WebView` 本身的功能是加载和执行包含 JavaScript 的网页。这些测试可能间接地依赖 JavaScript 的行为来设置某些状态或触发某些事件。

**逻辑推理、假设输入与输出:**

* **`TEST_F(WebViewTest, DeviceEmulationOutlineColor)`:**
    * **假设输入:**  启用设备仿真，并设置一个自定义的焦点环颜色。页面包含一些 `<span>` 元素。
    * **预期输出:** 在启用设备仿真期间，所有 `<span>` 元素的焦点环颜色都应为自定义颜色。禁用设备仿真后，颜色应恢复为原始颜色。
* **`TEST_F(WebViewTest, HitTestResultAtWithPageScale)`:**
    * **假设输入:** 加载一个包含 50x50 像素 `<img>` 元素的页面。点击坐标 (75, 75)。
    * **预期输出:** 初始状态下，由于点击位置不在图片范围内，命中测试结果应该不包含 `<img>` 元素。将页面放大 2 倍后，点击位置应在图片范围内，命中测试结果应该包含 `<img>` 元素。
* **`TEST_F(WebViewTest, AutoResizeMinimumSize)`:**
    * **假设输入:** 设置最小自动调整尺寸为 91x56，加载一个页面内容尺寸也为 91x56 的 HTML。
    * **预期输出:** `WebView` 的尺寸应调整为 91x56，并且没有滚动条。
* **`TEST_F(WebViewTest, TextInputType)`:**
    * **假设输入:** 加载包含 `<input type="password">` 的 HTML。
    * **预期输出:** `WebView` 报告的文本输入类型应为 `kWebTextInputTypePassword`。

**用户或编程常见的使用错误及举例说明:**

* **设备仿真颜色错误缓存:** `TEST_F(WebViewTest, DeviceEmulationOutlineColor)` 检查了即使在启用设备仿真后更改了焦点环颜色，新的颜色也会正确应用，而不会错误地从缓存中获取旧的颜色。这是一个潜在的错误场景，用户可能会在启用设备仿真后期望看到新的颜色生效，但由于缓存问题导致显示不正确。
* **命中测试坐标转换错误:** `HitTestResultAtWithPageScale` 和相关的测试用例确保了在页面缩放和偏移的情况下，命中测试能够正确地将屏幕坐标转换为页面内部坐标，从而准确地找到对应的元素。如果坐标转换有误，用户的点击可能会错误地指向其他元素或没有元素。
* **自动调整大小逻辑错误:** `AutoResize` 相关的测试用例覆盖了各种边界情况，例如最小/最大尺寸的限制、内容溢出等。这些测试防止了在自动调整大小时出现计算错误，导致 `WebView` 的尺寸不符合预期或出现不必要的滚动条。
* **文本输入类型识别错误:** `TextInputType` 相关的测试用例确保了 `WebView` 能够正确地根据 HTML 属性识别不同的输入类型，这对于键盘的显示和输入行为至关重要。识别错误可能导致用户无法输入预期的内容。
* **输入法组合状态管理错误:** `FinishComposingTextDoesNotAssert` 和相关的测试用例确保了在处理输入法组合文本时，即使在页面布局发生变化的情况下，也不会出现断言错误或其他崩溃问题。这保证了输入法功能的稳定性和可靠性。

**用户操作如何一步步的到达这里，作为调试线索:**

以下是一些用户操作可能触发这些测试所覆盖功能的场景：

* **开发者工具中的设备模式:** 用户在浏览器开发者工具中切换到不同的设备模式，这会触发设备仿真的相关代码，例如 `EnableDeviceEmulation` 和 `DisableDeviceEmulation`。`DeviceEmulationOutlineColor` 测试就模拟了这种场景。
* **用户点击网页元素:** 用户在网页上点击不同的元素会触发命中测试的相关逻辑。例如，用户点击一个图片，`HitTestResultAtWithPageScale` 这样的测试会验证是否能正确识别点击的是图片元素。
* **网页内容动态变化导致尺寸变化:** 网页的内容可能会动态加载或改变，导致页面的实际渲染尺寸发生变化。如果 `WebView` 启用了自动调整大小功能，相关的代码会被触发，就像 `AutoResize` 系列的测试所模拟的那样。
* **用户聚焦到输入框:** 当用户点击或通过 Tab 键聚焦到网页上的输入框时，`WebView` 需要识别输入框的类型和属性，以便正确地处理用户的输入。`TextInputType`, `InputMode`, `InputAction` 等测试覆盖了这些场景。
* **用户使用输入法输入文本:** 用户在使用中文、日文等输入法时，会先输入拼音或假名等组合文本，然后再选择最终的字符。`FinishComposingTextDoesNotAssert`, `FinishComposingTextCursorPositionChange`, `SetCompositionForNewCaretPositions` 等测试覆盖了 `WebView` 处理输入法组合文本的逻辑。
* **用户在移动设备上长按屏幕:** 在移动设备上长按可能会触发上下文菜单或文本选择。`LongPressOutsideInputShouldNotSelectPlaceholderText` 测试确保了在这种情况下不会出现意外的文本选中行为。

**功能归纳 (第2部分):**

这部分 `web_view_test.cc` 代码主要集中在测试 `WebView` 在**渲染、用户交互和文本输入处理**方面的核心功能。它验证了设备仿真对样式的影响，用户点击事件的准确识别，`WebView` 根据内容自动调整大小的能力，以及对不同类型和属性的 HTML 输入元素的正确处理，特别是与输入法相关的交互。这些测试确保了 `WebView` 能够正确地呈现网页内容，响应用户操作，并提供可靠的文本输入功能。

Prompt: 
```
这是目录为blink/renderer/core/exported/web_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共9部分，请归纳一下它的功能

"""
bileLayoutThemeForTest mobile_layout_theme_enabled(true);
    LayoutTheme::GetTheme().SetCustomFocusRingColor(custom_color);
  }

  EXPECT_NE(custom_color, original);
  web_view_impl->EnableDeviceEmulation(params);

  // All <span>s should have the custom outline color, and not (for example)
  // the original color fetched from cache.
  auto* span2 = MakeGarbageCollected<HTMLSpanElement>(document);
  document.body()->AppendChild(span2);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(custom_color, OutlineColor(span1));
  EXPECT_EQ(custom_color, OutlineColor(span2));

  // Disable mobile emulation. All <span>s should once again have the
  // original outline color.
  web_view_impl->DisableDeviceEmulation();
  auto* span3 = MakeGarbageCollected<HTMLSpanElement>(document);
  document.body()->AppendChild(span3);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(original, OutlineColor(span1));
  EXPECT_EQ(original, OutlineColor(span2));
  EXPECT_EQ(original, OutlineColor(span3));
}

TEST_F(WebViewTest, ActiveState) {
  RegisterMockedHttpURLLoad("visible_iframe.html");
  WebView* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "visible_iframe.html");

  ASSERT_TRUE(web_view);

  web_view->SetIsActive(true);
  EXPECT_TRUE(web_view->IsActive());

  web_view->SetIsActive(false);
  EXPECT_FALSE(web_view->IsActive());

  web_view->SetIsActive(true);
  EXPECT_TRUE(web_view->IsActive());
}

TEST_F(WebViewTest, HitTestResultAtWithPageScale) {
  std::string url = base_url_ + "specify_size.html?" + "50px" + ":" + "50px";
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(url), test::CoreTestDataPath("specify_size.html"));
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  gfx::PointF hit_point(75, 75);

  // Image is at top left quandrant, so should not hit it.
  WebHitTestResult negative_result =
      web_view->MainFrameWidget()->HitTestResultAt(hit_point);
  EXPECT_FALSE(
      negative_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  negative_result.Reset();

  // Scale page up 2x so image should occupy the whole viewport.
  web_view->SetPageScaleFactor(2.0f);
  WebHitTestResult positive_result =
      web_view->MainFrameWidget()->HitTestResultAt(hit_point);
  EXPECT_TRUE(positive_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  positive_result.Reset();
}

TEST_F(WebViewTest, HitTestResultAtWithPageScaleAndPan) {
  std::string url = base_url_ + "specify_size.html?" + "50px" + ":" + "50px";
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(url), test::CoreTestDataPath("specify_size.html"));
  WebViewImpl* web_view = web_view_helper_.Initialize();
  LoadFrame(web_view->MainFrameImpl(), url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  gfx::PointF hit_point(75, 75);

  // Image is at top left quandrant, so should not hit it.
  WebHitTestResult negative_result =
      web_view->MainFrameWidget()->HitTestResultAt(hit_point);
  EXPECT_FALSE(
      negative_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  negative_result.Reset();

  // Scale page up 2x so image should occupy the whole viewport.
  web_view->SetPageScaleFactor(2.0f);
  WebHitTestResult positive_result =
      web_view->MainFrameWidget()->HitTestResultAt(hit_point);
  EXPECT_TRUE(positive_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  positive_result.Reset();

  // Pan around the zoomed in page so the image is not visible in viewport.
  web_view->SetVisualViewportOffset(gfx::PointF(100, 100));
  WebHitTestResult negative_result2 =
      web_view->MainFrameWidget()->HitTestResultAt(hit_point);
  EXPECT_FALSE(
      negative_result2.GetNode().To<WebElement>().HasHTMLTagName("img"));
  negative_result2.Reset();
}

TEST_F(WebViewTest, HitTestResultForTapWithTapArea) {
  std::string url = RegisterMockedHttpURLLoad("hit_test.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  gfx::Point hit_point(55, 55);

  // Image is at top left quandrant, so should not hit it.
  WebHitTestResult negative_result =
      web_view->MainFrameWidget()->HitTestResultAt(gfx::PointF(hit_point));
  EXPECT_FALSE(
      negative_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  negative_result.Reset();

  // The tap area is 20 by 20 square, centered at 55, 55.
  gfx::Size tap_area(20, 20);
  WebHitTestResult positive_result =
      web_view->HitTestResultForTap(hit_point, tap_area);
  EXPECT_TRUE(positive_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  positive_result.Reset();

  // Move the hit point the image is just outside the tapped area now.
  hit_point = gfx::Point(61, 61);
  WebHitTestResult negative_result2 =
      web_view->HitTestResultForTap(hit_point, tap_area);
  EXPECT_FALSE(
      negative_result2.GetNode().To<WebElement>().HasHTMLTagName("img"));
  negative_result2.Reset();
}

TEST_F(WebViewTest, HitTestResultForTapWithTapAreaPageScaleAndPan) {
  std::string url = RegisterMockedHttpURLLoad("hit_test.html");
  WebViewImpl* web_view = web_view_helper_.Initialize();
  LoadFrame(web_view->MainFrameImpl(), url);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(100, 100));
  gfx::Point hit_point(55, 55);

  // Image is at top left quandrant, so should not hit it.
  WebHitTestResult negative_result =
      web_view->MainFrameWidget()->HitTestResultAt(gfx::PointF(hit_point));
  EXPECT_FALSE(
      negative_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  negative_result.Reset();

  // The tap area is 20 by 20 square, centered at 55, 55.
  gfx::Size tap_area(20, 20);
  WebHitTestResult positive_result =
      web_view->HitTestResultForTap(hit_point, tap_area);
  EXPECT_TRUE(positive_result.GetNode().To<WebElement>().HasHTMLTagName("img"));
  positive_result.Reset();

  // Zoom in and pan around the page so the image is not visible in viewport.
  web_view->SetPageScaleFactor(2.0f);
  web_view->SetVisualViewportOffset(gfx::PointF(100, 100));
  WebHitTestResult negative_result2 =
      web_view->HitTestResultForTap(hit_point, tap_area);
  EXPECT_FALSE(
      negative_result2.GetNode().To<WebElement>().HasHTMLTagName("img"));
  negative_result2.Reset();
}

void WebViewTest::TestAutoResize(
    const gfx::Size& min_auto_resize,
    const gfx::Size& max_auto_resize,
    const std::string& page_width,
    const std::string& page_height,
    int expected_width,
    int expected_height,
    HorizontalScrollbarState expected_horizontal_state,
    VerticalScrollbarState expected_vertical_state) {
  AutoResizeWebViewClient client;
  std::string url =
      base_url_ + "specify_size.html?" + page_width + ":" + page_height;
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL(url), test::CoreTestDataPath("specify_size.html"));
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(url, nullptr, &client);
  client.GetTestData().SetWebView(web_view);

  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  LocalFrameView* frame_view = frame->GetFrame()->View();
  frame_view->UpdateStyleAndLayout();
  EXPECT_FALSE(frame_view->LayoutPending());
  EXPECT_FALSE(frame_view->NeedsLayout());

  web_view->EnableAutoResizeMode(min_auto_resize, max_auto_resize);
  EXPECT_TRUE(frame_view->LayoutPending());
  EXPECT_TRUE(frame_view->NeedsLayout());
  frame_view->UpdateStyleAndLayout();

  EXPECT_TRUE(frame->GetFrame()->GetDocument()->IsHTMLDocument());

  EXPECT_EQ(expected_width, client.GetTestData().Width());
  EXPECT_EQ(expected_height, client.GetTestData().Height());

// Android disables main frame scrollbars.
#if !BUILDFLAG(IS_ANDROID)
  EXPECT_EQ(expected_horizontal_state,
            client.GetTestData().GetHorizontalScrollbarState());
  EXPECT_EQ(expected_vertical_state,
            client.GetTestData().GetVerticalScrollbarState());
#endif

  // Explicitly reset to break dependency on locally scoped client.
  web_view_helper_.Reset();
}

TEST_F(WebViewTest, AutoResizeMinimumSize) {
  gfx::Size min_auto_resize(91, 56);
  gfx::Size max_auto_resize(403, 302);
  std::string page_width = "91px";
  std::string page_height = "56px";
  int expected_width = 91;
  int expected_height = 56;
  TestAutoResize(min_auto_resize, max_auto_resize, page_width, page_height,
                 expected_width, expected_height, kNoHorizontalScrollbar,
                 kNoVerticalScrollbar);
}

TEST_F(WebViewTest, AutoResizeHeightOverflowAndFixedWidth) {
  gfx::Size min_auto_resize(90, 95);
  gfx::Size max_auto_resize(90, 100);
  std::string page_width = "60px";
  std::string page_height = "200px";
  int expected_width = 90;
  int expected_height = 100;
  TestAutoResize(min_auto_resize, max_auto_resize, page_width, page_height,
                 expected_width, expected_height, kNoHorizontalScrollbar,
                 kVisibleVerticalScrollbar);
}

TEST_F(WebViewTest, AutoResizeFixedHeightAndWidthOverflow) {
  gfx::Size min_auto_resize(90, 100);
  gfx::Size max_auto_resize(200, 100);
  std::string page_width = "300px";
  std::string page_height = "80px";
  int expected_width = 200;
  int expected_height = 100;
  TestAutoResize(min_auto_resize, max_auto_resize, page_width, page_height,
                 expected_width, expected_height, kVisibleHorizontalScrollbar,
                 kNoVerticalScrollbar);
}

// Next three tests disabled for https://bugs.webkit.org/show_bug.cgi?id=92318 .
// It seems we can run three AutoResize tests, then the next one breaks.
TEST_F(WebViewTest, AutoResizeInBetweenSizes) {
  gfx::Size min_auto_resize(90, 95);
  gfx::Size max_auto_resize(200, 300);
  std::string page_width = "100px";
  std::string page_height = "200px";
  int expected_width = 100;
  int expected_height = 200;
  TestAutoResize(min_auto_resize, max_auto_resize, page_width, page_height,
                 expected_width, expected_height, kNoHorizontalScrollbar,
                 kNoVerticalScrollbar);
}

TEST_F(WebViewTest, AutoResizeOverflowSizes) {
  gfx::Size min_auto_resize(90, 95);
  gfx::Size max_auto_resize(200, 300);
  std::string page_width = "300px";
  std::string page_height = "400px";
  int expected_width = 200;
  int expected_height = 300;
  TestAutoResize(min_auto_resize, max_auto_resize, page_width, page_height,
                 expected_width, expected_height, kVisibleHorizontalScrollbar,
                 kVisibleVerticalScrollbar);
}

TEST_F(WebViewTest, AutoResizeMaxSize) {
  gfx::Size min_auto_resize(90, 95);
  gfx::Size max_auto_resize(200, 300);
  std::string page_width = "200px";
  std::string page_height = "300px";
  int expected_width = 200;
  int expected_height = 300;
  TestAutoResize(min_auto_resize, max_auto_resize, page_width, page_height,
                 expected_width, expected_height, kNoHorizontalScrollbar,
                 kNoVerticalScrollbar);
}

void WebViewTest::TestTextInputType(WebTextInputType expected_type,
                                    const std::string& html_file) {
  RegisterMockedHttpURLLoad(html_file);
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + html_file);
  WebInputMethodController* controller =
      web_view->MainFrameImpl()->GetInputMethodController();
  EXPECT_EQ(kWebTextInputTypeNone, controller->TextInputType());
  EXPECT_EQ(kWebTextInputTypeNone, controller->TextInputInfo().type);
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  EXPECT_EQ(expected_type, controller->TextInputType());
  EXPECT_EQ(expected_type, controller->TextInputInfo().type);
  web_view->FocusedElement()->blur();
  EXPECT_EQ(kWebTextInputTypeNone, controller->TextInputType());
  EXPECT_EQ(kWebTextInputTypeNone, controller->TextInputInfo().type);
}

TEST_F(WebViewTest, TextInputType) {
  TestTextInputType(kWebTextInputTypeText, "input_field_default.html");
  TestTextInputType(kWebTextInputTypePassword, "input_field_password.html");
  TestTextInputType(kWebTextInputTypeEmail, "input_field_email.html");
  TestTextInputType(kWebTextInputTypeSearch, "input_field_search.html");
  TestTextInputType(kWebTextInputTypeNumber, "input_field_number.html");
  TestTextInputType(kWebTextInputTypeTelephone, "input_field_tel.html");
  TestTextInputType(kWebTextInputTypeURL, "input_field_url.html");
}

TEST_F(WebViewTest, TextInputInfoUpdateStyleAndLayout) {
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.Initialize();

  WebURL base_url = url_test_helpers::ToKURL("http://example.com/");
  // Here, we need to construct a document that has a special property:
  // Adding id="foo" to the <path> element will trigger creation of an SVG
  // instance tree for the use <use> element.
  // This is significant, because SVG instance trees are actually created lazily
  // during Document::updateStyleAndLayout code, thus incrementing the DOM tree
  // version and freaking out the EphemeralRange (invalidating it).
  frame_test_helpers::LoadHTMLString(
      web_view_impl->MainFrameImpl(),
      "<svg height='100%' version='1.1' viewBox='0 0 14 14' width='100%'>"
      "<use xmlns:xlink='http://www.w3.org/1999/xlink' xlink:href='#foo'></use>"
      "<path d='M 100 100 L 300 100 L 200 300 z' fill='#000'></path>"
      "</svg>"
      "<input>",
      base_url);
  web_view_impl->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  // Add id="foo" to <path>, thus triggering the condition described above.
  Document* document =
      web_view_impl->MainFrameImpl()->GetFrame()->GetDocument();
  document->body()
      ->QuerySelector(AtomicString("path"), ASSERT_NO_EXCEPTION)
      ->SetIdAttribute(AtomicString("foo"));

  // This should not DCHECK.
  EXPECT_EQ(kWebTextInputTypeText, web_view_impl->MainFrameImpl()
                                       ->GetInputMethodController()
                                       ->TextInputInfo()
                                       .type);
}

void WebViewTest::TestInputMode(WebTextInputMode expected_input_mode,
                                const std::string& html_file) {
  RegisterMockedHttpURLLoad(html_file);
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + html_file);
  web_view_impl->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  EXPECT_EQ(expected_input_mode, web_view_impl->MainFrameImpl()
                                     ->GetInputMethodController()
                                     ->TextInputInfo()
                                     .input_mode);
}

TEST_F(WebViewTest, InputMode) {
  TestInputMode(WebTextInputMode::kWebTextInputModeDefault,
                "input_mode_default.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeDefault,
                "input_mode_default_unknown.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeNone,
                "input_mode_type_none.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeText,
                "input_mode_type_text.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeTel,
                "input_mode_type_tel.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeUrl,
                "input_mode_type_url.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeEmail,
                "input_mode_type_email.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeNumeric,
                "input_mode_type_numeric.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeDecimal,
                "input_mode_type_decimal.html");
  TestInputMode(WebTextInputMode::kWebTextInputModeSearch,
                "input_mode_type_search.html");
}

void WebViewTest::TestInputAction(ui::TextInputAction expected_input_action,
                                  const std::string& html_file) {
  RegisterMockedHttpURLLoad(html_file);
  WebViewImpl* web_view_impl =
      web_view_helper_.InitializeAndLoad(base_url_ + html_file);
  web_view_impl->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  EXPECT_EQ(expected_input_action, web_view_impl->MainFrameImpl()
                                       ->GetInputMethodController()
                                       ->TextInputInfo()
                                       .action);
}

TEST_F(WebViewTest, TextInputAction) {
  TestInputAction(ui::TextInputAction::kDefault, "enter_key_hint_default.html");
  TestInputAction(ui::TextInputAction::kDefault,
                  "enter_key_hint_default_unknown.html");
  TestInputAction(ui::TextInputAction::kEnter, "enter_key_hint_enter.html");
  TestInputAction(ui::TextInputAction::kGo, "enter_key_hint_go.html");
  TestInputAction(ui::TextInputAction::kDone, "enter_key_hint_done.html");
  TestInputAction(ui::TextInputAction::kNext, "enter_key_hint_next.html");
  TestInputAction(ui::TextInputAction::kPrevious,
                  "enter_key_hint_previous.html");
  TestInputAction(ui::TextInputAction::kSearch, "enter_key_hint_search.html");
  TestInputAction(ui::TextInputAction::kSend, "enter_key_hint_send.html");
  TestInputAction(ui::TextInputAction::kNext, "enter_key_hint_mixed_case.html");
}

TEST_F(WebViewTest, TextInputInfoWithReplacedElements) {
  std::string url = RegisterMockedHttpURLLoad("div_with_image.html");
  url_test_helpers::RegisterMockedURLLoad(
      ToKURL("http://www.test.com/foo.png"),
      test::CoreTestDataPath("white-1x1.png"));
  WebViewImpl* web_view_impl = web_view_helper_.InitializeAndLoad(url);
  web_view_impl->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebTextInputInfo info = web_view_impl->MainFrameImpl()
                              ->GetInputMethodController()
                              ->TextInputInfo();

  EXPECT_EQ("foo\xef\xbf\xbc", info.value.Utf8());
}

TEST_F(WebViewTest, SetEditableSelectionOffsetsAndTextInputInfo) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebLocalFrameImpl* frame = web_view->MainFrameImpl();
  WebInputMethodController* active_input_method_controller =
      frame->GetInputMethodController();
  frame->SetEditableSelectionOffsets(5, 13);
  EXPECT_EQ("56789abc", frame->SelectionAsText());
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("0123456789abcdefghijklmnopqrstuvwxyz", info.value);
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(13, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  RegisterMockedHttpURLLoad("content_editable_populated.html");
  web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "content_editable_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  frame = web_view->MainFrameImpl();
  active_input_method_controller = frame->GetInputMethodController();
  frame->SetEditableSelectionOffsets(8, 19);
  EXPECT_EQ("89abcdefghi", frame->SelectionAsText());
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("0123456789abcdefghijklmnopqrstuvwxyz", info.value);
  EXPECT_EQ(8, info.selection_start);
  EXPECT_EQ(19, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
}

// Regression test for crbug.com/663645
TEST_F(WebViewTest, FinishComposingTextDoesNotAssert) {
  RegisterMockedHttpURLLoad("input_field_default.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_default.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();

  // The test requires non-empty composition.
  std::string composition_text("hello");
  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      5, 5);

  // Do arbitrary change to make layout dirty.
  Document& document = *web_view->MainFrameImpl()->GetFrame()->GetDocument();
  Element* br = document.CreateRawElement(html_names::kBrTag);
  document.body()->AppendChild(br);

  // Should not hit assertion when calling
  // WebInputMethodController::finishComposingText with non-empty composition
  // and dirty layout.
  active_input_method_controller->FinishComposingText(
      WebInputMethodController::kKeepSelection);
}

// Regression test for https://crbug.com/873999
TEST_F(WebViewTest, LongPressOutsideInputShouldNotSelectPlaceholderText) {
  RegisterMockedHttpURLLoad("input_placeholder.html");
  WebViewImpl* web_view =
      web_view_helper_.InitializeAndLoad(base_url_ + "input_placeholder.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  web_view->MainFrameViewWidget()->Resize(gfx::Size(500, 300));
  UpdateAllLifecyclePhases();
  RunPendingTasks();

  WebString input_id = WebString::FromUTF8("input");

  // Focus in input.
  EXPECT_TRUE(
      SimulateGestureAtElementById(WebInputEvent::Type::kGestureTap, input_id));

  // Long press below input.
  WebGestureEvent event(WebInputEvent::Type::kGestureLongPress,
                        WebInputEvent::kNoModifiers,
                        WebInputEvent::GetStaticTimeStampForTests(),
                        WebGestureDevice::kTouchscreen);
  event.SetPositionInWidget(gfx::PointF(100, 150));
  EXPECT_EQ(WebInputEventResult::kHandledSystem,
            web_view->MainFrameWidget()->HandleInputEvent(
                WebCoalescedInputEvent(event, ui::LatencyInfo())));
  EXPECT_TRUE(web_view->MainFrameImpl()->SelectionAsText().IsEmpty());
}

TEST_F(WebViewTest, FinishComposingTextCursorPositionChange) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);

  // Set up a composition that needs to be committed.
  std::string composition_text("hello");

  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();
  WebVector<ui::ImeTextSpan> empty_ime_text_spans;
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      3, 3);

  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello", info.value.Utf8());
  EXPECT_EQ(3, info.selection_start);
  EXPECT_EQ(3, info.selection_end);
  EXPECT_EQ(0, info.composition_start);
  EXPECT_EQ(5, info.composition_end);

  active_input_method_controller->FinishComposingText(
      WebInputMethodController::kKeepSelection);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(3, info.selection_start);
  EXPECT_EQ(3, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      3, 3);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helhellolo", info.value.Utf8());
  EXPECT_EQ(6, info.selection_start);
  EXPECT_EQ(6, info.selection_end);
  EXPECT_EQ(3, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  active_input_method_controller->FinishComposingText(
      WebInputMethodController::kDoNotKeepSelection);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ(8, info.selection_start);
  EXPECT_EQ(8, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
}

TEST_F(WebViewTest, SetCompositionForNewCaretPositions) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;

  active_input_method_controller->CommitText("hello", empty_ime_text_spans,
                                             WebRange(), 0);
  active_input_method_controller->CommitText("world", empty_ime_text_spans,
                                             WebRange(), -5);
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();

  EXPECT_EQ("helloworld", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Set up a composition that needs to be committed.
  std::string composition_text("ABC");

  // Caret is on the left of composing text.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      0, 0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  // Caret is on the right of composing text.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      3, 3);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(8, info.selection_start);
  EXPECT_EQ(8, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  // Caret is between composing text and left boundary.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      -2, -2);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(3, info.selection_start);
  EXPECT_EQ(3, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  // Caret is between composing text and right boundary.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      5, 5);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(10, info.selection_start);
  EXPECT_EQ(10, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  // Caret is on the left boundary.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      -5, -5);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  // Caret is on the right boundary.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      8, 8);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(13, info.selection_start);
  EXPECT_EQ(13, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  // Caret exceeds the left boundary.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      -100, -100);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);

  // Caret exceeds the right boundary.
  active_input_method_controller->SetComposition(
      WebString::FromUTF8(composition_text), empty_ime_text_spans, WebRange(),
      100, 100);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("helloABCworld", info.value.Utf8());
  EXPECT_EQ(13, info.selection_start);
  EXPECT_EQ(13, info.selection_end);
  EXPECT_EQ(5, info.composition_start);
  EXPECT_EQ(8, info.composition_end);
}

TEST_F(WebViewTest, SetCompositionWithEmptyText) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;

  active_input_method_controller->CommitText("hello", empty_ime_text_spans,
                                             WebRange(), 0);
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();

  EXPECT_EQ("hello", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  active_input_method_controller->SetComposition(
      WebString::FromUTF8(""), empty_ime_text_spans, WebRange(), 0, 0);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello", info.value.Utf8());
  EXPECT_EQ(5, info.selection_start);
  EXPECT_EQ(5, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  active_input_method_controller->SetComposition(
      WebString::FromUTF8(""), empty_ime_text_spans, WebRange(), -2, -2);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("hello", info.value.Utf8());
  EXPECT_EQ(3, info.selection_start);
  EXPECT_EQ(3, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);
}

TEST_F(WebViewTest, CommitTextForNewCaretPositions) {
  RegisterMockedHttpURLLoad("input_field_populated.html");
  WebViewImpl* web_view = web_view_helper_.InitializeAndLoad(
      base_url_ + "input_field_populated.html");
  web_view->MainFrameImpl()->GetFrame()->SetInitialFocus(false);
  WebInputMethodController* active_input_method_controller =
      web_view->MainFrameImpl()
          ->FrameWidget()
          ->GetActiveWebInputMethodController();

  WebVector<ui::ImeTextSpan> empty_ime_text_spans;

  // Caret is on the left of composing text.
  active_input_method_controller->CommitText("ab", empty_ime_text_spans,
                                             WebRange(), -2);
  WebTextInputInfo info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("ab", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Caret is on the right of composing text.
  active_input_method_controller->CommitText("c", empty_ime_text_spans,
                                             WebRange(), 1);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("cab", info.value.Utf8());
  EXPECT_EQ(2, info.selection_start);
  EXPECT_EQ(2, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Caret is on the left boundary.
  active_input_method_controller->CommitText("def", empty_ime_text_spans,
                                             WebRange(), -5);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("cadefb", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Caret is on the right boundary.
  active_input_method_controller->CommitText("g", empty_ime_text_spans,
                                             WebRange(), 6);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("gcadefb", info.value.Utf8());
  EXPECT_EQ(7, info.selection_start);
  EXPECT_EQ(7, info.selection_end);
  EXPECT_EQ(-1, info.composition_start);
  EXPECT_EQ(-1, info.composition_end);

  // Caret exceeds the left boundary.
  active_input_method_controller->CommitText("hi", empty_ime_text_spans,
                                             WebRange(), -100);
  info = active_input_method_controller->TextInputInfo();
  EXPECT_EQ("gcadefbhi", info.value.Utf8());
  EXPECT_EQ(0, info.selection_start);
  EXPECT_EQ(0, inf
"""


```