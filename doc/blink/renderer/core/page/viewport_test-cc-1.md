Response:
The user wants to understand the functionality of the provided C++ code snippet from `viewport_test.cc`. This is the second part of a five-part file.

My plan is to:
1. **Identify the core functionality:** The code consists of multiple test cases within the `ViewportTest` class. Each test case loads an HTML file (e.g., `viewport-42.html`) and then uses `RunViewportTest` to get `PageScaleConstraints`. The tests then assert the expected values for `layout_size`, `initial_scale`, `minimum_scale`, `maximum_scale`, and `user_zoom`.
2. **Explain the relationship with web technologies:** These tests are specifically designed to verify how Blink (the rendering engine) interprets and applies the viewport meta tag in HTML. The assertions directly relate to the properties defined within the viewport meta tag.
3. **Provide examples for JavaScript, HTML, and CSS:** I'll demonstrate how the viewport meta tag in HTML influences the behavior tested in the C++ code.
4. **Give examples of logical reasoning:** I can show how the input HTML (specifically the viewport meta tag) leads to the asserted output `PageScaleConstraints`.
5. **Illustrate common user/programming errors:**  I'll explain mistakes users make when setting viewport properties and how these tests could catch such errors.
6. **Explain the user journey for debugging:** I'll outline the steps a developer would take to reach this code during debugging, focusing on issues related to viewport behavior.
7. **Summarize the function of this specific part:** I will condense the above points into a concise summary focusing on the fact that this part of the file contains tests specifically for validating viewport meta tag parsing and application.
```cpp
t_size.height());
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
```

这是 `blink/renderer/core/page/viewport_test.cc` 文件的第二部分，延续了第一部分的内容。

**功能归纳：**

这部分代码主要功能是包含了一系列针对不同 HTML 文件中 `<meta name="viewport">` 标签的测试用例。每个测试用例都加载一个特定的 HTML 文件（例如 `viewport/viewport-42.html`），然后运行一个 `RunViewportTest` 函数来获取该页面计算出的视口约束 (`PageScaleConstraints`)。接着，测试用例会使用 `EXPECT_EQ` 和 `EXPECT_NEAR` 等断言来验证计算出的视口属性，例如布局大小 (`layout_size`)、初始缩放 (`initial_scale`)、最小缩放 (`minimum_scale`)、最大缩放 (`maximum_scale`) 以及用户是否可以缩放 (`user_zoom`) 是否与预期一致。

**与 JavaScript, HTML, CSS 的关系：**

这部分测试代码直接关联 HTML 的 `<meta name="viewport">` 标签。这个标签允许网页开发者控制网页在不同设备上的显示方式，包括视口的宽度、初始缩放级别、是否允许用户缩放等。

*   **HTML:** 每个 `TEST_F` 函数都加载一个特定的 HTML 文件，这些 HTML 文件是测试的输入。HTML 文件中包含 `<meta name="viewport" ...>` 标签，其内容定义了被测试的视口配置。例如，`viewport-42.html` 可能包含类似 `<meta name="viewport" content="width=320, initial-scale=2.0">` 的内容。
*   **CSS:** 虽然这段代码本身不直接操作 CSS，但视口设置会影响 CSS 的布局计算和媒体查询的行为。例如，如果视口宽度被设置为 `device-width`，那么 CSS 中的媒体查询可以根据设备的实际宽度来应用不同的样式。
*   **JavaScript:** JavaScript 可以读取和修改视口相关的属性（尽管直接修改视口 meta 标签比较复杂）。这段测试代码验证了 Blink 引擎对 HTML 中声明的视口元数据的解析和应用，而 JavaScript 代码的行为会受到这些视口设置的影响。例如，JavaScript 获取屏幕尺寸或滚动位置时，会受到视口大小和缩放的影响。

**逻辑推理的举例说明：**

**假设输入 (viewport-42.html):**

```html
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=1000, initial-scale=2.0">
    <title>Viewport Test 42</title>
</head>
<body>
  Content
</body>
</html>
```

**预期输出 (来自 `TEST_F(ViewportTest, viewport42)`):**

```
EXPECT_EQ(320, constraints.layout_size.width());
EXPECT_EQ(1000, constraints.layout_size.height());
EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
EXPECT_TRUE(page->GetViewportDescription().user_zoom);
```

**推理过程:**

1. HTML 中指定了 `width=1000`，这意味着布局宽度应该被设置为 1000 像素。
2. `initial-scale=2.0` 指定了初始缩放级别为 2.0。
3. 代码中的 `RunViewportTest(page, 320, 352)` 传入了设备的屏幕宽度为 320 像素。
4. Blink 引擎会根据 HTML 中的视口设置和设备屏幕宽度，计算出最终的视口约束。
5. 由于指定了 `width=1000` 和 `initial-scale=2.0`，当设备宽度为 320 时，为了显示 1000 像素的布局宽度，初始缩放会设置为 2.0。
6. 默认情况下，最小缩放通常是 1.0，最大缩放是 5.0，除非在 meta 标签中显式指定。
7. `user-zoom` 默认为 `yes`，除非显式设置为 `no`。

**用户或编程常见的使用错误举例说明：**

1. **错误地设置 `width` 为 `device-width`，但忘记设置 `initial-scale`：**  如果 HTML 中只有 `<meta name="viewport" content="width=device-width">`，可能会导致在不同设备上初始缩放级别不一致，用户可能需要手动缩放才能看到完整的内容。这段测试会确保在没有显式 `initial-scale` 时，引擎会做出合理的默认行为。
2. **将 `minimum-scale` 设置为大于 `maximum-scale` 的值：** 这是一个明显的逻辑错误，会导致浏览器行为不确定。这段测试可能会覆盖到这种情况，确保引擎能够正确处理或忽略这种无效的配置。
3. **忘记设置 `user-scalable=no` 来禁用用户缩放，导致布局在某些情况下显示不佳：** 开发者可能希望禁用用户缩放以防止布局错乱，但如果忘记设置，用户可能会意外缩放，破坏页面的呈现。这段测试通过检查 `page->GetViewportDescription().user_zoom` 来验证是否正确解析了 `user-scalable` 属性。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设开发者发现一个网页在特定移动设备上显示不正常，例如初始缩放级别错误或无法进行用户缩放。调试过程可能如下：

1. **用户反馈/Bug 报告：** 用户报告网页在他们的手机上看起来很小或者很大，或者无法放大缩小。
2. **开发者复现问题：** 开发者尝试在自己的设备或模拟器上复现问题。
3. **检查 HTML 源代码：** 开发者会查看网页的 HTML 源代码，特别是 `<meta name="viewport">` 标签，查看其配置是否正确。
4. **使用开发者工具：** 开发者可以使用浏览器开发者工具的 "Elements" 或 "Application" 面板，查看当前页面的视口设置。有些浏览器会显示解析后的视口信息。
5. **修改视口设置进行实验：** 开发者可能会尝试修改 `<meta name="viewport">` 的内容，刷新页面，观察变化。
6. **查看 Blink 源代码 (如果需要深入分析)：** 如果问题仍然存在，并且怀疑是浏览器引擎的解析或应用逻辑有问题，开发者可能会查看 Blink 引擎的源代码，例如 `viewport_test.cc` 或相关的视口处理代码。
7. **运行或分析测试用例：** 开发者可以找到相关的测试用例（例如这段代码），查看这些测试用例覆盖了哪些场景，以及预期行为是什么。如果怀疑是 Blink 的 bug，开发者甚至可以修改或添加新的测试用例来重现和验证问题。
8. **断点调试：** 开发者可能会在 Blink 源代码中设置断点，例如在视口 meta 标签解析或约束计算的地方，来单步执行代码，查看变量的值，以便理解引擎是如何处理特定的视口配置的。

总而言之，这部分代码是 Blink 引擎中用于测试视口功能的重要组成部分，它通过加载不同的 HTML 文件并断言计算出的视口约束，确保引擎能够正确解析和应用开发者在 HTML 中定义的视口配置，从而保证网页在不同设备上的良好显示效果。

### 提示词
```
这是目录为blink/renderer/core/page/viewport_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
t_size.height());
  EXPECT_NEAR(0.5f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.32f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport42) {
  RegisterMockedHttpURLLoad("viewport/viewport-42.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-42.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(1000, constraints.layout_size.height());
  EXPECT_NEAR(2.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport43) {
  RegisterMockedHttpURLLoad("viewport/viewport-43.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-43.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(64, constraints.layout_size.width());
  EXPECT_NEAR(70.4, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport44) {
  RegisterMockedHttpURLLoad("viewport/viewport-44.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-44.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(10000, constraints.layout_size.width());
  EXPECT_EQ(10000, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport45) {
  RegisterMockedHttpURLLoad("viewport/viewport-45.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-45.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(3200, constraints.layout_size.width());
  EXPECT_EQ(3520, constraints.layout_size.height());
  EXPECT_NEAR(0.1f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.1f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(0.1f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport46) {
  RegisterMockedHttpURLLoad("viewport/viewport-46.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-46.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(32, constraints.layout_size.width());
  EXPECT_NEAR(35.2, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport47) {
  RegisterMockedHttpURLLoad("viewport/viewport-47.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-47.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(3000, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport48) {
  RegisterMockedHttpURLLoad("viewport/viewport-48.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-48.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(3000, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport49) {
  RegisterMockedHttpURLLoad("viewport/viewport-49.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-49.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport50) {
  RegisterMockedHttpURLLoad("viewport/viewport-50.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-50.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport51) {
  RegisterMockedHttpURLLoad("viewport/viewport-51.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-51.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport52) {
  RegisterMockedHttpURLLoad("viewport/viewport-52.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-52.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport53) {
  RegisterMockedHttpURLLoad("viewport/viewport-53.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-53.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport54) {
  RegisterMockedHttpURLLoad("viewport/viewport-54.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-54.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport55) {
  RegisterMockedHttpURLLoad("viewport/viewport-55.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-55.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport56) {
  RegisterMockedHttpURLLoad("viewport/viewport-56.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-56.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(1078, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport57) {
  RegisterMockedHttpURLLoad("viewport/viewport-57.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-57.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport58) {
  RegisterMockedHttpURLLoad("viewport/viewport-58.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-58.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(3200, constraints.layout_size.width());
  EXPECT_EQ(3520, constraints.layout_size.height());
  EXPECT_NEAR(0.1f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.1f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport59) {
  RegisterMockedHttpURLLoad("viewport/viewport-59.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-59.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport60) {
  RegisterMockedHttpURLLoad("viewport/viewport-60.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-60.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(32, constraints.layout_size.width());
  EXPECT_NEAR(35.2, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport61) {
  RegisterMockedHttpURLLoad("viewport/viewport-61.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-61.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport62) {
  RegisterMockedHttpURLLoad("viewport/viewport-62.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-62.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport63) {
  RegisterMockedHttpURLLoad("viewport/viewport-63.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-63.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport64) {
  RegisterMockedHttpURLLoad("viewport/viewport-64.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-64.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport65) {
  RegisterMockedHttpURLLoad("viewport/viewport-65.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-65.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport66) {
  RegisterMockedHttpURLLoad("viewport/viewport-66.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-66.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport67) {
  RegisterMockedHttpURLLoad("viewport/viewport-67.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-67.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport68) {
  RegisterMockedHttpURLLoad("viewport/viewport-68.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-68.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport69) {
  RegisterMockedHttpURLLoad("viewport/viewport-69.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-69.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport70) {
  RegisterMockedHttpURLLoad("viewport/viewport-70.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-70.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport71) {
  RegisterMockedHttpURLLoad("viewport/viewport-71.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-71.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport72) {
  RegisterMockedHttpURLLoad("viewport/viewport-72.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-72.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport73) {
  RegisterMockedHttpURLLoad("viewport/viewport-73.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-73.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport74) {
  RegisterMockedHttpURLLoad("viewport/viewport-74.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-74.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport75) {
  RegisterMockedHttpURLLoad("viewport/viewport-75.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-75.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(64, constraints.layout_size.width());
  EXPECT_NEAR(70.4, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(5.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport76) {
  RegisterMockedHttpURLLoad("viewport/viewport-76.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-76.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(32, constraints.layout_size.width());
  EXPECT_NEAR(35.2, constraints.layout_size.height(), 0.01);
  EXPECT_NEAR(10.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(10.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport77) {
  RegisterMockedHttpURLLoad("viewport/viewport-77.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-77.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(1280, constraints.layout_size.width());
  EXPECT_EQ(1408, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport78) {
  RegisterMockedHttpURLLoad("viewport/viewport-78.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-78.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(100, constraints.layout_size.width());
  EXPECT_EQ(110, constraints.layout_size.height());
  EXPECT_NEAR(3.2f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(3.2f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport79) {
  RegisterMockedHttpURLLoad("viewport/viewport-79.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-79.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport80) {
  RegisterMockedHttpURLLoad("viewport/viewport-80.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-80.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(320, constraints.layout_size.width());
  EXPECT_EQ(352, constraints.layout_size.height());
  EXPECT_NEAR(1.0f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(1.0f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport81) {
  RegisterMockedHttpURLLoad("viewport/viewport-81.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-81.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(3000, constraints.layout_size.width());
  EXPECT_EQ(3300, constraints.layout_size.height());
  EXPECT_NEAR(0.25f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.25f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport82) {
  RegisterMockedHttpURLLoad("viewport/viewport-82.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-82.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(400, constraints.layout_size.width());
  EXPECT_EQ(440, constraints.layout_size.height());
  EXPECT_NEAR(0.8f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.8f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport83) {
  RegisterMockedHttpURLLoad("viewport/viewport-83.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-83.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_NEAR(1078, constraints.layout_size.height(), 0.01f);
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_scale, 0.01f);
  EXPECT_NEAR(5.0f, constraints.maximum_scale, 0.01f);
  EXPECT_TRUE(page->GetViewportDescription().user_zoom);
}

TEST_F(ViewportTest, viewport84) {
  RegisterMockedHttpURLLoad("viewport/viewport-84.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "viewport/viewport-84.html",
                                    nullptr, nullptr, SetViewportSettings);

  Page* page = web_view_helper.GetWebView()->GetPage();
  PageScaleConstraints constraints = RunViewportTest(page, 320, 352);

  EXPECT_EQ(980, constraints.layout_size.width());
  EXPECT_EQ(480, constraints.layout_size.height());
  EXPECT_NEAR(0.33f, constraints.initial_scale, 0.01f);
  EXPECT_NEAR(0.33f, constraints.minimum_
```