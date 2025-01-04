Response:
The user wants to understand the functionality of the provided C++ code snippet from `web_frame_test.cc`. This file seems to contain unit tests for the `WebFrame` class in the Chromium Blink engine.

Here's a breakdown of how to approach the request:

1. **Identify the core functionality:**  The code consists of several `TEST_P` and `TEST_F` blocks. These are Google Test macros indicating individual test cases. The test names provide hints about what's being tested.

2. **Analyze individual test cases:**  For each test case, understand what scenario it's setting up and what it's verifying (using `EXPECT_CALL`, `EXPECT_TRUE`, `ExpectOverscrollParams`, `EXPECT_EQ`).

3. **Look for connections to web technologies:** Determine if a test relates to JavaScript (e.g., `ExecuteScript`), HTML (e.g., creating iframe elements, manipulating styles), or CSS (e.g., `overscroll-behavior`).

4. **Infer logic and assumptions:**  For tests involving scrolling and overscroll, deduce the expected behavior based on the input scroll deltas and the assertions made. Consider the role of compositing (`CompositeForTest`).

5. **Identify potential user/programming errors:** Consider scenarios where the tested behavior might prevent or be caused by incorrect usage of web APIs or browser features.

6. **Aggregate and summarize:** Combine the findings from the individual test cases to provide a high-level overview of the file's purpose.

7. **Pay attention to the "part 15 of 19" instruction:**  This suggests the file focuses on a specific set of features related to `WebFrame`. The surrounding parts likely cover other aspects.

**Detailed analysis of the provided snippet:**

* **`WebFrameOverscrollTest`:**  This parameterized test suite focuses on overscroll behavior. It checks how the browser handles scrolling beyond the normal boundaries of a page or element.
    * Tests for root layer overscroll.
    * Tests for overscroll when nested elements (divs, iframes) are involved.
    * Tests for overscroll behavior on scaled pages.
    * Tests for handling small scroll values and preventing spurious overscroll events.
    * Tests for the `overscroll-behavior` CSS property and its effect on event propagation.
* **`WebFrameTest`:** This test suite covers various `WebFrame` functionalities.
    * `OrientationFrameDetach`:  Likely tests how orientation change events are handled when frames are detached.
    * `MaxFrames`: Checks the enforcement of the maximum number of frames allowed in a page.
    * `RotatedIframeViewportIntersection`: Tests how viewport intersection calculations work for rotated iframes.
    * `ImageDocumentLoadResponseEnd`: Tests the timing of resource loading for image documents.
    * `CopyImageDocument`: Tests the "Copy" command functionality for image documents.
    * `CopyTextInImageDocument`: Tests the "Copy" command when text content is added to an image document.
    * `ImeSelectionCommitDoesNotChangeClipboard`: Tests that IME composition commit doesn't unintentionally trigger clipboard changes.
* **`WebRemoteFrameVisibilityChangeTest` and `WebLocalFrameVisibilityChangeTest`:** These test suites focus on how the visibility state of remote and local frames is communicated and updated based on CSS properties and scrolling.

**Key observations related to web technologies:**

* **JavaScript interaction:** The tests use `ExecuteScript` to manipulate the DOM (e.g., setting styles, creating elements).
* **HTML structure:** The tests use HTML concepts like `iframe`, `div`, and document structure.
* **CSS properties:** The `overscroll-behavior` CSS property is explicitly tested. The tests also manipulate `display` and other style properties to affect visibility.

**Hypothetical Input and Output (for overscroll tests):**

* **Input:** A user performs a scroll gesture on a webpage with `overscroll-behavior: auto`. The scroll amount exceeds the scrollable boundary.
* **Output:** The browser reports an overscroll event with specific deltas and coordinates, as verified by `ExpectOverscrollParams`.

**Common User/Programming Errors:**

* **Incorrect `overscroll-behavior` usage:**  A developer might incorrectly set `overscroll-behavior: none` on an element, preventing desired overscroll effects.
* **Assuming overscroll always bubbles:** The tests demonstrate that `overscroll-behavior: none` in a subframe can prevent overscroll from reaching the main frame.
* **Not accounting for page scale:** The test `ScaledPageRootLayerOverscrolled` highlights that overscroll calculations need to consider the page zoom level.

By combining these observations, we can provide a comprehensive summary of the code's functionality.
这是目录为`blink/renderer/core/frame/web_frame_test.cc`的 Chromium Blink 引擎源代码文件的第 15 部分，共 19 部分。根据提供的代码片段，本部分主要关注 `WebFrame` 的以下功能和测试：

**核心功能：Overscroll 行为测试 (Overscroll Behavior)**

这一部分主要集中测试 `WebFrame` 对 **Overscroll** 行为的处理。 Overscroll 指的是用户滚动操作超出可滚动区域边界时的行为，常见于移动设备，可以触发一些特定的反馈效果，例如页面回弹。

**具体测试的功能点包括：**

* **根元素 Overscroll (Root Layer Overscrolled):**
    * 测试在页面根元素上进行 Overscroll 操作时，`WebFrame` 如何报告 Overscroll 的距离、速度和位置。
    * 验证 Overscroll 事件是否以及何时被触发。
    * 测试水平和垂直方向的 Overscroll 组合情况。
* **嵌套元素 Overscroll (Root Layer Overscrolled On InnerDiv/IFrame OverScroll):**
    * 测试当用户在可滚动的 `div` 或 `iframe` 元素内部进行 Overscroll 操作时，Overscroll 事件是否会冒泡到根元素，以及根元素如何处理。
    * 验证嵌套元素的滚动是否会影响根元素的 Overscroll 行为。
* **缩放页面 Overscroll (ScaledPageRootLayerOverscrolled):**
    * 测试在页面被缩放 (Page Scale Factor) 的情况下，Overscroll 的计算是否正确，包括累积的 Overscroll 量和未使用的滚动增量。
* **小数值滚动的 Overscroll 抑制 (NoOverscrollForSmallvalues):**
    * 测试当滚动增量非常小时，`WebFrame` 是否会抑制 Overscroll 事件的触发，避免不必要的反馈。
* **`overscroll-behavior` CSS 属性 (OverscrollBehaviorGoesToCompositor, SubframeOverscrollBehaviorPreventsChaining):**
    * 测试 CSS 属性 `overscroll-behavior` 对 Overscroll 行为的影响。
    * 验证 `overscroll-behavior: auto`、`contain` 和 `none` 这三种值如何改变 Overscroll 事件的触发和传递。
    * 测试在 `iframe` 中设置 `overscroll-behavior` 是否会阻止 Overscroll 事件冒泡到父框架。

**与 Javascript, HTML, CSS 的关系及举例说明：**

* **JavaScript:**
    * 代码中使用 `ExecuteScript` 方法来操作 DOM，例如设置元素的样式 (`document.body.style='overscroll-behavior: ...'`)。这表明 `WebFrame` 的 Overscroll 行为会受到 JavaScript 代码的影响。
    * **举例:**  `mainFrame->ExecuteScript(WebScriptSource(WebString("document.body.style='overscroll-behavior: none;'")));`  这段代码通过 JavaScript 将页面的 `overscroll-behavior` 设置为 `none`，从而阻止 Overscroll 效果。
* **HTML:**
    * 测试用例中加载了包含 `div` 和 `iframe` 元素的 HTML 文件 (`overscroll/div-overscroll.html`, `overscroll/iframe-overscroll.html`)，以模拟不同的页面结构和滚动容器。
    * **举例:**  `RegisterMockedHttpURLLoad("overscroll/iframe-overscroll.html");`  这行代码注册了一个用于测试的 HTML 文件，其中包含一个 `iframe` 元素。
* **CSS:**
    * 重点测试了 CSS 属性 `overscroll-behavior`，它允许开发者控制元素的滚动溢出行为。
    * **举例:**  `ExpectOverscrollParams(widget->last_overscroll(), ..., kOverscrollBehaviorAuto);`  这行代码断言在某个测试场景下，预期的 Overscroll 行为是 `kOverscrollBehaviorAuto`，这与 CSS 中设置的 `overscroll-behavior: auto` 相对应。

**逻辑推理和假设输入与输出：**

* **假设输入:** 用户在页面上进行向上滚动操作，超出页面顶部边界 50 像素。
* **假设输出 (基于 `RootLayerOverscrolled` 测试):**  `ExpectOverscrollParams` 可能会断言 `widget->last_overscroll()` 包含了如下信息：
    * `accumulatedRootOverscroll`: `gfx::Vector2dF(0, -50)` (垂直方向累积的 Overscroll 为 -50)
    * `unusedDelta`: `gfx::Vector2dF(0, -50)` (未被消耗的滚动增量为 -50)
    * `position`: `gfx::PointF(100, 100)` (事件发生的位置，可能根据测试设置)

* **假设输入 (基于 `RootLayerOverscrolledOnInnerDivOverScroll`):** 用户在一个内部 `div` 元素上进行向下 Overscroll 操作，使得 Overscroll 事件冒泡到根元素。
* **假设输出:** `ExpectOverscrollParams` 可能会断言根元素的 `widget->last_overscroll()` 包含了相应的 Overscroll 信息，即使滚动操作最初发生在子元素上。

**涉及用户或者编程常见的使用错误：**

* **错误地假设 Overscroll 会总是冒泡:**  开发者可能没有意识到 `overscroll-behavior: none` 可以阻止 Overscroll 事件冒泡，导致预期的事件处理逻辑没有被执行。例如，在一个嵌套的 `iframe` 中设置了 `overscroll-behavior: none`，父框架可能无法接收到来自 `iframe` 的 Overscroll 事件。
* **在缩放页面上进行 Overscroll 计算时未考虑缩放因子:**  开发者在处理 Overscroll 事件时，如果没有考虑到页面的缩放比例，可能会导致计算出的 Overscroll 量与实际不符。
* **过度依赖 Overscroll 事件进行滚动逻辑处理:**  如果开发者只依赖 Overscroll 事件来处理滚动相关的逻辑，那么当小数值滚动发生时，可能无法触发这些逻辑，因为测试表明小数值的滚动增量可能不会触发 Overscroll 事件。

**归纳一下它的功能 (第 15 部分):**

总而言之，`web_frame_test.cc` 的第 15 部分主要功能是 **测试 `WebFrame` 类对 Overscroll 行为的实现是否符合预期**。这包括对根元素和嵌套元素的 Overscroll 处理，在缩放页面下的 Overscroll 计算，以及 CSS 属性 `overscroll-behavior` 对 Overscroll 行为的影响。 这部分测试确保了 Blink 引擎能够正确地处理各种 Overscroll 场景，并与相关的 Web 技术 (JavaScript, HTML, CSS) 协同工作。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第15部分，共19部分，请归纳一下它的功能

"""
100, 0), gfx::PointF(100, 100), gfx::Vector2dF()));
  // ScrollUpdate(&webViewHelper, 100, 50);
  // Mock::VerifyAndClearExpectations(&client);

  // Scrolling up, Overscroll is not reported.
  // EXPECT_CALL(client, didOverscroll(_, _, _, _)).Times(0);
  // ScrollUpdate(&webViewHelper, 0, -50);
  // Mock::VerifyAndClearExpectations(&client);

  // Page scrolls horizontally, but over-scrolls vertically.
  // EXPECT_CALL(client, didOverscroll(gfx::Vector2dF(0, 100), gfx::Vector2dF(0,
  // 100), gfx::PointF(100, 100), gfx::Vector2dF()));
  // ScrollUpdate(&webViewHelper, -100, -100);
  // Mock::VerifyAndClearExpectations(&client);
}

TEST_P(WebFrameOverscrollTest, RootLayerOverscrolledOnInnerDivOverScroll) {
  RegisterMockedHttpURLLoad("overscroll/div-overscroll.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/div-overscroll.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 0, -316);

  // Scroll the Div to the end.
  ScrollUpdate(&web_view_helper, 0, -316);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollEnd(&web_view_helper);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 0, -150);

  // Now On Scrolling DIV, scroll is bubbled and root layer is over-scrolled.
  ScrollUpdate(&web_view_helper, 0, -150);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(0, 50),
                         gfx::Vector2dF(0, 50), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);
}

TEST_P(WebFrameOverscrollTest, RootLayerOverscrolledOnInnerIFrameOverScroll) {
  RegisterMockedHttpURLLoad("overscroll/iframe-overscroll.html");
  RegisterMockedHttpURLLoad("overscroll/scrollable-iframe.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/iframe-overscroll.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 0, -320);
  // Scroll the IFrame to the end.
  // This scroll will fully scroll the iframe but will be consumed before being
  // counted as overscroll.
  ScrollUpdate(&web_view_helper, 0, -320);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  // This scroll will again target the iframe but wont bubble further up. Make
  // sure that the unused scroll isn't handled as overscroll.
  ScrollUpdate(&web_view_helper, 0, -50);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollEnd(&web_view_helper);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 0, -150);

  // Now On Scrolling IFrame, scroll is bubbled and root layer is over-scrolled.
  ScrollUpdate(&web_view_helper, 0, -150);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(0, 50),
                         gfx::Vector2dF(0, 50), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollEnd(&web_view_helper);
}

TEST_P(WebFrameOverscrollTest, ScaledPageRootLayerOverscrolled) {
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/overscroll.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));
  web_view_impl->SetPageScaleFactor(3.0);

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  // Calculation of accumulatedRootOverscroll and unusedDelta on scaled page.
  // The point is (100, 100) because that is the position GenerateEvent uses.
  ScrollBegin(&web_view_helper, 0, 30);
  ScrollUpdate(&web_view_helper, 0, 30);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(0, -30),
                         gfx::Vector2dF(0, -30), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollUpdate(&web_view_helper, 0, 30);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(0, -60),
                         gfx::Vector2dF(0, -30), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollUpdate(&web_view_helper, 30, 30);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(-30, -90),
                         gfx::Vector2dF(-30, -30), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollUpdate(&web_view_helper, 30, 0);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(-60, -90),
                         gfx::Vector2dF(-30, 0), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  // Overscroll is not reported.
  ScrollEnd(&web_view_helper);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());
}

TEST_P(WebFrameOverscrollTest, NoOverscrollForSmallvalues) {
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "overscroll/overscroll.html",
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 10, 10);
  ScrollUpdate(&web_view_helper, 10, 10);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(-10, -10),
                         gfx::Vector2dF(-10, -10), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollUpdate(&web_view_helper, 0, 0.10);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(-10, -10.10),
                         gfx::Vector2dF(0, -0.10), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  ScrollUpdate(&web_view_helper, 0.10, 0);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(),
                         gfx::Vector2dF(-10.10, -10.10),
                         gfx::Vector2dF(-0.10, 0), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);

  // For residual values overscrollDelta should be reset and DidOverscroll
  // shouldn't be called.
  ScrollUpdate(&web_view_helper, 0, 0.09);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollUpdate(&web_view_helper, 0.09, 0.09);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollUpdate(&web_view_helper, 0.09, 0);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollUpdate(&web_view_helper, 0, -0.09);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollUpdate(&web_view_helper, -0.09, -0.09);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollUpdate(&web_view_helper, -0.09, 0);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());

  ScrollEnd(&web_view_helper);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());
}

TEST_P(WebFrameOverscrollTest, OverscrollBehaviorGoesToCompositor) {
  RegisterMockedHttpURLLoad("overscroll/overscroll.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(base_url_ + "overscroll/overscroll.html",
                                    nullptr, nullptr, ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();

  WebLocalFrame* mainFrame =
      web_view_helper.GetWebView()->MainFrame()->ToWebLocalFrame();
  EXPECT_EQ(web_view_helper.GetLayerTreeHost()->overscroll_behavior(),
            kOverscrollBehaviorAuto);
  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: auto;'")));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 100, 116);
  ScrollUpdate(&web_view_helper, 100, 100);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(-100, -100),
                         gfx::Vector2dF(-100, -100), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorAuto);
  EXPECT_EQ(web_view_helper.GetLayerTreeHost()->overscroll_behavior(),
            kOverscrollBehaviorAuto);

  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: contain;'")));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollUpdate(&web_view_helper, 100, 100);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(-200, -200),
                         gfx::Vector2dF(-100, -100), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorContain);
  EXPECT_EQ(web_view_helper.GetLayerTreeHost()->overscroll_behavior(),
            kOverscrollBehaviorContain);

  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: none;'")));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollUpdate(&web_view_helper, 100, 100);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  ExpectOverscrollParams(widget->last_overscroll(), gfx::Vector2dF(-300, -300),
                         gfx::Vector2dF(-100, -100), gfx::Vector2dF(),
                         gfx::PointF(100, 100), kOverscrollBehaviorNone);
  EXPECT_EQ(web_view_helper.GetLayerTreeHost()->overscroll_behavior(),
            kOverscrollBehaviorNone);
}

TEST_P(WebFrameOverscrollTest, SubframeOverscrollBehaviorPreventsChaining) {
  RegisterMockedHttpURLLoad("overscroll/iframe-overscroll.html");
  RegisterMockedHttpURLLoad("overscroll/scrollable-iframe.html");
  frame_test_helpers::WebViewHelper web_view_helper;

  web_view_helper.InitializeAndLoad(
      base_url_ + "overscroll/iframe-overscroll.html", nullptr, nullptr,
      ConfigureAndroid);
  web_view_helper.Resize(gfx::Size(200, 200));

  auto* widget = web_view_helper.GetMainFrameWidget();
  auto* layer_tree_host = web_view_helper.GetLayerTreeHost();

  WebLocalFrame* mainFrame =
      web_view_helper.GetWebView()->MainFrame()->ToWebLocalFrame();
  mainFrame->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: auto;'")));
  WebLocalFrame* subframe = web_view_helper.GetWebView()
                                ->MainFrame()
                                ->FirstChild()
                                ->ToWebLocalFrame();
  subframe->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: none;'")));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollBegin(&web_view_helper, 100, 116);
  ScrollUpdate(&web_view_helper, 100, 100);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());
  EXPECT_EQ(web_view_helper.GetLayerTreeHost()->overscroll_behavior(),
            kOverscrollBehaviorAuto);

  subframe->ExecuteScript(
      WebScriptSource(WebString("document.body.style="
                                "'overscroll-behavior: contain;'")));
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());

  ScrollUpdate(&web_view_helper, 100, 100);
  layer_tree_host->CompositeForTest(base::TimeTicks::Now(), false,
                                    base::OnceClosure());
  EXPECT_TRUE(widget->last_overscroll().is_null());
  EXPECT_EQ(web_view_helper.GetLayerTreeHost()->overscroll_behavior(),
            kOverscrollBehaviorAuto);
}

TEST_F(WebFrameTest, OrientationFrameDetach) {
  ScopedOrientationEventForTest orientation_event(true);
  RegisterMockedHttpURLLoad("orientation-frame-detach.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  WebViewImpl* web_view_impl = web_view_helper.InitializeAndLoad(
      base_url_ + "orientation-frame-detach.html");
  web_view_impl->MainFrameImpl()->SendOrientationChangeEvent();
}

TEST_F(WebFrameTest, MaxFrames) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeRemote();
  Page* page = web_view_helper.GetWebView()->GetPage();

  WebLocalFrameImpl* frame =
      web_view_helper.CreateLocalChild(*web_view_helper.RemoteMainFrame());
  while (page->SubframeCount() < Page::MaxNumberOfFrames()) {
    frame_test_helpers::CreateRemoteChild(*web_view_helper.RemoteMainFrame());
  }
  auto* iframe = MakeGarbageCollected<HTMLIFrameElement>(
      *frame->GetFrame()->GetDocument());
  iframe->setAttribute(html_names::kSrcAttr, g_empty_atom);
  frame->GetFrame()->GetDocument()->body()->appendChild(iframe);
  EXPECT_FALSE(iframe->ContentFrame());
}

class TestViewportIntersection : public FakeRemoteFrameHost {
 public:
  TestViewportIntersection() = default;
  ~TestViewportIntersection() override = default;

  const mojom::blink::ViewportIntersectionStatePtr& GetIntersectionState()
      const {
    return intersection_state_;
  }

  // FakeRemoteFrameHost:
  void UpdateViewportIntersection(
      mojom::blink::ViewportIntersectionStatePtr intersection_state,
      const std::optional<FrameVisualProperties>& visual_properties) override {
    intersection_state_ = std::move(intersection_state);
  }

 private:
  mojom::blink::ViewportIntersectionStatePtr intersection_state_;
};

TEST_F(WebFrameTest, RotatedIframeViewportIntersection) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize();
  WebViewImpl* web_view = web_view_helper.GetWebView();
  web_view->Resize(gfx::Size(800, 600));
  InitializeWithHTML(*web_view->MainFrameImpl()->GetFrame(), R"HTML(
<!DOCTYPE html>
<style>
  iframe {
    position: absolute;
    top: 200px;
    left: 200px;
    transform: rotate(45deg);
  }
</style>
<iframe></iframe>
  )HTML");
  TestViewportIntersection remote_frame_host;
  WebRemoteFrameImpl* remote_frame = frame_test_helpers::CreateRemote();
  frame_test_helpers::SwapRemoteFrame(
      web_view_helper.LocalMainFrame()->FirstChild(), remote_frame,
      remote_frame_host.BindNewAssociatedRemote());
  web_view->MainFrameImpl()
      ->GetFrame()
      ->View()
      ->UpdateAllLifecyclePhasesForTest();
  base::RunLoop().RunUntilIdle();
  ASSERT_TRUE(!remote_frame_host.GetIntersectionState()
                   ->viewport_intersection.IsEmpty());
  EXPECT_TRUE(
      gfx::Rect(remote_frame->GetFrame()->View()->Size())
          .Contains(
              remote_frame_host.GetIntersectionState()->viewport_intersection));
  ASSERT_TRUE(!remote_frame_host.GetIntersectionState()
                   ->main_frame_intersection.IsEmpty());
  EXPECT_TRUE(gfx::Rect(remote_frame->GetFrame()->View()->Size())
                  .Contains(remote_frame_host.GetIntersectionState()
                                ->main_frame_intersection));
  remote_frame->Detach();
}

TEST_F(WebFrameTest, ImageDocumentLoadResponseEnd) {
  // Loading an image resource directly generates an ImageDocument with
  // the document loader feeding image data into the resource of a generated
  // img tag. We expect the load finish time to be the same for the document
  // and the image resource.

  RegisterMockedHttpURLLoadWithMimeType("white-1x1.png", "image/png");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "white-1x1.png");
  WebViewImpl* web_view = web_view_helper.GetWebView();
  Document* document = web_view->MainFrameImpl()->GetFrame()->GetDocument();

  EXPECT_TRUE(document);
  EXPECT_TRUE(IsA<ImageDocument>(document));

  auto* img_document = To<ImageDocument>(document);
  ImageResourceContent* image_content = img_document->CachedImage();

  EXPECT_TRUE(image_content);
  EXPECT_NE(base::TimeTicks(), image_content->LoadResponseEnd());

  DocumentLoader* loader = document->Loader();

  EXPECT_TRUE(loader);
  EXPECT_EQ(loader->GetTiming().ResponseEnd(),
            image_content->LoadResponseEnd());
}

TEST_F(WebFrameTest, CopyImageDocument) {
  // After loading an image document, we should be able to copy it directly.

  RegisterMockedHttpURLLoadWithMimeType("white-1x1.png", "image/png");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "white-1x1.png");
  WebViewImpl* web_view = web_view_helper.GetWebView();
  WebLocalFrameImpl* web_frame = web_view->MainFrameImpl();
  Document* document = web_frame->GetFrame()->GetDocument();

  ASSERT_TRUE(document);
  EXPECT_TRUE(IsA<ImageDocument>(document));

  // Setup a mock clipboard host.
  PageTestBase::MockClipboardHostProvider mock_clipboard_host_provider(
      web_frame->GetFrame()->GetBrowserInterfaceBroker());

  SystemClipboard* system_clipboard =
      document->GetFrame()->GetSystemClipboard();
  ASSERT_TRUE(system_clipboard);

  EXPECT_TRUE(system_clipboard->ReadAvailableTypes().empty());

  bool result = web_frame->ExecuteCommand("Copy");
  test::RunPendingTasks();

  EXPECT_TRUE(result);

  Vector<String> types = system_clipboard->ReadAvailableTypes();
  EXPECT_EQ(2u, types.size());
  EXPECT_EQ("text/html", types[0]);
  EXPECT_EQ("image/png", types[1]);

  // Clear clipboard data
  system_clipboard->WritePlainText("");
  system_clipboard->CommitWrite();
}

TEST_F(WebFrameTest, CopyTextInImageDocument) {
  // If Javascript inserts other contents into an image document, we should be
  // able to copy those contents, not just the image itself.

  RegisterMockedHttpURLLoadWithMimeType("white-1x1.png", "image/png");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "white-1x1.png");
  WebViewImpl* web_view = web_view_helper.GetWebView();
  WebLocalFrameImpl* web_frame = web_view->MainFrameImpl();
  Document* document = web_frame->GetFrame()->GetDocument();

  ASSERT_TRUE(document);
  EXPECT_TRUE(IsA<ImageDocument>(document));

  Node* text = document->createTextNode("copy me");
  document->body()->appendChild(text);
  document->GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder().SelectAllChildren(*text).Build(),
      SetSelectionOptions());

  // Setup a mock clipboard host.
  PageTestBase::MockClipboardHostProvider mock_clipboard_host_provider(
      web_frame->GetFrame()->GetBrowserInterfaceBroker());

  SystemClipboard* system_clipboard =
      document->GetFrame()->GetSystemClipboard();
  ASSERT_TRUE(system_clipboard);

  EXPECT_TRUE(system_clipboard->ReadAvailableTypes().empty());

  bool result = web_frame->ExecuteCommand("Copy");
  test::RunPendingTasks();

  EXPECT_TRUE(result);

  Vector<String> types = system_clipboard->ReadAvailableTypes();
  EXPECT_EQ(2u, types.size());
  EXPECT_EQ("text/plain", types[0]);
  EXPECT_EQ("text/html", types[1]);

  // Clear clipboard data
  system_clipboard->WritePlainText("");
  system_clipboard->CommitWrite();
}

class SelectionMockWebFrameClient
    : public frame_test_helpers::TestWebFrameClient {
 public:
  MOCK_METHOD(void, DidChangeSelection, (bool, blink::SyncCondition));
};

TEST_F(WebFrameTest, ImeSelectionCommitDoesNotChangeClipboard) {
  using blink::ImeTextSpan;
  using ui::mojom::ImeTextSpanThickness;
  using ui::mojom::ImeTextSpanUnderlineStyle;

  RegisterMockedHttpURLLoad("foo.html");
  SelectionMockWebFrameClient web_frame_client;

  frame_test_helpers::WebViewHelper web_view_helper;
  WebLocalFrameImpl* web_frame =
      web_view_helper
          .InitializeAndLoad(base_url_ + "foo.html", &web_frame_client)
          ->MainFrameImpl();
  WebViewImpl* web_view = web_view_helper.GetWebView();
  WebFrameWidget* widget = web_view->MainFrameImpl()->FrameWidgetImpl();
  EXPECT_CALL(web_frame_client, DidChangeSelection(true, _))
      .WillRepeatedly(Return());  // Happens due to edit change.
  EXPECT_CALL(web_frame_client, DidChangeSelection(false, _))
      .WillRepeatedly(testing::Invoke(
          [widget] { EXPECT_FALSE(widget->HandlingInputEvent()); }));

  Document* document = web_frame->GetFrame()->GetDocument();

  document->write("<div id='sample' contenteditable>hello world</div>");
  document->getElementById(AtomicString("sample"))->Focus();

  Vector<ImeTextSpan> ime_text_spans;
  ime_text_spans.push_back(ImeTextSpan(
      ImeTextSpan::Type::kComposition, 0, 5, Color(255, 0, 0),
      ImeTextSpanThickness::kThin, ImeTextSpanUnderlineStyle::kSolid,
      Color::kTransparent, Color::kTransparent));
  InputMethodController& controller =
      web_frame->GetFrame()->GetInputMethodController();
  controller.SetCompositionFromExistingText(ime_text_spans, 0, 5);

  // Even though the commit came as part of a user interaction,
  // the internal selection to replace the composition (done as
  // part of the commit) should _not_ be marked as such, or it would
  // change the X11 clipboard (crbug.com/1213325).
  // The actual test for this is in the EXPECT_CALL above.
  //
  // Since the selection-to-clipboard logic isn't hooked up in
  // TestWebFrameClient, we cannot check that the actual clipboard
  // values don't change, but must be slightly more indirect
  // in our testing, and thus, we check for HandlingInputEvent()
  // instead (which, in the actual code, suppresses the clipboard logic).
  widget->SetHandlingInputEvent(true);
  controller.CommitText(String("replaced"), ime_text_spans, 0);
  widget->SetHandlingInputEvent(false);
}

class TestRemoteFrameHostForVisibility : public FakeRemoteFrameHost {
 public:
  TestRemoteFrameHostForVisibility() = default;
  ~TestRemoteFrameHostForVisibility() override = default;

  // FakeRemoteFrameHost:
  void VisibilityChanged(blink::mojom::FrameVisibility visibility) override {
    visibility_ = visibility;
  }

  blink::mojom::FrameVisibility visibility() const { return visibility_; }

 private:
  blink::mojom::FrameVisibility visibility_ =
      blink::mojom::FrameVisibility::kRenderedInViewport;
};

class WebRemoteFrameVisibilityChangeTest : public WebFrameTest {
 public:
  WebRemoteFrameVisibilityChangeTest() {
    RegisterMockedHttpURLLoad("visible_iframe.html");
    RegisterMockedHttpURLLoad("single_iframe.html");
    frame_ =
        web_view_helper_.InitializeAndLoad(base_url_ + "single_iframe.html")
            ->MainFrameImpl();
    web_view_helper_.Resize(gfx::Size(640, 480));
    web_remote_frame_ = frame_test_helpers::CreateRemote();
  }

  ~WebRemoteFrameVisibilityChangeTest() override = default;

  void ExecuteScriptOnMainFrame(const WebScriptSource& script) {
    MainFrame()->ExecuteScript(script);
    web_view_helper_.GetWebView()
        ->MainFrameViewWidget()
        ->SynchronouslyCompositeForTesting(base::TimeTicks::Now());
    RunPendingTasks();
  }

  void SwapLocalFrameToRemoteFrame() {
    frame_test_helpers::SwapRemoteFrame(
        MainFrame()->LastChild(), RemoteFrame(),
        remote_frame_host_.BindNewAssociatedRemote());
  }

  WebLocalFrame* MainFrame() { return frame_; }
  WebRemoteFrameImpl* RemoteFrame() { return web_remote_frame_; }
  TestRemoteFrameHostForVisibility* RemoteFrameHost() {
    return &remote_frame_host_;
  }

 private:
  TestRemoteFrameHostForVisibility remote_frame_host_;
  frame_test_helpers::WebViewHelper web_view_helper_;
  WebLocalFrame* frame_;
  Persistent<WebRemoteFrameImpl> web_remote_frame_;
};

TEST_F(WebRemoteFrameVisibilityChangeTest, FrameVisibilityChange) {
  SwapLocalFrameToRemoteFrame();
  ExecuteScriptOnMainFrame(WebScriptSource(
      "document.querySelector('iframe').style.display = 'none';"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kNotRendered,
            RemoteFrameHost()->visibility());

  ExecuteScriptOnMainFrame(WebScriptSource(
      "document.querySelector('iframe').style.display = 'block';"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kRenderedInViewport,
            RemoteFrameHost()->visibility());

  ExecuteScriptOnMainFrame(WebScriptSource(
      "var padding = document.createElement('div');"
      "padding.style = 'width: 400px; height: 800px;';"
      "document.body.insertBefore(padding, document.body.firstChild);"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kRenderedOutOfViewport,
            RemoteFrameHost()->visibility());

  ExecuteScriptOnMainFrame(
      WebScriptSource("document.scrollingElement.scrollTop = 800;"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kRenderedInViewport,
            RemoteFrameHost()->visibility());
}

TEST_F(WebRemoteFrameVisibilityChangeTest, ParentVisibilityChange) {
  SwapLocalFrameToRemoteFrame();
  ExecuteScriptOnMainFrame(
      WebScriptSource("document.querySelector('iframe').parentElement.style."
                      "display = 'none';"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kNotRendered,
            RemoteFrameHost()->visibility());
}

class TestLocalFrameHostForVisibility : public FakeLocalFrameHost {
 public:
  TestLocalFrameHostForVisibility() = default;
  ~TestLocalFrameHostForVisibility() override = default;

  // FakeLocalFrameHost:
  void VisibilityChanged(blink::mojom::FrameVisibility visibility) override {
    visibility_ = visibility;
  }

  blink::mojom::FrameVisibility visibility() const { return visibility_; }

 private:
  blink::mojom::FrameVisibility visibility_ =
      blink::mojom::FrameVisibility::kRenderedInViewport;
};

class WebLocalFrameVisibilityChangeTest
    : public WebFrameTest,
      public frame_test_helpers::TestWebFrameClient {
 public:
  WebLocalFrameVisibilityChangeTest() {
    RegisterMockedHttpURLLoad("visible_iframe.html");
    RegisterMockedHttpURLLoad("single_iframe.html");
    child_host_.Init(child_client_.GetRemoteNavigationAssociatedInterfaces());
    frame_ = web_view_helper_
                 .InitializeAndLoad(base_url_ + "single_iframe.html", this)
                 ->MainFrameImpl();
    web_view_helper_.Resize(gfx::Size(640, 480));
  }

  ~WebLocalFrameVisibilityChangeTest() override = default;

  void ExecuteScriptOnMainFrame(const WebScriptSource& script) {
    MainFrame()->ExecuteScript(script);
    web_view_helper_.GetWebView()
        ->MainFrameViewWidget()
        ->SynchronouslyCompositeForTesting(base::TimeTicks::Now());
    RunPendingTasks();
  }

  WebLocalFrame* MainFrame() { return frame_; }

  // frame_test_helpers::TestWebFrameClient:
  WebLocalFrame* CreateChildFrame(
      mojom::blink::TreeScopeType scope,
      const WebString& name,
      const WebString& fallback_name,
      const FramePolicy&,
      const WebFrameOwnerProperties&,
      FrameOwnerElementType,
      WebPolicyContainerBindParams policy_container_bind_params,
      ukm::SourceId document_ukm_source_id,
      FinishChildFrameCreationFn finish_creation) override {
    return CreateLocalChild(*Frame(), scope, &child_client_,
                            std::move(policy_container_bind_params),
                            finish_creation);
  }

  TestLocalFrameHostForVisibility& ChildHost() { return child_host_; }

 private:
  TestLocalFrameHostForVisibility child_host_;
  frame_test_helpers::TestWebFrameClient child_client_;
  frame_test_helpers::WebViewHelper web_view_helper_;
  WebLocalFrame* frame_;
};

TEST_F(WebLocalFrameVisibilityChangeTest, FrameVisibilityChange) {
  ExecuteScriptOnMainFrame(WebScriptSource(
      "document.querySelector('iframe').style.display = 'none';"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kNotRendered,
            ChildHost().visibility());

  ExecuteScriptOnMainFrame(WebScriptSource(
      "document.querySelector('iframe').style.display = 'block';"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kRenderedInViewport,
            ChildHost().visibility());

  ExecuteScriptOnMainFrame(WebScriptSource(
      "var padding = document.createElement('div');"
      "padding.style = 'width: 400px; height: 800px;';"
      "document.body.insertBefore(padding, document.body.firstChild);"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kRenderedOutOfViewport,
            ChildHost().visibility());

  ExecuteScriptOnMainFrame(
      WebScriptSource("document.scrollingElement.scrollTop = 800;"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kRenderedInViewport,
            ChildHost().visibility());
}

TEST_F(WebLocalFrameVisibilityChangeTest, ParentVisibilityChange) {
  ExecuteScriptOnMainFrame(
      WebScriptSource("document.querySelector('iframe').parentElement.style."
                      "display = 'none';"));
  EXPECT_EQ(blink::mojom::FrameVisibility::kNotRendered,
            ChildHost().visibility());
}

static void EnableGlobalReuseForUnownedMainFrames(WebSettings* settings) {
  settings->SetShou
"""


```