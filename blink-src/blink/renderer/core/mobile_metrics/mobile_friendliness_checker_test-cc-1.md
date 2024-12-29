Response:
The user wants me to analyze the provided C++ code snippet, which is part of a test file for the Chromium Blink engine. Specifically, this is the second part of the file `mobile_friendliness_checker_test.cc`.

My goal is to:
1. **Summarize the functionality** of this code snippet.
2. Explain its relation to **JavaScript, HTML, and CSS**, providing examples.
3. Describe any **logical reasoning** with input and output examples.
4. Point out potential **user or programming errors** illustrated by the tests.
5. Explain how a user's interaction could lead to the execution of this code for **debugging**.

Based on the code, it seems to be testing the `MobileFriendlinessChecker` class in Blink. This class likely analyzes web pages to determine how well they are suited for mobile devices. The tests use different HTML structures and CSS styles to verify the checker's behavior in various scenarios.

Here's a breakdown of the individual tests:

- `ImageTooWideDisplayNone`: Checks if images with `display: none` are considered for being too wide.
- `ScaleTextOutsideViewport`: Tests how the checker handles text overflowing the viewport due to scaling.
- `ScrollerOutsideViewport`: Examines the case where a horizontally scrolling container extends beyond the viewport.
- `SubScroller`: Verifies that a scrollable element within the viewport doesn't trigger issues.
- `SubScrollerHalfOutByMargin`: Tests scenarios where a scrollable element is partially outside the viewport due to margin.
- `SubScrollerOutByTranslate`: Similar to the above, but with `transform: translate`.
- `SubScrollerFitsWithinViewport`: Checks if a scrollable element that fits within the viewport is correctly handled.
- `SubScrollerTwice`: Evaluates the case with multiple scrollable elements partially outside the viewport.
- `SubScrollerInSubScroller`: Tests nested scrollable elements and how the outer scrollable affects the metric.
- `ScrollableLayoutView`: Checks the case where the entire body is wider than the viewport, leading to scrolling.
- `IFrame`: Tests the interaction with iframes and basic viewport properties.
- `IFrameVieportDeviceWidth`: Focuses on how the viewport settings within iframes are considered.
- `IFrameSmallTextRatio`: Examines the handling of small text within iframes.

I will now formulate the response based on these observations.
这是 blink/renderer/core/mobile_metrics/mobile_friendliness_checker_test.cc 文件的第二部分，延续了第一部分的功能，主要负责对 `MobileFriendlinessChecker` 类的更多场景进行单元测试。 该类的目的是检查网页在移动设备上的友好程度，并生成相应的指标数据。

**功能归纳:**

这部分代码的功能是为 `MobileFriendlinessChecker` 类编写更多的单元测试，覆盖了各种更复杂的 HTML 结构和 CSS 样式场景，以验证其在判断移动设备友好性方面的准确性和鲁棒性。  这些测试主要关注以下几个方面：

1. **隐藏元素的影响:**  测试了 `display: none` 的元素是否会被计入超出视口的内容。
2. **缩放和视口:** 测试了页面缩放后文本内容超出视口的情况。
3. **滚动容器:**  重点测试了各种滚动容器（包括根滚动和子滚动容器）超出视口的情况，以及嵌套滚动容器的处理。
4. **`<iframe>` 元素的处理:** 测试了包含 `<iframe>` 元素的页面，以及 `<iframe>` 元素自身的视口设置和文本大小对移动友好性指标的影响。

**与 Javascript, HTML, CSS 的关系举例:**

这些测试直接操作 HTML 结构和 CSS 样式，并通过 C++ 代码模拟浏览器渲染和布局的过程，来验证 `MobileFriendlinessChecker` 的行为。

* **HTML:**  测试用例通过构造不同的 HTML 结构来模拟各种网页布局，例如：
    * 使用 `<img>` 标签模拟过宽的图片。
    * 使用 `<div>` 标签创建滚动容器。
    * 使用 `<meta name="viewport">` 设置视口。
    * 使用 `<iframe>` 嵌入其他页面。
* **CSS:** 测试用例使用 CSS 样式来影响元素的布局和渲染，例如：
    * 使用 `width` 和 `height` 设置元素的尺寸。
    * 使用 `display: none` 隐藏元素。
    * 使用 `overflow: scroll` 创建滚动容器。
    * 使用 `transform: translate` 移动元素。
    * 使用 `margin` 设置元素的外边距。
    * 使用 `font-size` 设置文本大小。
* **Javascript:** 虽然这段代码本身没有直接涉及 Javascript，但 `MobileFriendlinessChecker` 在实际运行中会分析由 Javascript 动态修改后的 DOM 结构。  例如，Javascript 可能会动态添加超出视口的元素或者修改元素的样式导致超出视口。这些测试建立的基础能够保证在 Javascript 影响布局后，检查器也能正常工作。

**逻辑推理的假设输入与输出:**

例如，`TEST_F(MobileFriendlinessCheckerTest, ScaleTextOutsideViewport)` 这个测试：

* **假设输入 (HTML):**
  ```html
  <html>
    <head>
      <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
      <meta name="viewport" content="minimum-scale=1, initial-scale=3">
    </head>
    <body style="font: 76px Ahem; width: 480">
      foo foo foo foo foo foo foo foo foo foo
      ... (很多行文本) ...
    </body>
  </html>
  ```
* **逻辑推理:** 由于设置了 `initial-scale=3`，文本的实际渲染尺寸会很大，即使 `body` 的宽度是 480px，文本也会超出视口。
* **预期输出 (UKM Metric):** `ukm::builders::MobileFriendliness::kViewportInitialScaleX10NameHash` 的值会根据 `initial-scale` 计算（这里是 30，会被 bucket 到 26），`ukm::builders::MobileFriendliness::kTextContentOutsideViewportPercentageNameHash` 的值会大于 55，表示大量文本内容超出了视口。

再例如，`TEST_F(MobileFriendlinessCheckerTest, SubScrollerHalfOutByMargin)`:

* **假设输入 (HTML):**
  ```html
  <html>
    <head>
      <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
      <style>
        /* ... */
        div.scrollmenu {
          margin-left: 240px; /* 将滚动容器向右偏移一半视口宽度 */
          width: 480px;
          height: 800px;
          background-color: #333;
          overflow: scroll;
          white-space: nowrap;
        }
        /* ... */
      </style>
      <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
    </head>
    <body style="font: 40px/1 Ahem; line-height: 1">
      <div class="scrollmenu">
        <!-- ... 很多文本内容 ... -->
      </div>
    </body>
  </html>
  ```
* **逻辑推理:**  滚动容器的宽度和视口宽度相同，但是由于 `margin-left: 240px;`，滚动容器有一半的宽度会超出视口。容器内的文本内容也会相应有一半超出视口。
* **预期输出 (UKM Metric):** `ukm::builders::MobileFriendliness::kTextContentOutsideViewportPercentageNameHash` 的值为 50。

**涉及用户或编程常见的使用错误举例说明:**

* **未设置视口或视口设置不当:**  虽然测试中都设置了视口，但在实际开发中，开发者可能忘记设置 `<meta name="viewport">`，或者设置了不合适的 `width=device-width` 或 `initial-scale`，导致页面在不同设备上显示异常。`IFrameVieportDeviceWidth` 和 `IFrameSmallTextRatio` 等测试间接验证了检查器对于不同视口设置的处理。
* **内容超出视口但未提供滚动:** 开发者可能创建了宽度超过视口的内容，但没有使用 `overflow: auto` 或 `overflow: scroll` 提供滚动，导致用户无法看到所有内容。 `ScrollerOutsideViewport` 和类似的测试覆盖了这种情况。
* **使用了过大的固定宽度元素:** 开发者可能使用了固定的像素值来设置元素的宽度，而没有考虑不同屏幕尺寸，导致元素在小屏幕上超出视口。 `ImageTooWide` 以及其他涉及元素宽度的测试都在验证对这类问题的检测。
* **在 `<iframe>` 中使用了不合适的视口设置或文本大小:**  `IFrameSmallTextRatio` 测试表明，检查器也会考虑 `<iframe>` 内部的移动友好性问题，提示开发者需要关注嵌套页面的体验。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户访问网页:** 用户在移动设备或模拟器上访问一个网页。
2. **浏览器加载和渲染网页:** Chromium 浏览器开始加载 HTML、CSS 和 Javascript，并进行渲染和布局。
3. **触发移动友好性检查:** 在页面加载完成或特定时机，Blink 引擎会触发 `MobileFriendlinessChecker` 来分析页面的布局和特性。 这个触发可能是周期性的，也可能是在页面生命周期的某个阶段。
4. **执行 `MobileFriendlinessChecker` 代码:** `MobileFriendlinessChecker` 会遍历 DOM 树，计算各种指标，例如文本内容是否超出视口、是否有小文本等。
5. **执行到测试覆盖的代码:**  如果用户访问的网页的 HTML 结构或 CSS 样式与这些测试用例中模拟的场景相似，那么 `MobileFriendlinessChecker` 的执行路径就会涉及到这些测试用例所覆盖的代码逻辑。

**作为调试线索:**

如果开发者发现自己的网页在移动设备上显示不佳，并且怀疑是由于某些布局问题导致的，他们可能会：

1. **使用开发者工具进行检查:**  开发者可以使用 Chrome 的开发者工具来查看元素的尺寸、布局和计算后的样式，从而发现超出视口或文本过小的问题。
2. **查看性能指标:**  开发者可能会关注性能指标，例如 First Contentful Paint (FCP) 和 Largest Contentful Paint (LCP)，这些指标可能会受到布局问题的影响。
3. **模拟不同的设备尺寸:** 开发者可以在开发者工具中模拟不同的移动设备尺寸来测试页面的响应式设计。
4. **检查 UKM 数据 (如果可用):**  如果浏览器收集了 UKM (Use Keyed Metrics) 数据，开发者或者 Chromium 团队可以通过分析 `MobileFriendliness` 相关的 UKM 指标来诊断问题，这些指标正是由 `MobileFriendlinessChecker` 计算出来的。  例如，如果 `text_content_outside_viewport_percentage` 的值很高，就说明网页存在大量超出视口的内容。

总而言之，这部分测试代码通过模拟各种实际网页可能出现的布局场景，确保 `MobileFriendlinessChecker` 能够准确地识别出影响移动用户体验的问题，为开发者提供有价值的反馈，并最终提升移动网页的质量。

Prompt: 
```
这是目录为blink/renderer/core/mobile_metrics/mobile_friendliness_checker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""

  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, ImageTooWideDisplayNone) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body>
    <img style="width:2000px; height:50px; display:none">
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, ScaleTextOutsideViewport) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
    <meta name="viewport" content="minimum-scale=1, initial-scale=3">
  </head>
  <body style="font: 76px Ahem; width: 480">
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
    foo foo foo foo foo foo foo foo foo foo
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportInitialScaleX10NameHash,
            26);  // Bucketed 30 -> 26.
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              55);
}

TEST_F(MobileFriendlinessCheckerTest, ScrollerOutsideViewport) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
    <style>
      body {
        margin: 0px;
      }
      div.scrollmenu {
        background-color: #333;
        white-space: nowrap;
      }
      div.scrollmenu a {
        display: inline-block;
        color: white;
        padding: 14px;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 40px/1 Ahem; line-height: 1; height: 200px">
    <div class="scrollmenu">
      <a href="#1">First text</a>
      <a href="#2">Second text</a>
      <a href="#3">Third text</a>
      <a href="#4">Fourth text</a>
      <a href="#5">Fifth text</a>
      <a href="#6">Sixth text</a>
      <a href="#7">Seventh text</a>
      <a href="#8">Eighth text</a>
      <a href="#9">Ninth text</a>
      <a href="#10">Tenth text</a>
      <a href="#11">Eleventh text</a>
      <a href="#12">Twelveth text</a>
    </div>
  </body>
</html>
)HTML");
  // the viewport
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              10);
}

TEST_F(MobileFriendlinessCheckerTest, SubScroller) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
    <style>
      body {
        margin: 0px;
      }
      div.scrollmenu {
        width: 480px;
        background-color: #333;
        overflow: scroll;
        white-space: nowrap;
      }
      div.scrollmenu a {
        display: inline-block;
        color: white;
        padding: 14px;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 40px/1 Ahem; line-height: 1">
  <div class="scrollmenu">
    <a href="#1">First text</a>
    <a href="#2">Second text</a>
    <a href="#3">Third text</a>
    <a href="#4">Fourth text</a>
    <a href="#5">Fifth text</a>
    <a href="#6">Sixth text</a>
    <a href="#7">Seventh text</a>
    <a href="#8">Eighth text</a>
    <a href="#9">Ninth text</a>
    <a href="#10">Tenth text</a>
    <a href="#11">Eleventh text</a>
    <a href="#12">Twelveth text</a>
  </div>
  </body>
</html>
)HTML");
  // Fits within the viewport by scrollbar.
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, SubScrollerHalfOutByMargin) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
    <style>
      body {
        margin: 0px;
      }
      div.scrollmenu {
        margin-left: 240px;
        width: 480px;
        height: 800px;
        background-color: #333;
        overflow: scroll;
        white-space: nowrap;
      }
      div.scrollmenu a {
        display: inline-block;
        color: white;
        padding: 14px;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 40px/1 Ahem; line-height: 1">
  <div class="scrollmenu">
    <a href="#1">First text</a>
    <a href="#2">Second text</a>
    <a href="#3">Third text</a>
    <a href="#4">Fourth text</a>
    <a href="#5">Fifth text</a>
    <a href="#6">Sixth text</a>
    <a href="#7">Seventh text</a>
    <a href="#8">Eighth text</a>
    <a href="#9">Ninth text</a>
    <a href="#10">Tenth text</a>
    <a href="#11">Eleventh text</a>
    <a href="#12">Twelveth text</a>
  </div>
  </body>
</html>
)HTML");
  // Fits within the viewport by scrollbar.
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            50);
}

TEST_F(MobileFriendlinessCheckerTest, SubScrollerOutByTranslate) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
    <style>
      body {
        margin: 0px;
      }
      div.scrollmenu {
        transform: translate(360px, 0px);
        width: 480px;
        height: 800px;
        background-color: #333;
        overflow: scroll;
        white-space: nowrap;
      }
      div.scrollmenu a {
        display: inline-block;
        color: white;
        padding: 14px;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 40px/1 Ahem; line-height: 1">
  <div class="scrollmenu">
    <a href="#1">First text</a>
    <a href="#2">Second text</a>
    <a href="#3">Third text</a>
    <a href="#4">Fourth text</a>
    <a href="#5">Fifth text</a>
    <a href="#6">Sixth text</a>
    <a href="#7">Seventh text</a>
    <a href="#8">Eighth text</a>
    <a href="#9">Ninth text</a>
    <a href="#10">Tenth text</a>
    <a href="#11">Eleventh text</a>
    <a href="#12">Twelveth text</a>
  </div>
  </body>
</html>
)HTML");
  // Fits within the viewport by scrollbar.
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            75);
}

/*
 * TODO(kumagi): Get precise paint offset of rtl environment is hard.
TEST_F(MobileFriendlinessCheckerTest, SubScrollerGoesLeft) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <style>
      body {
        margin: 0px;
        direction: rtl;
      }
      div.scroller {
        margin-right: 360px;
        width: 480px;
        height: 800px;
        overflow: scroll;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0
minimum-scale=1.0">
  </head>
  <body style="font: 40px/1 Ahem; line-height: 1">
    <div class="scroller">
      <img style="width: 9000px; height: 1px">
    </div>
  </body>
</html>
)HTML");
  // Right to left language scrollbar goes to left.
  ExpectUkm(actual_mf.text_content_outside_viewport_percentage, 75);
}
*/

TEST_F(MobileFriendlinessCheckerTest, SubScrollerFitsWithinViewport) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <style>
      body {
        margin: 0px;
      }
      div.scroller1 {
        width: 481px;
        height: 1px;
        overflow: scroll;
      }
      div.scroller2 {
        width: 10px;
        height: 800px;
        overflow: scroll;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 40px/1 Ahem; line-height: 1">
    <div class="scroller1">
      <img style="width: 9000px; height: 1px">
      This div goes out of viewport width 1px.
    </div>
    <div class="scroller2">
      <img style="width: 9000px; height: 1px">
      This div fits within viewport width.
    </div>
  </body>
</html>
)HTML");
  // Only scroller1 gets out of viewport width.
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            1);
}

TEST_F(MobileFriendlinessCheckerTest, SubScrollerTwice) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <style>
      body {
        margin: 0px;
      }
      div.scroller {
        margin-left: 240px;
        width: 480px;
        height: 400px;
        overflow: scroll;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 40px/1 Ahem; line-height: 1">
    <div class="scroller">
      <img style="width: 9000px; height: 1px">
      hello this is a pen.
    </div>
    <div class="scroller">
      <img style="width: 9000px; height: 1px">
    </div>
  </body>
</html>
)HTML");
  // Both of subscrollers get out of viewport width.
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            50);
}

TEST_F(MobileFriendlinessCheckerTest, SubScrollerInSubScroller) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <style>
      body {
        margin: 0px;
      }
      div.scroller {
        width: 480px;
        height: 200px;
        overflow: scroll;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 20px/1; line-height: 1">
    <div class="scroller" style="margin-left: 240px;">
      240px*200px gets out of viewport.
      <img style="width: 9000px; height: 1px">
    </div>
    <div class="scroller" style="margin-left: 480px;">
      480px*200px gets out of viewport.
      <img style="width: 9000px; height: 1px">
    </div>
    <div class="scroller" style="margin-left: 240px;">
      240px*200px gets out of viewport.
      <img style="width: 9000px; height: 1px">
      <div class="scroller">
        Contents inside of scroller will be ignored from the
        text_content_outside_viewport_percentage metrics.
        <img style="width: 9000px; height: 1px">
      </div>
    </div>
    <div class="scroller" style="margin-left: 480px;">
      480px*200px gets out of viewport.
      Hereby (240px*2)*400px + (480px*2)*400px gets out of viewport(480px*800px),
      This is exactly 0.75. Then text_content_outside_viewport_percentage should be 75.
      <img style="width: 9000px; height: 1px">
      <div class="scroller">
        <img style="width: 9000px; height: 1px">
        <div class="scroller">
          <img style="width: 9000px; height: 1px">
        </div>
      </div>
    </div>
  </body>
</html>
)HTML");
  // Fits within the viewport by scrollbar.
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            75);
}

TEST_F(MobileFriendlinessCheckerTest, ScrollableLayoutView) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <style>
      body {
        margin: 0px;
        width: 960px;
        height: 800px;
      }
    </style>
    <meta name="viewport" content="width=480px, initial-scale=1.0 minimum-scale=1.0">
  </head>
  <body style="font: 20px/1; line-height: 1">
    <img style="width: 600px; height: 800px">
  </body>
</html>
)HTML");
  // Fits within the viewport by scrollbar.
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            25);
}

TEST_F(MobileFriendlinessCheckerTest, IFrame) {
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(kBaseUrl), blink::test::CoreTestDataPath(),
      WebString::FromUTF8("visible_iframe.html"));
  const ukm::mojom::UkmEntry ukm =
      CalculateMetricsForFile("single_iframe.html");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
}

TEST_F(MobileFriendlinessCheckerTest, IFrameVieportDeviceWidth) {
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(kBaseUrl), blink::test::CoreTestDataPath(),
      WebString::FromUTF8("viewport/viewport-1.html"));
  const ukm::mojom::UkmEntry ukm =
      CalculateMetricsForFile("page_contains_viewport_iframe.html");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

TEST_F(MobileFriendlinessCheckerTest, IFrameSmallTextRatio) {
  url_test_helpers::RegisterMockedURLLoadFromBase(
      WebString::FromUTF8(kBaseUrl), blink::test::CoreTestDataPath(),
      WebString::FromUTF8("small_text_iframe.html"));
  const ukm::mojom::UkmEntry ukm =
      CalculateMetricsForFile("page_contains_small_text_iframe.html");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

}  // namespace blink

"""


```