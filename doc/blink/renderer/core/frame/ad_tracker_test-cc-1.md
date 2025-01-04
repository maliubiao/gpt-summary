Response:
The user wants a summary of the functionality of the provided C++ code. This is the second part of a two-part code snippet. I need to analyze the code, understand its purpose, and explain how it relates to web technologies like JavaScript, HTML, and CSS. I should also provide examples of its behavior with hypothetical inputs and outputs, as well as common user or programming errors.

**Plan:**

1. **Identify the core purpose:** Based on the test names and the operations performed, the code seems to be testing the functionality of an `AdTracker` class. This class is responsible for identifying resources (like scripts, stylesheets, images, fonts) as being related to advertisements.

2. **Analyze individual tests:** Break down each `TEST_F` and `TEST_P` function to understand what specific scenario it's verifying. Look for patterns in how ad resources are identified (e.g., based on URL suffixes, whether they are loaded by ad scripts, or iframes are marked as ad frames).

3. **Relate to web technologies:** Connect the test scenarios to how JavaScript, HTML, and CSS are used in web pages, particularly in the context of advertising. For example, how JavaScript can create iframes or inject CSS, how CSS can load fonts and images, and how HTML structures the page and includes scripts and stylesheets.

4. **Provide hypothetical inputs and outputs:** For specific tests, create simple scenarios with example URLs and code snippets to illustrate how the `AdTracker` would classify resources.

5. **Identify potential errors:** Think about common mistakes developers might make when dealing with ad-related resources that could lead to incorrect tagging or unexpected behavior.

6. **Focus on the second part:** Since this is the second part, I need to synthesize the information from this part, assuming the first part established the basic setup and possibly some foundational tests.

7. **Structure the summary:** Organize the findings into clear sections addressing the requested points (functionality, relation to web technologies, input/output examples, common errors, and overall summary).
这是blink引擎中`ad_tracker_test.cc`文件的第二个部分，该文件专门用于测试 `AdTracker` 组件的功能。`AdTracker` 的核心职责是跟踪和识别网页中的广告资源。

**归纳一下它的功能:**

这部分测试文件主要关注以下 `AdTracker` 的功能：

1. **识别通过 JavaScript 动态创建的 iframe 是否为广告:** 测试用例验证了通过广告脚本创建的同源或跨域的 iframe 是否能被正确标记为由广告脚本创建。

    *   **与 JavaScript, HTML 的关系:** JavaScript 代码负责创建 `iframe` 元素并添加到文档中。HTML 定义了页面的结构。`AdTracker` 需要能够识别这些由 JavaScript 操作动态添加的元素，并根据其来源（是否来自广告脚本）进行标记。

    *   **假设输入与输出:**
        *   **输入:** 一个包含广告脚本的 HTML 页面，该脚本创建一个 iframe 并设置其 `src` 属性。
        *   **输出:** `AdTracker` 能够判断该 iframe 的 `LocalFrame` 对象的 `IsFrameCreatedByAdScript()` 方法返回 `true`。

2. **区分由普通脚本和广告脚本加载的资源:**  通过参数化测试 `AdTrackerVanillaOrAdSimTest`，该文件测试了在不同情况下（脚本本身是广告脚本还是普通脚本）加载的各种资源（例如，外部样式表、字体、图片）是否被正确标记为广告资源。

    *   **与 JavaScript, HTML, CSS 的关系:**
        *   **JavaScript:** 用于动态添加 `<link>` 标签来引入样式表。
        *   **HTML:**  包含 `<link>` 标签引入外部样式表，以及 `<script>` 标签引入脚本。
        *   **CSS:**  定义样式，并可能通过 `@import` 引入其他样式表，或通过 `url()` 引用图片和字体。
        `AdTracker` 需要判断这些通过不同方式加载的资源是否是由广告脚本直接或间接触发的。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，其中包含一个通过 `<script>` 标签引入的脚本（可能是广告脚本，也可能是普通脚本）。
            *   该脚本动态创建一个 `<link>` 标签，指向一个外部样式表。
            *   该样式表通过 `url()` 引用一个字体文件和一个图片文件。
        *   **输出:** `AdTracker` 的 `RequestWithUrlTaggedAsAd()` 方法能够根据脚本是否为广告脚本，正确地标记样式表、字体和图片资源。

3. **识别嵌套在广告 frame 中的资源:** 测试用例验证了如果一个 frame 被标记为广告 frame，那么该 frame 中加载的样式表以及样式表中引用的资源（字体、图片）也会被标记为广告资源。

    *   **与 HTML, CSS 的关系:** HTML 用于创建 `iframe` 元素，CSS 用于定义 frame 内元素的样式并引用其他资源。 `AdTracker` 需要能够沿着 frame 的层级结构传播广告标记。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个包含 `iframe` 的主页面。
            *   该 `iframe` 加载一个包含 `<link>` 标签的 HTML 页面，该标签指向一个外部样式表。
            *   该样式表引用字体和图片。
            *   在某些测试中，该 `iframe` 被显式标记为广告 frame。
        *   **输出:** 如果 iframe 是广告 frame，则其加载的样式表以及样式表中引用的字体和图片都会被 `AdTracker` 标记为广告资源。

4. **处理通过 JavaScript 设置的内联样式:** 测试用例验证了通过 JavaScript 设置元素的 `style` 属性，并且该样式中包含 `url()` 引用的资源（例如，背景图片），这些资源是否能被正确标记为广告资源，取决于设置该样式的脚本是否为广告脚本。

    *   **与 JavaScript, HTML, CSS 的关系:** JavaScript 用于操作 DOM 元素的样式，CSS 属性（例如 `background-image`）可以引用资源。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，包含一个带有特定 class 的 `div` 元素。
            *   一个脚本（可能是广告脚本），通过 JavaScript 获取该 `div` 元素，并设置其 `style` 属性，例如 `div.style.backgroundImage = "url('pixel.png')";`。
        *   **输出:** 如果脚本是广告脚本，则 `pixel.png` 会被 `AdTracker` 标记为广告资源。

5. **区分主 frame 和子 frame 中的样式标签的资源:**  测试用例验证了主 frame 中的 `<style>` 标签引入的资源不会被标记为广告，而子 frame（特别是广告 frame）中的 `<style>` 标签引入的资源会被标记为广告。

    *   **与 HTML, CSS 的关系:** HTML 中的 `<style>` 标签允许直接嵌入 CSS 代码。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个包含 `<style>` 标签的主页面，该标签引用字体和图片。
            *   或者，一个包含 `iframe` 的主页面，该 `iframe` 加载的页面包含 `<style>` 标签并引用字体和图片，并且该 `iframe` 被标记为广告 frame。
        *   **输出:** 主页面 `<style>` 标签中的资源不会被标记为广告，而广告 frame 中 `<style>` 标签中的资源会被标记为广告。

6. **处理通过 JavaScript 动态添加的样式标签:** 测试用例验证了通过 JavaScript 创建并添加到页面的 `<style>` 标签中引用的资源，是否会被标记为广告资源，取决于创建该标签的脚本是否为广告脚本。

    *   **与 JavaScript, HTML, CSS 的关系:** JavaScript 用于创建和操作 DOM 元素，包括动态创建 `<style>` 标签并添加 CSS 规则。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，包含一个脚本（可能是广告脚本）。
            *   该脚本通过 JavaScript 创建一个 `<style>` 元素，设置其内容（包含对字体和图片的引用），然后将该元素添加到页面的 `<head>` 中。
        *   **输出:** 如果创建 `<style>` 标签的脚本是广告脚本，则引用的字体和图片资源会被 `AdTracker` 标记为广告资源。

7. **处理样式表中的 `@import` 规则:** 测试用例验证了在样式表中使用 `@import` 引入的其他样式表以及被引入的样式表中引用的资源是否会被标记为广告资源，取决于引入的样式表本身是否被认为是广告样式表。

    *   **与 CSS 的关系:** `@import` 是 CSS 中用于引入其他样式表的规则。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，引入一个样式表（可能是广告样式表）。
            *   该样式表使用 `@import url("imported.css");` 引入另一个样式表。
            *   `imported.css` 中引用了字体和图片。
        *   **输出:** 如果引入的样式表是广告样式表，那么 `imported.css` 和其中引用的字体和图片都会被 `AdTracker` 标记为广告资源。

8. **处理样式表中的 `-webkit-image-set`:** 测试用例验证了在样式表中使用 `-webkit-image-set` 定义的背景图片是否会被标记为广告资源，取决于包含该样式的样式表是否为广告样式表。

    *   **与 CSS 的关系:** `-webkit-image-set` 是一个 CSS 函数，允许根据不同的像素密度指定不同的图片资源。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，引入一个样式表（可能是广告样式表）。
            *   该样式表包含类似 `.test { background-image: -webkit-image-set(url("pixel.png") 1x, url("pixel-2x.png") 2x); }` 的 CSS 规则。
        *   **输出:** 如果样式表是广告样式表，那么 `pixel.png` 和 `pixel-2x.png` 都会被 `AdTracker` 标记为广告资源。

9. **处理通过 `CSSStyleSheet` 接口创建的样式表:** 测试用例验证了使用 `new CSSStyleSheet()` 创建并通过 `document.adoptedStyleSheets` 应用到文档的样式表中引用的资源是否会被标记为广告资源，取决于创建该样式表的脚本是否为广告脚本。

    *   **与 JavaScript, CSS 的关系:**  JavaScript 提供了 `CSSStyleSheet` 接口来创建和操作样式表对象。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，包含一个脚本（可能是广告脚本）。
            *   该脚本使用 `new CSSStyleSheet()` 创建一个样式表对象，并使用 `insertRule()` 添加包含对字体和图片引用的 CSS 规则，最后将该样式表对象添加到 `document.adoptedStyleSheets`。
        *   **输出:** 如果创建 `CSSStyleSheet` 的脚本是广告脚本，则引用的字体和图片资源会被 `AdTracker` 标记为广告资源。

10. **测试由广告脚本触发的样式重计算导致的资源加载:** 测试用例验证了即使资源是由广告脚本触发的样式重计算导致的加载，如果这些资源本身不是由广告相关的 CSS 引入的，它们也不会被标记为广告资源。

    *   **与 JavaScript, HTML, CSS 的关系:**  JavaScript 可以动态修改 DOM 结构或元素属性，从而触发浏览器的样式重计算，这可能会导致新的资源加载。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，包含一个普通的外部样式表和一个广告脚本。
            *   该样式表定义了一些样式规则，引用了字体和图片。
            *   广告脚本运行时，通过修改 DOM 元素的 class 等属性，触发了样式重计算，导致字体和图片被加载。
        *   **输出:** 即使资源加载是由广告脚本触发的，但由于这些资源是由普通的样式表引入的，它们不会被 `AdTracker` 标记为广告资源。

11. **测试动态添加的无 `src` 属性的脚本标签:** 测试用例验证了通过广告脚本动态创建的没有 `src` 属性的 `<script>` 标签，即使后来被用于执行代码并加载资源，其加载的资源仍然会被标记为广告资源。

    *   **与 JavaScript, HTML 的关系:** JavaScript 可以动态创建 `<script>` 标签并添加到页面中，可以通过 `appendChild` 添加文本节点来包含脚本代码。

    *   **假设输入与输出:**
        *   **输入:**
            *   一个 HTML 页面，包含一个广告脚本。
            *   广告脚本动态创建一个没有 `src` 属性的 `<script>` 标签，并添加包含 `fetch('pixel.png')` 代码的文本节点。
            *   另一个普通脚本调用了动态添加的脚本中定义的函数，该函数执行 `fetch('pixel.png')`。
        *   **输出:** `pixel.png` 会被 `AdTracker` 标记为广告资源。

12. **测试动态添加的无 `src` 属性的脚本标签（非广告脚本创建）：** 测试用例验证了如果一个没有 `src` 属性的 `<script>` 标签不是由广告脚本创建的，即使之后被广告脚本调用，其加载的资源也不会被标记为广告资源。

13. **测试模块脚本:** 测试用例验证了模块脚本（`<script type="module">`）加载的资源是否会被标记为广告资源，取决于该模块脚本本身是否被认为是广告脚本。

14. **测试带有 `sourceURL` 的广告脚本:**  测试用例确认了即使广告脚本定义了 `//# sourceURL`，它加载的资源仍然会被正确标记为广告资源。

15. **测试禁用了 AdTracker 的情况:**  `AdTrackerDisabledSimTest` 测试类验证了当 AdTracker 功能被禁用时，相关的 API 调用（例如 `GetDocument().GetFrame()->GetAdTracker()` 和 `GetDocument().GetFrame()->IsAdFrame()`）会返回预期的结果（通常是 `nullptr` 或 `false`）。

总的来说，这部分测试用例覆盖了各种场景，旨在确保 `AdTracker` 能够准确地识别哪些资源是由广告引入或加载的，即使这些资源是通过复杂的 JavaScript 操作或 CSS 规则间接加载的。这对于浏览器正确地处理广告行为和实施相关策略至关重要。

**用户或编程常见的使用错误示例:**

*   **错误地假设只有通过 `<script>` 标签直接引入的脚本才会被认为是广告脚本。** 实际上，通过广告脚本动态创建的脚本或样式也会被纳入考虑。
*   **未能考虑到 iframe 的广告属性会影响其内部资源的标记。**  开发者可能认为在非广告主页面加载的 iframe 中的资源就一定不是广告，但如果该 iframe 被标记为广告 frame，情况就不同了。
*   **忽略了通过 JavaScript 动态修改样式或添加样式表也会触发资源加载，并且这些资源可能被标记为广告资源。**
*   **在测试环境中未能正确设置 `AdTracker` 的 ad suffix，导致测试结果不准确。**  例如，测试用例中使用了 `ad_tracker_->SetAdSuffix("ad=true");` 来模拟广告 URL 的标记。如果开发者在本地测试时忘记设置或设置错误，就可能观察到与预期不符的行为。

Prompt: 
```
这是目录为blink/renderer/core/frame/ad_tracker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能

"""
;
  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete(R"HTML(
    <body></body><script src=ad_script.js></script>
    )HTML");
  ad_resource.Complete(R"SCRIPT(
    var iframe = document.createElement("iframe");
    iframe.src = "iframe.html";
    document.body.appendChild(iframe);
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  iframe_resource.Complete("iframe data");

  auto* subframe =
      To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
  EXPECT_TRUE(subframe->IsFrameCreatedByAdScript());
}

TEST_F(AdTrackerSimTest, SameOriginDocWrittenSubframeFromAdScript) {
  SimSubresourceRequest ad_resource("https://example.com/ad_script.js",
                                    "text/javascript");
  ad_tracker_->SetAdSuffix("ad_script.js");

  main_resource_->Complete(R"HTML(
    <body></body><script src=ad_script.js></script>
    )HTML");
  ad_resource.Complete(R"SCRIPT(
    var iframe = document.createElement("iframe");
    document.body.appendChild(iframe);
    var iframeDocument = iframe.contentWindow.document;
    iframeDocument.open();
    iframeDocument.write("iframe data");
    iframeDocument.close();
    )SCRIPT");

  // Wait for script to run.
  base::RunLoop().RunUntilIdle();

  auto* subframe =
      To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
  EXPECT_TRUE(subframe->IsFrameCreatedByAdScript());
}

// This test class allows easy running of tests that only differ by whether
// one resource (or a set of resources) is vanilla or an ad.
class AdTrackerVanillaOrAdSimTest : public AdTrackerSimTest,
                                    public ::testing::WithParamInterface<bool> {
 public:
  bool IsAdRun() { return GetParam(); }

  String FlipURLOnAdRun(String vanilla_url) {
    return IsAdRun() ? vanilla_url + "?ad=true" : vanilla_url;
  }
};

TEST_P(AdTrackerVanillaOrAdSimTest, VanillaExternalStylesheetLoadsResources) {
  String vanilla_stylesheet_url = "https://example.com/style.css";
  String font_url = FlipURLOnAdRun("https://example.com/font.woff2");
  String image_url = FlipURLOnAdRun("https://example.com/pixel.png");
  SimSubresourceRequest stylesheet(vanilla_stylesheet_url, "text/css");
  SimSubresourceRequest font(font_url, "font/woff2");
  SimSubresourceRequest image(image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(kPageWithVanillaExternalStylesheet);
  stylesheet.Complete(IsAdRun() ? kStylesheetWithAdResources
                                : kStylesheetWithVanillaResources);

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(font_url);
  ad_tracker_->WaitForSubresource(image_url);

  font.Complete();
  image.Complete();

  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_stylesheet_url));
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(font_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(image_url), IsAdRun());
}

TEST_P(AdTrackerVanillaOrAdSimTest, AdExternalStylesheetLoadsResources) {
  String ad_stylesheet_url = "https://example.com/style.css?ad=true";
  String font_url = FlipURLOnAdRun("https://example.com/font.woff2");
  String image_url = FlipURLOnAdRun("https://example.com/pixel.png");
  SimSubresourceRequest stylesheet(ad_stylesheet_url, "text/css");
  SimSubresourceRequest font(font_url, "font/woff2");
  SimSubresourceRequest image(image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(kPageWithAdExternalStylesheet);
  stylesheet.Complete(IsAdRun() ? kStylesheetWithAdResources
                                : kStylesheetWithVanillaResources);

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(font_url);
  ad_tracker_->WaitForSubresource(image_url);

  font.Complete();
  image.Complete();

  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(ad_stylesheet_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(font_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(image_url));
}

TEST_P(AdTrackerVanillaOrAdSimTest, LinkRelStylesheetAddedByScript) {
  String script_url = FlipURLOnAdRun("https://example.com/script.js");
  String vanilla_stylesheet_url = "https://example.com/style.css";
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest script(script_url, "text/javascript");
  SimSubresourceRequest stylesheet(vanilla_stylesheet_url, "text/css");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(IsAdRun() ? kPageWithAdScript
                                     : kPageWithVanillaScript);
  script.Complete(R"SCRIPT(
    let link = document.createElement("link");
    link.rel = "stylesheet";
    link.href = "style.css";
    document.head.appendChild(link);
    )SCRIPT");

  // Wait for script to run.
  ad_tracker_->WaitForSubresource(vanilla_stylesheet_url);

  stylesheet.Complete(kStylesheetWithVanillaResources);

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(script_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_stylesheet_url),
            IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

TEST_P(AdTrackerVanillaOrAdSimTest, ExternalStylesheetInFrame) {
  String vanilla_stylesheet_url = "https://example.com/style.css";
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimRequest frame("https://example.com/frame.html", "text/html");
  SimSubresourceRequest stylesheet(vanilla_stylesheet_url, "text/css");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(kPageWithFrame);
  if (IsAdRun()) {
    auto* subframe =
        To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
    SetIsAdFrame(subframe);
  }

  frame.Complete(kPageWithVanillaExternalStylesheet);
  stylesheet.Complete(kStylesheetWithVanillaResources);
  Compositor().BeginFrame();

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_stylesheet_url),
            IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

// Note that we skip fonts as at rules aren't valid in inline CSS.
TEST_P(AdTrackerVanillaOrAdSimTest, InlineCSSSetByScript) {
  String script_url = FlipURLOnAdRun("https://example.com/script.js");
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest script(script_url, "text/javascript");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(IsAdRun() ? kPageWithAdScript
                                     : kPageWithVanillaScript);
  script.Complete(R"SCRIPT(
    let div = document.getElementsByClassName("test")[0];
    div.style = "background-image: url('pixel.png');";
    )SCRIPT");

  ad_tracker_->WaitForSubresource(vanilla_image_url);

  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(script_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

TEST_F(AdTrackerSimTest, StyleTagInMainframe) {
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(kPageWithStyleTagLoadingVanillaResources);

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

// This verifies that style tag resources in ad frames are correctly tagged
// according to the heuristic that all requests from an ad frame should also be
// tagged as ads.
TEST_P(AdTrackerVanillaOrAdSimTest, StyleTagInSubframe) {
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimRequest frame("https://example.com/frame.html", "text/html");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(kPageWithFrame);
  if (IsAdRun()) {
    auto* subframe =
        To<LocalFrame>(GetDocument().GetFrame()->Tree().FirstChild());
    SetIsAdFrame(subframe);
  }

  frame.Complete(kPageWithStyleTagLoadingVanillaResources);

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

TEST_P(AdTrackerVanillaOrAdSimTest, StyleTagAddedByScript) {
  String script_url = FlipURLOnAdRun("https://example.com/script.js");
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest script(script_url, "text/javascript");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(IsAdRun() ? kPageWithAdScript
                                     : kPageWithVanillaScript);
  script.Complete(String::Format(
      R"SCRIPT(
        let style = document.createElement("style");
        let text = document.createTextNode(`%s`);
        style.appendChild(text);
        document.head.appendChild(style);
      )SCRIPT",
      kStylesheetWithVanillaResources));

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(script_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

TEST_P(AdTrackerVanillaOrAdSimTest, VanillaImportInStylesheet) {
  String stylesheet_url = FlipURLOnAdRun("https://example.com/style.css");
  String vanilla_imported_stylesheet_url = "https://example.com/imported.css";
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest stylesheet(stylesheet_url, "text/css");
  SimSubresourceRequest imported_stylesheet(vanilla_imported_stylesheet_url,
                                            "text/css");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(IsAdRun() ? kPageWithAdExternalStylesheet
                                     : kPageWithVanillaExternalStylesheet);
  stylesheet.Complete(R"CSS(
    @import url(imported.css);
  )CSS");
  imported_stylesheet.Complete(kStylesheetWithVanillaResources);

  // Wait for stylesheets to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(stylesheet_url), IsAdRun());
  EXPECT_EQ(
      ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_imported_stylesheet_url),
      IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

TEST_P(AdTrackerVanillaOrAdSimTest, AdImportInStylesheet) {
  String stylesheet_url = FlipURLOnAdRun("https://example.com/style.css");
  String ad_imported_stylesheet_url =
      "https://example.com/imported.css?ad=true";
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest stylesheet(stylesheet_url, "text/css");
  SimSubresourceRequest imported_stylesheet(ad_imported_stylesheet_url,
                                            "text/css");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(IsAdRun() ? kPageWithAdExternalStylesheet
                                     : kPageWithVanillaExternalStylesheet);
  stylesheet.Complete(R"CSS(
    @import url(imported.css?ad=true);
  )CSS");
  imported_stylesheet.Complete(kStylesheetWithVanillaResources);

  // Wait for stylesheets to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(stylesheet_url), IsAdRun());
  EXPECT_TRUE(
      ad_tracker_->RequestWithUrlTaggedAsAd(ad_imported_stylesheet_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

TEST_P(AdTrackerVanillaOrAdSimTest, ImageSetInStylesheet) {
  String stylesheet_url = FlipURLOnAdRun("https://example.com/style.css");
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest stylesheet(stylesheet_url, "text/css");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(IsAdRun() ? kPageWithAdExternalStylesheet
                                     : kPageWithVanillaExternalStylesheet);

  // The image with the lowest scale factor that is still larger than the
  // device's scale factor is used.
  stylesheet.Complete(R"CSS(
    .test {
      background-image: -webkit-image-set( url("pixel.png") 100x,
                                           url("too_high.png") 999x);
    }
  )CSS");

  // Wait for stylesheet to fetch resource.
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(stylesheet_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

TEST_P(AdTrackerVanillaOrAdSimTest, ConstructableCSSCreatedByScript) {
  String script_url = FlipURLOnAdRun("https://example.com/script.js");
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest script(script_url, "text/javascript");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(IsAdRun() ? kPageWithAdScript
                                     : kPageWithVanillaScript);
  script.Complete(R"SCRIPT(
    const sheet = new CSSStyleSheet();
    sheet.insertRule(`
      @font-face {
        font-family: "Vanilla";
        src: url("font.woff2") format("woff2");
      }`);
    sheet.insertRule(`
      .test {
        font-family: "Vanilla";
        background-image: url("pixel.png");
      }`);
    document.adoptedStyleSheets = [sheet];
  )SCRIPT");

  // Wait for stylesheet to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(script_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url), IsAdRun());
  EXPECT_EQ(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url),
            IsAdRun());
}

// Vanilla resources loaded due to an ad's script's style recalculation
// shouldn't be tagged.
TEST_F(AdTrackerSimTest, StyleRecalcCausedByAdScript) {
  String ad_script_url = "https://example.com/script.js?ad=true";
  String vanilla_stylesheet_url = "https://example.com/style.css";
  String vanilla_font_url = "https://example.com/font.woff2";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest script(ad_script_url, "text/javascript");
  SimSubresourceRequest stylesheet(vanilla_stylesheet_url, "text/css");
  SimSubresourceRequest font(vanilla_font_url, "font/woff2");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(R"HTML(
    <head><link rel="stylesheet" href="style.css">
        <script async src="script.js?ad=true"></script></head>
    <body><div>Test</div></body>
  )HTML");
  stylesheet.Complete(kStylesheetWithVanillaResources);

  Compositor().BeginFrame();
  base::RunLoop().RunUntilIdle();
  // @font-face rules have fetches set up for src descriptors when the font face
  // is initialized in FontFace::InitCSSFontFace(). The fetch is not actually
  // performed, but the AdTracker is notified.
  EXPECT_TRUE(ad_tracker_->UrlHasBeenRequested(vanilla_font_url));
  EXPECT_FALSE(ad_tracker_->UrlHasBeenRequested(vanilla_image_url));

  // We override these to ensure the ad script appears on top of the stack when
  // the requests are made.
  ad_tracker_->SetExecutionContext(GetDocument().GetExecutionContext());
  ad_tracker_->SetScriptAtTopOfStack(ad_script_url);

  script.Complete(R"SCRIPT(
    let div = document.getElementsByTagName("div")[0];
    div.className = "test";
  )SCRIPT");

  // Wait for stylesheets to fetch resources.
  ad_tracker_->WaitForSubresource(vanilla_font_url);
  ad_tracker_->WaitForSubresource(vanilla_image_url);

  font.Complete();
  image.Complete();

  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(ad_script_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_stylesheet_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_font_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

// A dynamically added script with no src is still tagged as an ad if created
// by an ad script.
TEST_F(AdTrackerSimTest, DynamicallyAddedScriptNoSrc_StillTagged) {
  String ad_script_url = "https://example.com/script.js?ad=true";
  String vanilla_script_url = "https://example.com/script.js";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest ad_script(ad_script_url, "text/javascript");
  SimSubresourceRequest vanilla_script(vanilla_script_url, "text/javascript");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(R"HTML(
    <body><script src="script.js?ad=true"></script>
        <script src="script.js"></script></body>
  )HTML");

  ad_script.Complete(R"SCRIPT(
    let script = document.createElement("script");
    let text = document.createTextNode(
        "function getImage() { fetch('pixel.png'); }");
    script.appendChild(text);
    document.body.appendChild(script);
  )SCRIPT");

  // Fetch a resource using the function defined by dynamically added ad script.
  vanilla_script.Complete(R"SCRIPT(
    getImage();
  )SCRIPT");

  ad_tracker_->WaitForSubresource(vanilla_image_url);

  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(ad_script_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_script_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

// A dynamically added script with no src isn't tagged as an ad if not created
// by an ad script, even if it's later used by an ad script.
TEST_F(AdTrackerSimTest,
       DynamicallyAddedScriptNoSrc_NotTaggedBasedOnUseByAdScript) {
  String vanilla_script_url = "https://example.com/script.js";
  String ad_script_url = "https://example.com/script.js?ad=true";
  String vanilla_script2_url = "https://example.com/script2.js";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest vanilla_script(vanilla_script_url, "text/javascript");
  SimSubresourceRequest ad_script(ad_script_url, "text/javascript");
  SimSubresourceRequest vanilla_script2(vanilla_script2_url, "text/javascript");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(R"HTML(
    <body><script src="script.js"></script>
        <script src="script.js?ad=true"></script>
        <script src="script2.js"></script></body>
  )HTML");

  vanilla_script.Complete(R"SCRIPT(
    let script = document.createElement("script");
    let text = document.createTextNode(
        "function doNothing() {} " +
        "function getImage() { fetch('pixel.png'); }");
    script.appendChild(text);
    document.body.appendChild(script);
  )SCRIPT");

  ad_script.Complete(R"SCRIPT(
    doNothing();
  )SCRIPT");

  vanilla_script2.Complete(R"SCRIPT(
    getImage();
  )SCRIPT");

  ad_tracker_->WaitForSubresource(vanilla_image_url);

  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_script_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(ad_script_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_script2_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

TEST_F(AdTrackerSimTest, VanillaModuleScript_ResourceNotTagged) {
  String vanilla_script_url = "https://example.com/script.js";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest vanilla_script(vanilla_script_url, "text/javascript");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(R"HTML(
    <head><script type="module" src="script.js"></script></head>
    <body><div>Test</div></body>
  )HTML");

  vanilla_script.Complete(R"SCRIPT(
    fetch('pixel.png');
  )SCRIPT");

  ad_tracker_->WaitForSubresource(vanilla_image_url);

  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_script_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

TEST_F(AdTrackerSimTest, AdModuleScript_ResourceTagged) {
  String ad_script_url = "https://example.com/script.js?ad=true";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest ad_script(ad_script_url, "text/javascript");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(R"HTML(
    <head><script type="module" src="script.js?ad=true"></script></head>
    <body><div>Test</div></body>
  )HTML");

  ad_script.Complete(R"SCRIPT(
    fetch('pixel.png');
  )SCRIPT");

  ad_tracker_->WaitForSubresource(vanilla_image_url);

  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(ad_script_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

// A resource fetched with ad script at top of stack is still tagged as an ad
// when the ad script defines a sourceURL.
TEST_F(AdTrackerSimTest, AdScriptWithSourceURLAtTopOfStack_StillTagged) {
  String vanilla_script_url = "https://example.com/script.js";
  String ad_script_url = "https://example.com/script.js?ad=true";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest vanilla_script(vanilla_script_url, "text/javascript");
  SimSubresourceRequest ad_script(ad_script_url, "text/javascript");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(R"HTML(
    <head><script src="script.js?ad=true"></script>
          <script src="script.js"></script></head>
    <body><div>Test</div></body>
  )HTML");

  // We don't directly fetch in ad script as we aim to test ScriptAtTopOfStack()
  // not WillExecuteScript().
  ad_script.Complete(R"SCRIPT(
    function getImage() { fetch('pixel.png'); }
    //# sourceURL=source.js
  )SCRIPT");

  vanilla_script.Complete(R"SCRIPT(
    getImage();
  )SCRIPT");

  ad_tracker_->WaitForSubresource(vanilla_image_url);

  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(ad_script_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_script_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

// A dynamically added script with no src is still tagged as an ad if created
// by an ad script even if it defines a sourceURL.
TEST_F(AdTrackerSimTest, InlineAdScriptWithSourceURLAtTopOfStack_StillTagged) {
  String ad_script_url = "https://example.com/script.js?ad=true";
  String vanilla_script_url = "https://example.com/script.js";
  String vanilla_image_url = "https://example.com/pixel.png";
  SimSubresourceRequest ad_script(ad_script_url, "text/javascript");
  SimSubresourceRequest vanilla_script(vanilla_script_url, "text/javascript");
  SimSubresourceRequest image(vanilla_image_url, "image/png");

  ad_tracker_->SetAdSuffix("ad=true");

  main_resource_->Complete(R"HTML(
    <body><script src="script.js?ad=true"></script>
        <script src="script.js"></script></body>
  )HTML");

  ad_script.Complete(R"SCRIPT(
    let script = document.createElement("script");
    let text = document.createTextNode(
        "function getImage() { fetch('pixel.png'); } \n"
        + "//# sourceURL=source.js");
    script.appendChild(text);
    document.body.appendChild(script);
  )SCRIPT");

  // Fetch a resource using the function defined by dynamically added ad script.
  vanilla_script.Complete(R"SCRIPT(
    getImage();
  )SCRIPT");

  ad_tracker_->WaitForSubresource(vanilla_image_url);

  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(ad_script_url));
  EXPECT_FALSE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_script_url));
  EXPECT_TRUE(ad_tracker_->RequestWithUrlTaggedAsAd(vanilla_image_url));
}

class AdTrackerDisabledSimTest : public SimTest,
                                 private ScopedAdTaggingForTest {
 protected:
  AdTrackerDisabledSimTest() : ScopedAdTaggingForTest(false) {}
  void SetUp() override {
    SimTest::SetUp();
    main_resource_ = std::make_unique<SimRequest>(
        "https://example.com/test.html", "text/html");

    LoadURL("https://example.com/test.html");
  }

  std::unique_ptr<SimRequest> main_resource_;
};

TEST_F(AdTrackerDisabledSimTest, VerifyAdTrackingDisabled) {
  main_resource_->Complete("<body></body>");
  EXPECT_FALSE(GetDocument().GetFrame()->GetAdTracker());
  EXPECT_FALSE(GetDocument().GetFrame()->IsAdFrame());
}

INSTANTIATE_TEST_SUITE_P(All,
                         AdTrackerVanillaOrAdSimTest,
                         ::testing::Values(true, false));

}  // namespace blink

"""


```