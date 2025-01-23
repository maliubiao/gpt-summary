Response:
Let's break down the thought process for analyzing the provided C++ test file.

1. **Understand the Goal:** The core task is to understand what this test file is doing and how it relates to web technologies (JavaScript, HTML, CSS). The filename `document_loading_rendering_test.cc` gives a strong hint: it's about testing how the browser renders content as a document loads.

2. **High-Level Structure and Keywords:**  Scan the file for key elements:
    * `#include`:  These tell us the libraries and components being tested. Notice mentions of `gtest`, `Document`, `FrameRequestCallbackCollection`, `LayoutView`, `PaintLayer`, `SimTest`, etc. These are all Blink (Chromium's rendering engine) specific.
    * `namespace blink`: This confirms we're in Blink's codebase.
    * `class DocumentLoadingRenderingTest : public SimTest`:  This establishes the test fixture. `SimTest` suggests a simulated environment, meaning actual network requests aren't necessarily involved.
    * `TEST_F(...)`: This is the Google Test framework macro for defining individual test cases. The names of the tests (`ShouldResumeCommitsAfterBodyParsedWithoutSheets`, `ShouldResumeCommitsAfterBodyIfSheetsLoaded`, etc.) are extremely informative about the specific scenarios being tested.

3. **Focus on Individual Test Cases:** The most effective way to understand the file is to analyze each `TEST_F` function in detail.

4. **Deconstruct a Test Case (Example: `ShouldResumeCommitsAfterBodyParsedWithoutSheets`):**
    * **Setup:** `SimRequest main_resource(...)`, `LoadURL(...)`. This sets up a simulated HTTP request for a basic HTML page.
    * **Head Content:** `main_resource.Write("<!DOCTYPE html>");`, `main_resource.Write("<title>Test</title><style>div { color red; }</style>");`. This simulates the browser receiving parts of the HTML, specifically the `<head>` section. The `EXPECT_TRUE(Compositor().DeferMainFrameUpdate())` is crucial. It's asserting that rendering updates are being *deferred* at this stage.
    * **Body Content:** `main_resource.Write("<p>Hello World</p>");`. This simulates the start of the `<body>`. The key assertion here is `EXPECT_FALSE(Compositor().DeferMainFrameUpdate())`. This means rendering is now *resumed*.
    * **Finish Load:** `main_resource.Finish()`. The page is fully loaded. The assertion `EXPECT_FALSE(...)` confirms rendering remains resumed.
    * **Inference:** The test demonstrates that when a basic HTML page without external stylesheets is encountered, rendering is paused during the `<head>` parsing and resumes once the `<body>` starts.

5. **Identify Key Concepts and Relationships:** As you analyze multiple test cases, look for recurring patterns and concepts:
    * **Commits/Rendering Updates:** The `Compositor().DeferMainFrameUpdate()` checks are central. This relates to the browser's rendering pipeline and when it chooses to paint updates to the screen.
    * **Stylesheets:** Several tests explicitly deal with `<link rel="stylesheet">` and the loading of CSS. The tests show that rendering is often deferred until stylesheets are loaded.
    * **Document Structure:** The parsing of `<head>`, `<body>`, and the root element (like `<svg>` for SVG documents) are important triggers for rendering decisions.
    * **Resource Loading:** `SimRequest` and `SimSubresourceRequest` are used to simulate the loading of the main HTML and associated resources (like CSS).
    * **Iframes:** One test specifically focuses on how iframe content is rendered, especially when stylesheets are involved. This highlights the complexity of managing rendering across different frames.
    * **RequestAnimationFrame (RAF):** One test checks how RAF callbacks are handled in iframes when stylesheets are loading. This relates to JavaScript animation timing and synchronization with the rendering pipeline.

6. **Connect to Web Technologies:** Now, make the explicit links to JavaScript, HTML, and CSS:
    * **HTML:** The tests directly manipulate HTML structure using `main_resource.Write(...)`. The presence of `<link>`, `<style>`, `<body>`, `<iframe>`, and the overall document structure are key.
    * **CSS:** The tests simulate loading external CSS files and inline styles. The behavior of rendering based on whether stylesheets are loaded or pending is a major focus.
    * **JavaScript:** While no explicit JavaScript code is run *in the test*, the test about `RequestAnimationFrame` shows an indirect relationship. RAF is a JavaScript API, and the test verifies how its execution is tied to the loading and rendering state.

7. **Logical Reasoning (Hypothetical Inputs and Outputs):** For each test, think about the "input" (the sequence of HTML content and resource loading) and the expected "output" (whether `DeferMainFrameUpdate()` is true or false at different points). This is implicitly done in the assertions within the tests. You can formalize this by describing the scenario and the expected rendering behavior.

8. **Common Usage Errors:**  Consider what mistakes web developers might make that these tests are designed to prevent or highlight. For example:
    * **"Flash of Unstyled Content (FOUC)":**  The tests about stylesheet loading directly relate to preventing FOUC. The browser delays rendering until stylesheets are loaded to avoid showing unstyled content briefly.
    * **Script execution order:**  While not directly tested here, the deferral of rendering has implications for when JavaScript can safely interact with the DOM and styles.

9. **Structure the Explanation:**  Organize the findings logically:
    * Start with a high-level summary of the file's purpose.
    * Detail the core functionalities, referencing specific test cases as examples.
    * Explain the relationships to HTML, CSS, and JavaScript with concrete examples.
    * Provide hypothetical input/output scenarios based on the test logic.
    * Discuss common developer errors that the tests help to avoid.

10. **Refine and Elaborate:** Review the explanation for clarity and completeness. Ensure that the technical terms are explained sufficiently and that the connections to web development practices are clear. For instance, explicitly defining "commits" in the rendering context can be helpful.
这个C++源代码文件 `document_loading_rendering_test.cc` 是 Chromium Blink 引擎中的一个单元测试文件。它的主要功能是**测试在文档加载过程中，渲染引擎如何管理和控制渲染的提交（commits）时机。**  更具体地说，它验证了在不同的文档加载阶段和资源加载状态下，渲染引擎是否会暂停或恢复渲染过程。

以下是它的功能分解和与 Web 技术的关系：

**核心功能：测试渲染提交的暂停和恢复机制**

渲染引擎为了优化性能和避免不必要的渲染，会在文档加载的不同阶段暂停渲染提交。这个测试文件旨在验证以下几种情况：

* **在 `<head>` 标签内且有外部样式表时，暂停渲染提交。**  浏览器需要先加载并解析样式表，才能进行正确的渲染。
* **在 `<head>` 标签内但没有外部样式表时，暂停渲染提交直到 `<body>` 标签开始解析。** 即使没有外部样式表，也要等到主体部分开始，才能进行首次有意义的渲染。
* **在外部样式表加载完成后，恢复渲染提交。** 一旦样式信息可用，就可以开始进行渲染。
* **对于 `image/png` 等图像类型的文档，在接收到第一个字节后立即恢复渲染提交。**  图像不需要像 HTML 那样进行复杂的解析和布局，可以尽早显示。
* **对于 XML/SVG 文档，在解析到根元素 `<svg>` 并且外部样式表加载完成后，恢复渲染提交。** XML 文档的渲染也依赖于样式信息。
* **测试 `iframe` 加载时，父窗口渲染是否会受到子窗口未加载完成的样式表的影响。** 这涉及到跨文档的渲染同步问题。
* **测试在 `<body>` 标签之后添加样式表是否会阻止后续渲染。** 理论上，在 `<body>` 之后添加的样式表也会影响渲染，需要暂停并等待加载完成。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个测试文件直接关联着 HTML 和 CSS 的加载和解析过程，并间接影响到 JavaScript 的执行时机和效果。

1. **HTML:**
   * **关系:** 测试模拟了浏览器接收 HTML 文档片段的过程，例如 `<head>`, `<body>`, `<link>`, `<style>`, `<iframe>` 等标签的解析。渲染提交的暂停和恢复直接与 HTML 结构的解析阶段相关。
   * **举例:**
      * `main_resource.Write("<!DOCTYPE html><link rel=stylesheet href=test.css>");`  这行代码模拟了浏览器接收到包含外部样式表链接的 HTML 片段。测试会验证此时渲染是否暂停。
      * `main_resource.Write("<body>");`  这行代码模拟了 `<body>` 标签的开始，测试会验证在没有未完成加载的样式表时，渲染是否恢复。
      * `<iframe id=frame src=frame.html>` 这行 HTML 代码创建了一个内联框架，测试涉及到父窗口和子窗口的渲染同步。

2. **CSS:**
   * **关系:** 测试的核心场景之一就是外部样式表的加载。渲染引擎需要等待 CSS 加载并解析完成后才能进行准确的渲染，避免出现“无样式内容闪烁 (FOUC)”。
   * **举例:**
      * `SimSubresourceRequest css_resource("https://example.com/test.css", "text/css");` 这行代码模拟了加载一个 CSS 资源。
      * `css_resource.Complete("a { color: red; }");` 这行代码模拟了 CSS 资源加载完成。测试会验证在 CSS 加载完成前后渲染提交的状态变化。
      * 测试用例 `ShouldNotPaintIframeContentWithPendingSheets` 演示了当 `iframe` 中有未加载完成的样式表时，父窗口进行渲染，但 `iframe` 的内容不会被绘制，避免显示不完整的样式。

3. **JavaScript:**
   * **关系:** 虽然这个测试文件没有直接执行 JavaScript 代码，但渲染提交的暂停和恢复会影响到 JavaScript 的执行时机和效果。例如，如果 JavaScript 尝试访问尚未渲染的元素或应用样式，可能会得到不期望的结果。另外，`RequestAnimationFrame` (RAF) 的回调执行也与渲染管线同步，测试用例 `ShouldThrottleIframeLifecycleUntilPendingSheetsLoaded` 验证了当 `iframe` 有未加载完成的样式表时，RAF 回调是否会被延迟执行。
   * **举例:**
      * 在测试用例 `ShouldThrottleIframeLifecycleUntilPendingSheetsLoaded` 中，使用了 `child_frame->contentDocument()->RequestAnimationFrame(frame1_callback);`  这说明渲染提交的状态会影响到 JavaScript 的动画回调执行。如果渲染被暂停等待样式表加载，RAF 的回调也会被推迟，以确保在应用样式后再执行动画。

**逻辑推理与假设输入输出：**

以测试用例 `ShouldResumeCommitsAfterBodyIfSheetsLoaded` 为例：

* **假设输入:**
    1. HTML 内容首先写入 `<head>` 部分，包含一个外部样式表的链接： `<!DOCTYPE html><link rel=stylesheet href=test.css>`
    2. 开始加载外部样式表 `test.css`。
    3. 在样式表加载完成之前，HTML 内容继续写入 `<body>` 标签：`<body>`
    4. 外部样式表 `test.css` 加载完成。
    5. HTML 文档加载完成。

* **逻辑推理:**
    1. 在 `<head>` 部分且有未完成加载的样式表时，渲染提交应该被暂停 (`EXPECT_TRUE(Compositor().DeferMainFrameUpdate())`).
    2. 即使 `<body>` 标签开始解析，但由于样式表仍在加载，渲染提交仍然应该被暂停 (`EXPECT_TRUE(Compositor().DeferMainFrameUpdate())`).
    3. 一旦外部样式表加载完成，并且已经开始解析 `<body>`，渲染提交应该被恢复 (`EXPECT_FALSE(Compositor().DeferMainFrameUpdate())`).
    4. 文档加载完成后，渲染提交应该保持恢复状态 (`EXPECT_FALSE(Compositor().DeferMainFrameUpdate())`).

* **预期输出 (基于 `EXPECT_*` 断言):**
    * 在写入 `<link>` 标签后: `Compositor().DeferMainFrameUpdate()` 为 `true`
    * 在样式表开始加载后: `Compositor().DeferMainFrameUpdate()` 为 `true`
    * 在写入 `<body>` 标签后 (样式表未完成): `Compositor().DeferMainFrameUpdate()` 为 `true`
    * 在样式表加载完成后: `Compositor().DeferMainFrameUpdate()` 为 `false`
    * 在文档加载完成后: `Compositor().DeferMainFrameUpdate()` 为 `false`

**用户或编程常见的使用错误举例：**

这个测试文件旨在确保浏览器引擎的行为符合预期，从而避免开发者因为引擎行为不一致而犯错。  以下是一些与此测试相关的常见错误：

1. **忘记在 `<head>` 中引入 CSS 导致 FOUC:**
   * **错误:**  开发者可能将 CSS 放在 `<body>` 的底部或者通过 JavaScript 动态添加，导致页面在初始加载时没有样式，然后突然应用样式，造成视觉上的闪烁。
   * **测试关联:** 测试用例验证了在 `<head>` 中引入 CSS 时，渲染引擎会等待 CSS 加载完成，这正是为了避免 FOUC。

2. **误以为所有资源加载完成后才开始渲染:**
   * **错误:**  一些开发者可能认为浏览器会等待整个 HTML 文档和所有资源都加载完成后才开始渲染。实际上，浏览器会尽早地进行首次渲染，并在资源加载过程中逐步更新渲染。
   * **测试关联:** 测试用例如 `ShouldResumeCommitsAfterBodyParsedWithoutSheets` 表明，即使没有外部样式表，渲染也会在 `<body>` 开始解析后恢复，而不是等到文档完全加载完成。

3. **在 `iframe` 中使用未加载完成的样式进行 JavaScript 操作:**
   * **错误:**  开发者可能在父窗口的 JavaScript 中操作 `iframe` 的 DOM，并假设 `iframe` 的样式已经加载完成。如果 `iframe` 的样式表还在加载，JavaScript 获取到的元素样式可能是不正确的。
   * **测试关联:** 测试用例 `ShouldNotPaintIframeContentWithPendingSheets` 和 `ShouldThrottleIframeLifecycleUntilPendingSheetsLoaded` 强调了 `iframe` 的渲染和生命周期会受到其自身样式表加载状态的影响，开发者需要注意这种异步性。

4. **依赖于特定渲染时机执行 JavaScript 代码:**
   * **错误:**  开发者可能编写依赖于特定渲染帧或渲染提交时机执行的 JavaScript 代码，例如在某个元素渲染出来后立即获取其尺寸。然而，渲染时机可能受到多种因素的影响，包括样式表加载、资源加载等，这种依赖可能导致代码在不同情况下表现不一致。
   * **测试关联:**  测试验证了渲染提交的控制逻辑，帮助开发者理解渲染时机的不确定性，并促使他们编写更健壮、不依赖于特定渲染时机的代码。

总而言之，`document_loading_rendering_test.cc` 这个文件是 Blink 引擎质量保证的重要组成部分，它通过测试各种文档加载场景下的渲染提交行为，确保浏览器能够以最佳的方式处理 Web 内容，并帮助开发者避免常见的与渲染相关的错误。

### 提示词
```
这是目录为blink/renderer/core/frame/document_loading_rendering_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/frame_request_callback_collection.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class DocumentLoadingRenderingTest : public SimTest {};

TEST_F(DocumentLoadingRenderingTest,
       ShouldResumeCommitsAfterBodyParsedWithoutSheets) {
  SimRequest main_resource("https://example.com/test.html", "text/html");

  LoadURL("https://example.com/test.html");

  // Still in the head, should not resume commits.
  main_resource.Write("<!DOCTYPE html>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  main_resource.Write("<title>Test</title><style>div { color red; }</style>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Implicitly inserts the body. Since there's no loading stylesheets we
  // should resume commits.
  main_resource.Write("<p>Hello World</p>");
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  // Finish the load, should stay resumed.
  main_resource.Finish();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(DocumentLoadingRenderingTest,
       ShouldResumeCommitsAfterBodyIfSheetsLoaded) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_resource("https://example.com/test.css",
                                     "text/css");

  LoadURL("https://example.com/test.html");

  // Still in the head, should not resume commits.
  main_resource.Write("<!DOCTYPE html><link rel=stylesheet href=test.css>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Sheet is streaming in, but not ready yet.
  css_resource.Start();
  css_resource.Write("a { color: red; }");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Sheet finished, but no body yet, so don't resume.
  css_resource.Finish();
  test::RunPendingTasks();
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Body inserted and sheet is loaded so resume commits.
  main_resource.Write("<body>");
  test::RunPendingTasks();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  // Finish the load, should stay resumed.
  main_resource.Finish();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(DocumentLoadingRenderingTest, ShouldResumeCommitsAfterSheetsLoaded) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_resource("https://example.com/test.css",
                                     "text/css");

  LoadURL("https://example.com/test.html");

  // Still in the head, should not resume commits.
  main_resource.Write("<!DOCTYPE html><link rel=stylesheet href=test.css>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Sheet is streaming in, but not ready yet.
  css_resource.Start();
  css_resource.Write("a { color: red; }");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Body inserted, but sheet is still loading so don't resume.
  main_resource.Write("<body>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Sheet finished and there's a body so resume.
  css_resource.Finish();
  test::RunPendingTasks();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  // Finish the load, should stay resumed.
  main_resource.Finish();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(DocumentLoadingRenderingTest,
       ShouldResumeCommitsAfterDocumentElementWithNoSheets) {
  SimRequest main_resource("https://example.com/test.svg", "image/svg+xml");
  SimSubresourceRequest css_resource("https://example.com/test.css",
                                     "text/css");

  LoadURL("https://example.com/test.svg");

  // Sheet loading and no documentElement, so don't resume.
  main_resource.Write("<?xml-stylesheet type='text/css' href='test.css'?>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Sheet finishes loading, but no documentElement yet so don't resume.
  css_resource.Complete("a { color: red; }");
  test::RunPendingTasks();
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Root inserted so resume.
  main_resource.Write("<svg xmlns='http://www.w3.org/2000/svg'></svg>");
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  // Finish the load, should stay resumed.
  main_resource.Finish();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(DocumentLoadingRenderingTest, ShouldResumeCommitsAfterSheetsLoadForXml) {
  SimRequest main_resource("https://example.com/test.svg", "image/svg+xml");
  SimSubresourceRequest css_resource("https://example.com/test.css",
                                     "text/css");

  LoadURL("https://example.com/test.svg");

  // Not done parsing.
  main_resource.Write("<?xml-stylesheet type='text/css' href='test.css'?>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Sheet is streaming in, but not ready yet.
  css_resource.Start();
  css_resource.Write("a { color: red; }");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Root inserted, but sheet is still loading so don't resume.
  main_resource.Write("<svg xmlns='http://www.w3.org/2000/svg'></svg>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Finish the load, but sheets still loading so don't resume.
  main_resource.Finish();
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Sheet finished, so resume commits.
  css_resource.Finish();
  test::RunPendingTasks();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(DocumentLoadingRenderingTest, ShouldResumeCommitsAfterFinishParsingXml) {
  SimRequest main_resource("https://example.com/test.svg", "image/svg+xml");

  LoadURL("https://example.com/test.svg");

  // Finish parsing, no sheets loading so resume.
  main_resource.Finish();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(DocumentLoadingRenderingTest, ShouldResumeImmediatelyForImageDocuments) {
  SimRequest main_resource("https://example.com/test.png", "image/png");

  LoadURL("https://example.com/test.png");

  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Not really a valid image but enough for the test. ImageDocuments should
  // resume painting as soon as the first bytes arrive.
  main_resource.Write("image data");
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  main_resource.Finish();
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(DocumentLoadingRenderingTest, ShouldScheduleFrameAfterSheetsLoaded) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest first_css_resource("https://example.com/first.css",
                                           "text/css");
  SimSubresourceRequest second_css_resource("https://example.com/second.css",
                                            "text/css");

  LoadURL("https://example.com/test.html");

  // Load a stylesheet.
  main_resource.Write(
      "<!DOCTYPE html><link id=link rel=stylesheet href=first.css>");
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  first_css_resource.Start();
  first_css_resource.Write("body { color: red; }");
  main_resource.Write("<body>");
  first_css_resource.Finish();
  test::RunPendingTasks();

  // Sheet finished and there's a body so resume.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  main_resource.Finish();
  Compositor().BeginFrame();

  // Replace the stylesheet by changing href.
  auto* element = GetDocument().getElementById(AtomicString("link"));
  EXPECT_NE(nullptr, element);
  element->setAttribute(html_names::kHrefAttr, AtomicString("second.css"));
  EXPECT_FALSE(Compositor().NeedsBeginFrame());

  second_css_resource.Complete("body { color: red; }");
  EXPECT_TRUE(Compositor().NeedsBeginFrame());
}

TEST_F(DocumentLoadingRenderingTest,
       ShouldNotPaintIframeContentWithPendingSheets) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");
  SimSubresourceRequest css_resource("https://example.com/test.css",
                                     "text/css");

  LoadURL("https://example.com/test.html");

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <body style='background: white'>
    <iframe id=frame src=frame.html style='border: none'></iframe>
    <p style='transform: translateZ(0)'>Hello World</p>
  )HTML");

  // Main page is ready to begin painting as there's no pending sheets.
  // The frame is not yet loaded, so we only paint the main frame.
  auto frame1 = Compositor().BeginFrame();
  EXPECT_EQ(2u, frame1.DrawCount());
  EXPECT_TRUE(frame1.Contains(SimCanvas::kText, "black"));
  EXPECT_TRUE(frame1.Contains(SimCanvas::kRect, "white"));

  frame_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>html { background: pink; color: gray; }</style>
    <link rel=stylesheet href=test.css>
    <p style='background: yellow;'>Hello World</p>
    <div style='transform: translateZ(0); background: green;'>
        <p style='background: blue;'>Hello Layer</p>
        <div style='position: relative; background: red;'>Hello World</div>
    </div>
  )HTML");

  // Trigger a layout with a blocking sheet. For example, a parent frame
  // executing a script that reads offsetTop in the child frame could do this.
  auto* child_frame = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("frame")));
  child_frame->contentDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kTest);

  auto frame2 = Compositor().BeginFrame();

  // The child frame still has a sheet blocking in head, so nothing is painted.
  // Still only paint the main frame.
  EXPECT_EQ(2u, frame2.DrawCount());
  EXPECT_TRUE(frame2.Contains(SimCanvas::kText, "black"));
  EXPECT_TRUE(frame2.Contains(SimCanvas::kRect, "white"));

  // Finish loading the sheets in the child frame. After it we should continue
  // parsing and paint the frame contents.
  css_resource.Complete();
  test::RunPendingTasks();

  // First frame where all frames are loaded, should paint the text in the
  // child frame.
  auto frame3 = Compositor().BeginFrame();
  EXPECT_EQ(10u, frame3.DrawCount());
  // Paint commands for the main frame.
  EXPECT_TRUE(frame3.Contains(SimCanvas::kText, "black"));
  EXPECT_TRUE(frame3.Contains(SimCanvas::kRect, "white"));
  // Paint commands for the child frame.
  EXPECT_EQ(3u, frame3.DrawCount(SimCanvas::kText, "gray"));
  EXPECT_TRUE(frame3.Contains(SimCanvas::kRect, "pink"));
  EXPECT_TRUE(frame3.Contains(SimCanvas::kRect, "yellow"));
  EXPECT_TRUE(frame3.Contains(SimCanvas::kRect, "green"));
  EXPECT_TRUE(frame3.Contains(SimCanvas::kRect, "blue"));
  EXPECT_TRUE(frame3.Contains(SimCanvas::kRect, "red"));
}

namespace {

class CheckRafCallback final : public FrameCallback {
 public:
  void Invoke(double high_res_time_ms) override { was_called_ = true; }
  bool WasCalled() const { return was_called_; }

 private:
  bool was_called_ = false;
};

}  // namespace

TEST_F(DocumentLoadingRenderingTest,
       ShouldThrottleIframeLifecycleUntilPendingSheetsLoaded) {
  SimRequest main_resource("https://example.com/main.html", "text/html");
  SimRequest frame_resource("https://example.com/frame.html", "text/html");
  SimSubresourceRequest css_resource("https://example.com/frame.css",
                                     "text/css");

  LoadURL("https://example.com/main.html");

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));

  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <body style='background: red'>
    <iframe id=frame src=frame.html></iframe>
  )HTML");

  frame_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <link rel=stylesheet href=frame.css>
    <body style='background: blue'>
  )HTML");

  auto* child_frame = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("frame")));

  // Frame while the child frame still has pending sheets.
  auto* frame1_callback = MakeGarbageCollected<CheckRafCallback>();
  child_frame->contentDocument()->RequestAnimationFrame(frame1_callback);
  auto frame1 = Compositor().BeginFrame();
  EXPECT_FALSE(frame1_callback->WasCalled());
  EXPECT_TRUE(frame1.Contains(SimCanvas::kRect, "red"));
  EXPECT_FALSE(frame1.Contains(SimCanvas::kRect, "blue"));

  // Finish loading the sheets in the child frame. Should enable lifecycle
  // updates and raf callbacks.
  css_resource.Complete();
  test::RunPendingTasks();

  // Frame with all lifecycle updates enabled.
  auto* frame2_callback = MakeGarbageCollected<CheckRafCallback>();
  child_frame->contentDocument()->RequestAnimationFrame(frame2_callback);
  auto frame2 = Compositor().BeginFrame();
  EXPECT_TRUE(frame1_callback->WasCalled());
  EXPECT_TRUE(frame2_callback->WasCalled());
  EXPECT_TRUE(frame2.Contains(SimCanvas::kRect, "red"));
  EXPECT_TRUE(frame2.Contains(SimCanvas::kRect, "blue"));
}

TEST_F(DocumentLoadingRenderingTest,
       ShouldContinuePaintingWhenSheetsStartedAfterBody) {
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimSubresourceRequest css_head_resource("https://example.com/testHead.css",
                                          "text/css");
  SimSubresourceRequest css_body_resource("https://example.com/testBody.css",
                                          "text/css");

  LoadURL("https://example.com/test.html");

  // Still in the head, should not paint.
  main_resource.Write("<!DOCTYPE html><link rel=stylesheet href=testHead.css>");
  EXPECT_FALSE(GetDocument().HaveRenderBlockingResourcesLoaded());

  // Sheet is streaming in, but not ready yet.
  css_head_resource.Start();
  css_head_resource.Write("a { color: red; }");
  EXPECT_FALSE(GetDocument().HaveRenderBlockingResourcesLoaded());

  // Body inserted but sheet is still pending so don't paint.
  main_resource.Write("<body>");
  EXPECT_FALSE(GetDocument().HaveRenderBlockingResourcesLoaded());

  // Sheet finished and body inserted, ok to paint.
  css_head_resource.Finish();
  EXPECT_TRUE(GetDocument().HaveRenderBlockingResourcesLoaded());

  // In the body, should not stop painting.
  main_resource.Write("<link rel=stylesheet href=testBody.css>");
  EXPECT_TRUE(GetDocument().HaveRenderBlockingResourcesLoaded());

  // Finish loading the CSS resource (no change to painting).
  css_body_resource.Complete("a { color: red; }");
  EXPECT_TRUE(GetDocument().HaveRenderBlockingResourcesLoaded());

  // Finish the load, painting should stay enabled.
  main_resource.Finish();
  EXPECT_TRUE(GetDocument().HaveRenderBlockingResourcesLoaded());
}

}  // namespace blink
```