Response:
Let's break down the thought process for analyzing this test file.

1. **Identify the Core Subject:** The file name `render_blocking_resource_manager_test.cc` immediately points to the `RenderBlockingResourceManager`. This is the central component being tested. The `_test.cc` suffix indicates it's a unit test file.

2. **Understand the Purpose of Render Blocking:**  Think about why a browser would block rendering. Common reasons include:
    * Critical CSS needed for initial layout.
    * Blocking JavaScript that might modify the DOM structure or styles.
    * Fonts that are necessary for displaying text correctly.

3. **Examine the Includes:**  The `#include` directives provide valuable context:
    *  `render_blocking_resource_manager.h`: Confirms the core class being tested.
    *  `base/test/scoped_feature_list.h`, `blink/public/common/features.h`: Suggests feature flags and their influence on the rendering blocking logic.
    *  DOM-related headers (`element.h`, `web_local_frame_impl.h`, `html_head_element.h`):  Shows interactions with the DOM tree.
    *  Layout-related headers (`layout_object.h`, `layout_shift_tracker.h`): Indicates involvement with the layout process and potential impact on layout shifts.
    *  Style-related headers (`computed_style.h`):  Implies that styling and fonts are key aspects.
    *  Testing utilities (`sim_request.h`, `sim_test.h`, `unit_test_helpers.h`):  Confirms this is a simulated environment for testing.

4. **Analyze the Test Fixture:**  The `RenderBlockingResourceManagerTest` class inherits from `SimTest`. This tells us:
    * It's using a simulated browser environment, not a full browser instance.
    * It has access to methods for loading URLs, creating requests, and controlling the rendering pipeline (like `Compositor()`).
    * Utility methods like `GetRenderBlockingResourceManager()`, `HasRenderBlockingResources()`, and methods for manipulating font preload timeouts indicate the specific aspects being tested.

5. **Go Through the Individual Test Cases (`TEST_F`)**:  Each `TEST_F` function focuses on a specific scenario. Here's how to analyze them:
    * **Look at the Test Name:** The name is often descriptive (e.g., `FastFontFinishBeforeBody`, `SlowFontTimeoutAfterBody`).
    * **Examine the Setup:**  Note the `SimRequest` and `SimSubresourceRequest` objects being created. These represent the main HTML page and its resources (like fonts).
    * **Identify the HTML Snippet:** The `R"HTML(...)HTML"` blocks show the HTML being loaded. Pay attention to `<link rel="preload">`, `<style>`, `@font-face`, and `<script>` tags as these are often related to render blocking.
    * **Track the Resource Loading:** Observe the `main_resource.Write()`, `main_resource.Complete()`, and `font_resource.Complete()` calls. These simulate the loading process.
    * **Focus on the Assertions (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_GT`):** These are the core of the test logic. They verify expected behavior, especially regarding `Compositor().DeferMainFrameUpdate()` (whether rendering is blocked) and `HasRenderBlockingResources()`.
    * **Look for JavaScript Interaction:**  Note any `<script>` tags and their purpose (e.g., `document.fonts.load()`).
    * **Pay Attention to Font-Specific Logic:**  Look for tests involving `@font-face`, `font-display: optional`, and font preload.
    * **Identify Timeout Scenarios:**  Tests involving `GetRenderBlockingResourceManager().FontPreloadingTimerFired()` or `test::RunDelayedTasks()` are checking timeout behavior.

6. **Infer Functionality from Tests:**  Based on the test cases, you can deduce the features of the `RenderBlockingResourceManager`:
    * Manages resources that can block the initial rendering.
    * Handles font preloading and its impact on rendering.
    * Implements timeouts for font preloading to prevent indefinite blocking.
    * Considers the presence of the `<body>` element as a condition for unblocking.
    * Deals with "optional" fonts (`font-display: optional`) and their non-blocking behavior after the initial paint (unless explicitly loaded before).
    * Interacts with JavaScript's Font Loading API.
    * Works with stylesheets as render-blocking resources.

7. **Connect to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:**  The tests heavily rely on HTML structure (`<head>`, `<body>`, `<link>`, `<style>`, `<script>`). The presence and order of these elements are crucial.
    * **CSS:** `@font-face` rules, `font-display`, and external stylesheets are tested for their blocking behavior.
    * **JavaScript:** The `document.fonts.load()` API is used to trigger font loading imperatively.

8. **Consider User/Developer Errors:** Think about what mistakes a web developer might make related to render blocking:
    * Not preloading critical fonts.
    * Having too many blocking resources in the `<head>`.
    * Relying on synchronous JavaScript that delays resource discovery.
    * Misunderstanding the behavior of `font-display: optional`.

9. **Trace User Actions (Debugging Clues):** Imagine how a user's actions could lead to the scenarios being tested:
    * A user navigates to a webpage.
    * The browser starts downloading resources.
    * Some resources (like CSS and preloaded fonts) might block rendering.
    * Timeouts might occur if resources take too long to load.
    * JavaScript might be executed, potentially triggering font loads.

10. **Structure the Explanation:** Organize the findings into logical categories: functionality, relationships to web technologies, logical inferences, common errors, and debugging clues. Use examples from the code to illustrate your points.

By following these steps, you can systematically analyze a complex test file like this and understand the functionality and purpose of the code being tested.
这个文件 `blink/renderer/core/loader/render_blocking_resource_manager_test.cc` 是 Chromium Blink 引擎中的一个测试文件，专门用于测试 `RenderBlockingResourceManager` 类的功能。`RenderBlockingResourceManager` 的主要职责是 **管理和跟踪哪些资源会阻止页面的首次渲染**。

以下是该文件列举的功能，并结合 JavaScript、HTML 和 CSS 进行说明：

**主要功能:**

1. **测试渲染阻塞资源的管理:**
   - **识别渲染阻塞资源:**  测试 `RenderBlockingResourceManager` 是否能正确识别哪些资源会阻止首次渲染。这些资源通常包括：
     - **外部 CSS 样式表 (通过 `<link rel="stylesheet">`)**
     - **同步 JavaScript 脚本 (通过 `<script>` 标签，不带 `async` 或 `defer`)**
     - **预加载的字体资源 (通过 `<link rel="preload" as="font">`)**， 特别是当启用了 `RenderBlockingFonts` 功能时。
     - **通过 JavaScript 强制加载的字体 (`document.fonts.load()`)**， 特别是对于 `font-display: optional` 的字体。
   - **跟踪资源加载状态:**  测试当这些资源开始加载、加载完成或加载失败时，`RenderBlockingResourceManager` 是否能正确更新其状态。
   - **判断是否可以开始渲染:**  测试 `RenderBlockingResourceManager` 是否能正确判断所有必要的渲染阻塞资源都已加载完毕，从而允许浏览器开始渲染页面。

2. **测试字体预加载的渲染阻塞行为:**
   - **快速完成预加载:** 测试当预加载的字体在解析到 `<body>` 之前完成加载时，渲染阻塞是否被及时解除。
   - **延迟完成预加载:** 测试当预加载的字体在解析到 `<body>` 之后才完成加载时，渲染阻塞如何处理。
   - **字体预加载超时:** 测试当字体预加载超时后，渲染阻塞是否会被解除，即使字体尚未加载完成。
   - **测试 `font-display: optional` 的行为:**
     - **未预加载的情况:** 测试当 `font-display: optional` 的字体未被预加载，并且在首次渲染前未加载完成时，是否会使用回退字体渲染，并且不会因为后续字体加载完成而发生回流。
     - **预加载的情况:** 测试预加载 `font-display: optional` 的字体是否会阻塞渲染直到加载完成（在超时之前）。
     - **通过 JavaScript 加载的情况:** 测试通过 `document.fonts.load()` 加载 `font-display: optional` 的字体是否会阻塞渲染直到加载完成（在超时之前）。

3. **测试 `RenderBlockingFonts` 特性 (Feature Flag):**
   - 该测试文件包含一个名为 `RenderBlockingFontTest` 的测试类，专门用于测试 `features::kRenderBlockingFonts` 特性启用时的行为。
   - **字体预加载作为渲染阻塞资源:**  测试在该特性启用时，预加载的字体资源是否会成为渲染阻塞资源，即使没有直接在 CSS 中使用。
   - **最大阻塞时间 (`kMaxBlockingTimeMsForRenderBlockingFonts`):** 测试当字体预加载时间超过最大阻塞时间时，渲染阻塞是否会被解除。
   - **最大首次内容绘制延迟 (`kMaxFCPDelayMsForRenderBlockingFonts`):** 测试当字体预加载导致首次内容绘制延迟超过最大允许值时，渲染阻塞是否会被解除。
   - **与其他阻塞资源的交互:** 测试当同时存在字体预加载和其他类型的渲染阻塞资源时，阻塞行为如何。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**
    - **`<link rel="stylesheet">`:** 测试样式表作为渲染阻塞资源。例如，当 HTML 中包含 `<link rel="stylesheet" href="style.css">` 时，在 `style.css` 加载完成前，页面渲染会被阻塞。
    ```html
    <!doctype html>
    <head>
      <link rel="stylesheet" href="style.css">
    </head>
    <body>
      <div>Hello</div>
    </body>
    ```
    测试会验证在 `style.css` 完成加载前，`Compositor().DeferMainFrameUpdate()` 返回 `true` (表示渲染被延迟)。

    - **`<script src="...">` (同步):** 测试同步脚本作为渲染阻塞资源。当 HTML 中包含 `<script src="script.js"></script>` 时，浏览器会暂停 HTML 解析并执行脚本，在此期间渲染会被阻塞。
    ```html
    <!doctype html>
    <head>
      <script src="script.js"></script>
    </head>
    <body>
      <div>Hello</div>
    </body>
    ```
    测试会验证在 `script.js` 完成加载和执行前，渲染会被阻塞。

    - **`<link rel="preload" as="font">`:** 测试预加载字体作为渲染阻塞资源（尤其在 `RenderBlockingFonts` 特性启用时）。
    ```html
    <!doctype html>
    <head>
      <link rel="preload" as="font" type="font/woff2" href="font.woff2">
    </head>
    <body>
      <div>Hello</div>
    </body>
    ```
    测试会验证在 `font.woff2` 完成加载前，渲染是否被阻塞。

* **CSS:**
    - **`@font-face`:** 测试通过 `@font-face` 定义的字体资源的加载对渲染的影响。特别是结合 `font-display` 属性。
    ```css
    @font-face {
      font-family: 'custom-font';
      src: url('font.woff2') format('woff2');
      font-display: optional;
    }
    #target {
      font-family: 'custom-font', sans-serif;
    }
    ```
    测试会验证 `font-display: optional` 的字体在不同加载阶段对渲染阻塞和布局的影响。

* **JavaScript:**
    - **`document.fonts.load()`:** 测试通过 JavaScript 强制加载字体是否会影响渲染阻塞。
    ```html
    <!doctype html>
    <head>
      <style>
        @font-face {
          font-family: 'custom-font';
          src: url('font.woff2') format('woff2');
          font-display: optional;
        }
        #target {
          font-family: 'custom-font', sans-serif;
        }
      </style>
    </head>
    <body>
      <span id="target">Hello</span>
      <script>
        document.fonts.load("16px custom-font");
      </script>
    </body>
    ```
    测试会验证在 `document.fonts.load()` 完成前，渲染是否被阻塞。

**逻辑推理及假设输入与输出:**

以 `TEST_F(RenderBlockingResourceManagerTest, FastFontFinishBeforeBody)` 为例：

* **假设输入:**
    - HTML 包含一个预加载的字体资源 `<link rel="preload" as="font" ...>`。
    - 在浏览器解析到 `<body>` 标签之前，预加载的字体资源加载完成。
* **逻辑推理:**  由于预加载的字体在 `<body>` 之前完成加载，它不应该再阻塞首次渲染。一旦 `<body>` 被解析到，渲染应该可以开始。
* **预期输出:**
    - 在字体加载完成但 `<body>` 尚未解析时，`HasRenderBlockingResources()` 返回 `false` (字体不再阻塞)。
    - 在 `<body>` 解析后，`Compositor().DeferMainFrameUpdate()` 返回 `false` (渲染不再被延迟)。

**用户或编程常见的使用错误:**

1. **未预加载关键字体:**  开发者可能忘记预加载页面首次渲染所需的字体，导致浏览器在遇到 CSS 规则时才开始下载字体，从而延迟渲染。
   ```html
   <!doctype html>
   <head>
     <style>
       @font-face {
         font-family: 'my-font';
         src: url('my-font.woff2') format('woff2');
       }
       body {
         font-family: 'my-font';
       }
     </style>
   </head>
   <body> ... </body>
   ```
   用户会看到文本闪烁（先显示无样式文本，再应用字体）。

2. **在 `<head>` 中放置过多的同步 JavaScript:**  过多的同步脚本会阻塞 HTML 解析和渲染。
   ```html
   <!doctype html>
   <head>
     <script src="analytics.js"></script>
     <script src="complex-logic.js"></script>
     <link rel="stylesheet" href="style.css">
   </head>
   <body> ... </body>
   ```
   用户会看到页面长时间白屏。

3. **错误理解 `font-display: optional`:**  开发者可能认为 `font-display: optional` 的字体永远不会阻塞渲染，但实际上，如果通过预加载或 JavaScript 强制加载，它在加载完成前仍然可能阻塞渲染（直到超时）。

**用户操作如何一步步到达这里 (调试线索):**

假设开发者正在调试一个页面首次渲染缓慢的问题，并怀疑是字体加载导致的：

1. **用户访问网页:** 用户在浏览器地址栏输入网址或点击链接，导航到目标页面。
2. **浏览器发起请求:** 浏览器向服务器请求 HTML 文档。
3. **解析 HTML:** 浏览器开始解析接收到的 HTML 文档。
4. **遇到渲染阻塞资源:**  解析器遇到 `<link rel="stylesheet">` 或 `<script>` 或 `<link rel="preload" as="font">` 等标签。
5. **`RenderBlockingResourceManager` 介入:** `RenderBlockingResourceManager` 记录这些资源，并标记渲染为阻塞状态。
6. **下载资源:** 浏览器开始下载这些阻塞资源。
7. **测试文件模拟场景:** 该测试文件通过 `SimRequest` 和 `SimSubresourceRequest` 模拟了这些资源加载的不同阶段（快速完成、延迟完成、超时等）。
8. **验证阻塞状态:** 测试文件通过 `Compositor().DeferMainFrameUpdate()` 和 `HasRenderBlockingResources()` 等方法，断言在不同资源加载状态下，渲染是否被正确地阻塞或解除阻塞。
9. **开发者分析:** 开发者可以通过运行这些测试，验证 `RenderBlockingResourceManager` 的行为是否符合预期，从而帮助定位页面渲染缓慢的原因。例如，如果一个预加载的字体本应快速完成加载，但测试显示它仍然阻塞了渲染，那么可能需要检查字体资源的配置或网络状况。

总而言之，`blink/renderer/core/loader/render_blocking_resource_manager_test.cc` 是一个至关重要的测试文件，用于确保 Chromium Blink 引擎能够正确地管理和处理影响页面首次渲染的资源，从而提供更快的页面加载体验。

### 提示词
```
这是目录为blink/renderer/core/loader/render_blocking_resource_manager_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/loader/render_blocking_resource_manager.h"

#include "base/test/scoped_feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

class RenderBlockingResourceManagerTest : public SimTest {
 public:
  static Vector<char> ReadAhemWoff2() {
    return *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2"));
  }

 protected:
  RenderBlockingResourceManager& GetRenderBlockingResourceManager() {
    return *GetDocument().GetRenderBlockingResourceManager();
  }

  bool HasRenderBlockingResources() {
    return GetRenderBlockingResourceManager().HasRenderBlockingResources();
  }

  void DisableFontPreloadTimeout() {
    GetRenderBlockingResourceManager().DisableFontPreloadTimeoutForTest();
  }
  void SetFontPreloadTimeout(base::TimeDelta timeout) {
    GetRenderBlockingResourceManager().SetFontPreloadTimeoutForTest(timeout);
  }
  bool FontPreloadTimerIsActive() {
    return GetRenderBlockingResourceManager().FontPreloadTimerIsActiveForTest();
  }

  Element* GetTarget() {
    return GetDocument().getElementById(AtomicString("target"));
  }

  const Font& GetTargetFont() {
    return GetTarget()->GetLayoutObject()->Style()->GetFont();
  }
};

TEST_F(RenderBlockingResourceManagerTest, FastFontFinishBeforeBody) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <head>
      <link rel="preload" as="font" type="font/woff2"
            href="https://example.com/font.woff">
  )HTML");

  // Make sure timer doesn't fire in case the test runs slow.
  SetFontPreloadTimeout(base::Seconds(30));

  // Rendering is blocked due to ongoing font preloading.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  font_resource.Complete();
  test::RunPendingTasks();

  // Font preloading no longer blocks renderings. However, rendering is still
  // blocked, as we don't have BODY yet.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  main_resource.Complete("</head><body>some text</body>");

  // Rendering starts after BODY has arrived, as the font was loaded earlier.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());
}

TEST_F(RenderBlockingResourceManagerTest, FastFontFinishAfterBody) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <head>
      <link rel="preload" as="font" type="font/woff2"
            href="https://example.com/font.woff">
  )HTML");

  // Rendering is blocked due to ongoing font preloading.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  main_resource.Complete("</head><body>some text</body>");

  // Rendering is still blocked by font, even if we already have BODY, because
  // the font was *not* loaded earlier.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  font_resource.Complete();
  test::RunPendingTasks();

  // Rendering starts after font preloading has finished.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());
}

TEST_F(RenderBlockingResourceManagerTest, SlowFontTimeoutBeforeBody) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <head>
      <link rel="preload" as="font" type="font/woff2"
            href="https://example.com/font.woff">
  )HTML");

  // Rendering is blocked due to ongoing font preloading.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  GetRenderBlockingResourceManager().FontPreloadingTimerFired(nullptr);

  // Font preloading no longer blocks renderings after the timeout fires.
  // However, rendering is still blocked, as we don't have BODY yet.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  main_resource.Complete("</head><body>some text</body>");

  // Rendering starts after BODY has arrived.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  font_resource.Complete();
}

TEST_F(RenderBlockingResourceManagerTest, SlowFontTimeoutAfterBody) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <head>
      <link rel="preload" as="font" type="font/woff2"
            href="https://example.com/font.woff">
  )HTML");

  // Rendering is blocked due to ongoing font preloading.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  main_resource.Complete("</head><body>some text</body>");

  // Rendering is still blocked by font, even if we already have BODY.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  GetRenderBlockingResourceManager().FontPreloadingTimerFired(nullptr);

  // Rendering starts after we've waited for the font preloading long enough.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  font_resource.Complete();
}

// A trivial test case to verify test setup
TEST_F(RenderBlockingResourceManagerTest, RegularWebFont) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <span id=target style="position:relative">0123456789</span>
  )HTML");

  // Now rendering has started, as there's no blocking resources.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());

  // Now everything is loaded. The web font should be used in rendering.
  Compositor().BeginFrame().DrawCount();
  EXPECT_EQ(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());
}

TEST_F(RenderBlockingResourceManagerTest, OptionalFontWithoutPreloading) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <span id=target>0123456789</span>
    <script>document.fonts.load('25px/1 custom-font');</script>
  )HTML");

  // Now rendering has started, as there's no blocking resources.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());

  // Although the optional web font isn't preloaded, it finished loading before
  // the first time we try to render with it. Therefore it's used.
  Compositor().BeginFrame().Contains(SimCanvas::kText);
  EXPECT_EQ(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());

  main_resource.Finish();
}

TEST_F(RenderBlockingResourceManagerTest, OptionalFontMissingFirstFrame) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <span id=target>0123456789</span>
  )HTML");

  // Now rendering has started, as there's no blocking resources.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  // We render visible fallback as the 'optional' web font hasn't loaded.
  Compositor().BeginFrame();
  EXPECT_GT(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());

  font_resource.Complete(ReadAhemWoff2());

  // Since we have rendered fallback for the 'optional' font, even after it
  // finishes loading, we shouldn't use it, as otherwise there's a relayout.
  Compositor().BeginFrame();
  EXPECT_GT(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());

  main_resource.Finish();
}

TEST_F(RenderBlockingResourceManagerTest,
       OptionalFontForcedLayoutNoLayoutShift) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <span id=target>0123456789</span>
    <span>Element to track layout shift when font changes</span>
  )HTML");

  // Now rendering has started, as there's no blocking resources.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  // Force layout update, which lays out target but doesn't paint anything.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  test::RunPendingTasks();

  EXPECT_GT(250, GetTarget()->OffsetWidth());

  // Can't check ShouldSkipDrawing(), as it calls PaintRequested() on the font.

  font_resource.Complete(ReadAhemWoff2());

  // Even though target has been laid out with a fallback font, we can still
  // relayout with the web font since it hasn't been painted yet, which means
  // relayout and repaint do not cause layout shifting.
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_EQ(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());
  EXPECT_EQ(0.0, GetDocument().View()->GetLayoutShiftTracker().Score());
}

TEST_F(RenderBlockingResourceManagerTest, OptionalFontRemoveAndReadd) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <span id=target>0123456789</span>
  )HTML");

  // Now rendering has started, as there's no blocking resources.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  // The 'optional' web font isn't used, as it didn't finish loading before
  // rendering started. Text is rendered in visible fallback.
  Compositor().BeginFrame().Contains(SimCanvas::kText);
  EXPECT_GT(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());

  font_resource.Complete(ReadAhemWoff2());

  Element* style = GetDocument().QuerySelector(AtomicString("style"));
  style->remove();
  GetDocument().head()->appendChild(style);

  // After removing and readding the style sheet, we've created a new font face
  // that got loaded immediately from the memory cache. So it can be used.
  Compositor().BeginFrame().Contains(SimCanvas::kText);
  EXPECT_EQ(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());
}

TEST_F(RenderBlockingResourceManagerTest, OptionalFontSlowPreloading) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2"
          href="https://example.com/Ahem.woff2" crossorigin>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <span id=target>0123456789</span>
  )HTML");

  // Rendering is blocked due to font being preloaded.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  GetRenderBlockingResourceManager().FontPreloadingTimerFired(nullptr);

  // Rendering is unblocked after the font preloading has timed out.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  // First frame renders text with visible fallback, as the 'optional' web font
  // isn't loaded yet, and should be treated as in the failure period.
  Compositor().BeginFrame();
  EXPECT_GT(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());

  font_resource.Complete(ReadAhemWoff2());

  // The 'optional' web font should not cause relayout even if it finishes
  // loading now.
  Compositor().BeginFrame();
  EXPECT_GT(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());
}

TEST_F(RenderBlockingResourceManagerTest, OptionalFontFastPreloading) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2"
          href="https://example.com/Ahem.woff2" crossorigin>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <span id=target>0123456789</span>
  )HTML");

  // Rendering is blocked due to font being preloaded.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  // There are test flakes due to RenderBlockingResourceManager timeout firing
  // before the ResourceFinishObserver gets notified. So we disable the timeout.
  DisableFontPreloadTimeout();

  font_resource.Complete(ReadAhemWoff2());
  test::RunPendingTasks();

  // Rendering is unblocked after the font is preloaded.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  // The 'optional' web font should be used in the first paint.
  Compositor().BeginFrame();
  EXPECT_EQ(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());
}

TEST_F(RenderBlockingResourceManagerTest, OptionalFontSlowImperativeLoad) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <script>
    document.fonts.load('25px/1 custom-font');
    </script>
    <span id=target>0123456789</span>
  )HTML");

  // Rendering is blocked due to font being loaded via JavaScript API.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  GetRenderBlockingResourceManager().FontPreloadingTimerFired(nullptr);

  // Rendering is unblocked after the font preloading has timed out.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  // First frame renders text with visible fallback, as the 'optional' web font
  // isn't loaded yet, and should be treated as in the failure period.
  Compositor().BeginFrame();
  EXPECT_GT(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());

  font_resource.Complete(ReadAhemWoff2());

  // The 'optional' web font should not cause relayout even if it finishes
  // loading now.
  Compositor().BeginFrame();
  EXPECT_GT(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());
}

TEST_F(RenderBlockingResourceManagerTest, OptionalFontFastImperativeLoad) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <style>
      @font-face {
        font-family: custom-font;
        src: url(https://example.com/Ahem.woff2) format("woff2");
        font-display: optional;
      }
      #target {
        font: 25px/1 custom-font, monospace;
      }
    </style>
    <script>
    document.fonts.load('25px/1 custom-font');
    </script>
    <span id=target>0123456789</span>
  )HTML");

  // Make sure timer doesn't fire in case the test runs slow.
  SetFontPreloadTimeout(base::Seconds(30));

  // Rendering is blocked due to font being preloaded.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());
  EXPECT_TRUE(HasRenderBlockingResources());

  font_resource.Complete(ReadAhemWoff2());
  test::RunPendingTasks();

  // Rendering is unblocked after the font is preloaded.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  EXPECT_FALSE(HasRenderBlockingResources());

  // The 'optional' web font should be used in the first paint.
  Compositor().BeginFrame();
  EXPECT_EQ(250, GetTarget()->OffsetWidth());
  EXPECT_FALSE(GetTargetFont().ShouldSkipDrawing());
}

TEST_F(RenderBlockingResourceManagerTest, ScriptInsertedBodyUnblocksRendering) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest style_resource("https://example.com/sheet.css",
                                       "text/css");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <link rel="stylesheet" href="sheet.css">
  )HTML");

  Element* body = GetDocument().CreateElementForBinding(AtomicString("body"));
  GetDocument().setBody(To<HTMLElement>(body), ASSERT_NO_EXCEPTION);

  // Rendering should be blocked by the pending stylesheet.
  EXPECT_TRUE(GetDocument().body());
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  style_resource.Complete("body { width: 100px; }");

  // Rendering should be unblocked as all render-blocking resources are loaded
  // and there is a body, even though it's not inserted by parser.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
  Compositor().BeginFrame();
  EXPECT_EQ(100, GetDocument().body()->OffsetWidth());

  main_resource.Finish();
}

// https://crbug.com/1308083
TEST_F(RenderBlockingResourceManagerTest, ParserBlockingScriptBeforeFont) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");
  SimSubresourceRequest script_resource("https://example.com/script.js",
                                        "application/javascript");

  LoadURL("https://example.com");

  // Make sure timer doesn't fire in case the test runs slow.
  SetFontPreloadTimeout(base::Seconds(30));

  main_resource.Complete(R"HTML(
    <!doctype html>
    <script src="script.js"></script>
    <link rel="preload" as="font" type="font/woff2"
          href="font.woff2" crossorigin>
    <div>
      Lorem ipsum
    </div>
  )HTML");

  // Rendering is still blocked.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Parser is blocked by the synchronous script, so <link> isn't inserted yet.
  EXPECT_FALSE(GetDocument().QuerySelector(AtomicString("link")));

  // Preload scanner should have started font preloading and also the timer.
  // This should happen before the parser sets up the preload link element.
  EXPECT_TRUE(FontPreloadTimerIsActive());

  script_resource.Complete();
  font_resource.Complete();
}

class RenderBlockingFontTest : public RenderBlockingResourceManagerTest {
 public:
  void SetUp() override {
    // Use a longer timeout to prevent flakiness when test is running slow.
    std::map<std::string, std::string> parameters;
    parameters["max-fcp-delay"] = "500";
    scoped_feature_list_.InitAndEnableFeatureWithParameters(
        features::kRenderBlockingFonts, parameters);
    SimTest::SetUp();
  }

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
};

TEST_F(RenderBlockingFontTest, FastFontPreloadWithoutOtherBlockingResources) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2" crossorigin
          href="https://example.com/font.woff2">
    Body Content
  )HTML");

  // Rendering is blocked by font.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());
  test::RunPendingTasks();

  // Rendering is unblocked after font preload finishes.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(RenderBlockingFontTest, SlowFontPreloadWithoutOtherBlockingResources) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2" crossorigin
          href="https://example.com/font.woff2">
    Body Content
  )HTML");

  // Rendering is blocked by font.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Wait until we've delayed FCP for the max allowed amount of time, and the
  // relevant timeout fires.
  test::RunDelayedTasks(
      base::Milliseconds(features::kMaxFCPDelayMsForRenderBlockingFonts.Get()));

  // Rendering is unblocked as max FCP delay is reached.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());
}

TEST_F(RenderBlockingFontTest,
       SlowFontPreloadAndSlowBodyWithoutOtherBlockingResources) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");

  LoadURL("https://example.com");
  main_resource.Write(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2" crossorigin
          href="https://example.com/font.woff2">
  )HTML");

  // Rendering is blocked by font.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  // Wait until we've blocked rendering for the max allowed amount of time since
  // navigation, and the relevant timeout fires.
  test::RunDelayedTasks(base::Milliseconds(
      features::kMaxBlockingTimeMsForRenderBlockingFonts.Get()));

  // The font preload is no longer render-blocking, but Rendering is still
  // blocked because the document has no body.
  EXPECT_FALSE(GetRenderBlockingResourceManager().HasRenderBlockingFonts());
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  main_resource.Complete("Body Content");

  // Rendering is unblocked after body is inserted.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());
}

TEST_F(RenderBlockingFontTest, FastFontPreloadWithOtherBlockingResources) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");
  SimSubresourceRequest css_resource("https://example.com/style.css",
                                     "text/css");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2" crossorigin
          href="https://example.com/font.woff2">
    <link rel="stylesheet" href="https://example.com/style.css">
    Body Content
  )HTML");

  font_resource.Complete(ReadAhemWoff2());
  test::RunPendingTasks();

  // Rendering is still blocked by the style sheet.
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  css_resource.Complete("body { color: red; }");
  test::RunPendingTasks();

  // Rendering is unblocked after all resources are loaded.
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());
}

TEST_F(RenderBlockingFontTest, FontPreloadExceedingMaxBlockingTime) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");
  SimSubresourceRequest css_resource("https://example.com/style.css",
                                     "text/css");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2" crossorigin
          href="https://example.com/font.woff2">
    <link rel="stylesheet" href="https://example.com/style.css">
    Body Content
  )HTML");

  // Wait until we've blocked rendering for the max allowed amount of time since
  // navigation, and the relevant timeout fires.
  test::RunDelayedTasks(base::Milliseconds(
      features::kMaxBlockingTimeMsForRenderBlockingFonts.Get()));

  // The font preload is no longer render-blocking, but we still have a
  // render-blocking style sheet.
  EXPECT_FALSE(GetRenderBlockingResourceManager().HasRenderBlockingFonts());
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  css_resource.Complete("body { color: red; }");
  test::RunPendingTasks();

  // Rendering is unblocked after the style sheet is loaded.
  EXPECT_FALSE(GetRenderBlockingResourceManager().HasRenderBlockingFonts());
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());
}

TEST_F(RenderBlockingFontTest, FontPreloadExceedingMaxFCPDelay) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");
  SimSubresourceRequest css_resource("https://example.com/style.css",
                                     "text/css");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2" crossorigin
          href="https://example.com/font.woff2">
    <link rel="stylesheet" href="https://example.com/style.css">
    Body Content
  )HTML");

  css_resource.Complete("body { color: red; }");
  test::RunPendingTasks();

  // Now the font is the only render-blocking resource, and rendering would have
  // started without the font.
  EXPECT_TRUE(GetRenderBlockingResourceManager().HasRenderBlockingFonts());
  EXPECT_FALSE(
      GetRenderBlockingResourceManager().HasNonFontRenderBlockingResources());
  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  test::RunDelayedTasks(
      base::Milliseconds(features::kMaxFCPDelayMsForRenderBlockingFonts.Get()));

  // After delaying FCP for the max allowed time, the font is no longer
  // render-blocking.
  EXPECT_FALSE(GetRenderBlockingResourceManager().HasRenderBlockingFonts());
  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());
}

TEST_F(RenderBlockingFontTest, FontPreloadExceedingBothLimits) {
  SimRequest main_resource("https://example.com", "text/html");
  SimSubresourceRequest font_resource("https://example.com/font.woff2",
                                      "font/woff2");
  SimSubresourceRequest css_resource("https://example.com/style.css",
                                     "text/css");

  LoadURL("https://example.com");
  main_resource.Complete(R"HTML(
    <!doctype html>
    <link rel="preload" as="font" type="font/woff2" crossorigin
          href="https://example.com/font.woff2">
    <link rel="stylesheet" href="https://example.com/style.css">
    Body Content
  )HTML");

  css_resource.Complete("body { color: red; }");

  EXPECT_TRUE(Compositor().DeferMainFrameUpdate());

  test::RunDelayedTasks(
      base::Milliseconds(features::kMaxFCPDelayMsForRenderBlockingFonts.Get()));
  test::RunDelayedTasks(base::Milliseconds(
      features::kMaxBlockingTimeMsForRenderBlockingFonts.Get()));

  EXPECT_FALSE(Compositor().DeferMainFrameUpdate());

  font_resource.Complete(ReadAhemWoff2());
}

}  // namespace blink
```