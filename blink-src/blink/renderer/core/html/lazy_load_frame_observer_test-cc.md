Response:
The user wants a summary of the provided C++ code, which is a test file for a feature called "lazy loading of frames" in the Chromium browser.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Functionality:** The file name `lazy_load_frame_observer_test.cc` and the content strongly suggest this file tests the lazy loading of iframe elements. Keywords like "lazy," "frame," "viewport," and the use of `loading='lazy'` in the HTML examples confirm this.

2. **Determine the Test Scope:** The code uses the `SimTest` framework, which implies it's a unit test environment simulating browser behavior without full rendering. This means the tests focus on the logic of when frames start loading based on their position relative to the viewport.

3. **Analyze the Test Cases:** The various `TEST_P` and `TEST_F` functions represent different scenarios being tested. I need to categorize these scenarios. Some key categories emerge:
    * **Frame Origin:** Same-origin vs. cross-origin iframes.
    * **Viewport Position:** Above the fold, below the fold but near, far from the viewport.
    * **`loading` attribute:** Presence and value (`lazy`, `eager`).
    * **Nested Frames:** Testing the interaction of lazy loading with nested iframes.
    * **Navigation:**  How lazy loading interacts with frame navigations (e.g., `about:blank` then setting `src`).
    * **JavaScript URLs:** Iframes with `src="javascript:..."`.
    * **Dynamic Attribute Changes:** Changing the `loading` attribute after the iframe is created.
    * **Page Reloads:**  How lazy loading behaves on page reload.
    * **Network Conditions:** Tests parameterized by network connection type.

4. **Identify Key Concepts and Relationships:**
    * **Lazy Loading:** Deferring the loading of off-screen iframes until they are near the viewport.
    * **Viewport:** The visible area of the browser window.
    * **Loading Distance Threshold:** A configurable distance from the viewport within which frames start loading. This is influenced by network conditions.
    * **`loading` attribute:**  The HTML attribute controlling lazy loading behavior.
    * **Effective Connection Type (ECT):**  Network speed, influencing the loading distance threshold.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The `<iframe>` tag and the `loading` attribute are central.
    * **JavaScript:** The tests use JavaScript `onload` events to verify when frames load. Dynamic manipulation of the `loading` attribute via JavaScript is also tested.
    * **CSS:** While not explicitly tested, the `style` attribute is used to position frames and create scrollable content, which implicitly relates to layout.

6. **Infer Logical Reasoning (Hypotheses and Outputs):** For each test case, consider the expected behavior:
    * **Input:** HTML structure, viewport position, network conditions, `loading` attribute.
    * **Output:** Whether the iframe's `onload` event fires immediately or is delayed.

7. **Identify Potential User/Programming Errors:**
    * Misunderstanding the `loading` attribute's behavior.
    * Assuming lazy loading will *always* defer loading, even for above-the-fold content or same-origin iframes.
    * Not considering the impact of network conditions on the loading threshold.
    * Incorrectly using JavaScript to manipulate the `loading` attribute.

8. **Structure the Summary:** Organize the information logically, starting with the core function and then detailing the specific test scenarios and their implications. Use clear and concise language.

9. **Address the "Part 1" Instruction:**  Explicitly state that this is a summary of the *first part* and that the second part will likely contain further tests or details.

By following these steps, I can create a comprehensive and accurate summary of the provided C++ test file.
这是对 Chromium Blink 引擎中 `blink/renderer/core/html/lazy_load_frame_observer_test.cc` 文件第一部分的分析和功能归纳。

**文件功能归纳:**

该文件是用于测试 **iframe 元素的懒加载 (lazy loading)** 功能的单元测试。它主要验证了 `LazyLoadFrameObserver` 类的行为，该类负责决定何时开始加载那些设置了 `loading='lazy'` 属性的 iframe。

**详细功能点:**

* **测试懒加载的基本行为:**
    * 验证当 iframe 位于视口附近（考虑加载距离阈值）时，会被加载。
    * 验证当 iframe 远离视口时，不会立即加载，而是会延迟加载。
    * 验证相同来源的 iframe 不会进行懒加载。
* **测试不同视口位置的影响:**
    * 测试 iframe 位于视口上方（above the fold）时立即加载。
    * 测试 iframe 位于视口下方但在加载阈值内时加载。
    * 测试 iframe 位于视口下方且超出加载阈值时延迟加载。
* **测试跨域 iframe 的懒加载:**
    * 重点测试跨域 iframe 的懒加载行为，因为安全和性能的考虑可能使其与同源 iframe 有所不同。
* **测试 `loading` 属性的不同值:**
    * 测试 `loading='lazy'` 时，iframe 会被懒加载。
    * 测试 `loading='eager'` 时，iframe 会立即加载，即使它在视口之外。
    * 验证当没有 `loading` 属性时（默认行为），iframe 是否会被立即加载（在没有自动懒加载功能启用时）。
* **测试嵌套 iframe 的懒加载:**
    * 验证当父 iframe 被懒加载时，嵌套的 iframe 的加载行为。
    * 验证当父 iframe 的 `loading` 属性为 `eager` 时，嵌套的 `loading='lazy'` 的 iframe 是否会被懒加载。
    * 验证当父 iframe 没有 `loading` 属性时，嵌套的 `loading='lazy'` 的 iframe 是否会被懒加载。
    * 验证当父 iframe 的 `loading` 属性为 `eager` 时，嵌套的 `loading='eager'` 的 iframe 是否会被立即加载。
* **测试 JavaScript 动态设置 iframe 的 `src` 属性:**
    * 验证通过 JavaScript 将 `iframe.src` 设置为跨域 URL 时，是否仍然会触发懒加载（如果适用）。
* **测试 `javascript:` URL 的 iframe:**
    * 验证 `src` 属性设置为 `javascript:` 的 iframe 不会进行懒加载，而是立即执行。
* **测试动态修改 `loading` 属性:**
    * 验证在 iframe 创建后，通过 JavaScript 移除 `loading='lazy'` 属性后，iframe 会开始加载。
    * 验证在 iframe 创建后，通过 JavaScript 将 `loading` 属性设置为 `eager` 后，iframe 会立即加载。
* **测试页面重新加载时的懒加载行为:**
    * 验证在页面重新加载时，带有 `loading='lazy'` 属性的 iframe 是否会像初次加载时一样被延迟加载。
* **考虑网络连接类型的影响:**
    * 使用参数化测试 (`LazyLoadFramesParamsTest`)，根据不同的网络连接类型 (例如，Offline, Slow 2G, 3G, 4G) 测试懒加载的加载距离阈值。这反映了在慢速网络下，iframe 更早被加载的策略。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:** 该测试直接关联 HTML 的 `<iframe>` 标签和 `loading` 属性。`loading='lazy'` 是触发懒加载的关键。
    * **举例:**  `<iframe src='https://example.com/frame.html' loading='lazy'></iframe>`  这个 HTML 片段中的 `loading='lazy'` 会告诉浏览器延迟加载这个 iframe，直到它接近视口。
* **JavaScript:** 测试中使用了 JavaScript 的 `console.log()` 来标记 iframe 的加载事件 (onload)，以此来验证 iframe 何时被加载。同时，测试也模拟了通过 JavaScript 动态修改 iframe 属性 (`iframe.src`, `iframe.loading`) 的场景。
    * **举例:**  在测试代码中，可以看到像 `onload='console.log("child frame element onload");'` 这样的 HTML 属性，JavaScript 的 `console.log` 函数用于记录 iframe 的加载时刻。
    * **举例:** 测试中也模拟了通过 JavaScript 获取 iframe 元素并修改其 `loading` 属性：`child_frame_element->setAttribute(html_names::kLoadingAttr, AtomicString("eager"));`
* **CSS:** 虽然 CSS 本身不直接参与懒加载的控制，但测试用例中使用了 CSS 的 `style` 属性来控制 iframe 和容器的高度，从而模拟 iframe 在页面中的位置，影响其是否在视口附近。
    * **举例:** `<div style='height: %dpx;'></div>`  这样的 CSS 样式用于在 iframe 前创建一定高度的空白，控制 iframe 初始时是否在视口内。

**逻辑推理 (假设输入与输出):**

假设输入以下 HTML 片段和一个初始视口位置：

```html
<body onload='console.log("main body onload");'>
  <div style='height: 1000px;'></div>
  <iframe id='lazyFrame' src='https://example.com/frame.html' loading='lazy' style='width: 200px; height: 200px;' onload='console.log("lazy frame onload");'></iframe>
</body>
```

* **假设输入 1:** 初始视口位于页面顶部 (scrollY = 0)，加载距离阈值为 500px。
    * **预期输出 1:**  "main body onload" 会立即输出到控制台。"lazy frame onload" 不会立即输出，因为 iframe 的顶部距离视口顶部超过了 500px。
* **假设输入 2:** 用户滚动页面，使得 iframe 的顶部距离视口顶部小于 500px。
    * **预期输出 2:** 此时 "lazy frame onload" 会输出到控制台，表示 iframe 开始加载。
* **假设输入 3:** 将 iframe 的 `loading` 属性改为 `eager`： `<iframe id='lazyFrame' src='https://example.com/frame.html' loading='eager' ...>`，且初始视口位于页面顶部。
    * **预期输出 3:** "main body onload" 和 "lazy frame onload" 都会立即输出到控制台，因为 `loading='eager'` 会强制立即加载。

**涉及用户或编程常见的使用错误:**

* **错误地认为 `loading='lazy'` 会阻止所有 iframe 立即加载:** 用户可能认为所有带有 `loading='lazy'` 的 iframe 都必须滚动到视口附近才能加载。但实际上，如果 iframe 初始就在视口内或加载阈值内，它也会被立即加载。
    * **举例:**  如果一个带有 `loading='lazy'` 的 iframe 出现在页面的顶部，用户可能会惊讶地发现它在页面加载时就加载了。
* **忘记考虑加载距离阈值:** 开发者可能只关注 iframe 是否在当前视口内，而忽略了浏览器预先加载的机制。即使 iframe 稍微超出视口，也可能因为在加载阈值内而被加载。
    * **举例:** 一个 iframe 底部刚刚超出视口 100px，而加载阈值是 200px，那么这个 iframe 仍然会被加载。
* **在不需要懒加载的场景下使用 `loading='lazy'`:**  对于总是需要在页面加载时立即展示的 iframe（例如，位于视口上方的关键内容），使用 `loading='lazy'` 反而可能造成不必要的延迟。
* **动态修改 `loading` 属性的时机不当:** 如果在 iframe 已经开始加载后才将其 `loading` 属性从 `lazy` 改为 `eager`，可能不会有预期的效果，或者行为可能不一致。

总而言之，该测试文件的第一部分主要关注于验证 `loading='lazy'` 属性对 iframe 加载行为的影响，涵盖了不同场景下的基本懒加载机制，并考虑了网络连接类型等因素。这为确保 Chromium 浏览器正确实现和优化 iframe 的懒加载功能提供了保障。

Prompt: 
```
这是目录为blink/renderer/core/html/lazy_load_frame_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/lazy_load_frame_observer.h"

#include <memory>
#include <optional>
#include <tuple>

#include "base/ranges/algorithm.h"
#include "base/test/scoped_feature_list.h"
#include "third_party/blink/public/platform/web_effective_connection_type.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/exported/web_view_impl.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"
#include "ui/gfx/geometry/rect_f.h"

namespace blink {

namespace {

// Convenience enums to make it easy to access the appropriate value of the
// tuple parameters in the parameterized tests below, e.g. so that
// std::get<LazyFrameLoadingFeatureStatus>(GetParam()) can be used instead of
// std::get<0>(GetParam()) if they were just booleans.
enum class LazyFrameVisibleLoadTimeFeatureStatus { kDisabled, kEnabled };

class LazyLoadFramesParamsTest
    : public SimTest,
      public ::testing::WithParamInterface<
          std::tuple<LazyFrameVisibleLoadTimeFeatureStatus,
                     WebEffectiveConnectionType>> {
 public:
  static constexpr int kViewportWidth = 800;
  static constexpr int kViewportHeight = 600;

  void SetUp() override {
    WebEffectiveConnectionType ect =
        std::get<WebEffectiveConnectionType>(GetParam());
    GetNetworkStateNotifier().SetNetworkConnectionInfoOverride(
        true /*on_line*/, kWebConnectionTypeWifi, ect, 1000 /*http_rtt_msec*/,
        100 /*max_bandwidth_mbps*/);

    SimTest::SetUp();
    WebView().MainFrameWidget()->Resize(
        gfx::Size(kViewportWidth, kViewportHeight));

    Settings& settings = WebView().GetPage()->GetSettings();

    // These should match the values that would be returned by
    // GetLoadingDistanceThreshold().
    settings.SetLazyLoadingFrameMarginPxUnknown(200);
    settings.SetLazyLoadingFrameMarginPxOffline(300);
    settings.SetLazyLoadingFrameMarginPxSlow2G(400);
    settings.SetLazyLoadingFrameMarginPx2G(500);
    settings.SetLazyLoadingFrameMarginPx3G(600);
    settings.SetLazyLoadingFrameMarginPx4G(700);
    settings.SetLazyLoadEnabled(true);
  }

  int GetLoadingDistanceThreshold() const {
    static constexpr int kDistanceThresholdByEffectiveConnectionType[] = {
        200, 300, 400, 500, 600, 700};
    return kDistanceThresholdByEffectiveConnectionType[static_cast<int>(
        std::get<WebEffectiveConnectionType>(GetParam()))];
  }

  // Convenience function to load a page with a cross origin frame far down the
  // page such that it's not near the viewport.
  std::unique_ptr<SimRequest> LoadPageWithCrossOriginFrameFarFromViewport() {
    SimRequest main_resource("https://example.com/", "text/html");
    std::unique_ptr<SimRequest> child_frame_resource;

    LoadURL("https://example.com/");

    main_resource.Complete(String::Format(
        R"HTML(
          <body onload='console.log("main body onload");'>
          <div style='height: %dpx;'></div>
          <iframe src='https://crossorigin.com/subframe.html'
               style='width: 400px; height: 400px;' loading='lazy'
               onload='console.log("child frame element onload");'></iframe>
          </body>)HTML",
        kViewportHeight + GetLoadingDistanceThreshold() + 100));

    Compositor().BeginFrame();
    test::RunPendingTasks();

    // If the child frame is being lazy loaded, then the body's load event
    // should have already fired.
    EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
    EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

    if (!child_frame_resource) {
      child_frame_resource = std::make_unique<SimRequest>(
          "https://crossorigin.com/subframe.html", "text/html");
    }

    return child_frame_resource;
  }
};

TEST_P(LazyLoadFramesParamsTest, SameOriginFrame) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://example.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='https://example.com/subframe.html'
             style='width: 200px; height: 200px;'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_frame_resource.Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest, AboveTheFoldFrame) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='https://crossorigin.com/subframe.html'
             style='width: 200px; height: 200px;' loading='lazy'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight - 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_frame_resource.Complete("");
  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest, BelowTheFoldButNearViewportFrame) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='https://crossorigin.com/subframe.html'
             style='width: 200px; height: 200px;' loading='lazy'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_frame_resource.Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));

  // Scroll down until the child frame is visible.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();
}

TEST_P(LazyLoadFramesParamsTest, LoadCrossOriginFrameFarFromViewport) {
  std::unique_ptr<SimRequest> child_frame_resource =
      LoadPageWithCrossOriginFrameFarFromViewport();

  // Scroll down near the child frame to cause the child frame to start loading.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

  child_frame_resource->Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));

  // Scroll down so that the child frame is visible.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, GetLoadingDistanceThreshold() + 150),
      mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest,
       CrossOriginFrameFarFromViewportBecomesVisibleBeforeFinishedLoading) {
  std::unique_ptr<SimRequest> child_frame_resource =
      LoadPageWithCrossOriginFrameFarFromViewport();

  // Scroll down so that the child frame is visible.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, GetLoadingDistanceThreshold() + 150),
      mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

  child_frame_resource->Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest, NestedFrameInCrossOriginFrameFarFromViewport) {
  std::unique_ptr<SimRequest> child_frame_resource =
      LoadPageWithCrossOriginFrameFarFromViewport();

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // There's another nested cross origin iframe inside the first child frame,
  // even further down such that it's not near the viewport. It should start
  // loading immediately, even if LazyFrameLoading is enabled, since it's nested
  // inside a frame that was previously deferred.
  SimRequest nested_frame_resource("https://test.com/", "text/html");
  child_frame_resource->Complete(String::Format(
      "<div style='height: %dpx;'></div>"
      "<iframe src='https://test.com/' style='width: 200px; height: 200px;'>"
      "</iframe>",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  nested_frame_resource.Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest, AboutBlankChildFrameNavigation) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='BodyOnload()'>
        <script>
          function BodyOnload() {
            console.log('main body onload');
            document.getElementsByTagName('iframe')[0].src =
                'https://crossorigin.com/subframe.html';
          }
        </script>

        <div style='height: %dpx;'></div>
        <iframe
             style='width: 200px; height: 200px;' loading='lazy'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_EQ(1, static_cast<int>(base::ranges::count(
                   ConsoleMessages(), "child frame element onload")));

  // Scroll down near the child frame to cause the child frame to start loading.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_frame_resource.Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_EQ(2, static_cast<int>(base::ranges::count(
                   ConsoleMessages(), "child frame element onload")));
}

TEST_P(LazyLoadFramesParamsTest, JavascriptStringFrameUrl) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='javascript:"Hello World!";'
             style='width: 200px; height: 200px;'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest,
       CrossOriginFrameFarFromViewportWithLoadingAttributeEager) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='https://crossorigin.com/subframe.html'
             style='width: 200px; height: 200px;' loading='eager'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_frame_resource.Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeLazy));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeEager));
}

TEST_P(LazyLoadFramesParamsTest,
       LoadSameOriginFrameFarFromViewportWithLoadingAttributeLazy) {
  SimRequest main_resource("https://example.com/", "text/html");
  std::optional<SimRequest> child_frame_resource;

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
          <body onload='console.log("main body onload");'>
          <div style='height: %dpx;'></div>
          <iframe src='https://example.com/subframe.html'
               style='width: 400px; height: 400px;' loading='lazy'
               onload='console.log("child frame element onload");'></iframe>
          </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // If the child frame is being lazy loaded, then the body's load event
  // should have already fired.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeLazy));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeEager));

  if (!child_frame_resource) {
    child_frame_resource.emplace("https://example.com/subframe.html",
                                 "text/html");
  }

  // Scroll down near the child frame to cause the child frame to start loading.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

  child_frame_resource->Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));

  // Scroll down so that the child frame is visible.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, GetLoadingDistanceThreshold() + 150),
      mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest,
       LoadCrossOriginFrameFarFromViewportThenSetLoadingAttributeEager) {
  SimRequest main_resource("https://example.com/", "text/html");
  std::optional<SimRequest> child_frame_resource;

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe id='child_frame' src='https://crossorigin.com/subframe.html'
             style='width: 400px; height: 400px;' loading='lazy'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // If the child frame is being lazy loaded, then the body's load event
  // should have already fired.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

  if (!child_frame_resource) {
    child_frame_resource.emplace("https://crossorigin.com/subframe.html",
                                 "text/html");
  }

  Element* child_frame_element =
      GetDocument().getElementById(AtomicString("child_frame"));
  ASSERT_TRUE(child_frame_element);
  child_frame_element->setAttribute(html_names::kLoadingAttr,
                                    AtomicString("eager"));

  child_frame_resource->Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeLazy));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeEager));
}

TEST_P(LazyLoadFramesParamsTest,
       NestedFrameWithLazyLoadAttributeOnInFrameWithNoLoadingAttribute) {
  std::unique_ptr<SimRequest> child_frame_resource =
      LoadPageWithCrossOriginFrameFarFromViewport();

  // Scroll down near the child frame to cause the child frame to start loading.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  child_frame_resource->Complete(
      String::Format("<div style='height: %dpx;'></div>"
                     "<iframe src='https://test.com/' loading='lazy'"
                     "     style='width: 200px; height: 200px;'>"
                     "</iframe>",
                     kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest,
       NestedFrameWithLazyLoadAttributeOnInFrameWithLoadingAttributeEager) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='https://crossorigin.com/subframe.html'
             style='width: 200px; height: 200px;' loading='eager'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeLazy));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeEager));

  child_frame_resource.Complete(
      String::Format("<div style='height: %dpx;'></div>"
                     "<iframe src='https://test.com/' loading='lazy'"
                     "     style='width: 200px; height: 200px;'>"
                     "</iframe>",
                     kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_P(LazyLoadFramesParamsTest,
       NestedFrameWithLazyLoadAttributeOffInFrameWithLoadingAttributeEager) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                  "text/html");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='https://crossorigin.com/subframe.html'
             style='width: 200px; height: 200px;' loading='eager'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // There's another nested cross origin iframe inside the first child frame,
  // even further down such that it's not near the viewport. Since it has the
  // attribute loading=eager, it shouldn't be deferred. Note that this also
  // matches the default behavior that would happen if the load attribute was
  // omitted on the nested iframe entirely.
  SimRequest nested_frame_resource("https://test.com/", "text/html");

  child_frame_resource.Complete(
      String::Format("<div style='height: %dpx;'></div>"
                     "<iframe src='https://test.com/' loading='eager'"
                     "     style='width: 200px; height: 200px;'>"
                     "</iframe>",
                     kViewportHeight + GetLoadingDistanceThreshold() + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  nested_frame_resource.Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeLazy));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeEager));
}

INSTANTIATE_TEST_SUITE_P(
    LazyFrameLoading,
    LazyLoadFramesParamsTest,
    ::testing::Combine(
        ::testing::Values(LazyFrameVisibleLoadTimeFeatureStatus::kDisabled,
                          LazyFrameVisibleLoadTimeFeatureStatus::kEnabled),
        ::testing::Values(WebEffectiveConnectionType::kTypeUnknown,
                          WebEffectiveConnectionType::kTypeOffline,
                          WebEffectiveConnectionType::kTypeSlow2G,
                          WebEffectiveConnectionType::kType2G,
                          WebEffectiveConnectionType::kType3G,
                          WebEffectiveConnectionType::kType4G)));

class LazyLoadFramesTest : public SimTest {
 public:
  static constexpr int kViewportWidth = 800;
  static constexpr int kViewportHeight = 600;
  static constexpr int kLoadingDistanceThresholdPx = 1000;

  void SetUp() override {
    GetNetworkStateNotifier().SetSaveDataEnabledOverride(false);
    GetNetworkStateNotifier().SetNetworkConnectionInfoOverride(
        true /*on_line*/, kWebConnectionTypeWifi,
        WebEffectiveConnectionType::kType4G, 1000 /*http_rtt_msec*/,
        100 /*max_bandwidth_mbps*/);

    SimTest::SetUp();
    WebView().MainFrameWidget()->Resize(
        gfx::Size(kViewportWidth, kViewportHeight));

    Settings& settings = WebView().GetPage()->GetSettings();
    settings.SetLazyLoadingFrameMarginPx4G(kLoadingDistanceThresholdPx);
    settings.SetLazyLoadEnabled(true);
  }

  void TearDown() override {
    GetNetworkStateNotifier().SetSaveDataEnabledOverride(false);
    SimTest::TearDown();
  }

  void TestCrossOriginFrameIsImmediatelyLoaded(const char* iframe_attributes) {
    SimRequest main_resource("https://example.com/", "text/html");
    SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                    "text/html");
    LoadURL("https://example.com/");

    main_resource.Complete(String::Format(
        R"HTML(
          <body onload='console.log("main body onload");'>
          <div style='height: %dpx;'></div>
          <iframe src='https://crossorigin.com/subframe.html'
               style='width: 200px; height: 200px;' %s
               onload='console.log("child frame element onload");'></iframe>
          </body>)HTML",
        kViewportHeight + kLoadingDistanceThresholdPx + 100,
        iframe_attributes));

    Compositor().BeginFrame();
    test::RunPendingTasks();

    child_frame_resource.Complete("");
    Compositor().BeginFrame();
    test::RunPendingTasks();

    EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
    EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
  }

  void TestCrossOriginFrameIsLazilyLoaded(const char* iframe_attributes) {
    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");

    main_resource.Complete(String::Format(
        R"HTML(
          <body onload='console.log("main body onload");'>
          <div style='height: %dpx;'></div>
          <iframe src='https://crossorigin.com/subframe.html'
               style='width: 200px; height: 200px;' %s
               onload='console.log("child frame element onload");'></iframe>
          </body>)HTML",
        kViewportHeight + kLoadingDistanceThresholdPx + 100,
        iframe_attributes));

    Compositor().BeginFrame();
    test::RunPendingTasks();

    // The body's load event should have already fired.
    EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
    EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

    SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                    "text/html");

    // Scroll down near the child frame to cause the child frame to start
    // loading.
    GetDocument().View()->LayoutViewport()->SetScrollOffset(
        ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

    Compositor().BeginFrame();
    test::RunPendingTasks();

    EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

    child_frame_resource.Complete("");

    Compositor().BeginFrame();
    test::RunPendingTasks();

    EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
  }

  void TestLazyLoadUsedInPageReload(const char* iframe_attributes,
                                    bool is_deferral_expected_on_reload) {
    ConsoleMessages().clear();

    SimRequest main_resource("https://example.com/", "text/html");
    MainFrame().StartReload(WebFrameLoadType::kReload);

    main_resource.Complete(String::Format(
        R"HTML(
            <body onload='console.log("main body onload");'>
            <div style='height: %dpx;'></div>
            <iframe src='https://crossorigin.com/subframe.html' %s
                 style='width: 400px; height: 400px;'
                 onload='console.log("child frame element onload");'></iframe>
            </body>)HTML",
        LazyLoadFramesTest::kViewportHeight +
            LazyLoadFramesTest::kLoadingDistanceThresholdPx + 100,
        iframe_attributes));

    if (is_deferral_expected_on_reload) {
      // The body's load event should have already fired.
      EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
      EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

      GetDocument().View()->LayoutViewport()->SetScrollOffset(
          ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

      SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                      "text/html");
      Compositor().BeginFrame();
      test::RunPendingTasks();
      child_frame_resource.Complete("");
      test::RunPendingTasks();

      // Scroll down near the child frame to cause the child frame to start
      // loading.
      GetDocument().View()->LayoutViewport()->SetScrollOffset(
          ScrollOffset(0, LazyLoadFramesTest::kViewportHeight +
                              LazyLoadFramesTest::kLoadingDistanceThresholdPx),
          mojom::blink::ScrollType::kProgrammatic);

      Compositor().BeginFrame();
      test::RunPendingTasks();
    } else {
      SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                      "text/html");
      Compositor().BeginFrame();
      test::RunPendingTasks();
      child_frame_resource.Complete("");
    }
    test::RunPendingTasks();
    EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
    EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
  }
};

TEST_F(LazyLoadFramesTest, LazyLoadFrameUnsetLoadingAttributeWithoutAutomatic) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe id='child_frame' src='https://crossorigin.com/subframe.html'
             loading='lazy' style='width: 200px; height: 200px;'
             onload='console.log("child frame element onload");'></iframe>
        </body>)HTML",
      kViewportHeight + kLoadingDistanceThresholdPx + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // The body's load event should have already fired.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

  SimRequest child_frame_resource("https://crossorigin.com/subframe.html",
                                  "text/html");

  Element* child_frame_element =
      GetDocument().getElementById(AtomicString("child_frame"));
  ASSERT_TRUE(child_frame_element);
  child_frame_element->removeAttribute(html_names::kLoadingAttr);

  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

  child_frame_resource.Complete("");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("child frame element onload"));
}

TEST_F(LazyLoadFramesTest, LazyLoadWhenAttrLazy) {
  TestCrossOriginFrameIsLazilyLoaded("loading='lazy'");
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeLazy));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeEager));
}

TEST_F(LazyLoadFramesTest, LazyLoadWhenAttrEager) {
  TestCrossOriginFrameIsImmediatelyLoaded("loading='eager'");
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeLazy));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadFrameLoadingAttributeEager));
}

TEST_F(LazyLoadFramesTest, LazyLoadWhenAutomaticDisabled) {
  TestCrossOriginFrameIsImmediatelyLoaded("");
}

// Frames with loading=lazy should be deferred.
TEST_F(LazyLoadFramesTest, DeferredForAttributeLazy) {
  TestCrossOriginFrameIsLazilyLoaded("loading='lazy'");
  TestLazyLoad
"""


```