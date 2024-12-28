Response:
The user wants to understand the functionality of the `lazy_load_image_observer_test.cc` file in the Chromium Blink engine. I need to analyze the provided C++ code and explain its purpose.

Here's a breakdown of the tasks:

1. **Identify the purpose of the test file:** This file likely contains unit tests for the `LazyLoadImageObserver` class.
2. **Explain the core functionality being tested:**  Lazy loading of images.
3. **Relate the functionality to web technologies (JavaScript, HTML, CSS):** Explain how lazy loading is implemented using HTML attributes and how it interacts with browser rendering.
4. **Provide examples of logical reasoning with input and output:** Analyze specific test cases to demonstrate how lazy loading behavior is verified.
5. **Identify common user/programming errors related to lazy loading:** Think about potential pitfalls when using the `loading` attribute.
这个文件 `blink/renderer/core/html/lazy_load_image_observer_test.cc` 是 Chromium Blink 引擎的源代码文件，**它的主要功能是测试 `LazyLoadImageObserver` 类的功能。**

`LazyLoadImageObserver` 类的作用是**优化网页性能，通过延迟加载视口外的图片来减少初始加载时间和资源消耗。** 只有当图片接近或进入用户视口时，才会开始加载。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **HTML:**
   -  **`loading` 属性:** 该测试文件中的测试用例大量使用了 HTML `<img>` 标签的 `loading` 属性。这个属性是实现图片懒加载的核心。
     - `loading="lazy"`:  指示浏览器延迟加载该图片，只有当图片接近视口时才加载。
     - `loading="eager"`: 指示浏览器立即加载该图片，忽略懒加载优化。
     - `loading="auto"`:  浏览器自行决定是否懒加载，通常等同于不设置 `loading` 属性。
     - **示例:**
       ```html
       <img src="image.png" loading="lazy" onload="console.log('deferred_image onload');">
       ```
       这个 HTML 片段表示一个图片，当它接近视口时，浏览器会开始加载，加载完成后会触发 `onload` 事件，控制台会输出 'deferred_image onload'。测试用例会验证这个事件是否在预期的时间点触发。

2. **JavaScript:**
   - **`onload` 事件:** 测试用例经常使用 `onload` 事件来判断图片是否已经加载完成。
     - **示例:** 在上面的 HTML 例子中，JavaScript 的 `console.log` 用于标记 `onload` 事件的触发。测试代码会检查控制台输出，以此来验证图片的加载时机。
   - **操作 DOM:** 测试用例中会使用 JavaScript 操作 DOM，例如通过 `document.getElementById` 获取图片元素，并修改其属性（如 `loading` 属性）。这用于测试在运行时修改 `loading` 属性的效果。
     - **示例:**
       ```c++
       GetDocument()
           .getElementById(AtomicString("my_image"))
           ->setAttribute(html_names::kLoadingAttr, AtomicString("eager"));
       ```
       这段 C++ 代码模拟了 JavaScript 修改 `loading` 属性的行为，测试从 `lazy` 改为 `eager` 后，图片是否会立即开始加载。

3. **CSS:**
   - **影响布局和滚动:** CSS 样式会影响页面的布局和滚动条的位置，而图片的懒加载依赖于图片相对于视口的位置。测试用例会通过设置 CSS 样式来创建不同的页面布局，模拟图片在不同滚动位置的情况。
     - **示例:**
       ```html
       <div style='height: 10000px;'></div>
       ```
       这个 CSS 样式创建了一个很长的 `div`，导致页面出现滚动条，测试用例会通过滚动来触发懒加载。

**逻辑推理与假设输入输出:**

以下是一些测试用例的逻辑推理示例：

**测试用例 1: `ImgSrcset`**

- **假设输入:**
  -  一个包含 `srcset` 属性且 `loading="lazy"` 的 `<img>` 标签，初始时位于视口下方。
  -  初始视口大小为 100x1。
- **逻辑推理:**
  1. 页面初始加载时，由于图片在视口外，`onload` 事件不应触发。
  2. 调整视口大小不应触发加载。
  3. 向下滚动页面，使图片接近视口。
  4. 由于 `srcset` 存在，并且滚动后的视口大小可能更适合加载更大尺寸的图片，因此会请求 `srcset` 中合适的图片资源（`img.png?200w`）。
  5. 加载完成后，`onload` 事件应该触发。
- **预期输出:**
  - 初始时，控制台不包含 "deferred_image onload"。
  - 调整视口大小后，控制台仍然不包含 "deferred_image onload"。
  - 滚动后，控制台包含 "deferred_image onload"。

**测试用例 2: `NearViewport` (在视口附近)**

- **假设输入:**
  - 一个包含多个 `<img>` 标签的 HTML 页面，分别设置 `loading="eager"`, `loading="lazy"`, `loading="auto"` 和不设置 `loading` 属性。
  - 图片初始时位于视口下方，但距离视口的距离小于预设的懒加载阈值。
- **逻辑推理:**
  1. `loading="eager"` 的图片应该立即加载。
  2. `loading="lazy"` 的图片应该延迟加载，即使它在视口附近。
  3. `loading="auto"` 和未设置 `loading` 属性的图片，浏览器通常会立即加载。
- **预期输出:**
  - 初始加载后，只有 `loading="eager"` 的图片的 `onload` 事件会触发。
  - 随后，`loading="auto"` 和未设置 `loading` 属性的图片的 `onload` 事件也会触发。
  - `loading="lazy"` 的图片的 `onload` 事件只有在之后进一步滚动或触发加载条件后才会触发。

**用户或编程常见的使用错误:**

1. **忘记设置 `loading="lazy"`:**  如果开发者希望图片懒加载，但忘记设置 `loading="lazy"` 属性，浏览器将默认立即加载图片，导致性能优化失效。
   - **示例错误:** `<img src="image.png">`  （应为 `<img src="image.png" loading="lazy">`）

2. **对视口附近的图片设置 `loading="lazy"`:** 虽然这样做功能上没有问题，但对于初始就接近视口的图片设置懒加载可能会导致轻微的延迟，用户可能会先看到占位符或空白，然后再看到图片。对于首屏可见的图片，通常不建议使用懒加载。

3. **依赖 JavaScript 来实现懒加载，而不是使用 `loading` 属性:** 在 `loading` 属性被广泛支持之前，开发者通常使用 JavaScript 库来实现懒加载。现在浏览器原生支持了 `loading` 属性，应该优先使用它，因为它性能更好且更简洁。

4. **动态修改 `loading` 属性时理解不当:**  开发者可能不清楚动态修改 `loading` 属性的效果。例如，从 `lazy` 修改为 `eager` 会立即触发加载，反之则会停止正在进行的加载并进入延迟加载状态。

5. **在不支持 `loading` 属性的旧浏览器中期望懒加载生效:** `loading` 属性是相对较新的特性，旧版本的浏览器可能不支持。开发者需要考虑兼容性问题，或者使用 polyfill 来提供支持。

总而言之，`lazy_load_image_observer_test.cc` 通过各种测试用例，细致地验证了 `LazyLoadImageObserver` 类的正确性，涵盖了不同 `loading` 属性值、滚动位置、视口大小、动态属性修改以及与 iframe 的交互等场景，确保 Chromium 浏览器能够按照预期执行图片懒加载策略，从而提升网页性能和用户体验。

Prompt: 
```
这是目录为blink/renderer/core/html/lazy_load_image_observer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/html/lazy_load_image_observer.h"

#include <optional>
#include <tuple>

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/style_image.h"
#include "third_party/blink/renderer/core/testing/sim/sim_compositor.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/network/network_state_notifier.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

namespace {

const Vector<char>& TestImage() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(const Vector<char>, test_image,
                                  (*test::ReadFromFile(test::CoreTestDataPath(
                                      "notifications/500x500.png"))));
  return test_image;
}

class LazyLoadImagesSimTest : public SimTest {
 protected:
  void LoadMainResource(const String& html_body) {
    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");

    main_resource.Complete(html_body);
    GetDocument().UpdateStyleAndLayoutTree();
  }
};

TEST_F(LazyLoadImagesSimTest, ImgSrcset) {
  WebView().Resize(gfx::Size(100, 1));
  LoadMainResource(R"HTML(
        <body onload='console.log("main body onload");'>
          <div style='height:10000px;'></div>
          <img src="img.png" srcset="img.png?100w 100w, img.png?200w 200w"
           loading="lazy" onload= 'console.log("deferred_image onload");'>
        </body>)HTML");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("deferred_image onload"));

  // Resizing should not load the image.
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 1));
  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_FALSE(ConsoleMessages().Contains("deferred_image onload"));

  // Scrolling down should load the larger image.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 10000), mojom::blink::ScrollType::kProgrammatic);
  SimRequest image_resource("https://example.com/img.png?200w", "image/png");
  Compositor().BeginFrame();
  test::RunPendingTasks();
  image_resource.Complete(TestImage());
  test::RunPendingTasks();
  EXPECT_TRUE(ConsoleMessages().Contains("deferred_image onload"));

  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadImageLoadingAttributeLazy));
}

class LazyLoadImagesParamsTest
    : public SimTest,
      public ::testing::WithParamInterface<WebEffectiveConnectionType> {
 public:
  static constexpr int kViewportWidth = 800;
  static constexpr int kViewportHeight = 600;

  LazyLoadImagesParamsTest() = default;

  void SetUp() override {
    GetNetworkStateNotifier().SetNetworkConnectionInfoOverride(
        true /*on_line*/, kWebConnectionTypeWifi, GetParam(),
        1000 /*http_rtt_msec*/, 100 /*max_bandwidth_mbps*/);

    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(
        gfx::Size(kViewportWidth, kViewportHeight));

    Settings& settings = WebView().GetPage()->GetSettings();

    // These should match the values that would be returned by
    // GetMargin().
    settings.SetLazyLoadingImageMarginPxUnknown(200);
    settings.SetLazyLoadingImageMarginPxOffline(300);
    settings.SetLazyLoadingImageMarginPxSlow2G(400);
    settings.SetLazyLoadingImageMarginPx2G(500);
    settings.SetLazyLoadingImageMarginPx3G(600);
    settings.SetLazyLoadingImageMarginPx4G(700);
  }

  int GetMargin() const {
    static constexpr int kDistanceThresholdByEffectiveConnectionType[] = {
        200, 300, 400, 500, 600, 700};
    return kDistanceThresholdByEffectiveConnectionType[static_cast<int>(
        GetParam())];
  }
};

TEST_P(LazyLoadImagesParamsTest, NearViewport) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimSubresourceRequest css_resource("https://example.com/style.css",
                                     "text/css");

  SimSubresourceRequest eager_resource("https://example.com/eager.png",
                                       "image/png");
  std::optional<SimSubresourceRequest> lazy_resource, auto_resource,
      unset_resource;
  lazy_resource.emplace("https://example.com/lazy.png", "image/png");
  auto_resource.emplace("https://example.com/auto.png", "image/png");
  unset_resource.emplace("https://example.com/unset.png", "image/png");
  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <head>
          <link rel='stylesheet' href='https://example.com/style.css' />
        </head>
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <img src='https://example.com/eager.png' loading='eager'
             onload='console.log("eager onload");' />
        <img src='https://example.com/lazy.png' loading='lazy'
             onload='console.log("lazy onload");' />
        <img src='https://example.com/auto.png' loading='auto'
             onload='console.log("auto onload");' />
        <img src='https://example.com/unset.png'
             onload='console.log("unset onload");' />
        </body>)HTML",
      kViewportHeight + GetMargin() - 100));

  css_resource.Complete("img { width: 50px; height: 50px; }");
  test::RunPendingTasks();

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("eager onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("auto onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("unset onload"));

  eager_resource.Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("auto onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("unset onload"));

  auto_resource->Complete(TestImage());
  unset_resource->Complete(TestImage());

  // Run pending tasks to process load events from `auto_resource` and
  // `unset_resource`.
  test::RunPendingTasks();

  Compositor().BeginFrame();
  test::RunPendingTasks();

  // `loading=lazy` never blocks the window load event.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("auto onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("unset onload"));

  lazy_resource->Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("auto onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("unset onload"));
}

TEST_P(LazyLoadImagesParamsTest, FarFromViewport) {
  SimRequest main_resource("https://example.com/", "text/html");
  SimSubresourceRequest css_resource("https://example.com/style.css",
                                     "text/css");

  SimSubresourceRequest eager_resource("https://example.com/eager.png",
                                       "image/png");
  std::optional<SimSubresourceRequest> lazy_resource, auto_resource,
      unset_resource;
  lazy_resource.emplace("https://example.com/lazy.png", "image/png");
  auto_resource.emplace("https://example.com/auto.png", "image/png");
  unset_resource.emplace("https://example.com/unset.png", "image/png");

  LoadURL("https://example.com/");

  main_resource.Complete(String::Format(
      R"HTML(
        <head>
          <link rel='stylesheet' href='https://example.com/style.css' />
        </head>
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <img src='https://example.com/eager.png' loading='eager'
             onload='console.log("eager onload");' />
        <img src='https://example.com/lazy.png' loading='lazy'
             onload='console.log("lazy onload");' />
        <img src='https://example.com/auto.png' loading='auto'
             onload='console.log("auto onload");' />
        <img src='https://example.com/unset.png'
             onload='console.log("unset onload");' />
        </body>)HTML",
      kViewportHeight + GetMargin() + 100));

  css_resource.Complete("img { width: 50px; height: 50px; }");
  test::RunPendingTasks();

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("eager onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("auto onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("unset onload"));

  eager_resource.Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("auto onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("unset onload"));

  auto_resource->Complete(TestImage());
  unset_resource->Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));

  // Scroll down so that the images are near the viewport.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));

  lazy_resource->Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("auto onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("unset onload"));
}

INSTANTIATE_TEST_SUITE_P(
    LazyImageLoading,
    LazyLoadImagesParamsTest,
    ::testing::Values(WebEffectiveConnectionType::kTypeUnknown,
                      WebEffectiveConnectionType::kTypeOffline,
                      WebEffectiveConnectionType::kTypeSlow2G,
                      WebEffectiveConnectionType::kType2G,
                      WebEffectiveConnectionType::kType3G,
                      WebEffectiveConnectionType::kType4G));

class LazyLoadImagesTest : public SimTest {
 public:
  static constexpr int kViewportWidth = 800;
  static constexpr int kViewportHeight = 600;
  static constexpr int kLoadingDistanceThreshold = 300;

  void SetUp() override {
    GetNetworkStateNotifier().SetNetworkConnectionInfoOverride(
        true /*on_line*/, kWebConnectionTypeWifi,
        WebEffectiveConnectionType::kType4G, 1000 /*http_rtt_msec*/,
        100 /*max_bandwidth_mbps*/);
    SimTest::SetUp();
    WebView().MainFrameViewWidget()->Resize(
        gfx::Size(kViewportWidth, kViewportHeight));

    Settings& settings = WebView().GetPage()->GetSettings();
    settings.SetLazyLoadingImageMarginPx4G(kLoadingDistanceThreshold);
    settings.SetLazyLoadingFrameMarginPx4G(kLoadingDistanceThreshold);
  }

  String MakeMainResourceString(const char* image_attributes) {
    return String::Format(
        R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <img src='https://example.com/image.png' %s
             onload='console.log("image onload");' />
        </body>)HTML",
        kViewportHeight + kLoadingDistanceThreshold + 100, image_attributes);
  }

  void LoadMainResourceWithImageFarFromViewport(
      const String& main_resource_string) {
    SimRequest main_resource("https://example.com/", "text/html");
    LoadURL("https://example.com/");

    main_resource.Complete(main_resource_string);

    Compositor().BeginFrame();
    test::RunPendingTasks();
  }

  void LoadMainResourceWithImageFarFromViewport(const char* image_attributes) {
    LoadMainResourceWithImageFarFromViewport(
        MakeMainResourceString(image_attributes));
  }

  void TestLoadImageExpectingLazyLoad(const char* image_attributes) {
    LoadMainResourceWithImageFarFromViewport(image_attributes);
    EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
    EXPECT_FALSE(ConsoleMessages().Contains("image onload"));
  }

  void TestLoadImageExpectingFullImageLoad(const char* image_attributes) {
    SimSubresourceRequest full_resource("https://example.com/image.png",
                                        "image/png");

    LoadMainResourceWithImageFarFromViewport(image_attributes);

    EXPECT_FALSE(ConsoleMessages().Contains("main body onload"));
    EXPECT_FALSE(ConsoleMessages().Contains("image onload"));

    full_resource.Complete(TestImage());

    Compositor().BeginFrame();
    test::RunPendingTasks();

    EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
    EXPECT_TRUE(ConsoleMessages().Contains("image onload"));
    EXPECT_FALSE(GetDocument().IsUseCounted(
        WebFeature::kLazyLoadImageLoadingAttributeLazy));
    EXPECT_FALSE(GetDocument().IsUseCounted(
        WebFeature::kLazyLoadImageLoadingAttributeEager));
  }
};

TEST_F(LazyLoadImagesTest, LoadAllImagesIfPrinting) {
  TestLoadImageExpectingLazyLoad("id='my_image' loading='lazy'");

  // The body's load event should have already fired.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("child frame element onload"));

  Element* img = GetDocument().getElementById(AtomicString("my_image"));
  ASSERT_TRUE(img);

  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("image onload"));

  SimSubresourceRequest img_resource("https://example.com/image.png",
                                     "image/png");

  EXPECT_EQ(0, GetDocument().Fetcher()->BlockingRequestCount());

  EXPECT_TRUE(GetDocument().WillPrintSoon());

  // The loads in this case are blocking the load event.
  EXPECT_EQ(1, GetDocument().Fetcher()->BlockingRequestCount());

  img_resource.Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();
  EXPECT_TRUE(ConsoleMessages().Contains("image onload"));
}

TEST_F(LazyLoadImagesTest, LoadAllImagesIfPrintingIFrame) {
  SimRequest iframe_resource("https://example.com/iframe.html", "text/html");

  const String main_resource =
      String::Format(R"HTML(
    <body onload='console.log("main body onload");'>
    <div style='height: %dpx;'></div>
    <iframe id='iframe' src='iframe.html'></iframe>
    <img src='https://example.com/top-image.png' loading='lazy'
         onload='console.log("main body image onload");'>
    </body>)HTML",
                     kViewportHeight + kLoadingDistanceThreshold + 100);
  LoadMainResourceWithImageFarFromViewport(main_resource);

  iframe_resource.Complete(R"HTML(
    <!doctype html>
    <body onload='console.log("iframe body onload");'>
    <img src='https://example.com/image.png' id='my_image' loading='lazy'
         onload='console.log("iframe image onload");'>
  )HTML");

  // The body's load event should have already fired.
  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("iframe body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("main body image onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("iframe image onload"));

  auto* iframe = To<HTMLIFrameElement>(
      GetDocument().getElementById(AtomicString("iframe")));
  ASSERT_TRUE(iframe);
  ASSERT_TRUE(iframe->ContentFrame());

  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("main body image onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("iframe image onload"));

  SimSubresourceRequest img_resource("https://example.com/image.png",
                                     "image/png");

  Document* iframe_doc = To<LocalFrame>(iframe->ContentFrame())->GetDocument();
  ASSERT_TRUE(iframe_doc);
  EXPECT_EQ(0, iframe_doc->Fetcher()->BlockingRequestCount());
  EXPECT_EQ(0, GetDocument().Fetcher()->BlockingRequestCount());

  EXPECT_TRUE(iframe_doc->WillPrintSoon());

  // The loads in this case are blocking the load event.
  ASSERT_EQ(1, iframe_doc->Fetcher()->BlockingRequestCount());
  ASSERT_EQ(0, GetDocument().Fetcher()->BlockingRequestCount());

  img_resource.Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_FALSE(ConsoleMessages().Contains("main body image onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("iframe image onload"));
}

TEST_F(LazyLoadImagesTest, AttributeChangedFromLazyToEager) {
  TestLoadImageExpectingLazyLoad("id='my_image' loading='lazy'");

  SimSubresourceRequest full_resource("https://example.com/image.png",
                                      "image/png");
  GetDocument()
      .getElementById(AtomicString("my_image"))
      ->setAttribute(html_names::kLoadingAttr, AtomicString("eager"));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  full_resource.Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("image onload"));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadImageLoadingAttributeLazy));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadImageLoadingAttributeEager));
}

TEST_F(LazyLoadImagesTest, AttributeChangedFromAutoToEager) {
  TestLoadImageExpectingFullImageLoad("id='my_image' loading='auto'");

  SimSubresourceRequest full_resource("https://example.com/image.png",
                                      "image/png");
  GetDocument()
      .getElementById(AtomicString("my_image"))
      ->setAttribute(html_names::kLoadingAttr, AtomicString("eager"));

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("image onload"));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadImageLoadingAttributeLazy));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadImageLoadingAttributeEager));
}

TEST_F(LazyLoadImagesTest, AttributeChangedFromUnsetToEager) {
  TestLoadImageExpectingFullImageLoad("id='my_image'");

  SimSubresourceRequest full_resource("https://example.com/image.png",
                                      "image/png");
  GetDocument()
      .getElementById(AtomicString("my_image"))
      ->setAttribute(html_names::kLoadingAttr, AtomicString("eager"));

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("image onload"));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadImageLoadingAttributeLazy));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kLazyLoadImageLoadingAttributeEager));
}

TEST_F(LazyLoadImagesTest, ImageInsideLazyLoadedFrame) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(String::Format(
      R"HTML(
        <body onload='console.log("main body onload");'>
        <div style='height: %dpx;'></div>
        <iframe src='https://example.com/child_frame.html' loading='lazy'
                id='child_frame' width='300px' height='300px'
                onload='console.log("child frame onload");'></iframe>
        </body>)HTML",
      kViewportHeight + kLoadingDistanceThreshold + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("child frame onload"));

  SimRequest child_frame_resource("https://example.com/child_frame.html",
                                  "text/html");

  // Scroll down so that the iframe is near the viewport, but the images within
  // it aren't near the viewport yet.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 150), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  SimSubresourceRequest css_resource("https://example.com/style.css",
                                     "text/css");
  SimSubresourceRequest eager_resource("https://example.com/eager.png",
                                       "image/png");
  SimSubresourceRequest auto_resource("https://example.com/auto.png",
                                      "image/png");
  SimSubresourceRequest unset_resource("https://example.com/unset.png",
                                       "image/png");

  child_frame_resource.Complete(R"HTML(
      <head>
        <link rel='stylesheet' href='https://example.com/style.css' />
      </head>
      <body onload='window.parent.console.log("child body onload");'>
      <div style='height: 100px;'></div>
      <img src='https://example.com/eager.png' loading='eager'
           onload='window.parent.console.log("eager onload");' />
      <img src='https://example.com/lazy.png' loading='lazy'
           onload='window.parent.console.log("lazy onload");' />
      <img src='https://example.com/auto.png' loading='auto'
           onload='window.parent.console.log("auto onload");' />
      <img src='https://example.com/unset.png'
           onload='window.parent.console.log("unset onload");' />
      </body>)HTML");

  css_resource.Complete("img { width: 50px; height: 50px; }");

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("child frame onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("child body onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("eager onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("auto onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("unset onload"));

  eager_resource.Complete(TestImage());
  auto_resource.Complete(TestImage());
  unset_resource.Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));
  EXPECT_FALSE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("auto onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("unset onload"));

  SimSubresourceRequest lazy_resource("https://example.com/lazy.png",
                                      "image/png");

  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, 250), mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  lazy_resource.Complete(TestImage());

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(ConsoleMessages().Contains("main body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child frame onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("child body onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("eager onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("lazy onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("auto onload"));
  EXPECT_TRUE(ConsoleMessages().Contains("unset onload"));
}

// Allow lazy loading of file:/// urls.
TEST_F(LazyLoadImagesTest, LazyLoadFileUrls) {
  SimRequest main_resource("file:///test.html", "text/html");
  SimSubresourceRequest image_resource("file:///image.png", "image/png");

  LoadURL("file:///test.html");
  main_resource.Complete(String::Format(
      R"HTML(
        <div style='height: %dpx;'></div>
        <img id='lazy' src='file:///image.png' loading='lazy'/>
      )HTML",
      kViewportHeight + kLoadingDistanceThreshold + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  auto* lazy =
      To<HTMLImageElement>(GetDocument().getElementById(AtomicString("lazy")));
  EXPECT_FALSE(lazy->CachedImage()->IsLoading());

  // Scroll down such that the image is visible.
  GetDocument().View()->LayoutViewport()->SetScrollOffset(
      ScrollOffset(0, kViewportHeight + kLoadingDistanceThreshold),
      mojom::blink::ScrollType::kProgrammatic);

  Compositor().BeginFrame();
  test::RunPendingTasks();

  EXPECT_TRUE(lazy->CachedImage()->IsLoading());
}

// This is a regression test added for https://crbug.com/1213045, which was
// filed for a memory leak whereby lazy loaded images currently being deferred
// but that were removed from the DOM were never actually garbage collected.
TEST_F(LazyLoadImagesTest, GarbageCollectDeferredLazyLoadImages) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(String::Format(
      R"HTML(
        <body>
        <div style='height: %dpx;'></div>
        <img src='https://example.com/image.png' loading='lazy'>
        </body>)HTML",
      kViewportHeight + kLoadingDistanceThreshold + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WeakPersistent<HTMLImageElement> image =
      To<HTMLImageElement>(GetDocument().QuerySelector(AtomicString("img")));
  EXPECT_FALSE(image->complete());
  image->remove();
  EXPECT_FALSE(image->isConnected());
  EXPECT_FALSE(image->complete());
  EXPECT_NE(image, nullptr);

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();
  ThreadState::Current()->CollectAllGarbageForTesting();

  EXPECT_EQ(nullptr, image);
}

// This is a regression test added for https://crbug.com/40071424, which was
// filed as a result of outstanding decode promises *not* keeping an underlying
// lazyload-deferred image alive, even after removal from the DOM. Images of
// this sort must kept alive for the underlying decode request promise's sake.
TEST_F(LazyLoadImagesTest, DeferredLazyLoadImagesKeptAliveForDecodeRequest) {
  SimRequest main_resource("https://example.com/", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(String::Format(
      R"HTML(
        <body>
        <div style='height: %dpx;'></div>
        <img src='https://example.com/image.png' loading='lazy'>
        </body>)HTML",
      kViewportHeight + kLoadingDistanceThreshold + 100));

  Compositor().BeginFrame();
  test::RunPendingTasks();

  WeakPersistent<HTMLImageElement> image =
      To<HTMLImageElement>(GetDocument().QuerySelector(AtomicString("img")));

  ScriptState* script_state =
      ToScriptStateForMainWorld(GetDocument().GetFrame());
  v8::HandleScope handle_scope(script_state->GetIsolate());
  // This creates an outstanding decode request for the underlying image, which
  // keeps it alive solely for the sake of the promise's existence.
  image->decode(script_state, ASSERT_NO_EXCEPTION);

  EXPECT_FALSE(image->complete());
  image->remove();
  EXPECT_FALSE(image->isConnected());
  EXPECT_FALSE(image->complete());
  EXPECT_NE(image, nullptr);

  GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  test::RunPendingTasks();
  ThreadState::Current()->CollectAllGarbageForTesting();

  // After GC, the image is still non-null, since it is kept alive due to the
  // outstanding decode request.
  EXPECT_NE(image, nullptr);
}

}  // namespace

}  // namespace blink

"""

```