Response:
The user wants a summary of the functionality of the provided C++ code file. They are particularly interested in:
1. **General Functionality:** What does this code do?
2. **Relationship to Web Technologies:** How does it relate to JavaScript, HTML, and CSS?
3. **Logic and Assumptions:**  Can we infer input/output scenarios?
4. **Common Errors:** What mistakes might users or programmers make?
5. **User Journey:** How does a user's actions lead to this code being executed (for debugging)?

This is the first part of a two-part request, so the summary should focus on the functionality demonstrated in this code snippet.

**Plan:**

1. Identify the core class being tested: `MobileFriendlinessChecker`.
2. Analyze the test setup and helper functions.
3. Examine individual test cases to understand what aspects of mobile-friendliness are being checked.
4. Infer the relationship to web technologies based on the tested scenarios (e.g., viewport meta tag, font sizes, image widths).
5. Formulate assumptions about inputs and outputs for the tested scenarios.
6. Consider potential user/programmer errors related to the tested features.
7. Sketch out a basic user journey that would trigger the mobile-friendliness check.
8. Summarize the functionalities observed in this part of the code.
这是名为 `mobile_friendliness_checker_test.cc` 的 Chromium Blink 引擎源代码文件，其主要功能是 **测试 `MobileFriendlinessChecker` 类的各项功能**。这个类负责评估网页的移动设备友好程度，并记录相关的指标。

**功能归纳：**

1. **测试视口 (Viewport) 设置：**
    *   检查是否存在视口设置 (`kViewportDeviceWidthNameHash`)。
    *   检查视口是否使用 `width=device-width` 这样的设备宽度设置。
    *   检查视口是否设置了固定的宽度值 (`kViewportHardcodedWidthNameHash`)。
    *   检查是否允许用户缩放 (`kAllowUserZoomNameHash`)，包括对 `user-scalable` 和 `maximum-scale` 的检查。
    *   检查 `initial-scale` 的设置 (`kViewportInitialScaleX10NameHash`)。

2. **测试文本大小：**
    *   计算小文本在页面中所占的比例 (`kSmallTextRatioNameHash`)。
    *   根据 `font-size` CSS 属性判断文本大小。
    *   考虑设备像素比 (`device_scale`) 对文本大小的影响。
    *   忽略不可见元素的文本大小。
    *   测试 `text-size-adjust` CSS 属性对文本大小的影响。

3. **测试内容是否超出视口：**
    *   计算超出视口的内容（主要是文本和图片）的百分比 (`kTextContentOutsideViewportPercentageNameHash`)。
    *   考虑绝对定位元素对视口的影响。
    *   考虑 `overflow` 属性（如 `overflow-x: hidden` 或 `overflow: hidden`）对超出视口内容的影响。

4. **使用 UKM 记录指标：**
    *   使用 `ukm::TestAutoSetUkmRecorder` 记录测试期间生成的 UKM (User Keyed Metrics) 指标。
    *   每个测试用例都会检查生成的 `MobileFriendliness` UKM 事件中是否包含了预期的指标和值。

**与 Javascript, HTML, CSS 的关系及举例说明：**

这个测试文件直接关联到 HTML 和 CSS 的功能，因为 `MobileFriendlinessChecker` 的工作是分析解析后的网页结构和样式信息。虽然没有直接涉及 JavaScript 的测试，但网页的移动友好性也会受到 JavaScript 动态生成内容的影响，而这些动态生成的内容最终也会体现在 HTML 和 CSS 中。

*   **HTML:**
    *   **视口 Meta 标签：** 测试用例会加载包含不同视口设置的 HTML 文件，例如：
        *   `<meta name="viewport" content="width=device-width">` (测试 `kViewportDeviceWidthNameHash`)
        *   `<meta name="viewport" content="width=320">` (测试 `kViewportHardcodedWidthNameHash`)
        *   `<meta name="viewport" content="user-scalable=no">` (测试 `kAllowUserZoomNameHash`)
        *   `<meta name="viewport" content="initial-scale=0.5">` (测试 `kViewportInitialScaleX10NameHash`)
    *   **文本内容：** 测试用例会创建包含不同大小文本的 HTML 结构，例如使用 `<div>` 或 `<span>` 标签，并通过内联 `style` 属性设置 `font-size`。
        *   `<div style="font-size: 8px;">Small text.</div>` (影响 `kSmallTextRatioNameHash`)
    *   **图片：** 测试用例会插入不同尺寸的图片，以测试内容是否超出视口。
        *   `<img style="width: 720px; height: 800px;">` (影响 `kTextContentOutsideViewportPercentageNameHash`)
    *   **表格：** 测试用例使用表格来模拟可能导致页面宽度超出视口的情况。
    *   **绝对定位：** 测试用例使用 `position: absolute` 来放置元素，观察其对视口的影响。

*   **CSS:**
    *   **`font-size` 属性：**  用于判断文本是否过小，例如：
        *   `<div style="font-size: 7px;">...</div>`
    *   **`zoom` 属性：** 测试 CSS 的 `zoom` 属性是否会影响小文本的判断。
        *   `<body style="font-size: 12px; zoom: 50%;">`
    *   **`clip` 属性：**  测试被裁剪的元素是否会被计入小文本比例。
    *   **`text-size-adjust` 属性：** 测试该属性对文本大小的影响，特别是在表格中。
    *   **`overflow` 属性：** 测试 `overflow-x: hidden` 或 `overflow: hidden` 是否会阻止超出视口的内容被计算在内。
    *   **`width` 和 `height` 属性：** 用于设置图片和元素的尺寸，影响视口计算。
    *   **`position: absolute` 属性：** 用于测试绝对定位元素对视口的影响。

**逻辑推理，假设输入与输出：**

*   **假设输入:**  HTML 字符串 `<div style="font-size: 6px;">This is small text.</div>`
*   **预期输出 (部分):**  UKM 指标 `SmallTextRatioNameHash` 的值接近 100 (假设这是页面上唯一的文本)。

*   **假设输入:** HTML 字符串 `<meta name="viewport" content="width=device-width, maximum-scale=1.0">`
*   **预期输出 (部分):** UKM 指标 `AllowUserZoomNameHash` 的值为 false，因为 `maximum-scale` 为 1.0 限制了用户缩放。

**涉及用户或者编程常见的使用错误，请举例说明：**

*   **用户错误：** 用户在开发网页时可能忘记设置视口 meta 标签，导致页面在移动设备上以桌面模式渲染，字体过小，布局错乱。`MobileFriendlinessChecker` 会将 `ViewportDeviceWidthNameHash` 标记为 false，并可能将 `SmallTextRatioNameHash` 标记为较高的值。
*   **编程错误：** 开发者可能错误地设置了固定的视口宽度，导致页面在不同尺寸的移动设备上显示不佳。例如，设置 `<meta name="viewport" content="width=320">` 在现代大屏手机上会显得过窄。`MobileFriendlinessChecker` 会记录 `ViewportHardcodedWidthNameHash` 的值。
*   **编程错误：** 开发者可能限制了用户的缩放能力，导致用户无法看清小字，影响用户体验。例如，设置 `<meta name="viewport" content="user-scalable=no">`。`MobileFriendlinessChecker` 会将 `AllowUserZoomNameHash` 标记为 false。
*   **编程错误：** 开发者可能使用了过小的字体大小，导致文本在移动设备上难以阅读。`MobileFriendlinessChecker` 会增加 `SmallTextRatioNameHash` 的值。
*   **编程错误：** 开发者可能引入了宽度超出视口的内容（如过宽的图片或表格），导致用户需要水平滚动才能查看完整内容。`MobileFriendlinessChecker` 会增加 `TextContentOutsideViewportPercentageNameHash` 的值。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户访问网页：** 用户在移动设备上使用 Chrome 浏览器访问一个网页。
2. **Blink 渲染引擎开始解析：** Chrome 的 Blink 渲染引擎开始解析下载的 HTML、CSS 和 JavaScript 代码。
3. **创建 DOM 树和渲染树：** Blink 构建 DOM 树和渲染树，这个过程中会处理 HTML 结构和 CSS 样式。
4. **布局计算：** Blink 进行布局计算，确定页面上每个元素的位置和大小。
5. **`MobileFriendlinessChecker` 启动：**  在布局完成后，或者在特定的生命周期阶段，`MobileFriendlinessChecker` 被调用来分析页面的移动设备友好性。
6. **收集指标：** `MobileFriendlinessChecker` 会检查视口设置、文本大小、内容是否超出视口等信息。
7. **记录 UKM：**  收集到的指标会通过 UKM 记录下来，用于 Chrome 的遥测和性能分析。

**调试线索：** 如果开发者发现某个网页在 Chrome 的移动设备友好性检查中得分较低，他们可以：

*   **查看 UKM 数据：**  通过 Chrome 提供的工具（例如 `chrome://ukm/`，或者在开发者工具的 Performance 面板中查看相关指标），可以查看 `MobileFriendliness` 事件中记录的具体指标值，例如 `SmallTextRatioNameHash` 或 `TextContentOutsideViewportPercentageNameHash`，从而定位问题所在。
*   **分析 HTML 和 CSS：**  根据 UKM 中指示的问题，检查网页的 HTML 结构和 CSS 样式，特别是视口 meta 标签、字体大小设置、图片尺寸和 `overflow` 属性等。
*   **使用 Chrome 开发者工具：**  使用 Chrome 开发者工具的移动设备模拟功能，可以模拟不同尺寸的设备，并检查页面在这些设备上的渲染效果，帮助发现布局和字体大小方面的问题。

总而言之，`mobile_friendliness_checker_test.cc` 文件通过一系列单元测试，验证了 `MobileFriendlinessChecker` 类能够准确地评估网页的各种移动设备友好性特征，并将结果记录到 UKM 中，为 Chrome 的性能分析和网页开发者提供有价值的数据。

Prompt: 
```
这是目录为blink/renderer/core/mobile_metrics/mobile_friendliness_checker_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/mobile_metrics/mobile_friendliness_checker.h"

#include "components/ukm/test_ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/web/web_settings.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"

namespace blink {

static constexpr char kBaseUrl[] = "http://www.test.com/";
static constexpr int kDeviceWidth = 480;
static constexpr int kDeviceHeight = 800;
static constexpr float kMinimumZoom = 0.25f;
static constexpr float kMaximumZoom = 5;

class MobileFriendlinessCheckerTest : public testing::Test {
  static void ConfigureAndroidSettings(WebSettings* settings) {
    settings->SetViewportEnabled(true);
    settings->SetViewportMetaEnabled(true);
  }

  template <typename LoaderCallback>
  ukm::mojom::UkmEntry EvalMobileFriendlinessUKM(const LoaderCallback& load,
                                                 float device_scale) {
    auto helper = std::make_unique<frame_test_helpers::WebViewHelper>();
    helper->Initialize(nullptr, nullptr, ConfigureAndroidSettings);
    helper->GetWebView()->MainFrameWidget()->SetDeviceScaleFactorForTesting(
        device_scale);
    helper->Resize(gfx::Size(kDeviceWidth, kDeviceHeight));
    helper->GetWebView()->GetPage()->SetDefaultPageScaleLimits(kMinimumZoom,
                                                               kMaximumZoom);
    // Model Chrome text auto-sizing more accurately.
    helper->GetWebView()->GetPage()->GetSettings().SetTextAutosizingEnabled(
        true);
    helper->GetWebView()
        ->GetPage()
        ->GetSettings()
        .SetShrinksViewportContentToFit(true);
    helper->GetWebView()->GetPage()->GetSettings().SetViewportStyle(
        mojom::blink::ViewportStyle::kMobile);
    helper->LoadAhem();

    load(*helper);

    ukm::TestAutoSetUkmRecorder result;

    DCHECK(helper->GetWebView()->MainFrameImpl()->GetFrame()->IsLocalRoot());
    helper->GetWebView()
        ->MainFrameImpl()
        ->GetFrameView()
        ->UpdateAllLifecyclePhasesForTest();
    helper->GetWebView()
        ->MainFrameImpl()
        ->GetFrameView()
        ->GetMobileFriendlinessChecker()
        ->ComputeNowForTesting();

    auto entries = result.GetEntriesByName("MobileFriendliness");
    EXPECT_EQ(entries.size(), 1u);
    EXPECT_EQ(entries[0]->event_hash,
              ukm::builders::MobileFriendliness::kEntryNameHash);
    return *entries[0];
  }

 public:
  void TearDown() override {
    url_test_helpers::UnregisterAllURLsAndClearMemoryCache();
  }

  ukm::mojom::UkmEntry CalculateMetricsForHTMLString(const std::string& html,
                                                     float device_scale = 1.0) {
    return EvalMobileFriendlinessUKM(
        [&](frame_test_helpers::WebViewHelper& helper) {
          frame_test_helpers::LoadHTMLString(
              helper.GetWebView()->MainFrameImpl(), html,
              url_test_helpers::ToKURL("about:blank"));
        },
        device_scale);
  }

  ukm::mojom::UkmEntry CalculateMetricsForFile(const std::string& path,
                                               float device_scale = 1.0) {
    return EvalMobileFriendlinessUKM(
        [&](frame_test_helpers::WebViewHelper& helper) {
          url_test_helpers::RegisterMockedURLLoadFromBase(
              WebString::FromUTF8(kBaseUrl), blink::test::CoreTestDataPath(),
              WebString::FromUTF8(path));
          frame_test_helpers::LoadFrame(helper.GetWebView()->MainFrameImpl(),
                                        kBaseUrl + path);
        },
        device_scale);
  }

  static void ExpectUkm(const ukm::mojom::UkmEntry& ukm,
                        uint64_t name_hash,
                        int expected) {
    auto it = ukm.metrics.find(name_hash);
    EXPECT_NE(it, ukm.metrics.end());
    EXPECT_EQ(it->second, expected);
  }

  static void ExpectUkmLT(const ukm::mojom::UkmEntry& ukm,
                          uint64_t name_hash,
                          int expected) {
    auto it = ukm.metrics.find(name_hash);
    EXPECT_NE(it, ukm.metrics.end());
    EXPECT_LT(it->second, expected);
  }

  static void ExpectUkmGT(const ukm::mojom::UkmEntry& ukm,
                          uint64_t name_hash,
                          int expected) {
    auto it = ukm.metrics.find(name_hash);
    EXPECT_NE(it, ukm.metrics.end());
    EXPECT_GT(it->second, expected);
  }
  test::TaskEnvironment task_environment_;
};

TEST_F(MobileFriendlinessCheckerTest, NoViewportSetting) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString("<body>bar</body>");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, DeviceWidth) {
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForFile("viewport/viewport-1.html");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
}

TEST_F(MobileFriendlinessCheckerTest, HardcodedViewport) {
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForFile("viewport/viewport-30.html");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportHardcodedWidthNameHash,
            340);  // Bucketed 200 -> 340.
}

TEST_F(MobileFriendlinessCheckerTest, HardcodedViewportWithDeviceScale3) {
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForFile("viewport/viewport-30.html",
                              /*device_scale=*/3.0);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportHardcodedWidthNameHash,
            340);  // Bucketed 200 -> 340.
}

TEST_F(MobileFriendlinessCheckerTest, DeviceWidthWithInitialScale05) {
  // Specifying initial-scale=0.5 is usually not the best choice for most web
  // pages. But we cannot determine that such page must not be mobile friendly.
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForFile("viewport/viewport-34.html");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportInitialScaleX10NameHash,
            6);  // Bucketed 5 -> 6.
}

TEST_F(MobileFriendlinessCheckerTest, AllowUserScalableWithSmallMaxZoom) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
    <head>
      <meta name="viewport" content="user-scalable=yes, maximum-scale=1.1">
    </head>
  )HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            false);
}

TEST_F(MobileFriendlinessCheckerTest, AllowUserScalableWithLargeMaxZoom) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
    <head>
      <meta name="viewport" content="user-scalable=yes, maximum-scale=2.0">
    </head>
  )HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
}

TEST_F(MobileFriendlinessCheckerTest,
       AllowUserScalableWithLargeMaxZoomAndLargeInitialScale) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
    <head>
      <meta name="viewport" content="user-scalable=yes, maximum-scale=2.0, initial-scale=1.9">
    </head>
  )HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            false);
}

TEST_F(MobileFriendlinessCheckerTest, UserZoom) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForFile(
      "viewport-initial-scale-and-user-scalable-no.html");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            false);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportInitialScaleX10NameHash,
            18);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, NoText) {
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForHTMLString(R"HTML(<body></body>)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

TEST_F(MobileFriendlinessCheckerTest, NoSmallFonts) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="font-size: 9px">
      This is legible font size example.
    </div>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

TEST_F(MobileFriendlinessCheckerTest, NoSmallFontsWithDeviceScaleFactor) {
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="font-size:9px">
      This is legible font size example.
    </div>
  </body>
</html>
)HTML",
                                    /*device_scale=*/2.0);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

TEST_F(MobileFriendlinessCheckerTest, OnlySmallFonts) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="font-size:7px">
      Small font text.
    </div>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, OnlySmallFontsWithDeviceScaleFactor) {
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="font-size:8px">
      Small font text.
    </div>
  </body>
</html>
)HTML",
                                    /*device_scale=*/2.0);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, MostlySmallFont) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="font-size:12px">
      legible text.
      <div style="font-size:8px">
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
        The quick brown fox jumps over the lazy dog.<br>
      </div>
    </div>
  </body>
<html>
)HTML");
  ExpectUkmLT(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
              100);
  ExpectUkmGT(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
              80);
}

TEST_F(MobileFriendlinessCheckerTest, MostlySmallInSpan) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<div style="font-size: 12px">
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  x
  <span style="font-size:8px">
    This is the majority part of the document.
  </span>
  y
</div>
)HTML");
  ExpectUkmLT(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
              100);
  ExpectUkmGT(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
              80);
}

TEST_F(MobileFriendlinessCheckerTest, MultipleDivs) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="font-size: 12px">
      x
      <div style="font-size:8px">
        middle of div
        <div style="font-size:1px">
          inner of div
        </div>
      </div>
      y
    </div>
  </body>
</html>
)HTML");
  ExpectUkmLT(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
              90);
  ExpectUkmGT(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
              60);
}

TEST_F(MobileFriendlinessCheckerTest, DontCountInvisibleSmallFontArea) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="font-size: 12px">
      x
      <div style="font-size:4px;display:none;">
        this is an invisible string.
      </div>
    </div>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

TEST_F(MobileFriendlinessCheckerTest, ScaleZoomedLegibleFont) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=10">
  </head>
  <body style="font-size: 5px">
    Legible text in 50px.
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportInitialScaleX10NameHash,
            74);  // Bucketed 100 -> 74.
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

TEST_F(MobileFriendlinessCheckerTest, ViewportZoomedOutIllegibleFont) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=480, initial-scale=0.5">
  </head>
  <body style="font-size: 16px; width: 960px">
    Illegible text in 8px.
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportHardcodedWidthNameHash,
            480);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportInitialScaleX10NameHash,
            6);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, TooWideViewportWidthIllegibleFont) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=960">
  </head>
  <body style="font-size: 12px">
    Illegible text in 6px.
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportHardcodedWidthNameHash,
            820);  // Bucketed 960 -> 820.
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, CSSZoomedIllegibleFont) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body style="font-size: 12px; zoom:50%">
    Illegible text in 6px.
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::kViewportDeviceWidthNameHash,
            false);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kAllowUserZoomNameHash,
            true);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, OnlySmallFontsClipped) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body style="font-size: 6px; clip: rect(0 0 0 0); position: absolute">
    Small font text.
  </body>
</html>
)HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

TEST_F(MobileFriendlinessCheckerTest, NormalTextAndWideImage) {
  // Wide image forces Chrome to zoom out.
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body style="margin:0px">
    <img style="width:720px; height:800px">
    <p style="font-size: 12pt">Normal font text.</p>
  </body>
</html>
)HTML");
  // Automatic zoom-out makes text small and image fits in display.
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, SmallTextByWideTable) {
  // Wide image forces Chrome to zoom out.
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body style="font-size: 12pt">
    <table>
      <tr>
        <td width=100px>a</td>
        <td width=100px>b</td>
        <td width=100px>c</td>
      </tr>
    </table>
  </body>
</html>
)HTML");
  // Automatic zoom-out makes text small.
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest,
       NormalTextAndWideImageWithDeviceWidthViewport) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width">
  </head>
  <body>
    <img style="width:5000px; height:50px">
    <p style="font-size: 12pt">Normal font text.</p>
  </body>
</html>
)HTML");
  // Automatic zoom-out makes text small and image fits in display.
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              10);
}

TEST_F(MobileFriendlinessCheckerTest, ZIndex) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width,initial-scale=1.0">
  </head>
  <body style="margin:240px;font-size: 12pt">
    <div style="z-index: 1">
      hello
      <div style="z-index: 10">
        foo
        <img style="width:5000px; height:380px">
        <p>Normal font text.</p>
      </div>
    </div>
  </body>
</html>
)HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              50);
}

TEST_F(MobileFriendlinessCheckerTest, NormalTextAndWideImageWithInitialScale) {
  // initial-scale=1.0 prevents the automatic zoom out.
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body style="margin: 0px">
    <img style="width:3000px; height:240px">
    <p style="font-size: 9pt">Normal font text.</p>
  </body>
</html>
)HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              50);
}

TEST_F(MobileFriendlinessCheckerTest,
       NormalTextAndWideImageWithInitialScaleAndDeviceScale) {
  ukm::mojom::UkmEntry ukm =
      CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body style="margin: 0px">
    <img style="width:3000px; height:240px">
    <p style="font-size: 6pt">Illegible font text.</p>
  </body>
</html>
)HTML",
                                    /*device_scale=*/2.0);
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              100);
}

// This test shows that text will grow with text-size-adjust: auto in a
// fixed-width table.
TEST_F(MobileFriendlinessCheckerTest, FixedWidthTableTextSizeAdjustAuto) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body>
    <table width="800">
      <tr><td style="font-size: 12px; text-size-adjust: auto">
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
      </td></tr>
    </table>
  </body>
</html>
)HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash, 0);
}

// This test shows that text remains small with text-size-adjust: none in a
// fixed-width table.
TEST_F(MobileFriendlinessCheckerTest, FixedWidthTableTextSizeAdjustNone) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body>
    <table width="800">
      <tr><td style="font-size: 12px; text-size-adjust: none">
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
        blah blah blah blah blah blah blah blah blah blah blah blah blah blah
      </td></tr>
    </table>
  </body>
</html>
)HTML");
  ExpectUkm(ukm, ukm::builders::MobileFriendliness::kSmallTextRatioNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, TextNarrow) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=.25">
  </head>
  <body>
    <pre>foo foo foo foo foo</pre>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, TextTooWide) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="/fonts/ahem.css" />
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <pre style="font: 30px Ahem; line-height: 1">)HTML" +
      std::string(10000, 'a') +
      R"HTML(</pre>
  </body>
</html>
)HTML");
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              20);
}

TEST_F(MobileFriendlinessCheckerTest, TextAbsolutePositioning) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body style="font-size: 12px">
    <pre style="position:absolute; left:2000px">)HTML" +
      std::string(10000, 'a') +
      R"HTML(</pre>
  </body>
</html>
)HTML");
  ExpectUkmGT(ukm,
              ukm::builders::MobileFriendliness::
                  kTextContentOutsideViewportPercentageNameHash,
              14);
}

TEST_F(MobileFriendlinessCheckerTest, ImageAbsolutePositioning) {
  ukm::mojom::UkmEntry ukm_full = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body style="margin: 0px">
    <img style="width:480px; height:800px; position:absolute; left:480px">
  </body>
</html>
)HTML");
  ExpectUkm(ukm_full,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            100);

  ukm::mojom::UkmEntry ukm_half = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body style="margin: 0px">
    <img style="width:480px; height:800px; position:absolute; left:240px">
  </body>
</html>
)HTML");
  ExpectUkm(ukm_half,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            50);
}

TEST_F(MobileFriendlinessCheckerTest, SmallTextOutsideViewportCeiling) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body style="font-size: 12px">
    <pre style="position:absolute; left:2000px">x</pre>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            1);
}

TEST_F(MobileFriendlinessCheckerTest, TextTooWideOverflowXHidden) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body>
    <pre style="overflow-x:hidden; font-size:12px">)HTML" +
      std::string(10000, 'a') + R"HTML(</pre>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, TextTooWideHidden) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body>
    <pre style="overflow:hidden">)HTML" +
      std::string(10000, 'a') +
      R"HTML(</pre>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, TextTooWideHiddenInDiv) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body>
    <div style="overflow:hidden; font-size: 12px">
      <pre>)HTML" +
      std::string(10000, 'a') +
      R"HTML(
      </pre>
    </div>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, TextTooWideHiddenInDivDiv) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(
      R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body>
    <div style="overflow:hidden">
      <div>
        <pre>)HTML" +
      std::string(10000, 'a') +
      R"HTML(
        </pre>
      <div>
    </div>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, ImageNarrow) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <body>
    <img style="width:200px; height:50px">
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, ImageTooWide) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <img style="width:2000px; height:50px">
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            20);
}

TEST_F(MobileFriendlinessCheckerTest, ImageTooWide100) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body style="margin:0px;">
    <img style="width:960px; height:800px">
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            100);
}

TEST_F(MobileFriendlinessCheckerTest, WideImageClipped) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <div style="overflow: hidden">
      <img style="width:2000px; height:50px">
    </div>
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            0);
}

TEST_F(MobileFriendlinessCheckerTest, ImageTooWideTwoImages) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
  </head>
  <body style="width:4036px">
    <img style="width:2000px; height:50px">
    <img style="width:2000px; height:50px">
  </body>
</html>
)HTML");
  ExpectUkm(ukm,
            ukm::builders::MobileFriendliness::
                kTextContentOutsideViewportPercentageNameHash,
            46);
}

TEST_F(MobileFriendlinessCheckerTest, ImageTooWideAbsolutePosition) {
  ukm::mojom::UkmEntry ukm = CalculateMetricsForHTMLString(R"HTML(
<html>
  <head>
    <meta name="viewport" content="initial-scale=1.0">
  </head>
  <body>
    <img style="width:480px; height:800px; position:absolute; left:2000px">
"""


```