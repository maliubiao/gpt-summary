Response:
The user wants to understand the functionality of the provided C++ test file for the `HTMLFencedFrameElement` in the Chromium Blink engine. I need to break down the code and explain what each test case is verifying. Specifically, I should address:

1. **Overall Functionality:** What is the purpose of this test file?
2. **Relationship to Web Technologies:** How does this code relate to JavaScript, HTML, and CSS?
3. **Logic and Data Flow:** For each test, what are the inputs and expected outputs?
4. **Common Errors:** Are there any scenarios this test highlights where developers might make mistakes?

Let's go through the test cases one by one:

*   `FreezeSizeLayoutZoomFactor`: Tests how the fenced frame handles size changes when the layout zoom factor is adjusted after the size is frozen.
*   `CoerceFrameSizeTest`: Examines how the fenced frame coerces requested sizes to allowed ad sizes, particularly for opaque ads.
*   `HistogramTestInsecureContext`: Checks if a histogram is recorded when a fenced frame is created in an insecure context (HTTP).
*   `HistogramTestIncompatibleUrlHTTPDefault`: Verifies if histograms are logged when attempting to load incompatible URLs (like HTTP) into a fenced frame.
*   `HistogramTestResizeAfterFreeze`:  Tests if a histogram is recorded when a fenced frame is resized after its size has been frozen.
*   `HistogramTestSandboxFlags`: Checks if histograms are recorded when sandbox flags are not explicitly set on a fenced frame within a sandboxed main frame.
*   `HistogramTestSandboxFlagsInIframe`: Similar to the previous test, but with the fenced frame inside an iframe that has sandbox flags set.
*   `HistogramTestCanLoadOpaqueURL`: Tests a use counter related to loading opaque URLs in fenced frames.

Now, I'll structure the response to cover these points and provide specific examples.
这个C++测试文件 `html_fenced_frame_element_test.cc` 的主要功能是 **测试 `HTMLFencedFrameElement` 类的各种功能和行为**。`HTMLFencedFrameElement` 是 Chromium Blink 引擎中用于实现 `<fencedframe>` HTML 元素的类。`<fencedframe>` 元素是一种用于在网页中嵌入独立渲染内容的 HTML 元素，其主要特点是具有更强的隐私隔离性。

以下是该文件中各个测试用例的功能以及与 JavaScript、HTML、CSS 的关系：

**1. `FreezeSizeLayoutZoomFactor` 测试**

*   **功能:** 测试当 `fencedframe` 元素的尺寸被冻结后，浏览器布局缩放因子变化时，冻结尺寸是否会相应地缩放。
*   **与 HTML 的关系:**  `HTMLFencedFrameElement` 直接对应 HTML 中的 `<fencedframe>` 标签。这个测试模拟了在 HTML 中创建 `<fencedframe>` 元素并对其尺寸进行操作的情况。
*   **与 CSS 的关系:** 元素的尺寸通常可以通过 CSS 来控制。虽然这个测试没有直接操作 CSS，但它测试的是在布局过程中与尺寸相关的逻辑，而 CSS 最终会影响布局。
*   **逻辑推理:**
    *   **假设输入:**
        *   创建一个 `HTMLFencedFrameElement` 实例并添加到文档中。
        *   初始布局缩放因子为 `zoom_factor`。
        *   使用 `FreezeFrameSize` 方法将 `fencedframe` 的尺寸冻结为 `(200, 100)`。
        *   将布局缩放因子设置为 `zoom_factor * 2`。
    *   **预期输出:**  通过 `FrozenFrameSize()` 方法获取的冻结尺寸应该为 `(200 * 2, 100 * 2)`，即 `(400, 200)`。
    *   **后续输入:** 将布局缩放因子恢复为 `zoom_factor`。
    *   **预期输出:** 冻结尺寸保持不变，仍然是 `(400, 200)`。

**2. `CoerceFrameSizeTest` 测试**

*   **功能:** 测试 `fencedframe` 元素如何根据允许的广告尺寸（ad sizes）来调整（coerces）请求的尺寸。这通常用于广告场景，确保 `fencedframe` 的尺寸符合预定义的标准。
*   **与 HTML 的关系:** 测试的是 `<fencedframe>` 元素在处理尺寸属性时的逻辑。
*   **与 CSS 的关系:**  用户或脚本可能通过 CSS 或 HTML 属性设置 `fencedframe` 的尺寸，此测试验证了即使设置了任意尺寸，最终也会被调整为允许的尺寸。
*   **逻辑推理:**
    *   **假设输入:**
        *   创建一个 `HTMLFencedFrameElement` 实例。
        *   对于 `kAllowedAdSizes` 中定义的每个允许尺寸，将该尺寸作为请求尺寸传递给 `CoerceFrameSize` 方法。
        *   对于 `test_cases` 中定义的各种非法或超出范围的尺寸（例如负数、零、非常大、NaN），将这些尺寸作为请求尺寸传递给 `CoerceFrameSize` 方法。
    *   **预期输出:**
        *   对于允许的尺寸，`CoerceFrameSize` 方法应该返回相同的尺寸，不进行调整。
        *   对于非法的或超出范围的尺寸，`CoerceFrameSize` 方法应该返回一个允许的尺寸。具体返回哪个允许尺寸是实现细节，但测试会验证返回的尺寸是否在允许的尺寸列表中。
    *   **与 JavaScript 的关系:**  JavaScript 可以动态地设置或获取 `fencedframe` 的尺寸。此测试保证了即使 JavaScript 设置了不合规的尺寸，浏览器也会进行调整。
*   **用户或编程常见的使用错误:**
    *   **错误:** 开发者可能会尝试将 `fencedframe` 的尺寸设置为任意值，而没有考虑到广告平台的尺寸限制。
    *   **示例:**  `fencedFrameElement.style.width = '150px'; fencedFrameElement.style.height = '75px';`  如果 `(150, 75)` 不是允许的广告尺寸，浏览器会将其调整为最接近的允许尺寸。

**3. `HistogramTestInsecureContext` 测试**

*   **功能:** 测试当在不安全的上下文中（例如，通过 HTTP 加载的页面）创建 `fencedframe` 元素时，是否会记录相应的性能指标（histogram）。
*   **与 HTML 的关系:** 测试的是 `<fencedframe>` 元素在特定安全上下文下的创建行为。
*   **假设输入:**
    *   创建一个通过 HTTP 加载的文档环境。
    *   在该文档中创建一个 `HTMLFencedFrameElement` 实例。
*   **预期输出:** 名为 `kFencedFrameCreationOrNavigationOutcomeHistogram` 的性能指标应该记录一个值为 `FencedFrameCreationOutcome::kInsecureContext` 的样本。

**4. `HistogramTestIncompatibleUrlHTTPDefault` 测试**

*   **功能:** 测试当尝试将不兼容的 URL（例如，普通的 HTTP URL）加载到 `fencedframe` 元素时，是否会记录相应的性能指标。`fencedframe` 通常期望加载具有特定隔离属性的 URL。
*   **与 HTML 的关系:** 测试的是 `<fencedframe>` 元素 `src` 属性的行为。
*   **假设输入:**
    *   创建一个 `HTMLFencedFrameElement` 实例。
    *   尝试将一个 HTTP URL (例如 "http://example.com") 设置为 `fencedframe` 的 `src` 属性。
    *   尝试其他不兼容的 URL 类型，如 `blob:` 和 `file:`.
*   **预期输出:** 名为 `kFencedFrameCreationOrNavigationOutcomeHistogram` 的性能指标应该记录一个值为 `FencedFrameCreationOutcome::kIncompatibleURLDefault` 的样本。
*   **用户或编程常见的使用错误:**
    *   **错误:** 开发者可能会错误地认为可以将任何 URL 加载到 `fencedframe` 中。
    *   **示例:**  `<fencedframe src="http://example.com"></fencedframe>`  这样做通常不会按预期工作，并且浏览器会记录相应的指标。

**5. `HistogramTestResizeAfterFreeze` 测试**

*   **功能:** 测试当 `fencedframe` 元素的尺寸被冻结后，如果再次尝试调整其尺寸，是否会记录相应的性能指标。
*   **与 HTML 的关系:** 测试的是 `<fencedframe>` 元素尺寸冻结后的行为。
*   **与 JavaScript 的关系:**  JavaScript 可以尝试在尺寸冻结后再次调整 `fencedframe` 的尺寸。
*   **假设输入:**
    *   创建一个 `HTMLFencedFrameElement` 实例。
    *   调用 `OnResize` 方法冻结其尺寸。
    *   再次调用 `OnResize` 方法尝试调整尺寸。
*   **预期输出:** 名为 `kIsFencedFrameResizedAfterSizeFrozen` 的性能指标应该被记录一次。

**6. `HistogramTestSandboxFlags` 测试**

*   **功能:** 测试当在具有沙箱标志的父框架中创建 `fencedframe` 元素时，是否会记录与沙箱相关的性能指标。这旨在确保 `fencedframe` 的沙箱约束得到正确处理。
*   **与 HTML 的关系:** 测试的是 `<fencedframe>` 元素在沙箱环境下的创建行为。
*   **假设输入:**
    *   创建一个具有所有沙箱标志的文档环境。
    *   在该文档中创建一个 `HTMLFencedFrameElement` 实例，并设置 `src` 属性。
*   **预期输出:**
    *   名为 `kFencedFrameCreationOrNavigationOutcomeHistogram` 的性能指标应该记录一个值为 `FencedFrameCreationOutcome::kSandboxFlagsNotSet` 的样本，表明 `fencedframe` 没有显式设置沙箱标志。
    *   对于每个强制不沙箱化的标志（`kFencedFrameMandatoryUnsandboxedFlags`），如果父框架设置了该标志，则 `kFencedFrameMandatoryUnsandboxedFlagsSandboxed` 指标应该记录相应的计数。
    *   `kFencedFrameFailedSandboxLoadInTopLevelFrame` 指标应该记录为 `true`，因为 `fencedframe` 创建发生在最外层主框架中。

**7. `HistogramTestSandboxFlagsInIframe` 测试**

*   **功能:**  与上一个测试类似，但这次 `fencedframe` 是在一个具有沙箱标志的 `<iframe>` 元素内部创建的。
*   **与 HTML 的关系:** 测试 `<fencedframe>` 在 `<iframe>` 沙箱环境下的行为。
*   **假设输入:**
    *   创建一个主文档。
    *   在主文档中创建一个 `<iframe>` 元素，并设置其沙箱属性（例如，使用 JavaScript 设置）。
    *   在 `<iframe>` 的文档中创建一个 `HTMLFencedFrameElement` 实例，并设置 `src` 属性。
*   **预期输出:**
    *   `kFencedFrameFailedSandboxLoadInTopLevelFrame` 指标应该记录为 `false`，因为 `fencedframe` 创建不是发生在最外层主框架中。

**8. `HistogramTestCanLoadOpaqueURL` 测试**

*   **功能:** 测试与 `fencedframe` 是否可以加载不透明 URL 相关的用量计数器是否被正确触发。不透明 URL 通常用于隐私沙箱环境。
*   **与 JavaScript 的关系:**  测试与 JavaScript API `HTMLFencedFrameElement.canLoadOpaqueURL()` 的交互。
*   **假设输入:**
    *   获取文档的脚本状态。
    *   调用静态方法 `HTMLFencedFrameElement::canLoadOpaqueURL(script_state)`.
*   **预期输出:**  名为 `WebFeature::kFencedFrameCanLoadOpaqueURL` 的用量计数器应该被记录。

总而言之，这个测试文件全面地测试了 `HTMLFencedFrameElement` 类的核心功能，包括尺寸处理、在不同安全上下文下的行为以及与沙箱的交互。它通过记录各种性能指标来验证这些功能是否按预期工作。这些测试对于确保 `fencedframe` 元素在 Chromium 引擎中的正确性和稳定性至关重要。

Prompt: 
```
这是目录为blink/renderer/core/html/fenced_frame/html_fenced_frame_element_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2021 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"

#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/fenced_frame/fenced_frame_utils.h"
#include "third_party/blink/public/common/frame/fenced_frame_sandbox_flags.h"
#include "third_party/blink/public/platform/web_runtime_features.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_core.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/execution_context/security_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/screen.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_ad_sizes.h"
#include "third_party/blink/renderer/core/html/fenced_frame/fenced_frame_config.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"

namespace blink {

class HTMLFencedFrameElementTest : private ScopedFencedFramesForTest,
                                   public RenderingTest {
 public:
  HTMLFencedFrameElementTest()
      : ScopedFencedFramesForTest(true),
        RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {
    enabled_feature_list_.InitWithFeaturesAndParameters(
        {{blink::features::kFencedFrames, {}}}, {/* disabled_features */});
  }

 protected:
  void SetUp() override {
    RenderingTest::SetUp();
    SecurityContext& security_context =
        GetDocument().GetFrame()->DomWindow()->GetSecurityContext();
    security_context.SetSecurityOriginForTesting(nullptr);
    security_context.SetSecurityOrigin(
        SecurityOrigin::CreateFromString("https://fencedframedelegate.test"));
    EXPECT_EQ(security_context.GetSecureContextMode(),
              SecureContextMode::kSecureContext);
  }

  base::HistogramTester histogram_tester_;

 private:
  base::test::ScopedFeatureList enabled_feature_list_;
};

TEST_F(HTMLFencedFrameElementTest, FreezeSizeLayoutZoomFactor) {
  Document& doc = GetDocument();
  auto* fenced_frame = MakeGarbageCollected<HTMLFencedFrameElement>(doc);
  doc.body()->AppendChild(fenced_frame);
  UpdateAllLifecyclePhasesForTest();

  LocalFrame& frame = GetFrame();
  const float zoom_factor = frame.LayoutZoomFactor();
  const PhysicalSize size(200, 100);
  fenced_frame->FreezeFrameSize(size);
  frame.SetLayoutZoomFactor(zoom_factor * 2);
  EXPECT_EQ(*fenced_frame->FrozenFrameSize(),
            PhysicalSize(size.width * 2, size.height * 2));

  frame.SetLayoutZoomFactor(zoom_factor);
}

TEST_F(HTMLFencedFrameElementTest, CoerceFrameSizeTest) {
  Document& doc = GetDocument();
  auto* fenced_frame = MakeGarbageCollected<HTMLFencedFrameElement>(doc);
  fenced_frame->mode_ =
      blink::FencedFrame::DeprecatedFencedFrameMode::kOpaqueAds;
  doc.body()->AppendChild(fenced_frame);

  // Check that for allowed ad sizes, coercion is a no-op.
  for (const gfx::Size& allowed_size : kAllowedAdSizes) {
    const PhysicalSize requested_size(allowed_size);
    const PhysicalSize coerced_size =
        fenced_frame->CoerceFrameSize(requested_size);
    EXPECT_EQ(requested_size, coerced_size);
  }

  // Check that all of the coercion calls were logged properly.
  histogram_tester_.ExpectBucketCount(kIsOpaqueFencedFrameSizeCoercedHistogram,
                                      0, kAllowedAdSizes.size());

  // Check that for all additional test cases, the coerced size is one of the
  // allowed sizes.
  auto IsAllowedSize = [](const PhysicalSize coerced_size, int screen_width) {
    for (const gfx::Size& allowed_size : kAllowedAdSizes) {
      if (coerced_size == PhysicalSize(allowed_size)) {
        return true;
      }
    }

#if BUILDFLAG(IS_ANDROID)
    for (const int allowed_height : kAllowedAdHeights) {
      if (coerced_size == PhysicalSize(screen_width, allowed_height)) {
        return true;
      }
    }

    for (const gfx::Size& allowed_aspect_ratio : kAllowedAdAspectRatios) {
      if (coerced_size ==
          PhysicalSize(screen_width,
                       (screen_width * allowed_aspect_ratio.height()) /
                           allowed_aspect_ratio.width())) {
        return true;
      }
    }
#endif

    return false;
  };

  int screen_width = GetDocument().domWindow()->screen()->availWidth();

  std::vector<PhysicalSize> test_cases = {
      {-1, -1},
      {0, 0},
      {0, 100},
      {100, 0},
      {100, 100},
      {321, 51},
      {INT_MIN, INT_MIN},
      {INT_MIN / 2, INT_MIN / 2},
      {INT_MAX, INT_MAX},
      {INT_MAX / 2, INT_MAX / 2},
      {screen_width, 0},
      {screen_width, 50},
      {screen_width, 500},
      {screen_width + 10, 0},
      {screen_width + 10, 50},
      {screen_width + 10, 500},
      PhysicalSize(LayoutUnit(320.4), LayoutUnit(50.4)),
      PhysicalSize(LayoutUnit(320.6), LayoutUnit(50.6)),
      PhysicalSize(LayoutUnit(std::numeric_limits<double>::infinity()),
                   LayoutUnit(std::numeric_limits<double>::infinity())),
      PhysicalSize(LayoutUnit(std::numeric_limits<double>::quiet_NaN()),
                   LayoutUnit(std::numeric_limits<double>::quiet_NaN())),
      PhysicalSize(LayoutUnit(std::numeric_limits<double>::signaling_NaN()),
                   LayoutUnit(std::numeric_limits<double>::signaling_NaN())),
      PhysicalSize(LayoutUnit(std::numeric_limits<double>::denorm_min()),
                   LayoutUnit(std::numeric_limits<double>::denorm_min())),
  };

  int expected_coercion_count = 0;

  for (const PhysicalSize& requested_size : test_cases) {
    const PhysicalSize coerced_size =
        fenced_frame->CoerceFrameSize(requested_size);
    EXPECT_TRUE(IsAllowedSize(coerced_size, screen_width));

    // Coercion is not triggered for degenerate sizes
    if (!(coerced_size == requested_size) &&
        requested_size.width.ToDouble() > 0 &&
        requested_size.height.ToDouble() > 0) {
      expected_coercion_count++;
    }
  }

  // Check that all of the coercion calls were logged properly that we expect
  // to be logged.
  histogram_tester_.ExpectBucketCount(kIsOpaqueFencedFrameSizeCoercedHistogram,
                                      1, expected_coercion_count);
}

TEST_F(HTMLFencedFrameElementTest, HistogramTestInsecureContext) {
  Document& doc = GetDocument();

  SecurityContext& security_context =
      doc.GetFrame()->DomWindow()->GetSecurityContext();
  security_context.SetSecurityOriginForTesting(nullptr);
  security_context.SetSecurityOrigin(
      SecurityOrigin::CreateFromString("http://insecure_top_level.test"));

  auto* fenced_frame = MakeGarbageCollected<HTMLFencedFrameElement>(doc);
  fenced_frame->setConfig(
      FencedFrameConfig::Create(String("https://example.com/")));
  doc.body()->AppendChild(fenced_frame);

  histogram_tester_.ExpectUniqueSample(
      kFencedFrameCreationOrNavigationOutcomeHistogram,
      FencedFrameCreationOutcome::kInsecureContext, 1);
}

TEST_F(HTMLFencedFrameElementTest, HistogramTestIncompatibleUrlHTTPDefault) {
  std::vector<String> test_cases = {
      "http://example.com",
      "blob:https://example.com",
      "file://path/to/file",
      "file://localhost/path/to/file",
  };

  Document& doc = GetDocument();

  for (const String& url : test_cases) {
    auto* fenced_frame = MakeGarbageCollected<HTMLFencedFrameElement>(doc);
    fenced_frame->setConfig(FencedFrameConfig::Create(url));
    doc.body()->AppendChild(fenced_frame);
  }

  histogram_tester_.ExpectUniqueSample(
      kFencedFrameCreationOrNavigationOutcomeHistogram,
      FencedFrameCreationOutcome::kIncompatibleURLDefault, test_cases.size());
}

TEST_F(HTMLFencedFrameElementTest, HistogramTestResizeAfterFreeze) {
  Document& doc = GetDocument();

  auto* fenced_frame_opaque = MakeGarbageCollected<HTMLFencedFrameElement>(doc);
  doc.body()->AppendChild(fenced_frame_opaque);

  // The fenced frame was not navigated to any page. Manually tell it that it
  // should freeze the frame size.
  fenced_frame_opaque->should_freeze_frame_size_on_next_layout_ = true;

  // This first resize call will freeze the frame size.
  fenced_frame_opaque->OnResize(PhysicalRect(10, 20, 30, 40));

  // This second resize call will cause the resized after frozen
  // histogram to log.
  fenced_frame_opaque->OnResize(PhysicalRect(20, 30, 40, 50));

  histogram_tester_.ExpectTotalCount(kIsFencedFrameResizedAfterSizeFrozen, 1);
}

TEST_F(HTMLFencedFrameElementTest, HistogramTestSandboxFlags) {
  using WebSandboxFlags = network::mojom::WebSandboxFlags;

  Document& doc = GetDocument();

  doc.GetFrame()->DomWindow()->GetSecurityContext().SetSandboxFlags(
      WebSandboxFlags::kAll);

  auto* fenced_frame = MakeGarbageCollected<HTMLFencedFrameElement>(doc);
  fenced_frame->SetAttributeWithValidation(html_names::kSrcAttr,
                                           AtomicString("https://test.com/"),
                                           ASSERT_NO_EXCEPTION);
  doc.body()->AppendChild(fenced_frame);
  histogram_tester_.ExpectUniqueSample(
      kFencedFrameCreationOrNavigationOutcomeHistogram,
      FencedFrameCreationOutcome::kSandboxFlagsNotSet, 1);

  // Test that only the offending sandbox flags are being logged.
  for (int32_t i = 1; i <= static_cast<int32_t>(WebSandboxFlags::kMaxValue);
       i = i << 1) {
    WebSandboxFlags current_mask = static_cast<WebSandboxFlags>(i);
    histogram_tester_.ExpectBucketCount(
        kFencedFrameMandatoryUnsandboxedFlagsSandboxed, i,
        (kFencedFrameMandatoryUnsandboxedFlags & current_mask) !=
                WebSandboxFlags::kNone
            ? 1
            : 0);
  }

  // Test that it logged that the fenced frame creation attempt was in the
  // outermost main frame.
  histogram_tester_.ExpectUniqueSample(
      kFencedFrameFailedSandboxLoadInTopLevelFrame, true, 1);
}

TEST_F(HTMLFencedFrameElementTest, HistogramTestSandboxFlagsInIframe) {
  Document& doc = GetDocument();

  // Create iframe and embed it in the main document
  auto* iframe = MakeGarbageCollected<HTMLIFrameElement>(doc);
  iframe->SetAttributeWithValidation(html_names::kSrcAttr,
                                     AtomicString("https://test.com/"),
                                     ASSERT_NO_EXCEPTION);
  doc.body()->AppendChild(iframe);
  Document* iframe_doc = iframe->contentDocument();
  iframe_doc->GetFrame()->DomWindow()->GetSecurityContext().SetSandboxFlags(
      network::mojom::blink::WebSandboxFlags::kAll);

  // Create fenced frame and embed it in the main frame
  auto* fenced_frame =
      MakeGarbageCollected<HTMLFencedFrameElement>(*iframe_doc);
  fenced_frame->SetAttributeWithValidation(html_names::kSrcAttr,
                                           AtomicString("https://test.com/"),
                                           ASSERT_NO_EXCEPTION);
  iframe_doc->body()->AppendChild(fenced_frame);

  // Test that it logged that the fenced frame creation attempt was NOT in the
  // outermost main frame.
  histogram_tester_.ExpectUniqueSample(
      kFencedFrameFailedSandboxLoadInTopLevelFrame, false, 1);
}

TEST_F(HTMLFencedFrameElementTest, HistogramTestCanLoadOpaqueURL) {
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kFencedFrameCanLoadOpaqueURL));
  ScriptState* script_state =
      ToScriptStateForMainWorld(GetDocument().GetFrame());
  HTMLFencedFrameElement::canLoadOpaqueURL(script_state);
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kFencedFrameCanLoadOpaqueURL));
}

}  // namespace blink

"""

```