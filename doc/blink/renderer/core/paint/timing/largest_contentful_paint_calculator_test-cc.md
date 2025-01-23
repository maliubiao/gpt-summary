Response:
Let's break down the thought process to arrive at the analysis of the `largest_contentful_paint_calculator_test.cc` file.

1. **Understand the Goal:** The primary goal is to analyze a C++ test file within the Chromium/Blink project and explain its purpose, connections to web technologies, logical flow, potential user errors, and debugging context.

2. **Initial Scan for Keywords and Structure:**  Quickly skim the code for recognizable patterns:
    * `#include`: Indicates dependencies on other C++ files. Notice names like `largest_contentful_paint_calculator.h`, `html_image_element.h`, `paint_timing_detector.h`, etc. These immediately suggest a focus on rendering, painting, and specifically the Largest Contentful Paint (LCP) metric.
    * `namespace blink`:  Confirms it's Blink-specific code.
    * `class LargestContentfulPaintCalculatorTest : public RenderingTest`:  This is the core – a C++ test class inheriting from `RenderingTest`. This means it's designed to test rendering-related functionality.
    * `TEST_F(...)`: These are the individual test cases. Reading their names (`SingleImage`, `SingleText`, `ImageLargerText`, etc.) gives a high-level understanding of what's being tested.
    * Helper functions like `SetBodyInnerHTML`, `SetImage`, `UpdateAllLifecyclePhasesForTest`: These are common patterns in Blink testing for setting up test environments.
    * Assertions like `EXPECT_EQ`, `EXPECT_GT`, `EXPECT_FLOAT_EQ`: Standard C++ testing macros for verifying expected outcomes.
    * Code related to tracing (`trace_analyzer`):  Indicates that these tests might also check for the emission of performance-related trace events.

3. **Identify Core Functionality:** Based on the included headers and test names, the file clearly tests the `LargestContentfulPaintCalculator` class. The tests focus on scenarios involving images and text, which are the main content types relevant to LCP.

4. **Analyze Individual Test Cases:** Go through each `TEST_F` and understand what it's testing:
    * **`SingleImage`:** Checks LCP when a single image is present. Verifies the reported size, image bytes per pixel (BPP), and the emission of a trace event.
    * **`SingleText`:** Checks LCP when only text is present. Verifies the reported size and the absence of image BPP.
    * **`ImageLargerText`, `ImageSmallerText`, `TextLargerImage`, `TextSmallerImage`:** These tests compare the sizes of images and text and verify which element is reported as the LCP candidate.
    * **`LargestImageRemoved`, `LargestTextRemoved`:** Tests how LCP behaves when the largest candidate is removed from the DOM.
    * **`NoPaint`:** Tests the case where there's no content to paint.
    * **`SingleImageExcludedForEntropy`, `LargerImageExcludedForEntropy`, `LowEntropyImageNotExcludedAtLowerThreshold`:** These tests specifically focus on a feature that excludes low-entropy images from LCP consideration, based on a minimum bits-per-pixel threshold.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The `SetBodyInnerHTML` function directly manipulates the HTML content of the page under test. The tests use HTML elements like `<img>` and `<p>`.
    * **CSS:** While not explicitly manipulated in *this specific test file*, LCP is influenced by CSS. For example, CSS can affect the rendered size of images and text, which would impact the LCP calculation. Consider how `display: none` would prevent an element from being considered. *Initially, I might not see direct CSS manipulation, but it's crucial to understand the *implicit* influence of CSS on rendering.*
    * **JavaScript:**  While no JavaScript is directly executed in these tests, in a real web page, JavaScript can dynamically modify the DOM (adding/removing elements, changing content), which would trigger LCP updates. This connection needs to be mentioned.

6. **Infer Logical Flow and Assumptions:**
    * The tests assume that the `LargestContentfulPaintCalculator` correctly identifies the largest visible content element after rendering and painting.
    * They simulate the timing of content presentation using `SimulateImagePresentationPromise()` and `SimulateTextPresentationPromise()`. This mimics the real-world browser behavior of reporting paint times.
    * The tests rely on the `RenderingTest` base class to handle the setup of a minimal rendering environment.

7. **Identify Potential User/Programming Errors:**
    * **User:**  A user might *think* an element is the LCP candidate based on the source HTML, but CSS or JavaScript might make a different element larger at render time. Understanding how LCP is calculated based on *rendered* size is crucial.
    * **Programmer:**  A developer might incorrectly assume that simply adding an image to the DOM makes it the LCP candidate. They need to be aware of the timing of image loading and rendering. They might also not realize that very small or low-information images might be excluded due to entropy filtering.

8. **Reconstruct User Actions and Debugging:**
    *  Think about the steps a user takes to load a webpage: typing a URL, clicking a link, etc. The browser then parses HTML, loads resources (images), applies CSS, and executes JavaScript. LCP is a metric measured *during* this process.
    * For debugging LCP issues, developers would typically use browser developer tools (Performance tab, specifically the "Timings" section). They might also look at the trace events emitted by the browser, which is what these tests verify.

9. **Structure the Explanation:** Organize the findings into clear sections: Functionality, Relationship to Web Technologies, Logical Inference, User/Programming Errors, and Debugging Context. Use examples to illustrate the concepts.

10. **Refine and Review:** Read through the generated explanation, ensuring it's accurate, clear, and addresses all aspects of the prompt. For instance, initially, I might focus too much on the C++ code itself. The review process should emphasize connecting it back to the user experience and web development context. Ensure the assumptions and input/output examples are concrete and illustrative.

By following these steps, starting with a high-level understanding and gradually diving into the details, we can effectively analyze and explain the purpose and context of a complex code file like `largest_contentful_paint_calculator_test.cc`.
这个文件 `largest_contentful_paint_calculator_test.cc` 是 Chromium Blink 引擎中用于测试 `LargestContentfulPaintCalculator` 类的单元测试文件。`LargestContentfulPaintCalculator` 的主要功能是**计算并报告 Largest Contentful Paint (LCP)** 指标。LCP 是衡量用户在页面首次开始加载时，视窗内可见的最大的内容元素完成渲染的时间点。它是一个重要的用户体验指标，用于衡量页面的加载性能。

以下是 `largest_contentful_paint_calculator_test.cc` 文件的具体功能分解：

**1. 测试 Largest Contentful Paint 的计算逻辑:**

   -  它模拟不同的网页场景，包括包含不同大小的图片和文本内容的情况。
   -  它使用 `SetBodyInnerHTML` 函数动态设置网页的 HTML 内容。
   -  它使用 `SetImage` 函数模拟加载图片，并可以指定图片的大小（宽度、高度）和字节数。
   -  它通过调用 `UpdateAllLifecyclePhasesForTest()` 模拟 Blink 渲染引擎的生命周期阶段，包括布局和绘制。
   -  它使用 `SimulateImagePresentationPromise()` 和 `SimulateTextPresentationPromise()` 函数模拟图片和文本内容的呈现时间点。这些函数会触发 `LargestContentfulPaintCalculator` 更新 LCP 候选元素。
   -  它断言（使用 `EXPECT_EQ`, `EXPECT_GT`, `EXPECT_FLOAT_EQ` 等宏）在不同场景下，`LargestContentfulPaintCalculator` 计算出的 LCP 大小 (`LargestReportedSize()`)、候选元素数量 (`CountCandidates()`) 以及图片候选元素的每像素比特数 (`LargestContentfulPaintCandidateImageBPP()`) 是否符合预期。

**2. 测试 LCP 候选元素的识别:**

   -  测试识别单个图片作为 LCP 候选的情况 (`SingleImage`)。
   -  测试识别单个文本块作为 LCP 候选的情况 (`SingleText`)。
   -  测试比较图片和文本大小，确定哪个是 LCP 候选的情况 (`ImageLargerText`, `ImageSmallerText`, `TextLargerImage`, `TextSmallerImage`)。

**3. 测试 LCP 候选元素的移除场景:**

   -  测试当最大的图片 LCP 候选元素从 DOM 中移除后，LCP 指标是否保持不变 (`LargestImageRemoved`)。这验证了 LCP 指标是在元素渲染时确定的，移除后不会重新计算。
   -  测试当最大的文本 LCP 候选元素从 DOM 中移除后，LCP 指标是否保持不变 (`LargestTextRemoved`)。

**4. 测试无绘制内容的情况:**

   -  测试当页面没有可绘制内容时，LCP 指标是否为 0 (`NoPaint`)。

**5. 测试排除低信息熵图片的功能:**

   -  `SingleImageExcludedForEntropy`, `LargerImageExcludedForEntropy`, `LowEntropyImageNotExcludedAtLowerThreshold` 这几个测试用例涉及到 `kExcludeLowEntropyImagesFromLCP` 这个特性。这个特性旨在排除那些视觉上不重要（信息熵低）的图片作为 LCP 候选元素。
   -  这些测试用例通过设置不同的图片大小和字节数，来模拟不同信息熵的图片，并验证在启用该特性后，低信息熵的图片是否会被排除在 LCP 计算之外。`min_bpp` 参数用于设置排除的最低每像素比特数阈值。

**与 JavaScript, HTML, CSS 的关系:**

`largest_contentful_paint_calculator_test.cc` 虽然是 C++ 代码，但它直接测试的功能与浏览器如何渲染和衡量 Web 内容息息相关，因此与 JavaScript、HTML 和 CSS 功能都有关联：

* **HTML:** 测试用例通过 `SetBodyInnerHTML` 函数设置 HTML 内容，例如创建 `<img>` 元素和 `<p>` 元素。LCP 指标关注的是这些 HTML 元素渲染出来的内容。

   ```html
   // 例如在 SingleImage 测试中设置 HTML：
   <img id='target'/>
   ```

* **CSS:** CSS 样式会影响元素的渲染大小和可见性，从而影响 LCP 的计算。虽然这个测试文件本身没有直接操作 CSS，但测试的场景假设 CSS 样式会按照浏览器的默认行为或测试框架的设置应用。例如，如果一个图片被 CSS 设置为 `display: none;`，它就不会被认为是 LCP 候选元素。

* **JavaScript:** JavaScript 可以动态地修改 DOM 结构和样式，这会导致页面的重新渲染，并可能触发 LCP 的重新计算。虽然这个测试文件没有执行 JavaScript 代码，但它模拟了内容呈现的时间点，这与 JavaScript 动态加载内容和触发渲染有关。例如，一个 JavaScript 脚本可能会在稍后时刻加载一张大图，这张图就可能成为新的 LCP 候选元素。

**逻辑推理与假设输入输出:**

**假设输入 (以 `ImageLargerText` 测试为例):**

```html
<!DOCTYPE html>
<img id='target'/>
<p>This text should be larger than the image!!!!</p>
```

* `<img>` 元素的 id 为 'target'，大小设置为 3x3 像素，字节数为 100。
* `<p>` 元素包含一段文本。

**测试步骤:**

1. 设置 HTML 内容。
2. 设置 id 为 'target' 的图片。
3. 模拟所有生命周期阶段完成。
4. 模拟图片呈现时间点。
5. 断言当前的 LCP 大小为图片的像素面积 (3 * 3 = 9)。
6. 模拟文本呈现时间点。
7. 断言当前的 LCP 大小大于 9，因为文本的渲染面积大于图片。

**假设输出:**

* 在图片呈现后：`LargestReportedSize()` 应该返回 9，`CountCandidates()` 应该返回 1。
* 在文本呈现后：`LargestReportedSize()` 应该返回文本的渲染面积，`CountCandidates()` 应该返回 2。

**用户或编程常见的使用错误:**

* **用户错误:** 用户可能会误以为 LCP 是指页面加载的某个特定资源（例如最大的图片），但实际上 LCP 是指**最大的内容元素**完成渲染的时间。这个内容元素可以是图片、文本块或其他类型的内容。
* **编程错误:**
    * **错误地认为隐藏的元素是 LCP 候选:** 开发者可能会忘记，只有视窗内可见的元素才能成为 LCP 候选。使用 CSS (如 `display: none;`) 隐藏的元素不会被考虑。
    * **没有考虑动态加载的内容:** 如果页面的主要内容是通过 JavaScript 动态加载的，开发者需要确保这些内容在 LCP 发生之前完成渲染。如果动态加载延迟太久，LCP 可能会很晚。
    * **忽视初始视窗外的内容:**  只有初始视窗内可见的内容才能成为 LCP 候选。滚动到视窗内的内容不会触发 LCP 的重新计算。
    * **对低信息熵图片的误解:** 开发者可能没有意识到浏览器会排除某些低信息熵的图片作为 LCP 候选，导致他们认为某个大尺寸但内容简单的图片应该是 LCP 元素。

**用户操作是如何一步步的到达这里，作为调试线索:**

当用户访问一个网页时，浏览器会经历以下步骤，这些步骤与 `largest_contentful_paint_calculator_test.cc` 测试的场景息息相关，可以作为调试 LCP 相关问题的线索：

1. **用户在浏览器中输入 URL 或点击链接。**
2. **浏览器发起 HTTP 请求获取 HTML 文档。**
3. **浏览器解析 HTML 文档，构建 DOM 树。** 在这个阶段，`largest_contentful_paint_calculator_test.cc` 中的 `SetBodyInnerHTML` 模拟了这个过程。
4. **浏览器开始加载 HTML 中引用的资源，例如 CSS 样式表、JavaScript 文件和图片。** `SetImage` 函数模拟了图片加载的过程。
5. **浏览器构建 CSSOM 树，并将 CSSOM 和 DOM 结合生成渲染树。**
6. **浏览器进行布局（Layout），计算每个元素在屏幕上的位置和大小。** `UpdateAllLifecyclePhasesForTest()` 模拟了包括布局在内的生命周期阶段。
7. **浏览器进行绘制（Paint），将渲染树中的元素绘制到屏幕上。**  `LargestContentfulPaintCalculator` 会在这个阶段检测潜在的 LCP 候选元素。
8. **在绘制过程中，当一个潜在的 LCP 候选元素完成首次渲染时，`LargestContentfulPaintCalculator` 会记录其大小和时间。** `SimulateImagePresentationPromise()` 和 `SimulateTextPresentationPromise()` 模拟了内容呈现的时间点。
9. **浏览器持续监控，直到确定最终的 LCP 元素。**  通常，在首帧渲染后不久，或者当主要的视觉内容完成渲染时，LCP 指标会被确定。
10. **开发者可以使用浏览器的开发者工具（例如 Chrome DevTools 的 Performance 面板）查看 LCP 指标，以及哪些元素被认为是 LCP 候选元素。**  `trace_analyzer::Stop()` 和相关的代码用于在测试中分析 trace 事件，这类似于开发者在实际调试中查看性能追踪信息。

**调试线索:**

当开发者遇到 LCP 问题时，可以参考以下步骤，这与 `largest_contentful_paint_calculator_test.cc` 测试的逻辑相关：

1. **使用浏览器的性能分析工具（Performance 面板）记录页面加载过程。**
2. **查看 "Timings" 部分，找到 LCP 标记。** 这会显示 LCP 发生的时间点。
3. **查看 "Main" 线程的火焰图，找到与 LCP 相关的渲染活动。** 关注首次绘制较大内容元素的时刻。
4. **检查 "Largest Contentful Paint" 部分，查看浏览器识别的 LCP 元素。**
5. **如果 LCP 元素不是预期的，检查以下几点:**
   - **该元素是否在初始视窗内可见？**
   - **该元素的资源加载是否延迟？** (例如，图片加载缓慢)
   - **是否有 JavaScript 延迟了该元素的渲染？**
   - **是否有 CSS 样式阻止了该元素的早期渲染？**
   - **如果 LCP 元素是图片，检查其大小和是否启用了 `kExcludeLowEntropyImagesFromLCP` 特性。**

`largest_contentful_paint_calculator_test.cc` 文件通过各种测试用例，覆盖了 LCP 计算的多种场景和边界情况，帮助开发者理解 LCP 的工作原理，并为调试实际的 LCP 问题提供了理论基础和验证方法。

### 提示词
```
这是目录为blink/renderer/core/paint/timing/largest_contentful_paint_calculator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/timing/largest_contentful_paint_calculator.h"

#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/trace_event_analyzer.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/paint/timing/image_paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_test_helper.h"
#include "third_party/blink/renderer/core/paint/timing/text_paint_timing_detector.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkSurface.h"

namespace blink {

namespace {
constexpr const char kTraceCategories[] = "loading,rail,devtools.timeline";

constexpr const char kLCPCandidate[] = "largestContentfulPaint::Candidate";
}  // namespace

class LargestContentfulPaintCalculatorTest : public RenderingTest {
 public:
  void SetUp() override {
    // Advance the clock so we do not assign null TimeTicks.
    simulated_clock_.Advance(base::Milliseconds(100));
    EnableCompositing();
    RenderingTest::SetUp();

    mock_text_callback_manager_ =
        MakeGarbageCollected<MockPaintTimingCallbackManager>();
    GetTextPaintTimingDetector()->ResetCallbackManager(
        mock_text_callback_manager_);
    mock_image_callback_manager_ =
        MakeGarbageCollected<MockPaintTimingCallbackManager>();
    GetImagePaintTimingDetector()->ResetCallbackManager(
        mock_image_callback_manager_);
    trace_analyzer::Start(kTraceCategories);
  }

  void TearDown() override { RenderingTest::TearDown(); }

  ImagePaintTimingDetector* GetImagePaintTimingDetector() {
    return &GetFrame()
                .View()
                ->GetPaintTimingDetector()
                .GetImagePaintTimingDetector();
  }
  TextPaintTimingDetector* GetTextPaintTimingDetector() {
    return &GetFrame()
                .View()
                ->GetPaintTimingDetector()
                .GetTextPaintTimingDetector();
  }

  void SetImage(const char* id, int width, int height, int bytes = 0) {
    To<HTMLImageElement>(GetElementById(id))
        ->SetImageForTest(CreateImageForTest(width, height, bytes));
  }

  ImageResourceContent* CreateImageForTest(int width,
                                           int height,
                                           int bytes = 0) {
    sk_sp<SkColorSpace> src_rgb_color_space = SkColorSpace::MakeSRGB();
    SkImageInfo raster_image_info =
        SkImageInfo::MakeN32Premul(width, height, src_rgb_color_space);
    sk_sp<SkSurface> surface(SkSurfaces::Raster(raster_image_info));
    sk_sp<SkImage> image = surface->makeImageSnapshot();
    scoped_refptr<UnacceleratedStaticBitmapImage> original_image_data =
        UnacceleratedStaticBitmapImage::Create(image);
    // If a byte size is specified, then also assign a suitably-sized
    // vector of 0s to the image. This is used for bits-per-pixel
    // calculations.
    if (bytes > 0) {
      scoped_refptr<SharedBuffer> shared_buffer =
          SharedBuffer::Create(Vector<char>(bytes));
      original_image_data->SetData(shared_buffer, /*all_data_received=*/true);
    }
    ImageResourceContent* original_image_content =
        ImageResourceContent::CreateLoaded(original_image_data.get());
    return original_image_content;
  }

  uint64_t LargestReportedSize() {
    return GetLargestContentfulPaintCalculator()->largest_reported_size_;
  }

  double LargestContentfulPaintCandidateImageBPP() {
    return GetLargestContentfulPaintCalculator()->largest_image_bpp_;
  }

  uint64_t CountCandidates() {
    return GetLargestContentfulPaintCalculator()->count_candidates_;
  }

  void UpdateLargestContentfulPaintCandidate() {
    GetFrame().View()->GetPaintTimingDetector().UpdateLcpCandidate();
  }

  void SimulateContentPresentationPromise() {
    mock_text_callback_manager_->InvokePresentationTimeCallback(
        simulated_clock_.NowTicks());
    mock_image_callback_manager_->InvokePresentationTimeCallback(
        simulated_clock_.NowTicks());
    // Outside the tests, this is invoked by
    // |PaintTimingCallbackManagerImpl::ReportPaintTime|.
    UpdateLargestContentfulPaintCandidate();
  }

  // Outside the tests, the text callback and the image callback are run
  // together, as in |SimulateContentPresentationPromise|.
  void SimulateImagePresentationPromise() {
    mock_image_callback_manager_->InvokePresentationTimeCallback(
        simulated_clock_.NowTicks());
    // Outside the tests, this is invoked by
    // |PaintTimingCallbackManagerImpl::ReportPaintTime|.
    UpdateLargestContentfulPaintCandidate();
  }

  // Outside the tests, the text callback and the image callback are run
  // together, as in |SimulateContentPresentationPromise|.
  void SimulateTextPresentationPromise() {
    mock_text_callback_manager_->InvokePresentationTimeCallback(
        simulated_clock_.NowTicks());
    // Outside the tests, this is invoked by
    // |PaintTimingCallbackManagerImpl::ReportPaintTime|.
    UpdateLargestContentfulPaintCandidate();
  }

 private:
  LargestContentfulPaintCalculator* GetLargestContentfulPaintCalculator() {
    return GetFrame()
        .View()
        ->GetPaintTimingDetector()
        .GetLargestContentfulPaintCalculator();
  }

  base::SimpleTestTickClock simulated_clock_;
  Persistent<MockPaintTimingCallbackManager> mock_text_callback_manager_;
  Persistent<MockPaintTimingCallbackManager> mock_image_callback_manager_;
};

TEST_F(LargestContentfulPaintCalculatorTest, SingleImage) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='target'/>
  )HTML");
  SetImage("target", 100, 150, 1500);
  UpdateAllLifecyclePhasesForTest();
  SimulateImagePresentationPromise();

  auto analyzer = trace_analyzer::Stop();
  trace_analyzer::TraceEventVector events;
  using trace_analyzer::Query;
  Query q = Query::EventNameIs(kLCPCandidate);
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(1u, events.size());
  EXPECT_EQ(kTraceCategories, events[0]->category);

  EXPECT_TRUE(events[0]->HasStringArg("frame"));

  ASSERT_TRUE(events[0]->HasDictArg("data"));
  base::Value::Dict arg_dict = events[0]->GetKnownArgAsDict("data");
  EXPECT_TRUE(arg_dict.FindDouble("imageLoadStart").has_value());
  EXPECT_TRUE(arg_dict.FindDouble("imageLoadEnd").has_value());
  EXPECT_TRUE(arg_dict.FindDouble("imageDiscoveryTime").has_value());

  EXPECT_EQ(LargestReportedSize(), 15000u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 0.8f);
  EXPECT_EQ(CountCandidates(), 1u);
}

TEST_F(LargestContentfulPaintCalculatorTest, SingleText) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <p>This is some text</p>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  SimulateTextPresentationPromise();

  EXPECT_GT(LargestReportedSize(), 0u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 0.0f);
  EXPECT_EQ(CountCandidates(), 1u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, ImageLargerText) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='target'/>
    <p>This text should be larger than the image!!!!</p>
  )HTML");
  SetImage("target", 3, 3, 100);
  UpdateAllLifecyclePhasesForTest();
  SimulateImagePresentationPromise();
  EXPECT_EQ(LargestReportedSize(), 9u);
  EXPECT_EQ(CountCandidates(), 1u);
  SimulateTextPresentationPromise();

  EXPECT_GT(LargestReportedSize(), 9u);
  EXPECT_EQ(CountCandidates(), 2u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, ImageSmallerText) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='target'/>
    <p>.</p>
  )HTML");
  SetImage("target", 100, 200, /*bytes=*/250);
  UpdateAllLifecyclePhasesForTest();
  SimulateImagePresentationPromise();
  EXPECT_EQ(LargestReportedSize(), 20000u);
  EXPECT_EQ(CountCandidates(), 1u);
  SimulateTextPresentationPromise();

  // Text should not be reported, since it is smaller than the image.
  EXPECT_EQ(LargestReportedSize(), 20000u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 0.1f);
  EXPECT_EQ(CountCandidates(), 1u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, TextLargerImage) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='target'/>
    <p>.</p>
  )HTML");
  SetImage("target", 100, 200, /*bytes=*/250);
  UpdateAllLifecyclePhasesForTest();
  SimulateContentPresentationPromise();

  EXPECT_EQ(LargestReportedSize(), 20000u);
  EXPECT_EQ(CountCandidates(), 1u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, TextSmallerImage) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='target'/>
    <p>This text should be larger than the image!!!!</p>
  )HTML");
  SetImage("target", 3, 3, /*bytes=*/9);
  UpdateAllLifecyclePhasesForTest();
  SimulateContentPresentationPromise();

  // Image should not be reported, since it is smaller than the text. No image
  // BPP should be recorded.
  EXPECT_GT(LargestReportedSize(), 9u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 0.0f);
  EXPECT_EQ(CountCandidates(), 1u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, LargestImageRemoved) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='large'/>
    <img id='small'/>
    <p>Larger than the second image</p>
  )HTML");
  SetImage("large", 100, 200, 200);
  SetImage("small", 3, 3, 18);
  UpdateAllLifecyclePhasesForTest();
  SimulateImagePresentationPromise();
  SimulateTextPresentationPromise();
  // Image is larger than the text.
  EXPECT_EQ(LargestReportedSize(), 20000u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 0.08f);
  EXPECT_EQ(CountCandidates(), 1u);

  GetDocument().getElementById(AtomicString("large"))->remove();
  UpdateAllLifecyclePhasesForTest();
  // The LCP does not move after the image is removed.
  EXPECT_EQ(LargestReportedSize(), 20000u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 0.08f);
  EXPECT_EQ(CountCandidates(), 1u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, LargestTextRemoved) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='medium'/>
    <p id='large'>
      This text element should be larger than than the image!\n
      These words ensure that this is the case.\n
      But the image will be larger than the other paragraph!
    </p>
    <p id='small'>.</p>
  )HTML");
  SetImage("medium", 10, 5, /*bytes=*/50);
  UpdateAllLifecyclePhasesForTest();
  SimulateImagePresentationPromise();
  SimulateTextPresentationPromise();
  // Test is larger than the image.
  EXPECT_GT(LargestReportedSize(), 50u);
  // Image presentation occurred first, so we have would have two candidates.
  EXPECT_EQ(CountCandidates(), 2u);

  GetDocument().getElementById(AtomicString("large"))->remove();
  UpdateAllLifecyclePhasesForTest();
  // The LCP should not move after removal.
  EXPECT_GT(LargestReportedSize(), 50u);
  EXPECT_EQ(CountCandidates(), 2u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, NoPaint) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
  )HTML");
  UpdateAllLifecyclePhasesForTest();
  UpdateLargestContentfulPaintCandidate();
  EXPECT_EQ(LargestReportedSize(), 0u);
  EXPECT_EQ(CountCandidates(), 0u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, SingleImageExcludedForEntropy) {
  base::test::ScopedFeatureList scoped_features;
  scoped_features.InitAndEnableFeatureWithParameters(
      blink::features::kExcludeLowEntropyImagesFromLCP, {{"min_bpp", "2.0"}});
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='target'/>
  )HTML");
  // 600 bytes will cause a calculated entropy of 0.32bpp, which is below the
  // 2bpp threshold.
  SetImage("target", 100, 150, 600);
  UpdateAllLifecyclePhasesForTest();
  UpdateLargestContentfulPaintCandidate();

  EXPECT_EQ(LargestReportedSize(), 0u);
  EXPECT_EQ(CountCandidates(), 0u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest, LargerImageExcludedForEntropy) {
  base::test::ScopedFeatureList scoped_features;
  scoped_features.InitAndEnableFeatureWithParameters(
      blink::features::kExcludeLowEntropyImagesFromLCP, {{"min_bpp", "2.0"}});
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='small'/>
    <img id='large'/>
  )HTML");
  // Smaller image has 16 bpp of entropy, enough to be considered for LCP.
  // Larger image has only 0.32 bpp, which is below the 2bpp threshold.
  SetImage("small", 3, 3, 18);
  SetImage("large", 100, 200, 800);
  UpdateAllLifecyclePhasesForTest();
  SimulateImagePresentationPromise();

  EXPECT_EQ(LargestReportedSize(), 9u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 16.0f);
  EXPECT_EQ(CountCandidates(), 1u);
  trace_analyzer::Stop();
}

TEST_F(LargestContentfulPaintCalculatorTest,
       LowEntropyImageNotExcludedAtLowerThreshold) {
  base::test::ScopedFeatureList scoped_features;
  scoped_features.InitAndEnableFeatureWithParameters(
      blink::features::kExcludeLowEntropyImagesFromLCP, {{"min_bpp", "0.02"}});
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <img id='small'/>
    <img id='large'/>
  )HTML");
  // Smaller image has 16 bpp of entropy, enough to be considered for LCP.
  // Larger image has 0.32 bpp, which is now above the 0.2bpp threshold.
  SetImage("small", 3, 3, 18);
  SetImage("large", 100, 200, 800);
  UpdateAllLifecyclePhasesForTest();
  SimulateImagePresentationPromise();

  EXPECT_EQ(LargestReportedSize(), 20000u);
  EXPECT_FLOAT_EQ(LargestContentfulPaintCandidateImageBPP(), 0.32f);
  trace_analyzer::Stop();
}

}  // namespace blink
```