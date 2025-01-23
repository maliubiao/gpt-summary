Response:
The user wants me to analyze a C++ source code file from the Chromium Blink engine.
Specifically, the file `image_paint_timing_detector_test.cc`.

Here's a breakdown of the analysis I need to perform:

1. **Functionality:** Describe the purpose of this test file.
2. **Relationship to Web Technologies:** Explain how this code interacts with JavaScript, HTML, and CSS. Provide concrete examples.
3. **Logical Inference:**  If the test file involves reasoning about inputs and outputs, give an example.
4. **Common User/Programming Errors:** Identify potential mistakes related to the functionality being tested.
5. **User Operations and Debugging:** Explain how a user action might lead to this code being executed, providing debugging hints.
6. **Summary:**  Concisely summarize the file's functionality based on the provided code.

Let's go through each point based on the content of the provided code snippet.

**1. Functionality:**

The file `image_paint_timing_detector_test.cc` contains unit tests for the `ImagePaintTimingDetector` class. This class is responsible for detecting and recording the paint timing of images, particularly for the Largest Contentful Paint (LCP) metric. The tests cover various scenarios, including:

*   Basic image painting.
*   Handling of multiple images.
*   Impact of CSS properties (opacity, visibility, display).
*   Images inside iframes.
*   Removal and re-attachment of images.
*   Interaction with the performance timeline.
*   Trace event generation.

**2. Relationship to Web Technologies:**

*   **HTML:** The tests create HTML elements (`<img>`) and manipulate their properties. The tests verify that the paint timing detection correctly identifies the largest contentful image based on its rendered size within the HTML document.
*   **CSS:** The tests explicitly use CSS properties like `opacity`, `visibility`, and `display` to see how they affect the detection of image paint times. For example, images with `opacity: 0` or `display: none` are expected to be ignored.
*   **JavaScript:** While this is a C++ test file, the functionality being tested is directly related to how the browser renders web pages, which are often built with HTML, CSS, and JavaScript. JavaScript code can dynamically modify the DOM, including adding, removing, or changing the attributes of image elements, which would trigger the logic tested in this file.

**3. Logical Inference (Example):**

*   **Assumption:** If an image is painted within the viewport and is the largest so far, its paint time and size will be recorded as a potential LCP candidate.
*   **Input:** An HTML page with an `<img>` element having `width=100` and `height=100`, painted after another image with `width=50` and `height=50`.
*   **Output:** The `LargestImage()` function should return the record for the 100x100 image, and `LargestPaintSize()` should return 10000.

**4. Common User/Programming Errors:**

*   **Incorrectly assuming invisible images contribute to LCP:** Developers might expect images with `opacity: 0` or `display: none` to be considered for LCP, but this test file demonstrates that they are excluded.
    *   **Example:** A developer might add a large background image to a div and set its opacity to 0 initially, intending to animate it later. They might be surprised that this image doesn't contribute to the initial LCP.
*   **Not understanding the impact of layout and rendering on LCP:** The LCP is based on the *rendered* size of the image. A large image that is initially styled to be small via CSS, and then later resized with JavaScript, will only contribute to LCP when it's actually rendered at a larger size.
*   **Dynamically loading images and expecting immediate LCP updates:** If JavaScript loads images asynchronously, developers need to understand that the LCP might update only after the image is fully loaded and painted.

**5. User Operations and Debugging:**

*   **User Action:** A user navigates to a webpage containing images.
*   **How it reaches the code:**
    1. The browser's HTML parser encounters an `<img>` tag.
    2. The resource loader fetches the image data.
    3. The rendering engine (Blink) lays out the page and determines the size and position of the image.
    4. When the image is painted to the screen, the `ImagePaintTimingDetector` is notified.
    5. This test file verifies the correctness of the logic within the `ImagePaintTimingDetector` that determines if this paint event constitutes a new largest contentful paint.
*   **Debugging Clues:** If a website's LCP is unexpectedly high, developers might:
    *   Use browser developer tools (e.g., Chrome DevTools' "Performance" tab) to identify the LCP element.
    *   Inspect the network requests to check the loading time of the LCP image.
    *   Analyze the rendering timeline to see when the image was painted.
    *   Examine the CSS styles applied to the LCP element to ensure it's not initially hidden or sized incorrectly. The tests in this file provide insights into the factors that influence LCP calculation.

**6. Summary of Functionality (Part 1):**

This part of the `image_paint_timing_detector_test.cc` file focuses on verifying the core functionality of the `ImagePaintTimingDetector`. It tests scenarios involving single and multiple image elements, how the detector identifies the largest painted image, and how CSS properties like visibility and opacity affect the detection process. It also covers basic integration with the performance timeline and trace event generation for LCP candidates.

```
功能归纳:

这个C++测试文件 `image_paint_timing_detector_test.cc` 的主要功能是针对 Chromium Blink 引擎中的 `ImagePaintTimingDetector` 类进行单元测试。 该类负责检测和记录页面上图片元素的首次绘制时间，这是用于计算 Largest Contentful Paint (LCP) 指标的关键部分。

具体来说，该测试文件涵盖了以下方面的功能测试：

1. **基本图片绘制检测:** 验证在页面中添加图片元素后，`ImagePaintTimingDetector` 能正确识别并记录图片的绘制事件。
2. **LCP 候选选择:** 测试 `ImagePaintTimingDetector` 如何根据图片的大小和绘制时间选择 Largest Contentful Paint 的候选者。
3. **CSS 属性的影响:** 验证 CSS 属性如 `opacity`, `visibility`, 和 `display` 如何影响图片是否被视为 LCP 候选者。 例如，`opacity: 0` 或 `display: none` 的图片应该被忽略。
4. **动态添加和删除图片:** 测试在页面中动态添加或删除图片元素时，`ImagePaintTimingDetector` 如何更新其记录。
5. **iframe 中的图片:** 验证 `ImagePaintTimingDetector` 能正确处理嵌入到 iframe 中的图片元素的绘制事件。
6. **性能指标更新:** 测试 `ImagePaintTimingDetector` 如何更新 `PerformanceTimingForReporting` 中的 LCP 相关信息。
7. **Trace 事件生成:** 验证在图片成为 LCP 候选者时，是否正确生成了跟踪事件，方便开发者进行性能分析。
8. **图片加载完成时间:** 验证是否正确记录了图片的加载完成时间。

这些测试用例通过模拟各种场景，例如添加不同大小的图片，应用不同的 CSS 样式，动态修改 DOM 结构等，来确保 `ImagePaintTimingDetector` 能够准确可靠地工作，为浏览器正确计算 LCP 指标提供保障。
```
### 提示词
```
这是目录为blink/renderer/core/paint/timing/image_paint_timing_detector_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/timing/image_paint_timing_detector.h"

#include "base/functional/bind.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/test/trace_event_analyzer.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "components/ukm/test_ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "testing/gmock/include/gmock/gmock-matchers.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource.h"
#include "third_party/blink/renderer/core/paint/timing/largest_contentful_paint_calculator.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_test_helper.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/timing/dom_window_performance.h"
#include "third_party/blink/renderer/core/timing/performance_timing_for_reporting.h"
#include "third_party/blink/renderer/core/timing/window_performance.h"
#include "third_party/blink/renderer/platform/graphics/unaccelerated_static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "third_party/skia/include/core/SkImage.h"
#include "third_party/skia/include/core/SkSurface.h"

namespace blink {

#define SIMPLE_IMAGE       \
  "data:image/gif;base64," \
  "R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="

#define LARGE_IMAGE                                                            \
  "data:image/gif;base64,"                                                     \
  "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSF" \
  "lzAAAN1wAADdcBQiibeAAAAb5JREFUOMulkr1KA0EQgGdvTwwnYmER0gQsrFKmSy+pLESw9Qm0" \
  "F/ICNnba+h6iEOuAEWslKJKTOyJJvIT72d1xZuOFC0giOLA77O7Mt/PnNptN+I+49Xr9GhH3f3" \
  "mb0v1ht9vtLAUYYw5ItkgDL3KyD8PhcLvdbl/WarXT3DjLMnAcR/f7/YfxeKwtgC5RKQVhGILW" \
  "eg4hQ6hUKjWyucmhLFEUuWR3QYBWAZABQ9i5CCmXy16pVALP80BKaaG+70MQBLvzFMjRKKXh8j" \
  "6FSYKF7ITdEWLa4/ktokN74wiqjSMpnVcbQZqmEJHz+ckeCPFjWKwULpyspAqhdXVXdcnZcPjs" \
  "Ign+2BsVA8jVYuWlgJ3yBj0icgq2uoK+lg4t+ZvLomSKamSQ4AI5BcMADtMhyNoSgNIISUaFNt" \
  "wlazcDcBc4gjjVwCWid2usCWroYEhnaqbzFJLUzAHIXRDChXCcQP8zhkSZ5eNLgHAUzwDcRu4C" \
  "oIRn/wsGUQIIy4Vr9TH6SYFCNzw4nALn5627K4vIttOUOwfa5YnrDYzt/9OLv9I5l8kk5hZ3XL" \
  "O20b7tbR7zHLy/BX8G0IeBEM7ZN1NGIaFUaKLgAAAAAElFTkSuQmCC"

#define TRANSPARENT_PLACEHOLDER_IMAGE \
  "data:image/gif;base64,"            \
  "R0lGODlhAQABAIAAAP///////yH5BAEKAAEALAAAAAABAAEAAAICTAEAOw=="

using UkmPaintTiming = ukm::builders::Blink_PaintTiming;
using ::testing::Optional;

class ImagePaintTimingDetectorTest : public testing::Test,
                                     public PaintTestConfigurations {
 public:
  ImagePaintTimingDetectorTest()
      : test_task_runner_(
            base::MakeRefCounted<base::TestMockTimeTaskRunner>()) {}

  void SetUp() override {
    web_view_helper_.Initialize();

    // Enable compositing on the page before running the document lifecycle.
    web_view_helper_.GetWebView()
        ->GetPage()
        ->GetSettings()
        .SetAcceleratedCompositingEnabled(true);

    WebLocalFrameImpl& frame_impl = *web_view_helper_.LocalMainFrame();
    frame_impl.ViewImpl()->MainFrameViewWidget()->Resize(gfx::Size(640, 480));

    frame_test_helpers::LoadFrame(
        web_view_helper_.GetWebView()->MainFrameImpl(), "about:blank");
    GetDocument().View()->SetParentVisible(true);
    GetDocument().View()->SetSelfVisible(true);
  }

 protected:
  LocalFrameView& GetFrameView() { return *GetFrame()->View(); }
  LocalFrameView& GetChildFrameView() { return *GetChildFrame()->View(); }
  Document& GetDocument() { return *GetFrame()->GetDocument(); }
  Document* GetChildDocument() { return GetChildFrame()->GetDocument(); }
  PaintTimingDetector& GetPaintTimingDetector() {
    return GetFrameView().GetPaintTimingDetector();
  }
  PaintTimingDetector& GetChildPaintTimingDetector() {
    return GetChildFrameView().GetPaintTimingDetector();
  }

  const PerformanceTimingForReporting& GetPerformanceTimingForReporting() {
    PerformanceTimingForReporting* performance_for_reporting =
        DOMWindowPerformance::performance(*GetFrame()->DomWindow())
            ->timingForReporting();
    return *performance_for_reporting;
  }

  gfx::Rect GetViewportRect(LocalFrameView& view) {
    ScrollableArea* scrollable_area = view.GetScrollableArea();
    DCHECK(scrollable_area);
    return scrollable_area->VisibleContentRect();
  }

  ImageRecord* LargestImage() {
    return GetPaintTimingDetector()
        .GetImagePaintTimingDetector()
        .records_manager_.LargestImage();
  }

  ImageRecord* LargestPaintedImage() {
    return GetPaintTimingDetector()
        .GetImagePaintTimingDetector()
        .records_manager_.largest_painted_image_.Get();
  }

  ImageRecord* ChildFrameLargestImage() {
    return GetChildFrameView()
        .GetPaintTimingDetector()
        .GetImagePaintTimingDetector()
        .records_manager_.LargestImage();
  }

  size_t CountImageRecords() {
    return GetPaintTimingDetector()
        .GetImagePaintTimingDetector()
        .records_manager_.recorded_images_.size();
  }

  size_t ContainerTotalSize() {
    size_t result = GetPaintTimingDetector()
                        .GetImagePaintTimingDetector()
                        .records_manager_.recorded_images_.size() +
                    GetPaintTimingDetector()
                        .GetImagePaintTimingDetector()
                        .records_manager_.pending_images_.size() +
                    GetPaintTimingDetector()
                        .GetImagePaintTimingDetector()
                        .records_manager_.images_queued_for_paint_time_.size() +
                    GetPaintTimingDetector()
                        .GetImagePaintTimingDetector()
                        .records_manager_.image_finished_times_.size();

    return result;
  }

  size_t CountChildFrameRecords() {
    return GetChildPaintTimingDetector()
        .GetImagePaintTimingDetector()
        .records_manager_.recorded_images_.size();
  }

  void UpdateCandidate() { GetPaintTimingDetector().UpdateLcpCandidate(); }

  void UpdateCandidateForChildFrame() {
    GetChildPaintTimingDetector().UpdateLcpCandidate();
  }

  base::TimeTicks LargestPaintTime() {
    return GetPaintTimingDetector()
        .LatestLcpDetailsForTest()
        .largest_image_paint_time;
  }

  uint64_t LargestPaintSize() {
    return GetPaintTimingDetector()
        .LatestLcpDetailsForTest()
        .largest_image_paint_size;
  }

  static constexpr base::TimeDelta kQuantumOfTime = base::Milliseconds(10);

  void SimulatePassOfTime() {
    test_task_runner_->FastForwardBy(kQuantumOfTime);
  }

  void UpdateAllLifecyclePhases() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  void UpdateAllLifecyclePhasesAndInvokeCallbackIfAny() {
    UpdateAllLifecyclePhases();
    SimulatePassOfTime();
    while (mock_callback_manager_->CountCallbacks() > 0)
      InvokePresentationTimeCallback(mock_callback_manager_);
  }

  void SetBodyInnerHTML(const std::string& content) {
    frame_test_helpers::LoadHTMLString(
        web_view_helper_.GetWebView()->MainFrameImpl(), content,
        KURL("http://test.com"));
    mock_callback_manager_ =
        MakeGarbageCollected<MockPaintTimingCallbackManager>();
    GetPaintTimingDetector().GetImagePaintTimingDetector().ResetCallbackManager(
        mock_callback_manager_);
    UpdateAllLifecyclePhases();
  }

  void SetChildBodyInnerHTML(const String& content) {
    GetChildDocument()->SetBaseURLOverride(KURL("http://test.com"));
    GetChildDocument()->body()->setInnerHTML(content, ASSERT_NO_EXCEPTION);
    child_mock_callback_manager_ =
        MakeGarbageCollected<MockPaintTimingCallbackManager>();
    GetChildPaintTimingDetector()
        .GetImagePaintTimingDetector()
        .ResetCallbackManager(child_mock_callback_manager_);
    UpdateAllLifecyclePhases();
  }

  void InvokeCallback() {
    DCHECK_GT(mock_callback_manager_->CountCallbacks(), 0UL);
    InvokePresentationTimeCallback(mock_callback_manager_);
  }

  void InvokeChildFrameCallback() {
    DCHECK_GT(child_mock_callback_manager_->CountCallbacks(), 0UL);
    InvokePresentationTimeCallback(child_mock_callback_manager_);
    UpdateCandidateForChildFrame();
  }

  void InvokePresentationTimeCallback(
      MockPaintTimingCallbackManager* image_callback_manager) {
    image_callback_manager->InvokePresentationTimeCallback(
        test_task_runner_->NowTicks());
    UpdateCandidate();
  }

  void SetImageAndPaint(const char* id, int width, int height) {
    Element* element = GetDocument().getElementById(AtomicString(id));
    // Set image and make it loaded.
    ImageResourceContent* content = CreateImageForTest(width, height);
    To<HTMLImageElement>(element)->SetImageForTest(content);
  }

  void SetChildFrameImageAndPaint(const char* id, int width, int height) {
    DCHECK(GetChildDocument());
    Element* element = GetChildDocument()->getElementById(AtomicString(id));
    DCHECK(element);
    // Set image and make it loaded.
    ImageResourceContent* content = CreateImageForTest(width, height);
    To<HTMLImageElement>(element)->SetImageForTest(content);
  }

  void SetSVGImageAndPaint(const char* id, int width, int height) {
    Element* element = GetDocument().getElementById(AtomicString(id));
    // Set image and make it loaded.
    ImageResourceContent* content = CreateImageForTest(width, height);
    To<SVGImageElement>(element)->SetImageForTest(content);
  }

  void SimulateScroll() {
    GetPaintTimingDetector().NotifyScroll(mojom::blink::ScrollType::kUser);
  }

  void SimulateKeyDown() {
    GetPaintTimingDetector().NotifyInputEvent(WebInputEvent::Type::kKeyDown);
  }

  void SimulateKeyUp() {
    GetPaintTimingDetector().NotifyInputEvent(WebInputEvent::Type::kKeyUp);
  }

  LocalFrame* GetChildFrame() {
    return To<LocalFrame>(GetFrame()->Tree().FirstChild());
  }

  test::TaskEnvironment task_environment_;
  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;
  frame_test_helpers::WebViewHelper web_view_helper_;

 private:
  LocalFrame* GetFrame() {
    return web_view_helper_.GetWebView()->MainFrameImpl()->GetFrame();
  }
  ImageResourceContent* CreateImageForTest(int width, int height) {
    sk_sp<SkColorSpace> src_rgb_color_space = SkColorSpace::MakeSRGB();
    SkImageInfo raster_image_info =
        SkImageInfo::MakeN32Premul(width, height, src_rgb_color_space);
    sk_sp<SkSurface> surface(SkSurfaces::Raster(raster_image_info));
    sk_sp<SkImage> image = surface->makeImageSnapshot();
    scoped_refptr<UnacceleratedStaticBitmapImage> original_image_data =
        UnacceleratedStaticBitmapImage::Create(image);
    // To ensure that the image may be considered as an LCP candidate, allocate
    // a small amount of memory for the image (0.1bpp should exceed the LCP
    // entropy threshold).
    int bytes = (width * height / 80) + 1;
    scoped_refptr<SharedBuffer> shared_buffer =
        SharedBuffer::Create(Vector<char>(bytes));
    original_image_data->SetData(shared_buffer, /*all_data_received=*/true);
    ImageResourceContent* original_image_content =
        ImageResourceContent::CreateLoaded(original_image_data.get());
    return original_image_content;
  }

  PaintTimingCallbackManager::CallbackQueue callback_queue_;
  Persistent<MockPaintTimingCallbackManager> mock_callback_manager_;
  Persistent<MockPaintTimingCallbackManager> child_mock_callback_manager_;
};

constexpr base::TimeDelta ImagePaintTimingDetectorTest::kQuantumOfTime;

INSTANTIATE_PAINT_TEST_SUITE_P(ImagePaintTimingDetectorTest);

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_NoImage) {
  SetBodyInnerHTML(R"HTML(
    <div></div>
  )HTML");
  ImageRecord* record = LargestImage();
  EXPECT_FALSE(record);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_OneImage) {
  ukm::TestAutoSetUkmRecorder test_ukm_recorder;
  SetBodyInnerHTML(R"HTML(
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_EQ(record->recorded_size, 25ul);
  EXPECT_FALSE(record->load_time.is_null());
  // Simulate some input event to force StopRecordEntries().
  SimulateKeyDown();
  auto entries = test_ukm_recorder.GetEntriesByName(UkmPaintTiming::kEntryName);
  EXPECT_EQ(1ul, entries.size());
  auto* entry = entries[0].get();
  test_ukm_recorder.ExpectEntryMetric(
      entry, UkmPaintTiming::kLCPDebugging_HasViewportImageName, false);
}

TEST_P(ImagePaintTimingDetectorTest, InsertionOrderIsSecondaryRankingKey) {
  SetBodyInnerHTML(R"HTML(
  )HTML");

  auto* image1 = MakeGarbageCollected<HTMLImageElement>(GetDocument());
  image1->setAttribute(html_names::kIdAttr, AtomicString("image1"));
  GetDocument().body()->AppendChild(image1);
  SetImageAndPaint("image1", 5, 5);

  auto* image2 = MakeGarbageCollected<HTMLImageElement>(GetDocument());
  image2->setAttribute(html_names::kIdAttr, AtomicString("image2"));
  GetDocument().body()->AppendChild(image2);
  SetImageAndPaint("image2", 5, 5);

  auto* image3 = MakeGarbageCollected<HTMLImageElement>(GetDocument());
  image3->setAttribute(html_names::kIdAttr, AtomicString("image3"));
  GetDocument().body()->AppendChild(image3);
  SetImageAndPaint("image3", 5, 5);

  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();

  EXPECT_EQ(LargestImage()->node_id, DOMNodeIds::ExistingIdForNode(image1));
  EXPECT_EQ(LargestPaintSize(), 25ul);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_TraceEvent_Candidate) {
  using trace_analyzer::Query;
  trace_analyzer::Start("loading");
  {
    SetBodyInnerHTML(R"HTML(
      <img id="target"></img>
    )HTML");
    SetImageAndPaint("target", 5, 5);
    UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  }
  auto analyzer = trace_analyzer::Stop();
  trace_analyzer::TraceEventVector events;
  Query q = Query::EventNameIs("LargestImagePaint::Candidate");
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(1u, events.size());
  EXPECT_EQ("loading", events[0]->category);

  EXPECT_TRUE(events[0]->HasStringArg("frame"));

  ASSERT_TRUE(events[0]->HasDictArg("data"));
  base::Value::Dict arg_dict = events[0]->GetKnownArgAsDict("data");
  EXPECT_GT(arg_dict.FindInt("DOMNodeId").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("size").value_or(-1), 0);
  EXPECT_EQ(arg_dict.FindInt("candidateIndex").value_or(-1), 1);
  std::optional<bool> isMainFrame = arg_dict.FindBool("isMainFrame");
  EXPECT_TRUE(isMainFrame.has_value());
  EXPECT_EQ(true, isMainFrame.value());
  std::optional<bool> is_outermost_main_frame =
      arg_dict.FindBool("isOutermostMainFrame");
  EXPECT_TRUE(is_outermost_main_frame.has_value());
  EXPECT_EQ(true, is_outermost_main_frame.value());
  std::optional<bool> is_embedded_frame = arg_dict.FindBool("isEmbeddedFrame");
  EXPECT_TRUE(is_embedded_frame.has_value());
  EXPECT_EQ(false, is_embedded_frame.value());
  EXPECT_EQ(arg_dict.FindInt("frame_x").value_or(-1), 8);
  EXPECT_EQ(arg_dict.FindInt("frame_y").value_or(-1), 8);
  EXPECT_EQ(arg_dict.FindInt("frame_width").value_or(-1), 5);
  EXPECT_EQ(arg_dict.FindInt("frame_height").value_or(-1), 5);
  EXPECT_EQ(arg_dict.FindInt("root_x").value_or(-1), 8);
  EXPECT_EQ(arg_dict.FindInt("root_y").value_or(-1), 8);
  EXPECT_EQ(arg_dict.FindInt("root_width").value_or(-1), 5);
  EXPECT_EQ(arg_dict.FindInt("root_height").value_or(-1), 5);
}

TEST_P(ImagePaintTimingDetectorTest,
       LargestImagePaint_TraceEvent_Candidate_Frame) {
  using trace_analyzer::Query;
  trace_analyzer::Start("loading");
  {
    GetDocument().SetBaseURLOverride(KURL("http://test.com"));
    SetBodyInnerHTML(R"HTML(
      <style>iframe { display: block; position: relative; margin-left: 30px; margin-top: 50px; width: 250px; height: 250px;} </style>
      <iframe> </iframe>
    )HTML");
    SetChildBodyInnerHTML(R"HTML(
    <style>body { margin: 10px;} #target { width: 200px; height: 200px; }
    </style>
    <img id="target"></img>
  )HTML");
    SetChildFrameImageAndPaint("target", 5, 5);
    UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
    InvokeChildFrameCallback();
  }
  auto analyzer = trace_analyzer::Stop();
  trace_analyzer::TraceEventVector events;
  Query q = Query::EventNameIs("LargestImagePaint::Candidate");
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(1u, events.size());
  EXPECT_EQ("loading", events[0]->category);

  EXPECT_TRUE(events[0]->HasStringArg("frame"));

  ASSERT_TRUE(events[0]->HasDictArg("data"));
  base::Value::Dict arg_dict = events[0]->GetKnownArgAsDict("data");
  EXPECT_GT(arg_dict.FindInt("DOMNodeId").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("size").value_or(-1), 0);
  EXPECT_EQ(arg_dict.FindInt("candidateIndex").value_or(-1), 1);
  std::optional<bool> isMainFrame = arg_dict.FindBool("isMainFrame");
  EXPECT_TRUE(isMainFrame.has_value());
  EXPECT_EQ(false, isMainFrame.value());
  std::optional<bool> is_outermost_main_frame =
      arg_dict.FindBool("isOutermostMainFrame");
  EXPECT_TRUE(is_outermost_main_frame.has_value());
  EXPECT_EQ(false, is_outermost_main_frame.value());
  std::optional<bool> is_embedded_frame = arg_dict.FindBool("isEmbeddedFrame");
  EXPECT_TRUE(is_embedded_frame.has_value());
  EXPECT_EQ(false, is_embedded_frame.value());
  EXPECT_EQ(arg_dict.FindInt("frame_x").value_or(-1), 10);
  EXPECT_EQ(arg_dict.FindInt("frame_y").value_or(-1), 10);
  EXPECT_EQ(arg_dict.FindInt("frame_width").value_or(-1), 200);
  EXPECT_EQ(arg_dict.FindInt("frame_height").value_or(-1), 200);
  EXPECT_GT(arg_dict.FindInt("root_x").value_or(-1), 40);
  EXPECT_GT(arg_dict.FindInt("root_y").value_or(-1), 60);
  EXPECT_EQ(arg_dict.FindInt("root_width").value_or(-1), 200);
  EXPECT_EQ(arg_dict.FindInt("root_height").value_or(-1), 200);
}

TEST_P(ImagePaintTimingDetectorTest, UpdatePerformanceTiming) {
  LargestContentfulPaintDetailsForReporting largest_contentful_paint_details =
      GetPerformanceTimingForReporting()
          .LargestContentfulPaintDetailsForMetrics();
  EXPECT_EQ(largest_contentful_paint_details.image_paint_size, 0u);
  EXPECT_EQ(largest_contentful_paint_details.image_paint_time, 0u);
  SetBodyInnerHTML(R"HTML(
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  largest_contentful_paint_details =
      GetPerformanceTimingForReporting()
          .LargestContentfulPaintDetailsForMetrics();
  EXPECT_EQ(largest_contentful_paint_details.image_paint_size, 25u);
  EXPECT_GT(largest_contentful_paint_details.image_paint_time, 0u);
}

TEST_P(ImagePaintTimingDetectorTest, UpdatePerformanceTimingToZero) {
  SetBodyInnerHTML(R"HTML(
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  auto largest_contentful_paint_details =
      GetPerformanceTimingForReporting()
          .LargestContentfulPaintDetailsForMetrics();
  EXPECT_EQ(largest_contentful_paint_details.image_paint_size, 25u);
  EXPECT_GT(largest_contentful_paint_details.image_paint_time, 0u);
  GetDocument().body()->RemoveChild(
      GetDocument().getElementById(AtomicString("target")));
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(largest_contentful_paint_details.image_paint_size, 25u);
  EXPECT_GT(largest_contentful_paint_details.image_paint_time, 0u);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_OpacityZero) {
  SetBodyInnerHTML(R"HTML(
    <style>
    img {
      opacity: 0;
    }
    </style>
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(CountImageRecords(), 0u);
  ImageRecord* record = LargestImage();
  EXPECT_FALSE(record);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_VisibilityHidden) {
  SetBodyInnerHTML(R"HTML(
    <style>
    img {
      visibility: hidden;
    }
    </style>
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(CountImageRecords(), 0u);
  ImageRecord* record = LargestImage();
  EXPECT_FALSE(record);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_DisplayNone) {
  SetBodyInnerHTML(R"HTML(
    <style>
    img {
      display: none;
    }
    </style>
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(CountImageRecords(), 0u);
  ImageRecord* record = LargestImage();
  EXPECT_FALSE(record);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_OpacityNonZero) {
  SetBodyInnerHTML(R"HTML(
    <style>
    img {
      opacity: 0.01;
    }
    </style>
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(CountImageRecords(), 1u);
  ImageRecord* record = LargestImage();
  EXPECT_TRUE(record);
}

TEST_P(ImagePaintTimingDetectorTest,
       IgnoreImageUntilInvalidatedRectSizeNonZero) {
  SetBodyInnerHTML(R"HTML(
    <img id="target"></img>
  )HTML");
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(CountImageRecords(), 0u);
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_EQ(CountImageRecords(), 1u);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_Largest) {
  SetBodyInnerHTML(R"HTML(
    <style>img { display:block }</style>
    <img id="smaller"></img>
    <img id="medium"></img>
    <img id="larger"></img>
  )HTML");
  SetImageAndPaint("smaller", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record;
  record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_EQ(record->recorded_size, 25ul);

  SetImageAndPaint("larger", 9, 9);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(LargestPaintSize(), 81ul);
}

TEST_P(ImagePaintTimingDetectorTest,
       LargestImagePaint_IgnoreThoseOutsideViewport) {
  SetBodyInnerHTML(R"HTML(
    <style>
      img {
        position: fixed;
        top: -100px;
      }
    </style>
    <img id="target"></img>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record = LargestImage();
  EXPECT_FALSE(record);
}

TEST_P(ImagePaintTimingDetectorTest,
       LargestImagePaint_UpdateOnRemovingTheLastImage) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <img id="target"></img>
    </div>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record;
  record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_NE(LargestPaintTime(), base::TimeTicks());
  EXPECT_EQ(LargestPaintSize(), 25ul);

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("target")));
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_NE(LargestPaintTime(), base::TimeTicks());
  EXPECT_EQ(LargestPaintSize(), 25u);
}

TEST_P(ImagePaintTimingDetectorTest, LargestImagePaint_UpdateOnRemoving) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <img id="target1"></img>
      <img id="target2"></img>
    </div>
  )HTML");
  SetImageAndPaint("target1", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record1 = LargestImage();
  EXPECT_TRUE(record1);
  EXPECT_NE(LargestPaintTime(), base::TimeTicks());
  base::TimeTicks first_largest_image_paint = LargestPaintTime();

  SetImageAndPaint("target2", 10, 10);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record2 = LargestImage();
  EXPECT_TRUE(record2);
  EXPECT_NE(LargestPaintTime(), base::TimeTicks());
  base::TimeTicks second_largest_image_paint = LargestPaintTime();

  EXPECT_NE(record1, record2);
  EXPECT_NE(first_largest_image_paint, second_largest_image_paint);

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("target2")));
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record3 = LargestImage();
  EXPECT_EQ(record2, record3);
  EXPECT_EQ(second_largest_image_paint, LargestPaintTime());
  EXPECT_EQ(LargestPaintSize(), 100u);
}

TEST_P(ImagePaintTimingDetectorTest,
       LargestImagePaint_NodeRemovedBetweenRegistrationAndInvocation) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <img id="target"></img>
    </div>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhases();

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("target")));

  InvokeCallback();

  ImageRecord* record;
  record = LargestImage();
  EXPECT_FALSE(record);
}

TEST_P(ImagePaintTimingDetectorTest,
       RemoveRecordFromAllContainersAfterImageRemoval) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <img id="target"></img>
    </div>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(ContainerTotalSize(), 2u);

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("target")));
  EXPECT_EQ(ContainerTotalSize(), 0u);
}

TEST_P(ImagePaintTimingDetectorTest,
       RemoveRecordFromAllContainersAfterInvisibleImageRemoved) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        position: relative;
        left: 100px;
      }
      #parent {
        background-color: yellow;
        height: 50px;
        width: 50px;
        overflow: scroll;
      }
    </style>
    <div id='parent'>
      <img id='target'></img>
    </div>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  // The out-of-viewport image will not have been recorded yet.
  EXPECT_EQ(ContainerTotalSize(), 1u);

  GetDocument().body()->RemoveChild(
      GetDocument().getElementById(AtomicString("parent")));
  EXPECT_EQ(ContainerTotalSize(), 0u);
}

TEST_P(ImagePaintTimingDetectorTest,
       RemoveRecordFromAllContainersAfterBackgroundImageRemoval) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        background-image: url()HTML" SIMPLE_IMAGE R"HTML();
      }
    </style>
    <div id="parent">
      <div id="target">
        place-holder
      </div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  EXPECT_EQ(ContainerTotalSize(), 2u);

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("target")));
  EXPECT_EQ(ContainerTotalSize(), 0u);
}

TEST_P(ImagePaintTimingDetectorTest,
       RemoveRecordFromAllContainersAfterImageRemovedAndCallbackInvoked) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <img id="target"></img>
    </div>
  )HTML");
  SetImageAndPaint("target", 5, 5);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(ContainerTotalSize(), 4u);

  GetDocument()
      .getElementById(AtomicString("parent"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("target")));
  // Lazy deletion from |images_queued_for_paint_time_|.
  EXPECT_EQ(ContainerTotalSize(), 1u);
  InvokeCallback();
  EXPECT_EQ(ContainerTotalSize(), 0u);
}

TEST_P(ImagePaintTimingDetectorTest,
       LargestImagePaint_ReattachedNodeNotTreatedAsNew) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
    </div>
  )HTML");
  auto* image = MakeGarbageCollected<HTMLImageElement>(GetDocument());
  image->setAttribute(html_names::kIdAttr, AtomicString("target"));
  GetDocument().getElementById(AtomicString("parent"))->AppendChild(image);
  SetImageAndPaint("target", 5, 5);
  test_task_runner_->FastForwardBy(base::Seconds(1));
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  ImageRecord* record;
  record = LargestImage();
  EXPECT_TRUE(record);
  // UpdateAllLifecyclePhasesAndInvokeCallbackIfAny() moves time forward
  // kQuantumOfTime so we should take that into account.
  EXPECT_EQ(record->paint_time,
            base::TimeTicks() + base::Seconds(1) + kQuantumOfTime);

  GetDocument().getElementById(AtomicString("parent"))->RemoveChild(image);
  test_task_runner_->FastForwardBy(base::Seconds(1));
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_EQ(record->paint_time,
            base::TimeTicks() + base::Seconds(1) + kQuantumOfTime);

  GetDocument().getElementById(AtomicString("parent"))->AppendChild(image);
  SetImageAndPaint("target", 5, 5);
  test_task_runner_->FastForwardBy(base::Seconds(1));
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_EQ(record->paint_time,
            base::TimeTicks() + base::Seconds(1) + kQuantumOfTime);
}

// This is to prove that a presentation time is assigned only to nodes of the
// frame who register the presentation time. In other words, presentation time A
// should match frame A; presentation time B should match frame B.
TEST_P(ImagePaintTimingDetectorTest,
       MatchPresentationTimeToNodesOfDifferentFrames) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <img height="5" width="5" id="smaller"></img>
      <img height="9" width="9" id="larger"></img>
    </div>
  )HTML");

  SetImageAndPaint("smaller", 5, 5);
  UpdateAllLifecyclePhases();
  SimulatePassOfTime();
  SetImageAndPaint("larger", 9, 9);
  UpdateAllLifecyclePhases();
  SimulatePassOfTime();
  InvokeCallback();
  // record1 is the smaller.
  ImageRecord* record1 = LargestPaintedImage();
  DCHECK_EQ(record1->recorded_size, 25ul);
  const base::TimeTicks record1Time = record1->paint_time;
  UpdateAllLifecyclePhases();
  SimulatePassOfTime();
  InvokeCallback();
  // record2 is the larger.
  ImageRecord* record2 = LargestPaintedImage();
  DCHECK_EQ(record2->recorded_size, 81ul);
  EXPECT_NE(record1Time, record2->paint_time);
}

TEST_P(ImagePaintTimingDetectorTest,
       LargestImagePaint_UpdateResultWhenLargestChanged) {
  base::TimeTicks time1 = test_task_runner_->NowTicks();
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <img id="target1"></img>
      <img id="target2"></img>
    </div>
  )HTML");
  SetImageAndPaint("target1", 5, 5);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  base::TimeTicks time2 = test_task_runner_->NowTicks();
  base::TimeTicks result1 = LargestPaintTime();
  EXPECT_GE(result1, time1);
  EXPECT_GE(time2, result1);

  SetImageAndPaint("target2", 10, 10);
  UpdateAllLifecyclePhasesAndInvokeCallbackIfAny();
  base::TimeTicks time3 = test_task_runner_->NowTicks();
  base::TimeTicks result2 = LargestPaintTime();
  EXPECT_GE(result2, time2);
  EXPECT_GE(time3, result2);
}

TEST_P(ImagePaintTimingDetectorTest, OnePresentationPromiseForOneFrame) {
  SetBodyInnerHTML(R"HTML(
    <style>img { display:block }</style>
    <div id="parent">
      <img id="1"></img>
      <img id="2"></img>
    </div>
  )HTML");
  SetImageAndPaint("1", 5, 5);
  UpdateAllLifecyclePhases();
  SimulatePassOfTime();

  SetImageAndPaint("2", 9, 9);
  UpdateAllLifecyclePhases();
  SimulatePassOfTime();

  // This callback only assigns a time to the 5x5 image.
  InvokeCallback();
  ImageRecord* record;
  record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_EQ(record->recorded_size, 81ul);
  EXPECT_TRUE(record->paint_time.is_null());

  // This callback assigns a time to the 9x9 image.
  InvokeCallback();
  record = LargestImage();
  EXPECT_TRUE(record);
  EXPECT_EQ(record->recorded_size, 81ul);
  EXPECT_FALSE(record->paint_time.is_null());
}

TEST_P(ImagePaintTimingDetectorTest, VideoImage)
```