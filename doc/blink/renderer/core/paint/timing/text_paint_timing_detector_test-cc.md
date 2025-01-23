Response:
My thinking process to analyze the C++ test file went through these stages:

1. **Identify the Core Class Under Test:** The filename `text_paint_timing_detector_test.cc` and the included header `#include "third_party/blink/renderer/core/paint/timing/text_paint_timing_detector.h"` immediately tell me the primary focus is the `TextPaintTimingDetector` class. The "test" suffix indicates this file contains unit tests for that class.

2. **Understand the Purpose of the Tested Class:**  The name `TextPaintTimingDetector` strongly suggests it's responsible for detecting and recording timing information related to text rendering within the Blink engine. The "paint timing" part points to its involvement in performance metrics related to when text becomes visible on the screen.

3. **Analyze the Test Structure:** I looked at the test fixture `TextPaintTimingDetectorTest`. Common setup patterns in C++ unit tests include:
    * **Setup (`SetUp`)**:  Initializes the environment required for testing. In this case, it sets up a mock web view, enables compositing, loads a blank page, and advances the clock. This suggests the tests interact with a simulated browser environment.
    * **Helper Methods**: The class includes numerous helper methods like `GetFrameView`, `GetPaintTimingDetector`, `SetBodyInnerHTML`, `AppendDivElementToBody`, etc. These methods abstract away the complexities of creating and manipulating DOM elements and the rendering pipeline within the tests, making the tests more readable and focused.
    * **Individual Tests (`TEST_F`)**: Each `TEST_F` macro defines an individual test case for specific scenarios related to text paint timing.

4. **Examine Individual Test Cases:** I scanned through the names of the test cases to get a sense of the functionalities being tested. Keywords like "LargestTextPaint," "Opacity," "Removed," "Clipped," "Iframe," "UserInput," and "SVGText" provided clues. I also looked at the code within some of these test cases to understand the specific assertions being made. For example, `EXPECT_FALSE(TextRecordOfLargestTextPaint())` suggests verifying that no largest text was detected under certain conditions.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** Based on the setup (loading HTML, manipulating DOM elements), the test cases clearly involve the interaction of HTML and CSS. JavaScript, while not directly manipulated in *this* test file, is implicitly involved because Blink is a rendering engine for web content, which includes executing JavaScript. The tests simulate scenarios that a web browser would encounter when rendering web pages.

6. **Infer Logic and Identify Assumptions:** I deduced the logic being tested by observing the actions performed in the tests and the assertions made. For instance, tests involving "LargestTextPaint" imply the `TextPaintTimingDetector` has logic to determine the "largest" text element based on its rendered size. The "Opacity" tests suggest the detector considers element visibility. Tests with iframes show the detector's ability to handle nested browsing contexts.

7. **Consider Potential User Errors and Debugging:**  By understanding the purpose of the `TextPaintTimingDetector`, I could infer potential user errors that could lead to the code being executed. For example, a user creating a very large text element or hiding text with CSS might trigger the logic being tested. The setup involving `frame_test_helpers` suggests that developers use this kind of test setup for debugging rendering-related issues within Blink.

8. **Synthesize the Information:** I organized my findings into the requested categories:

    * **Functionality:**  Summarized the core responsibility of the `TextPaintTimingDetector` and its key features based on the tests.
    * **Relationship to Web Technologies:**  Explicitly linked the tests to HTML, CSS, and the implicit role of JavaScript. Provided concrete examples from the test code.
    * **Logic and I/O:**  Presented illustrative "if-then" scenarios based on the test cases, demonstrating the input and expected output of the detector's logic.
    * **User/Programming Errors:**  Described common web development mistakes that could interact with the `TextPaintTimingDetector`.
    * **User Operations and Debugging:**  Explained how user interactions in a web browser eventually lead to the execution of this code within the rendering pipeline and how developers use these tests for debugging.

By following these steps, I was able to analyze the C++ test file and extract the relevant information to answer the prompt comprehensively. The key was to leverage the information within the code itself (class names, method names, test names, assertions) to understand the underlying functionality and its connections to web technologies and potential user scenarios.
这个文件 `text_paint_timing_detector_test.cc` 是 Chromium Blink 引擎中的一个 C++ 单元测试文件，专门用于测试 `TextPaintTimingDetector` 类的功能。 `TextPaintTimingDetector` 的主要职责是**检测页面中首次绘制出的可见文本，并记录其绘制时间**，这对于衡量用户感知的页面加载速度非常重要。

以下是该文件测试的主要功能点以及它们与 JavaScript、HTML 和 CSS 的关系，以及一些逻辑推理、用户错误和调试线索的说明：

**功能列举:**

* **检测最大的文本绘制 (Largest Text Paint - LCP):**  这是该检测器的核心功能。测试用例涵盖了各种场景，以验证能够正确识别页面中首次渲染的最大的文本元素。
* **处理不同的文本元素:**  测试用例包含了对不同 HTML 元素（如 `<div>`, `<span>`, `<p>`, `<h1>` 等）内文本的检测。
* **考虑 CSS 样式的影响:** 测试用例验证了 `TextPaintTimingDetector` 能否正确处理 CSS 样式对文本可见性和大小的影响，例如：
    * `font-size` 的变化。
    * `opacity: 0` 导致的文本不可见。
    * 文本是否在视口内 (`position: fixed`, `top: -100px` 等)。
    * 包含溢出隐藏 (`overflow: hidden`) 的父元素。
    * `text-overflow: ellipsis` 生成的省略号。
* **处理 DOM 节点的添加和移除:** 测试用例验证了在 DOM 节点动态添加或移除时，检测器能否正确更新其记录。
* **处理用户交互的影响:** 测试用例模拟了用户输入 (例如 `mousedown`) 和滚动事件，验证这些交互是否会影响 LCP 的检测和记录。通常，首次内容绘制 (FCP) 和 LCP 在用户首次交互后会停止记录。
* **处理 iframe 中的文本:** 测试用例验证了在嵌入的 `<iframe>` 中，检测器能否正确识别和记录文本绘制时间。
* **处理 SVG 文本:** 测试用例验证了对 SVG `<text>` 元素的检测能力。
* **记录绘制时间:** 测试用例验证了能够正确记录首次绘制的时间点。
* **性能追踪 (Trace Events):**  测试用例验证了在检测到候选的 LCP 文本时，会发出相应的性能追踪事件。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  HTML 定义了页面的结构和内容，包括文本元素。测试用例通过 `SetBodyInnerHTML` 方法加载不同的 HTML 结构，例如：
    ```c++
    SetBodyInnerHTML(R"HTML(
      <div>The only text</div>
    )HTML");
    ```
    这模拟了在 HTML 中添加一个包含文本的 `<div>` 元素。
* **CSS:** CSS 负责控制文本的样式和布局。测试用例使用 CSS 来影响文本的可见性和大小，例如：
    ```c++
    SetElementStyle(text, "font-size: 200px"); // 使用 CSS 设置字体大小
    ```
    以及测试 `opacity: 0` 的场景：
    ```c++
    SetBodyInnerHTML(R"HTML(
      <style>
      div {
        opacity: 0;
      }
      </style>
    )HTML");
    ```
* **JavaScript:** 虽然这个测试文件本身没有直接执行 JavaScript 代码，但 `TextPaintTimingDetector` 的最终目的是为了提供性能指标，这些指标通常会被 JavaScript API (例如 Performance API) 暴露出来，供开发者使用。此外，JavaScript 的动态 DOM 操作（例如通过 `document.createElement` 和 `appendChild` 添加元素）会触发 `TextPaintTimingDetector` 的逻辑。测试用例中的 `AppendDivElementToBody` 等方法模拟了这种动态添加行为。

**逻辑推理及假设输入与输出:**

假设我们有以下 HTML 片段：

```html
<div>Small text</div>
<div style="font-size: 24px;">Large text</div>
```

**假设输入:**  上述 HTML 代码被加载到浏览器中。

**逻辑推理:** `TextPaintTimingDetector` 会遍历渲染树，计算每个可见文本元素的渲染大小。由于 "Large text" 的 `font-size` 更大，其渲染后的像素面积可能会更大。

**预期输出:**  `TextPaintTimingDetector` 应该将包含 "Large text" 的 `<div>` 元素识别为 Largest Text Paint 的候选元素，并记录其首次绘制的时间。  相关的测试用例可能会断言 `TextRecordOfLargestTextPaint()->node_` 指向该 `<div>` 元素。

**用户或编程常见的使用错误及举例说明:**

* **错误地认为隐藏的文本会被计入 LCP:** 用户可能会认为通过 `display: none` 或 `visibility: hidden` 隐藏的文本也应该被计入 LCP。`TextPaintTimingDetector` 的设计目标是检测 *可见* 的文本，因此这些隐藏的文本不会被计入。相关的测试用例（如测试 `opacity: 0` 的用例）验证了这一点。
* **在用户交互后仍然期望 LCP 更新:** 用户可能会错误地认为在页面加载完成后，即使发生了用户交互（例如点击、滚动），LCP 的值仍然会更新。实际上，LCP 的计算通常在首次用户交互后停止。相关的测试用例模拟了用户输入和滚动事件来验证这一点。
* **动态添加文本后期望立即更新 LCP:**  用户可能会在 JavaScript 中动态添加大量文本，并期望 LCP 的值立即反映出来。实际上，LCP 的更新发生在浏览器的渲染过程中。测试用例通过模拟 DOM 操作来验证这种场景。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器地址栏输入网址或点击链接:** 这是用户发起页面加载的起点。
2. **浏览器发起网络请求，下载 HTML 资源:** 浏览器开始获取页面的 HTML 内容。
3. **浏览器解析 HTML，构建 DOM 树:**  浏览器解析下载的 HTML，生成文档对象模型 (DOM) 树。
4. **浏览器解析 CSS，构建 CSSOM 树:** 浏览器解析 CSS 样式，构建 CSS 对象模型 (CSSOM) 树。
5. **浏览器将 DOM 树和 CSSOM 树合并，构建渲染树:** 渲染树包含了所有需要渲染的可见元素及其样式信息。
6. **布局 (Layout/Reflow):** 浏览器计算渲染树中每个元素的几何属性（位置、大小等）。
7. **绘制 (Paint):** 浏览器将渲染树中的元素绘制到屏幕上的位图。在这个阶段，`TextPaintTimingDetector` 会检测首次绘制的文本元素。
8. **合成 (Compositing):** 如果使用了硬件加速，浏览器会将不同的图层合成为最终的屏幕图像。

作为调试线索，如果开发者怀疑 LCP 的计算有问题，他们可能会：

* **检查页面的 HTML 结构:**  确认是否有大量的文本内容在首屏渲染。
* **审查 CSS 样式:**  查看是否有样式影响了文本的可见性或渲染。
* **使用浏览器的开发者工具 (Performance 面板):**  查看 "Largest Contentful Paint" 指标，并分析渲染过程中的 "Paint" 事件。
* **运行类似此测试文件中的单元测试:**  Blink 的开发者可以使用这些测试用例来验证 `TextPaintTimingDetector` 在特定场景下的行为是否符合预期。
* **设置断点:**  在 `text_paint_timing_detector.cc` 文件中的相关代码处设置断点，例如在 `LargestTextPaintManager::UpdateMetricsCandidate()` 或 `TextPaintTimingDetector::Record()` 等方法中，来追踪代码的执行流程和变量值。

总而言之，`text_paint_timing_detector_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎能够准确地检测和报告 Largest Text Paint 指标，这对于提升用户体验和优化网页性能至关重要。 它涵盖了各种与 HTML、CSS 相关的场景，并考虑了用户交互和 DOM 操作的影响。

### 提示词
```
这是目录为blink/renderer/core/paint/timing/text_paint_timing_detector_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/paint/timing/text_paint_timing_detector.h"

#include "base/test/test_mock_time_task_runner.h"
#include "base/test/trace_event_analyzer.h"
#include "base/time/time.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_detector.h"
#include "third_party/blink/renderer/core/paint/timing/paint_timing_test_helper.h"
#include "third_party/blink/renderer/core/svg/svg_text_content_element.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/platform/testing/runtime_enabled_features_test_helpers.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {

class TextPaintTimingDetectorTest : public testing::Test {
 public:
  TextPaintTimingDetectorTest()
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
    // Advance clock so it isn't 0 as rendering code asserts in that case.
    AdvanceClock(base::Microseconds(1));
  }

 protected:
  LocalFrameView& GetFrameView() { return *GetFrame()->View(); }
  PaintTimingDetector& GetPaintTimingDetector() {
    return GetFrameView().GetPaintTimingDetector();
  }
  Document& GetDocument() { return *GetFrame()->GetDocument(); }

  gfx::Rect GetViewportRect(LocalFrameView& view) {
    ScrollableArea* scrollable_area = view.GetScrollableArea();
    DCHECK(scrollable_area);
    return scrollable_area->VisibleContentRect();
  }

  LocalFrameView& GetChildFrameView() {
    return *To<LocalFrame>(GetFrame()->Tree().FirstChild())->View();
  }
  Document* GetChildDocument() {
    return To<LocalFrame>(GetFrame()->Tree().FirstChild())->GetDocument();
  }

  TextPaintTimingDetector* GetTextPaintTimingDetector() {
    return &GetPaintTimingDetector().GetTextPaintTimingDetector();
  }

  TextPaintTimingDetector& GetChildFrameTextPaintTimingDetector() {
    return GetChildFrameView()
        .GetPaintTimingDetector()
        .GetTextPaintTimingDetector();
  }

  LargestTextPaintManager& GetLargestTextPaintManager() {
    return *GetTextPaintTimingDetector()->ltp_manager_;
  }

  wtf_size_t CountRecordedSize() {
    DCHECK(GetTextPaintTimingDetector());
    return GetTextPaintTimingDetector()->recorded_set_.size();
  }

  wtf_size_t TextQueuedForPaintTimeSize(const LocalFrameView& view) {
    return view.GetPaintTimingDetector()
        .GetTextPaintTimingDetector()
        .texts_queued_for_paint_time_.size();
  }

  wtf_size_t ContainerTotalSize() {
    return CountRecordedSize() + TextQueuedForPaintTimeSize(GetFrameView());
  }

  void SimulateInputEvent() {
    GetPaintTimingDetector().NotifyInputEvent(WebInputEvent::Type::kMouseDown);
  }

  void SimulateScroll() {
    GetPaintTimingDetector().NotifyScroll(mojom::blink::ScrollType::kUser);
  }

  void SimulateKeyUp() {
    GetPaintTimingDetector().NotifyInputEvent(WebInputEvent::Type::kKeyUp);
  }

  void InvokeCallback() {
    DCHECK_GT(mock_callback_manager_->CountCallbacks(), 0u);
    InvokePresentationTimeCallback(mock_callback_manager_);
    // Outside the tests, this is invoked by
    // |PaintTimingCallbackManagerImpl::ReportPaintTime|.
    GetLargestTextPaintManager().UpdateMetricsCandidate();
  }

  void ChildFramePresentationTimeCallBack() {
    DCHECK_GT(child_frame_mock_callback_manager_->CountCallbacks(), 0u);
    InvokePresentationTimeCallback(child_frame_mock_callback_manager_);
    // Outside the tests, this is invoked by
    // |PaintTimingCallbackManagerImpl::ReportPaintTime|.
    GetChildFrameTextPaintTimingDetector().UpdateMetricsCandidate();
  }

  void InvokePresentationTimeCallback(
      MockPaintTimingCallbackManager* callback_manager) {
    callback_manager->InvokePresentationTimeCallback(
        test_task_runner_->NowTicks());
  }

  base::TimeTicks LargestPaintTime() {
    return GetPaintTimingDetector()
        .LatestLcpDetailsForTest()
        .largest_text_paint_time;
  }

  uint64_t LargestPaintSize() {
    return GetPaintTimingDetector()
        .LatestLcpDetailsForTest()
        .largest_text_paint_size;
  }

  void SetBodyInnerHTML(const std::string& content) {
    frame_test_helpers::LoadHTMLString(
        web_view_helper_.GetWebView()->MainFrameImpl(), content,
        KURL("http://test.com"));
    mock_callback_manager_ =
        MakeGarbageCollected<MockPaintTimingCallbackManager>();
    GetTextPaintTimingDetector()->ResetCallbackManager(mock_callback_manager_);
    UpdateAllLifecyclePhases();
  }

  void SetChildBodyInnerHTML(const String& content) {
    GetChildDocument()->SetBaseURLOverride(KURL("http://test.com"));
    GetChildDocument()->body()->setInnerHTML(content, ASSERT_NO_EXCEPTION);
    child_frame_mock_callback_manager_ =
        MakeGarbageCollected<MockPaintTimingCallbackManager>();
    GetChildFrameTextPaintTimingDetector().ResetCallbackManager(
        child_frame_mock_callback_manager_);
    UpdateAllLifecyclePhases();
  }

  void UpdateAllLifecyclePhases() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  static constexpr base::TimeDelta kQuantumOfTime = base::Milliseconds(10);

  // This only triggers ReportPresentationTime in main frame.
  void UpdateAllLifecyclePhasesAndSimulatePresentationTime() {
    UpdateAllLifecyclePhases();
    // Advance the clock for a bit so different presentation callbacks get
    // different times.
    AdvanceClock(kQuantumOfTime);
    while (mock_callback_manager_->CountCallbacks() > 0)
      InvokeCallback();
  }

  void SimulatePresentationTime() {
    AdvanceClock(kQuantumOfTime);
    while (mock_callback_manager_->CountCallbacks() > 0)
      InvokeCallback();
  }

  void CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(
      wtf_size_t size) {
    UpdateAllLifecyclePhases();
    EXPECT_EQ(TextQueuedForPaintTimeSize(GetFrameView()), size);
    SimulatePresentationTime();
  }

  Element* AppendFontBlockToBody(String content) {
    Element* font = GetDocument().CreateRawElement(html_names::kFontTag);
    font->setAttribute(html_names::kSizeAttr, AtomicString("5"));
    Text* text = GetDocument().createTextNode(content);
    font->AppendChild(text);
    Element* div = GetDocument().CreateRawElement(html_names::kDivTag);
    div->AppendChild(font);
    GetDocument().body()->AppendChild(div);
    return font;
  }

  Element* AppendDivElementToBody(String content, String style = "") {
    Element* div = GetDocument().CreateRawElement(html_names::kDivTag);
    div->setAttribute(html_names::kStyleAttr, AtomicString(style));
    Text* text = GetDocument().createTextNode(content);
    div->AppendChild(text);
    GetDocument().body()->AppendChild(div);
    return div;
  }

  TextRecord* TextRecordOfLargestTextPaint() {
    return GetLargestTextPaintManager().LargestText();
  }

  TextRecord* ChildFrameTextRecordOfLargestTextPaint() {
    return GetChildFrameView()
        .GetPaintTimingDetector()
        .GetTextPaintTimingDetector()
        .ltp_manager_->LargestText();
  }

  void SetFontSize(Element* font_element, uint16_t font_size) {
    DCHECK_EQ(font_element->nodeName(), "FONT");
    font_element->setAttribute(html_names::kSizeAttr,
                               AtomicString(WTF::String::Number(font_size)));
  }

  void SetElementStyle(Element* element, String style) {
    element->setAttribute(html_names::kStyleAttr, AtomicString(style));
  }

  void RemoveElement(Element* element) {
    element->GetLayoutObject()->Parent()->GetNode()->removeChild(element);
  }

  base::TimeTicks NowTicks() const { return test_task_runner_->NowTicks(); }

  void AdvanceClock(base::TimeDelta delta) {
    test_task_runner_->FastForwardBy(delta);
  }

  void LoadAhem() { web_view_helper_.LoadAhem(); }

 private:
  LocalFrame* GetFrame() {
    return web_view_helper_.GetWebView()->MainFrameImpl()->GetFrame();
  }

  test::TaskEnvironment task_environment_;
  frame_test_helpers::WebViewHelper web_view_helper_;
  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;
  Persistent<MockPaintTimingCallbackManager> mock_callback_manager_;
  Persistent<MockPaintTimingCallbackManager> child_frame_mock_callback_manager_;
};

constexpr base::TimeDelta TextPaintTimingDetectorTest::kQuantumOfTime;

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_NoText) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_FALSE(TextRecordOfLargestTextPaint());
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_OneText) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* only_text = AppendDivElementToBody("The only text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, only_text);
}

TEST_F(TextPaintTimingDetectorTest, LaterSameSizeCandidate) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* first = AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  AppendDivElementToBody("text");
  AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, first);
}

TEST_F(TextPaintTimingDetectorTest,
       LargestTextPaint_FontSizeChange_MultipleUpdates) {
  SetBodyInnerHTML(R"HTML()HTML");
  Element* text = AppendDivElementToBody("text");
  SetElementStyle(text, "font-size: 200px");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  SetElementStyle(text, "font-size: 300px");
  CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(0u);
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_TraceEvent_Candidate) {
  using trace_analyzer::Query;
  trace_analyzer::Start("loading");
  {
    SetBodyInnerHTML(R"HTML(
      )HTML");
    AppendDivElementToBody("The only text");
    UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  }
  auto analyzer = trace_analyzer::Stop();
  trace_analyzer::TraceEventVector events;
  Query q = Query::EventNameIs("LargestTextPaint::Candidate");
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(1u, events.size());
  EXPECT_EQ("loading", events[0]->category);

  EXPECT_TRUE(events[0]->HasStringArg("frame"));

  ASSERT_TRUE(events[0]->HasDictArg("data"));
  base::Value::Dict arg_dict = events[0]->GetKnownArgAsDict("data");
  EXPECT_GT(arg_dict.FindInt("DOMNodeId").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("size").value_or(-1), 0);
  EXPECT_EQ(arg_dict.FindInt("candidateIndex").value_or(-1), 1);
  std::optional<bool> is_main_frame = arg_dict.FindBool("isMainFrame");
  EXPECT_TRUE(is_main_frame.has_value());
  EXPECT_EQ(true, is_main_frame.value());
  std::optional<bool> is_outermost_main_frame =
      arg_dict.FindBool("isOutermostMainFrame");
  EXPECT_TRUE(is_outermost_main_frame.has_value());
  EXPECT_EQ(true, is_outermost_main_frame.value());
  std::optional<bool> is_embedded_frame = arg_dict.FindBool("isEmbeddedFrame");
  EXPECT_TRUE(is_embedded_frame.has_value());
  EXPECT_EQ(false, is_embedded_frame.value());
  EXPECT_GT(arg_dict.FindInt("frame_x").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("frame_y").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("frame_width").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("frame_height").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("root_x").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("root_y").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("root_width").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("root_height").value_or(-1), 0);
}

TEST_F(TextPaintTimingDetectorTest,
       LargestTextPaint_TraceEvent_Candidate_Frame) {
  using trace_analyzer::Query;
  trace_analyzer::Start("loading");
  {
    GetDocument().SetBaseURLOverride(KURL("http://test.com"));
    SetBodyInnerHTML(R"HTML(
      <style>body { margin: 15px; } iframe { display: block; position: relative; margin-top: 50px; } </style>
      <iframe> </iframe>
    )HTML");
    SetChildBodyInnerHTML(R"HTML(
    <style>body { margin: 10px;} #target { width: 200px; height: 200px; }
    </style>
    <div>Some content</div>
  )HTML");
    UpdateAllLifecyclePhasesAndSimulatePresentationTime();
    ChildFramePresentationTimeCallBack();
  }
  auto analyzer = trace_analyzer::Stop();
  trace_analyzer::TraceEventVector events;
  Query q = Query::EventNameIs("LargestTextPaint::Candidate");
  analyzer->FindEvents(q, &events);
  EXPECT_EQ(1u, events.size());
  EXPECT_EQ("loading", events[0]->category);

  EXPECT_TRUE(events[0]->HasStringArg("frame"));

  ASSERT_TRUE(events[0]->HasDictArg("data"));
  base::Value::Dict arg_dict = events[0]->GetKnownArgAsDict("data");
  EXPECT_GT(arg_dict.FindInt("DOMNodeId").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("size").value_or(-1), 0);
  EXPECT_EQ(arg_dict.FindInt("candidateIndex").value_or(-1), 1);
  std::optional<bool> is_main_frame = arg_dict.FindBool("isMainFrame");
  EXPECT_TRUE(is_main_frame.has_value());
  EXPECT_EQ(false, is_main_frame.value());
  std::optional<bool> is_outermost_main_frame =
      arg_dict.FindBool("isOutermostMainFrame");
  EXPECT_TRUE(is_outermost_main_frame.has_value());
  EXPECT_EQ(false, is_outermost_main_frame.value());
  std::optional<bool> is_embedded_frame = arg_dict.FindBool("isEmbeddedFrame");
  EXPECT_TRUE(is_embedded_frame.has_value());
  EXPECT_EQ(false, is_embedded_frame.value());
  // There's sometimes a 1 pixel offset for the y dimensions.
  EXPECT_EQ(arg_dict.FindInt("frame_x").value_or(-1), 10);
  EXPECT_GE(arg_dict.FindInt("frame_y").value_or(-1), 9);
  EXPECT_LE(arg_dict.FindInt("frame_y").value_or(-1), 10);
  EXPECT_GT(arg_dict.FindInt("frame_width").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("frame_height").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("root_x").value_or(-1), 25);
  EXPECT_GT(arg_dict.FindInt("root_y").value_or(-1), 50);
  EXPECT_GT(arg_dict.FindInt("root_width").value_or(-1), 0);
  EXPECT_GT(arg_dict.FindInt("root_height").value_or(-1), 0);
}

TEST_F(TextPaintTimingDetectorTest, AggregationBySelfPaintingInlineElement) {
  SetBodyInnerHTML(R"HTML(
    <div style="background: yellow">
      tiny
      <span id="target"
        style="position: relative; background: blue; top: 100px; left: 100px">
        this is the largest text in the world.</span>
    </div>
  )HTML");
  Element* span = GetDocument().getElementById(AtomicString("target"));
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, span);
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_OpacityZero) {
  SetBodyInnerHTML(R"HTML(
    <style>
    div {
      opacity: 0;
    }
    </style>
  )HTML");
  AppendDivElementToBody("The only text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint(), nullptr);
}

TEST_F(TextPaintTimingDetectorTest,
       NodeRemovedBeforeAssigningPresentationTime) {
  SetBodyInnerHTML(R"HTML(
    <div id="parent">
      <div id="remove">The only text</div>
    </div>
  )HTML");
  UpdateAllLifecyclePhases();
  GetDocument()
      .getElementById(AtomicString("parent"))
      ->RemoveChild(GetDocument().getElementById(AtomicString("remove")));
  InvokeCallback();
  EXPECT_EQ(TextRecordOfLargestTextPaint(), nullptr);
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_LargestText) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  AppendDivElementToBody("medium text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();

  Element* large_text = AppendDivElementToBody("a long-long-long text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();

  AppendDivElementToBody("small");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();

  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, large_text);
}

TEST_F(TextPaintTimingDetectorTest, UpdateResultWhenCandidateChanged) {
  base::TimeTicks time1 = NowTicks();
  SetBodyInnerHTML(R"HTML(
    <div>small text</div>
  )HTML");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  base::TimeTicks time2 = NowTicks();
  base::TimeTicks first_largest = LargestPaintTime();
  EXPECT_GE(first_largest, time1);
  EXPECT_GE(time2, first_largest);

  AppendDivElementToBody("a long-long-long text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  base::TimeTicks time3 = NowTicks();
  base::TimeTicks second_largest = LargestPaintTime();
  EXPECT_GE(second_largest, time2);
  EXPECT_GE(time3, second_largest);
}

// There is a risk that a text that is just recorded is selected to be the
// metric candidate. The algorithm should skip the text record if its paint time
// hasn't been recorded yet.
TEST_F(TextPaintTimingDetectorTest, PendingTextIsLargest) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  AppendDivElementToBody("text");
  GetFrameView().UpdateAllLifecyclePhasesForTest();
  // We do not call presentation-time callback here in order to not set the
  // paint time.
  EXPECT_FALSE(TextRecordOfLargestTextPaint());
}

// The same node may be visited by recordText for twice before the paint time
// is set. In some previous design, this caused the node to be recorded twice.
TEST_F(TextPaintTimingDetectorTest, VisitSameNodeTwiceBeforePaintTimeIsSet) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* text = AppendDivElementToBody("text");
  GetFrameView().UpdateAllLifecyclePhasesForTest();
  // Change a property of the text to trigger repaint.
  text->setAttribute(html_names::kStyleAttr, AtomicString("color:red;"));
  GetFrameView().UpdateAllLifecyclePhasesForTest();
  InvokeCallback();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, text);
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_ReportFirstPaintTime) {
  base::TimeTicks start_time = NowTicks();
  AdvanceClock(base::Seconds(1));
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* text = AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  AdvanceClock(base::Seconds(1));
  text->setAttribute(html_names::kStyleAttr,
                     AtomicString("position:fixed;left:30px"));
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  AdvanceClock(base::Seconds(1));
  TextRecord* record = TextRecordOfLargestTextPaint();
  EXPECT_TRUE(record);
  EXPECT_EQ(record->paint_time, start_time + base::Seconds(1) + kQuantumOfTime);
}

TEST_F(TextPaintTimingDetectorTest,
       LargestTextPaint_IgnoreTextOutsideViewport) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div.out {
        position: fixed;
        top: -100px;
      }
    </style>
    <div class='out'>text outside of viewport</div>
  )HTML");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_FALSE(TextRecordOfLargestTextPaint());
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_RemovedText) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* large_text = AppendDivElementToBody(
      "(large text)(large text)(large text)(large text)(large text)(large "
      "text)");
  AppendDivElementToBody("small text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  TextRecord* record = TextRecordOfLargestTextPaint();
  EXPECT_NE(record, nullptr);
  EXPECT_EQ(record->node_, large_text);
  uint64_t size_before_remove = LargestPaintSize();
  base::TimeTicks time_before_remove = LargestPaintTime();
  EXPECT_GT(size_before_remove, 0u);
  EXPECT_GT(time_before_remove, base::TimeTicks());

  RemoveElement(large_text);
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint(), record);
  // LCP values should remain unchanged.
  EXPECT_EQ(LargestPaintSize(), size_before_remove);
  EXPECT_EQ(LargestPaintTime(), time_before_remove);
}

TEST_F(TextPaintTimingDetectorTest,
       RemoveRecordFromAllContainerAfterTextRemoval) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* text = AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(ContainerTotalSize(), 1u);

  RemoveElement(text);
  EXPECT_EQ(ContainerTotalSize(), 0u);
}

TEST_F(TextPaintTimingDetectorTest,
       RemoveRecordFromAllContainerAfterRepeatedAttachAndDetach) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* text1 = AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(ContainerTotalSize(), 1u);

  Element* text2 = AppendDivElementToBody("text2");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(ContainerTotalSize(), 2u);

  RemoveElement(text1);
  EXPECT_EQ(ContainerTotalSize(), 1u);

  GetDocument().body()->AppendChild(text1);
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(ContainerTotalSize(), 2u);

  RemoveElement(text1);
  EXPECT_EQ(ContainerTotalSize(), 1u);

  RemoveElement(text2);
  EXPECT_EQ(ContainerTotalSize(), 0u);
}

TEST_F(TextPaintTimingDetectorTest,
       DestroyLargestTextPaintMangerAfterUserInput) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_TRUE(GetTextPaintTimingDetector()->IsRecordingLargestTextPaint());

  SimulateInputEvent();
  EXPECT_FALSE(GetTextPaintTimingDetector()->IsRecordingLargestTextPaint());
}

TEST_F(TextPaintTimingDetectorTest, DoNotStopRecordingLCPAfterKeyUp) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_TRUE(GetTextPaintTimingDetector()->IsRecordingLargestTextPaint());

  SimulateKeyUp();
  EXPECT_TRUE(GetTextPaintTimingDetector()->IsRecordingLargestTextPaint());
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_TextRecordAfterRemoval) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* text = AppendDivElementToBody("text to remove");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  TextRecord* record = TextRecordOfLargestTextPaint();
  EXPECT_NE(record, nullptr);
  EXPECT_EQ(record->node_, text);
  base::TimeTicks largest_paint_time = LargestPaintTime();
  EXPECT_NE(largest_paint_time, base::TimeTicks());
  uint64_t largest_paint_size = LargestPaintSize();
  EXPECT_NE(largest_paint_size, 0u);

  RemoveElement(text);
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint(), record);
  // LCP values should remain unchanged.
  EXPECT_EQ(largest_paint_time, LargestPaintTime());
  EXPECT_EQ(largest_paint_size, LargestPaintSize());
}

TEST_F(TextPaintTimingDetectorTest,
       LargestTextPaint_CompareVisualSizeNotActualSize) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  AppendDivElementToBody("a long text", "position:fixed;left:-10px");
  Element* short_text = AppendDivElementToBody("short");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, short_text);
}

TEST_F(TextPaintTimingDetectorTest, LargestTextPaint_CompareSizesAtFirstPaint) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  Element* shortening_long_text = AppendDivElementToBody("123456789");
  AppendDivElementToBody("12345678");  // 1 letter shorter than the above.
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  // The visual size becomes smaller when less portion intersecting with
  // viewport.
  SetElementStyle(shortening_long_text, "position:fixed;left:-10px");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, shortening_long_text);
}

TEST_F(TextPaintTimingDetectorTest, TreatEllipsisAsText) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <div style="font:10px Ahem;white-space:nowrap;width:50px;overflow:hidden;text-overflow:ellipsis;">
    00000000000000000000000000000000000000000000000000000000000000000000000000
    00000000000000000000000000000000000000000000000000000000000000000000000000
    </div>
  )HTML");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();

  EXPECT_EQ(CountRecordedSize(), 1u);
  EXPECT_NE(TextRecordOfLargestTextPaint(), nullptr);
}

TEST_F(TextPaintTimingDetectorTest, CaptureFileUploadController) {
  SetBodyInnerHTML("<input type='file'>");
  Element* element = GetDocument().QuerySelector(AtomicString("input"));
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();

  EXPECT_EQ(CountRecordedSize(), 1u);
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, element);
}

TEST_F(TextPaintTimingDetectorTest, CapturingListMarkers) {
  SetBodyInnerHTML(R"HTML(
    <ul>
      <li>List item</li>
    </ul>
    <ol>
      <li>Another list item</li>
    </ol>
  )HTML");

  CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(3u);
}

TEST_F(TextPaintTimingDetectorTest, CaptureSVGText) {
  SetBodyInnerHTML(R"HTML(
    <svg height="40" width="300">
      <text x="0" y="15">A SVG text.</text>
    </svg>
  )HTML");

  auto* elem = To<SVGTextContentElement>(
      GetDocument().QuerySelector(AtomicString("text")));
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(CountRecordedSize(), 1u);
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, elem);
}

// This is for comparison with the ClippedByViewport test.
TEST_F(TextPaintTimingDetectorTest, NormalTextUnclipped) {
  SetBodyInnerHTML(R"HTML(
    <div id='d'>text</div>
  )HTML");
  EXPECT_EQ(TextQueuedForPaintTimeSize(GetFrameView()), 1u);
}

TEST_F(TextPaintTimingDetectorTest, ClippedByViewport) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #d { margin-top: 1234567px }
    </style>
    <div id='d'>text</div>
  )HTML");
  // Make sure the margin-top is larger than the viewport height.
  DCHECK_LT(GetViewportRect(GetFrameView()).height(), 1234567);
  EXPECT_EQ(TextQueuedForPaintTimeSize(GetFrameView()), 0u);
}

TEST_F(TextPaintTimingDetectorTest, ClippedByParentVisibleRect) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #outer1 {
        overflow: hidden;
        height: 1px;
        width: 1px;
      }
      #outer2 {
        overflow: hidden;
        height: 2px;
        width: 2px;
      }
    </style>
    <div id='outer1'></div>
    <div id='outer2'></div>
  )HTML");
  Element* div1 = GetDocument().CreateRawElement(html_names::kDivTag);
  Text* text1 = GetDocument().createTextNode(
      "########################################################################"
      "######################################################################"
      "#");
  div1->AppendChild(text1);
  GetDocument()
      .body()
      ->getElementById(AtomicString("outer1"))
      ->AppendChild(div1);

  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, div1);
  EXPECT_EQ(TextRecordOfLargestTextPaint()->recorded_size, 1u);

  Element* div2 = GetDocument().CreateRawElement(html_names::kDivTag);
  Text* text2 = GetDocument().createTextNode(
      "########################################################################"
      "######################################################################"
      "#");
  div2->AppendChild(text2);
  GetDocument()
      .body()
      ->getElementById(AtomicString("outer2"))
      ->AppendChild(div2);

  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(TextRecordOfLargestTextPaint()->node_, div2);
  // This size is larger than the size of the first object . But the exact size
  // depends on different platforms. We only need to ensure this size is larger
  // than the first size.
  EXPECT_GT(TextRecordOfLargestTextPaint()->recorded_size, 1u);
}

TEST_F(TextPaintTimingDetectorTest, Iframe) {
  SetBodyInnerHTML(R"HTML(
    <iframe width=100px height=100px></iframe>
  )HTML");
  SetChildBodyInnerHTML("A");
  UpdateAllLifecyclePhases();
  EXPECT_EQ(TextQueuedForPaintTimeSize(GetChildFrameView()), 1u);
  ChildFramePresentationTimeCallBack();
  TextRecord* text = ChildFrameTextRecordOfLargestTextPaint();
  EXPECT_TRUE(text);
}

TEST_F(TextPaintTimingDetectorTest, Iframe_ClippedByViewport) {
  SetBodyInnerHTML(R"HTML(
    <iframe width=100px height=100px></iframe>
  )HTML");
  SetChildBodyInnerHTML(R"HTML(
    <style>
      #d { margin-top: 200px }
    </style>
    <div id='d'>text</div>
  )HTML");
  DCHECK_EQ(GetViewportRect(GetChildFrameView()).height(), 100);
  UpdateAllLifecyclePhases();
  EXPECT_EQ(TextQueuedForPaintTimeSize(GetChildFrameView()), 0u);
}

TEST_F(TextPaintTimingDetectorTest, SameSizeShouldNotBeIgnored) {
  SetBodyInnerHTML(R"HTML(
    <div>text</div>
    <div>text</div>
    <div>text</div>
    <div>text</div>
  )HTML");
  CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(4u);
}

TEST_F(TextPaintTimingDetectorTest, VisibleTextAfterUserInput) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(CountRecordedSize(), 1u);

  SimulateInputEvent();
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(CountRecordedSize(), 1u);
}

TEST_F(TextPaintTimingDetectorTest, VisibleTextAfterUserScroll) {
  SetBodyInnerHTML(R"HTML(
  )HTML");
  AppendDivElementToBody("text");
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(CountRecordedSize(), 1u);

  SimulateScroll();
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_EQ(CountRecordedSize(), 1u);
}

TEST_F(TextPaintTimingDetectorTest, OpacityZeroHTML) {
  SetBodyInnerHTML(R"HTML(
    <style>
      :root {
        opacity: 0;
        will-change: opacity;
      }
    </style>
    <div>Text</div>
  )HTML");
  CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(0u);

  // Change the opacity of documentElement, now the img should be a candidate.
  GetDocument().documentElement()->setAttribute(html_names::kStyleAttr,
                                                AtomicString("opacity: 1"));
  UpdateAllLifecyclePhasesAndSimulatePresentationTime();
  EXPECT_TRUE(TextRecordOfLargestTextPaint());
}

TEST_F(TextPaintTimingDetectorTest, OpacityZeroHTML2) {
  SetBodyInnerHTML(R"HTML(
    <style>
      #target {
        opacity: 0;
        will-change: opacity;
      }
    </style>
    <div id="target">Text</div>
  )HTML");
  CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(0u);

  GetDocument().documentElement()->setAttribute(html_names::kStyleAttr,
                                                AtomicString("opacity: 0"));
  CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(0u);

  GetDocument().documentElement()->setAttribute(html_names::kStyleAttr,
                                                AtomicString("opacity: 1"));
  CheckSizeOfTextQueuedForPaintTimeAfterUpdateLifecyclePhases(0u);
}

}  // namespace blink
```