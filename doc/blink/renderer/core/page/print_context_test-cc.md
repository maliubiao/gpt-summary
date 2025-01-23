Response:
My thought process to answer the prompt about `print_context_test.cc` goes like this:

1. **Understand the Core Request:** The primary goal is to analyze the functionality of the given C++ test file, relate it to web technologies (HTML, CSS, JavaScript), identify potential issues, and describe the user journey leading to this code being executed. The prompt also explicitly asks for a summary in this first part.

2. **Initial Examination of Includes and Namespaces:** I start by looking at the `#include` directives. These give immediate clues about the file's purpose. I see includes related to:
    * `print_context.h`: This is the most important. The test file is clearly testing the `PrintContext` class.
    * `testing/gmock/include/gmock/gmock.h` and `testing/gtest/include/gtest/gtest.h`:  This confirms it's a unit test file using Google Test and Google Mock frameworks.
    * `third_party/blink/...`:  Numerous Blink-specific headers indicate the aspects of the rendering engine being tested. Key ones include `core/dom/document.h`, `core/frame/...`, `core/html/...`, `core/layout/...`, `core/paint/...`, and `platform/graphics/...`. This tells me the tests likely involve manipulating the DOM, layout, and painting processes related to printing.
    * `base/test/scoped_feature_list.h` and `gpu/config/gpu_finch_features.h`: This suggests the tests might involve enabling or disabling certain features related to printing, potentially GPU-accelerated printing.
    * `components/viz/test/...`: This indicates involvement with the Viz compositor, suggesting tests related to how printing interacts with the compositing process.
    * Skia headers (`third_party/skia/include/core/SkCanvas.h`): This strongly points to tests involving the actual drawing operations during printing.

3. **Analyze the Test Fixtures and Helper Classes:** I notice the `PrintContextTest` and `PrintContextFrameTest` classes. `PrintContextTest` inherits from `PaintTestConfigurations` and `RenderingTest`, standard Blink test base classes. This confirms the focus on rendering-related tests. The `MockPageContextCanvas` class is a custom mock of the SkCanvas, allowing the tests to verify the drawing calls made during printing.

4. **Examine the Test Methods:**  The names of the `TEST_P` methods are very informative: `LinkTarget`, `LinkTargetInCompositedScroller`, `LinkTargetUnderAnonymousBlockBeforeBlock`, `LinkedTarget`, `LinkedTargetSecondPage`, etc. These names strongly suggest that the tests are focused on how hyperlinks are handled during the printing process, including:
    * Drawing visual cues for links (the "link targets").
    * Handling links in different layout scenarios (scrolling containers, inline/block elements).
    * Testing named anchors and cross-page links.
    * Considering different writing modes (vertical-rl, etc.).
    * Interactions with SVG elements.

5. **Infer Functionality Based on Test Structure:**  The structure of the tests follows a pattern:
    * Set up an HTML document using `SetBodyInnerHTML`.
    * Optionally mock drawing behavior using `MockPageContextCanvas`.
    * Invoke the printing process using `PrintSinglePage` or similar methods.
    * Assertions on the recorded drawing operations or other outcomes.

6. **Relate to Web Technologies:** Based on the tested scenarios (links, layout, SVG) and the included headers, I can clearly see the connection to HTML (structure, links, anchors), CSS (styling, layout, writing modes), and indirectly to JavaScript (though the tests themselves are C++, the features they test are often triggered or manipulated by JavaScript in real browser usage).

7. **Identify Potential Issues/User Errors:**  The tests implicitly highlight potential issues:
    * Incorrect rendering of link targets in complex layouts.
    * Problems with cross-page links or named anchors during printing.
    * Unexpected behavior with different writing modes or scaling.

8. **Trace User Actions:**  I consider how a user might trigger the printing functionality:
    * Clicking the "Print" option in the browser menu.
    * Using the keyboard shortcut (Ctrl+P or Cmd+P).
    * JavaScript code calling `window.print()`.

9. **Construct Examples and Scenarios:** To illustrate the relationships with web technologies and potential issues, I create concrete examples based on the test names and code snippets within the file.

10. **Formulate the Summary:** Finally, I synthesize my observations into a concise summary that captures the main purpose of the file: testing the print functionality of the Blink rendering engine, specifically focusing on the correct rendering of interactive elements like hyperlinks in various layout scenarios.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe it tests just basic printing.
* **Correction:** The detailed test names and mocking of canvas operations reveal a deeper focus on link handling and accurate visual representation during print.

* **Initial thought:** How does JavaScript fit in?
* **Refinement:** While the tests are C++, they verify features that JavaScript can trigger (e.g., dynamic content affecting layout before printing) or rely on (e.g., `window.print()`). The tests ensure the underlying rendering engine behaves correctly regardless of how printing is initiated.

* **Initial thought:**  Just visual rendering?
* **Refinement:**  The focus on `LinkTarget` and `LinkedTarget` shows it's not just about visual output, but also about ensuring the interactive nature of links is preserved (or at least represented) in the printed output.

By following this detailed analysis and refinement process, I can generate a comprehensive and accurate answer to the prompt.
这是对 Chromium Blink 引擎源代码文件 `blink/renderer/core/page/print_context_test.cc` 的第一部分分析。

**功能归纳:**

这个文件的主要功能是 **测试 Blink 渲染引擎中 `PrintContext` 类的功能**。 `PrintContext` 负责处理网页的打印逻辑，包括：

* **确定打印页面的布局和分割:**  如何将一个长的网页内容分割成多个打印页面。
* **在每个页面上绘制内容:**  调用底层的绘图接口（Skia）来渲染每个页面的内容。
* **处理打印相关的事件:**  例如 `beforeprint` 事件。
* **生成打印文档的元数据:** 例如链接和锚点的目标信息。

**与 Javascript, HTML, CSS 的关系:**

这个测试文件通过构建包含 HTML、CSS 样式的文档，并模拟打印过程，来验证 `PrintContext` 是否正确地处理了这些 Web 技术带来的影响。

* **HTML:**
    * **链接 (`<a>` 标签):** 大量的测试用例都在验证打印时如何处理链接，包括链接的目标区域的绘制、跨页链接的处理、以及锚点链接的处理。
        * **举例:** `TEST_P(PrintContextTest, LinkTarget)` 测试了打印包含简单链接的页面时，是否在链接所在区域绘制了标记，以便用户识别可点击的区域。
    * **图片 (`<img>` 标签):**  一些测试用例中包含了图片，用于测试链接包含图片时的边界计算。
        * **举例:** `TEST_P(PrintContextTest, LinkTargetBoundingBox)` 测试了当链接内部包含图片时，链接目标区域是否能正确包裹住整个图片。
    * **SVG (`<svg>` 标签):**  测试了打印包含 SVG 图形的页面时，链接的处理是否正确。
        * **举例:** `TEST_P(PrintContextTest, LinkTargetSvg)` 测试了 SVG 内部的链接是否被正确识别并绘制了目标区域。
    * **锚点 (`<a name="...">` 标签):**  测试了打印包含锚点的页面时，链接到这些锚点的链接是否能正确地记录目标位置。
        * **举例:** `TEST_P(PrintContextTest, LinkedTarget)` 测试了不同形式的锚点链接（例如 `#fragment`, `#中文`, `#%编码`）是否都能被正确处理。
* **CSS:**
    * **定位 (position: absolute, relative):** 测试了绝对定位和相对定位的元素内的链接在打印时的处理。
        * **举例:** `TEST_P(PrintContextTest, LinkTargetRelativelyPositionedInline)` 测试了相对定位的行内元素内的链接目标区域是否会受到定位的影响。
    * **布局 (display: block, inline, overflow: scroll):** 测试了不同布局方式下的链接处理。
        * **举例:** `TEST_P(PrintContextTest, LinkTargetInCompositedScroller)` 测试了在可滚动容器内的链接是否被正确处理。
    * **书写模式 (writing-mode: vertical-rl, vertical-lr):** 测试了不同书写模式下，页面分割和链接处理是否正确。
        * **举例:** 多个以 `ScaledVerticalRL`, `ScaledVerticalLR` 开头的测试用例，验证了在垂直书写模式下，页面数量的计算是否正确。
    * **分页符 (break-before: page, break-after: page):** 测试了分页符对页面分割的影响。
        * **举例:** `TEST_P(PrintContextTest, LinkedTargetSecondPage)` 测试了链接到一个位于下一页的锚点时，目标位置的记录是否正确。
    * **行高 (line-height):**  `TEST_P(PrintContextTest, LinkInFragmentedContainer)` 中使用了 `line-height` 来影响链接的布局，测试跨页链接的处理。
* **Javascript:**
    * **`beforeprint` 事件:** 测试用例中会触发 `BeforePrintEvent`，模拟 Javascript 中 `window.onbeforeprint` 事件的触发，以验证 `PrintContext` 对此事件的处理。

**逻辑推理 (假设输入与输出):**

大多数测试用例的核心逻辑是：

1. **假设输入:**  一段包含特定 HTML 和 CSS 结构的字符串，用于设置页面内容。
2. **执行:** 调用 `PrintSinglePage` 函数，模拟打印单个页面的过程，并使用 `MockPageContextCanvas` 记录绘制操作。
3. **验证输出:**  断言 `MockPageContextCanvas` 记录的绘制操作是否符合预期。  例如，对于链接，会验证是否在正确的坐标和尺寸绘制了矩形区域。

**举例说明:**

在 `TEST_P(PrintContextTest, LinkTarget)` 中：

* **假设输入:**  HTML 字符串 `AbsoluteBlockHtmlForLink(50, 60, 70, 80, "http://www.google.com")`，它会生成一个绝对定位的链接。
* **执行:**  `PrintSinglePage(canvas)` 会触发打印过程。
* **验证输出:**  `EXPECT_SKRECT_EQ(50, 60, 70, 80, operations[0].rect)` 断言在坐标 (50, 60)，宽度 70，高度 80 的位置记录了一个绘制矩形的操作，这对应着链接的边界。

**用户或编程常见的使用错误:**

这个测试文件主要关注 Blink 引擎的内部逻辑，直接关联用户或编程错误的例子较少。但可以推断出一些潜在的错误场景，这些测试旨在防止这些错误：

* **链接目标区域计算错误:**  开发者可能会错误地认为链接只覆盖文本内容，而忽略了图片或其他内联元素。测试用例如 `TEST_P(PrintContextTest, LinkTargetBoundingBox)` 确保了即使链接内部包含复杂内容，其可点击区域在打印时也能被正确识别。
* **跨页链接处理错误:**  当一个链接的目标（锚点）位于不同的页面时，如果 `PrintContext` 处理不当，可能无法正确标记链接的目标位置。`TEST_P(PrintContextTest, LinkedTargetSecondPage)` 就测试了这种情况。
* **不同布局模式下链接处理不一致:**  开发者可能会依赖于某些特定的布局方式来放置链接，而忽略了打印时的布局可能与屏幕显示不同。测试用例覆盖了不同的布局场景，确保 `PrintContext` 在各种情况下都能正确处理链接。

**用户操作如何一步步的到达这里 (调试线索):**

1. **用户在浏览器中打开一个网页。**
2. **网页加载并渲染完成，包括 HTML 结构、CSS 样式和可能的 Javascript 交互。**
3. **用户触发打印操作。** 这可以通过多种方式实现：
    * 点击浏览器菜单中的 "打印" 选项。
    * 使用键盘快捷键 (例如 Ctrl+P 或 Cmd+P)。
    * 网页上的 Javascript 代码调用 `window.print()` 方法。
4. **浏览器接收到打印请求后，会将渲染引擎（Blink）中的 `PrintContext` 类激活。**
5. **`PrintContext` 会分析当前页面的 DOM 树、布局信息和样式，并根据打印设置（例如纸张大小、方向）来确定如何分割页面。**
6. **`PrintContext` 会遍历每一页，并指示底层的绘图系统 (Skia) 来绘制页面内容，包括文本、图片、链接等。**  在绘制链接时，会记录链接的目标区域信息。
7. **这个测试文件 `print_context_test.cc` 的作用就是在开发过程中，通过模拟上述步骤，来验证 `PrintContext` 在处理各种网页结构和样式时，其行为是否符合预期，特别是对于链接的处理是否正确。**

**总结:**

总而言之，`blink/renderer/core/page/print_context_test.cc` 是一个至关重要的测试文件，它专注于验证 Blink 渲染引擎中负责网页打印的核心组件 `PrintContext` 的正确性。 它通过构建各种包含 HTML、CSS 结构的测试用例，模拟打印过程，并检查链接等关键元素的渲染和元数据生成是否符合预期，从而保证了 Chromium 浏览器打印功能的稳定性和正确性。

### 提示词
```
这是目录为blink/renderer/core/page/print_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/core/page/print_context.h"

#include <memory>

#include "base/test/scoped_feature_list.h"
#include "components/viz/test/test_context_provider.h"
#include "components/viz/test/test_gles2_interface.h"
#include "components/viz/test/test_raster_interface.h"
#include "gpu/config/gpu_finch_features.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/events/before_print_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/canvas/canvas_rendering_context.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_painter.h"
#include "third_party/blink/renderer/core/scroll/scrollbar_theme.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/graphics/canvas_resource_provider.h"
#include "third_party/blink/renderer/platform/graphics/gpu/shared_gpu_context.h"
#include "third_party/blink/renderer/platform/graphics/graphics_context.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/graphics/test/gpu_test_utils.h"
#include "third_party/blink/renderer/platform/testing/paint_test_configurations.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder_stream.h"
#include "third_party/skia/include/core/SkCanvas.h"

using testing::_;

namespace blink {

const int kPageWidth = 800;
const int kPageHeight = 600;

class MockPageContextCanvas : public SkCanvas {
 public:
  enum OperationType { kDrawRect, kDrawPoint };

  struct Operation {
    OperationType type;
    SkRect rect;
  };

  MockPageContextCanvas() : SkCanvas(kPageWidth, kPageHeight) {}
  ~MockPageContextCanvas() override = default;

  void onDrawAnnotation(const SkRect& rect,
                        const char key[],
                        SkData* value) override {
    // Ignore PDF node key annotations, defined in SkPDFDocument.cpp.
    if (0 == strcmp(key, "PDF_Node_Key"))
      return;

    if (rect.width() == 0 && rect.height() == 0) {
      SkPoint point = getTotalMatrix().mapXY(rect.x(), rect.y());
      Operation operation = {kDrawPoint,
                             SkRect::MakeXYWH(point.x(), point.y(), 0, 0)};
      recorded_operations_.push_back(operation);
    } else {
      Operation operation = {kDrawRect, rect};
      getTotalMatrix().mapRect(&operation.rect);
      recorded_operations_.push_back(operation);
    }
  }

  const Vector<Operation>& RecordedOperations() const {
    return recorded_operations_;
  }

  MOCK_METHOD2(onDrawRect, void(const SkRect&, const SkPaint&));
  MOCK_METHOD3(onDrawPicture,
               void(const SkPicture*, const SkMatrix*, const SkPaint*));
  MOCK_METHOD5(onDrawImage2,
               void(const SkImage*,
                    SkScalar,
                    SkScalar,
                    const SkSamplingOptions&,
                    const SkPaint*));
  MOCK_METHOD6(onDrawImageRect2,
               void(const SkImage*,
                    const SkRect&,
                    const SkRect&,
                    const SkSamplingOptions&,
                    const SkPaint*,
                    SrcRectConstraint));

 private:
  Vector<Operation> recorded_operations_;
};

class PrintContextTest : public PaintTestConfigurations, public RenderingTest {
 protected:
  explicit PrintContextTest(LocalFrameClient* local_frame_client = nullptr)
      : RenderingTest(local_frame_client) {}
  ~PrintContextTest() override = default;

  void SetUp() override {
    RenderingTest::SetUp();
    print_context_ =
        MakeGarbageCollected<PrintContext>(GetDocument().GetFrame());
    base::FieldTrialParams auto_flush_params;
    auto_flush_params["max_pinned_image_kb"] = "1";
    print_feature_list_.InitAndEnableFeatureWithParameters(
        kCanvas2DAutoFlushParams, auto_flush_params);
  }

  void TearDown() override {
    RenderingTest::TearDown();
    CanvasRenderingContext::GetCanvasPerformanceMonitor().ResetForTesting();
    print_feature_list_.Reset();
  }

  PrintContext& GetPrintContext() { return *print_context_.Get(); }

  void SetBodyInnerHTML(String body_content) {
    GetDocument().body()->setAttribute(html_names::kStyleAttr,
                                       AtomicString("margin: 0"));
    GetDocument().body()->setInnerHTML(body_content);
  }

  gfx::Rect PrintSinglePage(SkCanvas& canvas, int page_index = 0) {
    GetDocument().SetPrinting(Document::kBeforePrinting);
    Event* event = MakeGarbageCollected<BeforePrintEvent>();
    GetPrintContext().GetFrame()->DomWindow()->DispatchEvent(*event);
    GetPrintContext().BeginPrintMode(
        WebPrintParams(gfx::SizeF(kPageWidth, kPageHeight)));
    GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kTest);

    gfx::Rect page_rect = GetPrintContext().PageRect(page_index);

    PaintRecordBuilder builder;
    GraphicsContext& context = builder.Context();
    context.SetPrinting(true);
    GetDocument().View()->PrintPage(context, page_index, CullRect(page_rect));
    GetPrintContext().OutputLinkedDestinations(
        context,
        GetDocument().GetLayoutView()->FirstFragment().ContentsProperties(),
        page_rect);
    builder.EndRecording().Playback(&canvas);
    GetPrintContext().EndPrintMode();

    // The drawing operations are relative to the current page.
    return gfx::Rect(page_rect.size());
  }

  static String AbsoluteBlockHtmlForLink(int x,
                                         int y,
                                         int width,
                                         int height,
                                         String url,
                                         String children = String()) {
    StringBuilder ts;
    ts << "<a style='position: absolute; left: " << x << "px; top: " << y
       << "px; width: " << width << "px; height: " << height << "px' href='"
       << url << "'>" << (children ? children : url) << "</a>";
    return ts.ReleaseString();
  }

  static String InlineHtmlForLink(String url, String children = String()) {
    StringBuilder ts;
    ts << "<a href='" << url << "'>" << (children ? children : url) << "</a>";
    return ts.ReleaseString();
  }

  static String HtmlForAnchor(int x, int y, String name, String text_content) {
    StringBuilder ts;
    ts << "<a name='" << name << "' style='position: absolute; left: " << x
       << "px; top: " << y << "px'>" << text_content << "</a>";
    return ts.ReleaseString();
  }

 private:
  std::unique_ptr<DummyPageHolder> page_holder_;
  Persistent<PrintContext> print_context_;
  base::test::ScopedFeatureList print_feature_list_;
};

class PrintContextFrameTest : public PrintContextTest {
 public:
  PrintContextFrameTest()
      : PrintContextTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
};

#define EXPECT_SKRECT_EQ(expectedX, expectedY, expectedWidth, expectedHeight, \
                         actualRect)                                          \
  do {                                                                        \
    EXPECT_EQ(expectedX, actualRect.x());                                     \
    EXPECT_EQ(expectedY, actualRect.y());                                     \
    EXPECT_EQ(expectedWidth, actualRect.width());                             \
    EXPECT_EQ(expectedHeight, actualRect.height());                           \
  } while (false)

INSTANTIATE_PAINT_TEST_SUITE_P(PrintContextTest);

TEST_P(PrintContextTest, LinkTarget) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
      AbsoluteBlockHtmlForLink(50, 60, 70, 80, "http://www.google.com") +
      AbsoluteBlockHtmlForLink(150, 160, 170, 180,
                               "http://www.google.com#fragment"));
  PrintSinglePage(canvas);

  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(2u, operations.size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 60, 70, 80, operations[0].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(150, 160, 170, 180, operations[1].rect);
}

TEST_P(PrintContextTest, LinkTargetInCompositedScroller) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
      "<div style='width: 200px; height: 200px; overflow: scroll;"
      "            position: relative; will-change: scroll-position'>" +
      AbsoluteBlockHtmlForLink(50, 60, 70, 80, "http://www.google.com") +
      AbsoluteBlockHtmlForLink(250, 60, 70, 80, "http://www.google.com") +
      "</div>");
  PrintSinglePage(canvas);

  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(1u, operations.size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 60, 70, 80, operations[0].rect);
}

TEST_P(PrintContextTest, LinkTargetUnderAnonymousBlockBeforeBlock) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML("<div style='padding-top: 50px'>" +
                   InlineHtmlForLink("http://www.google.com",
                                     "<img style='width: 111; height: 10'>") +
                   "<div> " +
                   InlineHtmlForLink("http://www.google1.com",
                                     "<img style='width: 122; height: 20'>") +
                   "</div>" + "</div>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(4u, operations.size());
  // First 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(0, 59, 111, 1, operations[0].rect);
  // First image:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(0, 50, 111, 10, operations[1].rect);
  // Second 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
  EXPECT_SKRECT_EQ(0, 79, 122, 1, operations[2].rect);
  // Second image:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[3].type);
  EXPECT_SKRECT_EQ(0, 60, 122, 20, operations[3].rect);
}

TEST_P(PrintContextTest, LinkTargetContainingABlock) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
      "<div style='padding-top: 50px; width:555px;'>" +
      InlineHtmlForLink("http://www.google2.com",
                        "<div style='width:133px; height: 30px'>BLOCK</div>") +
      "</div>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(5u, operations.size());
  // Empty line before the line with the block inside:
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, operations[0].type);
  EXPECT_SKRECT_EQ(0, 50, 0, 0, operations[0].rect);
  // The line with the block inside:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(0, 50, 555, 30, operations[1].rect);
  // Empty line after the line with the block inside:
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, operations[2].type);
  EXPECT_SKRECT_EQ(0, 80, 0, 0, operations[2].rect);
  // The block:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[3].type);
  EXPECT_SKRECT_EQ(0, 50, 133, 30, operations[3].rect);
  // The line inside the block (with the text "BLOCK") (we cannot reliably test
  // the size of this rectangle, as it varies across platforms):
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[4].type);
}

TEST_P(PrintContextTest, LinkTargetUnderInInlines) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
      "<span><b><i><img style='width: 40px; height: 40px'><br>" +
      InlineHtmlForLink("http://www.google3.com",
                        "<img style='width: 144px; height: 40px'>") +
      "</i></b></span>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(2u, operations.size());
  // The 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(0, 79, 144, 1, operations[0].rect);
  // The image:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(0, 40, 144, 40, operations[1].rect);
}

TEST_P(PrintContextTest, LinkTargetUnderInInlinesMultipleLines) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
      "<span><b><i><img style='width: 40px; height: 40px'><br>" +
      InlineHtmlForLink("http://www.google3.com",
                        "<img style='width: 144px; height: 40px'><br><img "
                        "style='width: 14px; height: 40px'>") +
      "</i></b></span>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(4u, operations.size());
  // The 'A' element on the second line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(0, 79, 144, 1, operations[0].rect);
  // The 'A' element on the third line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(0, 119, 14, 1, operations[1].rect);
  // The second image:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
  EXPECT_SKRECT_EQ(0, 40, 144, 40, operations[2].rect);
  // The third image:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[3].type);
  EXPECT_SKRECT_EQ(0, 80, 14, 40, operations[3].rect);
}

TEST_P(PrintContextTest, LinkTargetUnderInInlinesMultipleLinesCulledInline) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML("<span><b><i><br>" +
                   InlineHtmlForLink("http://www.google3.com", "xxx<br>xxx") +
                   "</i></b></span>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(3u, operations.size());
  // In this test, only check that we have rectangles. We cannot reliably test
  // their size, since it varies across platforms.
  //
  // Second line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  // Newline at the end of the second line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  // Third line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
}

TEST_P(PrintContextTest, LinkTargetRelativelyPositionedInline) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML(
      "<a style='position: relative; top: 50px; left: 50px' "
      "href='http://www.google3.com'>"
      "  <img style='width: 1px; height: 40px'>"
      "</a>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(2u, operations.size());
  // The 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 89, 1, 1, operations[0].rect);
  // The image:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(50, 50, 1, 40, operations[1].rect);
}

TEST_P(PrintContextTest, LinkTargetUnderRelativelyPositionedInline) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
        + "<span style='position: relative; top: 50px; left: 50px'><b><i><img style='width: 1px; height: 40px'><br>"
        + InlineHtmlForLink("http://www.google3.com", "<img style='width: 155px; height: 50px'>")
        + "</i></b></span>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(2u, operations.size());
  // The 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 139, 155, 1, operations[0].rect);
  // The image:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(50, 90, 155, 50, operations[1].rect);
}

TEST_P(PrintContextTest,
       LinkTargetUnderRelativelyPositionedInlineMultipleLines) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
        + "<span style='position: relative; top: 50px; left: 50px'><b><i><img style='width: 1px; height: 40px'><br>"
        + InlineHtmlForLink(
            "http://www.google3.com",
            "<img style='width: 10px; height: 50px'><br><img style='width: 155px; height: 50px'>")
        + "</i></b></span>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(4u, operations.size());
  // The 'A' element on the second line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 139, 10, 1, operations[0].rect);
  // The 'A' element on the third line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(50, 189, 155, 1, operations[1].rect);
  // The image on the second line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
  EXPECT_SKRECT_EQ(50, 90, 10, 50, operations[2].rect);
  // The image on the third line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[3].type);
  EXPECT_SKRECT_EQ(50, 140, 155, 50, operations[3].rect);
}

TEST_P(PrintContextTest,
       LinkTargetUnderRelativelyPositionedInlineMultipleLinesCulledInline) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
      +"<span style='position: relative; top: 50px; left: 50px'><b><i><br>" +
      InlineHtmlForLink("http://www.google3.com", "xxx<br>xxx") +
      "</i></b></span>");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(3u, operations.size());
  // In this test, only check that we have rectangles. We cannot reliably test
  // their size, since it varies across platforms.
  //
  // Second line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  // Newline at end of second line.
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  // Third line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
}

TEST_P(PrintContextTest, SingleLineLinkNextToWrappedLink) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(R"HTML(
    <div style="width:120px;">
      <a href="http://www.google.com/">
        <img style="width:50px; height:20px;">
      </a>
      <a href="http://www.google.com/maps/">
        <img style="width:50px; height:20px;">
        <img style="width:60px; height:20px;">
      </a>
    </div>
  )HTML");
  PrintSinglePage(canvas);
  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(6u, operations.size());
  // First 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(0, 19, 50, 1, operations[0].rect);
  // Image inside first 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(0, 0, 50, 20, operations[1].rect);
  // Second 'A' element on the first line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
  EXPECT_SKRECT_EQ(50, 19, 50, 1, operations[2].rect);
  // Second 'A' element on the second line:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[3].type);
  EXPECT_SKRECT_EQ(0, 39, 60, 1, operations[3].rect);
  // First image in the second 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[4].type);
  EXPECT_SKRECT_EQ(50, 0, 50, 20, operations[4].rect);
  // Second image in the second 'A' element:
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[5].type);
  EXPECT_SKRECT_EQ(0, 20, 60, 20, operations[5].rect);
}

TEST_P(PrintContextTest, LinkTargetSvg) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(R"HTML(
    <svg width='100' height='100'>
    <a xlink:href='http://www.w3.org'><rect x='20' y='20' width='50'
    height='50'/></a>
    <text x='10' y='90'><a
    xlink:href='http://www.google.com'><tspan>google</tspan></a></text>
    </svg>
  )HTML");
  PrintSinglePage(canvas);

  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(2u, operations.size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(20, 20, 50, 50, operations[0].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_EQ(10, operations[1].rect.x());
  EXPECT_GE(90, operations[1].rect.y());
}

TEST_P(PrintContextTest, LinkedTarget) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  GetDocument().SetBaseURLOverride(KURL("http://a.com/"));
  // Careful about locations, the page is 800x600 and only one page is printed.
  SetBodyInnerHTML(
      // Generates a Link_Named_Dest_Key annotation.
      AbsoluteBlockHtmlForLink(50, 60, 10, 10, "#fragment") +
      // Generates no annotation.
      AbsoluteBlockHtmlForLink(50, 160, 10, 10, "#not-found") +
      // Generates a Link_Named_Dest_Key annotation.
      AbsoluteBlockHtmlForLink(50, 260, 10, 10, u"#\u00F6") +
      // Generates a Link_Named_Dest_Key annotation.
      AbsoluteBlockHtmlForLink(50, 360, 10, 10, "#") +
      // Generates a Link_Named_Dest_Key annotation.
      AbsoluteBlockHtmlForLink(50, 460, 10, 10, "#t%6Fp") +
      // Generates a Define_Named_Dest_Key annotation.
      HtmlForAnchor(450, 60, "fragment", "fragment") +
      // Generates no annotation.
      HtmlForAnchor(450, 160, "fragment-not-used", "fragment-not-used")
      // Generates a Define_Named_Dest_Key annotation.
      + HtmlForAnchor(450, 260, u"\u00F6", "O")
      // TODO(1117212): The escaped version currently takes precedence.
      // Generates a Define_Named_Dest_Key annotation.
      //+ HtmlForAnchor(450, 360, "%C3%B6", "O2")
  );
  PrintSinglePage(canvas);

  Vector<MockPageContextCanvas::Operation> operations =
      canvas.RecordedOperations();
  ASSERT_EQ(8u, operations.size());
  // The DrawRect operations come from a stable iterator.
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 60, 10, 10, operations[0].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(50, 260, 10, 10, operations[1].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
  EXPECT_SKRECT_EQ(50, 360, 10, 10, operations[2].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[3].type);
  EXPECT_SKRECT_EQ(50, 460, 10, 10, operations[3].rect);

  // The DrawPoint operations come from an unstable iterator.
  std::sort(operations.begin() + 4, operations.begin() + 8,
            [](const MockPageContextCanvas::Operation& a,
               const MockPageContextCanvas::Operation& b) {
              return std::pair(a.rect.x(), a.rect.y()) <
                     std::pair(b.rect.x(), b.rect.y());
            });
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, operations[4].type);
  EXPECT_SKRECT_EQ(0, 0, 0, 0, operations[4].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, operations[5].type);
  EXPECT_SKRECT_EQ(0, 0, 0, 0, operations[5].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, operations[6].type);
  EXPECT_SKRECT_EQ(450, 60, 0, 0, operations[6].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, operations[7].type);
  EXPECT_SKRECT_EQ(450, 260, 0, 0, operations[7].rect);
}

TEST_P(PrintContextTest, EmptyLinkedTarget) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  GetDocument().SetBaseURLOverride(KURL("http://a.com/"));
  SetBodyInnerHTML(AbsoluteBlockHtmlForLink(50, 60, 70, 80, "#fragment") +
                   HtmlForAnchor(250, 260, "fragment", ""));
  PrintSinglePage(canvas);

  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(2u, operations.size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 60, 70, 80, operations[0].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, operations[1].type);
  EXPECT_SKRECT_EQ(250, 260, 0, 0, operations[1].rect);
}

TEST_P(PrintContextTest, LinkTargetBoundingBox) {
  testing::NiceMock<MockPageContextCanvas> canvas;
  SetBodyInnerHTML(
      AbsoluteBlockHtmlForLink(50, 60, 70, 20, "http://www.google.com",
                               "<img style='width: 200px; height: 100px'>"));
  PrintSinglePage(canvas);

  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(1u, operations.size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 60, 200, 100, operations[0].rect);
}

TEST_P(PrintContextTest, LinkInFragmentedContainer) {
  SetBodyInnerHTML(R"HTML(
    <style>
      body {
        margin: 0;
        line-height: 50px;
        orphans: 1;
        widows: 1;
      }
    </style>
    <div style="height:calc(100vh - 90px);"></div>
    <div>
      <a href="http://www.google.com">link 1</a><br>
      <!-- Page break here. -->
      <a href="http://www.google.com">link 2</a><br>
      <a href="http://www.google.com">link 3</a><br>
    </div>
  )HTML");

  testing::NiceMock<MockPageContextCanvas> first_page_canvas;
  gfx::Rect page_rect = PrintSinglePage(first_page_canvas, 0);
  Vector<MockPageContextCanvas::Operation> operations =
      first_page_canvas.RecordedOperations();

  // TODO(crbug.com/1392701): Should be 1.
  ASSERT_EQ(operations.size(), 3u);

  const auto& page1_link1 = operations[0];
  EXPECT_EQ(page1_link1.type, MockPageContextCanvas::kDrawRect);
  EXPECT_GE(page1_link1.rect.y(), page_rect.height() - 90);
  EXPECT_LE(page1_link1.rect.bottom(), page_rect.height() - 40);

  testing::NiceMock<MockPageContextCanvas> second_page_canvas;
  page_rect = PrintSinglePage(second_page_canvas, 1);
  operations = second_page_canvas.RecordedOperations();

  // TODO(crbug.com/1392701): Should be 2.
  ASSERT_EQ(operations.size(), 3u);
  // TODO(crbug.com/1392701): Should be operations[0]
  const auto& page2_link1 = operations[1];
  // TODO(crbug.com/1392701): Should be operations[1]
  const auto& page2_link2 = operations[2];

  EXPECT_EQ(page2_link1.type, MockPageContextCanvas::kDrawRect);
  EXPECT_GE(page2_link1.rect.y(), page_rect.y());
  EXPECT_LE(page2_link1.rect.bottom(), page_rect.y() + 50);
  EXPECT_EQ(page2_link2.type, MockPageContextCanvas::kDrawRect);
  EXPECT_GE(page2_link2.rect.y(), page_rect.y() + 50);
  EXPECT_LE(page2_link2.rect.bottom(), page_rect.y() + 100);
}

TEST_P(PrintContextTest, LinkedTargetSecondPage) {
  SetBodyInnerHTML(R"HTML(
    <a style="display:block; width:33px; height:33px;" href="#nextpage"></a>
    <div style="break-before:page;"></div>
    <div id="nextpage" style="margin-top:50px; width:100px; height:100px;"></div>
  )HTML");

  // The link is on the first page.
  testing::NiceMock<MockPageContextCanvas> first_canvas;
  PrintSinglePage(first_canvas, 0);
  const Vector<MockPageContextCanvas::Operation>* operations =
      &first_canvas.RecordedOperations();
  ASSERT_EQ(1u, operations->size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, (*operations)[0].type);
  EXPECT_SKRECT_EQ(0, 0, 33, 33, (*operations)[0].rect);

  // The destination is on the second page.
  testing::NiceMock<MockPageContextCanvas> second_canvas;
  PrintSinglePage(second_canvas, 1);
  operations = &second_canvas.RecordedOperations();
  ASSERT_EQ(1u, operations->size());
  EXPECT_EQ(MockPageContextCanvas::kDrawPoint, (*operations)[0].type);
  EXPECT_SKRECT_EQ(0, 50, 0, 0, (*operations)[0].rect);
}

// Here are a few tests to check that shrink to fit doesn't mess up page count.

TEST_P(PrintContextTest, ScaledVerticalRL1) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:vertical-rl; }</style>
    <div style="break-after:page;">x</div>
    <div style="inline-size:10000px; block-size:10px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(2, page_count);
}

TEST_P(PrintContextTest, ScaledVerticalRL2) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:vertical-rl; }</style>
    <div style="break-after:page;">x</div>
    <div style="inline-size:10000px; block-size:500px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(2, page_count);
}

TEST_P(PrintContextTest, ScaledVerticalRL3) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:vertical-rl; }</style>
    <div style="break-after:page;">x</div>
    <div style="break-after:page; inline-size:10000px; block-size:10px;"></div>
    <div style="inline-size:10000px; block-size:10px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(3, page_count);
}

TEST_P(PrintContextTest, ScaledVerticalLR1) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:vertical-lr; }</style>
    <div style="break-after:page;">x</div>
    <div style="inline-size:10000px; block-size:10px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(2, page_count);
}

TEST_P(PrintContextTest, ScaledVerticalLR2) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:vertical-lr; }</style>
    <div style="break-after:page;">x</div>
    <div style="inline-size:10000px; block-size:500px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(2, page_count);
}

TEST_P(PrintContextTest, ScaledVerticalLR3) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:vertical-lr; }</style>
    <div style="break-after:page;">x</div>
    <div style="break-after:page; inline-size:10000px; block-size:10px;"></div>
    <div style="inline-size:10000px; block-size:10px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(3, page_count);
}

TEST_P(PrintContextTest, ScaledHorizontalTB1) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:horizontal-tb; }</style>
    <div style="break-after:page;">x</div>
    <div style="inline-size:10000px; block-size:10px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(2, page_count);
}

TEST_P(PrintContextTest, ScaledHorizontalTB2) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:horizontal-tb; }</style>
    <div style="break-after:page;">x</div>
    <div style="inline-size:10000px; block-size:500px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(2, page_count);
}

TEST_P(PrintContextTest, ScaledHorizontalTB3) {
  SetBodyInnerHTML(R"HTML(
    <style>html { writing-mode:horizontal-tb; }</style>
    <div style="break-after:page;">x</div>
    <div style="break-after:page; inline-size:10000px; block-size:10px;"></div>
    <div style="inline-size:10000px; block-size:10px;"></div>
  )HTML");

  int page_count = PrintContext::NumberOfPages(GetDocument().GetFrame(),
                                               gfx::SizeF(500, 500));
  EXPECT_EQ(3, page_count);
}

TEST_P(PrintContextTest, SvgMarkersOnMultiplePages) {
  SetBodyInnerHTML(R"HTML(
    <style>
      svg {
        display: block;
      }
    </style>
    <svg style="break-after: page">
      <marker id="m1" markerUnits=
```