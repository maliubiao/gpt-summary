Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a test file for the printing functionality within the Chromium Blink rendering engine.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Functionality:** The file name `print_context_test.cc` immediately suggests that this file contains tests for the `PrintContext` class. This class is responsible for handling the process of rendering web content for printing.

2. **Analyze the Test Structure:** The code uses the Google Test framework (`TEST_P`, `EXPECT_CALL`, `ASSERT_EQ`, etc.). This indicates that the file is designed to verify the behavior of the `PrintContext` under various conditions.

3. **Examine Individual Tests:** Go through each `TEST_P` function and understand what it's testing. Look for patterns and keywords related to printing.

    * **`SimpleTest`:**  Tests basic printing of SVG markers. This reveals a core function of `PrintContext`: handling vector graphics.
    * **`WithSubframe` and `WithScrolledSubframe`:**  These test scenarios involving iframes and how the printing process handles content within them, including scrolling. This points to the `PrintContext`'s ability to traverse frame hierarchies.
    * **`BasicPrintPageLayout`:** Focuses on how the `PrintContext` adjusts the page layout (width) for printing and reverts it afterwards. This is a critical aspect of preparing content for printing.
    * **`Canvas2DBeforePrint`, `Canvas2DPixelated`, `Canvas2DAutoFlushingSuppressed`, `Canvas2DAutoFlushBeforePrinting`:** These tests specifically target the interaction between the `PrintContext` and the HTML5 `<canvas>` element. They cover scenarios like executing JavaScript's `beforeprint` event, handling `image-rendering: pixelated`, and managing canvas flushing behavior during printing (especially in the context of vector vs. raster printing).
    * **`PrintContextAcceleratedCanvasTest` and `PrintContextOOPRCanvasTest`:** These variations test the `<canvas>` printing behavior when hardware acceleration or out-of-process rasterization is enabled. This shows that the `PrintContext` needs to handle different rendering pipelines.
    * **`Canvas2DFlushForImageListener` and `Canvas2DNoFlushForImageListener`:** These delve deeper into how changes to a source canvas during the `beforeprint` event affect the printing mode (vector or raster).
    * **`SubframePrintPageLayout` (DISABLED):**  While disabled, the name suggests it tests layout adjustments for subframes specifically. The "DISABLED" indicates a known issue or complexity in this area.
    * **`TransparentRootBackgroundWithShouldPrintBackgroundDisabled/Enabled` and `WhiteRootBackgroundWithShouldPrintBackgroundDisabled/Enabled`:** These test how the `PrintContext` handles the document's background color in conjunction with the "Print background graphics" setting.

4. **Identify Relationships to Web Technologies:**  Based on the tests, identify the connections to JavaScript, HTML, and CSS.

    * **JavaScript:** The `beforeprint` event is a clear connection. The tests modify canvas content using JavaScript within this event handler.
    * **HTML:** The tests manipulate the DOM using methods like `SetBodyInnerHTML` and create elements like `<canvas>`, `<iframe>`, and `<style>`.
    * **CSS:** Tests involve inline styles, embedded styles (`<style>`), and CSS properties like `image-rendering`, `background`, and layout-related properties (width, height, margin, etc.).

5. **Infer Logical Reasoning (Input/Output):** For tests using `EXPECT_CALL`,  the input is the state of the DOM and the printing parameters, and the output is the expected calls to the mock canvas object (`MockPageContextCanvas`), including the type of operation and the drawn geometry. For example, a test might set up an HTML structure with a rectangle and then expect `onDrawRect` to be called with the corresponding coordinates and dimensions.

6. **Identify Potential User/Programming Errors:** The tests related to canvas flushing and the `beforeprint` event highlight potential issues where JavaScript code might unexpectedly trigger rasterization or interfere with vector printing. Incorrectly setting the "Print background graphics" option could also lead to unexpected output.

7. **Trace User Operations:** Think about the steps a user would take to trigger the printing process. This involves opening a webpage, potentially interacting with it (scrolling, etc.), and then initiating the print action (e.g., through the browser menu or a keyboard shortcut).

8. **Synthesize a Summary:** Combine the observations from the previous steps to create a concise description of the file's functionality. Emphasize the key areas being tested.

9. **Address Part 2 of the Request:**  Since this is part 2 of the request, focus specifically on summarizing the *accumulated* knowledge about the file's purpose from both parts.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the individual test names. It's important to look at the *code within* the tests to understand the underlying behavior being verified.
*  Don't just list the tests; group thematically to provide a more coherent summary. For example, group all the canvas-related tests together.
* Be precise about the web technologies involved. Don't just say "web page stuff"; specifically mention JavaScript, HTML, and CSS.
*  Ensure the explanation of user operations is realistic and covers common scenarios.
* For the input/output examples, pick a simple and illustrative test case.

By following this systematic approach, one can effectively analyze and summarize the functionality of the provided test code.
好的，根据您提供的代码片段，我们可以归纳一下 `blink/renderer/core/page/print_context_test.cc` 文件的功能：

**总体功能归纳:**

这个测试文件主要用于测试 Blink 渲染引擎中 `PrintContext` 类的功能。`PrintContext` 负责将网页内容渲染成适合打印的格式。  这些测试涵盖了 `PrintContext` 在处理各种网页元素、布局、以及与 JavaScript 交互时的行为。

**具体功能点总结:**

* **基本打印流程测试:** 测试 `PrintContext` 能否正确地将简单的内容绘制到模拟的打印画布上，例如 SVG 标记。
* **子框架（iframe）打印测试:**  测试 `PrintContext` 如何处理包含子框架的页面，包括子框架的定位、裁剪和滚动状态。
* **页面布局调整测试:** 验证 `PrintContext` 在开始打印时如何调整主框架的布局（例如，根据纸张大小缩小页面宽度），并在打印结束后恢复原始布局。  也测试了子框架的布局在打印时的行为。
* **Canvas 元素打印测试:** 这是测试的重点，涵盖了多种场景：
    * **`beforeprint` 事件交互:** 测试在打印前通过 JavaScript `beforeprint` 事件修改 Canvas 内容，并验证这些修改是否被正确地绘制出来。
    * **`image-rendering: pixelated` 样式:** 测试 Canvas 是否能根据 CSS 属性 `image-rendering: pixelated` 选择合适的绘制方式。
    * **Canvas 自动刷新抑制:**  测试在打印过程中，为了支持矢量打印，`PrintContext` 如何抑制 Canvas 的自动刷新机制，以避免不必要的位图转换。
    * **硬件加速和 OOP-R Canvas 的支持:**  测试在启用硬件加速或使用 Out-of-Process Rasterization (OOP-R) 时，`PrintContext` 对 Canvas 元素的处理。
    * **Canvas 状态变化监听:** 测试当作为 `drawImage` 源的 Canvas 内容发生变化时，是否会触发 Canvas 的刷新，并影响打印模式（矢量或位图）。
    * **打印前 Canvas 的自动刷新:** 测试在打印开始前 Canvas 由于内存限制等原因自动刷新后，对后续矢量打印的影响。
* **背景打印控制:** 测试通过 `WebSettings::SetShouldPrintBackgrounds` 设置是否打印背景色，并验证 `PrintContext` 是否按照设置工作。

**与 JavaScript, HTML, CSS 的关系及举例:**

* **JavaScript:**
    * **功能关系:**  测试利用 JavaScript 的 `beforeprint` 事件在打印前动态修改 Canvas 的内容。
    * **举例说明:**  在 `Canvas2DBeforePrint` 测试中，JavaScript 代码获取 Canvas 上下文，并使用 `fillRect` 方法绘制矩形。测试验证这些矩形是否被绘制到模拟的打印画布上。
* **HTML:**
    * **功能关系:**  测试依赖于 HTML 结构来创建需要打印的内容，例如使用 `<iframe>` 创建子框架，使用 `<canvas>` 创建画布元素。
    * **举例说明:** 在 `WithSubframe` 测试中，HTML 代码创建了一个包含 `<iframe>` 的页面。测试验证 `PrintContext` 是否能正确地渲染子框架中的链接。
* **CSS:**
    * **功能关系:**  测试中使用了 CSS 样式来影响元素的渲染，例如设置 Canvas 的 `image-rendering` 属性或设置 Body 的背景色。
    * **举例说明:** 在 `Canvas2DPixelated` 测试中，CSS 样式 `image-rendering: pixelated` 被应用于 Canvas 元素。测试验证 `PrintContext` 是否因此调用了 `onDrawImageRect2` 方法，表明使用了位图绘制。

**逻辑推理的假设输入与输出:**

以 `SimpleTest` 为例：

* **假设输入:**  包含两个 SVG `<marker>` 定义和一个使用这些 marker 的 `<path>` 的 HTML 字符串。
* **预期输出:**  模拟的打印画布 `first_page_canvas` 和 `second_page_canvas` 的 `didTranslate` 和 `onDrawRect` 方法被以特定的参数调用。例如，`first_page_canvas` 的 `didTranslate` 被调用一次，参数为 (1, 0)，`onDrawRect` 被调用一次，绘制一个 100x75 的矩形。`second_page_canvas` 的 `didTranslate` 被调用一次，参数为 (2, 0)，`onDrawRect` 被调用一次，绘制一个 50x25 的矩形。

**涉及用户或编程常见的使用错误:**

* **Canvas 在 `beforeprint` 事件中的意外行为:** 用户可能会在 `beforeprint` 事件中执行大量耗时的 Canvas 操作，导致打印性能下降或出现意外的渲染结果。例如，没有意识到某些 Canvas 操作可能会触发刷新，导致无法进行矢量打印。
* **不理解打印背景设置的影响:** 用户可能期望打印出背景色或背景图片，但忘记在浏览器打印设置中启用 "打印背景图形"，导致打印结果缺少背景。
* **子框架布局的误解:** 开发者可能假设子框架的打印布局会与主框架完全一致，但实际上 `PrintContext` 对子框架的处理可能有所不同，例如在某些情况下不会调整子框架的布局。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个包含复杂元素（例如，Canvas、iframe、SVG）的网页。**
2. **用户尝试打印该网页（通常通过浏览器菜单 "文件" -> "打印"，或者使用快捷键如 Ctrl+P 或 Cmd+P）。**
3. **浏览器内部开始构建打印预览或直接进行打印。**
4. **Blink 渲染引擎的 `PrintContext` 类被激活，负责将网页内容转换为打印格式。**
5. **在 `PrintContext` 的处理过程中，会遍历 DOM 树，处理各种元素，并调用相应的绘制方法。**
6. **如果页面包含 Canvas 元素，`PrintContext` 会根据 Canvas 的状态（例如，是否被 JavaScript 修改过、是否使用了硬件加速）选择合适的打印方式（矢量或位图）。**
7. **如果页面包含 iframe，`PrintContext` 需要处理子框架的布局和内容。**
8. **`print_context_test.cc` 文件中的测试用例模拟了上述步骤中的各种场景，以验证 `PrintContext` 的行为是否符合预期。**

**作为第 2 部分的归纳总结:**

综合您提供的代码片段以及您提到这是第 2 部分，可以推断出第 1 部分可能包含了一些基础的 `PrintContext` 测试或相关的辅助代码。

**总而言之，`blink/renderer/core/page/print_context_test.cc` 文件的主要功能是全面测试 Blink 渲染引擎中 `PrintContext` 类的各种功能，特别是涉及到 Canvas 元素、子框架以及与 JavaScript 和 CSS 交互的打印场景，以确保打印功能的正确性和稳定性。**

### 提示词
```
这是目录为blink/renderer/core/page/print_context_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
"userSpaceOnUse" overflow="visible">
        <rect width="100" height="75" transform="translate(1,0)"/>
      </marker>
      <path d="M0,0h1" marker-start="url(#m1)"/>
    </svg>
    <svg>
      <marker id="m2" markerUnits="userSpaceOnUse" overflow="visible">
        <rect width="50" height="25" transform="translate(2,0)"/>
      </marker>
      <path d="M0,0h1" marker-start="url(#m2)"/>
    </svg>
  )HTML");

  class MockCanvas : public SkCanvas {
   public:
    MockCanvas() : SkCanvas(kPageWidth, kPageHeight) {}

    MOCK_METHOD2(onDrawRect, void(const SkRect&, const SkPaint&));
    MOCK_METHOD2(didTranslate, void(SkScalar, SkScalar));
  };

  MockCanvas first_page_canvas;
  EXPECT_CALL(first_page_canvas, didTranslate(1, 0)).Times(1);
  EXPECT_CALL(first_page_canvas, onDrawRect(SkRect::MakeWH(100, 75), _))
      .Times(1);
  PrintSinglePage(first_page_canvas, 0);

  MockCanvas second_page_canvas;
  EXPECT_CALL(second_page_canvas, didTranslate(2, 0)).Times(1);
  EXPECT_CALL(second_page_canvas, onDrawRect(SkRect::MakeWH(50, 25), _))
      .Times(1);
  PrintSinglePage(second_page_canvas, 1);
}

INSTANTIATE_PAINT_TEST_SUITE_P(PrintContextFrameTest);

TEST_P(PrintContextFrameTest, WithSubframe) {
  GetDocument().SetBaseURLOverride(KURL("http://a.com/"));
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar { display: none }</style>
    <iframe src='http://b.com/' width='500' height='500'
     style='border-width: 5px; margin: 5px; position: absolute; top: 90px;
    left: 90px'></iframe>
  )HTML");
  SetChildFrameHTML(
      AbsoluteBlockHtmlForLink(50, 60, 70, 80, "#fragment") +
      AbsoluteBlockHtmlForLink(150, 160, 170, 180, "http://www.google.com") +
      AbsoluteBlockHtmlForLink(250, 260, 270, 280,
                               "http://www.google.com#fragment"));

  MockPageContextCanvas canvas;
  PrintSinglePage(canvas);

  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(2u, operations.size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(250, 260, 170, 180, operations[0].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(350, 360, 270, 280, operations[1].rect);
}

TEST_P(PrintContextFrameTest, WithScrolledSubframe) {
  GetDocument().SetBaseURLOverride(KURL("http://a.com/"));
  SetBodyInnerHTML(R"HTML(
    <style>::-webkit-scrollbar { display: none }</style>
    <iframe src='http://b.com/' width='500' height='500'
     style='border-width: 5px; margin: 5px; position: absolute; top: 90px;
    left: 90px'></iframe>
  )HTML");
  SetChildFrameHTML(
      AbsoluteBlockHtmlForLink(10, 10, 20, 20, "http://invisible.com") +
      AbsoluteBlockHtmlForLink(50, 60, 70, 80, "http://partly.visible.com") +
      AbsoluteBlockHtmlForLink(150, 160, 170, 180, "http://www.google.com") +
      AbsoluteBlockHtmlForLink(250, 260, 270, 280,
                               "http://www.google.com#fragment") +
      AbsoluteBlockHtmlForLink(850, 860, 70, 80,
                               "http://another.invisible.com"));

  ChildDocument().domWindow()->scrollTo(100, 100);

  MockPageContextCanvas canvas;
  PrintSinglePage(canvas);

  const Vector<MockPageContextCanvas::Operation>& operations =
      canvas.RecordedOperations();
  ASSERT_EQ(3u, operations.size());
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[0].type);
  EXPECT_SKRECT_EQ(50, 60, 70, 80,
                   operations[0].rect);  // FIXME: the rect should be clipped.
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[1].type);
  EXPECT_SKRECT_EQ(150, 160, 170, 180, operations[1].rect);
  EXPECT_EQ(MockPageContextCanvas::kDrawRect, operations[2].type);
  EXPECT_SKRECT_EQ(250, 260, 270, 280, operations[2].rect);
}

// This tests that we properly resize and re-layout pages for printing.
TEST_P(PrintContextFrameTest, BasicPrintPageLayout) {
  gfx::SizeF page_size(400, 400);
  float maximum_shrink_ratio = 1.1;
  auto* node = GetDocument().documentElement();

  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size),
                                          maximum_shrink_ratio);
  EXPECT_EQ(node->OffsetWidth(), 400);
  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(node->OffsetWidth(), 800);

  SetBodyInnerHTML(R"HTML(
      <div style='border: 0px; margin: 0px; background-color: #0000FF;
      width:800px; height:400px'></div>)HTML");
  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size),
                                          maximum_shrink_ratio);
  EXPECT_EQ(node->OffsetWidth(), 440);
  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(node->OffsetWidth(), 800);
}

TEST_P(PrintContextTest, Canvas2DBeforePrint) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<canvas id='c' width=100 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(
      "window.addEventListener('beforeprint', (ev) => {"
      "const ctx = document.getElementById('c').getContext('2d');"
      "ctx.fillRect(0, 0, 10, 10);"
      "ctx.fillRect(50, 50, 10, 10);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  EXPECT_CALL(canvas, onDrawRect(_, _)).Times(testing::AtLeast(2));

  PrintSinglePage(canvas);
}

TEST_P(PrintContextTest, Canvas2DPixelated) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML(
      "<canvas id='c' style='image-rendering: pixelated' "
      "width=100 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(
      "window.addEventListener('beforeprint', (ev) => {"
      "const ctx = document.getElementById('c').getContext('2d');"
      "ctx.fillRect(0, 0, 10, 10);"
      "ctx.fillRect(50, 50, 10, 10);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  EXPECT_CALL(canvas, onDrawImageRect2(_, _, _, _, _, _));

  PrintSinglePage(canvas);
}

TEST_P(PrintContextTest, Canvas2DAutoFlushingSuppressed) {
  // When printing, we're supposed to make a best effore to avoid flushing
  // a canvas's PaintOps in order to support vector printing whenever possible.
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<canvas id='c' width=200 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  // Note: source_canvas is 10x10, which consumes 400 bytes for pixel data,
  // which is larger than the 100 limit set in PrintContextTest::SetUp().
  script_element->setTextContent(
      "source_canvas = document.createElement('canvas');"
      "source_canvas.width = 10;"
      "source_canvas.height = 10;"
      "source_ctx = source_canvas.getContext('2d');"
      "source_ctx.fillRect(1000, 0, 1, 1);"
      "window.addEventListener('beforeprint', (ev) => {"
      "  ctx = document.getElementById('c').getContext('2d');"
      "  ctx.fillStyle = 'green';"
      "  ctx.fillRect(0, 0, 100, 100);"
      "  ctx.drawImage(source_canvas, 101, 0);"
      // Next op normally triggers an auto-flush due to exceeded memory limit
      // but in this case, the auto-flush is suppressed.
      "  ctx.fillRect(0, 0, 1, 1);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  // Verify that the auto-flush was suppressed by checking that the first
  // fillRect call flowed through to 'canvas'.
  testing::Sequence s;
  // The first fillRect call
  EXPECT_CALL(canvas, onDrawRect(_, _))
      .Times(testing::Exactly(1))
      .InSequence(s);
  // The drawImage call
  EXPECT_CALL(canvas, onDrawImageRect2(_, _, _, _, _, _)).InSequence(s);
  // The secondFillRect
  EXPECT_CALL(canvas, onDrawRect(_, _)).InSequence(s);

  PrintSinglePage(canvas);
}

// For testing printing behavior when 2d canvases are gpu-accelerated.
class PrintContextAcceleratedCanvasTest : public PrintContextTest {
 public:
  void SetUp() override {
    accelerated_canvas_scope_ =
        std::make_unique<ScopedAccelerated2dCanvasForTest>(true);
    test_context_provider_ = viz::TestContextProvider::Create();
    InitializeSharedGpuContextGLES2(test_context_provider_.get());

    PrintContextTest::SetUp();

    GetDocument().GetSettings()->SetAcceleratedCompositingEnabled(true);
  }

  void TearDown() override {
    // Call base class TeardDown first to ensure Canvas2DLayerBridge is
    // destroyed before the TestContextProvider.
    PrintContextTest::TearDown();

    SharedGpuContext::Reset();
    test_context_provider_ = nullptr;
    accelerated_canvas_scope_ = nullptr;
  }

 private:
  scoped_refptr<viz::TestContextProvider> test_context_provider_;
  std::unique_ptr<ScopedAccelerated2dCanvasForTest> accelerated_canvas_scope_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(PrintContextAcceleratedCanvasTest);

TEST_P(PrintContextAcceleratedCanvasTest, Canvas2DBeforePrint) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<canvas id='c' width=100 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(
      "window.addEventListener('beforeprint', (ev) => {"
      "const ctx = document.getElementById('c').getContext('2d');"
      "ctx.fillRect(0, 0, 10, 10);"
      "ctx.fillRect(50, 50, 10, 10);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  // 2 fillRects.
  EXPECT_CALL(canvas, onDrawRect(_, _)).Times(testing::Exactly(2));

  PrintSinglePage(canvas);
}

namespace {

class AcceleratedCompositingTestPlatform
    : public blink::TestingPlatformSupport {
 public:
  bool IsGpuCompositingDisabled() const override { return false; }
};

}  // namespace

// For testing printing behavior when 2d canvas contexts use oop rasterization.
class PrintContextOOPRCanvasTest : public PrintContextTest {
 public:
  void SetUp() override {
    accelerated_canvas_scope_ =
        std::make_unique<ScopedAccelerated2dCanvasForTest>(true);
    std::unique_ptr<viz::TestGLES2Interface> gl_context =
        std::make_unique<viz::TestGLES2Interface>();
    gl_context->set_gpu_rasterization(true);
    std::unique_ptr<viz::TestContextSupport> context_support =
        std::make_unique<viz::TestContextSupport>();
    std::unique_ptr<viz::TestRasterInterface> raster_interface =
        std::make_unique<viz::TestRasterInterface>();
    test_context_provider_ = base::MakeRefCounted<viz::TestContextProvider>(
        std::move(context_support), std::move(gl_context),
        std::move(raster_interface),
        /*shared_image_interface=*/nullptr,
        /*support_locking=*/false);

    InitializeSharedGpuContextGLES2(test_context_provider_.get());

    PrintContextTest::SetUp();
    accelerated_compositing_scope_ = std::make_unique<
        ScopedTestingPlatformSupport<AcceleratedCompositingTestPlatform>>();

    GetDocument().GetSettings()->SetAcceleratedCompositingEnabled(true);
  }

  void TearDown() override {
    // Call base class TeardDown first to ensure Canvas2DLayerBridge is
    // destroyed before the TestContextProvider.
    accelerated_compositing_scope_ = nullptr;
    test_context_provider_ = nullptr;
    SharedGpuContext::Reset();
    PrintContextTest::TearDown();
    accelerated_canvas_scope_ = nullptr;
  }

 private:
  scoped_refptr<viz::TestContextProvider> test_context_provider_;
  std::unique_ptr<ScopedAccelerated2dCanvasForTest> accelerated_canvas_scope_;
  std::unique_ptr<
      ScopedTestingPlatformSupport<AcceleratedCompositingTestPlatform>>
      accelerated_compositing_scope_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(PrintContextOOPRCanvasTest);

TEST_P(PrintContextOOPRCanvasTest, Canvas2DBeforePrint) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<canvas id='c' width=100 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(
      "window.addEventListener('beforeprint', (ev) => {"
      "const ctx = document.getElementById('c').getContext('2d');"
      "ctx.fillRect(0, 0, 10, 10);"
      "ctx.fillRect(50, 50, 10, 10);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  // 2 fillRects.
  EXPECT_CALL(canvas, onDrawRect(_, _)).Times(testing::Exactly(2));

  PrintSinglePage(canvas);
}

TEST_P(PrintContextOOPRCanvasTest, Canvas2DFlushForImageListener) {
  base::test::ScopedFeatureList feature_list_;
  // Verifies that a flush triggered by a change to a source canvas results
  // in printing falling out of vector print mode.

  // This test needs to run with CanvasOopRasterization enabled in order to
  // exercise the FlushForImageListener code path in CanvasResourceProvider.
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<canvas id='c' width=200 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(
      "source_canvas = document.createElement('canvas');"
      "source_canvas.width = 5;"
      "source_canvas.height = 5;"
      "source_ctx = source_canvas.getContext('2d', {willReadFrequently: "
      "'false'});"
      "source_ctx.fillRect(0, 0, 1, 1);"
      "image_data = source_ctx.getImageData(0, 0, 5, 5);"
      "window.addEventListener('beforeprint', (ev) => {"
      "  ctx = document.getElementById('c').getContext('2d');"
      "  ctx.drawImage(source_canvas, 0, 0);"
      // Touching source_ctx forces a flush of both contexts, which cancels
      // vector printing.
      "  source_ctx.putImageData(image_data, 0, 0);"
      "  ctx.fillRect(0, 0, 1, 1);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  // Verify that the auto-flush caused the canvas printing to fall out of
  // vector mode.
  testing::Sequence s;
  // The bitmap blit
  EXPECT_CALL(canvas, onDrawImageRect2(_, _, _, _, _, _)).InSequence(s);
  // The fill rect in the event listener should leave no trace here because
  // it is supposed to be included in the canvas blit.
  EXPECT_CALL(canvas, onDrawRect(_, _))
      .Times(testing::Exactly(0))
      .InSequence(s);

  PrintSinglePage(canvas);
}

TEST_P(PrintContextOOPRCanvasTest, Canvas2DNoFlushForImageListener) {
  // Verifies that a the canvas printing stays in vector mode after a
  // canvas to canvas drawImage, as long as the source canvas is not
  // touched afterwards.
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<canvas id='c' width=200 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  script_element->setTextContent(
      "source_canvas = document.createElement('canvas');"
      "source_canvas.width = 5;"
      "source_canvas.height = 5;"
      "source_ctx = source_canvas.getContext('2d');"
      "source_ctx.fillRect(0, 0, 1, 1);"
      "window.addEventListener('beforeprint', (ev) => {"
      "  ctx = document.getElementById('c').getContext('2d');"
      "  ctx.fillStyle = 'green';"
      "  ctx.fillRect(0, 0, 100, 100);"
      "  ctx.drawImage(source_canvas, 0, 0, 5, 5, 101, 0, 10, 10);"
      "  ctx.fillRect(0, 0, 1, 1);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  // Verify that the auto-flush caused the canvas printing to fall out of
  // vector mode.
  testing::Sequence s;
  // The fillRect call
  EXPECT_CALL(canvas, onDrawRect(_, _))
      .Times(testing::Exactly(1))
      .InSequence(s);
  // The drawImage
  EXPECT_CALL(canvas, onDrawImageRect2(_, _, _, _, _, _)).InSequence(s);
  // The fill rect after the drawImage
  EXPECT_CALL(canvas, onDrawRect(_, _))
      .Times(testing::Exactly(1))
      .InSequence(s);

  PrintSinglePage(canvas);
}

TEST_P(PrintContextTest, Canvas2DAutoFlushBeforePrinting) {
  // This test verifies that if an autoflush is triggered before printing,
  // and the canvas is not cleared in the beforeprint handler, then the canvas
  // cannot be vector printed.
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<canvas id='c' width=200 height=100></canvas>");
  GetDocument().GetSettings()->SetScriptEnabled(true);
  Element* const script_element =
      GetDocument().CreateRawElement(html_names::kScriptTag);
  // Note: source_canvas is 20x20, which consumes 1600 bytes for pixel data,
  // which is larger than the 1KB limit set in PrintContextTest::SetUp().
  script_element->setTextContent(
      "source_canvas = document.createElement('canvas');"
      "source_canvas.width = 20;"
      "source_canvas.height = 20;"
      "source_ctx = source_canvas.getContext('2d');"
      "source_ctx.fillRect(0, 0, 1, 1);"
      "ctx = document.getElementById('c').getContext('2d');"
      "ctx.fillRect(0, 0, 100, 100);"
      "ctx.drawImage(source_canvas, 101, 0);"
      // Next op triggers an auto-flush due to exceeded memory limit
      "ctx.fillRect(0, 0, 1, 1);"
      "window.addEventListener('beforeprint', (ev) => {"
      "  ctx.fillRect(0, 0, 1, 1);"
      "});");
  GetDocument().body()->AppendChild(script_element);

  // Verify that the auto-flush caused the canvas printing to fall out of
  // vector mode.
  testing::Sequence s;
  // The bitmap blit
  EXPECT_CALL(canvas, onDrawImageRect2(_, _, _, _, _, _)).InSequence(s);
  // The fill rect in the event listener should leave no trace here because
  // it is supposed to be included in the canvas blit.
  EXPECT_CALL(canvas, onDrawRect(_, _))
      .Times(testing::Exactly(0))
      .InSequence(s);

  PrintSinglePage(canvas);
}

// This tests that we don't resize or re-layout subframes in printed content.
// TODO(weili): This test fails when the iframe isn't the root scroller - e.g.
// Adding ScopedImplicitRootScrollerForTest disabler(false);
// https://crbug.com/841602.
TEST_P(PrintContextFrameTest, DISABLED_SubframePrintPageLayout) {
  SetBodyInnerHTML(R"HTML(
      <div style='border: 0px; margin: 0px; background-color: #0000FF;
      width:800px; height:400px'></div>
      <iframe id="target" src='http://b.com/' width='100%' height='100%'
      style='border: 0px; margin: 0px; position: absolute; top: 0px;
      left: 0px'></iframe>)HTML");
  gfx::SizeF page_size(400, 400);
  float maximum_shrink_ratio = 1.1;
  auto* parent = GetDocument().documentElement();
  // The child document element inside iframe.
  auto* child = ChildDocument().documentElement();
  // The iframe element in the document.
  auto* target = GetDocument().getElementById(AtomicString("target"));

  GetDocument().GetFrame()->StartPrinting(WebPrintParams(page_size),
                                          maximum_shrink_ratio);
  EXPECT_EQ(parent->OffsetWidth(), 440);
  EXPECT_EQ(child->OffsetWidth(), 800);
  EXPECT_EQ(target->OffsetWidth(), 440);
  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(parent->OffsetWidth(), 800);
  EXPECT_EQ(child->OffsetWidth(), 800);
  EXPECT_EQ(target->OffsetWidth(), 800);

  GetDocument().GetFrame()->StartPrinting(WebPrintParams());
  EXPECT_EQ(parent->OffsetWidth(), 800);
  EXPECT_EQ(child->OffsetWidth(), 800);
  EXPECT_EQ(target->OffsetWidth(), 800);
  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(parent->OffsetWidth(), 800);
  EXPECT_EQ(child->OffsetWidth(), 800);
  EXPECT_EQ(target->OffsetWidth(), 800);

  ASSERT_TRUE(ChildDocument() != GetDocument());
  ChildDocument().GetFrame()->StartPrinting(WebPrintParams(page_size),
                                            maximum_shrink_ratio);
  EXPECT_EQ(parent->OffsetWidth(), 800);
  EXPECT_EQ(child->OffsetWidth(), 400);
  EXPECT_EQ(target->OffsetWidth(), 800);
  GetDocument().GetFrame()->EndPrinting();
  EXPECT_EQ(parent->OffsetWidth(), 800);
  //  The child frame should return to the original size.
  EXPECT_EQ(child->OffsetWidth(), 800);
  EXPECT_EQ(target->OffsetWidth(), 800);
}

TEST_P(PrintContextTest,
       TransparentRootBackgroundWithShouldPrintBackgroundDisabled) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("");

  GetDocument().GetSettings()->SetShouldPrintBackgrounds(false);
  EXPECT_CALL(canvas, onDrawRect(_, _)).Times(0);
  PrintSinglePage(canvas);
}

TEST_P(PrintContextTest,
       TransparentRootBackgroundWithShouldPrintBackgroundEnabled) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("");

  GetDocument().GetSettings()->SetShouldPrintBackgrounds(true);
  EXPECT_CALL(canvas, onDrawRect(_, _)).Times(0);
  PrintSinglePage(canvas);
}

TEST_P(PrintContextTest, WhiteRootBackgroundWithShouldPrintBackgroundDisabled) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<style>body { background: white; }</style>");

  GetDocument().GetSettings()->SetShouldPrintBackgrounds(false);
  EXPECT_CALL(canvas, onDrawRect(_, _)).Times(0);
  PrintSinglePage(canvas);
}

TEST_P(PrintContextTest, WhiteRootBackgroundWithShouldPrintBackgroundEnabled) {
  MockPageContextCanvas canvas;
  SetBodyInnerHTML("<style>body { background: white; }</style>");

  GetDocument().GetSettings()->SetShouldPrintBackgrounds(true);
  // We should paint the specified white background.
  EXPECT_CALL(canvas, onDrawRect(_, _)).Times(1);
  PrintSinglePage(canvas);
}

}  // namespace blink
```