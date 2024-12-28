Response:
My thought process to analyze the given code snippet and generate the summary would be as follows:

1. **Understand the Context:** The prompt clearly states this is part 9 of 19 of the `web_frame_test.cc` file in Chromium's Blink rendering engine. This immediately tells me the primary function is testing the `WebFrame` and `WebLocalFrameImpl` classes.

2. **High-Level Overview:** I'd scan the code to identify the main testing themes. The `TEST_F` macro is the key here. I see several test names related to:
    * Selection manipulation (`MoveRangeSelectionExtent`, `SelectRange`)
    * Smart Clip functionality (`SmartClipData`)
    * Position calculations (`PositionForPointTest`)
    * Caret movement and alignment (`SelectRangeStaysHorizontallyAlignedWhenMoved`, `MoveCaretStaysHorizontallyAlignedWhenMoved`)
    * Composited selection bounds (`CompositedSelectionBoundsTest`)
    * Frame loading and document handling (`HTMLDocument`, `EmptyDocument`)
    * Caret positioning in empty documents (`MoveCaretSelectionTowardsWindowPointWithNoSelection`)
    * Spellchecking (`ReplaceMisspelledRange`)

3. **Detailed Analysis of Each Test:** I would go through each `TEST_F` block and try to understand its specific purpose. This involves looking at:
    * **Setup:** What HTML file is being loaded (`RegisterMockedHttpURLLoad`)?  What helper functions are used (`InitializeTextSelectionWebView`, `WebViewHelper`)?
    * **Actions:** What methods are being called on the `WebFrame` or `WebLocalFrameImpl` object (e.g., `MoveRangeSelectionExtent`, `SelectRange`, `ExecuteScript`, `ExtractSmartClipDataInternal`, `MoveCaretSelection`, `SetTextCheckClient`)?
    * **Assertions:** What are the `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_GE`, `EXPECT_STREQ`, `EXPECT_NEAR`, `ASSERT_EQ`, `ASSERT_NE`, `ASSERT_TRUE`, `ASSERT_FALSE` checks verifying?

4. **Identifying Relationships with Web Technologies:**  As I analyze each test, I consider how it relates to JavaScript, HTML, and CSS:
    * **JavaScript:** Tests using `ExecuteScript` clearly involve JavaScript interaction. Specifically, they are calling JavaScript functions within the loaded HTML to manipulate the DOM and selection.
    * **HTML:** The loaded HTML files (`.html`) define the structure and content being tested. The tests verify how the `WebFrame` handles different HTML elements and their arrangements.
    * **CSS:** Tests involving visual properties like positioning, scrolling, and compositing are related to CSS. The `SmartClipData` tests, for instance, extract HTML with inline styles. Tests with names like `CompositedSelectionBoundsTest` are directly about how the rendering engine handles selection in the context of CSS layout and compositing.

5. **Recognizing Logic and Assumptions:**  For tests involving selection manipulation, I look for the initial state, the actions performed, and the expected outcome. For example, in `MoveRangeSelectionExtent`, the initial selection and the subsequent selections after moving the extent to different points are explicitly asserted. The assumptions are that the underlying selection logic correctly updates the selection range based on the given coordinates.

6. **Spotting Potential User/Programming Errors:**  While the code is primarily testing, I can infer potential errors based on the test scenarios:
    * Incorrectly calculating or providing coordinates for selection manipulation.
    * Assuming selection behavior will be consistent regardless of the element's properties (e.g., `user-select: none` preventing selection).
    * Not accounting for scrolling when trying to select elements outside the viewport.

7. **Summarization (Instruction Following):** Based on the detailed analysis, I would then synthesize a concise summary addressing the specific instructions:
    * **List Functionalities:** Enumerate the key features being tested (selection, smart clip, caret movement, compositing, etc.).
    * **JavaScript/HTML/CSS Relationship with Examples:** Provide concrete examples from the tests showing the interaction with these technologies.
    * **Logical Inference (Input/Output):** Give examples of tests with clear input (actions) and expected output (assertions).
    * **User/Programming Errors:** Provide examples of potential pitfalls based on the tested scenarios.
    * **Overall Function:**  Provide a high-level summary of the file's purpose.
    * **Part of a Larger Whole:** Acknowledge that this is part 9 of 19, indicating a comprehensive testing suite.

8. **Refinement:** I would review the generated summary to ensure clarity, accuracy, and completeness, making sure it directly addresses all parts of the prompt. For instance, initially, I might just say "tests selection," but refining it to "tests the functionality of moving and manipulating text selections" is more informative.
好的，让我们来分析一下这个代码片段 (`web_frame_test.cc` 的第 9 部分)。

**功能归纳:**

这部分代码主要集中在测试 `WebFrame` 类在处理文本选择、智能剪贴板功能以及光标移动等方面的行为。它通过模拟用户交互和执行脚本命令来验证这些功能是否按预期工作。具体来说，测试了以下几个主要方面：

1. **`MoveRangeSelectionExtent` 功能测试:**
   - 测试了 `MoveRangeSelectionExtent` 方法如何根据给定的屏幕坐标来扩展或收缩文本选择范围。
   - 验证了移动选择范围时，起始点和终点的不同组合以及超出边界的情况。
   - 测试了在可编辑的输入框中使用 `MoveRangeSelectionExtent` 时，输入框是否会滚动以显示被选择的内容。
   - 测试了 `MoveRangeSelectionExtent` 是否能正确处理起始和结束点交换的情况。
   - 验证了 `MoveRangeSelectionExtent` 在特定情况下不能使选择范围折叠成一个点。

2. **智能剪贴板 (Smart Clip) 功能测试:**
   - 测试了 `ExtractSmartClipDataInternal` 方法，该方法用于从指定区域提取文本和 HTML 内容，用于智能剪贴板功能。
   - 验证了在不同缩放级别下，智能剪贴板能否正确提取内容和边界信息。
   - 测试了当元素设置了 `user-select: none` 样式时，智能剪贴板是否会返回空字符串。
   - 验证了即使裁剪区域的起始和结束位置在 DOM 树中是反向的，智能剪贴板功能也不会崩溃。

3. **`PositionForPoint` 功能测试 (DISABLED):**
   - 这个测试被禁用了，但其目的是测试 `PositionForPoint` 方法，该方法根据给定的坐标计算在特定布局对象中的文本偏移量。
   - 涉及可编辑的 `<span>` 和 `<div>` 元素。

4. **光标和选择范围的水平对齐测试:**
   - 测试了使用 `SelectRange` 方法移动选择范围的起始或结束点时，是否会保持水平方向的对齐。
   - 测试了使用 `MoveCaretSelection` 方法移动光标时，是否会保持水平方向的对齐。

5. **组合选择边界 (Composited Selection Bounds) 测试:**
   - 一系列 `CompositedSelectionBoundsTest`，用于测试在启用硬件加速合成的情况下，文本选择边界的计算是否正确。
   - 涵盖了各种场景，包括基本文本、变换、垂直排版、RTL 文本、分层、iframe、可编辑内容、SVG、以及不同类型的输入元素。
   - 这些测试通过 JavaScript 注入来模拟用户点击选择文本，并断言计算出的选择边界是否与预期一致。

6. **文档加载测试:**
   - 测试了加载包含 `<body>` 标签的 HTML 文档是否会触发 `DidCommitNavigation` 事件。
   - 测试了加载空的文档或 SVG 文档时的行为。

7. **在没有选择的情况下移动光标:**
   - 测试了在没有初始选择的情况下调用 `MoveCaretSelection` 方法是否会崩溃。

8. **拼写检查和替换测试:**
   - 测试了 `ReplaceMisspelledRange` 方法，该方法用于替换拼写错误的文本范围。
   - 使用 `WebTextCheckClient` 模拟拼写检查服务。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  所有测试都依赖于加载不同的 HTML 文件来构建测试场景。例如：
    - `move_range_selection_extent.html` 包含可选择的文本，用于测试 `MoveRangeSelectionExtent`。
    - `smartclip.html` 包含带有特定样式的元素，用于测试智能剪贴板的数据提取。
    - `composited_selection_bounds_basic.html` 包含基本的文本布局，用于测试组合选择边界。

* **CSS:**  CSS 样式影响着文本的布局和渲染，从而影响选择范围和智能剪贴板的提取结果。例如：
    - `smartclip.html` 中使用了 `padding`, `margin`, `border` 等 CSS 属性来定义元素的外观，这些属性会影响智能剪贴板提取的 HTML 内容。
    - `smartclip_user_select_none.html` 使用了 `user-select: none` 样式来禁用文本选择，测试智能剪贴板在这种情况下的行为。
    - 组合选择边界的测试，如 `composited_selection_bounds_transformed.html`，测试了 CSS 变换对选择边界计算的影响。

* **JavaScript:**  JavaScript 被用来执行测试中的操作和断言。例如：
    - `frame->ExecuteScript(WebString::FromUTF8("selectRange();"));`  使用 JavaScript 代码 `selectRange()` 来预先选择一段文本，为后续的 `MoveRangeSelectionExtent` 测试做准备。
    - 在组合选择边界的测试中，JavaScript 代码 (`expectedResult`) 用于定义预期的选择边界信息，并模拟用户点击来触发选择。

**逻辑推理、假设输入与输出:**

**示例 1: `MoveRangeSelectionExtent` 测试**

* **假设输入:**
    - 加载 `move_range_selection_extent.html`，其中包含文本 "16-char header. This text is initially selected. 16-char footer."，并且 "This text is initially selected." 处于选中状态。
    - 调用 `frame->MoveRangeSelectionExtent(gfx::Point(640, 480));`，假设屏幕右下角附近。
* **逻辑推理:**  由于给定的坐标 (640, 480) 位于选中文本的结束位置之后，选择范围应该会扩展到包含后续的 " 16-char footer."。
* **预期输出:** `SelectionAsString(frame)` 返回 "This text is initially selected. 16-char footer."。

**示例 2: 智能剪贴板测试**

* **假设输入:**
    - 加载 `smartclip.html`，其中包含带有特定样式的 `<div>` 元素，包括一个包含 "Price 10,000,000won" 的 `<div>`。
    - 调用 `frame->GetFrame()->ExtractSmartClipDataInternal(crop_rect, clip_text, clip_html, clip_rect);`，其中 `crop_rect` 定义了包含 "Price 10,000,000won" 的区域。
* **逻辑推理:**  智能剪贴板功能应该能够识别并提取指定区域内的文本内容和相关的 HTML 结构。
* **预期输出:**
    - `clip_text` 将包含 "\nPrice 10,000,000won"。
    - `clip_html` 将包含包含 "Price 10,000,000won" 的 `<div>` 元素的 HTML 代码。

**用户或编程常见的使用错误举例:**

1. **`MoveRangeSelectionExtent` 的坐标错误:**  开发者可能错误地计算了目标坐标，导致选择范围扩展到不期望的位置或根本没有扩展。例如，如果提供的坐标位于当前选择范围的起始点之前，可能会导致选择范围收缩或不变，而不是扩展。

2. **假设 `user-select: none` 不会影响智能剪贴板:** 开发者可能认为智能剪贴板总能提取内容，而忽略了 CSS 属性 `user-select: none` 会阻止文本被选中，从而影响智能剪贴板的提取结果。

3. **在组合选择边界测试中，预期的边界值不准确:**  由于渲染引擎的复杂性以及不同平台间的差异，手动计算精确的组合选择边界可能很困难。开发者可能会因为计算错误或者对渲染逻辑的理解偏差，导致测试断言失败。

4. **忘记更新生命周期阶段 (lifecycle phases):** 在进行布局、渲染相关的测试时，开发者可能忘记调用 `UpdateAllLifecyclePhases`，导致测试结果不准确，因为渲染树可能没有更新到最新的状态。

**总结 (本部分功能):**

这部分 `web_frame_test.cc` 主要负责测试 `WebFrame` 在处理文本选择和智能剪贴板功能时的各种场景。它涵盖了基于坐标的选择范围移动、智能剪贴板的内容提取、光标移动的对齐、以及在硬件加速合成下的选择边界计算。这些测试确保了 Blink 引擎在文本处理方面的核心功能能够正确稳定地工作，并能与 HTML、CSS 和 JavaScript 进行正确的交互。 它是整个 `WebFrame` 功能测试的重要组成部分。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第9部分，共19部分，请归纳一下它的功能

"""
ase_url_ + "move_range_selection_extent.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);

  frame->MoveRangeSelectionExtent(gfx::Point(640, 480));
  EXPECT_EQ("This text is initially selected. 16-char footer.",
            SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(gfx::Point());
  EXPECT_EQ("16-char header. ", SelectionAsString(frame));

  // Reset with swapped base and extent.
  frame->SelectRange(end_rect.origin(), BottomRightMinusOne(start_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(gfx::Point(640, 480));
  EXPECT_EQ(" 16-char footer.", SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(gfx::Point());
  EXPECT_EQ("16-char header. This text is initially selected.",
            SelectionAsString(frame));

  frame->ExecuteCommand(WebString::FromUTF8("Unselect"));
  EXPECT_EQ("", SelectionAsString(frame));
}

TEST_F(WebFrameTest, MoveRangeSelectionExtentCannotCollapse) {
  WebLocalFrameImpl* frame;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  RegisterMockedHttpURLLoad("move_range_selection_extent.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "move_range_selection_extent.html",
                                 &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);

  frame->MoveRangeSelectionExtent(BottomRightMinusOne(start_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));

  // Reset with swapped base and extent.
  frame->SelectRange(end_rect.origin(), BottomRightMinusOne(start_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));

  frame->MoveRangeSelectionExtent(BottomRightMinusOne(end_rect));
  EXPECT_EQ("This text is initially selected.", SelectionAsString(frame));
}

TEST_F(WebFrameTest, MoveRangeSelectionExtentScollsInputField) {
  WebLocalFrameImpl* frame;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  RegisterMockedHttpURLLoad("move_range_selection_extent_input_field.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(
      base_url_ + "move_range_selection_extent_input_field.html",
      &web_view_helper);
  frame = web_view_helper.LocalMainFrame();
  EXPECT_EQ("Length", SelectionAsString(frame));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);

  EXPECT_EQ(0, frame->GetFrame()
                   ->Selection()
                   .ComputeVisibleSelectionInDOMTree()
                   .RootEditableElement()
                   ->scrollLeft());
  frame->MoveRangeSelectionExtent(gfx::Point(end_rect.x() + 500, end_rect.y()));
  EXPECT_GE(frame->GetFrame()
                ->Selection()
                .ComputeVisibleSelectionInDOMTree()
                .RootEditableElement()
                ->scrollLeft(),
            1);
  EXPECT_EQ("Lengthy text goes here.", SelectionAsString(frame));
}

TEST_F(WebFrameTest, SmartClipData) {
  static const char kExpectedClipText[] = "\nPrice 10,000,000won";
  static const char kExpectedClipHtml[] =
      "<div id=\"div4\" style=\"padding: 10px; margin: 10px; border: 2px solid "
      "skyblue; float: left; width: 190px; height: 30px; color: rgb(0, 0, 0); "
      "font-family: myahem; font-size: 8px; font-style: normal; "
      "font-variant-ligatures: normal; font-variant-caps: normal; font-weight: "
      "400; letter-spacing: normal; orphans: 2; text-align: start; "
      "text-indent: 0px; text-transform: none; widows: 2; "
      "word-spacing: 0px; -webkit-text-stroke-width: 0px; white-space: normal; "
      "text-decoration-thickness: initial; text-decoration-style: initial; "
      "text-decoration-color: initial;\">Air conditioner</div><div id=\"div5\" "
      "style=\"padding: 10px; margin: 10px; border: 2px solid skyblue; float: "
      "left; width: 190px; height: 30px; color: rgb(0, 0, 0); font-family: "
      "myahem; font-size: 8px; font-style: normal; font-variant-ligatures: "
      "normal; font-variant-caps: normal; font-weight: 400; letter-spacing: "
      "normal; orphans: 2; text-align: start; text-indent: 0px; "
      "text-transform: none; widows: 2; word-spacing: 0px; "
      "-webkit-text-stroke-width: 0px; white-space: normal; "
      "text-decoration-thickness: "
      "initial; text-decoration-style: initial; text-decoration-color: "
      "initial;\">Price 10,000,000won</div>";
  String clip_text;
  String clip_html;
  gfx::Rect clip_rect;
  RegisterMockedHttpURLLoad("Ahem.ttf");
  RegisterMockedHttpURLLoad("smartclip.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "smartclip.html");
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  web_view_helper.Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  gfx::Rect crop_rect(300, 125, 152, 50);
  frame->GetFrame()->ExtractSmartClipDataInternal(crop_rect, clip_text,
                                                  clip_html, clip_rect);
  EXPECT_EQ(String(kExpectedClipText), clip_text);
  EXPECT_EQ(String(kExpectedClipHtml), clip_html);
}

TEST_F(WebFrameTest, SmartClipDataWithPinchZoom) {
  static const char kExpectedClipText[] = "\nPrice 10,000,000won";
  static const char kExpectedClipHtml[] =
      "<div id=\"div4\" style=\"padding: 10px; margin: 10px; border: 2px solid "
      "skyblue; float: left; width: 190px; height: 30px; color: rgb(0, 0, 0); "
      "font-family: myahem; font-size: 8px; font-style: normal; "
      "font-variant-ligatures: normal; font-variant-caps: normal; font-weight: "
      "400; letter-spacing: normal; orphans: 2; text-align: start; "
      "text-indent: 0px; text-transform: none; widows: 2; "
      "word-spacing: 0px; -webkit-text-stroke-width: 0px; white-space: normal; "
      "text-decoration-thickness: initial; text-decoration-style: initial; "
      "text-decoration-color: initial;\">Air conditioner</div><div id=\"div5\" "
      "style=\"padding: 10px; margin: 10px; border: 2px solid skyblue; float: "
      "left; width: 190px; height: 30px; color: rgb(0, 0, 0); font-family: "
      "myahem; font-size: 8px; font-style: normal; font-variant-ligatures: "
      "normal; font-variant-caps: normal; font-weight: 400; letter-spacing: "
      "normal; orphans: 2; text-align: start; text-indent: 0px; "
      "text-transform: none; widows: 2; word-spacing: 0px; "
      "-webkit-text-stroke-width: 0px; white-space: normal; "
      "text-decoration-thickness: "
      "initial; text-decoration-style: initial; text-decoration-color: "
      "initial;\">Price 10,000,000won</div>";
  String clip_text;
  String clip_html;
  gfx::Rect clip_rect;
  RegisterMockedHttpURLLoad("Ahem.ttf");
  RegisterMockedHttpURLLoad("smartclip.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "smartclip.html");
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  web_view_helper.Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  web_view_helper.GetWebView()->SetPageScaleFactor(1.5);
  web_view_helper.GetWebView()->SetVisualViewportOffset(gfx::PointF(167, 100));
  gfx::Rect crop_rect(200, 38, 228, 75);
  frame->GetFrame()->ExtractSmartClipDataInternal(crop_rect, clip_text,
                                                  clip_html, clip_rect);
  EXPECT_EQ(String(kExpectedClipText), clip_text);
  EXPECT_EQ(String(kExpectedClipHtml), clip_html);
}

TEST_F(WebFrameTest, SmartClipReturnsEmptyStringsWhenUserSelectIsNone) {
  String clip_text;
  String clip_html;
  gfx::Rect clip_rect;
  RegisterMockedHttpURLLoad("Ahem.ttf");
  RegisterMockedHttpURLLoad("smartclip_user_select_none.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ +
                                    "smartclip_user_select_none.html");
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  web_view_helper.Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  gfx::Rect crop_rect(0, 0, 100, 100);
  frame->GetFrame()->ExtractSmartClipDataInternal(crop_rect, clip_text,
                                                  clip_html, clip_rect);
  EXPECT_STREQ("", clip_text.Utf8().c_str());
  EXPECT_STREQ("", clip_html.Utf8().c_str());
}

TEST_F(WebFrameTest, SmartClipDoesNotCrashPositionReversed) {
  String clip_text;
  String clip_html;
  gfx::Rect clip_rect;
  RegisterMockedHttpURLLoad("Ahem.ttf");
  RegisterMockedHttpURLLoad("smartclip_reversed_positions.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ +
                                    "smartclip_reversed_positions.html");
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  web_view_helper.Resize(gfx::Size(500, 500));
  UpdateAllLifecyclePhases(web_view_helper.GetWebView());
  // Left upper corner of the rect will be end position in the DOM hierarchy.
  gfx::Rect crop_rect(30, 110, 400, 250);
  // This should not still crash. See crbug.com/589082 for more details.
  frame->GetFrame()->ExtractSmartClipDataInternal(crop_rect, clip_text,
                                                  clip_html, clip_rect);
}

static int ComputeOffset(LayoutObject* layout_object, int x, int y) {
  return layout_object->PositionForPoint(PhysicalOffset(x, y))
      .GetPosition()
      .ComputeOffsetInContainerNode();
}

// positionForPoint returns the wrong values for contenteditable spans. See
// http://crbug.com/238334.
TEST_F(WebFrameTest, DISABLED_PositionForPointTest) {
  RegisterMockedHttpURLLoad("select_range_span_editable.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "select_range_span_editable.html",
                                 &web_view_helper);
  WebLocalFrameImpl* main_frame = web_view_helper.LocalMainFrame();
  LayoutObject* layout_object = main_frame->GetFrame()
                                    ->Selection()
                                    .ComputeVisibleSelectionInDOMTree()
                                    .RootEditableElement()
                                    ->GetLayoutObject();
  EXPECT_EQ(0, ComputeOffset(layout_object, -1, -1));
  EXPECT_EQ(64, ComputeOffset(layout_object, 1000, 1000));

  RegisterMockedHttpURLLoad("select_range_div_editable.html");
  InitializeTextSelectionWebView(base_url_ + "select_range_div_editable.html",
                                 &web_view_helper);
  main_frame = web_view_helper.LocalMainFrame();
  layout_object = main_frame->GetFrame()
                      ->Selection()
                      .ComputeVisibleSelectionInDOMTree()
                      .RootEditableElement()
                      ->GetLayoutObject();
  EXPECT_EQ(0, ComputeOffset(layout_object, -1, -1));
  EXPECT_EQ(64, ComputeOffset(layout_object, 1000, 1000));
}

#if BUILDFLAG(IS_FUCHSIA) || BUILDFLAG(IS_APPLE) || BUILDFLAG(IS_LINUX) || \
    BUILDFLAG(IS_CHROMEOS)
// TODO(crbug.com/1090246): Fix these tests on Fuchsia and re-enable.
// TODO(crbug.com/1317375): Build these tests on all platforms.
#define MAYBE_SelectRangeStaysHorizontallyAlignedWhenMoved \
  DISABLED_SelectRangeStaysHorizontallyAlignedWhenMoved
#define MAYBE_MoveCaretStaysHorizontallyAlignedWhenMoved \
  DISABLED_MoveCaretStaysHorizontallyAlignedWhenMoved
#else
#define MAYBE_SelectRangeStaysHorizontallyAlignedWhenMoved \
  SelectRangeStaysHorizontallyAlignedWhenMoved
#define MAYBE_MoveCaretStaysHorizontallyAlignedWhenMoved \
  MoveCaretStaysHorizontallyAlignedWhenMoved
#endif
TEST_F(WebFrameTest, MAYBE_SelectRangeStaysHorizontallyAlignedWhenMoved) {
  RegisterMockedHttpURLLoad("move_caret.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "move_caret.html",
                                 &web_view_helper);
  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();

  gfx::Rect initial_start_rect;
  gfx::Rect initial_end_rect;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  frame->ExecuteScript(WebScriptSource("selectRange();"));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      initial_start_rect, initial_end_rect);
  gfx::Point moved_start(initial_start_rect.origin());

  moved_start.Offset(0, 40);
  frame->SelectRange(moved_start, BottomRightMinusOne(initial_end_rect));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  moved_start.Offset(0, -80);
  frame->SelectRange(moved_start, BottomRightMinusOne(initial_end_rect));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  gfx::Point moved_end(BottomRightMinusOne(initial_end_rect));

  moved_end.Offset(0, 40);
  frame->SelectRange(initial_start_rect.origin(), moved_end);
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  moved_end.Offset(0, -80);
  frame->SelectRange(initial_start_rect.origin(), moved_end);
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);
}

TEST_F(WebFrameTest, MAYBE_MoveCaretStaysHorizontallyAlignedWhenMoved) {
  WebLocalFrameImpl* frame;
  RegisterMockedHttpURLLoad("move_caret.html");

  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "move_caret.html",
                                 &web_view_helper);
  frame = (WebLocalFrameImpl*)web_view_helper.GetWebView()->MainFrame();

  gfx::Rect initial_start_rect;
  gfx::Rect initial_end_rect;
  gfx::Rect start_rect;
  gfx::Rect end_rect;

  frame->ExecuteScript(WebScriptSource("selectCaret();"));
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      initial_start_rect, initial_end_rect);
  gfx::Point move_to(initial_start_rect.origin());

  move_to.Offset(0, 40);
  frame->MoveCaretSelection(move_to);
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);

  move_to.Offset(0, -80);
  frame->MoveCaretSelection(move_to);
  web_view_helper.GetWebView()->MainFrameViewWidget()->CalculateSelectionBounds(
      start_rect, end_rect);
  EXPECT_EQ(start_rect, initial_start_rect);
  EXPECT_EQ(end_rect, initial_end_rect);
}

class CompositedSelectionBoundsTest
    : public WebFrameTest,
      private ScopedCompositedSelectionUpdateForTest {
 protected:
  CompositedSelectionBoundsTest()
      : ScopedCompositedSelectionUpdateForTest(true) {
    RegisterMockedHttpURLLoad("Ahem.ttf");

    web_view_helper_.Initialize(nullptr, nullptr);
    web_view_helper_.GetWebView()->GetSettings()->SetDefaultFontSize(12);
    web_view_helper_.GetWebView()->SetDefaultPageScaleLimits(1, 1);
    web_view_helper_.Resize(gfx::Size(640, 480));
  }

  void RunTestWithNoSelection(const char* test_file) {
    RegisterMockedHttpURLLoad(test_file);
    web_view_helper_.GetWebView()->MainFrameWidget()->SetFocus(true);
    frame_test_helpers::LoadFrame(
        web_view_helper_.GetWebView()->MainFrameImpl(), base_url_ + test_file);
    UpdateAllLifecyclePhases(web_view_helper_.GetWebView());

    cc::LayerTreeHost* layer_tree_host = web_view_helper_.GetLayerTreeHost();
    const cc::LayerSelection& selection = layer_tree_host->selection();

    ASSERT_EQ(selection, cc::LayerSelection());
    ASSERT_EQ(selection.start, cc::LayerSelectionBound());
    ASSERT_EQ(selection.end, cc::LayerSelectionBound());
  }

  void RunTest(const char* test_file, bool selection_is_caret = false) {
    RegisterMockedHttpURLLoad(test_file);
    web_view_helper_.GetWebView()->MainFrameWidget()->SetFocus(true);
    frame_test_helpers::LoadFrame(
        web_view_helper_.GetWebView()->MainFrameImpl(), base_url_ + test_file);

    UpdateAllLifecyclePhases(web_view_helper_.GetWebView());

    v8::Isolate* isolate = web_view_helper_.GetAgentGroupScheduler().Isolate();
    v8::HandleScope handle_scope(isolate);
    v8::Local<v8::Value> result =
        web_view_helper_.GetWebView()
            ->MainFrameImpl()
            ->ExecuteScriptAndReturnValue(WebScriptSource("expectedResult"));
    ASSERT_FALSE(result.IsEmpty() || (*result)->IsUndefined());

    ASSERT_TRUE((*result)->IsArray());
    v8::Array& expected_result = *v8::Array::Cast(*result);
    ASSERT_GE(expected_result.Length(), 10u);

    v8::Local<v8::Context> context =
        expected_result.GetCreationContext(isolate).ToLocalChecked();
    v8::Context::Scope v8_context_scope(context);

    int start_edge_start_in_layer_x = expected_result.Get(context, 1)
                                          .ToLocalChecked()
                                          .As<v8::Int32>()
                                          ->Value();
    int start_edge_start_in_layer_y = expected_result.Get(context, 2)
                                          .ToLocalChecked()
                                          .As<v8::Int32>()
                                          ->Value();
    int start_edge_end_in_layer_x = expected_result.Get(context, 3)
                                        .ToLocalChecked()
                                        .As<v8::Int32>()
                                        ->Value();
    int start_edge_end_in_layer_y = expected_result.Get(context, 4)
                                        .ToLocalChecked()
                                        .As<v8::Int32>()
                                        ->Value();

    int end_edge_start_in_layer_x = expected_result.Get(context, 6)
                                        .ToLocalChecked()
                                        .As<v8::Int32>()
                                        ->Value();
    int end_edge_start_in_layer_y = expected_result.Get(context, 7)
                                        .ToLocalChecked()
                                        .As<v8::Int32>()
                                        ->Value();
    int end_edge_end_in_layer_x = expected_result.Get(context, 8)
                                      .ToLocalChecked()
                                      .As<v8::Int32>()
                                      ->Value();
    int end_edge_end_in_layer_y = expected_result.Get(context, 9)
                                      .ToLocalChecked()
                                      .As<v8::Int32>()
                                      ->Value();

    gfx::PointF hit_point;

    if (expected_result.Length() >= 17) {
      hit_point = gfx::PointF(expected_result.Get(context, 15)
                                  .ToLocalChecked()
                                  .As<v8::Int32>()
                                  ->Value(),
                              expected_result.Get(context, 16)
                                  .ToLocalChecked()
                                  .As<v8::Int32>()
                                  ->Value());
    } else {
      hit_point =
          gfx::PointF((start_edge_start_in_layer_x + start_edge_end_in_layer_x +
                       end_edge_start_in_layer_x + end_edge_end_in_layer_x) /
                          4,
                      (start_edge_start_in_layer_y + start_edge_end_in_layer_y +
                       end_edge_start_in_layer_y + end_edge_end_in_layer_y) /
                              4 +
                          3);
    }

    WebGestureEvent gesture_event(WebInputEvent::Type::kGestureTap,
                                  WebInputEvent::kNoModifiers,
                                  WebInputEvent::GetStaticTimeStampForTests(),
                                  WebGestureDevice::kTouchscreen);
    gesture_event.SetFrameScale(1);
    gesture_event.SetPositionInWidget(hit_point);
    gesture_event.SetPositionInScreen(hit_point);

    web_view_helper_.GetWebView()
        ->MainFrameImpl()
        ->GetFrame()
        ->GetEventHandler()
        .HandleGestureEvent(gesture_event);

    UpdateAllLifecyclePhases(web_view_helper_.GetWebView());

    cc::LayerTreeHost* layer_tree_host = web_view_helper_.GetLayerTreeHost();
    const cc::LayerSelection& selection = layer_tree_host->selection();

    ASSERT_NE(selection, cc::LayerSelection());
    ASSERT_NE(selection.start, cc::LayerSelectionBound());
    ASSERT_NE(selection.end, cc::LayerSelectionBound());

    blink::Node* layer_owner_node_for_start =
        V8Node::ToWrappable(web_view_helper_.GetAgentGroupScheduler().Isolate(),
                            expected_result.Get(context, 0).ToLocalChecked());
    // Hidden selection does not always have a layer (might be hidden due to not
    // having been painted.
    ASSERT_TRUE(layer_owner_node_for_start || selection.start.hidden);
    int start_layer_id = 0;
    if (layer_owner_node_for_start) {
      start_layer_id = LayerIdFromNode(layer_tree_host->root_layer(),
                                       layer_owner_node_for_start);
    }
    if (selection_is_caret) {
      // The selection data are recorded on the caret layer which is the next
      // layer for the current test cases.
      start_layer_id++;
      EXPECT_EQ("Caret",
                layer_tree_host->LayerById(start_layer_id)->DebugName());
      // The locations are relative to the caret layer.
      start_edge_end_in_layer_x -= start_edge_start_in_layer_x;
      start_edge_end_in_layer_y -= start_edge_start_in_layer_y;
      start_edge_start_in_layer_x = 0;
      start_edge_start_in_layer_y = 0;
    }
    EXPECT_EQ(start_layer_id, selection.start.layer_id);

    EXPECT_NEAR(start_edge_start_in_layer_x, selection.start.edge_start.x(), 1);
    EXPECT_NEAR(start_edge_start_in_layer_y, selection.start.edge_start.y(), 1);
    EXPECT_NEAR(start_edge_end_in_layer_x, selection.start.edge_end.x(), 1);

    blink::Node* layer_owner_node_for_end =
        V8Node::ToWrappable(web_view_helper_.GetAgentGroupScheduler().Isolate(),
                            expected_result.Get(context, 5).ToLocalChecked());
    // Hidden selection does not always have a layer (might be hidden due to not
    // having been painted.
    ASSERT_TRUE(layer_owner_node_for_end || selection.end.hidden);
    int end_layer_id = 0;
    if (layer_owner_node_for_end) {
      end_layer_id = LayerIdFromNode(layer_tree_host->root_layer(),
                                     layer_owner_node_for_end);
    }

    if (selection_is_caret) {
      // The selection data are recorded on the caret layer which is the next
      // layer for the current test cases.
      end_layer_id++;
      EXPECT_EQ(start_layer_id, end_layer_id);
      // The locations are relative to the caret layer.
      end_edge_end_in_layer_x -= end_edge_start_in_layer_x;
      end_edge_end_in_layer_y -= end_edge_start_in_layer_y;
      end_edge_start_in_layer_x = 0;
      end_edge_start_in_layer_y = 0;
    }
    EXPECT_EQ(end_layer_id, selection.end.layer_id);

    EXPECT_NEAR(end_edge_start_in_layer_x, selection.end.edge_start.x(), 1);
    EXPECT_NEAR(end_edge_start_in_layer_y, selection.end.edge_start.y(), 1);
    EXPECT_NEAR(end_edge_end_in_layer_x, selection.end.edge_end.x(), 1);

    // Platform differences can introduce small stylistic deviations in
    // y-axis positioning, the details of which aren't relevant to
    // selection behavior. However, such deviations from the expected value
    // should be consistent for the corresponding y coordinates.
    int y_bottom_epsilon = 0;
    if (expected_result.Length() == 13) {
      y_bottom_epsilon = expected_result.Get(context, 12)
                             .ToLocalChecked()
                             .As<v8::Int32>()
                             ->Value();
    }

    int y_bottom_deviation =
        start_edge_end_in_layer_y - selection.start.edge_end.y();
    EXPECT_GE(y_bottom_epsilon, std::abs(y_bottom_deviation));
    EXPECT_EQ(y_bottom_deviation,
              end_edge_end_in_layer_y - selection.end.edge_end.y());

    if (expected_result.Length() >= 15) {
      bool start_hidden = expected_result.Get(context, 13)
                              .ToLocalChecked()
                              .As<v8::Boolean>()
                              ->Value();
      bool end_hidden = expected_result.Get(context, 14)
                            .ToLocalChecked()
                            .As<v8::Boolean>()
                            ->Value();

      EXPECT_EQ(start_hidden, selection.start.hidden);
      EXPECT_EQ(end_hidden, selection.end.hidden);
    }
  }

  void RunTestWithMultipleFiles(
      const char* test_file,
      std::initializer_list<const char*> auxiliary_files) {
    for (const char* auxiliary_file : auxiliary_files) {
      RegisterMockedHttpURLLoad(auxiliary_file);
    }

    RunTest(test_file);
  }

  void RunTestWithCaret(const char* test_file) {
    RunTest(test_file, /*selection_is_caret*/ true);
  }

  static int LayerIdFromNode(const cc::Layer* root_layer, blink::Node* node) {
    Vector<const cc::Layer*> layers;
    if (node->IsDocumentNode()) {
      layers = CcLayersByName(root_layer,
                              "Scrolling background of LayoutView #document");
    } else {
      DCHECK(node->IsElementNode());
      layers = CcLayersByDOMElementId(root_layer,
                                      To<Element>(node)->GetIdAttribute());
    }

    EXPECT_EQ(layers.size(), 1u);
    return layers[0]->id();
  }

  frame_test_helpers::WebViewHelper web_view_helper_;
};

TEST_F(CompositedSelectionBoundsTest, None) {
  RunTestWithNoSelection("composited_selection_bounds_none.html");
}
TEST_F(CompositedSelectionBoundsTest, NoneReadonlyCaret) {
  RunTestWithNoSelection(
      "composited_selection_bounds_none_readonly_caret.html");
}
TEST_F(CompositedSelectionBoundsTest, DetachedFrame) {
  RunTestWithNoSelection("composited_selection_bounds_detached_frame.html");
}

TEST_F(CompositedSelectionBoundsTest, Basic) {
  RunTest("composited_selection_bounds_basic.html");
}
TEST_F(CompositedSelectionBoundsTest, Transformed) {
  RunTest("composited_selection_bounds_transformed.html");
}
TEST_F(CompositedSelectionBoundsTest, VerticalRightToLeft) {
  RunTest("composited_selection_bounds_vertical_rl.html");
}
TEST_F(CompositedSelectionBoundsTest, VerticalLeftToRight) {
  RunTest("composited_selection_bounds_vertical_lr.html");
}
TEST_F(CompositedSelectionBoundsTest, BasicRTL) {
  RunTest("composited_selection_bounds_basic_rtl.html");
}
TEST_F(CompositedSelectionBoundsTest, VerticalRightToLeftRTL) {
  RunTest("composited_selection_bounds_vertical_rl_rtl.html");
}
TEST_F(CompositedSelectionBoundsTest, VerticalLeftToRightRTL) {
  RunTest("composited_selection_bounds_vertical_lr_rtl.html");
}
TEST_F(CompositedSelectionBoundsTest, SplitLayer) {
  RunTest("composited_selection_bounds_split_layer.html");
}
TEST_F(CompositedSelectionBoundsTest, Iframe) {
  RunTestWithMultipleFiles("composited_selection_bounds_iframe.html",
                           {"composited_selection_bounds_basic.html"});
}
TEST_F(CompositedSelectionBoundsTest, Editable) {
  web_view_helper_.GetWebView()->GetSettings()->SetDefaultFontSize(16);
  RunTestWithCaret("composited_selection_bounds_editable.html");
}
TEST_F(CompositedSelectionBoundsTest, EditableDiv) {
  RunTestWithCaret("composited_selection_bounds_editable_div.html");
}
TEST_F(CompositedSelectionBoundsTest, SVGBasic) {
  RunTest("composited_selection_bounds_svg_basic.html");
}
TEST_F(CompositedSelectionBoundsTest, SVGTextWithFragments) {
  RunTest("composited_selection_bounds_svg_text_with_fragments.html");
}
TEST_F(CompositedSelectionBoundsTest, LargeSelectionScroll) {
  RunTest("composited_selection_bounds_large_selection_scroll.html");
}
TEST_F(CompositedSelectionBoundsTest, LargeSelectionNoScroll) {
  RunTest("composited_selection_bounds_large_selection_noscroll.html");
}
#if BUILDFLAG(IS_WIN) || BUILDFLAG(IS_LINUX) || BUILDFLAG(IS_CHROMEOS)
#if !BUILDFLAG(IS_ANDROID)
TEST_F(CompositedSelectionBoundsTest, Input) {
  web_view_helper_.GetWebView()->GetSettings()->SetDefaultFontSize(16);
  RunTest("composited_selection_bounds_input.html");
}
TEST_F(CompositedSelectionBoundsTest, InputScrolled) {
  web_view_helper_.GetWebView()->GetSettings()->SetDefaultFontSize(16);
  RunTest("composited_selection_bounds_input_scrolled.html");
}
#endif
#endif

class CompositedSelectionBoundsTestWithImage
    : public CompositedSelectionBoundsTest {
 public:
  CompositedSelectionBoundsTestWithImage() : CompositedSelectionBoundsTest() {
    RegisterMockedHttpURLLoad("notifications/120x120.png");
  }
};

TEST_F(CompositedSelectionBoundsTestWithImage, Replaced) {
  RunTest("composited_selection_bounds_replaced.html");
}

TEST_F(CompositedSelectionBoundsTestWithImage, ReplacedRTL) {
  RunTest("composited_selection_bounds_replaced_rtl.html");
}

TEST_F(CompositedSelectionBoundsTestWithImage, ReplacedVerticalLR) {
  RunTest("composited_selection_bounds_replaced_vertical_lr.html");
}

class TestWillInsertBodyWebFrameClient final
    : public frame_test_helpers::TestWebFrameClient {
 public:
  TestWillInsertBodyWebFrameClient() = default;
  ~TestWillInsertBodyWebFrameClient() override = default;

  bool did_load() const { return did_load_; }

  // frame_test_helpers::TestWebFrameClient:
  void DidCommitNavigation(
      WebHistoryCommitType commit_type,
      bool should_reset_browser_interface_broker,
      const ParsedPermissionsPolicy& permissions_policy_header,
      const DocumentPolicyFeatureState& document_policy_header) final {
    did_load_ = true;
  }

 private:
  bool did_load_ = false;
};

TEST_F(WebFrameTest, HTMLDocument) {
  RegisterMockedHttpURLLoad("clipped-body.html");

  TestWillInsertBodyWebFrameClient web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad(base_url_ + "clipped-body.html",
                                    &web_frame_client);

  EXPECT_TRUE(web_frame_client.did_load());
}

TEST_F(WebFrameTest, EmptyDocument) {
  RegisterMockedHttpURLLoad("frameserializer/svg/green_rectangle.svg");

  TestWillInsertBodyWebFrameClient web_frame_client;
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.Initialize(&web_frame_client);

  EXPECT_FALSE(web_frame_client.did_load());
}

TEST_F(WebFrameTest, MoveCaretSelectionTowardsWindowPointWithNoSelection) {
  frame_test_helpers::WebViewHelper web_view_helper;
  web_view_helper.InitializeAndLoad("about:blank");
  WebFrame* frame = web_view_helper.GetWebView()->MainFrame();

  // This test passes if this doesn't crash.
  frame->ToWebLocalFrame()->MoveCaretSelection(gfx::Point());
}

class TextCheckClient : public WebTextCheckClient {
 public:
  TextCheckClient() : number_of_times_checked_(0) {}
  ~TextCheckClient() override = default;

  // WebTextCheckClient:
  bool IsSpellCheckingEnabled() const override { return true; }
  void RequestCheckingOfText(
      const WebString&,
      std::unique_ptr<WebTextCheckingCompletion> completion) override {
    ++number_of_times_checked_;
    Vector<WebTextCheckingResult> results;
    const int kMisspellingStartOffset = 1;
    const int kMisspellingLength = 8;
    results.push_back(WebTextCheckingResult(
        kWebTextDecorationTypeSpelling, kMisspellingStartOffset,
        kMisspellingLength, WebVector<WebString>()));
    completion->DidFinishCheckingText(results);
  }

  int NumberOfTimesChecked() const { return number_of_times_checked_; }

 private:
  int number_of_times_checked_;
};

TEST_F(WebFrameTest, ReplaceMisspelledRange) {
  RegisterMockedHttpURLLoad("spell.html");
  frame_test_helpers::WebViewHelper web_view_helper;
  InitializeTextSelectionWebView(base_url_ + "spell.html", &web_view_helper);

  WebLocalFrameImpl* frame = web_view_helper.LocalMainFrame();
  TextCheckClient textcheck;
  frame->SetTextCheckClient(&textcheck);

  Document* document = frame->GetFrame()->
"""


```