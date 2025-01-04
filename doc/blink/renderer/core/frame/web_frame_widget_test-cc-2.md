Response:
The user wants a summary of the functionalities of the provided C++ code snippet. This is the third part of a larger file, so I need to consider what functionalities have been covered in the previous parts to provide a comprehensive summary.

The code snippet primarily focuses on testing the `WebFrameWidget` class, particularly its ability to correctly determine and report the visible line bounds of text elements in various scenarios.

Here's a breakdown of the functionalities in this part:

1. **Testing `resizable` visual property:** Checks if applying the `resizable` property updates the background color.
2. **Testing line bounds after layout changes:** Verifies that the reported line bounds are correct after a layout shift caused by changing the height of a div.
3. **Testing line bounds after page scroll:** Ensures that page scrolling doesn't affect the reported line bounds (as they are in document coordinates).
4. **Testing line bounds after element scroll:** Checks if scrolling within an element correctly updates the reported line bounds.
5. **Testing line bounds during text input:** Verifies that line bounds are correctly updated as text is added to a text area, including handling newlines.
6. **Testing line bounds during text deletion:** Checks if deleting characters and newlines in a text area correctly updates the reported line bounds.
7. **Testing line bounds in iframes:** Verifies that line bounds are calculated correctly within an iframe.
8. **Testing line bounds with different zoom levels:** Ensures that line bounds are scaled correctly when different zoom levels are applied to the main frame and subframes.
9. **Testing clipped line bounds in iframes:** Checks if the reported line bounds in an iframe are correctly clipped to the iframe's visible area.
10. **Testing event handling and swap promises:** Focuses on how input events affect the compositor and swap promises, ensuring that swap promises are not broken unexpectedly.
这是`blink/renderer/core/frame/web_frame_widget_test.cc`文件的第三部分，延续了前两部分的功能，主要集中在测试 `WebFrameWidget` 的以下功能：

**总体功能归纳：**

这部分代码主要用于测试 `WebFrameWidget` 在各种场景下，特别是与文本相关的场景中，是否能正确地报告和更新可见的文本行边界 (line bounds)。它还测试了 `WebFrameWidget` 如何处理输入事件以及与 compositor 的交互，特别是关于 swap promises 的行为。

**具体功能及其与 Javascript, HTML, CSS 的关系：**

1. **测试 `resizable` 属性对样式的影响:**
   - **功能:** 测试通过 `VisualProperties` 修改 `resizable` 属性是否会触发样式的重新计算和应用。
   - **与 HTML/CSS 的关系:**  `resizable` 属性通常通过 CSS 来控制元素的尺寸是否可以被用户调整。这里通过 C++ 代码模拟修改这个属性，并验证背景颜色是否根据预设的逻辑改变。
   - **假设输入与输出:**
     - **假设输入:**  一个包含 `body` 元素的 HTML 页面，CSS 默认 `background-color` 为黄色，当 `resizable` 为 false 时 `background-color` 变为青色。
     - **输出:** 当 `resizable` 设置为 true 时，`body` 的计算样式 `background-color` 为黄色；设置为 false 时，`background-color` 为青色。

2. **测试布局改变后行边界是否正确:**
   - **功能:** 测试当页面布局发生改变（例如，一个 `div` 的高度变化）后，文本输入框的行边界是否仍然能被正确计算。
   - **与 HTML/CSS 的关系:**  页面布局由 HTML 结构和 CSS 样式共同决定。这里测试了修改 HTML 元素的样式导致布局变化后，`WebFrameWidget` 获取到的文本行边界是否正确。
   - **假设输入与输出:**
     - **假设输入:** 一个包含文本输入框的 HTML 页面，输入框下方有一个高度为 0 的 `div`。焦点在输入框上，输入了一些文字。
     - **操作:**  将下方 `div` 的高度修改为 200px，导致输入框向下移动。
     - **输出:**  在布局改变前后获取到的行边界信息是对应的，只是在布局改变后整体向下偏移了 200px。

3. **测试页面滚动后行边界是否正确:**
   - **功能:** 测试当页面发生滚动后，文本区域的行边界是否仍然能被正确计算。
   - **与 HTML/CSS 的关系:**  页面滚动影响的是视口 (viewport) 的位置，而文本的行边界是相对于文档的。
   - **假设输入与输出:**
     - **假设输入:** 一个高度大于视口的 HTML 页面，包含一个绝对定位的文本区域，焦点在该文本区域上。
     - **操作:**  向下滚动页面 50 像素。
     - **输出:**  在滚动前后获取到的文本区域行边界信息相同，因为行边界是相对于文档的，页面滚动不影响其相对位置。

4. **测试元素滚动后行边界是否正确:**
   - **功能:** 测试当元素内部发生滚动后，其内部文本的行边界是否能被正确计算。
   - **与 HTML/CSS 的关系:**  元素的滚动影响的是元素内容相对于元素自身容器的位置。
   - **假设输入与输出:**
     - **假设输入:** 一个包含可滚动文本区域的 HTML 页面，焦点在该文本区域上，文本内容超出区域高度。
     - **操作:**  向下滚动文本区域 50 像素。
     - **输出:**  在滚动前后获取到的文本行边界信息是对应的，在滚动后整体向上偏移了 50px。

5. **测试提交文本时行边界是否正确:**
   - **功能:** 测试在文本输入框中逐个输入字符和换行符时，行边界是否能随着文本内容的增加而正确更新。
   - **与 Javascript/HTML 的关系:**  这里模拟了用户在文本框中输入内容的过程，涉及到 Javascript 对 DOM 元素的修改。
   - **假设输入与输出:**
     - **假设输入:** 一个空的文本区域，焦点在其上。
     - **操作:**  逐个输入 "hello world" 的字符，然后再输入一个换行符，接着逐个输入 "goodbye world" 的字符。
     - **输出:**  每输入一个字符，行边界的宽度会相应增加。输入换行符后，会新增一行边界，后续输入的字符会出现在第二行的边界中。

6. **测试删除文本时行边界是否正确:**
   - **功能:** 测试在文本区域中删除字符和换行符时，行边界是否能随着文本内容的减少而正确更新。
   - **与 Javascript/HTML 的关系:**  这里模拟了用户删除文本的过程，涉及到 Javascript 对 DOM 元素的修改。
   - **假设输入与输出:**
     - **假设输入:** 一个包含两行文本的文本区域，焦点在第二行末尾。
     - **操作:**  逐个删除第二行的字符，直到删除换行符，再逐个删除第一行的字符。
     - **输出:**  每删除一个字符，对应行的边界宽度会减少。删除换行符后，两行文本合并为一行，边界也会相应合并。

7. **测试在 `iframe` 中的行边界:**
   - **功能:** 测试在 `iframe` 子框架中，文本元素的行边界是否能被正确计算，并考虑到父框架的布局影响。
   - **与 HTML 的关系:**  涉及到 HTML 的 `iframe` 元素，以及父子框架之间的布局关系。
   - **假设输入与输出:**
     - **假设输入:** 一个包含 `iframe` 的父页面，`iframe` 中包含一个文本输入框，输入框获得焦点。
     - **输出:**  获取到的行边界的纵坐标会考虑到父页面中在 `iframe` 之前的元素高度以及 `iframe` 自身在其父页面中的偏移。

8. **测试不同缩放比例下的行边界:**
   - **功能:** 测试当主框架和子框架设置了不同的缩放比例 (`zoom`) 时，文本元素的行边界是否能被正确计算。
   - **与 CSS 的关系:**  涉及到 CSS 的 `zoom` 属性对元素尺寸的影响。
   - **假设输入与输出:**
     - **假设输入:** 一个包含 `iframe` 的父页面，父页面和子页面分别设置了不同的 `zoom` 属性，子页面中包含一个文本输入框，输入框获得焦点。
     - **输出:**  获取到的行边界的尺寸会受到主框架和子框架的 `zoom` 属性的影响，进行相应的缩放计算。

9. **测试 `iframe` 中被裁剪的行边界:**
   - **功能:** 测试当 `iframe` 的显示区域小于其内部内容时，文本元素的行边界是否会被正确裁剪到 `iframe` 的可视区域内。
   - **与 HTML/CSS 的关系:**  涉及到 `iframe` 的尺寸限制以及内部内容的溢出处理。
   - **假设输入与输出:**
     - **假设输入:** 一个包含 `iframe` 的父页面，`iframe` 的宽度和高度小于其内部文本内容的实际渲染尺寸，子页面中的文本输入框获得焦点。
     - **输出:**  获取到的行边界的宽度和高度会被限制在 `iframe` 的可视区域内。

10. **测试事件处理和 Swap Promise:**
    - **功能:** 测试 `WebFrameWidget` 如何处理不同类型的输入事件（键盘事件、鼠标事件），以及这些事件是否会导致 compositor 更新和影响 swap promises 的状态。Swap promises 用于跟踪 compositor 帧的提交过程。
    - **与 Javascript 的关系:** 输入事件通常由用户的交互触发，并通过 Javascript 进行处理。这里测试了底层引擎如何响应这些事件。
    - **假设输入与输出:**
        - **假设输入:** 模拟各种键盘和鼠标事件。
        - **输出:** 验证在不同的情况下，swap promise 的状态会如何变化（Pending, Resolved, Broken），以及是否会触发 compositor 的更新。例如，非 rAF 对齐的事件在没有触发更新的情况下可能会导致 swap promise 被 broken。

**常见使用错误举例：**

- **没有触发布局更新就期望获取到最新的行边界:**  在修改了 DOM 结构或样式后，如果没有触发布局更新（例如，通过 `widget->UpdateAllLifecyclePhases()`），直接获取行边界可能会得到旧的值。
- **在异步操作完成前就获取行边界:**  例如，在字体加载完成前就尝试获取依赖于该字体的文本元素的行边界，可能会得到不准确的结果。
- **没有考虑 `iframe` 的影响:**  在处理 `iframe` 中的元素行边界时，如果没有考虑到父框架的布局、滚动和缩放等因素，计算结果可能会出错。

总而言之，这部分测试代码覆盖了 `WebFrameWidget` 在处理各种与文本显示和用户交互相关的场景时的正确性，确保了浏览器引擎能够准确地获取和更新页面中元素的几何信息，这对于诸如光标定位、文本选择、辅助功能等特性至关重要。

Prompt: 
```
这是目录为blink/renderer/core/frame/web_frame_widget_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
 resizable: true
  // Default is set in /third_party/blink/renderer/core/frame/settings.json5.
  WebView().MainFrameWidget()->ApplyVisualProperties(visual_properties);
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  EXPECT_EQ(Color::FromRGB(/*yellow*/ 255, 255, 0),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyBackgroundColor()));

  // resizable: false
  visual_properties.resizable = false;
  WebView().MainFrameWidget()->ApplyVisualProperties(visual_properties);
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  EXPECT_EQ(Color::FromRGB(/*cyan*/ 0, 255, 255),
            GetDocument().body()->GetComputedStyle()->VisitedDependentColor(
                GetCSSPropertyBackgroundColor()));
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreCorrectAfterLayoutChange) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          border: 0;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
        }
      </style>
      <div id='d' style='height: 0;'/>
      <input type='text' id='first' class='target' />
      )HTML");
  Compositor().BeginFrame();
  // Finish font loading, and trigger invalidations.
  font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();
  HTMLInputElement* first = DynamicTo<HTMLInputElement>(
      GetDocument().getElementById(AtomicString("first")));
  // Focus the element and check the line bounds.
  first->Focus();
  first->SetValue("hello world");
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  Vector<gfx::Rect>& expected = widget->GetVisibleLineBoundsOnScreen();
  // Offset each line bound by 200 pixels downwards (for after layout shift).
  for (auto& i : expected) {
    i.Offset(0, 200);
  }

  GetDocument()
      .getElementById(AtomicString("d"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 200px"));
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i), actual.at(i));
  }
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreCorrectAfterPageScroll) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          border: 0;
          height: 150vh;
          overflow: scrollY;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
          position: absolute;
          top: 100px;
        }
      </style>
      <textarea type='text' id='first' class='target' >
          The quick brown fox jumps over the lazy dog.
      </textarea>
      )HTML");
  Compositor().BeginFrame();
  // Finish font loading, and trigger invalidations.
  font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();
  HTMLTextAreaElement* first = DynamicTo<HTMLTextAreaElement>(
      GetDocument().getElementById(AtomicString("first")));
  // Focus the element and check the line bounds.
  first->Focus();
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);

  Vector<gfx::Rect> expected;
  for (auto& i : widget->GetVisibleLineBoundsOnScreen()) {
    gfx::Rect bound(i.origin(), i.size());
    bound.Offset(0, -50);
    expected.push_back(bound);
  }

  // Scroll by 50 pixels down.
  widget->FocusedLocalFrameInWidget()->View()->LayoutViewport()->ScrollBy(
      ScrollOffset(0, 50), mojom::blink::ScrollType::kUser);
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);

  // As line bounds are calculated in document coordinates, a document scroll
  // should not have any effect. Assert that they are the same as before.
  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i).ToString(), actual.at(i).ToString());
  }
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreCorrectAfterElementScroll) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          border: 0;
          height: 150vh;
          overflow: scrollY;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
          overflow-y: scroll;
          position: absolute;
          top: 150px;
        }
      </style>
      <textarea type='text' id='first' class='target' >
          The quick brown fox jumps over the lazy dog.
          The quick brown fox jumps over the lazy dog.
          The quick brown fox jumps over the lazy dog.
          The quick brown fox jumps over the lazy dog.
      </textarea>
      )HTML");
  Compositor().BeginFrame();
  // Finish font loading, and trigger invalidations.
  font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();
  HTMLTextAreaElement* first = DynamicTo<HTMLTextAreaElement>(
      GetDocument().getElementById(AtomicString("first")));
  // Focus the element and check the line bounds.
  first->Focus();
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  Vector<gfx::Rect> expected;

  // Offset each line bound by 50 pixels upwards (for after a scroll down).
  for (auto& i : widget->GetVisibleLineBoundsOnScreen()) {
    gfx::Rect bound(i.origin(), i.size());
    bound.Offset(0, -50);
    expected.push_back(bound);
  }

  // Scroll element by 50 pixels down.
  GetDocument().FocusedElement()->scrollBy(0, 50);
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);

  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  EXPECT_EQ(expected.size(), actual.size());
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i), actual.at(i));
  }
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreCorrectAfterCommit) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          border: 0;
          height: 150vh;
          overflow: scrollY;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
          overflow-y: scroll;
        }
      </style>
      <textarea type='text' id='first' class='target' ></textarea>
      )HTML");
  Compositor().BeginFrame();
  // Finish font loading, and trigger invalidations.
  font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();
  HTMLTextAreaElement* first = DynamicTo<HTMLTextAreaElement>(
      GetDocument().getElementById(AtomicString("first")));
  // Focus the element and check the line bounds.
  first->Focus();
  gfx::Point origin =
      first->GetBoundingClientRect()->ToEnclosingRect().origin();
  String text = "hello world";
  for (wtf_size_t i = 0; i < text.length(); ++i) {
    first->SetValue(first->Value() + text[i]);
    widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
    EXPECT_EQ(1U, widget->GetVisibleLineBoundsOnScreen().size());
    EXPECT_EQ(gfx::Rect(origin.x(), origin.y(), 10 * (i + 1), 10),
              widget->GetVisibleLineBoundsOnScreen().at(0));
  }
  first->SetValue(first->Value() + "\n");
  String new_text = "goodbye world";
  for (wtf_size_t i = 0; i < new_text.length(); ++i) {
    first->SetValue(first->Value() + new_text[i]);
    widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
    EXPECT_EQ(2U, widget->GetVisibleLineBoundsOnScreen().size());
    EXPECT_EQ(gfx::Rect(origin.x(), origin.y() + 10, 10 * (i + 1), 10),
              widget->GetVisibleLineBoundsOnScreen().at(1));
  }
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreCorrectAfterDelete) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest request("https://example.com/test.html", "text/html");
  SimSubresourceRequest font_resource("https://example.com/Ahem.woff2",
                                      "font/woff2");
  LoadURL("https://example.com/test.html");
  request.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          border: 0;
          height: 150vh;
          overflow: scrollY;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
          overflow-y: scroll;
        }
      </style>
      <textarea type='text' id='first' class='target' ></textarea>
      )HTML");
  Compositor().BeginFrame();
  // Finish font loading, and trigger invalidations.
  font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();
  HTMLTextAreaElement* first = DynamicTo<HTMLTextAreaElement>(
      GetDocument().getElementById(AtomicString("first")));

  first->Focus();
  first->SetValue("hello world\rgoodbye world");
  gfx::Point origin =
      first->GetBoundingClientRect()->ToEnclosingRect().origin();

  String last_line = "goodbye world";
  for (wtf_size_t i = last_line.length() - 1; i > 0; --i) {
    widget->FocusedWebLocalFrameInWidget()->DeleteSurroundingText(1, 0);
    widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
    EXPECT_EQ(2U, widget->GetVisibleLineBoundsOnScreen().size());
    EXPECT_EQ(gfx::Rect(origin.x(), origin.y() + 10, 10 * i, 10),
              widget->GetVisibleLineBoundsOnScreen().at(1));
  }

  // Remove the last character on the second line.
  // This is outside the for loop as after this happens, there should only be 1
  // line bound.
  widget->FocusedWebLocalFrameInWidget()->DeleteSurroundingText(1, 0);
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  EXPECT_EQ(1U, widget->GetVisibleLineBoundsOnScreen().size());

  // Remove the new line character.
  widget->FocusedWebLocalFrameInWidget()->DeleteSurroundingText(1, 0);
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  EXPECT_EQ(1U, widget->GetVisibleLineBoundsOnScreen().size());

  String first_line = "hello world";
  for (wtf_size_t i = first_line.length() - 1; i > 0; --i) {
    widget->FocusedWebLocalFrameInWidget()->DeleteSurroundingText(1, 0);
    widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
    EXPECT_EQ(1U, widget->GetVisibleLineBoundsOnScreen().size());
    EXPECT_EQ(gfx::Rect(origin.x(), origin.y(), 10 * i, 10),
              widget->GetVisibleLineBoundsOnScreen().at(0));
  }

  // Remove last character
  widget->FocusedWebLocalFrameInWidget()->DeleteSurroundingText(1, 0);
  widget->UpdateAllLifecyclePhases(DocumentUpdateReason::kTest);
  EXPECT_EQ(0U, widget->GetVisibleLineBoundsOnScreen().size());
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsInFrame) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest child_frame_resource("https://example.com/child_frame.html",
                                  "text/html");
  SimSubresourceRequest child_font_resource("https://example.com/Ahem.woff2",
                                            "font/woff2");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      R"HTML(
        <!doctype html>
        <style>
          html, body, iframe {
            margin: 0;
            padding: 0;
            border: 0;
          }
        </style>
        <div style='height: 123px;'></div>
        <iframe src='https://example.com/child_frame.html'
                id='child_frame' width='300px' height='300px'></iframe>)HTML");
  Compositor().BeginFrame();

  child_frame_resource.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
        }
      </style>
      <div style='height: 42px;'></div>
      <input type='text' id='first' class='target' value='ABCD' />
      <script>
        first.focus();
      </script>
      )HTML");
  Compositor().BeginFrame();

  child_font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();

  Vector<gfx::Rect> expected(Vector({gfx::Rect(0, /* 123+42= */ 165, 40, 10)}));
  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  EXPECT_EQ(expected.size(), actual.size());
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i), actual.at(i));
  }
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsWithDifferentZoom) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(1000, 1000));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest child_frame_resource("https://example.com/child_frame.html",
                                  "text/html");
  SimSubresourceRequest child_font_resource("https://example.com/Ahem.woff2",
                                            "font/woff2");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      R"HTML(
        <!doctype html>
        <style>
          html, body, iframe {
            margin: 0;
            padding: 0;
            border: 0;
          }
          html {
            zoom: 1.2;
          }
        </style>
        <div style='height: 70px;'></div>
        <iframe src='https://example.com/child_frame.html'
                id='child_frame' width='300px' height='300px'></iframe>)HTML");
  Compositor().BeginFrame();

  child_frame_resource.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        html {
          zoom: 1.5;
        }
        body {
          margin: 0;
          padding: 0;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
        }
      </style>
      <div style='height: 40px;'></div>
      <input type='text' id='first' class='target' value='ABCD' />
      <script>
        first.focus();
      </script>
      )HTML");
  Compositor().BeginFrame();

  child_font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();

  Vector<gfx::Rect> expected(
      Vector({gfx::Rect(0, /* 70*1.2+40*1.2*1.5= */ 156, /* 40*1.2*1.5= */ 72,
                        /* 10*1.2*1.5= */ 18)}));
  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  EXPECT_EQ(expected.size(), actual.size());
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i), actual.at(i));
  }
}

TEST_F(WebFrameWidgetSimTest, TestLineBoundsAreClippedInSubframe) {
  std::unique_ptr<ScopedReportVisibleLineBoundsForTest> enabled =
      std::make_unique<ScopedReportVisibleLineBoundsForTest>(true);
  WebView().ResizeVisualViewport(gfx::Size(200, 200));
  auto* widget = WebView().MainFrameViewWidget();
  SimRequest main_resource("https://example.com/test.html", "text/html");
  SimRequest child_frame_resource("https://example.com/child_frame.html",
                                  "text/html");
  SimSubresourceRequest child_font_resource("https://example.com/Ahem.woff2",
                                            "font/woff2");

  LoadURL("https://example.com/test.html");
  main_resource.Complete(
      R"HTML(
        <!doctype html>
        <style>
          html, body, iframe {
            margin: 0;
            padding: 0;
            border: 0;
          }
        </style>
        <div style='height: 100px;'></div>
        <iframe src='https://example.com/child_frame.html'
                id='child_frame' width='200px' height='100px'></iframe>)HTML");
  Compositor().BeginFrame();

  child_frame_resource.Complete(
      R"HTML(
      <!doctype html>
      <style>
        @font-face {
          font-family: custom-font;
          src: url(https://example.com/Ahem.woff2) format("woff2");
        }
        body {
          margin: 0;
          padding: 0;
          zoom: 11;
        }
        .target {
          font: 10px/1 custom-font, monospace;
          margin: 0;
          padding: 0;
          border: none;
        }
      </style>
      <input type='text' id='first' class='target' value='ABCD' />
      <script>
        first.focus();
      </script>
      )HTML");
  Compositor().BeginFrame();

  child_font_resource.Complete(
      *test::ReadFromFile(test::CoreTestDataPath("Ahem.woff2")));
  Compositor().BeginFrame();

  // The expected top value is 100 because of the spacer div in the main frame.
  // The expected width is 40 * 11 = 440 but this should be clipped to the
  // screen width which is 200px.
  // The expected height is 10 * 11 = 110 but this should be clipped as to the
  // screen height of 200px - 100px for the top of the bound.
  Vector<gfx::Rect> expected(Vector({gfx::Rect(0, 100, 200, 100)}));
  Vector<gfx::Rect>& actual = widget->GetVisibleLineBoundsOnScreen();
  EXPECT_EQ(expected.size(), actual.size());
  for (wtf_size_t i = 0; i < expected.size(); ++i) {
    EXPECT_EQ(expected.at(i), actual.at(i));
  }
}

class EventHandlingWebFrameWidgetSimTest : public SimTest {
 public:
  void SetUp() override {
    SimTest::SetUp();

    WebView().StopDeferringMainFrameUpdate();
    GetWebFrameWidget().UpdateCompositorViewportRect(gfx::Rect(200, 100));
    Compositor().BeginFrame();
  }

  frame_test_helpers::TestWebFrameWidget* CreateWebFrameWidget(
      base::PassKey<WebLocalFrame> pass_key,
      CrossVariantMojoAssociatedRemote<
          mojom::blink::FrameWidgetHostInterfaceBase> frame_widget_host,
      CrossVariantMojoAssociatedReceiver<mojom::blink::FrameWidgetInterfaceBase>
          frame_widget,
      CrossVariantMojoAssociatedRemote<mojom::blink::WidgetHostInterfaceBase>
          widget_host,
      CrossVariantMojoAssociatedReceiver<mojom::blink::WidgetInterfaceBase>
          widget,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner,
      const viz::FrameSinkId& frame_sink_id,
      bool hidden,
      bool never_composited,
      bool is_for_child_local_root,
      bool is_for_nested_main_frame,
      bool is_for_scalable_page) override {
    return MakeGarbageCollected<TestWebFrameWidget>(
        pass_key, std::move(frame_widget_host), std::move(frame_widget),
        std::move(widget_host), std::move(widget), std::move(task_runner),
        frame_sink_id, hidden, never_composited, is_for_child_local_root,
        is_for_nested_main_frame, is_for_scalable_page);
  }

 protected:
  // A test `cc::SwapPromise` implementation that can be used to track the state
  // of the swap promise.
  class TestSwapPromise : public cc::SwapPromise {
   public:
    enum class State {
      kPending,
      kResolved,
      kBroken,
      kMaxValue = kBroken,
    };

    explicit TestSwapPromise(State* state) : state_(state) {
      DCHECK(state_);
      *state_ = State::kPending;
    }

    void DidActivate() override {}

    void WillSwap(viz::CompositorFrameMetadata* metadata) override {}

    void DidSwap() override {
      DCHECK_EQ(State::kPending, *state_);
      *state_ = State::kResolved;
    }

    DidNotSwapAction DidNotSwap(DidNotSwapReason reason,
                                base::TimeTicks) override {
      DCHECK_EQ(State::kPending, *state_);
      *state_ = State::kBroken;
      return DidNotSwapAction::BREAK_PROMISE;
    }

    int64_t GetTraceId() const override { return 0; }

   private:
    State* const state_;
  };

  // A test `WebFrameWidget` implementation that fakes handling of an event.
  class TestWebFrameWidget : public frame_test_helpers::TestWebFrameWidget {
   public:
    using frame_test_helpers::TestWebFrameWidget::TestWebFrameWidget;

    WebInputEventResult HandleInputEvent(
        const WebCoalescedInputEvent& coalesced_event) override {
      if (event_causes_update_) {
        RequestUpdateIfNecessary();
      }
      return WebInputEventResult::kHandledApplication;
    }

    void set_event_causes_update(bool event_causes_update) {
      event_causes_update_ = event_causes_update;
    }

    void RequestUpdateIfNecessary() {
      if (update_requested_) {
        return;
      }

      LayerTreeHost()->SetNeedsCommit();
      update_requested_ = true;
    }

    void QueueSwapPromise(TestSwapPromise::State* state) {
      LayerTreeHost()->GetSwapPromiseManager()->QueueSwapPromise(
          std::make_unique<TestSwapPromise>(state));
    }

    void SendInputEventAndWaitForDispatch(
        std::unique_ptr<WebInputEvent> event) {
      MainThreadEventQueue* input_event_queue =
          GetWidgetInputHandlerManager()->input_event_queue();
      input_event_queue->HandleEvent(
          std::make_unique<WebCoalescedInputEvent>(std::move(event),
                                                   ui::LatencyInfo()),
          MainThreadEventQueue::DispatchType::kNonBlocking,
          mojom::blink::InputEventResultState::kSetNonBlocking,
          WebInputEventAttribution(), nullptr, base::DoNothing());
      FlushInputHandlerTasks();
    }

    void CompositeAndWaitForPresentation(SimCompositor& compositor) {
      base::RunLoop swap_run_loop;
      base::RunLoop presentation_run_loop;

      // Register callbacks for swap and presentation times.
      base::TimeTicks swap_time;
      NotifySwapAndPresentationTimeForTesting(
          {WTF::BindOnce(
               [](base::OnceClosure swap_quit_closure,
                  base::TimeTicks* swap_time, base::TimeTicks timestamp) {
                 DCHECK(!timestamp.is_null());
                 *swap_time = timestamp;
                 std::move(swap_quit_closure).Run();
               },
               swap_run_loop.QuitClosure(), WTF::Unretained(&swap_time)),
           WTF::BindOnce(
               [](base::OnceClosure presentation_quit_closure,
                  const viz::FrameTimingDetails& presentation_details) {
                 base::TimeTicks timestamp =
                     presentation_details.presentation_feedback.timestamp;
                 CHECK(!timestamp.is_null());
                 std::move(presentation_quit_closure).Run();
               },
               presentation_run_loop.QuitClosure())});

      // Composite and wait for the swap to complete.
      compositor.BeginFrame(/*time_delta_in_seconds=*/0.016, /*raster=*/true);
      swap_run_loop.Run();

      // Present and wait for it to complete.
      viz::FrameTimingDetails timing_details;
      timing_details.presentation_feedback = gfx::PresentationFeedback(
          swap_time + base::Milliseconds(2), base::Milliseconds(16), 0);
      LastCreatedFrameSink()->NotifyDidPresentCompositorFrame(1,
                                                              timing_details);
      presentation_run_loop.Run();
    }

   private:
    // Whether an update is already requested. Used to avoid calling
    // `LayerTreeHost::SetNeedsCommit()` multiple times.
    bool update_requested_ = false;

    // Whether handling of the event should end up in an update or not.
    bool event_causes_update_ = false;
  };

  TestWebFrameWidget& GetTestWebFrameWidget() {
    return static_cast<TestWebFrameWidget&>(GetWebFrameWidget());
  }
};

// Verifies that when a non-rAF-aligned event is handled without causing an
// update, swap promises will be broken.
TEST_F(EventHandlingWebFrameWidgetSimTest, NonRafAlignedEventWithoutUpdate) {
  TestSwapPromise::State swap_promise_state;
  GetTestWebFrameWidget().QueueSwapPromise(&swap_promise_state);
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().set_event_causes_update(false);

  GetTestWebFrameWidget().SendInputEventAndWaitForDispatch(
      std::make_unique<WebKeyboardEvent>(
          WebInputEvent::Type::kRawKeyDown, WebInputEvent::kNoModifiers,
          WebInputEvent::GetStaticTimeStampForTests()));
  EXPECT_EQ(TestSwapPromise::State::kBroken, swap_promise_state);
}

// Verifies that when a non-rAF-aligned event is handled without causing an
// update while an update is already requested, swap promises won't be broken.
TEST_F(EventHandlingWebFrameWidgetSimTest,
       NonRafAlignedEventWithoutUpdateAfterUpdate) {
  GetTestWebFrameWidget().RequestUpdateIfNecessary();

  TestSwapPromise::State swap_promise_state;
  GetTestWebFrameWidget().QueueSwapPromise(&swap_promise_state);
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().set_event_causes_update(false);

  GetTestWebFrameWidget().SendInputEventAndWaitForDispatch(
      std::make_unique<WebKeyboardEvent>(
          WebInputEvent::Type::kRawKeyDown, WebInputEvent::kNoModifiers,
          WebInputEvent::GetStaticTimeStampForTests()));
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().CompositeAndWaitForPresentation(Compositor());
  EXPECT_EQ(TestSwapPromise::State::kResolved, swap_promise_state);
}

// Verifies that when a non-rAF-aligned event is handled and causes an update,
// swap promises won't be broken.
TEST_F(EventHandlingWebFrameWidgetSimTest, NonRafAlignedEventWithUpdate) {
  TestSwapPromise::State swap_promise_state;
  GetTestWebFrameWidget().QueueSwapPromise(&swap_promise_state);
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().set_event_causes_update(true);

  GetTestWebFrameWidget().SendInputEventAndWaitForDispatch(
      std::make_unique<WebKeyboardEvent>(
          WebInputEvent::Type::kRawKeyDown, WebInputEvent::kNoModifiers,
          WebInputEvent::GetStaticTimeStampForTests()));
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().CompositeAndWaitForPresentation(Compositor());
  EXPECT_EQ(TestSwapPromise::State::kResolved, swap_promise_state);
}

// Verifies that when a rAF-aligned event is handled without causing an update,
// swap promises won't be broken.
TEST_F(EventHandlingWebFrameWidgetSimTest, RafAlignedEventWithoutUpdate) {
  TestSwapPromise::State swap_promise_state;
  GetTestWebFrameWidget().QueueSwapPromise(&swap_promise_state);
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().set_event_causes_update(false);

  GetTestWebFrameWidget().SendInputEventAndWaitForDispatch(
      std::make_unique<WebMouseEvent>(WebInputEvent::Type::kMouseMove, 0,
                                      base::TimeTicks::Now()));
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().CompositeAndWaitForPresentation(Compositor());
  EXPECT_EQ(TestSwapPromise::State::kResolved, swap_promise_state);
}

// Verifies that when a rAF-aligned event is handled and causes an update, swap
// promises won't be broken.
TEST_F(EventHandlingWebFrameWidgetSimTest, RafAlignedEventWithUpdate) {
  TestSwapPromise::State swap_promise_state;
  GetTestWebFrameWidget().QueueSwapPromise(&swap_promise_state);
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().set_event_causes_update(true);

  GetTestWebFrameWidget().SendInputEventAndWaitForDispatch(
      std::make_unique<WebMouseEvent>(WebInputEvent::Type::kMouseMove, 0,
                                      base::TimeTicks::Now()));
  EXPECT_EQ(TestSwapPromise::State::kPending, swap_promise_state);

  GetTestWebFrameWidget().CompositeAndWaitForPresentation(Compositor());
  EXPECT_EQ(TestSwapPromise::State::kResolved, swap_promise_state);
}

}  // namespace blink

"""


```