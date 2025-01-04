Response:
The user wants a summary of the functionality of the provided C++ code snippet from a Chromium Blink engine file. I need to identify the main purpose of the code and its interactions with web technologies like JavaScript, HTML, and CSS. I also need to analyze the test cases to understand the logic and potential errors.

Here's a plan:
1. **Identify the main purpose:** Look for keywords and test names to understand the core functionality being tested.
2. **Relate to web technologies:** Analyze how the tests interact with HTML elements, CSS styles, and potentially JavaScript (though less evident in this snippet).
3. **Analyze test cases for logic and I/O:**  Examine individual test cases, inferring their input (HTML/CSS) and expected output (state of scrollbars, use counters).
4. **Identify potential user/programming errors:**  Look for test cases that might highlight incorrect usage or common mistakes.
5. **Synthesize the information:** Combine the above points into a concise summary.
这是对`blink/renderer/core/layout/scrollbars_test.cc`文件部分代码的分析，这部分主要关注以下功能：

**核心功能归纳：**

这部分代码主要测试了 **滚动条的用户交互行为以及自定义滚动条样式对 UseCounter (用于统计功能使用情况) 的影响**，以及 **滚动槽 (scrollbar-gutter) 属性在不同场景下的表现**。

**具体功能点：**

1. **UseCounter 机制测试 (针对鼠标和触摸交互):**
   - **负面测试 (不触发 UseCounter 的情况):**
     - 使用鼠标滚轮滚动页面。
     - 鼠标悬停在滚动条上。
     - 点击滚动条的 track (除了 thumb 部分)。
     - 点击滚动条外，然后释放鼠标在滚动条的 thumb 上。
     - 使用触摸手势点击滚动条的 track (除了 thumb 部分)。
     - 使用触摸手势点击滚动条外，然后结束触摸在滚动条的 thumb 上。
   - **正面测试 (触发 UseCounter 的情况):**
     - 使用鼠标点击并拖动滚动条的 thumb。
     - 使用触摸手势点击滚动条的 thumb。
   - **涉及到的 UseCounter 特性 (WebFeature):**
     - `kVerticalScrollbarThumbScrollingWithMouse`
     - `kHorizontalScrollbarThumbScrollingWithMouse`
     - `kVerticalScrollbarThumbScrollingWithTouch`
     - `kHorizontalScrollbarThumbScrollingWithTouch`

2. **自定义滚动条样式对 UseCounter 的影响:**
   - 测试了使用百分比长度单位 (`%`) 定义自定义滚动条的宽度/高度和 thumb 的最小宽度/高度时，`kCustomScrollbarPercentThickness` 和 `kCustomScrollbarPartPercentLength` 这两个 UseCounter 是否会被触发。

3. **滚动角 (Scroll Corner) 的测试:**
   - 测试了当没有滚动条时，滚动角是否也会消失 (针对 overlay scrollbars 启用时)。

4. **自定义滚动条布局更新优化:**
   - 测试了在修改影响自定义滚动条尺寸的样式后，是否需要立即进行 beginFrame 操作来更新布局，以验证优化的效果。

5. **自定义滚动条的假设厚度 (Hypothetical Thickness) 计算:**
   - 测试了在有自定义滚动条样式的情况下，如何计算滚动条的理论厚度，这可能用于布局计算。

6. **无限滚动场景下的滚动条按钮行为:**
   - 测试了在无限滚动页面中，用户按下滚动条按钮后，即使在内容加载后，滚动是否会继续进行。

7. **自定义滚动条 track 的 margin 处理:**
   - 测试了当自定义滚动条的 track 设置了带小数或者缩放后的 margin 时，是否会导致断言失败 (DCHECK failure)，验证了 margin 值的正确处理。

8. **滚动条的配色方案 (Color Scheme):**
   - 测试了在设置了 `color-scheme` CSS 属性后，滚动条的不同部分的绘制是否会使用对应的配色方案。

9. **滚动槽 (scrollbar-gutter) 属性测试:**
   - 测试了 `scrollbar-gutter` 属性的不同值 (`auto`, `stable`, `stable both-edges`) 在经典滚动条和 overlay 滚动条模式下，以及在不同的 `writing-mode` (水平和垂直) 下对元素布局 (offset 和 client 尺寸) 和滚动条占用空间的影响。

**与 JavaScript, HTML, CSS 的关系举例：**

* **HTML:**  代码中使用了大量的 HTML 字符串来创建测试页面结构，例如 `<div>` 元素，并设置了 `id` 和 `style` 属性。
    ```cpp
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <div id='scrollable'>
       <div id='content'></div>
      </div>
    )HTML");
    ```
* **CSS:** 代码中通过内联样式或者 `<style>` 标签来设置 CSS 属性，影响滚动条的显示和行为，例如：
    ```cpp
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
       #content { height: 350px; width: 350px; }
      </style>
      ...
    )HTML");
    ```
    以及自定义滚动条样式：
    ```cpp
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        ::-webkit-scrollbar { width: 10px; height: 10%; }
        ::-webkit-scrollbar-thumb { min-width: 10%; min-height: 10px; }
      </style>
      ...
    )HTML");
    ```
    还有针对 `scrollbar-gutter` 属性的测试：
    ```cpp
    request.Complete(R"HTML(
      <!DOCTYPE html>
      <style>
        div {
          width: 100px;
          height: 100px;
          overflow: auto;
          writing-mode: horizontal-tb;
        }
        #auto {
          scrollbar-gutter: auto;
        }
        ...
      </style>
      ...
    )HTML");
    ```
* **JavaScript:** 虽然这段代码主要是 C++ 测试代码，但在某些测试用例中，使用了 JavaScript 来动态修改页面内容或样式，例如在无限滚动的测试中：
    ```cpp
    MainFrame().ExecuteScript(WebScriptSource(
        "document.getElementById('big').style.height = '1000px';"));
    ```

**逻辑推理 (假设输入与输出):**

**示例 1：`UseCounterPositiveWhenThumbIsScrolledWithMouse`**

* **假设输入:**
    * HTML 包含一个可滚动的 `<div>` 元素。
    * 用户在垂直滚动条的 thumb 部分按下鼠标。
    * 用户释放鼠标。
* **预期输出:**
    * `GetDocument().IsUseCounted(WebFeature::kVerticalScrollbarThumbScrollingWithMouse)` 返回 `true`。

**示例 2：`CustomScrollbarPercentSize`**

* **假设输入:**
    * HTML 包含一个设置了自定义滚动条样式的 `<div>`，其中滚动条的 `height` 和 thumb 的 `min-width` 使用了百分比单位。
* **预期输出:**
    * `GetDocument().IsUseCounted(WebFeature::kCustomScrollbarPercentThickness)` 返回 `true`。
    * `GetDocument().IsUseCounted(WebFeature::kCustomScrollbarPartPercentLength)` 返回 `true`。

**用户或编程常见的使用错误举例：**

1. **错误地认为鼠标悬停在滚动条上会触发 thumb 滚动的 UseCounter。**  测试用例 `UseCounterNegativeWhenThumbIsNotScrolledWithMouse` 中明确指出悬停不会触发。
2. **在使用触摸设备时，错误地认为点击滚动条的 track 也会触发 thumb 滚动的 UseCounter。**  测试用例 `UseCounterNegativeWhenThumbIsNotScrolledWithTouch` 中验证了这一点。
3. **在编写自定义滚动条样式时，错误地使用了不支持的长度单位或属性，导致样式失效或渲染错误。** 虽然代码本身不直接展示这个错误，但测试用例 `CustomScrollbarPercentSize` 强调了对百分比单位的支持，暗示了其他单位可能需要不同的处理或统计方式。
4. **不理解 `scrollbar-gutter` 属性在不同场景下的表现，例如在 overlay scrollbars 启用时，`stable` 和 `auto` 的行为可能一致。** 测试用例 `ScrollbarGutterWithHorizontalTextAndOverlayScrollbars` 和 `ScrollbarGutterWithVerticalTextAndOverlayScrollbars` 明确了这一点。

总而言之，这段代码细致地测试了 Blink 引擎中滚动条的各种交互行为、自定义样式以及相关的功能统计，确保了滚动条功能的正确性和用户体验的一致性。

Prompt: 
```
这是目录为blink/renderer/core/layout/scrollbars_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能

"""
 )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();
  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  EXPECT_TRUE(scrollable_area->HorizontalScrollbar());
  Scrollbar* vertical_scrollbar = scrollable_area->VerticalScrollbar();
  Scrollbar* horizontal_scrollbar = scrollable_area->HorizontalScrollbar();
  EXPECT_EQ(vertical_scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  EXPECT_EQ(horizontal_scrollbar->PressedPart(), ScrollbarPart::kNoPart);

  // Scrolling the page with a mouse wheel won't trigger the UseCounter.
  auto& widget = GetWebFrameWidget();
  widget.DispatchThroughCcInputHandler(
      GenerateWheelGestureEvent(WebInputEvent::Type::kGestureScrollBegin,
                                gfx::Point(100, 100), ScrollOffset(0, -100)));
  widget.DispatchThroughCcInputHandler(
      GenerateWheelGestureEvent(WebInputEvent::Type::kGestureScrollUpdate,
                                gfx::Point(100, 100), ScrollOffset(0, -100)));
  widget.DispatchThroughCcInputHandler(GenerateWheelGestureEvent(
      WebInputEvent::Type::kGestureScrollEnd, gfx::Point(100, 100)));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithMouse));

  // Hovering over the vertical scrollbar won't trigger the UseCounter.
  HandleMouseMoveEvent(195, 5);
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithMouse));

  // Hovering over the horizontal scrollbar won't trigger the UseCounter.
  HandleMouseMoveEvent(5, 195);
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kHorizontalScrollbarThumbScrollingWithMouse));

  // Clicking on the vertical scrollbar won't trigger the UseCounter.
  HandleMousePressEvent(195, 175);
  EXPECT_EQ(vertical_scrollbar->PressedPart(),
            ScrollbarPart::kForwardTrackPart);
  HandleMouseReleaseEvent(195, 175);
  // Let injected scroll gesture run.
  widget.FlushInputHandlerTasks();
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithMouse));

  // Clicking on the horizontal scrollbar won't trigger the UseCounter.
  HandleMousePressEvent(175, 195);
  EXPECT_EQ(horizontal_scrollbar->PressedPart(),
            ScrollbarPart::kForwardTrackPart);
  HandleMouseReleaseEvent(175, 195);
  // Let injected scroll gesture run.
  widget.FlushInputHandlerTasks();
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kHorizontalScrollbarThumbScrollingWithMouse));

  // Clicking outside the scrollbar and then releasing over the thumb of the
  // vertical scrollbar won't trigger the UseCounter.
  HandleMousePressEvent(50, 50);
  HandleMouseMoveEvent(195, 5);
  HandleMouseReleaseEvent(195, 5);
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithMouse));

  // Clicking outside the scrollbar and then releasing over the thumb of the
  // horizontal scrollbar won't trigger the UseCounter.
  HandleMousePressEvent(50, 50);
  HandleMouseMoveEvent(5, 195);
  HandleMouseReleaseEvent(5, 195);
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kHorizontalScrollbarThumbScrollingWithMouse));
}

TEST_P(ScrollbarsTest, UseCounterPositiveWhenThumbIsScrolledWithMouse) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
     #content { height: 350px; width: 350px; }
    </style>
    <div id='scrollable'>
     <div id='content'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();
  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  EXPECT_TRUE(scrollable_area->HorizontalScrollbar());
  Scrollbar* vertical_scrollbar = scrollable_area->VerticalScrollbar();
  Scrollbar* horizontal_scrollbar = scrollable_area->HorizontalScrollbar();
  EXPECT_EQ(vertical_scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  EXPECT_EQ(horizontal_scrollbar->PressedPart(), ScrollbarPart::kNoPart);

  // Clicking the thumb on the vertical scrollbar will trigger the UseCounter.
  HandleMousePressEvent(195, 5);
  EXPECT_EQ(vertical_scrollbar->PressedPart(), ScrollbarPart::kThumbPart);
  HandleMouseReleaseEvent(195, 5);
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithMouse));

  // Clicking the thumb on the horizontal scrollbar will trigger the UseCounter.
  HandleMousePressEvent(5, 195);
  EXPECT_EQ(horizontal_scrollbar->PressedPart(), ScrollbarPart::kThumbPart);
  HandleMouseReleaseEvent(5, 195);
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kHorizontalScrollbarThumbScrollingWithMouse));
}

TEST_P(ScrollbarsTest, UseCounterNegativeWhenThumbIsNotScrolledWithTouch) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
     #content { height: 350px; width: 350px; }
    </style>
    <div id='scrollable'>
     <div id='content'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();
  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  EXPECT_TRUE(scrollable_area->HorizontalScrollbar());
  Scrollbar* vertical_scrollbar = scrollable_area->VerticalScrollbar();
  Scrollbar* horizontal_scrollbar = scrollable_area->HorizontalScrollbar();
  EXPECT_EQ(vertical_scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  EXPECT_EQ(horizontal_scrollbar->PressedPart(), ScrollbarPart::kNoPart);

  // Tapping on the vertical scrollbar won't trigger the UseCounter.
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapDown, gfx::Point(195, 175)));
  EXPECT_EQ(vertical_scrollbar->PressedPart(),
            ScrollbarPart::kForwardTrackPart);
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapCancel, gfx::Point(195, 175)));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithTouch));

  // Tapping on the horizontal scrollbar won't trigger the UseCounter.
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapDown, gfx::Point(175, 195)));
  EXPECT_EQ(horizontal_scrollbar->PressedPart(),
            ScrollbarPart::kForwardTrackPart);
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapCancel, gfx::Point(175, 195)));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kHorizontalScrollbarThumbScrollingWithTouch));

  // Tapping outside the scrollbar and then releasing over the thumb of the
  // vertical scrollbar won't trigger the UseCounter.
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapDown, gfx::Point(50, 50)));
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapCancel, gfx::Point(195, 5)));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithTouch));

  // Tapping outside the scrollbar and then releasing over the thumb of the
  // horizontal scrollbar won't trigger the UseCounter.
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapDown, gfx::Point(50, 50)));
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapCancel, gfx::Point(5, 195)));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kHorizontalScrollbarThumbScrollingWithTouch));
}

TEST_P(ScrollbarsTest, UseCounterPositiveWhenThumbIsScrolledWithTouch) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
     #content { height: 350px; width: 350px; }
    </style>
    <div id='scrollable'>
     <div id='content'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();
  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  EXPECT_TRUE(scrollable_area->HorizontalScrollbar());
  Scrollbar* vertical_scrollbar = scrollable_area->VerticalScrollbar();
  Scrollbar* horizontal_scrollbar = scrollable_area->HorizontalScrollbar();
  EXPECT_EQ(vertical_scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  EXPECT_EQ(horizontal_scrollbar->PressedPart(), ScrollbarPart::kNoPart);

  // Clicking the thumb on the vertical scrollbar will trigger the UseCounter.
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapDown, gfx::Point(195, 5)));
  EXPECT_EQ(vertical_scrollbar->PressedPart(), ScrollbarPart::kThumbPart);
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapCancel, gfx::Point(195, 5)));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kVerticalScrollbarThumbScrollingWithTouch));

  // Clicking the thumb on the horizontal scrollbar will trigger the UseCounter.
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapDown, gfx::Point(5, 195)));
  EXPECT_EQ(horizontal_scrollbar->PressedPart(), ScrollbarPart::kThumbPart);
  WebView().MainFrameViewWidget()->HandleInputEvent(GenerateTouchGestureEvent(
      WebInputEvent::Type::kGestureTapCancel, gfx::Point(5, 195)));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kHorizontalScrollbarThumbScrollingWithTouch));
}

TEST_P(ScrollbarsTest, UseCounterCustomScrollbarPercentSize) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      ::-webkit-scrollbar { width: 10px; height: 10%; }
      ::-webkit-scrollbar-thumb { min-width: 10%; min-height: 10px; }
    </style>
    <div id="target" style="width: 100px; height: 100px; overflow: auto">
      <div id="child" style="width: 50px; height: 50px"></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  // No scrollbars initially.
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kCustomScrollbarPercentThickness));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCustomScrollbarPartPercentLength));

  // Show vertical scrollbar which uses fixed lengths for thickness
  // (width: 10px) and thumb minimum length (min-height: 10px).
  auto* child = GetDocument().getElementById(AtomicString("child"));
  child->setAttribute(html_names::kStyleAttr,
                      AtomicString("width: 50px; height: 200px"));
  Compositor().BeginFrame();
  EXPECT_FALSE(
      GetDocument().IsUseCounted(WebFeature::kCustomScrollbarPercentThickness));
  EXPECT_FALSE(GetDocument().IsUseCounted(
      WebFeature::kCustomScrollbarPartPercentLength));

  // Show horizontal scrollbar which uses percent lengths for thickness
  // (height: 10%) and thumb minimum length (min-width: 10%).
  child->setAttribute(html_names::kStyleAttr,
                      AtomicString("width: 200px; height: 50px"));
  Compositor().BeginFrame();
  EXPECT_TRUE(
      GetDocument().IsUseCounted(WebFeature::kCustomScrollbarPercentThickness));
  EXPECT_TRUE(GetDocument().IsUseCounted(
      WebFeature::kCustomScrollbarPartPercentLength));
}

TEST_P(ScrollbarsTest, CheckScrollCornerIfThereIsNoScrollbar) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #container {
        width: 50px;
        height: 100px;
        overflow-x: auto;
      }
      #content {
        width: 75px;
        height: 50px;
        background-color: green;
      }
      #container::-webkit-scrollbar {
        height: 8px;
        width: 8px;
      }
      #container::-webkit-scrollbar-corner {
        background: transparent;
      }
    </style>
    <div id='container'>
        <div id='content'></div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  auto* element = GetDocument().getElementById(AtomicString("container"));
  auto* scrollable_container = GetScrollableArea(*element);

  // There should initially be a scrollbar and a scroll corner.
  EXPECT_TRUE(scrollable_container->HasScrollbar());
  EXPECT_TRUE(scrollable_container->ScrollCorner());

  // Make the container non-scrollable so the scrollbar and corner disappear.
  element->setAttribute(html_names::kStyleAttr, AtomicString("width: 100px;"));
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EXPECT_FALSE(scrollable_container->HasScrollbar());
  EXPECT_FALSE(scrollable_container->ScrollCorner());
}

TEST_P(ScrollbarsTest, NoNeedsBeginFrameForCustomScrollbarAfterBeginFrame) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      ::-webkit-scrollbar { height: 20px; }
      ::-webkit-scrollbar-thumb { background-color: blue; }
      #target { width: 200px; height: 200px; overflow: scroll; }
    </style>
    <div id="target">
      <div style="width: 500px; height: 500px"></div>
    </div>
  )HTML");

  while (Compositor().NeedsBeginFrame())
    Compositor().BeginFrame();

  auto* target = GetDocument().getElementById(AtomicString("target"));
  auto* scrollbar = To<CustomScrollbar>(
      target->GetLayoutBox()->GetScrollableArea()->HorizontalScrollbar());
  LayoutCustomScrollbarPart* thumb = scrollbar->GetPart(kThumbPart);
  auto thumb_size = thumb->Size();
  EXPECT_FALSE(thumb->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(Compositor().NeedsBeginFrame());

  WebView().MainFrameViewWidget()->UpdateAllLifecyclePhases(
      DocumentUpdateReason::kTest);
  EXPECT_FALSE(thumb->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(Compositor().NeedsBeginFrame());

  target->setAttribute(html_names::kStyleAttr, AtomicString("width: 400px"));
  EXPECT_TRUE(Compositor().NeedsBeginFrame());
  Compositor().BeginFrame();
  EXPECT_FALSE(thumb->ShouldCheckForPaintInvalidation());
  EXPECT_FALSE(Compositor().NeedsBeginFrame());
  EXPECT_NE(thumb_size, thumb->Size());
}

TEST_P(ScrollbarsTest, CustomScrollbarHypotheticalThickness) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #target1::-webkit-scrollbar { width: 22px; height: 33px; }
      #target2::-webkit-scrollbar:horizontal { height: 13px; }
      ::-webkit-scrollbar:vertical { width: 21px; }
    </style>
    <div id="target1" style="width: 60px; height: 70px; overflow: scroll"></div>
    <div id="target2" style="width: 80px; height: 90px; overflow: scroll"></div>
  )HTML");

  Compositor().BeginFrame();

  auto* target1 = GetDocument().getElementById(AtomicString("target1"));
  auto* scrollable_area1 = target1->GetLayoutBox()->GetScrollableArea();
  EXPECT_EQ(
      33, CustomScrollbar::HypotheticalScrollbarThickness(
              scrollable_area1, kHorizontalScrollbar, target1->GetLayoutBox()));
  EXPECT_EQ(22,
            CustomScrollbar::HypotheticalScrollbarThickness(
                scrollable_area1, kVerticalScrollbar, target1->GetLayoutBox()));

  auto* target2 = GetDocument().getElementById(AtomicString("target2"));
  auto* scrollable_area2 = target2->GetLayoutBox()->GetScrollableArea();
  EXPECT_EQ(
      13, CustomScrollbar::HypotheticalScrollbarThickness(
              scrollable_area2, kHorizontalScrollbar, target2->GetLayoutBox()));
  EXPECT_EQ(21,
            CustomScrollbar::HypotheticalScrollbarThickness(
                scrollable_area2, kVerticalScrollbar, target2->GetLayoutBox()));
}

// For infinite scrolling page (load more content when scroll to bottom), user
// press on scrollbar button should keep scrolling after content loaded.
// Disable on Android since VirtualTime not work for Android.
// http://crbug.com/633321
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
TEST_P(ScrollbarsTestWithVirtualTimer,
       DISABLED_PressScrollbarButtonOnInfiniteScrolling) {
#else
TEST_P(ScrollbarsTestWithVirtualTimer,
       PressScrollbarButtonOnInfiniteScrolling) {
#endif
  TimeAdvance();
  GetDocument().GetFrame()->GetSettings()->SetScrollAnimatorEnabled(false);
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  RunTasksForPeriod(base::Milliseconds(1000));
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    html, body{
      margin: 0;
    }
    ::-webkit-scrollbar {
      width: 30px;
      height: 30px;
    }
    ::-webkit-scrollbar-button {
      width: 30px;
      height: 30px;
      background: #00FF00;
      display: block;
    }
    ::-webkit-scrollbar-thumb {
      background: #0000FF;
    }
    ::-webkit-scrollbar-track {
      background: #aaaaaa;
    }
    #big {
      height: 400px;
    }
    </style>
    <div id='big'>
    </div>
  )HTML");

  Compositor().BeginFrame();

  ScrollableArea* scrollable_area =
      WebView().MainFrameImpl()->GetFrameView()->LayoutViewport();
  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();

  // Scroll to bottom.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 400),
                                   mojom::blink::ScrollType::kProgrammatic,
                                   mojom::blink::ScrollBehavior::kInstant);
  EXPECT_EQ(scrollable_area->ScrollOffsetInt(), gfx::Vector2d(0, 200));

  HandleMouseMoveEvent(195, 195);
  HandleMousePressEvent(195, 195);
  ASSERT_EQ(scrollbar->PressedPart(), ScrollbarPart::kForwardButtonEndPart);

  // Wait for 2 delay.
  RunTasksForPeriod(base::Milliseconds(1000));
  RunTasksForPeriod(base::Milliseconds(1000));
  // Change #big size.
  MainFrame().ExecuteScript(WebScriptSource(
      "document.getElementById('big').style.height = '1000px';"));
  Compositor().BeginFrame();

  RunTasksForPeriod(base::Milliseconds(1000));
  RunTasksForPeriod(base::Milliseconds(1000));

  // Verify that the scrollbar autopress timer requested some scrolls via
  // gestures. The button was pressed for 2 seconds and the timer fires
  // every 250ms - we should have at least 7 injected gesture updates.
  EXPECT_GT(GetWebFrameWidget().GetInjectedScrollEvents().size(), 6u);

  // Let injected scroll gestures run.
  GetWebFrameWidget().FlushInputHandlerTasks();
}

class ScrollbarTrackMarginsTest : public ScrollbarsTest {
 public:
  void PrepareTest(const String& track_style) {
    WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

    SimRequest request("https://example.com/test.html", "text/html");
    LoadURL("https://example.com/test.html");
    request.Complete(R"HTML(
      <!DOCTYPE html>
        <style>
        ::-webkit-scrollbar {
          width: 10px;
        })HTML" + track_style +
                     R"HTML(
        #d1 {
          position: absolute;
          left: 0;
          right: 0;
          top: 0;
          bottom: 0;
          overflow-x:scroll;
          overflow-y:scroll;
        }
      </style>
      <div id='d1'/>
    )HTML");

    // No DCHECK failure. Issue 801123.
    Compositor().BeginFrame();

    Element* div = GetDocument().getElementById(AtomicString("d1"));
    ASSERT_TRUE(div);

    auto* div_scrollable = GetScrollableArea(*div);

    ASSERT_TRUE(div_scrollable->HorizontalScrollbar());
    CustomScrollbar* horizontal_scrollbar =
        To<CustomScrollbar>(div_scrollable->HorizontalScrollbar());
    horizontal_track_ = horizontal_scrollbar->GetPart(kTrackBGPart);
    ASSERT_TRUE(horizontal_track_);

    ASSERT_TRUE(div_scrollable->VerticalScrollbar());
    CustomScrollbar* vertical_scrollbar =
        To<CustomScrollbar>(div_scrollable->VerticalScrollbar());
    vertical_track_ = vertical_scrollbar->GetPart(kTrackBGPart);
    ASSERT_TRUE(vertical_track_);
  }

  Persistent<LayoutCustomScrollbarPart> horizontal_track_;
  Persistent<LayoutCustomScrollbarPart> vertical_track_;
};

INSTANTIATE_PAINT_TEST_SUITE_P(ScrollbarTrackMarginsTest);

TEST_P(ScrollbarTrackMarginsTest,
       CustomScrollbarFractionalMarginsWillNotCauseDCHECKFailure) {
  PrepareTest(R"CSS(
    ::-webkit-scrollbar-track {
      margin-left: 10.2px;
      margin-top: 20.4px;
      margin-right: 30.6px;
      margin-bottom: 40.8px;
    })CSS");

  EXPECT_EQ(10, horizontal_track_->MarginLeft());
  EXPECT_EQ(31, horizontal_track_->MarginRight());
  EXPECT_EQ(20, vertical_track_->MarginTop());
  EXPECT_EQ(41, vertical_track_->MarginBottom());
}

TEST_P(ScrollbarTrackMarginsTest,
       CustomScrollbarScaledMarginsWillNotCauseDCHECKFailure) {
  WebView().SetZoomFactorForDeviceScaleFactor(1.25f);

  PrepareTest(R"CSS(
    ::-webkit-scrollbar-track {
      margin-left: 11px;
      margin-top: 21px;
      margin-right: 31px;
      margin-bottom: 41px;
    })CSS");

  EXPECT_EQ(14, horizontal_track_->MarginLeft());
  EXPECT_EQ(39, horizontal_track_->MarginRight());
  EXPECT_EQ(26, vertical_track_->MarginTop());
  EXPECT_EQ(51, vertical_track_->MarginBottom());
}

class ScrollbarColorSchemeTest : public ScrollbarAppearanceTest {};

INSTANTIATE_TEST_SUITE_P(NonOverlay,
                         ScrollbarColorSchemeTest,
                         testing::Values(false));

TEST_P(ScrollbarColorSchemeTest, ThemeEnginePaint) {
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();

  ScopedStubThemeEngine scoped_theme;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #scrollable {
        width: 100px;
        height: 100px;
        overflow: scroll;
        color-scheme: dark;
      }
      #filler {
        width: 200px;
        height: 200px;
      }
    </style>
    <div id="scrollable">
      <div id="filler"></div>
    </div>
  )HTML");

  ColorSchemeHelper color_scheme_helper(GetDocument());
  color_scheme_helper.SetPreferredColorScheme(
      mojom::blink::PreferredColorScheme::kDark);

  Compositor().BeginFrame();

  auto* theme_engine = static_cast<StubWebThemeEngine*>(
      WebThemeEngineHelper::GetNativeThemeEngine());
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            theme_engine->GetPaintedPartColorScheme(
                WebThemeEngine::kPartScrollbarHorizontalThumb));
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            theme_engine->GetPaintedPartColorScheme(
                WebThemeEngine::kPartScrollbarVerticalThumb));
  EXPECT_EQ(mojom::blink::ColorScheme::kDark,
            theme_engine->GetPaintedPartColorScheme(
                WebThemeEngine::kPartScrollbarCorner));
}

// Test scrollbar-gutter values with classic scrollbars and horizontal-tb text.
TEST_P(ScrollbarsTest, ScrollbarGutterWithHorizontalTextAndClassicScrollbars) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      div {
        width: 100px;
        height: 100px;
        overflow: auto;
        writing-mode: horizontal-tb;
      }
      #auto {
        scrollbar-gutter: auto;
      }
      #stable {
        scrollbar-gutter: stable;
      }
      #stable_both_edges {
        scrollbar-gutter: stable both-edges;
      }
    </style>
    <div id="auto"></div>
    <div id="stable"></div>
    <div id="stable_both_edges"></div>
  )HTML");
  Compositor().BeginFrame();
  auto* auto_ = GetDocument().getElementById(AtomicString("auto"));
  auto* box_auto = auto_->GetLayoutBox();
  EXPECT_EQ(box_auto->OffsetWidth(), 100);
  EXPECT_EQ(box_auto->ClientWidth(), 100);
  PhysicalBoxStrut box_auto_scrollbars = box_auto->ComputeScrollbars();
  EXPECT_EQ(box_auto_scrollbars.top, 0);
  EXPECT_EQ(box_auto_scrollbars.bottom, 0);
  EXPECT_EQ(box_auto_scrollbars.left, 0);
  EXPECT_EQ(box_auto_scrollbars.right, 0);

  auto* stable = GetDocument().getElementById(AtomicString("stable"));
  auto* box_stable = stable->GetLayoutBox();
  EXPECT_EQ(box_stable->OffsetWidth(), 100);
  EXPECT_EQ(box_stable->ClientWidth(), 85);
  PhysicalBoxStrut box_stable_scrollbars = box_stable->ComputeScrollbars();
  EXPECT_EQ(box_stable_scrollbars.top, 0);
  EXPECT_EQ(box_stable_scrollbars.bottom, 0);
  EXPECT_EQ(box_stable_scrollbars.left, 0);
  EXPECT_EQ(box_stable_scrollbars.right, 15);

  auto* stable_both_edges =
      GetDocument().getElementById(AtomicString("stable_both_edges"));
  auto* box_stable_both_edges = stable_both_edges->GetLayoutBox();
  EXPECT_EQ(box_stable_both_edges->OffsetWidth(), 100);
  EXPECT_EQ(box_stable_both_edges->ClientWidth(), 70);
  PhysicalBoxStrut box_stable_both_edges_scrollbars =
      box_stable_both_edges->ComputeScrollbars();
  EXPECT_EQ(box_stable_both_edges_scrollbars.top, 0);
  EXPECT_EQ(box_stable_both_edges_scrollbars.bottom, 0);
  EXPECT_EQ(box_stable_both_edges_scrollbars.left, 15);
  EXPECT_EQ(box_stable_both_edges_scrollbars.right, 15);
}

// Test scrollbar-gutter values with classic scrollbars and vertical-rl text.
TEST_P(ScrollbarsTest, ScrollbarGutterWithVerticalTextAndClassicScrollbars) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      div {
        width: 100px;
        height: 100px;
        overflow: auto;
        writing-mode: vertical-rl;
      }
      #auto {
        scrollbar-gutter: auto;
      }
      #stable {
        scrollbar-gutter: stable;
      }
      #stable_both_edges {
        scrollbar-gutter: stable both-edges;
      }
    </style>
    <div id="auto"></div>
    <div id="stable"></div>
    <div id="stable_both_edges"></div>
  )HTML");
  Compositor().BeginFrame();
  auto* auto_ = GetDocument().getElementById(AtomicString("auto"));
  auto* box_auto = auto_->GetLayoutBox();
  EXPECT_EQ(box_auto->OffsetHeight(), 100);
  EXPECT_EQ(box_auto->ClientHeight(), 100);
  PhysicalBoxStrut box_auto_scrollbars = box_auto->ComputeScrollbars();
  EXPECT_EQ(box_auto_scrollbars.top, 0);
  EXPECT_EQ(box_auto_scrollbars.bottom, 0);
  EXPECT_EQ(box_auto_scrollbars.left, 0);
  EXPECT_EQ(box_auto_scrollbars.right, 0);

  auto* stable = GetDocument().getElementById(AtomicString("stable"));
  auto* box_stable = stable->GetLayoutBox();
  EXPECT_EQ(box_stable->OffsetHeight(), 100);
  EXPECT_EQ(box_stable->ClientHeight(), 85);
  PhysicalBoxStrut box_stable_scrollbars = box_stable->ComputeScrollbars();
  EXPECT_EQ(box_stable_scrollbars.top, 0);
  EXPECT_EQ(box_stable_scrollbars.bottom, 15);
  EXPECT_EQ(box_stable_scrollbars.left, 0);
  EXPECT_EQ(box_stable_scrollbars.right, 0);

  auto* stable_both_edges =
      GetDocument().getElementById(AtomicString("stable_both_edges"));
  auto* box_stable_both_edges = stable_both_edges->GetLayoutBox();
  EXPECT_EQ(box_stable_both_edges->OffsetHeight(), 100);
  EXPECT_EQ(box_stable_both_edges->ClientHeight(), 70);
  PhysicalBoxStrut box_stable_both_edges_scrollbars =
      box_stable_both_edges->ComputeScrollbars();
  EXPECT_EQ(box_stable_both_edges_scrollbars.top, 15);
  EXPECT_EQ(box_stable_both_edges_scrollbars.bottom, 15);
  EXPECT_EQ(box_stable_both_edges_scrollbars.left, 0);
  EXPECT_EQ(box_stable_both_edges_scrollbars.right, 0);
}

// Test scrollbar-gutter values with overlay scrollbars and horizontal-tb text.
TEST_P(ScrollbarsTest, ScrollbarGutterWithHorizontalTextAndOverlayScrollbars) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      div {
        width: 100px;
        height: 100px;
        overflow: auto;
        writing-mode: horizontal-tb;
      }
      #auto {
        scrollbar-gutter: auto;
      }
      #stable {
        scrollbar-gutter: stable;
      }
      #stable_both_edges {
        scrollbar-gutter: stable both-edges;
      }
    </style>
    <div id="auto"></div>
    <div id="stable"></div>
    <div id="stable_both_edges"></div>
  )HTML");
  Compositor().BeginFrame();
  auto* auto_ = GetDocument().getElementById(AtomicString("auto"));
  auto* box_auto = auto_->GetLayoutBox();
  EXPECT_EQ(box_auto->OffsetWidth(), 100);
  EXPECT_EQ(box_auto->ClientWidth(), 100);
  PhysicalBoxStrut box_auto_scrollbars = box_auto->ComputeScrollbars();
  EXPECT_EQ(box_auto_scrollbars.top, 0);
  EXPECT_EQ(box_auto_scrollbars.bottom, 0);
  EXPECT_EQ(box_auto_scrollbars.left, 0);
  EXPECT_EQ(box_auto_scrollbars.right, 0);

  auto* stable = GetDocument().getElementById(AtomicString("stable"));
  auto* box_stable = stable->GetLayoutBox();
  EXPECT_EQ(box_stable->OffsetWidth(), 100);
  EXPECT_EQ(box_stable->ClientWidth(), 100);
  PhysicalBoxStrut box_stable_scrollbars = box_stable->ComputeScrollbars();
  EXPECT_EQ(box_stable_scrollbars.top, 0);
  EXPECT_EQ(box_stable_scrollbars.bottom, 0);
  EXPECT_EQ(box_stable_scrollbars.left, 0);
  EXPECT_EQ(box_stable_scrollbars.right, 0);

  auto* stable_both_edges =
      GetDocument().getElementById(AtomicString("stable_both_edges"));
  auto* box_stable_both_edges = stable_both_edges->GetLayoutBox();
  EXPECT_EQ(box_stable_both_edges->OffsetWidth(), 100);
  EXPECT_EQ(box_stable_both_edges->ClientWidth(), 100);
  PhysicalBoxStrut box_stable_both_edges_scrollbars =
      box_stable_both_edges->ComputeScrollbars();
  EXPECT_EQ(box_stable_both_edges_scrollbars.top, 0);
  EXPECT_EQ(box_stable_both_edges_scrollbars.bottom, 0);
  EXPECT_EQ(box_stable_both_edges_scrollbars.left, 0);
  EXPECT_EQ(box_stable_both_edges_scrollbars.right, 0);
}

// Test scrollbar-gutter values with overlay scrollbars and vertical-rl text.
TEST_P(ScrollbarsTest, ScrollbarGutterWithVerticalTextAndOverlayScrollbars) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(800, 600));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      div {
        width: 100px;
        height: 100px;
        overflow: auto;
        writing-mode: vertical-rl;
      }
      #auto {
        scrollbar-gutter: auto;
      }
      #stable {
        scrollbar-gutter: stable;
      }
      #stable_both_edges {
        scrollbar-gutter: stable both-edges;
      }
    </style>
    <div id="auto"></div>
    <div id="stable"></div>
    <div id="stable_both_edges"></div>
  )HTML");
  Compositor().BeginFrame();
  auto* auto_ = GetDocument().getElementById(AtomicString("auto"));
  auto* box_auto = auto_->GetLayoutBox();
  EXPECT_EQ(box_auto->OffsetHeight(), 100);
  EXPECT_EQ(box_auto->ClientHeight(), 100);
  PhysicalBoxStrut box_auto_scrollbars = box_auto->ComputeScrollbars();
  EXPECT_EQ(box
"""


```