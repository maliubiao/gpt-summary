Response:
The user wants a summary of the functionality of the provided C++ code snippet. This snippet is a part of a larger test file for scrollbar behavior in the Chromium Blink engine.

The core function of this specific part of the test file seems to be verifying the correct behavior of mouse cursor interaction with custom scrollbars. It checks if the cursor style changes appropriately based on the CSS rules applied to different parts of the scrollbar (track, thumb, buttons, corners). It also tests the interaction of the cursor with overlay scrollbars and how they affect hit-testing and hover states of elements underneath.

To provide a good summary, I should:
1. **Identify the main theme:** Mouse interaction with custom scrollbars.
2. **List specific scenarios tested:** Hovering over different parts of custom scrollbars with and without custom cursor styles, interactions with overlay scrollbars, impact on elements below scrollbars, interaction with iframes, and handling of mouse events (move, press, release, context menu).
3. **Mention relevant technologies:**  The tests use HTML, CSS (specifically `-webkit-scrollbar` pseudo-elements), and JavaScript (in the broader context of the test file setup).
4. **Highlight logical assumptions and outputs:**  The tests assume specific HTML/CSS structures and verify that the `CursorType()` and `HoveredPart()` match the expected values.
5. **Point out potential user/developer errors:**  While not explicitly present in this snippet, the tests implicitly address the importance of correctly styling scrollbar pseudo-elements for expected cursor behavior.

Let's break down the code block by block to confirm the details:
- Tests for hovering over different parts of a custom scrollbar (thumb, track-piece, button, corner) and verifying the cursor style.
- Tests for cursor inheritance on scrollbar parts.
- Tests for interaction of mouse cursor with overlay scrollbars, ensuring they don't activate elements below them when active.
- Tests for mouse interaction with custom scrollbars, confirming they don't interfere with element hover states.
- Tests for interaction between overlay scrollbars and iframes.
- Tests for interaction between scrollbars and parent elements, ensuring the parent remains hovered when the scrollbar is hovered.
- Tests for hovering over the root scrollbar.
- Tests for updating the scrollbar's `HoveredPart` on mouse release and context menu events.
- Tests for custom scrollbar behavior in overlay scrollbar themes.
- Tests related to device emulation and its impact on root and div scrollbars.
- Tests for custom scrollbar recreation when style owner changes.
- Tests for overlay scrollbar fading behavior for non-composited scrollers.
这个代码片段（第2部分）主要关注**鼠标在自定义滚动条上的交互行为和样式效果**。它通过一系列测试用例，验证了当鼠标悬停在不同类型的自定义滚动条组件上时，光标样式是否按照CSS定义正确显示，以及是否正确触发相应的事件。

以下是功能的详细归纳：

1. **测试鼠标悬停在自定义滚动条的不同部分时的光标样式：**
   - 针对 `::-webkit-scrollbar-thumb` (滚动条滑块)：验证鼠标悬停时，光标样式是否为 `pointer` (如果滚动容器本身设置了 `cursor: pointer`) 或 `auto` (如果滑块自身设置了 `cursor: auto`)。
   - 针对 `::-webkit-scrollbar-track-piece` (滚动条轨道):
     - 验证鼠标悬停在设置了自定义 `cursor` 样式的轨道片段上时，光标样式是否正确显示。例如，设置为 `cursor: text` 或 `cursor: help`。
     - 验证鼠标悬停在没有自定义 `cursor` 样式的轨道片段上时，是否会继承父元素（`::-webkit-scrollbar` 或滚动容器）的 `cursor` 样式。
   - 针对 `::-webkit-scrollbar-button` (滚动条上的按钮): 验证鼠标悬停在设置了自定义 `cursor` 样式的按钮上时，光标样式是否正确显示。
   - 针对 `::-webkit-scrollbar-corner` (滚动条角落): 验证鼠标悬停在设置了自定义 `cursor` 样式的角落时，光标样式是否正确显示。
   - 针对 iframe 中的自定义滚动条角落：验证鼠标悬停在 iframe 的滚动条角落时，光标样式是否正确显示。

2. **测试鼠标悬停在 overlay 滚动条上的行为：**
   - 验证当 overlay 滚动条启用时，鼠标悬停在滚动条上**不会**激活下方的链接或其他可交互元素，除非滚动条处于淡出状态。这通过 `HitTestResult` 检查和 `HandleMouseMoveEvent` 模拟鼠标移动来实现。
   - 验证鼠标悬停在自定义滚动条上**不会**改变当前激活的元素 (`document.HoverElement()`)。

3. **测试鼠标悬停在 overlay 滚动条和 iframe 上的交互：**
   - 验证当 overlay 滚动条启用时，鼠标悬停在滚动条上**不会**导致 iframe 获得 hover 状态。

4. **测试鼠标悬停在普通滚动条和父元素上的交互：**
   - 验证鼠标悬停在普通滚动条上时，拥有该滚动条的父元素仍然处于 hover 状态。

5. **测试鼠标悬停在根滚动条上的行为：**
   - 验证鼠标悬停在文档根元素的滚动条上时，文档根元素 (`<html>`) 处于 hover 状态。

6. **测试鼠标释放时更新滚动条的悬停部分 (`HoveredPart`)：**
   - 验证当鼠标在滚动条上按下并移动离开，然后释放时，滚动条的 `HoveredPart` 会正确更新为 `kNoPart`。

7. **测试在滚动条上弹出上下文菜单时更新滚动条的按下部分 (`PressedPart`)：**
   - 验证当鼠标在滚动条上按下后，弹出上下文菜单，滚动条的 `PressedPart` 会被重置为 `kNoPart`。

8. **测试在 overlay 滚动条主题下使用自定义滚动条不会导致崩溃。**

9. **测试通过设备模拟器更改设备类型对根滚动条和 div 滚动条的影响：**
   - 验证通过设备模拟器切换到移动设备模式后，根滚动条会被替换为视口滚动条，而 div 元素的自定义滚动条仍然保留。

10. **测试当样式所有者改变时，自定义滚动条是否会重新创建：**
    - 验证当一个元素应用的 CSS 类发生变化，导致其自定义滚动条样式发生改变时，滚动条会重新创建以应用新的样式。

11. **测试非合成图层的 overlay 滚动条的淡出行为：**
    - 验证对于非合成图层的滚动容器，其 overlay 滚动条会在一段时间后淡出并设置隐藏状态。

**与 JavaScript, HTML, CSS 的关系：**

- **HTML:**  测试用例中使用了 HTML 结构来创建包含滚动条的元素 (`<div>`)，并设置了内容使其产生滚动条。例如，创建了 `id='d1'` 和 `id='d2'` 的 div 元素，并通过设置 `overflow: auto` 使 `d1` 出现滚动条。
- **CSS:**  测试的核心在于验证 CSS 样式对自定义滚动条外观和行为的影响，特别是使用了 `-webkit-scrollbar` 及其相关的伪元素（如 `::-webkit-scrollbar-thumb`, `::-webkit-scrollbar-track-piece` 等）来设置滚动条的样式，包括 `cursor` 属性。
   - **示例：**
     ```css
     ::-webkit-scrollbar {
       width: 5px;
       cursor: pointer;
     }

     ::-webkit-scrollbar-thumb {
       cursor: auto;
     }
     ```
     这段 CSS 代码定义了滚动条的宽度和光标样式，以及滚动条滑块的光标样式。测试用例会验证当鼠标悬停在这些部分时，光标是否按照这里的定义显示。
- **JavaScript:**  虽然这段代码本身是 C++ 测试代码，但它测试的是浏览器引擎对 HTML 和 CSS 的解析和渲染结果，这最终会影响到 JavaScript 中与滚动相关的 API 和事件的行为。例如，鼠标事件的处理会影响到 JavaScript 代码中对滚动条状态的判断。

**逻辑推理、假设输入与输出：**

**假设输入：** 一个包含设置了自定义滚动条样式的 HTML 页面，鼠标在特定的坐标位置发生移动或点击事件。

**输出：**
- `EXPECT_EQ(hit_test_result.InnerElement(), div);`：验证在特定坐标位置，命中测试的结果是预期的 DOM 元素。
- `EXPECT_TRUE(hit_test_result.GetScrollbar());`：验证在特定坐标位置，命中测试的结果包含滚动条对象。
- `EXPECT_EQ(hit_test_result.GetScrollbar()->HoveredPart(), kThumbPart);`：验证鼠标悬停在滚动条特定部分（例如滑块）时，滚动条对象记录的悬停部分是正确的。
- `EXPECT_EQ(ui::mojom::blink::CursorType::kPointer, CursorType());`：验证当前鼠标光标的类型与预期的类型一致。

**用户或编程常见的使用错误：**

虽然这段代码是测试代码，但它反映了在开发中使用自定义滚动条时可能遇到的问题：

1. **未能正确设置 `-webkit-scrollbar` 相关伪元素的样式：** 开发者可能只设置了 `::-webkit-scrollbar` 的样式，而忽略了滑块、轨道等部分的样式，导致浏览器使用默认样式或出现不一致的行为。测试用例通过检查不同部分的样式继承和自定义效果，确保开发者能够正确控制滚动条的各个部分。
2. **对 overlay 滚动条的行为理解不足：** 开发者可能期望 overlay 滚动条在激活状态下仍然能够穿透并触发下层元素的事件。测试用例验证了 overlay 滚动条在激活时会拦截鼠标事件，避免意外触发下层元素。
3. **在动态修改样式后，滚动条没有正确更新：** 测试用例验证了当样式所有者改变时，自定义滚动条会重新创建，这提示开发者需要注意动态修改样式后，滚动条是否会按预期更新。

总而言之，这段测试代码深入验证了 Blink 引擎在处理自定义滚动条样式和鼠标交互时的正确性和一致性，确保开发者能够通过 CSS 精确控制滚动条的外观和行为。

### 提示词
```
这是目录为blink/renderer/core/layout/scrollbars_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
height: 5px;
      width: 5px;
      cursor: pointer;
    }

    ::-webkit-scrollbar-thumb {
      background: none;
      height: 5px;
      width: 5px;
      cursor: auto;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));
  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 5);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  HandleMouseMoveEvent(195, 5);
  EXPECT_EQ(hit_test_result.GetScrollbar()->HoveredPart(), kThumbPart);

  EXPECT_EQ(ui::mojom::blink::CursorType::kPointer, CursorType());
}

// Ensure mouse cursor should be custom style when hovering over the custom
// scrollbar-track-piece with custom cursor style.
TEST_P(ScrollbarsTest, MouseOverCustomScrollbarTrackPieceWithCustomCursor) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
      height: 5px;
      width: 5px;
      cursor: pointer;
    }

    ::-webkit-scrollbar-thumb {
      background: none;
      height: 5px;
      width: 5px;
      cursor: auto;
    }

    ::-webkit-scrollbar-track-piece {
      background: none;
      height: 5px;
      width: 5px;
      cursor: text;
    }

    ::-webkit-scrollbar-track-piece:start {
      background: none;
      height: 5px;
      width: 5px;
      cursor: help;
    }

    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));

  div->scrollTo(0, 100);
  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 5);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());

  HandleMouseMoveEvent(195, 5);
  EXPECT_EQ(hit_test_result.GetScrollbar()->HoveredPart(), kBackTrackPart);
  EXPECT_EQ(ui::mojom::blink::CursorType::kHelp, CursorType());

  HandleMouseMoveEvent(195, 190);
  EXPECT_EQ(hit_test_result.GetScrollbar()->HoveredPart(), kForwardTrackPart);
  EXPECT_EQ(ui::mojom::blink::CursorType::kIBeam, CursorType());
}

// Ensure mouse cursor should inherit the style set by the custom
// scrollbar-track when hovering over the custom scrollbar-track-piece
// that has no style set.
TEST_P(ScrollbarsTest, MouseOverCustomScrollbarTrackPieceWithoutStyle) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
      height: 5px;
      width: 5px;
      cursor: pointer;
    }

    ::-webkit-scrollbar-thumb {
      background: none;
      height: 5px;
      width: 5px;
      cursor: auto;
    }

    ::-webkit-scrollbar-track {
      background: none;
      height: 5px;
      width: 5px;
      cursor: help;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));
  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 190);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  HandleMouseMoveEvent(195, 190);

  EXPECT_EQ(hit_test_result.GetScrollbar()->HoveredPart(), kForwardTrackPart);
  EXPECT_EQ(ui::mojom::blink::CursorType::kHelp, CursorType());
}

// Ensure mouse cursor should inherit the style set by the custom scrollbar
// when hovering over the custom scrollbar-track-piece that both
// scrollbar-track and scrollbar-track-piece has no style set.
TEST_P(ScrollbarsTest,
       MouseOverCustomScrollbarTrackPieceBothTrackAndTrackPieceWithoutStyle) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
      height: 5px;
      width: 5px;
      cursor: pointer;
    }

    ::-webkit-scrollbar-thumb {
      background: none;
      height: 5px;
      width: 5px;
      cursor: auto;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));
  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 190);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  HandleMouseMoveEvent(195, 190);

  EXPECT_EQ(hit_test_result.GetScrollbar()->HoveredPart(), kForwardTrackPart);
  EXPECT_EQ(ui::mojom::blink::CursorType::kHand, CursorType());
}

// Ensure mouse cursor should be custom style when hovering over the custom
// scrollbar-button with custom cursor style;
TEST_P(ScrollbarsTest, MouseOverCustomScrollbarButtonTrackWithCustomCursor) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
      height: 5px;
      width: 5px;
      cursor: pointer;
    }

    ::-webkit-scrollbar-thumb {
      background: none;
      height: 5px;
      width: 5px;
      cursor: auto;
    }

    ::-webkit-scrollbar-button {
      background: none;
      height: 5px;
      width: 5px;
      cursor: help;
      display: block;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));
  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 2);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.GetScrollbar());

  HandleMouseMoveEvent(195, 2);

  EXPECT_EQ(ui::mojom::blink::CursorType::kHelp, CursorType());
}

// Ensure mouse cursor should be custom style when hovering over the custom
// scrollbar-corner with custom cursor style;
TEST_P(ScrollbarsTest, MouseOverCustomScrollbarCornerTrackWithCustomCursor) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    #d1 {
      width: 200px;
      height: 200px;
      overflow: auto;
      cursor: move;
    }
    #d2 {
      height: 400px;
      width: 400px;
    }
    ::-webkit-scrollbar {
      background: none;
      height: 5px;
      width: 5px;
      cursor: pointer;
    }

    ::-webkit-scrollbar-thumb {
      background: none;
      height: 5px;
      width: 5px;
      cursor: auto;
    }

    ::-webkit-scrollbar-corner {
      cursor: help;
    }
    </style>
    <div id='d1'>
        <div id='d2'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));
  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 195);

  EXPECT_EQ(hit_test_result.InnerElement(), div);
  EXPECT_TRUE(hit_test_result.IsOverScrollCorner());

  HandleMouseMoveEvent(195, 195);

  EXPECT_EQ(ui::mojom::blink::CursorType::kHelp, CursorType());
}

TEST_P(ScrollbarsTest, MouseOverCustomScrollbarCornerFrame) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest()) {
    return;
  }

  WebView().MainFrameViewWidget()->Resize(gfx::Size(250, 250));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
    }
    iframe {
      width: 200px;
      height: 200px;
    }
    </style>
    <iframe id="iframe" srcdoc="<style>
        body { width: 200vw; height: 200vh; }
        ::-webkit-scrollbar { cursor: pointer; }
        ::-webkit-scrollbar-corner { cursor: help; }
    </style>"></iframe>
  )HTML");

  // Wait for load.
  test::RunPendingTasks();
  Compositor().BeginFrame();

  Document& iframe_document =
      *To<HTMLIFrameElement>(
           GetDocument().getElementById(AtomicString("iframe")))
           ->contentDocument();

  // Ensure hittest has DIV and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 195);

  EXPECT_EQ(hit_test_result.InnerElement(), iframe_document.documentElement());
  EXPECT_TRUE(hit_test_result.IsOverScrollCorner());

  HandleMouseMoveEvent(195, 195);

  EXPECT_EQ(ui::mojom::blink::CursorType::kHelp, CursorType());
}

// Makes sure that mouse hover over an overlay scrollbar doesn't activate
// elements below (except the Element that owns the scrollbar) unless the
// scrollbar is faded out.
TEST_P(ScrollbarsTest, MouseOverLinkAndOverlayScrollbar) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest())
    return;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <a id='a' href='javascript:void(0);' style='font-size: 20px'>
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    </a>
    <div style='position: absolute; top: 1000px'>
      end
    </div>
  )HTML");

  Compositor().BeginFrame();

  // Enable the Scrollbar.
  WebView()
      .MainFrameImpl()
      ->GetFrameView()
      ->LayoutViewport()
      ->SetScrollbarsHiddenForTesting(false);

  Document& document = GetDocument();
  Element* a_tag = document.getElementById(AtomicString("a"));

  // This position is on scrollbar if it's enabled, or on the <a> element.
  int x = 190;
  int y = a_tag->OffsetTop();

  // Ensure hittest only has scrollbar.
  HitTestResult hit_test_result = HitTest(x, y);

  EXPECT_FALSE(hit_test_result.URLElement());
  EXPECT_TRUE(hit_test_result.InnerElement());
  ASSERT_TRUE(hit_test_result.GetScrollbar());
  EXPECT_FALSE(hit_test_result.GetScrollbar()->IsCustomScrollbar());

  // Mouse over link. Mouse cursor should be hand.
  HandleMouseMoveEvent(a_tag->OffsetLeft(), a_tag->OffsetTop());

  EXPECT_EQ(ui::mojom::blink::CursorType::kHand, CursorType());

  // Mouse over enabled overlay scrollbar. Mouse cursor should be pointer and no
  // active hover element.
  HandleMouseMoveEvent(x, y);

  EXPECT_EQ(ui::mojom::blink::CursorType::kPointer, CursorType());

  HandleMousePressEvent(x, y);

  EXPECT_TRUE(document.GetActiveElement());
  EXPECT_TRUE(document.HoverElement());

  HandleMouseReleaseEvent(x, y);

  // Mouse over disabled overlay scrollbar. Mouse cursor should be hand and has
  // active hover element.
  WebView()
      .MainFrameImpl()
      ->GetFrameView()
      ->LayoutViewport()
      ->SetScrollbarsHiddenForTesting(true);

  // Ensure hittest only has link
  hit_test_result = HitTest(x, y);

  EXPECT_TRUE(hit_test_result.URLElement());
  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_FALSE(hit_test_result.GetScrollbar());

  HandleMouseMoveEvent(x, y);

  EXPECT_EQ(ui::mojom::blink::CursorType::kHand, CursorType());

  HandleMousePressEvent(x, y);

  EXPECT_TRUE(document.GetActiveElement());
  EXPECT_TRUE(document.HoverElement());
}

// Makes sure that mouse hover over an custom scrollbar doesn't change the
// activate elements.
TEST_P(ScrollbarsTest, MouseOverCustomScrollbar) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #scrollbar {
      position: absolute;
      top: 0;
      left: 0;
      height: 180px;
      width: 180px;
      overflow-x: auto;
    }
    ::-webkit-scrollbar {
      width: 8px;
    }
    ::-webkit-scrollbar-thumb {
      background-color: hsla(0, 0%, 56%, 0.6);
    }
    </style>
    <div id='scrollbar'>
      <div style='position: absolute; top: 1000px;'>
        make scrollbar show
      </div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* scrollbar_div = document.getElementById(AtomicString("scrollbar"));
  EXPECT_TRUE(scrollbar_div);

  // Ensure hittest only has DIV
  HitTestResult hit_test_result = HitTest(1, 1);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_FALSE(hit_test_result.GetScrollbar());

  // Mouse over DIV
  HandleMouseMoveEvent(1, 1);

  // DIV :hover
  EXPECT_EQ(document.HoverElement(), scrollbar_div);

  // Ensure hittest has DIV and scrollbar
  hit_test_result = HitTest(175, 1);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  EXPECT_TRUE(hit_test_result.GetScrollbar()->IsCustomScrollbar());

  // Mouse over scrollbar
  HandleMouseMoveEvent(175, 1);

  // Custom not change the DIV :hover
  EXPECT_EQ(document.HoverElement(), scrollbar_div);
  EXPECT_EQ(hit_test_result.GetScrollbar()->HoveredPart(),
            ScrollbarPart::kThumbPart);
}

// Makes sure that mouse hover over an overlay scrollbar doesn't hover iframe
// below.
TEST_P(ScrollbarsTest, MouseOverScrollbarAndIFrame) {
  // This test is specifically checking the behavior when overlay scrollbars
  // are enabled.
  ENABLE_OVERLAY_SCROLLBARS(true);
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest())
    return;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest main_resource("https://example.com/", "text/html");
  SimRequest frame_resource("https://example.com/iframe.html", "text/html");
  LoadURL("https://example.com/");
  main_resource.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      margin: 0;
      height: 2000px;
    }
    iframe {
      height: 200px;
      width: 200px;
    }
    </style>
    <iframe id='iframe' src='iframe.html'>
    </iframe>
  )HTML");
  Compositor().BeginFrame();

  frame_resource.Complete("<!DOCTYPE html>");
  Compositor().BeginFrame();

  // Enable the Scrollbar.
  WebView()
      .MainFrameImpl()
      ->GetFrameView()
      ->LayoutViewport()
      ->SetScrollbarsHiddenForTesting(false);

  Document& document = GetDocument();
  Element* iframe = document.getElementById(AtomicString("iframe"));
  DCHECK(iframe);

  // Ensure hittest only has IFRAME.
  HitTestResult hit_test_result = HitTest(5, 5);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_FALSE(hit_test_result.GetScrollbar());

  // Mouse over IFRAME.
  HandleMouseMoveEvent(5, 5);

  // IFRAME hover.
  EXPECT_EQ(document.HoverElement(), iframe);

  // Ensure hittest has scrollbar.
  hit_test_result = HitTest(195, 5);
  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  EXPECT_TRUE(hit_test_result.GetScrollbar()->Enabled());

  // Mouse over scrollbar.
  HandleMouseMoveEvent(195, 5);

  // IFRAME not hover.
  EXPECT_NE(document.HoverElement(), iframe);

  // Disable the Scrollbar.
  WebView()
      .MainFrameImpl()
      ->GetFrameView()
      ->LayoutViewport()
      ->SetScrollbarsHiddenForTesting(true);

  // Ensure hittest has IFRAME and no scrollbar.
  hit_test_result = HitTest(196, 5);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_FALSE(hit_test_result.GetScrollbar());

  // Mouse over disabled scrollbar.
  HandleMouseMoveEvent(196, 5);

  // IFRAME hover.
  EXPECT_EQ(document.HoverElement(), iframe);
}

// Makes sure that mouse hover over a scrollbar also hover the element owns the
// scrollbar.
TEST_P(ScrollbarsTest, MouseOverScrollbarAndParentElement) {
  // This test requires that scrollbars take up space.
  ENABLE_OVERLAY_SCROLLBARS(false);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #parent {
      position: absolute;
      top: 0;
      left: 0;
      height: 180px;
      width: 180px;
      overflow-y: scroll;
    }
    </style>
    <div id='parent'>
      <div id='child' style='position: absolute; top: 1000px;'>
        make scrollbar enabled
      </div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* parent_div = document.getElementById(AtomicString("parent"));
  Element* child_div = document.getElementById(AtomicString("child"));
  EXPECT_TRUE(parent_div);
  EXPECT_TRUE(child_div);

  auto* scrollable_area = GetScrollableArea(*parent_div);

  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  EXPECT_FALSE(scrollable_area->VerticalScrollbar()->IsOverlayScrollbar());

  // Ensure hittest only has DIV.
  HitTestResult hit_test_result = HitTest(1, 1);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_FALSE(hit_test_result.GetScrollbar());

  // Mouse over DIV.
  HandleMouseMoveEvent(1, 1);

  // DIV :hover.
  EXPECT_EQ(document.HoverElement(), parent_div);

  // Ensure hittest has DIV and scrollbar.
  hit_test_result = HitTest(175, 5);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  EXPECT_FALSE(hit_test_result.GetScrollbar()->IsCustomScrollbar());
  EXPECT_TRUE(hit_test_result.GetScrollbar()->Enabled());

  // Mouse over scrollbar.
  HandleMouseMoveEvent(175, 5);

  // Not change the DIV :hover.
  EXPECT_EQ(document.HoverElement(), parent_div);

  // Disable the Scrollbar by remove the childDiv.
  child_div->remove();
  Compositor().BeginFrame();

  // Ensure hittest has DIV and no scrollbar.
  hit_test_result = HitTest(175, 5);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_TRUE(hit_test_result.GetScrollbar());
  EXPECT_FALSE(hit_test_result.GetScrollbar()->Enabled());
  EXPECT_LT(hit_test_result.InnerElement()->clientWidth(), 180);

  // Mouse over disabled scrollbar.
  HandleMouseMoveEvent(175, 5);

  // Not change the DIV :hover.
  EXPECT_EQ(document.HoverElement(), parent_div);
}

// Makes sure that mouse over a root scrollbar also hover the html element.
TEST_P(ScrollbarsTest, MouseOverRootScrollbar) {
  // Skip this test if scrollbars don't allow hit testing on the platform.
  if (!WebView().GetPage()->GetScrollbarTheme().AllowsHitTest())
    return;

  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body {
      overflow: scroll;
    }
    </style>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  // Ensure hittest has <html> element and scrollbar.
  HitTestResult hit_test_result = HitTest(195, 5);

  EXPECT_TRUE(hit_test_result.InnerElement());
  EXPECT_EQ(hit_test_result.InnerElement(), document.documentElement());
  EXPECT_TRUE(hit_test_result.GetScrollbar());

  // Mouse over scrollbar.
  HandleMouseMoveEvent(195, 5);

  // Hover <html element.
  EXPECT_EQ(document.HoverElement(), document.documentElement());
}

TEST_P(ScrollbarsTest, MouseReleaseUpdatesScrollbarHoveredPart) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    #scrollbar {
      position: absolute;
      top: 0;
      left: 0;
      height: 180px;
      width: 180px;
      overflow-x: auto;
    }
    ::-webkit-scrollbar {
      width: 8px;
    }
    ::-webkit-scrollbar-thumb {
      background-color: hsla(0, 0%, 56%, 0.6);
    }
    </style>
    <div id='scrollbar'>
      <div style='position: absolute; top: 1000px;'>make scrollbar
    shows</div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* scrollbar_div = document.getElementById(AtomicString("scrollbar"));
  EXPECT_TRUE(scrollbar_div);

  auto* scrollable_area = GetScrollableArea(*scrollbar_div);

  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  EXPECT_EQ(scrollbar->HoveredPart(), ScrollbarPart::kNoPart);

  // Mouse moved over the scrollbar.
  HandleMouseMoveEvent(175, 1);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  EXPECT_EQ(scrollbar->HoveredPart(), ScrollbarPart::kThumbPart);

  // Mouse pressed.
  HandleMousePressEvent(175, 1);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kThumbPart);
  EXPECT_EQ(scrollbar->HoveredPart(), ScrollbarPart::kThumbPart);

  // Mouse moved off the scrollbar while still pressed.
  HandleMouseLeaveEvent();
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kThumbPart);
  EXPECT_EQ(scrollbar->HoveredPart(), ScrollbarPart::kThumbPart);

  // Mouse released.
  HandleMouseReleaseEvent(1, 1);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);
  EXPECT_EQ(scrollbar->HoveredPart(), ScrollbarPart::kNoPart);
}

TEST_P(ScrollbarsTest, ContextMenuUpdatesScrollbarPressedPart) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
    body { margin: 0px }
    #scroller { overflow-x: auto; width: 180px; height: 100px }
    #spacer { height: 300px }
    ::-webkit-scrollbar { width: 8px }
    ::-webkit-scrollbar-thumb {
      background-color: hsla(0, 0%, 56%, 0.6)
    }
    </style>
    <div id='scroller'>
      <div id='spacer'></div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* scrollbar_div = document.getElementById(AtomicString("scroller"));
  EXPECT_TRUE(scrollbar_div);

  auto* scrollable_area = GetScrollableArea(*scrollbar_div);

  EXPECT_TRUE(scrollable_area->VerticalScrollbar());
  Scrollbar* scrollbar = scrollable_area->VerticalScrollbar();
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);

  // Mouse moved over the scrollbar.
  HandleMouseMoveEvent(175, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);

  // Press the scrollbar.
  HandleMousePressEvent(175, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kThumbPart);

  // ContextMenu while still pressed.
  HandleContextMenuEvent(175, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);

  // Mouse moved off the scrollbar.
  HandleMousePressEvent(50, 5);
  EXPECT_EQ(scrollbar->PressedPart(), ScrollbarPart::kNoPart);
}

TEST_P(ScrollbarsTest,
       CustomScrollbarInOverlayScrollbarThemeWillNotCauseDCHECKFails) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style type='text/css'>
       ::-webkit-scrollbar {
        width: 16px;
        height: 16px;
        overflow: visible;
      }
      div {
        width: 1000px;
      }
    </style>
    <div style='position: absolute; top: 1000px;'>
      end
    </div>
  )HTML");

  // No DCHECK Fails. Issue 676678.
  Compositor().BeginFrame();
}

// Make sure root custom scrollbar can change by Emulator but div custom
// scrollbar not.
TEST_P(ScrollbarsTest, CustomScrollbarChangeToMobileByEmulator) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style type='text/css'>
    body {
      height: 10000px;
      margin: 0;
    }
    #d1 {
      height: 200px;
      width: 200px;
      overflow: auto;
    }
    #d2 {
      height: 2000px;
    }
    ::-webkit-scrollbar {
      width: 10px;
    }
    </style>
    <div id='d1'>
      <div id='d2'/>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  ScrollableArea* root_scrollable = document.View()->LayoutViewport();

  Element* div = document.getElementById(AtomicString("d1"));

  auto* div_scrollable = GetScrollableArea(*div);

  VisualViewport& viewport = WebView().GetPage()->GetVisualViewport();

  DCHECK(root_scrollable->VerticalScrollbar());
  DCHECK(root_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  DCHECK(!root_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  DCHECK(!root_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());

  DCHECK(!viewport.LayerForHorizontalScrollbar());

  DCHECK(div_scrollable->VerticalScrollbar());
  DCHECK(div_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  DCHECK(!div_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  DCHECK(!div_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());

  // Turn on mobile emulator.
  DeviceEmulationParams params;
  params.screen_type = mojom::EmulatedScreenType::kMobile;
  WebView().EnableDeviceEmulation(params);

  // For root Scrollbar, mobile emulator will change them to page VisualViewport
  // scrollbar layer.
  EXPECT_TRUE(viewport.LayerForVerticalScrollbar());
  EXPECT_FALSE(root_scrollable->VerticalScrollbar());

  EXPECT_TRUE(div_scrollable->VerticalScrollbar()->IsCustomScrollbar());

  // Turn off mobile emulator.
  WebView().DisableDeviceEmulation();

  EXPECT_TRUE(root_scrollable->VerticalScrollbar());
  EXPECT_TRUE(root_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  EXPECT_FALSE(root_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  EXPECT_FALSE(root_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());

  DCHECK(!viewport.LayerForHorizontalScrollbar());

  EXPECT_TRUE(div_scrollable->VerticalScrollbar());
  EXPECT_TRUE(div_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  EXPECT_FALSE(div_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  EXPECT_FALSE(div_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());
}

// Ensure custom scrollbar recreate when style owner change,
TEST_P(ScrollbarsTest, CustomScrollbarWhenStyleOwnerChange) {
  WebView().MainFrameViewWidget()->Resize(gfx::Size(200, 200));

  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style type='text/css'>
    #d1 {
      height: 200px;
      width: 200px;
      overflow: auto;
    }
    #d2 {
      height: 2000px;
    }
    ::-webkit-scrollbar {
      width: 10px;
    }
    .custom::-webkit-scrollbar {
      width: 5px;
    }
    </style>
    <div id='d1'>
      <div id='d2'></div>
    </div>
  )HTML");

  Compositor().BeginFrame();

  Document& document = GetDocument();

  Element* div = document.getElementById(AtomicString("d1"));

  auto* div_scrollable = GetScrollableArea(*div);

  DCHECK(div_scrollable->VerticalScrollbar());
  DCHECK(div_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  DCHECK_EQ(div_scrollable->VerticalScrollbar()->Width(), 10);
  DCHECK(!div_scrollable->VerticalScrollbar()->IsOverlayScrollbar());
  DCHECK(!div_scrollable->VerticalScrollbar()->GetTheme().IsMockTheme());

  div->setAttribute(html_names::kClassAttr, AtomicString("custom"));
  Compositor().BeginFrame();

  EXPECT_TRUE(div_scrollable->VerticalScrollbar()->IsCustomScrollbar());
  EXPECT_EQ(div_scrollable->VerticalScrollbar()->Width(), 5);
}

// Make sure overlay scrollbars on non-composited scrollers fade out and set
// the hidden bit as needed.
// To avoid TSAN/ASAN race issue, this test use Virtual Time and give scrollbar
// a huge fadeout delay.
// Disable on Android since VirtualTime not work for Android.
// http://crbug.com/633321
#if BUILDFLAG(IS_ANDROID) || BUILDFLAG(IS_IOS)
TEST_P(ScrollbarsTestWithVirtualTimer,
       DISABLED_TestNonCompositedOverlayScrollbarsFade) {
#else
TEST_P(ScrollbarsTestWithVirtualTimer, TestNonCompositedOverlayScrollbarsFade) {
#endif
  // Scrollbars are always composited in RasterInducingScroll.
  if (RuntimeEnabledFeatures::RasterInducingScrollEnabled()) {
    return;
  }

  // This test relies on mock overlay scrollbars.
  ScopedMockOverlayScrollbars mock_overlay_scrollbars(true);

  TimeAdvance();
  constexpr base::TimeDelta kMockOverlayFadeOutDelay = base::Seconds(5);

  ScrollbarTheme& theme = GetScrollbarTheme();
  ASSERT_TRUE(theme.IsMockTheme());
  ASSERT_TRUE(theme.UsesOverlayScrollbars());
  ScrollbarThemeOverlayMock& mock_overlay_theme =
      static_cast<ScrollbarThemeOverlayMock&>(theme);
  mock_overlay_theme.SetOverlayScrollbarFadeOutDelay(kMockOverlayFadeOutDelay);

  WebView().MainFrameViewWidget()->Resize(gfx::Size(640, 480));
  SimRequest request("https://example.com/test.html", "text/html");
  LoadURL("https://example.com/test.html");
  RunTasksForPeriod(kMockOverlayFadeOutDelay);
  request.Complete(R"HTML(
    <!DOCTYPE html>
    <style>
      #space {
        width: 1000px;
        height: 1000px;
      }
      #container {
        width: 200px;
        height: 200px;
        overflow: scroll;
        /* Ensure the scroller is non-composited. */
        border: border: 2px solid;
        border-radius: 25px;
      }
      div { height:1000px; width: 200px; }
    </style>
    <div id='container'>
      <div id='space'></div>
    </div>
  )HTML");
  Compositor().BeginFrame();

  Document& document = GetDocument();
  Element* container = document.getElementById(AtomicString("container"));
  auto* scrollable_area = GetScrollableArea(*container);

  DCHECK(!scrollable_area->UsesCompositedScrolling());

  EXPECT_FALSE(scrollable_area->ScrollbarsHiddenIfOverlay());
  RunTasksForPeriod(kMockOverlayFadeOutDelay);
  EXPECT_TRUE(scrollable_area->ScrollbarsHiddenIfOverlay());

  scrollable_area->SetScrollOffset(ScrollOffset(10, 10),
                                   mojom::blink::ScrollType::kProgrammatic,
                                   mojom::blink::ScrollBehavior::kInstant);

  EXPECT_FALSE(scrollable_area->ScrollbarsHiddenIfOverlay());
  RunTasksForPeriod(kMockOverlayFadeOutDelay);
  EXPECT_TRUE(scrollable_area->ScrollbarsHiddenIfOverlay());

  MainFrame().ExecuteScript(WebScriptSource(
      "doc
```