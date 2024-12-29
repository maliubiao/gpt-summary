Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is part of a test file for the Blink rendering engine's scrolling functionality.

Here's a breakdown of the code and its purpose:

1. **Test Fixture:** The code uses `TEST_P(ScrollingTest, ...)` which indicates it's part of a parameterized test suite named `ScrollingTest`. This means the tests are run with different configurations (the parameter `P`).

2. **Focus on Scrolling:** The test names and the operations within the tests clearly revolve around different aspects of scrolling in Blink.

3. **HTML/CSS Interaction:** Many tests load HTML snippets (`LoadHTML`) and manipulate CSS properties (e.g., `setAttribute(html_names::kStyleAttr, ...)`), suggesting the tests are validating how Blink handles scrolling behavior defined by HTML and CSS.

4. **Layer Tree and Compositing:** The code interacts with `cc::Layer` objects (e.g., `MainFrameScrollingContentsLayer()`, `ScrollingContentsLayerByDOMElementId()`). This signifies that the tests are examining how scrolling is handled at the compositing level, which is crucial for performance.

5. **Scroll Hit Testing:** Several tests are focused on "main thread scroll hit test region" and "non-composited scroll hit test rects". This relates to how Blink determines which element should receive scroll events, especially for non-composited scrolling.

6. **IFrames:**  A significant portion of the tests deal with scrolling within iframes, including nested iframes and scenarios where iframes are styled with `position: fixed` or transformations.

7. **Scrollbars:** Some tests verify the presence and properties of scrollbar layers.

8. **Region Capture:**  The `ElementRegionCaptureData` test deals with capturing specific regions of elements, which might be related to features like screen sharing or recording.

9. **JavaScript Interaction (Indirect):** While there's no direct JavaScript code in this snippet, some tests (like `setupScrollbarLayerShouldNotCrash`) load HTML that might execute JavaScript. The tests implicitly check how Blink's scrolling behaves after such JavaScript execution.

**Plan for the Summary:**

*   Identify the core purpose of the file.
*   List the specific features being tested.
*   Provide examples of how these features relate to HTML, CSS, and JavaScript.
*   Give examples of test cases that involve logical reasoning (input/output).
*   Point out potential user/programming errors that these tests might be preventing.
*   Explain how a user might trigger the code being tested.
这个代码片段是 `blink/renderer/core/page/scrolling/scrolling_test.cc` 文件的一部分，专注于测试 Blink 引擎中与页面滚动相关的各种功能。这是该测试文件的第 3 部分，因此它会涵盖该文件功能的一个子集。

**归纳一下它的功能：**

这部分代码主要测试了以下与滚动相关的核心功能：

*   **非合成滚动（Non-Composited Scrolling）的命中测试区域（Hit-Test Region）的计算和更新：**
    *   测试了在各种布局和元素组合下，Blink 如何确定哪些区域可以触发主线程滚动（即非合成滚动）。
    *   包括了使用 `main_thread_scroll_hit_test_region()` 和 `non_composited_scroll_hit_test_rects()` 来验证这些区域的计算结果。
    *   涵盖了嵌套元素、覆盖元素、以及快速非合成滚动命中测试的场景。
*   **元素区域捕获数据（Element Region Capture Data）：**
    *   测试了如何为特定的 DOM 元素设置和获取用于区域捕获的边界信息。
    *   验证了这些边界信息是否正确地传递到了合成器层（Compositor Layer）。
*   **溢出滚动（Overflow Scrolling）和溢出隐藏（Overflow Hidden）：**
    *   测试了 `overflow: scroll` 和 `overflow: hidden` 属性对滚动条显示和滚动行为的影响。
    *   验证了滚动节点的 `user_scrollable_horizontal` 和 `user_scrollable_vertical` 属性是否正确设置。
*   **iframe 中的滚动：**
    *   测试了 iframe 元素及其内部文档的滚动行为。
    *   包括了 iframe 的嵌套、RTL（从右到左）布局、以及 iframe 显隐状态变化对滚动命中测试区域的影响。
*   **滚动条图层（Scrollbar Layer）的创建和属性：**
    *   测试了滚动条图层的正确创建，以及其 `contents_opaque()` 属性的设置。
*   **嵌套 iframe 的主线程滚动区域：**
    *   测试了在嵌套 iframe 的复杂场景下，非合成滚动命中测试区域的计算，包括绝对定位和固定定位的 iframe。
*   **iframe 的合成滚动（Composited Scrolling）：**
    *   测试了合成滚动 iframe 是否没有主线程滚动命中测试区域。
*   **iframe 显隐状态变化对非合成滚动的影响：**
    *   测试了通过 `display: none` 和 `visibility: hidden` 来隐藏和显示 iframe 时，非合成滚动命中测试区域的变化。
*   **带有滚动的主框架下 iframe 的显隐状态变化：**
    *   与上述类似，但主框架自身也是可滚动的，测试非合成滚动区域是否正确地放在了视口的滚动层上。
*   **嵌套 iframe 的非合成滚动：**
    *   测试了多层嵌套 iframe 下，非合成滚动命中测试区域的计算。
*   **带有变换（Transform）的 iframe 的非合成滚动：**
    *   测试了当 iframe 应用了 CSS `transform` 属性时，非合成滚动命中测试区域的计算。
*   **页面缩放（Page Scale）对 iframe 非合成滚动的影响：**
    *   测试了页面缩放是否影响了非合成滚动命中测试区域的计算（实际上，测试表明不影响）。
*   **非合成滚动元素变换属性变化的影响：**
    *   测试了当一个可滚动元素的 `transform` 属性发生变化时，非合成滚动命中测试区域的更新。
*   **在合成更新前滚动偏移被覆盖的情况：**
    *   模拟了在合成器线程产生滚动后，主线程又设置了滚动偏移的情况，验证了 Blink 能否正确处理这种情况。
*   **更新可视视口滚动层（Visual Viewport Scroll Layer）：**
    *   测试了当可视视口的缩放和位置发生变化时，其滚动层的滚动偏移是否正确更新。

**与 JavaScript, HTML, CSS 的功能关系及举例说明：**

*   **HTML:** 测试文件加载 HTML 代码片段来创建各种页面结构，例如包含可滚动 div、iframe 等。
    *   **例子:**  `<div id="scrollable">...</div>` 定义了一个可滚动的 div 元素。`<iframe srcdoc="..."></iframe>` 创建了一个内联的 iframe。
*   **CSS:**  测试文件使用 CSS 来控制元素的布局、大小、滚动行为和渲染属性。
    *   **例子:**  `overflow: scroll;` CSS 属性使得元素在内容溢出时显示滚动条。 `position: fixed;` 用于创建固定定位的元素。 `transform: scale(2);` 用于缩放元素。
*   **JavaScript (间接):** 虽然这段代码本身是 C++ 测试代码，但它测试的功能是与 JavaScript 交互的。JavaScript 可以动态地修改元素的样式、滚动位置等，而这些操作会触发 Blink 的滚动逻辑。
    *   **例子:**  `iframe->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));` 这段 C++ 代码模拟了 JavaScript 设置 iframe 的 `display` 样式为 `none` 的行为。

**逻辑推理的假设输入与输出：**

*   **测试用例: `NestedIFramesMainThreadScrollingRegion`**
    *   **假设输入:** 一个 HTML 页面，其中包含一个绝对定位的 iframe，该 iframe 内部嵌套了另一个 iframe，最内层的 iframe 中有一个设置了 `overflow: auto` 的 div。
    *   **预期输出:**  `MainFrameScrollingContentsLayer()` 的 `main_thread_scroll_hit_test_region()` 应该包含最内层可滚动 div 的位置和大小信息，即使它被嵌套在多层 iframe 中。例如，预期输出是 `cc::Region(gfx::Rect(0, 1200, 65, 65))`。
*   **测试用例: `IframeNonCompositedScrollingHideAndShow`**
    *   **假设输入:** 一个包含 iframe 的 HTML 页面。
    *   **操作:** 先加载页面，然后使用 JavaScript (通过 C++ 代码模拟) 将 iframe 的 `display` 属性设置为 `none`，再将其恢复为空字符串。
    *   **预期输出:** 初始加载时，主内容滚动层的 `main_thread_scroll_hit_test_region()` (或 `non_composited_scroll_hit_test_rects()`) 应该包含 iframe 的区域。当 iframe 被隐藏时，这个区域应该为空。当 iframe 再次显示时，这个区域应该重新计算并包含 iframe 的区域。

**涉及用户或者编程常见的使用错误：**

*   **忘记处理嵌套滚动容器的滚动事件：** 用户可能会在复杂的页面结构中创建多层嵌套的可滚动容器，但忘记正确处理滚动事件的冒泡或捕获，导致滚动行为不符合预期。这些测试可以帮助开发者确保 Blink 在这种情况下正确地识别可滚动的区域。
*   **错误地假设固定定位元素或带有 transform 属性的元素也能参与快速非合成滚动：** 这些测试验证了 Blink 是否正确地将这些元素排除在快速非合成滚动命中测试之外，从而避免潜在的性能问题或行为不一致。
*   **在 JavaScript 中动态修改元素的样式，导致滚动行为意外变化：** 用户可能会在 JavaScript 中动态地修改元素的 `display`、`visibility` 或 `transform` 属性，而没有意识到这些修改会对滚动命中测试区域产生影响。这些测试确保了 Blink 在这些动态变化发生时能够正确地更新滚动相关的状态。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户浏览网页：** 用户在浏览器中打开一个包含复杂滚动结构的网页，例如包含多层嵌套的 iframe，或者使用了 `overflow: scroll` 的 div 元素。
2. **用户进行滚动操作：** 用户尝试滚动页面或特定的可滚动元素，例如使用鼠标滚轮、拖动滚动条、或者使用触摸手势。
3. **Blink 引擎处理滚动事件：** 当用户进行滚动操作时，浏览器内核 Blink 引擎会接收到这些事件。
4. **命中测试（Hit-Testing）：** Blink 需要确定用户的滚动操作是针对哪个可滚动元素。这涉及到命中测试，即判断鼠标指针或触摸点是否位于某个可滚动元素的滚动区域内。
5. **计算滚动区域：**  Blink 会根据元素的布局、样式（例如 `overflow`、`position`、`transform` 等）以及是否是 iframe 等因素，计算出哪些区域可以触发滚动。
6. **触发 `scrolling_test.cc` 中的代码（间接）：** 如果在开发或调试 Blink 引擎的滚动功能，开发者可能会运行 `scrolling_test.cc` 中的测试用例，以验证上述滚动处理逻辑是否正确。这些测试用例模拟了各种复杂的滚动场景，并断言 Blink 的行为是否符合预期。例如，`NestedIFramesMainThreadScrollingRegion` 测试模拟了用户在一个包含嵌套 iframe 的页面上滚动的情况，并验证 Blink 是否正确计算了最内层可滚动 div 的命中测试区域。

**总结:** 这部分测试代码旨在全面验证 Blink 引擎在处理各种复杂滚动场景时的正确性和健壮性，特别是关注非合成滚动的命中测试、iframe 的滚动行为以及元素属性变化对滚动的影响。它可以帮助开发者发现和修复与滚动相关的 bug，并确保浏览器能够为用户提供流畅的滚动体验。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/scrolling_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
nt, covered1, covered2, covered3.
                   // TODO(crbug.com/357905840): Ideally covered2 should be
                   // fast, but for now
                   // it's marked not fast by the background chunk of covering2.
                   gfx::Rect(50, 150, 100, 400),
                   // covering3.
                   gfx::Rect(0, 450, 100, 50)}),
              non_fast_region);
    EXPECT_EQ(2u, scroll_hit_test_rects->size());
    // standalone.
    EXPECT_EQ(gfx::Rect(50, 50, 100, 100),
              scroll_hit_test_rects->at(0).hit_test_rect);
    // covering2.
    EXPECT_EQ(gfx::Rect(0, 350, 100, 50),
              scroll_hit_test_rects->at(1).hit_test_rect);
  } else {
    EXPECT_EQ(RegionFromRects(
                  {// standalone, nested-parent, covered1, covered2, covered3.
                   gfx::Rect(50, 50, 100, 500),
                   // convering2, coverting3.
                   gfx::Rect(0, 350, 100, 50), gfx::Rect(0, 450, 100, 50)}),
              non_fast_region);
    EXPECT_TRUE(scroll_hit_test_rects->empty());
  }
}

TEST_P(ScrollingTest, ElementRegionCaptureData) {
  LoadHTML(R"HTML(
              <head>
                <style type="text/css">
                  body {
                    height: 2000px;
                  }
                  #scrollable {
                    margin-top: 50px;
                    margin-left: 50px;
                    width: 200px;
                    height: 200px;
                    overflow: scroll;
                  }
                  #content {
                    width: 1000px;
                    height: 1000px;
                  }
                </style>
              </head>

              <body>
                <div id="scrollable">
                  <div id="content"></div>
                </div>
              </body>
            )HTML");

  Element* scrollable_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("scrollable"));
  Element* content_element =
      GetFrame()->GetDocument()->getElementById(AtomicString("content"));

  const RegionCaptureCropId scrollable_id(
      GUIDToToken(base::Uuid::GenerateRandomV4()));
  const RegionCaptureCropId content_id(
      GUIDToToken(base::Uuid::GenerateRandomV4()));

  scrollable_element->SetRegionCaptureCropId(
      std::make_unique<RegionCaptureCropId>(scrollable_id));
  content_element->SetRegionCaptureCropId(
      std::make_unique<RegionCaptureCropId>(content_id));
  ForceFullCompositingUpdate();

  const cc::Layer* container_layer = MainFrameScrollingContentsLayer();
  const cc::Layer* contents_layer =
      ScrollingContentsLayerByDOMElementId("scrollable");
  ASSERT_TRUE(container_layer);
  ASSERT_TRUE(contents_layer);

  const base::flat_map<viz::RegionCaptureCropId, gfx::Rect>& container_bounds =
      container_layer->capture_bounds().bounds();
  const base::flat_map<viz::RegionCaptureCropId, gfx::Rect>& contents_bounds =
      contents_layer->capture_bounds().bounds();

  EXPECT_EQ(1u, container_bounds.size());
  EXPECT_FALSE(container_bounds.begin()->first.is_zero());
  EXPECT_EQ(scrollable_id.value(), container_bounds.begin()->first);
  EXPECT_EQ((gfx::Size{200, 200}), container_bounds.begin()->second.size());

  EXPECT_EQ(1u, contents_bounds.size());
  EXPECT_FALSE(contents_bounds.begin()->first.is_zero());
  EXPECT_EQ(content_id.value(), contents_bounds.begin()->first);
  EXPECT_EQ((gfx::Rect{0, 0, 1000, 1000}), contents_bounds.begin()->second);
}

TEST_P(ScrollingTest, overflowScrolling) {
  SetupHttpTestURL("overflow-scrolling.html");

  // Verify the scroll node of the accelerated scrolling element.
  auto* scroll_node = ScrollNodeByDOMElementId("scrollable");
  ASSERT_TRUE(scroll_node);
  EXPECT_TRUE(scroll_node->user_scrollable_horizontal);
  EXPECT_TRUE(scroll_node->user_scrollable_vertical);

  EXPECT_TRUE(ScrollbarLayerForScrollNode(
      scroll_node, cc::ScrollbarOrientation::kHorizontal));
  EXPECT_TRUE(ScrollbarLayerForScrollNode(scroll_node,
                                          cc::ScrollbarOrientation::kVertical));
}

TEST_P(ScrollingTest, overflowHidden) {
  SetupHttpTestURL("overflow-hidden.html");

  // Verify the scroll node of the accelerated scrolling element.
  const auto* scroll_node = ScrollNodeByDOMElementId("unscrollable-y");
  ASSERT_TRUE(scroll_node);
  EXPECT_TRUE(scroll_node->user_scrollable_horizontal);
  EXPECT_FALSE(scroll_node->user_scrollable_vertical);

  scroll_node = ScrollNodeByDOMElementId("unscrollable-x");
  ASSERT_TRUE(scroll_node);
  EXPECT_FALSE(scroll_node->user_scrollable_horizontal);
  EXPECT_TRUE(scroll_node->user_scrollable_vertical);
}

TEST_P(ScrollingTest, iframeScrolling) {
  RegisterMockedHttpURLLoad("iframe-scrolling.html");
  RegisterMockedHttpURLLoad("iframe-scrolling-inner.html");
  NavigateToHttp("iframe-scrolling.html");
  ForceFullCompositingUpdate();

  Element* scrollable_frame =
      GetFrame()->GetDocument()->getElementById(AtomicString("scrollable"));
  ASSERT_TRUE(scrollable_frame);

  LayoutObject* layout_object = scrollable_frame->GetLayoutObject();
  ASSERT_TRUE(layout_object);
  ASSERT_TRUE(layout_object->IsLayoutEmbeddedContent());

  auto* layout_embedded_content = To<LayoutEmbeddedContent>(layout_object);
  ASSERT_TRUE(layout_embedded_content);

  LocalFrameView* inner_frame_view =
      To<LocalFrameView>(layout_embedded_content->ChildFrameView());
  ASSERT_TRUE(inner_frame_view);

  // Verify the scroll node of the accelerated scrolling iframe.
  auto* scroll_node =
      ScrollNodeForScrollableArea(inner_frame_view->LayoutViewport());
  ASSERT_TRUE(scroll_node);
  EXPECT_TRUE(ScrollbarLayerForScrollNode(
      scroll_node, cc::ScrollbarOrientation::kHorizontal));
  EXPECT_TRUE(ScrollbarLayerForScrollNode(scroll_node,
                                          cc::ScrollbarOrientation::kVertical));
}

TEST_P(ScrollingTest, rtlIframe) {
  RegisterMockedHttpURLLoad("rtl-iframe.html");
  RegisterMockedHttpURLLoad("rtl-iframe-inner.html");
  NavigateToHttp("rtl-iframe.html");
  ForceFullCompositingUpdate();

  Element* scrollable_frame =
      GetFrame()->GetDocument()->getElementById(AtomicString("scrollable"));
  ASSERT_TRUE(scrollable_frame);

  LayoutObject* layout_object = scrollable_frame->GetLayoutObject();
  ASSERT_TRUE(layout_object);
  ASSERT_TRUE(layout_object->IsLayoutEmbeddedContent());

  auto* layout_embedded_content = To<LayoutEmbeddedContent>(layout_object);
  ASSERT_TRUE(layout_embedded_content);

  LocalFrameView* inner_frame_view =
      To<LocalFrameView>(layout_embedded_content->ChildFrameView());
  ASSERT_TRUE(inner_frame_view);

  // Verify the scroll node of the accelerated scrolling iframe.
  const auto* scroll_node =
      ScrollNodeForScrollableArea(inner_frame_view->LayoutViewport());
  ASSERT_TRUE(scroll_node);

  int expected_scroll_position = 958 + (inner_frame_view->LayoutViewport()
                                                ->VerticalScrollbar()
                                                ->IsOverlayScrollbar()
                                            ? 0
                                            : 15);
  ASSERT_EQ(expected_scroll_position, CurrentScrollOffset(scroll_node).x());
}

TEST_P(ScrollingTest, setupScrollbarLayerShouldNotCrash) {
  SetupHttpTestURL("setup_scrollbar_layer_crash.html");
  // This test document setup an iframe with scrollbars, then switch to
  // an empty document by javascript.
}

#if BUILDFLAG(IS_MAC) || BUILDFLAG(IS_ANDROID)
TEST_P(ScrollingTest, DISABLED_setupScrollbarLayerShouldSetScrollLayerOpaque)
#else
TEST_P(ScrollingTest, setupScrollbarLayerShouldSetScrollLayerOpaque)
#endif
{
  ScopedMockOverlayScrollbars mock_overlay_scrollbar(false);

  SetupHttpTestURL("wide_document.html");

  LocalFrameView* frame_view = GetFrame()->View();
  ASSERT_TRUE(frame_view);

  auto* scroll_node = ScrollNodeForScrollableArea(frame_view->LayoutViewport());
  ASSERT_TRUE(scroll_node);

  auto* horizontal_scrollbar_layer = ScrollbarLayerForScrollNode(
      scroll_node, cc::ScrollbarOrientation::kHorizontal);
  ASSERT_TRUE(horizontal_scrollbar_layer);
  EXPECT_EQ(!frame_view->LayoutViewport()
                 ->HorizontalScrollbar()
                 ->IsOverlayScrollbar(),
            horizontal_scrollbar_layer->contents_opaque());

  EXPECT_FALSE(ScrollbarLayerForScrollNode(
      scroll_node, cc::ScrollbarOrientation::kVertical));
}

TEST_P(ScrollingTest, NestedIFramesMainThreadScrollingRegion) {
  // This page has an absolute IFRAME. It contains a scrollable child DIV
  // that's nested within an intermediate IFRAME.
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            #spacer {
              height: 10000px;
            }
            iframe {
              position: absolute;
              top: 1200px;
              left: 0px;
              width: 200px;
              height: 200px;
              border: 0;
            }

          </style>
          <div id="spacer"></div>
          <iframe srcdoc="
              <!DOCTYPE html>
              <style>
                body { margin: 0; }
                iframe { width: 100px; height: 100px; border: 0; }
              </style>
              <iframe srcdoc='<!DOCTYPE html>
                              <style>
                                body { margin: 0; }
                                div {
                                  width: 65px;
                                  height: 65px;
                                  overflow: auto;
                                  /* Make the div not eligible for fast scroll
                                     hit test. */
                                  border-radius: 5px;
                                }
                                p {
                                  width: 300px;
                                  height: 300px;
                                }
                              </style>
                              <div>
                                <p></p>
                              </div>'>
              </iframe>">
          </iframe>
      )HTML");

  ForceFullCompositingUpdate();

  // Scroll the frame to ensure the rect is in the correct coordinate space.
  GetFrame()->GetDocument()->View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 1000), mojom::blink::ScrollType::kProgrammatic);

  ForceFullCompositingUpdate();

  auto* non_fast_layer = MainFrameScrollingContentsLayer();
  EXPECT_EQ(cc::Region(gfx::Rect(0, 1200, 65, 65)),
            non_fast_layer->main_thread_scroll_hit_test_region());
  // Nested scroll is not eligible for fast non-composited scroll hit test.
  EXPECT_TRUE(non_fast_layer->non_composited_scroll_hit_test_rects()->empty());
}

// Same as above but test that the rect is correctly calculated into the fixed
// region when the containing iframe is position: fixed.
TEST_P(ScrollingTest, NestedFixedIFramesMainThreadScrollingRegion) {
  // This page has a fixed IFRAME. It contains a scrollable child DIV that's
  // nested within an intermediate IFRAME.
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            #spacer {
              height: 10000px;
            }
            #iframe {
              position: fixed;
              top: 20px;
              left: 0px;
              width: 200px;
              height: 200px;
              border: 20px solid blue;
            }

          </style>
          <div id="spacer"></div>
          <iframe id="iframe" srcdoc="
              <!DOCTYPE html>
              <style>
                body { margin: 0; }
                iframe { width: 100px; height: 100px; border: 0; }
              </style>
              <iframe srcdoc='<!DOCTYPE html>
                              <style>
                                body { margin: 0; }
                                div {
                                  width: 75px;
                                  height: 75px;
                                  overflow: auto;
                                  /* Make the div not eligible for fast scroll
                                     hit test. */
                                  border-radius: 5px;
                                }
                                p {
                                  width: 300px;
                                  height: 300px;
                                }
                              </style>
                              <div>
                                <p></p>
                              </div>'>
              </iframe>">
          </iframe>
      )HTML");

  ForceFullCompositingUpdate();

  // Scroll the frame to ensure the rect is in the correct coordinate space.
  GetFrame()->GetDocument()->View()->GetScrollableArea()->SetScrollOffset(
      ScrollOffset(0, 1000), mojom::blink::ScrollType::kProgrammatic);

  ForceFullCompositingUpdate();
  auto* non_fast_layer = LayerByDOMElementId("iframe");
  EXPECT_EQ(cc::Region(gfx::Rect(20, 20, 75, 75)),
            non_fast_layer->main_thread_scroll_hit_test_region());
  // Nested scroll is not eligible for fast non-composited scroll hit test.
  EXPECT_TRUE(non_fast_layer->non_composited_scroll_hit_test_rects()->empty());
}

TEST_P(ScrollingTest, IframeCompositedScrolling) {
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      body { margin: 0; }
      iframe { height: 100px; width: 100px; }
    </style>
    <iframe id="iframe1" srcdoc="<!DOCTYPE html>"></iframe>
    <iframe id="iframe2" srcdoc="
      <!DOCTYPE html>
      <style>body { height: 1000px; }</style>">
    </iframe>
  )HTML");
  ForceFullCompositingUpdate();

  // Should not have main_thread_scroll_hit_test_region or
  // non_composited_scroll_hit_test_rects on any layer.
  for (auto& layer : RootCcLayer()->children()) {
    EXPECT_TRUE(layer->main_thread_scroll_hit_test_region().IsEmpty());
    EXPECT_FALSE(layer->non_composited_scroll_hit_test_rects());
  }
}

TEST_P(ScrollingTest, IframeNonCompositedScrollingHideAndShow) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            body {
              margin: 0;
            }
            iframe {
              height: 100px;
              width: 100px;
            }
          </style>
          <iframe id="iframe" srcdoc="
              <!DOCTYPE html>
              <style>
                body {height: 1000px;}
              </style>"></iframe>
      )HTML");

  ForceFullCompositingUpdate();

  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    // Should have a NonCompositedScrollHitTestRect initially.
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->main_thread_scroll_hit_test_region()
                    .IsEmpty());
    EXPECT_EQ(gfx::Rect(2, 2, 100, 100),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    // Should have a MainThreadScrollHitTestRegion initially.
    EXPECT_EQ(cc::Region(gfx::Rect(2, 2, 100, 100)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->non_composited_scroll_hit_test_rects()
                    ->empty());
  }

  // Hiding the iframe should clear the MainThreadScrollHitTestRegion and
  // NonCompositedScrollHitTestRect.
  Element* iframe =
      GetFrame()->GetDocument()->getElementById(AtomicString("iframe"));
  iframe->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));
  ForceFullCompositingUpdate();
  EXPECT_TRUE(MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region()
                  .IsEmpty());
  EXPECT_FALSE(MainFrameScrollingContentsLayer()
                   ->non_composited_scroll_hit_test_rects());

  // Showing it again should compute the MainThreadScrollHitTestRegion or
  // NonCompositedScrollHitTestRect.
  iframe->setAttribute(html_names::kStyleAttr, g_empty_atom);
  ForceFullCompositingUpdate();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->main_thread_scroll_hit_test_region()
                    .IsEmpty());
    EXPECT_EQ(gfx::Rect(2, 2, 100, 100),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    EXPECT_EQ(cc::Region(gfx::Rect(2, 2, 100, 100)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->non_composited_scroll_hit_test_rects()
                    ->empty());
  }
}

// Same as above but use visibility: hidden instead of display: none.
TEST_P(ScrollingTest, IframeNonCompositedScrollingHideAndShowVisibility) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            body {
              margin: 0;
            }
            iframe {
              height: 100px;
              width: 100px;
            }
          </style>
          <iframe id="iframe" srcdoc="
              <!DOCTYPE html>
              <style>
                body {height: 1000px;}
              </style>"></iframe>
      )HTML");

  ForceFullCompositingUpdate();

  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    // Should have a NonCompositedScrollHitTestRect initially.
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->main_thread_scroll_hit_test_region()
                    .IsEmpty());
    EXPECT_EQ(gfx::Rect(2, 2, 100, 100),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    // Should have a MainThreadScrollHitTestRegion initially.
    EXPECT_EQ(cc::Region(gfx::Rect(2, 2, 100, 100)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->non_composited_scroll_hit_test_rects()
                    ->empty());
  }

  // Hiding the iframe should clear the MainThreadScrollHitTestRegion and
  // NonCompositedScrollHitTestRect.
  Element* iframe =
      GetFrame()->GetDocument()->getElementById(AtomicString("iframe"));
  iframe->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));
  ForceFullCompositingUpdate();
  EXPECT_TRUE(MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region()
                  .IsEmpty());
  EXPECT_FALSE(MainFrameScrollingContentsLayer()
                   ->non_composited_scroll_hit_test_rects());

  // Showing it again should compute the MainThreadScrollHitTestRegion or
  // NonCompositedScrollHitTestRect.
  iframe->setAttribute(html_names::kStyleAttr, g_empty_atom);
  ForceFullCompositingUpdate();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->main_thread_scroll_hit_test_region()
                    .IsEmpty());
    EXPECT_EQ(gfx::Rect(2, 2, 100, 100),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    EXPECT_EQ(cc::Region(gfx::Rect(2, 2, 100, 100)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->non_composited_scroll_hit_test_rects()
                    ->empty());
  }
}

// Same as above but the main frame is scrollable. This should cause the non
// fast scrollable regions to go on the outer viewport's scroll layer.
TEST_P(ScrollingTest, IframeNonCompositedScrollingHideAndShowScrollable) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            body {
              height: 1000px;
              margin: 0;
            }
            iframe {
              height: 100px;
              width: 100px;
            }
          </style>
          <iframe id="iframe" srcdoc="
              <!DOCTYPE html>
              <style>
                body {height: 1000px;}
              </style>"></iframe>
      )HTML");

  ForceFullCompositingUpdate();

  Page* page = GetFrame()->GetPage();
  const auto* inner_viewport_scroll_layer =
      page->GetVisualViewport().LayerForScrolling();
  Element* iframe =
      GetFrame()->GetDocument()->getElementById(AtomicString("iframe"));

  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    // Should have a MainThreadScrollHitTestRegion initially.
    EXPECT_FALSE(MainFrameScrollingContentsLayer()
                     ->non_composited_scroll_hit_test_rects()
                     ->empty());
  } else {
    // Should have a MainThreadScrollHitTestRegion initially.
    EXPECT_FALSE(MainFrameScrollingContentsLayer()
                     ->main_thread_scroll_hit_test_region()
                     .IsEmpty());
  }

  // Ensure the visual viewport's scrolling layer didn't get a
  // MainThreadScrollHitTestRegion or NonCompositedScrollHitTestRect.
  EXPECT_TRUE(inner_viewport_scroll_layer->main_thread_scroll_hit_test_region()
                  .IsEmpty());
  EXPECT_FALSE(
      inner_viewport_scroll_layer->non_composited_scroll_hit_test_rects());

  // Hiding the iframe should clear the MainThreadScrollHitTestRegion and
  // NonCompositedScrollHitTestRect.
  iframe->setAttribute(html_names::kStyleAttr, AtomicString("display: none"));
  ForceFullCompositingUpdate();
  EXPECT_TRUE(MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region()
                  .IsEmpty());
  EXPECT_FALSE(MainFrameScrollingContentsLayer()
                   ->non_composited_scroll_hit_test_rects());

  iframe->setAttribute(html_names::kStyleAttr, g_empty_atom);
  ForceFullCompositingUpdate();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    // Showing it again should compute the NonCompositedScrollHitTestRect.
    EXPECT_FALSE(MainFrameScrollingContentsLayer()
                     ->non_composited_scroll_hit_test_rects()
                     ->empty());
  } else {
    // Showing it again should compute the MainThreadScrollHitTestRegion.
    EXPECT_FALSE(MainFrameScrollingContentsLayer()
                     ->main_thread_scroll_hit_test_region()
                     .IsEmpty());
  }
}

TEST_P(ScrollingTest, IframeNonCompositedScrollingNested) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <style>body { margin: 0; }</style>
    <iframe style="width: 1000px; height: 1000px; border: none;
                   margin-left: 51px; margin-top: 52px"
     srcdoc="
       <!DOCTYPE html>
       <style>body { margin: 50px 0; }</style>
       <div style='width: 100px; height: 100px; overflow: scroll'>
         <div style='height: 1000px'></div>
       </div>
       <iframe style='width: 211px; height: 211px; padding: 10px; border: none'
        srcdoc='
          <!DOCTYPE html>
          <style>body { margin: 0; width: 1000px; height: 1000px; }</style>
       '></iframe>
     "></iframe>
    <div style="height: 2000px"></div>
  )HTML");
  ForceFullCompositingUpdate();

  auto main_thread_region =
      MainFrameScrollingContentsLayer()->main_thread_scroll_hit_test_region();
  auto* hit_test_rects =
      MainFrameScrollingContentsLayer()->non_composited_scroll_hit_test_rects();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_TRUE(main_thread_region.IsEmpty());
    EXPECT_EQ(2u, hit_test_rects->size());
    EXPECT_EQ(gfx::Rect(51, 102, 100, 100),
              hit_test_rects->at(0).hit_test_rect);
    EXPECT_EQ(gfx::Rect(61, 212, 211, 211),
              hit_test_rects->at(1).hit_test_rect);
  } else {
    EXPECT_EQ(RegionFromRects(
                  {gfx::Rect(51, 102, 100, 100), gfx::Rect(61, 212, 211, 211)}),
              main_thread_region);
    EXPECT_TRUE(hit_test_rects->empty());
  }
}

TEST_P(ScrollingTest, IframeNonCompositedScrollingTransformed) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <iframe style="position: absolute; left: 300px; top: 300px;
                   width: 200px; height: 200px; border: none;
                   transform: scale(2)"
     srcdoc="
       <!DOCTYPE html>
       <style>body { margin: 0; }</style>
       <iframe style='width: 120px; height: 120px; padding: 10px; border: none'
        srcdoc='
          <!DOCTYPE html>
          <style>body { margin: 0; width: 1000px; height: 1000px }</style>
        '></iframe>
     "></iframe>
    <div style="height: 2000px"></div>
  )HTML");
  ForceFullCompositingUpdate();

  EXPECT_EQ(
      cc::Region(gfx::Rect(220, 220, 240, 240)),
      MainFrameScrollingContentsLayer()->main_thread_scroll_hit_test_region());
  // The scale makes the scroller not eligible for fast non-composited scroll
  // hit test.
  EXPECT_TRUE(MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->empty());
}

TEST_P(ScrollingTest, IframeNonCompositedScrollingPageScaled) {
  GetFrame()->GetPage()->SetPageScaleFactor(2.f);
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <iframe style="position: absolute; left: 300px; top: 300px;
                   width: 200px; height: 200px; border: none"
     srcdoc="
       <!DOCTYPE html>
       <style>body { margin: 0; }</style>
       <iframe style='width: 120px; height: 120px; padding: 10px; border: none'
        srcdoc='
          <!DOCTYPE html>
          <style>body { margin: 0; width: 1000px; height: 1000px }</style>
        '></iframe>
     "></iframe>
    <div style="height: 2000px"></div>
  )HTML");
  ForceFullCompositingUpdate();

  // cc::Layer::main_thread_scroll_hit_test_region and
  // non_composited_scroll_hit_test_rects are in layer space and are not
  // affected by the page scale.
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->main_thread_scroll_hit_test_region()
                    .IsEmpty());
    EXPECT_EQ(gfx::Rect(310, 310, 120, 120),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    EXPECT_EQ(cc::Region(gfx::Rect(310, 310, 120, 120)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
    EXPECT_TRUE(MainFrameScrollingContentsLayer()
                    ->non_composited_scroll_hit_test_rects()
                    ->empty());
  }
}

TEST_P(ScrollingTest, NonCompositedScrollTransformChange) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
    <!DOCTYPE html>
    <style>body { margin: 0; }</style>
    <div id="scroll" style="width: 222px; height: 222px; overflow: scroll;
                            transform: translateX(0)">
      <div style="height: 1000px"></div>
    </div>
  )HTML");
  ForceFullCompositingUpdate();

  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_EQ(gfx::Rect(0, 0, 222, 222),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    EXPECT_EQ(cc::Region(gfx::Rect(0, 0, 222, 222)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
  }

  GetFrame()->GetDocument()->body()->SetInlineStyleProperty(
      CSSPropertyID::kPadding, "10px");
  ForceFullCompositingUpdate();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_EQ(gfx::Rect(10, 10, 222, 222),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    EXPECT_EQ(cc::Region(gfx::Rect(10, 10, 222, 222)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
  }

  GetFrame()
      ->GetDocument()
      ->getElementById(AtomicString("scroll"))
      ->SetInlineStyleProperty(CSSPropertyID::kTransform, "translateX(100px)");
  ForceFullCompositingUpdate();
  if (RuntimeEnabledFeatures::FastNonCompositedScrollHitTestEnabled()) {
    EXPECT_EQ(gfx::Rect(110, 10, 222, 222),
              MainFrameScrollingContentsLayer()
                  ->non_composited_scroll_hit_test_rects()
                  ->at(0)
                  .hit_test_rect);
  } else {
    EXPECT_EQ(cc::Region(gfx::Rect(110, 10, 222, 222)),
              MainFrameScrollingContentsLayer()
                  ->main_thread_scroll_hit_test_region());
  }
}

TEST_P(ScrollingTest, ScrollOffsetClobberedBeforeCompositingUpdate) {
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            #container {
              width: 300px;
              height: 300px;
              overflow: auto;
              will-change: transform;
            }
            #spacer {
              height: 1000px;
            }
          </style>
          <div id="container">
            <div id="spacer"></div>
          </div>
      )HTML");
  ForceFullCompositingUpdate();

  auto* scrollable_area = ScrollableAreaByDOMElementId("container");
  ASSERT_EQ(0, scrollable_area->GetScrollOffset().y());
  const auto* scroll_node = ScrollNodeForScrollableArea(scrollable_area);

  // Simulate 100px of scroll coming from the compositor thread during a commit.
  gfx::Vector2dF compositor_delta(0, 100.f);
  cc::CompositorCommitData commit_data;
  commit_data.scrolls.push_back(
      {scrollable_area->GetScrollElementId(), compositor_delta, std::nullopt});
  RootCcLayer()->layer_tree_host()->ApplyCompositorChanges(&commit_data);
  // The compositor offset is reflected in blink and cc scroll tree.
  gfx::PointF expected_scroll_position =
      gfx::PointAtOffsetFromOrigin(compositor_delta);
  EXPECT_EQ(expected_scroll_position, scrollable_area->ScrollPosition());
  EXPECT_EQ(expected_scroll_position, CurrentScrollOffset(scroll_node));

  // Before updating the lifecycle, set the scroll offset back to what it was
  // before the commit from the main thread.
  scrollable_area->SetScrollOffset(ScrollOffset(0, 0),
                                   mojom::blink::ScrollType::kProgrammatic);

  // Ensure the offset is up-to-date on the cc::Layer even though, as far as
  // the main thread is concerned, it was unchanged since the last time we
  // pushed the scroll offset.
  ForceFullCompositingUpdate();
  EXPECT_EQ(gfx::PointF(), CurrentScrollOffset(scroll_node));
}

TEST_P(ScrollingTest, UpdateVisualViewportScrollLayer) {
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            #box {
              width: 300px;
              height: 1000px;
              background-color: red;
            }
          </style>
          <div id="box">
          </div>
      )HTML");
  ForceFullCompositingUpdate();

  Page* page = GetFrame()->GetPage();
  const auto* inner_viewport_scroll_node =
      ScrollNodeForScrollableArea(&page->GetVisualViewport());

  page->GetVisualViewport().SetScale(2);
  ForceFullCompositingUpdate();
  EXPECT_EQ(gfx::PointF(0, 0), CurrentScrollOffset(inner_viewport_scroll_node));

  page->GetVisualViewport().SetLocation(gfx::PointF(10, 20));
  ForceFullCompositingUpdate();
  EXPECT_EQ(gfx::PointF(10, 20),
            CurrentScrollOffset(inner_viewport_scroll_node));
}

TEST_P(ScrollingTest, NonCompositedMainThreadScrollHitTestRegion) {
  SetPreferCompositingToLCDText(false);
  LoadHTML(R"HTML(
          <!DOCTYPE html>
          <style>
            body { margin: 0; }
            #composited_container {
              will-change: transform;
              border: 20px solid blue;
            }
            #scroller {
              height: 200px;
              width: 200px;
              overflow-y: scroll;
            }
          </style>
          <div id="composited_container">
            <div id="scroller">
              <div id="forcescroll" style="height: 1000px;"></div>
            </div>
          </div>
      )HTML");
  ForceFullCompositingUpdate();

  const auto* cc_layer = LayerByD
"""


```