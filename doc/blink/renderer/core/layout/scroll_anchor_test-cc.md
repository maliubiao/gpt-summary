Response:
The user wants a summary of the functionality of the provided C++ code. The code is a unit test file (`scroll_anchor_test.cc`) for the scroll anchoring feature in the Chromium Blink rendering engine.

Here's a breakdown of how to address the request:

1. **Identify the core purpose:** The file tests the `ScrollAnchor` class.
2. **Analyze the test cases:**  Each `TEST_F` function tests a specific aspect of scroll anchoring. Group these aspects into functional categories.
3. **Relate to web technologies:** Connect the tested functionalities to concepts in HTML, CSS, and JavaScript. Scroll anchoring directly affects how web pages maintain their scroll position when content changes, which users experience through these technologies.
4. **Infer logic and provide examples:**  For tests involving layout changes and scroll adjustments, create simple scenarios with assumed inputs and outputs.
5. **Identify potential errors:** Look for tests that address edge cases or user interactions that might lead to unexpected behavior. These often highlight common mistakes.
6. **Summarize the overall functionality:** Combine the identified aspects into a concise description of the file's purpose.
ThisC++代码文件 `scroll_anchor_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `ScrollAnchor` 类的功能。`ScrollAnchor` 负责在页面内容发生变化时，尽量保持用户的滚动位置不发生大的偏移，提供更平滑的用户体验。

以下是代码中测试的主要功能点归纳：

**核心功能：页面滚动锚定 (Scroll Anchoring)**

* **基本锚定：** 测试当页面内容发生变化（例如，元素高度变化）时，滚动条是否能智能调整，将用户之前看到的某个元素保持在视野内的能力。
    * **假设输入：** 页面加载后滚动到某个位置，然后通过 JavaScript 或 CSS 修改页面上某个元素的高度。
    * **预期输出：** 滚动条会进行调整，使得在修改高度之前用户关注的元素（锚点元素）尽量保持在屏幕上的相同位置。
* **视觉视口锚定 (Visual Viewport Anchoring)：** 测试在缩放或移动视觉视口时，滚动锚定是否能正常工作。
* **清除祖先滚动容器的锚定：**  当在一个嵌套的滚动容器中进行非锚定滚动时，应该清除其所有祖先滚动容器的滚动锚定。
* **分数偏移量的处理：** 确保在比较滚动偏移量时，对浮点数进行正确的舍入处理。
* **避免粘性定位元素作为锚点：** 测试滚动锚定是否会避免选择粘性定位的元素作为锚点，因为这些元素在滚动时位置会发生变化。
* **包含独立渲染层的元素的锚定：** 测试当锚点元素位于具有自身渲染层的元素内时，滚动锚定是否正常工作。
* **拖动滚动条时的锚定：**  测试在用户通过拖动滚动条进行滚动时，滚动锚定是否能正常工作。
* **移除包含独立渲染层的滚动容器：** 测试移除包含具有自身渲染层的子元素的滚动容器时，是否会发生崩溃。
* **Flexbox 布局下的延迟调整：** 测试在 Flexbox 布局下，由于布局计算的延迟，滚动锚定是否也能延迟调整。
* **禁用打印时的锚定：** 验证在打印模式下，滚动锚定功能是否被禁用。

**序列化和恢复锚点信息**

* **序列化锚点 (Serialize Anchor)：** 测试将当前页面的滚动锚点信息（包括锚点元素的 CSS 选择器和相对偏移量）序列化为字符串的功能。
    * **关系到 HTML, CSS:**  序列化过程会提取锚点元素的 CSS 选择器（例如 `#id`, `.class`, `tagname`, `nth-child` 等），这直接依赖于页面的 HTML 结构和 CSS 样式。
    * **假设输入：** 页面加载并滚动到一定位置，触发序列化操作。
    * **预期输出：**  生成一个包含锚点元素 CSS 选择器和相对于视口的偏移量的字符串。
* **恢复锚点 (Restore Anchor)：** 测试使用之前序列化的锚点信息，恢复到之前的滚动位置和锚点状态。
    * **关系到 HTML, CSS:** 恢复过程需要使用序列化的 CSS 选择器来重新定位锚点元素，并根据保存的偏移量调整滚动位置。如果页面的 HTML 结构在序列化后发生了显著变化，恢复可能会失败或定位到错误的元素。
    * **假设输入：**  一个有效的序列化锚点字符串。
    * **预期输出：** 页面滚动到与序列化信息对应的位置，并将相应的元素设置为锚点。
* **序列化选择器的限制：**  测试序列化锚点时，选择器长度是否有限制。
* **处理重复 ID 的情况：** 测试在页面中存在重复 ID 的情况下，序列化锚点如何选择正确的元素。
* **不为伪元素或 Shadow DOM 元素创建锚点：**  验证滚动锚定不会选择伪元素 (e.g., `::after`) 或 Shadow DOM 内的元素作为锚点。

**常见使用错误示例 (推断)**

虽然代码本身是测试代码，但我们可以根据测试的功能推断出一些用户或编程常见的错误：

* **修改 DOM 结构后期望滚动位置完全不变：** 用户可能认为滚动锚定能完美地保持滚动位置，但如果修改 DOM 结构导致锚点元素被移除或其父元素发生重大变化，锚定可能会失败或产生不理想的结果。
* **过度依赖 ID 选择器：** 如果页面的 ID 不是唯一的，滚动锚定在序列化和恢复时可能会定位到错误的元素。测试中包含了处理重复 ID 的情况，说明这是一个需要考虑的问题。
* **在 Shadow DOM 中操作锚点：**  滚动锚定不会跨越 Shadow DOM 的边界，尝试在 Shadow DOM 中设置或恢复锚点可能会失败。
* **对伪元素进行锚定操作：**  伪元素不是真实的 DOM 元素，不能作为滚动锚定的目标。

**总结：**

`scroll_anchor_test.cc` 文件的主要功能是全面测试 Blink 引擎中 `ScrollAnchor` 类的各种功能和边界情况，确保在各种页面内容变化和用户交互下，滚动锚定能够有效地工作，提供更稳定的用户滚动体验。它涵盖了基本锚定、视觉视口锚定、嵌套滚动容器的处理，以及锚点信息的序列化和恢复等关键方面。 这部分代码侧重于滚动锚定的核心逻辑和在不同场景下的行为验证。

Prompt: 
```
这是目录为blink/renderer/core/layout/scroll_anchor_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/scroll_anchor.h"

#include "build/build_config.h"
#include "third_party/blink/public/common/input/web_mouse_event.h"
#include "third_party/blink/renderer/core/css/css_property_names.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/editing/finder/text_finder.h"
#include "third_party/blink/renderer/core/frame/find_in_page.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/root_frame_viewport.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/page/print_context.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_animator_base.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/testing/unit_test_helpers.h"

namespace blink {

using Corner = ScrollAnchor::Corner;

class ScrollAnchorTest : public SimTest {
 public:
  ScrollAnchorTest() = default;

 protected:
  void SetUp() override {
    SimTest::SetUp();
    ResizeView(gfx::Size(800, 600));
    String kUrl = "https://example.com/test.html";
    SimRequest request(kUrl, "text/html");
    LoadURL(kUrl);
    request.Complete("<!DOCTYPE html>");
  }

  void Update() { Compositor().BeginFrame(); }

  void SetBodyInnerHTML(const String& body_content) {
    GetDocument().body()->setInnerHTML(body_content, ASSERT_NO_EXCEPTION);
    Update();
  }

  ScrollableArea* LayoutViewport() {
    return GetDocument().View()->LayoutViewport();
  }

  VisualViewport& GetVisualViewport() {
    return GetDocument().View()->GetPage()->GetVisualViewport();
  }

  ScrollableArea* ScrollerForElement(Element* element) {
    return To<LayoutBox>(element->GetLayoutObject())->GetScrollableArea();
  }

  ScrollAnchor& GetScrollAnchor(ScrollableArea* scroller) {
    DCHECK(scroller->IsPaintLayerScrollableArea());
    return *(scroller->GetScrollAnchor());
  }

  void SetHeight(Element* element, int height) {
    element->setAttribute(html_names::kStyleAttr,
                          AtomicString(String::Format("height: %dpx", height)));
    Update();
  }

  void ScrollLayoutViewport(ScrollOffset delta) {
    Element* scrolling_element = GetDocument().scrollingElement();
    if (delta.x()) {
      scrolling_element->setScrollLeft(scrolling_element->scrollLeft() +
                                       delta.x());
    }
    if (delta.y()) {
      scrolling_element->setScrollTop(scrolling_element->scrollTop() +
                                      delta.y());
    }
  }

  void ValidateSerializedAnchor(const String& expected_selector,
                                const LogicalOffset& expected_offset) {
    SerializedAnchor serialized =
        GetScrollAnchor(LayoutViewport()).GetSerializedAnchor();
    EXPECT_TRUE(serialized.IsValid());
    EXPECT_EQ(serialized.selector, expected_selector);
    EXPECT_EQ(serialized.relative_offset, expected_offset);

    StaticElementList* ele_list =
        GetDocument().QuerySelectorAll(AtomicString(serialized.selector));
    EXPECT_EQ(ele_list->length(), 1u);
  }

  Scrollbar* VerticalScrollbarForElement(Element* element) {
    return ScrollerForElement(element)->VerticalScrollbar();
  }

  void MouseDownOnVerticalScrollbar(Scrollbar* scrollbar) {
    DCHECK_EQ(true, scrollbar->GetTheme().AllowsHitTest());
    int thumb_center = scrollbar->GetTheme().ThumbPosition(*scrollbar) +
                       scrollbar->GetTheme().ThumbLength(*scrollbar) / 2;
    scrollbar_drag_point_ =
        gfx::PointF(scrollbar->GetLayoutBox()
                        ->GetScrollableArea()
                        ->ConvertFromScrollbarToContainingEmbeddedContentView(
                            *scrollbar, gfx::Point(0, thumb_center)));
    scrollbar->MouseDown(blink::WebMouseEvent(
        blink::WebInputEvent::Type::kMouseDown, *scrollbar_drag_point_,
        *scrollbar_drag_point_, blink::WebPointerProperties::Button::kLeft, 0,
        blink::WebInputEvent::kNoModifiers, base::TimeTicks::Now()));
  }

  void MouseDragVerticalScrollbar(Scrollbar* scrollbar, float scroll_delta_y) {
    DCHECK(scrollbar_drag_point_);
    ScrollableArea* scroller = scrollbar->GetLayoutBox()->GetScrollableArea();
    scrollbar_drag_point_->Offset(
        0, scroll_delta_y *
               (scrollbar->GetTheme().TrackLength(*scrollbar) -
                scrollbar->GetTheme().ThumbLength(*scrollbar)) /
               (scroller->MaximumScrollOffset().y() -
                scroller->MinimumScrollOffset().y()));
    scrollbar->MouseMoved(blink::WebMouseEvent(
        blink::WebInputEvent::Type::kMouseMove, *scrollbar_drag_point_,
        *scrollbar_drag_point_, blink::WebPointerProperties::Button::kLeft, 0,
        blink::WebInputEvent::kNoModifiers, base::TimeTicks::Now()));
  }

  void MouseUpOnVerticalScrollbar(Scrollbar* scrollbar) {
    DCHECK(scrollbar_drag_point_);
    scrollbar->MouseDown(blink::WebMouseEvent(
        blink::WebInputEvent::Type::kMouseUp, *scrollbar_drag_point_,
        *scrollbar_drag_point_, blink::WebPointerProperties::Button::kLeft, 0,
        blink::WebInputEvent::kNoModifiers, base::TimeTicks::Now()));
    scrollbar_drag_point_.reset();
  }

  std::optional<gfx::PointF> scrollbar_drag_point_;
};

// TODO(skobes): Convert this to web-platform-tests when visual viewport API is
// launched (http://crbug.com/635031).
TEST_F(ScrollAnchorTest, VisualViewportAnchors) {
  SetBodyInnerHTML(R"HTML(
    <style>
        * { font-size: 1.2em; font-family: sans-serif; }
        div { height: 100px; width: 20px; background-color: pink; }
    </style>
    <div id='div'></div>
    <div id='text'><b>This is a scroll anchoring test</div>
  )HTML");

  ScrollableArea* l_viewport = LayoutViewport();
  VisualViewport& v_viewport = GetVisualViewport();

  v_viewport.SetScale(2.0);

  // No anchor at origin (0,0).
  EXPECT_EQ(nullptr, GetScrollAnchor(l_viewport).AnchorObject());

  // Scroll the visual viewport to bring #text to the top.
  int top = GetDocument()
                .getElementById(AtomicString("text"))
                ->GetBoundingClientRect()
                ->top();
  v_viewport.SetLocation(gfx::PointF(0, top));

  SetHeight(GetDocument().getElementById(AtomicString("div")), 10);
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("text"))->GetLayoutObject(),
      GetScrollAnchor(l_viewport).AnchorObject());
  EXPECT_EQ(top - 90, v_viewport.ScrollOffsetInt().y());

  SetHeight(GetDocument().getElementById(AtomicString("div")), 100);
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("text"))->GetLayoutObject(),
      GetScrollAnchor(l_viewport).AnchorObject());
  EXPECT_EQ(top, v_viewport.ScrollOffsetInt().y());

  // Scrolling the visual viewport should clear the anchor.
  v_viewport.SetLocation(gfx::PointF(0, 0));
  EXPECT_EQ(nullptr, GetScrollAnchor(l_viewport).AnchorObject());
}

// Test that a non-anchoring scroll on scroller clears scroll anchors for all
// parent scrollers.
TEST_F(ScrollAnchorTest, ClearScrollAnchorsOnAncestors) {
  SetBodyInnerHTML(R"HTML(
    <style>
        body { height: 1000px } div { height: 200px }
        #scroller { height: 100px; width: 200px; overflow: scroll; }
    </style>
    <div id='changer'>abc</div>
    <div id='anchor'>def</div>
    <div id='scroller'><div></div></div>
  )HTML");

  ScrollableArea* viewport = LayoutViewport();

  ScrollLayoutViewport(ScrollOffset(0, 250));
  SetHeight(GetDocument().getElementById(AtomicString("changer")), 300);

  EXPECT_EQ(350, viewport->ScrollOffsetInt().y());
  EXPECT_EQ(
      GetDocument().getElementById(AtomicString("anchor"))->GetLayoutObject(),
      GetScrollAnchor(viewport).AnchorObject());

  // Scrolling the nested scroller should clear the anchor on the main frame.
  ScrollableArea* scroller = ScrollerForElement(
      GetDocument().getElementById(AtomicString("scroller")));
  scroller->ScrollBy(ScrollOffset(0, 100), mojom::blink::ScrollType::kUser);
  EXPECT_EQ(nullptr, GetScrollAnchor(viewport).AnchorObject());
}

TEST_F(ScrollAnchorTest, AncestorClearingWithSiblingReference) {
  SetBodyInnerHTML(R"HTML(
    <style>
    .scroller {
      overflow: scroll;
      width: 400px;
      height: 400px;
    }
    .space {
      width: 100px;
      height: 600px;
    }
    </style>
    <div id='s1' class='scroller'>
      <div id='anchor' class='space'></div>
    </div>
    <div id='s2' class='scroller'>
      <div class='space'></div>
    </div>
  )HTML");
  Element* s1 = GetDocument().getElementById(AtomicString("s1"));
  Element* s2 = GetDocument().getElementById(AtomicString("s2"));
  Element* anchor = GetDocument().getElementById(AtomicString("anchor"));

  // Set non-zero scroll offsets for #s1 and #document
  s1->setScrollTop(100);
  ScrollLayoutViewport(ScrollOffset(0, 100));

  // Invalidate layout.
  SetHeight(anchor, 500);

  // This forces layout, during which both #s1 and #document will anchor to
  // #anchor. Then the scroll clears #s2 and #document.  Since #anchor is still
  // referenced by #s1, its IsScrollAnchorObject bit must remain set.
  s2->setScrollTop(100);

  // This should clear #s1.  If #anchor had its bit cleared already we would
  // crash in update().
  s1->RemoveChild(anchor);
  Update();
}

TEST_F(ScrollAnchorTest, FractionalOffsetsAreRoundedBeforeComparing) {
  SetBodyInnerHTML(R"HTML(
    <style> body { height: 1000px } </style>
    <div id='block1' style='height: 50.4px'>abc</div>
    <div id='block2' style='height: 100px'>def</div>
  )HTML");

  ScrollableArea* viewport = LayoutViewport();
  ScrollLayoutViewport(ScrollOffset(0, 100));

  GetDocument()
      .getElementById(AtomicString("block1"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 50.6px"));
  Update();

  EXPECT_EQ(101, viewport->ScrollOffsetInt().y());
}

TEST_F(ScrollAnchorTest, AvoidStickyAnchorWhichMovesWithScroll) {
  SetBodyInnerHTML(R"HTML(
    <style> body { height: 1000px } </style>
    <div id='block1' style='height: 50px'>abc</div>
    <div id='block2' style='height: 100px; position: sticky; top: 0;'>
        def</div>
  )HTML");

  ScrollableArea* viewport = LayoutViewport();
  ScrollLayoutViewport(ScrollOffset(0, 60));

  GetDocument()
      .getElementById(AtomicString("block1"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("height: 100px"));
  Update();

  EXPECT_EQ(60, viewport->ScrollOffsetInt().y());
}

TEST_F(ScrollAnchorTest, AnchorWithLayerInScrollingDiv) {
  SetBodyInnerHTML(R"HTML(
    <style>
        #scroller { overflow: scroll; width: 500px; height: 400px; }
        div { height: 100px }
        #block2 { overflow: hidden }
        #space { height: 1000px; }
    </style>
    <div id='scroller'><div id='space'>
    <div id='block1'>abc</div>
    <div id='block2'>def</div>
    </div></div>
  )HTML");

  ScrollableArea* scroller = ScrollerForElement(
      GetDocument().getElementById(AtomicString("scroller")));
  Element* block1 = GetDocument().getElementById(AtomicString("block1"));
  Element* block2 = GetDocument().getElementById(AtomicString("block2"));

  scroller->ScrollBy(ScrollOffset(0, 150), mojom::blink::ScrollType::kUser);

  // In this layout pass we will anchor to #block2 which has its own PaintLayer.
  SetHeight(block1, 200);
  EXPECT_EQ(250, scroller->ScrollOffsetInt().y());
  EXPECT_EQ(block2->GetLayoutObject(),
            GetScrollAnchor(scroller).AnchorObject());

  // Test that the anchor object can be destroyed without affecting the scroll
  // position.
  block2->remove();
  Update();
  EXPECT_EQ(250, scroller->ScrollOffsetInt().y());
}

TEST_F(ScrollAnchorTest, AnchorWhileDraggingScrollbar) {
  // Dragging the scrollbar is inherently inaccurate. Allow many pixels slop in
  // the scroll position.
  const int kScrollbarDragAccuracy = 10;
  USE_NON_OVERLAY_SCROLLBARS_OR_QUIT();
  SetBodyInnerHTML(R"HTML(
    <style>
        #scroller { overflow: scroll; width: 500px; height: 400px; }
        div { height: 100px }
        #block2 { overflow: hidden }
        #space { height: 1000px; }
    </style>
    <div id='scroller'><div id='space'>
    <div id='block1'>abc</div>
    <div id='block2'>def</div>
    </div></div>
  )HTML");
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  ScrollableArea* scroller = ScrollerForElement(scroller_element);

  Element* block1 = GetDocument().getElementById(AtomicString("block1"));
  Element* block2 = GetDocument().getElementById(AtomicString("block2"));

  Scrollbar* scrollbar = VerticalScrollbarForElement(scroller_element);
  scroller->MouseEnteredScrollbar(*scrollbar);
  MouseDownOnVerticalScrollbar(scrollbar);
  MouseDragVerticalScrollbar(scrollbar, 150);

  // Process the injected scroll gestures.
  GetWebFrameWidget().FlushInputHandlerTasks();
  Compositor().BeginFrame();

  EXPECT_NEAR(150, scroller->GetScrollOffset().y(), kScrollbarDragAccuracy);

  // In this layout pass we will anchor to #block2 which has its own PaintLayer.
  SetHeight(block1, 200);
  EXPECT_NEAR(250, scroller->ScrollOffsetInt().y(), kScrollbarDragAccuracy);
  EXPECT_EQ(block2->GetLayoutObject(),
            GetScrollAnchor(scroller).AnchorObject());

  // If we continue dragging the scroller should scroll from the newly anchored
  // position.
  MouseDragVerticalScrollbar(scrollbar, 12);

  // Process the injected scroll gesture.
  GetWebFrameWidget().FlushInputHandlerTasks();
  Compositor().BeginFrame();

  EXPECT_NEAR(262, scroller->ScrollOffsetInt().y(), kScrollbarDragAccuracy);
  MouseUpOnVerticalScrollbar(scrollbar);
}

// Verify that a nested scroller with a div that has its own PaintLayer can be
// removed without causing a crash. This test passes if it doesn't crash.
TEST_F(ScrollAnchorTest, RemoveScrollerWithLayerInScrollingDiv) {
  SetBodyInnerHTML(R"HTML(
    <style>
        body { height: 2000px }
        #scroller { overflow: scroll; width: 500px; height: 400px}
        #block1 { height: 100px; width: 100px; overflow: hidden}
        #anchor { height: 1000px; }
    </style>
    <div id='changer1'></div>
    <div id='scroller'>
      <div id='changer2'></div>
      <div id='block1'></div>
      <div id='anchor'></div>
    </div>
  )HTML");

  ScrollableArea* viewport = LayoutViewport();
  ScrollableArea* scroller = ScrollerForElement(
      GetDocument().getElementById(AtomicString("scroller")));
  Element* changer1 = GetDocument().getElementById(AtomicString("changer1"));
  Element* changer2 = GetDocument().getElementById(AtomicString("changer2"));
  Element* anchor = GetDocument().getElementById(AtomicString("anchor"));

  scroller->ScrollBy(ScrollOffset(0, 150), mojom::blink::ScrollType::kUser);
  ScrollLayoutViewport(ScrollOffset(0, 50));

  // In this layout pass both the inner and outer scroller will anchor to
  // #anchor.
  SetHeight(changer1, 100);
  SetHeight(changer2, 100);
  EXPECT_EQ(250, scroller->ScrollOffsetInt().y());
  EXPECT_EQ(anchor->GetLayoutObject(),
            GetScrollAnchor(scroller).AnchorObject());
  EXPECT_EQ(anchor->GetLayoutObject(),
            GetScrollAnchor(viewport).AnchorObject());

  // Test that the inner scroller can be destroyed without crashing.
  GetDocument().getElementById(AtomicString("scroller"))->remove();
  Update();
}

TEST_F(ScrollAnchorTest, FlexboxDelayedClampingAlsoDelaysAdjustment) {
  SetBodyInnerHTML(R"HTML(
    <style>
        html { overflow: hidden; }
        body {
            position: absolute; display: flex;
            top: 0; bottom: 0; margin: 0;
        }
        #scroller { overflow: auto; }
        #spacer { width: 600px; height: 1200px; }
        #before { height: 50px; }
        #anchor {
            width: 100px; height: 100px;
            background-color: #8f8;
        }
    </style>
    <div id='scroller'>
        <div id='spacer'>
            <div id='before'></div>
            <div id='anchor'></div>
        </div>
    </div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->setScrollTop(100);

  SetHeight(GetDocument().getElementById(AtomicString("before")), 100);
  EXPECT_EQ(150, ScrollerForElement(scroller)->ScrollOffsetInt().y());
}

TEST_F(ScrollAnchorTest, FlexboxDelayedAdjustmentRespectsSANACLAP) {
  SetBodyInnerHTML(R"HTML(
    <style>
        html { overflow: hidden; }
        body {
            position: absolute; display: flex;
            top: 0; bottom: 0; margin: 0;
        }
        #scroller { overflow: auto; }
        #spacer { width: 600px; height: 1200px; }
        #anchor {
            position: relative; top: 50px;
            width: 100px; height: 100px;
            background-color: #8f8;
        }
    </style>
    <div id='scroller'>
        <div id='spacer'>
            <div id='anchor'></div>
        </div>
    </div>
  )HTML");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  scroller->setScrollTop(100);

  GetDocument()
      .getElementById(AtomicString("spacer"))
      ->setAttribute(html_names::kStyleAttr, AtomicString("margin-top: 50px"));
  Update();
  EXPECT_EQ(100, ScrollerForElement(scroller)->ScrollOffsetInt().y());
}

// This test verifies that scroll anchoring is disabled when the document is in
// printing mode.
TEST_F(ScrollAnchorTest, AnchoringDisabledForPrinting) {
  SetBodyInnerHTML(R"HTML(
    <style> body { height: 1000px } div { height: 100px } </style>
    <div id='block1'>abc</div>
    <div id='block2'>def</div>
  )HTML");

  ScrollableArea* viewport = LayoutViewport();
  ScrollLayoutViewport(ScrollOffset(0, 150));

  // This will trigger printing and layout.
  PrintContext::NumberOfPages(GetDocument().GetFrame(), gfx::SizeF(500, 500));

  EXPECT_EQ(150, viewport->ScrollOffsetInt().y());
  EXPECT_EQ(nullptr, GetScrollAnchor(viewport).AnchorObject());
}

TEST_F(ScrollAnchorTest, SerializeAnchorSimple) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        div { height: 100px; }
      </style>
      <div id='block1'>abc</div>
      <div id='block2'>def</div>")HTML");

  ScrollLayoutViewport(ScrollOffset(0, 150));
  ValidateSerializedAnchor("#block2", LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorUsesTagname) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        span, a { display: block; height: 100px; }
      </style>
      <div id='ancestor'>
        <a class='foobar'>abc</a>
        <span class='barbaz'>def</span>
      </div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 150));
  ValidateSerializedAnchor("#ancestor>span", LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorSetsIsAnchorBit) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        div { height: 100px; }
        .scroller {
          overflow: scroll;
          width: 400px;
          height: 400px;
        }
      </style>
      <div id='s1' class='scroller'>
        <div id='anchor'>abc</div>
      </div>")HTML");

  ScrollLayoutViewport(ScrollOffset(0, 50));
  ValidateSerializedAnchor("#anchor", LogicalOffset(0, -50));

  Element* s1 = GetDocument().getElementById(AtomicString("s1"));
  Element* anchor = GetDocument().getElementById(AtomicString("anchor"));
  // Remove the anchor. If the IsScrollAnchorObject bit is set as it should be,
  // the anchor object will get cleaned up correctly.
  s1->RemoveChild(anchor);
  // Trigger a re-layout, which will crash if it wasn't properly cleaned up when
  // removing it from the DOM.
  ScrollLayoutViewport(ScrollOffset(0, 25));
}

TEST_F(ScrollAnchorTest, SerializeAnchorSetsSavedRelativeOffset) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        div { height: 100px; }
      </style>
      <div id='block1'>abc</div>
      <div id='block2'>def</div>")HTML");

  ScrollLayoutViewport(ScrollOffset(0, 150));
  GetScrollAnchor(LayoutViewport()).Clear();
  ValidateSerializedAnchor("#block2", LogicalOffset(0, -50));

  SetHeight(GetDocument().getElementById(AtomicString("block1")), 200);
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 250);
}

TEST_F(ScrollAnchorTest, SerializeAnchorUsesClassname) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        span { display: block; height: 100px; }
      </style>
      <div id='ancestor'>
        <span class='foobar'>abc</span>
        <span class='barbaz'>def</span>
      </div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 150));
  ValidateSerializedAnchor("#ancestor>.barbaz", LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorUsesNthChild) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        p,span { display: block; height: 100px; }
      </style>
      <div id='ancestor'>
        <span class='foobar'>abc</span>
        <span class='foobar'>def</span>
      </div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 150));
  ValidateSerializedAnchor("#ancestor>:nth-child(2)", LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorUsesLeastSpecificSelector) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        div.hundred { height: 100px; }
        div.thousand { height: 1000px; }
      </style>
      <div id='ancestor' class='thousand'>
       <div class='hundred'>abc</div>
       <div class='hundred'>def</div>
       <div class='hundred'>
         <div class='hundred foobar'>
           <div class='hundred'>ghi</div>
         </div>
       <div class='hundred barbaz'></div>
      </div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 250));
  ValidateSerializedAnchor("#ancestor>:nth-child(3)>.foobar>div",
                           LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorWithNoIdAttribute) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        div.hundred { height: 100px; }
        div.thousand { height: 1000px; }
      </style>
      <div class='thousand'>
       <div class='hundred'>abc</div>
       <div class='hundred'>def</div>
       <div class='hundred'>
         <div class='hundred foobar'>
           <div class='hundred'>ghi</div>
         </div>
       <div class='hundred barbaz'></div>
      </div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 250));
  ValidateSerializedAnchor("html>body>div>:nth-child(3)>.foobar>div",
                           LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorChangesWithScroll) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        span { margin: 0; display: block; height: 100px; }
      </style>
      <div id='ancestor'>
        <span class='foobar'>abc</span>
        <span class='barbaz'>def</span>
      </div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 50));
  ValidateSerializedAnchor("#ancestor>.foobar", LogicalOffset(0, -50));

  ScrollLayoutViewport(ScrollOffset(0, 100));
  ValidateSerializedAnchor("#ancestor>.barbaz", LogicalOffset(0, -50));

  ScrollLayoutViewport(ScrollOffset(0, -100));
  ValidateSerializedAnchor("#ancestor>.foobar", LogicalOffset(0, -50));

  ScrollLayoutViewport(ScrollOffset(0, -49));
  ValidateSerializedAnchor("#ancestor>.foobar", LogicalOffset(0, -1));
}

TEST_F(ScrollAnchorTest, SerializeAnchorVerticalWritingMode) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body {
          height: 100px;
          width: 1000px;
          margin: 0;
          writing-mode:
          vertical-lr;
        }
        div { width: 100px; height: 100px; }
      </style>
      <div class = 'foobar'>abc</div>
      <div class = 'barbaz'>def</div>)HTML");

  ScrollLayoutViewport(ScrollOffset(50, 0));
  ValidateSerializedAnchor("html>body>.foobar", LogicalOffset(0, -50));

  ScrollLayoutViewport(ScrollOffset(25, 0));
  ValidateSerializedAnchor("html>body>.foobar", LogicalOffset(0, -75));

  ScrollLayoutViewport(ScrollOffset(75, 0));
  ValidateSerializedAnchor("html>body>.barbaz", LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, RestoreAnchorVerticalRlWritingMode) {
  SetBodyInnerHTML(R"HTML(
      <style>
      body {
          height: 100px;
          margin: 0;
          writing-mode:
          vertical-rl;
        }
        div.big { width: 800px; }
        div { width: 100px; height: 100px; }
      </style>
      <div class='big'></div>
      <div id='last'></div>
      )HTML");

  SerializedAnchor serialized_anchor("#last", LogicalOffset(0, 0));

  EXPECT_TRUE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().x(), 0);
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 0);
}

TEST_F(ScrollAnchorTest, SerializeAnchorQualifiedTagName) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        ns\\:div { height: 100px; display: block; }
      </style>
      <div style='height:100px'>foobar</div>
      <ns:div style='height: 100px; display: block;'
      xmlns:ns='http://www.w3.org/2005/Atom'>abc</ns:div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 150));
  ValidateSerializedAnchor("html>body>ns\\:div", LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorLimitsSelectorLength) {
  StringBuilder builder;
  builder.Append("<style> body { height: 1000px; margin: 0; }</style>");
  builder.Append("<div style='height:100px'>foobar</div>");
  builder.Append("<");
  for (int i = 0; i <= kMaxSerializedSelectorLength; i++) {
    builder.Append("a");
  }
  builder.Append(" style='display:block; height:100px;'/>");
  SetBodyInnerHTML(builder.ToString());

  ScrollLayoutViewport(ScrollOffset(0, 150));
  SerializedAnchor serialized =
      GetScrollAnchor(LayoutViewport()).GetSerializedAnchor();
  EXPECT_FALSE(serialized.IsValid());
}

TEST_F(ScrollAnchorTest, SerializeAnchorIgnoresDuplicatedId) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        span { display: block; height: 100px; }
      </style>
      <div id='ancestor'>
      </div>
      <div id='ancestor'>
        <span class='foobar'>abc</span>
        <span class='barbaz'>def</span>
      </div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 150));
  ValidateSerializedAnchor("html>body>:nth-child(3)>.barbaz",
                           LogicalOffset(0, -50));
}

TEST_F(ScrollAnchorTest, SerializeAnchorFailsForPseudoElement) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        div { height: 100px }
        div:after { content: "foobar"; display: block; margin-top: 50px; }
      </style>
      <div>abc</div>
      <div id='block1'>def</div>)HTML");

  ScrollLayoutViewport(ScrollOffset(0, 50));
  EXPECT_FALSE(GetScrollAnchor(LayoutViewport()).AnchorObject());
}

TEST_F(ScrollAnchorTest, SerializeAnchorFailsForShadowDOMElement) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 5000px; margin: 0; }
        div { height: 200px; }
      </style>
      <div id='host'></div>
      <div></div>
      <div></div>)HTML");
  auto* host = GetDocument().getElementById(AtomicString("host"));
  auto& shadow_root = host->AttachShadowRootForTesting(ShadowRootMode::kOpen);
  shadow_root.setInnerHTML(R"HTML(
      <style>
        div { height: 100px; }
      </style>
      <div></div>)HTML");
  Update();

  ScrollLayoutViewport(ScrollOffset(0, 50));

  SerializedAnchor serialized =
      GetScrollAnchor(LayoutViewport()).GetSerializedAnchor();
  EXPECT_FALSE(serialized.IsValid());

  LayoutObject* anchor_object =
      GetScrollAnchor(LayoutViewport()).AnchorObject();
  EXPECT_TRUE(anchor_object->GetNode()->IsInShadowTree());
}

TEST_F(ScrollAnchorTest, RestoreAnchorSimple) {
  SetBodyInnerHTML(
      "<style> body { height: 1000px; margin: 0; } div { height: 100px } "
      "</style>"
      "<div id='block1'>abc</div>"
      "<div id='block2'>def</div>");

  EXPECT_FALSE(GetScrollAnchor(LayoutViewport()).AnchorObject());

  SerializedAnchor serialized_anchor("#block2", LogicalOffset(0, 0));

  EXPECT_TRUE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 100);

  SetHeight(GetDocument().getElementById(AtomicString("block1")), 200);
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 200);

  SetHeight(GetDocument().getElementById(AtomicString("block1")), 50);
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 50);
}

TEST_F(ScrollAnchorTest, RestoreAnchorNonTrivialSelector) {
  SetBodyInnerHTML(R"HTML(
      <style>
        body { height: 1000px; margin: 0; }
        div.hundred { height: 100px; }
        div.thousand { height: 1000px; }
      </style>
      <div id='block1' class='hundred'>abc</div>
      <div id='ancestor' class='thousand'>
       <div class='hundred'>abc</div>
       <div class='hundred'>def</div>
       <div class='hundred'>
         <div class='hundred foobar'>
           <div class='hundred'>ghi</div>
         </div>
       <div class='hundred barbaz'></div>
      </div>)HTML");

  SerializedAnchor serialized_anchor("#ancestor>:nth-child(3)>.foobar>div",
                                     LogicalOffset(0, -50));

  EXPECT_TRUE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));

  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 350);

  SetHeight(GetDocument().getElementById(AtomicString("block1")), 200);
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 450);
}

TEST_F(ScrollAnchorTest, RestoreAnchorFailsForInvalidSelectors) {
  SetBodyInnerHTML(
      "<style> body { height: 1000px; margin: 0; } div { height: 100px } "
      "</style>"
      "<div id='block1'>abc</div>"
      "<div id='block2'>def</div>");

  EXPECT_FALSE(GetScrollAnchor(LayoutViewport()).AnchorObject());

  SerializedAnchor serialized_anchor("article", LogicalOffset(0, 0));

  EXPECT_FALSE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));

  SerializedAnchor serialized_anchor_2("", LogicalOffset(0, 0));

  EXPECT_FALSE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor_2));

  SerializedAnchor serialized_anchor_3("foobar", LogicalOffset(0, 0));

  EXPECT_FALSE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor_3));
}

// Ensure that when the serialized selector refers to a non-box, non-text
// element(meaning its corresponding LayoutObject can't be the anchor object)
// that restoration will still succeed.
TEST_F(ScrollAnchorTest, RestoreAnchorSucceedsForNonBoxNonTextElement) {
  SetBodyInnerHTML(
      "<style> body { height: 1000px; margin: 0; } div { height: 100px } "
      "</style>"
      "<div id='block1'>abc</div>"
      "<code>some code</code>");

  EXPECT_FALSE(GetScrollAnchor(LayoutViewport()).AnchorObject());

  SerializedAnchor serialized_anchor("html>body>code", LogicalOffset(0, 0));

  EXPECT_TRUE(
      GetScrollAnchor(LayoutViewport()).RestoreAnchor(serialized_anchor));

  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 100);

  SetHeight(GetDocument().getElementById(AtomicString("block1")), 200);
  EXPECT_EQ(LayoutViewport()->ScrollOffsetInt().y(), 200);

  GetScrollAnchor(LayoutViewport()).GetSerializedAnchor();
  ValidateSerializedAnchor("html>body>code", LogicalOffset(0, 0));
}

TEST_F(ScrollAnchorTest, RestoreAnchorSucceedsWhenScriptForbidden) {
  SetBodyInnerHTML(
      "<style> body { height: 1000px; margin: 0; } div { height: 100px } "
      "</style>"
      "<div id='block1'>abc</div>"
      "<div id='block2'>def</div>");

  EXPECT_FALSE(GetScrollAnchor(LayoutViewport()).AnchorObject());

  SerializedAnchor serialized_anchor("#block2", LogicalOffset(0, 0));

  ScriptForbiddenScope scope;
  EXPECT_TRUE(
    
"""


```