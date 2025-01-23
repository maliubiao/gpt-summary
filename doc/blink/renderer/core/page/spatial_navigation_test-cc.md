Response:
The user wants to understand the functionality of the `spatial_navigation_test.cc` file in the Chromium Blink engine. This file is a unit test file. I need to:

1. **Identify the purpose of the tests:** The file name suggests it tests the spatial navigation functionality.
2. **Explain spatial navigation:** Briefly describe what spatial navigation is in the context of web browsers.
3. **Relate to web technologies:** Explain how spatial navigation interacts with HTML, CSS, and JavaScript.
4. **Provide examples:**  Give concrete examples of test cases and what they verify.
5. **Illustrate with hypothetical inputs and outputs:**  Demonstrate how specific test inputs lead to expected outcomes.
6. **Discuss potential user/developer errors:** Explain common mistakes related to spatial navigation.
7. **Outline the user journey to reach this code:** Describe the steps a developer might take to investigate this file.
8. **Summarize the functionality:** Concisely state the main purpose of the file.
好的，这是您提供的 Chromium Blink 引擎源代码文件 `blink/renderer/core/page/spatial_navigation_test.cc` 的功能分析：

**功能归纳：**

这个 C++ 文件 `spatial_navigation_test.cc` 的主要功能是**测试 Blink 引擎中空间导航（Spatial Navigation）功能的正确性**。它通过编写一系列单元测试用例，模拟各种场景，验证空间导航在不同布局、元素状态和用户操作下的行为是否符合预期。

**详细功能列举：**

1. **测试空间导航的核心逻辑：** 文件中定义了多个以 `TEST_F` 开头的测试函数，每个函数都针对空间导航的特定方面进行测试，例如：
    * 计算搜索起始位置 (`SearchOrigin`) 的逻辑。
    * 判断元素是否在可视区域内 (`IsOffscreen`) 的逻辑。
    * 查找元素的滚动容器 (`ScrollableAreaOrDocumentOf`) 的逻辑。
    * 处理不同类型的元素（如链接、按钮、iframe、可滚动容器）时的行为。
    * 处理视口缩放和滚动的情况。
    * 处理行内元素和多行文本的情况。
    * 处理元素被裁剪的情况。

2. **模拟浏览器环境：**  该文件使用了 `RenderingTest` 基类，这表示它运行在一个模拟的渲染环境中，可以方便地创建和操作 DOM 结构，设置样式，模拟用户交互等。

3. **使用断言进行验证：** 每个测试用例都使用了 `EXPECT_EQ`、`EXPECT_TRUE`、`EXPECT_FALSE`、`EXPECT_LT` 等 GTest 提供的断言宏，来验证实际的计算结果或状态是否与预期一致。

4. **覆盖多种场景：** 测试用例覆盖了各种复杂的布局情况，例如：
    * 元素位于 iframe 中。
    * 元素位于可滚动的 overflow 容器中。
    * 元素被其他元素裁剪。
    * 元素部分可见或完全不可见。
    * 视口被缩放或滚动。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

空间导航是一种浏览器特性，允许用户使用键盘上的方向键（通常是 Tab 键结合 Shift 键或者专门的方向键）在网页上的可聚焦元素之间进行导航。  `spatial_navigation_test.cc` 文件测试的就是 Blink 引擎如何根据 HTML 结构、CSS 样式和 JavaScript 可能产生的影响来决定下一个焦点元素。

* **HTML:**  HTML 结构定义了网页上的元素及其层级关系，空间导航需要理解这种结构来确定哪些元素是可聚焦的，以及它们之间的相对位置。
    * **例子:**  测试用例中通过 `SetBodyInnerHTML` 设置 HTML 内容，例如 `<a id='child'>link</a>`，测试空间导航是否能正确识别这个链接元素。

* **CSS:** CSS 样式影响元素的位置、大小、是否可见以及是否可以滚动。空间导航需要考虑这些样式信息来计算元素的位置和可见性，从而确定导航的目标。
    * **例子:**  测试用例中通过 `<style>` 标签设置 CSS 样式，例如设置 `iframe` 的宽高和 `overflow` 属性，测试空间导航在 iframe 或可滚动容器中的行为。

* **JavaScript:** JavaScript 可以动态地修改 DOM 结构和 CSS 样式，也可能会通过编程方式设置焦点。空间导航需要在这些动态变化后仍然能够正常工作。虽然这个测试文件本身没有直接执行 JavaScript 代码，但它测试的逻辑会受到 JavaScript 对 DOM 和样式的修改的影响。
    * **例子:**  虽然没有直接的 JavaScript 代码，但测试用例模拟了焦点元素在不同位置的情况，这可能是在 JavaScript 的影响下发生的。

**逻辑推理、假设输入与输出举例：**

**假设输入：**

```html
<!DOCTYPE html>
<div style='width: 100px; height: 100px; overflow: auto;'>
  <button id='top' style='margin-bottom: 150px;'>Top</button>
  <button id='bottom'>Bottom</button>
</div>
```

**测试用例目标：**  测试当焦点在 `#top` 按钮时，按下向下方向键，空间导航是否能正确将焦点移动到 `#bottom` 按钮。

**逻辑推理：**

1. `#top` 按钮在 `#bottom` 按钮的上方。
2. 容器设置了 `overflow: auto`，意味着内容超出时会出现滚动条。
3. 由于 `#top` 的 `margin-bottom`，`#bottom` 在容器的视口下方，需要向下滚动才能看到。
4. 空间导航的向下搜索应该考虑到这种滚动情况，并找到在垂直方向上最接近且在下方的可聚焦元素。

**预期输出（部分）：**

```c++
  // ... 设置 HTML 并获取元素 ...
  GetDocument()->getElementById(AtomicString("top"))->focus(); // 假设焦点在 top 按钮

  // 模拟按下向下方向键
  WebKeyboardEvent event;
  event.windowsKeyCode = ui::VKEY_DOWN;
  event.type = WebInputEvent::Type::kKeyDown;
  GetFrame().GetEventHandler().HandleKeyEvent(event);

  // 验证焦点是否移动到了 bottom 按钮
  EXPECT_EQ(GetDocument()->focusedElement()->GetIdAttribute(), "bottom");
```

**用户或编程常见的使用错误举例：**

1. **错误地假设绝对定位元素会影响空间导航顺序：**  开发者可能会认为使用 `position: absolute` 的元素会脱离文档流，从而影响空间导航的顺序。然而，空间导航仍然会考虑这些元素在视觉上的位置。

2. **忘记考虑 `tabindex` 属性：**  `tabindex` 属性可以显式地指定元素的 Tab 键遍历顺序。开发者可能会忽略这个属性，导致空间导航的顺序与预期不符。例如，设置了 `tabindex="-1"` 的元素将不会被 Tab 键选中，但可能仍然可以通过空间导航的方向键到达。

3. **在 JavaScript 中过度干预焦点管理：**  开发者可能会使用 JavaScript 监听键盘事件并手动设置焦点，这可能会与浏览器的默认空间导航行为冲突，导致用户体验混乱。

**用户操作如何一步步到达这里（作为调试线索）：**

假设开发者遇到了一个与空间导航相关的 Bug，例如用户在特定网页上使用方向键导航时，焦点跳转到了错误的位置。为了调试这个问题，开发者可能会按照以下步骤操作：

1. **复现 Bug：** 在浏览器中访问出现问题的网页，并尝试重现导航错误的步骤。
2. **定位相关代码：** 根据 Bug 的表现，推测问题可能出在 Blink 引擎的空间导航模块。
3. **查找空间导航相关文件：** 在 Blink 源代码目录中搜索与 "spatial navigation" 相关的代码文件，例如 `blink/renderer/core/page/spatial_navigation.cc` 和 `blink/renderer/core/page/spatial_navigation_controller.cc`。
4. **查看测试文件：** 为了理解空间导航的实现原理和已有的测试覆盖范围，开发者会查看相关的测试文件，例如您提供的 `blink/renderer/core/page/spatial_navigation_test.cc`。
5. **分析测试用例：**  开发者会仔细阅读测试用例，了解各种场景下空间导航的预期行为。
6. **运行测试：** 开发者可能会运行这些测试用例，确保现有的功能是正常的。
7. **修改代码并添加新的测试：** 如果发现 Bug，开发者会修改空间导航的实现代码，并添加新的测试用例来覆盖导致 Bug 的场景，确保修复的正确性。

**总结（针对第 1 部分）：**

`blink/renderer/core/page/spatial_navigation_test.cc` 的第 1 部分主要集中在测试空间导航中**确定搜索起始位置 (`SearchOrigin`)** 以及**判断元素是否在屏幕上 (`IsOffscreen`)** 的核心逻辑。它包含了大量的测试用例，覆盖了各种元素类型、布局情况和视口状态，为理解和验证 Blink 引擎的空间导航机制提供了重要的依据。 这些测试用例使用了各种 HTML 和 CSS 构造来模拟不同的网页场景。

### 提示词
```
这是目录为blink/renderer/core/page/spatial_navigation_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/spatial_navigation.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/renderer/core/frame/frame_test_helpers.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/frame/web_remote_frame_impl.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"
#include "third_party/blink/renderer/core/testing/sim/sim_request.h"
#include "third_party/blink/renderer/core/testing/sim/sim_test.h"
#include "third_party/blink/renderer/platform/testing/url_test_helpers.h"
#include "ui/events/keycodes/dom/dom_key.h"

namespace blink {

class SpatialNavigationTest : public RenderingTest {
 public:
  SpatialNavigationTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

  void SetUp() override {
    RenderingTest::SetUp();
    GetDocument().GetSettings()->SetSpatialNavigationEnabled(true);
  }

  PhysicalRect TopOfVisualViewport() {
    PhysicalRect visual_viewport = RootViewport(&GetFrame());
    visual_viewport.SetY(visual_viewport.Y() - 1);
    visual_viewport.SetHeight(LayoutUnit(0));
    return visual_viewport;
  }

  PhysicalRect BottomOfVisualViewport() {
    PhysicalRect visual_viewport = RootViewport(&GetFrame());
    visual_viewport.SetY(visual_viewport.Bottom() + 1);
    visual_viewport.SetHeight(LayoutUnit(0));
    return visual_viewport;
  }

  PhysicalRect LeftSideOfVisualViewport() {
    PhysicalRect visual_viewport = RootViewport(&GetFrame());
    visual_viewport.SetX(visual_viewport.X() - 1);
    visual_viewport.SetWidth(LayoutUnit(0));
    return visual_viewport;
  }

  PhysicalRect RightSideOfVisualViewport() {
    PhysicalRect visual_viewport = RootViewport(&GetFrame());
    visual_viewport.SetX(visual_viewport.Right() + 1);
    visual_viewport.SetWidth(LayoutUnit(0));
    return visual_viewport;
  }

  void AssertUseSidesOfVisualViewport(Node* focus_node) {
    EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), focus_node,
                           SpatialNavigationDirection::kUp),
              BottomOfVisualViewport());
    EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), focus_node,
                           SpatialNavigationDirection::kDown),
              TopOfVisualViewport());
    EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), focus_node,
                           SpatialNavigationDirection::kLeft),
              RightSideOfVisualViewport());
    EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), focus_node,
                           SpatialNavigationDirection::kRight),
              LeftSideOfVisualViewport());
  }

  void AssertNormalizedHeight(Element* e, int line_height, bool will_shrink) {
    PhysicalRect search_origin =
        SearchOrigin(RootViewport(e->GetDocument().GetFrame()), e,
                     SpatialNavigationDirection::kDown);
    PhysicalRect uncropped = NodeRectInRootFrame(e);

    // SearchOrigin uses the normalized height.
    // If |e| is line broken, SearchOrigin should only use the first line.
    PhysicalRect normalized =
        ShrinkInlineBoxToLineBox(*e->GetLayoutObject(), uncropped);
    EXPECT_EQ(search_origin, normalized);
    if (will_shrink) {
      EXPECT_LT(search_origin.Height(), uncropped.Height());
      EXPECT_EQ(search_origin.Height(), line_height);
      EXPECT_EQ(search_origin.X(), uncropped.X());
      EXPECT_EQ(search_origin.Y(), uncropped.Y());
      EXPECT_EQ(search_origin.Width(), uncropped.Width());
    } else {
      EXPECT_EQ(search_origin, uncropped);
    }

    // Focus candidates will also use normalized heights.
    // If |e| is line broken, the rect should still include all lines.
    normalized = ShrinkInlineBoxToLineBox(*e->GetLayoutObject(), uncropped,
                                          LineBoxes(*e->GetLayoutObject()));
    FocusCandidate candidate(e, SpatialNavigationDirection::kDown);
    EXPECT_EQ(normalized, candidate.rect_in_root_frame);
  }

  bool HasSameSearchOriginRectAndCandidateRect(Element* a) {
    PhysicalRect a_origin =
        SearchOrigin(RootViewport(a->GetDocument().GetFrame()), a,
                     SpatialNavigationDirection::kDown);
    FocusCandidate a_candidate(a, SpatialNavigationDirection::kDown);
    return a_candidate.rect_in_root_frame == a_origin;
  }

  bool Intersects(Element* a, Element* b) {
    PhysicalRect a_origin =
        SearchOrigin(RootViewport(a->GetDocument().GetFrame()), a,
                     SpatialNavigationDirection::kDown);
    PhysicalRect b_origin =
        SearchOrigin(RootViewport(b->GetDocument().GetFrame()), b,
                     SpatialNavigationDirection::kDown);

    return a_origin.Intersects(b_origin);
  }
};

TEST_F(SpatialNavigationTest, RootFramesVisualViewport) {
  // Test RootViewport with a pinched viewport.
  VisualViewport& visual_viewport = GetFrame().GetPage()->GetVisualViewport();
  visual_viewport.SetScale(2);
  visual_viewport.SetLocation(gfx::PointF(200, 200));

  LocalFrameView* root_frame_view = GetFrame().LocalFrameRoot().View();
  const PhysicalRect roots_visible_doc_rect(
      root_frame_view->GetScrollableArea()->VisibleContentRect());
  // Convert the root frame's visible rect from document space -> frame space.
  // For the root frame, frame space == root frame space, obviously.
  PhysicalRect viewport_rect_of_root_frame =
      root_frame_view->DocumentToFrame(roots_visible_doc_rect);

  EXPECT_EQ(viewport_rect_of_root_frame, RootViewport(&GetFrame()));
}

TEST_F(SpatialNavigationTest, FindContainerWhenEnclosingContainerIsDocument) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<a id='child'>link</a>");

  Element* child_element = GetDocument().getElementById(AtomicString("child"));
  Node* enclosing_container = ScrollableAreaOrDocumentOf(child_element);

  EXPECT_EQ(enclosing_container, GetDocument());
  EXPECT_TRUE(IsScrollableAreaOrDocument(enclosing_container));
}

TEST_F(SpatialNavigationTest, FindContainerWhenEnclosingContainerIsIframe) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  iframe {"
      "    width: 100px;"
      "    height: 100px;"
      "  }"
      "</style>"
      "<iframe id='iframe'></iframe>");

  SetChildFrameHTML(
      "<!DOCTYPE html>"
      "<a>link</a>");

  UpdateAllLifecyclePhasesForTest();
  Element* iframe = GetDocument().QuerySelector(AtomicString("iframe"));
  Element* link = ChildDocument().QuerySelector(AtomicString("a"));
  Node* enclosing_container = ScrollableAreaOrDocumentOf(link);

  EXPECT_FALSE(IsOffscreen(iframe));
  EXPECT_FALSE(IsOffscreen(&ChildDocument()));
  EXPECT_FALSE(IsOffscreen(link));

  EXPECT_EQ(enclosing_container, ChildDocument());
  EXPECT_TRUE(IsScrollableAreaOrDocument(enclosing_container));
}

TEST_F(SpatialNavigationTest,
       FindContainerWhenEnclosingContainerIsScrollableOverflowBox) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  #content {"
      "    margin-top: 200px;"  // Outside the div's viewport.
      "  }"
      "  #container {"
      "    height: 100px;"
      "    overflow: scroll;"
      "  }"
      "</style>"
      "<div id='container'>"
      "  <div id='content'>some text here</div>"
      "</div>");

  Element* content = GetDocument().getElementById(AtomicString("content"));
  Element* container = GetDocument().getElementById(AtomicString("container"));
  Node* enclosing_container = ScrollableAreaOrDocumentOf(content);

  // TODO(crbug.com/889840):
  // VisibleBoundsInLocalRoot does not (yet) take div-clipping into
  // account. The node is off screen, but nevertheless VBIVV returns a non-
  // empty rect. If you fix VisibleBoundsInLocalRoot, change to
  // EXPECT_TRUE here and stop using LayoutObject in IsOffscreen().
  EXPECT_FALSE(content->VisibleBoundsInLocalRoot().IsEmpty());  // EXPECT_TRUE.

  EXPECT_TRUE(IsOffscreen(content));
  EXPECT_FALSE(IsOffscreen(container));

  EXPECT_EQ(enclosing_container, container);
  EXPECT_TRUE(IsScrollableAreaOrDocument(enclosing_container));
}

TEST_F(SpatialNavigationTest, ZooomPutsElementOffScreen) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<button id='a'>hello</button><br>"
      "<button id='b' style='margin-top: 70%'>bello</button>");

  Element* a = GetDocument().getElementById(AtomicString("a"));
  Element* b = GetDocument().getElementById(AtomicString("b"));
  EXPECT_FALSE(IsOffscreen(a));
  EXPECT_FALSE(IsOffscreen(b));

  // Now, test IsOffscreen with a pinched viewport.
  VisualViewport& visual_viewport = GetFrame().GetPage()->GetVisualViewport();
  visual_viewport.SetScale(2);
  // #b is no longer visible.
  EXPECT_FALSE(IsOffscreen(a));
  EXPECT_TRUE(IsOffscreen(b));
}

TEST_F(SpatialNavigationTest, RootViewportRespectsVisibleSize) {
  EXPECT_EQ(RootViewport(&GetFrame()), PhysicalRect(0, 0, 800, 600));

  VisualViewport& visual_viewport = GetFrame().GetPage()->GetVisualViewport();
  visual_viewport.SetSize({123, 123});
  EXPECT_EQ(RootViewport(&GetFrame()), PhysicalRect(0, 0, 123, 123));
}

TEST_F(SpatialNavigationTest, StartAtVisibleFocusedElement) {
  SetBodyInnerHTML("<button id='b'>hello</button>");
  Element* b = GetDocument().getElementById(AtomicString("b"));

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kDown),
            NodeRectInRootFrame(b));
}

TEST_F(SpatialNavigationTest, StartAtVisibleFocusedScroller) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  #content {"
      "    margin-top: 200px;"  // Outside the div's viewport.
      "  }"
      "  #scroller {"
      "    height: 100px;"
      "    overflow: scroll;"
      "  }"
      "</style>"
      "<div id='scroller'>"
      "  <div id='content'>some text here</div>"
      "</div>");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), scroller,
                         SpatialNavigationDirection::kDown),
            NodeRectInRootFrame(scroller));
}

TEST_F(SpatialNavigationTest, StartAtVisibleFocusedIframe) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  iframe {"
      "    width: 100px;"
      "    height: 100px;"
      "  }"
      "</style>"
      "<iframe id='iframe'></iframe>");

  SetChildFrameHTML(
      "<!DOCTYPE html>"
      "<div>some text here</div>");

  Element* iframe = GetDocument().getElementById(AtomicString("iframe"));
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), iframe,
                         SpatialNavigationDirection::kDown),
            NodeRectInRootFrame(iframe));
}

TEST_F(SpatialNavigationTest, StartAtTopWhenGoingDownwardsWithoutFocus) {
  EXPECT_EQ(PhysicalRect(0, -1, 111, 0),
            SearchOrigin({0, 0, 111, 222}, nullptr,
                         SpatialNavigationDirection::kDown));

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), nullptr,
                         SpatialNavigationDirection::kDown),
            TopOfVisualViewport());
}

TEST_F(SpatialNavigationTest, StartAtBottomWhenGoingUpwardsWithoutFocus) {
  EXPECT_EQ(
      PhysicalRect(0, 222 + 1, 111, 0),
      SearchOrigin({0, 0, 111, 222}, nullptr, SpatialNavigationDirection::kUp));

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), nullptr,
                         SpatialNavigationDirection::kUp),
            BottomOfVisualViewport());
}

TEST_F(SpatialNavigationTest, StartAtLeftSideWhenGoingEastWithoutFocus) {
  EXPECT_EQ(PhysicalRect(-1, 0, 0, 222),
            SearchOrigin({0, 0, 111, 222}, nullptr,
                         SpatialNavigationDirection::kRight));

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), nullptr,
                         SpatialNavigationDirection::kRight),
            LeftSideOfVisualViewport());
}

TEST_F(SpatialNavigationTest, StartAtRightSideWhenGoingWestWithoutFocus) {
  EXPECT_EQ(PhysicalRect(111 + 1, 0, 0, 222),
            SearchOrigin({0, 0, 111, 222}, nullptr,
                         SpatialNavigationDirection::kLeft));

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), nullptr,
                         SpatialNavigationDirection::kLeft),
            RightSideOfVisualViewport());
}

TEST_F(SpatialNavigationTest,
       StartAtBottomWhenGoingUpwardsAndFocusIsOffscreen) {
  SetBodyInnerHTML(
      "<button id='b' style='margin-top: 120%;'>B</button>");  // Outside the
                                                               // visual
                                                               // viewport.
  Element* b = GetDocument().getElementById(AtomicString("b"));
  EXPECT_TRUE(IsOffscreen(b));

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kUp),
            BottomOfVisualViewport());
}

TEST_F(SpatialNavigationTest, StartAtContainersEdge) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  div {"
      "    height: 100px;"
      "    width: 100px;"
      "    overflow: scroll;"
      "  }"
      "  button {"
      "    margin-top: 200px;"  // Outside the div's viewport.
      "  }"
      "</style>"
      "<div id='container'>"
      "  <button id='b'>B</button>"
      "</div>");

  Element* b = GetDocument().getElementById(AtomicString("b"));
  const Element* container =
      GetDocument().getElementById(AtomicString("container"));
  const PhysicalRect container_box = NodeRectInRootFrame(container);

  // TODO(crbug.com/889840):
  // VisibleBoundsInLocalRoot does not (yet) take div-clipping into
  // account. The node is off screen, but nevertheless VBIVV returns a non-
  // empty rect. If you fix VisibleBoundsInLocalRoot, change to
  // EXPECT_TRUE here and stop using LayoutObject in IsOffscreen().
  EXPECT_FALSE(b->VisibleBoundsInLocalRoot().IsEmpty());  // EXPECT_TRUE.
  EXPECT_TRUE(IsOffscreen(b));

  // Go down.
  PhysicalRect container_top_edge = container_box;
  container_top_edge.SetHeight(LayoutUnit(0));
  container_top_edge.SetY(container_top_edge.Y() - 1);
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kDown),
            container_top_edge);

  // Go up.
  PhysicalRect container_bottom_edge = container_box;
  container_bottom_edge.SetHeight(LayoutUnit(0));
  container_bottom_edge.SetY(container_bottom_edge.Right() + 1);
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kUp),
            container_bottom_edge);

  // Go right.
  PhysicalRect container_leftmost_edge = container_box;
  container_leftmost_edge.SetWidth(LayoutUnit(0));
  container_leftmost_edge.SetX(container_leftmost_edge.X() - 1);
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kRight),
            container_leftmost_edge);

  // Go left.
  PhysicalRect container_rightmost_edge = container_box;
  container_rightmost_edge.SetX(container_bottom_edge.Right() + 1);
  container_rightmost_edge.SetWidth(LayoutUnit(0));
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kLeft),
            container_rightmost_edge);
}

TEST_F(SpatialNavigationTest,
       StartFromDocEdgeWhenFocusIsClippedInOffscreenScroller) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  div {"
      "    margin-top: 120%;"  // Outside the visual viewport.
      "    height: 100px;"
      "    width: 100px;"
      "    overflow: scroll;"
      "  }"
      "  button {"
      "    margin-top: 300px;"  // Outside the div's scrollport.
      "  }"
      "</style>"
      "<div id='scroller'>"
      "  <button id='b'>B</button>"
      "</div>");

  Element* scroller = GetDocument().getElementById(AtomicString("scroller"));
  Element* b = GetDocument().getElementById(AtomicString("b"));

  EXPECT_TRUE(IsOffscreen(scroller));
  EXPECT_TRUE(IsOffscreen(b));

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kUp),
            BottomOfVisualViewport());
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kDown),
            TopOfVisualViewport());
}

TEST_F(SpatialNavigationTest,
       StartFromDocEdgeWhenFocusIsClippedInNestedOffscreenScroller) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  div {"
      "   margin-top: 120%;"  // Outside the visual viewport.
      "   height: 100px;"
      "   width: 100px;"
      "   overflow: scroll;"
      "}"
      "a {"
      "  display: block;"
      "  margin-top: 300px;"
      "}"
      "</style>"
      "<div id='scroller1'>"
      "  <div id='scroller2'>"
      "    <a id='link'>link</a>"
      "  </div>"
      "</div>");

  Element* scroller1 = GetDocument().getElementById(AtomicString("scroller1"));
  Element* scroller2 = GetDocument().getElementById(AtomicString("scroller2"));
  Element* link = GetDocument().getElementById(AtomicString("link"));

  EXPECT_TRUE(IsScrollableAreaOrDocument(scroller1));
  EXPECT_TRUE(IsScrollableAreaOrDocument(scroller2));
  EXPECT_TRUE(IsOffscreen(scroller1));
  EXPECT_TRUE(IsOffscreen(scroller1));
  EXPECT_TRUE(IsOffscreen(link));

  AssertUseSidesOfVisualViewport(link);
}

TEST_F(SpatialNavigationTest, PartiallyVisible) {
  // <button>'s bottom is clipped.
  SetBodyInnerHTML("<button id='b' style='height: 900px;'>B</button>");
  Element* b = GetDocument().getElementById(AtomicString("b"));

  EXPECT_FALSE(IsOffscreen(b));  // <button> is not completely offscreen.

  PhysicalRect button_in_root_frame = NodeRectInRootFrame(b);

  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kUp),
            Intersection(button_in_root_frame, RootViewport(&GetFrame())));

  // Do some scrolling.
  ScrollableArea* root_scroller = GetDocument().View()->GetScrollableArea();
  root_scroller->SetScrollOffset(ScrollOffset(0, 600),
                                 mojom::blink::ScrollType::kProgrammatic);
  PhysicalRect button_after_scroll = NodeRectInRootFrame(b);
  ASSERT_NE(button_in_root_frame,
            button_after_scroll);  // As we scrolled, the
                                   // <button>'s position in
                                   // the root frame changed.

  // <button>'s top is clipped.
  EXPECT_FALSE(IsOffscreen(b));  // <button> is not completely offscreen.
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), b,
                         SpatialNavigationDirection::kUp),
            Intersection(button_after_scroll, RootViewport(&GetFrame())));
}

TEST_F(SpatialNavigationTest,
       StartFromDocEdgeWhenOffscreenIframeDisplaysFocus) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  iframe {"
      "    margin-top: 120%;"  // Outside the visual viewport.
      "    height: 100px;"
      "    width: 100px;"
      "  }"
      "</style>"
      "<iframe id='iframe'></iframe>");

  SetChildFrameHTML(
      "<!DOCTYPE html>"
      "<a id='link'>link</a>");

  UpdateAllLifecyclePhasesForTest();
  Element* link = ChildDocument().QuerySelector(AtomicString("a"));
  Element* iframe = GetDocument().QuerySelector(AtomicString("iframe"));

  // The <iframe> is not displayed in the visual viewport. In other words, it is
  // being offscreen. And so is also its content, the <a>.
  EXPECT_TRUE(IsOffscreen(iframe));
  EXPECT_TRUE(IsOffscreen(&ChildDocument()));
  EXPECT_TRUE(IsOffscreen(link));

  AssertUseSidesOfVisualViewport(link);
}

TEST_F(SpatialNavigationTest, DivsCanClipIframes) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  div {"
      "    height: 100px;"
      "    width: 100px;"
      "    overflow: scroll;"
      "  }"
      "  iframe {"
      "    margin-top: 200px;"  // Outside the div's viewport.
      "    height: 50px;"
      "    width: 50px;"
      "  }"
      "</style>"
      "<div>"
      "  <iframe id='iframe'></iframe>"
      "</div>");

  SetChildFrameHTML(
      "<!DOCTYPE html>"
      "<a>link</a>");

  UpdateAllLifecyclePhasesForTest();
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Element* iframe = GetDocument().QuerySelector(AtomicString("iframe"));
  Element* link = ChildDocument().QuerySelector(AtomicString("a"));
  EXPECT_FALSE(IsOffscreen(div));

  // TODO(crbug.com/889840):
  // VisibleBoundsInLocalRoot does not (yet) take div-clipping into
  // account. The node is off screen, but nevertheless VBIVV returns a non-
  // empty rect. If you fix VisibleBoundsInLocalRoot, change to
  // EXPECT_TRUE here and stop using LayoutObject in IsOffscreen().
  EXPECT_FALSE(iframe->VisibleBoundsInLocalRoot().IsEmpty());  // EXPECT_TRUE.

  // The <iframe> is not displayed in the visual viewport because it is clipped
  // by the div. In other words, it is being offscreen. And so is also its
  // content, the <a>.
  EXPECT_TRUE(IsOffscreen(iframe));
  EXPECT_TRUE(IsOffscreen(&ChildDocument()));
  EXPECT_TRUE(IsOffscreen(link));
}

TEST_F(SpatialNavigationTest, PartiallyVisibleIFrame) {
  // <a> is off screen. The <iframe> is visible, but partially off screen.
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  iframe {"
      "    width: 200%;"
      "    height: 100px;"
      "  }"
      "</style>"
      "<iframe id='iframe'></iframe>");

  SetChildFrameHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  #child {"
      "    margin-left: 120%;"
      "  }"
      "</style>"
      "<a id='child'>link</a>");

  UpdateAllLifecyclePhasesForTest();
  Element* child_element =
      ChildDocument().getElementById(AtomicString("child"));
  Node* enclosing_container = ScrollableAreaOrDocumentOf(child_element);
  EXPECT_EQ(enclosing_container, ChildDocument());

  EXPECT_TRUE(IsOffscreen(child_element));         // Completely offscreen.
  EXPECT_FALSE(IsOffscreen(enclosing_container));  // Partially visible.

  PhysicalRect iframe = NodeRectInRootFrame(enclosing_container);

  // When searching downwards we start at activeElement's
  // container's (here: the iframe's) topmost visible edge.
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), child_element,
                         SpatialNavigationDirection::kDown),
            OppositeEdge(SpatialNavigationDirection::kDown,
                         Intersection(iframe, RootViewport(&GetFrame()))));

  // When searching upwards we start at activeElement's
  // container's (here: the iframe's) bottommost visible edge.
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), child_element,
                         SpatialNavigationDirection::kUp),
            OppositeEdge(SpatialNavigationDirection::kUp,
                         Intersection(iframe, RootViewport(&GetFrame()))));

  // When searching eastwards, "to the right", we start at activeElement's
  // container's (here: the iframe's) leftmost visible edge.
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), child_element,
                         SpatialNavigationDirection::kRight),
            OppositeEdge(SpatialNavigationDirection::kRight,
                         Intersection(iframe, RootViewport(&GetFrame()))));

  // When searching westwards, "to the left", we start at activeElement's
  // container's (here: the iframe's) rightmost visible edge.
  EXPECT_EQ(SearchOrigin(RootViewport(&GetFrame()), child_element,
                         SpatialNavigationDirection::kLeft),
            OppositeEdge(SpatialNavigationDirection::kLeft,
                         Intersection(iframe, RootViewport(&GetFrame()))));
}

TEST_F(SpatialNavigationTest, BottomOfPinchedViewport) {
  PhysicalRect origin = SearchOrigin(RootViewport(&GetFrame()), nullptr,
                                     SpatialNavigationDirection::kUp);
  EXPECT_EQ(origin.Height(), 0);
  EXPECT_EQ(origin.Width(), GetFrame().View()->Width());
  EXPECT_EQ(origin.X(), 0);
  EXPECT_EQ(origin.Y(), GetFrame().View()->Height() + 1);
  EXPECT_EQ(origin, BottomOfVisualViewport());

  // Now, test SearchOrigin with a pinched viewport.
  VisualViewport& visual_viewport = GetFrame().GetPage()->GetVisualViewport();
  visual_viewport.SetScale(2);
  visual_viewport.SetLocation(gfx::PointF(200, 200));
  origin = SearchOrigin(RootViewport(&GetFrame()), nullptr,
                        SpatialNavigationDirection::kUp);
  EXPECT_EQ(origin.Height(), 0);
  EXPECT_LT(origin.Width(), GetFrame().View()->Width());
  EXPECT_GT(origin.X(), 0);
  EXPECT_LT(origin.Y(), GetFrame().View()->Height() + 1);
  EXPECT_EQ(origin, BottomOfVisualViewport());
}

TEST_F(SpatialNavigationTest, StraightTextNoFragments) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  body {font: 10px/10px Ahem; width: 500px}"
      "</style>"
      "<a href='#' id='a'>blaaaaa blaaaaa blaaaaa</a>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  EXPECT_FALSE(IsFragmentedInline(*a->GetLayoutObject()));
}

TEST_F(SpatialNavigationTest, LineBrokenTextHasFragments) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  body {font: 10px/10px Ahem; width: 40px}"
      "</style>"
      "<a href='#' id='a'>blaaaaa blaaaaa blaaaaa</a>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  EXPECT_TRUE(IsFragmentedInline(*a->GetLayoutObject()));
}

TEST_F(SpatialNavigationTest, ManyClientRectsButNotLineBrokenText) {
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  div {width: 20px; height: 20px;}"
      "</style>"
      "<a href='#' id='a'><div></div></a>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  EXPECT_FALSE(IsFragmentedInline(*a->GetLayoutObject()));
}

TEST_F(SpatialNavigationTest, UseTheFirstFragment) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<style>"
      "  body {font: 10px/10px Ahem; margin: 0; width: 50px;}"
      "</style>"
      "<a href='#' id='a'>12345 12</a>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  EXPECT_TRUE(IsFragmentedInline(*a->GetLayoutObject()));

  // Search downards.
  PhysicalRect origin_down = SearchOrigin(RootViewport(&GetFrame()), a,
                                          SpatialNavigationDirection::kDown);
  PhysicalRect origin_fragment =
      SearchOriginFragment(NodeRectInRootFrame(a), *a->GetLayoutObject(),
                           SpatialNavigationDirection::kDown);
  EXPECT_EQ(origin_down, origin_fragment);
  EXPECT_EQ(origin_down.Height(), 10);
  EXPECT_EQ(origin_down.Width(), 50);
  EXPECT_EQ(origin_down.X(), 0);
  EXPECT_EQ(origin_down.Y(), 0);

  // Search upwards.
  PhysicalRect origin_up = SearchOrigin(RootViewport(&GetFrame()), a,
                                        SpatialNavigationDirection::kUp);
  PhysicalRect origin_fragment_up =
      SearchOriginFragment(NodeRectInRootFrame(a), *a->GetLayoutObject(),
                           SpatialNavigationDirection::kUp);
  EXPECT_EQ(origin_up, origin_fragment_up);
  EXPECT_EQ(origin_up.Height(), 10);
  EXPECT_EQ(origin_up.Width(), 20);
  EXPECT_EQ(origin_up.X(), 0);
  EXPECT_EQ(origin_up.Y(), 10);

  // Search from the top fragment.
  PhysicalRect origin_left = SearchOrigin(RootViewport(&GetFrame()), a,
                                          SpatialNavigationDirection::kLeft);
  EXPECT_EQ(origin_left, origin_down);

  // Search from the bottom fragment.
  PhysicalRect origin_right = SearchOrigin(RootViewport(&GetFrame()), a,
                                           SpatialNavigationDirection::kRight);
  EXPECT_EQ(origin_right, origin_up);
}

TEST_F(SpatialNavigationTest, InlineImageLink) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<body style='font: 17px Ahem;'>"
      "<a id='a'><img id='pic' width='50' height='50'></a>"
      "</body>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(a));
  PhysicalRect uncropped_link = NodeRectInRootFrame(a);
  EXPECT_EQ(uncropped_link.Width(), 50);
  EXPECT_EQ(uncropped_link.Height(), 50);

  // The link gets its img's dimensions.
  PhysicalRect search_origin = SearchOrigin(RootViewport(&GetFrame()), a,
                                            SpatialNavigationDirection::kDown);
  EXPECT_EQ(search_origin, uncropped_link);
}

TEST_F(SpatialNavigationTest, InlineImageLinkWithLineHeight) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<body style='font: 17px Ahem; line-height: 13px;'>"
      "<a id='a'><img id='pic' width='50' height='50'></a>"
      "</body>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(a));
  PhysicalRect uncropped_link = NodeRectInRootFrame(a);
  EXPECT_EQ(uncropped_link.Width(), 50);
  EXPECT_EQ(uncropped_link.Height(), 50);

  // The link gets its img's dimensions.
  PhysicalRect search_origin = SearchOrigin(RootViewport(&GetFrame()), a,
                                            SpatialNavigationDirection::kDown);
  EXPECT_EQ(search_origin, uncropped_link);
}

TEST_F(SpatialNavigationTest, InlineImageTextLinkWithLineHeight) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<div style='font: 16px Ahem; line-height: 13px;'>"
      "<a id='a'><img width='30' height='30' id='replacedinline'>aaa</a> "
      "<a id='b'>b</a><br/>"
      "<a id='c'>cccccccc</a>"
      "</div>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  Element* b = GetDocument().getElementById(AtomicString("b"));
  Element* c = GetDocument().getElementById(AtomicString("c"));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(a));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(b));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(c));

  // The link gets its img's height.
  PhysicalRect search_origin = SearchOrigin(RootViewport(&GetFrame()), a,
                                            SpatialNavigationDirection::kDown);
  EXPECT_EQ(search_origin.Height(), 30);

  EXPECT_FALSE(Intersects(a, c));
  EXPECT_FALSE(Intersects(b, c));
}

TEST_F(SpatialNavigationTest, InlineLinkWithInnerBlock) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<div style='font: 20px Ahem; line-height: 16px;'>"
      "<a id='a'>a<span style='display: inline-block; width: 40px; height: "
      "45px; color: red'>a</span>a</a><a id='b'>bbb</a><br/>"
      "<a id='c'>cccccccc</a>"
      "</div>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  Element* b = GetDocument().getElementById(AtomicString("b"));
  Element* c = GetDocument().getElementById(AtomicString("c"));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(a));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(b));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(c));

  // The link gets its inner block's height.
  PhysicalRect search_origin = SearchOrigin(RootViewport(&GetFrame()), a,
                                            SpatialNavigationDirection::kDown);
  EXPECT_EQ(search_origin.Height(), 45);

  EXPECT_FALSE(Intersects(a, c));
  EXPECT_FALSE(Intersects(b, c));
}

TEST_F(SpatialNavigationTest, NoOverlappingLinks) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<div style='font: 17px Ahem;'>"
      "  <a id='a'>aaa</a> <a id='b'>bbb</a><br/>"
      "  <a id='c'>cccccccc</a>"
      "</div>");
  Element* a = GetDocument().getElementById(AtomicString("a"));
  Element* b = GetDocument().getElementById(AtomicString("b"));
  Element* c = GetDocument().getElementById(AtomicString("c"));
  AssertNormalizedHeight(a, 17, false);
  AssertNormalizedHeight(b, 17, false);
  AssertNormalizedHeight(c, 17, false);
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(a));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(b));
  EXPECT_TRUE(HasSameSearchOriginRectAndCandidateRect(c));
  EXPECT_FALSE(Intersects(a, b));
  EXPECT_FALSE(Intersects(a, c));
}

TEST_F(SpatialNavigationTest, OverlappingLinks) {
  LoadAhem();
  SetBodyInnerHTML(
      "<!DOCTYPE html>"
      "<div style='font: 16px Ahem; line-height: 13px;'>"
      "  <a id='a'>aaa</a> <a id='b'>bbb</a><br/>"
      "  <a id='c'>cccccccc</a>"
```