Response:
The user wants a summary of the functionalities of the given C++ code, which is a test file for `LayoutView` in the Chromium Blink rendering engine. I need to identify what aspects of `LayoutView` are being tested. The test names and the code within each test provide clues.

Here's a breakdown of the tests and their apparent functionalities:

*   **`UpdateCountersLayout`**: Tests if layout is triggered correctly when CSS counters are updated. This involves CSS properties like `counter-increment` and the `content: counter()` function.
*   **`DisplayNoneFrame`**: Tests how a frame (iframe) with `display: none` is handled in the layout process. This relates to HTML iframes and the CSS `display` property.
*   **`NamedPages`**: Tests the functionality of named pages for printing, likely involving CSS properties related to page breaks and named pages.
*   **`NamedPagesAbsPos`**: Similar to `NamedPages`, but specifically tests named pages in combination with absolutely positioned elements.
*   **`LayoutViewHitTestTest`**:  A parameterized test suite focusing on hit testing within the `LayoutView`. This involves determining which element is at a given coordinate. The different test cases within this suite cover various layout scenarios.
    *   **`BlockInInlineBelowBottom`**: Hit testing when a block element is inside an inline element and the hit point is below the block.
    *   **`BlockInInlineWithListItem`**: Hit testing with a block element inside an inline element within a list item.
    *   **`EmptySpan`**: Hit testing an empty span element.
    *   **`FlexBlockChildren`**: Hit testing with flexbox layout.
    *   **`FloatLeftLeft`, `FloatLeftMiddle`, `FloatLeftRight`**: Hit testing involving floated elements with different DOM structures.
    *   **`FloatRightLeft`, `FloatRightMiddle`, `FloatRightRight`**: Similar to the `FloatLeft` tests but with right-floated elements.
    *   **`PositionAbsolute`**: Hit testing with absolutely positioned elements.
    *   **`HitTestHorizontal`**: Comprehensive hit testing with a specific layout involving nested spans.
    *   **`HitTestVerticalLR`**: Hit testing with vertical writing mode.

Based on this analysis, I can now formulate a summary of the file's functionalities.这个C++代码文件 `layout_view_test.cc` 是 Chromium Blink 引擎中 `LayoutView` 类的单元测试文件。它的主要功能是验证 `LayoutView` 类的各种行为和功能是否符合预期。

以下是该文件测试的主要功能归纳：

1. **CSS 计数器 (CSS Counters) 的更新和布局触发：**
    *   测试当修改元素的 CSS 计数器相关属性（如 `counter-increment`）时，`LayoutView` 是否能正确检测到需要重新布局。

    **与 CSS 的关系举例：**
    *   代码中使用了 `<style>` 标签定义了 CSS 规则 `div.incX { counter-increment: x }` 和 `div::before { content: counter(y) }`，这些是标准的 CSS 语法，用于定义和显示计数器。
    *   测试逻辑修改了元素的 `class` 属性，从而改变了其应用的 CSS 规则，验证了 `LayoutView` 对 CSS 变化的响应。
    *   **假设输入与输出：**
        *   **假设输入：** 初始状态下，一个 `div` 元素没有 `counter-increment` 属性。然后通过 JavaScript 修改其 `class` 属性，添加了 `counter-increment` 属性。
        *   **预期输出：** `GetDocument().View()->NeedsLayout()` 的返回值会从 `false` 变为 `true`，表明需要重新布局。

2. **`display: none` 的 iframe 处理：**
    *   测试当一个 iframe 元素的 `display` 属性设置为 `none` 时，`LayoutView` 对其内容的处理方式。例如，验证其是否不应该有子元素，是否不应该计算样式。

    **与 HTML 和 CSS 的关系举例：**
    *   测试代码创建了一个 `<iframe>` 元素，并设置了 `style="display:none"`，这直接关联了 HTML 结构和 CSS 属性。
    *   测试验证了 `frame_doc->documentElement()->GetComputedStyle()` 返回空，说明 `display: none` 的 iframe 不会计算样式。

3. **命名页 (Named Pages) 的处理：**
    *   测试在打印上下文中，`LayoutView` 如何识别和管理通过 CSS 的 `page` 属性和 `break-before: page` 属性定义的命名页。

    **与 HTML 和 CSS 的关系举例：**
    *   代码中使用了 `<div style="break-before:page;">` 和 `<div style="page:yksi;">` 等 CSS 样式，这些是 CSS 分页控制的特性。
    *   测试验证了 `view->NamedPageAtIndex(index)` 方法能根据页面的位置返回正确的页面名称。

    *   **假设输入与输出：**
        *   **假设输入：** HTML 中包含多个 `div` 元素，部分元素设置了 `break-before:page` 和 `page:some-name` 样式。
        *   **预期输出：** `view->NamedPageAtIndex(index)` 对于设置了 `page` 属性的页面会返回对应的名称，否则返回空字符串。

4. **命中测试 (Hit Testing)：**
    *   测试 `LayoutView` 的命中测试功能，即给定屏幕坐标，判断哪个元素位于该坐标下。
    *   涵盖了多种布局场景，包括：
        *   块级元素在行内元素下方
        *   块级元素在带有列表项的行内元素中
        *   空 `<span>` 元素
        *   Flexbox 布局
        *   浮动元素 (float: left 和 float: right)
        *   绝对定位元素 (position: absolute)
        *   水平和垂直书写模式 (writing-mode: vertical-lr)

    **与 JavaScript, HTML, CSS 的关系举例：**
    *   虽然测试代码本身是 C++，但它验证的功能直接关系到用户与网页的交互，例如，用户点击屏幕的某个位置，浏览器需要通过命中测试来确定用户点击了哪个元素，这通常是 JavaScript 事件处理的基础。
    *   测试用例中使用了各种 HTML 结构（如 `<div>`, `<span>`, `<li>`) 和 CSS 样式（如 `display: flex`, `float`, `position: absolute`, `writing-mode`）来模拟不同的布局场景。
    *   **假设输入与输出：**
        *   **假设输入：**  一个包含嵌套 `div` 和 `span` 元素的 HTML 结构，并应用了特定的 CSS 样式。提供一组屏幕坐标 (left, top)。
        *   **预期输出：** `HitTest(left, top)` 方法返回一个 `PositionWithAffinity` 对象，该对象指向预期被命中的 DOM 节点和偏移量。例如，在 `TEST_P(LayoutViewHitTestTest, BlockInInlineBelowBottom)` 中，点击特定坐标应该返回文本节点 `cd` 的特定位置。

5. **不同的编辑行为 (Editing Behavior) 的影响：**
    *   使用参数化测试 `LayoutViewHitTestTest`，针对不同的 `EditingBehavior`（例如 Mac, Windows, Android），验证命中测试的结果是否符合特定平台的行为。

**该文件涉及的用户或编程常见的使用错误：**

*   **CSS 计数器更新后未触发布局：** 开发者可能会错误地认为修改 CSS 计数器不会影响布局，导致界面显示不同步。此测试确保了引擎能正确处理这种情况。
*   **`display: none` 的 iframe 的错误操作：** 开发者可能会尝试在 `display: none` 的 iframe 中执行某些需要布局信息的 JavaScript 操作，这可能会导致错误或意外的行为。测试验证了 `LayoutView` 对这种状态的处理。
*   **错误理解命名页的工作方式：** 开发者可能不清楚如何正确使用 CSS 属性来定义和命名页面，或者错误地假设命名页在非打印上下文中也起作用。
*   **命中测试的边界情况处理不当：** 开发者在编写 JavaScript 事件处理代码时，可能会忽略命中测试的一些边界情况，例如点击元素边缘或浮动元素周围的区域。这些测试用例覆盖了多种边界情况，帮助确保命中测试的准确性。

**总结该文件的功能：**

总而言之，`blink/renderer/core/layout/layout_view_test.cc` 文件的主要功能是**全面测试 `LayoutView` 类的各种布局和命中测试相关的功能，确保其在不同的 CSS 属性、HTML 结构和编辑行为下都能正确工作**。这对于保证 Chromium 浏览器的页面渲染和用户交互的正确性至关重要。

Prompt: 
```
这是目录为blink/renderer/core/layout/layout_view_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/layout_view.h"

#include "build/build_config.h"
#include "third_party/blink/public/mojom/webpreferences/web_preferences.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/page/print_context.h"
#include "third_party/blink/renderer/core/testing/core_unit_test_helper.h"

namespace blink {

class LayoutViewTest : public RenderingTest {
 public:
  LayoutViewTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}
};

TEST_F(LayoutViewTest, UpdateCountersLayout) {
  SetBodyInnerHTML(R"HTML(
    <style>
      div.incX { counter-increment: x }
      div.incY { counter-increment: y }
      div::before { content: counter(y) }
    </style>
    <div id=inc></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  Element* inc = GetElementById("inc");

  inc->setAttribute(html_names::kClassAttr, AtomicString("incX"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_FALSE(GetDocument().View()->NeedsLayout());

  UpdateAllLifecyclePhasesForTest();
  inc->setAttribute(html_names::kClassAttr, AtomicString("incY"));
  GetDocument().UpdateStyleAndLayoutTree();
  EXPECT_TRUE(GetDocument().View()->NeedsLayout());
}

TEST_F(LayoutViewTest, DisplayNoneFrame) {
  SetBodyInnerHTML(R"HTML(
    <iframe id="iframe" style="display:none"></iframe>
  )HTML");

  auto* iframe = To<HTMLIFrameElement>(GetElementById("iframe"));
  Document* frame_doc = iframe->contentDocument();
  ASSERT_TRUE(frame_doc);
  frame_doc->OverrideIsInitialEmptyDocument();
  frame_doc->View()->BeginLifecycleUpdates();
  UpdateAllLifecyclePhasesForTest();

  LayoutObject* view = frame_doc->GetLayoutView();
  ASSERT_TRUE(view);
  EXPECT_FALSE(view->CanHaveChildren());
  EXPECT_FALSE(frame_doc->documentElement()->GetComputedStyle());

  frame_doc->body()->setInnerHTML(R"HTML(
    <div id="div"></div>
  )HTML");

  EXPECT_FALSE(frame_doc->NeedsLayoutTreeUpdate());
}

TEST_F(LayoutViewTest, NamedPages) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <style>
      div:empty { height:10px; }
    </style>
    <!-- First page: -->
    <div></div>
    <!-- Second page: -->
    <div style="break-before:page;"></div>
    <!-- Third page: -->
    <div style="page:yksi;"></div>
    <!-- Fourth page: -->
    <div style="page:yksi;">
      <div style="page:yksi; break-before:page;"></div>
      <!-- Fifth page: -->
      <div style="page:yksi; break-before:page;"></div>
    </div>
    <!-- Sixth page: -->
    <div style="page:kaksi;"></div>
    <!-- Seventh page: -->
    <div style="page:maksitaksi;"></div>
    <!-- Eighth page: -->
    <div></div>
    <!-- Ninth page: -->
    <div style="page:yksi;"></div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const LayoutView* view = GetDocument().GetLayoutView();
  ASSERT_TRUE(view);

  ScopedPrintContext print_context(&GetDocument().View()->GetFrame());
  print_context->BeginPrintMode(WebPrintParams(gfx::SizeF(500, 500)));

  EXPECT_EQ(view->NamedPageAtIndex(0), AtomicString());
  EXPECT_EQ(view->NamedPageAtIndex(1), AtomicString());
  EXPECT_EQ(view->NamedPageAtIndex(2), "yksi");
  EXPECT_EQ(view->NamedPageAtIndex(3), "yksi");
  EXPECT_EQ(view->NamedPageAtIndex(4), "yksi");
  EXPECT_EQ(view->NamedPageAtIndex(5), "kaksi");
  EXPECT_EQ(view->NamedPageAtIndex(6), "maksitaksi");
  EXPECT_EQ(view->NamedPageAtIndex(7), AtomicString());
  EXPECT_EQ(view->NamedPageAtIndex(8), "yksi");

  // We don't provide a name for pages that don't exist.
  EXPECT_EQ(view->NamedPageAtIndex(9), AtomicString());
  EXPECT_EQ(view->NamedPageAtIndex(100), AtomicString());
}

TEST_F(LayoutViewTest, NamedPagesAbsPos) {
  SetBodyInnerHTML(R"HTML(
    <!DOCTYPE html>
    <div style="page:woohoo;">
      <div style="height:10px;"></div>
      <div style="break-before:page; height:10px;"></div>
      <div style="break-before:page; height:10px;">
        <div style="position:absolute; height:150vh;"></div>
      </div>
      <div style="break-before:page; height:10px;"></div>
      <div style="break-before:page; height:10px;"></div>
    </div>
  )HTML");

  UpdateAllLifecyclePhasesForTest();
  const LayoutView* view = GetDocument().GetLayoutView();
  ASSERT_TRUE(view);

  ScopedPrintContext print_context(&GetDocument().View()->GetFrame());
  print_context->BeginPrintMode(WebPrintParams(gfx::SizeF(500, 500)));

  EXPECT_EQ(view->NamedPageAtIndex(0), "woohoo");
  EXPECT_EQ(view->NamedPageAtIndex(1), "woohoo");
  EXPECT_EQ(view->NamedPageAtIndex(2), "woohoo");
  EXPECT_EQ(view->NamedPageAtIndex(3), "woohoo");
  EXPECT_EQ(view->NamedPageAtIndex(4), "woohoo");
}

struct HitTestConfig {
  mojom::EditingBehavior editing_behavior;
};

class LayoutViewHitTestTest : public testing::WithParamInterface<HitTestConfig>,
                              public RenderingTest {
 public:
  LayoutViewHitTestTest()
      : RenderingTest(MakeGarbageCollected<SingleChildLocalFrameClient>()) {}

 protected:
  bool IsAndroidOrWindowsOrChromeOSEditingBehavior() {
    return GetParam().editing_behavior ==
               mojom::EditingBehavior::kEditingAndroidBehavior ||
           GetParam().editing_behavior ==
               mojom::EditingBehavior::kEditingWindowsBehavior ||
           GetParam().editing_behavior ==
               mojom::EditingBehavior::kEditingChromeOSBehavior;
  }

  void SetUp() override {
    RenderingTest::SetUp();
    GetFrame().GetSettings()->SetEditingBehaviorType(
        GetParam().editing_behavior);
  }

  PositionWithAffinity HitTest(int left, int top) {
    const HitTestRequest hit_request(HitTestRequest::kActive);
    const HitTestLocation hit_location(PhysicalOffset(left, top));
    HitTestResult hit_result(hit_request, hit_location);
    if (!GetLayoutView().HitTest(hit_location, hit_result))
      return PositionWithAffinity();
    return hit_result.GetPosition();
  }
};

INSTANTIATE_TEST_SUITE_P(
    All,
    LayoutViewHitTestTest,
    ::testing::Values(
        HitTestConfig{mojom::EditingBehavior::kEditingMacBehavior},
        HitTestConfig{mojom::EditingBehavior::kEditingWindowsBehavior},
        HitTestConfig{mojom::EditingBehavior::kEditingUnixBehavior},
        HitTestConfig{mojom::EditingBehavior::kEditingAndroidBehavior},
        HitTestConfig{mojom::EditingBehavior::kEditingChromeOSBehavior}));

// See editing/selection/click-after-nested-block.html
TEST_P(LayoutViewHitTestTest, BlockInInlineBelowBottom) {
  LoadAhem();
  InsertStyleElement("body { margin: 0px; font: 10px/15px Ahem; }");
  SetBodyInnerHTML(
      "<div id=target>"
      "<div id=line1>ab</div>"
      "<div><span><div id=line2>cd</div></span></div>"
      "</div>");
  const auto& line2 = *GetElementById("line2");
  const auto& cd = *To<Text>(line2.firstChild());
  const auto& cd_0 = PositionWithAffinity(Position(cd, 0));
  const auto& cd_1 =
      PositionWithAffinity(Position(cd, 1), TextAffinity::kDownstream);
  const auto& cd_2 =
      PositionWithAffinity(Position(cd, 2), TextAffinity::kUpstream);
  const auto& kEndOfLine = PositionWithAffinity(Position::AfterNode(line2));

  // hit test on line 2
  EXPECT_EQ(cd_0, HitTest(0, 20));
  EXPECT_EQ(cd_0, HitTest(5, 20));
  EXPECT_EQ(cd_1, HitTest(10, 20));
  EXPECT_EQ(cd_1, HitTest(15, 20));
  EXPECT_EQ(cd_2, HitTest(20, 20));
  EXPECT_EQ(cd_2, HitTest(25, 20));

  // hit test below line 2
  if (IsAndroidOrWindowsOrChromeOSEditingBehavior()) {
    EXPECT_EQ(cd_0, HitTest(0, 50));
    EXPECT_EQ(cd_0, HitTest(5, 50));
    EXPECT_EQ(cd_1, HitTest(10, 50));
    EXPECT_EQ(cd_1, HitTest(15, 50));
    EXPECT_EQ(cd_2, HitTest(20, 50));
    EXPECT_EQ(cd_2, HitTest(25, 50));
  } else {
    // ShouldMoveCaretToHorizontalBoundaryWhenPastTopOrBottom behavior is
    // in effect.
    EXPECT_EQ(kEndOfLine, HitTest(0, 50));
    EXPECT_EQ(kEndOfLine, HitTest(5, 50));
    EXPECT_EQ(kEndOfLine, HitTest(10, 50));
    EXPECT_EQ(kEndOfLine, HitTest(15, 50));
    EXPECT_EQ(kEndOfLine, HitTest(25, 50));
  }
}

// See editing/pasteboard/drag-drop-list.html
TEST_P(LayoutViewHitTestTest, BlockInInlineWithListItem) {
  LoadAhem();
  InsertStyleElement("body { margin: 0px; font: 10px/15px Ahem; }");
  SetBodyInnerHTML("<li id=target><span><div id=inner>abc</div></span>");
  const auto& target = *GetElementById("target");
  const auto& span = *target.firstChild();
  const auto& inner = *GetElementById("inner");
  const auto& abc = *To<Text>(inner.firstChild());

  // Note: span@0 comes from |LayoutObject::FindPosition()| via
  // |LayoutObject::CreatePositionWithAffinity()| for anonymous block
  // containing list marker.
  // LayoutBlockFlow (anonymous)
  //    LayoutInsideListMarker {::marker}
  //      LayoutText (anonymous)
  //      LayoutInline {SPAN}
  EXPECT_EQ(PositionWithAffinity(Position(span, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(span, 0)), HitTest(0, 10));
  if (IsAndroidOrWindowsOrChromeOSEditingBehavior()) {
    EXPECT_EQ(PositionWithAffinity(Position(abc, 1)), HitTest(10, 5));
    EXPECT_EQ(PositionWithAffinity(Position(abc, 1)), HitTest(10, 10));
    EXPECT_EQ(PositionWithAffinity(Position(abc, 3), TextAffinity::kUpstream),
              HitTest(100, 5));
    EXPECT_EQ(PositionWithAffinity(Position(abc, 3), TextAffinity::kUpstream),
              HitTest(100, 10));
  } else {
    EXPECT_EQ(PositionWithAffinity(Position::BeforeNode(inner)),
              HitTest(10, 5));
    EXPECT_EQ(PositionWithAffinity(Position::BeforeNode(inner)),
              HitTest(10, 10));
    EXPECT_EQ(PositionWithAffinity(Position::BeforeNode(inner)),
              HitTest(100, 5));
    EXPECT_EQ(PositionWithAffinity(Position::BeforeNode(inner)),
              HitTest(100, 10));
  }
  EXPECT_EQ(PositionWithAffinity(Position(abc, 3), TextAffinity::kUpstream),
            HitTest(100, 15));
  EXPECT_EQ(PositionWithAffinity(Position(abc, 3), TextAffinity::kUpstream),
            HitTest(100, 20));
  EXPECT_EQ(PositionWithAffinity(Position(abc, 3), TextAffinity::kUpstream),
            HitTest(100, 25));
}

TEST_P(LayoutViewHitTestTest, EmptySpan) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 50px; }"
      "b { border: solid 5px green; }");
  SetBodyInnerHTML("<div id=target>AB<b></b></div>");
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.firstChild());
  const auto after_ab =
      PositionWithAffinity(Position(ab, 2), TextAffinity::kUpstream);

  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(10, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(after_ab, HitTest(20, 5));
  EXPECT_EQ(after_ab, HitTest(25, 5));
  EXPECT_EQ(after_ab, HitTest(30, 5));
  EXPECT_EQ(after_ab, HitTest(35, 5));
  EXPECT_EQ(after_ab, HitTest(40, 5));
  EXPECT_EQ(after_ab, HitTest(45, 5));
  EXPECT_EQ(after_ab, HitTest(50, 5));
  EXPECT_EQ(after_ab, HitTest(55, 5));
}

// http://crbug.com/1233862
TEST_P(LayoutViewHitTestTest, FlexBlockChildren) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#t { display: flex; }");
  SetBodyInnerHTML("<div id=t><div id=ab>ab</div><div id=xy>XY</div></div>");

  const auto& ab = *To<Text>(GetElementById("ab")->firstChild());
  const auto& xy = *To<Text>(GetElementById("xy")->firstChild());

  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(10, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(20, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(25, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(30, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(35, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(40, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(45, 5));
}

// http://crbug.com/1171070
// See also, FloatLeft*, DOM order of "float" should not affect hit testing.
TEST_P(LayoutViewHitTestTest, FloatLeftLeft) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 70px; }"
      ".float { float: left; margin-right: 10px; }");
  SetBodyInnerHTML("<div id=target><div class=float>ab</div>xy</div>");
  // FragmentItem
  //   [0] kLine (30,0)x(20,10)
  //   [1] kBox/Floating (0,0)x(20,10)
  //   [2] kText "xy" (30,0)x(20,10)
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.firstChild()->firstChild());
  auto& xy = *To<Text>(target.lastChild());

  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(20, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(25, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(30, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(35, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(40, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(45, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(50, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(55, 5));
}

// http://crbug.com/1171070
// See also, FloatLeft*, DOM order of "float" should not affect hit testing.
TEST_P(LayoutViewHitTestTest, FloatLeftMiddle) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 70px; }"
      ".float { float: left; margin-right: 10px; }");
  SetBodyInnerHTML("<div id=target>x<div class=float>ab</div>y</div>");
  // FragmentItem
  //   [0] kLine (30,0)x(20,10)
  //   [1] kText "x" (30,0)x(10,10)
  //   [1] kBox/Floating (0,0)x(20,10)
  //   [2] kText "y" (40,0)x(10,10)
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.firstChild()->nextSibling()->firstChild());
  auto& x = *To<Text>(target.firstChild());
  auto& y = *To<Text>(target.lastChild());

  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(x, 0)), HitTest(20, 5));
  EXPECT_EQ(PositionWithAffinity(Position(x, 0)), HitTest(25, 5));
  EXPECT_EQ(PositionWithAffinity(Position(x, 0)), HitTest(30, 5));
  EXPECT_EQ(PositionWithAffinity(Position(x, 0)), HitTest(35, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 0)), HitTest(40, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 0)), HitTest(45, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 1), TextAffinity::kUpstream),
            HitTest(50, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 1), TextAffinity::kUpstream),
            HitTest(55, 5));
}

// http://crbug.com/1171070
// See also, FloatLeft*, DOM order of "float" should not affect hit testing.
TEST_P(LayoutViewHitTestTest, FloatLeftRight) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 70px; }"
      ".float { float: left; margin-right: 10px; }");
  SetBodyInnerHTML("<div id=target>xy<div class=float>ab</div></div>");
  // FragmentItem
  //   [0] kLine (30,0)x(20,10)
  //   [1] kText "xy" (30,0)x(20,10)
  //   [2] kBox/Floating (0,0)x(20,10)
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.lastChild()->firstChild());
  auto& xy = *To<Text>(target.firstChild());

  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(20, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(25, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(30, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(35, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(40, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(45, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(50, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(55, 5));
}

// http://crbug.com/1171070
// See also, FloatRight*, DOM order of "float" should not affect hit testing.
TEST_P(LayoutViewHitTestTest, FloatRightLeft) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 50px; }"
      ".float { float: right; }");
  SetBodyInnerHTML("<div id=target>xy<div class=float>ab</div></div>");
  // FragmentItem
  //   [0] kLine (0,0)x(20,10)
  //   [1] kBox/Floating (30,0)x(20,10)
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.lastChild()->firstChild());
  auto& xy = *To<Text>(target.firstChild());

  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(20, 5))
      << "at right of 'xy'";
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(25, 5))
      << "right of 'xy'";
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(30, 5))
      << "inside float";
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(35, 5))
      << "inside float";
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(40, 5))
      << "inside float";
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(45, 5))
      << "inside float";

  // |HitTestResult| holds <body>.
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(50, 5))
      << "at right side of float";
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(55, 5))
      << "right of float";
}

// http://crbug.com/1171070
// See also, FloatRight*, DOM order of "float" should not affect hit testing.
TEST_P(LayoutViewHitTestTest, FloatRightMiddle) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 50px; }"
      ".float { float: right; }");
  SetBodyInnerHTML("<div id=target>x<div class=float>ab</div>y</div>");
  // FragmentItem
  //   [0] kLine (0,0)x(20,10)
  //   [1] kText "x" (0,0)x(10,10)
  //   [2] kBox/Floating (30,0)x(20,10)
  //   [3] kText "y" (10,0)x(10,10)
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.firstChild()->nextSibling()->firstChild());
  auto& x = *To<Text>(target.firstChild());
  auto& y = *To<Text>(target.lastChild());

  EXPECT_EQ(PositionWithAffinity(Position(x, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(x, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 0)), HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 1), TextAffinity::kUpstream),
            HitTest(20, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 1), TextAffinity::kUpstream),
            HitTest(25, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(30, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(35, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(40, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(45, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 1), TextAffinity::kUpstream),
            HitTest(50, 5));
  EXPECT_EQ(PositionWithAffinity(Position(y, 1), TextAffinity::kUpstream),
            HitTest(55, 5));
}

// http://crbug.com/1171070
// See also, FloatRight*, DOM order of "float" should not affect hit testing.
TEST_P(LayoutViewHitTestTest, FloatRightRight) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 50px; }"
      ".float { float: right; }");
  SetBodyInnerHTML("<div id=target><div class=float>ab</div>xy</div>");
  //   [0] kLine (0,0)x(20,10)
  //   [1] kBox/Floating (30,0)x(20,10)
  //   [2] kText "xy" (0,0)x(20,10)
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.firstChild()->firstChild());
  auto& xy = *To<Text>(target.lastChild());

  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(20, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(25, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(30, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(35, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(40, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(45, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(50, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(55, 5));
}

TEST_P(LayoutViewHitTestTest, PositionAbsolute) {
  LoadAhem();
  InsertStyleElement(
      "body { margin: 0px; font: 10px/10px Ahem; }"
      "#target { width: 70px; }"
      ".abspos { position: absolute; left: 40px; top: 0px; }");
  SetBodyInnerHTML("<div id=target><div class=abspos>ab</div>xy</div>");
  // FragmentItem
  //   [0] kLine (0,0)x(20,10)
  //   [2] kText "xy" (30,0)x(20,10)
  // Note: position:absolute isn't in FragmentItems of #target.
  auto& target = *GetElementById("target");
  auto& ab = *To<Text>(target.firstChild()->firstChild());
  auto& xy = *To<Text>(target.lastChild());

  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(0, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 0)), HitTest(5, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 1), TextAffinity::kDownstream),
            HitTest(15, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(20, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(25, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(30, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(35, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(40, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 0)), HitTest(45, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(50, 5));
  EXPECT_EQ(PositionWithAffinity(Position(ab, 1), TextAffinity::kDownstream),
            HitTest(55, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(60, 5));
  EXPECT_EQ(PositionWithAffinity(Position(xy, 2), TextAffinity::kUpstream),
            HitTest(65, 5));
}

TEST_P(LayoutViewHitTestTest, HitTestHorizontal) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id="div" style="position: relative; font: 10px/10px Ahem;
        top: 100px; left: 50px; width: 200px; height: 80px">
      <span id="span1">ABCDE</span><span id="span2"
          style="position: relative; top: 30px">XYZ</span>
    </div>
  )HTML");

  // (50, 100)         (250, 100)
  //   |------------------|
  //   |ABCDE             |
  //   |                  |
  //   |                  |
  //   |     XYZ          |
  //   |                  |
  //   |                  |
  //   |------------------|
  // (50, 180)         (250, 180)
  auto* div = GetElementById("div");
  auto* text1 = GetElementById("span1")->firstChild();
  auto* text2 = GetElementById("span2")->firstChild();

  HitTestResult result;
  // In body, but not in any descendants.
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(1, 1)), result);
  EXPECT_EQ(GetDocument().body(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Top-left corner of div and span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 101)), result);
  EXPECT_EQ(text1, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Top-right corner (outside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(251, 101)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(251, 101), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 3), TextAffinity::kUpstream),
            result.GetPosition());

  // Top-right corner (inside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(249, 101)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(199, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 3), TextAffinity::kUpstream),
            result.GetPosition());

  // Top-right corner (inside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(99, 101)), result);
  EXPECT_EQ(text1, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(49, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 5), TextAffinity::kUpstream),
            result.GetPosition());

  // Top-right corner (outside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(101, 101)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(51, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Bottom-left corner (outside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 181)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(51, 181), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Bottom-left corner (inside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 179)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 79), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Bottom-left corner (outside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 111)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 11), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-left corner of span2.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(101, 131)), result);
  EXPECT_EQ(text2, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(51, 31), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text2, 0), TextAffinity::kDownstream),
            result.GetPosition());
}

TEST_P(LayoutViewHitTestTest, HitTestVerticalLR) {
  LoadAhem();
  SetBodyInnerHTML(R"HTML(
    <style>body { margin: 0 }</style>
    <div id="div" style="position: relative; font: 10px/10px Ahem;
        top: 100px; left: 50px; width: 200px; height: 80px;
        writing-mode: vertical-lr">
      <span id="span1">ABCDE</span><span id="span2"
          style="position: relative; left: 30px">XYZ</span>
    </div>
  )HTML");

  // (50, 100)         (250, 100)
  //   |------------------|
  //   |A                 |
  //   |B                 |
  //   |C                 |
  //   |D                 |
  //   |E                 |
  //   |   X              |
  //   |   Y              |
  //   |   Z              |
  //   |------------------|
  // (50, 180)         (250, 180)
  auto* div = GetElementById("div");
  auto* text1 = GetElementById("span1")->firstChild();
  auto* text2 = GetElementById("span2")->firstChild();

  HitTestResult result;
  // In body, but not in any descendants.
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(1, 1)), result);
  EXPECT_EQ(GetDocument().body(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Top-left corner of div and span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(51, 101)), result);
  EXPECT_EQ(text1, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(1, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Top-right corner (outside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(251, 101)), result);
  EXPECT_EQ(GetDocument().documentElement(), result.InnerNode());
  EXPECT_EQ(PhysicalOffset(251, 101), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-right corner (inside) of div.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(249, 101)), result);
  EXPECT_EQ(div, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(199, 1), result.LocalPoint());
  EXPECT_EQ(
      IsAndroidOrWindowsOrChromeOSEditingBehavior()
          ? PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream)
          : PositionWithAffinity(Position(text2, 3), TextAffinity::kDownstream),
      result.GetPosition());

  // Top-right corner (inside) of span1.
  result = HitTestResult();
  GetLayoutView().HitTest(HitTestLocation(PhysicalOffset(59, 101)), result);
  EXPECT_EQ(text1, result.InnerNode());
  EXPECT_EQ(PhysicalOffset(9, 1), result.LocalPoint());
  EXPECT_EQ(PositionWithAffinity(Position(text1, 0), TextAffinity::kDownstream),
            result.GetPosition());

  // Top-right corner (outside) of span1.
  result 
"""


```