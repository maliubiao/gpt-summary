Response:
The user wants to understand the functionality of the `snap_coordinator_test.cc` file in the Chromium Blink engine. This file is a C++ test file, so its main function is to test the functionality of the `SnapCoordinator` class.

Here's a breakdown of how to approach the request:

1. **Identify the core purpose:** The file tests the `SnapCoordinator` class.
2. **Infer the functionality of `SnapCoordinator`:** Based on the test names and included headers, `SnapCoordinator` likely manages scroll snapping behavior in web pages. This includes identifying snap containers, snap areas, and calculating their properties.
3. **Connect to web technologies (JavaScript, HTML, CSS):**  Scroll snapping is controlled by CSS properties like `scroll-snap-type` and `scroll-snap-align`. The tests likely verify how the `SnapCoordinator` interprets these CSS properties.
4. **Analyze the test cases:**  The names of the tests provide clues about the specific functionalities being tested, such as handling nested elements, fixed-position elements, dynamic changes to styles, and interactions with the viewport.
5. **Consider user actions and debugging:**  Think about how a web developer might encounter issues related to scroll snapping and how these tests could help in debugging.
6. **Address the specific requests:** Provide examples, logical inferences (with assumptions), potential user errors, and a summary of the functionality.
```
文件 blink/renderer/core/page/scrolling/snap_coordinator_test.cc 的功能归纳：

这个 C++ 文件是 Chromium Blink 引擎中 `SnapCoordinator` 类的单元测试文件。它的主要功能是验证 `SnapCoordinator` 类的各种功能是否按预期工作。`SnapCoordinator` 负责处理网页中的 CSS Scroll Snap 功能。

**具体功能测试点包括：**

1. **识别和管理 Snap Container (滚动捕捉容器):**
   - 测试能否正确识别设置了 `scroll-snap-type` 属性的元素作为滚动捕捉容器。
   - 测试当滚动捕捉容器的样式或子元素发生变化时，`SnapCoordinator` 是否能正确更新。

2. **识别和管理 Snap Area (滚动捕捉区域):**
   - 测试能否正确识别设置了 `scroll-snap-align` 属性的元素作为滚动捕捉区域。
   - 测试嵌套的滚动捕捉区域是否被正确的滚动捕捉容器捕获。
   - 测试 `position: fixed` 的元素是否不会被识别为滚动捕捉区域。
   - 测试动态添加、删除或修改滚动捕捉区域时，`SnapCoordinator` 的行为是否正确。

3. **与 Viewport 的交互:**
   - 测试当 `scroll-snap-type` 设置在 `documentElement` 或 `body` 上时，`SnapCoordinator` 如何处理 viewport 的滚动捕捉。
   - 测试当 `body` 或 `documentElement` 作为 viewport 定义元素且具有滚动属性时，滚动捕捉区域的归属问题。

4. **计算 Snap Container 和 Snap Area 的数据:**
   - 测试 `SnapCoordinator` 能否正确计算 `SnapContainerData` (滚动捕捉容器数据)，包括 `scroll-snap-type`、容器的裁剪矩形和最大滚动位置。
   - 测试 `SnapCoordinator` 能否正确计算 `SnapAreaData` (滚动捕捉区域数据)，包括 `scroll-snap-align`、区域的矩形、是否必须捕捉等属性。
   - 测试计算过程中是否考虑了元素的边距、边框、内边距和 `scroll-margin` 等盒模型属性。
   - 测试计算过程中是否考虑了元素的 `transform: scale()` 变换。
   - 测试计算过程中是否考虑了 `writing-mode: vertical-rl` 垂直书写模式的影响。

5. **处理滚动位置和目标捕捉区域:**
   - 测试当滚动位置发生变化时，`SnapCoordinator` 能否正确识别当前捕捉到的滚动捕捉区域。
   - 测试当当前捕捉到的滚动捕捉区域被移除时，`SnapCoordinator` 的行为。
   - 测试当添加新的滚动捕捉区域时，是否会影响当前捕捉到的滚动捕捉区域。

**与 Javascript, HTML, CSS 的关系举例说明：**

* **CSS:**  `snap_coordinator_test.cc` 通过设置不同的 CSS 属性（例如 `scroll-snap-type: both mandatory;` 和 `scroll-snap-align: start;`）来模拟网页中的滚动捕捉行为，并验证 `SnapCoordinator` 是否正确解析和响应这些 CSS 规则。例如，测试用例 `SimpleSnapElement` 通过设置 `<div id='snap-element' style='scroll-snap-align: start;'></div>` 来验证能否识别该元素为滚动捕捉区域。

* **HTML:** 测试用例通过构建不同的 HTML 结构（例如嵌套的 `div` 元素）来模拟各种网页布局，并验证 `SnapCoordinator` 在不同结构下的行为。例如，`NestedSnapElementCaptured` 测试用例验证在嵌套滚动容器的情况下，滚动捕捉区域是否被正确的容器捕获。

* **Javascript (间接关系):** 虽然这个测试文件本身是用 C++ 编写的，它测试的功能直接影响了 Javascript 中与滚动相关的 API 的行为。当 Javascript 代码尝试滚动到一个使用了 CSS Scroll Snap 的容器时，`SnapCoordinator` 的工作会影响最终的滚动位置。例如，开发者可能会使用 `element.scrollTo()` 方法，而 `SnapCoordinator` 会确保滚动最终停留在指定的捕捉点上。

**逻辑推理 (假设输入与输出):**

**假设输入:**  一个 HTML 结构如下：

```html
<div id="container" style="overflow: scroll; scroll-snap-type: y mandatory; height: 200px;">
  <div style="height: 100px; scroll-snap-align: start;">Item 1</div>
  <div style="height: 100px; scroll-snap-align: start;">Item 2</div>
</div>
```

**预期输出 (部分):**

* `SnapCoordinator` 会识别 `id="container"` 的 `div` 元素为一个垂直方向的强制滚动捕捉容器。
* `SnapCoordinator` 会识别两个 `height: 100px` 的 `div` 元素为滚动捕捉区域，并且它们的 `scroll-snap-align` 属性为 `start`。
* 当用户滚动 `container` 时，滚动会停留在 `Item 1` 的顶部或者 `Item 2` 的顶部。

**涉及用户或者编程常见的使用错误 (举例说明):**

* **错误地在非滚动容器上设置 `scroll-snap-type`:** 如果用户在没有 `overflow: scroll` 或 `overflow: auto` 的元素上设置 `scroll-snap-type`，则滚动捕捉不会生效。`SnapCoordinator` 的测试会验证这种情况下的行为，可能不会创建任何滚动捕捉数据。

* **滚动捕捉区域的尺寸大于滚动容器:** 如果滚动捕捉区域的尺寸大于滚动容器的可视区域，可能会导致捕捉行为不符合预期。测试用例会涵盖不同尺寸的滚动捕捉区域，确保 `SnapCoordinator` 能正确处理。

* **忘记设置 `scroll-snap-align`:** 如果一个元素被包含在滚动捕捉容器中，但没有设置 `scroll-snap-align` 属性，则它不会被视为滚动捕捉区域。测试用例 `SimpleSnapElement` 确保了只有设置了 `scroll-snap-align` 的元素才会被识别。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中访问一个使用了 CSS Scroll Snap 的网页。**
2. **用户尝试滚动网页上的一个滚动容器。**
3. **浏览器的渲染引擎 (Blink) 在处理滚动事件时，会调用 `SnapCoordinator` 来确定最终的滚动位置。**
4. **如果滚动捕捉行为不符合预期，开发者可能会尝试调试。** 他们可能会：
   - **检查 CSS 样式:** 确认 `scroll-snap-type` 和 `scroll-snap-align` 属性是否正确设置。
   - **使用浏览器的开发者工具:** 查看元素的 Computed Style，确认滚动捕捉相关的属性是否生效。
   - **查看 Layout Tree:** 确认元素的布局是否符合预期，例如是否有正确的滚动容器。
   - **查看 Compositor Layers:**  在复杂的情况下，滚动捕捉可能涉及到合成层。
5. **如果问题涉及到 Blink 引擎内部的逻辑，开发者或 Chromium 贡献者可能会查看 `SnapCoordinator` 相关的代码，包括这个测试文件，来理解 `SnapCoordinator` 的行为和预期结果。** 这个测试文件可以帮助他们理解在各种情况下 `SnapCoordinator` 应该如何工作，从而定位 bug 的原因。例如，如果 fixed position 的元素被错误地识别为 snap area，那么 `PositionFixedSnapElement` 这个测试用例就能提供线索。

**功能归纳 (第1部分):**

这个测试文件的主要目的是验证 `SnapCoordinator` 类在处理 CSS Scroll Snap 功能时的核心逻辑，包括识别滚动捕捉容器和区域，处理不同类型的元素和布局，以及计算相关的几何数据。它确保了 Blink 引擎能够正确地实现和处理网页中定义的滚动捕捉行为。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/snap_coordinator_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"

#include <gtest/gtest.h>

#include <memory>

#include "cc/input/scroll_snap_data.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-shared.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/core/testing/scoped_mock_overlay_scrollbars.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

using html_names::kStyleAttr;

class SnapCoordinatorTest : public testing::Test,
                            public ScopedMockOverlayScrollbars {
 protected:
  void SetUp() override {
    page_holder_ = std::make_unique<DummyPageHolder>(
        gfx::Size(), nullptr, nullptr, WTF::BindOnce([](Settings& settings) {
          settings.SetAcceleratedCompositingEnabled(true);
        }));

    GetDocument().View()->SetParentVisible(true);
    GetDocument().View()->SetSelfVisible(true);

    SetHTML(R"HTML(
      <style>
          #snap-container {
              height: 1000px;
              width: 1000px;
              overflow: scroll;
              scroll-snap-type: both mandatory;
          }
          #snap-element-fixed-position {
               position: fixed;
          }
      </style>
      <body>
        <div id='snap-container'>
          <div id='snap-element'></div>
          <div id='intermediate'>
             <div id='nested-snap-element'></div>
          </div>
          <div id='snap-element-fixed-position'></div>
          <div style='width:2000px; height:2000px;'></div>
        </div>
      </body>
    )HTML");
    UpdateAllLifecyclePhasesForTest();
  }

  void TearDown() override { page_holder_ = nullptr; }

  Document& GetDocument() { return page_holder_->GetDocument(); }

  void SetHTML(const char* html_content) {
    GetDocument().documentElement()->setInnerHTML(html_content);
  }

  Element& SnapContainer() {
    return *GetDocument().getElementById(AtomicString("snap-container"));
  }

  unsigned SizeOfSnapAreas(const ContainerNode& node) {
    for (auto& fragment : node.GetLayoutBox()->PhysicalFragments()) {
      if (fragment.PropagatedSnapAreas()) {
        return 0u;
      }
      if (auto* snap_areas = fragment.SnapAreas()) {
        return snap_areas->size();
      }
    }
    return 0u;
  }

  bool IsUseCounted(mojom::WebFeature feature) {
    return GetDocument().IsUseCounted(feature);
  }

  void ClearUseCounter(mojom::WebFeature feature) {
    GetDocument().ClearUseCounterForTesting(feature);
    DCHECK(!IsUseCounted(feature));
  }

  void SetUpSingleSnapArea() {
    SetHTML(R"HTML(
      <style>
      #scroller {
        width: 140px;
        height: 160px;
        padding: 0px;
        scroll-snap-type: both mandatory;
        scroll-padding: 10px;
        overflow: scroll;
      }
      #container {
        margin: 0px;
        padding: 0px;
        width: 500px;
        height: 500px;
      }
      #area {
        position: relative;
        top: 200px;
        left: 200px;
        width: 100px;
        height: 100px;
        scroll-margin: 8px;
      }
      </style>
      <div id='scroller'>
        <div id='container'>
          <div id="area"></div>
        </div>
      </div>
      )HTML");
    UpdateAllLifecyclePhasesForTest();
  }

  void UpdateAllLifecyclePhasesForTest() {
    GetDocument().View()->UpdateAllLifecyclePhasesForTest();
  }

  const cc::SnapContainerData* GetSnapContainerData(LayoutBox& layout_box) {
    if (layout_box.GetScrollableArea()) {
      return layout_box.GetScrollableArea()->GetSnapContainerData();
    }
    return nullptr;
  }

  test::TaskEnvironment task_environment_;
  std::unique_ptr<DummyPageHolder> page_holder_;
};

TEST_F(SnapCoordinatorTest, SimpleSnapElement) {
  Element& snap_element =
      *GetDocument().getElementById(AtomicString("snap-element"));
  snap_element.setAttribute(kStyleAttr,
                            AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(1U, SizeOfSnapAreas(SnapContainer()));
}

TEST_F(SnapCoordinatorTest, NestedSnapElement) {
  Element& snap_element =
      *GetDocument().getElementById(AtomicString("nested-snap-element"));
  snap_element.setAttribute(kStyleAttr,
                            AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(1U, SizeOfSnapAreas(SnapContainer()));
}

TEST_F(SnapCoordinatorTest, ModifySnapElement) {
  Element& snap_element =
      *GetDocument().getElementById(AtomicString("snap-element"));
  snap_element.setAttribute(kStyleAttr,
                            AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();
  EXPECT_EQ(1U, SizeOfSnapAreas(SnapContainer()));

  snap_element.setAttribute(kStyleAttr,
                            AtomicString("scroll-snap-align: end;"));

  // Set scrollable area will set paint invalidation while scroll, will crash
  // if snap-element not set needs update.
  SnapContainer().GetLayoutBox()->SetShouldDoFullPaintInvalidation();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(1U, SizeOfSnapAreas(SnapContainer()));
}

TEST_F(SnapCoordinatorTest, NestedSnapElementCaptured) {
  Element& snap_element =
      *GetDocument().getElementById(AtomicString("nested-snap-element"));
  snap_element.setAttribute(kStyleAttr,
                            AtomicString("scroll-snap-align: start;"));

  Element* intermediate =
      GetDocument().getElementById(AtomicString("intermediate"));
  intermediate->setAttribute(kStyleAttr, AtomicString("overflow: scroll;"));

  UpdateAllLifecyclePhasesForTest();

  // Intermediate scroller captures nested snap elements first so ancestor
  // does not get them.
  EXPECT_EQ(0U, SizeOfSnapAreas(SnapContainer()));
  EXPECT_EQ(1U, SizeOfSnapAreas(*intermediate));
}

TEST_F(SnapCoordinatorTest, PositionFixedSnapElement) {
  Element& snap_element = *GetDocument().getElementById(
      AtomicString("snap-element-fixed-position"));
  snap_element.setAttribute(kStyleAttr,
                            AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  // Position fixed elements are contained in document and not its immediate
  // ancestor scroller. They cannot be a valid snap destination so they should
  // not contribute snap points to their immediate snap container or document
  // See: https://lists.w3.org/Archives/Public/www-style/2015Jun/0376.html
  EXPECT_EQ(0U, SizeOfSnapAreas(SnapContainer()));

  Element* body = GetDocument().ViewportDefiningElement();
  EXPECT_EQ(0U, SizeOfSnapAreas(*body));
}

TEST_F(SnapCoordinatorTest, UpdateStyleForSnapElement) {
  Element& snap_element =
      *GetDocument().getElementById(AtomicString("snap-element"));
  snap_element.setAttribute(kStyleAttr,
                            AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(1U, SizeOfSnapAreas(SnapContainer()));

  snap_element.remove();
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(0U, SizeOfSnapAreas(SnapContainer()));

  // Add a new snap element
  Element& container =
      *GetDocument().getElementById(AtomicString("snap-container"));
  container.setInnerHTML(R"HTML(
    <div style='scroll-snap-align: start;'>
        <div style='width:2000px; height:2000px;'></div>
    </div>
  )HTML");
  UpdateAllLifecyclePhasesForTest();

  EXPECT_EQ(1U, SizeOfSnapAreas(SnapContainer()));
}

TEST_F(SnapCoordinatorTest, ViewportScrollSnapStyleComesFromDocumentElement) {
  SetHTML(R"HTML(
    <style>
    :root {
      scroll-snap-type: both mandatory;
    }
    body {
     scroll-snap-type: none;
    }
    </style>
    <body>
      <div style='scroll-snap-align: start;'></div>
    </body>
    )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* body = GetDocument().body();
  EXPECT_EQ(body, GetDocument().ViewportDefiningElement());

  const cc::SnapContainerData* viewport_data =
      GetSnapContainerData(*GetDocument().GetLayoutView());
  EXPECT_TRUE(viewport_data);
  EXPECT_EQ(viewport_data->scroll_snap_type(),
            cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                               cc::SnapStrictness::kMandatory));

  const cc::SnapContainerData* body_data =
      GetSnapContainerData(*body->GetLayoutBox());

  EXPECT_FALSE(body_data);
}

TEST_F(SnapCoordinatorTest, LayoutViewCapturesWhenBodyElementViewportDefining) {
  SetHTML(R"HTML(
    <style>
    body {
        overflow: scroll;
        scroll-snap-type: both mandatory;
        height: 1000px;
        width: 1000px;
        margin: 5px;
    }
    </style>
    <body>
        <div id='snap-element' style='scroll-snap-align: start;></div>
        <div id='intermediate'>
            <div id='nested-snap-element'
                style='scroll-snap-align: start;'></div>
        </div>
        <div style='width:2000px; height:2000px;'></div>
    </body>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  // Sanity check that body is the viewport defining element
  EXPECT_EQ(GetDocument().body(), GetDocument().ViewportDefiningElement());

  // When body is viewport defining and overflows then any snap points on the
  // body element will be captured by layout view as the snap container.
  EXPECT_EQ(2U, SizeOfSnapAreas(GetDocument()));
  EXPECT_EQ(0U, SizeOfSnapAreas(*(GetDocument().body())));
  EXPECT_EQ(0U, SizeOfSnapAreas(*(GetDocument().documentElement())));
}

TEST_F(SnapCoordinatorTest,
       LayoutViewCapturesWhenDocumentElementViewportDefining) {
  SetHTML(R"HTML(
    <style>
    :root {
        overflow: scroll;
        scroll-snap-type: both mandatory;
        height: 500px;
        width: 500px;
    }
    body {
        margin: 5px;
    }
    </style>
    <html>
       <body>
           <div id='snap-element' style='scroll-snap-align: start;></div>
           <div id='intermediate'>
             <div id='nested-snap-element'
                 style='scroll-snap-align: start;'></div>
          </div>
          <div style='width:2000px; height:2000px;'></div>
       </body>
    </html>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  // Sanity check that document element is the viewport defining element
  EXPECT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());

  // When document is viewport defining and overflows then any snap points on
  // the document element will be captured by layout view as the snap
  // container.
  EXPECT_EQ(2U, SizeOfSnapAreas(GetDocument()));
  EXPECT_EQ(0U, SizeOfSnapAreas(*(GetDocument().body())));
  EXPECT_EQ(0U, SizeOfSnapAreas(*(GetDocument().documentElement())));
}

TEST_F(SnapCoordinatorTest,
       BodyCapturesWhenBodyOverflowAndDocumentElementViewportDefining) {
  SetHTML(R"HTML(
    <style>
    :root {
        overflow: scroll;
        scroll-snap-type: both mandatory;
        height: 500px;
        width: 500px;
    }
    body {
        overflow: scroll;
        scroll-snap-type: both mandatory;
        height: 1000px;
        width: 1000px;
        margin: 5px;
    }
    </style>
    <html>
       <body style='overflow: scroll; scroll-snap-type: both mandatory;
    height:1000px; width:1000px;'>
           <div id='snap-element' style='scroll-snap-align: start;></div>
           <div id='intermediate'>
             <div id='nested-snap-element'
                 style='scroll-snap-align: start;'></div>
          </div>
          <div style='width:2000px; height:2000px;'></div>
       </body>
    </html>
  )HTML");

  UpdateAllLifecyclePhasesForTest();

  // Sanity check that document element is the viewport defining element
  EXPECT_EQ(GetDocument().documentElement(),
            GetDocument().ViewportDefiningElement());

  // When body and document elements are both scrollable then body element
  // should capture snap points defined on it as opposed to layout view.
  Element& body = *GetDocument().body();
  EXPECT_EQ(2U, SizeOfSnapAreas(body));
  EXPECT_EQ(0U, SizeOfSnapAreas(*GetDocument().documentElement()));
  EXPECT_EQ(0U, SizeOfSnapAreas(GetDocument()));
}

#define EXPECT_EQ_CONTAINER(expected, actual)                          \
  {                                                                    \
    EXPECT_EQ(expected.max_position(), actual.max_position());         \
    EXPECT_EQ(expected.scroll_snap_type(), actual.scroll_snap_type()); \
    EXPECT_EQ(expected.proximity_range(), actual.proximity_range());   \
    EXPECT_EQ(expected.size(), actual.size());                         \
    EXPECT_EQ(expected.rect(), actual.rect());                         \
  }

#define EXPECT_EQ_AREA(expected, actual)                             \
  {                                                                  \
    EXPECT_EQ(expected.scroll_snap_align, actual.scroll_snap_align); \
    EXPECT_EQ(expected.rect, actual.rect);                           \
    EXPECT_EQ(expected.must_snap, actual.must_snap);                 \
  }

// The following tests check the SnapContainerData and SnapAreaData are
// correctly calculated.
TEST_F(SnapCoordinatorTest, SnapDataCalculation) {
  SetUpSingleSnapArea();
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  ScrollableArea* scrollable_area =
      scroller_element->GetLayoutBox()->GetScrollableArea();
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(kStyleAttr,
                             AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;
  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = scroller_element->clientWidth();
  double height = scroller_element->clientHeight();
  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(10, 10, width - 20, height - 20), max_position);
  cc::SnapAreaData expected_area(cc::ScrollSnapAlign(cc::SnapAlignment::kStart),
                                 gfx::RectF(192, 192, 116, 116), false, false,
                                 cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, ScrolledSnapDataCalculation) {
  SetUpSingleSnapArea();
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  ScrollableArea* scrollable_area =
      scroller_element->GetLayoutBox()->GetScrollableArea();
  scroller_element->scrollBy(20, 20);
  EXPECT_EQ(gfx::PointF(20, 20), scrollable_area->ScrollPosition());
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(kStyleAttr,
                             AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;
  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = scroller_element->clientWidth();
  double height = scroller_element->clientHeight();
  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(10, 10, width - 20, height - 20), max_position);
  cc::SnapAreaData expected_area(cc::ScrollSnapAlign(cc::SnapAlignment::kStart),
                                 gfx::RectF(192, 192, 116, 116), false, false,
                                 cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, ScrolledSnapDataCalculationOnViewport) {
  SetHTML(R"HTML(
    <style>
    :root {
      scroll-snap-type: both mandatory;
    }
    body {
      margin: 0px;
      overflow: scroll;
    }
    #container {
      width: 1000px;
      height: 1000px;
    }
    #area {
      position: relative;
      top: 200px;
      left: 200px;
      width: 100px;
      height: 100px;
    }
    </style>
    <div id='container'>
    <div id="area"></div>
    </div>
    )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* body = GetDocument().body();
  EXPECT_EQ(body, GetDocument().ViewportDefiningElement());
  ScrollableArea* scrollable_area = GetDocument().View()->LayoutViewport();
  body->scrollBy(20, 20);
  EXPECT_EQ(gfx::PointF(20, 20), scrollable_area->ScrollPosition());
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(kStyleAttr,
                             AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();
  const cc::SnapContainerData* data =
      GetSnapContainerData(*GetDocument().GetLayoutView());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;

  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = body->clientWidth();
  double height = body->clientHeight();
  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(0, 0, width, height), max_position);

  cc::SnapAreaData expected_area(cc::ScrollSnapAlign(cc::SnapAlignment::kStart),
                                 gfx::RectF(200, 200, 100, 100), false, false,
                                 cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, SnapDataCalculationWithBoxModel) {
  SetUpSingleSnapArea();
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(
      kStyleAttr, AtomicString("scroll-snap-align: start; margin: 2px; border: "
                               "9px solid; padding: 5px;"));
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  scroller_element->setAttribute(
      kStyleAttr,
      AtomicString("margin: 3px; border: 10px solid; padding: 4px;"));
  UpdateAllLifecyclePhasesForTest();
  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;

  ScrollableArea* scrollable_area =
      scroller_element->GetLayoutBox()->GetScrollableArea();
  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = scroller_element->clientWidth();
  double height = scroller_element->clientHeight();

  // rect.x = rect.y = scroller.border + scroller.scroll-padding
  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(20, 20, width - 20, height - 20), max_position);
  // rect.x = scroller.border + scroller.padding + area.left + area.margin
  //          - area.scroll-margin
  // rect.y = scroller.border + scroller.padding + area.top + area.margin
  //          - area.scroll-margin
  // rect.width = area.width +
  //              2 * (area.padding + area.border + area.scroll-margin)
  // rect.height = area.height +
  //               2 * (area.padding + area.border + area.scroll-margin)
  cc::SnapAreaData expected_area(cc::ScrollSnapAlign(cc::SnapAlignment::kStart),
                                 gfx::RectF(208, 208, 144, 144), false, false,
                                 cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, NegativeMarginSnapDataCalculation) {
  SetUpSingleSnapArea();
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(
      kStyleAttr,
      AtomicString("scroll-snap-align: start; scroll-margin: -8px;"));
  UpdateAllLifecyclePhasesForTest();
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;

  ScrollableArea* scrollable_area =
      scroller_element->GetLayoutBox()->GetScrollableArea();
  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = scroller_element->clientWidth();
  double height = scroller_element->clientHeight();

  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(10, 10, width - 20, height - 20), max_position);
  cc::SnapAreaData expected_area(cc::ScrollSnapAlign(cc::SnapAlignment::kStart),
                                 gfx::RectF(208, 208, 84, 84), false, false,
                                 cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, AsymmetricalSnapDataCalculation) {
  SetUpSingleSnapArea();
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(kStyleAttr, AtomicString(R"HTML(
        scroll-snap-align: center;
        scroll-margin-top: 2px;
        scroll-margin-right: 4px;
        scroll-margin-bottom: 6px;
        scroll-margin-left: 8px;
      )HTML"));
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  scroller_element->setAttribute(kStyleAttr, AtomicString(R"HTML(
        scroll-padding-top: 10px;
        scroll-padding-right: 12px;
        scroll-padding-bottom: 14px;
        scroll-padding-left: 16px;
      )HTML"));
  UpdateAllLifecyclePhasesForTest();
  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;

  ScrollableArea* scrollable_area =
      scroller_element->GetLayoutBox()->GetScrollableArea();
  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = scroller_element->clientWidth();
  double height = scroller_element->clientHeight();

  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(16, 10, width - 28, height - 24), max_position);
  cc::SnapAreaData expected_area(
      cc::ScrollSnapAlign(cc::SnapAlignment::kCenter),
      gfx::RectF(192, 198, 112, 108), false, false, cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, ScaledSnapDataCalculation) {
  SetUpSingleSnapArea();
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(
      kStyleAttr,
      AtomicString("scroll-snap-align: end; transform: scale(4, 4);"));
  UpdateAllLifecyclePhasesForTest();
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;

  ScrollableArea* scrollable_area =
      scroller_element->GetLayoutBox()->GetScrollableArea();
  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = scroller_element->clientWidth();
  double height = scroller_element->clientHeight();
  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(10, 10, width - 20, height - 20), max_position);

  // The area is scaled from center, so it pushes the area's top-left corner to
  // (50, 50).
  cc::SnapAreaData expected_area(cc::ScrollSnapAlign(cc::SnapAlignment::kEnd),
                                 gfx::RectF(42, 42, 416, 416), false, false,
                                 cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, VerticalRlSnapDataCalculation) {
  SetUpSingleSnapArea();
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(
      kStyleAttr, AtomicString("scroll-snap-align: start; left: -200px;"));
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  scroller_element->setAttribute(kStyleAttr,
                                 AtomicString("writing-mode: vertical-rl;"));
  UpdateAllLifecyclePhasesForTest();
  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
  cc::SnapContainerData actual_container = *data;

  ScrollableArea* scrollable_area =
      scroller_element->GetLayoutBox()->GetScrollableArea();
  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());

  double width = scroller_element->clientWidth();
  double height = scroller_element->clientHeight();

  cc::SnapContainerData expected_container(
      cc::ScrollSnapType(false, cc::SnapAxis::kBoth,
                         cc::SnapStrictness::kMandatory),
      gfx::RectF(10, 10, width - 20, height - 20), max_position);
  // Under vertical-rl writing mode, 'start' should align to the right
  // and 'end' should align to the left.
  cc::SnapAreaData expected_area(
      cc::ScrollSnapAlign(cc::SnapAlignment::kStart, cc::SnapAlignment::kEnd),
      gfx::RectF(192, 192, 116, 116), false, false, cc::ElementId(10));
  expected_container.AddSnapAreaData(expected_area);

  EXPECT_EQ_CONTAINER(expected_container, actual_container);
  EXPECT_EQ_AREA(expected_area, actual_container.at(0));
}

TEST_F(SnapCoordinatorTest, ChangeOverflowToVisible) {
  SetUpSingleSnapArea();

  // Ensure we have at least one snap-area.
  GetDocument()
      .getElementById(AtomicString("area"))
      ->setAttribute(kStyleAttr, AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  const cc::SnapContainerData* data =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);

  // Scroller should no longer be considered a snap container
  scroller_element->setAttribute(kStyleAttr,
                                 AtomicString("overflow : visible"));
  UpdateAllLifecyclePhasesForTest();
  data = GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_FALSE(data);

  // Scroller should be considered a snap container again
  scroller_element->setAttribute(kStyleAttr, AtomicString("overflow : scroll"));
  UpdateAllLifecyclePhasesForTest();
  data = GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data);
}

TEST_F(SnapCoordinatorTest, CurrentSnappedAreaRemoved) {
  SetUpSingleSnapArea();
  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(kStyleAttr,
                             AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();
  scroller_element->scrollTo(250, 250);
  UpdateAllLifecyclePhasesForTest();

  const cc::SnapContainerData* data_ptr =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data_ptr);
  cc::SnapContainerData data = *data_ptr;
  cc::TargetSnapAreaElementIds expected_snap_targets(data.at(0).element_id,
                                                     data.at(0).element_id);
  EXPECT_TRUE(expected_snap_targets.x);
  EXPECT_EQ(expected_snap_targets, data.GetTargetSnapAreaElementIds());

  area_element->setAttribute(kStyleAttr,
                             AtomicString("scroll-snap-align: none;"));
  UpdateAllLifecyclePhasesForTest();

  // Removing a snap area should also remove it as the target snap area.
  data_ptr = GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data_ptr);
  data = *data_ptr;
  EXPECT_EQ(cc::TargetSnapAreaElementIds(), data.GetTargetSnapAreaElementIds());
}

TEST_F(SnapCoordinatorTest, AddingSnapAreaDoesNotRemoveCurrentSnapTarget) {
  // Set up 2 areas. Mark the other as a snap area later.
  SetHTML(R"HTML(
      <style>
      #scroller {
        width: 140px;
        height: 160px;
        padding: 0px;
        scroll-snap-type: both mandatory;
        scroll-padding: 10px;
        overflow: scroll;
      }
      #container {
        margin: 0px;
        padding: 0px;
        width: 500px;
        height: 500px;
      }
      #area {
        position: relative;
        top: 200px;
        left: 200px;
        width: 100px;
        height: 100px;
        scroll-margin: 8px;
      }
      #area2 {
        position: relative;
        top: 400px;
        left: 400px;
        width: 100px;
        height: 100px;
        scroll-margin: 8px;
      }
      </style>
      <div id='scroller'>
        <div id='container'>
          <div id="area"></div>
          <div id="area2"></div>
        </div>
      </div>
      )HTML");
  UpdateAllLifecyclePhasesForTest();

  Element* scroller_element =
      GetDocument().getElementById(AtomicString("scroller"));
  Element* area_element = GetDocument().getElementById(AtomicString("area"));
  area_element->setAttribute(kStyleAttr,
                             AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();
  scroller_element->scrollTo(250, 250);
  UpdateAllLifecyclePhasesForTest();

  const cc::SnapContainerData* data_ptr =
      GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data_ptr);
  cc::SnapContainerData data = *data_ptr;
  cc::TargetSnapAreaElementIds expected_snap_targets(data.at(0).element_id,
                                                     data.at(0).element_id);
  EXPECT_TRUE(expected_snap_targets.x);
  EXPECT_EQ(expected_snap_targets, data.GetTargetSnapAreaElementIds());

  Element* area2_element = GetDocument().getElementById(AtomicString("area2"));
  area2_element->setAttribute(kStyleAttr,
                              AtomicString("scroll-snap-align: start;"));
  UpdateAllLifecyclePhasesForTest();

  // Adding another snap area should not affect the current snapped target.
  data_ptr = GetSnapContainerData(*scroller_element->GetLayoutBox());
  EXPECT_TRUE(data_ptr);
  data = *data_ptr;
  EXPECT_EQ(expected_snap_targets, data.GetTargetSnapAreaElementIds());
}

TES
"""


```