Response:
Let's break down the thought process for analyzing the `snap_coordinator.cc` file.

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to web technologies, logical reasoning, common errors, and debugging tips. Essentially, a comprehensive overview from a developer's perspective.

2. **Initial Scan and Keyword Recognition:**  Quickly read through the code, looking for key terms related to scrolling, snapping, layout, and CSS properties. Words like `SnapCoordinator`, `ScrollSnapType`, `ScrollSnapAlign`, `snap_container`, `snap_area`, `scrollPadding`, `scrollMargin`, `LayoutBox`, `Element`, `ComputedStyle`, etc., stand out. These give a strong indication of the file's purpose.

3. **Identify Core Functionality - `UpdateSnapContainerData`:** The function `UpdateSnapContainerData` is the most significant in terms of understanding the overall logic. It takes a `LayoutBox` (the scroll container) as input and seems to calculate and update data related to scroll snapping. The presence of `GetPhysicalSnapType`, calculations involving padding, margins, and the iteration through `snap_area` elements within the container confirms this.

4. **Dissect `UpdateSnapContainerData`:**
    * **Input:** A `LayoutBox` representing a scroll container.
    * **Purpose:** To gather and update information necessary for scroll snapping on this container.
    * **Key Steps:**
        * Retrieve the `ScrollableArea` associated with the container.
        * Get the `scroll-snap-type` CSS property.
        * Early exit if `scroll-snap-type` is `none`.
        * Create a `cc::SnapContainerData` object to hold the information.
        * Calculate the maximum scroll position.
        * Calculate the effective scrollport rectangle, considering `scroll-padding`.
        * Iterate through child elements (`snap_area`) that are potential snap points.
        * For each snap area, calculate `cc::SnapAreaData` using `CalculateSnapAreaData`.
        * Store the calculated data in the `SnapContainerData` object.
        * Compare the new data with the old data and update if there are changes.
    * **Output:** Returns `true` if the snap container data was updated, `false` otherwise.

5. **Analyze `CalculateSnapAreaData`:** This function is responsible for calculating the properties of individual snap areas within a container.
    * **Input:** A snap area `Element` and the `LayoutBox` of the snap container.
    * **Purpose:** To determine the snap area's geometry, alignment, and other relevant properties for snapping.
    * **Key Steps:**
        * Get the `ComputedStyle` for both the snap area and the container.
        * Determine the bounding box of the snap area relative to the container, handling both regular elements and `::column` pseudo-elements.
        * Account for `scroll-margin`.
        * Calculate the physical alignment using `GetPhysicalAlignment`.
        * Check if the `scroll-snap-stop` property is set to `always`.
        * Determine if the snap area has focus within it.
        * Obtain the compositor element ID.
    * **Output:** A `cc::SnapAreaData` object containing the calculated information.

6. **Understand the Helper Functions:** Briefly understand the purpose of functions like `GetPhysicalSnapType` and `GetPhysicalAlignment`. They deal with mapping logical CSS properties to physical layout based on writing modes and container/area sizes.

7. **Relate to Web Technologies:** Connect the code to CSS properties (`scroll-snap-type`, `scroll-snap-align`, `scroll-padding`, `scroll-margin`, `scroll-snap-stop`), HTML elements (acting as scroll containers and snap areas), and JavaScript (for potential dynamic manipulation or triggering of scrolling).

8. **Consider Logical Reasoning (Input/Output):** Think about specific scenarios and what the code would do. For example, if a container has `scroll-snap-type: x mandatory;` and child elements with `scroll-snap-align: start;`, the code will identify these snap points and the scrolling will "snap" to the beginning of these elements.

9. **Identify Potential Errors:** Think about common mistakes developers might make when using scroll snapping, such as incorrect property values, overlapping snap areas, or forgetting to define a snap container.

10. **Outline Debugging Steps:**  Consider how a developer might trace the execution of this code. What user actions lead to this code being executed?  This helps in providing debugging guidance.

11. **Structure the Answer:** Organize the findings into logical sections: functionality, relation to web technologies, logical reasoning, common errors, and debugging. Use clear and concise language, providing examples where appropriate.

12. **Review and Refine:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any jargon that needs explanation and make sure the examples are helpful. For instance, I initially focused heavily on just describing the functions. Then I realized the request explicitly asked for how this connects to HTML, CSS, and JavaScript, so I added more details and examples in those sections. I also made sure to explicitly link user actions to the code execution for debugging.
好的，让我们详细分析一下 `blink/renderer/core/page/scrolling/snap_coordinator.cc` 文件的功能。

**文件功能概述:**

`snap_coordinator.cc` 文件的核心职责是管理和计算与 CSS Scroll Snap 功能相关的逻辑。它负责识别页面上的滚动容器和滚动捕捉点（snap areas），并计算它们的位置、对齐方式等信息，以便浏览器在滚动操作完成后能够将滚动位置“捕捉”到预定义的点上。

**具体功能分解:**

1. **识别滚动捕捉容器 (Snap Container):**  该文件中的代码会检查页面上的 `LayoutBox` 对象，判断哪些是滚动捕捉容器。一个元素成为滚动捕捉容器的条件是其 CSS 样式中设置了 `scroll-snap-type` 属性。

2. **识别滚动捕捉区域 (Snap Area):**  在滚动捕捉容器内部，该文件会识别哪些元素是滚动捕捉区域。一个元素成为滚动捕捉区域的条件是其 CSS 样式中设置了 `scroll-snap-align` 属性。

3. **计算捕捉容器数据 (`UpdateSnapContainerData`):**
   -  这个函数是核心，负责收集和更新滚动捕捉容器的相关数据。
   -  **获取 `scroll-snap-type`:**  读取容器的 `scroll-snap-type` 属性，确定捕捉的严格程度（`mandatory` 或 `proximity`）和轴向（`x`, `y`, `both`）。
   -  **处理 `scroll-padding`:** 考虑容器的 `scroll-padding` 属性，定义了滚动端口（scrollport）的内边距，影响捕捉点的计算。
   -  **计算最大滚动位置:** 获取滚动容器的最大滚动范围。
   -  **迭代捕捉区域:** 遍历容器内的所有子元素，找到设置了 `scroll-snap-align` 的元素，即滚动捕捉区域。
   -  **计算捕捉区域数据 (`CalculateSnapAreaData`):**  对于每个捕捉区域，计算其详细信息：
      -  **位置和大小:** 获取捕捉区域相对于滚动捕捉容器的位置和尺寸。
      -  **`scroll-snap-align`:** 读取捕捉区域的 `scroll-snap-align` 属性，确定捕捉点在区域内的对齐方式（`start`, `end`, `center`）。
      -  **`scroll-margin`:** 考虑捕捉区域的 `scroll-margin` 属性，定义了捕捉区域的外边距，影响捕捉点的计算。
      -  **`scroll-snap-stop`:** 读取捕捉区域的 `scroll-snap-stop` 属性，确定滚动是否必须在此捕捉点停止。
      -  **焦点状态:** 检查捕捉区域是否包含焦点。
      -  **元素ID:** 获取捕捉区域元素的 CompositorElementId。
   -  **存储数据:** 将计算出的捕捉容器和捕捉区域数据存储起来，供后续滚动处理使用。
   -  **比较新旧数据:** 检查捕捉容器的数据是否有变化，如果有变化会触发重绘等操作。

4. **处理书写模式 (Writing Mode):**  代码中考虑了不同的书写模式（例如，从右到左的 RTL 布局），并调整捕捉对齐方式以适应这些模式。例如，`AdjustForRtlWritingMode` 函数会将 `start` 对齐转换为 `end` 对齐。

5. **计算物理对齐方式 (`GetPhysicalAlignment`):**  根据捕捉区域和捕捉容器的样式以及布局信息，将逻辑上的对齐方式（`start`, `end`）转换为物理上的对齐方式（例如，左对齐或右对齐）。

**与 JavaScript, HTML, CSS 的关系:**

这个文件是 Chromium 渲染引擎的一部分，直接响应和处理 HTML 结构和 CSS 样式。

* **HTML:**  HTML 元素作为滚动捕捉容器和滚动捕捉区域。例如：
  ```html
  <div style="overflow: auto; scroll-snap-type: y mandatory;">
    <div style="height: 200px; scroll-snap-align: start;">Section 1</div>
    <div style="height: 200px; scroll-snap-align: start;">Section 2</div>
  </div>
  ```
  在这个例子中，外层的 `div` 是滚动捕捉容器，内层的两个 `div` 是滚动捕捉区域。

* **CSS:**  CSS 属性 `scroll-snap-type`, `scroll-snap-align`, `scroll-padding`, `scroll-margin`, `scroll-snap-stop` 直接控制着滚动捕捉的行为。`snap_coordinator.cc` 的代码会解析这些 CSS 属性的值并根据其进行计算。

* **JavaScript:** JavaScript 可以用来动态地修改 CSS 属性，从而影响滚动捕捉的行为。例如，可以使用 JavaScript 来添加或移除 `scroll-snap-align` 属性，或者动态地更改 `scroll-padding` 的值。当 JavaScript 修改这些样式时，渲染引擎会重新计算滚动捕捉数据，`snap_coordinator.cc` 的代码会被再次调用。

**逻辑推理 (假设输入与输出):**

**假设输入 1:**

```html
<div style="width: 300px; height: 200px; overflow-x: auto; scroll-snap-type: x mandatory;">
  <div style="width: 100%; height: 100%; scroll-snap-align: start;">Item 1</div>
  <div style="width: 100%; height: 100%; scroll-snap-align: start;">Item 2</div>
  <div style="width: 100%; height: 100%; scroll-snap-align: start;">Item 3</div>
</div>
```

**预期输出 1:**

`SnapCoordinator` 会识别外层的 `div` 作为横向滚动捕捉容器，并识别三个内层的 `div` 作为捕捉区域。计算出的捕捉点将位于每个子元素的左边缘。当用户水平滚动时，滚动会自动停止在每个子元素的开始位置。

**假设输入 2:**

```html
<div style="width: 200px; height: 300px; overflow-y: auto; scroll-snap-type: y proximity;">
  <div style="height: 100px;"></div>
  <div style="height: 100px; scroll-snap-align: center;">Item A</div>
  <div style="height: 100px;"></div>
  <div style="height: 100px; scroll-snap-align: center;">Item B</div>
  <div style="height: 100px;"></div>
</div>
```

**预期输出 2:**

`SnapCoordinator` 会识别外层的 `div` 作为纵向滚动捕捉容器，并识别 "Item A" 和 "Item B" 所在的 `div` 作为捕捉区域。由于 `scroll-snap-type` 是 `proximity`，滚动捕捉的严格程度较低。当用户垂直滚动时，如果在滚动结束时，滚动位置足够接近捕捉区域的中心，则滚动会捕捉到中心位置。

**用户或编程常见的使用错误:**

1. **忘记设置 `scroll-snap-type`:**  如果滚动容器没有设置 `scroll-snap-type` 属性，`SnapCoordinator` 不会将其视为滚动捕捉容器，因此内部的 `scroll-snap-align` 属性不会生效。
   ```html
   <!-- 错误：缺少 scroll-snap-type -->
   <div style="overflow: auto;">
     <div style="height: 200px; scroll-snap-align: start;">Section</div>
   </div>
   ```

2. **捕捉区域尺寸大于捕捉容器:** 如果捕捉区域的尺寸大于捕捉容器的尺寸，可能会导致意料之外的捕捉行为。例如，如果一个全屏的 `div` 被设置为捕捉区域，那么滚动可能无法捕捉到任何特定的点。代码中使用了 `WebFeature::kScrollSnapCoveringSnapArea` 来记录这种情况。

3. **`scroll-snap-align` 值错误:**  `scroll-snap-align` 属性的值必须是 `start`, `end`, `center`, `none` 中的一个或两个（分别用于水平和垂直方向）。使用其他值会导致浏览器忽略该属性。

4. **误解 `mandatory` 和 `proximity` 的区别:**  `mandatory` 意味着滚动必须停止在捕捉点上，而 `proximity` 意味着只有当滚动停止时足够接近捕捉点时才会发生捕捉。混淆这两者可能导致用户体验不佳。

5. **忽略 `scroll-padding` 和 `scroll-margin`:** 没有正确设置或理解 `scroll-padding` 和 `scroll-margin` 可能导致捕捉点的位置不符合预期，尤其是当滚动容器有内边距或捕捉区域有外边距时。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户加载包含滚动捕捉的网页:**  当用户在浏览器中打开一个包含使用了 CSS Scroll Snap 功能的网页时，渲染引擎开始解析 HTML 和 CSS。

2. **样式计算和布局:**  渲染引擎的样式计算模块会解析 CSS 规则，包括 `scroll-snap-type` 和 `scroll-snap-align` 等属性。布局模块会根据计算出的样式信息构建布局树，确定元素的位置和大小。在这个阶段，`snap_coordinator.cc` 中 `UpdateSnapContainerData` 函数可能会被调用，用于初始化或更新滚动捕捉容器的数据。

3. **用户执行滚动操作:**  当用户在支持滚动捕捉的元素上进行滚动操作（例如，使用鼠标滚轮、触摸滑动、键盘操作）时，滚动事件会被触发。

4. **滚动处理和捕捉逻辑:**  在滚动处理过程中，`snap_coordinator.cc` 中的代码会参与到滚动捕捉的逻辑中。
   -  当滚动即将结束时，浏览器会检查滚动容器是否是滚动捕捉容器。
   -  如果是，它会查找附近的滚动捕捉区域。
   -  根据 `scroll-snap-type` 的值，浏览器会决定是否需要将滚动位置调整到最近的捕捉点。
   -  `CalculateSnapAreaData` 函数会被用来获取捕捉区域的精确位置和对齐方式。

5. **滚动完成和动画:**  如果需要进行捕捉，浏览器会平滑地将滚动位置动画到目标捕捉点。

**调试线索:**

* **断点调试:**  在 `snap_coordinator.cc` 的 `UpdateSnapContainerData` 和 `CalculateSnapAreaData` 函数中设置断点，可以观察滚动捕捉数据的计算过程，查看哪些元素被识别为滚动捕捉容器和捕捉区域，以及它们的属性值。

* **日志输出:**  可以在代码中添加日志输出语句，打印关键变量的值，例如 `scroll-snap-type` 的值、捕捉区域的位置和对齐方式等。

* **Layout Tree Inspector:** 使用 Chromium 的开发者工具中的 Layout Tree Inspector 可以查看元素的布局信息，包括是否是滚动捕捉容器以及相关的属性。

* **Performance 面板:** 检查滚动操作时的性能，看是否有过多的布局或重绘，这可能与滚动捕捉的计算有关。

* **UseCounters:**  代码中使用了 `UseCounter` 来统计 `WebFeature::kScrollSnapCoveringSnapArea` 的使用情况，这可以帮助开发者了解是否存在捕捉区域尺寸大于捕捉容器的情况。

通过以上分析，我们可以看到 `snap_coordinator.cc` 文件在 Chromium 渲染引擎中扮演着关键角色，负责实现 CSS Scroll Snap 功能的核心逻辑。理解其功能有助于我们更好地开发和调试与滚动捕捉相关的网页。

Prompt: 
```
这是目录为blink/renderer/core/page/scrolling/snap_coordinator.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/scrolling/snap_coordinator.h"

#include "third_party/blink/renderer/core/dom/column_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/layout/geometry/box_strut.h"
#include "third_party/blink/renderer/core/layout/layout_block.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/platform/geometry/length_functions.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "ui/gfx/geometry/quad_f.h"

namespace blink {
namespace {
// This is experimentally determined and corresponds to the UA decided
// parameter as mentioned in spec.
// If changing this, consider modifying the following tests:
// - web_tests/fast/scrolling/area-at-exact-proximity-range-doesnt-crash.html
// - web_tests/fast/scroll-snap/scroll-snap-proximity-gesture.html
// accordingly.
constexpr float kProximityRatio = 1.0 / 3.0;

cc::SnapAlignment AdjustForRtlWritingMode(cc::SnapAlignment align) {
  if (align == cc::SnapAlignment::kStart)
    return cc::SnapAlignment::kEnd;

  if (align == cc::SnapAlignment::kEnd)
    return cc::SnapAlignment::kStart;

  return align;
}

// Snap types are categorized according to the spec
// https://drafts.csswg.org/css-scroll-snap-1/#snap-axis
cc::ScrollSnapType GetPhysicalSnapType(const LayoutBox& snap_container) {
  cc::ScrollSnapType scroll_snap_type =
      snap_container.Style()->GetScrollSnapType();
  if (scroll_snap_type.axis == cc::SnapAxis::kInline) {
    if (snap_container.Style()->IsHorizontalWritingMode())
      scroll_snap_type.axis = cc::SnapAxis::kX;
    else
      scroll_snap_type.axis = cc::SnapAxis::kY;
  }
  if (scroll_snap_type.axis == cc::SnapAxis::kBlock) {
    if (snap_container.Style()->IsHorizontalWritingMode())
      scroll_snap_type.axis = cc::SnapAxis::kY;
    else
      scroll_snap_type.axis = cc::SnapAxis::kX;
  }
  // Writing mode does not affect the cases where axis is kX, kY or kBoth.
  return scroll_snap_type;
}

}  // namespace
// TODO(sunyunjia): Move the static functions to an anonymous namespace.

// static
bool SnapCoordinator::UpdateSnapContainerData(LayoutBox& snap_container) {
  ScrollableArea* scrollable_area =
      ScrollableArea::GetForScrolling(&snap_container);
  const auto* old_snap_container_data = scrollable_area->GetSnapContainerData();
  auto snap_type = GetPhysicalSnapType(snap_container);

  // Scrollers that don't have any snap areas assigned to them and don't snap
  // require no further processing. These are the most common types and thus
  // returning as early as possible ensures efficiency.
  if (snap_type.is_none) {
    // Clear the old data if needed.
    if (old_snap_container_data) {
      snap_container.SetNeedsPaintPropertyUpdate();
      scrollable_area->SetScrollsnapchangingTargetIds(std::nullopt);
      scrollable_area->SetScrollsnapchangeTargetIds(std::nullopt);
      scrollable_area->SetSnappedQueryTargetIds(std::nullopt);
      if (RuntimeEnabledFeatures::CSSScrollSnapChangeEventEnabled()) {
        scrollable_area->EnqueueScrollSnapChangeEvent();
      }
      scrollable_area->SetSnapContainerData(std::nullopt);
    }
    return false;
  }

  cc::SnapContainerData snap_container_data(snap_type);

  gfx::PointF max_position = scrollable_area->ScrollOffsetToPosition(
      scrollable_area->MaximumScrollOffset());
  snap_container_data.set_max_position(max_position);
  snap_container_data.set_targeted_area_id(
      scrollable_area->GetTargetedSnapAreaId());

  // Scroll-padding represents inward offsets from the corresponding edge of
  // the scrollport.
  // https://drafts.csswg.org/css-scroll-snap-1/#scroll-padding Scrollport is
  // the visual viewport of the scroll container (through which the scrollable
  // overflow region can be viewed) coincides with its padding box.
  // https://drafts.csswg.org/css-overflow-3/#scrollport. So we use the
  // PhysicalRect of the padding box here. The coordinate is relative to the
  // container's border box.
  PhysicalRect container_rect(
      snap_container.OverflowClipRect(PhysicalOffset()));

  const ComputedStyle* container_style = snap_container.Style();
  // The percentage of scroll-padding is different from that of normal
  // padding, as scroll-padding resolves the percentage against corresponding
  // dimension of the scrollport[1], while the normal padding resolves that
  // against "width".[2,3] We use MinimumValueForLength here to ensure kAuto
  // is resolved to LayoutUnit() which is the correct behavior for padding.
  //
  // [1] https://drafts.csswg.org/css-scroll-snap-1/#scroll-padding
  //     "relative to the corresponding dimension of the scroll container’s
  //      scrollport"
  // [2] https://drafts.csswg.org/css-box/#padding-props
  // [3] See for example LayoutBoxModelObject::ComputedCSSPadding where it
  //     uses |MinimumValueForLength| but against the "width".
  container_rect.ContractEdges(
      MinimumValueForLength(container_style->ScrollPaddingTop(),
                            container_rect.Height()),
      MinimumValueForLength(container_style->ScrollPaddingRight(),
                            container_rect.Width()),
      MinimumValueForLength(container_style->ScrollPaddingBottom(),
                            container_rect.Height()),
      MinimumValueForLength(container_style->ScrollPaddingLeft(),
                            container_rect.Width()));
  snap_container_data.set_rect(gfx::RectF(container_rect));
  snap_container_data.set_has_horizontal_writing_mode(
      container_style->IsHorizontalWritingMode());

  if (snap_container_data.scroll_snap_type().strictness ==
      cc::SnapStrictness::kProximity) {
    PhysicalSize size = container_rect.size;
    size.Scale(kProximityRatio);
    gfx::PointF range(size.width.ToFloat(), size.height.ToFloat());
    snap_container_data.set_proximity_range(range);
  }

  cc::TargetSnapAreaElementIds new_target_ids;
  const cc::TargetSnapAreaElementIds old_target_ids =
      old_snap_container_data
          ? old_snap_container_data->GetTargetSnapAreaElementIds()
          : cc::TargetSnapAreaElementIds();

  for (auto& fragment : snap_container.PhysicalFragments()) {
    if (auto* snap_areas = fragment.SnapAreas()) {
      for (Element* snap_area : *snap_areas) {
        cc::SnapAreaData snap_area_data =
            CalculateSnapAreaData(*snap_area, snap_container);
        // The target snap elements should be preserved in the new container
        // only if the respective snap areas are still present.
        if (old_target_ids.x == snap_area_data.element_id) {
          new_target_ids.x = old_target_ids.x;
        }
        if (old_target_ids.y == snap_area_data.element_id) {
          new_target_ids.y = old_target_ids.y;
        }

        if (snap_area_data.rect.width() > snap_container_data.rect().width() ||
            snap_area_data.rect.height() >
                snap_container_data.rect().height()) {
          snap_container.GetDocument().CountUse(
              WebFeature::kScrollSnapCoveringSnapArea);
        }
        snap_container_data.AddSnapAreaData(snap_area_data);
      }
    }
  }

  snap_container_data.SetTargetSnapAreaElementIds(new_target_ids);

  if (!old_snap_container_data ||
      *old_snap_container_data != snap_container_data) {
    snap_container.SetNeedsPaintPropertyUpdate();
    scrollable_area->SetSnapContainerData(snap_container_data);
    return true;
  }
  return false;
}

// https://drafts.csswg.org/css-scroll-snap-1/#scroll-snap-align
// After normalization:
//   * inline corresponds to x, and block corresponds to y
//   * start corresponds to left or top
//   * end corresponds to right or bottom
// In other words, the adjusted logical properties map to a physical layout
// as if the writing mode were horizontal left to right and top to bottom.
static cc::ScrollSnapAlign GetPhysicalAlignment(
    const ComputedStyle& area_style,
    const ComputedStyle& container_style,
    const PhysicalRect& area_rect,
    const PhysicalRect& container_rect) {
  cc::ScrollSnapAlign align = area_style.GetScrollSnapAlign();
  cc::ScrollSnapAlign adjusted_alignment;
  // Start and end alignments are resolved with respect to the writing mode of
  // the snap container unless the scroll snap area is larger than the snapport,
  // in which case they are resolved with respect to the writing mode of the box
  // itself. (This allows items in a container to have consistent snap alignment
  // in general, while ensuring that start always aligns the item to allow
  // reading its contents from the beginning.)
  WritingDirectionMode writing_direction =
      container_style.GetWritingDirection();
  WritingDirectionMode area_writing_direction =
      area_style.GetWritingDirection();
  if (area_writing_direction.IsHorizontal()) {
    if (area_rect.Width() > container_rect.Width())
      writing_direction = area_writing_direction;
  } else {
    if (area_rect.Height() > container_rect.Height())
      writing_direction = area_writing_direction;
  }

  bool rtl = (writing_direction.IsRtl());
  if (writing_direction.IsHorizontal()) {
    adjusted_alignment.alignment_inline =
        rtl ? AdjustForRtlWritingMode(align.alignment_inline)
            : align.alignment_inline;
    adjusted_alignment.alignment_block = align.alignment_block;
  } else {
    bool flipped = writing_direction.IsFlippedBlocks();
    adjusted_alignment.alignment_inline =
        flipped ? AdjustForRtlWritingMode(align.alignment_block)
                : align.alignment_block;
    adjusted_alignment.alignment_block =
        rtl ? AdjustForRtlWritingMode(align.alignment_inline)
            : align.alignment_inline;
  }
  return adjusted_alignment;
}

// static
cc::SnapAreaData SnapCoordinator::CalculateSnapAreaData(
    Element& snap_area,
    const LayoutBox& snap_container) {
  const ComputedStyle* container_style = snap_container.Style();
  const ComputedStyle* area_style = snap_area.GetComputedStyle();
  cc::SnapAreaData snap_area_data;

  // Calculate the bounding box of all fragments generated by `snap_area`,
  // relatively to `snap_container`.
  const MapCoordinatesFlags mapping_mode =
      kTraverseDocumentBoundaries | kIgnoreScrollOffset;
  Vector<gfx::QuadF> quads;
  if (const LayoutBox* box = snap_area.GetLayoutBox()) {
    box->QuadsInAncestor(quads, &snap_container, mapping_mode);
  } else {
    // Since there's no layout object associated, this has to be a snap area for
    // a ::column pseudo-element.
    const auto& column_pseudo = To<ColumnPseudoElement>(snap_area);
    const auto* multicol_box = DynamicTo<LayoutBox>(
        column_pseudo.UltimateOriginatingElement()->GetLayoutObject());
    DCHECK(multicol_box->IsFragmentationContextRoot());
    quads.push_back(multicol_box->LocalRectToAncestorQuad(
        column_pseudo.ColumnRect(), &snap_container, mapping_mode));
  }

  PhysicalRect area_rect;
  for (const gfx::QuadF& quad : quads) {
    area_rect.UniteIfNonZero(PhysicalRect::EnclosingRect(quad.BoundingBox()));
  }

  PhysicalBoxStrut area_margin(
      area_style->ScrollMarginTop(), area_style->ScrollMarginRight(),
      area_style->ScrollMarginBottom(), area_style->ScrollMarginLeft());
  area_rect.Expand(area_margin);
  snap_area_data.rect = gfx::RectF(area_rect);

  PhysicalRect container_rect = snap_container.PhysicalBorderBoxRect();

  snap_area_data.scroll_snap_align = GetPhysicalAlignment(
      *area_style, *container_style, area_rect, container_rect);

  snap_area_data.must_snap =
      (area_style->ScrollSnapStop() == EScrollSnapStop::kAlways);

  snap_area_data.has_focus_within = snap_area.HasFocusWithin();

  snap_area_data.element_id =
      CompositorElementIdFromDOMNodeId(snap_area.GetDomNodeId());

  return snap_area_data;
}

}  // namespace blink

"""

```