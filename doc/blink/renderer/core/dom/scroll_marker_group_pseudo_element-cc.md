Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a comprehensive analysis of the `scroll_marker_group_pseudo_element.cc` file in the Chromium Blink engine. This includes its functionality, relationships with web technologies (JavaScript, HTML, CSS), logical reasoning, potential user errors, and how a user might trigger this code.

2. **Initial Code Scan and Keyword Identification:** I'll first read through the code, looking for key terms and patterns. Keywords like `ScrollMarkerPseudoElement`, `focus_group_`, `selected_marker_`, `ScrollIntoView`, `PseudoElement`, and concepts like "focus," "selection," and "scrolling" stand out. The namespace `blink` immediately tells me this is part of the Blink rendering engine.

3. **Core Functionality Identification:** Based on the keywords and the overall structure, I can infer the primary purpose of this class: to manage a group of scroll markers. These markers likely represent points of interest within a scrollable container. The class seems responsible for:
    * **Organization:** Maintaining a group of `ScrollMarkerPseudoElement` instances (`focus_group_`).
    * **Navigation:** Allowing navigation between these markers (using `FindNextScrollMarker`, `FindPreviousScrollMarker`).
    * **Selection:** Keeping track of the currently selected marker (`selected_marker_`).
    * **Activation:**  Triggering scrolling to a specific marker (`ActivateScrollMarker`, `ScrollIntoViewNoVisualUpdate`).
    * **Synchronization:** Updating the selected marker based on the current scroll position (`UpdateSelectedScrollMarker`).

4. **Relationship to Web Technologies:**
    * **CSS:** The class deals with pseudo-elements (`PseudoElement`). This immediately links it to CSS. The file itself doesn't *parse* CSS, but it *reacts* to CSS-driven features, specifically scroll-snap and potentially scrollbar customization (where these markers might visually appear). The `::` syntax for pseudo-elements is crucial here.
    * **HTML:** The originating element (`originating_element`) ties this to the HTML structure. The scroll markers relate to elements within the HTML content.
    * **JavaScript:**  While the C++ code itself doesn't *directly* interact with JS, it provides functionality that JavaScript *could* potentially trigger or interact with. For example, JavaScript could programmatically scroll a container, which would indirectly trigger the logic in `UpdateSelectedScrollMarker`. Accessibility features or custom scrollbar implementations might use JavaScript to manipulate focus or trigger actions related to these markers.

5. **Logical Reasoning and Examples:**
    * **Navigation:** I can create hypothetical scenarios for navigating between markers. If the markers are A, B, and C, and the current selection is B, then "next" should be C and "previous" should be A. The code handles wrapping around the ends of the list.
    * **Selection:**  When a marker is selected, others should be deselected. The code maintains this state.
    * **Scroll Synchronization:**  As the user scrolls, the `UpdateSelectedScrollMarker` function determines which marker is currently in view. I can create a scenario where scrolling past a marker should automatically select it.

6. **Potential User Errors:** This is trickier because the C++ code doesn't directly involve user input. Errors would likely occur at a higher level (HTML, CSS, or JavaScript) that *lead* to this code being executed in unexpected ways. For instance:
    * Incorrect CSS configuration for scroll-snap could lead to unexpected marker behavior.
    * JavaScript errors when manipulating scroll position or focus could interfere with the marker selection logic.
    *  Accessibility issues if markers are not properly linked or labeled.

7. **Debugging and User Actions:** To understand how a user reaches this code, I need to consider the use cases of scroll markers:
    * **Scroll Snap Points:**  A common use case. The user scrolls, and the browser snaps to predefined points. These points could be represented by scroll markers. The user's scrolling action triggers the update logic.
    * **Custom Scrollbars:**  More advanced implementations might use these markers to represent sections or headings in a scrollable area, offering a way to quickly navigate. Clicking on such a marker would trigger the `ScrollIntoView` logic.
    * **Accessibility Features:**  Screen readers or other assistive technologies might interact with these markers to provide navigation cues. Focusing on a marker via keyboard navigation would be relevant.

8. **Structure and Refine:**  Finally, I organize my thoughts into the requested categories (functionality, relationships, reasoning, errors, debugging). I try to provide clear, concise explanations and concrete examples where possible. I double-check that my analysis aligns with the code's logic and the overall purpose of a rendering engine. I also pay attention to the specific details asked for in the prompt, like providing assumptions for logical deductions.

By following these steps, I can dissect the C++ code and provide a comprehensive explanation that addresses all aspects of the request. The process involves understanding the code's purpose within the larger context of a web browser and relating its functionality to the familiar concepts of HTML, CSS, and JavaScript.
好的，我们来分析一下 `blink/renderer/core/dom/scroll_marker_group_pseudo_element.cc` 这个 Chromium Blink 引擎源代码文件。

**文件功能：**

这个文件定义了 `ScrollMarkerGroupPseudoElement` 类，其主要功能是管理一组与滚动相关的伪元素（`ScrollMarkerPseudoElement`）。  更具体地说，它负责：

1. **组织和维护滚动标记伪元素：**  它持有一个 `focus_group_` 成员，用于存储一组 `ScrollMarkerPseudoElement` 对象。这些滚动标记通常代表滚动容器内的特定位置或内容片段。
2. **管理滚动标记的选择状态：**  它跟踪当前选中的滚动标记 (`selected_marker_`) 和待选中的滚动标记 (`pending_selected_marker_`)。
3. **处理滚动标记之间的导航：**  提供了 `FindNextScrollMarker` 和 `FindPreviousScrollMarker` 方法，允许在组内的滚动标记之间进行循环导航。
4. **激活滚动标记并触发滚动：**  `ActivateNextScrollMarker` 和 `ActivatePrevScrollMarker` 方法用于激活下一个或上一个滚动标记，并触发滚动操作，使对应的标记进入视图。
5. **根据滚动位置更新选中标记：** `UpdateSelectedScrollMarker` 方法根据当前的滚动偏移量，确定哪个滚动标记应该被选中。这实现了当用户滚动时，自动更新当前选中的标记的功能。
6. **作为焦点组的一部分：**  滚动标记组自身可以作为焦点组的一部分，允许用户通过键盘导航在滚动标记之间移动焦点。
7. **生命周期管理：** 提供 `AddToFocusGroup`、`RemoveFromFocusGroup`、`Dispose` 和 `ClearFocusGroup` 等方法来管理滚动标记的添加、移除和清理。
8. **快照管理：**  `UpdateSnapshotInternal`、`UpdateSnapshot` 和 `ValidateSnapshot` 方法用于管理和更新选中滚动标记的快照，可能用于优化渲染或避免不必要的重绘。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

这个 C++ 文件本身不直接包含 JavaScript、HTML 或 CSS 代码，但它的功能是为这些 Web 技术提供底层支持，以实现更丰富的滚动交互体验。

* **CSS:**
    * **关联性:**  `ScrollMarkerGroupPseudoElement` 是一个伪元素。伪元素是由 CSS 创建的抽象元素，用于向 HTML 元素添加样式或行为。这个类很可能对应于 CSS 中定义的某种伪元素选择器，例如，用于自定义滚动条的标记，或者与 `scroll-snap-points` 相关联的视觉指示器。
    * **举例:**  假设 CSS 定义了如下样式，用于在滚动容器中创建滚动捕捉点指示器：

      ```css
      .scroll-container::-webkit-scroll-marker-group { /*  可能用于标识滚动标记组 */
          /*  样式  */
      }

      .scroll-container li::marker { /*  假设列表项作为滚动捕捉点 */
          scroll-snap-align: start;
      }
      ```

      当浏览器渲染 `.scroll-container` 时，Blink 引擎可能会创建 `ScrollMarkerGroupPseudoElement` 的实例来管理与滚动捕捉点（例如 `li::marker`）相关的 `ScrollMarkerPseudoElement` 实例。

* **HTML:**
    * **关联性:**  `ScrollMarkerGroupPseudoElement` 与 HTML 元素相关联，因为它是一个伪元素，而伪元素总是附着在某个真实的 HTML 元素上 (`originating_element`)。  它管理的是与 HTML 结构中特定内容相关的滚动标记。
    * **举例:**  考虑一个包含多个章节的 `<div>` 元素：

      ```html
      <div class="scroll-container">
          <h2>Chapter 1</h2>
          <p>Content of chapter 1...</p>
          <h2>Chapter 2</h2>
          <p>Content of chapter 2...</p>
      </div>
      ```

      浏览器可能会在滚动容器上创建一个 `ScrollMarkerGroupPseudoElement`，并将每个 `<h2>` 元素视为一个滚动标记。当用户滚动时，或者通过某种交互，这个 C++ 类负责更新当前与视图中心对齐的章节对应的滚动标记的选中状态。

* **JavaScript:**
    * **关联性:**  虽然这个 C++ 文件不直接执行 JavaScript，但 JavaScript 可以通过 DOM API 与滚动行为进行交互，从而间接地触发 `ScrollMarkerGroupPseudoElement` 的功能。例如，JavaScript 可以监听滚动事件，或者编程方式地滚动容器。
    * **举例:**  一个 JavaScript 脚本可能会监听滚动事件，并根据当前的滚动位置高亮显示导航栏中对应的章节链接。  这个过程背后，Blink 引擎的 `ScrollMarkerGroupPseudoElement` 可能正在维护滚动标记的状态，以便 JavaScript 可以查询并做出相应的更新。

      ```javascript
      const scrollContainer = document.querySelector('.scroll-container');
      const chapterLinks = document.querySelectorAll('.navigation a');

      scrollContainer.addEventListener('scroll', () => {
          //  某种方式获取当前选中的滚动标记（可能通过查询 DOM 或监听特定事件）
          const selectedMarker = getCurrentSelectedScrollMarker();

          chapterLinks.forEach(link => {
              if (link.getAttribute('href') === `#${selectedMarker.id}`) {
                  link.classList.add('active');
              } else {
                  link.classList.remove('active');
              }
          });
      });
      ```

**逻辑推理、假设输入与输出：**

假设我们有一个包含三个滚动标记的滚动容器，分别对应 HTML 中的三个 `<h2>` 标题。

* **假设输入:**
    1. 用户刚刚加载了页面，滚动容器的初始滚动位置在顶部，第一个标题可见。
    2. `focus_group_` 包含三个 `ScrollMarkerPseudoElement` 对象，分别对应三个标题。
    3. `selected_marker_` 当前为 `nullptr` 或指向第一个滚动标记。
    4. 用户开始向下滚动页面。
    5. 当滚动到第二个标题完全可见时，触发 `UpdateSelectedScrollMarker` 方法，传入当前的滚动偏移量。

* **逻辑推理过程:**
    1. `UpdateSelectedScrollMarker` 方法会遍历 `ScrollMarkers()`（假设返回 `focus_group_` 中的元素）。
    2. 对于每个滚动标记，它会计算将其完全显示所需的滚动偏移量 (`target_offset`)。
    3. 它将 `target_offset` 与当前的滚动偏移量 (`scroll_offset`) 进行比较。
    4. 当第二个滚动标记的 `target_offset` 小于或等于当前的 `scroll_offset` 时，该标记被认为是当前选中的。

* **输出:**
    1. `UpdateSelectedScrollMarker` 方法将 `pending_selected_marker_` 设置为指向第二个滚动标记。
    2. 在后续的 `UpdateSnapshotInternal` 调用中，`SetSelected` 方法会被调用，将 `selected_marker_` 更新为指向第二个滚动标记，并更新相关状态（例如，取消选择之前的标记）。

**用户或编程常见的使用错误：**

1. **CSS 配置错误导致滚动标记无法正确生成或定位：**
   * **错误示例:**  如果 CSS 中 `scroll-snap-points` 或相关的样式配置不正确，可能导致 `ScrollMarkerPseudoElement` 没有被正确创建，或者创建的位置不符合预期。
   * **调试线索:** 检查 CSS 样式表中与滚动捕捉相关的属性是否正确设置。查看浏览器的开发者工具中的“元素”面板，确认是否生成了预期的伪元素。

2. **JavaScript 操作滚动位置与预期不符，导致选中标记错乱：**
   * **错误示例:**  JavaScript 代码直接修改滚动位置，但没有考虑到 `ScrollMarkerGroupPseudoElement` 的更新逻辑，导致选中的标记与实际可见的内容不一致。
   * **调试线索:**  检查 JavaScript 中操作滚动位置的代码，确保在滚动后触发了必要的更新或事件，以便 `UpdateSelectedScrollMarker` 能够被调用。

3. **无障碍性问题，滚动标记没有提供足够的语义信息：**
   * **错误示例:**  虽然 `ScrollMarkerGroupPseudoElement` 在视觉上可能表示了滚动位置，但如果没有提供相应的 ARIA 属性或语义化的 HTML 结构，屏幕阅读器用户可能无法理解这些标记的含义和用途。
   * **调试线索:**  检查与滚动标记相关的 HTML 元素是否具有适当的 ARIA 属性（例如 `aria-label`、`role="tab"` 等），以便辅助技术能够正确解释它们。

**用户操作如何一步步到达这里，作为调试线索：**

以下是一些用户操作可能触发 `ScrollMarkerGroupPseudoElement` 相关代码执行的步骤：

1. **页面加载和渲染：**
   * 用户在浏览器中打开一个包含可滚动内容的网页。
   * Blink 引擎开始解析 HTML、CSS，并构建 DOM 树和渲染树。
   * 如果 CSS 中定义了相关的伪元素或滚动捕捉点，Blink 引擎会创建 `ScrollMarkerGroupPseudoElement` 和 `ScrollMarkerPseudoElement` 的实例。

2. **滚动操作：**
   * 用户使用鼠标滚轮、触摸屏滑动、键盘方向键或拖动滚动条来滚动页面。
   * 滚动事件被触发，Blink 引擎会更新滚动容器的滚动偏移量。
   * 滚动事件可能会触发 `UpdateSelectedScrollMarker` 方法，根据新的滚动位置更新选中的滚动标记。

3. **焦点操作：**
   * 用户可能通过 Tab 键或其他方式将焦点移动到滚动容器内的某个元素，或者直接移动到滚动标记上（如果它们是可聚焦的）。
   * 焦点变化可能会触发与 `ScrollMarkerGroupPseudoElement` 相关的焦点管理逻辑，例如 `AddToFocusGroup`、`FindNextScrollMarker` 等。

4. **编程方式的滚动：**
   * 网页上的 JavaScript 代码可能调用 `scrollTo()`、`scrollBy()` 或其他方法来滚动容器。
   * 这些编程方式的滚动操作也会触发 Blink 引擎的滚动更新流程，并可能间接调用 `UpdateSelectedScrollMarker`。

5. **点击滚动标记（如果可交互）：**
   * 如果滚动标记被设计为可点击的交互元素（例如，自定义滚动条上的指示器），用户点击这些标记会触发相应的事件处理逻辑。
   * 点击事件可能会调用 `ActivateScrollMarker` 方法，触发滚动到该标记对应的位置。

**调试线索:**

* **断点调试:** 在 `ScrollMarkerGroupPseudoElement.cc` 中设置断点，例如在 `UpdateSelectedScrollMarker`、`ActivateScrollMarker` 等关键方法上，可以观察代码的执行流程和变量状态。
* **日志输出:** 在关键位置添加 `DLOG` 或其他日志输出语句，可以记录滚动偏移量、选中的标记等信息，帮助理解代码的行为。
* **开发者工具检查:** 使用 Chrome 开发者工具的“元素”面板，查看是否生成了预期的伪元素，以及它们的样式和属性。使用“性能”面板分析滚动事件的处理过程。
* **事件监听:** 在 JavaScript 中监听 `scroll`、`focus` 等事件，观察事件触发的顺序和相关信息，可以帮助理解用户操作如何影响 `ScrollMarkerGroupPseudoElement` 的行为。

希望以上分析能够帮助你理解 `blink/renderer/core/dom/scroll_marker_group_pseudo_element.cc` 文件的功能以及它在 Chromium Blink 引擎中的作用。

### 提示词
```
这是目录为blink/renderer/core/dom/scroll_marker_group_pseudo_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2024 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"

namespace blink {

ScrollMarkerGroupPseudoElement::ScrollMarkerGroupPseudoElement(
    Element* originating_element,
    PseudoId pseudo_id)
    : PseudoElement(originating_element, pseudo_id),
      ScrollSnapshotClient(originating_element->GetDocument().GetFrame()) {}

void ScrollMarkerGroupPseudoElement::Trace(Visitor* v) const {
  v->Trace(selected_marker_);
  v->Trace(pending_selected_marker_);
  v->Trace(focus_group_);
  PseudoElement::Trace(v);
}

void ScrollMarkerGroupPseudoElement::AddToFocusGroup(
    ScrollMarkerPseudoElement& scroll_marker) {
  scroll_marker.SetScrollMarkerGroup(this);
  focus_group_.push_back(scroll_marker);
}

ScrollMarkerPseudoElement* ScrollMarkerGroupPseudoElement::FindNextScrollMarker(
    const Element& current) {
  if (wtf_size_t index = focus_group_.Find(current); index != kNotFound) {
    return focus_group_[index == focus_group_.size() - 1 ? 0u : index + 1];
  }
  return nullptr;
}

ScrollMarkerPseudoElement*
ScrollMarkerGroupPseudoElement::FindPreviousScrollMarker(
    const Element& current) {
  if (wtf_size_t index = focus_group_.Find(current); index != kNotFound) {
    return focus_group_[index == 0u ? focus_group_.size() - 1 : index - 1];
  }
  return nullptr;
}

void ScrollMarkerGroupPseudoElement::RemoveFromFocusGroup(
    const ScrollMarkerPseudoElement& scroll_marker) {
  if (wtf_size_t index = focus_group_.Find(scroll_marker); index != kNotFound) {
    focus_group_.EraseAt(index);
    if (selected_marker_ == scroll_marker) {
      if (index == focus_group_.size()) {
        if (index == 0) {
          selected_marker_ = nullptr;
          return;
        }
        --index;
      }
      selected_marker_ = focus_group_[index];
    }
  }
}

void ScrollMarkerGroupPseudoElement::ActivateNextScrollMarker(bool focus) {
  ActivateScrollMarker(&ScrollMarkerGroupPseudoElement::FindNextScrollMarker,
                       focus);
}

void ScrollMarkerGroupPseudoElement::ActivatePrevScrollMarker(bool focus) {
  ActivateScrollMarker(
      &ScrollMarkerGroupPseudoElement::FindPreviousScrollMarker, focus);
}

void ScrollMarkerGroupPseudoElement::ActivateScrollMarker(
    ScrollMarkerPseudoElement* (ScrollMarkerGroupPseudoElement::*
                                    find_scroll_marker_func)(const Element&),
    bool focus) {
  if (!selected_marker_) {
    return;
  }
  ScrollMarkerPseudoElement* scroll_marker =
      (this->*find_scroll_marker_func)(*Selected());
  if (!scroll_marker || scroll_marker == selected_marker_) {
    return;
  }
  // parentElement is ::column for column scroll marker and
  // ultimate originating element for regular scroll marker.
  mojom::blink::ScrollIntoViewParamsPtr params =
      scroll_into_view_util::CreateScrollIntoViewParams(
          *scroll_marker->parentElement()->GetComputedStyle());
  scroll_marker->ScrollIntoViewNoVisualUpdate(std::move(params));
  if (focus) {
    GetDocument().SetFocusedElement(scroll_marker,
                                    FocusParams(SelectionBehaviorOnFocus::kNone,
                                                mojom::blink::FocusType::kNone,
                                                /*capabilities=*/nullptr));
  }
  SetSelected(*scroll_marker);
}

bool ScrollMarkerGroupPseudoElement::SetSelected(
    ScrollMarkerPseudoElement& scroll_marker) {
  if (selected_marker_ == scroll_marker) {
    return false;
  }
  if (selected_marker_) {
    selected_marker_->SetSelected(false);
  }
  scroll_marker.SetSelected(true);
  selected_marker_ = scroll_marker;
  pending_selected_marker_.Clear();
  return true;
}

void ScrollMarkerGroupPseudoElement::Dispose() {
  HeapVector<Member<ScrollMarkerPseudoElement>> focus_group =
      std::move(focus_group_);
  for (ScrollMarkerPseudoElement* scroll_marker : focus_group) {
    scroll_marker->SetScrollMarkerGroup(nullptr);
  }
  if (selected_marker_) {
    selected_marker_->SetSelected(false);
    selected_marker_ = nullptr;
  }
  PseudoElement::Dispose();
}

void ScrollMarkerGroupPseudoElement::ClearFocusGroup() {
  focus_group_.clear();
}

bool ScrollMarkerGroupPseudoElement::UpdateSelectedScrollMarker(
    const ScrollOffset& offset) {
  // Implements scroll tracking for scroll marker controls as per
  // https://drafts.csswg.org/css-overflow-5/#scroll-container-scroll.
  Element* originating_element = UltimateOriginatingElement();
  if (!originating_element) {
    return false;
  }
  auto* scroller = DynamicTo<LayoutBox>(originating_element->GetLayoutObject());
  if (!scroller || !scroller->IsScrollContainer()) {
    return false;
  }
  ScrollMarkerPseudoElement* selected = nullptr;
  PhysicalOffset scroll_offset = PhysicalOffset::FromVector2dFFloor(offset);
  ScrollableArea* scrollable_area = scroller->GetScrollableArea();
  CHECK(scrollable_area);
  ScrollOffset max_offset = scrollable_area->MaximumScrollOffset();
  ScrollOffset min_offset = scrollable_area->MinimumScrollOffset();
  for (ScrollMarkerPseudoElement* scroll_marker : ScrollMarkers()) {
    if (!selected) {
      selected = scroll_marker;
    }
    const LayoutBox* target_box =
        scroll_marker->UltimateOriginatingElement()->GetLayoutBox();
    if (!target_box) {
      continue;
    }
    const LayoutObject* scroll_marker_object = scroll_marker->GetLayoutObject();
    CHECK(scroll_marker_object);
    PhysicalBoxStrut scroll_margin =
        target_box->Style() ? target_box->Style()->ScrollMarginStrut()
                            : PhysicalBoxStrut();
    // Ignore sticky position offsets for the purposes of scrolling elements
    // into view. See https://www.w3.org/TR/css-position-3/#stickypos-scroll for
    // details
    const MapCoordinatesFlags flag =
        (RuntimeEnabledFeatures::CSSPositionStickyStaticScrollPositionEnabled())
            ? kIgnoreStickyOffset
            : 0;
    PhysicalRect rect_to_scroll = scroller->AbsoluteToLocalRect(
        scroll_marker_object->AbsoluteBoundingBoxRectForScrollIntoView(), flag);
    rect_to_scroll.Expand(scroll_margin);
    ScrollOffset target_scroll_offset =
        scroll_into_view_util::GetScrollOffsetToExpose(
            *scrollable_area, rect_to_scroll, scroll_margin,
            scroll_into_view_util::PhysicalAlignmentFromSnapAlignStyle(
                *target_box, kHorizontalScroll),
            scroll_into_view_util::PhysicalAlignmentFromSnapAlignStyle(
                *target_box, kVerticalScroll));
    PhysicalOffset target_offset(LayoutUnit(target_scroll_offset.x()),
                                 LayoutUnit(target_scroll_offset.y()));
    // Note: use of abs here is determined by the fact that for direction: rtl
    // the scroll offset starts at zero and goes to the negative side, all the
    // target offsets go to the negative side as well. We can't end up in
    // situation of scroll offset to be on the wrong side of zero, so it's safe
    // to do so.
    // TODO(crbug.com/332396355): We should not really have to check the
    // min/max-offsets.
    if ((target_offset.left.Abs() <= scroll_offset.left.Abs() ||
         max_offset.x() == min_offset.x()) &&
        (target_offset.top.Abs() <= scroll_offset.top.Abs() ||
         max_offset.y() == min_offset.y())) {
      selected = scroll_marker;
    }
  }
  if (selected) {
    // We avoid calling ScrollMarkerPseudoElement::SetSelected here so as not to
    // cause style to be dirty right after layout, which might violate lifecycle
    // expectations.
    pending_selected_marker_ = selected;
  }
  return false;
}

bool ScrollMarkerGroupPseudoElement::UpdateSnapshotInternal() {
  if (pending_selected_marker_) {
    return SetSelected(*pending_selected_marker_);
  }
  return false;
}

void ScrollMarkerGroupPseudoElement::UpdateSnapshot() {
  UpdateSnapshotInternal();
}

bool ScrollMarkerGroupPseudoElement::ValidateSnapshot() {
  return !UpdateSnapshotInternal();
}

bool ScrollMarkerGroupPseudoElement::ShouldScheduleNextService() {
  return false;
}

}  // namespace blink
```