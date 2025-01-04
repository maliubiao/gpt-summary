Response:
Let's break down the thought process to analyze the `autoscroll_controller.cc` file and generate the comprehensive answer.

1. **Understand the Goal:** The request asks for a detailed explanation of the `AutoscrollController`'s functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common usage errors, and debugging information.

2. **Initial Skim and Identify Key Areas:** Read through the code, noting the included headers, class definition, member variables, and methods. Look for keywords like "autoscroll," "scroll," "mouse," "drag," "selection," and "middle click." This gives a high-level understanding of the controller's purpose.

3. **Identify Core Functionality:**  Based on the initial skim, it's clear the controller manages automatic scrolling in various scenarios:
    * Selection autoscroll (dragging the mouse while selecting text).
    * Drag-and-drop autoscroll.
    * Middle-click autoscroll.

4. **Analyze Each Functionality in Detail:**  Go through the code function by function, focusing on the purpose and logic of each method:

    * **Constructor & Trace:** Basic object setup and debugging support.
    * **`SelectionAutoscrollInProgress`, `AutoscrollInProgress`, `AutoscrollInProgressFor`:** Status checks. Note how they rely on the `autoscroll_type_` and `autoscroll_layout_object_` members.
    * **`StartAutoscrollForSelection`:**  Crucial function. Identify how it finds the scrollable element (`LayoutBox::FindAutoscrollable`) and sets the state.
    * **`StopAutoscroll`:**  Resets the state. Pay attention to resetting `pressed_layout_object_`.
    * **`StopAutoscrollIfNeeded`:** Handles cases where the layout object involved is being removed. Important for preventing dangling pointers.
    * **`UpdateDragAndDrop`:** Logic for initiating and updating drag-and-drop autoscroll. Observe how it determines the scroll direction and sets the state.
    * **`CanScrollDirection`:** Helper function to determine if scrolling is possible in a given direction. Notice the check for visual viewport maximum scroll offset.
    * **`HandleMouseMoveForMiddleClickAutoscroll`:**  Complex logic. Understand how it calculates velocity based on mouse movement, applies an exponential function, and updates the cursor. Note the interaction with `ChromeClient`.
    * **`HandleMouseReleaseForMiddleClickAutoscroll`:** Handles the end of middle-click autoscroll and the toggle behavior.
    * **`StopMiddleClickAutoscroll`:**  Resets middle-click autoscroll state.
    * **`MiddleClickAutoscrollInProgress`:**  Status check.
    * **`StartMiddleClickAutoscroll`:** Initiates middle-click autoscroll, finding scrollable ancestors. Notice the propagation checks (`ScrollManager::CanPropagate`).
    * **`Animate`:**  The core animation loop. Understand how it calculates the scroll offset and triggers the actual scrolling (`autoscroll_layout_object_->Autoscroll`). Note the different logic for drag-and-drop and selection.
    * **`ScheduleMainThreadAnimation`:**  Mechanism to trigger the animation.
    * **`UpdateCachedAutoscrollForSelectionState`:**  Informs the browser about the autoscroll state, potentially affecting UI elements like the I-beam cursor.
    * **`IsAutoscrolling`:** General status check.

5. **Identify Relationships with Web Technologies:**

    * **JavaScript:** Think about how JavaScript events (like `mousedown`, `mousemove`, `mouseup`, `dragstart`, `dragover`, `drop`) trigger actions that eventually lead to this controller being involved. Consider the `Selection` API and how it interacts with mouse dragging.
    * **HTML:** How does the structure of the HTML document influence scrolling?  Focus on scrollable elements, `overflow` properties, and the existence of frames (`<iframe>`).
    * **CSS:** How do CSS properties like `overflow`, `overflow-x`, `overflow-y`, and potentially custom cursors relate to autoscrolling?

6. **Develop Logical Reasoning Examples:**  Create simple scenarios (inputs) and predict the controller's behavior (outputs). Think about edge cases and different combinations of actions.

7. **Identify Common Usage Errors:** Consider developer mistakes that could lead to unexpected autoscroll behavior or prevent it from working. Focus on incorrect event handling or assumptions about scrollable elements.

8. **Outline User Interaction for Debugging:**  Describe the sequence of user actions that would trigger the code in this file. This helps in understanding the context and setting up debugging scenarios.

9. **Structure the Answer:** Organize the information logically using headings and bullet points. Start with a general overview and then delve into specifics. Provide clear examples and explanations. Use the file structure and function names as a guide.

10. **Refine and Review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check for any redundancies or areas where more detail is needed. For example, initially, I might have overlooked the details about scroll propagation in the middle-click scenario and would need to go back and add that. Ensure the examples are concrete and easy to understand. Double-check the connection to JavaScript, HTML, and CSS.

By following this structured approach, focusing on understanding the code's purpose and its interactions with the broader browser environment, we can generate a comprehensive and informative answer like the example provided in the initial prompt.
好的，让我们详细分析一下 `blink/renderer/core/page/autoscroll_controller.cc` 这个文件的功能。

**功能概述**

`AutoscrollController` 类的主要功能是**控制页面或特定元素在用户进行某些操作时的自动滚动行为**。这些操作主要包括：

* **鼠标拖拽选择文本 (Selection Autoscroll):** 当用户按住鼠标并拖动以选择文本，如果鼠标光标移动到可滚动元素的边缘时，该控制器会触发自动滚动，以便用户可以选择更多内容。
* **拖放操作 (Drag and Drop Autoscroll):** 当用户拖动一个元素到另一个可滚动元素的边缘时，该控制器会触发自动滚动，以便用户可以将元素放置在目标元素的可见区域内。
* **鼠标中键自动滚动 (Middle Click Autoscroll):**  当用户点击鼠标中键并拖动时，该控制器会根据鼠标移动的速度和方向，控制页面的自动滚动。

**与 JavaScript, HTML, CSS 的关系**

`AutoscrollController` 的功能与前端技术有着密切的联系，因为它直接响应用户的交互行为，而这些交互行为通常发生在渲染的 HTML 结构上，并受到 CSS 样式的控制。JavaScript 可以通过事件监听等方式间接地影响到自动滚动。

**举例说明:**

* **HTML:**
    * 当一个 `<div>` 元素设置了 `overflow: auto;` 或 `overflow: scroll;` 属性，使其成为可滚动元素时，`AutoscrollController` 就能识别到这个元素，并在用户进行拖拽选择或拖放操作时，对其进行自动滚动。
    * 当用户拖动鼠标选择跨越 `<iframe>` 边界的文本时，`AutoscrollController` 需要处理跨框架的自动滚动逻辑。
* **CSS:**
    * CSS 的 `overflow` 属性决定了元素是否以及如何滚动。这直接影响了 `AutoscrollController` 是否会尝试自动滚动该元素。
    * CSS 可以定义自定义光标。当进行鼠标中键自动滚动时，`AutoscrollController` 会根据滚动的方向和速度改变鼠标光标（例如，箭头指向滚动的方向），这需要与 CSS 的光标设置机制交互。
* **JavaScript:**
    * JavaScript 可以监听 `mousedown`, `mousemove`, `mouseup`, `dragstart`, `dragover`, `drop` 等鼠标和拖放事件。虽然 `AutoscrollController` 主要在 Blink 渲染引擎内部工作，但这些 JavaScript 事件的发生是触发自动滚动的先决条件。例如，用户在 `mousedown` 时开始拖动选择文本，这个事件会传递到 Blink 引擎，进而可能触发 `AutoscrollController` 的工作。
    * 一些复杂的 Web 应用可能会使用 JavaScript 来实现自定义的拖拽和滚动行为，这可能与 `AutoscrollController` 的默认行为发生冲突。开发者需要注意协调这些行为。

**逻辑推理 (假设输入与输出)**

假设用户在一个包含可滚动 `<div>` 元素的页面上进行以下操作：

**场景 1：鼠标拖拽选择文本**

* **假设输入:**
    * 用户在 `<div>` 元素的可见区域内按下鼠标左键。
    * 用户拖动鼠标，光标移动到 `<div>` 元素的下边缘。
    * `<div>` 元素具有 `overflow-y: auto;` 且内容超出可见区域。
* **逻辑推理:**
    * `AutoscrollController` 检测到鼠标按下的目标元素是一个可滚动元素。
    * 当鼠标光标接近或超出 `<div>` 元素的边界时，`AutoscrollController` 计算需要滚动的偏移量和方向。
    * `AutoscrollController` 调用相应的滚动 API，使 `<div>` 元素的内容向下滚动。
* **预期输出:**
    * `<div>` 元素的内容持续向下滚动，直到鼠标光标离开边界或用户释放鼠标左键。
    * 用户能够选择到原本不可见的文本内容。

**场景 2：拖放操作**

* **假设输入:**
    * 用户开始拖动一个元素（例如，一张图片）。
    * 用户将拖动的元素移动到一个具有 `overflow: scroll;` 属性的 `<div>` 元素的右边缘。
    * `<div>` 元素的内容超出可见区域。
* **逻辑推理:**
    * `AutoscrollController` 检测到拖动操作的目标元素是一个可滚动元素。
    * 当拖动的元素接近或超出 `<div>` 元素的边界时，`AutoscrollController` 计算需要滚动的偏移量和方向。
    * `AutoscrollController` 调用相应的滚动 API，使 `<div>` 元素的内容向右滚动。
* **预期输出:**
    * `<div>` 元素的内容持续向右滚动，直到拖动的元素离开边界或用户释放鼠标。
    * 用户可以将拖动的元素放置在 `<div>` 元素中原本不可见的区域。

**场景 3：鼠标中键自动滚动**

* **假设输入:**
    * 用户在页面上点击鼠标中键。
    * 用户向上拖动鼠标。
* **逻辑推理:**
    * `AutoscrollController` 检测到鼠标中键按下事件。
    * 根据鼠标向上拖动的距离和速度，计算出垂直方向的滚动速度。
    * `AutoscrollController` 调用滚动 API，使页面向上滚动。
    * 光标会变成指示向上滚动的特殊光标。
* **预期输出:**
    * 页面内容向上滚动，速度与鼠标拖动的速度成比例。
    * 鼠标光标显示为向上滚动的指示。

**用户或编程常见的使用错误**

* **错误地假设所有元素都会自动滚动:** 用户可能会期望在任何元素上拖动鼠标都能触发自动滚动，但实际上只有设置了 `overflow` 属性并具有滚动能力的元素才会触发。
* **在 JavaScript 中阻止了默认行为:** 如果 JavaScript 代码中使用了 `event.preventDefault()` 阻止了鼠标事件的默认行为，可能会干扰 `AutoscrollController` 的工作，导致自动滚动失效。
* **误解鼠标中键滚动的触发机制:** 用户可能不清楚鼠标中键需要按住并拖动才能触发自动滚动，而不是简单地点击。
* **开发者错误地禁用了滚动:** 开发者可能通过 CSS 或 JavaScript 禁用了元素的滚动，导致 `AutoscrollController` 无法工作。例如，设置了 `overflow: hidden;` 或 `touch-action: none;`。
* **框架嵌套导致的自动滚动问题:** 在包含多个嵌套框架的页面中，自动滚动的行为可能会变得复杂，用户可能不清楚当前正在滚动的具体是哪个框架。

**用户操作如何一步步到达这里 (调试线索)**

以下步骤描述了用户如何触发 `AutoscrollController` 中的代码，作为调试线索：

**鼠标拖拽选择文本:**

1. **用户在浏览器中打开一个网页。**
2. **页面渲染完成后，用户将鼠标光标移动到包含可选择文本的元素上。**
3. **用户按下鼠标左键并保持按住状态。**
4. **用户拖动鼠标光标，使其移动到可滚动元素的边缘（例如，底部边缘）。**
5. **此时，Blink 渲染引擎会检测到鼠标拖动事件，并判断当前鼠标光标的位置是否接近可滚动元素的边界。**
6. **如果满足条件，EventHandler 会调用 AutoscrollController 的相关方法（例如，`StartAutoscrollForSelection` 或在 `Animate` 方法中执行滚动逻辑）。**
7. **AutoscrollController 计算滚动偏移量，并调用底层的滚动 API 来滚动元素。**
8. **当用户释放鼠标左键或将鼠标光标移回元素内部时，自动滚动停止。**

**拖放操作:**

1. **用户开始拖动一个元素（通常是通过鼠标按下并移动）。**
2. **用户将拖动的元素（鼠标光标）移动到另一个可滚动元素的边缘。**
3. **Blink 渲染引擎会检测到 `dragover` 事件，并判断拖动目标是否接近可滚动元素的边界。**
4. **EventHandler 会调用 AutoscrollController 的 `UpdateDragAndDrop` 方法。**
5. **`UpdateDragAndDrop` 方法会判断是否需要启动自动滚动，并更新内部状态。**
6. **在动画循环中（`Animate` 方法），如果满足自动滚动的条件，则会调用滚动 API。**
7. **当用户将拖动的元素移开边界或释放鼠标时，自动滚动停止。**

**鼠标中键自动滚动:**

1. **用户在浏览器窗口中点击鼠标中键。**
2. **EventHandler 接收到鼠标中键按下事件。**
3. **EventHandler (或相关的输入处理模块) 可能会调用 `AutoscrollController::StartMiddleClickAutoscroll` 来启动中键自动滚动。**
4. **用户按住鼠标中键并拖动鼠标。**
5. **Blink 渲染引擎会持续接收 `mousemove` 事件。**
6. **`AutoscrollController::HandleMouseMoveForMiddleClickAutoscroll` 方法会根据鼠标移动的距离和速度计算滚动速度。**
7. **`AutoscrollController` 通过 `page_->GetChromeClient().AutoscrollFling()` 将滚动请求传递给浏览器进程进行处理。**
8. **浏览器进程根据滚动速度执行平滑滚动。**
9. **当用户释放鼠标中键时，`AutoscrollController::HandleMouseReleaseForMiddleClickAutoscroll` 被调用，并停止自动滚动。**

通过理解这些用户操作流程，开发者可以使用浏览器的开发者工具，例如在 `AutoscrollController` 的关键方法上设置断点，来调试自动滚动相关的行为。可以观察变量的值、调用堆栈等信息，以便追踪问题的根源。

希望这个详细的解释能够帮助你理解 `blink/renderer/core/page/autoscroll_controller.cc` 的功能和相关知识。

Prompt: 
```
这是目录为blink/renderer/core/page/autoscroll_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2013 Google Inc. All rights reserved.
 * Copyright (C) 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All rights
 * reserved.
 * Copyright (C) 2006 Alexey Proskuryakov (ap@webkit.org)
 * Copyright (C) 2012 Digia Plc. and/or its subsidiary(-ies)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/page/autoscroll_controller.h"

#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/scroll_manager.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/platform/cursors.h"
#include "ui/base/cursor/cursor.h"

namespace blink {

// Delay time in second for start autoscroll if pointer is in border edge of
// scrollable element.
constexpr base::TimeDelta kAutoscrollDelay = base::Seconds(0.2);

static const int kNoMiddleClickAutoscrollRadius = 15;

static const ui::Cursor& MiddleClickAutoscrollCursor(
    const gfx::Vector2dF& velocity,
    bool scroll_vert,
    bool scroll_horiz) {
  // At the original click location we draw a 4 arrowed icon. Over this icon
  // there won't be any scroll, So don't change the cursor over this area.
  bool east = velocity.x() < 0;
  bool west = velocity.x() > 0;
  bool north = velocity.y() > 0;
  bool south = velocity.y() < 0;

  if (north && scroll_vert) {
    if (scroll_horiz) {
      if (east)
        return NorthEastPanningCursor();
      if (west)
        return NorthWestPanningCursor();
    }
    return NorthPanningCursor();
  }
  if (south && scroll_vert) {
    if (scroll_horiz) {
      if (east)
        return SouthEastPanningCursor();
      if (west)
        return SouthWestPanningCursor();
    }
    return SouthPanningCursor();
  }
  if (east && scroll_horiz)
    return EastPanningCursor();
  if (west && scroll_horiz)
    return WestPanningCursor();
  if (scroll_vert && !scroll_horiz)
    return MiddlePanningVerticalCursor();
  if (scroll_horiz && !scroll_vert)
    return MiddlePanningHorizontalCursor();
  return MiddlePanningCursor();
}

AutoscrollController::AutoscrollController(Page& page) : page_(&page) {}

void AutoscrollController::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
  visitor->Trace(autoscroll_layout_object_);
  visitor->Trace(pressed_layout_object_);
  visitor->Trace(horizontal_autoscroll_layout_box_);
  visitor->Trace(vertical_autoscroll_layout_box_);
}

bool AutoscrollController::SelectionAutoscrollInProgress() const {
  return autoscroll_type_ == kAutoscrollForSelection;
}

bool AutoscrollController::AutoscrollInProgress() const {
  return autoscroll_layout_object_ != nullptr;
}

bool AutoscrollController::AutoscrollInProgressFor(
    const LayoutBox* layout_object) const {
  return autoscroll_layout_object_ == layout_object;
}

void AutoscrollController::StartAutoscrollForSelection(
    LayoutObject* layout_object) {
  // We don't want to trigger the autoscroll or the middleClickAutoscroll if
  // it's already active.
  if (autoscroll_type_ != kNoAutoscroll)
    return;
  LayoutBox* scrollable = LayoutBox::FindAutoscrollable(
      layout_object, /*is_middle_click_autoscroll*/ false);
  if (!scrollable && layout_object->GetNode()) {
    scrollable = layout_object->GetNode()->AutoscrollBox();
  }
  if (!scrollable)
    return;

  pressed_layout_object_ = DynamicTo<LayoutBox>(layout_object);
  autoscroll_type_ = kAutoscrollForSelection;
  autoscroll_layout_object_ = scrollable;
  UpdateCachedAutoscrollForSelectionState(true);
  ScheduleMainThreadAnimation();
}

void AutoscrollController::StopAutoscroll() {
  if (pressed_layout_object_) {
    if (pressed_layout_object_->GetNode())
      pressed_layout_object_->GetNode()->StopAutoscroll();
    pressed_layout_object_ = nullptr;
  }
  UpdateCachedAutoscrollForSelectionState(false);
  autoscroll_layout_object_ = nullptr;
  autoscroll_type_ = kNoAutoscroll;
}

void AutoscrollController::StopAutoscrollIfNeeded(LayoutObject* layout_object) {
  if (pressed_layout_object_ == layout_object)
    pressed_layout_object_ = nullptr;

  if (horizontal_autoscroll_layout_box_ == layout_object)
    horizontal_autoscroll_layout_box_ = nullptr;

  if (vertical_autoscroll_layout_box_ == layout_object)
    vertical_autoscroll_layout_box_ = nullptr;

  if (MiddleClickAutoscrollInProgress() && !horizontal_autoscroll_layout_box_ &&
      !vertical_autoscroll_layout_box_) {
    page_->GetChromeClient().AutoscrollEnd(layout_object->GetFrame());
    autoscroll_type_ = kNoAutoscroll;
  }

  if (autoscroll_layout_object_ != layout_object)
    return;
  UpdateCachedAutoscrollForSelectionState(false);
  autoscroll_layout_object_ = nullptr;
  autoscroll_type_ = kNoAutoscroll;
}

void AutoscrollController::UpdateDragAndDrop(Node* drop_target_node,
                                             const gfx::PointF& event_position,
                                             base::TimeTicks event_time) {
  if (!drop_target_node || !drop_target_node->GetLayoutObject()) {
    StopAutoscroll();
    return;
  }

  if (autoscroll_layout_object_ &&
      autoscroll_layout_object_->GetFrame() !=
          drop_target_node->GetLayoutObject()->GetFrame())
    return;

  drop_target_node->GetLayoutObject()
      ->GetFrameView()
      ->UpdateAllLifecyclePhasesExceptPaint(DocumentUpdateReason::kScroll);

  LayoutBox* scrollable =
      LayoutBox::FindAutoscrollable(drop_target_node->GetLayoutObject(),
                                    /*is_middle_click_autoscroll*/ false);
  if (!scrollable) {
    StopAutoscroll();
    return;
  }

  Page* page =
      scrollable->GetFrame() ? scrollable->GetFrame()->GetPage() : nullptr;
  if (!page) {
    StopAutoscroll();
    return;
  }

  PhysicalOffset offset =
      scrollable->CalculateAutoscrollDirection(event_position);
  if (offset.IsZero()) {
    StopAutoscroll();
    return;
  }

  drag_and_drop_autoscroll_reference_position_ =
      PhysicalOffset::FromPointFRound(event_position) + offset;

  if (autoscroll_type_ == kNoAutoscroll) {
    autoscroll_type_ = kAutoscrollForDragAndDrop;
    autoscroll_layout_object_ = scrollable;
    drag_and_drop_autoscroll_start_time_ = event_time;
    UseCounter::Count(drop_target_node->GetDocument(),
                      WebFeature::kDragAndDropScrollStart);
    ScheduleMainThreadAnimation();
  } else if (autoscroll_layout_object_ != scrollable) {
    drag_and_drop_autoscroll_start_time_ = event_time;
    autoscroll_layout_object_ = scrollable;
  }
}

bool CanScrollDirection(LayoutBox* layout_box,
                        Page* page,
                        ScrollOrientation orientation) {
  DCHECK(layout_box);

  bool can_scroll = orientation == ScrollOrientation::kHorizontalScroll
                        ? layout_box->HasScrollableOverflowX()
                        : layout_box->HasScrollableOverflowY();

  if (page) {
    // TODO: Consider only doing this when the layout_box is the document to
    // correctly handle autoscrolling a DIV when pinch-zoomed.
    // See comments on crrev.com/c/2109286
    ScrollOffset maximum_scroll_offset =
        page->GetVisualViewport().MaximumScrollOffset();
    can_scroll =
        can_scroll || (orientation == ScrollOrientation::kHorizontalScroll
                           ? maximum_scroll_offset.x() > 0
                           : maximum_scroll_offset.y() > 0);
  }

  return can_scroll;
}

void AutoscrollController::HandleMouseMoveForMiddleClickAutoscroll(
    LocalFrame* frame,
    const gfx::PointF& position_global,
    bool is_middle_button) {
  if (!MiddleClickAutoscrollInProgress())
    return;

  bool horizontal_autoscroll_possible =
      horizontal_autoscroll_layout_box_ &&
      horizontal_autoscroll_layout_box_->GetNode();
  bool vertical_autoscroll_possible =
      vertical_autoscroll_layout_box_ &&
      vertical_autoscroll_layout_box_->GetNode();
  if (horizontal_autoscroll_possible &&
      !horizontal_autoscroll_layout_box_->IsUserScrollable() &&
      vertical_autoscroll_possible &&
      !vertical_autoscroll_layout_box_->IsUserScrollable()) {
    StopMiddleClickAutoscroll(frame);
    return;
  }

  LocalFrameView* view = frame->View();
  if (!view)
    return;

  gfx::Vector2dF distance = gfx::ScaleVector2d(
      position_global - middle_click_autoscroll_start_pos_global_,
      1 / frame->DevicePixelRatio());

  if (fabs(distance.x()) <= kNoMiddleClickAutoscrollRadius)
    distance.set_x(0);
  if (fabs(distance.y()) <= kNoMiddleClickAutoscrollRadius)
    distance.set_y(0);

  const float kExponent = 2.2f;
  const float kMultiplier = -0.000008f;
  const int x_signum = (distance.x() < 0) ? -1 : (distance.x() > 0);
  const int y_signum = (distance.y() < 0) ? -1 : (distance.y() > 0);
  gfx::Vector2dF velocity(
      pow(fabs(distance.x()), kExponent) * kMultiplier * x_signum,
      pow(fabs(distance.y()), kExponent) * kMultiplier * y_signum);

  bool can_scroll_vertically =
      vertical_autoscroll_possible
          ? CanScrollDirection(vertical_autoscroll_layout_box_,
                               frame->GetPage(),
                               ScrollOrientation::kVerticalScroll)
          : false;
  bool can_scroll_horizontally =
      horizontal_autoscroll_possible
          ? CanScrollDirection(horizontal_autoscroll_layout_box_,
                               frame->GetPage(),
                               ScrollOrientation::kHorizontalScroll)
          : false;

  if (velocity != last_velocity_) {
    last_velocity_ = velocity;
    if (middle_click_mode_ == kMiddleClickInitial)
      middle_click_mode_ = kMiddleClickHolding;
    page_->GetChromeClient().SetCursorOverridden(false);
    view->SetCursor(MiddleClickAutoscrollCursor(velocity, can_scroll_vertically,
                                                can_scroll_horizontally));
    page_->GetChromeClient().SetCursorOverridden(true);
    page_->GetChromeClient().AutoscrollFling(velocity, frame);
  }
}

void AutoscrollController::HandleMouseReleaseForMiddleClickAutoscroll(
    LocalFrame* frame,
    bool is_middle_button) {
  DCHECK(RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled());
  if (!MiddleClickAutoscrollInProgress())
    return;

  // We only want to execute this event once per event dispatch loop so
  // we restrict to processing it only on the local root.
  if (!frame->IsLocalRoot())
    return;

  if (middle_click_mode_ == kMiddleClickInitial && is_middle_button)
    middle_click_mode_ = kMiddleClickToggled;
  else if (middle_click_mode_ == kMiddleClickHolding)
    StopMiddleClickAutoscroll(frame);
}

void AutoscrollController::StopMiddleClickAutoscroll(LocalFrame* frame) {
  if (!MiddleClickAutoscrollInProgress())
    return;

  page_->GetChromeClient().AutoscrollEnd(frame);
  autoscroll_type_ = kNoAutoscroll;
  page_->GetChromeClient().SetCursorOverridden(false);
  frame->LocalFrameRoot().GetEventHandler().UpdateCursor();
  horizontal_autoscroll_layout_box_ = nullptr;
  vertical_autoscroll_layout_box_ = nullptr;
}

bool AutoscrollController::MiddleClickAutoscrollInProgress() const {
  return autoscroll_type_ == kAutoscrollForMiddleClick;
}

void AutoscrollController::StartMiddleClickAutoscroll(
    LocalFrame* frame,
    LayoutBox* scrollable,
    const gfx::PointF& position,
    const gfx::PointF& position_global) {
  DCHECK(RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled());
  DCHECK(scrollable);
  // We don't want to trigger the autoscroll or the middleClickAutoscroll if
  // it's already active.
  if (autoscroll_type_ != kNoAutoscroll)
    return;

  autoscroll_type_ = kAutoscrollForMiddleClick;
  middle_click_mode_ = kMiddleClickInitial;
  middle_click_autoscroll_start_pos_global_ = position_global;

  bool can_scroll_vertically = false;
  bool can_scroll_horizontally = false;

  // Scroll propagation can be prevented in either direction independently.
  // We check whether autoscroll can be prevented in either direction after
  // checking whether the layout box can be scrolled. If propagation is not
  // allowed, we do not perform further checks for whether parents can be
  // scrolled in that direction.
  bool can_propagate_vertically = true;
  bool can_propagate_horizontally = true;

  LayoutObject* layout_object = scrollable;

  while (layout_object && !(can_scroll_horizontally && can_scroll_vertically)) {
    if (LayoutBox* layout_box = DynamicTo<LayoutBox>(layout_object)) {
      // Check whether the layout box can be scrolled and has horizontal
      // scrollable area.
      if (can_propagate_vertically &&
          CanScrollDirection(layout_box, frame->GetPage(),
                             ScrollOrientation::kVerticalScroll) &&
          !vertical_autoscroll_layout_box_) {
        vertical_autoscroll_layout_box_ = layout_box;
        can_scroll_vertically = true;
      }
      // Check whether the layout box can be scrolled and has vertical
      // scrollable area.
      if (can_propagate_horizontally &&
          CanScrollDirection(layout_box, frame->GetPage(),
                             ScrollOrientation::kHorizontalScroll) &&
          !horizontal_autoscroll_layout_box_) {
        horizontal_autoscroll_layout_box_ = layout_box;
        can_scroll_horizontally = true;
      }

      can_propagate_vertically = ScrollManager::CanPropagate(
          layout_box, ScrollPropagationDirection::kVertical);
      can_propagate_horizontally = ScrollManager::CanPropagate(
          layout_box, ScrollPropagationDirection::kHorizontal);
    }

    // Exit loop if we can't propagate to the parent in any direction or if
    // layout boxes have been found for both directions.
    if ((!can_propagate_vertically && !can_propagate_horizontally) ||
        (can_scroll_horizontally && can_scroll_vertically))
      break;

    if (!layout_object->Parent() &&
        layout_object->GetNode() == layout_object->GetDocument() &&
        layout_object->GetDocument().LocalOwner()) {
      layout_object =
          layout_object->GetDocument().LocalOwner()->GetLayoutObject();
    } else {
      layout_object = layout_object->Parent();
    }
  }

  UseCounter::Count(frame->GetDocument(),
                    WebFeature::kMiddleClickAutoscrollStart);

  last_velocity_ = gfx::Vector2dF();

  if (LocalFrameView* view = frame->View()) {
    view->SetCursor(MiddleClickAutoscrollCursor(
        last_velocity_, can_scroll_vertically, can_scroll_horizontally));
  }
  page_->GetChromeClient().SetCursorOverridden(true);
  page_->GetChromeClient().AutoscrollStart(
      gfx::ScalePoint(position, 1 / frame->DevicePixelRatio()), frame);
}

void AutoscrollController::Animate() {
  // Middle-click autoscroll isn't handled on the main thread.
  if (MiddleClickAutoscrollInProgress())
    return;

  if (!autoscroll_layout_object_ || !autoscroll_layout_object_->GetFrame()) {
    StopAutoscroll();
    return;
  }

  EventHandler& event_handler =
      autoscroll_layout_object_->GetFrame()->GetEventHandler();
  PhysicalOffset offset =
      autoscroll_layout_object_->CalculateAutoscrollDirection(
          event_handler.LastKnownMousePositionInRootFrame());
  PhysicalOffset selection_point =
      PhysicalOffset::FromPointFRound(
          event_handler.LastKnownMousePositionInRootFrame()) +
      offset;
  switch (autoscroll_type_) {
    case kAutoscrollForDragAndDrop:
      ScheduleMainThreadAnimation();
      if ((base::TimeTicks::Now() - drag_and_drop_autoscroll_start_time_) >
          kAutoscrollDelay)
        autoscroll_layout_object_->Autoscroll(
            drag_and_drop_autoscroll_reference_position_);
      break;
    case kAutoscrollForSelection:
      if (!event_handler.MousePressed()) {
        StopAutoscroll();
        return;
      }
      event_handler.UpdateSelectionForMouseDrag();

      // UpdateSelectionForMouseDrag may call layout to cancel auto scroll
      // animation.
      if (autoscroll_type_ != kNoAutoscroll) {
        DCHECK(autoscroll_layout_object_);
        ScheduleMainThreadAnimation();
        autoscroll_layout_object_->Autoscroll(selection_point);
      }
      break;
    case kNoAutoscroll:
    case kAutoscrollForMiddleClick:
      break;
  }
}

void AutoscrollController::ScheduleMainThreadAnimation() {
  page_->GetChromeClient().ScheduleAnimation(
      autoscroll_layout_object_->GetFrame()->View());
}

void AutoscrollController::UpdateCachedAutoscrollForSelectionState(
    bool autoscroll_selection) {
  if (!autoscroll_layout_object_ || !autoscroll_layout_object_->GetFrame() ||
      !autoscroll_layout_object_->GetFrame()->IsAttached() ||
      !autoscroll_layout_object_->GetFrame()->IsOutermostMainFrame()) {
    return;
  }
  autoscroll_layout_object_->GetFrame()
      ->LocalFrameRoot()
      .Client()
      ->NotifyAutoscrollForSelectionInMainFrame(autoscroll_selection);
}

bool AutoscrollController::IsAutoscrolling() const {
  return (autoscroll_type_ != kNoAutoscroll);
}

}  // namespace blink

"""

```