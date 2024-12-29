Response:
Let's break down the thought process for analyzing the `spatial_navigation_controller.cc` file.

1. **Understand the Core Purpose:** The file name itself, "spatial_navigation_controller," strongly suggests its main function: controlling navigation between focusable elements on a webpage using directional input (like arrow keys). The comments at the top confirm this. The key idea is moving focus based on spatial relationships, not just tab order.

2. **Identify Key Dependencies (Includes):**  The included headers provide clues about the functionalities the class interacts with. I'd scan these and categorize them:

    * **Input/Events:** `mojom/input/focus_type.mojom-blink.h`, `third_party/blink/renderer/core/events/keyboard_event.h`, `third_party/blink/renderer/core/events/web_input_event_conversion.h`, `third_party/blink/renderer/core/input/event_handler.h`. This confirms the role of handling keyboard input (specifically arrow keys) and interacting with the event system.
    * **DOM Structure:** `third_party/blink/renderer/core/dom/document.h`, `third_party/blink/renderer/core/dom/element.h`, `third_party/blink/renderer/core/dom/element_traversal.h`, `third_party/blink/renderer/core/dom/focus_params.h`, `third_party/blink/renderer/core/dom/node.h`. This highlights its interaction with the Document Object Model to find and manipulate elements.
    * **Layout/Rendering:** `third_party/blink/renderer/core/layout/hit_test_location.h`, `third_party/blink/renderer/core/layout/hit_test_result.h`, `third_party/blink/renderer/core/layout/layout_object.h`. This indicates its reliance on layout information to determine element positions and visibility.
    * **Frames/Pages:** `third_party/blink/renderer/core/frame/local_dom_window.h`, `third_party/blink/renderer/core/frame/local_frame.h`, `third_party/blink/renderer/core/frame/settings.h`, `third_party/blink/renderer/core/frame/visual_viewport.h`, `third_party/blink/renderer/core/page/focus_controller.h`, `third_party/blink/renderer/core/page/page.h`, `third_party/blink/renderer/core/page/spatial_navigation.h`. This shows it operates within the context of frames and pages, managing focus across frame boundaries.
    * **HTML Elements:**  Includes for specific HTML elements like `HTMLFormControlElement`, `HTMLFormElement`, `HTMLBodyElement`, `HTMLFrameOwnerElement`, `HTMLHtmlElement`, `HTMLVideoElement`. This reveals that it has specific logic for handling certain HTML elements.
    * **Scrolling:** `public/mojom/scroll/scroll_into_view_params.mojom-blink.h`, `third_party/blink/renderer/core/scroll/scroll_into_view_util.h`. This points to its ability to trigger scrolling when no suitable focusable element is found in the current view.
    * **Styling:** `third_party/blink/renderer/core/css/style_change_reason.h`. This suggests that spatial navigation can sometimes trigger style updates.
    * **Editing:** `third_party/blink/renderer/core/editing/editing_utilities.h`, `third_party/blink/renderer/core/editing/frame_selection.h`. This indicates some interaction with editable content.

3. **Analyze Key Methods:**  I'd go through the public and important private methods to understand their responsibilities:

    * **`HandleArrowKeyboardEvent`:**  The primary function for handling arrow key presses, determining the navigation direction, and initiating the focus change.
    * **`HandleEnterKeyboardEvent`:** Handles the Enter key, likely for "activating" the currently interested element.
    * **`HandleImeSubmitKeyboardEvent`:** Deals with submitting forms when using IME.
    * **`HandleEscapeKeyboardEvent`:**  Likely for blurring the currently focused element or resetting the interest.
    * **`Advance`:** The core logic for finding the next focusable element in a given direction. This involves traversing the DOM, considering visibility, and calculating distances.
    * **`FindNextCandidateInContainer`:**  A helper for `Advance`, focusing on finding the best candidate within a specific container.
    * **`AdvanceWithinContainer`:** Another helper for `Advance`, dealing with the logic of searching within a scrollable container.
    * **`StartingNode`:** Determines the starting point for the spatial navigation search.
    * **`MoveInterestTo`:**  Actually changes the focus to the new element, handling potential frame transitions and dispatching a mousemove event.
    * **`DispatchMouseMoveAt`:** Simulates a mousemove event, which is important for updating hover states.
    * **`IsValidCandidate`:** Determines if an element is a valid target for spatial navigation.
    * **`GetInterestedElement` and `GetFocusedElement`:**  Getters for the currently focused or "interested" element.

4. **Identify Relationships with Web Technologies:**  Now, connect the methods and dependencies to JavaScript, HTML, and CSS:

    * **JavaScript:**
        * Event Handling:  `HandleArrowKeyboardEvent`, `HandleEnterKeyboardEvent` are triggered by browser events that JavaScript event listeners could also be attached to. The interaction involves determining if the JavaScript has already handled the event (`focused && focused != event->target()`).
        * Focus Management:  `MoveInterestTo` directly manipulates focus, which is a core part of JavaScript's interaction with the DOM. JavaScript code can also call `element.focus()` or `element.blur()`.
        * Form Submission: `HandleImeSubmitKeyboardEvent` triggers form submission, which can be initiated by JavaScript.
    * **HTML:**
        * Focusable Elements: The logic relies on HTML attributes and element types to determine focusability (`IsKeyboardFocusable`, `tabindex`).
        * Element Structure:  The DOM traversal methods (`ElementTraversal::FirstWithin`, `ElementTraversal::Next`) work directly with the HTML structure.
        * Form Elements: Specific handling for `<form>` and form controls.
        * Iframes:  Special consideration for navigating in and out of `<iframe>` elements.
    * **CSS:**
        * Visibility:  The `IsUnobscured` check and consideration of off-screen elements are influenced by CSS properties like `display`, `visibility`, and `overflow`.
        * Layout:  Calculating element positions and distances (`ComputeDistanceDataForNode`, `RectInViewport`) relies on the CSS layout.
        * Hover Effects: `DispatchMouseMoveAt` is used to trigger CSS `:hover` effects.

5. **Infer Logic and Create Examples:**  Based on the method names and functionality, create plausible scenarios:

    * **Arrow Key Navigation:** Pressing an arrow key triggers `HandleArrowKeyboardEvent`, which calls `Advance` to find the next focusable element in that direction.
    * **Enter Key Activation:** Pressing Enter on a focused element calls `HandleEnterKeyboardEvent`, potentially triggering a click or other action.
    * **IME Submission:** When using an IME, pressing Enter might call `HandleImeSubmitKeyboardEvent` to submit a form.
    * **Escape Key Blur:** Pressing Escape calls `HandleEscapeKeyboardEvent` to remove focus.
    * **Spatial Navigation Algorithm:**  Imagine a grid of buttons. Pressing the down arrow from one button should move focus to the button directly below it, even if the tab order is different.

6. **Consider User/Developer Errors:** Think about how developers or users might misuse or encounter issues with spatial navigation:

    * **Incorrect `tabindex`:**  Developers might misuse `tabindex`, making spatial navigation behave unexpectedly.
    * **Overlapping Elements:** If elements significantly overlap, the "unobscured" check might fail, leading to unexpected focus behavior.
    * **JavaScript Interfering:**  JavaScript event handlers might prevent the default spatial navigation behavior.

7. **Trace User Operations:**  Describe the sequence of actions that lead to the spatial navigation code being executed:

    * User presses an arrow key.
    * The browser captures the key event.
    * The event is dispatched to the rendering engine.
    * The `KeyboardEventManager` likely processes the event.
    * For arrow keys, it calls `SpatialNavigationController::HandleArrowKeyboardEvent`.

8. **Review and Refine:**  Read through the analysis, ensuring clarity, accuracy, and completeness. Add specific code snippet examples where relevant. Ensure the assumptions about input/output are reasonable and illustrative.

This structured approach allows for a comprehensive analysis of the code, covering its functionality, relationships with web technologies, potential issues, and debugging context.
好的，让我们来详细分析一下 `blink/renderer/core/page/spatial_navigation_controller.cc` 这个文件。

**文件功能概述**

`spatial_navigation_controller.cc` 文件的核心功能是**实现基于空间关系的键盘导航**，也被称为**Spatial Navigation (SpatNav)**。  与传统的 Tab 键顺序导航不同，空间导航允许用户使用方向键（上下左右箭头键）在网页上的可聚焦元素之间进行导航，依据的是这些元素在屏幕上的物理位置关系。

**具体功能点：**

1. **处理方向键事件:**  监听并处理键盘事件中的方向键（上、下、左、右箭头键）。
2. **确定导航方向:**  根据按下的方向键，确定用户想要移动焦点的方向。
3. **查找下一个可聚焦元素:**  在指定方向上，查找与当前焦点元素在空间上最接近且有效的下一个可聚焦元素。
4. **移动焦点:** 将焦点从当前元素移动到找到的下一个元素。
5. **处理 Enter 键:**  处理 Enter 键的按下和释放，模拟点击行为。
6. **处理 IME 提交:** 处理输入法（IME）的提交事件，通常用于提交表单。
7. **处理 Escape 键:**  处理 Escape 键，通常用于取消焦点或清除兴趣点。
8. **模拟 `mousemove` 事件:** 在焦点移动后，会模拟触发 `mousemove` 事件，以便激活 CSS 的 `:hover` 样式。
9. **跨 Frame 导航:**  支持在不同的 iframe 之间进行空间导航。
10. **处理滚动容器:**  能够识别滚动容器，并在容器内部或外部进行导航。
11. **考虑元素遮挡和可见性:**  在查找下一个焦点元素时，会考虑元素的可见性和是否被遮挡。
12. **避免某些元素的聚焦:**  定义了一些规则来避免聚焦某些特定的元素，例如文档或 body 元素上的点击处理程序。

**与 JavaScript, HTML, CSS 的关系及举例说明**

* **HTML:**
    * **可聚焦元素:**  空间导航的目标是 HTML 中可以接收焦点的元素，例如：`<a>`, `<button>`, `<input>`, `<textarea>`, 具有 `tabindex` 属性的元素等。`IsValidCandidate` 函数会判断一个元素是否是有效的空间导航候选者，这直接关联到 HTML 元素的属性和类型。
        ```html
        <button>按钮 1</button>
        <a href="#">链接 2</a>
        <input type="text">
        <div tabindex="0">可聚焦的 div</div>
        ```
    * **iframe:**  空间导航需要处理跨 iframe 的焦点移动。代码中可以看到对 `HTMLFrameOwnerElement` 的处理。
        ```html
        <iframe src="other_page.html"></iframe>
        ```
    * **表单元素:**  `HandleImeSubmitKeyboardEvent` 专门处理表单的提交，涉及到 `<form>` 和其内部的表单控件。
        ```html
        <form>
          <input type="text" name="username">
          <button type="submit">提交</button>
        </form>
        ```

* **CSS:**
    * **元素定位和布局:**  空间导航的核心是基于元素的空间位置。代码中使用了 `RectInViewport` 等函数来获取元素的屏幕坐标和尺寸，这依赖于 CSS 的布局计算。
    * **`visibility` 和 `display`:**  `IsValidCandidate` 会考虑元素的可见性，如果元素被设置为 `display: none` 或 `visibility: hidden`，通常不会被认为是有效的导航目标。
    * **`:hover` 样式:**  `DispatchMouseMoveAt` 函数模拟 `mousemove` 事件，是为了触发 CSS 的 `:hover` 样式，提供视觉反馈。
        ```css
        button:hover {
          background-color: lightblue;
        }
        ```

* **JavaScript:**
    * **事件监听:** 虽然 `spatial_navigation_controller.cc` 是 C++ 代码，但它处理的键盘事件是由浏览器的 JavaScript 事件循环传递过来的。JavaScript 可以监听 `keydown`, `keypress`, `keyup` 等事件，`SpatialNavigationController` 会在这些事件到达 Blink 渲染引擎后进行处理。
    * **焦点管理 API:**  `MoveInterestTo` 函数最终会调用元素的 `focus()` 方法来移动焦点，这是 JavaScript 提供的 DOM API。JavaScript 也可以通过 `document.activeElement` 获取当前焦点元素。
    * **自定义事件处理:**  网页开发者可能会编写 JavaScript 代码来监听键盘事件并阻止默认行为（例如使用 `event.preventDefault()`），这可能会影响空间导航的行为。`HandleArrowKeyboardEvent` 中有判断 `focused && focused != event->target()` 的逻辑，就是为了避免与 JavaScript 的自定义事件处理冲突。

**逻辑推理 (假设输入与输出)**

假设当前焦点在页面上的一个按钮 A 上，用户按下了下箭头键。

* **假设输入:**
    * 当前焦点元素: 按钮 A
    * 按下的键盘事件: `KeyboardEvent`，键码为下箭头键
    * 页面上存在其他可聚焦元素 B, C, D，它们相对于 A 的位置如下：
        * B 在 A 的正下方
        * C 在 A 的右下方
        * D 在 A 的左下方
* **逻辑推理过程:**
    1. `HandleArrowKeyboardEvent` 被调用，识别到是下箭头。
    2. `Advance(kDown)` 被调用。
    3. `StartingNode()` 返回按钮 A。
    4. `FindNextCandidateInContainer` 或类似的函数会被调用，遍历页面上的可聚焦元素，并计算它们相对于 A 在向下方向上的距离。
    5. 根据距离和是否被遮挡等因素，选择最合适的下一个焦点元素。假设 B 在 A 的正下方，距离最近且未被遮挡，则 B 被选中。
    6. `MoveInterestTo(B)` 被调用。
    7. 焦点从按钮 A 移动到按钮 B。
    8. `DispatchMouseMoveAt(B)` 被调用，模拟鼠标移动到按钮 B 上，可能触发 B 的 `:hover` 样式。
* **假设输出:**
    * 焦点移动到按钮 B。
    * 如果有 CSS 定义，按钮 B 可能呈现 `:focus` 状态的样式。
    * 如果有 CSS 定义，按钮 B 可能呈现 `:hover` 状态的样式。

**用户或编程常见的使用错误**

1. **误用 `tabindex`:**  开发者可能错误地使用 `tabindex` 属性，导致元素的焦点顺序与空间位置不一致，使得空间导航体验不佳。例如，给页面上所有元素都设置了 `tabindex="1"`，实际上就禁用了默认的 Tab 键顺序，也可能干扰空间导航。
2. **元素遮挡:**  如果可聚焦元素被其他元素完全遮挡，空间导航可能仍然会将其识别为候选目标，但用户可能无法看到焦点移动到那里。
3. **JavaScript 阻止默认行为:**  开发者可能编写 JavaScript 代码来捕获方向键事件并调用 `event.preventDefault()`，阻止了浏览器的默认滚动或空间导航行为。
4. **动态内容加载:**  如果页面上的可聚焦元素是动态加载的，空间导航可能在元素加载完成前无法正确识别它们。
5. **焦点陷阱:**  在某些复杂的 Web 应用中，可能会出现焦点被困在某个区域内，无法通过空间导航移动到其他区域的情况。这通常是由于 DOM 结构或 CSS 布局导致的。

**用户操作如何一步步到达这里 (作为调试线索)**

1. **用户打开一个启用了空间导航的网页:** Chromium 浏览器默认情况下启用了空间导航（可以通过实验性功能开关进行控制）。
2. **用户在网页上与某个元素交互，使其获得焦点:** 例如，用户点击了一个链接或输入框。
3. **用户按下方向键 (例如下箭头键):**
4. **操作系统捕获到键盘事件:**
5. **浏览器进程接收到键盘事件:**
6. **渲染器进程 (Blink) 接收到键盘事件:**
7. **`KeyboardEventManager` 接收到键盘事件:** 这个类负责将原始的键盘事件转换为 Blink 内部的 `KeyboardEvent` 对象。
8. **`SpatialNavigationController::HandleArrowKeyboardEvent` 被调用:**  `KeyboardEventManager` 会判断这是一个方向键事件，并且当前页面启用了空间导航，从而调用 `SpatialNavigationController` 的相应处理函数。
9. **`SpatialNavigationController` 中的逻辑开始执行:**  查找下一个焦点元素，移动焦点，触发 `mousemove` 等。

**调试线索:**

* **断点:** 在 `HandleArrowKeyboardEvent`, `Advance`, `FindNextCandidateInContainer`, `MoveInterestTo` 等关键函数设置断点，可以观察空间导航的执行流程。
* **日志输出:**  在上述函数中添加日志输出，记录当前焦点元素、目标方向、找到的候选元素等信息，帮助理解导航过程。
* **Layout Tree Inspector:**  使用 Chrome 开发者工具的 Layout 标签页，查看元素的布局信息（位置、尺寸、层叠上下文等），可以帮助理解空间导航算法是如何判断元素之间的空间关系的。
* **Event Listeners:** 使用 Chrome 开发者工具的 Elements 标签页，查看当前焦点元素和其父元素的事件监听器，确认是否有 JavaScript 代码阻止了默认行为。
* **实验性功能开关:**  检查 `chrome://flags` 中是否启用了或禁用了与空间导航相关的实验性功能。

希望这个详细的分析能够帮助你理解 `spatial_navigation_controller.cc` 的功能和它在 Chromium Blink 引擎中的作用。

Prompt: 
```
这是目录为blink/renderer/core/page/spatial_navigation_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/spatial_navigation_controller.h"

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/web_input_event_conversion.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/hit_test_location.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"

namespace blink {

namespace {

SpatialNavigationDirection FocusDirectionForKey(KeyboardEvent* event) {
  if (event->ctrlKey() || event->metaKey() || event->shiftKey())
    return SpatialNavigationDirection::kNone;

  SpatialNavigationDirection ret_val = SpatialNavigationDirection::kNone;
  const AtomicString key(event->key());
  if (key == keywords::kArrowDown) {
    ret_val = SpatialNavigationDirection::kDown;
  } else if (key == keywords::kArrowUp) {
    ret_val = SpatialNavigationDirection::kUp;
  } else if (key == keywords::kArrowLeft) {
    ret_val = SpatialNavigationDirection::kLeft;
  } else if (key == keywords::kArrowRight) {
    ret_val = SpatialNavigationDirection::kRight;
  }

  // TODO(bokan): We should probably assert that we don't get anything else but
  // currently KeyboardEventManager sends non-arrow keys here.

  return ret_val;
}

void ClearFocusInExitedFrames(LocalFrame* old_frame,
                              const LocalFrame* const new_frame) {
  while (old_frame && new_frame != old_frame) {
    // Focus is going away from this document, so clear the focused element.
    old_frame->GetDocument()->ClearFocusedElement();
    old_frame->GetDocument()->SetSequentialFocusNavigationStartingPoint(
        nullptr);
    Frame* parent = old_frame->Tree().Parent();
    old_frame = DynamicTo<LocalFrame>(parent);
  }
}

bool IsSkippableCandidate(const Element* element) {
  // SpatNav tries to ignore certain, inconvenient focus candidates.
  // If an element is recognized as focusable by
  // SupportsSpatialNavigationFocus() but has one or several focusable
  // descendant(s), then we might ignore it in favor for its focusable
  // descendant(s).

  if (element->GetIntegralAttribute(html_names::kTabindexAttr, -1) >= 0) {
    // non-negative tabindex was set explicitly.
    return false;
  }

  if (IsRootEditableElement(*element))
    return false;

  return true;
}

bool IsEqualDistanceAndContainsBestCandidate(
    const FocusCandidate& candidate,
    const FocusCandidate& best_candidate,
    const double& candidate_distance,
    const double& best_distance) {
  return std::fabs(candidate_distance - best_distance) <
             std::numeric_limits<double>::epsilon() &&
         candidate.rect_in_root_frame.Contains(
             best_candidate.rect_in_root_frame);
}

// Determines whether the given candidate is closer to the current interested
// node (in the given direction) than the current best. If so, it'll replace
// the current best.
static void ConsiderForBestCandidate(SpatialNavigationDirection direction,
                                     const FocusCandidate& current_interest,
                                     const FocusCandidate& candidate,
                                     FocusCandidate* best_candidate,
                                     double& best_distance,
                                     FocusCandidate* previous_best_candidate,
                                     double& previous_best_distance) {
  DCHECK(candidate.visible_node->IsElementNode());
  DCHECK(candidate.visible_node->GetLayoutObject());

  // Ignore iframes that don't have a src attribute
  if (FrameOwnerElement(candidate) &&
      (!FrameOwnerElement(candidate)->ContentFrame() ||
       candidate.rect_in_root_frame.IsEmpty()))
    return;

  // Ignore off-screen focusables, if there's nothing in the direction we'll
  // scroll until they come on-screen.
  if (candidate.is_offscreen)
    return;

  double distance =
      ComputeDistanceDataForNode(direction, current_interest, candidate);
  if (distance == kMaxDistance)
    return;

  Element* candidate_element = To<Element>(candidate.visible_node);
  Element* best_candidate_element = To<Element>(best_candidate->visible_node);

  if (candidate_element->IsDescendantOf(best_candidate_element) &&
      IsSkippableCandidate(best_candidate_element) &&
      best_candidate->rect_in_root_frame.Contains(
          candidate.rect_in_root_frame)) {
    // Revert to previous best_candidate because current best_candidate is
    // a skippable candidate.
    *best_candidate = *previous_best_candidate;
    best_distance = previous_best_distance;

    previous_best_distance = kMaxDistance;
  }

  // In case of a tie, we must prefer a container to a contained element since
  // interest moves from outside in (e.g. see ComputeDistanceDataForNode)
  if ((distance < best_distance ||
       IsEqualDistanceAndContainsBestCandidate(candidate, *best_candidate,
                                               distance, best_distance)) &&
      IsUnobscured(candidate)) {
    *previous_best_candidate = *best_candidate;
    previous_best_distance = best_distance;
    *best_candidate = candidate;
    best_distance = distance;
  }
}

}  // namespace

SpatialNavigationController::SpatialNavigationController(Page& page)
    : page_(&page) {
  DCHECK(page_->GetSettings().GetSpatialNavigationEnabled());
}

bool SpatialNavigationController::HandleArrowKeyboardEvent(
    KeyboardEvent* event) {
  DCHECK(page_->GetSettings().GetSpatialNavigationEnabled());

  // TODO(bokan): KeyboardEventManager sends non-arrow keys here. KEM should
  // filter out the non-arrow keys for us.
  SpatialNavigationDirection direction = FocusDirectionForKey(event);
  if (direction == SpatialNavigationDirection::kNone)
    return false;

  // If the focus has already moved by a previous handler, return false.
  const Element* focused = GetFocusedElement();
  if (focused && focused != event->target()) {
    // SpatNav does not need to handle this arrow key because
    // the webpage had a key-handler that already moved focus.
    return false;
  }

  return Advance(direction);
}

bool SpatialNavigationController::HandleEnterKeyboardEvent(
    KeyboardEvent* event) {
  DCHECK(page_->GetSettings().GetSpatialNavigationEnabled());

  Element* interest_element = GetInterestedElement();

  if (!interest_element)
    return false;

  if (event->type() == event_type_names::kKeydown) {
    enter_key_down_seen_ = true;
    interest_element->SetActive(true);
  } else if (event->type() == event_type_names::kKeypress) {
    enter_key_press_seen_ = true;
  } else if (event->type() == event_type_names::kKeyup) {
    interest_element->SetActive(false);
  }

  return true;
}

void SpatialNavigationController::ResetEnterKeyState() {
  enter_key_down_seen_ = false;
  enter_key_press_seen_ = false;
}

bool SpatialNavigationController::HandleImeSubmitKeyboardEvent(
    KeyboardEvent* event) {
  DCHECK(page_->GetSettings().GetSpatialNavigationEnabled());

  auto* element = DynamicTo<HTMLFormControlElement>(GetFocusedElement());
  if (!element)
    return false;

  if (!element->formOwner())
    return false;

  element->formOwner()->SubmitImplicitly(*event, true);
  return true;
}

bool SpatialNavigationController::HandleEscapeKeyboardEvent(
    KeyboardEvent* event) {
  DCHECK(page_->GetSettings().GetSpatialNavigationEnabled());

  if (Element* focused = GetFocusedElement())
    focused->blur();
  else
    MoveInterestTo(nullptr);

  return true;
}

void SpatialNavigationController::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
}

bool SpatialNavigationController::Advance(
    SpatialNavigationDirection direction) {
  Node* interest_node = StartingNode();
  if (!interest_node)
    return false;

  interest_node->GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kSpatialNavigation);

  Node* container = ScrollableAreaOrDocumentOf(interest_node);

  const PhysicalRect visible_rect =
      PhysicalRect::EnclosingRect(page_->GetVisualViewport().VisibleRect());
  const PhysicalRect start_box =
      SearchOrigin(visible_rect, interest_node, direction);

  if (IsScrollableAreaOrDocument(interest_node) &&
      !IsOffscreen(interest_node)) {
    // A visible scroller has interest. Search inside of it from one of its
    // edges.
    PhysicalRect edge = OppositeEdge(direction, start_box);
    if (AdvanceWithinContainer(*interest_node, edge, direction, nullptr))
      return true;
  }

  // The interested scroller had nothing. Let's search outside of it.
  Node* skipped_tree = interest_node;
  while (container) {
    if (AdvanceWithinContainer(*container, start_box, direction, skipped_tree))
      return true;

    // Containers are not focused “on the way out”. This prevents containers
    // from acting as “focus traps”. Take <c> <a> </c> <b>. Focus can move from
    // <a> to <b> but not from <a> to the scroll container <c>. If we'd allow
    // focus to move from <a> to <c>, the user would never be able to exit <c>.
    // When the scroll container <c> is focused, we move focus back to <a>...
    skipped_tree = container;
    // Nothing found in |container| so search the parent container.
    container = ScrollableAreaOrDocumentOf(container);

    // TODO(bokan): This needs to update the parent document when the _current_
    // container is a document since we're crossing the document boundary.
    // Currently this will fail if we're going from an inner document to a
    // sub-scroller in a parent document.
    if (auto* document = DynamicTo<Document>(container))
      document->UpdateStyleAndLayout(DocumentUpdateReason::kSpatialNavigation);
  }

  return false;
}

FocusCandidate SpatialNavigationController::FindNextCandidateInContainer(
    Node& container,
    const PhysicalRect& starting_rect_in_root_frame,
    SpatialNavigationDirection direction,
    Node* interest_child_in_container) {
  Element* element = ElementTraversal::FirstWithin(container);

  FocusCandidate current_interest;
  current_interest.rect_in_root_frame = starting_rect_in_root_frame;
  current_interest.focusable_node = interest_child_in_container;
  current_interest.visible_node = interest_child_in_container;

  FocusCandidate best_candidate, previous_best_candidate;
  double previous_best_distance = kMaxDistance;
  double best_distance = kMaxDistance;
  for (; element;
       element =
           IsScrollableAreaOrDocument(element)
               ? ElementTraversal::NextSkippingChildren(*element, &container)
               : ElementTraversal::Next(*element, &container)) {
    if (element == interest_child_in_container)
      continue;

    if (HasRemoteFrame(element))
      continue;

    if (!IsValidCandidate(element))
      continue;

    FocusCandidate candidate = FocusCandidate(element, direction);
    if (candidate.IsNull())
      continue;

    ConsiderForBestCandidate(direction, current_interest, candidate,
                             &best_candidate, best_distance,
                             &previous_best_candidate, previous_best_distance);
  }

  return best_candidate;
}

bool SpatialNavigationController::AdvanceWithinContainer(
    Node& container,
    const PhysicalRect& starting_rect_in_root_frame,
    SpatialNavigationDirection direction,
    Node* interest_child_in_container) {
  DCHECK(IsScrollableAreaOrDocument(&container));

  FocusCandidate candidate =
      FindNextCandidateInContainer(container, starting_rect_in_root_frame,
                                   direction, interest_child_in_container);

  if (candidate.IsNull()) {
    // Nothing to focus in this container, scroll if possible.
    // NOTE: If no scrolling is performed (i.e. ScrollInDirection returns
    // false), the spatial navigation algorithm will skip this container.
    return ScrollInDirection(&container, direction);
  }

  auto* element = To<Element>(candidate.focusable_node);
  DCHECK(element);
  MoveInterestTo(element);
  return true;
}

Node* SpatialNavigationController::StartingNode() {
  // FIXME: Directional focus changes don't yet work with RemoteFrames.
  const auto* current_frame =
      DynamicTo<LocalFrame>(page_->GetFocusController().FocusedOrMainFrame());
  if (!current_frame)
    return nullptr;

  Document* focused_document = current_frame->GetDocument();
  if (!focused_document)
    return nullptr;

  Node* focused_element = focused_document->FocusedElement();
  if (!focused_element)  // An iframe's document is focused.
    focused_element = focused_document;

  return focused_element;
}

void SpatialNavigationController::MoveInterestTo(Node* next_node) {
  DCHECK(!next_node || next_node->IsElementNode());
  auto* element = To<Element>(next_node);

  if (!element) {
    DispatchMouseMoveAt(nullptr);
    return;
  }

  // Before focusing the new element, check if we're leaving an iframe (= moving
  // focus out of an iframe). In this case, we want the exited [nested] iframes
  // to lose focus. This is tested in snav-iframe-nested.html.
  LocalFrame* old_frame = page_->GetFocusController().FocusedFrame();
  ClearFocusInExitedFrames(old_frame, next_node->GetDocument().GetFrame());

  element->Focus(FocusParams(SelectionBehaviorOnFocus::kReset,
                             mojom::blink::FocusType::kSpatialNavigation,
                             nullptr, FocusOptions::Create(),
                             FocusTrigger::kUserGesture));
  // The focused element could be changed due to elm.focus() on focus handlers.
  // So we need to update the current focused element before DispatchMouseMove.
  // This is tested in snav-applies-hover-with-focused.html.
  Element* current_interest = GetInterestedElement();
  DispatchMouseMoveAt(current_interest);
}

void SpatialNavigationController::DispatchMouseMoveAt(Element* element) {
  gfx::PointF event_position(-1, -1);
  if (element) {
    event_position = RectInViewport(*element).origin();
    event_position.Offset(1, 1);
  }

  // TODO(bokan): Can we get better screen coordinates?
  gfx::PointF event_position_screen = event_position;
  int click_count = 0;
  WebMouseEvent fake_mouse_move_event(
      WebInputEvent::Type::kMouseMove, event_position, event_position_screen,
      WebPointerProperties::Button::kNoButton, click_count,
      WebInputEvent::kRelativeMotionEvent, base::TimeTicks::Now());
  Vector<WebMouseEvent> coalesced_events, predicted_events;

  DCHECK(IsA<LocalFrame>(page_->MainFrame()));
  LocalFrame* frame = DynamicTo<LocalFrame>(page_->MainFrame());

  DCHECK(frame);
  frame->GetEventHandler().HandleMouseMoveEvent(
      TransformWebMouseEvent(frame->View(), fake_mouse_move_event),
      coalesced_events, predicted_events);
}

bool SpatialNavigationController::IsValidCandidate(
    const Element* element) const {
  if (!element || !element->isConnected() || !element->GetLayoutObject())
    return false;

  LocalFrame* frame = element->GetDocument().GetFrame();
  if (!frame)
    return false;

  // If the author installed a click handler on the main document or body, we
  // almost certainly don't want to actually interest it. Doing so leads to
  // issues since the document/body will likely contain most of the other
  // content on the page.
  if (frame->IsOutermostMainFrame()) {
    if (IsA<HTMLHtmlElement>(element) || IsA<HTMLBodyElement>(element))
      return false;
  }

  return element->IsKeyboardFocusable();
}

Element* SpatialNavigationController::GetInterestedElement() const {
  Frame* frame = page_->GetFocusController().FocusedOrMainFrame();
  auto* local_frame = DynamicTo<LocalFrame>(frame);
  if (!local_frame) {
    return nullptr;
  }

  Document* document = local_frame->GetDocument();
  if (!document) {
    return nullptr;
  }

  return document->ActiveElement();
}

Element* SpatialNavigationController::GetFocusedElement() const {
  LocalFrame* frame = page_->GetFocusController().FocusedFrame();
  if (!frame || !frame->GetDocument()) {
    return nullptr;
  }

  return frame->GetDocument()->FocusedElement();
}

}  // namespace blink

"""

```