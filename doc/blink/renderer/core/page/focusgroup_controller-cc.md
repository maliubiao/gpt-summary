Response:
Let's break down the thought process for analyzing this `FocusgroupController.cc` file.

**1. Initial Understanding - What is the Core Functionality?**

The filename and the initial imports (`focusgroup_controller.h`, `FocusgroupDirection`, etc.) strongly suggest this class is responsible for managing focus navigation within groups of elements. Keywords like "focusgroup," "advance," "keyboard event," and "grid" give crucial hints.

**2. Dissecting the Public Methods (The API):**

* **`HandleArrowKeyboardEvent`:** This immediately signals that the controller is involved in responding to arrow key presses. The arguments (`KeyboardEvent`, `LocalFrame`) tell us it's tied to browser events and the frame context.
* **`Advance`:** This is likely the central logic for moving focus. It takes a starting element and a direction. The presence of specific `AdvanceForward`, `AdvanceBackward`, and `AdvanceInGrid` methods suggests different navigation strategies.
* **`AdvanceForward` & `AdvanceBackward`:**  These clearly handle linear navigation within focus groups.
* **`WrapForward` & `WrapBackward`:**  These methods deal with the concept of focus wrapping around the boundaries of a focus group.
* **`AdvanceInGrid`:** This isolates the specialized logic for navigating grid-based focus groups.
* **`WrapOrFlowInGrid`:** This handles wrapping or flowing within grid structures.
* **`Focus`:** This is the final step - actually setting the focus on an element.

**3. Identifying Key Concepts and Data Structures:**

* **`FocusgroupDirection`:** Enumeration defining the direction of focus movement.
* **`FocusgroupType`:** Distinguishes between different types of focus groups (linear, grid).
* **`FocusgroupFlags`:** Bitmask likely controlling behaviors like extending, wrapping, and axis support.
* **`GridFocusgroupStructureInfo`:**  Dedicated structure for managing grid layouts.
* **`Element`:**  The fundamental DOM element being navigated.
* **`Document`, `LocalFrame`, `LocalDomWindow`:**  Core browser concepts indicating the context of the focus operation.

**4. Tracing the Flow of Logic (Example: `HandleArrowKeyboardEvent`):**

* Check if focusgroup feature is enabled.
* Determine the `FocusgroupDirection` from the event.
* Ensure there's a document and a focused element.
* Verify the focused element matches the event target (to prevent interference from other key handlers).
* Call `Advance` to perform the actual focus change.

**5. Connecting to Web Technologies (HTML, CSS, JavaScript):**

* **HTML:**  The concept of focus groups likely maps to specific HTML elements or attributes. Thinking about how developers might define focusable areas leads to potential examples (e.g., `tabindex`, custom attributes). Grids immediately bring to mind CSS Grid Layout.
* **CSS:**  CSS likely influences the visual presentation and layout of focus groups, especially grids. Visual focus indicators (the outline) are also relevant.
* **JavaScript:**  JavaScript can trigger focus changes programmatically (`element.focus()`) and can interfere with or augment the default focus behavior. Event listeners can also react to focus changes.

**6. Considering Edge Cases and Errors:**

* **User Errors:**  Incorrect use of focus-related HTML attributes or JavaScript focus manipulation could lead to unexpected behavior. Thinking about common developer mistakes helps identify these.
* **Logical Errors:**  The code itself might have bugs. Analyzing the conditions and branches within functions like `CanExitFocusgroupForward` helps uncover potential issues (e.g., incorrect wrapping behavior, getting stuck).

**7. Inferring User Interaction and Debugging:**

* **User Actions:**  Think about the basic user actions that would trigger this code: pressing arrow keys, using Tab to navigate, clicking on elements.
* **Debugging Clues:**  The file provides clues for debugging focus-related issues. Knowing that `FocusgroupController` exists and how it handles events allows developers to set breakpoints and trace the flow of focus navigation.

**8. Structuring the Output:**

Organize the findings into logical categories: Functionality, Relationships to Web Tech, Logical Reasoning, Common Errors, and Debugging. Use clear and concise language, providing specific examples where possible.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe this just handles simple Tab navigation. **Correction:** The presence of "grid" and arrow key handling suggests more complex logic.
* **Initial thought:** The connection to CSS is only about styling the focus outline. **Correction:**  CSS Grid Layout is directly relevant to the `AdvanceInGrid` logic.
* **Initial thought:**  User errors are just about bad JavaScript. **Correction:**  Incorrect HTML attributes like `tabindex` can also cause issues.

By following these steps, combining code analysis with an understanding of web technologies and common development practices, a comprehensive analysis of `FocusgroupController.cc` can be achieved. The key is to be inquisitive, make connections, and consider the different layers involved in web development.
这个 `focusgroup_controller.cc` 文件是 Chromium Blink 渲染引擎中负责处理焦点组导航的核心组件。它的主要功能是**响应用户的键盘输入（主要是方向键），并根据定义的焦点组规则来移动页面上的焦点**。

下面详细列举它的功能，并说明与 JavaScript、HTML、CSS 的关系，以及逻辑推理、常见错误和调试线索：

**功能列表:**

1. **处理方向键事件 (`HandleArrowKeyboardEvent`):**  当用户在页面上按下方向键时，这个函数会被调用。它判断是否应该由 `FocusgroupController` 来处理这个事件。
2. **前进焦点 (`Advance`, `AdvanceForward`, `AdvanceBackward`):** 这是核心的焦点移动逻辑。根据给定的起始元素和移动方向，它会找到下一个或者上一个应该获得焦点的元素。
3. **处理焦点循环 (`WrapForward`, `WrapBackward`):**  在一个焦点组内部，如果移动到边界，可以实现焦点的循环，即从最后一个元素移动到第一个，或者从第一个移动到最后一个。
4. **处理网格焦点组 (`AdvanceInGrid`, `WrapOrFlowInGrid`):**  专门处理网格布局（例如使用 CSS Grid 或类似语义的结构）的焦点导航，允许在行和列之间移动焦点，并处理网格的循环或流动行为。
5. **判断是否可以退出焦点组 (`CanExitFocusgroupForward`, `CanExitFocusgroupForwardRecursive`):**  在向前移动焦点时，需要判断是否可以安全地从当前的焦点组移出，并进入下一个焦点组。
6. **设置焦点 (`Focus`):**  最终将焦点设置到目标元素上。

**与 JavaScript, HTML, CSS 的关系:**

* **HTML:**
    * **焦点组的定义:**  HTML 元素可以通过特定的属性（虽然代码中没有直接体现，但实际应用中可能存在，或者根据 DOM 结构推断）被识别为焦点组的容器或焦点组内的元素。例如，可以使用 `tabindex` 属性来控制元素的聚焦顺序，而焦点组的概念可以看作是对 `tabindex` 更高级的管理。
    * **可聚焦元素:**  只有可聚焦的 HTML 元素（例如 `<a>`, `<button>`, `<input>`, 以及设置了 `tabindex` 的元素）才能成为焦点组导航的目标。
    * **假设输入与输出:**
        * **假设输入:** HTML 结构如下:
          ```html
          <div tabindex="0" id="group1">
            <button id="button1">Button 1</button>
            <button id="button2">Button 2</button>
          </div>
          <button id="button3">Button 3</button>
          ```
        * **用户操作:** 焦点在 `button1` 上，按下向右方向键。
        * **逻辑推理:** `FocusgroupController` 会识别出 `button1` 属于 `group1` 这个焦点组，并根据向前移动的规则，将焦点移动到 `button2`。
        * **输出:** 焦点移动到 `button2`。

* **CSS:**
    * **视觉呈现:** CSS 用于控制焦点元素的视觉呈现，例如通过 `:focus` 伪类添加高亮边框或背景色。`FocusgroupController` 本身不直接操作 CSS，但焦点移动的结果会触发 CSS 样式的改变。
    * **布局影响:** 特别是对于网格焦点组，CSS Grid Layout 的定义会直接影响 `AdvanceInGrid` 的逻辑，决定了元素在行和列中的位置关系。
    * **假设输入与输出 (网格):**
        * **假设输入:** HTML 和 CSS 定义了一个 2x2 的 CSS Grid:
          ```html
          <div tabindex="0" id="grid" style="display: grid; grid-template-columns: 1fr 1fr; grid-template-rows: 1fr 1fr;">
            <button id="cell1">Cell 1</button>
            <button id="cell2">Cell 2</button>
            <button id="cell3">Cell 3</button>
            <button id="cell4">Cell 4</button>
          </div>
          ```
        * **用户操作:** 焦点在 `cell1` 上，按下向下方向键。
        * **逻辑推理:** `FocusgroupController` 会识别出当前焦点在网格内，并根据向下移动的规则，将焦点移动到同一列的下一个元素，即 `cell3`。
        * **输出:** 焦点移动到 `cell3`。

* **JavaScript:**
    * **事件监听:** JavaScript 可以监听 `keydown` 事件，虽然 `FocusgroupController` 主要处理方向键，但开发者可以编写 JavaScript 代码来干预或自定义焦点行为。
    * **程序化焦点控制:** JavaScript 可以使用 `element.focus()` 方法来直接设置焦点，这可能会与 `FocusgroupController` 的行为产生交互。
    * **用户定义的焦点组:**  开发者可以使用 JavaScript 来动态地创建或修改焦点组的结构，虽然 `FocusgroupController` 的核心逻辑在 C++ 中，但 JavaScript 可以通过 DOM 操作来影响其行为。
    * **用户或编程常见的使用错误:**
        * **错误假设:** 开发者可能错误地假设焦点会按照 DOM 树的顺序移动，而忽略了焦点组的定义。
        * **JavaScript 干预:** JavaScript 代码可能在方向键事件中阻止了默认行为（`preventDefault()`），导致 `FocusgroupController` 无法正常工作。
        * **不正确的 `tabindex` 使用:**  在焦点组内部或外部使用了混乱的 `tabindex` 值，导致焦点的移动路径不符合预期。

**逻辑推理的假设输入与输出:**

* **假设输入:**
    * 当前焦点在 ID 为 `itemA` 的元素上。
    * 用户按下向右方向键。
    * `itemA` 属于一个线性的、不循环的焦点组，该焦点组中 `itemA` 之后是 `itemB`，再之后是 `itemC`。
* **逻辑推理过程:**
    1. `HandleArrowKeyboardEvent` 判断是向右方向键。
    2. `Advance` 被调用，方向为 `ForwardInline` (假设向右对应 `ForwardInline`)。
    3. `AdvanceForward` 被调用。
    4. 代码会查找 `itemA` 所属的焦点组。
    5. 代码会查找焦点组中 `itemA` 之后的下一个可聚焦元素，即 `itemB`。
    6. `Focus` 函数会被调用，将焦点设置到 `itemB` 上。
* **输出:** 焦点移动到 ID 为 `itemB` 的元素上。

**用户或编程常见的使用错误:**

1. **`tabindex` 使用不当:**  开发者可能会随意使用 `tabindex` 值，导致焦点顺序混乱，与焦点组的预期行为不符。例如，在同一个焦点组中跳过某些元素，或者在不应该聚焦的元素上设置了 `tabindex="0"`。
    * **用户操作导致错误:** 用户按下 Tab 键或方向键，发现焦点跳转的顺序不符合视觉顺序或逻辑分组。
2. **焦点陷阱:**  创建了无法通过键盘导航退出的焦点组。例如，一个对话框内的元素形成了一个焦点组，但没有提供明确的“取消”或“关闭”按钮，导致用户只能在对话框内部循环。
    * **用户操作导致错误:** 用户使用 Tab 键或方向键尝试离开某个区域，但焦点始终被限制在该区域内。
3. **JavaScript 干扰:**  开发者编写的 JavaScript 代码意外地修改了焦点，或者在方向键事件中做了与焦点导航冲突的操作。
    * **用户操作导致错误:** 用户按下方向键，期望移动焦点，但页面上发生了其他意料之外的事情，例如滚动、动画，或者焦点根本没有移动到预期的元素。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户与页面交互:** 用户在浏览器中打开一个网页。
2. **页面加载和渲染:** 浏览器加载 HTML、CSS 和 JavaScript，并渲染页面。
3. **用户操作（方向键）：** 用户按下键盘上的方向键（例如上、下、左、右）。
4. **浏览器事件分发:** 操作系统捕获到键盘事件，并将其传递给浏览器。浏览器识别出这是一个与页面相关的事件。
5. **事件传递到渲染进程:** 浏览器的渲染进程接收到键盘事件。
6. **事件到达 Blink 引擎:** Blink 引擎的事件处理机制接收到 `KeyboardEvent`。
7. **`EventHandler::HandleEvent`:** Blink 的事件处理模块会处理这个事件。
8. **`HTMLInputElement::dispatchEvent` 或类似函数:**  事件可能会经过一些 DOM 元素的事件分发过程。
9. **`Document::dispatchScopedEvent` 或类似函数:** 事件沿着 DOM 树冒泡或捕获。
10. **`KeyboardEvent` 监听器（可能）：** 如果页面上有 JavaScript 代码监听了 `keydown` 或 `keyup` 事件，这些监听器可能会被触发。
11. **`FocusController::HandleKeyboardEvent`:**  Blink 的 `FocusController` 会接收到键盘事件，并判断是否需要进行焦点移动。
12. **`FocusgroupController::HandleArrowKeyboardEvent`:** 如果 `FocusController` 认为这是一个需要焦点组处理的方向键事件，它会调用 `FocusgroupController` 的 `HandleArrowKeyboardEvent` 函数。

**作为调试线索:**

* **断点设置:**  在 `focusgroup_controller.cc` 的关键函数（例如 `HandleArrowKeyboardEvent`, `AdvanceForward`, `AdvanceInGrid`）设置断点，可以跟踪焦点移动的流程。
* **事件监听:**  在浏览器的开发者工具中，可以监听 `focus` 和 `blur` 事件，观察焦点在哪些元素之间移动。
* **DOM 状态检查:**  在调试过程中，可以查看当前页面的 DOM 结构，特别是元素的 `tabindex` 属性，以及是否有被识别为焦点组的元素。
* **日志输出:**  可以在 `FocusgroupController` 的代码中添加日志输出，记录焦点移动的路径和决策过程。
* **性能分析:**  如果焦点移动出现性能问题，可以使用浏览器的性能分析工具来查看是否有耗时的操作。

总而言之，`focusgroup_controller.cc` 是 Chromium Blink 引擎中实现复杂键盘焦点导航的关键组件，它与 HTML 的结构、CSS 的布局以及 JavaScript 的事件处理和焦点控制都有着密切的联系。理解它的工作原理对于开发可访问的、易于键盘操作的 Web 应用至关重要。

### 提示词
```
这是目录为blink/renderer/core/page/focusgroup_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2022 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/page/focusgroup_controller.h"

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/focusgroup_flags.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/focusgroup_controller_utils.h"
#include "third_party/blink/renderer/core/page/grid_focusgroup_structure_info.h"

namespace blink {

using utils = FocusgroupControllerUtils;

// static
bool FocusgroupController::HandleArrowKeyboardEvent(KeyboardEvent* event,
                                                    const LocalFrame* frame) {
  DCHECK(frame);
  DCHECK(frame->DomWindow());
  ExecutionContext* context = frame->DomWindow()->GetExecutionContext();
  DCHECK(RuntimeEnabledFeatures::FocusgroupEnabled(context));

  FocusgroupDirection direction = utils::FocusgroupDirectionForEvent(event);
  if (direction == FocusgroupDirection::kNone)
    return false;

  if (!frame->GetDocument())
    return false;

  Element* focused = frame->GetDocument()->FocusedElement();
  if (!focused || focused != event->target()) {
    // The FocusgroupController shouldn't handle this arrow key event when the
    // focus already moved to a different element than where it came from. The
    // webpage likely had a key-handler that moved the focus.
    return false;
  }

  return Advance(focused, direction);
}

// static
bool FocusgroupController::Advance(Element* initial_element,
                                   FocusgroupDirection direction) {
  // Only allow grid focusgroup navigation when the focus is on a grid
  // focusgroup item.
  Element* grid_root = utils::FindNearestFocusgroupAncestor(
      initial_element, FocusgroupType::kGrid);
  if (grid_root && utils::IsGridFocusgroupItem(initial_element))
    return AdvanceInGrid(initial_element, grid_root, direction);

  // Only allow linear focusgroup navigation when the focus is on a focusgroup
  // item.
  if (!utils::IsFocusgroupItem(initial_element))
    return false;

  if (utils::IsDirectionForward(direction)) {
    return AdvanceForward(initial_element, direction);
  } else {
    DCHECK(utils::IsDirectionBackward(direction));
    return AdvanceBackward(initial_element, direction);
  }
}

// static
bool FocusgroupController::AdvanceForward(Element* initial_element,
                                          FocusgroupDirection direction) {
  DCHECK(initial_element);
  DCHECK(utils::IsDirectionForward(direction));
  DCHECK(utils::IsFocusgroupItem(initial_element));

  Element* nearest_focusgroup = utils::FindNearestFocusgroupAncestor(
      initial_element, FocusgroupType::kLinear);
  // We only allow focusgroup navigation when we are inside of a focusgroup.
  if (!nearest_focusgroup)
    return false;

  // When the focusgroup we're in doesn't support the axis of the arrow key
  // pressed, it might still be able to descend so we can't return just yet.
  // However, if it can't descend, we should return right away.
  bool can_only_descend = !utils::IsAxisSupported(
      nearest_focusgroup->GetFocusgroupFlags(), direction);

  // We use the first element after the focusgroup we're in, excluding its
  // subtree, as a shortcut to determine if we exited the current focusgroup
  // without having to compute the current focusgroup ancestor on every pass.
  Element* first_element_after_focusgroup =
      utils::NextElement(nearest_focusgroup, /* skip_subtree */ true);

  Element* current = initial_element;

  while (true) {
    // 1. Determine whether to descend in other focusgroup.
    bool skip_subtree = false;
    FocusgroupFlags current_flags = current->GetFocusgroupFlags();
    bool descended = false;
    if (current_flags != FocusgroupFlags::kNone) {
      // When we're on a non-extending focusgroup, we shouldn't go into it. Same
      // for when we're at the root of an extending focusgroup that doesn't
      // support the axis of the arrow pressed.
      if (!(current_flags & FocusgroupFlags::kExtend) ||
          !utils::IsAxisSupported(current_flags, direction)) {
        skip_subtree = true;
      } else {
        nearest_focusgroup = current;
        first_element_after_focusgroup =
            utils::NextElement(nearest_focusgroup, /* skip_subtree */ true);
        descended = true;
      }
    }

    // See comment where |can_only_descend| is declared.
    if (can_only_descend && !descended)
      return false;

    // 2. Move |current| to the next element.
    current = utils::NextElement(current, skip_subtree);

    // 3. When |current| is located on the next element after the focusgroup
    // we're currently in, it means that we just exited the current
    // focusgroup we were in. We need to validate that we have the right to
    // exit it, since there are a few cases that might prevent us from going
    // to the next element. See the function `CanExitFocusgroupForward` for more
    // details about when we shouldn't allow exiting the current focusgroup.
    //
    // When this is true, we have exited the current focusgroup we were in. If
    // we were in an extending focusgroup, we should advance to the next item in
    // the parent focusgroup if the axis is supported.
    if (current && current == first_element_after_focusgroup) {
      if (CanExitFocusgroupForward(nearest_focusgroup, current, direction)) {
        nearest_focusgroup = utils::FindNearestFocusgroupAncestor(
            current, FocusgroupType::kLinear);
        first_element_after_focusgroup =
            utils::NextElement(nearest_focusgroup, /* skip_subtree */ true);
      } else {
        current = nullptr;
      }
    }

    // 4. When |current| is null, try to wrap.
    if (!current) {
      current = WrapForward(nearest_focusgroup, direction);

      if (!current) {
        // We couldn't wrap and we're out of options.
        break;
      }
    }

    // Avoid looping infinitely by breaking when the next logical element is the
    // one we started on.
    if (current == initial_element)
      break;

    // 5. |current| is finally on the next element. Focus it if it's one that
    // should be part of the focusgroup, otherwise continue the loop until it
    // finds the next item or can't find any.
    if (utils::IsFocusgroupItem(current)) {
      Focus(current, direction);
      return true;
    }
  }
  return false;
}

// static
//
// This function validates that we can exit the current focusgroup by calling
// `CanExitFocusgroupForwardRecursive`, which validates that all ancestor
// focusgroups can be exited safely. We need to validate that the ancestor
// focusgroups can be exited only if they are exited. Here are the key scenarios
// where we prohibit a focusgroup from being exited: a. If we're going to an
// element that isn't part of a focusgroup. b. If we're exiting a root
// focusgroup (one that doesn't extend). c. If we're going to a focusgroup that
// doesn't support the direction. d. If we're exiting a focusgroup that should
// wrap.
bool FocusgroupController::CanExitFocusgroupForward(
    const Element* exiting_focusgroup,
    const Element* next_element,
    FocusgroupDirection direction) {
  DCHECK(exiting_focusgroup);
  DCHECK(next_element);
  DCHECK(utils::NextElement(exiting_focusgroup, /*skip_subtree */ true) ==
         next_element);

  const Element* next_element_focusgroup = utils::FindNearestFocusgroupAncestor(
      next_element, FocusgroupType::kLinear);
  if (!next_element_focusgroup)
    return false;

  return CanExitFocusgroupForwardRecursive(
      exiting_focusgroup, next_element, direction,
      utils::WrapsInDirection(exiting_focusgroup->GetFocusgroupFlags(),
                              direction));
}

// static
bool FocusgroupController::CanExitFocusgroupForwardRecursive(
    const Element* exiting_focusgroup,
    const Element* next_element,
    FocusgroupDirection direction,
    bool check_wrap) {
  DCHECK(exiting_focusgroup);
  DCHECK(next_element);

  // When this is true, we are not exiting |exiting_focusgroup| and thus won't
  // be exiting any ancestor focusgroup.
  if (utils::NextElement(exiting_focusgroup, /* skip_subtree */ true) !=
      next_element) {
    return true;
  }

  FocusgroupFlags exiting_focusgroup_flags =
      exiting_focusgroup->GetFocusgroupFlags();
  DCHECK(exiting_focusgroup_flags != FocusgroupFlags::kNone);

  if (!(exiting_focusgroup_flags & FocusgroupFlags::kExtend))
    return false;

  const Element* parent_focusgroup = utils::FindNearestFocusgroupAncestor(
      exiting_focusgroup, FocusgroupType::kLinear);
  FocusgroupFlags parent_focusgroup_flags =
      parent_focusgroup ? parent_focusgroup->GetFocusgroupFlags()
                        : FocusgroupFlags::kNone;

  DCHECK(utils::IsAxisSupported(exiting_focusgroup_flags, direction));
  if (!utils::IsAxisSupported(parent_focusgroup_flags, direction))
    return false;

  if (check_wrap) {
    DCHECK(utils::WrapsInDirection(exiting_focusgroup_flags, direction));
    if (!utils::WrapsInDirection(parent_focusgroup_flags, direction))
      return false;
  }

  return CanExitFocusgroupForwardRecursive(parent_focusgroup, next_element,
                                           direction, check_wrap);
}

// static
Element* FocusgroupController::WrapForward(Element* nearest_focusgroup,
                                           FocusgroupDirection direction) {
  // 1. Get the focusgroup that initiates the wrapping scope in this axis. We
  // need to go up to the root-most focusgroup in order to be able to get the
  // "next" element, ie. the first item of this focusgroup. Stopping at the
  // first focusgroup that supports wrapping in that axis would break the
  // extend behavior and return the wrong element.
  Element* focusgroup_wrap_root = nullptr;
  for (Element* focusgroup = nearest_focusgroup; focusgroup;
       focusgroup = utils::FindNearestFocusgroupAncestor(
           focusgroup, FocusgroupType::kLinear)) {
    FocusgroupFlags flags = focusgroup->GetFocusgroupFlags();
    if (!utils::WrapsInDirection(flags, direction))
      break;

    focusgroup_wrap_root = focusgroup;

    if (!(flags & FocusgroupFlags::kExtend))
      break;
  }

  // 2. There are no next valid element and we can't wrap - `AdvanceForward`
  // should fail.
  if (!focusgroup_wrap_root)
    return nullptr;

  // 3. Set the focus on the first element within the subtree of the
  // current focusgroup.
  return utils::NextElement(focusgroup_wrap_root, /* skip_subtree */ false);
}

// static
bool FocusgroupController::AdvanceBackward(Element* initial_element,
                                           FocusgroupDirection direction) {
  DCHECK(initial_element);
  DCHECK(utils::IsDirectionBackward(direction));
  DCHECK(utils::IsFocusgroupItem(initial_element));

  // 1. Validate that we're in a focusgroup. Keep the reference to the current
  // focusgroup we're in since we'll use it if we need to wrap.
  Element* initial_focusgroup = utils::FindNearestFocusgroupAncestor(
      initial_element, FocusgroupType::kLinear);
  if (!initial_focusgroup)
    return false;
  bool can_only_ascend = !utils::IsAxisSupported(
      initial_focusgroup->GetFocusgroupFlags(), direction);

  Element* current = initial_element;
  Element* parent = FlatTreeTraversal::ParentElement(*current);
  while (true) {
    // 2. To find the previous focusgroup item, we start by getting the previous
    // element in preorder traversal. We are guaranteed to have a non-null
    // previous element since, below, we return as soon as the current as
    // reached the root most focusgroup.
    current = utils::PreviousElement(current);
    DCHECK(current);

    // 3. When going to the previous element in preorder traversal, there are 3
    // possible cases. We either moved:
    // i. to the sibling of the last element;
    // ii. to a descendant of the sibling of the last element;
    // iii. to the parent of the last element.
    //
    // When in (i), we know we are still part of the focusgroup the last element
    // was in. We can assume that the value of |current| is valid.
    //
    // When in (ii), we need to validate that we didn't descend into a different
    // focusgroup. `utils::AdjustElementOutOfUnrelatedFocusgroup` takes care of
    // that and, if it did descend in a separate focusgroup, it will return an
    // adjusted value for |current| out of that other focusgroup.
    //
    // When in (iii), we first need to try to wrap. If it succeeded, the
    // |current| element will be located on the last element of the focusgroup
    // and might have descended into another focusgroup. Once again, we'll need
    // to validate and potentially adjust the element using
    // `utils::AdjustElementOutOfUnrelatedFocusgroup`. If we can't wrap, we
    // must validate that |current|, which is now located on its parent, is
    // still part of the focusgroup.
    bool ascended = false;
    if (current == parent) {
      // Case (iii).
      Element* wrap_result = WrapBackward(current, direction);
      if (wrap_result) {
        current = utils::AdjustElementOutOfUnrelatedFocusgroup(
            wrap_result, parent, direction);
        parent = FlatTreeTraversal::ParentElement(*current);
      } else {
        // Wrapping wasn't an option. At this point, we can only attempt to
        // ascend to the parent.

        // We can't ascend out of a non-extending focusgroup.
        FocusgroupFlags current_flags = current->GetFocusgroupFlags();
        if (current_flags != FocusgroupFlags::kNone &&
            !(current_flags & FocusgroupFlags::kExtend)) {
          return false;
        }

        // We can't ascend if there is no focusgroup ancestor.
        Element* parent_focusgroup = utils::FindNearestFocusgroupAncestor(
            current, FocusgroupType::kLinear);
        if (!parent_focusgroup)
          return false;

        // We can't ascend if the parent focusgroup doesn't support the axis of
        // the arrow key pressed.
        if (!utils::IsAxisSupported(parent_focusgroup->GetFocusgroupFlags(),
                                    direction)) {
          return false;
        }

        // At this point, we are certain that we can ascend to the parent
        // element.
        ascended = true;
        parent = FlatTreeTraversal::ParentElement(*parent);
        // No need to check if the new |parent| is null or not because, if that
        // was the case, the check above for the |parent_focusgroup| would have
        // failed and returned early.
      }
    } else if (FlatTreeTraversal::ParentElement(*current) != parent) {
      // Case (ii).
      current = utils::AdjustElementOutOfUnrelatedFocusgroup(current, parent,
                                                             direction);
      parent = FlatTreeTraversal::ParentElement(*current);
    }

    // Avoid looping infinitely by breaking when the previous logical element is
    // the one we started on.
    if (current == initial_element)
      break;

    // 4. At this point, we know that |current| is a valid element in our
    // focusgroup. The only thing left to do is set the focus on the element if
    // it's a focusgroup item and we're allowed to do so. If not, we'll stay in
    // the loop until we find a suitable previous focusgroup item.
    if (!utils::IsFocusgroupItem(current))
      continue;

    // 5. When in a focusgroup that doesn't support the arrow axis, we still
    // iterate over the previous elements in the hopes of ascending to another
    // focusgroup. Ascending from a focusgroup that doesn't support the arrow
    // axis is permitted only when the focused element was the first focusgroup
    // item in a focusgroup.
    if (can_only_ascend && !ascended) {
      // Here, since we found out that there was a previous item, ascending is
      // not an option anymore so we break out of the loop to indicate that
      // advancing backward wasn't possible.
      break;
    }

    Focus(current, direction);
    return true;
  }

  return false;
}

// static
Element* FocusgroupController::WrapBackward(Element* current,
                                            FocusgroupDirection direction) {
  DCHECK(current);
  DCHECK(utils::IsDirectionBackward(direction));

  FocusgroupFlags current_flags = current->GetFocusgroupFlags();

  if (current_flags == FocusgroupFlags::kNone)
    return nullptr;

  if (!utils::IsAxisSupported(current_flags, direction))
    return nullptr;

  if (!utils::WrapsInDirection(current_flags, direction))
    return nullptr;

  // Don't wrap when on a focusgroup that got its wrapping behavior in this
  // axis from its parent focusgroup - that other focusgroup will handle the
  // wrapping once we'll reach it.
  Element* parent_focusgroup =
      utils::FindNearestFocusgroupAncestor(current, FocusgroupType::kLinear);
  if (current_flags & FocusgroupFlags::kExtend && parent_focusgroup &&
      utils::WrapsInDirection(parent_focusgroup->GetFocusgroupFlags(),
                              direction)) {
    return nullptr;
  }

  return utils::LastElementWithin(current);
}

// static
bool FocusgroupController::AdvanceInGrid(Element* initial_element,
                                         Element* grid_root,
                                         FocusgroupDirection direction) {
  DCHECK(initial_element);
  DCHECK(grid_root);

  grid_root->GetDocument().View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kFocusgroup);

  auto* helper = utils::CreateGridFocusgroupStructureInfoForGridRoot(grid_root);

  Element* current = initial_element;
  while (true) {
    // 1. Move to the next cell in the appropriate |direction|.
    Element* previous = current;
    switch (direction) {
      case FocusgroupDirection::kBackwardInline:
        current = helper->PreviousCellInRow(current);
        break;
      case FocusgroupDirection::kForwardInline:
        current = helper->NextCellInRow(current);
        break;
      case FocusgroupDirection::kBackwardBlock:
        current = helper->PreviousCellInColumn(current);
        break;
      case FocusgroupDirection::kForwardBlock:
        current = helper->NextCellInColumn(current);
        break;
      default:
        NOTREACHED();
    }

    // 2. If no next cell was found, attempt to wrap/flow.
    if (!current) {
      current = WrapOrFlowInGrid(previous, direction, helper);
      if (!current) {
        // There are no cell and we were unable to wrap/flow. The advance step
        // failed.
        break;
      }
    }

    // Avoid looping infinitely by breaking when the new next/previous logical
    // element is the one we started on.
    if (current == initial_element)
      break;

    // 3. Only set the focus on grid focusgroup items. If we're on a cell that
    // isn't a grid focusgroup item, keep going to the next/previous element
    // until we find a valid item or we exhausted all the options.
    if (utils::IsGridFocusgroupItem(current)) {
      Focus(current, direction);
      return true;
    }
  }

  return false;
}

// static
Element* FocusgroupController::WrapOrFlowInGrid(
    Element* element,
    FocusgroupDirection direction,
    GridFocusgroupStructureInfo* helper) {
  DCHECK(element);
  DCHECK(helper->Root());
  FocusgroupFlags flags = helper->Root()->GetFocusgroupFlags();

  switch (direction) {
    case FocusgroupDirection::kBackwardInline:
      // This is only possible when on the first cell within a row.
      if (flags & FocusgroupFlags::kWrapInline) {
        // Wrapping backward in a row means that we should move the focus to the
        // last cell in the same row.
        Element* row = helper->RowForCell(element);
        DCHECK(row);
        return helper->LastCellInRow(row);
      } else if (flags & FocusgroupFlags::kRowFlow) {
        // Flowing backward in a row means that we should move the focus to the
        // last cell of the previous row. If there is no previous row, move the
        // focus to the last cell of the last row within the grid.
        Element* row = helper->RowForCell(element);
        Element* previous_row = helper->PreviousRow(row);
        if (!previous_row) {
          previous_row = helper->LastRow();
        }
        return helper->LastCellInRow(previous_row);
      }
      break;

    case FocusgroupDirection::kForwardInline:
      // This is only possible when on the last cell within a row.
      if (flags & FocusgroupFlags::kWrapInline) {
        // Wrapping forward in a row means that we should move the focus to the
        // first cell of the same row.
        Element* row = helper->RowForCell(element);
        DCHECK(row);
        return helper->FirstCellInRow(row);
      } else if (flags & FocusgroupFlags::kRowFlow) {
        // Flowing forward in a row means that we should move the focus to the
        // first cell in the next row. If there is no next row, then we should
        // move the focus to the first cell of the first row within the grid.
        Element* row = helper->RowForCell(element);
        Element* next_row = helper->NextRow(row);
        if (!next_row) {
          next_row = helper->FirstRow();
        }
        return helper->FirstCellInRow(next_row);
      }
      break;

    case FocusgroupDirection::kBackwardBlock:
      // This is only possible when on the first cell within a column.
      if (flags & FocusgroupFlags::kWrapBlock) {
        // Wrapping backward in a column means that we should move the focus to
        // the last cell in the same column.
        unsigned cell_index = helper->ColumnIndexForCell(element);
        return helper->LastCellInColumn(cell_index);
      } else if (flags & FocusgroupFlags::kColFlow) {
        // Flowing backward in a column means that we should move the focus to
        // the last cell of the previous column. If there is no previous
        // column, then we should move the focus to the last cell of the last
        // column in the grid.
        unsigned cell_index = helper->ColumnIndexForCell(element);
        if (cell_index == 0)
          cell_index = helper->ColumnCount();
        return helper->LastCellInColumn(cell_index - 1);
      }
      break;

    case FocusgroupDirection::kForwardBlock:
      // This is only possible when on the last cell within a column.
      if (flags & FocusgroupFlags::kWrapBlock) {
        // Wrapping forward in a column means that we should move the focus to
        // first cell in the same column.
        unsigned cell_index = helper->ColumnIndexForCell(element);
        return helper->FirstCellInColumn(cell_index);
      } else if (flags & FocusgroupFlags::kColFlow) {
        // Flowing forward in a column means that we should move the focus to
        // the first cell of the next column. If there is no next column, then
        // we should move the focus to the first cell of the first column within
        // the grid.
        unsigned cell_index = helper->ColumnIndexForCell(element) + 1;
        if (cell_index >= helper->ColumnCount())
          cell_index = 0;
        return helper->FirstCellInColumn(cell_index);
      }
      break;
    default:
      NOTREACHED();
  }

  return nullptr;
}

// static
void FocusgroupController::Focus(Element* element,
                                 FocusgroupDirection direction) {
  DCHECK(element);
  element->Focus(FocusParams(SelectionBehaviorOnFocus::kReset,
                             utils::IsDirectionForward(direction)
                                 ? mojom::blink::FocusType::kForward
                                 : mojom::blink::FocusType::kBackward,
                             nullptr));
}

}  // namespace blink
```