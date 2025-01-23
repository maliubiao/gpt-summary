Response:
The user wants a summary of the functionality of the provided C++ source code file `blink/renderer/core/input/event_handler.cc`. I need to identify the core responsibilities of this file by analyzing its content, including:

1. **Core Functionality:** What is the primary role of `EventHandler`?  Based on the file name and included headers, it likely handles input events.
2. **Relationship with Web Technologies:** How does this C++ code interact with JavaScript, HTML, and CSS? Look for connections in the code.
3. **Logical Reasoning:**  Are there any logical deductions or workflows implemented in the code? I should look for examples where input leads to a specific output or state change.
4. **Common Usage Errors:** What mistakes might a developer or user make that would involve this code?
5. **User Interaction Flow:** How does a user's action in the browser eventually trigger code execution in this file?
6. **Concise Summary:**  Finally, I need to summarize the identified functionalities in a clear and concise manner, as this is only the first part of the file.
```
功能归纳：

blink/renderer/core/input/event_handler.cc 文件主要负责处理浏览器接收到的各种输入事件，例如鼠标事件、键盘事件、触摸事件等，并将这些事件分发到相应的目标进行处理。  它在 Chromium Blink 引擎中扮演着核心的角色，连接了用户输入与页面内容的交互。

**核心功能点包括：**

1. **事件接收与分发:**  该文件是接收底层浏览器输入事件的入口，它负责接收操作系统或其他浏览器组件传递过来的 WebInputEvent，并将其转换为 Blink 内部的事件对象 (MouseEvent, KeyboardEvent, TouchEvent 等)。然后根据事件类型和位置，确定事件的目标元素，并将事件传递给该元素或其相关的事件监听器进行处理。
2. **鼠标事件处理:** 负责处理各种鼠标事件，如点击 (mousedown, mouseup, click)、移动 (mousemove)、滚轮 (wheel) 等。它需要进行命中测试 (hit testing) 以确定鼠标事件发生时鼠标指针下的元素。
3. **键盘事件处理:**  处理键盘按键事件 (keydown, keyup, keypress)，涉及到文本输入、快捷键操作等。
4. **触摸事件处理:**  处理触摸屏上的触摸操作事件 (touchstart, touchmove, touchend, touchcancel)。
5. **拖放 (Drag and Drop) 功能:**  管理拖放操作的整个流程，包括 dragstart, drag, dragenter, dragover, drop, dragend 等事件的处理。
6. **光标 (Cursor) 管理:**  根据鼠标指针下的元素和其样式 (CSS `cursor` 属性) 决定显示的光标样式。
7. **选择 (Selection) 控制:**  与 `SelectionController` 协作，处理用户通过鼠标或键盘进行的文本或元素选择操作。
8. **滚动 (Scroll) 管理:**  与 `ScrollManager` 协作，处理页面滚动事件，包括用户滚动和程序化滚动。
9. **焦点 (Focus) 管理 (间接相关):** 虽然代码片段中没有直接体现，但事件处理通常与焦点管理密切相关，例如，键盘事件的目标元素通常是当前拥有焦点的元素。
10. **手势 (Gesture) 识别 (间接相关):** 通过 `GestureManager` 处理更高级的手势操作，这些手势可能由多个触摸事件或鼠标事件组合而成。

**与 JavaScript, HTML, CSS 的关系：**

*   **JavaScript:**  `EventHandler` 的最终目标是将事件传递给 JavaScript 代码中注册的事件监听器。当 JavaScript 代码通过 `addEventListener` 等方法为一个 HTML 元素注册了事件监听器后，当相应的事件发生并被 `EventHandler` 处理后，会触发 JavaScript 监听器的执行。
    *   **举例:**  用户点击一个按钮 `<button onclick="myFunction()">Click Me</button>`。
        1. 操作系统捕获到鼠标点击事件。
        2. 该事件被传递到 Blink 引擎。
        3. `EventHandler` 接收到鼠标按下 (mousedown) 和鼠标抬起 (mouseup) 事件。
        4. `EventHandler` 进行命中测试，确定点击的目标是该 `<button>` 元素。
        5. `EventHandler` 将 "click" 事件分发到该按钮元素。
        6. 浏览器执行按钮元素上注册的 JavaScript 函数 `myFunction()`。
*   **HTML:**  HTML 定义了页面上的元素，这些元素是事件的目标。`EventHandler` 需要理解 HTML 结构，进行命中测试以确定事件发生的位置和目标元素。
    *   **举例:**  用户在一个链接 `<a>` 元素上移动鼠标。
        1. 操作系统捕获到鼠标移动事件。
        2. `EventHandler` 接收到 `mousemove` 事件。
        3. `EventHandler` 进行命中测试，确定鼠标指针当前位于该 `<a>` 元素之上。
        4. `EventHandler` 可能会触发一些与链接相关的行为，例如高亮显示或显示链接目标地址（如果鼠标悬停一段时间）。
*   **CSS:**  CSS 样式会影响事件处理的某些方面，例如：
    *   **光标样式:** CSS 的 `cursor` 属性决定了鼠标指针在不同元素上显示的样式，`EventHandler` 会根据元素的 CSS 样式来设置光标。
    *   **事件穿透 (pointer-events):**  CSS 的 `pointer-events` 属性可以控制元素是否可以成为鼠标事件的目标，`EventHandler` 在进行命中测试时会考虑这个属性。
    *   **可编辑区域:** CSS 样式决定了哪些区域是可编辑的，这会影响键盘事件和文本输入的处理。
    *   **拖放效果:** CSS 样式可以影响拖放操作的视觉反馈。
    *   **举例 (光标):**  一个设置了 `cursor: pointer;` 样式的 `<div>` 元素。
        1. 当鼠标移动到该 `<div>` 元素上方时，`EventHandler` 进行命中测试。
        2. `EventHandler` 获取该 `<div>` 元素的计算样式，发现 `cursor` 属性为 `pointer`。
        3. `EventHandler` 指示浏览器将鼠标光标更改为手指形状。

**逻辑推理的假设输入与输出：**

*   **假设输入:**  用户在屏幕坐标 (100, 200) 处点击鼠标左键。当前页面有一个位于该坐标下的按钮元素 `<button id="myButton">Click Me</button>`.
*   **逻辑推理:**
    1. `EventHandler` 接收到 `mousedown` 事件，坐标为 (100, 200)。
    2. 进行命中测试，确定坐标 (100, 200) 处的元素是 ID 为 "myButton" 的按钮。
    3. 如果该按钮上没有捕获鼠标事件，则将 `mousedown` 事件分发给该按钮元素。
*   **假设输出:**  按钮元素接收到 `mousedown` 事件，可能触发其默认行为（例如按钮按下的视觉效果）或与其关联的 JavaScript 事件监听器。

**用户或编程常见的使用错误：**

*   **preventDefault() 的误用:**  JavaScript 代码中不恰当地调用 `event.preventDefault()` 可能会阻止浏览器的默认行为，例如阻止链接的跳转或表单的提交。这与 `EventHandler` 的工作息息相关，因为它负责处理和分发事件，而 `preventDefault()` 会影响事件的传播和默认行为的执行。
    *   **例子:**  一个开发者为了实现自定义的链接跳转动画，在 `<a>` 元素的 `click` 事件监听器中调用了 `event.preventDefault()`，但忘记实现实际的跳转逻辑，导致链接点击后没有任何反应。
*   **事件监听器的注册错误:**  开发者可能将事件监听器注册到错误的元素上，或者使用了错误的事件类型，导致事件无法被正确处理。虽然这主要是 JavaScript 编程的错误，但最终会影响 `EventHandler` 的事件分发流程。
    *   **例子:**  开发者想要监听一个输入框的键盘输入事件，但错误地将监听器注册到了包含该输入框的 `<div>` 元素上，导致键盘事件无法被正确捕获。
*   **冒泡和捕获阶段的理解错误:**  对事件冒泡和捕获阶段的理解不足可能导致事件处理逻辑出现问题。例如，在捕获阶段阻止了事件的传播，导致目标元素无法接收到事件。`EventHandler` 负责按照正确的顺序处理事件的捕获和冒泡阶段。
*   **命中测试的假设错误:**  在某些复杂的布局中，开发者可能会错误地假设事件会命中某个特定的元素，而实际上由于元素的层叠顺序、transform 等 CSS 属性的影响，事件可能被其他元素拦截。 `EventHandler` 的命中测试逻辑是确定事件目标的关键。

**用户操作如何一步步到达这里（作为调试线索）：**

以一个简单的鼠标点击操作为例：

1. **用户操作:** 用户将鼠标指针移动到浏览器窗口的某个位置，并按下鼠标左键。
2. **操作系统捕获:** 操作系统 (Windows, macOS, Linux 等) 捕获到鼠标事件，包括鼠标的位置和按键状态。
3. **浏览器进程接收:**  浏览器进程接收到操作系统传递的鼠标事件信息。
4. **渲染进程处理 (输入管道):**  浏览器进程将事件信息传递给负责渲染页面的渲染进程。渲染进程的输入管道 (Input Pipeline)  接收并初步处理这些事件。
5. **WebInputEvent 创建:**  输入管道将操作系统的原生事件信息转换为 Blink 引擎内部的 `WebInputEvent` 对象。
6. **EventHandler 接收:**  `blink/renderer/core/input/event_handler.cc` 中的 `EventHandler` 对象接收到这个 `WebInputEvent`。
7. **事件类型判断与转换:**  `EventHandler` 根据 `WebInputEvent` 的类型，将其转换为更具体的事件对象，例如 `MouseEvent`。
8. **命中测试:**  `EventHandler` 使用事件的屏幕坐标或客户端坐标，执行命中测试 (通过调用 `HitTestResultAtLocation` 等方法)，确定鼠标点击位置下的 DOM 元素。这个过程会遍历渲染树，找到最合适的事件目标。
9. **事件分发:**  `EventHandler` 将创建的事件对象分发到目标元素。这可能涉及到事件冒泡或捕获阶段的处理，将事件传递给目标元素及其祖先元素上注册的事件监听器。
10. **JavaScript 处理 (如果存在):** 如果目标元素或其祖先元素上注册了相应的 JavaScript 事件监听器，这些监听器会被执行。

**功能归纳（针对提供的代码片段 - 第1部分）：**

根据提供的代码片段，该部分主要集中在 `EventHandler` 类的**初始化、基本属性定义、以及一些辅助函数的实现**。  核心功能仍然是处理输入事件，但具体到这部分，更侧重于：

*   **`EventHandler` 类的构造和析构:**  初始化各种成员变量，例如 `SelectionController`, `hover_timer_`, `cursor_update_timer_` 以及各种事件管理器 (MouseEventManager, KeyboardEventManager 等)。
*   **跟踪鼠标和触摸状态:**  维护一些状态信息，例如 `capturing_mouse_events_element_` (正在捕获鼠标事件的元素), `last_mouse_move_event_subframe_` (上次鼠标移动事件的子框架) 等。
*   **命中测试的基础设施:**  提供了 `PerformHitTest` 和 `HitTestResultAtLocation` 方法，用于确定给定坐标下的元素。
*   **光标更新机制:**  定义了 `UpdateCursor` 和 `CursorUpdateTimerFired` 方法，用于根据鼠标位置和元素样式更新光标。
*   **与滚动相关的初步功能:**  包含与滚动相关的 `BubblingScroll` 和 `StopAutoscroll` 方法，但具体的滚动逻辑可能在 `ScrollManager` 中实现。
*   **一些辅助函数:**  例如 `UsesHandCursor` (判断是否应该显示手型光标), `ShouldShowResizeForNode` (判断是否应该显示调整大小的光标), `IsSelectingLink` (判断是否正在选择链接) 等。

总而言之，这部分代码搭建了 `EventHandler` 的基本框架，并实现了处理输入事件的一些核心辅助功能，为后续更复杂的事件处理逻辑奠定了基础。
```
### 提示词
```
这是目录为blink/renderer/core/input/event_handler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
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

#include "third_party/blink/renderer/core/input/event_handler.h"

#include <memory>
#include <utility>

#include "base/check.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/mojom/use_counter/metrics/web_feature.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/web/web_link_preview_triggerer.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/events/pointer_event_factory.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_frame_set_element.h"
#include "third_party/blink/renderer/core/input/event_handling_util.h"
#include "third_party/blink/renderer/core/input/input_device_capabilities.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/custom_scrollbar.h"
#include "third_party/blink/renderer/core/layout/geometry/physical_offset.h"
#include "third_party/blink/renderer/core/layout/hit_test_request.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_custom_scrollbar_part.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/anchor_element_interaction_tracker.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/autoscroll_controller.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/drag_state.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/touch_adjustment.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/scroll/scroll_types.h"
#include "third_party/blink/renderer/core/scroll/scrollbar.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/core/style/computed_style_base_constants.h"
#include "third_party/blink/renderer/core/style/cursor_data.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image_for_container.h"
#include "third_party/blink/renderer/core/svg/svg_use_element.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/cursors.h"
#include "third_party/blink/renderer/platform/geometry/layout_unit.h"
#include "third_party/blink/renderer/platform/graphics/image_orientation.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/post_cancellable_task.h"
#include "third_party/blink/renderer/platform/windows_keyboard_codes.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/skia/include/core/SkBitmap.h"
#include "ui/base/cursor/cursor.h"
#include "ui/base/cursor/mojom/cursor_type.mojom-blink.h"
#include "ui/base/dragdrop/mojom/drag_drop_types.mojom-blink.h"
#include "ui/display/screen_info.h"
#include "ui/display/screen_infos.h"
#include "ui/gfx/geometry/point.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/point_f.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/size_conversions.h"
#include "ui/gfx/geometry/size_f.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

// Refetch the event target node if it is removed or currently is the shadow
// node inside an <input> element.  If a mouse event handler changes the input
// element type to one that has a EmbeddedContentView associated, we'd like to
// EventHandler::handleMousePressEvent to pass the event to the
// EmbeddedContentView and thus the event target node can't still be the shadow
// node.
bool ShouldRefetchEventTarget(const MouseEventWithHitTestResults& mev) {
  Node* target_node = mev.InnerNode();
  if (!target_node || !target_node->parentNode())
    return true;
  if (auto* shadow_root = DynamicTo<ShadowRoot>(target_node))
    return IsA<HTMLInputElement>(shadow_root->host());
  return false;
}

gfx::Point GetMiddleSelectionCaretOfPosition(
    const PositionWithAffinity& position) {
  const LocalCaretRect& local_caret_rect = LocalCaretRectOfPosition(position);
  if (local_caret_rect.IsEmpty())
    return gfx::Point();
  const gfx::Rect rect = AbsoluteCaretBoundsOf(position);
  // In a multiline edit, rect.bottom() would end up on the next line, so
  // take the midpoint in order to use this corner point directly.
  if (local_caret_rect.layout_object->IsHorizontalWritingMode())
    return {rect.x(), (rect.y() + rect.bottom()) / 2};

  // When text is vertical, rect.right() would end up on the next line, so
  // take the midpoint in order to use this corner point directly.
  return {(rect.x() + rect.right()) / 2, rect.y()};
}

bool ContainsEvenAtEdge(const gfx::Rect& rect, const gfx::Point& point) {
  return point.x() >= rect.x() && point.x() <= rect.right() &&
         point.y() >= rect.y() && point.y() <= rect.bottom();
}

gfx::Point DetermineHotSpot(const Image& image,
                            bool hot_spot_specified,
                            const gfx::Point& specified_hot_spot) {
  if (hot_spot_specified) {
    return specified_hot_spot;
  }

  // If hot spot is not specified externally, it can be extracted from some
  // image formats (e.g. .cur).
  gfx::Point intrinsic_hot_spot;
  const bool image_has_intrinsic_hot_spot =
      image.GetHotSpot(intrinsic_hot_spot);
  const gfx::Rect image_rect = image.Rect();
  if (image_has_intrinsic_hot_spot && image_rect.Contains(intrinsic_hot_spot))
    return intrinsic_hot_spot;

  // If neither is provided, use a default value of (0, 0).
  return gfx::Point();
}

// Returns whether the hit element contains a title and isn't a SVGUseElement or
// part of an SVGUseElement.
bool HasTitleAndNotSVGUseElement(const HitTestResult& hovered_node_result) {
  Node* inner_node = hovered_node_result.InnerNode();
  if (!inner_node) {
    return false;
  }
  auto* element = DynamicTo<Element>(inner_node);
  if (!element || element->title().IsNull()) {
    return false;
  }
  ShadowRoot* containing_shadow_root = inner_node->ContainingShadowRoot();
  if (IsA<SVGUseElement>(element) ||
      (containing_shadow_root &&
       IsA<SVGUseElement>(containing_shadow_root->host()))) {
    return false;
  }
  return true;
}

// Get the entire style of scrollbar to get the cursor style of scrollbar
const ComputedStyle* GetComputedStyleFromScrollbar(
    const LayoutObject& layout_object,
    const HitTestResult& result) {
  if (result.IsOverScrollCorner()) {
    PaintLayerScrollableArea* scrollable_area =
        To<LayoutBox>(layout_object).GetScrollableArea();

    // For a frame, hit tests over scroll controls are considered to be over
    // the document element, but the scrollable area belongs to the LayoutView,
    // not the document element's LayoutObject.
    if (layout_object.IsDocumentElement()) {
      scrollable_area = layout_object.View()->GetScrollableArea();
    }

    // TODO(crbug.com/1519197): if the mouse is over a scroll corner, there must
    // be a scrollable area. Investigate where this is coming from.
    if (!scrollable_area) {
      SCOPED_CRASH_KEY_STRING64("cr1519197", "hit-object",
                                layout_object.DebugName().Utf8());
      base::debug::DumpWithoutCrashing();
      return nullptr;
    }

    LayoutCustomScrollbarPart* scroll_corner_layout_object =
        scrollable_area->ScrollCorner();
    if (scroll_corner_layout_object) {
      return scroll_corner_layout_object->Style();
    }
  }

  if (result.GetScrollbar() && result.GetScrollbar()->IsCustomScrollbar()) {
    const auto& custom_scroll_bar = To<CustomScrollbar>(*result.GetScrollbar());

    if (const ComputedStyle* style =
            custom_scroll_bar.GetScrollbarPartStyleForCursor(
                custom_scroll_bar.HoveredPart())) {
      return style;
    }
  }
  return nullptr;
}

}  // namespace

// The amount of time to wait for a cursor update on style and layout changes
// Set to 50Hz, no need to be faster than common screen refresh rate
static constexpr base::TimeDelta kCursorUpdateInterval = base::Milliseconds(20);

// The maximum size a cursor can be without falling back to the default cursor
// when intersecting browser native UI.
// https://developer.mozilla.org/en-US/docs/Web/CSS/cursor#icon_size_limits.
static const int kMaximumCursorSizeWithoutFallback = 32;

// The minimum amount of time an element stays active after a ShowPress
// This is roughly 9 frames, which should be long enough to be noticeable.
constexpr base::TimeDelta kMinimumActiveInterval = base::Seconds(0.15);

EventHandler::EventHandler(LocalFrame& frame)
    : frame_(frame),
      selection_controller_(MakeGarbageCollected<SelectionController>(frame)),
      hover_timer_(frame.GetTaskRunner(TaskType::kUserInteraction),
                   this,
                   &EventHandler::HoverTimerFired),
      cursor_update_timer_(
          frame.GetTaskRunner(TaskType::kInternalUserInteraction),
          this,
          &EventHandler::CursorUpdateTimerFired),
      should_only_fire_drag_over_event_(false),
      event_handler_registry_(
          frame_->IsLocalRoot()
              ? MakeGarbageCollected<EventHandlerRegistry>(*frame_)
              : &frame_->LocalFrameRoot().GetEventHandlerRegistry()),
      scroll_manager_(MakeGarbageCollected<ScrollManager>(frame)),
      mouse_event_manager_(
          MakeGarbageCollected<MouseEventManager>(frame, *scroll_manager_)),
      mouse_wheel_event_manager_(
          MakeGarbageCollected<MouseWheelEventManager>(frame,
                                                       *scroll_manager_)),
      keyboard_event_manager_(
          MakeGarbageCollected<KeyboardEventManager>(frame, *scroll_manager_)),
      pointer_event_manager_(
          MakeGarbageCollected<PointerEventManager>(frame,
                                                    *mouse_event_manager_)),
      gesture_manager_(
          MakeGarbageCollected<GestureManager>(frame,
                                               *scroll_manager_,
                                               *mouse_event_manager_,
                                               *pointer_event_manager_,
                                               *selection_controller_)),
      active_interval_timer_(frame.GetTaskRunner(TaskType::kUserInteraction),
                             this,
                             &EventHandler::ActiveIntervalTimerFired) {}

void EventHandler::Trace(Visitor* visitor) const {
  visitor->Trace(frame_);
  visitor->Trace(selection_controller_);
  visitor->Trace(hover_timer_);
  visitor->Trace(cursor_update_timer_);
  visitor->Trace(capturing_mouse_events_element_);
  visitor->Trace(capturing_subframe_element_);
  visitor->Trace(last_mouse_move_event_subframe_);
  visitor->Trace(last_scrollbar_under_mouse_);
  visitor->Trace(drag_target_);
  visitor->Trace(frame_set_being_resized_);
  visitor->Trace(event_handler_registry_);
  visitor->Trace(scroll_manager_);
  visitor->Trace(mouse_event_manager_);
  visitor->Trace(mouse_wheel_event_manager_);
  visitor->Trace(keyboard_event_manager_);
  visitor->Trace(pointer_event_manager_);
  visitor->Trace(gesture_manager_);
  visitor->Trace(active_interval_timer_);
  visitor->Trace(last_deferred_tap_element_);
}

void EventHandler::Clear() {
  hover_timer_.Stop();
  cursor_update_timer_.Stop();
  active_interval_timer_.Stop();
  last_mouse_move_event_subframe_ = nullptr;
  last_scrollbar_under_mouse_ = nullptr;
  frame_set_being_resized_ = nullptr;
  drag_target_ = nullptr;
  should_only_fire_drag_over_event_ = false;
  capturing_mouse_events_element_ = nullptr;
  capturing_subframe_element_ = nullptr;
  pointer_event_manager_->Clear();
  scroll_manager_->Clear();
  gesture_manager_->Clear();
  mouse_event_manager_->Clear();
  mouse_wheel_event_manager_->Clear();
  last_show_press_timestamp_.reset();
  last_deferred_tap_element_ = nullptr;
  should_use_touch_event_adjusted_point_ = false;
  touch_adjustment_result_.unique_event_id = 0;
}

void EventHandler::UpdateSelectionForMouseDrag() {
  mouse_event_manager_->UpdateSelectionForMouseDrag();
}

void EventHandler::StartMiddleClickAutoscroll(LayoutObject* layout_object) {
  DCHECK(RuntimeEnabledFeatures::MiddleClickAutoscrollEnabled());
  if (!layout_object->IsBox())
    return;
  AutoscrollController* controller = scroll_manager_->GetAutoscrollController();
  if (!controller)
    return;

  LayoutBox* scrollable = LayoutBox::FindAutoscrollable(
      layout_object, /*is_middle_click_autoscroll*/ true);

  controller->StartMiddleClickAutoscroll(
      layout_object->GetFrame(), scrollable,
      LastKnownMousePositionInRootFrame(),
      mouse_event_manager_->LastKnownMouseScreenPosition());
  mouse_event_manager_->InvalidateClick();
}

void EventHandler::PerformHitTest(const HitTestLocation& location,
                                  HitTestResult& result,
                                  bool no_lifecycle_update) const {
  // LayoutView::hitTest causes a layout, and we don't want to hit that until
  // the first layout because until then, there is nothing shown on the screen -
  // the user can't have intentionally clicked on something belonging to this
  // page.  Furthermore, mousemove events before the first layout should not
  // lead to a premature layout() happening, which could show a flash of white.
  // See also the similar code in Document::performMouseEventHitTest.
  // The check to LifecycleUpdatesActive() prevents hit testing to frames
  // that have already had layout but are throttled to prevent painting
  // because the current Document isn't ready to render yet. In that case
  // the lifecycle update prompted by HitTest() would fail.
  if (!frame_->ContentLayoutObject() || !frame_->View() ||
      !frame_->View()->DidFirstLayout() ||
      !frame_->View()->LifecycleUpdatesActive())
    return;

  if (no_lifecycle_update) {
    frame_->ContentLayoutObject()->HitTestNoLifecycleUpdate(location, result);
  } else {
    frame_->ContentLayoutObject()->HitTest(location, result);
  }
  const HitTestRequest& request = result.GetHitTestRequest();
  if (!request.ReadOnly()) {
    frame_->GetDocument()->UpdateHoverActiveState(
        request.Active(), !request.Move(), result.InnerElement());
  }
}

HitTestResult EventHandler::HitTestResultAtLocation(
    const HitTestLocation& location,
    HitTestRequest::HitTestRequestType hit_type,
    const LayoutObject* stop_node,
    bool no_lifecycle_update,
    std::optional<HitTestRequest::HitNodeCb> hit_node_cb) {
  TRACE_EVENT0("blink", "EventHandler::HitTestResultAtLocation");

  // We always send HitTestResultAtLocation to the main frame if we have one,
  // otherwise we might hit areas that are obscured by higher frames.
  if (frame_->GetPage()) {
    LocalFrame& main_frame = frame_->LocalFrameRoot();
    if (frame_ != &main_frame) {
      LocalFrameView* frame_view = frame_->View();
      LocalFrameView* main_view = main_frame.View();
      if (frame_view && main_view) {
        HitTestLocation adjusted_location;
        if (location.IsRectBasedTest()) {
          DCHECK(location.IsRectilinear());
          if (hit_type & HitTestRequest::kHitTestVisualOverflow) {
            // Apply ancestor transforms to location rect
            PhysicalRect local_rect = location.BoundingBox();
            PhysicalRect main_frame_rect =
                frame_view->GetLayoutView()->LocalToAncestorRect(
                    local_rect, main_view->GetLayoutView(),
                    kTraverseDocumentBoundaries);
            adjusted_location = HitTestLocation(main_frame_rect);
          } else {
            // Don't apply ancestor transforms to bounding box
            PhysicalOffset main_content_point = main_view->ConvertFromRootFrame(
                frame_view->ConvertToRootFrame(location.BoundingBox().offset));
            adjusted_location = HitTestLocation(
                PhysicalRect(main_content_point, location.BoundingBox().size));
          }
        } else {
          adjusted_location = HitTestLocation(main_view->ConvertFromRootFrame(
              frame_view->ConvertToRootFrame(location.Point())));
        }
        return main_frame.GetEventHandler().HitTestResultAtLocation(
            adjusted_location, hit_type, stop_node, no_lifecycle_update);
      }
    }
  }
  // HitTestResultAtLocation is specifically used to hitTest into all frames,
  // thus it always allows child frame content.
  HitTestRequest request(hit_type | HitTestRequest::kAllowChildFrameContent,
                         stop_node, std::move(hit_node_cb));
  HitTestResult result(request, location);
  PerformHitTest(location, result, no_lifecycle_update);
  return result;
}

void EventHandler::StopAutoscroll() {
  scroll_manager_->StopMiddleClickAutoscroll();
  scroll_manager_->StopAutoscroll();
}

// TODO(bokan): This should be merged with logicalScroll assuming
// defaultSpaceEventHandler's chaining scroll can be done crossing frames.
bool EventHandler::BubblingScroll(mojom::blink::ScrollDirection direction,
                                  ui::ScrollGranularity granularity,
                                  Node* starting_node) {
  return scroll_manager_->BubblingScroll(
      direction, granularity, starting_node,
      mouse_event_manager_->MousePressNode());
}

gfx::PointF EventHandler::LastKnownMousePositionInRootFrame() const {
  return frame_->GetPage()->GetVisualViewport().ViewportToRootFrame(
      mouse_event_manager_->LastKnownMousePositionInViewport());
}

gfx::PointF EventHandler::LastKnownMouseScreenPosition() const {
  return mouse_event_manager_->LastKnownMouseScreenPosition();
}

gfx::Point EventHandler::DragDataTransferLocationForTesting() {
  if (mouse_event_manager_->GetDragState().drag_data_transfer_)
    return mouse_event_manager_->GetDragState()
        .drag_data_transfer_->DragLocation();

  return gfx::Point();
}

static bool IsSubmitImage(const Node* node) {
  auto* html_input_element = DynamicTo<HTMLInputElement>(node);
  return html_input_element &&
         html_input_element->FormControlType() == FormControlType::kInputImage;
}

bool EventHandler::UsesHandCursor(const Node* node) {
  if (!node)
    return false;
  return ((node->IsLink() || IsSubmitImage(node)) && !IsEditable(*node));
}

void EventHandler::CursorUpdateTimerFired(TimerBase*) {
  DCHECK(frame_);
  DCHECK(frame_->GetDocument());

  UpdateCursor();
}

void EventHandler::UpdateCursor() {
  TRACE_EVENT0("input", "EventHandler::updateCursor");

  // We must do a cross-frame hit test because the frame that triggered the
  // cursor update could be occluded by a different frame.
  DCHECK_EQ(frame_, &frame_->LocalFrameRoot());

  LocalFrameView* view = frame_->View();
  if (!view || !view->ShouldSetCursor())
    return;

  auto* layout_view = view->GetLayoutView();
  if (!layout_view)
    return;

  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kInput);

  HitTestRequest request(HitTestRequest::kReadOnly |
                         HitTestRequest::kAllowChildFrameContent);
  HitTestLocation location(view->ViewportToFrame(
      mouse_event_manager_->LastKnownMousePositionInViewport()));
  HitTestResult result(request, location);
  layout_view->HitTest(location, result);

  if (LocalFrame* frame = result.InnerNodeFrame()) {
    std::optional<ui::Cursor> optional_cursor =
        frame->GetEventHandler().SelectCursor(location, result);
    if (optional_cursor.has_value()) {
      view->SetCursor(optional_cursor.value());
    }
  }
}

bool EventHandler::ShouldShowResizeForNode(const LayoutObject& layout_object,
                                           const HitTestLocation& location) {
  const PaintLayer* layer = layout_object.EnclosingLayer();
  const PaintLayerScrollableArea* scrollable_area = layer->GetScrollableArea();
  return scrollable_area &&
         scrollable_area->IsAbsolutePointInResizeControl(
             ToRoundedPoint(location.Point()), kResizerForPointer);
}

bool EventHandler::IsSelectingLink(const HitTestResult& result) {
  // If a drag may be starting or we're capturing mouse events for a particular
  // node, don't treat this as a selection.
  // TODO(editing-dev): The use of UpdateStyleAndLayout needs to be audited. See
  // http://crbug.com/590369 for more details.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kSelection);

  const bool mouse_selection =
      !capturing_mouse_events_element_ &&
      mouse_event_manager_->MousePressed() &&
      GetSelectionController().MouseDownMayStartSelect() &&
      !mouse_event_manager_->MouseDownMayStartDrag() &&
      !frame_->Selection().ComputeVisibleSelectionInDOMTree().IsNone();
  return mouse_selection && result.IsOverLink();
}

bool EventHandler::ShouldShowIBeamForNode(const Node* node,
                                          const HitTestResult& result) {
  if (!node)
    return false;

  if (node->IsTextNode() && (node->CanStartSelection() || result.IsOverLink()))
    return true;

  return IsEditable(*node);
}

std::optional<ui::Cursor> EventHandler::SelectCursor(
    const HitTestLocation& location,
    const HitTestResult& result) {
  if (scroll_manager_->InResizeMode())
    return std::nullopt;

  Page* page = frame_->GetPage();
  if (!page)
    return std::nullopt;
  if (scroll_manager_->MiddleClickAutoscrollInProgress())
    return std::nullopt;

  if (result.GetScrollbar() && !result.GetScrollbar()->IsCustomScrollbar()) {
    return PointerCursor();
  }

  Node* node = result.InnerPossiblyPseudoNode();
  if (!node || !node->GetLayoutObject()) {
    return SelectAutoCursor(result, node, IBeamCursor());
  }

  const LayoutObject& layout_object = *node->GetLayoutObject();
  if (ShouldShowResizeForNode(layout_object, location)) {
    const LayoutBox* box = layout_object.EnclosingLayer()->GetLayoutBox();
    EResize resize = box->StyleRef().UsedResize();
    switch (resize) {
      case EResize::kVertical:
        return NorthSouthResizeCursor();
      case EResize::kHorizontal:
        return EastWestResizeCursor();
      case EResize::kBoth:
        if (box->ShouldPlaceBlockDirectionScrollbarOnLogicalLeft()) {
          return SouthWestResizeCursor();
        } else {
          return SouthEastResizeCursor();
        }
      default:
        return PointerCursor();
    }
  }

  {
    ui::Cursor override_cursor;
    switch (layout_object.GetCursor(result.LocalPoint(), override_cursor)) {
      case kSetCursorBasedOnStyle:
        break;
      case kSetCursor:
        return override_cursor;
      case kDoNotSetCursor:
        return std::nullopt;
    }
  }

  const ComputedStyle* scrollbar_style =
      GetComputedStyleFromScrollbar(layout_object, result);

  const ComputedStyle& style =
      scrollbar_style ? *scrollbar_style : layout_object.StyleRef();

  if (const CursorList* cursors = style.Cursors()) {
    for (const auto& cursor : *cursors) {
      const StyleImage* style_image = cursor.GetImage();
      if (!style_image || !style_image->CanRender()) {
        continue;
      }
      // The 'cursor' property only allow url() and image-set(). Either of
      // those will return false from their CanRender() implementation if they
      // don't have an ImageResourceContent (and the former should always have
      // one).
      CHECK(style_image->CachedImage());

      // Compute the concrete object size in DIP based on the
      // default cursor size obtained from the OS.
      gfx::SizeF size =
          style_image->ImageSize(1,
                                 gfx::SizeF(page->GetChromeClient()
                                                .GetScreenInfos(*frame_)
                                                .system_cursor_size),
                                 kRespectImageOrientation);

      float scale = style_image->ImageScaleFactor();
      Image* image = style_image->CachedImage()->GetImage();
      if (image->IsSVGImage()) {
        // `StyleImage::ImageSize` does not take `StyleImage::ImageScaleFactor`
        // into account when computing the size for SVG images.
        size.Scale(1 / scale);
      }

      if (size.IsEmpty() ||
          !ui::Cursor::AreDimensionsValidForWeb(
              gfx::ToCeiledSize(gfx::ScaleSize(size, scale)), scale)) {
        continue;
      }

      const float device_scale_factor =
          page->GetChromeClient().GetScreenInfo(*frame_).device_scale_factor;

      // If the image is an SVG, then adjust the scale to reflect the device
      // scale factor so that the SVG can be rasterized in the native
      // resolution and scaled down to the correct size for the cursor.
      scoped_refptr<Image> svg_image_holder;
      if (auto* svg_image = DynamicTo<SVGImage>(image)) {
        scale *= device_scale_factor;
        // Re-scale back from DIP to device pixels.
        size.Scale(scale);

        // TODO(fs): Should pass proper URL. Use StyleImage::GetImage.
        svg_image_holder = SVGImageForContainer::Create(
            *svg_image, size, device_scale_factor, nullptr,
            frame_->GetDocument()
                ->GetStyleEngine()
                .ResolveColorSchemeForEmbedding(&style));
        image = svg_image_holder.get();
      }

      // Convert from DIP to physical pixels.
      gfx::Point hot_spot = gfx::ScaleToRoundedPoint(cursor.HotSpot(), scale);

      const bool hot_spot_specified = cursor.HotSpotSpecified();
      ui::Cursor custom_cursor = ui::Cursor::NewCustom(
          image->AsSkBitmapForCurrentFrame(kRespectImageOrientation),
          DetermineHotSpot(*image, hot_spot_specified, hot_spot), scale);

      // For large cursors below the max size, limit their ability to cover UI
      // elements by removing them when they are not fully contained by the
      // visual viewport. Careful, we need to make sure to translate coordinate
      // spaces if we are in an OOPIF.
      //
      // TODO(csharrison): Consider sending a fallback cursor in the IPC to the
      // browser process so we can do that calculation there instead, this would
      // ensure even a compromised renderer could not obscure browser UI with a
      // large cursor. Also, consider augmenting the intervention to drop the
      // cursor for iframes if the cursor image obscures content in the parent
      // frame.
      gfx::SizeF custom_bitmap_size(custom_cursor.custom_bitmap().width(),
                                    custom_cursor.custom_bitmap().height());
      custom_bitmap_size.Scale(1.f / custom_cursor.image_scale_factor());
      if (custom_bitmap_size.width() > kMaximumCursorSizeWithoutFallback ||
          custom_bitmap_size.height() > kMaximumCursorSizeWithoutFallback) {
        PhysicalOffset ancestor_location =
            frame_->ContentLayoutObject()->LocalToAncestorPoint(
                location.Point(),
                nullptr,  // no ancestor maps all the way up the hierarchy
                kTraverseDocumentBoundaries | kApplyRemoteMainFrameTransform);

        // Check the cursor rect with device and accessibility scaling applied.
        const float scale_factor =
            cursor_accessibility_scale_factor_ *
            (image->IsSVGImage() ? 1.f : device_scale_factor);
        gfx::SizeF scaled_size(custom_bitmap_size);
        scaled_size.Scale(scale_factor);
        gfx::PointF scaled_hot_spot(custom_cursor.custom_hotspot());
        scaled_hot_spot.Scale(scale_factor /
                              custom_cursor.image_scale_factor());
        PhysicalRect cursor_rect(
            ancestor_location -
                PhysicalOffset::FromPointFFloor(scaled_hot_spot),
            PhysicalSize::FromSizeFFloor(scaled_size));

        PhysicalRect frame_rect(page->GetVisualViewport().VisibleContentRect());
        frame_->ContentLayoutObject()->MapToVisualRectInAncestorSpace(
            nullptr, frame_rect);

        if (!frame_rect.Contains(cursor_rect)) {
          continue;
        }
      }

      return custom_cursor;
    }
  }

  const ui::Cursor& i_beam =
      style.IsHorizontalWritingMode() ? IBeamCursor() : VerticalTextCursor();

  switch (style.Cursor()) {
    case ECursor::kAuto:
      return SelectAutoCursor(result, node, i_beam);
    case ECursor::kCrosshair:
      return CrossCursor();
    case ECursor::kPointer:
      return IsSelectingLink(result) ? i_beam : HandCursor();
    case ECursor::kMove:
      return MoveCursor();
    case ECursor::kAllScroll:
      return MoveCursor();
    case ECursor::kEResize:
      return EastResizeCursor();
    case ECursor::kWResize:
      return WestResizeCursor();
    case EC
```