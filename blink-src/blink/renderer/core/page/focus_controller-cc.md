Response:
The user wants a summary of the functionality of the provided C++ code snippet from `focus_controller.cc`. I need to identify the core responsibilities of this file based on the included headers and the code itself. I also need to connect these functionalities to web technologies like JavaScript, HTML, and CSS, providing illustrative examples. Furthermore, I need to discuss potential user or programming errors related to this code and describe how a user action might lead to this part of the code being executed, which can serve as debugging information.

Here's a breakdown of the thought process:

1. **Identify the core purpose:** The filename `focus_controller.cc` strongly suggests that this code manages the focus state within the Blink rendering engine. This will likely involve tracking the currently focused element, handling focus changes, and determining the order of focus traversal.

2. **Analyze included headers:** The included headers provide valuable clues about the file's functionalities:
    * `mojom/input/focus_type.mojom-blink.h`: Indicates involvement in different types of focus (e.g., programmatic, user-initiated).
    * Accessibility headers (`ax_object_cache.h`):  Suggests focus management is relevant to accessibility.
    * DOM headers (`dom/*.h`):  Confirms interaction with the Document Object Model, particularly elements and nodes.
    * Event headers (`dom/events/event.h`): Implies handling focus-related events (focus, blur, focusin, focusout).
    * Editing headers (`editing/*.h`): Suggests a connection to text input and editing, where focus is crucial.
    * Frame headers (`frame/*.h`): Indicates managing focus across different frames (iframes).
    * HTML headers (`html/*.h`): Shows specific handling for various HTML elements, especially form controls.
    * Layout headers (`layout/*.h`): Suggests that layout properties influence focus behavior (e.g., `display: contents`, positioning).
    * Page headers (`page/*.h`): Points to managing focus at the page level.
    * Spatial navigation (`page/spatial_navigation.h`): Hints at handling focus changes based on spatial relationships of elements.

3. **Examine the provided code:**
    * **`MaybeAdjustSearchElementForFocusGroup` and `MaybeRestoreFocusedElementForFocusGroup`:** These functions suggest special handling for "focus groups," potentially related to accessibility or custom UI components.
    * **`IsOpenPopoverWithInvoker` and related functions:**  Clearly indicates managing focus within popover elements, especially those triggered by invokers (buttons or other controls).
    * **Reading flow functions (`ReadingFlowContainerOrDisplayContents`, `IsReadingFlowItemScopeOwner`, `IsReadingFlowScopeOwner`):**  Points to a mechanism for navigating focus based on the reading order of content, which is crucial for accessibility and user experience in certain layouts.
    * **`FocusNavigation` class:** This is a key class that encapsulates the logic for determining the next and previous focusable elements within a given scope. It handles both DOM order and reading order traversal.
    * **`ScopedFocusNavigation` class:** This class appears to manage focus navigation within different scopes (documents, shadow trees, iframes, popovers, etc.), using the `FocusNavigation` class to perform the actual traversal.
    * **`DispatchBlurEvent` and `DispatchFocusEvent`:** These functions handle the firing of standard focus and blur events on DOM elements.
    * **`IsLikelyCaptchaIframe` and `IsLikelyWithinCaptchaIframe`:** Shows specific logic to potentially handle focus differently within or around iframes that are likely captchas.

4. **Relate to JavaScript, HTML, and CSS:**
    * **JavaScript:**  JavaScript can programmatically set focus using `element.focus()` and `window.focus()`. Focus events (focus, blur, focusin, focusout) are also handled by JavaScript. This code is responsible for implementing the underlying logic that makes these JavaScript APIs work.
    * **HTML:** HTML elements can be focusable (e.g., `<input>`, `<button>`, elements with `tabindex`). The `tabindex` attribute directly influences the focus order, and this code likely respects and uses this attribute. The `<slot>` element and shadow DOM features are explicitly handled, as are popovers.
    * **CSS:**  CSS properties like `display: none`, `visibility: hidden`, and `position: absolute/fixed` can affect whether an element is focusable or the order in which elements are focused. The code specifically mentions handling `display: contents`. Reading flow layout, though driven by layout algorithms, is influenced by CSS.

5. **Provide examples:**  For each connection to web technologies, I need to provide simple examples of how they interact.

6. **Consider logical reasoning (though not explicitly requested strongly by this snippet):** The logic for determining the next focusable element involves traversing the DOM or a reading-flow order. The input would be a starting element and a direction (forward or backward). The output would be the next focusable element in that direction.

7. **Identify user/programming errors:** Common errors include:
    * Setting `tabindex` to non-numeric values or inconsistent values.
    * Forgetting to make elements focusable when they should be.
    * Incorrectly using shadow DOM or slots, leading to unexpected focus behavior.
    * Not handling focus and blur events correctly in JavaScript, leading to accessibility issues or broken interactions.

8. **Describe user actions:**  Focus changes are typically triggered by user actions like:
    * Clicking on an element.
    * Tabbing through elements using the keyboard.
    * Programmatic focus via JavaScript.
    * Opening or closing popovers.

9. **Summarize the functionality:**  Finally, I need to provide a concise summary of the file's main purpose, drawing on the points identified above.

By following this process, I can generate a comprehensive and accurate answer to the user's request. The decomposed steps ensure that I address all aspects of the prompt and provide relevant and informative details.
这是 `blink/renderer/core/page/focus_controller.cc` 文件的第一部分代码，主要负责**管理页面中的焦点 (focus)**。  它决定了哪个元素是当前获得焦点的元素，以及当用户通过键盘（例如 Tab 键）或其他方式移动焦点时，哪个元素应该接收焦点。

**以下是该代码片段功能的详细归纳：**

**核心功能：**

1. **追踪和管理焦点状态：**  `FocusController` 负责记录当前页面或特定 frame 中哪个元素拥有焦点。
2. **焦点移动逻辑：** 决定当焦点需要移动时，哪个元素应该成为新的焦点。这包括：
    * **顺序焦点导航 (Sequential Focus Navigation)：**  处理使用 Tab 键或 Shift+Tab 键在可聚焦元素之间移动焦点。 这涉及到理解 `tabindex` 属性以及文档的 DOM 结构和阅读顺序。
    * **空间导航 (Spatial Navigation)：** (虽然这个代码片段中没有直接体现，但头文件包含 `spatial_navigation.h` 表明 `FocusController` 与空间导航有关，空间导航是指使用方向键在元素之间移动焦点)。
    * **框架间的焦点管理：**  处理焦点在不同 iframe 之间的切换。
    * **弹窗 (Popover) 的焦点管理：**  处理与 popover 元素相关的焦点行为，包括打开和关闭 popover 时的焦点设置。
3. **触发焦点和失焦事件：**  当焦点发生变化时，`FocusController` 负责触发相应的 `focus` 和 `blur` (以及 `focusin` 和 `focusout`) 事件。
4. **处理不同类型的焦点：** 区分不同类型的焦点变化，例如用户操作引起的焦点变化、脚本引起的焦点变化等 (`mojom::blink::FocusType`)。
5. **处理 Shadow DOM 和 Slot 的焦点：**  理解 Shadow DOM 的边界和 `<slot>` 元素的投影机制，确保焦点能够正确地进入和退出 Shadow DOM 树。
6. **处理 Reading Flow 的焦点：** 针对某些特定的布局模式（例如 CSS Grid 或 Flexbox），按照内容的阅读顺序来确定焦点顺序，而不是单纯的 DOM 顺序。
7. **处理 Captcha Iframe：**  包含一些启发式逻辑来识别可能是验证码的 iframe，并可能对其焦点行为进行特殊处理。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**
    * **`tabindex` 属性:** `FocusController` 密切关注 HTML 元素的 `tabindex` 属性，以确定元素的焦点顺序。
        * **举例：** 如果一个按钮设置了 `tabindex="1"`，而一个输入框没有设置 `tabindex` (默认为 0)，那么在顺序焦点导航中，按钮会比输入框先获得焦点。
    * **可聚焦元素 (Focusable Elements):**  `FocusController` 需要判断哪些 HTML 元素是可聚焦的，例如 `<input>`, `<button>`, `<a>` (带有 `href` 属性), 以及设置了 `tabindex` 的元素。
        * **举例：** `<div>` 元素默认是不可聚焦的，除非设置了 `tabindex` 属性。
    * **Shadow DOM 和 `<slot>`:** `FocusController` 需要理解 Shadow DOM 的边界，以及如何将焦点传递到 `<slot>` 中投影的元素。
        * **举例：** 当焦点在一个使用了 Shadow DOM 的自定义元素上时，按下 Tab 键，焦点可能会进入该 Shadow DOM 内部的可聚焦元素。
    * **Popover API:**  代码中处理了 `popover` 属性，确保打开 popover 时焦点被正确地设置在 popover 内部的元素上，关闭时焦点返回到触发 popover 的元素（invoker）。
        * **举例：**  一个按钮绑定了一个 `popovertarget` 指向一个 popover 元素。当点击按钮打开 popover 时，焦点会被设置在 popover 内部的第一个可聚焦元素上。

* **JavaScript:**
    * **`element.focus()` 和 `element.blur()` 方法:**  JavaScript 可以通过这些方法来主动设置或移除元素的焦点。 `FocusController` 负责响应这些 JavaScript 调用。
        * **假设输入：** JavaScript 调用 `document.getElementById('myInput').focus()`。
        * **输出：** `FocusController` 会将焦点设置到 ID 为 `myInput` 的元素上，并触发相应的 `focus` 和 `focusin` 事件。
    * **`focus` 和 `blur` 事件:** 当元素的焦点状态改变时，浏览器会触发这些事件。 `FocusController` 是触发这些事件的基础。
        * **假设输入：** 用户点击了一个输入框。
        * **输出：** `FocusController` 将焦点设置到该输入框，并触发该输入框的 `focus` 和 `focusin` 事件。

* **CSS:**
    * **`display: none` 和 `visibility: hidden`:** 这些 CSS 属性会影响元素是否可聚焦。通常，不可见的元素是不可聚焦的。
        * **举例：** 一个设置了 `display: none` 的按钮不会获得焦点。
    * **`display: contents`:**  代码中考虑了 `display: contents` 属性，因为它会影响元素的布局，进而影响基于阅读顺序的焦点导航。
    * **`position: absolute` 和 `position: fixed`:**  在阅读顺序焦点导航中，这些定位方式的元素可能会被特殊处理，通常会在 reading flow 元素的最后进行访问。

**逻辑推理的假设输入与输出：**

由于这部分代码主要关注焦点管理框架，直接进行具体的逻辑推理需要更多的上下文。但是，我们可以对 `FocusNavigation` 类进行简单的假设：

* **假设输入：**
    * 当前焦点元素：一个列表中的某个 `<li>` 元素。
    * 导航方向：向前 (按下 Tab 键)。
    * 列表中的下一个元素是一个链接 `<a>`，它是可聚焦的。
* **输出：** `FocusNavigation::Next()` 方法会返回该链接 `<a>` 元素。

**用户或编程常见的使用错误及举例说明：**

1. **不正确的 `tabindex` 值：**  开发者可能会设置无效的 `tabindex` 值（例如非数字），或者使用负的 `tabindex` 导致元素可聚焦但无法通过顺序导航访问。
    * **举例：** `<button tabindex="abc">Click Me</button>` 或 `<div tabindex="-1">This is focusable but not in tab order</div>`。
2. **忽略语义化的 HTML 标签：**  过度使用 `<div>` 和 `<span>` 而不使用具有默认焦点行为的标签（如 `<button>`, `<input>`, `<a>`），可能会导致需要手动添加 `tabindex`，容易出错。
3. **在 JavaScript 中错误地管理焦点：**  使用 `focus()` 和 `blur()` 方法时，没有考虑到用户的操作或者没有在适当的时机设置焦点，可能导致用户体验不佳。
    * **举例：**  在一个表单验证失败后，没有将焦点设置到第一个错误的输入框上。
4. **Shadow DOM 焦点陷阱：**  在 Shadow DOM 中，如果没有正确处理焦点委托 (`delegatesFocus`)，可能会导致焦点无法进入或退出 Shadow DOM 树。
5. **忘记处理 popover 的焦点：**  打开 popover 后，焦点如果没有正确地设置在 popover 内部，可能会导致键盘导航混乱。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **页面加载完成：** 当网页加载完毕，渲染引擎会创建 `FocusController` 对象。
2. **用户交互：**
    * **按下 Tab 键或 Shift+Tab 键：**  浏览器会通知 `FocusController` 需要进行顺序焦点导航。`FocusController` 会根据当前焦点元素和文档结构，找到下一个或上一个可聚焦的元素。
    * **点击鼠标：** 用户点击一个可聚焦的元素，浏览器会通知 `FocusController` 将焦点设置到该元素。
    * **JavaScript 调用 `element.focus()`：**  JavaScript 代码执行到 `element.focus()` 时，会调用 Blink 引擎相应的接口，最终会涉及到 `FocusController` 的逻辑。
    * **打开或关闭 Popover：** 当用户触发打开 popover 的操作（例如点击一个带有 `popovertarget` 的按钮）时，`FocusController` 会负责将焦点转移到 popover 内部。
3. **事件触发：** `FocusController` 在焦点发生变化时，会触发 `focus`, `blur`, `focusin`, `focusout` 等事件。

**总结：**

总而言之，`blink/renderer/core/page/focus_controller.cc` 的这部分代码是 Chromium Blink 引擎中负责管理页面焦点状态的核心组件。它处理了焦点追踪、焦点移动逻辑（包括顺序导航、Shadow DOM、Popover 等）、事件触发，并与 HTML 的 `tabindex` 属性、JavaScript 的焦点操作以及 CSS 的显示属性等密切相关。理解这部分代码的功能对于调试与焦点相关的 bug，以及理解浏览器如何处理用户交互至关重要。

Prompt: 
```
这是目录为blink/renderer/core/page/focus_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2006, 2007 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nuanti Ltd.
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

#include "third_party/blink/renderer/core/page/focus_controller.h"

#include <limits>

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/dom/container_node.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/popover_data.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_group_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/scroll_marker_pseudo_element.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"  // For firstPositionInOrBeforeNode
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/frame/frame_client.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/remote_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/listed_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/physical_box_fragment.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_changed_observer.h"
#include "third_party/blink/renderer/core/page/frame_tree.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/spatial_navigation.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

const Element* MaybeAdjustSearchElementForFocusGroup(const Element& element,
                                                     bool get_last) {
  auto* scroll_marker = DynamicTo<ScrollMarkerPseudoElement>(element);
  if (!scroll_marker) {
    return &element;
  }
  CHECK(scroll_marker->ScrollMarkerGroup());
  const auto& scroll_markers =
      scroll_marker->ScrollMarkerGroup()->ScrollMarkers();
  return get_last ? scroll_markers.back() : scroll_markers.front();
}

// https://open-ui.org/components/focusgroup.explainer/#last-focused-memory
Element* MaybeRestoreFocusedElementForFocusGroup(Element* element) {
  if (!element) {
    return nullptr;
  }
  auto* scroll_marker = DynamicTo<ScrollMarkerPseudoElement>(element);
  if (!scroll_marker) {
    return element;
  }
  CHECK(scroll_marker->ScrollMarkerGroup());
  if (!scroll_marker->ScrollMarkerGroup()->Selected()) {
    return scroll_marker;
  }
  return scroll_marker->ScrollMarkerGroup()->Selected();
}

bool IsOpenPopoverWithInvoker(const Node* node) {
  auto* popover = DynamicTo<HTMLElement>(node);
  return popover && popover->HasPopoverAttribute() && popover->popoverOpen() &&
         popover->GetPopoverData()->invoker();
}

const Element* InclusiveAncestorOpenPopoverWithInvoker(const Element* element) {
  for (; element; element = FlatTreeTraversal::ParentElement(*element)) {
    if (IsOpenPopoverWithInvoker(element)) {
      return element;  // Return the popover
    }
  }
  return nullptr;
}

bool IsOpenPopoverInvoker(const Node* node) {
  auto* invoker = DynamicTo<HTMLFormControlElement>(node);
  if (!invoker)
    return false;
  HTMLElement* popover = const_cast<HTMLFormControlElement*>(invoker)
                             ->popoverTargetElement()
                             .popover;
  // There could be more than one invoker for a given popover. Only return true
  // if this invoker was the one that was actually used.
  return popover && popover->popoverOpen() &&
         popover->GetPopoverData()->invoker() == invoker;
}

// If node is a reading-flow container or a display: contents element whose
// layout parent is a reading-flow container, return that container.
// This is a helper for SetReadingFlowInfo.
const ContainerNode* ReadingFlowContainerOrDisplayContents(
    const ContainerNode* node) {
  if (!node) {
    return nullptr;
  }
  if (node->IsReadingFlowContainer()) {
    return node;
  }
  if (const Element* element = DynamicTo<Element>(node);
      element && element->HasDisplayContentsStyle()) {
    ContainerNode* closest_layout_parent =
        LayoutTreeBuilderTraversal::LayoutParent(*node);
    if (closest_layout_parent &&
        closest_layout_parent->IsReadingFlowContainer()) {
      return closest_layout_parent;
    }
  }
  return nullptr;
}

// A reading-flow item scope owner is a reading-flow item that is not a scope
// owner by other definitions.
bool IsReadingFlowItemScopeOwner(const ContainerNode* node) {
  // An iframe scope behaves the same way as a reading-flow item scope. We add
  // this condition to avoid overlapping definition, which will mess up finding
  // focusable elements across scopes.
  if (IsA<HTMLIFrameElement>(node)) {
    return false;
  }
  if (const Element* element = DynamicTo<Element>(node)) {
    if (ContainerNode* closest_layout_parent =
            LayoutTreeBuilderTraversal::LayoutParent(*element)) {
      return closest_layout_parent->IsReadingFlowContainer();
    }
  }
  return false;
}

// Returns true if node is a reading-flow container, a display: contents
// with a reading-flow container as its layout parent, or a reading-flow
// item scope owner.
bool IsReadingFlowScopeOwner(const ContainerNode* node) {
  return ReadingFlowContainerOrDisplayContents(node) ||
         IsReadingFlowItemScopeOwner(node);
}

// This class defines the navigation order.
class FocusNavigation : public GarbageCollected<FocusNavigation> {
 public:
  FocusNavigation(ContainerNode& root, FocusController::OwnerMap& owner_map)
      : root_(&root), owner_map_(owner_map) {
    Element* element = DynamicTo<Element>(root);
    if (ShadowRoot* shadow_root = DynamicTo<ShadowRoot>(root)) {
      // We need to check the shadow host when the root is a shadow root.
      element = &shadow_root->host();
    }
    if (auto* container = ReadingFlowContainerOrDisplayContents(element)) {
      SetReadingFlowInfo(*container);
    }
  }
  FocusNavigation(ContainerNode& root,
                  HTMLSlotElement& slot,
                  FocusController::OwnerMap& owner_map)
      : root_(&root), slot_(&slot), owner_map_(owner_map) {
    // Slot scope might have to follow reading flow if its closest layout
    // parent is a reading flow container.
    // TODO(crbug.com/336358906): Re-evaluate for content-visibility case.
    if (auto* container = ReadingFlowContainerOrDisplayContents(&slot)) {
      SetReadingFlowInfo(*container);
    }
  }

#if DCHECK_IS_ON()
  // Elements that have position absolute/fixed or display: contents will not
  // be sorted in reading-flow order. They should be visited at the end of
  // the reading flow elements, in DOM order.
  bool ShouldBeAtEndOfReadingFlow(const Element& element) {
    if (LayoutObject* layout = element.GetLayoutObject()) {
      return layout->IsFixedPositioned() || layout->IsAbsolutePositioned();
    }
    return element.HasDisplayContentsStyle();
  }
#endif

  void SetReadingFlowInfo(const ContainerNode& reading_flow_container) {
    DCHECK(reading_flow_container.GetLayoutBox());
    DCHECK(!reading_flow_container_);
    reading_flow_container_ = reading_flow_container;
    auto* children = MakeGarbageCollected<HeapVector<Member<Element>>>();
    // Layout box only includes elements that are in the reading flow
    // container's layout. For each reading flow item, check if itself or its
    // ancestor should be included in this scope instead, in reading flow order.
    for (Element* reading_flow_item :
         reading_flow_container_->GetLayoutBox()->ReadingFlowElements()) {
      do {
        if (IsOwnedByRoot(*reading_flow_item)) {
          // TODO(dizhangg) this check is O(n^2)
          if (!children->Contains(reading_flow_item)) {
            children->push_back(reading_flow_item);
          }
          break;
        }
        reading_flow_item =
            FlatTreeTraversal::ParentElement(*reading_flow_item);
        // If parent is reading flow container, then we have traversed all
        // potential parents and there is no reading flow item to add.
      } while (reading_flow_item &&
               reading_flow_item != reading_flow_container_);
    }
    // If a child is not in the sorted children, we add it after in DOM order.
    // This includes elements with computed style display:contents,
    // position:absolute, and position:fixed.
    for (Element& child : ElementTraversal::ChildrenOf(*root_)) {
      // TODO(dizhangg) this check is O(n^2)
      if (!children->Contains(child) && IsOwnedByRoot(child)) {
#if DCHECK_IS_ON()
        DCHECK(ShouldBeAtEndOfReadingFlow(child));
#endif
        children->push_back(child);
      }
    }
    reading_flow_next_elements_.ReserveCapacityForSize(children->size());
    reading_flow_previous_elements_.ReserveCapacityForSize(children->size());
    Element* prev_element = nullptr;
    for (Element* child : *children) {
      // Pseudo elements in reading-flow are not focusable and should not be
      // included in the elements to traverse.
      if (child->IsPseudoElement()) {
        continue;
      }
      if (!prev_element) {
        reading_flow_first_element_ = child;
      } else {
        reading_flow_next_elements_.insert(prev_element, child);
      }
      reading_flow_previous_elements_.insert(child, prev_element);
      prev_element = child;
    }
    if (prev_element) {
      reading_flow_next_elements_.insert(prev_element, nullptr);
      reading_flow_last_element_ = prev_element;
    }
#if DCHECK_IS_ON()
    // At this point, the number of reading flow elements added should equal the
    // number of children.
    size_t num_children = 0;
    for (Element& child : ElementTraversal::ChildrenOf(*root_)) {
      DCHECK(reading_flow_next_elements_.Contains(&child));
      ++num_children;
    }
    DCHECK_EQ(reading_flow_next_elements_.size(), num_children);
#endif
  }

  const Element* NextInDomOrder(const Element& current) {
    Element* next;
    if (RuntimeEnabledFeatures::PseudoElementsFocusableEnabled()) {
      const Element* adjusted_current =
          MaybeAdjustSearchElementForFocusGroup(current, /*get_last=*/true);
      next = ElementTraversal::NextIncludingPseudo(*adjusted_current, root_);
      while (next && !IsOwnedByRoot(*next)) {
        next = ElementTraversal::NextIncludingPseudo(*next, root_);
      }
      next = MaybeRestoreFocusedElementForFocusGroup(next);
    } else {
      next = ElementTraversal::Next(current, root_);
      while (next && !IsOwnedByRoot(*next)) {
        next = ElementTraversal::Next(*next, root_);
      }
    }
    return next;
  }

  // Given current element, find next element to traverse:
  // 1. If current scope is in a reading-flow container and the current element
  //    is a reading flow element, use the reading flow.
  // 2. Else, use the DOM tree order.
  const Element* Next(const Element& current) {
    return reading_flow_container_ &&
                   reading_flow_next_elements_.Contains(&current)
               ? reading_flow_next_elements_.at(&current)
               : NextInDomOrder(current);
  }

  const Element* PreviousInDomOrder(const Element& current) {
    Element* previous;
    if (RuntimeEnabledFeatures::PseudoElementsFocusableEnabled()) {
      const Element* adjusted_current =
          MaybeAdjustSearchElementForFocusGroup(current, /*get_last=*/false);
      previous =
          ElementTraversal::PreviousIncludingPseudo(*adjusted_current, root_);
      if (previous == root_) {
        return nullptr;
      }
      while (previous && !IsOwnedByRoot(*previous)) {
        previous = ElementTraversal::PreviousIncludingPseudo(*previous, root_);
      }
      previous = MaybeRestoreFocusedElementForFocusGroup(previous);
    } else {
      previous = ElementTraversal::Previous(current, root_);
      if (previous == root_) {
        return nullptr;
      }
      while (previous && !IsOwnedByRoot(*previous)) {
        previous = ElementTraversal::Previous(*previous, root_);
      }
    }
    return previous;
  }

  // Given current element, find previous element to traverse:
  // 1. If current scope is in a reading-flow container and the current element
  //    is a reading flow element, use the reading flow.
  // 2. Else, use the DOM tree order.
  const Element* Previous(const Element& current) {
    return reading_flow_container_ &&
                   reading_flow_previous_elements_.Contains(&current)
               ? reading_flow_previous_elements_.at(&current)
               : PreviousInDomOrder(current);
  }

  const Element* First() {
    if (reading_flow_first_element_) {
      return reading_flow_first_element_;
    }
    Element* first = ElementTraversal::FirstChild(*root_);
    while (first && !IsOwnedByRoot(*first))
      first = ElementTraversal::Next(*first, root_);
    return first;
  }

  const Element* Last() {
    if (reading_flow_last_element_) {
      return reading_flow_last_element_;
    }
    const Element* last = ElementTraversal::LastWithin(*root_);
    while (last && !IsOwnedByRoot(const_cast<Element&>(*last))) {
      last = ElementTraversal::Previous(*last, root_);
    }
    return last;
  }

  Element* Owner() {
    if (slot_) {
      return slot_.Get();
    }
    if (IsReadingFlowScopeOwner(root_)) {
      return DynamicTo<Element>(*root_);
    }
    return FindOwner(*root_);
  }

  bool HasReadingFlowContainer() { return reading_flow_container_ != nullptr; }

  void Trace(Visitor* visitor) const {
    visitor->Trace(root_);
    visitor->Trace(slot_);
    visitor->Trace(reading_flow_container_);
    visitor->Trace(reading_flow_first_element_);
    visitor->Trace(reading_flow_last_element_);
    visitor->Trace(reading_flow_next_elements_);
    visitor->Trace(reading_flow_previous_elements_);
  }

 private:
  Element* TreeOwner(ContainerNode* node) {
    if (ShadowRoot* shadow_root = DynamicTo<ShadowRoot>(node))
      return &shadow_root->host();
    // FIXME: Figure out the right thing for OOPI here.
    if (Frame* frame = node->GetDocument().GetFrame())
      return frame->DeprecatedLocalOwner();
    return nullptr;
  }

  // Owner of a FocusNavigation:
  // - If node is in slot scope, owner is the assigned slot (found by traversing
  //   ancestors).
  // - If node is in a reading-flow container, owner is that container (found
  //   by traversing ancestors).
  // - If node is in a reading-flow item, owner is that reading flow item (found
  //   by traversing ancestors).
  // - If node is in slot fallback content scope, owner is the parent or
  //   shadowHost element.
  // - If node is in shadow tree scope, owner is the parent or shadowHost
  //   element.
  // - If node is in frame scope, owner is the iframe node.
  // - If node is inside an open popover with an invoker, owner is the invoker.
  Element* FindOwner(ContainerNode& node) {
    auto result = owner_map_.find(&node);
    if (result != owner_map_.end())
      return result->value.Get();

    // Fallback contents owner is set to the nearest ancestor slot node even if
    // the slot node have assigned nodes.

    Element* owner = nullptr;
    Element* owner_slot_or_reading_flow_container = nullptr;
    if (Element* element = DynamicTo<Element>(node)) {
      owner_slot_or_reading_flow_container =
          FocusController::FindScopeOwnerSlotOrReadingFlowContainer(*element);
    }
    if (owner_slot_or_reading_flow_container) {
      owner = owner_slot_or_reading_flow_container;
    } else if (IsA<HTMLSlotElement>(node.parentNode())) {
      owner = node.ParentOrShadowHostElement();
    } else if (&node == node.GetTreeScope().RootNode()) {
      owner = TreeOwner(&node);
    } else if (IsOpenPopoverWithInvoker(&node)) {
      owner = DynamicTo<HTMLElement>(node)->GetPopoverData()->invoker();
    } else if (node.parentNode()) {
      owner = FindOwner(*node.parentNode());
    }

    owner_map_.insert(&node, owner);
    return owner;
  }

  bool IsOwnedByRoot(ContainerNode& node) { return FindOwner(node) == Owner(); }

  Member<ContainerNode> root_;
  Member<HTMLSlotElement> slot_;
  FocusController::OwnerMap& owner_map_;
  // This member is the reading-flow container if it is exists.
  Member<const ContainerNode> reading_flow_container_;
  // These members are the first and last reading flow elements in
  // the reading flow container if it has children.
  Member<Element> reading_flow_first_element_;
  Member<Element> reading_flow_last_element_;
  // Maps each element in reading_flow_container_ with its next and previous
  // reading ordered elements.
  HeapHashMap<Member<const Element>, Member<const Element>>
      reading_flow_next_elements_;
  HeapHashMap<Member<const Element>, Member<const Element>>
      reading_flow_previous_elements_;
};

class ScopedFocusNavigation {
  STACK_ALLOCATED();

 public:
  // Searches through the given tree scope, starting from start element, for
  // the next/previous selectable element that comes after/before start element.
  // The order followed is as specified in the HTML spec[1], which is elements
  // with tab indexes first (from lowest to highest), and then elements without
  // tab indexes (in document order).  The search algorithm also conforms the
  // Shadow DOM spec[2], which inserts sequence in a shadow tree into its host.
  //
  // @param start The element from which to start searching. The element after
  //              this will be focused. May be null.
  // @return The focus element that comes after/before start element.
  //
  // [1]
  // https://html.spec.whatwg.org/C/#sequential-focus-navigation
  // [2] https://w3c.github.io/webcomponents/spec/shadow/#focus-navigation
  Element* FindFocusableElement(mojom::blink::FocusType type) {
    return (type == mojom::blink::FocusType::kForward)
               ? NextFocusableElement()
               : PreviousFocusableElement();
  }

  Element* CurrentElement() const { return const_cast<Element*>(current_); }
  Element* Owner() const;

  static ScopedFocusNavigation CreateFor(const Element&,
                                         FocusController::OwnerMap&);
  static ScopedFocusNavigation CreateForDocument(Document&,
                                                 FocusController::OwnerMap&);
  static ScopedFocusNavigation OwnedByNonFocusableFocusScopeOwner(
      Element&,
      FocusController::OwnerMap&);
  static ScopedFocusNavigation OwnedByShadowHost(const Element&,
                                                 FocusController::OwnerMap&);
  static ScopedFocusNavigation OwnedByHTMLSlotElement(
      const HTMLSlotElement&,
      FocusController::OwnerMap&);
  static ScopedFocusNavigation OwnedByIFrame(const HTMLFrameOwnerElement&,
                                             FocusController::OwnerMap&);
  static ScopedFocusNavigation OwnedByPopoverInvoker(
      const Element&,
      FocusController::OwnerMap&);
  static ScopedFocusNavigation OwnedByReadingFlow(const Element&,
                                                  FocusController::OwnerMap&);
  static HTMLSlotElement* FindFallbackScopeOwnerSlot(const Element&);

 private:
  ScopedFocusNavigation(ContainerNode& scoping_root_node,
                        const Element* current,
                        FocusController::OwnerMap&);

  Element* FindElementWithExactTabIndex(int tab_index, mojom::blink::FocusType);
  Element* NextElementWithGreaterTabIndex(int tab_index);
  Element* PreviousElementWithLowerTabIndex(int tab_index);
  int ReadingFlowAdjustedTabIndex(const Element& element);
  Element* NextFocusableElement();
  Element* PreviousFocusableElement();

  void SetCurrentElement(const Element* element) { current_ = element; }
  void MoveToNext();
  void MoveToPrevious();
  void MoveToFirst();
  void MoveToLast();

  const Element* current_;
  FocusNavigation* navigation_;
};

ScopedFocusNavigation::ScopedFocusNavigation(
    ContainerNode& scoping_root_node,
    const Element* current,
    FocusController::OwnerMap& owner_map)
    : current_(current) {
  if (auto* slot = DynamicTo<HTMLSlotElement>(scoping_root_node)) {
    if (slot->AssignedNodes().empty()) {
      navigation_ = MakeGarbageCollected<FocusNavigation>(scoping_root_node,
                                                          *slot, owner_map);
    } else {
      // Here, slot->AssignedNodes() are non null, so the slot must be inside
      // the shadow tree.
      DCHECK(scoping_root_node.ContainingShadowRoot());
      navigation_ = MakeGarbageCollected<FocusNavigation>(
          scoping_root_node.ContainingShadowRoot()->host(), *slot, owner_map);
    }
  } else {
    navigation_ =
        MakeGarbageCollected<FocusNavigation>(scoping_root_node, owner_map);
  }
  DCHECK(navigation_);
}

void ScopedFocusNavigation::MoveToNext() {
  DCHECK(CurrentElement());
  SetCurrentElement(navigation_->Next(*CurrentElement()));
}

void ScopedFocusNavigation::MoveToPrevious() {
  DCHECK(CurrentElement());
  SetCurrentElement(navigation_->Previous(*CurrentElement()));
}

void ScopedFocusNavigation::MoveToFirst() {
  SetCurrentElement(navigation_->First());
}

void ScopedFocusNavigation::MoveToLast() {
  SetCurrentElement(navigation_->Last());
}

Element* ScopedFocusNavigation::Owner() const {
  Element* owner = navigation_->Owner();
  // TODO(crbug.com/335909581): If the returned owner is a reading-flow
  // scope owner and a popover, we want the scope owner to be the invoker.
  if (IsOpenPopoverWithInvoker(owner) && IsReadingFlowScopeOwner(owner)) {
    return DynamicTo<HTMLElement>(owner)->GetPopoverData()->invoker();
  }
  return owner;
}

ScopedFocusNavigation ScopedFocusNavigation::CreateFor(
    const Element& current,
    FocusController::OwnerMap& owner_map) {
  if (HTMLElement* owner =
          FocusController::FindScopeOwnerSlotOrReadingFlowContainer(current)) {
    return ScopedFocusNavigation(*owner, &current, owner_map);
  }
  if (HTMLSlotElement* slot =
          ScopedFocusNavigation::FindFallbackScopeOwnerSlot(current)) {
    return ScopedFocusNavigation(*slot, &current, owner_map);
  }
  if (auto* popover = InclusiveAncestorOpenPopoverWithInvoker(&current)) {
    return ScopedFocusNavigation(const_cast<Element&>(*popover), &current,
                                 owner_map);
  }
  DCHECK(current.IsInTreeScope());
  return ScopedFocusNavigation(current.GetTreeScope().RootNode(), &current,
                               owner_map);
}

ScopedFocusNavigation ScopedFocusNavigation::CreateForDocument(
    Document& document,
    FocusController::OwnerMap& owner_map) {
  return ScopedFocusNavigation(document, nullptr, owner_map);
}

ScopedFocusNavigation ScopedFocusNavigation::OwnedByNonFocusableFocusScopeOwner(
    Element& element,
    FocusController::OwnerMap& owner_map) {
  if (IsShadowHost(element)) {
    return ScopedFocusNavigation::OwnedByShadowHost(element, owner_map);
  }
  if (IsReadingFlowScopeOwner(&element)) {
    return ScopedFocusNavigation::OwnedByReadingFlow(element, owner_map);
  }
  return ScopedFocusNavigation::OwnedByHTMLSlotElement(
      To<HTMLSlotElement>(element), owner_map);
}

ScopedFocusNavigation ScopedFocusNavigation::OwnedByShadowHost(
    const Element& element,
    FocusController::OwnerMap& owner_map) {
  DCHECK(IsShadowHost(element));
  return ScopedFocusNavigation(*element.GetShadowRoot(), nullptr, owner_map);
}

ScopedFocusNavigation ScopedFocusNavigation::OwnedByIFrame(
    const HTMLFrameOwnerElement& frame,
    FocusController::OwnerMap& owner_map) {
  DCHECK(frame.ContentFrame());
  return ScopedFocusNavigation(
      *To<LocalFrame>(frame.ContentFrame())->GetDocument(), nullptr, owner_map);
}

ScopedFocusNavigation ScopedFocusNavigation::OwnedByPopoverInvoker(
    const Element& invoker,
    FocusController::OwnerMap& owner_map) {
  DCHECK(IsA<HTMLFormControlElement>(invoker));
  HTMLElement* popover =
      DynamicTo<HTMLFormControlElement>(const_cast<Element&>(invoker))
          ->popoverTargetElement()
          .popover;
  DCHECK(IsOpenPopoverWithInvoker(popover));
  return ScopedFocusNavigation(*popover, nullptr, owner_map);
}

ScopedFocusNavigation ScopedFocusNavigation::OwnedByReadingFlow(
    const Element& owner,
    FocusController::OwnerMap& owner_map) {
  DCHECK(IsReadingFlowScopeOwner(&owner));
  HTMLElement& element = const_cast<HTMLElement&>(To<HTMLElement>(owner));
  return ScopedFocusNavigation(element, nullptr, owner_map);
}

ScopedFocusNavigation ScopedFocusNavigation::OwnedByHTMLSlotElement(
    const HTMLSlotElement& element,
    FocusController::OwnerMap& owner_map) {
  HTMLSlotElement& slot = const_cast<HTMLSlotElement&>(element);
  return ScopedFocusNavigation(slot, nullptr, owner_map);
}

HTMLSlotElement* ScopedFocusNavigation::FindFallbackScopeOwnerSlot(
    const Element& element) {
  Element* parent = const_cast<Element*>(element.parentElement());
  while (parent) {
    if (auto* slot = DynamicTo<HTMLSlotElement>(parent))
      return slot->AssignedNodes().empty() ? slot : nullptr;
    parent = parent->parentElement();
  }
  return nullptr;
}

// Checks whether |element| is an <iframe> and seems like a captcha based on
// heuristics. The heuristics cannot be perfect and therefore is a subject to
// change, e.g. adding a list of domains of captcha providers to be compared
// with 'src' attribute.
bool IsLikelyCaptchaIframe(const Element& element) {
  auto* iframe_element = DynamicTo<HTMLIFrameElement>(element);
  if (!iframe_element) {
    return false;
  }
  DEFINE_STATIC_LOCAL(String, kCaptcha, ("captcha"));
  return iframe_element->FastGetAttribute(html_names::kSrcAttr)
             .Contains(kCaptcha) ||
         iframe_element->title().Contains(kCaptcha) ||
         iframe_element->GetIdAttribute().Contains(kCaptcha) ||
         iframe_element->GetNameAttribute().Contains(kCaptcha);
}

// Checks whether |element| is a captcha <iframe> or enclosed with such an
// <iframe>.
bool IsLikelyWithinCaptchaIframe(const Element& element,
                                 FocusController::OwnerMap& owner_map) {
  if (IsLikelyCaptchaIframe(element)) {
    return true;
  }
  ScopedFocusNavigation scope =
      ScopedFocusNavigation::CreateFor(element, owner_map);
  Element* scope_owner = scope.Owner();
  return scope_owner && IsLikelyCaptchaIframe(*scope_owner);
}

inline void DispatchBlurEvent(const Document& document,
                              Element& focused_element) {
  focused_element.DispatchBlurEvent(nullptr, mojom::blink::FocusType::kPage);
  if (focused_element == document.FocusedElement()) {
    focused_element.DispatchFocusOutEvent(event_type_names::kFocusout, nullptr);
    if (focused_element == document.FocusedElement())
      focused_element.DispatchFocusOutEvent(event_type_names::kDOMFocusOut,
                                            nullptr);
  }
}

inline void DispatchFocusEvent(const Document& document,
                               Element& focused_element) {
  focused_element.DispatchFocusEvent(nullptr, mojom::blink::FocusType::kPage);
  if (focused_element == document.FocusedElement()) {
    focused_element.DispatchFocusInEvent(event_type_names::kFocusin, nullptr,
                                         mojom::blink::FocusType::kPage);
    if (focused_element == document.FocusedElement()) {
      focused_element.DispatchFocusInEvent(event_type_names::kDOMFocusIn,
                                           nullptr,
                                           mojom::blink::FocusType::kPage);
    }
  }
}

inline void DispatchEventsOnWindowAndFocusedElement(Document* document,
                                                    bool focused) {
  DCHECK(document);
  // If we have a focused element we should dispatch blur on it before we blur
  // the window.  If we have a focused element we should dispatch focus on it
  // after we focus the window.  https://bugs.webkit.org/show_bug.cgi?id=27105

  // Do not fire events while modal dialogs are up.  See
  // https://bugs.webkit.org/show_bug.cgi?id=33962
  if (Page* page = document->GetPage()) {
    if (page->Paused())
      return;
  }

  if (!focused && document->FocusedElement()) {
    Element* focused_element = document->FocusedElement();
    // Use focus_type mojom::blink::FocusType::kPage, same as used in
    // DispatchBlurEvent.
    focused_element->SetFocused(false, mojom::blink::FocusType::kPage);
    focused_element->SetHasFocusWithinUpToAncestor(false, nullptr);
    DispatchBlurEvent(*document, *focused_element);
  }

  if (LocalDOMWindow* window = document->domWindow()) {
    window->DispatchEvent(*Event::Create(focused ? event_type_names::kFocus
                                                 : event_type_names::kBlur));
  }
  if (focused && document->FocusedElement()) {
    Element* focused_element(document->FocusedElement());
    // Use focus_type mojom::blink::FocusType::kPage, same as used in
    // DispatchFocusEvent.
    focused_element->SetFocused(true, mojom::blink::FocusType::kPage);
    focused_element->SetHasFocusWithinUpToAncestor(true, nullptr);
    DispatchFocusEvent(*document, *focused_element);
  }
}

inline bool HasCustomFocusLogic(const Element& element) {
  auto* html_element = DynamicTo<HTMLElement>(element);
  return html_element && html_element->HasCustomFocusLogic();
}

inline bool IsShadowHostWithoutCustomFocusLogic(const Element& element) {
  return IsShadowHost(element) && !HasCustomFocusLogic(element);
}

inline bool IsNonKeyboardFocusableShadowHost(const Element& element) {
  if (!IsShadowHostWithoutCustomFocusLogic(element) ||
      element.IsShadowHostWithDelegatesFocus()) {
    return false;
  }
  if (!element.IsFocusable()) {
    return true;
  }
  if (element.IsKeyboardFocusable()) {
    return false;
  }
  // This host supports focus, but cannot be keyboard focused. For example:
  // - Tabindex is negative
  // -
"""


```