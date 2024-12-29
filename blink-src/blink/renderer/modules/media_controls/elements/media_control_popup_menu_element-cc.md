Response:
Let's break down the thought process for analyzing the provided C++ code for `MediaControlPopupMenuElement`.

**1. Initial Understanding of the Purpose:**

The file name `media_control_popup_menu_element.cc` immediately suggests this code is responsible for the behavior of a popup menu within the media controls of a web page. Keywords like "popup," "menu," and "media controls" are strong indicators.

**2. Identifying Key Classes and Structures:**

* **`MediaControlPopupMenuElement`:** This is the central class. It inherits from `MediaControlDivElement`, indicating it's likely a visible DOM element (a `<div>`).
* **`EventListener`:**  A nested class suggests it's managing events specifically for this popup menu. This is a common pattern in Blink.
* **Includes:**  Looking at the included header files provides valuable context:
    *  Headers related to DOM, events, HTML elements (`HTMLMediaElement`, `HTMLElement`), CSS, and keyboard events. This reinforces the idea of a UI element interacting with the browser's core functionalities.
    *  Headers related to media controls specifically (`MediaControlOverflowMenuButtonElement`, `MediaControlsImpl`). This confirms its place within the larger media controls system.
    *  Headers from `platform/` (like `keyboard_codes.h`) indicate interaction with lower-level platform features.

**3. Analyzing Key Methods and Their Functionality:**

* **`SetIsWanted(bool wanted)`:** This is a crucial method. The name suggests controlling the visibility of the popup. The logic inside confirms this: it calls `ShowPopoverInternal` to display and `HidePopoverInternal` to hide. It also manages the `EventListener` lifecycle here.
* **`DefaultEventHandler(Event& event)`:**  This method handles various events (pointermove, focusout, click, focus). Understanding how it reacts to these events reveals core menu behavior (focusing items on hover, closing on focus loss, selecting items on click).
* **Event Listener (`Invoke`):**  The `Invoke` method within the `EventListener` is where the actual event handling logic resides. It handles `keydown` (arrow keys for navigation, Enter/Space for selection, Escape for closing) and other events like `resize`, `scroll`, and `beforetoggle` (which trigger hiding the menu).
* **`SelectFirstItem`, `SelectNextItem`, `SelectPreviousItem`:** These methods handle navigation within the menu using focus.
* **`CloseFromKeyboard`:**  Handles closing the menu with the Escape key.
* **`FocusPopupAnchorIfOverflowClosed`:**  Focuses the overflow button after a menu item is selected, if other related menus are not open.
* **`SetPosition`:**  A temporary workaround (as noted in the TODOs) for positioning the popup. It uses explicit pixel calculations.

**4. Identifying Connections to JavaScript, HTML, and CSS:**

* **JavaScript:**  The code directly interacts with JavaScript events (keydown, click, focus, etc.). The `DispatchSimulatedClick` call demonstrates triggering JavaScript handlers. The `addEventListener` and `removeEventListener` calls manage JavaScript event listeners.
* **HTML:**  The class inherits from `MediaControlDivElement`, implying it corresponds to a `<div>` element in the HTML structure of the media controls. The code also manipulates HTML attributes like `tabindex` and `popover`.
* **CSS:** The `SetPosition` method directly manipulates CSS properties (`bottom`, `right`) using the `style()` object. The mention of the `anchor-scope` CSS property in the TODOs further emphasizes the connection to CSS for positioning. The `FocusListItemIfDisplayed` method checks for the `display` CSS property.

**5. Logical Reasoning and Assumptions:**

* **Assumption:**  The media controls are implemented as a set of HTML elements.
* **Assumption:**  The `MediaControlsImpl` class manages the overall state and behavior of the media controls.
* **Reasoning:**  The event handling logic clearly shows how keyboard navigation and mouse clicks are used to interact with the menu. The focus management ensures a good user experience.

**6. Identifying Potential User/Programming Errors:**

* **User Error:**  Accidentally pressing the wrong key (e.g., pressing a letter key while navigating with arrow keys). The code handles only specific keys.
* **Programming Error:**  Incorrectly implementing or handling events within the menu items themselves, leading to unexpected behavior when an item is clicked. Forgetting to update the `last_focused_element_` correctly could also cause issues.

**7. Tracing User Operations:**

The process involved thinking about how a user would interact with media controls to open and use a popup menu:

1. **User interacts with a trigger:**  Clicking an "overflow" button (represented by `MediaControlOverflowMenuButtonElement`) is the most likely trigger.
2. **Trigger activates the menu:** The button's click handler (likely in JavaScript or a related C++ class) would call `SetIsWanted(true)` on the `MediaControlPopupMenuElement`.
3. **Menu is displayed:** `SetIsWanted(true)` calls `ShowPopoverInternal` making the menu visible.
4. **User navigates:**  The user presses arrow keys (Up/Down) or Tab/Shift+Tab. The `EventListener::Invoke` method handles the `keydown` event and calls `SelectNextItem` or `SelectPreviousItem`.
5. **User selects an item:** The user presses Enter or Space. The `EventListener::Invoke` method calls `DispatchSimulatedClick` on the focused menu item, triggering its action.
6. **Menu closes:** The menu might close after an item is selected (`OnItemSelected`), or if the user presses Escape (`CloseFromKeyboard`), or if the window is resized or scrolled (`SetIsWanted(false)` in the event listener). Focusing outside the menu also triggers closing via the `focusout` handler and `HideIfNotFocused`.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the `SetPosition` method. Recognizing the TODOs and the comment about it being temporary shifts the focus to the more central logic of showing, hiding, and event handling.
*  Realizing the significance of the `EventListener` and its role in decoupling event handling from the main class is important.
*  Connecting the C++ code to the corresponding HTML elements and CSS styles requires inferring based on class names and method names (like `style()->setProperty`).

By following these steps and constantly relating the code back to its purpose within the browser's media controls, a comprehensive understanding of the `MediaControlPopupMenuElement` can be achieved.
好的，让我们来分析一下 `blink/renderer/modules/media_controls/elements/media_control_popup_menu_element.cc` 这个文件。

**功能概述:**

这个 C++ 文件定义了 `MediaControlPopupMenuElement` 类，该类负责实现媒体控件中的弹出菜单功能。当用户与媒体控件交互时，可能会出现一个包含多个选项的弹出菜单，例如播放速度选择、字幕选择等。这个类处理了该弹出菜单的显示、隐藏、导航、选择等行为。

**与 JavaScript, HTML, CSS 的关系:**

这个 C++ 文件是 Chromium Blink 引擎的一部分，负责渲染和处理网页内容。它与 JavaScript、HTML 和 CSS 都有密切关系：

* **HTML:**  `MediaControlPopupMenuElement` 最终会渲染成 HTML 元素（很可能是一个 `<div>` 元素）。它继承自 `MediaControlDivElement`，进一步暗示了这一点。HTML 定义了媒体控件的结构，而弹出菜单是其中的一部分。
    * **举例:**  在 HTML 中，可能存在一个包含 `video` 标签的结构，其内部会自动生成或包含媒体控件元素。当用户点击某个触发弹出菜单的按钮（例如“更多选项”按钮）时，这个 C++ 类就会被激活，创建并显示相应的 HTML 结构。
* **CSS:**  CSS 用于控制弹出菜单的样式和布局，例如菜单的位置、大小、背景颜色、字体等。
    * **举例:**  CSS 可能会定义 `.media-control-popup-menu` 类的样式，控制菜单的边框、阴影以及子菜单项的排列方式。`SetPosition()` 函数中直接操作了元素的 style 属性，设置了 `bottom` 和 `right` 属性，这直接影响了 CSS 的渲染效果。
* **JavaScript:** JavaScript 可以用来控制弹出菜单的显示和隐藏，以及处理菜单项的点击事件。虽然这个 C++ 文件主要负责底层的逻辑，但 JavaScript 可以通过事件监听等方式与这个 C++ 类进行交互。
    * **举例:**  当用户点击弹出菜单中的某个选项时，JavaScript 可以监听这个点击事件，并执行相应的操作，例如更改播放速度或选择字幕轨道。C++ 代码中的 `DispatchSimulatedClick(event)`  表明了 C++ 可以触发 JavaScript 的点击事件。

**逻辑推理 (假设输入与输出):**

假设用户点击了媒体控件中的“更多选项”按钮（对应 `MediaControlOverflowMenuButtonElement`）。

* **假设输入:** 用户点击事件发生在“更多选项”按钮上。
* **逻辑推理过程:**
    1. “更多选项”按钮的点击事件会被捕获。
    2. 相关的事件处理逻辑（可能在 JavaScript 或其他 C++ 代码中）会调用 `MediaControlPopupMenuElement` 的 `SetIsWanted(true)` 方法。
    3. `SetIsWanted(true)` 会：
        * 调用 `ShowPopoverInternal` 显示弹出菜单。
        * 调用 `SetPosition` 设置弹出菜单的位置（临时方案）。
        * 调用 `SelectFirstItem` 选中第一个菜单项。
        * 启动事件监听器 (`EventListener`)，监听键盘事件、窗口滚动/缩放事件和 `beforetoggle` 事件。
    4. 弹出菜单在屏幕上显示出来，其位置由 `SetPosition` 计算，第一个菜单项处于选中状态。
* **假设输出:** 一个包含多个选项的弹出菜单出现在屏幕上，通常位于“更多选项”按钮附近，并且第一个选项被高亮显示。

**用户或编程常见的使用错误:**

* **用户错误:**
    * **误触:** 用户可能在不经意间点击了触发弹出菜单的按钮。代码中监听了 `beforetoggle` 事件，当 popover 即将显示或隐藏时会触发，并调用 `SetIsWanted(false)`，这可能是一种尝试处理快速连续触发的情况。
    * **键盘操作不当:** 用户可能期望使用 Tab 键在菜单项之间循环，但如果焦点没有正确管理，可能会导致导航混乱。代码中实现了 `SelectNextItem` 和 `SelectPreviousItem` 来处理 Tab 和箭头键的导航。
* **编程错误:**
    * **事件监听泄漏:** 如果 `EventListener` 没有在弹出菜单不再需要时正确停止监听事件，可能会导致内存泄漏或意外的行为。代码中的 `StopListening()` 方法以及在 `RemovedFrom` 中设置 `event_listener_ = nullptr` 就是为了避免这个问题。
    * **焦点管理错误:** 如果弹出菜单的焦点管理不当，用户可能无法使用键盘正确导航或选择菜单项。代码中通过 `FocusListItemIfDisplayed` 和 `last_focused_element_` 来管理焦点。
    * **位置计算错误:**  `SetPosition` 方法是一个临时的解决方案，如果计算位置的逻辑有误，可能会导致弹出菜单显示在屏幕外或不正确的位置。TODO 注释也指出了这一点。

**用户操作到达这里的调试线索:**

为了调试 `MediaControlPopupMenuElement` 的行为，可以按照以下步骤追踪用户操作：

1. **用户交互起点:** 确定用户触发弹出菜单的初始操作是什么。通常是点击媒体控件上的某个按钮，例如“更多选项”按钮。
2. **事件传播:**  使用浏览器的开发者工具（例如 Chrome DevTools）的 "Event Listeners" 面板，查看该按钮上绑定的事件监听器。追踪点击事件的处理函数。
3. **代码追踪:** 如果事件处理函数是 JavaScript 代码，可以逐步调试该代码，找到调用 Blink 引擎相关 C++ 代码的入口。如果事件处理直接发生在 C++ 代码中（例如，按钮本身就是一个 C++ 对象），则需要分析按钮的事件处理逻辑。
4. **`SetIsWanted` 调用:** 重点关注 `SetIsWanted(true)` 被调用的时机和条件。这通常是弹出菜单显示的关键点。
5. **`EventListener` 的启动:**  检查 `EventListener` 何时被创建和启动 (`StartListening()`)。确保它监听了必要的事件。
6. **键盘和鼠标事件处理:** 当弹出菜单显示后，尝试使用键盘（Tab, Shift+Tab, 箭头键, Enter, Space, Esc）和鼠标进行操作。使用 DevTools 的 "Elements" 面板查看焦点的变化，并使用 "Event Listeners" 面板查看触发的事件以及它们是如何被 `EventListener::Invoke` 处理的。
7. **`SetPosition` 的调用:**  检查 `SetPosition` 方法的调用，确保弹出菜单的位置计算是正确的。
8. **`SetIsWanted(false)` 调用:**  追踪 `SetIsWanted(false)` 被调用的时机，例如点击菜单项、按下 Esc 键、窗口滚动/缩放等。
9. **`RemovedFrom` 调用:**  当包含弹出菜单的元素从 DOM 树中移除时，会调用 `RemovedFrom` 方法，确保资源被正确清理。

通过以上步骤，可以逐步追踪用户操作，理解 `MediaControlPopupMenuElement` 的工作原理，并定位可能存在的问题。关注日志输出、断点调试以及对相关事件的分析是关键的调试手段。

Prompt: 
```
这是目录为blink/renderer/modules/media_controls/elements/media_control_popup_menu_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/modules/media_controls/elements/media_control_popup_menu_element.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_focus_options.h"
#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/css/css_style_declaration.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/native_event_listener.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/event_type_names.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/geometry/dom_rect.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/keywords.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_elements_helper.h"
#include "third_party/blink/renderer/modules/media_controls/elements/media_control_overflow_menu_button_element.h"
#include "third_party/blink/renderer/modules/media_controls/media_controls_impl.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

class MediaControlPopupMenuElement::EventListener final
    : public NativeEventListener {
 public:
  explicit EventListener(MediaControlPopupMenuElement* popup_menu)
      : popup_menu_(popup_menu) {}

  ~EventListener() final = default;

  void StartListening() {
    popup_menu_->addEventListener(event_type_names::kKeydown, this, false);
    popup_menu_->addEventListener(event_type_names::kBeforetoggle, this, false);

    LocalDOMWindow* window = popup_menu_->GetDocument().domWindow();
    if (!window)
      return;

    window->addEventListener(event_type_names::kScroll, this, true);
    if (DOMWindow* outer_window = window->top()) {
      if (outer_window != window)
        outer_window->addEventListener(event_type_names::kScroll, this, true);
      outer_window->addEventListener(event_type_names::kResize, this, true);
    }
  }

  void StopListening() {
    popup_menu_->removeEventListener(event_type_names::kKeydown, this, false);
    popup_menu_->removeEventListener(event_type_names::kBeforetoggle, this,
                                     false);

    LocalDOMWindow* window = popup_menu_->GetDocument().domWindow();
    if (!window)
      return;

    window->removeEventListener(event_type_names::kScroll, this, true);
    if (DOMWindow* outer_window = window->top()) {
      if (outer_window != window) {
        outer_window->removeEventListener(event_type_names::kScroll, this,
                                          true);
      }
      outer_window->removeEventListener(event_type_names::kResize, this, true);
    }
  }

  void Trace(Visitor* visitor) const final {
    NativeEventListener::Trace(visitor);
    visitor->Trace(popup_menu_);
  }

 private:
  void Invoke(ExecutionContext*, Event* event) final {
    if (event->type() == event_type_names::kKeydown) {
      auto* keyboard_event = To<KeyboardEvent>(event);
      bool handled = true;

      switch (keyboard_event->keyCode()) {
        case VKEY_TAB:
          keyboard_event->shiftKey() ? popup_menu_->SelectPreviousItem()
                                     : popup_menu_->SelectNextItem();
          break;
        case VKEY_UP:
          popup_menu_->SelectPreviousItem();
          break;
        case VKEY_DOWN:
          popup_menu_->SelectNextItem();
          break;
        case VKEY_ESCAPE:
          popup_menu_->CloseFromKeyboard();
          break;
        case VKEY_RETURN:
        case VKEY_SPACE:
          To<Element>(event->target()->ToNode())->DispatchSimulatedClick(event);
          popup_menu_->FocusPopupAnchorIfOverflowClosed();
          break;
        default:
          handled = false;
      }

      if (handled) {
        event->stopPropagation();
        event->SetDefaultHandled();
      }
    } else if (event->type() == event_type_names::kResize ||
               event->type() == event_type_names::kScroll ||
               event->type() == event_type_names::kBeforetoggle) {
      popup_menu_->SetIsWanted(false);
    }
  }

  Member<MediaControlPopupMenuElement> popup_menu_;
};

MediaControlPopupMenuElement::~MediaControlPopupMenuElement() = default;

void MediaControlPopupMenuElement::SetIsWanted(bool wanted) {
  MediaControlDivElement::SetIsWanted(wanted);

  if (wanted) {
    ShowPopoverInternal(/*invoker*/ nullptr, /*exception_state*/ nullptr);
    // TODO(crbug.com/341741271): Remove this once anchor positioning, the
    // anchor attribute, and the `anchor-scope` CSS property are stable enough
    // to depend on for positioning here.
    SetPosition();

    SelectFirstItem();

    if (!event_listener_)
      event_listener_ = MakeGarbageCollected<EventListener>(this);
    event_listener_->StartListening();
  } else {
    if (event_listener_)
      event_listener_->StopListening();
    if (popoverOpen()) {
      HidePopoverInternal(HidePopoverFocusBehavior::kNone,
                          HidePopoverTransitionBehavior::kNoEventsNoWaiting,
                          nullptr);
    }
  }
}

void MediaControlPopupMenuElement::OnItemSelected() {
  SetIsWanted(false);
}

void MediaControlPopupMenuElement::DefaultEventHandler(Event& event) {
  if (event.type() == event_type_names::kPointermove &&
      event.target() != this) {
    To<Element>(event.target()->ToNode())
        ->Focus(FocusParams(FocusTrigger::kUserGesture));
    last_focused_element_ = To<Element>(event.target()->ToNode());
  } else if (event.type() == event_type_names::kFocusout) {
    GetDocument()
        .GetTaskRunner(TaskType::kMediaElementEvent)
        ->PostTask(
            FROM_HERE,
            WTF::BindOnce(&MediaControlPopupMenuElement::HideIfNotFocused,
                          WrapWeakPersistent(this)));
  } else if (event.type() == event_type_names::kClick &&
             event.target() != this) {
    // Since event.target() != this, we know that one of our children was
    // clicked.
    OnItemSelected();

    event.stopPropagation();
    event.SetDefaultHandled();
  } else if (event.type() == event_type_names::kFocus &&
             event.target() == this) {
    // When the popup menu gains focus from scrolling, switch focus
    // back to the last focused item in the menu.
    if (last_focused_element_) {
      FocusOptions* focus_options = FocusOptions::Create();
      focus_options->setPreventScroll(true);
      last_focused_element_->Focus(FocusParams(
          SelectionBehaviorOnFocus::kNone, mojom::blink::FocusType::kNone,
          nullptr, focus_options, FocusTrigger::kUserGesture));
    }
  }

  MediaControlDivElement::DefaultEventHandler(event);
}

bool MediaControlPopupMenuElement::KeepEventInNode(const Event& event) const {
  return MediaControlElementsHelper::IsUserInteractionEvent(event);
}

void MediaControlPopupMenuElement::RemovedFrom(ContainerNode& container) {
  if (IsWanted())
    SetIsWanted(false);
  event_listener_ = nullptr;

  MediaControlDivElement::RemovedFrom(container);
}

void MediaControlPopupMenuElement::Trace(Visitor* visitor) const {
  MediaControlDivElement::Trace(visitor);
  visitor->Trace(event_listener_);
  visitor->Trace(last_focused_element_);
}

MediaControlPopupMenuElement::MediaControlPopupMenuElement(
    MediaControlsImpl& media_controls)
    : MediaControlDivElement(media_controls) {
  // When clicking the scroll bar, chrome will find its first focusable parent
  // and focus on it. In order to prevent popup menu from losing focus (which
  // will close the menu), we make the popup menu focusable.
  // TODO(media) There is currently no test for this behavior.
  setTabIndex(0);

  setAttribute(html_names::kPopoverAttr, keywords::kAuto);
  SetIsWanted(false);
}

// TODO(crbug.com/1309178): This entire function and the one callsite can be
// removed once anchor positioning is enabled by default.
// TODO(crbug.com/341741271): Ensure all required APIs are stable, including
// the anchor attribute and the `anchor-scope` CSS property.
void MediaControlPopupMenuElement::SetPosition() {
  // The popup is positioned slightly on the inside of the bottom right
  // corner.
  static constexpr int kPopupMenuMarginPx = 4;
  static const char kImportant[] = "important";
  static const char kPx[] = "px";

  DOMRect* bounding_client_rect = PopupAnchor()->GetBoundingClientRect();
  LocalDOMWindow* dom_window = GetDocument().domWindow();

  DCHECK(bounding_client_rect);
  DCHECK(dom_window);

  WTF::String bottom_str_value =
      WTF::String::Number(dom_window->innerHeight() -
                          bounding_client_rect->bottom() + kPopupMenuMarginPx) +
      kPx;
  WTF::String right_str_value =
      WTF::String::Number(dom_window->innerWidth() -
                          bounding_client_rect->right() + kPopupMenuMarginPx) +
      kPx;

  style()->setProperty(dom_window, "bottom", bottom_str_value, kImportant,
                       ASSERT_NO_EXCEPTION);
  style()->setProperty(dom_window, "right", right_str_value, kImportant,
                       ASSERT_NO_EXCEPTION);
}

Element* MediaControlPopupMenuElement::PopupAnchor() const {
  return &GetMediaControls().OverflowButton();
}

void MediaControlPopupMenuElement::HideIfNotFocused() {
  if (!IsWanted())
    return;

  // Cancel hiding if the focused element is a descendent of this element
  auto* focused_element = GetDocument().FocusedElement();
  while (focused_element) {
    if (focused_element == this) {
      return;
    }

    focused_element = focused_element->parentElement();
  }

  SetIsWanted(false);
}

// Focus the given item in the list if it is displayed. Returns whether it was
// focused.
bool MediaControlPopupMenuElement::FocusListItemIfDisplayed(Node* node) {
  auto* element = To<Element>(node);

  if (!element->InlineStyle() ||
      !element->InlineStyle()->HasProperty(CSSPropertyID::kDisplay)) {
    element->Focus(FocusParams(FocusTrigger::kUserGesture));
    last_focused_element_ = element;
    return true;
  }

  return false;
}

void MediaControlPopupMenuElement::SelectFirstItem() {
  for (Node* target = firstChild(); target; target = target->nextSibling()) {
    if (FocusListItemIfDisplayed(target))
      break;
  }
}

void MediaControlPopupMenuElement::SelectNextItem() {
  Element* focused_element = GetDocument().FocusedElement();
  if (!focused_element || focused_element->parentElement() != this)
    return;

  for (Node* target = focused_element->nextSibling(); target;
       target = target->nextSibling()) {
    if (FocusListItemIfDisplayed(target))
      break;
  }
}

void MediaControlPopupMenuElement::SelectPreviousItem() {
  Element* focused_element = GetDocument().FocusedElement();
  if (!focused_element || focused_element->parentElement() != this)
    return;

  for (Node* target = focused_element->previousSibling(); target;
       target = target->previousSibling()) {
    if (FocusListItemIfDisplayed(target))
      break;
  }
}

void MediaControlPopupMenuElement::CloseFromKeyboard() {
  SetIsWanted(false);
  PopupAnchor()->Focus(FocusParams(FocusTrigger::kUserGesture));
}

void MediaControlPopupMenuElement::FocusPopupAnchorIfOverflowClosed() {
  if (!GetMediaControls().OverflowMenuIsWanted() &&
      !GetMediaControls().PlaybackSpeedListIsWanted() &&
      !GetMediaControls().TextTrackListIsWanted()) {
    PopupAnchor()->Focus(FocusParams(FocusTrigger::kUserGesture));
  }
}

}  // namespace blink

"""

```