Response:
The user wants a summary of the provided C++ code snippet from the Chromium Blink engine's `html_element.cc` file. Specifically, they are asking for:

1. **Functionality:** What does this code do?
2. **Relationships to web technologies:** How does it relate to JavaScript, HTML, and CSS? Provide examples.
3. **Logical inferences:** If there are any logical deductions, explain them with input and output examples.
4. **Common usage errors:**  Point out potential mistakes developers might make when interacting with these features.
5. **Overall function:**  A concise summary of the code's purpose.

Let's break down the code section by section to address these points.

**Code Section 1: `IsNodePopoverDescendant`**

This function checks if a given `node` is a descendant of the current `HTMLElement`, specifically if the current element is a popover. It traverses up the ancestor chain of the `node`, looking for popovers.

* **Functionality:** Determines if a node is contained within a popover element.
* **Relationships:**
    * **HTML:** Relates to the `popover` attribute on HTML elements.
    * **JavaScript:**  JavaScript can interact with popover elements and potentially call functions related to their structure.
* **Logical Inference:**
    * **Input:** A DOM `Node` and an `HTMLElement` with the `popover` attribute.
    * **Output:** `true` if the `Node` is a descendant of the `HTMLElement` popover, `false` otherwise.
* **Common Errors:**  Incorrectly assuming a node is a popover descendant when it's not, especially with nested popovers and the `popover=manual` type.

**Code Section 2: `MaybeQueuePopoverHideEvent`**

This function handles the delayed hiding of a popover based on the `popover-hide-delay` CSS property. It checks the popover's visibility and the computed style for the delay. If a valid delay exists, it schedules a task to hide the popover.

* **Functionality:** Implements the delayed hiding behavior for popovers triggered by hover.
* **Relationships:**
    * **CSS:** Directly uses the `popover-hide-delay` CSS property.
    * **HTML:** Operates on elements with the `popover` attribute.
    * **JavaScript:** JavaScript can trigger events that might lead to this function being called, although the delay itself is CSS-driven.
* **Logical Inference:**
    * **Input:** An `HTMLElement` with the `popover` attribute.
    * **Output:**  Schedules a task to hide the popover after a delay, *or* does nothing if the popover is already hidden or the delay is infinite/NaN.
* **Common Errors:**  Setting very short `popover-hide-delay` values that lead to flickering, or expecting immediate hiding when a delay is set.

**Code Section 3: `HoveredElementChanged`**

This static function is triggered when the currently hovered element changes. It checks if the old or new hovered element is within an open popover and either queues a hide event (for the old element losing hover) or cancels a pending hide event (for the new element being hovered).

* **Functionality:** Manages the show/hide behavior of popovers based on hover events.
* **Relationships:**
    * **HTML:**  Relates to elements with the `popover` attribute.
    * **JavaScript:**  While not directly invoked by JavaScript, the browser's event system (which JavaScript can interact with) triggers this function.
* **Logical Inference:**
    * **Input:** The previously hovered `Element` and the newly hovered `Element`.
    * **Output:**  May schedule a popover to hide after a delay *or* cancel a previously scheduled hide event, depending on the popover structure and hover status.
* **Common Errors:**  Assuming that moving the mouse between elements within the *same* popover will always keep it open (the logic handles this by cancelling the hide task).

**Code Section 4: `SetImplicitAnchor` and `implicitAnchor`**

These functions deal with implicitly anchoring a popover to another element. This is likely part of the popover API, where a popover might automatically position itself relative to a trigger element.

* **Functionality:** Manages the implicit relationship between a popover and its anchor element.
* **Relationships:**
    * **HTML:** Likely related to an attribute or mechanism for implicitly associating a popover with another element.
    * **JavaScript:** JavaScript would be used to set or retrieve this implicit anchor.
* **Logical Inference:**
    * **Input (for `SetImplicitAnchor`):** An `HTMLElement` with the `popover` attribute and a target `Element` to act as the anchor.
    * **Output (for `SetImplicitAnchor`):** Establishes the implicit anchor relationship.
    * **Input (for `implicitAnchor`):** An `HTMLElement` with the `popover` attribute.
    * **Output (for `implicitAnchor`):** Returns the implicitly associated anchor `Element` or `nullptr`.
* **Common Errors:**  Incorrectly setting or expecting an implicit anchor to work when the popover type or relationships are not configured correctly.

**Overall Function of the Code Snippet**

This section of `html_element.cc` primarily focuses on the behavior and management of **HTML popover elements**, specifically related to hover interactions and implicit anchoring. It handles:

* Determining if an element is within a popover.
* Implementing the delayed hiding of popovers triggered by hover using the `popover-hide-delay` CSS property.
* Managing popover visibility based on mouse hover events.
* Establishing and managing implicit anchor relationships between popovers and other elements.
这是 `blink/renderer/core/html/html_element.cc` 文件的一部分，主要负责处理 **HTML 弹出框（Popover）元素** 的相关功能，特别是与鼠标悬停交互相关的逻辑。

以下是代码段中各个函数的功能以及它们与 JavaScript、HTML 和 CSS 的关系：

**1. `IsNodePopoverDescendant(const Node& node) const`**

* **功能:**  判断给定的 `node` 是否是当前 `HTMLElement` 弹出框元素的后代。它会向上遍历 `node` 的父节点，查找是否有祖先元素是当前弹出框元素。
* **与 JavaScript 的关系:** JavaScript 可以通过 DOM API 获取节点，然后调用此函数来判断节点是否在某个弹出框内。例如，在处理鼠标事件时。
* **与 HTML 的关系:**  此函数直接关联 HTML 的 `popover` 属性，用于判断元素是否是弹出框。
* **与 CSS 的关系:**  没有直接关系，但弹出框的显示与隐藏可能会受到 CSS 样式的影响。
* **逻辑推理:**
    * **假设输入:** 一个 `HTMLElement` 对象 `popoverElement` 具有 `popover` 属性，以及一个 DOM 节点 `childNode`。
    * **输出:** 如果 `childNode` 是 `popoverElement` 的后代，则返回 `true`，否则返回 `false`。
* **用户或编程常见的使用错误:**  错误地假设某个节点是弹出框的后代，导致逻辑错误。例如，在嵌套弹出框的情况下，只判断直接父级是否是弹出框。

**2. `MaybeQueuePopoverHideEvent()`**

* **功能:**  根据 CSS 属性 `popover-hide-delay` 的值，决定是否延迟隐藏当前弹出框。如果弹出框当前可见，并且 `popover-hide-delay` 设置了有限的延迟时间，则会创建一个延迟任务来隐藏弹出框。
* **与 JavaScript 的关系:**  JavaScript 可以操作元素的 CSS 样式，从而影响 `popover-hide-delay` 的值。
* **与 HTML 的关系:**  此函数针对具有 `popover` 属性的 HTML 元素。
* **与 CSS 的关系:**  直接读取和使用 `popover-hide-delay` CSS 属性的值。
* **逻辑推理:**
    * **假设输入:** 一个 `HTMLElement` 对象 `popoverElement` 具有 `popover` 属性，并且当前可见。其计算样式中 `popover-hide-delay` 的值为 "0.5s"。
    * **输出:**  会创建一个延迟 0.5 秒执行的任务，该任务会调用 `HidePopoverInternal` 方法来隐藏 `popoverElement`。
* **用户或编程常见的使用错误:**
    * 设置过短的 `popover-hide-delay` 值，导致弹出框在鼠标稍微移开后就立即消失，用户体验不佳。
    * 误以为 `popover-hide-delay` 为无限值时（例如 `infinite` 或 `NaN`）会立即隐藏弹出框。

**3. `HoveredElementChanged(Element* old_element, Element* new_element)`**

* **功能:**  这是一个静态函数，当鼠标悬停的元素发生改变时被调用。它会检查之前悬停的元素 (`old_element`) 和当前悬停的元素 (`new_element`) 是否是已打开的弹出框的后代。
    * 如果 `old_element` 是某个打开的弹出框的后代，并且鼠标移开了，则会调用该弹出框的 `MaybeQueuePopoverHideEvent()` 来可能延迟隐藏它。
    * 如果 `new_element` 是某个打开的弹出框的后代，并且鼠标移入，则会取消该弹出框可能存在的延迟隐藏任务。
* **与 JavaScript 的关系:**  虽然此函数本身不是 JavaScript 代码，但它响应浏览器中发生的鼠标悬停事件，这些事件可以通过 JavaScript 监听和处理。
* **与 HTML 的关系:**  此函数主要处理具有 `popover` 属性的 HTML 元素。
* **与 CSS 的关系:**  间接与 CSS 的 `popover-hide-delay` 属性相关，因为它会触发 `MaybeQueuePopoverHideEvent()`。
* **逻辑推理:**
    * **假设输入:**  鼠标从 `div1` 元素上移开 (`old_element` 为 `div1`)，然后移动到 `div2` 元素上 (`new_element` 为 `div2`)。假设有一个已打开的弹出框 `popover1`，`div1` 是 `popover1` 的后代，而 `div2` 不是。
    * **输出:** 会调用 `popover1` 的 `MaybeQueuePopoverHideEvent()` 方法，可能会启动一个延迟隐藏 `popover1` 的任务。
    * **假设输入:** 鼠标从 `span1` 元素上移开 (`old_element` 为 `span1`)，然后移动到 `span2` 元素上 (`new_element` 为 `span2`)。假设有一个已打开的弹出框 `popover2`，`span1` 和 `span2` 都是 `popover2` 的后代。
    * **输出:**  如果 `popover2` 之前因为鼠标移开 `span1` 而启动了延迟隐藏任务，那么当鼠标移动到 `span2` 上时，该延迟隐藏任务会被取消。
* **用户或编程常见的使用错误:**  在复杂的 UI 结构中，没有充分理解鼠标悬停事件和弹出框延迟隐藏之间的关系，导致弹出框出现意外的显示或隐藏行为。

**4. `SetImplicitAnchor(Element* element)`**

* **功能:** 设置当前弹出框元素的隐式锚点元素。隐式锚点意味着弹出框会根据这个锚点元素进行定位和交互。
* **与 JavaScript 的关系:** JavaScript 可以调用此方法来设置弹出框的隐式锚点。
* **与 HTML 的关系:** 此功能与 HTML 中定义弹出框锚定关系的方式有关，可能通过某种属性或机制实现。
* **与 CSS 的关系:**  弹出框的定位可能会受到 CSS 样式的影响，但此函数本身不直接操作 CSS。
* **逻辑推理:**
    * **假设输入:** 一个 `HTMLElement` 对象 `popoverElement` 具有 `popover` 属性，以及一个 `Element` 对象 `anchorElement`。
    * **输出:**  `popoverElement` 将会以 `anchorElement` 作为其隐式锚点。
* **用户或编程常见的使用错误:**
    * 在弹出框已经显示的情况下尝试更改其隐式锚点，可能会导致意想不到的布局变化。
    * 将一个不合适的元素设置为隐式锚点，可能会导致弹出框定位错误。

**5. `implicitAnchor() const`**

* **功能:** 获取当前弹出框元素的隐式锚点元素。
* **与 JavaScript 的关系:** JavaScript 可以调用此方法来获取弹出框的隐式锚点。
* **与 HTML 的关系:**  与 `SetImplicitAnchor` 对应，用于获取 HTML 中定义的弹出框锚定关系。
* **与 CSS 的关系:**  无直接关系。
* **逻辑推理:**
    * **假设输入:** 一个 `HTMLElement` 对象 `popoverElement` 具有 `popover` 属性，并且之前通过 `SetImplicitAnchor` 设置了一个锚点元素 `anchorElement`。
    * **输出:** 返回 `anchorElement`。

**归纳一下，这段代码的主要功能是:**

处理 HTML 弹出框元素与鼠标悬停相关的行为，包括：

* **判断元素是否在弹出框内。**
* **根据 CSS 属性 `popover-hide-delay` 实现弹出框的延迟隐藏。**
* **响应鼠标悬停事件，控制弹出框的显示和隐藏，包括取消延迟隐藏任务。**
* **管理弹出框的隐式锚点元素。**

这段代码是浏览器引擎实现 HTML 弹出框特性的核心逻辑之一，确保了弹出框在鼠标交互时的预期行为。

### 提示词
```
这是目录为blink/renderer/core/html/html_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
delay` CSS property, which works for all popover types, and
// needs to keep popovers open when a descendant is hovered.
bool HTMLElement::IsNodePopoverDescendant(const Node& node) const {
  CHECK(RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled());
  CHECK(HasPopoverAttribute());
  const HTMLElement* ancestor = FindTopmostRelatedPopover(
      node, {PopoverAncestorOptions::kIncludeManualPopovers});
  while (ancestor) {
    if (ancestor == this) {
      return true;
    }
    const HTMLElement* new_ancestor = FindTopmostRelatedPopover(
        *ancestor, PopoverAncestorOptionsSet{
                       PopoverAncestorOptions::kExclusive,
                       PopoverAncestorOptions::kIncludeManualPopovers});
    DCHECK_NE(new_ancestor, ancestor);
    ancestor = new_ancestor;
  }
  return false;
}

void HTMLElement::MaybeQueuePopoverHideEvent() {
  CHECK(RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled());
  CHECK(HasPopoverAttribute());
  // If the popover isn't showing, or it has an infinite PopoverHideDelay, do
  // nothing.
  if (GetPopoverData()->visibilityState() == PopoverVisibilityState::kHidden) {
    return;
  }
  if (!GetComputedStyle()) {
    return;
  }
  float hide_delay_seconds = GetComputedStyle()->PopoverHideDelay();
  // If the value is infinite or NaN, don't hide the popover.
  if (!std::isfinite(hide_delay_seconds)) {
    return;
  }
  // Queue the task to hide this popover.
  GetPopoverData()->setHoverHideTask(PostDelayedCancellableTask(
      *GetExecutionContext()->GetTaskRunner(TaskType::kInternalDefault),
      FROM_HERE,
      WTF::BindOnce(
          [](HTMLElement* popover) {
            if (!popover->HasPopoverAttribute()) {
              return;
            }
            // We're hover-hiding this popover, so remove *all* hover show
            // tasks.
            popover->GetPopoverData()->hoverShowTasks().clear();
            if (!popover->popoverOpen()) {
              return;
            }
            popover->HidePopoverInternal(
                HidePopoverFocusBehavior::kFocusPreviousElement,
                HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
                /*exception_state=*/nullptr);
          },
          WrapWeakPersistent(this)),
      base::Seconds(hide_delay_seconds)));
}

// static
void HTMLElement::HoveredElementChanged(Element* old_element,
                                        Element* new_element) {
  if (!RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled()) {
    return;
  }
  // If either element has an interest target, do nothing.
  // TODO(crbug.com/326681249): This will be handled in future by a separate
  // InterestLost() function.
  if ((old_element && old_element->interestTargetElement()) ||
      (new_element && new_element->interestTargetElement())) {
    return;
  }
  if (old_element) {
    // For the previously-hovered element: loop through all showing popovers
    // (including popover=manual) and see if the element that just lost focus
    // was an ancestor. If so, queue a task to hide it after a delay.
    for (auto& popover : old_element->GetDocument().AllOpenPopovers()) {
      if (popover->IsNodePopoverDescendant(*old_element)) {
        popover->MaybeQueuePopoverHideEvent();
      }
    }
  }
  // It is possible that both old_element and new_element are descendants of
  // the same open popover, in which case we'll queue a hide task and then
  // immediately cancel it, resulting in no change.
  if (new_element) {
    // For the newly-hovered element: loop through all showing popovers and see
    // if the newly-focused element is an ancestor. If so, cancel that popover's
    // hide-after-delay task.
    for (auto& popover : new_element->GetDocument().AllOpenPopovers()) {
      if (popover->IsNodePopoverDescendant(*new_element)) {
        popover->GetPopoverData()->setHoverHideTask(TaskHandle());
      }
    }
  }
}

void HTMLElement::SetImplicitAnchor(Element* element) {
  CHECK(RuntimeEnabledFeatures::CustomizableSelectEnabled() ||
        RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled());
  CHECK(HasPopoverAttribute());
  if (auto* old_implicit_anchor =
          GetPopoverData() ? GetPopoverData()->implicitAnchor() : nullptr) {
    old_implicit_anchor->DecrementImplicitlyAnchoredElementCount();
  }
  GetPopoverData()->setImplicitAnchor(element);
  if (element) {
    element->IncrementImplicitlyAnchoredElementCount();
  }
}

Element* HTMLElement::implicitAnchor() const {
  return GetPopoverData() ? GetPopoverData()->implicitAnchor() : nullptr;
}

bool HTMLElement::DispatchFocusEvent(
    Element* old_focused_element,
    mojom::blink::FocusType type,
    InputDeviceCapabilities* source_capabilities) {
  return Element::DispatchFocusEvent(old_focused_element, type,
                                     source_capabilities);
}

bool HTMLElement::IsValidBuiltinCommand(HTMLElement& invoker,
                                        CommandEventType command) {
  return Element::IsValidBuiltinCommand(invoker, command) ||
         command == CommandEventType::kTogglePopover ||
         command == CommandEventType::kHidePopover ||
         command == CommandEventType::kShowPopover ||
         (RuntimeEnabledFeatures::HTMLInvokeActionsV2Enabled() &&
          (command == CommandEventType::kToggleFullscreen ||
           command == CommandEventType::kRequestFullscreen ||
           command == CommandEventType::kExitFullscreen));
}

bool HTMLElement::HandleCommandInternal(HTMLElement& invoker,
                                        CommandEventType command) {
  CHECK(IsValidBuiltinCommand(invoker, command));

  if (Element::HandleCommandInternal(invoker, command)) {
    return true;
  }

  bool is_fullscreen_action = command == CommandEventType::kToggleFullscreen ||
                              command == CommandEventType::kRequestFullscreen ||
                              command == CommandEventType::kExitFullscreen;

  if (PopoverType() == PopoverValueType::kNone && !is_fullscreen_action) {
    return false;
  }

  auto& document = GetDocument();

  // Note that the order is: `mousedown` which runs popover light dismiss
  // code, then (for clicked elements) focus is set to the clicked
  // element, then |DOMActivate| runs here. Also note that the light
  // dismiss code will not hide popovers when an activating element is
  // clicked. Taking that together, if the clicked control is a triggering
  // element for a popover, light dismiss will do nothing, focus will be
  // set to the triggering element, then this code will run and will set
  // focus to the previously focused element. If instead the clicked
  // control is not a triggering element, then the light dismiss code will
  // hide the popover and set focus to the previously focused element,
  // then the normal focus management code will reset focus to the clicked
  // control.
  bool can_show =
      IsPopoverReady(PopoverTriggerAction::kShow,
                     /*exception_state=*/nullptr,
                     /*include_event_handler_text=*/true, &document) &&
      (command == CommandEventType::kTogglePopover ||
       command == CommandEventType::kShowPopover);
  bool can_hide =
      IsPopoverReady(PopoverTriggerAction::kHide,
                     /*exception_state=*/nullptr,
                     /*include_event_handler_text=*/true, &document) &&
      (command == CommandEventType::kTogglePopover ||
       command == CommandEventType::kHidePopover);
  if (can_hide) {
    HidePopoverInternal(
        HidePopoverFocusBehavior::kFocusPreviousElement,
        HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
        /*exception_state=*/nullptr);
    return true;
  } else if (can_show) {
    // TODO(crbug.com/1121840) HandleCommandInternal is called for both
    // `popovertarget` and `commandfor`.
    InvokePopover(invoker);
    return true;
  }

  if (!RuntimeEnabledFeatures::HTMLInvokeActionsV2Enabled()) {
    return false;
  }

  LocalFrame* frame = document.GetFrame();

  if (command == CommandEventType::kToggleFullscreen) {
    if (Fullscreen::IsFullscreenElement(*this)) {
      Fullscreen::ExitFullscreen(document);
      return true;
    } else if (LocalFrame::HasTransientUserActivation(frame)) {
      Fullscreen::RequestFullscreen(*this);
      return true;
    } else {
      String message = "Cannot request fullscreen without a user gesture.";
      AddConsoleMessage(mojom::ConsoleMessageSource::kJavaScript,
                        mojom::ConsoleMessageLevel::kWarning, message);
      return false;
    }
  } else if (command == CommandEventType::kRequestFullscreen) {
    if (Fullscreen::IsFullscreenElement(*this)) {
      return true;
    }
    if (LocalFrame::HasTransientUserActivation(frame)) {
      Fullscreen::RequestFullscreen(*this);
      return true;
    } else {
      String message = "Cannot request fullscreen without a user gesture.";
      AddConsoleMessage(mojom::ConsoleMessageSource::kJavaScript,
                        mojom::ConsoleMessageLevel::kWarning, message);
      return false;
    }
  } else if (command == CommandEventType::kExitFullscreen) {
    if (Fullscreen::IsFullscreenElement(*this)) {
      Fullscreen::ExitFullscreen(document);
    }
    return true;
  }
  return false;
}

const AtomicString& HTMLElement::autocapitalize() const {
  DEFINE_STATIC_LOCAL(const AtomicString, kNone, ("none"));
  DEFINE_STATIC_LOCAL(const AtomicString, kCharacters, ("characters"));
  DEFINE_STATIC_LOCAL(const AtomicString, kWords, ("words"));
  DEFINE_STATIC_LOCAL(const AtomicString, kSentences, ("sentences"));

  const AtomicString& value = FastGetAttribute(html_names::kAutocapitalizeAttr);
  if (value.empty())
    return g_empty_atom;

  if (EqualIgnoringASCIICase(value, kNone) ||
      EqualIgnoringASCIICase(value, keywords::kOff)) {
    return kNone;
  }
  if (EqualIgnoringASCIICase(value, kCharacters))
    return kCharacters;
  if (EqualIgnoringASCIICase(value, kWords))
    return kWords;
  // "sentences", "on", or an invalid value
  return kSentences;
}

void HTMLElement::setAutocapitalize(const AtomicString& value) {
  setAttribute(html_names::kAutocapitalizeAttr, value);
}

bool HTMLElement::isContentEditableForBinding() const {
  return IsEditableOrEditingHost(*this);
}

bool HTMLElement::draggable() const {
  return EqualIgnoringASCIICase(FastGetAttribute(html_names::kDraggableAttr),
                                "true");
}

void HTMLElement::setDraggable(bool value) {
  setAttribute(html_names::kDraggableAttr,
               value ? keywords::kTrue : keywords::kFalse);
}

bool HTMLElement::spellcheck() const {
  return IsSpellCheckingEnabled();
}

void HTMLElement::setSpellcheck(bool enable) {
  setAttribute(html_names::kSpellcheckAttr,
               enable ? keywords::kTrue : keywords::kFalse);
}

void HTMLElement::click() {
  DispatchSimulatedClick(nullptr, SimulatedClickCreationScope::kFromScript);
  if (IsA<HTMLInputElement>(this)) {
    UseCounter::Count(GetDocument(),
                      WebFeature::kHTMLInputElementSimulatedClick);
  }
}

void HTMLElement::AccessKeyAction(SimulatedClickCreationScope creation_scope) {
  DispatchSimulatedClick(nullptr, creation_scope);
}

String HTMLElement::title() const {
  return FastGetAttribute(html_names::kTitleAttr);
}

TranslateAttributeMode HTMLElement::GetTranslateAttributeMode() const {
  const AtomicString& value = FastGetAttribute(html_names::kTranslateAttr);

  if (value == g_null_atom)
    return kTranslateAttributeInherit;
  if (EqualIgnoringASCIICase(value, "yes") || EqualIgnoringASCIICase(value, ""))
    return kTranslateAttributeYes;
  if (EqualIgnoringASCIICase(value, "no"))
    return kTranslateAttributeNo;

  return kTranslateAttributeInherit;
}

bool HTMLElement::translate() const {
  for (const HTMLElement* element = this; element;
       element = Traversal<HTMLElement>::FirstAncestor(*element)) {
    TranslateAttributeMode mode = element->GetTranslateAttributeMode();
    if (mode != kTranslateAttributeInherit) {
      DCHECK(mode == kTranslateAttributeYes || mode == kTranslateAttributeNo);
      return mode == kTranslateAttributeYes;
    }
  }

  // Default on the root element is translate=yes.
  return true;
}

void HTMLElement::setTranslate(bool enable) {
  setAttribute(html_names::kTranslateAttr, AtomicString(enable ? "yes" : "no"));
}

// Returns the conforming 'dir' value associated with the state the attribute is
// in (in its canonical case), if any, or the empty string if the attribute is
// in a state that has no associated keyword value or if the attribute is not in
// a defined state (e.g. the attribute is missing and there is no missing value
// default).
// http://www.whatwg.org/specs/web-apps/current-work/multipage/common-dom-interfaces.html#limited-to-only-known-values
static inline const AtomicString& ToValidDirValue(const AtomicString& value) {
  DEFINE_STATIC_LOCAL(const AtomicString, ltr_value, ("ltr"));
  DEFINE_STATIC_LOCAL(const AtomicString, rtl_value, ("rtl"));
  DEFINE_STATIC_LOCAL(const AtomicString, auto_value, ("auto"));

  if (EqualIgnoringASCIICase(value, ltr_value))
    return ltr_value;
  if (EqualIgnoringASCIICase(value, rtl_value))
    return rtl_value;
  if (EqualIgnoringASCIICase(value, auto_value))
    return auto_value;
  return g_null_atom;
}

const AtomicString& HTMLElement::dir() {
  return ToValidDirValue(FastGetAttribute(html_names::kDirAttr));
}

void HTMLElement::setDir(const AtomicString& value) {
  setAttribute(html_names::kDirAttr, value);
}

HTMLFormElement* HTMLElement::formOwner() const {
  if (const auto* internals = GetElementInternals())
    return internals->Form();
  return nullptr;
}

HTMLFormElement* HTMLElement::FindFormAncestor() const {
  return Traversal<HTMLFormElement>::FirstAncestor(*this);
}

bool HTMLElement::ElementAffectsDirectionality(const Node* node) {
  auto* html_element = DynamicTo<HTMLElement>(node);
  auto* input_element = DynamicTo<HTMLInputElement>(node);
  return (html_element && (IsA<HTMLBDIElement>(*html_element) ||
                           IsValidDirAttribute(html_element->FastGetAttribute(
                               html_names::kDirAttr)))) ||
         (input_element && input_element->IsTelephone());
}

bool HTMLElement::HasDirectionAuto() const {
  // <bdi> defaults to dir="auto"
  // https://html.spec.whatwg.org/C/#the-bdi-element
  const AtomicString& direction = FastGetAttribute(html_names::kDirAttr);
  return (IsA<HTMLBDIElement>(*this) && !IsValidDirAttribute(direction)) ||
         EqualIgnoringASCIICase(direction, "auto");
}

const TextControlElement*
HTMLElement::ElementIfAutoDirectionalityFormAssociatedOrNull(
    const Element* element) {
  const TextControlElement* text_element =
      DynamicTo<TextControlElement>(element);
  if (text_element && text_element->IsAutoDirectionalityFormAssociated()) {
    return text_element;
  }
  return nullptr;
}

bool HTMLElement::CalculateAndAdjustAutoDirectionality() {
  // This can become a CHECK() when the TextInputNotAlwaysDirAuto flag is
  // removed.
  DCHECK(HasDirectionAuto());

  // Note that HTMLSlotElement overrides this method in order to defer
  // its work in some cases.

  TextDirection text_direction;
  std::optional<TextDirection> resolve_result = ResolveAutoDirectionality();
  if (resolve_result) {
    text_direction = *resolve_result;
  } else {
    text_direction = TextDirection::kLtr;
  }
  if (CachedDirectionality() != text_direction) {
    UpdateDirectionalityAndDescendant(text_direction);

    const ComputedStyle* style = GetComputedStyle();
    if (style && style->Direction() != text_direction) {
      SetNeedsStyleRecalc(kLocalStyleChange,
                          StyleChangeReasonForTracing::Create(
                              style_change_reason::kWritingModeChange));
      return true;
    }
  }

  return false;
}

void HTMLElement::UpdateDirectionalityAfterInputTypeChange(
    const AtomicString& old_value,
    const AtomicString& new_value) {
  OnDirAttrChanged(
      AttributeModificationParams(html_names::kDirAttr, old_value, new_value,
                                  AttributeModificationReason::kDirectly));
}

void HTMLElement::AdjustDirectionAutoAfterRecalcAssignedNodes() {
  // If the slot has dir=auto, then the resulting directionality may
  // have changed.
  ChildrenChange fakeChange = {
      .type = ChildrenChangeType::kAllChildrenRemoved,
      .by_parser = ChildrenChangeSource::kAPI,
      .affects_elements = ChildrenChangeAffectsElements::kYes,
  };
  AdjustDirectionalityIfNeededAfterChildrenChanged(fakeChange);
}

Node::InsertionNotificationRequest HTMLElement::InsertedInto(
    ContainerNode& insertion_point) {
  // Process the superclass first to ensure that `InActiveDocument()` is
  // updated.
  Element::InsertedInto(insertion_point);
  HideNonce();

  if (IsFormAssociatedCustomElement())
    EnsureElementInternals().InsertedInto(insertion_point);

  return kInsertionDone;
}

void HTMLElement::RemovedFrom(ContainerNode& insertion_point) {
  if (HasPopoverAttribute() &&
      !GetDocument().StatePreservingAtomicMoveInProgress()) {
    // If a popover is removed from the document, make sure it gets
    // removed from the popover element stack and the top layer.
    bool was_in_document = insertion_point.isConnected();
    if (was_in_document) {
      // We can't run focus event handlers while removing elements.
      HidePopoverInternal(HidePopoverFocusBehavior::kNone,
                          HidePopoverTransitionBehavior::kNoEventsNoWaiting,
                          /*exception_state=*/nullptr);
    }
  }

  Element::RemovedFrom(insertion_point);
  if (IsFormAssociatedCustomElement())
    EnsureElementInternals().RemovedFrom(insertion_point);
}

void HTMLElement::DidMoveToNewDocument(Document& old_document) {
  if (IsFormAssociatedCustomElement())
    EnsureElementInternals().DidMoveToNewDocument(old_document);
  Element::DidMoveToNewDocument(old_document);
}

void HTMLElement::AddHTMLLengthToStyle(MutableCSSPropertyValueSet* style,
                                       CSSPropertyID property_id,
                                       const String& value,
                                       AllowPercentage allow_percentage,
                                       AllowZero allow_zero) {
  HTMLDimension dimension;
  if (!ParseDimensionValue(value, dimension))
    return;
  if (property_id == CSSPropertyID::kWidth &&
      (dimension.IsPercentage() || dimension.IsRelative())) {
    UseCounter::Count(GetDocument(), WebFeature::kHTMLElementDeprecatedWidth);
  }
  if (dimension.IsRelative())
    return;
  if (dimension.IsPercentage() &&
      allow_percentage == kDontAllowPercentageValues)
    return;
  if (dimension.Value() == 0 && allow_zero == kDontAllowZeroValues)
    return;
  CSSPrimitiveValue::UnitType unit =
      dimension.IsPercentage() ? CSSPrimitiveValue::UnitType::kPercentage
                               : CSSPrimitiveValue::UnitType::kPixels;
  AddPropertyToPresentationAttributeStyle(style, property_id, dimension.Value(),
                                          unit);
}

static Color ParseColorStringWithCrazyLegacyRules(const String& color_string) {
  // Per spec, only look at the first 128 digits of the string.
  const size_t kMaxColorLength = 128;
  // We'll pad the buffer with two extra 0s later, so reserve two more than the
  // max.
  Vector<char, kMaxColorLength + 2> digit_buffer;

  wtf_size_t i = 0;
  // Skip a leading #.
  if (color_string[0] == '#')
    i = 1;

  // Grab the first 128 characters, replacing non-hex characters with 0.
  // Non-BMP characters are replaced with "00" due to them appearing as two
  // "characters" in the String.
  for (; i < color_string.length() && digit_buffer.size() < kMaxColorLength;
       i++) {
    if (!IsASCIIHexDigit(color_string[i]))
      digit_buffer.push_back('0');
    else
      digit_buffer.push_back(color_string[i]);
  }

  if (!digit_buffer.size())
    return Color::kBlack;

  // Pad the buffer out to at least the next multiple of three in size.
  digit_buffer.push_back('0');
  digit_buffer.push_back('0');

  if (digit_buffer.size() < 6) {
    return Color::FromRGB(ToASCIIHexValue(digit_buffer[0]),
                          ToASCIIHexValue(digit_buffer[1]),
                          ToASCIIHexValue(digit_buffer[2]));
  }

  // Split the digits into three components, then search the last 8 digits of
  // each component.
  DCHECK_GE(digit_buffer.size(), 6u);
  wtf_size_t component_length = digit_buffer.size() / 3;
  wtf_size_t component_search_window_length =
      std::min<wtf_size_t>(component_length, 8);
  wtf_size_t red_index = component_length - component_search_window_length;
  wtf_size_t green_index =
      component_length * 2 - component_search_window_length;
  wtf_size_t blue_index = component_length * 3 - component_search_window_length;
  // Skip digits until one of them is non-zero, or we've only got two digits
  // left in the component.
  while (digit_buffer[red_index] == '0' && digit_buffer[green_index] == '0' &&
         digit_buffer[blue_index] == '0' &&
         (component_length - red_index) > 2) {
    red_index++;
    green_index++;
    blue_index++;
  }
  DCHECK_LT(red_index + 1, component_length);
  DCHECK_GE(green_index, component_length);
  DCHECK_LT(green_index + 1, component_length * 2);
  DCHECK_GE(blue_index, component_length * 2);
  SECURITY_DCHECK(blue_index + 1 < digit_buffer.size());

  int red_value =
      ToASCIIHexValue(digit_buffer[red_index], digit_buffer[red_index + 1]);
  int green_value =
      ToASCIIHexValue(digit_buffer[green_index], digit_buffer[green_index + 1]);
  int blue_value =
      ToASCIIHexValue(digit_buffer[blue_index], digit_buffer[blue_index + 1]);
  return Color::FromRGB(red_value, green_value, blue_value);
}

// Color parsing that matches HTML's "rules for parsing a legacy color value"
bool HTMLElement::ParseColorWithLegacyRules(const String& attribute_value,
                                            Color& parsed_color) {
  // An empty string doesn't apply a color. (One containing only whitespace
  // does, which is why this check occurs before stripping.)
  if (attribute_value.empty())
    return false;

  String color_string = attribute_value.StripWhiteSpace();

  // "transparent" doesn't apply a color either.
  if (EqualIgnoringASCIICase(color_string, "transparent"))
    return false;

  // If the string is a 3/6-digit hex color or a named CSS color, use that.
  // Apply legacy rules otherwise. Note color.setFromString() accepts 4/8-digit
  // hex color, so restrict its use with length checks here to support legacy
  // HTML attributes.

  bool success = false;
  if ((color_string.length() == 4 || color_string.length() == 7) &&
      color_string[0] == '#')
    success = parsed_color.SetFromString(color_string);
  if (!success)
    success = parsed_color.SetNamedColor(color_string);
  if (!success) {
    parsed_color = ParseColorStringWithCrazyLegacyRules(color_string);
    success = true;
  }

  return success;
}

void HTMLElement::AddHTMLColorToStyle(MutableCSSPropertyValueSet* style,
                                      CSSPropertyID property_id,
                                      const String& attribute_value) {
  Color parsed_color;
  if (!ParseColorWithLegacyRules(attribute_value, parsed_color))
    return;

  style->SetProperty(property_id, *cssvalue::CSSColor::Create(parsed_color));
}

void HTMLElement::AddHTMLBackgroundImageToStyle(
    MutableCSSPropertyValueSet* style,
    const String& url_value,
    const AtomicString& initiator_name) {
  String url = StripLeadingAndTrailingHTMLSpaces(url_value);
  if (url.empty()) {
    return;
  }
  auto* image_value = MakeGarbageCollected<CSSImageValue>(
      CSSUrlData(AtomicString(url), GetDocument().CompleteURL(url),
                 Referrer(GetExecutionContext()->OutgoingReferrer(),
                          GetExecutionContext()->GetReferrerPolicy()),
                 OriginClean::kTrue, false /* is_ad_related */));
  if (initiator_name) {
    image_value->SetInitiator(initiator_name);
  }
  style->SetLonghandProperty(CSSPropertyValue(
      CSSPropertyName(CSSPropertyID::kBackgroundImage), *image_value));
}

LabelsNodeList* HTMLElement::labels() {
  if (!IsLabelable())
    return nullptr;
  return EnsureCachedCollection<LabelsNodeList>(kLabelsNodeListType);
}

bool HTMLElement::IsInteractiveContent() const {
  return false;
}

void HTMLElement::DefaultEventHandler(Event& event) {
  auto* keyboard_event = DynamicTo<KeyboardEvent>(event);
  if (event.type() == event_type_names::kKeypress && keyboard_event) {
    HandleKeypressEvent(*keyboard_event);
    if (event.DefaultHandled())
      return;
  }

  Element::DefaultEventHandler(event);
}

bool HTMLElement::HandleKeyboardActivation(Event& event) {
  auto* keyboard_event = DynamicTo<KeyboardEvent>(event);
  if (keyboard_event) {
    if (event.type() == event_type_names::kKeydown &&
        keyboard_event->key() == " ") {
      SetActive(true);
      // No setDefaultHandled() - IE dispatches a keypress in this case.
      return true;
    }
    if (event.type() == event_type_names::kKeypress) {
      switch (keyboard_event->charCode()) {
        case '\r':
          DispatchSimulatedClick(&event);
          event.SetDefaultHandled();
          return true;
        case ' ':
          // Prevent scrolling down the page.
          event.SetDefaultHandled();
          return true;
      }
    }
    if (event.type() == event_type_names::kKeyup &&
        keyboard_event->key() == " ") {
      if (IsActive())
        DispatchSimulatedClick(&event);
      event.SetDefaultHandled();
      return true;
    }
  }
  return false;
}

bool HTMLElement::MatchesReadOnlyPseudoClass() const {
  return !MatchesReadWritePseudoClass();
}

// https://html.spec.whatwg.org/multipage/semantics-other.html#selector-read-write
// The :read-write pseudo-class must match ... elements that are editing hosts
// or editable and are neither input elements nor textarea elements
bool HTMLElement::MatchesReadWritePseudoClass() const {
  return IsEditableOrEditingHost(*this);
}

void HTMLElement::HandleKeypressEvent(KeyboardEvent& event) {
  if (!IsSpatialNavigationEnabled(GetDocument().GetFrame()) ||
      SupportsFocus(UpdateBehavior::kStyleAndLayout) ==
          FocusableState::kNotFocusable) {
    return;
  }
  // The SupportsFocus call above will almost always ensure style and layout is
  // clean, but it isn't guaranteed for all overrides. So double-check.
  GetDocument().UpdateStyleAndLayoutTree();

  // If the element is a text form control (like <input type=text> or
  // <textarea>) or has contentEditable attribute on, we should enter a space or
  // newline even in spatial navigation mode instead of handling it as a "click"
  // action.
  if (IsTextControl() || IsEditable(*this))
    return;
  int char_code = event.charCode();
  if (char_code == '\r' || char_code == ' ') {
    DispatchSimulatedClick(&event);
    event.SetDefaultHandled();
  }
}

int HTMLElement::AdjustedOffsetForZoom(LayoutUnit offset) {
  const auto* layout_object = GetLayoutObject();
  DCHECK(layout_object);
  return AdjustForAbsoluteZoom::AdjustLayoutUnit(offset,
                                                 layout_object->StyleRef())
      .Round();
}

int HTMLElement::OffsetTopOrLeft(bool top) {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  const auto* layout_object = GetLayoutBoxModelObject();
  if (!layout_object)
    return 0;

  HeapHashSet<Member<TreeScope>> ancestor_tree_scopes = GetAncestorTreeScopes();
  LayoutUnit offset;
  Element* offset_parent = this;
  // This loop adds up all of the offsetTop/offsetLeft values for this and
  // parent shadow-hidden offsetParents up the flat tree. If
  // |ancestor_tree_scopes| doesn't contain the next |offset_parent|'s
  // TreeScope, then we know that |offset_parent| is shadow-hidden from |this|.
  do {
    // offset_parent->OffsetParent() may update style and layout:
    Element* next_offset_parent = offset_parent->OffsetParent();
    if (const auto* offset_parent_layout_object =
            offset_parent->GetLayoutBoxModelObject()) {
      if (top) {
        offset += offset_parent_layout_object->OffsetTop(next_offset_parent);
      } else {
        offset += offset_parent_layout_object->OffsetLeft(next_offset_parent);
      }
    }
    offset_parent = next_offset_parent;
  } while (offset_parent &&
           !ancestor_tree_scopes.Contains(&offset_parent->GetTreeScope()));

  return AdjustedOffsetForZoom(offset);
}

int HTMLElement::offsetLeftForBinding() {
  return OffsetTopOrLeft(/*top=*/false);
}

int HTMLElement::offsetTopForBinding() {
  return OffsetTopOrLeft(/*top=*/true);
}

int HTMLElement::offsetWidthForBinding() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  int result = 0;
  if (const auto* layout_object = GetLayoutBoxModelObject()) {
    result = AdjustedOffsetForZoom(layout_object->OffsetWidth());
    RecordScrollbarSizeForStudy(result, /* is_width= */ true,
                                /* is_offset= */ true);
  }
  return result;
}

DISABLE_CFI_PERF
int HTMLElement::offsetHeightForBinding() {
  GetDocument().EnsurePaintLocationDataValidForNode(
      this, DocumentUpdateReason::kJavaScript);
  int result = 0;
  if (const auto* layout_object = GetLayoutBoxModelObject()) {
    result = AdjustedOffsetForZoom(layout_object->OffsetHeight());
    RecordScrollbarSizeForStudy(result, /* is_width= */ false,
                                /* is_offset= */ true);
  }
  return result;
}

Element* HTMLElement::unclosedOffsetParent() {
  GetDocument().UpdateStyleAndLayoutForNode(this,
                                            DocumentUpdateReason::kJavaScript);

  LayoutObject* layout_object = GetLayoutObject();
  if (!layout_object)
    return nullptr;

  return layout_object->OffsetParent(this);
}

void HTMLElement::OnDirAttrChanged(const AttributeModificationParams& params) {
  // If an ancestor has dir=auto, and this node has the first character,
  // changes to dir attribute may affect the ancestor.
  bool is_old_valid = IsValidDirAttribute(params.old_value);
  bool is_new_valid = IsValidDirAttribute(params.new_value);
  if (!is_old_valid && !is_new_valid) {
    return;
  }

  GetDocument().SetHasDirAttribute();

  bool is_old_auto = SelfOrAncestorHasDirAutoAttribute();
  bool is_new_auto = HasDirectionAuto();

  if (is_new_auto) {
    if (auto* input_element = DynamicTo<HTMLInputElement>(*this)) {
      input_element->EnsureShadowSubtree();
    }
  }

  if (is_old_valid != is_new_valid) {
    UpdateAncestorWithDirAuto(UpdateAncestorTraversal::ExcludeSelf);
  }

  if (is_old_auto) {
    if (!RecalcSelfOrAncestorHasDirAuto()) {
      ClearSelfOrAncestorHasDirAutoAttribute();
      UpdateDescendantHasDirAutoAttribute(false /* has_dir_auto */);
    }
  } else {
    if (RecalcSelfOrAncestorHasDirAuto()) {
      SetSelfOrAncestorHasDirAutoAttribute();
      UpdateDescendantHasDirAutoAttribute(true /* has_dir_auto */);
    }
  }

  if (is_new_auto) {
    CalculateAndAdjustAutoDirectionality();
  } else {
    std::optional<TextDirection> text_direction;
    if (EqualIgnoringASCIICase(params.new_value, "ltr")) {
      text_direction = TextDirection::kLtr;
    } else if (EqualIgnoringASCIICase(params.new_value, "rtl")) {
      text_direction = TextDirection::kRtl;
    }

    if (!text_direction.has_value()) {
      if (HTMLElement* parent = DynamicTo<HTMLElement>(parentElement())) {
        text_direction = parent->CachedDirectionality();
      } else {
        text_direction = TextDirection::kLtr;
      }
    }

    UpdateDirectionalityAndDescendant(*text_direction);
  }

  SetNeedsStyleRecalc(
      kSubtreeStyleChange,
      StyleChangeReasonForTracing::Create(style_change_reason::kPseudoClass));
  PseudoStateChanged(CSSSelector::kPseudoDir);
}

void HTMLElement::OnPopoverChanged(const AttributeModificationParams& params) {
  UpdatePopoverAttribute(params.new_value);
}

void HTMLElement::OnFormAttrChanged(const AttributeModificationParams& params) {
  if (IsFormAssociatedCustomElement())
    EnsureElementInternals().FormAttributeChanged();
}

void HTMLElement::OnLangAttrChanged(const AttributeModificationParams& params) {
  LangAttributeChanged();
}

void HTMLElement::OnNonceAttrChanged(
    const AttributeModificationParams& params) {
  if (params.new_value != g_empty_atom)
    setNonce(params.new_value);
}

ElementInternals* HTMLElement::attachInternals(
    ExceptionState& exception_state) {
  // 1. If this's is value is not null, then throw a "NotSupportedError"
  // DOMException
```