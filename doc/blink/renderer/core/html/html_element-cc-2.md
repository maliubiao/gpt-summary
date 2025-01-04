Response:
The user wants a summary of the functionality of the provided C++ code snippet from `html_element.cc`, focusing on its role in handling popovers within the Chromium Blink engine. I need to:

1. **Identify the main function:** The code primarily deals with showing and hiding popovers.
2. **Explain the logic:**  The code manages the stacking of different popover types (auto and hint), handles events related to showing and hiding, manages focus, and considers anchor and invoker relationships between popovers.
3. **Relate to web technologies:**  Connect the code to JavaScript (event handling), HTML (`popover` attribute), and CSS (`:popover-open` pseudo-class).
4. **Infer assumptions and outputs:**  Analyze the code to understand how it behaves under different conditions.
5. **Identify potential user errors:** Pinpoint scenarios where incorrect usage or unexpected behavior might occur.
6. **Synthesize the information:** Combine all these points into a concise summary for part 3 of a 5-part explanation.
这是 `blink/renderer/core/html/html_element.cc` 文件关于 HTML 元素处理 popover 功能的一部分代码。

**功能归纳:**

这段代码主要负责处理 HTML 元素的 **显示 (show)** 和 **隐藏 (hide)** popover 的逻辑，特别是当 popover 的 `popover` 属性值为 `auto` 或 `hint` 时。它管理着 popover 的堆叠顺序，以及在显示和隐藏 popover 时触发的事件和焦点管理。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

1. **HTML:**
   - **`popover` 属性:**  这段代码的核心逻辑是基于 HTML 元素的 `popover` 属性，特别是当其值为 `auto` 或 `hint` 时。代码会检查和操作具有这些属性值的元素。
   - **`popovertarget` 属性:**  代码中涉及到 `invoker`，这通常指带有 `popovertarget` 属性的元素，用于触发关联 popover 的显示。当 `showPopoverInternal` 被调用时，它会接收一个 `invoker` 参数。
   - **`anchor` 属性:** 代码中也提到了 `anchorElement()`，这指的是 popover 元素的 `anchor` 属性，用于将 popover 定位到特定的锚点元素。
   - **Toggle 事件 (`toggle`, `beforetoggle`):** 代码在显示和隐藏 popover 的过程中会触发 `toggle` 和 `beforetoggle` 事件。例如，在 `ShowPopoverInternal` 中，会创建并分发一个 `toggle` 事件。

   **举例:**
   ```html
   <button popovertarget="my-popover">显示 Popover</button>
   <div id="my-popover" popover="auto">这是一个自动 popover。</div>

   <div id="anchor-element">锚点</div>
   <div id="another-popover" popover="hint" anchor="anchor-element">这是一个提示 popover。</div>
   ```

2. **JavaScript:**
   - **`showPopover()` 和 `hidePopover()` 方法:** 代码实现了 `showPopoverInternal` 和 `HidePopoverInternal`，它们对应于 JavaScript 中 HTML 元素上的 `showPopover()` 和 `hidePopover()` 方法。JavaScript 可以调用这些方法来控制 popover 的显示和隐藏。
   - **事件监听:**  JavaScript 可以监听 `toggle` 和 `beforetoggle` 事件，以便在 popover 状态改变前后执行自定义逻辑。

   **举例:**
   ```javascript
   const popoverElement = document.getElementById('my-popover');
   popoverElement.addEventListener('toggle', (event) => {
       console.log('Popover 状态改变:', event.newState);
   });

   const button = document.querySelector('button');
   button.onclick = () => {
       const targetPopover = document.getElementById(button.getAttribute('popovertarget'));
       targetPopover.showPopover();
   };
   ```

3. **CSS:**
   - **`:popover-open` 伪类:** 代码中使用了 `PseudoStateChanged(CSSSelector::kPseudoPopoverOpen)`，这表示当 popover 显示时，会应用 `:popover-open` 伪类，从而允许开发者通过 CSS 设置 popover 打开时的样式。

   **举例:**
   ```css
   #my-popover:popover-open {
       border: 2px solid blue;
       background-color: lightyellow;
   }
   ```

**逻辑推理与假设输入/输出:**

**假设输入:**

1. 一个 `popover="auto"` 的 `div` 元素和一个触发它的 `<button popovertarget="the-div">`。
2. 用户点击了这个按钮。

**逻辑推理:**

- `ShowPopoverInternal` 函数会被调用，`invoker` 是那个按钮元素。
- 代码会检查当前文档中是否有其他 `auto` 或 `hint` 类型的 popover 正在显示。
- 如果有，根据 popover 的类型和层叠规则（例如，新的 `auto` popover 会关闭之前的 `auto` popover），可能需要先隐藏其他 popover。
- 新的 `auto` popover 会被添加到文档的 `PopoverAutoStack()` 中。
- 触发 `beforetoggle` 事件（`oldState` 为 "closed"，`newState` 为 "open"）。
- 如果 `beforetoggle` 事件没有被取消，则 popover 会被添加到顶层 (top layer)。
- 应用 `:popover-open` 伪类。
- 触发 `toggle` 事件（`oldState` 为 "closed"，`newState` 为 "open"）。
- 如果没有其他需要聚焦的元素，焦点可能会被设置到 popover 元素本身或其内部具有 `autofocus` 属性的元素。

**输出:**

- 该 `div` 元素会显示在屏幕上，覆盖在其他内容之上。
- 按钮元素触发的 `toggle` 事件会被分发。
- 任何应用了 `:popover-open` 伪类的 CSS 规则都会生效。

**用户或编程常见的使用错误举例:**

1. **在 `beforetoggle` 事件处理函数中改变 popover 的 `popover` 属性值:** 代码中对此进行了检查，如果发生这种情况，会抛出 `DOMException`。

   **举例:**
   ```javascript
   popoverElement.addEventListener('beforetoggle', (event) => {
       if (someCondition) {
           popoverElement.popover = 'manual'; // 错误！
       }
   });
   ```

2. **在 `beforetoggle` 事件处理函数中调用 `showPopover()` 导致无限循环:** 代码中尝试检测并处理这种情况，会发出警告信息，并停止触发事件。

   **举例:**
   ```javascript
   let isShowingAnother = false;
   popoverElement.addEventListener('beforetoggle', (event) => {
       if (event.newState === 'open' && !isShowingAnother) {
           isShowingAnother = true;
           document.getElementById('another-popover').showPopover(); // 可能导致问题
       }
   });
   ```

3. **错误地管理焦点:** 开发者可能期望在 popover 关闭后焦点回到特定的元素，但如果没有正确处理 `previouslyFocusedElement`，焦点可能会丢失。

**这段代码的功能总结:**

这段代码的核心功能是实现 `auto` 和 `hint` 类型的 popover 的显示和隐藏机制。它负责管理 popover 的堆叠，处理相关的事件（`toggle` 和 `beforetoggle`），以及在 popover 显示和隐藏时进行焦点管理。代码还考虑了 popover 之间的关联，例如通过 `anchor` 属性和触发元素 (`invoker`) 建立的联系，并处理了在事件处理过程中可能出现的错误情况。

Prompt: 
```
这是目录为blink/renderer/core/html/html_element.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
::kShow, exception_state,
                      /*include_event_handler_text=*/true,
                      &original_document)) {
    return;
  }

  bool should_restore_focus = false;
  auto original_type = PopoverType();
  bool new_popover_is_auto = original_type == PopoverValueType::kAuto;
  if (new_popover_is_auto || original_type == PopoverValueType::kHint) {
    auto& auto_stack = original_document.PopoverAutoStack();
    auto& hint_stack = original_document.PopoverHintStack();
    HTMLDocument::PopoverStack* append_to_stack = nullptr;
    auto focus_behavior = HidePopoverFocusBehavior::kNone;
    if (new_popover_is_auto) {
      // If the new popover is an auto-popover:
      //  - It cannot be in the hint stack (hints only), so close the entire
      //    hint stack.
      //  - If the new auto has an ancestor in the auto stack, close all
      //    popovers past that point in the auto stack. Otherwise, close the
      //    entire auto stack.
      //  - Set append_to_stack to the auto stack.
      CloseEntirePopoverStack(hint_stack, focus_behavior, transition_behavior);
      HideAllPopoversUntil(
          FindTopmostPopoverAncestor(*this, auto_stack, invoker),
          original_document, focus_behavior, transition_behavior);
      append_to_stack = &auto_stack;
    } else {
      // If the new popover is a hint-popover:
      //  - If the new hint has an ancestor in the hint stack:
      //     - Close all popovers past that point in the hint stack
      //     - Set append_to_stack to the hint stack.
      //  - Otherwise:
      //     - Close the entire hint stack
      //     - If the new hint has an ancestor in the auto stack:
      //        - close all popovers past that point in the auto stack
      //        - Set append_to_stack to the auto stack.
      //     - Otherwise set append_to_stack to the hint stack.
      //  - Add the new hint to append_to_stack.
      if (auto* ancestor =
              FindTopmostPopoverAncestor(*this, hint_stack, invoker)) {
        HideAllPopoversUntil(ancestor, original_document, focus_behavior,
                             transition_behavior);
        append_to_stack = &hint_stack;
      } else {
        CloseEntirePopoverStack(hint_stack, focus_behavior,
                                transition_behavior);
        if (auto* auto_ancestor =
                FindTopmostPopoverAncestor(*this, auto_stack, invoker)) {
          HideAllPopoversUntil(auto_ancestor, original_document, focus_behavior,
                               transition_behavior);
          append_to_stack = &auto_stack;
        } else {
          append_to_stack = &hint_stack;
        }
      }
    }
    CHECK(append_to_stack);

    // The 'beforetoggle' event handlers could have changed this popover, e.g.
    // by changing its type, removing it from the document, moving it to
    // another document, or calling showPopover().
    if (PopoverType() != original_type) {
      if (exception_state) {
        exception_state->ThrowDOMException(
            DOMExceptionCode::kInvalidStateError,
            "The value of the popover attribute was changed while hiding the "
            "popover.");
      }
      return;
    }
    if (!IsPopoverReady(PopoverTriggerAction::kShow, exception_state,
                        /*include_event_handler_text=*/true,
                        &original_document)) {
      return;
    }

    // We only restore focus for popover=auto/hint, and only for the first
    // popover in the stack. If there's nothing showing, restore focus.
    should_restore_focus = !original_document.TopmostPopoverOrHint();

    // Add this popover to the appropriate popover stack.
    CHECK(!append_to_stack->Contains(this));
    append_to_stack->push_back(this);

    CloseWatcher* close_watcher = nullptr;
    if (auto* window = GetDocument().domWindow()) {
      close_watcher = CloseWatcher::Create(*window);
    }
    if (close_watcher) {
      auto* event_listener =
          MakeGarbageCollected<PopoverCloseWatcherEventListener>(this);
      close_watcher->addEventListener(event_type_names::kClose, event_listener);
      close_watcher->addEventListener(event_type_names::kCancel,
                                      event_listener);
    }
    GetPopoverData()->setCloseWatcher(close_watcher);
  }

  MarkPopoverInvokersDirty(*this);
  GetPopoverData()->setPreviouslyFocusedElement(nullptr);
  Element* originally_focused_element = original_document.FocusedElement();
  original_document.AddToTopLayer(this);
  // Make the popover match `:popover-open` and remove `display:none` styling:
  GetPopoverData()->setVisibilityState(PopoverVisibilityState::kShowing);
  GetPopoverData()->setInvoker(invoker);
  if (RuntimeEnabledFeatures::PopoverAnchorRelationshipsEnabled() ||
      (RuntimeEnabledFeatures::CustomizableSelectEnabled() &&
       HTMLSelectElement::IsPopoverForAppearanceBase(this))) {
    SetImplicitAnchor(invoker);
  }

  PseudoStateChanged(CSSSelector::kPseudoPopoverOpen);
  if (HTMLSelectElement::IsPopoverForAppearanceBase(this)) {
    // If this element is the ::picker(select) popover, then we need to
    // invalidate the select element's :open pseudo-class at the same time as
    // :popover-open https://issues.chromium.org/issues/375004874
    OwnerShadowHost()->PseudoStateChanged(CSSSelector::kPseudoOpen);
  }

  CHECK(!original_document.AllOpenPopovers().Contains(this));
  original_document.AllOpenPopovers().insert(this);

  // Queue a delayed hide event, if necessary.
  if (RuntimeEnabledFeatures::HTMLPopoverActionHoverEnabled()) {
    if (!GetDocument().HoverElement() ||
        !IsNodePopoverDescendant(*GetDocument().HoverElement())) {
      MaybeQueuePopoverHideEvent();
    }
  }

  SetPopoverFocusOnShow();

  // Store the element to focus when this popover closes.
  if (should_restore_focus && HasPopoverAttribute()) {
    GetPopoverData()->setPreviouslyFocusedElement(originally_focused_element);
  }

  // Queue the "opening" toggle event.
  String old_state = "closed";
  ToggleEvent* after_event;
  if (GetPopoverData()->hasPendingToggleEventTask()) {
    // There's already a queued 'toggle' event. Cancel it and fire a new one
    // keeping the original value for old_state.
    old_state =
        GetPopoverData()->pendingToggleEventStartedClosed() ? "closed" : "open";
    GetPopoverData()->cancelPendingToggleEventTask();
  } else {
    GetPopoverData()->setPendingToggleEventStartedClosed(true);
  }
  after_event = ToggleEvent::Create(event_type_names::kToggle,
                                    Event::Cancelable::kNo, old_state,
                                    /*new_state*/ "open");
  CHECK_EQ(after_event->newState(), "open");
  CHECK_EQ(after_event->oldState(), old_state);
  CHECK(!after_event->bubbles());
  CHECK(!after_event->cancelable());
  after_event->SetTarget(this);
  GetPopoverData()->setPendingToggleEventTask(PostCancellableTask(
      *original_document.GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
      WTF::BindOnce(
          [](HTMLElement* element, ToggleEvent* event) {
            CHECK(element);
            CHECK(event);
            element->DispatchEvent(*event);
          },
          WrapPersistent(this), WrapPersistent(after_event))));
}

// static
void HTMLElement::CloseEntirePopoverStack(
    HTMLDocument::PopoverStack& stack,
    HidePopoverFocusBehavior focus_behavior,
    HidePopoverTransitionBehavior transition_behavior) {
  while (!stack.empty()) {
    // TODO(masonf) If a popover's beforetoggle handler opens a new popover, it
    // is possible to get an infinite loop here. Need to break that loop.
    stack.back()->HidePopoverInternal(focus_behavior, transition_behavior,
                                      /*exception_state*/ nullptr);
  }
}

// static
// All popovers up to, but not including, |endpoint|, will be hidden. If
// endpoint is nullptr, all popover stacks will be closed. If endpoint is in
// the hint stack, it'll be closed up to endpoint, and the auto stack will be
// left as-is. Otherwise the entire hint stack will be closed, and the same
// check will be made against the auto stack.
void HTMLElement::HideAllPopoversUntil(
    const HTMLElement* endpoint,
    Document& document,
    HidePopoverFocusBehavior focus_behavior,
    HidePopoverTransitionBehavior transition_behavior) {
  CHECK(!endpoint || endpoint->HasPopoverAttribute());
  CHECK(!endpoint || endpoint->PopoverType() == PopoverValueType::kAuto ||
        endpoint->PopoverType() == PopoverValueType::kHint);

  if (endpoint && !endpoint->popoverOpen()) {
    return;
  }

  if (!endpoint) {
    CloseEntirePopoverStack(document.PopoverHintStack(), focus_behavior,
                            transition_behavior);
    CloseEntirePopoverStack(document.PopoverAutoStack(), focus_behavior,
                            transition_behavior);
    return;
  }

  // Given an ancestor to leave open, this finds the last (counting from the
  // top of the stack) popover that should be closed. The ancestor *must* be
  // in the stack. If this returns nullptr, the ancestor is the top of the
  // stack.
  auto find_last_to_hide =
      [](const HTMLElement* endpoint,
         HTMLDocument::PopoverStack& stack) -> const HTMLElement* {
    const HTMLElement* last_to_hide = nullptr;
    for (auto it = stack.rbegin(); it != stack.rend(); ++it) {
      if (*it == endpoint) {
        return last_to_hide;
      }
      last_to_hide = *it;
    }
    NOTREACHED() << "ancestor must be in the stack";
  };

  auto hide_stack_until = [&find_last_to_hide, &focus_behavior,
                           &transition_behavior,
                           &document](const HTMLElement* endpoint,
                                      HTMLDocument::PopoverStack& stack) {
    // We never throw exceptions from HideAllPopoversUntil, since it is always
    // used to close other popovers that are already showing.
    ExceptionState* exception_state = nullptr;
    bool repeating_hide = false;
    do {
      auto* last_to_hide = find_last_to_hide(endpoint, stack);
      if (!last_to_hide) {
        // find_last_to_hide returns nullptr if endpoint is on the top of the
        // stack.
        return;
      }
      while (last_to_hide && last_to_hide->popoverOpen()) {
        CHECK(!stack.empty());
        stack.back()->HidePopoverInternal(focus_behavior, transition_behavior,
                                          exception_state);
      }
      // Now check if we're left with endpoint at the top of the stack.
      CHECK(!repeating_hide || stack.back() == endpoint);
      repeating_hide = stack.Contains(endpoint) && stack.back() != endpoint;
      if (repeating_hide) {
        // No longer fire events.
        transition_behavior = HidePopoverTransitionBehavior::kNoEventsNoWaiting;
        document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
            mojom::blink::ConsoleMessageSource::kOther,
            mojom::blink::ConsoleMessageLevel::kWarning,
            "The `beforetoggle` event handler for a popover triggered another "
            "popover to be shown. This is not recommended."));
      }
    } while (repeating_hide);
  };

  // First check the hint stack.
  auto& hint_stack = document.PopoverHintStack();
  if (hint_stack.Contains(endpoint)) {
    // If the hint stack contains this endpoint, close the popovers above that
    // point in the stack, then return.
    CHECK(RuntimeEnabledFeatures::HTMLPopoverHintEnabled());
    CHECK_EQ(endpoint->PopoverType(), PopoverValueType::kHint);
    hide_stack_until(endpoint, hint_stack);
    return;
  }

  // If the endpoint wasn't in the hint stack, close the entire hint stack.
  CloseEntirePopoverStack(document.PopoverHintStack(), focus_behavior,
                          transition_behavior);

  // Now check the auto stack.
  auto& auto_stack = document.PopoverAutoStack();
  if (!auto_stack.Contains(endpoint)) {
    // Event handlers from hint popovers could have closed our endpoint.
    return;
  }
  hide_stack_until(endpoint, auto_stack);
}

void HTMLElement::hidePopover(ExceptionState& exception_state) {
  HidePopoverInternal(
      HidePopoverFocusBehavior::kFocusPreviousElement,
      HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions,
      &exception_state);
}

void HTMLElement::HidePopoverInternal(
    HidePopoverFocusBehavior focus_behavior,
    HidePopoverTransitionBehavior transition_behavior,
    ExceptionState* exception_state) {
  if (!IsPopoverReady(PopoverTriggerAction::kHide, exception_state,
                      /*include_event_handler_text=*/true, /*document=*/nullptr)) {
    return;
  }
  auto& document = GetDocument();
  bool show_warning =
      transition_behavior != HidePopoverTransitionBehavior::kNoEventsNoWaiting;
  PopoverData::ScopedStartShowingOrHiding scoped_was_showing_or_hiding(
      *this, show_warning);
  if (scoped_was_showing_or_hiding) {
    // We're in a loop, so stop firing events.
    transition_behavior = HidePopoverTransitionBehavior::kNoEventsNoWaiting;
  }

  auto& hint_stack = document.PopoverHintStack();
  auto& auto_stack = document.PopoverAutoStack();
  HTMLDocument::PopoverStack* stack_containing_this = nullptr;
  if (PopoverType() == PopoverValueType::kAuto ||
      PopoverType() == PopoverValueType::kHint) {
    // Hide any popovers above us in the stack.
    HideAllPopoversUntil(this, document, focus_behavior, transition_behavior);
    // The 'beforetoggle' event handlers could have changed this popover, e.g.
    // by changing its type, removing it from the document, or calling
    // hidePopover().
    if (!IsPopoverReady(PopoverTriggerAction::kHide, exception_state,
                        /*include_event_handler_text=*/true, &document)) {
      return;
    }
    if (!auto_stack.empty() && auto_stack.back() == this) {
      stack_containing_this = &auto_stack;
    } else {
      stack_containing_this = &hint_stack;
    }
    CHECK(!stack_containing_this->empty() &&
          stack_containing_this->back() == this);
  }

  MarkPopoverInvokersDirty(*this);
  GetPopoverData()->setInvoker(nullptr);
  // Events are only fired in the case that the popover is not being removed
  // from the document.
  if (transition_behavior ==
      HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions) {
    // Fire the "closing" beforetoggle event.
    auto* event = ToggleEvent::Create(
        event_type_names::kBeforetoggle, Event::Cancelable::kNo,
        /*old_state*/ "open", /*new_state*/ "closed");
    CHECK(!event->bubbles());
    CHECK(!event->cancelable());
    CHECK_EQ(event->oldState(), "open");
    CHECK_EQ(event->newState(), "closed");
    event->SetTarget(this);
    auto result = DispatchEvent(*event);
    if (result != DispatchEventResult::kNotCanceled) {
      // The event can be cancelled before dispatch, if the target or execution
      // context no longer exists, etc. See crbug.com/1445329.
      CHECK_EQ(result, DispatchEventResult::kCanceledBeforeDispatch);
      return;
    }
    if (stack_containing_this && !stack_containing_this->empty() &&
        stack_containing_this->back() != this) {
      CHECK(PopoverType() == PopoverValueType::kAuto ||
            PopoverType() == PopoverValueType::kHint);
      AddConsoleMessage(
          mojom::blink::ConsoleMessageSource::kOther,
          mojom::blink::ConsoleMessageLevel::kWarning,
          "The `beforetoggle` event handler for a popover triggered another "
          "popover to be shown. This is not recommended.");
      HideAllPopoversUntil(this, document, focus_behavior,
                           HidePopoverTransitionBehavior::kNoEventsNoWaiting);
    }

    // The 'beforetoggle' event handler could have changed this popover, e.g. by
    // changing its type, removing it from the document, or calling
    // showPopover().
    if (!IsPopoverReady(PopoverTriggerAction::kHide, exception_state,
                        /*include_event_handler_text=*/true, &document)) {
      return;
    }

    // Queue the "closing" toggle event.
    String old_state = "open";
    ToggleEvent* after_event;
    if (GetPopoverData()->hasPendingToggleEventTask()) {
      // There's already a queued 'toggle' event. Cancel it and fire a new one
      // keeping the original value for old_state.
      old_state = GetPopoverData()->pendingToggleEventStartedClosed() ? "closed"
                                                                      : "open";
      GetPopoverData()->cancelPendingToggleEventTask();
    } else {
      GetPopoverData()->setPendingToggleEventStartedClosed(false);
    }
    after_event = ToggleEvent::Create(event_type_names::kToggle,
                                      Event::Cancelable::kNo, old_state,
                                      /*new_state*/ "closed");
    CHECK_EQ(after_event->newState(), "closed");
    CHECK_EQ(after_event->oldState(), old_state);
    CHECK(!after_event->bubbles());
    CHECK(!after_event->cancelable());
    after_event->SetTarget(this);
    GetPopoverData()->setPendingToggleEventTask(PostCancellableTask(
        *document.GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
        WTF::BindOnce(
            [](HTMLElement* element, ToggleEvent* event) {
              CHECK(element);
              CHECK(event);
              element->DispatchEvent(*event);
            },
            WrapPersistent(this), WrapPersistent(after_event))));

    document.ScheduleForTopLayerRemoval(this,
                                        Document::TopLayerReason::kPopover);
  } else {
    document.RemoveFromTopLayerImmediately(this);
  }

  // Remove this popover from the stack.
  if (PopoverType() != PopoverValueType::kManual) {
    if (!hint_stack.empty() && this == hint_stack.back()) {
      CHECK_EQ(PopoverType(), PopoverValueType::kHint);
      CHECK(RuntimeEnabledFeatures::HTMLPopoverHintEnabled());
      hint_stack.pop_back();
    } else {
      CHECK(!auto_stack.empty());
      CHECK_EQ(auto_stack.back(), this);
      auto_stack.pop_back();
    }
  }

  // Re-apply display:none, and stop matching `:popover-open`.
  GetPopoverData()->setVisibilityState(PopoverVisibilityState::kHidden);

  PseudoStateChanged(CSSSelector::kPseudoPopoverOpen);
  if (HTMLSelectElement::IsPopoverForAppearanceBase(this)) {
    // If this element is the ::picker(select) popover, then we need to
    // invalidate the select element's :open pseudo-class at the same time as
    // :popover-open https://issues.chromium.org/issues/375004874
    OwnerShadowHost()->PseudoStateChanged(CSSSelector::kPseudoOpen);
  }

  document.AllOpenPopovers().erase(this);

  Element* previously_focused_element =
      GetPopoverData()->previouslyFocusedElement();
  if (previously_focused_element) {
    GetPopoverData()->setPreviouslyFocusedElement(nullptr);
    if (focus_behavior == HidePopoverFocusBehavior::kFocusPreviousElement &&
        contains(document.AdjustedFocusedElement())) {
      FocusOptions* focus_options = FocusOptions::Create();
      focus_options->setPreventScroll(true);
      previously_focused_element->Focus(FocusParams(
          SelectionBehaviorOnFocus::kRestore, mojom::blink::FocusType::kScript,
          /*capabilities=*/nullptr, focus_options));
    }
  }

  if (auto* close_watcher = GetPopoverData()->closeWatcher()) {
    close_watcher->destroy();
    GetPopoverData()->setCloseWatcher(nullptr);
  }
}

void HTMLElement::SetPopoverFocusOnShow() {
  // The layout must be updated here because we call Element::isFocusable,
  // which requires an up-to-date layout.
  GetDocument().UpdateStyleAndLayoutTreeForElement(
      this, DocumentUpdateReason::kPopover);

  if (auto* dialog = DynamicTo<HTMLDialogElement>(this)) {
    if (RuntimeEnabledFeatures::PopoverDialogNewFocusBehaviorEnabled()) {
      dialog->SetFocusForDialog();
    } else {
      HTMLDialogElement::SetFocusForDialogLegacy(dialog);
    }
    return;
  }

  Element* control = IsAutofocusable() ? this : GetAutofocusDelegate();

  // If the popover does not use autofocus, then the focus should remain on the
  // currently active element.
  // https://open-ui.org/components/popover.research.explainer#focus-management
  if (!control)
    return;

  // 3. Run the focusing steps for control.
  control->Focus();

  // 4. Let topDocument be the active document of control's node document's
  // browsing context's top-level browsing context.
  // 5. If control's node document's origin is not the same as the origin of
  // topDocument, then return.
  Document& doc = control->GetDocument();
  if (!doc.IsActive())
    return;
  if (!doc.IsInMainFrame() &&
      !doc.TopFrameOrigin()->CanAccess(
          doc.GetExecutionContext()->GetSecurityOrigin())) {
    return;
  }

  // 6. Empty topDocument's autofocus candidates.
  // 7. Set topDocument's autofocus processed flag to true.
  doc.TopDocument().FinalizeAutofocus();
}

namespace {

// Remember to keep kMinValue and kMaxValue in sync.
enum class PopoverAncestorOptions {
  kExclusive,
  kIncludeManualPopovers,

  // For `PopoverAncestorOptionsSet`.
  kMinValue = kExclusive,
  kMaxValue = kIncludeManualPopovers,
};
using PopoverAncestorOptionsSet =
    base::EnumSet<PopoverAncestorOptions,
                  PopoverAncestorOptions::kMinValue,
                  PopoverAncestorOptions::kMaxValue>;

template <typename UnaryPredicate>
const HTMLElement* NearestMatchingAncestor(
    const Node* original_node,
    const PopoverAncestorOptionsSet ancestor_options,
    const UnaryPredicate get_candidate_popover) {
  if (!original_node) {
    return nullptr;
  }
  bool exclusive = ancestor_options.Has(PopoverAncestorOptions::kExclusive);
  auto* node =
      exclusive ? FlatTreeTraversal::Parent(*original_node) : original_node;
  for (; node; node = FlatTreeTraversal::Parent(*node)) {
    auto* candidate_popover = get_candidate_popover(node);
    if (!candidate_popover || !candidate_popover->popoverOpen()) {
      continue;
    }
    if (exclusive && candidate_popover == original_node) {
      continue;
    }
    if (!ancestor_options.Has(PopoverAncestorOptions::kIncludeManualPopovers) &&
        candidate_popover->PopoverType() == PopoverValueType::kManual) {
      continue;
    }
    DCHECK(!exclusive || candidate_popover != original_node);
    return candidate_popover;
  }
  return nullptr;
}

const HTMLElement* NearestOpenPopover(
    const Node* node,
    const PopoverAncestorOptionsSet ancestor_options =
        PopoverAncestorOptionsSet()) {
  return NearestMatchingAncestor(
      node, ancestor_options,
      [](const Node* test_node) { return DynamicTo<HTMLElement>(test_node); });
}

const HTMLElement* NearestTargetPopoverForInvoker(
    const Node* node,
    const PopoverAncestorOptionsSet ancestor_options =
        PopoverAncestorOptionsSet()) {
  return NearestMatchingAncestor(
      node, ancestor_options, [](const Node* test_node) -> const HTMLElement* {
        auto* form_element =
            DynamicTo<HTMLFormControlElement>(const_cast<Node*>(test_node));
        if (!form_element) {
          return nullptr;
        }
        auto* button_element = DynamicTo<HTMLButtonElement>(form_element);
        auto* target_element =
            button_element ? button_element->commandForElement() : nullptr;

        return target_element
                   ? DynamicTo<HTMLElement>(target_element)
                   : form_element->popoverTargetElement().popover.Get();
      });
}

}  // namespace

// static
// This function will return the topmost (highest in the popover stack)
// ancestral popover for the provided popover. Popovers can be related to each
// other in several ways, creating a tree of popovers. There are three paths
// through which one popover (call it the "child" popover) can have an ancestor
// popover (call it the "parent" popover):
//  1. the popovers are nested within each other in the DOM tree. In this case,
//     the descendant popover is the "child" and its ancestor popover is the
//     "parent".
//  2. a popover has an `anchor` attribute pointing to another element in the
//     DOM. In this case, the popover is the "child", and the DOM-contained
//     popover of its anchor element is the "parent". If the anchor doesn't
//     point to an element, or that element isn't contained within a popover, no
//     such relationship exists.
//  3. an invoking element (e.g. a <button>) has a `popovertarget` attribute
//     pointing to a popover. In this case, the popover is the "child", and the
//     DOM-contained popover of the invoking element is the "parent". As with
//     anchor, the invoker must be in a popover and reference an open popover.
// In each of the relationships formed above, the parent popover must be
// strictly lower in the popover stack than the child popover, or it does not
// form a valid ancestral relationship. This eliminates non-showing popovers and
// self-pointers (e.g. a popover with an anchor attribute that points back to
// the same popover), and it allows for the construction of a well-formed tree
// from the (possibly cyclic) graph of connections. For example, if two popovers
// have anchors pointing to each other, the only valid relationship is that the
// first one to open is the "parent" and the second is the "child".
// Additionally, a `popover=hint` cannot be the ancestor of a `popover=auto`.
const HTMLElement* HTMLElement::FindTopmostPopoverAncestor(
    Element& new_popover_or_top_layer_element,
    HTMLDocument::PopoverStack& stack_to_check,
    Element* new_popovers_invoker,
    TopLayerElementType top_layer_element_type) {
  bool is_popover = top_layer_element_type == TopLayerElementType::kPopover;
  HTMLElement* new_popover =
      is_popover ? DynamicTo<HTMLElement>(new_popover_or_top_layer_element)
                 : nullptr;
  if (is_popover) {
    CHECK(new_popover);
    CHECK(new_popover->HasPopoverAttribute());
    CHECK_NE(new_popover->PopoverType(), PopoverValueType::kManual);
    CHECK(!new_popover->popoverOpen());
  } else {
    CHECK(!new_popover);
    CHECK(!new_popovers_invoker);
  }

  // Build a map from each open popover to its position in the stack.
  HeapHashMap<Member<const HTMLElement>, int> popover_positions;
  int indx = 0;
  for (auto popover : stack_to_check) {
    popover_positions.Set(popover, indx++);
  }
  if (is_popover) {
    popover_positions.Set(new_popover, indx++);
  }

  const HTMLElement* topmost_popover_ancestor = nullptr;
  auto check_ancestor = [new_popover, &topmost_popover_ancestor,
                         &popover_positions](const Element* to_check) {
    const HTMLElement* candidate_ancestor;
    bool ok_nesting = false;
    while (!ok_nesting) {
      candidate_ancestor = NearestOpenPopover(to_check);
      if (!candidate_ancestor ||
          !popover_positions.Contains(candidate_ancestor)) {
        return;
      }
      CHECK_NE(candidate_ancestor->PopoverType(), PopoverValueType::kManual);
      CHECK_NE(candidate_ancestor->PopoverType(), PopoverValueType::kNone);
      ok_nesting = !new_popover ||
                   new_popover->PopoverType() == PopoverValueType::kHint ||
                   candidate_ancestor->PopoverType() == PopoverValueType::kAuto;
      if (!ok_nesting) {
        to_check = FlatTreeTraversal::ParentElement(*candidate_ancestor);
      }
    }
    int candidate_position = popover_positions.at(candidate_ancestor);
    if (!topmost_popover_ancestor ||
        popover_positions.at(topmost_popover_ancestor) < candidate_position) {
      topmost_popover_ancestor = candidate_ancestor;
    }
  };
  // Add the three types of ancestor relationships to the map:
  // 1. DOM tree ancestor.
  check_ancestor(
      FlatTreeTraversal::ParentElement(new_popover_or_top_layer_element));
  // 2. Anchor attribute.
  check_ancestor(new_popover_or_top_layer_element.anchorElement());
  // 3. Invoker to popover
  check_ancestor(new_popovers_invoker);
  return topmost_popover_ancestor;
}

// static
const HTMLElement* HTMLElement::TopLayerElementPopoverAncestor(
    Element& top_layer_element,
    TopLayerElementType top_layer_element_type) {
  CHECK(top_layer_element_type != TopLayerElementType::kPopover);
  Document& document = top_layer_element.GetDocument();
  // Check the hint stack first.
  if (auto* ancestor = FindTopmostPopoverAncestor(
          top_layer_element, document.PopoverHintStack(), nullptr,
          top_layer_element_type)) {
    return ancestor;
  }
  // Then the auto stack.
  return FindTopmostPopoverAncestor(top_layer_element,
                                    document.PopoverAutoStack(), nullptr,
                                    top_layer_element_type);
}

namespace {
// For light dismiss, we need to find the closest popover that the user has
// clicked. For hover triggering, we need to find the closest popover that is
// related to a hovered node. In both cases, this is the nearest DOM ancestor
// that is either a popover or the invoking element for a popover. It is
// possible both exist, in which case the topmost one (highest on the popover
// stack) is returned.
const HTMLElement* FindTopmostRelatedPopover(
    const Node& node,
    const PopoverAncestorOptionsSet& ancestor_options =
        PopoverAncestorOptionsSet()) {
  auto& document = node.GetDocument();
  // Check if we're in an invoking element or a popover, and choose
  // the higher popover on the stack.
  auto* direct_popover_ancestor = NearestOpenPopover(&node, ancestor_options);
  auto* invoker_popover_ancestor =
      NearestTargetPopoverForInvoker(&node, ancestor_options);
  auto get_stack_position = [&document](const HTMLElement* popover) {
    auto& auto_stack = document.PopoverAutoStack();
    auto& hint_stack = document.PopoverHintStack();
    auto pos = hint_stack.Find(popover);
    if (pos != kNotFound) {
      return pos + auto_stack.size() + 1;
    }
    pos = auto_stack.Find(popover);
    return pos == kNotFound ? 0 : (pos + 1);
  };
  if (!invoker_popover_ancestor ||
      get_stack_position(direct_popover_ancestor) >
          get_stack_position(invoker_popover_ancestor)) {
    return direct_popover_ancestor;
  }
  return invoker_popover_ancestor;
}
}  // namespace

// static
void HTMLElement::HandlePopoverLightDismiss(const Event& event,
                                            const Node& target_node) {
  CHECK(event.isTrusted());
  auto& document = target_node.GetDocument();
  if (!document.TopmostPopoverOrHint()) {
    return;
  }

  if (!IsA<PointerEvent>(event)) {
    return;
  }

  // PointerEventManager will call this function before actually dispatching
  // the event.
  CHECK(!event.HasEventPath());
  CHECK_EQ(Event::PhaseType::kNone, event.eventPhase());

  const AtomicString& event_type = event.type();
  if (event_type == event_type_names::kPointerdown) {
    document.SetPopoverPointerdownTarget(
        FindTopmostRelatedPopover(target_node));
  } else if (event_type == event_type_names::kPointerup) {
    // Hide everything up to the clicked element. We do this on pointerup,
    // rather than pointerdown or click, primarily for accessibility concerns.
    // See
    // https://www.w3.org/WAI/WCAG21/Understanding/pointer-cancellation.html
    // for more information on why it is better to perform potentially
    // destructive actions (including hiding a popover) on pointer-up rather
    // than pointer-down. To properly handle the use case where a user starts
    // a pointer-drag on a popover, and finishes off the popover (to highlight
    // text), the ancestral popover is stored in pointerdown and compared
    // here.
    auto* ancestor_popover = FindTopmostRelatedPopover(target_node);
    bool same_target = ancestor_popover == document.PopoverPointerdownTarget();
    document.SetPopoverPointerdownTarget(nullptr);
    if (same_target) {
      HideAllPopoversUntil(
          ancestor_popover, document, HidePopoverFocusBehavior::kNone,
          HidePopoverTransitionBehavior::kFireEventsAndWaitForTransitions);
    }
  }
}

void HTMLElement::InvokePopover(Element& invoker) {
  CHECK(HasPopoverAttribute());
  ShowPopoverInternal(&invoker, /*exception_state=*/nullptr);
}

// Must be called on an Element that is a popover. Returns true if |node| is a
// descendant of this popover. This includes the case where |node| is contained
// within another popover, and the container popover is a descendant of this
// popover. This also includes "indirect" relationships that the popover API
// provides, such as through invoking elements or via the anchor attribute.
// Note that in the special case of popover=manual popovers, which do not
// usually have ancestral relationships, this function *will* check for invoker
// and anchor relationships to form descendant edges. This is important for the
// `popover-hide-
"""


```