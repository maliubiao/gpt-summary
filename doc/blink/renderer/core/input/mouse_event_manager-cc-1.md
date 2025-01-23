Response:
Let's break down the thought process for analyzing this code snippet of `mouse_event_manager.cc`.

1. **Understand the Core Purpose:** The filename `mouse_event_manager.cc` immediately tells us this code is responsible for handling mouse events within the Blink rendering engine. The context (`blink/renderer/core/input`) further clarifies that it deals with the core input processing.

2. **Identify Key Functions:**  Start by skimming the code and noting the names of the prominent functions. This gives a high-level overview of the responsibilities. In this snippet, the important functions are:
    * `HandleMouseDraggedEvent`
    * `HandleDrag`
    * `TryStartDrag`
    * `DispatchDragSrcEvent`
    * `DispatchDragEvent`
    * `ClearDragDataTransfer`
    * `DragSourceEndedAt`
    * `ResetDragSource`
    * `DragThresholdExceeded`
    * `ClearDragHeuristicState`
    * `HandleSvgPanIfNeeded`
    * `InvalidateClick`
    * Accessors like `MousePressed`, `MousePressNode`, etc.

3. **Group Functions by Functionality:**  Once the key functions are identified, try to group them based on their related actions. This helps to organize the analysis. Here, clear groupings emerge:
    * **Drag and Drop:**  `HandleDrag`, `TryStartDrag`, `DispatchDragSrcEvent`, `DispatchDragEvent`, `ClearDragDataTransfer`, `DragSourceEndedAt`, `ResetDragSource`, `DragThresholdExceeded`, `ClearDragHeuristicState`.
    * **Selection (Indirectly):** `HandleMouseDraggedEvent` interacts with `SelectionController`.
    * **Focus:** `FocusDocumentView`.
    * **SVG Pan:** `HandleSvgPanIfNeeded`.
    * **Click Handling:** `InvalidateClick`, `SetClickCount`.
    * **State Management:** Accessors like `MousePressed`, `MousePressNode`, `MouseDownMayStartDrag`.

4. **Analyze Individual Function Logic:**  For each function, carefully read the code and understand its purpose, inputs, and outputs. Look for:
    * **Conditions and Checks:**  `if` statements, `DCHECK` calls, etc., reveal the logic flow and preconditions. For example, the checks for button presses and `mouse_pressed_` in `HandleMouseDraggedEvent`.
    * **Function Calls:**  What other Blink components are being called?  This highlights the interactions. For example, calls to `frame_->GetEventHandler().GetSelectionController()`, `frame_->GetPage()->GetDragController()`, `frame_->View()`, and `target_node->DispatchEvent()`.
    * **State Updates:** How does the function modify the state of the `MouseEventManager` or other objects?  Note the updates to `mouse_down_may_start_drag_`, `mouse_down_pos_`, `GetDragState()`.

5. **Connect to Web Standards (HTML, CSS, JavaScript):** Think about how the actions performed by these functions relate to web browser behavior.
    * **Drag and Drop:**  This directly corresponds to the HTML Drag and Drop API. Note the events like `dragstart`, `dragend`.
    * **Selection:** Mouse dragging is a primary way to select text and other content.
    * **Focus:** Clicking often focuses elements.
    * **SVG Pan:**  This relates to user interaction with SVG images.
    * **Mouse Events:**  The entire purpose is to handle `mousemove`, `mousedown`, `mouseup`, etc., which are fundamental DOM events in JavaScript.

6. **Consider User Interactions and Errors:**  How does a user's mouse movements lead to this code being executed? What common mistakes might developers make that relate to this code?
    * **User Actions:**  Clicking, dragging, moving the mouse are the obvious triggers.
    * **Developer Errors:**  Incorrectly handling drag events in JavaScript, relying on specific event ordering, not preventing default drag behavior when necessary.

7. **Trace the Execution Path (Debugging):** Imagine a simple scenario (e.g., a user dragging text). Mentally trace the execution flow through the functions. This helps understand the sequence of operations.

8. **Focus on the "Part 2" Request:** The prompt specifically asks for a *summary* of the functionality of *this particular part* of the code. This means focusing on the functions present in *this* snippet, even if the overall file has other responsibilities.

9. **Refine and Organize the Output:** Structure the analysis clearly using headings, bullet points, and examples. Explain the connections to web technologies and user interactions. Provide concrete examples for assumptions, potential errors, and debugging.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just handles mouse clicks."  **Correction:**  Realize that a significant portion is dedicated to drag and drop, not just simple clicks.
* **Focusing too narrowly:** Initially, I might focus only on the code details. **Correction:**  Step back and consider the broader context of web browser behavior and the purpose of these actions within a rendering engine.
* **Overlooking connections:**  Might miss the link between `HandleMouseDraggedEvent` and text selection. **Correction:**  Pay attention to calls to `SelectionController`.
* **Not being specific enough:**  Instead of saying "handles dragging," specify *which* drag events and the purpose of each.

By following these steps, iterating, and refining the analysis, we can arrive at a comprehensive and accurate description of the provided code snippet's functionality.
这是目录为blink/renderer/core/input/mouse_event_manager.cc的chromium blink引擎源代码文件的第二部分，主要负责处理鼠标拖拽相关的事件和逻辑。

**归纳其主要功能如下:**

1. **处理鼠标拖拽事件 (`HandleMouseDraggedEvent`)**:
    - 检查是否满足拖拽的条件 (左键按下或特定笔按钮按下)。
    - 如果不满足拖拽条件，则直接返回，不进行任何拖拽处理。
    - 如果是按下 Esc 键同时拖拽，且鼠标移出元素，也会直接返回。
    - 在 Windows 上禁用 Pen 的拖拽。
    - 调用 `HandleDrag` 函数来实际处理拖拽逻辑。
    - 如果 `HandleDrag` 没有处理拖拽，则尝试进行文本选择操作。
    - 如果可能，启动自动滚动功能 (autoscroll)，特别是针对文本选择后的拖拽。

2. **处理拖拽的通用逻辑 (`HandleDrag`)**:
    - 负责判断是否应该开始拖拽操作。
    - 在 `mouse_down_may_start_drag_` 为 true 的情况下，会进行命中测试，判断鼠标按下时的元素是否可拖拽。
    - 如果没有找到可拖拽的元素，则重置拖拽源。
    - 如果拖拽阈值未达到，则取消拖拽，但仍然返回 `true`，阻止后续默认处理（如文本选择）。
    - 调用 `TryStartDrag` 尝试启动拖拽。
    - 如果成功启动拖拽，则取消可能发生的点击事件，并发送 `pointercancel` 事件。
    - 返回 `true` 表示拖拽相关处理已经完成，不再进行默认处理。

3. **尝试启动拖拽 (`TryStartDrag`)**:
    - 清空之前的拖拽数据 (`ClearDragDataTransfer`)。
    - 创建新的拖拽数据传输对象 (`DataTransfer`)。
    - 调用 `DragController` 来填充拖拽数据。
    - 触发 `dragstart` 事件。如果事件被取消，则返回 `false`。
    - 检查拖拽操作是否可以在当前状态下继续 (例如，`dragSrc` 是否仍然存在)。
    - 如果是在密码字段上进行文本选择拖拽，则取消拖拽。
    - 设置剪贴板访问策略为受保护。
    - 调用 `DragController::StartDrag` 真正启动拖拽。
    - 如果 `StartDrag` 失败，则触发 `dragend` 事件。

4. **分发拖拽源事件 (`DispatchDragSrcEvent`)**:
    - 用于分发 `dragstart`、`dragend` 等发生在拖拽源元素的事件。
    - 调用 `DispatchDragEvent` 来执行实际的分发。

5. **分发拖拽事件 (`DispatchDragEvent`)**:
    - 创建并分发 `DragEvent` 对象到目标节点。
    - 设置事件的各种属性，例如是否冒泡、是否可取消、坐标、相关目标、数据传输对象等。

6. **清除拖拽数据传输对象 (`ClearDragDataTransfer`)**:
    - 清除拖拽图片。
    - 设置数据传输对象的访问策略为 `kNumb`，表示不可用。

7. **拖拽源结束 (`DragSourceEndedAt`)**:
    - 在拖拽操作结束后被调用。
    - 设置拖拽的目标操作类型。
    - 触发 `dragend` 事件。
    - 清除拖拽数据和重置拖拽源。
    - 防止因按下 Esc 键结束拖拽后，后续的鼠标移动事件再次触发拖拽。

8. **获取拖拽状态 (`GetDragState`)**:
    - 返回全局的拖拽状态对象。

9. **重置拖拽源 (`ResetDragSource`)**:
    - 清除当前的拖拽源节点。
    - 只有当请求重置的 frame 在拖拽源节点的 frame 的上层时才允许重置。

10. **判断是否超过拖拽阈值 (`DragThresholdExceeded`)**:
    - 判断鼠标移动的距离是否超过了预设的拖拽阈值。

11. **清除拖拽启发式状态 (`ClearDragHeuristicState`)**:
    - 用于防止在鼠标再次按下之前，`mousemove` 事件触发拖拽。

12. **处理 SVG 平移 (`HandleSvgPanIfNeeded`)**:
    - 如果启用了 SVG 平移，则更新平移状态。

13. **取消点击 (`InvalidateClick`)**:
    - 重置点击计数和按下鼠标的元素。

14. **获取和设置鼠标状态**:
    - 提供了一些方法来获取和设置鼠标的按下状态、按下的节点、点击计数等。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

- **JavaScript:**
    - 这些 C++ 代码最终会触发 JavaScript 中的拖拽事件，例如 `dragstart`, `drag`, `dragend`, `dragenter`, `dragleave`, `dragover`, `drop`。
    - 例如，当用户开始拖拽一个图片时，`TryStartDrag` 函数会触发 JavaScript 的 `dragstart` 事件，开发者可以在 JavaScript 中监听这个事件并自定义拖拽行为。
    - `DispatchDragEvent` 函数负责创建 `DragEvent` 对象，这个对象会被传递到 JavaScript 事件处理函数中。

- **HTML:**
    - HTML 元素通过设置 `draggable="true"` 属性可以变为可拖拽。
    - 例如，`<div draggable="true">可以拖拽的元素</div>`，当用户尝试拖动这个 `div` 元素时，`MouseEventManager` 中的相关逻辑会被触发。
    - 拖拽过程中，鼠标悬停的目标元素会触发 `dragenter` 和 `dragover` 事件，这些事件也由 Blink 的事件处理机制传递到 JavaScript。

- **CSS:**
    - CSS 可以影响拖拽的外观，例如通过 `cursor` 属性设置拖拽时的鼠标样式。
    - 开发者可以使用 CSS 来样式化被拖拽的元素或拖拽的目标区域。

**逻辑推理的假设输入与输出:**

**假设输入:** 用户在浏览器中点击并按住鼠标左键，然后移动鼠标，试图拖拽一个标记为 `draggable="true"` 的图片元素。

**输出 (在该代码片段的范围内):**

1. **`HandleMouseDraggedEvent`**: 接收到鼠标移动事件，判断是左键拖拽，且满足其他拖拽条件。
2. **`HandleDrag`**:
   - 如果是第一次移动，且移动距离小于拖拽阈值，则可能不会立即启动拖拽，但会记录状态。
   - 当移动距离超过阈值后，`mouse_down_may_start_drag_` 为 true，进行命中测试找到被拖拽的图片元素。
   - 调用 `TryStartDrag`。
3. **`TryStartDrag`**:
   - 创建 `DataTransfer` 对象。
   - `DragController` 可能会根据图片元素的内容填充 `DataTransfer` 的数据（例如图片的 URL）。
   - 触发 JavaScript 的 `dragstart` 事件。
   - 如果 `dragstart` 没有被取消，调用 `DragController::StartDrag` 启动浏览器的原生拖拽。

**涉及用户或编程常见的使用错误及举例说明:**

1. **用户错误:**
    - **过快的拖拽:** 用户可能快速点击和移动鼠标，导致一些中间状态没有正确更新，尽管 Blink 的事件处理会尽力捕捉。
    - **在不应该拖拽的地方拖拽:** 用户可能尝试拖拽没有设置 `draggable="true"` 的元素，此时拖拽操作不会启动。

2. **编程错误:**
    - **`dragstart` 事件处理不当:** JavaScript 开发者可能在 `dragstart` 事件处理函数中执行了耗时的操作，导致拖拽卡顿或失败。
    ```javascript
    document.addEventListener('dragstart', (event) => {
      // 错误示例：执行耗时操作
      for (let i = 0; i < 1000000000; i++) {
        // ...
      }
    });
    ```
    - **忘记在 `dragover` 中调用 `preventDefault()`:** 如果开发者希望元素成为拖放的目标，必须在 `dragover` 事件处理函数中调用 `preventDefault()`，否则 `drop` 事件不会触发。
    ```javascript
    document.addEventListener('dragover', (event) => {
      // 正确的做法是调用 preventDefault()
      event.preventDefault();
    });
    ```
    - **错误地操作 `DataTransfer` 对象:** 在 `dragstart` 事件中设置了错误的数据类型或格式，导致拖放到目标时无法正确处理。

**用户操作是如何一步步到达这里的，作为调试线索:**

1. **用户操作:** 用户将鼠标光标移动到一个可拖拽的元素上。
2. **用户操作:** 用户按下鼠标左键 (`mousedown` 事件)。`MouseEventManager` 会记录鼠标按下的位置和时间，并设置 `mouse_down_may_start_drag_ = true;`。
3. **用户操作:** 用户按住鼠标左键并移动鼠标 (`mousemove` 事件连续触发)。
4. **Blink 处理:** 每次 `mousemove` 事件到达 `MouseEventManager` 时，`HandleMouseDraggedEvent` 会被调用。
5. **逻辑判断:** `HandleMouseDraggedEvent` 检查鼠标左键是否按下，以及移动的距离是否超过拖拽阈值 (`DragThresholdExceeded`)。
6. **启动拖拽:** 如果满足拖拽条件，`HandleDrag` 会被调用，并尝试通过 `TryStartDrag` 启动拖拽。
7. **事件分发:** `TryStartDrag` 内部会调用 `DispatchDragSrcEvent` 来触发 JavaScript 的 `dragstart` 事件。

**调试线索:**

- **检查鼠标事件是否被正确捕获:** 使用浏览器的开发者工具的 "Event Listeners" 面板，查看目标元素是否绑定了预期的鼠标事件监听器。
- **断点调试 C++ 代码:** 在 `HandleMouseDraggedEvent`、`HandleDrag` 和 `TryStartDrag` 等关键函数设置断点，观察代码的执行流程和变量的值，例如 `mouse_down_may_start_drag_`、拖拽阈值、`GetDragState()` 的内容等。
- **查看 JavaScript 控制台输出:** 在 JavaScript 的拖拽事件处理函数中添加 `console.log` 输出，查看事件对象的数据和触发顺序。
- **使用 Chrome 的 `about:tracing`:** 可以记录 Blink 内部的事件和函数调用，更详细地分析鼠标事件的处理过程。
- **检查 `draggable` 属性:** 确认被拖拽的 HTML 元素是否正确设置了 `draggable="true"` 属性。
- **检查 CSS 样式:** 某些 CSS 样式可能会干扰拖拽行为，例如 `pointer-events: none;`。

总而言之，这个代码片段是 Chromium Blink 引擎中处理鼠标拖拽的核心部分，它连接了底层的鼠标事件和上层的 JavaScript 拖拽 API，负责判断何时启动拖拽、收集拖拽数据、以及触发相应的事件。理解这部分代码的功能对于调试与拖拽相关的 bug 以及深入理解浏览器的工作原理至关重要。

### 提示词
```
这是目录为blink/renderer/core/input/mouse_event_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
WebInputEvent::Modifiers::kIsCompatibilityEventForTouch,
      base::TimeTicks::Now());
  HitTestRequest request(HitTestRequest::kReadOnly);
  MouseEventWithHitTestResults mev =
      event_handling_util::PerformMouseEventHitTest(frame_, request,
                                                    mouse_drag_event);
  mouse_down_may_start_drag_ = true;
  ResetDragSource();
  mouse_down_pos_ = frame_->View()->ConvertFromRootFrame(
      gfx::ToFlooredPoint(mouse_drag_event.PositionInRootFrame()));
  return HandleDrag(mev, DragInitiator::kTouch);
}

void MouseEventManager::FocusDocumentView() {
  Page* page = frame_->GetPage();
  if (!page)
    return;
  page->GetFocusController().FocusDocumentView(frame_);
}

WebInputEventResult MouseEventManager::HandleMouseDraggedEvent(
    const MouseEventWithHitTestResults& event) {
  TRACE_EVENT0("blink", "MouseEventManager::handleMouseDraggedEvent");

  bool is_pen = event.Event().pointer_type ==
                blink::WebPointerProperties::PointerType::kPen;

  WebPointerProperties::Button pen_drag_button =
      WebPointerProperties::Button::kLeft;
  if (frame_->GetSettings() &&
      frame_->GetSettings()->GetBarrelButtonForDragEnabled())
    pen_drag_button = WebPointerProperties::Button::kBarrel;

  // Only handles dragging for mouse left button drag and pen drag button.
  if ((!is_pen &&
       event.Event().button != WebPointerProperties::Button::kLeft) ||
      (is_pen && event.Event().button != pen_drag_button)) {
    mouse_down_may_start_drag_ = false;
    return WebInputEventResult::kNotHandled;
  }

  //  When pressing Esc key while dragging and the object is outside of the
  //  we get a mouse leave event here.
  if (!mouse_pressed_ ||
      event.Event().GetType() == WebInputEvent::Type::kMouseLeave)
    return WebInputEventResult::kNotHandled;

  // We disable the drag and drop actions on pen input on windows.
  bool should_handle_drag = true;
#if BUILDFLAG(IS_WIN)
  should_handle_drag = !is_pen;
#endif

  if (should_handle_drag && HandleDrag(event, DragInitiator::kMouse)) {
    // `HandleDrag()` returns true for both kHandledApplication and
    // kHandledSystem.  We are returning kHandledApplication here to make the
    // UseCounter in the caller work.
    return WebInputEventResult::kHandledApplication;
  }

  Node* target_node = event.InnerNode();
  if (!target_node)
    return WebInputEventResult::kNotHandled;

  LayoutObject* layout_object = target_node->GetLayoutObject();
  if (!layout_object) {
    Node* parent = FlatTreeTraversal::Parent(*target_node);
    if (!parent)
      return WebInputEventResult::kNotHandled;

    layout_object = parent->GetLayoutObject();
    if (!layout_object || !layout_object->IsListBox()) {
      return WebInputEventResult::kNotHandled;
    }
  }

  // |SelectionController| calls |PositionForPoint()| which requires
  // |kPrePaintClean|.
  if (LocalFrameView* frame_view = frame_->View()) {
    frame_view->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kInput);
  }

  mouse_down_may_start_drag_ = false;

  WebInputEventResult selection_controller_drag_result =
      frame_->GetEventHandler()
          .GetSelectionController()
          .HandleMouseDraggedEvent(event, mouse_down_pos_,
                                   last_known_mouse_position_in_root_frame_);

  // The call into HandleMouseDraggedEvent may have caused a re-layout,
  // so get the LayoutObject again.
  layout_object = target_node->GetLayoutObject();

  if (layout_object && mouse_down_may_start_autoscroll_ &&
      !scroll_manager_->MiddleClickAutoscrollInProgress() &&
      !frame_->Selection().SelectedHTMLForClipboard().empty()) {
    if (AutoscrollController* controller =
            scroll_manager_->GetAutoscrollController()) {
      // Avoid updating the lifecycle unless it's possible to autoscroll.
      layout_object->GetFrameView()->UpdateAllLifecyclePhasesExceptPaint(
          DocumentUpdateReason::kScroll);

      // The lifecycle update above may have invalidated the previous layout.
      layout_object = target_node->GetLayoutObject();
      if (layout_object) {
        controller->StartAutoscrollForSelection(layout_object);
        mouse_down_may_start_autoscroll_ = false;
      }
    }
  }

  return selection_controller_drag_result;
}

// TODO(mustaq@chromium.org): The return value here is questionable.  Why even a
// failing `TryStartDrag()` below returns a `true` here?
bool MouseEventManager::HandleDrag(const MouseEventWithHitTestResults& event,
                                   DragInitiator initiator) {
  DCHECK(event.Event().GetType() == WebInputEvent::Type::kMouseMove);
  // Callers must protect the reference to LocalFrameView, since this function
  // may dispatch DOM events, causing page/LocalFrameView to go away.
  DCHECK(frame_);
  DCHECK(frame_->View());
  if (!frame_->GetPage())
    return false;

  if (mouse_down_may_start_drag_) {
    HitTestRequest request(HitTestRequest::kReadOnly);
    HitTestLocation location(mouse_down_pos_);
    HitTestResult result(request, location);
    frame_->ContentLayoutObject()->HitTest(location, result);
    Node* node = result.InnerNode();
    if (node) {
      DragController::SelectionDragPolicy selection_drag_policy =
          event.Event().TimeStamp() - mouse_down_timestamp_ < kTextDragDelay
              ? DragController::kDelayedSelectionDragResolution
              : DragController::kImmediateSelectionDragResolution;
      GetDragState().drag_src_ =
          frame_->GetPage()->GetDragController().DraggableNode(
              frame_, node, mouse_down_pos_, selection_drag_policy,
              GetDragState().drag_type_);
    } else {
      ResetDragSource();
    }

    if (!GetDragState().drag_src_)
      mouse_down_may_start_drag_ = false;  // no element is draggable
  }

  if (!mouse_down_may_start_drag_) {
    return initiator == DragInitiator::kMouse &&
           !frame_->GetEventHandler()
                .GetSelectionController()
                .MouseDownMayStartSelect() &&
           !mouse_down_may_start_autoscroll_;
  }

  if (initiator == DragInitiator::kMouse &&
      !DragThresholdExceeded(
          gfx::ToFlooredPoint(event.Event().PositionInRootFrame()))) {
    ResetDragSource();
    return true;
  }

  if (!TryStartDrag(event)) {
    // Something failed to start the drag, clean up.
    ClearDragDataTransfer();
    ResetDragSource();
  } else {
    // Once we're past the drag threshold, we don't want to treat this gesture
    // as a click.
    InvalidateClick();

    // Since drag operation started we need to send a pointercancel for the
    // corresponding pointer.
    if (initiator == DragInitiator::kMouse) {
      frame_->GetEventHandler().HandlePointerEvent(
          WebPointerEvent::CreatePointerCausesUaActionEvent(
              WebPointerProperties::PointerType::kMouse,
              event.Event().TimeStamp()),
          Vector<WebPointerEvent>(), Vector<WebPointerEvent>());
    }
  }

  mouse_down_may_start_drag_ = false;
  // Whether or not the drag actually started, no more default handling (like
  // selection).
  return true;
}

DataTransfer* MouseEventManager::CreateDraggingDataTransfer() const {
  return DataTransfer::Create(DataTransfer::kDragAndDrop,
                              DataTransferAccessPolicy::kWritable,
                              DataObject::Create());
}

bool MouseEventManager::TryStartDrag(
    const MouseEventWithHitTestResults& event) {
  // The DataTransfer would only be non-empty if we missed a dragEnd.
  // Clear it anyway, just to make sure it gets numbified.
  ClearDragDataTransfer();

  GetDragState().drag_data_transfer_ = CreateDraggingDataTransfer();

  DragController& drag_controller = frame_->GetPage()->GetDragController();
  if (!drag_controller.PopulateDragDataTransfer(frame_, GetDragState(),
                                                mouse_down_pos_)) {
    return false;
  }

  if (DispatchDragSrcEvent(event_type_names::kDragstart, mouse_down_) !=
      WebInputEventResult::kNotHandled) {
    return false;
  }

  // Dispatching the event could cause |frame_| to be detached.
  if (!frame_->GetPage())
    return false;

  // If dispatching dragstart brings about another mouse down -- one way
  // this will happen is if a DevTools user breaks within a dragstart
  // handler and then clicks on the suspended page -- the drag state is
  // reset. Hence, need to check if this particular drag operation can
  // continue even if dispatchEvent() indicates no (direct) cancellation.
  // Do that by checking if m_dragSrc is still set.
  if (!GetDragState().drag_src_)
    return false;

  // Do not start dragging in password field.
  // TODO(editing-dev): The use of
  // updateStyleAndLayoutIgnorePendingStylesheets needs to be audited.  See
  // http://crbug.com/590369 for more details.
  frame_->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kInput);
  if (GetDragState().drag_type_ == kDragSourceActionSelection &&
      IsInPasswordField(
          frame_->Selection().ComputeVisibleSelectionInDOMTree().Start())) {
    return false;
  }

  // Set the clipboard access policy to protected
  // (https://html.spec.whatwg.org/multipage/dnd.html#concept-dnd-p) to
  // prevent changes in the clipboard after dragstart event has been fired:
  // https://html.spec.whatwg.org/multipage/dnd.html#dndevents
  // According to
  // https://html.spec.whatwg.org/multipage/dnd.html#dom-datatransfer-setdragimage,
  // drag image is only allowed to be changed during dragstart event.
  GetDragState().drag_data_transfer_->SetAccessPolicy(
      DataTransferAccessPolicy::kTypesReadable);

  if (drag_controller.StartDrag(frame_, GetDragState(), event.Event(),
                                mouse_down_pos_)) {
    return true;
  }

  // Drag was canned at the last minute - we owe m_dragSrc a DRAGEND event
  DispatchDragSrcEvent(event_type_names::kDragend, event.Event());

  return false;
}

// Returns if we should continue "default processing", i.e., whether
// eventhandler canceled.
WebInputEventResult MouseEventManager::DispatchDragSrcEvent(
    const AtomicString& event_type,
    const WebMouseEvent& event) {
  CHECK(event_type == event_type_names::kDrag ||
        event_type == event_type_names::kDragend ||
        event_type == event_type_names::kDragstart);

  return DispatchDragEvent(event_type, GetDragState().drag_src_.Get(), nullptr,
                           event, GetDragState().drag_data_transfer_.Get());
}

WebInputEventResult MouseEventManager::DispatchDragEvent(
    const AtomicString& event_type,
    Node* drag_target,
    Node* related_target,
    const WebMouseEvent& event,
    DataTransfer* data_transfer) {
  LocalFrameView* view = frame_->View();
  // FIXME: We might want to dispatch a dragleave even if the view is gone.
  if (!view)
    return WebInputEventResult::kNotHandled;

  // We should be setting relatedTarget correctly following the spec:
  // https://html.spec.whatwg.org/C/#dragevent
  // At the same time this should prevent exposing a node from another document.
  if (related_target &&
      related_target->GetDocument() != drag_target->GetDocument())
    related_target = nullptr;

  DragEventInit* initializer = DragEventInit::Create();
  initializer->setBubbles(true);
  initializer->setCancelable(event_type != event_type_names::kDragleave &&
                             event_type != event_type_names::kDragend);
  MouseEvent::SetCoordinatesFromWebPointerProperties(
      event.FlattenTransform(), frame_->GetDocument()->domWindow(),
      initializer);
  initializer->setButton(0);
  initializer->setButtons(
      MouseEvent::WebInputEventModifiersToButtons(event.GetModifiers()));
  initializer->setRelatedTarget(related_target);
  initializer->setView(frame_->GetDocument()->domWindow());
  initializer->setComposed(true);
  initializer->setGetDataTransfer(data_transfer);
  initializer->setSourceCapabilities(
      frame_->GetDocument()->domWindow()
          ? frame_->GetDocument()
                ->domWindow()
                ->GetInputDeviceCapabilities()
                ->FiresTouchEvents(event.FromTouch())
          : nullptr);
  UIEventWithKeyState::SetFromWebInputEventModifiers(
      initializer, static_cast<WebInputEvent::Modifiers>(event.GetModifiers()));

  DragEvent* me = DragEvent::Create(event_type, initializer, event.TimeStamp(),
                                    event.FromTouch()
                                        ? MouseEvent::kFromTouch
                                        : MouseEvent::kRealOrIndistinguishable);

  return event_handling_util::ToWebInputEventResult(
      drag_target->DispatchEvent(*me));
}

void MouseEventManager::ClearDragDataTransfer() {
  if (!frame_->GetPage())
    return;
  if (GetDragState().drag_data_transfer_) {
    GetDragState().drag_data_transfer_->ClearDragImage();
    GetDragState().drag_data_transfer_->SetAccessPolicy(
        DataTransferAccessPolicy::kNumb);
  }
}

void MouseEventManager::DragSourceEndedAt(
    const WebMouseEvent& event,
    ui::mojom::blink::DragOperation operation) {
  if (GetDragState().drag_src_) {
    GetDragState().drag_data_transfer_->SetDestinationOperation(operation);
    // The return value is ignored because dragend is not cancelable.
    DispatchDragSrcEvent(event_type_names::kDragend, event);
  }
  ClearDragDataTransfer();
  ResetDragSource();
  // In case the drag was ended due to an escape key press we need to ensure
  // that consecutive mousemove events don't reinitiate the drag and drop.
  mouse_down_may_start_drag_ = false;
}

DragState& MouseEventManager::GetDragState() {
  DCHECK(frame_->GetPage());
  return frame_->GetPage()->GetDragController().GetDragState();
}

void MouseEventManager::ResetDragSource() {
  // Check validity of drag source.
  if (!frame_->GetPage())
    return;

  Node* drag_src = GetDragState().drag_src_;
  if (!drag_src)
    return;

  Frame* drag_src_frame = drag_src->GetDocument().GetFrame();
  if (!drag_src_frame) {
    // The frame containing the drag_src has been navigated away, so the
    // drag_src is no longer has an owning frame and is invalid.
    // See https://crbug.com/903705 for more details.
    GetDragState().drag_src_ = nullptr;
    return;
  }

  // Only allow resetting drag_src_ if the frame requesting reset is above the
  // drag_src_ node's frame in the frame hierarchy. This way, unrelated frames
  // can't reset a drag state.
  if (!drag_src_frame->Tree().IsDescendantOf(frame_))
    return;

  GetDragState().drag_src_ = nullptr;
}

bool MouseEventManager::DragThresholdExceeded(
    const gfx::Point& drag_location_in_root_frame) const {
  LocalFrameView* view = frame_->View();
  if (!view)
    return false;
  gfx::Point drag_location =
      view->ConvertFromRootFrame(drag_location_in_root_frame);
  gfx::Vector2d delta = drag_location - mouse_down_pos_;

  // WebKit's drag thresholds depend on the type of object being dragged. If we
  // want to revive that behavior, we can multiply the threshold constants with
  // a number based on dragState().m_dragType.

  return abs(delta.x()) >= kDragThresholdX || abs(delta.y()) >= kDragThresholdY;
}

void MouseEventManager::ClearDragHeuristicState() {
  // Used to prevent mouseMoveEvent from initiating a drag before
  // the mouse is pressed again.
  mouse_pressed_ = false;
  mouse_down_may_start_drag_ = false;
  mouse_down_may_start_autoscroll_ = false;
}

bool MouseEventManager::HandleSvgPanIfNeeded(bool is_release_event) {
  if (!svg_pan_)
    return false;
  svg_pan_ = !is_release_event;
  frame_->GetDocument()->AccessSVGExtensions().UpdatePan(
      frame_->View()->ViewportToFrame(last_known_mouse_position_));
  return true;
}

void MouseEventManager::InvalidateClick() {
  click_count_ = 0;
  mousedown_element_ = nullptr;
}

bool MouseEventManager::MousePressed() {
  return mouse_pressed_;
}

void MouseEventManager::ReleaseMousePress() {
  mouse_pressed_ = false;
}

Node* MouseEventManager::MousePressNode() {
  return mouse_press_node_.Get();
}

void MouseEventManager::SetMousePressNode(Node* node) {
  mouse_press_node_ = node;
}

void MouseEventManager::SetMouseDownElement(Element* element) {
  // TODO(mustaq): Why is SetDocument() not called earlier at
  // LocalFrame::DidAttachDocument()?  Because this is delayed call, the methods
  // MouseEventManager::WillBeRemoved() are not called until a mouse-press or
  // tap!
  SetDocument(element ? element->ownerDocument() : nullptr);
  mousedown_element_ = element;
}

void MouseEventManager::SetClickCount(int click_count) {
  click_count_ = click_count;
}

bool MouseEventManager::MouseDownMayStartDrag() {
  return mouse_down_may_start_drag_;
}

}  // namespace blink
```