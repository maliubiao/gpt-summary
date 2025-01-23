Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Request:** The core request is to understand the *functionality* of the provided code, particularly its relation to web technologies (HTML, CSS, JavaScript), its internal logic, potential errors, and how a user's action leads to this code being executed. The request also specifies this is the second part of a larger file and asks for a summary.

2. **High-Level Overview (Initial Scan):**  The code deals with drag-and-drop operations. Keywords like `DragController`, `DragState`, `DataTransfer`, `DragImage`, `WebMouseEvent`, and functions like `StartDrag`, `PopulateDragDataTransfer`, `DoSystemDrag` immediately suggest this.

3. **Decomposition by Function:** The most effective way to understand the code is to analyze each function individually. For each function:
    * **Purpose:** What does this function do?  Look at the function name and the actions performed within it.
    * **Inputs:** What are the parameters and their types?
    * **Outputs:** What does the function return? What side effects does it have (e.g., modifying member variables)?
    * **Key Logic:**  Identify the main conditional statements, loops, and operations.
    * **Connections to Web Technologies:**  Does this function interact with DOM elements, CSS properties (like `user-drag`), JavaScript events (like `dragstart`), or data transfer mechanisms?
    * **Potential Issues/Errors:** Are there any obvious edge cases or error conditions handled (or not handled)?
    * **Relationship to User Actions:** How might a user action trigger this function?

4. **Detailed Analysis of Key Functions (Iterative Refinement):**

    * **`UpdateDragAndDrop` section:**  This part focuses on how a potential drop interacts with the target element. It involves checking the allowed drag operations (`src_op_mask`), creating a `WebMouseEvent`, and calling `UpdateDragAndDrop` on the event handler. The return value of `UpdateDragAndDrop` determines the success of the operation and clipboard access. This clearly relates to JavaScript event handling of drag-and-drop.

    * **`SelectTextInsteadOfDrag`:**  This function decides whether a click should initiate text selection or a drag. It checks if the node is text, editable, or within a draggable ancestor. This is directly related to how the browser interprets user interactions based on DOM structure and the `draggable` attribute.

    * **`DraggableNode`:** This is crucial for determining *what* is being dragged. It checks if the drag started on a selection, an image, a link, or a generic draggable element (using the `user-drag` CSS property). This demonstrates how HTML attributes and CSS properties influence drag behavior.

    * **`PrepareDataTransferForImageDrag`:** This function prepares the data transfer object when dragging an image. It handles selection if the image is in an editable area and calls `DeclareAndWriteDragImage`. This is a concrete example of data being prepared for the drag operation, linking to the `DataTransfer` API in JavaScript.

    * **`PopulateDragDataTransfer`:** This function populates the `DataTransfer` object with data based on the type of drag (selection, image, link, DHTML). It uses `WriteURL`, `WriteSelection`, `DeclareAndWriteDragImage`, and `SetDragImageElement`. This directly relates to the `DataTransfer` API and the different data formats that can be dragged.

    * **Helper Functions (e.g., `DragLocationForDHTMLDrag`, `DragRectForSelectionDrag`, `DragImageForImage`, etc.):** These functions handle the visual aspects of dragging, such as positioning and sizing the drag image. They demonstrate how the browser creates a visual representation of the dragged item.

    * **`StartDrag`:** This function is the entry point for initiating a drag. It performs hit testing, determines the drag image and its position, and calls `DoSystemDrag`. This is where the browser starts the underlying system-level drag-and-drop operation.

    * **`DoSystemDrag`:** This function interacts with the browser's chrome (UI) to perform the actual system drag. It uses the `WebDragData` structure to pass information to the browser process.

    * **`GetDragOperation` and `IsCopyKeyDown`:** These handle the drag operation based on modifiers (like Ctrl or Alt).

5. **Identifying Relationships with Web Technologies:** As the analysis progresses, explicitly note the connections to HTML (draggable attribute, anchor elements, image elements), CSS (`user-drag` property), and JavaScript (`DataTransfer` API, drag events). Provide concrete examples where possible.

6. **Logical Inferences and Assumptions:**  Consider what inputs and outputs are likely for specific functions. For example, in `SelectTextInsteadOfDrag`, if the input is a text node within a `<div>` with `draggable="true"`, the output would be `false`.

7. **User and Programming Errors:** Think about common mistakes. For instance, forgetting to set the `draggable` attribute, incorrect use of `preventDefault` in JavaScript drag event handlers, or issues with the types of data added to the `DataTransfer` object.

8. **Tracing User Actions:**  Work backward from the code. How does a user action (like clicking and dragging) lead to this specific code being executed?  Think about the event flow: mouse down, mouse move, `dragstart` event (potentially), and then the browser's internal drag handling.

9. **Summarization:**  Once the individual functions are understood, synthesize the information into a concise summary of the file's overall purpose. Highlight the key responsibilities and interactions with other parts of the browser.

10. **Second Part Specifics:** Pay attention to the "This is part 2" instruction. This implies the previous part likely handled the initial setup and event handling of the drag. This second part focuses more on the ongoing drag operation, data transfer, and visual aspects. The summary should reflect this distinction.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This looks complex."  **Correction:** Break it down function by function.
* **Initial thought:** "How does JavaScript fit in?" **Correction:** Look for interactions with browser APIs like `DataTransfer` and event handling mechanisms.
* **Realization:** Some functions are tightly coupled (e.g., the helper functions for drag image and rect calculations). Group related functions in the explanation.
* **Emphasis:** Highlight the core purpose of the `DragController`: managing the initiation, execution, and data transfer of drag-and-drop operations within the Blink rendering engine.

By following this structured approach, combining code analysis with an understanding of web technologies and user interactions, it's possible to generate a comprehensive and accurate explanation of the given code snippet.
好的，我们来归纳一下 `blink/renderer/core/page/drag_controller.cc` 文件中提供的第二部分代码的功能。

**第二部分代码功能归纳：**

这部分代码主要负责处理正在进行的拖放操作的各种细节，包括：

1. **更新拖放状态和数据传输对象：**
   - `UpdateDragAndDrop`:  处理拖放过程中鼠标移动到潜在的放置目标上时发生的事件。它会创建一个 `WebMouseEvent` 并传递给目标元素的事件处理器 (`UpdateDragAndDrop`)。
   - 根据目标元素的处理结果，决定是否允许放置（通过设置 `DataTransferAccessPolicy`）。
   - 如果目标元素未明确设置 `dropEffect`，则根据源操作掩码 (`src_op_mask`) 设置默认的拖放操作 (`operation`)。
   - 确保选择的拖放操作是被拖动源所支持的。

2. **确定是否应该开始文本选择而不是拖动：**
   - `SelectTextInsteadOfDrag`:  判断在点击时是否应该开始文本选择而不是启动拖动。
   - 它会检查点击的节点是否是文本节点，是否可编辑，以及其祖先元素是否可拖动。
   - 如果点击发生在未选中的可选择文本上，且该文本不可拖动，则返回 `true`，指示应该开始选择文本。

3. **确定可拖动的节点：**
   - `DraggableNode`:  确定用户实际想要拖动的DOM节点。
   - 首先检查拖动是否发生在已选中的文本上。
   - 遍历起始节点的祖先元素，查找带有 `draggable` 属性或特定类型的元素（如图片或链接）。
   - 根据找到的可拖动元素类型设置 `drag_type` (例如 `kDragSourceActionSelection`, `kDragSourceActionImage`, `kDragSourceActionLink`, `kDragSourceActionDHTML`)。
   - 考虑 `selectionDragPolicy`，决定是立即开始拖动选中文本还是查找其他可拖动元素。

4. **填充拖放数据传输对象：**
   - `PopulateDragDataTransfer`:  在拖动开始时，将数据写入 `DataTransfer` 对象，以便目标可以接收。
   - 根据 `drag_type`，写入不同的数据：
     - **选中文本:** 调用 `data_transfer->WriteSelection()`。
     - **图片:** 调用 `PrepareDataTransferForImageDrag`，其中会声明并写入拖动图像的相关信息（图像本身、链接、标签）。
     - **链接:** 调用 `data_transfer->WriteURL()` 写入链接地址和文本内容。
     - **DHTML元素:** 设置拖动图像元素及其偏移量。

5. **辅助函数，用于处理不同类型的拖动：**
   - `PrepareDataTransferForImageDrag`:  专门为图片拖动准备 `DataTransfer` 对象，包括处理富文本编辑的情况。
   - `DragLocationForDHTMLDrag`:  计算 DHTML 元素拖动时的拖动图像位置。
   - `DragRectForSelectionDrag`:  计算选中文本拖动时的拖动矩形。
   - `MaxDragImageSize`:  定义拖动图像的最大尺寸。
   - `CanDragImage`:  检查图片元素是否可以被拖动（例如，确保图片已加载）。
   - `DragImageForImage`:  创建图片拖动时的拖动图像。
   - `DragRectForImage`:  计算图片拖动时的拖动矩形。
   - `DragImageForLink`:  创建链接拖动时的拖动图像。
   - `DragRectForLink`:  计算链接拖动时的拖动矩形。
   - `ClippedSelection`:  裁剪选择区域，使其位于可视视口内。
   - `DragImageForSelection`:  创建选中文本拖动时的拖动图像。
   - `SelectEnclosingAnchorIfContentEditable`:  如果拖动发生在可编辑内容中的链接上，则选中整个链接。
   - `DetermineDragImageAndRect`:  根据拖动类型确定合适的拖动图像和矩形。

6. **启动系统拖动：**
   - `StartDrag`:  当拖动开始时被调用。
   - 执行命中测试，确保被拖动的节点仍然在鼠标下方。
   - 根据拖动类型进行额外的检查（例如，图片和链接的 URL 是否为空）。
   - 调用 `DetermineDragImageAndRect` 获取拖动图像和位置。
   - 调用 `DoSystemDrag` 启动底层的操作系统拖动。

7. **执行系统拖动操作：**
   - `DoSystemDrag`:  与浏览器的 Chrome 部分交互，启动实际的系统拖放操作。
   - 它会将拖动数据、操作掩码、拖动图像和偏移量传递给 ChromeClient。

8. **获取拖放操作类型：**
   - `GetDragOperation`:  根据拖动数据判断可能的拖放操作类型（例如，如果包含 URL 且不是源自身发起的拖动，则可能是复制）。

9. **检查复制键是否按下：**
   - `IsCopyKeyDown`:  判断在拖动过程中复制键（Ctrl 或 Alt，取决于操作系统）是否被按下。

10. **管理拖动状态：**
    - `GetDragState`: 获取或创建 `DragState` 对象，用于存储拖动相关的状态信息。
    - `ContextDestroyed`: 清理拖动状态。

11. **生命周期管理和追踪：**
    - `ContextDestroyed`:  当关联的上下文被销毁时清理资源。
    - `Trace`:  用于垃圾回收的追踪。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML:**
    * **`draggable` 属性:** `DraggableNode` 函数会检查元素的 `draggable` 属性来判断元素是否可以拖动。例如，`<div draggable="true">This can be dragged</div>`。
    * **`<a>` 标签:** `DraggableNode` 和 `PopulateDragDataTransfer` 中会特殊处理链接元素，允许拖动链接地址。例如，`<a href="https://example.com">Example Link</a>`。
    * **`<img>` 标签:**  `DraggableNode` 和 `PopulateDragDataTransfer` 中会特殊处理图片元素，允许拖动图片本身或其链接。例如，`<img src="image.png">`。
    * **用户选择:**  `DraggableNode` 会检查用户是否选中了文本，并允许拖动选中的文本。

* **CSS:**
    * **`user-drag` 属性:** `DraggableNode` 函数会检查元素的 `user-drag` CSS 属性。例如，`<div style="user-drag: element;">This can be dragged</div>`。

* **JavaScript:**
    * **拖放事件 (dragstart, dragover, drop 等):**  虽然这段 C++ 代码本身不直接处理 JavaScript 事件，但它是浏览器引擎中处理拖放操作的核心部分，响应 JavaScript 事件的触发。例如，当 JavaScript 代码触发 `dragstart` 事件时，最终会调用到 `DragController::StartDrag`。
    * **`DataTransfer` API:**  这段代码大量使用了 `DataTransfer` 对象，这是 JavaScript 中用于在拖放操作期间传递数据的 API。`PopulateDragDataTransfer` 函数会将各种数据（URL、文本、HTML、文件等）写入到 `DataTransfer` 对象中，供 JavaScript 的 `drop` 事件处理函数访问。
        * **假设输入:** JavaScript 代码在 `dragstart` 事件中设置了 `dataTransfer.setData('text/plain', 'Hello Drag')`。
        * **输出:**  `PopulateDragDataTransfer` 可能会将这个文本数据写入到内部的 `DataTransfer` 对象中，以便目标可以读取。
    * **`preventDefault()`:** 如果 JavaScript 代码在某些拖放事件中调用了 `preventDefault()`，可能会影响 `DragController` 的行为，例如阻止默认的拖放操作。

**逻辑推理的假设输入与输出：**

* **假设输入:** 用户点击并开始拖动一个 `draggable="true"` 的 `<div>` 元素。
* **输出:** `DraggableNode` 函数会识别出该 `<div>` 元素是可拖动的，并将 `drag_type` 设置为 `kDragSourceActionDHTML`。
* **假设输入:** 用户点击并开始拖动一张图片。
* **输出:** `DraggableNode` 函数会识别出该 `<img>` 元素是可拖动的，并将 `drag_type` 设置为 `kDragSourceActionImage`。`PopulateDragDataTransfer` 会将图片的 URL 和相关信息写入 `DataTransfer` 对象。
* **假设输入:** 用户在选中文本后开始拖动。
* **输出:** `DraggableNode` 函数会识别出拖动源是选中文本，并将 `drag_type` 设置为 `kDragSourceActionSelection`。`PopulateDragDataTransfer` 会将选中的文本内容写入 `DataTransfer` 对象。

**用户或编程常见的使用错误：**

* **用户错误:**
    * **期望拖动不可拖动的元素:** 用户可能尝试拖动没有 `draggable` 属性或 `user-drag` 样式的元素，导致拖动无法开始。
    * **在不支持拖放的目标上释放:** 用户可能将元素拖放到不支持 `drop` 事件处理的目标上，导致放置操作无法完成。

* **编程错误:**
    * **忘记设置 `draggable` 属性:** 开发者可能希望某个元素可拖动，但忘记添加 `draggable="true"` 属性。
    * **`dragstart` 事件中未正确设置 `dataTransfer`:** 开发者可能在 JavaScript 的 `dragstart` 事件处理函数中没有正确地设置 `dataTransfer` 对象，导致拖动时没有携带必要的数据。
        * **示例:**  `event.dataTransfer.setData()` 的第一个参数（MIME 类型）不正确或缺失，导致目标无法识别数据。
    * **在 `dragover` 或 `drop` 事件中忘记调用 `preventDefault()`:**  开发者可能忘记在目标元素的 `dragover` 事件中调用 `preventDefault()` 来允许放置，或者在 `drop` 事件中忘记调用 `preventDefault()` 来阻止浏览器的默认行为。
    * **安全策略问题:** 尝试在不同的域之间拖放数据时，可能会遇到浏览器的安全策略限制，导致数据无法访问。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户在网页上执行“点击并拖动”操作。** 这通常发生在鼠标按下（`mousedown` 或类似的事件）并在按住鼠标按钮的同时移动鼠标（`mousemove` 事件）。
2. **浏览器捕获到这些鼠标事件，并判断是否应该开始拖放操作。** 这涉及到检查点击位置的元素是否可拖动（通过 `draggable` 属性或 `user-drag` 样式），以及是否满足其他拖动条件。
3. **如果确定可以开始拖动，浏览器会触发 `dragstart` 事件。** JavaScript 代码可以监听这个事件并执行自定义的逻辑，例如设置 `dataTransfer` 对象。
4. **Blink 引擎的事件处理机制会将 `dragstart` 事件传递到相应的 C++ 代码中，最终到达 `DragController::StartDrag` 函数。**
5. **`StartDrag` 函数会执行一系列操作，包括命中测试、确定拖动类型、填充 `DataTransfer` 对象，并最终调用 `DoSystemDrag` 来启动操作系统的拖放机制。**
6. **在拖动过程中，当鼠标移动到新的位置时，可能会触发 `dragover` 事件。**  如果鼠标移动到一个潜在的放置目标上，`DragController::UpdateDragAndDrop` 函数会被调用，以处理与目标元素的交互。
7. **当用户释放鼠标按钮时，会触发 `drop` 事件。** 浏览器会再次调用 Blink 引擎的相应代码来处理放置操作，读取 `DataTransfer` 对象中的数据，并通知 JavaScript 代码。

**调试线索:**

* **在 JavaScript 代码中设置断点监听拖放事件 (`dragstart`, `drag`, `dragover`, `drop`, `dragend`)，查看事件对象和 `dataTransfer` 对象的内容。**
* **在 Blink 引擎的 `DragController` 相关的 C++ 代码中设置断点，例如 `StartDrag`, `PopulateDragDataTransfer`, `UpdateDragAndDrop`，以跟踪拖放操作的执行流程和状态。**
* **检查元素的 `draggable` 属性和 `user-drag` 样式。**
* **使用浏览器的开发者工具查看控制台的错误信息，特别是与拖放相关的错误。**
* **如果涉及到跨域拖放，检查浏览器的安全策略设置。**

总而言之，这部分 `drag_controller.cc` 代码是 Chromium Blink 引擎中处理拖放操作的核心组件，它负责识别可拖动的元素，管理拖放过程中的数据传输，并与操作系统的拖放机制进行交互。它与 HTML、CSS 和 JavaScript 的拖放 API 紧密相关，共同实现了网页上的拖放功能。

### 提示词
```
这是目录为blink/renderer/core/page/drag_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
onsMask src_op_mask = drag_data->DraggingSourceOperationMask();
  data_transfer->SetSourceOperation(src_op_mask);

  WebMouseEvent event = CreateMouseEvent(drag_data);
  if (local_root.GetEventHandler().UpdateDragAndDrop(event, data_transfer) ==
      WebInputEventResult::kNotHandled) {
    data_transfer->SetAccessPolicy(
        DataTransferAccessPolicy::kNumb);  // invalidate clipboard here for
                                           // security
    return false;
  }

  if (!data_transfer->DropEffectIsInitialized()) {
    operation = DefaultOperationForDrag(src_op_mask);
  } else {
    operation = data_transfer->DestinationOperation();
    if (!(src_op_mask & static_cast<int>(operation))) {
      // The element picked an operation which is not supported by the source.
      operation = DragOperation::kNone;
    }
  }

  data_transfer->SetAccessPolicy(
      DataTransferAccessPolicy::kNumb);  // invalidate clipboard here for
                                         // security
  return true;
}

bool SelectTextInsteadOfDrag(const Node& node) {
  if (!node.IsTextNode())
    return false;

  // Editable elements loose their draggability,
  // see https://github.com/whatwg/html/issues/3114.
  if (IsEditable(node))
    return true;

  for (Node& ancestor_node : NodeTraversal::InclusiveAncestorsOf(node)) {
    auto* html_element = DynamicTo<HTMLElement>(ancestor_node);
    if (html_element && html_element->draggable())
      return false;
  }

  return node.CanStartSelection();
}

Node* DragController::DraggableNode(const LocalFrame* src,
                                    Node* start_node,
                                    const gfx::Point& drag_origin,
                                    SelectionDragPolicy selection_drag_policy,
                                    DragSourceAction& drag_type) const {
  if (src->Selection().Contains(PhysicalOffset(drag_origin))) {
    drag_type = kDragSourceActionSelection;
    if (selection_drag_policy == kImmediateSelectionDragResolution)
      return start_node;
  } else {
    drag_type = kDragSourceActionNone;
  }

  Node* node = nullptr;
  DragSourceAction candidate_drag_type = kDragSourceActionNone;
  for (const LayoutObject* layout_object = start_node->GetLayoutObject();
       layout_object; layout_object = layout_object->Parent()) {
    node = layout_object->NonPseudoNode();
    if (!node) {
      // Anonymous layout blocks don't correspond to actual DOM nodes, so we
      // skip over them for the purposes of finding a draggable node.
      continue;
    }
    if (drag_type != kDragSourceActionSelection &&
        SelectTextInsteadOfDrag(*node)) {
      // We have a click in an unselected, selectable text that is not
      // draggable... so we want to start the selection process instead
      // of looking for a parent to try to drag.
      return nullptr;
    }
    if (node->IsElementNode()) {
      EUserDrag drag_mode = layout_object->Style()->UserDrag();
      if (drag_mode == EUserDrag::kNone)
        continue;
      // Even if the image is part of a selection, we always only drag the image
      // in this case.
      if (layout_object->IsImage() && src->GetSettings() &&
          src->GetSettings()->GetLoadsImagesAutomatically()) {
        drag_type = kDragSourceActionImage;
        return node;
      }
      // Other draggable elements are considered unselectable.
      if (drag_mode == EUserDrag::kElement) {
        candidate_drag_type = kDragSourceActionDHTML;
        break;
      }
      // TODO(crbug.com/369219144): Should this be
      // DynamicTo<HTMLAnchorElementBase>?
      auto* html_anchor_element = DynamicTo<HTMLAnchorElement>(node);
      if (html_anchor_element && html_anchor_element->IsLiveLink()) {
        candidate_drag_type = kDragSourceActionLink;
        break;
      }
    }
  }

  if (candidate_drag_type == kDragSourceActionNone) {
    // Either:
    // 1) Nothing under the cursor is considered draggable, so we bail out.
    // 2) There was a selection under the cursor but selectionDragPolicy is set
    //    to DelayedSelectionDragResolution and no other draggable element could
    //    be found, so bail out and allow text selection to start at the cursor
    //    instead.
    return nullptr;
  }

  DCHECK(node);
  if (drag_type == kDragSourceActionSelection) {
    // Dragging unselectable elements in a selection has special behavior if
    // selectionDragPolicy is DelayedSelectionDragResolution and this drag was
    // flagged as a potential selection drag. In that case, don't allow
    // selection and just drag the entire selection instead.
    DCHECK_EQ(selection_drag_policy, kDelayedSelectionDragResolution);
    node = start_node;
  } else {
    // If the cursor isn't over a selection, then just drag the node we found
    // earlier.
    DCHECK_EQ(drag_type, kDragSourceActionNone);
    drag_type = candidate_drag_type;
  }
  return node;
}

static void PrepareDataTransferForImageDrag(LocalFrame* source,
                                            DataTransfer* data_transfer,
                                            Element* node,
                                            const KURL& link_url,
                                            const KURL& image_url,
                                            const String& label) {
  node->GetDocument().UpdateStyleAndLayoutTree();
  if (IsRichlyEditable(*node)) {
    // TODO(crbug.com/331666850): Replace `EphemeralRange` usage with `Range`.
    Range* range = source->GetDocument()->createRange();
    range->selectNode(node, ASSERT_NO_EXCEPTION);
    source->Selection().SetSelection(
        SelectionInDOMTree::Builder()
            .SetBaseAndExtent(EphemeralRange(range))
            .Build(),
        SetSelectionOptions());
  }
  data_transfer->DeclareAndWriteDragImage(node, link_url, image_url, label);
}

bool DragController::PopulateDragDataTransfer(LocalFrame* src,
                                              const DragState& state,
                                              const gfx::Point& drag_origin) {
#if DCHECK_IS_ON()
  DCHECK(DragTypeIsValid(state.drag_type_));
#endif
  DCHECK(src);
  if (!src->View() || !src->ContentLayoutObject())
    return false;

  HitTestLocation location(drag_origin);
  HitTestResult hit_test_result =
      src->GetEventHandler().HitTestResultAtLocation(location);
  // FIXME: Can this even happen? I guess it's possible, but should verify
  // with a web test.
  Node* hit_inner_node = hit_test_result.InnerNode();
  if (!hit_inner_node ||
      !state.drag_src_->IsShadowIncludingInclusiveAncestorOf(*hit_inner_node)) {
    // The original node being dragged isn't under the drag origin anymore...
    // maybe it was hidden or moved out from under the cursor. Regardless, we
    // don't want to start a drag on something that's not actually under the
    // drag origin.
    return false;
  }
  const KURL& link_url = hit_test_result.AbsoluteLinkURL();
  const KURL& image_url = hit_test_result.AbsoluteImageURL();

  DataTransfer* data_transfer = state.drag_data_transfer_.Get();
  Node* node = state.drag_src_.Get();

  // TODO(crbug.com/369219144): Should this be DynamicTo<HTMLAnchorElementBase>?
  auto* html_anchor_element = DynamicTo<HTMLAnchorElement>(node);
  if (html_anchor_element && html_anchor_element->IsLiveLink() &&
      !link_url.IsEmpty()) {
    // Simplify whitespace so the title put on the clipboard resembles what
    // the user sees on the web page. This includes replacing newlines with
    // spaces.
    data_transfer->WriteURL(node, link_url,
                            hit_test_result.TextContent().SimplifyWhiteSpace());
  }

  if (state.drag_type_ == kDragSourceActionSelection) {
    data_transfer->WriteSelection(src->Selection());
  } else if (state.drag_type_ == kDragSourceActionImage) {
    auto* element = DynamicTo<Element>(node);
    if (image_url.IsEmpty() || !element)
      return false;
    PrepareDataTransferForImageDrag(src, data_transfer, element, link_url,
                                    image_url,
                                    hit_test_result.AltDisplayString());
  } else if (state.drag_type_ == kDragSourceActionLink) {
    if (link_url.IsEmpty())
      return false;
  } else if (state.drag_type_ == kDragSourceActionDHTML) {
    LayoutObject* layout_object = node->GetLayoutObject();
    if (!layout_object) {
      // The layoutObject has disappeared, this can happen if the onStartDrag
      // handler has hidden the element in some way. In this case we just kill
      // the drag.
      return false;
    }

    gfx::Rect bounding_including_descendants =
        layout_object->AbsoluteBoundingBoxRectIncludingDescendants();
    gfx::Point drag_element_location =
        drag_origin - bounding_including_descendants.OffsetFromOrigin();
    data_transfer->SetDragImageElement(node, drag_element_location);

    // FIXME: For DHTML/draggable element drags, write element markup to
    // clipboard.
  }

  // Observe context related to source to allow dropping drag_state_ when the
  // Document goes away.
  SetExecutionContext(src->DomWindow());

  return true;
}

namespace {

gfx::Point DragLocationForDHTMLDrag(const gfx::Point& mouse_dragged_point,
                                    const gfx::Point& drag_initiation_location,
                                    const gfx::Point& drag_image_offset,
                                    bool is_link_image) {
  if (is_link_image) {
    return gfx::Point(mouse_dragged_point.x() - drag_image_offset.x(),
                      mouse_dragged_point.y() - drag_image_offset.y());
  }

  return gfx::Point(drag_initiation_location.x() - drag_image_offset.x(),
                    drag_initiation_location.y() - drag_image_offset.y());
}

gfx::Rect DragRectForSelectionDrag(const LocalFrame& frame) {
  frame.View()->UpdateLifecycleToLayoutClean(DocumentUpdateReason::kSelection);
  gfx::Rect dragging_rect =
      gfx::ToEnclosingRect(DragController::ClippedSelection(frame));
  int x1 = dragging_rect.x();
  int y1 = dragging_rect.y();
  int x2 = dragging_rect.right();
  int y2 = dragging_rect.bottom();
  gfx::Point origin(std::min(x1, x2), std::min(y1, y2));
  gfx::Size size(std::abs(x2 - x1), std::abs(y2 - y1));
  return gfx::Rect(origin, size);
}

const gfx::Size MaxDragImageSize(float device_scale_factor) {
#if BUILDFLAG(IS_MAC)
  // Match Safari's drag image size.
  static const gfx::Size kMaxDragImageSize(400, 400);
#else
  static const gfx::Size kMaxDragImageSize(200, 200);
#endif
  return gfx::ScaleToFlooredSize(kMaxDragImageSize, device_scale_factor);
}

bool CanDragImage(const Element& element) {
  auto* layout_image = DynamicTo<LayoutImage>(element.GetLayoutObject());
  if (!layout_image)
    return false;
  const ImageResourceContent* image_content = layout_image->CachedImage();
  if (!image_content || image_content->ErrorOccurred() ||
      image_content->GetImage()->IsNull())
    return false;
  scoped_refptr<const SharedBuffer> buffer = image_content->ResourceBuffer();
  if (!buffer || !buffer->size())
    return false;
  // We shouldn't be starting a drag for an image that can't provide an
  // extension.
  // This is an early detection for problems encountered later upon drop.
  DCHECK(!image_content->GetImage()->FilenameExtension().empty());
  return true;
}

std::unique_ptr<DragImage> DragImageForImage(
    const Element& element,
    float device_scale_factor,
    const gfx::Size& image_element_size_in_pixels) {
  auto* layout_image = To<LayoutImage>(element.GetLayoutObject());
  const LayoutImageResource& image_resource = *layout_image->ImageResource();
  scoped_refptr<Image> image =
      image_resource.GetImage(image_element_size_in_pixels);
  RespectImageOrientationEnum respect_orientation =
      image_resource.ImageOrientation();

  gfx::Size image_size = image->Size(respect_orientation);
  if (image_size.Area64() > kMaxOriginalImageArea)
    return nullptr;

  InterpolationQuality interpolation_quality = GetDefaultInterpolationQuality();
  if (layout_image->StyleRef().ImageRendering() == EImageRendering::kPixelated)
    interpolation_quality = kInterpolationNone;

  gfx::Vector2dF image_scale =
      DragImage::ClampedImageScale(image_size, image_element_size_in_pixels,
                                   MaxDragImageSize(device_scale_factor));

  return DragImage::Create(image.get(), respect_orientation,
                           interpolation_quality, kDragImageAlpha, image_scale);
}

gfx::Rect DragRectForImage(const DragImage* drag_image,
                           const gfx::Point& drag_initiation_location,
                           const gfx::Point& image_element_location,
                           const gfx::Size& image_element_size_in_pixels) {
  if (!drag_image)
    return gfx::Rect(drag_initiation_location, gfx::Size());

  gfx::Size original_size = image_element_size_in_pixels;
  gfx::Size new_size = drag_image->Size();

  // Properly orient the drag image and orient it differently if it's smaller
  // than the original
  float scale = new_size.width() / static_cast<float>(original_size.width());
  gfx::Vector2dF offset = image_element_location - drag_initiation_location;
  gfx::Point origin = drag_initiation_location +
                      gfx::ToRoundedVector2d(gfx::ScaleVector2d(offset, scale));
  return gfx::Rect(origin, new_size);
}

std::unique_ptr<DragImage> DragImageForLink(const KURL& link_url,
                                            const String& link_text,
                                            float device_scale_factor) {
  return DragImage::Create(link_url, link_text, device_scale_factor);
}

gfx::Rect DragRectForLink(const DragImage* link_image,
                          const gfx::Point& origin,
                          float device_scale_factor,
                          float page_scale_factor) {
  if (!link_image)
    return gfx::Rect(origin, gfx::Size());

  gfx::Size image_size = link_image->Size();
  // Offset the image so that the cursor is horizontally centered.
  gfx::PointF image_offset(-image_size.width() / 2.f, -kLinkDragBorderInset);
  // |origin| is in the coordinate space of the frame's contents whereas the
  // size of |link_image| is in physical pixels. Adjust the image offset to be
  // scaled in the frame's contents.
  // TODO(crbug.com/331670940): Unify this calculation with the
  // `DragImageForImage` scaling code.
  float scale = 1.f / (device_scale_factor * page_scale_factor);
  image_offset.Scale(scale);
  image_offset += origin.OffsetFromOrigin();
  return gfx::Rect(gfx::ToRoundedPoint(image_offset), image_size);
}

}  // namespace

// static
gfx::RectF DragController::ClippedSelection(const LocalFrame& frame) {
  DCHECK(frame.View());
  return DataTransfer::ClipByVisualViewport(
      gfx::RectF(frame.Selection().AbsoluteUnclippedBounds()), frame);
}

// static
std::unique_ptr<DragImage> DragController::DragImageForSelection(
    LocalFrame& frame,
    float opacity) {
  if (!frame.Selection().ComputeVisibleSelectionInDOMTreeDeprecated().IsRange())
    return nullptr;

  frame.View()->UpdateAllLifecyclePhasesExceptPaint(
      DocumentUpdateReason::kDragImage);
  DCHECK(frame.GetDocument()->IsActive());

  gfx::RectF painting_rect = DragController::ClippedSelection(frame);
  PaintFlags paint_flags =
      PaintFlag::kSelectionDragImageOnly | PaintFlag::kOmitCompositingInfo;

  PaintRecordBuilder builder;
  frame.View()->PaintOutsideOfLifecycle(
      builder.Context(), paint_flags,
      CullRect(gfx::ToEnclosingRect(painting_rect)));

  auto property_tree_state = frame.View()
                                 ->GetLayoutView()
                                 ->FirstFragment()
                                 .LocalBorderBoxProperties()
                                 .Unalias();
  return DataTransfer::CreateDragImageForFrame(
      frame, opacity, painting_rect.size(), painting_rect.OffsetFromOrigin(),
      builder, property_tree_state);
}

namespace {

void SelectEnclosingAnchorIfContentEditable(LocalFrame* frame) {
  if (frame->Selection()
          .ComputeVisibleSelectionInDOMTreeDeprecated()
          .IsCaret() &&
      frame->Selection()
          .ComputeVisibleSelectionInDOMTreeDeprecated()
          .IsContentEditable()) {
    // A user can initiate a drag on a link without having any text
    // selected.  In this case, we should expand the selection to
    // the enclosing anchor element.
    if (Node* anchor = EnclosingAnchorElement(
            frame->Selection()
                .ComputeVisibleSelectionInDOMTreeDeprecated()
                .Anchor())) {
      frame->Selection().SetSelection(
          SelectionInDOMTree::Builder().SelectAllChildren(*anchor).Build(),
          SetSelectionOptions());
    }
  }
}

std::unique_ptr<DragImage> DetermineDragImageAndRect(
    gfx::Rect& drag_obj_rect,
    gfx::Point& effective_drag_initiation_location,
    LocalFrame* frame,
    const DragState& state,
    const HitTestResult& hit_test_result,
    const gfx::Point& drag_initiation_location,
    const gfx::Point& mouse_dragged_point) {
  DataTransfer* data_transfer = state.drag_data_transfer_.Get();
  const KURL& link_url = hit_test_result.AbsoluteLinkURL();
  float device_scale_factor =
      frame->GetChromeClient().GetScreenInfo(*frame).device_scale_factor;

  gfx::Point drag_offset;

  // HTML DnD spec allows setting the drag image, even if it is a link, image or
  // text we are dragging.
  std::unique_ptr<DragImage> drag_image =
      data_transfer->CreateDragImage(drag_offset, device_scale_factor, frame);
  if (drag_image) {
    drag_obj_rect.set_origin(
        DragLocationForDHTMLDrag(mouse_dragged_point, drag_initiation_location,
                                 drag_offset, !link_url.IsEmpty()));
    drag_obj_rect.set_size(drag_image.get()->Size());
  } else {
    drag_obj_rect = gfx::Rect();
  }

  effective_drag_initiation_location = drag_initiation_location;

  // If |drag_image| is not provided, try to determine a drag-source-specific
  // image and location.
  if (state.drag_type_ == kDragSourceActionSelection) {
    if (!drag_image) {
      drag_image =
          DragController::DragImageForSelection(*frame, kDragImageAlpha);
      drag_obj_rect = DragRectForSelectionDrag(*frame);
    }
  } else if (state.drag_type_ == kDragSourceActionImage) {
    if (!drag_image) {
      auto* element = DynamicTo<Element>(state.drag_src_.Get());
      const gfx::Rect& image_rect = hit_test_result.ImageRect();
      // TODO(crbug.com/331670941): Remove this scaling and simply pass
      // `imageRect`to `dragImageForImage` once all platforms are migrated
      // to use zoom for dsf.
      gfx::Size image_size_in_pixels = gfx::ScaleToFlooredSize(
          image_rect.size(), frame->GetPage()->GetVisualViewport().Scale());

      // Pass the selected image size in DIP becasue dragImageForImage clips the
      // image in DIP.  The coordinates of the locations are in Viewport
      // coordinates, and they're converted in the Blink client.
      // TODO(crbug.com/331753419): Consider clipping screen coordinates to
      // use a high resolution image on high DPI screens.
      drag_image = DragImageForImage(*element, device_scale_factor,
                                     image_size_in_pixels);
      drag_obj_rect =
          DragRectForImage(drag_image.get(), effective_drag_initiation_location,
                           image_rect.origin(), image_size_in_pixels);
    }
  } else if (state.drag_type_ == kDragSourceActionLink) {
    if (!drag_image) {
      DCHECK(frame->GetPage());
      drag_image = DragImageForLink(link_url, hit_test_result.TextContent(),
                                    device_scale_factor);
      drag_obj_rect = DragRectForLink(drag_image.get(), mouse_dragged_point,
                                      device_scale_factor,
                                      frame->GetPage()->PageScaleFactor());
    }
    // Why is the initiation location different only for link-drags?
    effective_drag_initiation_location = mouse_dragged_point;
  }

  return drag_image;
}

}  // namespace

bool DragController::StartDrag(LocalFrame* frame,
                               const DragState& state,
                               const WebMouseEvent& drag_event,
                               const gfx::Point& drag_initiation_location) {
  DCHECK(frame);
  if (!frame->View() || !frame->ContentLayoutObject())
    return false;

  HitTestLocation location(drag_initiation_location);
  HitTestResult hit_test_result =
      frame->GetEventHandler().HitTestResultAtLocation(location);
  Node* hit_inner_node = hit_test_result.InnerNode();
  if (!hit_inner_node ||
      !state.drag_src_->IsShadowIncludingInclusiveAncestorOf(*hit_inner_node)) {
    // The original node being dragged isn't under the drag origin anymore...
    // maybe it was hidden or moved out from under the cursor. Regardless, we
    // don't want to start a drag on something that's not actually under the
    // drag origin.
    return false;
  }

  // Note that drag_origin is different from event position.
  gfx::Point mouse_dragged_point = frame->View()->ConvertFromRootFrame(
      gfx::ToFlooredPoint(drag_event.PositionInRootFrame()));

  // Check early return conditions.
  if (state.drag_type_ == kDragSourceActionImage) {
    const KURL& image_url = hit_test_result.AbsoluteImageURL();
    auto* element = DynamicTo<Element>(state.drag_src_.Get());
    if (image_url.IsEmpty() || !element || !CanDragImage(*element))
      return false;
  } else if (state.drag_type_ == kDragSourceActionLink) {
    const KURL& link_url = hit_test_result.AbsoluteLinkURL();
    if (link_url.IsEmpty())
      return false;
  } else if (state.drag_type_ != kDragSourceActionSelection &&
             state.drag_type_ != kDragSourceActionDHTML) {
    NOTREACHED();
  }

  if (state.drag_type_ == kDragSourceActionLink)
    SelectEnclosingAnchorIfContentEditable(frame);

  gfx::Rect drag_obj_rect;
  gfx::Point effective_drag_initiation_location;

  std::unique_ptr<DragImage> drag_image = DetermineDragImageAndRect(
      drag_obj_rect, effective_drag_initiation_location, frame, state,
      hit_test_result, drag_initiation_location, mouse_dragged_point);

  DoSystemDrag(drag_image.get(), drag_obj_rect,
               effective_drag_initiation_location,
               state.drag_data_transfer_.Get(), frame);
  return true;
}

void DragController::DoSystemDrag(DragImage* image,
                                  const gfx::Rect& drag_obj_rect,
                                  const gfx::Point& drag_initiation_location,
                                  DataTransfer* data_transfer,
                                  LocalFrame* frame) {
  did_initiate_drag_ = true;
  drag_initiator_ = frame->DomWindow();
  SetExecutionContext(frame->DomWindow());

  // TODO(crbug.com/331753420): `drag_obj_rect` and `drag_initiation_location`
  // should be passed in as `gfx::RectF` and `gfx::PointF` respectively to
  // avoid unnecessary rounding.
  gfx::Point adjusted_drag_obj_location =
      frame->View()->FrameToViewport(drag_obj_rect.origin());
  gfx::Point adjusted_event_pos =
      frame->View()->FrameToViewport(drag_initiation_location);
  gfx::Vector2d cursor_offset = adjusted_event_pos - adjusted_drag_obj_location;
  WebDragData drag_data = data_transfer->GetDataObject()->ToWebDragData();
  drag_data.SetReferrerPolicy(drag_initiator_->GetReferrerPolicy());
  DragOperationsMask drag_operation_mask = data_transfer->SourceOperation();

  SkBitmap drag_image = image ? image->Bitmap() : SkBitmap();
  page_->GetChromeClient().StartDragging(frame, drag_data, drag_operation_mask,
                                         std::move(drag_image), cursor_offset,
                                         drag_obj_rect);
}

DragOperation DragController::GetDragOperation(DragData* drag_data) {
  // FIXME: To match the MacOS behaviour we should return DragOperation::kNone
  // if we are a modal window, we are the drag source, or the window is an
  // attached sheet If this can be determined from within WebCore
  // operationForDrag can be pulled into WebCore itself
  DCHECK(drag_data);
  return drag_data->ContainsURL() && !did_initiate_drag_ ? DragOperation::kCopy
                                                         : DragOperation::kNone;
}

bool DragController::IsCopyKeyDown(DragData* drag_data) {
  int modifiers = drag_data->GetModifiers();

#if BUILDFLAG(IS_MAC)
  return modifiers & WebInputEvent::kAltKey;
#else
  return modifiers & WebInputEvent::kControlKey;
#endif
}

DragState& DragController::GetDragState() {
  if (!drag_state_)
    drag_state_ = MakeGarbageCollected<DragState>();
  return *drag_state_;
}

void DragController::ContextDestroyed() {
  drag_state_ = nullptr;
}

void DragController::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
  visitor->Trace(document_under_mouse_);
  visitor->Trace(drag_initiator_);
  visitor->Trace(drag_state_);
  visitor->Trace(file_input_element_under_mouse_);
  ExecutionContextLifecycleObserver::Trace(visitor);
}

}  // namespace blink
```