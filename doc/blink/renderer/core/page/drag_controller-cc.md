Response:
The user wants a summary of the functionalities of the `drag_controller.cc` file in the Chromium Blink engine. I need to analyze the provided code snippet and identify its key responsibilities. Specifically, I should focus on how it handles drag and drop operations, its interactions with JavaScript, HTML, and CSS, and any potential user errors. Finally, I need to explain how a user action can lead to this code being executed and provide a concise summary of its functions.

Here's a plan:
1. **Identify Core Functionality:** Look for the main classes and methods related to drag and drop.
2. **Relate to Web Technologies:** Determine how the `DragController` interacts with DOM elements, events, and styles.
3. **Analyze Logic and Data Flow:**  Examine how drag events are processed and what data is exchanged.
4. **Consider User Errors:** Think about scenarios where users might encounter issues related to drag and drop.
5. **Trace User Actions:**  Outline the sequence of user interactions that trigger this code.
6. **Summarize Functionality:** Condense the findings into a clear and concise overview.
```
功能概括：

blink/renderer/core/page/drag_controller.cc 文件的主要功能是 **处理网页中的拖放（Drag and Drop）操作**。它负责协调从拖动开始到结束的整个过程，包括识别可拖动的元素、处理拖动事件、确定拖放目标、执行拖放操作以及更新用户界面。

以下是更详细的功能点：

1. **接收和解析拖放数据 (DragData):**  `DragController` 接收来自浏览器进程的 `DragData` 对象，其中包含了拖动操作的各种信息，例如拖动的数据类型（文本、URL、文件等）、数据内容、鼠标位置、按键状态等。
2. **启动拖动 (Initiate Drag):**  当用户开始拖动一个元素时，`DragController` 会被调用，记录拖动的发起者 (`drag_initiator_`) 和起始状态。
3. **处理拖动过程中的事件:**
    *   **`DragEnteredOrUpdated`:**  当拖动鼠标进入或在某个 Frame 内移动时被调用，用于判断是否允许在该区域进行拖放操作，并确定允许的拖放操作类型 (拷贝、移动、链接)。
    *   **`DragExited`:** 当拖动鼠标离开某个 Frame 时被调用，用于清理状态并通知该 Frame 的事件处理器。
    *   **`PerformDrag`:** 当用户释放鼠标完成拖放操作时被调用，执行实际的拖放动作。
4. **判断拖放目标:**  `DragController` 通过 Hit Testing 来确定鼠标指针下的元素 (`document_under_mouse_`)，并判断该元素是否可以作为拖放的目标。
5. **区分不同类型的拖放操作:**
    *   **DHTML 拖放:** 处理通过 JavaScript 的 `dragstart`, `dragenter`, `dragover`, `dragleave`, `drop`, `dragend` 等事件实现的拖放。
    *   **编辑区域拖放:**  处理拖放到可编辑区域（如 `<textarea>`, `contenteditable` 元素）的操作，包括插入文本、HTML 片段或文件。
    *   **链接拖放:**  处理拖动链接到其他位置的操作，可能导致在新标签页打开链接。
    *   **文件拖放:**  处理拖动本地文件到浏览器窗口的操作，特别是拖放到 `<input type="file">` 元素。
6. **与剪贴板交互:**  创建和管理 `DataTransfer` 对象，用于在拖放过程中传递数据，并控制对剪贴板的访问权限。
7. **控制拖动光标 (Drag Caret):** 在拖动到可编辑区域时，显示和更新拖动光标的位置。
8. **执行拖放命令:**  对于编辑区域的拖放，会生成相应的编辑命令 (例如 `DragAndDropCommand`) 来修改文档内容。
9. **处理跨域拖放:** 考虑安全性，会检查拖动源和目标是否同源，以防止潜在的安全风险。
10. **处理 `drop` 事件的默认行为:**  在某些情况下，如果事件没有被 JavaScript 阻止默认行为，`DragController` 会执行默认的拖放操作，例如在新标签页打开拖动的链接。

**与 JavaScript, HTML, CSS 的关系举例说明：**

*   **JavaScript:**
    *   **`dragstart` 事件:** 当 JavaScript 代码监听了元素的 `dragstart` 事件并调用了 `dataTransfer.setData()` 设置了拖动数据后，`DragController` 会接收到这些数据。
        ```javascript
        const element = document.getElementById('draggable');
        element.addEventListener('dragstart', (event) => {
          event.dataTransfer.setData('text/plain', 'This is the data being dragged');
        });
        ```
    *   **`dragenter`, `dragover`, `dragleave`, `drop` 事件:**  当拖动鼠标经过或释放到目标元素上时，浏览器会触发这些事件。JavaScript 可以监听这些事件并调用 `event.preventDefault()` 来阻止浏览器的默认拖放行为，或者通过 `event.dataTransfer.dropEffect` 来设置允许的拖放操作类型。`DragController` 会根据 JavaScript 的处理结果来决定最终的操作。
        ```javascript
        const dropArea = document.getElementById('dropzone');
        dropArea.addEventListener('dragover', (event) => {
          event.preventDefault(); // 允许 drop
        });
        dropArea.addEventListener('drop', (event) => {
          event.preventDefault();
          const data = event.dataTransfer.getData('text/plain');
          dropArea.textContent = 'Dropped: ' + data;
        });
        ```
*   **HTML:**
    *   **`draggable` 属性:**  HTML 元素的 `draggable="true"` 属性使元素可以被拖动。`DragController` 会识别这些可拖动的元素。
        ```html
        <div id="draggable" draggable="true">Drag me!</div>
        ```
    *   **`<input type="file">` 元素:**  `DragController` 会特殊处理拖动文件到文件输入框的操作。
        ```html
        <input type="file" id="fileInput">
        ```
    *   **`contenteditable` 属性:**  `DragController` 会处理拖动内容到带有 `contenteditable` 属性的元素的操作。
        ```html
        <div contenteditable="true">Edit me by dragging content here.</div>
        ```
*   **CSS:**
    *   CSS 可以通过 `cursor` 属性来改变拖动过程中的鼠标光标样式，但这主要是由浏览器渲染引擎处理，`DragController` 更多关注逻辑上的处理。

**逻辑推理的假设输入与输出：**

假设输入：用户拖动一个带有 `draggable="true"` 属性的图片元素，并将其释放到一个可编辑的 `<div>` 元素中。

*   **假设输入:**
    *   拖动源:  一个 `<img>` 元素，`draggable="true"`，`src="image.png"`
    *   拖动目标: 一个 `<div contenteditable="true">` 元素
    *   用户操作:  按下鼠标左键拖动图片，然后释放到 `<div>` 上。
*   **逻辑推理过程:**
    1. `DragController` 接收到 `dragstart` 事件，识别拖动源。
    2. 在拖动过程中，`DragController` 通过 `DragEnteredOrUpdated` 和 Hit Testing 确定鼠标下的元素是可编辑的 `<div>`。
    3. `DragController` 判断这是一个拖放到可编辑区域的操作。
    4. 当鼠标释放时，`PerformDrag` 被调用。
    5. `DragController` 创建 `DataTransfer` 对象，包含图片的 URL。
    6. 如果 JavaScript 没有阻止默认行为，`DragController` 会尝试将图片插入到 `<div>` 中。
*   **预期输出:**  `<img>` 标签被插入到可编辑的 `<div>` 元素中。

**用户或编程常见的使用错误举例说明：**

1. **忘记在 `dragover` 事件中调用 `event.preventDefault()`:**  如果用户想实现自定义的拖放效果，但忘记在拖放目标元素的 `dragover` 事件处理函数中调用 `event.preventDefault()`，浏览器会默认不允许在该元素上进行 drop 操作。
    ```javascript
    dropArea.addEventListener('dragover', (event) => {
      // 缺少 event.preventDefault();  导致无法 drop
    });
    ```
2. **错误地设置 `dataTransfer` 的数据类型:**  拖动源设置了错误的数据类型，导致目标元素无法正确处理拖放的数据。例如，拖动源设置了 `text/html`，但目标元素期望的是 `text/plain`。
    ```javascript
    // 拖动源
    element.addEventListener('dragstart', (event) => {
      event.dataTransfer.setData('text/html', '<p>Some HTML</p>');
    });

    // 拖放目标
    dropArea.addEventListener('drop', (event) => {
      const textData = event.dataTransfer.getData('text/plain'); // 期望 text/plain
      // textData 将为空
    });
    ```
3. **跨域拖放限制:**  尝试在不同源的 Frame 之间进行拖放，可能会受到浏览器的安全限制。开发者需要理解同源策略对拖放操作的影响。
4. **在拖动事件处理函数中进行耗时操作:**  在 `dragenter` 或 `dragover` 等事件处理函数中执行大量的同步操作可能会导致页面卡顿，影响用户体验。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在网页上选择了一个可拖动的元素：**  这个元素可能设置了 `draggable="true"` 属性，或者是一个链接、图片等浏览器默认可拖动的元素。
2. **用户按下鼠标左键并开始拖动该元素：**  这会触发拖动源元素的 `dragstart` 事件。
3. **鼠标指针在页面上移动：**  当鼠标指针进入不同的 Frame 或元素时，会触发目标元素的 `dragenter` 和 `dragover` 事件。  `DragController::DragEnteredOrUpdated` 方法会被调用，以确定是否允许在该位置进行拖放。
4. **用户将鼠标指针移动到另一个可作为拖放目标的元素上：**  `DragController` 会通过 Hit Testing 识别当前鼠标下的元素。
5. **用户释放鼠标左键：**  这会触发目标元素的 `drop` 事件。 `DragController::PerformDrag` 方法会被调用，执行实际的拖放操作。
6. **拖动操作结束：**  无论拖放成功与否，拖动源元素的 `dragend` 事件都会被触发，`DragController::DragEnded` 方法会被调用，进行清理工作。

**调试线索：** 如果开发者想要调试拖放功能，可以在以下关键点设置断点：

*   `DragController::DragController` (构造函数，查看 `DragController` 的创建时机)
*   `DragController::InitiateDrag` (查看拖动开始时的数据)
*   `DragController::DragEnteredOrUpdated` (查看拖动过程中目标元素的判断和操作类型的确定)
*   `DragController::PerformDrag` (查看实际拖放操作的执行)
*   与 JavaScript 拖放事件监听器相关的代码 (例如 `dragstart`, `dragenter`, `dragover`, `drop` 事件处理函数)。

通过以上分析，可以更全面地理解 `blink/renderer/core/page/drag_controller.cc` 文件的功能及其在 Chromium Blink 引擎中的作用。
```
Prompt: 
```
这是目录为blink/renderer/core/page/drag_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2007, 2009, 2010 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Google Inc.
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

#include "third_party/blink/renderer/core/page/drag_controller.h"

#include <memory>

#include "base/memory/scoped_refptr.h"
#include "build/build_config.h"
#include "third_party/blink/public/common/page/drag_operation.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/platform/web_common.h"
#include "third_party/blink/public/platform/web_drag_data.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_access_policy.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/drag_and_drop_command.h"
#include "third_party/blink/renderer/core/editing/drag_caret.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/plugin_document.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/hit_test_request.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_theme.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/loader/frame_load_request.h"
#include "third_party/blink/renderer/core/loader/frame_loader.h"
#include "third_party/blink/renderer/core/loader/resource/image_resource_content.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/drag_data.h"
#include "third_party/blink/renderer/core/page/drag_image.h"
#include "third_party/blink/renderer/core/page/drag_state.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/graphics/image.h"
#include "third_party/blink/renderer/platform/graphics/image_orientation.h"
#include "third_party/blink/renderer/platform/graphics/paint/paint_record_builder.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_fetcher.h"
#include "third_party/blink/renderer/platform/loader/fetch/resource_request.h"
#include "third_party/blink/renderer/platform/weborigin/security_origin.h"
#include "third_party/blink/renderer/platform/wtf/shared_buffer.h"
#include "ui/base/dragdrop/mojom/drag_drop_types.mojom-blink.h"
#include "ui/display/screen_info.h"
#include "ui/gfx/geometry/point_conversions.h"
#include "ui/gfx/geometry/rect.h"
#include "ui/gfx/geometry/rect_conversions.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/geometry/vector2d_conversions.h"

#if BUILDFLAG(IS_WIN)
#include <windows.h>
#endif

namespace blink {

using mojom::blink::FormControlType;
using ui::mojom::blink::DragOperation;

static const int kMaxOriginalImageArea = 1500 * 1500;
static const int kLinkDragBorderInset = 2;
#if BUILDFLAG(IS_ANDROID)
// Android handles drag image transparency at the browser level
static const float kDragImageAlpha = 1.00f;
#else
static const float kDragImageAlpha = 0.75f;
#endif

#if DCHECK_IS_ON()
static bool DragTypeIsValid(DragSourceAction action) {
  switch (action) {
    case kDragSourceActionDHTML:
    case kDragSourceActionImage:
    case kDragSourceActionLink:
    case kDragSourceActionSelection:
      return true;
    case kDragSourceActionNone:
      return false;
  }
  NOTREACHED();
}
#endif  // DCHECK_IS_ON()

static WebMouseEvent CreateMouseEvent(DragData* drag_data) {
  WebMouseEvent result(
      WebInputEvent::Type::kMouseMove, drag_data->ClientPosition(),
      drag_data->GlobalPosition(), WebPointerProperties::Button::kLeft, 0,
      static_cast<WebInputEvent::Modifiers>(drag_data->GetModifiers()),
      base::TimeTicks::Now());
  result.SetFrameScale(1);
  return result;
}

static DataTransfer* CreateDraggingDataTransfer(DataTransferAccessPolicy policy,
                                                DragData* drag_data) {
  return DataTransfer::Create(DataTransfer::kDragAndDrop, policy,
                              drag_data->PlatformData());
}

DragController::DragController(Page* page)
    : ExecutionContextLifecycleObserver(
          static_cast<ExecutionContext*>(nullptr)),
      page_(page),
      document_under_mouse_(nullptr),
      drag_initiator_(nullptr),
      file_input_element_under_mouse_(nullptr),
      document_is_handling_drag_(false),
      drag_destination_action_(kDragDestinationActionNone),
      did_initiate_drag_(false) {}

static DocumentFragment* DocumentFragmentFromDragData(
    DragData* drag_data,
    LocalFrame* frame,
    Range* context,
    bool allow_plain_text,
    DragSourceType& drag_source_type,
    bool is_richly_editable_position) {
  DCHECK(drag_data);
  CHECK(is_richly_editable_position ||
        RuntimeEnabledFeatures::
            DropUrlAsPlainTextInPlainTextOnlyEditablePositionEnabled());
  drag_source_type = DragSourceType::kHTMLSource;

  Document& document = context->OwnerDocument();
  if (drag_data->ContainsCompatibleContent()) {
    if (DocumentFragment* fragment = drag_data->AsFragment(frame))
      return fragment;

    if (is_richly_editable_position &&
        drag_data->ContainsURL(DragData::kDoNotConvertFilenames)) {
      String title;
      String url = drag_data->AsURL(DragData::kDoNotConvertFilenames, &title);
      if (!url.empty()) {
        auto* anchor = MakeGarbageCollected<HTMLAnchorElement>(document);
        anchor->SetHref(AtomicString(url));
        if (title.empty()) {
          // Try the plain text first because the url might be normalized or
          // escaped.
          if (drag_data->ContainsPlainText())
            title = drag_data->AsPlainText();
          if (title.empty())
            title = url;
        }
        Node* anchor_text = document.createTextNode(title);
        anchor->AppendChild(anchor_text);
        DocumentFragment* fragment = document.createDocumentFragment();
        fragment->AppendChild(anchor);
        return fragment;
      }
    }
  }
  if (allow_plain_text && drag_data->ContainsPlainText()) {
    drag_source_type = DragSourceType::kPlainTextSource;
    return CreateFragmentFromText(EphemeralRange(context),
                                  drag_data->AsPlainText());
  }

  return nullptr;
}

bool DragController::DragIsMove(FrameSelection& selection,
                                DragData* drag_data) {
  return document_under_mouse_ ==
             (drag_initiator_ ? drag_initiator_->document() : nullptr) &&
         selection.SelectionHasFocus() &&
         selection.ComputeVisibleSelectionInDOMTreeDeprecated()
             .IsContentEditable() &&
         selection.ComputeVisibleSelectionInDOMTreeDeprecated().IsRange() &&
         !IsCopyKeyDown(drag_data);
}

void DragController::ClearDragCaret() {
  page_->GetDragCaret().Clear();
}

void DragController::DragEnded() {
  drag_initiator_ = nullptr;
  did_initiate_drag_ = false;
  page_->GetDragCaret().Clear();
}

void DragController::DragExited(DragData* drag_data, LocalFrame& local_root) {
  DCHECK(drag_data);

  LocalFrameView* frame_view(local_root.View());
  if (frame_view) {
    DataTransferAccessPolicy policy = DataTransferAccessPolicy::kTypesReadable;
    DataTransfer* data_transfer = CreateDraggingDataTransfer(policy, drag_data);
    data_transfer->SetSourceOperation(drag_data->DraggingSourceOperationMask());
    local_root.GetEventHandler().CancelDragAndDrop(CreateMouseEvent(drag_data),
                                                   data_transfer);
    data_transfer->SetAccessPolicy(
        DataTransferAccessPolicy::kNumb);  // invalidate clipboard here for
                                           // security
  }
  MouseMovedIntoDocument(nullptr);
  if (file_input_element_under_mouse_)
    file_input_element_under_mouse_->SetCanReceiveDroppedFiles(false);
  file_input_element_under_mouse_ = nullptr;
}

void DragController::PerformDrag(DragData* drag_data, LocalFrame& local_root) {
  DCHECK(drag_data);
  document_under_mouse_ = local_root.DocumentAtPoint(
      PhysicalOffset::FromPointFRound(drag_data->ClientPosition()));
  LocalFrame::NotifyUserActivation(
      document_under_mouse_ ? document_under_mouse_->GetFrame() : nullptr,
      mojom::blink::UserActivationNotificationType::kInteraction);
  if ((drag_destination_action_ & kDragDestinationActionDHTML) &&
      document_is_handling_drag_) {
    bool prevented_default = false;
    if (drag_data->ForceDefaultAction()) {
      // Tell the document that the drag has left the building.
      DragExited(drag_data, local_root);
    } else if (local_root.View()) {
      // Sending an event can result in the destruction of the view and part.
      DataTransfer* data_transfer = CreateDraggingDataTransfer(
          DataTransferAccessPolicy::kReadable, drag_data);
      data_transfer->SetSourceOperation(
          drag_data->DraggingSourceOperationMask());
      EventHandler& event_handler = local_root.GetEventHandler();
      prevented_default = event_handler.PerformDragAndDrop(
                              CreateMouseEvent(drag_data), data_transfer) !=
                          WebInputEventResult::kNotHandled;
      if (!prevented_default && document_under_mouse_) {
        // When drop target is plugin element and it can process drag, we
        // should prevent default behavior.
        const HitTestLocation location(local_root.View()->ConvertFromRootFrame(
            PhysicalOffset::FromPointFRound(drag_data->ClientPosition())));
        const HitTestResult result =
            event_handler.HitTestResultAtLocation(location);
        auto* html_plugin_element =
            DynamicTo<HTMLPlugInElement>(result.InnerNode());
        prevented_default |=
            html_plugin_element && html_plugin_element->CanProcessDrag();
      }

      // Invalidate clipboard here for security.
      data_transfer->SetAccessPolicy(DataTransferAccessPolicy::kNumb);
    }
    if (prevented_default) {
      document_under_mouse_ = nullptr;
      ClearDragCaret();
      return;
    }
  }

  if ((drag_destination_action_ & kDragDestinationActionEdit) &&
      ConcludeEditDrag(drag_data)) {
    document_under_mouse_ = nullptr;
    return;
  }

  if (OperationForLoad(drag_data, local_root) != DragOperation::kNone) {
    ResourceRequest resource_request(drag_data->AsURL());
    resource_request.SetHasUserGesture(LocalFrame::HasTransientUserActivation(
        document_under_mouse_ ? document_under_mouse_->GetFrame() : nullptr));

    // Use a unique origin to match other navigations that are initiated
    // outside of a renderer process (e.g. omnibox navigations).  Here, the
    // initiator of the navigation is a user dragging files from *outside* of
    // the current page.  See also https://crbug.com/930049.
    //
    // TODO(crbug.com/331733543): Once supported, use the source of the drag as
    // the initiator of the navigation below.
    resource_request.SetRequestorOrigin(SecurityOrigin::CreateUniqueOpaque());

    FrameLoadRequest request(nullptr, resource_request);

    // Open the dropped URL in a new tab to avoid potential data-loss in the
    // current tab. See https://crbug.com/451659.
    request.SetNavigationPolicy(
        NavigationPolicy::kNavigationPolicyNewForegroundTab);
    local_root.Navigate(request, WebFrameLoadType::kStandard);
  }

  document_under_mouse_ = nullptr;
}

void DragController::MouseMovedIntoDocument(Document* new_document) {
  if (document_under_mouse_ == new_document)
    return;

  // If we were over another document clear the selection
  if (document_under_mouse_)
    ClearDragCaret();
  document_under_mouse_ = new_document;
}

DragController::Operation DragController::DragEnteredOrUpdated(
    DragData* drag_data,
    LocalFrame& local_root) {
  DCHECK(drag_data);

  MouseMovedIntoDocument(local_root.DocumentAtPoint(
      PhysicalOffset::FromPointFRound(drag_data->ClientPosition())));

  // TODO(crbug.com/331682039): Replace `AcceptsLoadDrops` with a Setting used
  // in core.
  drag_destination_action_ =
      page_->GetChromeClient().AcceptsLoadDrops()
          ? kDragDestinationActionAny
          : static_cast<DragDestinationAction>(kDragDestinationActionDHTML |
                                               kDragDestinationActionEdit);

  Operation drag_operation;
  document_is_handling_drag_ =
      TryDocumentDrag(drag_data, drag_destination_action_,
                      drag_operation.operation, local_root);
  if (!document_is_handling_drag_ &&
      (drag_destination_action_ & kDragDestinationActionLoad)) {
    drag_operation.operation = OperationForLoad(drag_data, local_root);
  }

  drag_operation.document_is_handling_drag = document_is_handling_drag_;
  return drag_operation;
}

static HTMLInputElement* AsFileInput(Node* node) {
  DCHECK(node);
  for (; node; node = node->OwnerShadowHost()) {
    auto* html_input_element = DynamicTo<HTMLInputElement>(node);
    if (html_input_element &&
        html_input_element->FormControlType() == FormControlType::kInputFile) {
      return html_input_element;
    }
  }
  return nullptr;
}

// This can return null if an empty document is loaded.
static Element* ElementUnderMouse(Document* document_under_mouse,
                                  const PhysicalOffset& point) {
  HitTestRequest request(HitTestRequest::kReadOnly | HitTestRequest::kActive);
  HitTestLocation location(point);
  HitTestResult result(request, location);
  document_under_mouse->GetLayoutView()->HitTest(location, result);

  Node* n = result.InnerNode();
  while (n && !n->IsElementNode())
    n = n->ParentOrShadowHostNode();
  if (n && n->IsInShadowTree())
    n = n->OwnerShadowHost();

  return To<Element>(n);
}

bool DragController::TryDocumentDrag(DragData* drag_data,
                                     DragDestinationAction action_mask,
                                     DragOperation& drag_operation,
                                     LocalFrame& local_root) {
  DCHECK(drag_data);

  if (!document_under_mouse_)
    return false;

  // This is the renderer-side check for https://crbug.com/59081 to prevent
  // drags between cross-origin frames within the same page. This logic relies
  // on the browser process to have already filtered out any drags that might
  // span distinct `blink::Page` objects but still be part of the same logical
  // page. Otherwise, `drag_initiator_` will be null here and the drag will
  // incorrectly be allowed to proceed.
  //
  // Note: One example where the drag start frame and the drop target frame can
  // be part of the same logical page, but belong to different `blink::Page`
  // instances is if the two frames are hosted in different renderer processes.
  auto* under_mouse_origin =
      document_under_mouse_->GetExecutionContext()->GetSecurityOrigin();
  if (drag_initiator_ &&
      !under_mouse_origin->CanAccess(drag_initiator_->GetSecurityOrigin())) {
    return false;
  }

  bool is_handling_drag = false;
  if (action_mask & kDragDestinationActionDHTML) {
    is_handling_drag = TryDHTMLDrag(drag_data, drag_operation, local_root);
    // Do not continue if m_documentUnderMouse has been reset by tryDHTMLDrag.
    // tryDHTMLDrag fires dragenter event. The event listener that listens
    // to this event may create a nested run loop (open a modal dialog),
    // which could process dragleave event and reset m_documentUnderMouse in
    // dragExited.
    if (!document_under_mouse_)
      return false;
  }

  // It's unclear why this check is after tryDHTMLDrag.
  // We send drag events in tryDHTMLDrag and that may be the reason.
  LocalFrameView* frame_view = document_under_mouse_->View();
  if (!frame_view)
    return false;

  if (is_handling_drag) {
    page_->GetDragCaret().Clear();
    return true;
  }

  if ((action_mask & kDragDestinationActionEdit) &&
      CanProcessDrag(drag_data, local_root)) {
    PhysicalOffset point = frame_view->ConvertFromRootFrame(
        PhysicalOffset::FromPointFRound(drag_data->ClientPosition()));
    Element* element = ElementUnderMouse(document_under_mouse_.Get(), point);
    if (!element)
      return false;

    HTMLInputElement* element_as_file_input = AsFileInput(element);
    if (file_input_element_under_mouse_ != element_as_file_input) {
      if (file_input_element_under_mouse_)
        file_input_element_under_mouse_->SetCanReceiveDroppedFiles(false);
      file_input_element_under_mouse_ = element_as_file_input;
    }

    if (!file_input_element_under_mouse_) {
      page_->GetDragCaret().SetCaretPosition(
          document_under_mouse_->GetFrame()->PositionForPoint(point));
    }

    LocalFrame* inner_frame = element->GetDocument().GetFrame();
    drag_operation = DragIsMove(inner_frame->Selection(), drag_data)
                         ? DragOperation::kMove
                         : DragOperation::kCopy;
    if (file_input_element_under_mouse_) {
      bool can_receive_dropped_files = false;
      if (!file_input_element_under_mouse_->IsDisabledFormControl()) {
        can_receive_dropped_files = file_input_element_under_mouse_->Multiple()
                                        ? drag_data->NumberOfFiles() > 0
                                        : drag_data->NumberOfFiles() == 1;
      }
      if (!can_receive_dropped_files)
        drag_operation = DragOperation::kNone;
      file_input_element_under_mouse_->SetCanReceiveDroppedFiles(
          can_receive_dropped_files);
    }

    return true;
  }

  // We are not over an editable region. Make sure we're clearing any prior drag
  // cursor.
  page_->GetDragCaret().Clear();
  if (file_input_element_under_mouse_)
    file_input_element_under_mouse_->SetCanReceiveDroppedFiles(false);
  file_input_element_under_mouse_ = nullptr;
  return false;
}

DragOperation DragController::OperationForLoad(DragData* drag_data,
                                               LocalFrame& local_root) {
  DCHECK(drag_data);
  Document* doc = local_root.DocumentAtPoint(
      PhysicalOffset::FromPointFRound(drag_data->ClientPosition()));

  if (doc &&
      (did_initiate_drag_ || IsA<PluginDocument>(doc) || IsEditable(*doc)))
    return DragOperation::kNone;
  return GetDragOperation(drag_data);
}

// Returns true if node at |point| is editable with populating |dragCaret| and
// |range|, otherwise returns false.
static bool SetSelectionToDragCaret(LocalFrame* frame,
                                    const SelectionInDOMTree& drag_caret,
                                    Range*& range,
                                    const PhysicalOffset& point) {
  frame->Selection().SetSelection(drag_caret, SetSelectionOptions());
  // TODO(crbug.com/40458806): Audit the usage of `UpdateStyleAndLayout`.
  frame->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (!frame->Selection().ComputeVisibleSelectionInDOMTree().IsNone()) {
    return frame->Selection()
        .ComputeVisibleSelectionInDOMTree()
        .IsContentEditable();
  }

  const PositionWithAffinity& position = frame->PositionForPoint(point);
  if (!position.IsConnected())
    return false;

  frame->Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(position).Build(),
      SetSelectionOptions());
  // TODO(crbug.com/40458806): Audit the usage of `UpdateStyleAndLayout`.
  frame->GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  const VisibleSelection& visible_selection =
      frame->Selection().ComputeVisibleSelectionInDOMTree();
  range = CreateRange(visible_selection.ToNormalizedEphemeralRange());
  return !visible_selection.IsNone() && visible_selection.IsContentEditable();
}

DispatchEventResult DragController::DispatchTextInputEventFor(
    LocalFrame* inner_frame,
    DragData* drag_data) {
  // Layout should be clean due to a hit test performed in |elementUnderMouse|.
  DCHECK(!inner_frame->GetDocument()->NeedsLayoutTreeUpdate());
  DCHECK(page_->GetDragCaret().HasCaret());
  String text = page_->GetDragCaret().IsContentRichlyEditable()
                    ? ""
                    : drag_data->AsPlainText();
  const PositionWithAffinity& caret_position =
      page_->GetDragCaret().CaretPosition();
  DCHECK(caret_position.IsConnected()) << caret_position;
  Element* target = FindEventTargetFrom(
      *inner_frame,
      CreateVisibleSelection(
          SelectionInDOMTree::Builder().Collapse(caret_position).Build()));
  if (!target)
    return DispatchEventResult::kNotCanceled;
  return target->DispatchEvent(
      *TextEvent::CreateForDrop(inner_frame->DomWindow(), text));
}

bool DragController::ConcludeEditDrag(DragData* drag_data) {
  DCHECK(drag_data);

  HTMLInputElement* file_input = file_input_element_under_mouse_;
  if (file_input_element_under_mouse_) {
    file_input_element_under_mouse_->SetCanReceiveDroppedFiles(false);
    file_input_element_under_mouse_ = nullptr;
  }

  if (!document_under_mouse_)
    return false;

  PhysicalOffset point = document_under_mouse_->View()->ConvertFromRootFrame(
      PhysicalOffset::FromPointFRound(drag_data->ClientPosition()));
  Element* element = ElementUnderMouse(document_under_mouse_.Get(), point);
  if (!element)
    return false;
  LocalFrame* inner_frame = element->ownerDocument()->GetFrame();
  DCHECK(inner_frame);

  if (page_->GetDragCaret().HasCaret() &&
      DispatchTextInputEventFor(inner_frame, drag_data) !=
          DispatchEventResult::kNotCanceled)
    return true;

  if (drag_data->ContainsFiles() && file_input) {
    // fileInput should be the element we hit tested for, unless it was made
    // display:none in a drop event handler.
    if (file_input->GetLayoutObject())
      DCHECK_EQ(file_input, element);
    if (file_input->IsDisabledFormControl())
      return false;

    return file_input->ReceiveDroppedFiles(drag_data);
  }

  if (!page_->GetDragController().CanProcessDrag(
          drag_data, inner_frame->LocalFrameRoot())) {
    page_->GetDragCaret().Clear();
    return false;
  }

  if (page_->GetDragCaret().HasCaret()) {
    // TODO(crbug.com/40458806): Audit the usage of` UpdateStyleAndLayout`.
    page_->GetDragCaret()
        .CaretPosition()
        .GetPosition()
        .GetDocument()
        ->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  }

  const PositionWithAffinity& caret_position =
      page_->GetDragCaret().CaretPosition();
  if (!caret_position.IsConnected()) {
    // "editing/pasteboard/drop-text-events-sideeffect-crash.html" and
    // "editing/pasteboard/drop-text-events-sideeffect.html" reach here.
    page_->GetDragCaret().Clear();
    return false;
  }
  VisibleSelection drag_caret = CreateVisibleSelection(
      SelectionInDOMTree::Builder().Collapse(caret_position).Build());
  page_->GetDragCaret().Clear();
  // |innerFrame| can be removed by event handler called by
  // |dispatchTextInputEventFor()|.
  if (!inner_frame->Selection().IsAvailable()) {
    // "editing/pasteboard/drop-text-events-sideeffect-crash.html" reaches
    // here.
    return false;
  }
  Range* range = CreateRange(drag_caret.ToNormalizedEphemeralRange());
  Element* root_editable_element =
      inner_frame->Selection()
          .ComputeVisibleSelectionInDOMTreeDeprecated()
          .RootEditableElement();

  // For range to be null a WebKit client must have done something bad while
  // manually controlling drag behaviour
  if (!range)
    return false;
  ResourceFetcher* fetcher = range->OwnerDocument().Fetcher();
  ResourceCacheValidationSuppressor validation_suppressor(fetcher);

  // Start new Drag&Drop command group, invalidate previous command group.
  // Assume no other places is firing |DeleteByDrag| and |InsertFromDrop|.
  inner_frame->GetEditor().RegisterCommandGroup(
      MakeGarbageCollected<DragAndDropCommand>(*inner_frame->GetDocument()));

  bool drag_is_move = DragIsMove(inner_frame->Selection(), drag_data);
  bool is_richly_editable_position =
      IsRichlyEditablePosition(drag_caret.Anchor());

  if (drag_is_move || is_richly_editable_position) {
    DragSourceType drag_source_type = DragSourceType::kHTMLSource;
    if (!RuntimeEnabledFeatures::
            DropUrlAsPlainTextInPlainTextOnlyEditablePositionEnabled()) {
      is_richly_editable_position = true;
    }
    DocumentFragment* fragment = DocumentFragmentFromDragData(
        drag_data, inner_frame, range, true, drag_source_type,
        is_richly_editable_position);
    if (!fragment)
      return false;

    if (drag_is_move) {
      // NSTextView behavior is to always smart delete on moving a selection,
      // but only to smart insert if the selection granularity is word
      // granularity.
      const DeleteMode delete_mode =
          inner_frame->GetEditor().SmartInsertDeleteEnabled()
              ? DeleteMode::kSmart
              : DeleteMode::kSimple;
      const InsertMode insert_mode =
          (delete_mode == DeleteMode::kSmart &&
           inner_frame->Selection().Granularity() == TextGranularity::kWord &&
           drag_data->CanSmartReplace())
              ? InsertMode::kSmart
              : InsertMode::kSimple;

      if (!inner_frame->GetEditor().DeleteSelectionAfterDraggingWithEvents(
              FindEventTargetFrom(
                  *inner_frame,
                  inner_frame->Selection()
                      .ComputeVisibleSelectionInDOMTreeDeprecated()),
              delete_mode, drag_caret.Anchor())) {
        return false;
      }

      inner_frame->Selection().SetSelection(
          SelectionInDOMTree::Builder()
              .SetBaseAndExtent(EphemeralRange(range))
              .Build(),
          SetSelectionOptions());
      if (inner_frame->Selection().IsAvailable()) {
        DCHECK(document_under_mouse_);
        if (!inner_frame->GetEditor().ReplaceSelectionAfterDraggingWithEvents(
                element, drag_data, fragment, range, insert_mode,
                drag_source_type))
          return false;
      }
    } else {
      if (SetSelectionToDragCaret(inner_frame, drag_caret.AsSelection(), range,
                                  point)) {
        DCHECK(document_under_mouse_);
        if (!inner_frame->GetEditor().ReplaceSelectionAfterDraggingWithEvents(
                element, drag_data, fragment, range,
                drag_data->CanSmartReplace() ? InsertMode::kSmart
                                             : InsertMode::kSimple,
                drag_source_type))
          return false;
      }
    }
  } else {
    String text = drag_data->AsPlainText();
    if (text.empty())
      return false;

    if (SetSelectionToDragCaret(inner_frame, drag_caret.AsSelection(), range,
                                point)) {
      DCHECK(document_under_mouse_);
      if (!inner_frame->GetEditor().ReplaceSelectionAfterDraggingWithEvents(
              element, drag_data,
              CreateFragmentFromText(EphemeralRange(range), text), range,
              InsertMode::kSimple, DragSourceType::kPlainTextSource))
        return false;
    }
  }

  if (root_editable_element) {
    if (LocalFrame* frame = root_editable_element->GetDocument().GetFrame()) {
      frame->GetEventHandler().UpdateDragStateAfterEditDragIfNeeded(
          root_editable_element);
    }
  }

  return true;
}

bool DragController::CanProcessDrag(DragData* drag_data,
                                    LocalFrame& local_root) {
  DCHECK(drag_data);

  if (!drag_data->ContainsCompatibleContent())
    return false;

  if (!local_root.ContentLayoutObject())
    return false;

  const PhysicalOffset point_in_local_root =
      local_root.View()->ConvertFromRootFrame(
          PhysicalOffset::FromPointFRound(drag_data->ClientPosition()));

  const HitTestResult result =
      local_root.GetEventHandler().HitTestResultAtLocation(
          HitTestLocation(point_in_local_root));

  if (!result.InnerNode())
    return false;

  if (drag_data->ContainsFiles() && AsFileInput(result.InnerNode()))
    return true;

  if (auto* plugin = DynamicTo<HTMLPlugInElement>(result.InnerNode())) {
    if (!plugin->CanProcessDrag() && !IsEditable(*result.InnerNode()))
      return false;
  } else if (!IsEditable(*result.InnerNode())) {
    return false;
  }

  if (did_initiate_drag_ &&
      document_under_mouse_ ==
          (drag_initiator_ ? drag_initiator_->document() : nullptr)) {
    const PhysicalOffset point_in_frame =
        result.InnerNode()
            ->GetDocument()
            .GetFrame()
            ->View()
            ->ConvertFromRootFrame(
                PhysicalOffset::FromPointFRound(drag_data->ClientPosition()));
    return !result.IsSelected(HitTestLocation(point_in_frame));
  }

  return true;
}

static DragOperation DefaultOperationForDrag(DragOperationsMask src_op_mask) {
  // This is designed to match IE's operation fallback for the case where
  // the page calls preventDefault() in a drag event but doesn't set dropEffect.
  if (src_op_mask == kDragOperationEvery)
    return DragOperation::kCopy;
  if (src_op_mask == kDragOperationNone)
    return DragOperation::kNone;
  if (src_op_mask & kDragOperationMove)
    return DragOperation::kMove;
  if (src_op_mask & kDragOperationCopy)
    return DragOperation::kCopy;
  if (src_op_mask & kDragOperationLink)
    return DragOperation::kLink;

  return DragOperation::kNone;
}

bool DragController::TryDHTMLDrag(DragData* drag_data,
                                  DragOperation& operation,
                                  LocalFrame& local_root) {
  DCHECK(drag_data);
  DCHECK(document_under_mouse_);
  if (!local_root.View())
    return false;

  DataTransferAccessPolicy policy = DataTransferAccessPolicy::kTypesReadable;
  DataTransfer* data_transfer = CreateDraggingDataTransfer(policy, drag_data);
  DragOperati
"""


```