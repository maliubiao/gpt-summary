Response:
My thought process to answer the request involves several steps:

1. **Understanding the Goal:** The main goal is to analyze the provided C++ code snippet from `context_menu_controller.cc` in the Chromium Blink engine. The request asks for the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common user/programming errors, user interaction leading to this code, and a summary of its functions (for this first part).

2. **Initial Code Scan and Keyword Identification:** I first quickly scan the code for prominent keywords and included headers. This gives me a high-level overview. Key terms like "ContextMenu," "MouseEvent," "HitTestResult," "Selection," "Editor," "HTML," "Canvas," "Video," "Audio," "Plugin," "SpellCheck," and the included headers (`#include`) point towards the file's core purpose. The presence of `third_party/blink/public/common/context_menu_data/` strongly suggests handling context menu related data structures.

3. **Deconstructing Functionality Based on Code Sections:** I then go through the code section by section, focusing on the purpose of each function and significant code blocks:

    * **Copyright and Includes:**  Acknowledge the copyright information and note the various included headers. These headers provide clues about the dependencies and functionalities the class relies on. For instance, `#include "third_party/blink/renderer/core/page/page.h"` tells me it interacts with the `Page` class.

    * **Namespace and Helper Functions:** Identify the `blink` namespace and any private helper functions. `SetAutofillData` suggests handling autofill information. `UnvisitedNodeOrAncestorHasContextMenuListener` hints at traversing the DOM tree for event listeners. `EnumToBitmask` is a utility function for flag manipulation.

    * **Constructor and Destructor:** Note the basic setup of the `ContextMenuController` class.

    * **`Trace`:**  Recognize this as a standard Chromium tracing method for debugging and memory management.

    * **`ClearContextMenu`:**  Understand its role in resetting the context menu state.

    * **`DocumentDetached`:** See how it handles document removal and potential invalidation of the context menu.

    * **`HandleContextMenuEvent`:** Identify this as the entry point for handling right-click events (or similar context menu triggers). It sets up the location and calls `ShowContextMenu`.

    * **`ShowContextMenuAtPoint`:** A programmatic way to trigger the context menu at a specific point.

    * **`CustomContextMenuItemSelected`:**  Deals with actions chosen from the context menu.

    * **`GetContextMenuNodeWithImageContents`:**  This is a crucial function for determining if an image is the target of the context menu, even if it's behind other elements. I pay close attention to the logic involving `HitTestResult`, checks for event listeners, cross-frame boundaries, and opaque nodes. The histogram logging (`base::UmaHistogramCounts1000`) provides insight into performance monitoring.

    * **`ContextMenuImageNodeForFrame` and `ContextMenuNodeForFrame`:** These functions retrieve the relevant image or general node associated with the context menu, specifically for a given frame. The caching mechanism (`image_selection_cached_result_`) is important here.

    * **`CustomContextMenuAction` and `ContextMenuClosed`:** These handle further stages of the context menu lifecycle.

    * **`ComputeEditFlags`:** This function calculates which editing actions are available based on the current selection and the document's state.

    * **`ComputeSelectionRect`:** This calculates the bounding rectangle of the current text selection, taking into account different frames and the visual viewport.

    * **`ShouldShowContextMenuFromTouch`:**  Determines whether a context menu should appear on touch interactions based on various criteria.

    * **`ShowContextMenu` (the main logic):** This is the heart of the file. I meticulously analyze its steps:
        * Checking `ContextMenuAllowedScope`.
        * Resetting the `context_menu_client_receiver_`.
        * Performing a `HitTestResult`.
        * Handling keyboard-initiated context menus.
        * Extracting data like link URLs, titles, alt text.
        * Handling media elements (video, audio, plugins), including their specific properties and actions.
        * Detecting canvas elements.
        * Handling text selection and extracting the selected text.
        * Checking for text fragments/highlights.
        * Handling editable content and spellchecking (including asynchronous spellchecking).

4. **Identifying Relationships with Web Technologies:** As I go through the code, I explicitly look for interactions with HTML, CSS, and JavaScript concepts:

    * **HTML:**  The code directly interacts with various HTML elements (`HTMLAnchorElement`, `HTMLImageElement`, `HTMLVideoElement`, etc.). The logic for determining the context menu's content often depends on the type of HTML element the user right-clicked on.

    * **CSS:** While not directly manipulating CSS properties, the `HitTestResult` and the concept of "opaque nodes" indirectly relate to how CSS rendering affects the ability to target elements with the context menu. The visual viewport calculations also involve the rendered layout.

    * **JavaScript:** The presence of event listeners (checked by `UnvisitedNodeOrAncestorHasContextMenuListener`) is a direct tie-in to JavaScript. The context menu can be triggered by JavaScript events, and custom context menu items can execute JavaScript.

5. **Constructing Examples and Scenarios:**  Based on my understanding, I create illustrative examples for logical reasoning, user errors, and user actions:

    * **Logical Reasoning:** I focus on the `GetContextMenuNodeWithImageContents` function and illustrate how the code determines the image even if it's behind other elements. I create a scenario with overlapping divs and an image.

    * **User Errors:** I consider common user actions that might lead to unexpected behavior or limitations, like trying to access the context menu on an image behind an opaque element.

    * **User Actions:** I trace the most common user interaction: a right-click on various elements (link, image, text, video) and explain how the code processes this event.

6. **Formulating the Summary:**  Finally, I synthesize my findings into a concise summary that captures the core responsibilities of the `ContextMenuController`.

7. **Review and Refinement:** I review my entire answer for clarity, accuracy, and completeness, ensuring that all parts of the request are addressed. I make sure the examples are clear and easy to understand. I double-check for any inconsistencies or areas where my explanation could be improved. For instance, ensuring I correctly attributed the influence of CSS through the rendering pipeline rather than direct CSS manipulation in the C++ code.
这是对 `blink/renderer/core/page/context_menu_controller.cc` 文件第一部分的分析和功能归纳。

**功能列举:**

1. **处理上下文菜单事件:**  该文件主要负责处理用户触发的上下文菜单事件（通常是鼠标右键点击）。它接收鼠标事件，确定上下文菜单应该显示的位置和内容。

2. **执行命中测试 (Hit Testing):**  当用户触发上下文菜单时，`ContextMenuController` 使用命中测试来确定用户点击的具体元素。这包括确定点击位置下的节点、图像、链接、媒体元素等。

3. **构建上下文菜单数据:**  根据命中测试的结果，该文件会构建一个 `ContextMenuData` 对象，其中包含了将要显示在上下文菜单中的各种信息和选项。这些信息包括：
    *  选中的文本
    *  链接 URL
    *  图像/媒体 URL
    *  是否可编辑
    *  媒体类型 (图像、视频、音频、插件、Canvas)
    *  编辑标志 (剪切、复制、粘贴等)
    *  拼写检查建议

4. **与各种 DOM 元素交互:**  代码中包含了大量的与不同 HTML 元素类型交互的逻辑，例如：
    * `HTMLAnchorElement` (链接)
    * `HTMLImageElement` (图像)
    * `HTMLVideoElement` (视频)
    * `HTMLAudioElement` (音频)
    * `HTMLCanvasElement` (画布)
    * `HTMLInputElement` (输入框)
    * `HTMLFormElement` (表单)
    * `HTMLObjectElement`, `HTMLEmbedElement` (插件)

5. **处理图像内容:**  特别关注用户右键点击图像的情况，包括直接点击图像和点击覆盖在图像上的其他元素（需要进行穿透测试）。它可以获取图像的 URL，并判断是否可以保存或在新标签页中打开。

6. **处理媒体内容:**  处理视频和音频元素的上下文菜单项，例如播放/暂停、静音、循环、全屏、画中画等。

7. **处理插件:**  支持插件的上下文菜单，允许插件提供自定义的上下文菜单项。

8. **处理文本选择:**  如果用户选中了文本，上下文菜单会包含与文本相关的操作，例如复制、剪切、粘贴、查找等。

9. **处理可编辑内容:**  对于可编辑的区域（例如 `<textarea>` 或设置了 `contenteditable` 属性的元素），上下文菜单会包含编辑相关的选项，例如撤销、重做、剪切、复制、粘贴、删除、全选。

10. **与拼写检查器交互:**  对于可编辑区域，当用户右键点击被标记为拼写错误的单词时，会从拼写检查器获取建议并显示在上下文菜单中。

11. **处理来自触摸屏的上下文菜单:**  根据设置和上下文数据判断是否应该显示触摸屏上的上下文菜单。

12. **记录统计信息:** 使用 `base::UmaHistogram...` 函数记录关于上下文菜单操作的统计信息，例如图像选择的深度和结果。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  该文件直接操作和检查各种 HTML 元素。
    * **举例:** 当用户右键点击一个 `<img>` 标签时，代码会识别出这是一个图像元素，并从 `src` 属性中提取图像的 URL，以便在上下文菜单中提供 "在新标签页中打开图片" 或 "保存图片" 等选项。

* **JavaScript:**  该文件会检查元素上是否注册了 `contextmenu` 事件监听器。
    * **举例:** 如果一个网站使用 JavaScript 为某个 `<div>` 元素添加了自定义的 `contextmenu` 事件处理函数，当用户在该 `<div>` 上右键点击时，`UnvisitedNodeOrAncestorHasContextMenuListener` 函数会检测到这个监听器，并且可能会阻止默认上下文菜单的显示，或者影响默认上下文菜单的内容。

* **CSS:**  CSS 的渲染结果会影响命中测试的结果。
    * **举例:**  如果一个 `<div>` 元素使用 CSS 设置了 `opacity: 0.5;`，并且覆盖在一个 `<img>` 元素上，命中测试仍然可能穿透这个半透明的 `<div>` 并选中下面的 `<img>`。 然而，如果 `<div>` 设置了不透明的背景色，可能会阻止选中下面的图像。 `GetContextMenuNodeWithImageContents` 中对 `BackgroundIsKnownToBeOpaqueInRect` 的检查就体现了这一点。

**逻辑推理的假设输入与输出:**

**假设输入:** 用户在以下 HTML 结构中的图像上点击鼠标右键：

```html
<div style="background-color: white;">
  <img src="image.jpg">
</div>
```

**输出:**  `GetContextMenuNodeWithImageContents` 函数会进行以下逻辑推理：

1. **命中测试首先命中 `<div>` 元素。**
2. **检查 `<div>` 是否有上下文菜单监听器。** (假设没有)
3. **检查 `<div>` 的背景是否不透明。** (假设 `background-color: white;` 被认为是不透明的)
4. **继续向下穿透，命中 `<img>` 元素。**
5. **判断 `<img>` 是一个图像元素，且 `src` 属性不为空。**
6. **输出: `found_image_node` 指向该 `<img>` 元素，并且 `outcome` 包含 `ImageSelectionOutcome::kImageFoundPenetrating`。**

**假设输入:** 用户在一个可编辑的 `<textarea>` 元素中选中了一些文本，并点击鼠标右键。

**输出:**

1. **命中测试会确定用户点击在 `<textarea>` 元素内。**
2. **代码会判断该元素是可编辑的 (`result.IsContentEditable()` 为真)。**
3. **`ComputeEditFlags` 会根据当前的编辑状态 (是否可以撤销、重做、剪切、复制、粘贴等) 设置 `data.edit_flags`。**
4. **`data.selected_text` 会被设置为用户选中的文本。**
5. **上下文菜单将包含与文本编辑相关的选项，例如 "剪切"、"复制"、"粘贴" 等。**

**用户或编程常见的使用错误举例说明:**

* **用户错误:**  用户期望在一个被完全透明的 `<div>` 覆盖的图像上点击右键时，上下文菜单显示图像相关的选项，但实际上由于命中测试首先命中了 `<div>`，导致上下文菜单显示的是 `<div>` 相关的选项 (如果没有自定义的 `contextmenu` 监听器)。 `GetContextMenuNodeWithImageContents` 的穿透测试可以缓解这个问题，但如果中间层是不透明的，则无法穿透。

* **编程错误:**  开发者可能错误地阻止了默认的上下文菜单行为，但没有提供替代的上下文菜单。例如，使用 JavaScript 的 `event.preventDefault()` 阻止了 `contextmenu` 事件，但没有调用任何显示自定义菜单的逻辑，导致用户无法使用上下文菜单。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户执行操作触发上下文菜单:**  最常见的操作是用户在网页上点击鼠标右键。其他触发方式可能包括：
    * 在键盘上按下上下文菜单键 (通常在右 `Ctrl` 键附近)。
    * 长按触摸屏。
    * 某些辅助功能触发。

2. **浏览器捕获到上下文菜单事件:** 操作系统或浏览器内核捕获到用户的操作，并将其转换为一个上下文菜单事件 (例如，`MouseEvent` 类型为 `contextmenu`)。

3. **事件被路由到渲染进程:** 浏览器进程将该事件传递给负责渲染当前网页的渲染进程 (Blink)。

4. **事件到达 `EventHandler`:** 渲染进程的 `EventHandler` 接收到该事件。

5. **`EventHandler` 调用 `ContextMenuController::HandleContextMenuEvent`:** `EventHandler` 判断这是一个上下文菜单事件，并将其传递给 `ContextMenuController` 的 `HandleContextMenuEvent` 方法。

6. **`HandleContextMenuEvent` 执行命中测试:**  `HandleContextMenuEvent` 使用点击的坐标调用 `frame->GetEventHandler().HitTestResultAtLocation()` 进行命中测试，以确定用户点击的具体元素。

7. **构建 `ContextMenuData`:**  根据命中测试的结果，以及对不同元素类型的判断，`ShowContextMenu` 函数会逐步构建 `ContextMenuData` 对象，填充各种属性。

8. **将上下文菜单数据发送到浏览器进程:**  `ContextMenuController` 将构建好的 `ContextMenuData` 通过 IPC (进程间通信) 发送回浏览器进程。

9. **浏览器进程显示上下文菜单:**  浏览器进程根据接收到的 `ContextMenuData`，生成并显示原生的上下文菜单。

**功能归纳 (第一部分):**

总的来说，`blink/renderer/core/page/context_menu_controller.cc` 文件的第一部分主要负责 **接收和处理用户的上下文菜单触发事件，并通过执行命中测试和分析目标元素的信息，构建用于生成上下文菜单的数据结构 (ContextMenuData)。**  它深入地与 HTML DOM 结构交互，识别不同类型的元素 (链接、图像、媒体、可编辑内容等)，并提取相关信息，以便为用户提供相应的上下文菜单选项。该部分还处理了图像元素的特殊逻辑，即使图像被其他元素遮挡也尝试获取图像信息。

### 提示词
```
这是目录为blink/renderer/core/page/context_menu_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007 Apple Inc. All rights reserved.
 * Copyright (C) 2010 Igalia S.L
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

#include "third_party/blink/renderer/core/page/context_menu_controller.h"

#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/ranges/algorithm.h"
#include "components/shared_highlighting/core/common/shared_highlighting_features.h"
#include "third_party/blink/public/common/context_menu_data/context_menu_data.h"
#include "third_party/blink/public/common/context_menu_data/edit_flags.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_menu_source_type.h"
#include "third_party/blink/public/common/navigation/impression.h"
#include "third_party/blink/public/mojom/context_menu/context_menu.mojom-blink.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_plugin.h"
#include "third_party/blink/public/web/web_text_check_client.h"
#include "third_party/blink/renderer/core/annotation/annotation_agent_container_impl.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_target.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/editing_tri_state.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/selection_controller.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/fragment_directive/text_fragment_handler.h"
#include "third_party/blink/renderer/core/frame/attribution_src_loader.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/picture_in_picture_controller.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/frame/web_frame_widget_impl.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/html_anchor_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_frame_element_base.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/loader/document_loader.h"
#include "third_party/blink/renderer/core/page/context_menu_provider.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/exported/wrapped_resource_response.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

void SetAutofillData(Node* node, ContextMenuData& data) {
  if (auto* form_control = DynamicTo<HTMLFormControlElement>(node)) {
    data.form_control_type = form_control->FormControlType();
    data.field_renderer_id = form_control->GetDomNodeId();
    if (auto* form = form_control->Form()) {
      data.form_renderer_id = form->GetDomNodeId();
    } else {
      data.form_renderer_id = 0;
    }
  }
  if (auto* html_element =
          node ? DynamicTo<HTMLElement>(RootEditableElement(*node)) : nullptr) {
    ContentEditableType content_editable =
        html_element->contentEditableNormalized();
    data.is_content_editable_for_autofill =
        (content_editable == ContentEditableType::kPlaintextOnly ||
         content_editable == ContentEditableType::kContentEditable) &&
        !DynamicTo<HTMLFormElement>(node) &&
        !DynamicTo<HTMLFormControlElement>(node);
    if (data.is_content_editable_for_autofill) {
      data.field_renderer_id = html_element->GetDomNodeId();
      data.form_renderer_id = html_element->GetDomNodeId();
    }
  }
}

// Returns true if node or any of its ancestors have a context menu event
// listener. Uses already_visited_nodes to track nodes which have already
// been checked across multiple calls to this function, which could cause
// the output to be false despite having an ancestor context menu listener.
bool UnvisitedNodeOrAncestorHasContextMenuListener(
    Node* node,
    HeapHashSet<Member<Node>>& already_visited_nodes) {
  Node* current_node_for_parent_traversal = node;
  while (current_node_for_parent_traversal != nullptr) {
    if (current_node_for_parent_traversal->HasEventListeners(
            event_type_names::kContextmenu)) {
      return true;
    }
    // If we've already checked this node, all of its ancestors must not
    // have had listeners (or, we already detected a listener and broke out
    // early).
    if (!already_visited_nodes.insert(current_node_for_parent_traversal)
             .is_new_entry) {
      break;
    }
    current_node_for_parent_traversal =
        current_node_for_parent_traversal->parentNode();
  }
  return false;
}

template <class enumType>
uint32_t EnumToBitmask(enumType outcome) {
  return 1 << static_cast<uint8_t>(outcome);
}

}  // namespace

ContextMenuController::ContextMenuController(Page* page) : page_(page) {}

ContextMenuController::~ContextMenuController() = default;

void ContextMenuController::Trace(Visitor* visitor) const {
  visitor->Trace(page_);
  visitor->Trace(menu_provider_);
  visitor->Trace(hit_test_result_);
  visitor->Trace(context_menu_client_receiver_);
  visitor->Trace(image_selection_cached_result_);
}

void ContextMenuController::ClearContextMenu() {
  if (menu_provider_)
    menu_provider_->ContextMenuCleared();
  menu_provider_ = nullptr;
  context_menu_client_receiver_.reset();
  hit_test_result_ = HitTestResult();
  image_selection_cached_result_ = nullptr;
}

void ContextMenuController::DocumentDetached(Document* document) {
  if (Node* inner_node = hit_test_result_.InnerNode()) {
    // Invalidate the context menu info if its target document is detached.
    if (inner_node->GetDocument() == document)
      ClearContextMenu();
  }
}

void ContextMenuController::HandleContextMenuEvent(MouseEvent* mouse_event) {
  DCHECK(mouse_event->type() == event_type_names::kContextmenu);
  LocalFrame* frame = mouse_event->target()->ToNode()->GetDocument().GetFrame();
  PhysicalOffset location =
      PhysicalOffset::FromPointFRound(mouse_event->AbsoluteLocation());

  if (ShowContextMenu(frame, location, mouse_event->GetMenuSourceType(),
                      mouse_event))
    mouse_event->SetDefaultHandled();
}

void ContextMenuController::ShowContextMenuAtPoint(
    LocalFrame* frame,
    float x,
    float y,
    ContextMenuProvider* menu_provider) {
  menu_provider_ = menu_provider;
  if (!ShowContextMenu(frame, PhysicalOffset(LayoutUnit(x), LayoutUnit(y)),
                       kMenuSourceNone))
    ClearContextMenu();
}

void ContextMenuController::CustomContextMenuItemSelected(unsigned action) {
  if (!menu_provider_)
    return;
  menu_provider_->ContextMenuItemSelected(action);
  ClearContextMenu();
}

Node* ContextMenuController::GetContextMenuNodeWithImageContents() {
  uint32_t outcome = 0;
  uint32_t hit_test_depth = 0;
  LocalFrame* top_hit_frame =
      hit_test_result_.InnerNode()->GetDocument().GetFrame();
  Node* found_image_node = nullptr;
  HeapHashSet<Member<Node>> already_visited_nodes_for_context_menu_listener;

  for (const auto& raw_node : hit_test_result_.ListBasedTestResult()) {
    hit_test_depth++;
    Node* node = raw_node.Get();

    // Execute context menu listener and cross frame checks before image check
    // because these checks should also apply to the image node itself before
    // breaking.
    if (UnvisitedNodeOrAncestorHasContextMenuListener(
            node, already_visited_nodes_for_context_menu_listener)) {
      outcome |=
          EnumToBitmask(ImageSelectionOutcome::kFoundContextMenuListener);
      // Don't break because it allows us to log the failure reason only
      // if an image node was otherwise available lower in the hit test.
    }
    if (top_hit_frame != node->GetDocument().GetFrame()) {
      outcome |= EnumToBitmask(ImageSelectionOutcome::kBlockedByCrossFrameNode);
      // Don't break because it allows us to log the failure reason only
      // if an image node was otherwise available lower in the hit test.
    }

    if (IsA<HTMLCanvasElement>(node) ||
        !HitTestResult::AbsoluteImageURL(node).IsEmpty()) {
      found_image_node = node;

      if (hit_test_depth == 1) {
        outcome |= EnumToBitmask(ImageSelectionOutcome::kImageFoundStandard);
        // The context menu listener check is only necessary when penetrating,
        // so clear the bit so we don't want to log it if the image was on top.
        outcome &=
            ~EnumToBitmask(ImageSelectionOutcome::kFoundContextMenuListener);
      } else {
        outcome |= EnumToBitmask(ImageSelectionOutcome::kImageFoundPenetrating);
      }
      break;
    }
    // IMPORTANT: Check after image checks above so that non-transparent
    // image elements don't trigger the opaque check.
    if (node->GetLayoutBox() != nullptr &&
        node->GetLayoutBox()->BackgroundIsKnownToBeOpaqueInRect(
            HitTestLocation::RectForPoint(
                hit_test_result_.PointInInnerNodeFrame()))) {
      outcome |= EnumToBitmask(ImageSelectionOutcome::kBlockedByOpaqueNode);
      // Don't break because it allows us to log the failure reason only
      // if an image node was otherwise available lower in the hit test.
    }
  }

  // Only log if we found an image node within the hit test.
  if (found_image_node != nullptr) {
    base::UmaHistogramCounts1000("Blink.ContextMenu.ImageSelection.Depth",
                                 hit_test_depth);
    for (uint32_t i = 0;
         i <= static_cast<uint8_t>(ImageSelectionOutcome::kMaxValue); i++) {
      unsigned val = 1 << i;
      if (outcome & val) {
        base::UmaHistogramEnumeration(
            "Blink.ContextMenu.ImageSelection.Outcome",
            ImageSelectionOutcome(i));
      }
    }
  }
  // If there is anything preventing this image selection, return nullptr.
  uint32_t blocking_image_selection_mask =
      ~(EnumToBitmask(ImageSelectionOutcome::kImageFoundStandard) |
        EnumToBitmask(ImageSelectionOutcome::kImageFoundPenetrating));
  if (outcome & blocking_image_selection_mask) {
    return nullptr;
  }
  image_selection_cached_result_ = found_image_node;
  return found_image_node;
}

Node* ContextMenuController::ContextMenuImageNodeForFrame(LocalFrame* frame) {
  ImageSelectionRetrievalOutcome outcome;
  // We currently will fail to retrieve an image if another hit test is made
  // on a non-image node is made before retrieval of the image.
  if (!image_selection_cached_result_) {
    outcome = ImageSelectionRetrievalOutcome::kImageNotFound;
  } else if (image_selection_cached_result_->GetDocument().GetFrame() !=
             frame) {
    outcome = ImageSelectionRetrievalOutcome::kCrossFrameRetrieval;
  } else {
    outcome = ImageSelectionRetrievalOutcome::kImageFound;
  }

  base::UmaHistogramEnumeration(
      "Blink.ContextMenu.ImageSelection.RetrievalOutcome", outcome);

  return outcome == ImageSelectionRetrievalOutcome::kImageFound
             ? image_selection_cached_result_
             : nullptr;
}

// TODO(crbug.com/1184297) Cache image node when the context menu is shown and
//    return that rather than refetching.
Node* ContextMenuController::ContextMenuNodeForFrame(LocalFrame* frame) {
  return hit_test_result_.InnerNodeFrame() == frame
             ? hit_test_result_.InnerNodeOrImageMapImage()
             : nullptr;
}

void ContextMenuController::CustomContextMenuAction(uint32_t action) {
  CustomContextMenuItemSelected(action);
}

void ContextMenuController::ContextMenuClosed(const KURL& link_followed) {
  if (link_followed.IsValid()) {
    WebLocalFrameImpl* selected_web_frame =
        WebLocalFrameImpl::FromFrame(hit_test_result_.InnerNodeFrame());
    if (selected_web_frame)
      selected_web_frame->SendPings(link_followed);
  }
  ClearContextMenu();
}

static int ComputeEditFlags(Document& selected_document, Editor& editor) {
  int edit_flags = ContextMenuDataEditFlags::kCanDoNone;
  if (editor.CanUndo())
    edit_flags |= ContextMenuDataEditFlags::kCanUndo;
  if (editor.CanRedo())
    edit_flags |= ContextMenuDataEditFlags::kCanRedo;
  if (editor.CanCut())
    edit_flags |= ContextMenuDataEditFlags::kCanCut;
  if (editor.CanCopy())
    edit_flags |= ContextMenuDataEditFlags::kCanCopy;
  if (editor.CanPaste())
    edit_flags |= ContextMenuDataEditFlags::kCanPaste;
  if (editor.CanDelete())
    edit_flags |= ContextMenuDataEditFlags::kCanDelete;
  if (editor.CanEditRichly())
    edit_flags |= ContextMenuDataEditFlags::kCanEditRichly;
  if (IsA<HTMLDocument>(selected_document) ||
      selected_document.IsXHTMLDocument()) {
    edit_flags |= ContextMenuDataEditFlags::kCanTranslate;
    if (selected_document.queryCommandEnabled("selectAll", ASSERT_NO_EXCEPTION))
      edit_flags |= ContextMenuDataEditFlags::kCanSelectAll;
  }
  return edit_flags;
}

static gfx::Rect ComputeSelectionRect(LocalFrame* selected_frame) {
  gfx::Rect anchor;
  gfx::Rect focus;
  selected_frame->Selection().ComputeAbsoluteBounds(anchor, focus);
  anchor = selected_frame->View()->ConvertToRootFrame(anchor);
  focus = selected_frame->View()->ConvertToRootFrame(focus);

  gfx::Rect combined_rect = anchor;
  combined_rect.UnionEvenIfEmpty(focus);

  // Intersect the selection rect and the visible bounds of the focused_element
  // to ensure the selection rect is visible.
  Document* doc = selected_frame->GetDocument();
  if (doc) {
    if (Element* focused_element = doc->FocusedElement())
      combined_rect.Intersect(focused_element->VisibleBoundsInLocalRoot());
  }

  // TODO(bokan): This method may not work as expected when the local root
  // isn't the main frame since the result won't be transformed and clipped by
  // the visual viewport (which is accessible only from the outermost main
  // frame).
  if (selected_frame->LocalFrameRoot().IsOutermostMainFrame()) {
    VisualViewport& visual_viewport =
        selected_frame->GetPage()->GetVisualViewport();

    gfx::Rect rect_in_visual_viewport =
        visual_viewport.RootFrameToViewport(combined_rect);
    rect_in_visual_viewport.Intersect(gfx::Rect(visual_viewport.Size()));
    return rect_in_visual_viewport;
  }

  return combined_rect;
}

bool ContextMenuController::ShouldShowContextMenuFromTouch(
    const ContextMenuData& data) {
  return page_->GetSettings().GetAlwaysShowContextMenuOnTouch() ||
         !data.link_url.is_empty() ||
         data.media_type == mojom::blink::ContextMenuDataMediaType::kImage ||
         data.media_type == mojom::blink::ContextMenuDataMediaType::kVideo ||
         data.is_editable || data.opened_from_highlight ||
         !data.selected_text.empty();
}

bool ContextMenuController::ShowContextMenu(LocalFrame* frame,
                                            const PhysicalOffset& point,
                                            WebMenuSourceType source_type,
                                            const MouseEvent* mouse_event) {
  // Displaying the context menu in this function is a big hack as we don't
  // have context, i.e. whether this is being invoked via a script or in
  // response to user input (Mouse event WM_RBUTTONDOWN,
  // Keyboard events KeyVK_APPS, Shift+F10). Check if this is being invoked
  // in response to the above input events before popping up the context menu.
  if (!ContextMenuAllowedScope::IsContextMenuAllowed())
    return false;

  if (context_menu_client_receiver_.is_bound())
    context_menu_client_receiver_.reset();

  HitTestRequest::HitTestRequestType type =
      HitTestRequest::kReadOnly | HitTestRequest::kActive |
      HitTestRequest::kPenetratingList | HitTestRequest::kListBased;

  HitTestLocation location(point);
  HitTestResult result(type, location);
  if (frame)
    result = frame->GetEventHandler().HitTestResultAtLocation(location, type);
  if (!result.InnerNodeOrImageMapImage())
    return false;

  // Clear any previously set cached results if we are resetting the hit test
  // result.
  image_selection_cached_result_ = nullptr;

  hit_test_result_ = result;
  result.SetToShadowHostIfInUAShadowRoot();

  LocalFrame* selected_frame = result.InnerNodeFrame();
  // Tests that do not require selection pass mouse_event = nullptr
  if (mouse_event) {
    selected_frame->GetEventHandler()
        .GetSelectionController()
        .UpdateSelectionForContextMenuEvent(
            mouse_event, hit_test_result_,
            PhysicalOffset(ToFlooredPoint(point)));
  }

  ContextMenuData data;
  data.mouse_position = selected_frame->View()->FrameToViewport(
      result.RoundedPointInInnerNodeFrame());

  data.edit_flags = ComputeEditFlags(
      *selected_frame->GetDocument(),
      To<LocalFrame>(page_->GetFocusController().FocusedOrMainFrame())
          ->GetEditor());

  if (mouse_event && source_type == kMenuSourceKeyboard) {
    Node* target_node = mouse_event->target()->ToNode();
    if (target_node && IsA<Element>(target_node)) {
      // Get the url from an explicitly set target, e.g. the focused element
      // when the context menu is evoked from the keyboard. Note: the innerNode
      // could also be set. It is used to identify a relevant inner media
      // element. In most cases, the innerNode will already be set to any
      // relevant inner media element via the median x,y point from the focused
      // element's bounding box. As the media element in most cases fills the
      // entire area of a focused link or button, this generally suffices.
      // Example: When Shift+F10 is used with <a><img></a>, any image-related
      // context menu options, such as open image in new tab, must be presented.
      result.SetURLElement(target_node->EnclosingLinkEventParentOrSelf());
    }
  }
  data.link_url = GURL(result.AbsoluteLinkURL());

  auto* html_element = DynamicTo<HTMLElement>(result.InnerNode());
  if (html_element) {
    data.title_text = html_element->title().Utf8();
    data.alt_text = html_element->AltText().Utf8();
  }
  if (!result.AbsoluteMediaURL().IsEmpty() ||
      result.GetMediaStreamDescriptor() || result.GetMediaSourceHandle()) {
    if (!result.AbsoluteMediaURL().IsEmpty())
      data.src_url = GURL(result.AbsoluteMediaURL());

    // We know that if absoluteMediaURL() is not empty or element has a media
    // stream descriptor or element has a media source handle, then this is a
    // media element.
    auto* media_element = To<HTMLMediaElement>(result.InnerNode());
    if (IsA<HTMLVideoElement>(*media_element)) {
      // A video element should be presented as an audio element when it has an
      // audio track but no video track.
      if (media_element->HasAudio() && !media_element->HasVideo()) {
        data.media_type = mojom::blink::ContextMenuDataMediaType::kAudio;
      } else {
        data.media_type = mojom::blink::ContextMenuDataMediaType::kVideo;
      }

      if (media_element->SupportsPictureInPicture()) {
        data.media_flags |= ContextMenuData::kMediaCanPictureInPicture;
        if (PictureInPictureController::IsElementInPictureInPicture(
                media_element))
          data.media_flags |= ContextMenuData::kMediaPictureInPicture;
      }

      auto* video_element = To<HTMLVideoElement>(media_element);
      if (video_element->HasReadableVideoFrame()) {
        data.media_flags |= ContextMenuData::kMediaHasReadableVideoFrame;
      }
    } else if (IsA<HTMLAudioElement>(*media_element)) {
      data.media_type = mojom::blink::ContextMenuDataMediaType::kAudio;
    }

    data.suggested_filename = media_element->title().Utf8();
    if (media_element->error())
      data.media_flags |= ContextMenuData::kMediaInError;
    if (media_element->paused())
      data.media_flags |= ContextMenuData::kMediaPaused;
    if (media_element->muted())
      data.media_flags |= ContextMenuData::kMediaMuted;
    if (media_element->SupportsLoop())
      data.media_flags |= ContextMenuData::kMediaCanLoop;
    if (media_element->Loop())
      data.media_flags |= ContextMenuData::kMediaLoop;
    if (media_element->SupportsSave())
      data.media_flags |= ContextMenuData::kMediaCanSave;
    if (media_element->HasAudio())
      data.media_flags |= ContextMenuData::kMediaHasAudio;
    if (media_element->HasVideo()) {
      data.media_flags |= ContextMenuData::kMediaHasVideo;
    }
    if (media_element->IsEncrypted()) {
      data.media_flags |= ContextMenuData::kMediaEncrypted;
    }

    // Media controls can be toggled only for video player. If we toggle
    // controls for audio then the player disappears, and there is no way to
    // return it back. Don't set this bit for fullscreen video, since
    // toggling is ignored in that case.
    if (IsA<HTMLVideoElement>(media_element) && media_element->HasVideo() &&
        !media_element->IsFullscreen())
      data.media_flags |= ContextMenuData::kMediaCanToggleControls;
    if (media_element->ShouldShowAllControls())
      data.media_flags |= ContextMenuData::kMediaControls;
  } else if (IsA<HTMLObjectElement>(*result.InnerNode()) ||
             IsA<HTMLEmbedElement>(*result.InnerNode())) {
    if (auto* embedded = DynamicTo<LayoutEmbeddedContent>(
            result.InnerNode()->GetLayoutObject())) {
      WebPluginContainerImpl* plugin_view = embedded->Plugin();
      if (plugin_view) {
        data.media_type = mojom::blink::ContextMenuDataMediaType::kPlugin;

        WebPlugin* plugin = plugin_view->Plugin();
        data.link_url = GURL(KURL(plugin->LinkAtPosition(data.mouse_position)));

        auto* plugin_element = To<HTMLPlugInElement>(result.InnerNode());
        data.src_url = GURL(
            plugin_element->GetDocument().CompleteURL(plugin_element->Url()));

        // Figure out the text selection and text edit flags.
        WebString text = plugin->SelectionAsText();
        if (!text.IsEmpty()) {
          data.selected_text = text.Utf8();
          if (plugin->CanCopy())
            data.edit_flags |= ContextMenuDataEditFlags::kCanCopy;
        }
        bool plugin_can_edit_text = plugin->CanEditText();
        if (plugin_can_edit_text) {
          data.is_editable = true;
          if (!!(data.edit_flags & ContextMenuDataEditFlags::kCanCopy))
            data.edit_flags |= ContextMenuDataEditFlags::kCanCut;
          data.edit_flags |= ContextMenuDataEditFlags::kCanPaste;

          if (plugin->HasEditableText())
            data.edit_flags |= ContextMenuDataEditFlags::kCanSelectAll;

          if (plugin->CanUndo())
            data.edit_flags |= ContextMenuDataEditFlags::kCanUndo;
          if (plugin->CanRedo())
            data.edit_flags |= ContextMenuDataEditFlags::kCanRedo;
        }
        // Disable translation for plugins.
        data.edit_flags &= ~ContextMenuDataEditFlags::kCanTranslate;

        // Figure out the media flags.
        data.media_flags |= ContextMenuData::kMediaCanSave;
        if (plugin->SupportsPaginatedPrint())
          data.media_flags |= ContextMenuData::kMediaCanPrint;

        // Add context menu commands that are supported by the plugin.
        // Only show rotate view options if focus is not in an editable text
        // area.
        if (!plugin_can_edit_text && plugin->CanRotateView())
          data.media_flags |= ContextMenuData::kMediaCanRotate;
      }
    }
  } else {
    // Check image media last to ensure that penetrating image selection
    // does not override a topmost media element.
    // TODO(benwgold): Consider extending penetration to all media types.
    Node* potential_image_node = result.InnerNodeOrImageMapImage();
    SCOPED_BLINK_UMA_HISTOGRAM_TIMER(
        "Blink.ContextMenu.ImageSelection.ElapsedTime");
    potential_image_node = GetContextMenuNodeWithImageContents();

    if (potential_image_node != nullptr &&
        IsA<HTMLCanvasElement>(potential_image_node)) {
      data.media_type = mojom::blink::ContextMenuDataMediaType::kCanvas;
      // TODO(crbug.com/1267243): Support WebGPU canvas.
      data.has_image_contents =
          !To<HTMLCanvasElement>(potential_image_node)->IsWebGPU();
    } else if (potential_image_node != nullptr &&
               !HitTestResult::AbsoluteImageURL(potential_image_node)
                    .IsEmpty()) {
      data.src_url =
          GURL(HitTestResult::AbsoluteImageURL(potential_image_node));
      data.media_type = mojom::blink::ContextMenuDataMediaType::kImage;
      data.media_flags |= ContextMenuData::kMediaCanPrint;
      data.has_image_contents =
          HitTestResult::GetImage(potential_image_node) &&
          !HitTestResult::GetImage(potential_image_node)->IsNull();
    }
  }
  // If it's not a link, an image, a media element, or an image/media link,
  // show a selection menu or a more generic page menu.
  if (selected_frame->GetDocument()->Loader()) {
    data.frame_encoding =
        selected_frame->GetDocument()->EncodingName().GetString().Utf8();
  }

  data.selection_start_offset = 0;
  // HitTestResult::isSelected() ensures clean layout by performing a hit test.
  // If source_type is |kMenuSourceAdjustSelection| or
  // |kMenuSourceAdjustSelectionReset| we know the original HitTestResult in
  // SelectionController passed the inside check already, so let it pass.
  if (result.IsSelected(location) ||
      source_type == kMenuSourceAdjustSelection ||
      source_type == kMenuSourceAdjustSelectionReset) {
    // Remove any unselectable content from the selected text.
    data.selected_text =
        selected_frame
            ->SelectedText(TextIteratorBehavior::Builder()
                               .SetSkipsUnselectableContent(true)
                               .Build())
            .Utf8();
    WebRange range =
        selected_frame->GetInputMethodController().GetSelectionOffsets();
    // TODO(crbug.com/40093243): `range.StartOffset()` shouldn't be negative but
    // it happens. crbug.com/40093243#comment28 suggested not to show context
    // menu. For now, prefer showing it at wrong place/data than not showing.
    if (range.StartOffset() >= 0) {
      data.selection_start_offset = range.StartOffset();
    }
    if (!result.IsContentEditable()) {
      TextFragmentHandler::OpenedContextMenuOverSelection(selected_frame);
      AnnotationAgentContainerImpl* annotation_container =
          AnnotationAgentContainerImpl::CreateIfNeeded(
              *selected_frame->GetDocument());
      annotation_container->OpenedContextMenuOverSelection();
    }
  }

  // If there is a text fragment at the same location as the click indicate that
  // the context menu is being opened from an existing highlight.
  if (result.InnerNodeFrame()) {
    result.InnerNodeFrame()->View()->UpdateAllLifecyclePhasesExceptPaint(
        DocumentUpdateReason::kHitTest);
    if (TextFragmentHandler::IsOverTextFragment(result)) {
      data.opened_from_highlight = true;
    }
  }

  if (result.IsContentEditable()) {
    data.is_editable = true;
    SpellChecker& spell_checker = selected_frame->GetSpellChecker();

    // Spellchecker adds spelling markers to misspelled words and attaches
    // suggestions to these markers in the background. Therefore, when a
    // user right-clicks a mouse on a word, Chrome just needs to find a
    // spelling marker on the word instead of spellchecking it.
    std::pair<String, String> misspelled_word_and_description =
        spell_checker.SelectMisspellingAsync();
    const String& misspelled_word = misspelled_word_and_description.first;
    if (misspelled_word.length()) {
      auto to_u16string = [](const String& s) -> std::u16string {
        return s.empty() ? std::u16string()
                         : WTF::VisitCharacters(s, [](auto chars) {
                             return std::u16string(chars.begin(), chars.end());
                           });
      };
      data.misspelled_word = to_u16string(misspelled_word);
      const String& description = misspelled_word_and_description.second;
      if (description.length()) {
        // Suggestions were cached for the misspelled word (won't be true for
        // Hunspell, or Windows platform spellcheck if the
        // kWinRetrieveSuggestionsOnlyOnDemand feature flag is set).
        Vector<String> suggestions;
        description.Split('\n', suggestions);
        WebVector<std::u16string> web_suggestions(suggestions.size());
        base::ranges::transform(suggestions, web_suggestions.begin(),
                                to_u16string);
        data.dictionary_suggestions = web_suggestions.ReleaseVector();
      } else if (spell_checker.GetTextCheckerClient()) {
        // No suggestions cached for the misspelled word. Retrieve suggestions
        // for it (Windows platform spellchecker will do this later from
        // SpellingMenuObserver::InitMenu on the browser process side to avoid a
        // blocking IPC here).
        size_t misspelled_offset, misspelled_length;
        WebVector<WebString> web_suggestions;
        spell_checker.GetTextCheckerClient()->CheckSpelling(
            WebString::FromUTF16(data.misspelled_word), misspelled_offset,
            misspelled_length, &web_suggestions);
        WebVector<std::u16string> suggestions(web_suggestions.size());
        base::ranges::transform(web_suggestions, suggestions.begin(),
```