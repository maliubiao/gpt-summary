Response:
The user wants to understand the functionality of the `ax_object.cc` file in the Chromium Blink rendering engine. I need to extract the key responsibilities of this file based on the provided source code and explain its connections to web technologies like JavaScript, HTML, and CSS. Additionally, I need to address potential user errors and debugging approaches.

**Plan:**

1. **Identify Core Functionality:** Analyze the included headers, class definition (`AXObject`), and its methods to determine the primary purpose of the file. It seems to be related to accessibility.
2. **Explain Relationship to Web Technologies:**  Look for code sections that interact with HTML elements, CSS styling (through layout objects), and potentially JavaScript events or DOM manipulation.
3. **Provide Examples:** For each identified relationship, create concrete examples demonstrating the interaction.
4. **Address Logical Reasoning:** Identify any logical steps or algorithms within the code and provide example inputs and expected outputs.
5. **Highlight User/Programming Errors:** Analyze the code for potential pitfalls or common mistakes users or developers might make that would involve this code.
6. **Describe User Interaction for Debugging:** Outline the steps a user might take in a web browser that would eventually lead to the execution of code within this file.
7. **Summarize Functionality:**  Condense the findings into a concise summary of the file's purpose.
这是目录为`blink/renderer/modules/accessibility/ax_object.cc`的 Chromium Blink 引擎源代码文件的一部分。根据提供的代码片段，可以归纳出它的主要功能是**定义了 `AXObject` 类，这是 Blink 中用于表示可访问性树中节点的核心类。** `AXObject` 封装了关于页面元素的可访问性信息，并提供了操作这些信息和与其他可访问性对象交互的方法。

以下是根据代码片段更详细的功能分解：

**核心功能：**

1. **表示可访问性对象:** `AXObject` 类是可访问性树中节点的抽象表示。每个 `AXObject` 对应于 HTML 页面中的一个元素或其他可访问的实体（例如，文本节点，图像地图链接）。
2. **存储可访问性属性:**  `AXObject` 存储了与可访问性相关的各种属性，例如：
    *   **角色 (Role):**  描述元素的语义含义和用途（例如，按钮、链接、文本框）。代码中通过 `DetermineRoleValue()` 方法确定角色的值。
    *   **父对象 (Parent):**  指向可访问性树中的父节点。
    *   **子对象 (Children):**  （虽然未在此片段中直接显示，但 `AXObject` 管理着子对象）。
    *   **忽略状态 (Ignored):**  指示该对象是否应该被可访问性 API 暴露。代码中包含了检查和管理忽略原因的逻辑。
    *   **其他属性:** 例如，名称、描述、帮助文本、状态等（虽然在此片段中没有全部展示，但后续部分会涉及）。
3. **管理脏标记 (Dirty Flags):** `AXObject` 具有 `has_dirty_descendants_` 标志，用于标记其子孙节点是否需要更新。这用于优化可访问性树的更新过程，避免不必要的重新计算。 `SetHasDirtyDescendants()` 和 `SetAncestorsHaveDirtyDescendants()` 方法用于管理这些标记。
4. **确定角色 (Role Determination):**  `DetermineRoleValue()` 方法（虽然在此片段中只是被调用）是 `AXObject` 的关键部分，它根据 HTML 元素的标签名、ARIA 属性等来确定其可访问性角色。代码中定义了 `kAriaRoles` 和 `kReverseRoles` 等映射，用于将 ARIA 角色名映射到内部角色值。
5. **提供工具方法:**  包含一些辅助方法，例如：
    *   `GetNodeString()`:  返回表示 DOM 节点的字符串，用于调试。
    *   `TruncateString()` 和 `TruncateAndAddStringAttribute()`: 用于限制字符串属性的长度。
    *   `AddIntAttribute()` 和 `AddIntListAttributeFromObjects()`: 用于向可访问性节点数据添加整数属性。
6. **与可访问性缓存交互:** `AXObject` 与 `AXObjectCacheImpl` 紧密协作，`AXObjectCacheImpl` 负责管理页面中所有 `AXObject` 的生命周期和关系。

**与 JavaScript, HTML, CSS 的关系：**

*   **HTML:** `AXObject` 对应于 HTML 页面中的元素。它的角色、属性等很大程度上取决于 HTML 元素的标签名和属性（例如，`role`, `aria-label`, `alt`）。
    *   **举例:** 当一个 `<div>` 元素设置了 `role="button"` 属性时，对应的 `AXObject` 的角色会被确定为 `ax::mojom::blink::Role::kButton`。
    *   **举例:** `<img>` 元素的 `alt` 属性会影响 `AXObject` 的名称。如果 `alt` 属性为空，可能会导致该 `AXObject` 被标记为忽略 (通过 `kAXEmptyAlt` 原因)。
*   **CSS:** CSS 影响元素的渲染和可见性，这会间接地影响 `AXObject` 的忽略状态。
    *   **举例:** 如果一个元素设置了 `display: none` 或 `visibility: hidden`，对应的 `AXObject` 可能会因为 `kAXNotRendered` 或 `kAXNotVisible` 而被忽略。
    *   **举例:** CSS 还可以通过伪元素等方式创建渲染对象，这些渲染对象可能会影响 `AXObject` 的属性和层次结构。
*   **JavaScript:** JavaScript 可以动态地修改 HTML 结构和属性，包括 ARIA 属性。这些修改会触发 `AXObjectCache` 的更新，从而创建或修改相应的 `AXObject`。
    *   **举例:** JavaScript 使用 `setAttribute('aria-label', '新的标签')` 修改元素属性后，对应的 `AXObject` 的名称也会更新。
    *   **举例:** JavaScript 可以动态创建新的 HTML 元素，这些元素会被添加到可访问性树中，并创建对应的 `AXObject`。

**逻辑推理示例：**

假设输入一个 HTML 片段：

```html
<div role="button" aria-pressed="false">点击我</div>
```

1. **假设输入:**  Blink 渲染引擎解析到这个 `<div>` 元素。
2. **`AXObjectCache` 创建 `AXObject`:**  `AXObjectCache` 会为这个元素创建一个 `AXObject` 实例。
3. **角色推断:**  `DetermineRoleValue()` 方法会被调用。由于元素具有 `role="button"` 属性，`kAriaRoles` 映射会将 "button" 映射到 `ax::mojom::blink::Role::kButton`。
4. **属性设置:**  `AXObject` 的其他属性也会被设置，例如，名称可能从文本内容 "点击我" 中获取，状态可能从 `aria-pressed="false"` 中获取。
5. **假设输出:**  创建的 `AXObject` 的 `role_` 成员变量的值为 `ax::mojom::blink::Role::kButton`。

**用户或编程常见的使用错误：**

1. **滥用 `role="presentation"` 或 `role="none"`:**  开发者可能会错误地将重要的语义信息元素标记为 `presentation` 或 `none`，导致屏幕阅读器等辅助技术无法理解其含义。
    *   **举例:**  `<div role="presentation"><button>提交</button></div>`  这样标记后，屏幕阅读器可能只关注到 "提交" 文本，而忽略了它是一个按钮。
2. **ARIA 属性使用不当:**  错误地使用 ARIA 属性可能会导致可访问性问题。
    *   **举例:**  使用 `aria-hidden="true"` 隐藏了内容，但该内容对于理解页面是必要的，这会导致用户无法访问关键信息。
3. **动态更新后未触发可访问性树更新:**  JavaScript 动态修改了页面内容，但没有正确地通知可访问性引擎，导致辅助技术上的信息过时。这通常不是 `ax_object.cc` 的错误，而是上层逻辑的问题。

**用户操作到达这里的调试线索：**

用户与网页的任何交互都可能触发可访问性树的更新，从而涉及到 `ax_object.cc` 中的代码。以下是一些示例：

1. **页面加载:** 当浏览器加载一个网页时，Blink 渲染引擎会解析 HTML 并创建 DOM 树，同时也会构建可访问性树。在这个过程中，会为每个相关的 DOM 节点创建 `AXObject` 实例，涉及到 `ax_object.cc` 中 `AXObject` 的构造和初始化。
2. **DOM 结构变化:** 用户操作或 JavaScript 脚本导致 DOM 结构发生变化（例如，添加、删除或移动元素）时，`AXObjectCache` 会更新可访问性树，这可能导致新的 `AXObject` 被创建或现有的 `AXObject` 被修改。
3. **属性变化:** 用户操作或 JavaScript 脚本修改了元素的属性（特别是 ARIA 属性）时，相关的 `AXObject` 的属性也需要更新。
4. **焦点变化:** 当用户通过键盘或鼠标将焦点移动到页面上的不同元素时，可访问性引擎需要更新当前焦点所在的 `AXObject`。
5. **辅助技术交互:** 当屏幕阅读器等辅助技术与网页交互时，它们会查询可访问性树中的信息，这会导致 `AXObject` 的各种方法被调用以获取属性和执行操作。

**调试线索示例:**

1. **用户使用 Tab 键在表单元素之间导航:**  这会导致焦点在不同的表单控件之间移动，每个控件都有对应的 `AXObject`。调试时，可以查看当焦点移动时，哪些 `AXObject` 的属性被查询，以及 `DetermineRoleValue()` 如何为这些控件确定角色。
2. **用户点击一个带有 `aria-expanded` 属性的按钮:**  点击操作可能会触发 JavaScript 代码更新 `aria-expanded` 的值。调试时，可以观察到对应按钮的 `AXObject` 的状态变化，以及可访问性树的更新是否正确地反映了展开/折叠状态。

**总结功能:**

`blink/renderer/modules/accessibility/ax_object.cc` 文件定义了 `AXObject` 类，它是 Blink 引擎中可访问性树的基本构建块。它负责表示页面元素的可访问性信息，包括角色、属性和状态，并管理可访问性树的更新过程。该文件与 HTML 结构、CSS 渲染以及 JavaScript 的 DOM 操作紧密相关，确保了网页内容能够被辅助技术正确地理解和访问。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共10部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2008, 2009, 2011 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/modules/accessibility/ax_object.h"

#include <algorithm>
#include <ostream>

#include "base/auto_reset.h"
#include "base/numerics/safe_conversions.h"
#include "base/ranges/algorithm.h"
#include "base/strings/string_util.h"
#include "build/build_config.h"
#include "build/chromeos_buildflags.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_keyboard_event.h"
#include "third_party/blink/public/common/input/web_menu_source_type.h"
#include "third_party/blink/public/mojom/frame/user_activation_notification_type.mojom-blink.h"
#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/public/mojom/scroll/scroll_into_view_params.mojom-blink.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/accessibility/axid.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/events/simulated_click_options.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/custom/element_internals.h"
#include "third_party/blink/renderer/core/html/fenced_frame/html_fenced_frame_element.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_data_list_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/forms/html_opt_group_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_hr_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_map_element.h"
#include "third_party/blink/renderer/core/html/html_no_script_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/html/html_table_section_element.h"
#include "third_party/blink/renderer/core/html/html_title_element.h"
#include "third_party/blink/renderer/core/html/media/html_media_element.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/input/context_menu_allowed_scope.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_box_model_object.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/scroll/scroll_into_view_util.h"
#include "third_party/blink/renderer/core/svg/svg_desc_element.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/svg/svg_g_element.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"
#include "third_party/blink/renderer/core/svg/svg_title_element.h"
#include "third_party/blink/renderer/modules/accessibility/aria_notification.h"
#include "third_party/blink/renderer/modules/accessibility/ax_enums.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"
#if DCHECK_IS_ON()
#include "third_party/blink/renderer/modules/accessibility/ax_debug_utils.h"
#endif
#include "third_party/blink/renderer/bindings/core/v8/v8_highlight_type.h"
#include "third_party/blink/renderer/modules/accessibility/ax_image_map_link.h"
#include "third_party/blink/renderer/modules/accessibility/ax_inline_text_box.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"
#include "third_party/blink/renderer/modules/accessibility/ax_range.h"
#include "third_party/blink/renderer/modules/accessibility/ax_selection.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/keyboard_codes.h"
#include "third_party/blink/renderer/platform/language.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/platform_locale.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"
#include "ui/accessibility/accessibility_features.h"
#include "ui/accessibility/ax_action_data.h"
#include "ui/accessibility/ax_common.h"
#include "ui/accessibility/ax_enums.mojom-blink-forward.h"
#include "ui/accessibility/ax_node_data.h"
#include "ui/accessibility/ax_role_properties.h"
#include "ui/accessibility/ax_tree_id.h"
#include "ui/accessibility/ax_tree_source.h"
#include "ui/events/keycodes/dom/dom_code.h"
#include "ui/events/keycodes/dom/keycode_converter.h"
#include "ui/gfx/geometry/transform.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

#if defined(AX_FAIL_FAST_BUILD)
// TODO(accessibility) Move this out of DEBUG by having a new enum in
// ax_enums.mojom, and a matching ToString() in ax_enum_utils, as well as move
// out duplicate code of String IgnoredReasonName(AXIgnoredReason reason) in
// inspector_type_builder_helper.cc.
String IgnoredReasonName(AXIgnoredReason reason) {
  switch (reason) {
    case kAXActiveFullscreenElement:
      return "activeFullscreenElement";
    case kAXActiveModalDialog:
      return "activeModalDialog";
    case kAXAriaModalDialog:
      return "activeAriaModalDialog";
    case kAXAriaHiddenElement:
      return "ariaHiddenElement";
    case kAXAriaHiddenSubtree:
      return "ariaHiddenSubtree";
    case kAXEmptyAlt:
      return "emptyAlt";
    case kAXEmptyText:
      return "emptyText";
    case kAXHiddenByChildTree:
      return "hiddenByChildTree";
    case kAXInertElement:
      return "inertElement";
    case kAXInertSubtree:
      return "inertSubtree";
    case kAXLabelContainer:
      return "labelContainer";
    case kAXLabelFor:
      return "labelFor";
    case kAXNotRendered:
      return "notRendered";
    case kAXNotVisible:
      return "notVisible";
    case kAXPresentational:
      return "presentationalRole";
    case kAXProbablyPresentational:
      return "probablyPresentational";
    case kAXUninteresting:
      return "uninteresting";
  }
  NOTREACHED();
}

String GetIgnoredReasonsDebugString(AXObject::IgnoredReasons& reasons) {
  if (reasons.size() == 0)
    return "";
  String string_builder = "(";
  for (wtf_size_t count = 0; count < reasons.size(); count++) {
    if (count > 0)
      string_builder = string_builder + ',';
    string_builder = string_builder + IgnoredReasonName(reasons[count].reason);
  }
  string_builder = string_builder + ")";
  return string_builder;
}

#endif

String GetNodeString(Node* node) {
  if (node->IsTextNode()) {
    String string_builder = "\"";
    string_builder = string_builder + node->nodeValue();
    string_builder = string_builder + "\"";
    return string_builder;
  }

  Element* element = DynamicTo<Element>(node);
  if (!element) {
    return To<Document>(node)->IsLoadCompleted() ? "#document"
                                                 : "#document (loading)";
  }

  String string_builder = "<";

  string_builder = string_builder + element->tagName().LowerASCII();
  // Cannot safely get @class from SVG elements.
  if (!element->IsSVGElement() &&
      element->FastHasAttribute(html_names::kClassAttr)) {
    string_builder = string_builder + "." +
                     element->FastGetAttribute(html_names::kClassAttr);
  }
  if (element->FastHasAttribute(html_names::kIdAttr)) {
    string_builder =
        string_builder + "#" + element->FastGetAttribute(html_names::kIdAttr);
  }
  if (element->FastHasAttribute(html_names::kSlotAttr)) {
    string_builder = string_builder + " slot=" +
                     element->FastGetAttribute(html_names::kSlotAttr);
  }
  return string_builder + ">";
}

#if DCHECK_IS_ON()
bool IsValidRole(ax::mojom::blink::Role role) {
  // Check for illegal roles that should not be assigned in Blink.
  switch (role) {
    case ax::mojom::blink::Role::kCaret:
    case ax::mojom::blink::Role::kClient:
    case ax::mojom::blink::Role::kColumn:
    case ax::mojom::blink::Role::kDesktop:
    case ax::mojom::blink::Role::kKeyboard:
    case ax::mojom::blink::Role::kImeCandidate:
    case ax::mojom::blink::Role::kListGrid:
    case ax::mojom::blink::Role::kPane:
    case ax::mojom::blink::Role::kPdfActionableHighlight:
    case ax::mojom::blink::Role::kPdfRoot:
    case ax::mojom::blink::Role::kPreDeprecated:
    case ax::mojom::blink::Role::kTableHeaderContainer:
    case ax::mojom::blink::Role::kTitleBar:
    case ax::mojom::blink::Role::kUnknown:
    case ax::mojom::blink::Role::kWebView:
    case ax::mojom::blink::Role::kWindow:
      return false;
    default:
      return true;
  }
}
#endif

constexpr wtf_size_t kNumRoles =
    static_cast<wtf_size_t>(ax::mojom::blink::Role::kMaxValue) + 1;

using ARIARoleMap =
    HashMap<String, ax::mojom::blink::Role, CaseFoldingHashTraits<String>>;

struct RoleEntry {
  const char* role_name;
  ax::mojom::blink::Role role;
};

// Mapping of ARIA role name to internal role name.
// This is used for the following:
// 1. Map from an ARIA role to the internal role when building tree.
// 2. Map from an internal role to an ARIA role name, for debugging, the
//    xml-roles object attribute and element.computedRole.
const RoleEntry kAriaRoles[] = {
    {"alert", ax::mojom::blink::Role::kAlert},
    {"alertdialog", ax::mojom::blink::Role::kAlertDialog},
    {"application", ax::mojom::blink::Role::kApplication},
    {"article", ax::mojom::blink::Role::kArticle},
    {"banner", ax::mojom::blink::Role::kBanner},
    {"blockquote", ax::mojom::blink::Role::kBlockquote},
    {"button", ax::mojom::blink::Role::kButton},
    {"caption", ax::mojom::blink::Role::kCaption},
    {"cell", ax::mojom::blink::Role::kCell},
    {"code", ax::mojom::blink::Role::kCode},
    {"checkbox", ax::mojom::blink::Role::kCheckBox},
    {"columnheader", ax::mojom::blink::Role::kColumnHeader},
    {"combobox", ax::mojom::blink::Role::kComboBoxGrouping},
    {"comment", ax::mojom::blink::Role::kComment},
    {"complementary", ax::mojom::blink::Role::kComplementary},
    {"contentinfo", ax::mojom::blink::Role::kContentInfo},
    {"definition", ax::mojom::blink::Role::kDefinition},
    {"deletion", ax::mojom::blink::Role::kContentDeletion},
    {"dialog", ax::mojom::blink::Role::kDialog},
    {"directory", ax::mojom::blink::Role::kList},
    // -------------------------------------------------
    // DPub Roles:
    // www.w3.org/TR/dpub-aam-1.0/#mapping_role_table
    {"doc-abstract", ax::mojom::blink::Role::kDocAbstract},
    {"doc-acknowledgments", ax::mojom::blink::Role::kDocAcknowledgments},
    {"doc-afterword", ax::mojom::blink::Role::kDocAfterword},
    {"doc-appendix", ax::mojom::blink::Role::kDocAppendix},
    {"doc-backlink", ax::mojom::blink::Role::kDocBackLink},
    // Deprecated in DPUB-ARIA 1.1. Use a listitem inside of a doc-bibliography.
    {"doc-biblioentry", ax::mojom::blink::Role::kDocBiblioEntry},
    {"doc-bibliography", ax::mojom::blink::Role::kDocBibliography},
    {"doc-biblioref", ax::mojom::blink::Role::kDocBiblioRef},
    {"doc-chapter", ax::mojom::blink::Role::kDocChapter},
    {"doc-colophon", ax::mojom::blink::Role::kDocColophon},
    {"doc-conclusion", ax::mojom::blink::Role::kDocConclusion},
    {"doc-cover", ax::mojom::blink::Role::kDocCover},
    {"doc-credit", ax::mojom::blink::Role::kDocCredit},
    {"doc-credits", ax::mojom::blink::Role::kDocCredits},
    {"doc-dedication", ax::mojom::blink::Role::kDocDedication},
    // Deprecated in DPUB-ARIA 1.1. Use a listitem inside of a doc-endnotes.
    {"doc-endnote", ax::mojom::blink::Role::kDocEndnote},
    {"doc-endnotes", ax::mojom::blink::Role::kDocEndnotes},
    {"doc-epigraph", ax::mojom::blink::Role::kDocEpigraph},
    {"doc-epilogue", ax::mojom::blink::Role::kDocEpilogue},
    {"doc-errata", ax::mojom::blink::Role::kDocErrata},
    {"doc-example", ax::mojom::blink::Role::kDocExample},
    {"doc-footnote", ax::mojom::blink::Role::kDocFootnote},
    {"doc-foreword", ax::mojom::blink::Role::kDocForeword},
    {"doc-glossary", ax::mojom::blink::Role::kDocGlossary},
    {"doc-glossref", ax::mojom::blink::Role::kDocGlossRef},
    {"doc-index", ax::mojom::blink::Role::kDocIndex},
    {"doc-introduction", ax::mojom::blink::Role::kDocIntroduction},
    {"doc-noteref", ax::mojom::blink::Role::kDocNoteRef},
    {"doc-notice", ax::mojom::blink::Role::kDocNotice},
    {"doc-pagebreak", ax::mojom::blink::Role::kDocPageBreak},
    {"doc-pagefooter", ax::mojom::blink::Role::kDocPageFooter},
    {"doc-pageheader", ax::mojom::blink::Role::kDocPageHeader},
    {"doc-pagelist", ax::mojom::blink::Role::kDocPageList},
    {"doc-part", ax::mojom::blink::Role::kDocPart},
    {"doc-preface", ax::mojom::blink::Role::kDocPreface},
    {"doc-prologue", ax::mojom::blink::Role::kDocPrologue},
    {"doc-pullquote", ax::mojom::blink::Role::kDocPullquote},
    {"doc-qna", ax::mojom::blink::Role::kDocQna},
    {"doc-subtitle", ax::mojom::blink::Role::kDocSubtitle},
    {"doc-tip", ax::mojom::blink::Role::kDocTip},
    {"doc-toc", ax::mojom::blink::Role::kDocToc},
    // End DPub roles.
    // -------------------------------------------------
    {"document", ax::mojom::blink::Role::kDocument},
    {"emphasis", ax::mojom::blink::Role::kEmphasis},
    {"feed", ax::mojom::blink::Role::kFeed},
    {"figure", ax::mojom::blink::Role::kFigure},
    {"form", ax::mojom::blink::Role::kForm},
    {"generic", ax::mojom::blink::Role::kGenericContainer},
    // -------------------------------------------------
    // ARIA Graphics module roles:
    // https://rawgit.com/w3c/graphics-aam/master/
    {"graphics-document", ax::mojom::blink::Role::kGraphicsDocument},
    {"graphics-object", ax::mojom::blink::Role::kGraphicsObject},
    {"graphics-symbol", ax::mojom::blink::Role::kGraphicsSymbol},
    // End ARIA Graphics module roles.
    // -------------------------------------------------
    {"grid", ax::mojom::blink::Role::kGrid},
    {"gridcell", ax::mojom::blink::Role::kGridCell},
    {"group", ax::mojom::blink::Role::kGroup},
    {"heading", ax::mojom::blink::Role::kHeading},
    {"img", ax::mojom::blink::Role::kImage},
    // role="image" is listed after role="img" to treat the synonym img
    // as a computed name image
    {"image", ax::mojom::blink::Role::kImage},
    {"insertion", ax::mojom::blink::Role::kContentInsertion},
    {"link", ax::mojom::blink::Role::kLink},
    {"list", ax::mojom::blink::Role::kList},
    {"listbox", ax::mojom::blink::Role::kListBox},
    {"listitem", ax::mojom::blink::Role::kListItem},
    {"log", ax::mojom::blink::Role::kLog},
    {"main", ax::mojom::blink::Role::kMain},
    {"marquee", ax::mojom::blink::Role::kMarquee},
    {"math", ax::mojom::blink::Role::kMath},
    {"menu", ax::mojom::blink::Role::kMenu},
    {"menubar", ax::mojom::blink::Role::kMenuBar},
    {"menuitem", ax::mojom::blink::Role::kMenuItem},
    {"menuitemcheckbox", ax::mojom::blink::Role::kMenuItemCheckBox},
    {"menuitemradio", ax::mojom::blink::Role::kMenuItemRadio},
    {"mark", ax::mojom::blink::Role::kMark},
    {"meter", ax::mojom::blink::Role::kMeter},
    {"navigation", ax::mojom::blink::Role::kNavigation},
    // role="presentation" is the same as role="none".
    {"presentation", ax::mojom::blink::Role::kNone},
    // role="none" is listed after role="presentation", so that it is the
    // canonical name in devtools and tests.
    {"none", ax::mojom::blink::Role::kNone},
    {"note", ax::mojom::blink::Role::kNote},
    {"option", ax::mojom::blink::Role::kListBoxOption},
    {"paragraph", ax::mojom::blink::Role::kParagraph},
    {"progressbar", ax::mojom::blink::Role::kProgressIndicator},
    {"radio", ax::mojom::blink::Role::kRadioButton},
    {"radiogroup", ax::mojom::blink::Role::kRadioGroup},
    {"region", ax::mojom::blink::Role::kRegion},
    {"row", ax::mojom::blink::Role::kRow},
    {"rowgroup", ax::mojom::blink::Role::kRowGroup},
    {"rowheader", ax::mojom::blink::Role::kRowHeader},
    {"scrollbar", ax::mojom::blink::Role::kScrollBar},
    {"search", ax::mojom::blink::Role::kSearch},
    {"searchbox", ax::mojom::blink::Role::kSearchBox},
    {"sectionfooter", ax::mojom::blink::Role::kSectionFooter},
    {"sectionheader", ax::mojom::blink::Role::kSectionHeader},
    {"separator", ax::mojom::blink::Role::kSplitter},
    {"slider", ax::mojom::blink::Role::kSlider},
    {"spinbutton", ax::mojom::blink::Role::kSpinButton},
    {"status", ax::mojom::blink::Role::kStatus},
    {"strong", ax::mojom::blink::Role::kStrong},
    {"subscript", ax::mojom::blink::Role::kSubscript},
    {"suggestion", ax::mojom::blink::Role::kSuggestion},
    {"superscript", ax::mojom::blink::Role::kSuperscript},
    {"switch", ax::mojom::blink::Role::kSwitch},
    {"tab", ax::mojom::blink::Role::kTab},
    {"table", ax::mojom::blink::Role::kTable},
    {"tablist", ax::mojom::blink::Role::kTabList},
    {"tabpanel", ax::mojom::blink::Role::kTabPanel},
    {"term", ax::mojom::blink::Role::kTerm},
    {"textbox", ax::mojom::blink::Role::kTextField},
    {"time", ax::mojom::blink::Role::kTime},
    {"timer", ax::mojom::blink::Role::kTimer},
    {"toolbar", ax::mojom::blink::Role::kToolbar},
    {"tooltip", ax::mojom::blink::Role::kTooltip},
    {"tree", ax::mojom::blink::Role::kTree},
    {"treegrid", ax::mojom::blink::Role::kTreeGrid},
    {"treeitem", ax::mojom::blink::Role::kTreeItem}};

// More friendly names for debugging, and for WPT tests.
// These are roles which map from the ARIA role name to the internal role when
// building the tree, but in DevTools or testing, we want to show the ARIA
// role name, since that is the publicly visible concept.
const RoleEntry kReverseRoles[] = {
    {"banner", ax::mojom::blink::Role::kHeader},
    {"button", ax::mojom::blink::Role::kToggleButton},
    {"button", ax::mojom::blink::Role::kPopUpButton},
    {"contentinfo", ax::mojom::blink::Role::kFooter},
    {"option", ax::mojom::blink::Role::kMenuListOption},
    {"option", ax::mojom::blink::Role::kListBoxOption},
    {"group", ax::mojom::blink::Role::kDetails},
    {"generic", ax::mojom::blink::Role::kSectionWithoutName},
    {"combobox", ax::mojom::blink::Role::kComboBoxMenuButton},
    {"combobox", ax::mojom::blink::Role::kComboBoxSelect},
    {"combobox", ax::mojom::blink::Role::kTextFieldWithComboBox}};

static ARIARoleMap* CreateARIARoleMap() {
  ARIARoleMap* role_map = new ARIARoleMap;

  for (auto aria_role : kAriaRoles)
    role_map->Set(String(aria_role.role_name), aria_role.role);

  return role_map;
}

// The role name vector contains only ARIA roles, and no internal roles.
static Vector<AtomicString>* CreateAriaRoleNameVector() {
  Vector<AtomicString>* role_name_vector = new Vector<AtomicString>(kNumRoles);
  role_name_vector->Fill(g_null_atom, kNumRoles);

  for (auto aria_role : kAriaRoles) {
    (*role_name_vector)[static_cast<wtf_size_t>(aria_role.role)] =
        AtomicString(aria_role.role_name);
  }

  for (auto reverse_role : kReverseRoles) {
    (*role_name_vector)[static_cast<wtf_size_t>(reverse_role.role)] =
        AtomicString(reverse_role.role_name);
  }

  return role_name_vector;
}

void AddIntListAttributeFromObjects(ax::mojom::blink::IntListAttribute attr,
                                    const AXObject::AXObjectVector& objects,
                                    ui::AXNodeData* node_data) {
  DCHECK(node_data);
  std::vector<int32_t> ids;
  for (const auto& obj : objects) {
    if (!obj->IsIgnored()) {
      ids.push_back(obj->AXObjectID());
    }
  }
  if (!ids.empty())
    node_data->AddIntListAttribute(attr, ids);
}

// Max length for attributes such as aria-label.
static constexpr uint32_t kMaxStringAttributeLength = 10000;
// Max length for a static text name.
// Length of War and Peace (http://www.gutenberg.org/files/2600/2600-0.txt).
static constexpr uint32_t kMaxStaticTextLength = 3227574;

std::string TruncateString(const String& str,
                           uint32_t max_len = kMaxStringAttributeLength) {
  auto str_utf8 = str.Utf8(kStrictUTF8Conversion);
  if (str_utf8.size() > max_len) {
    std::string truncated;
    base::TruncateUTF8ToByteSize(str_utf8, max_len, &truncated);
    return truncated;
  }
  return str_utf8;
}

bool TruncateAndAddStringAttribute(
    ui::AXNodeData* dst,
    ax::mojom::blink::StringAttribute attribute,
    const String& value,
    uint32_t max_len = kMaxStringAttributeLength) {
  if (!value.empty()) {
    std::string value_utf8 = TruncateString(value, max_len);
    if (!value_utf8.empty()) {
      dst->AddStringAttribute(attribute, value_utf8);
      return true;
    }
  }
  return false;
}

void AddIntAttribute(const AXObject* obj,
                     ax::mojom::blink::IntAttribute node_data_attr,
                     const QualifiedName& attr_name,
                     ui::AXNodeData* node_data,
                     int min_value = INT_MIN) {
  const AtomicString& value = obj->AriaAttribute(attr_name);
  if (!value.empty()) {
    int value_as_int = value.ToInt();
    if (value_as_int >= min_value) {
      node_data->AddIntAttribute(node_data_attr, value_as_int);
    }
  }
}

void AddIntListAttributeFromOffsetVector(
    ax::mojom::blink::IntListAttribute attr,
    const Vector<int>& offsets,
    ui::AXNodeData* node_data) {
  std::vector<int32_t> offset_values;
  for (int offset : offsets)
    offset_values.push_back(static_cast<int32_t>(offset));
  DCHECK(node_data);
  if (!offset_values.empty())
    node_data->AddIntListAttribute(attr, offset_values);
}

const QualifiedName& DeprecatedAriaColtextAttrName() {
  DEFINE_STATIC_LOCAL(QualifiedName, aria_coltext_attr,
                      (AtomicString("aria-coltext")));
  return aria_coltext_attr;
}

const QualifiedName& DeprecatedAriaRowtextAttrName() {
  DEFINE_STATIC_LOCAL(QualifiedName, aria_rowtext_attr,
                      (AtomicString("aria-rowtext")));
  return aria_rowtext_attr;
}

}  // namespace

int32_t ToAXMarkerType(DocumentMarker::MarkerType marker_type) {
  ax::mojom::blink::MarkerType result;
  switch (marker_type) {
    case DocumentMarker::kSpelling:
      result = ax::mojom::blink::MarkerType::kSpelling;
      break;
    case DocumentMarker::kGrammar:
      result = ax::mojom::blink::MarkerType::kGrammar;
      break;
    case DocumentMarker::kTextFragment:
    case DocumentMarker::kTextMatch:
      result = ax::mojom::blink::MarkerType::kTextMatch;
      break;
    case DocumentMarker::kActiveSuggestion:
      result = ax::mojom::blink::MarkerType::kActiveSuggestion;
      break;
    case DocumentMarker::kSuggestion:
      result = ax::mojom::blink::MarkerType::kSuggestion;
      break;
    case DocumentMarker::kCustomHighlight:
      result = ax::mojom::blink::MarkerType::kHighlight;
      break;
    default:
      result = ax::mojom::blink::MarkerType::kNone;
      break;
  }

  return static_cast<int32_t>(result);
}

int32_t ToAXHighlightType(const V8HighlightType& highlight_type) {
  switch (highlight_type.AsEnum()) {
    case V8HighlightType::Enum::kHighlight:
      return static_cast<int32_t>(ax::mojom::blink::HighlightType::kHighlight);
    case V8HighlightType::Enum::kSpellingError:
      return static_cast<int32_t>(
          ax::mojom::blink::HighlightType::kSpellingError);
    case V8HighlightType::Enum::kGrammarError:
      return static_cast<int32_t>(
          ax::mojom::blink::HighlightType::kGrammarError);
  }
  NOTREACHED();
}

const AXObject* FindAncestorWithAriaHidden(const AXObject* start) {
  for (const AXObject* object = start;
       object && !IsA<Document>(object->GetNode());
       object = object->ParentObject()) {
    if (object->IsAriaHiddenRoot()) {
      return object;
    }
  }

  return nullptr;
}

// static
unsigned AXObject::number_of_live_ax_objects_ = 0;

AXObject::AXObject(AXObjectCacheImpl& ax_object_cache)
    : id_(0),
      parent_(nullptr),
      role_(ax::mojom::blink::Role::kUnknown),
      explicit_container_id_(0),
      cached_live_region_root_(nullptr),
      ax_object_cache_(&ax_object_cache) {
  ++number_of_live_ax_objects_;
}

AXObject::~AXObject() {
  DCHECK(IsDetached());
  --number_of_live_ax_objects_;
}

void AXObject::SetHasDirtyDescendants(bool dirty) {
  CHECK(!dirty || CachedIsIncludedInTree())
      << "Only included nodes can be marked as having dirty descendants: "
      << this;
  has_dirty_descendants_ = dirty;
}

void AXObject::SetAncestorsHaveDirtyDescendants() {
  CHECK(!IsDetached());
  CHECK(AXObjectCache()
            .lifecycle()
            .StateAllowsAXObjectsToGainFinalizationNeededBit())
      << AXObjectCache();

  // Set the dirty bit for the root AX object when created. For all other
  // objects, this is set by a descendant needing to be updated, and
  // AXObjectCacheImpl::FinalizeTree() will therefore process an object
  // if its parent has has_dirty_descendants_ set. The root, however, has no
  // parent, so there is no parent to mark in order to cause the root to update
  // itself. Therefore this bit serves a second purpose of determining
  // whether AXObjectCacheImpl::FinalizeTree() needs to update the root
  // object.
  if (IsRoot()) {
    // Need at least the root object to be flagged in order for
    // FinalizeTree() to do anything.
    SetHasDirtyDescendants(true);
    return;
  }

  if (AXObjectCache().EntireDocumentIsDirty()) {
    // No need to walk parent chain when marking the entire document dirty,
    // as every node will have the bit set. In addition, attempting to repair
    // the parent chain while marking everything dirty is actually against
    // the point, because all child-parent relationships will be rebuilt
    // from the top down.
    if (CachedIsIncludedInTree()) {
      SetHasDirtyDescendants(true);
    }
    return;
  }

  AXObject* ancestor = this;

  while (true) {
    ancestor = ancestor->ParentObject();
    if (!ancestor) {
      break;
    }
    DCHECK(!ancestor->IsDetached());

    // We need to to continue setting bits through AX objects for which
    // IsIncludedInTree is false, since those objects are omitted
    // from the generated tree. However, don't set the bit on unincluded
    // objects, during the clearing phase in
    // AXObjectCacheImpl::FinalizeTree(), only included nodes are
    // visited.
    if (!ancestor->CachedIsIncludedInTree()) {
      continue;
    }
    if (ancestor->has_dirty_descendants_) {
      break;
    }
    ancestor->SetHasDirtyDescendants(true);
  }
#if DCHECK_IS_ON()
  // Walk up the tree looking for dirty bits that failed to be set. If any
  // are found, this is a bug.
  bool fail = false;
  for (auto* obj = ParentObject(); obj; obj = obj->ParentObject()) {
    if (obj->CachedIsIncludedInTree() && !obj->has_dirty_descendants_) {
      fail = true;
      break;
    }
  }
  DCHECK(!fail) << "Failed to set dirty bits on some ancestors:\n"
                << ParentChainToStringHelper(this);
#endif
}

void AXObject::Init(AXObject* parent) {
  CHECK(!parent_) << "Should not already have a cached parent:"
                  << "\n* Child = " << GetNode() << " / " << GetLayoutObject()
                  << "\n* Parent = " << parent_
                  << "\n* Equal to passed-in parent? " << (parent == parent_);
  // Every AXObject must have a parent unless it's the root.
  CHECK(parent || IsRoot())
      << "The following node should have a parent: " << GetNode();
  CHECK(!AXObjectCache().IsFrozen());
#if DCHECK_IS_ON()
  CHECK(!is_initializing_);
  base::AutoReset<bool> reentrancy_protector(&is_initializing_, true);
#endif  // DCHECK_IS_ON()

  // Set the parent as soon as possible, so that we can use it in computations
  // for the role and cached value. We will set it again at the end of the
  // method using SetParent(), to ensure all of the normal code paths for
  // setting the parent are followed.
  parent_ = parent;

  // The role must be determined immediately.
  // Note: in order to avoid reentrancy, the role computation cannot use the
  // ParentObject(), although it can use the DOM parent.
  role_ = DetermineRoleValue();
#if DCHECK_IS_ON()
  DCHECK(IsValidRole(role_)) << "Illegal " << role_ << " for\n"
```