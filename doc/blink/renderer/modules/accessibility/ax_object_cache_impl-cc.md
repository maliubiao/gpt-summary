Response:
My thought process to answer the request about `ax_object_cache_impl.cc` went something like this:

1. **Understand the Core Purpose:** The file name and the `accessibility` directory immediately suggest its function is related to making web content accessible to users with disabilities, primarily through assistive technologies. The `cache` part hints at managing and storing accessibility information. The `impl` indicates this is likely the implementation of an interface or abstract class.

2. **Scan the Includes:**  The included headers provide valuable clues:
    * `ax_object.h`, `ax_node_object.h`, `ax_relation_cache.h`: These confirm the file deals with accessibility objects and their relationships.
    * `core/dom/*`, `core/html/*`, `core/layout/*`: This points to the interaction with the Document Object Model (DOM), HTML elements, and the layout engine – the core components of how a browser renders web pages.
    * `public/mojom/render_accessibility.mojom-blink.h`: This signals communication with other parts of the Chromium rendering process related to accessibility.
    * `ui/accessibility/*`: This indicates interaction with the platform's accessibility APIs (e.g., Windows MSAA/UIA, macOS Accessibility API, Linux AT-SPI).

3. **Analyze the Code Snippet (Focus on the provided part):**
    * **Copyright Notice:** Standard boilerplate, confirms Google's involvement and the license.
    * **Includes:** (Already analyzed).
    * **`SCOPED_DISALLOW_LIFECYCLE_TRANSITION()`:**  This macro (especially with the `DocumentLifecycle` mention) is a crucial indicator. It suggests the code needs to prevent modifications to the document's state while performing its operations to maintain consistency. This hints at potential race conditions or data corruption if the document changes unexpectedly during accessibility calculations.
    * **Namespace `blink`:** Confirms this is Blink-specific code.
    * **`RetargetInput` functions:** These functions suggest a mechanism to redirect focus or click events from certain elements (like buttons inside custom selects) to their logical parent. This is an accessibility technique to provide a more consistent and usable experience for assistive technologies.
    * **`IsInitialEmptyDocument`:**  This function is about optimization. It avoids unnecessary accessibility tree updates for truly empty initial pages.
    * **`IsDisplayLocked` functions:**  These are important for handling situations where the rendering process is paused or locked (e.g., during a synchronous script execution). Accessibility information might be stale in these scenarios.
    * **`IsActive`:**  Simple check for document activity.
    * **`HasAriaCellRole`:**  Checks for specific ARIA roles related to tables, indicating the code understands and utilizes ARIA attributes.
    * **`CanIgnoreSpaceNextTo` and `CanIgnoreSpace`:** These functions are about optimizing the accessibility tree by removing redundant whitespace. This is crucial for screen readers, which can be overwhelmed by excessive whitespace.
    * **`IsLayoutTextRelevantForAccessibility`:**  Determines if a text node should be included in the accessibility tree, taking into account layout, whitespace, and previous decisions.
    * **`IsHiddenTextNodeRelevantForAccessibility`:** Handles cases where text nodes are hidden using CSS or other mechanisms.
    * **`IsShadowContentRelevantForAccessibility`:**  Deals with the complexities of Shadow DOM and determines which parts of shadow trees are relevant for accessibility.
    * **`IsLayoutObjectRelevantForAccessibility`:**  Determines if a layout object (representing a rendered element) should have an associated accessibility object.
    * **`IsSubtreePrunedForAccessibility`:** Defines rules for pruning entire subtrees from the accessibility tree for optimization and to avoid exposing irrelevant elements.
    * **`IsInPrunableHiddenContainerInclusive`:**  Identifies elements within `<head>`, `<style>`, `<script>`, or frames, which are typically not relevant for accessibility.
    * **`DetermineAXObjectType`:**  This is a central function that decides *what kind* of accessibility object to create for a given DOM node or layout object, based on various relevance criteria. This is the core logic for building the accessibility tree.
    * **`kSizeMb`, `kBucketCount`, `LogNodeDataSizeDistribution`:**  These indicate performance monitoring and logging of accessibility data sizes.

4. **Connect to Javascript, HTML, CSS:** Based on the above analysis, the connections are clear:
    * **HTML:** The code directly interacts with HTML elements (`HTMLButtonElement`, `HTMLSelectElement`, `<img>`, etc.) and their attributes (like `role`, `aria-hidden`).
    * **CSS:** The code considers CSS rendering (e.g., `IsDisplayLocked`, hidden text nodes) and layout objects. The decisions about whitespace relevance are influenced by how elements are laid out.
    * **JavaScript:**  While this specific file doesn't directly execute JavaScript, it reacts to changes caused by JavaScript. For example, if JavaScript dynamically adds or removes elements, the accessibility tree needs to be updated, and this code plays a role in that update process. The `RetargetInput` function might be used in scenarios where JavaScript is used to create custom interactive elements.

5. **Formulate Examples, Assumptions, and Errors:**  Based on the functions identified, I could then formulate examples of how JavaScript, HTML, and CSS influence accessibility and how this code might react. I also considered common developer errors (like incorrect ARIA attributes) and how users might trigger the code (e.g., navigating with a screen reader, using the keyboard).

6. **Structure the Answer:** Finally, I organized the information into a clear and comprehensive answer, addressing each part of the prompt:
    * **Functionality Summary:**  A high-level overview.
    * **Relationship to Javascript, HTML, CSS:** Concrete examples.
    * **Logic and Assumptions:** Illustrative examples with input and output.
    * **User/Programming Errors:** Common mistakes and their consequences.
    * **User Steps to Reach the Code:**  A debugging perspective.
    * **Summary of Part 1:** Concise recap of the identified functionalities.

By following these steps, I was able to piece together a detailed understanding of the `ax_object_cache_impl.cc` file's role and its interactions with the browser's rendering engine and web content. The key was to leverage the available information – file name, includes, code snippets – and connect it to my existing knowledge of web technologies and accessibility concepts.
这是 `blink/renderer/modules/accessibility/ax_object_cache_impl.cc` 文件的第 1 部分，主要负责 Chromium Blink 引擎中**可访问性对象缓存**的实现。  它构建并维护一个代表网页可访问性信息的树形结构，以便辅助技术（如屏幕阅读器）能够理解和与网页内容交互。

**功能归纳（第 1 部分）：**

1. **核心职责：可访问性对象管理:**  `AXObjectCacheImpl` 负责创建、存储、更新和删除代表网页元素的 `AXObject`。 这些 `AXObject` 包含了辅助技术理解网页结构和内容所需的语义信息。

2. **决定可访问性对象的创建时机和类型:**  `DetermineAXObjectType` 函数是核心，它基于 DOM 节点和布局对象的信息，决定是否需要为特定元素创建可访问性对象，以及创建哪种类型的对象 (`kCreateFromLayout`, `kCreateFromNode`, `kPruneSubtree`)。  这涉及到一系列复杂的规则，判断元素是否对辅助技术有意义。

3. **处理 HTML 结构和语义:** 代码中包含了大量针对不同 HTML 元素 (`<button>`, `<input>`, `<img>`, `<table>` 等) 的特殊处理逻辑。  例如，它会考虑 `<select>` 元素内部自定义按钮的情况 (`RetargetInput`)，确保辅助技术能够正确与 `<select>` 交互。

4. **考虑 CSS 样式和布局:**  代码会检查元素的布局信息 (`LayoutObject`)，判断其是否可见、是否被 CSS 隐藏等，从而决定是否需要创建对应的可访问性对象。 `IsDisplayLocked` 系列函数用于处理渲染过程中的锁定状态。

5. **优化和性能考虑:**
    * **缓存:**  `AXObjectCacheImpl` 本身就是一个缓存，避免重复创建和计算可访问性信息。
    * **剪枝 (Pruning):** `IsSubtreePrunedForAccessibility` 和 `IsInPrunableHiddenContainerInclusive` 等函数用于判断某些子树是否对辅助技术没有意义（例如 `<head>`, `<style>`, `<script>` 内部的元素，或者某些特定的 shadow DOM 内容），从而进行剪枝，提高性能。
    * **忽略不必要的空白:** `CanIgnoreSpace` 和 `IsLayoutTextRelevantForAccessibility` 等函数用于判断并忽略渲染后不影响辅助技术理解的空白字符，减少不必要的对象创建。
    * **性能指标记录:**  `LogNodeDataSizeDistribution` 函数表明代码关注性能，并会记录可访问性对象数据的大小分布。

6. **处理 Shadow DOM:** 代码中包含 `IsShadowContentRelevantForAccessibility` 函数，专门处理 Shadow DOM 中的节点，决定哪些 shadow 内容需要暴露给辅助技术。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **HTML:**  `AXObjectCacheImpl` 的主要输入是 HTML 结构。它会根据 HTML 标签和属性（特别是 ARIA 属性）来创建不同的 `AXObject`。
    * **例子:**  对于一个 `<button>` 元素，会创建一个表示按钮的 `AXObject`，并可能包含按钮的文本内容、是否禁用等信息。对于带有 `aria-label` 属性的 `<div>`，会读取该属性作为可访问性标签。
    * **假设输入:**  HTML 代码 `<button>Click me</button>`
    * **输出:**  创建一个 `AXObject`，其角色 (role) 为 "button"，名称 (name) 为 "Click me"。

* **CSS:** CSS 的渲染结果影响着 `AXObjectCacheImpl` 的判断。例如，`display: none` 或 `visibility: hidden` 的元素通常不会创建可访问性对象。
    * **例子:**  一个设置了 `display: none` 的 `<div>` 元素，`DetermineAXObjectType` 函数可能会返回 `kPruneSubtree`，不会为其创建 `AXObject`。
    * **假设输入:**  HTML `<div style="display: none;">Hidden content</div>`
    * **输出:**  不会为该 `div` 创建 `AXObject`。

* **JavaScript:** 虽然这个文件本身主要是 C++ 代码，但 JavaScript 的动态操作会触发 `AXObjectCacheImpl` 的更新。当 JavaScript 修改 DOM 结构或属性时，缓存需要相应地更新。
    * **例子:**  JavaScript 通过 `document.createElement` 创建一个新的 `<img>` 元素并添加到 DOM 中，这会触发 `AXObjectCacheImpl` 为该图片创建一个 `AXObject`。
    * **假设输入:**  JavaScript 代码 `document.body.appendChild(document.createElement('img'))` 执行。
    * **输出:**  创建一个表示该 `<img>` 元素的 `AXObject`。

**逻辑推理的假设输入与输出:**

* **假设输入:**  一个包含大量空白字符的文本节点。
* **输出:**  `IsLayoutTextRelevantForAccessibility` 函数会根据 `CanIgnoreSpace` 的结果，可能决定忽略这些空白字符，从而不为这些空白字符创建单独的 `AXObject`。

**用户或编程常见的使用错误举例:**

* **错误使用 `aria-hidden="true"`:**  开发者可能错误地将对辅助技术重要的内容设置为 `aria-hidden="true"`，导致辅助技术无法访问这些内容。 `AXObjectCacheImpl` 会忠实地反映这种设置，不会为这些元素创建 `AXObject`。
* **动态更新内容后未及时通知辅助技术:** 虽然 `AXObjectCacheImpl` 会监听 DOM 变化，但过于频繁或复杂的动态更新可能导致辅助技术获取到的信息不一致。开发者需要使用 ARIA live regions 等机制来明确通知辅助技术内容的更新。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户使用支持辅助功能的浏览器浏览网页。**
2. **辅助技术 (例如屏幕阅读器) 请求页面的可访问性信息。**
3. **浏览器 (Chromium) 的渲染引擎开始构建可访问性树。**
4. **在构建过程中，当遇到 DOM 节点或布局对象时，会调用 `AXObjectCacheImpl::GetOrCreate` 或类似的方法。**
5. **`DetermineAXObjectType` 函数会被调用，根据当前节点和布局信息，判断是否需要创建 `AXObject`，以及创建哪种类型的对象。**
6. **如果需要创建 `AXObject`，则会分配相应的对象，并填充其属性和关系。**

**总结 (第 1 部分功能):**

`ax_object_cache_impl.cc` 的第 1 部分主要关注于 **可访问性对象的创建和管理决策**。它基于 HTML 结构、CSS 样式和一些优化策略，判断哪些 DOM 元素需要创建对应的可访问性对象，以及创建哪种类型的对象。  这部分代码是构建完整可访问性树的基础，直接影响辅助技术如何理解和与网页内容交互。它体现了 Blink 引擎在可访问性方面的核心逻辑和对性能的考虑。

### 提示词
```
这是目录为blink/renderer/modules/accessibility/ax_object_cache_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共8部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2014, Google Inc. All rights reserved.
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

#include "third_party/blink/renderer/modules/accessibility/ax_object_cache_impl.h"

#include <iterator>
#include <numeric>

#include "base/auto_reset.h"
#include "base/check.h"
#include "base/containers/contains.h"
#include "base/memory/scoped_refptr.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/ranges/algorithm.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "services/metrics/public/cpp/ukm_recorder.h"
#include "third_party/abseil-cpp/absl/cleanup/cleanup.h"
#include "third_party/blink/public/mojom/render_accessibility.mojom-blink.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/public/web/web_plugin_container.h"
#include "third_party/blink/renderer/core/accessibility/scoped_blink_ax_event_intent.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_lifecycle.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/events/event_util.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/frame/web_local_frame_impl.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/forms/html_button_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_label_element.h"
#include "third_party/blink/renderer/core/html/forms/html_option_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/listed_element.h"
#include "third_party/blink/renderer/core/html/html_area_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_map_element.h"
#include "third_party/blink/renderer/core/html/html_menu_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_plugin_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_table_row_element.h"
#include "third_party/blink/renderer/core/html/html_title_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html/shadow/shadow_element_names.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/inline/abstract_inline_text_box.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/layout/table/layout_table.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_cell.h"
#include "third_party/blink/renderer/core/layout/table/layout_table_row.h"
#include "third_party/blink/renderer/core/page/chrome_client.h"
#include "third_party/blink/renderer/core/page/focus_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/page_animator.h"
#include "third_party/blink/renderer/core/style/content_data.h"
#include "third_party/blink/renderer/core/svg/svg_graphics_element.h"
#include "third_party/blink/renderer/core/svg/svg_style_element.h"
#include "third_party/blink/renderer/modules/accessibility/aria_notification.h"
#include "third_party/blink/renderer/modules/accessibility/ax_block_flow_iterator.h"
#include "third_party/blink/renderer/modules/accessibility/ax_image_map_link.h"
#include "third_party/blink/renderer/modules/accessibility/ax_inline_text_box.h"
#include "third_party/blink/renderer/modules/accessibility/ax_media_control.h"
#include "third_party/blink/renderer/modules/accessibility/ax_media_element.h"
#include "third_party/blink/renderer/modules/accessibility/ax_node_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_object.h"
#include "third_party/blink/renderer/modules/accessibility/ax_progress_indicator.h"
#include "third_party/blink/renderer/modules/accessibility/ax_relation_cache.h"
#include "third_party/blink/renderer/modules/accessibility/ax_slider.h"
#include "third_party/blink/renderer/modules/accessibility/ax_validation_message.h"
#include "third_party/blink/renderer/platform/graphics/dom_node_id.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "ui/accessibility/ax_common.h"
#include "ui/accessibility/ax_enums.mojom-blink.h"
#include "ui/accessibility/ax_event.h"
#include "ui/accessibility/ax_location_and_scroll_updates.h"
#include "ui/accessibility/ax_node.h"
#include "ui/accessibility/ax_role_properties.h"
#include "ui/accessibility/mojom/ax_location_and_scroll_updates.mojom-blink.h"
#include "ui/accessibility/mojom/ax_relative_bounds.mojom-blink.h"
#if DCHECK_IS_ON()
#include "third_party/blink/renderer/modules/accessibility/ax_debug_utils.h"
#endif

// Prevent code that runs during the lifetime of the stack from altering the
// document lifecycle, for the main document, and the popup document if present.
#if DCHECK_IS_ON()
#define SCOPED_DISALLOW_LIFECYCLE_TRANSITION()                               \
  DocumentLifecycle::DisallowTransitionScope scoped(document_->Lifecycle()); \
  DocumentLifecycle::DisallowTransitionScope scoped2(                        \
      popup_document_ ? popup_document_->Lifecycle()                         \
                      : document_->Lifecycle());
#else
#define SCOPED_DISALLOW_LIFECYCLE_TRANSITION()
#endif  // DCHECK_IS_ON()

namespace blink {

using mojom::blink::FormControlType;

namespace {

Node* RetargetInput(Node* node) {
  // Any click/focus that occurs on a <button> inside of a custom <select>
  // should be treated as if it occurred on the <select>. The custom button is
  // not actually present in the accessibility tree, but the select is present
  // as a Role::kMenuList object.
  if (IsA<HTMLButtonElement>(node)) {
    // Fallback button case.
    Node* possible_select = node->OwnerShadowHost();
    if (!possible_select) {
      // Custom button case.
      possible_select = NodeTraversal::Parent(*node);
    }
    if (auto* select = DynamicTo<HTMLSelectElement>(possible_select)) {
      if (select->IsAppearanceBaseButton() && node == select->SlottedButton()) {
        return select;
      }
    }
  }
  return node;
}

Element* RetargetInput(Element* element) {
  return DynamicTo<Element>(RetargetInput(static_cast<Node*>(element)));
}

bool IsInitialEmptyDocument(const Document& document) {
  // Do not fire for initial empty top document. This helps avoid thrashing the
  // a11y tree, causing an extra serialization.
  // TODO(accessibility) This is an ugly special case -- find a better way.
  // Note: Document::IsInitialEmptyDocument() did not work -- should it?
  if (document.body() && document.body()->hasChildren())
    return false;

  if (document.head() && document.head()->hasChildren())
    return false;

  if (document.ParentDocument())
    return false;

  // No contents and not a child document, return true if about::blank.
  return document.Url().IsAboutBlankURL();
}

// Return true if display locked or inside slot recalc, false otherwise.
// Also returns false if not a safe time to perform the check.
bool IsDisplayLocked(const Node* node, bool inclusive = false) {
  if (!node)
    return false;
  // The IsDisplayLockedPreventingPaint() function may attempt to do
  // a flat tree traversal of ancestors. If we're in a flat tree traversal
  // forbidden scope, return false. Additionally, flat tree traversal
  // might call AssignedSlot, so if we're in a slot assignment recalc
  // forbidden scope, return false.
  if (node->GetDocument().IsFlatTreeTraversalForbidden() ||
      node->GetDocument()
          .GetSlotAssignmentEngine()
          .HasPendingSlotAssignmentRecalc()) {
    return false;  // Cannot safely perform this check now.
  }
  return DisplayLockUtilities::IsDisplayLockedPreventingPaint(node, inclusive);
}

bool IsDisplayLocked(const LayoutObject* object) {
  bool inclusive = false;
  while (object) {
    if (const auto* node = object->GetNode())
      return IsDisplayLocked(node, inclusive);
    inclusive = true;
    object = object->Parent();
  }
  return false;
}

bool IsActive(Document& document) {
  return document.IsActive() && !document.IsDetached();
}

bool HasAriaCellRole(Element* elem) {
  DCHECK(elem);
  const AtomicString& role_str =
      AXObject::AriaAttribute(*elem, html_names::kRoleAttr);
  if (role_str.empty())
    return false;

  return ui::IsCellOrTableHeader(
      AXObject::FirstValidRoleInRoleString(role_str));
}

// Return true if whitespace is not necessary to keep adjacent_node separate
// in screen reader output from surrounding nodes.
bool CanIgnoreSpaceNextTo(LayoutObject* layout_object,
                          bool is_after,
                          int counter = 0) {
  if (!layout_object)
    return true;

  if (counter > 3)
    return false;  // Don't recurse more than 3 times.

  auto* elem = DynamicTo<Element>(layout_object->GetNode());

  // Can usually ignore space next to a <br>.
  // Exception: if the space was next to a <br> with an ARIA role.
  if (layout_object->IsBR()) {
    // As an example of a <br> with a role, Google Docs uses:
    // <span contenteditable=false> <br role="presentation></span>.
    // This construct hides the <br> from the AX tree and uses the space
    // instead, presenting a hard line break as a soft line break.
    DCHECK(elem);
    return !is_after ||
           !AXObject::HasAriaAttribute(*elem, html_names::kRoleAttr);
  }

  // If adjacent to a whitespace character, the current space can be ignored.
  if (layout_object->IsText()) {
    auto* layout_text = To<LayoutText>(layout_object);
    if (layout_text->HasEmptyText())
      return false;
    if (layout_text->TransformedText()
            .Impl()
            ->ContainsOnlyWhitespaceOrEmpty()) {
      return true;
    }
    auto adjacent_char =
        is_after ? layout_text->FirstCharacterAfterWhitespaceCollapsing()
                 : layout_text->LastCharacterAfterWhitespaceCollapsing();
    return adjacent_char == ' ' || adjacent_char == '\n' ||
           adjacent_char == '\t';
  }

  // Keep spaces between images and other visible content, in case the image is
  // used inline as a symbol mimicking text. This is not necessary for other
  // types of images, such as a canvas.
  // Note that relying the layout object via IsLayoutImage() was a cause of
  // flakiness, as the layout object could change to a LayoutBlockFlow if the
  // image failed to load. However, we still check IsLayoutImage() in order
  // to detect CSS images, which don't have the same issue of changing layout.
  if (layout_object->IsLayoutImage() || IsA<HTMLImageElement>(elem) ||
      (IsA<HTMLInputElement>(elem) &&
       To<HTMLInputElement>(elem)->FormControlType() ==
           FormControlType::kInputImage)) {
    return false;
  }

  // Do not keep spaces between blocks.
  if (!layout_object->IsLayoutInline())
    return true;

  // If next to an element that a screen reader will always read separately,
  // the the space can be ignored.
  // Elements that are naturally focusable even without a tabindex tend
  // to be rendered separately even if there is no space between them.
  // Some ARIA roles act like table cells and don't need adjacent whitespace to
  // indicate separation.
  // False negatives are acceptable in that they merely lead to extra whitespace
  // static text nodes.
  if (elem && HasAriaCellRole(elem))
    return true;

  // Test against the appropriate child text node.
  auto* layout_inline = To<LayoutInline>(layout_object);
  LayoutObject* child =
      is_after ? layout_inline->FirstChild() : layout_inline->LastChild();
  if (!child && elem) {
    // No children of inline element. Check adjacent sibling in same direction.
    Node* adjacent_node =
        is_after ? NodeTraversal::NextIncludingPseudoSkippingChildren(*elem)
                 : NodeTraversal::PreviousAbsoluteSiblingIncludingPseudo(*elem);
    return adjacent_node &&
           CanIgnoreSpaceNextTo(adjacent_node->GetLayoutObject(), is_after,
                                ++counter);
  }
  return CanIgnoreSpaceNextTo(child, is_after, ++counter);
}

bool CanIgnoreSpace(const LayoutText& layout_text) {
  Node* node = layout_text.GetNode();

  // Will now look at sibling nodes. We need the closest element to the
  // whitespace markup-wise, e.g. tag1 in these examples:
  // [whitespace] <tag1><tag2>x</tag2></tag1>
  // <span>[whitespace]</span> <tag1><tag2>x</tag2></tag1>.
  // Do not use LayoutTreeBuilderTraversal or FlatTreeTraversal as this may need
  // to be called during slot assignment, when flat tree traversal is forbidden.
  Node* prev_node =
      NodeTraversal::PreviousAbsoluteSiblingIncludingPseudo(*node);
  if (!prev_node)
    return false;

  Node* next_node = NodeTraversal::NextIncludingPseudoSkippingChildren(*node);
  if (!next_node)
    return false;

  // Ignore extra whitespace-only text if a sibling will be presented
  // separately by screen readers whether whitespace is there or not.
  if (CanIgnoreSpaceNextTo(prev_node->GetLayoutObject(), false) ||
      CanIgnoreSpaceNextTo(next_node->GetLayoutObject(), true)) {
    return false;
  }

  // If the prev/next node is also a text node and the adjacent character is
  // not whitespace, CanIgnoreSpaceNextTo will return false. In some cases that
  // is what we want; in other cases it is not. Examples:
  //
  // 1a: <p><span>Hello</span><span>[whitespace]</span><span>World</span></p>
  // 1b: <p><span>Hello</span>[whitespace]<span>World</span></p>
  // 2:  <div><ul><li style="display:inline;">x</li>[whitespace]</ul>y</div>
  //
  // In the first case, we want to preserve the whitespace (crbug.com/435765).
  // In the second case, the whitespace in the markup is not relevant because
  // the "x" is separated from the "y" by virtue of being inside a different
  // block. In order to distinguish these two scenarios, we can use the
  // LayoutBox associated with each node. For the first scenario, each node's
  // LayoutBox is the LayoutBlockFlow associated with the <p>. For the second
  // scenario, the LayoutBox of "x" and the whitespace is the LayoutBlockFlow
  // associated with the <ul>; the LayoutBox of "y" is the one associated with
  // the <div>.
  LayoutBox* box = layout_text.EnclosingBox();
  if (!box)
    return false;

  if (prev_node->GetLayoutObject() && prev_node->GetLayoutObject()->IsText()) {
    LayoutBox* prev_box = prev_node->GetLayoutObject()->EnclosingBox();
    if (prev_box != box)
      return false;
  }

  if (next_node->GetLayoutObject() && next_node->GetLayoutObject()->IsText()) {
    LayoutBox* next_box = next_node->GetLayoutObject()->EnclosingBox();
    if (next_box != box)
      return false;
  }

  return true;
}

bool IsLayoutTextRelevantForAccessibility(const LayoutText& layout_text) {
  if (!layout_text.Parent())
    return false;

  Node* node = layout_text.GetNode();
  DCHECK(node);  // Anonymous text is processed earlier, doesn't reach here.

#if DCHECK_IS_ON()
  DCHECK(node->GetDocument().Lifecycle().GetState() >=
         DocumentLifecycle::kAfterPerformLayout)
      << "Unclean document at lifecycle "
      << node->GetDocument().Lifecycle().ToString();
#endif

  // Ignore empty text.
  if (layout_text.HasEmptyText())
    return false;

  // Always keep if anything other than collapsible whitespace.
  if (!layout_text.IsAllCollapsibleWhitespace() || layout_text.IsBR())
    return true;

  // Use previous decision for this whitespace. This is helpful for performance,
  // consistency (flake reduction) and code simplicity, as we do not need to
  // recompute block subtrees when inline nodes change. It also helps ensure
  // that whitespace nodes do not change whether they store a layout object
  // at inopportune times.
  // TODO(accessibility) Convert this method and callers of it to member
  // methods so we can access whitespace_ignored_map_ directly.
  AXObjectCacheImpl* cache = static_cast<AXObjectCacheImpl*>(
      node->GetDocument().ExistingAXObjectCache());
  auto& whitespace_ignored_map = cache->whitespace_ignored_map();
  DOMNodeId whitespace_node_id = node->GetDomNodeId();
  auto it = whitespace_ignored_map.find(whitespace_node_id);
  if (it != whitespace_ignored_map.end()) {
    return it->value;
  }

  // Compute ignored value for whitespace and record decision.
  bool ignore_whitespace = CanIgnoreSpace(layout_text);
  // Memoize the result.
  whitespace_ignored_map.insert(whitespace_node_id, ignore_whitespace);
  return ignore_whitespace;
}

bool IsHiddenTextNodeRelevantForAccessibility(const Text& text_node,
                                              bool is_display_locked) {
  // Children of an <iframe> tag will always be replaced by a new Document,
  // either loaded from the iframe src or empty. In fact, we don't even parse
  // them and they are treated like one text node. Consider irrelevant.
  if (AXObject::IsFrame(text_node.parentElement()))
    return false;

  // Layout has more info available to determine if whitespace is relevant.
  // If display-locked, layout object may be missing or stale:
  // Assume that all display-locked text nodes are relevant, but only create
  // an AXNodeObject in order to avoid using a stale layout object.
  if (is_display_locked)
    return true;

  // If unrendered + no parent, it is in a shadow tree. Consider irrelevant.
  if (!text_node.parentElement()) {
    DCHECK(text_node.IsInShadowTree());
    return false;
  }

  // If unrendered and in <canvas>, consider even whitespace relevant.
  if (text_node.parentElement()->IsInCanvasSubtree())
    return true;

  // Must be unrendered because of CSS. Consider relevant if non-whitespace.
  // Allowing rendered non-whitespace to be considered relevant will allow
  // use for accessible relations such as labelledby and describedby.
  return !text_node.ContainsOnlyWhitespaceOrEmpty();
}

bool IsShadowContentRelevantForAccessibility(const Node* node) {
  DCHECK(node->ContainingShadowRoot());

  // Return false if inside a shadow tree of something that can't have children,
  // for example, an <img> has a user agent shadow root containing a <span> for
  // the alt text. Do not create an accessible for that as it would be unable
  // to have a parent that has it as a child.
  if (!AXObject::CanHaveChildren(To<Element>(*node->OwnerShadowHost()))) {
    return false;
  }

  if (node->IsInUserAgentShadowRoot()) {
    // Native <img> create extra child nodes to hold alt text, which are not
    // allowed as children. Note: images can have image map children, but these
    // are moved from the <map> descendants and are not descendants of the
    // image. See AXNodeObject::AddImageMapChildren().
    if (IsA<HTMLImageElement>(node->OwnerShadowHost())) {
      return false;
    }
    // aria-hidden subtrees can safely be pruned when it's in a UA shadow root.
    // Make an exception for file input, which needs to gather its name from
    // aria-hidden contents.
    if (const Element* element = DynamicTo<Element>(node)) {
      if (element->FastGetAttribute(html_names::kAriaHiddenAttr) == "true") {
        return false;
      }

      // <select>'s autofill preview should not be included in the accessibility
      // tree.
      if (element->ShadowPseudoId() ==
          shadow_element_names::kSelectAutofillPreview) {
        return false;
      }
    }
  }

  // If inside a <object>/<embed>, the shadow content is relevant only if it is
  // fallback content.
  if (const HTMLPlugInElement* plugin_element =
          DynamicTo<HTMLPlugInElement>(node->OwnerShadowHost())) {
    return plugin_element->UseFallbackContent();
  }

  // All other shadow content is relevant.
  return true;
}

bool IsLayoutObjectRelevantForAccessibility(const LayoutObject& layout_object) {
  if (layout_object.IsAnonymous()) {
    // Anonymous means there is no DOM node, and it's been inserted by the
    // layout engine within the tree. An example is an anonymous block that is
    // inserted as a parent of an inline where there are block siblings.
    return AXObjectCacheImpl::IsRelevantPseudoElementDescendant(layout_object);
  }

  if (layout_object.IsText())
    return IsLayoutTextRelevantForAccessibility(To<LayoutText>(layout_object));

  // An AXImageMapLink will be created, which does not store the LayoutObject.
  if (IsA<HTMLAreaElement>(layout_object.GetNode()))
    return false;

  return true;
}

bool IsSubtreePrunedForAccessibility(const Element* node) {
  if (IsA<HTMLAreaElement>(node) && !IsA<HTMLMapElement>(node->parentNode()))
    return true;  // <area> without parent <map> is not relevant.

  if (IsA<HTMLMapElement>(node))
    return true;  // Contains children for an img, but is not its own object.

  if (node->HasTagName(html_names::kColgroupTag) ||
      node->HasTagName(html_names::kColTag)) {
    return true;  // Affects table layout, but doesn't get it's own AXObject.
  }

  if (node->IsPseudoElement()) {
    if (!AXObjectCacheImpl::IsRelevantPseudoElement(*node))
      return true;
  }

  if (const HTMLSlotElement* slot =
          ToHTMLSlotElementIfSupportsAssignmentOrNull(node)) {
    if (!AXObjectCacheImpl::IsRelevantSlotElement(*slot))
      return true;
  }

  // An HTML <title> does not require an AXObject: the document's name is
  // retrieved directly via the inner text.
  if (IsA<HTMLTitleElement>(node))
    return true;

  // ::scroll-marker pseudo elements are attached to the
  // ::scroll-marker-group's layout object, so don't create them
  // here, instead they will be created as part of the
  // AXNodeObject::AddPseudoElementChildrenFromLayoutTree.
  if (node->IsScrollMarkerPseudoElement()) {
    return true;
  }

  return false;
}

// Return true if node is head/style/script or any descendant of those.
// Also returns true for descendants of any type of frame, because the frame
// itself is in the tree, but not DOM descendants (their contents are in a
// different document).
bool IsInPrunableHiddenContainerInclusive(const Node& node,
                                          bool parent_ax_known,
                                          bool is_display_locked) {
  int max_depth_to_check = INT_MAX;
  if (parent_ax_known) {
    // Optimization: only need to check the current object if the parent the
    // parent_ax is already known, because it we are attempting to add this
    // object from something already relevant in the AX tree, and therefore
    // can't be inside a <head>, <style>, <script> or SVG <style> element.
    // However, there is an edge case that if it is display locked content
    // we must also check the parent, which can be visible and included
    // in the tree. This edge case is handled to satisfy tests and is not
    // likely to be a real-world condition.
    max_depth_to_check = is_display_locked ? 2 : 1;
  }

  for (const Node* ancestor = &node; ancestor;
       ancestor = ancestor->parentElement()) {
    // Objects inside <head> are pruned.
    if (IsA<HTMLHeadElement>(ancestor))
      return true;
    // Objects inside a <style> are pruned.
    if (IsA<HTMLStyleElement>(ancestor))
      return true;
    // Objects inside a <script> are true.
    if (IsA<HTMLScriptElement>(ancestor))
      return true;
    // Elements inside of a frame/iframe are true unless inside a document
    // that is a child of the frame. In the case where descendants are allowed,
    // they will be in a different document, and therefore this loop will not
    // reach the frame/iframe.
    if (AXObject::IsFrame(ancestor))
      return true;
    // Style elements in SVG are not display: none, unlike HTML style
    // elements, but they are still hidden along with their contents and thus
    // treated as true for accessibility.
    if (IsA<SVGStyleElement>(ancestor))
      return true;

    if (--max_depth_to_check <= 0)
      break;
  }

  // All other nodes are relevant, even if hidden.
  return false;
}

// -----------------------------------------------------------------------------
// DetermineAXObjectType() determines what type of AXObject should be created
// for the given node and layout_object.
// * Pass in the Node, the LayoutObject or both.
// * Passing in |parent_ax_known| when there is  known parent is an optimization
// and does not affect the return value.
// Some general rules:
// * If neither the node nor layout object are relevant for accessibility, will
// return kPruneSubtree, which will cause no AXObject to be created, and
// result in the entire subtree being pruned at that point.
// * If the node is part of a forbidden subtree, then kPruneSubtree is used.
// * If both the node and layout are relevant, kCreateFromLayout is preferred,
// otherwise: kCreateFromNode for relevant nodes, kCreateFromLayout for layout.
// -----------------------------------------------------------------------------
AXObjectType DetermineAXObjectType(const Node* node,
                                   const LayoutObject* layout_object,
                                   bool parent_ax_known = false) {
  DCHECK(layout_object || node);
  bool is_display_locked =
      node ? IsDisplayLocked(node) : IsDisplayLocked(layout_object);
  if (is_display_locked)
    layout_object = nullptr;
  DCHECK(!node || !layout_object || layout_object->GetNode() == node);

  bool is_node_relevant = false;

  if (node) {
    if (!node->isConnected()) {
      return kPruneSubtree;
    }

    if (node->ContainingShadowRoot() &&
        !IsShadowContentRelevantForAccessibility(node)) {
      return kPruneSubtree;
    }

    if (!IsA<Element>(node) && !IsA<Text>(node)) {
      // All remaining types, such as the document node, doctype node.
      return layout_object ? kCreateFromLayout : kPruneSubtree;
    }

    if (const Element* element = DynamicTo<Element>(node)) {
      if (IsSubtreePrunedForAccessibility(element))
        return kPruneSubtree;
      else
        is_node_relevant = true;
    } else {  // Text is the only remaining type.
      if (layout_object) {
        // If there's layout for this text, it will either be pruned or an
        // AXNodeObject with layout will be created for it. The logic of whether
        // to return kCreateFromLayout or kPruneSubtree will come purely from
        // is_layout_relevant further down.
        return IsLayoutObjectRelevantForAccessibility(*layout_object)
                   ? kCreateFromLayout
                   : kPruneSubtree;
      } else {
        // Otherwise, base the decision on the best info we have on the node.
        is_node_relevant = IsHiddenTextNodeRelevantForAccessibility(
            To<Text>(*node), is_display_locked);
      }
    }
  }

  bool is_layout_relevant =
      layout_object && IsLayoutObjectRelevantForAccessibility(*layout_object);

  // Prune if neither the LayoutObject nor Node are relevant.
  if (!is_layout_relevant && !is_node_relevant)
    return kPruneSubtree;

  // If a node is not rendered, prune if it is in head/style/script or a DOM
  // descendant of an iframe.
  if (!is_layout_relevant && IsInPrunableHiddenContainerInclusive(
                                 *node, parent_ax_known, is_display_locked)) {
    return kPruneSubtree;
  }

  return is_layout_relevant ? kCreateFromLayout : kCreateFromNode;
}

const int kSizeMb = 1000000;
const int kSize10Mb = 10 * kSizeMb;
const int kSizeGb = 1000 * kSizeMb;
const int kBucketCount = 100;

void LogNodeDataSizeDistribution(
    const ui::AXNodeData::AXNodeDataSize& node_data_size) {
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.Int",
      base::saturated_cast<int>(node_data_size.int_attribute_size), 1,
      kSize10Mb, kBucketCount);
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.Float",
      base::saturated_cast<int>(node_data_size.float_attribute_size), 1,
      kSize10Mb, kBucketCount);
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.Bool",
      base::saturated_cast<int>(node_data_size.bool_attribute_size), 1, kSizeMb,
      kBucketCount);
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.String",
      base::saturated_cast<int>(node_data_size.string_attribute_size), 1,
      kSizeGb, kBucketCount);
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.IntList",
      base::saturated_cast<int>(node_data_size.int_list_attribhute_size), 1,
      kSize10Mb, kBucketCount);
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.StringList",
      base::saturated_cast<int>(node_data_size.string_list_attribute_size), 1,
      kSizeGb, kBucketCount);
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.HTML",
      base::saturated_cast<int>(node_data_size.html_attribute_size), 1, kSizeGb,
      kBucketCount);
  UMA_HISTOGRAM_CUSTOM_COUNTS(
      "Accessibility.Performance.AXObjectCacheImpl.Incremental.ChildIds",
      base::saturated_cast<int>(node_data_size.child_ids_size), 1, kSize10Mb,
      kBucketCount
```