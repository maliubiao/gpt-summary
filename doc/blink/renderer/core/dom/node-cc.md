Response:
My thought process to analyze the provided code snippet and fulfill the request goes like this:

1. **Understand the Goal:** The request asks for a summary of the `node.cc` file's functionality within the Chromium Blink rendering engine. It also requires relating this functionality to web technologies (JavaScript, HTML, CSS), providing examples, inferring logic (with input/output examples), identifying potential user/programming errors, describing user actions that lead to this code, and finally, summarizing the function of the provided snippet (the first part).

2. **Initial Code Scan (Headers and Namespaces):** I'll start by looking at the included headers. These give a broad overview of the areas the `Node` class interacts with:
    * **Core DOM:** `dom/node.h`, `dom/attr.h`, `dom/element.h`, `dom/text.h`, `dom/document.h`, etc. This strongly suggests the file deals with the fundamental building blocks of the DOM tree.
    * **Bindings (V8):** `bindings/core/v8/...`. This indicates interaction with JavaScript.
    * **CSS:** `css/css_selector.h`, `css/resolver/style_resolver.h`, `css/style_engine.h`. This points to how nodes relate to styling.
    * **Events:** `dom/events/...`, `events/...`. Nodes are central to event handling.
    * **Layout:** `layout/...`. Nodes are part of the rendering process.
    * **Accessibility:** `accessibility/ax_object_cache.h`. Accessibility information is associated with nodes.
    * **Other areas:**  Animation, display locking, editing, fullscreen, HTML-specific elements, input, inspector, painting, SVG, view transitions, etc. These suggest the `Node` class is a foundational component used across various rendering engine features.

3. **Identify Key Responsibilities (Based on Headers and Class Members):**
    * **DOM Tree Structure:** The presence of `parent_or_shadow_host_node_`, `previous_`, `next_`, and methods like `insertBefore`, `removeChild`, `appendChild` strongly indicate the management of the DOM tree hierarchy.
    * **Node Properties:** Methods like `nodeValue`, `nodeName`, `nodeType` are about accessing basic node information.
    * **Event Handling:** The inclusion of event-related headers and the base class `EventTarget` signify the role of `Node` in event dispatching and handling.
    * **Styling:** The inclusion of CSS-related headers and mentions of layout objects suggest involvement in applying styles and creating the render tree.
    * **Relationships:**  Methods to get ancestors, descendants, and siblings are crucial for navigating the DOM.
    * **Cloning:** The presence of `NodeCloningData` suggests support for copying nodes.
    * **Rare Data:** The `NodeRareData` and `ElementRareDataVector` suggest optimization by storing less frequently used data separately.
    * **Pseudo-elements:** The `PseudoAwarePreviousSibling`, `PseudoAwareNextSibling`, `PseudoAwareFirstChild`, `PseudoAwareLastChild` methods explicitly deal with the concept of CSS pseudo-elements.

4. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The `Node` class represents elements, attributes, text nodes, comments, and other components defined in HTML. Parsing HTML creates instances of `Node` subclasses.
    * **CSS:** CSS selectors target `Node` objects. The styling applied affects the `layout_object_` associated with `Element` nodes. Pseudo-elements, which are part of CSS, are explicitly handled.
    * **JavaScript:**  JavaScript interacts with the DOM through the `Node` interface. JavaScript can create, modify, delete, and traverse `Node` objects. Event listeners in JavaScript are attached to `Node` objects. The V8 binding headers confirm this interaction.

5. **Infer Logic and Provide Examples:**
    * **Tree Manipulation:**  `insertBefore` adds a node before another. *Input:* A parent `Element`, a `new_child` `Element`, and a `ref_child` `Element` that's already a child. *Output:* `new_child` is inserted before `ref_child`.
    * **Event Handling:**  An event listener attached to a button. *Input:* A button `Element`, an event type "click", a JavaScript function. *Output:* When the button is clicked, the JavaScript function is executed.
    * **CSS Styling:** A CSS rule like `p { color: blue; }`. *Input:* A `<p>` element. *Output:* The text color of the `<p>` element is blue.

6. **Identify Potential Errors:**
    * **Hierarchy Errors:** Trying to insert a node where it doesn't belong (e.g., inserting a `Document` as a child of an `Element`).
    * **Incorrect Node Types:**  Attempting an operation on a node type that doesn't support it (e.g., calling `insertBefore` on a text node).
    * **Detached Nodes:**  Manipulating nodes that are no longer part of the DOM.

7. **Describe User Actions Leading to This Code:**  Every interaction with a webpage that modifies the DOM or triggers events will involve `node.cc`. Examples:
    * Clicking a button.
    * Submitting a form.
    * JavaScript code that manipulates the DOM (e.g., `document.createElement`, `element.appendChild`).
    * The browser parsing HTML and CSS.
    * Animations and transitions.

8. **Summarize the Functionality of the Snippet (Part 1):** Based on the analysis, the first part of `node.cc` focuses on:
    * **Core Node Class Definition:**  Defining the fundamental `Node` class and its basic attributes.
    * **DOM Tree Management:** Providing core methods for manipulating the tree structure (insertion, deletion, navigation).
    * **Event Handling Foundation:** Integrating with the event system through the `EventTarget` base class.
    * **Relationships and Traversal:** Offering methods to navigate the DOM tree (parent, children, siblings).
    * **Interaction with Other Blink Components:**  Including headers related to CSS, layout, accessibility, etc., indicating its central role.
    * **JavaScript Binding:**  Preparing the `Node` class for interaction with JavaScript.
    * **Optimization:** Using `NodeRareData` for less frequently used data.
    * **Debugging and Statistics:** Including code for dumping node statistics (conditional compilation).

By following this thought process, I can systematically analyze the code, extract its core functionalities, relate them to web technologies, and address all aspects of the request. The detailed examination of headers and the initial code structure is crucial for understanding the scope and purpose of the file.

## 对 blink/renderer/core/dom/node.cc (第1部分) 功能的归纳

根据提供的代码片段，`blink/renderer/core/dom/node.cc` 文件的主要功能是**定义和实现了 Blink 渲染引擎中 DOM (文档对象模型) 的核心基类 `Node`**。  它是所有 DOM 节点类型的基类，例如 Element, Text, Document 等。

**具体功能点包括:**

1. **DOM 树结构的管理:**
   - 维护了节点在 DOM 树中的基本关系，例如父节点 (`parent_or_shadow_host_node_`)、前一个兄弟节点 (`previous_`)、后一个兄弟节点 (`next_`)。
   - 提供了插入节点 (`insertBefore`) 和移动节点 (`moveBefore`) 的基本方法。

2. **节点的基本属性和方法:**
   - 定义了节点的通用属性，例如 `nodeValue`。
   - 提供了获取子节点列表 (`childNodes`) 的方法。
   - 提供了获取根节点 (`TreeRoot`, `getRootNode`) 的方法。

3. **事件处理的基础:**
   - `Node` 类继承自 `EventTarget`，使其能够成为事件的目标，并支持添加和移除事件监听器（虽然具体的事件处理逻辑可能在其他地方实现）。

4. **与渲染引擎其他组件的交互:**
   - 包含了大量与其他 Blink 核心模块的头文件，例如：
     - **CSS:**  `css_selector.h`, `style_resolver.h`, `style_engine.h` (表明节点与样式计算和应用有关)。
     - **Layout:** `layout_object.h` (表明节点与布局对象关联)。
     - **Accessibility:** `accessibility/ax_object_cache.h` (表明节点与可访问性信息关联)。
     - **Events:**  `events/...` (更详细的事件相关类)。
     - **DOM 相关:**  `attr.h`, `element.h`, `text.h`, `document.h` 等 (与其他 DOM 节点类型的定义交互)。

5. **伪元素的支持:**
   - 提供了处理伪元素的方法，例如 `PseudoAwarePreviousSibling`, `PseudoAwareNextSibling`, `PseudoAwareFirstChild`, `PseudoAwareLastChild`，这使得节点能够感知并遍历包括 CSS 伪元素在内的节点树。

6. **节点标识:**
   - 提供了获取和根据 ID 查找节点的方法 (`GetDomNodeId`, `FromDomNodeId`)。

7. **内部数据管理:**
   - 使用 `NodeRareData` 和 `ElementRareDataVector` 来存储一些不常用的节点数据，以优化内存使用。

8. **调试和统计:**
   - 包含了用于统计节点数量和类型的信息 (`DUMP_NODE_STATISTICS`)，用于调试和性能分析。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **HTML:**  HTML 标签在渲染引擎中会被解析成 `Node` 对象的实例。例如，`<p>` 标签会生成一个 `Element` 类型的 `Node` 对象，标签内的文本会生成 `Text` 类型的 `Node` 对象。
* **JavaScript:**  JavaScript 可以通过 DOM API 与 `Node` 对象进行交互。
    - **例子 1 (假设输入与输出):**
      ```javascript
      // 假设页面上有一个 id 为 "myDiv" 的 div 元素
      const myDiv = document.getElementById('myDiv'); // 输入：HTML 中存在 id 为 "myDiv" 的元素
      console.log(myDiv.nodeName); // 输出： "DIV" (取决于浏览器实现，可能是大写)
      ```
    - **例子 2 (假设输入与输出):**
      ```javascript
      const newParagraph = document.createElement('p'); // 输入：调用 createElement
      const textNode = document.createTextNode('Hello'); // 输入：调用 createTextNode
      newParagraph.appendChild(textNode);
      myDiv.insertBefore(newParagraph, myDiv.firstChild); // 输入：调用 insertBefore
      // 输出：一个新的 <p> 元素被插入到 id 为 "myDiv" 的 div 元素的第一个子节点之前。
      ```
* **CSS:** CSS 样式规则会影响 `Node` 对象的渲染。
    - **例子:**  CSS 规则 `p { color: blue; }` 会影响所有 `<p>` 标签对应的 `Element` 节点的文本颜色。渲染引擎会遍历 DOM 树，找到匹配选择器的节点，并应用相应的样式。

**用户或编程常见的使用错误举例说明:**

* **类型错误:** 尝试将一个不允许作为子节点的节点类型插入到另一个节点中。例如，尝试将 `Document` 节点插入到 `Element` 节点中，会导致 `HierarchyRequestError`。
    - **用户操作:** 用户不太可能直接触发此类错误，这通常是编程错误。
    - **调试线索:**  在 JavaScript 中调用了 `insertBefore` 或类似的方法，传入了不兼容的节点类型。
* **在错误的父节点上操作:** 尝试在一个节点上调用 `insertBefore`，但传入的 `ref_child` 并不是该节点的直接子节点。
    - **用户操作:**  同样，这通常是编程错误。
    - **调试线索:**  检查 `insertBefore` 的第二个参数，确认它是否是第一个参数节点的直接子节点。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中打开一个网页。**
2. **浏览器开始解析 HTML 代码，构建 DOM 树。**  每当解析到一个 HTML 标签、文本内容等，Blink 引擎会创建相应的 `Node` 对象实例（例如 `Element`, `Text`）。 `node.cc` 中的代码会被调用来创建和连接这些节点。
3. **用户与网页进行交互，例如点击按钮、填写表单。** 这些交互可能触发 JavaScript 代码的执行。
4. **JavaScript 代码调用 DOM API 来修改 DOM 结构或样式。** 例如，使用 `document.createElement()`, `element.appendChild()`, `element.insertBefore()` 等方法。  这些方法最终会调用 `node.cc` 中实现的相应 C++ 方法。
5. **CSS 引擎根据 CSS 规则和 DOM 结构计算节点的样式。**  这会涉及到遍历 DOM 树，访问 `Node` 对象的属性，并创建关联的布局对象。
6. **如果出现错误，例如 JavaScript 代码尝试执行上述的错误操作，浏览器的开发者工具可能会显示错误信息。**  调试时，开发者可能会查看调用栈，发现最终调用到了 `node.cc` 中的相关方法，从而定位问题。

**总结 `node.cc` 第一部分的功能:**

总而言之，`blink/renderer/core/dom/node.cc` 的第一部分主要定义了 `Node` 类，这个核心类是 Blink 渲染引擎中表示 DOM 结构的基础。它负责维护 DOM 树的基本结构，提供操作 DOM 树的通用方法，并为事件处理和与渲染引擎其他组件的交互提供了基础。它定义了所有 DOM 节点共有的属性和行为，是理解 Blink DOM 实现的关键入口点。

### 提示词
```
这是目录为blink/renderer/core/dom/node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011 Apple Inc. All
 * rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2009 Torch Mobile Inc. All rights reserved.
 * (http://www.torchmobile.com/)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public License
 * along with this library; see the file COPYING.LIB.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "third_party/blink/renderer/core/dom/node.h"

#include <algorithm>

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_get_root_node_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_node_string_trustedscript.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_union_string_trustedscript.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/animation/scroll_timeline.h"
#include "third_party/blink/renderer/core/css/css_selector.h"
#include "third_party/blink/renderer/core/css/resolver/style_resolver.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_document_state.h"
#include "third_party/blink/renderer/core/display_lock/display_lock_utilities.h"
#include "third_party/blink/renderer/core/dom/attr.h"
#include "third_party/blink/renderer/core/dom/attribute.h"
#include "third_party/blink/renderer/core/dom/child_list_mutation_scope.h"
#include "third_party/blink/renderer/core/dom/child_node_list.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/document_part_root.h"
#include "third_party/blink/renderer/core/dom/document_type.h"
#include "third_party/blink/renderer/core/dom/dom_node_ids.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_rare_data_vector.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/add_event_listener_options_resolved.h"
#include "third_party/blink/renderer/core/dom/events/event.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatcher.h"
#include "third_party/blink/renderer/core/dom/events/event_listener.h"
#include "third_party/blink/renderer/core/dom/events/event_path.h"
#include "third_party/blink/renderer/core/dom/events/mutation_event_suppression_scope.h"
#include "third_party/blink/renderer/core/dom/flat_tree_node_data.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/mutation_observer_registration.h"
#include "third_party/blink/renderer/core/dom/node_cloning_data.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/dom/node_rare_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/part.h"
#include "third_party/blink/renderer/core/dom/processing_instruction.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_engine.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/template_content_document_fragment.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/dom/text_visitor.h"
#include "third_party/blink/renderer/core/dom/tree_scope_adopter.h"
#include "third_party/blink/renderer/core/dom/user_action_element_set.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/event_target_names.h"
#include "third_party/blink/renderer/core/events/event_util.h"
#include "third_party/blink/renderer/core/events/gesture_event.h"
#include "third_party/blink/renderer/core/events/input_event.h"
#include "third_party/blink/renderer/core/events/keyboard_event.h"
#include "third_party/blink/renderer/core/events/mouse_event.h"
#include "third_party/blink/renderer/core/events/mutation_event.h"
#include "third_party/blink/renderer/core/events/pointer_event.h"
#include "third_party/blink/renderer/core/events/pointer_event_factory.h"
#include "third_party/blink/renderer/core/events/text_event.h"
#include "third_party/blink/renderer/core/events/touch_event.h"
#include "third_party/blink/renderer/core/events/ui_event.h"
#include "third_party/blink/renderer/core/events/wheel_event.h"
#include "third_party/blink/renderer/core/exported/web_plugin_container_impl.h"
#include "third_party/blink/renderer/core/frame/event_handler_registry.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/visual_viewport.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/custom/custom_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_slot_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input/event_handler.h"
#include "third_party/blink/renderer/core/input/input_device_capabilities.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_embedded_content.h"
#include "third_party/blink/renderer/core/layout/layout_shift_tracker.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/mathml_names.h"
#include "third_party/blink/renderer/core/page/context_menu_controller.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/core/page/scrolling/top_document_root_scroller_controller.h"
#include "third_party/blink/renderer/core/paint/paint_layer.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/style/computed_style_constants.h"
#include "third_party/blink/renderer/core/svg/graphics/svg_image.h"
#include "third_party/blink/renderer/core/svg/svg_element.h"
#include "third_party/blink/renderer/core/trustedtypes/trusted_script.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_pseudo_element_base.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_supplement.h"
#include "third_party/blink/renderer/core/view_transition/view_transition_utils.h"
#include "third_party/blink/renderer/core/xml_names.h"
#include "third_party/blink/renderer/core/xmlns_names.h"
#include "third_party/blink/renderer/platform/bindings/dom_data_store.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/v8_dom_wrapper.h"
#include "third_party/blink/renderer/platform/graphics/dom_node_id.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_hash_set.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/instance_counters.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/traced_value.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/allocator/partitions.h"
#include "third_party/blink/renderer/platform/wtf/hash_set.h"
#include "third_party/blink/renderer/platform/wtf/size_assertions.h"
#include "third_party/blink/renderer/platform/wtf/text/character_visitor.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

using ReattachHookScope = LayoutShiftTracker::ReattachHookScope;

// We want to keep Node small.  This struct + assert calls our attention to a
// change that might be undesirable, so that we make sure to consider whether
// it's worthwhile.
struct SameSizeAsNode : EventTarget {
  uint32_t node_flags_;
  subtle::UncompressedMember<int> uncompressed[2];
  Member<void*> members[4];
};

ASSERT_SIZE(Node, SameSizeAsNode);

// Right now we have the member variables of Node ordered so as to
// reduce padding.  If the object layout of its base class changes, this
// ordering might stop being optimal.  This struct + assert are intended
// to catch if that happens, so that we can reorder the members again.
struct NotSmallerThanNode : EventTarget {
  subtle::UncompressedMember<int> uncompressed[2];
  Member<void*> members[4];
  uint32_t node_flags_;
};

static_assert(sizeof(Node) <= sizeof(NotSmallerThanNode),
              "members of node should be reordered for better packing");

#if DUMP_NODE_STATISTICS
using WeakNodeSet = HeapHashSet<WeakMember<Node>>;
static WeakNodeSet& LiveNodeSet() {
  DEFINE_STATIC_LOCAL(Persistent<WeakNodeSet>, set,
                      (MakeGarbageCollected<WeakNodeSet>()));
  return *set;
}

void Node::DumpStatistics() {
  size_t nodes_with_rare_data = 0;

  size_t element_nodes = 0;
  size_t attr_nodes = 0;
  size_t text_nodes = 0;
  size_t cdata_nodes = 0;
  size_t comment_nodes = 0;
  size_t pi_nodes = 0;
  size_t document_nodes = 0;
  size_t doc_type_nodes = 0;
  size_t fragment_nodes = 0;
  size_t shadow_root_nodes = 0;

  HashMap<String, size_t> per_tag_count;

  size_t attributes = 0;
  size_t elements_with_attribute_storage = 0;
  size_t elements_with_rare_data = 0;
  size_t elements_with_named_node_map = 0;

  {
    ScriptForbiddenScope forbid_script_during_raw_iteration;
    for (Node* node : LiveNodeSet()) {
      if (node->data_) {
        ++nodes_with_rare_data;
        if (auto* element = DynamicTo<Element>(node)) {
          ++elements_with_rare_data;
          if (element->HasNamedNodeMap())
            ++elements_with_named_node_map;
        }
      }

      switch (node->getNodeType()) {
        case kElementNode: {
          ++element_nodes;

          // Tag stats
          auto* element = To<Element>(node);
          auto result = per_tag_count.insert(element->tagName(), 1);
          if (!result.is_new_entry)
            result.stored_value->value++;

          size_t attributeCount = element->AttributesWithoutUpdate().size();
          if (attributeCount) {
            attributes += attributeCount;
            ++elements_with_attribute_storage;
          }
          break;
        }
        case kAttributeNode: {
          ++attr_nodes;
          break;
        }
        case kTextNode: {
          ++text_nodes;
          break;
        }
        case kCdataSectionNode: {
          ++cdata_nodes;
          break;
        }
        case kCommentNode: {
          ++comment_nodes;
          break;
        }
        case kProcessingInstructionNode: {
          ++pi_nodes;
          break;
        }
        case kDocumentNode: {
          ++document_nodes;
          break;
        }
        case kDocumentTypeNode: {
          ++doc_type_nodes;
          break;
        }
        case kDocumentFragmentNode: {
          if (node->IsShadowRoot())
            ++shadow_root_nodes;
          else
            ++fragment_nodes;
          break;
        }
      }
    }
  }

  std::stringstream per_tag_stream;
  for (const auto& entry : per_tag_count) {
    per_tag_stream << "  Number of <" << entry.key.Utf8().data()
                   << "> tags: " << entry.value << "\n";
  }

  LOG(INFO) << "\n"
            << "Number of Nodes: " << LiveNodeSet().size() << "\n"
            << "Number of Nodes with RareData: " << nodes_with_rare_data
            << "\n\n"

            << "NodeType distribution:\n"
            << "  Number of Element nodes: " << element_nodes << "\n"
            << "  Number of Attribute nodes: " << attr_nodes << "\n"
            << "  Number of Text nodes: " << text_nodes << "\n"
            << "  Number of CDATASection nodes: " << cdata_nodes << "\n"
            << "  Number of Comment nodes: " << comment_nodes << "\n"
            << "  Number of ProcessingInstruction nodes: " << pi_nodes << "\n"
            << "  Number of Document nodes: " << document_nodes << "\n"
            << "  Number of DocumentType nodes: " << doc_type_nodes << "\n"
            << "  Number of DocumentFragment nodes: " << fragment_nodes << "\n"
            << "  Number of ShadowRoot nodes: " << shadow_root_nodes << "\n"

            << "Element tag name distribution:\n"
            << per_tag_stream.str()

            << "Attributes:\n"
            << "  Number of Attributes (non-Node and Node): " << attributes
            << " x " << sizeof(Attribute) << "Bytes\n"
            << "  Number of Elements with attribute storage: "
            << elements_with_attribute_storage << " x " << sizeof(ElementData)
            << "Bytes\n"
            << "  Number of Elements with RareData: " << elements_with_rare_data
            << " x " << sizeof(ElementRareData) << "Bytes\n"
            << "  Number of Elements with NamedNodeMap: "
            << elements_with_named_node_map << " x " << sizeof(NamedNodeMap)
            << "Bytes";
}
#endif

Node::Node(TreeScope* tree_scope, ConstructionType type)
    : node_flags_(type),
      parent_or_shadow_host_node_(nullptr),
      tree_scope_(tree_scope),
      previous_(nullptr),
      next_(nullptr),
      layout_object_(nullptr),
      data_(nullptr) {
  DCHECK(tree_scope_ || type == kCreateDocument || type == kCreateShadowRoot);
#if DUMP_NODE_STATISTICS
  LiveNodeSet().insert(this);
#endif
  InstanceCounters::IncrementCounter(InstanceCounters::kNodeCounter);
  // Document is required for probe sink.
  if (tree_scope_)
    probe::NodeCreated(this);
}

Node::~Node() {
  InstanceCounters::DecrementCounter(InstanceCounters::kNodeCounter);
}

DOMNodeId Node::GetDomNodeId() {
  return DOMNodeIds::IdForNode(this);
}

// static
Node* Node::FromDomNodeId(DOMNodeId dom_node_id) {
  return DOMNodeIds::NodeForId(dom_node_id);
}

NodeRareData& Node::CreateRareData() {
  if (IsElementNode()) {
    data_ = MakeGarbageCollected<ElementRareDataVector>();
  } else {
    data_ = MakeGarbageCollected<NodeRareData>();
  }
  return *data_;
}

Node* Node::ToNode() {
  return this;
}

String Node::nodeValue() const {
  return String();
}

void Node::setNodeValue(const String&, ExceptionState&) {
  // By default, setting nodeValue has no effect.
}

NodeList* Node::childNodes() {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (this_node)
    return EnsureRareData().EnsureNodeLists().EnsureChildNodeList(*this_node);
  return EnsureRareData().EnsureNodeLists().EnsureEmptyChildNodeList(*this);
}

Node* Node::PseudoAwarePreviousSibling() const {
  Element* parent = parentElement();
  if (!parent || HasPreviousSibling()) {
    return previousSibling();
  }

  // Note the [[fallthrough]] attributes, the order of the cases matters and
  // corresponds to the ordering of pseudo elements in a traversal:
  // ::scroll-marker-group(before), ::marker, ::scroll-marker, ::check,
  // ::before, non-pseudo Elements, ::after, ::select-arrow,
  // ::scroll-marker-group(after), ::view-transition. The fallthroughs ensure
  // this ordering by checking for each kind of node in-turn.
  switch (GetPseudoId()) {
    case kPseudoIdViewTransition:
      if (Node* previous =
              parent->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdScrollNextButton:
      if (Node* next =
              parent->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupAfter:
      if (Node* next = parent->GetPseudoElement(kPseudoIdSelectArrow)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdSelectArrow:
      if (Node* next = parent->GetPseudoElement(kPseudoIdAfter)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdAfter:
      if (Node* previous = parent->lastChild())
        return previous;
      [[fallthrough]];
    case kPseudoIdNone:
      if (Node* previous = parent->GetPseudoElement(kPseudoIdBefore))
        return previous;
      [[fallthrough]];
    case kPseudoIdBefore:
      if (Node* previous = parent->GetPseudoElement(kPseudoIdCheck)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdCheck:
      if (Node* previous = parent->GetPseudoElement(kPseudoIdScrollMarker)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarker:
      if (Node* previous = parent->GetPseudoElement(kPseudoIdMarker)) {
        return previous;
      }
      [[fallthrough]];
    case kPseudoIdMarker:
      if (Node* next =
              parent->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupBefore:
      if (Node* next = parent->GetPseudoElement(kPseudoIdScrollPrevButton)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollPrevButton:
      return nullptr;
    // The pseudos of the view transition subtree have a known structure and
    // cannot create other pseudos so these are handled separately of the above
    // fallthrough cases. For details on view-transition pseudo ordering, see
    // https://chromium.googlesource.com/chromium/src/+/main/third_party/blink/renderer/core/view_transition/README.md#pseudo-element-traversal
    case kPseudoIdViewTransitionNew:
      CHECK_EQ(parent->GetPseudoId(), kPseudoIdViewTransitionImagePair);
      return parent->GetPseudoElement(
          kPseudoIdViewTransitionOld,
          To<PseudoElement>(this)->view_transition_name());
    case kPseudoIdViewTransitionGroup: {
      const Vector<AtomicString>& names =
          GetDocument().GetStyleEngine().ViewTransitionTags();
      wtf_size_t found_index =
          names.Find(To<PseudoElement>(this)->view_transition_name());
      CHECK_NE(found_index, kNotFound);
      if (found_index == 0) {
        return nullptr;
      }

      CHECK_EQ(parent->GetPseudoId(), kPseudoIdViewTransition);
      return parent->GetPseudoElement(kPseudoIdViewTransitionGroup,
                                      names[found_index - 1]);
    }
    case kPseudoIdViewTransitionImagePair:
    case kPseudoIdViewTransitionOld:
      return nullptr;
    default:
      NOTREACHED();
  }
}

Node* Node::PseudoAwareNextSibling() const {
  Element* parent = parentElement();
  if (!parent || HasNextSibling()) {
    return nextSibling();
  }

  // See comments in PseudoAwarePreviousSibling.
  switch (GetPseudoId()) {
    case kPseudoIdScrollPrevButton:
      if (Node* next =
              parent->GetPseudoElement(kPseudoIdScrollMarkerGroupBefore)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupBefore:
      if (Node* next = parent->GetPseudoElement(kPseudoIdMarker)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdMarker:
      if (Node* next = parent->GetPseudoElement(kPseudoIdScrollMarker)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarker:
      if (Node* next = parent->GetPseudoElement(kPseudoIdCheck)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdCheck:
      if (Node* next = parent->GetPseudoElement(kPseudoIdBefore))
        return next;
      [[fallthrough]];
    case kPseudoIdBefore:
      if (parent->HasChildren())
        return parent->firstChild();
      [[fallthrough]];
    case kPseudoIdNone:
      if (Node* next = parent->GetPseudoElement(kPseudoIdAfter))
        return next;
      [[fallthrough]];
    case kPseudoIdAfter:
      if (Node* next = parent->GetPseudoElement(kPseudoIdSelectArrow)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdSelectArrow:
      if (Node* next =
              parent->GetPseudoElement(kPseudoIdScrollMarkerGroupAfter)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollMarkerGroupAfter:
      if (Node* next = parent->GetPseudoElement(kPseudoIdScrollNextButton)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdScrollNextButton:
      if (Node* next = parent->GetPseudoElement(kPseudoIdViewTransition)) {
        return next;
      }
      [[fallthrough]];
    case kPseudoIdViewTransition:
      return nullptr;
    case kPseudoIdViewTransitionOld:
      CHECK_EQ(parent->GetPseudoId(), kPseudoIdViewTransitionImagePair);
      return parent->GetPseudoElement(
          kPseudoIdViewTransitionNew,
          To<PseudoElement>(this)->view_transition_name());
    case kPseudoIdViewTransitionGroup: {
      const Vector<AtomicString>& names =
          GetDocument().GetStyleEngine().ViewTransitionTags();
      wtf_size_t found_index =
          names.Find(To<PseudoElement>(this)->view_transition_name());
      CHECK_NE(found_index, kNotFound);
      if (found_index == names.size() - 1) {
        return nullptr;
      }

      CHECK_EQ(parent->GetPseudoId(), kPseudoIdViewTransition);
      return parent->GetPseudoElement(kPseudoIdViewTransitionGroup,
                                      names[found_index + 1]);
    }
    case kPseudoIdViewTransitionImagePair:
    case kPseudoIdViewTransitionNew:
      return nullptr;
    default:
      NOTREACHED();
  }
}

Node* Node::PseudoAwareFirstChild() const {
  if (const auto* current_element = DynamicTo<Element>(this)) {
    // See comments in PseudoAwarePreviousSibling for details on view-transition
    // pseudo traversal.
    if (GetPseudoId() == kPseudoIdViewTransition) {
      const Vector<AtomicString>& names =
          GetDocument().GetStyleEngine().ViewTransitionTags();
      if (names.empty()) {
        return nullptr;
      }
      return current_element->GetPseudoElement(kPseudoIdViewTransitionGroup,
                                               names.front());
    }
    if (GetPseudoId() == kPseudoIdViewTransitionGroup) {
      return current_element->GetPseudoElement(
          kPseudoIdViewTransitionImagePair,
          To<PseudoElement>(this)->view_transition_name());
    }
    if (GetPseudoId() == kPseudoIdViewTransitionImagePair) {
      const AtomicString& name =
          To<PseudoElement>(this)->view_transition_name();
      if (Node* first = current_element->GetPseudoElement(
              kPseudoIdViewTransitionOld, name)) {
        return first;
      }

      return current_element->GetPseudoElement(kPseudoIdViewTransitionNew,
                                               name);
    }
    if (Node* first =
            current_element->GetPseudoElement(kPseudoIdScrollPrevButton)) {
      return first;
    }
    if (Node* first = current_element->GetPseudoElement(
            kPseudoIdScrollMarkerGroupBefore)) {
      return first;
    }
    if (Node* first = current_element->GetPseudoElement(kPseudoIdMarker))
      return first;
    if (Node* first =
            current_element->GetPseudoElement(kPseudoIdScrollMarker)) {
      return first;
    }
    if (Node* first = current_element->GetPseudoElement(kPseudoIdCheck)) {
      return first;
    }
    if (Node* first = current_element->GetPseudoElement(kPseudoIdBefore))
      return first;
    if (Node* first = current_element->firstChild())
      return first;
    if (Node* first = current_element->GetPseudoElement(kPseudoIdAfter)) {
      return first;
    }
    if (Node* first = current_element->GetPseudoElement(kPseudoIdSelectArrow)) {
      return first;
    }
    if (Node* first = current_element->GetPseudoElement(
            kPseudoIdScrollMarkerGroupAfter)) {
      return first;
    }
    if (Node* first =
            current_element->GetPseudoElement(kPseudoIdScrollNextButton)) {
      return first;
    }
    return current_element->GetPseudoElement(kPseudoIdViewTransition);
  }

  return firstChild();
}

Node* Node::PseudoAwareLastChild() const {
  if (const auto* current_element = DynamicTo<Element>(this)) {
    // See comments in PseudoAwarePreviousSibling for details on view-transition
    // pseudo traversal.
    if (GetPseudoId() == kPseudoIdViewTransition) {
      const Vector<AtomicString>& names =
          GetDocument().GetStyleEngine().ViewTransitionTags();
      if (names.empty()) {
        return nullptr;
      }
      return current_element->GetPseudoElement(kPseudoIdViewTransitionGroup,
                                               names.back());
    }
    if (GetPseudoId() == kPseudoIdViewTransitionGroup) {
      return current_element->GetPseudoElement(
          kPseudoIdViewTransitionImagePair,
          To<PseudoElement>(this)->view_transition_name());
    }
    if (GetPseudoId() == kPseudoIdViewTransitionImagePair) {
      const AtomicString& name =
          To<PseudoElement>(this)->view_transition_name();
      if (Node* last = current_element->GetPseudoElement(
              kPseudoIdViewTransitionNew, name)) {
        return last;
      }

      return current_element->GetPseudoElement(kPseudoIdViewTransitionOld,
                                               name);
    }
    if (Node* last =
            current_element->GetPseudoElement(kPseudoIdViewTransition)) {
      return last;
    }
    if (Node* last =
            current_element->GetPseudoElement(kPseudoIdScrollNextButton)) {
      return last;
    }
    if (Node* last = current_element->GetPseudoElement(
            kPseudoIdScrollMarkerGroupAfter)) {
      return last;
    }
    if (Node* last = current_element->GetPseudoElement(kPseudoIdSelectArrow)) {
      return last;
    }
    if (Node* last = current_element->GetPseudoElement(kPseudoIdAfter))
      return last;
    if (Node* last = current_element->lastChild())
      return last;
    if (Node* last = current_element->GetPseudoElement(kPseudoIdBefore))
      return last;
    if (Node* last = current_element->GetPseudoElement(kPseudoIdCheck)) {
      return last;
    }
    if (Node* last = current_element->GetPseudoElement(kPseudoIdScrollMarker)) {
      return last;
    }
    if (Node* last = current_element->GetPseudoElement(kPseudoIdMarker)) {
      return last;
    }
    if (Node* last = current_element->GetPseudoElement(
            kPseudoIdScrollMarkerGroupBefore)) {
      return last;
    }
    return current_element->GetPseudoElement(kPseudoIdScrollPrevButton);
  }

  return lastChild();
}

Node& Node::TreeRoot() const {
  if (IsInTreeScope()) {
    return GetTreeScope().RootNode();
  }
  const Node* node = this;
  while (node->parentNode())
    node = node->parentNode();
  return const_cast<Node&>(*node);
}

Node* Node::getRootNode(const GetRootNodeOptions* options) const {
  return (options->hasComposed() && options->composed())
             ? &ShadowIncludingRoot()
             : &TreeRoot();
}

Node* Node::insertBefore(Node* new_child,
                         Node* ref_child,
                         ExceptionState& exception_state) {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (this_node)
    return this_node->InsertBefore(new_child, ref_child, exception_state);

  exception_state.ThrowDOMException(
      DOMExceptionCode::kHierarchyRequestError,
      "This node type does not support this method.");
  return nullptr;
}

Node* Node::insertBefore(Node* new_child, Node* ref_child) {
  return insertBefore(new_child, ref_child, ASSERT_NO_EXCEPTION);
}

Node* Node::moveBefore(Node* new_child,
                       Node* ref_child,
                       ExceptionState& exception_state) {
  DCHECK(new_child);

  // Only perform a state-preserving atomic move if the new parent and the child
  // are ALREADY connected, and its document is the same as `this`'s. If the
  // child is NOT connected to this document, then script could run during the
  // node's initial post-insertion steps (i.e.,
  // `Node::DidNotifySubtreeInsertionsToDocument()`), and no script is permitted
  // to run during atomic moves.
  const bool perform_state_preserving_atomic_move =
      // "If either parent or node are not connected, then..."
      isConnected() && new_child->isConnected() &&
      // "If parent’s shadow-including root is not the same as node’s
      // shadow-including root, then..."
      GetDocument() == new_child->GetDocument() &&
      // "If node is not an Element or a CharacterData node, then ..."
      (new_child->IsElementNode() || new_child->IsCharacterDataNode()) &&
      // "If parent is not an Element or DocumentFragment node, then throw a
      // "HierarchyRequestError" DOMException."
      (IsElementNode() || IsDocumentFragment());
  // These two conditions below are caught by `EnsurePreInsertionValidity()`
  // that gets invoked in `insertBefore()`:
  //
  // "If node is a host-including inclusive ancestor of parent, then...
  // "If child is non-null and its parent is not parent, then..."

  // ...throw a "HierarchyRequestError" DOMException."
  if (!perform_state_preserving_atomic_move) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "State-preserving atomic move cannot be performed on nodes "
        "participating in an invalid hierarchy.");
    return nullptr;
  }

  // No script can run synchronously during the move. That means it is
  // impossible for nested `moveBefore()` calls to occur. Assert that no atomic
  // move is already in progress.
  DCHECK(!GetDocument().StatePreservingAtomicMoveInProgress());
  GetDocument().SetStatePreservingAtomicMoveInProgress(true);

  // Mutation events are disabled during the `moveBefore()` API.
  MutationEventSuppressionScope scope(GetDocument());

  ContainerNode* old_parent = new_child->parentNode();

  Node* return_node = insertBefore(new_child, ref_child, exception_state);
  GetDocument().SetStatePreservingAtomicMoveInProgress(false);
  new_child->MovedFrom(*old_parent);

  // We don't need to conditionally return `nullptr` if `exception_state` had an
  // exception. `insertBefore()` already handles this for us, so we can just
  // unconditionally return its value.
  return return_node;
}

Node* Node::replaceChild(Node* new_child,
                         Node* old_child,
                         ExceptionState& exception_state) {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (this_node)
    return this_node->ReplaceChild(new_child, o
```