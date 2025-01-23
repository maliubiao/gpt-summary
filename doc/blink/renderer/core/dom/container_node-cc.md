Response:
My thinking process to arrive at the summary of `ContainerNode.cc` functionality involved several steps, focusing on extracting key information from the provided code snippet and relating it to web development concepts.

1. **Initial Scan for Keywords and Includes:** I first quickly scanned the header includes at the beginning of the file. This gave me a high-level idea of the domains this class interacts with. I noted includes related to:
    * DOM manipulation (`container_node.h`, `node.h`, `document_part_root.h`, etc.)
    * JavaScript bindings (`v8_get_html_options.h`, `v8_get_inner_html_options.h`)
    * CSS (`selector_query.h`, `style_change_reason.h`, `style_engine.h`)
    * Events (`events/`, `mutation_event.h`)
    * Layout (`layout/`)
    * Accessibility (`accessibility/ax_object_cache.h`)
    * HTML elements (`html/`)
    * Shadow DOM (`shadow_root.h`, `slot_assignment_recalc_forbidden_scope.h`)

2. **Focus on the Class Name:** The class name `ContainerNode` immediately suggests its core responsibility: managing child nodes. This is a fundamental concept in the DOM.

3. **Analyzing Key Methods:** I then started looking at the prominent methods defined in the snippet. Methods like `InsertBefore`, `AppendChild`, `ReplaceChild`, `RemoveChild`, and `ParserTakeAllChildrenFrom` directly deal with manipulating the structure of the DOM tree. The `Parser...` methods indicate involvement in how the HTML parser builds the DOM.

4. **Identifying Core Functionality Areas:** Based on the includes and the key methods, I identified the primary functional areas of `ContainerNode`:
    * **DOM Manipulation:**  This is the most obvious function, handling the addition, removal, and replacement of child nodes.
    * **HTML Parsing Integration:** The `Parser...` methods clearly link this class to the HTML parsing process.
    * **JavaScript Interaction:** The inclusion of V8 binding headers indicates that these DOM manipulations are exposed to JavaScript.
    * **CSS Styling:** The interaction with CSS-related classes suggests that changes in the DOM structure can trigger style recalculations.
    * **Event Handling:** The inclusion of event-related headers and the presence of methods like `DispatchChildInsertionEvents` and `DispatchChildRemovalEvents` show that `ContainerNode` plays a role in dispatching DOM mutation events.
    * **Shadow DOM Support:**  The inclusion of `shadow_root.h` and related classes indicates that `ContainerNode` is involved in managing shadow trees.
    * **Accessibility:** The inclusion of `ax_object_cache.h` implies involvement in updating accessibility information when the DOM changes.

5. **Connecting to Web Development Concepts:**  I then connected these functional areas to common web development concepts:
    * **JavaScript's DOM API:** The methods directly correspond to JavaScript methods like `insertBefore`, `appendChild`, `replaceChild`, and `removeChild`.
    * **HTML Structure:** The class is responsible for maintaining the hierarchical structure of HTML documents.
    * **CSS Styling and Rendering:**  Changes to the DOM structure can affect how elements are styled and rendered.
    * **Dynamic Web Pages:**  JavaScript uses these DOM manipulation methods to create dynamic and interactive web pages.
    * **Shadow DOM Encapsulation:**  The class helps manage the boundaries and behavior of shadow DOM.
    * **Accessibility for Users:**  Ensuring that DOM changes are reflected in the accessibility tree is crucial for users with disabilities.

6. **Considering Error Handling and Edge Cases:** I noticed the `ExceptionState` parameter in many methods, indicating that `ContainerNode` needs to handle potential errors during DOM manipulation, such as trying to insert a node in an invalid location.

7. **Recognizing Internal Mechanisms:**  I also observed internal mechanisms like `ChildListMutationScope` which suggests a way to batch or track DOM changes for efficiency and event dispatch.

8. **Formulating the Summary:** Finally, I synthesized the information gathered into a concise summary, highlighting the key responsibilities of `ContainerNode`: managing child nodes, its role in the HTML parsing process, its interaction with JavaScript and CSS, its involvement in event dispatching, and its support for shadow DOM and accessibility. I emphasized its central role in the core DOM manipulation logic of the Blink rendering engine.

Essentially, I read the code with a focus on identifying the *actions* the class performs and the *data structures* it manipulates, then interpreted those actions and data structures in the context of how web browsers work and how web developers interact with the DOM.
好的，根据你提供的 `blink/renderer/core/dom/container_node.cc` 文件的代码片段，我可以归纳一下它的主要功能：

**`ContainerNode.cc` 的主要功能是实现 DOM 树中可以包含其他节点（子节点）的节点的通用行为和逻辑。它定义了 `ContainerNode` 类，这个类是诸如 `Document`、`Element` 和 `DocumentFragment` 等可以拥有子节点的 DOM 节点的基类。**

以下是更详细的功能点：

* **子节点管理的核心逻辑:**  `ContainerNode` 实现了添加、插入、替换和移除子节点的关键方法，例如 `insertBefore()`, `appendChild()`, `replaceChild()`, `removeChild()`。这些方法负责维护节点间的父子关系和兄弟关系，并更新 DOM 树的结构。
* **HTML 解析集成:**  提供了 `ParserTakeAllChildrenFrom()` 和 `ParserInsertBefore()` 等方法，用于在 HTML 解析过程中高效地构建 DOM 树。这些方法通常在没有完整 DOM 事件和观察者通知的情况下操作节点，以提高解析性能。
* **DOM 变更通知:**  在子节点发生变化时，负责触发相应的 DOM 变更事件（例如 `DOMNodeInserted`, `DOMNodeRemoved`，以及 Mutation Observers 的通知）。可以看到代码中使用了 `ChildListMutationScope` 来管理这些通知。
* **与 JavaScript 的交互:**  虽然代码片段本身不直接包含 JavaScript 代码，但通过引入 V8 相关的头文件 (`v8_get_html_options.h`, `v8_get_inner_html_options.h`) 可以推断出，`ContainerNode` 的功能最终会暴露给 JavaScript，允许 JavaScript 代码通过 DOM API 操作这些节点。
* **CSS 样式更新:** 当 DOM 结构发生变化时，可能会影响元素的样式。代码中包含了与 CSS 相关的头文件 (`style_change_reason.h`, `style_engine.h`)，表明 `ContainerNode` 的操作可能会触发样式的重新计算。
* **Shadow DOM 支持:** 代码中包含了 `shadow_root.h` 和 `slot_assignment_recalc_forbidden_scope.h`，说明 `ContainerNode` 也参与了 Shadow DOM 的管理，包括处理 slot 的分配等。
* **辅助功能 (Accessibility):** 引入了 `ax_object_cache.h`，暗示当 DOM 结构变化时，`ContainerNode` 的操作也会更新辅助功能树，以确保屏幕阅读器等工具能正确理解页面内容。
* **错误处理:**  许多方法都接受 `ExceptionState&` 参数，用于处理在 DOM 操作过程中可能出现的错误，例如尝试插入无效的子节点。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **JavaScript:**
    * **例子:**  JavaScript 代码调用 `element.appendChild(newNode)` 会最终调用到 `ContainerNode::AppendChild()` 或其相关方法，将 `newNode` 添加到 `element` 的子节点列表中。
    * **假设输入与输出:**
        * **假设输入:** 一个 HTML 元素 `<div id="parent"></div>`，以及一段 JavaScript 代码 `document.getElementById('parent').appendChild(document.createElement('p'));`
        * **输出:** `ContainerNode::AppendChild()` 被调用，`parent` 元素的内部会添加一个新的 `<p>` 元素。
* **HTML:**
    * **例子:** 当浏览器解析 HTML 文档时，遇到包含子元素的标签（例如 `<div><p>Text</p></div>`），会调用 `ContainerNode` 的 `ParserAppendChild()` 或相关方法来构建 DOM 树的层次结构。
    * **用户操作:** 用户打开一个包含嵌套元素的 HTML 页面。浏览器会解析 HTML，并使用 `ContainerNode` 的方法来创建 `div` 元素，然后将 `p` 元素作为其子节点添加进去。
* **CSS:**
    * **例子:** 当通过 JavaScript 移除一个元素，导致其父元素的子节点列表发生变化时，`ContainerNode` 的 `removeChild()` 方法会被调用，这可能会触发 CSS 引擎重新计算父元素的样式，例如 `:first-child` 或 `:last-child` 伪类的应用可能会因此改变。
    * **假设输入与输出:**
        * **假设输入:** 一个 HTML 结构 `<ul id="list"><li>Item 1</li><li>Item 2</li></ul>`，CSS 规则 `li:last-child { color: red; }`，以及 JavaScript 代码 `document.getElementById('list').removeChild(document.getElementById('list').lastChild);`
        * **输出:** `ContainerNode::RemoveChild()` 被调用移除最后一个 `<li>` 元素。移除后，倒数第二个 `<li>` 元素会变为新的最后一个子元素，CSS 引擎会重新应用样式，使其颜色变为红色。

**用户或编程常见的使用错误举例说明：**

* **错误:** 尝试将一个节点添加到它自身的祖先节点中，会导致 `HierarchyRequestError`。
    * **用户操作/调试线索:**  开发者编写 JavaScript 代码尝试执行类似 `document.body.appendChild(document.documentElement)` 的操作。当代码执行到这里时，Blink 引擎会调用 `ContainerNode::EnsurePreInsertionValidity()` 进行校验，发现 `document.documentElement` 是 `document.body` 的祖先，从而抛出异常。
* **错误:**  在应该传入 `Node` 类型的地方传入了错误的对象类型。
    * **用户操作/调试线索:** 开发者可能错误地将一个字符串或者 `undefined` 传递给 `appendChild()` 方法，例如 `element.appendChild("some text")`。虽然 JavaScript 会尝试将其转换为 `Text` 节点，但在某些情况下可能会导致预期之外的结果或错误。调试时，可以观察 JavaScript 调用栈，最终会指向 Blink 引擎中处理节点插入的相关方法。
* **错误:** 尝试在不允许添加特定子节点的父节点上添加该类型的子节点。
    * **用户操作/调试线索:** 开发者尝试将 `<script>` 标签直接添加到 `<body>` 之外的某些类型的节点中（在不允许的情况下）。Blink 引擎在执行插入操作时会检查节点类型是否允许，并在 `ContainerNode::EnsurePreInsertionValidity()` 或类似的检查中发现错误，抛出 `HierarchyRequestError`。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **用户在浏览器中加载了一个网页。**
2. **网页中的 HTML 被 Blink 引擎的 HTML 解析器解析。** 解析器会调用 `ContainerNode` 的 `ParserAppendChild()` 或 `ParserInsertBefore()` 等方法来构建 DOM 树。
3. **网页中的 JavaScript 代码执行，调用了 DOM 操作方法，例如 `document.createElement()`, `appendChild()`, `insertBefore()`, `removeChild()` 等。** 这些 JavaScript 调用会被桥接到 Blink 引擎的 C++ 代码，最终会调用到 `ContainerNode` 类中相应的方法。
4. **用户与网页进行交互，例如点击按钮，触发了 JavaScript 代码执行 DOM 操作。**  例如，点击按钮后，JavaScript 代码可能会动态创建一个新的 `<div>` 元素并将其添加到页面中，这会调用到 `ContainerNode::AppendChild()`。
5. **浏览器执行了某些内部操作，例如移动 DOM 节点，或者进行模板实例化。** 这些操作也可能涉及调用 `ContainerNode` 的方法来修改 DOM 结构。

作为调试线索，当你在 Chromium 源码中看到 `ContainerNode` 的相关代码被调用时，可以反向追踪 JavaScript 代码或 HTML 解析过程，了解是哪个用户操作或内部机制触发了这次调用。同时，检查传入 `ContainerNode` 方法的参数，例如要插入的节点、参考节点等，可以帮助你理解 DOM 树结构是如何被修改的。

总结来说，`ContainerNode.cc` 文件定义了 Blink 引擎中处理 DOM 树结构变化的核心逻辑，是实现动态网页功能的基础。它连接了 HTML 解析、JavaScript DOM 操作、CSS 样式更新以及辅助功能等多个方面。

### 提示词
```
这是目录为blink/renderer/core/dom/container_node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 1999 Lars Knoll (knoll@kde.org)
 *           (C) 1999 Antti Koivisto (koivisto@kde.org)
 *           (C) 2001 Dirk Mueller (mueller@kde.org)
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009, 2013 Apple Inc. All rights
 * reserved.
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

#include "third_party/blink/renderer/core/dom/container_node.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_get_html_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_get_inner_html_options.h"
#include "third_party/blink/renderer/core/accessibility/ax_object_cache.h"
#include "third_party/blink/renderer/core/css/selector_query.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/css/style_engine.h"
#include "third_party/blink/renderer/core/dom/child_frame_disconnector.h"
#include "third_party/blink/renderer/core/dom/child_list_mutation_scope.h"
#include "third_party/blink/renderer/core/dom/class_collection.h"
#include "third_party/blink/renderer/core/dom/document_part_root.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/events/event_dispatch_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/events/scoped_event_queue.h"
#include "third_party/blink/renderer/core/dom/flat_tree_traversal.h"
#include "third_party/blink/renderer/core/dom/layout_tree_builder_traversal.h"
#include "third_party/blink/renderer/core/dom/name_node_list.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/node_child_removal_tracker.h"
#include "third_party/blink/renderer/core/dom/node_cloning_data.h"
#include "third_party/blink/renderer/core/dom/node_lists_node_data.h"
#include "third_party/blink/renderer/core/dom/node_rare_data.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/dom/part.h"
#include "third_party/blink/renderer/core/dom/part_root.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/slot_assignment_recalc_forbidden_scope.h"
#include "third_party/blink/renderer/core/dom/static_node_list.h"
#include "third_party/blink/renderer/core/dom/whitespace_attacher.h"
#include "third_party/blink/renderer/core/editing/serializers/serialization.h"
#include "third_party/blink/renderer/core/events/mutation_event.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/deprecation/deprecation.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/web_feature.h"
#include "third_party/blink/renderer/core/html/forms/html_field_set_element.h"
#include "third_party/blink/renderer/core/html/forms/html_form_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/radio_node_list.h"
#include "third_party/blink/renderer/core/html/html_collection.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_document.h"
#include "third_party/blink/renderer/core/html/html_frame_owner_element.h"
#include "third_party/blink/renderer/core/html/html_tag_collection.h"
#include "third_party/blink/renderer/core/html/html_template_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/layout/layout_inline.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/core/layout/layout_text_combine.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/timing/soft_navigation_heuristics.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/bindings/runtime_call_stats.h"
#include "third_party/blink/renderer/platform/bindings/script_forbidden_scope.h"
#include "third_party/blink/renderer/platform/bindings/script_regexp.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/casting.h"
#include "third_party/blink/renderer/platform/wtf/wtf_size_t.h"

namespace blink {

static void DispatchChildInsertionEvents(Node&);
static void DispatchChildRemovalEvents(Node&);

namespace {

// This class is helpful to detect necessity of
// RecheckNodeInsertionStructuralPrereq() after removeChild*() inside
// InsertBefore(), AppendChild(), and ReplaceChild().
//
// After removeChild*(), we can detect necessity of
// RecheckNodeInsertionStructuralPrereq() by
//  - DOM tree version of |node_document_| was increased by at most one.
//  - If |node| and |parent| are in different documents, Document for
//    |parent| must not be changed.
class DOMTreeMutationDetector {
  STACK_ALLOCATED();

 public:
  DOMTreeMutationDetector(const Node& node, const Node& parent)
      : node_(&node),
        node_document_(&node.GetDocument()),
        parent_document_(&parent.GetDocument()),
        parent_(&parent),
        original_node_document_version_(node_document_->DomTreeVersion()),
        original_parent_document_version_(parent_document_->DomTreeVersion()) {}

  bool NeedsRecheck() {
    if (node_document_ != node_->GetDocument()) {
      return false;
    }
    if (node_document_->DomTreeVersion() > original_node_document_version_ + 1)
      return false;
    if (parent_document_ != parent_->GetDocument())
      return false;
    if (node_document_ == parent_document_)
      return true;
    return parent_document_->DomTreeVersion() ==
           original_parent_document_version_;
  }

 private:
  const Node* const node_;
  Document* const node_document_;
  Document* const parent_document_;
  const Node* const parent_;
  const uint64_t original_node_document_version_;
  const uint64_t original_parent_document_version_;
};

inline bool CheckReferenceChildParent(const Node& parent,
                                      const Node* next,
                                      const Node* old_child,
                                      ExceptionState& exception_state) {
  if (next && next->parentNode() != &parent) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "The node before which the new node is "
                                      "to be inserted is not a child of this "
                                      "node.");
    return false;
  }
  if (old_child && old_child->parentNode() != &parent) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kNotFoundError,
        "The node to be replaced is not a child of this node.");
    return false;
  }
  return true;
}

}  // namespace

// This dispatches various events; DOM mutation events, blur events, IFRAME
// unload events, etc.
// Returns true if DOM mutation should be proceeded.
static inline bool CollectChildrenAndRemoveFromOldParent(
    Node& node,
    NodeVector& nodes,
    ExceptionState& exception_state) {
  if (auto* fragment = DynamicTo<DocumentFragment>(node)) {
    GetChildNodes(*fragment, nodes);
    fragment->RemoveChildren();
    return !nodes.empty();
  }
  nodes.push_back(&node);
  node.remove(exception_state);
  return !exception_state.HadException() && !nodes.empty();
}

void ContainerNode::ParserTakeAllChildrenFrom(ContainerNode& old_parent) {
  while (Node* child = old_parent.firstChild()) {
    // Explicitly remove since appending can fail, but this loop shouldn't be
    // infinite.
    old_parent.ParserRemoveChild(*child);
    ParserAppendChild(child);
  }
}

ContainerNode::~ContainerNode() {
  DCHECK(isConnected() || !NeedsStyleRecalc());
}

// Returns true if |new_child| contains this node. In that case,
// |exception_state| has an exception.
// https://dom.spec.whatwg.org/#concept-tree-host-including-inclusive-ancestor
bool ContainerNode::IsHostIncludingInclusiveAncestorOfThis(
    const Node& new_child,
    ExceptionState& exception_state) const {
  // Non-ContainerNode can contain nothing.
  if (!new_child.IsContainerNode())
    return false;

  bool child_contains_parent = false;
  if (IsInShadowTree() || GetDocument().IsTemplateDocument()) {
    child_contains_parent = new_child.ContainsIncludingHostElements(*this);
  } else {
    const Node& root = TreeRoot();
    auto* fragment = DynamicTo<DocumentFragment>(root);
    if (fragment && fragment->IsTemplateContent()) {
      child_contains_parent = new_child.ContainsIncludingHostElements(*this);
    } else {
      child_contains_parent = new_child.contains(this);
    }
  }
  if (child_contains_parent) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "The new child element contains the parent.");
  }
  return child_contains_parent;
}

// EnsurePreInsertionValidity() is an implementation of step 2 to 6 of
// https://dom.spec.whatwg.org/#concept-node-ensure-pre-insertion-validity and
// https://dom.spec.whatwg.org/#concept-node-replace .
DISABLE_CFI_PERF
bool ContainerNode::EnsurePreInsertionValidity(
    const Node* new_child,
    const VectorOf<Node>* new_children,
    const Node* next,
    const Node* old_child,
    ExceptionState& exception_state) const {
  DCHECK(!(next && old_child));
  CHECK_NE(!new_child, !new_children);

  // Use common case fast path if possible.
  if (new_child && (new_child->IsElementNode() || new_child->IsTextNode()) &&
      IsElementNode()) {
    DCHECK(ChildTypeAllowed(new_child->getNodeType()));
    // 2. If node is a host-including inclusive ancestor of parent, throw a
    // HierarchyRequestError.
    if (IsHostIncludingInclusiveAncestorOfThis(*new_child, exception_state)) {
      return false;
    }
    // 3. If child is not null and its parent is not parent, then throw a
    // NotFoundError.
    return CheckReferenceChildParent(*this, next, old_child, exception_state);
  }

  // This should never happen, but also protect release builds from tree
  // corruption.
  if (new_child) {
    CHECK(!new_child->IsPseudoElement());
  } else {
    for (const Node* child : *new_children) {
      CHECK(!child->IsPseudoElement());
    }
  }

  if (auto* document = DynamicTo<Document>(this)) {
    // Step 2 is unnecessary. No one can have a Document child.
    // Step 3:
    if (!CheckReferenceChildParent(*this, next, old_child, exception_state))
      return false;
    // Step 4-6.
    return document->CanAcceptChild(new_child, new_children, next, old_child,
                                    exception_state);
  }

  // 2. If node is a host-including inclusive ancestor of parent, throw a
  // HierarchyRequestError.
  if (new_child) {
    if (IsHostIncludingInclusiveAncestorOfThis(*new_child, exception_state)) {
      return false;
    }
  } else {
    for (const Node* child : *new_children) {
      if (IsHostIncludingInclusiveAncestorOfThis(*child, exception_state)) {
        return false;
      }
    }
  }

  // 3. If child is not null and its parent is not parent, then throw a
  // NotFoundError.
  if (!CheckReferenceChildParent(*this, next, old_child, exception_state))
    return false;

  // 4. If node is not a DocumentFragment, DocumentType, Element, Text,
  // ProcessingInstruction, or Comment node, throw a HierarchyRequestError.
  // 5. If either node is a Text node and parent is a document, or node is a
  // doctype and parent is not a document, throw a HierarchyRequestError.
  auto is_child_allowed = [&](const Node* child) -> bool {
    if (!ChildTypeAllowed(child->getNodeType())) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kHierarchyRequestError,
          "Nodes of type '" + child->nodeName() +
              "' may not be inserted inside nodes of type '" + nodeName() +
              "'.");
      return false;
    }
    return true;
  };
  if (new_children) {
    for (const Node* child : *new_children) {
      if (!is_child_allowed(child)) {
        return false;
      }
    }
  } else if (auto* child_fragment = DynamicTo<DocumentFragment>(new_child)) {
    for (Node* node = child_fragment->firstChild(); node;
         node = node->nextSibling()) {
      if (!is_child_allowed(node)) {
        return false;
      }
    }
  } else {
    if (!is_child_allowed(new_child)) {
      return false;
    }
  }
  // Step 6 is unnecessary for non-Document nodes.
  return true;
}

// We need this extra structural check because prior DOM mutation operations
// dispatched synchronous events, so their handlers may have modified DOM
// trees.
bool ContainerNode::RecheckNodeInsertionStructuralPrereq(
    const NodeVector& new_children,
    const Node* next,
    ExceptionState& exception_state) {
  for (const auto& child : new_children) {
    if (child->parentNode()) {
      // A new child was added to another parent before adding to this
      // node.  Firefox and Edge don't throw in this case.
      return false;
    }
    if (auto* document = DynamicTo<Document>(this)) {
      // For Document, no need to check host-including inclusive ancestor
      // because a Document node can't be a child of other nodes.
      // However, status of existing doctype or root element might be changed
      // and we need to check it again.
      if (!document->CanAcceptChild(child, /*new_children*/ nullptr, next,
                                    /*old_child*/ nullptr, exception_state)) {
        return false;
      }
    } else {
      if (IsHostIncludingInclusiveAncestorOfThis(*child, exception_state))
        return false;
    }
  }
  return CheckReferenceChildParent(*this, next, nullptr, exception_state);
}

template <typename Functor>
void ContainerNode::InsertNodeVector(
    const NodeVector& targets,
    Node* next,
    const Functor& mutator,
    NodeVector& post_insertion_notification_targets) {
  probe::WillInsertDOMNode(this);
  {
    EventDispatchForbiddenScope assert_no_event_dispatch;
    ScriptForbiddenScope forbid_script;
    for (const auto& target_node : targets) {
      DCHECK(target_node);
      DCHECK(!target_node->parentNode());
      Node& child = *target_node;
      mutator(*this, child, next);
      ChildListMutationScope(*this).ChildAdded(child);
      if (GetDocument().MayContainShadowRoots())
        child.CheckSlotChangeAfterInserted();
      probe::DidInsertDOMNode(&child);
      NotifyNodeInsertedInternal(child, post_insertion_notification_targets);
    }
  }
}

void ContainerNode::DidInsertNodeVector(
    const NodeVector& targets,
    Node* next,
    const NodeVector& post_insertion_notification_targets) {
  Node* unchanged_previous =
      targets.size() > 0 ? targets[0]->previousSibling() : nullptr;
  const Document& document = GetDocument();
  for (const auto& target_node : targets) {
    ChildrenChanged(ChildrenChange::ForInsertion(
        *target_node, unchanged_previous, next, ChildrenChangeSource::kAPI));
    CheckSoftNavigationHeuristicsTracking(document, *target_node);
  }
  for (const auto& descendant : post_insertion_notification_targets) {
    if (descendant->isConnected())
      descendant->DidNotifySubtreeInsertionsToDocument();
  }
  for (const auto& target_node : targets) {
    if (target_node->parentNode() == this)
      DispatchChildInsertionEvents(*target_node);
  }
  DispatchSubtreeModifiedEvent();
}

class ContainerNode::AdoptAndInsertBefore {
 public:
  inline void operator()(ContainerNode& container,
                         Node& child,
                         Node* next) const {
    DCHECK(next);
    DCHECK_EQ(next->parentNode(), &container);
    container.GetTreeScope().AdoptIfNeeded(child);
    container.InsertBeforeCommon(*next, child);
  }
};

class ContainerNode::AdoptAndAppendChild {
 public:
  inline void operator()(ContainerNode& container, Node& child, Node*) const {
    container.GetTreeScope().AdoptIfNeeded(child);
    container.AppendChildCommon(child);
  }
};

void ContainerNode::InsertBefore(const VectorOf<Node>& new_children,
                                 Node* ref_child,
                                 ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#concept-node-pre-insert

  // insertBefore(node, null) is equivalent to appendChild(node)
  if (!ref_child) {
    AppendChildren(new_children, exception_state);
    return;
  }

  if (!EnsurePreInsertionValidity(/*new_child*/ nullptr, &new_children,
                                  ref_child, /*old_child*/ nullptr,
                                  exception_state)) {
    return;
  }

  if (new_children.size() == 1u) {
    // If there's exactly one child then Node::ConvertNodeUnionsIntoNodes
    // didn't remove it from the old parent.
    Node* new_child = new_children[0];

    // 2. Let reference child be child.
    // 3. If reference child is node, set it to node’s next sibling.
    if (ref_child == new_child) {
      if (!new_child->HasNextSibling()) {
        return AppendChildren(new_children, exception_state);
      }
      ref_child = new_child->nextSibling();
    }

    DOMTreeMutationDetector detector(*new_child, *this);
    new_child->remove(exception_state);
    if (exception_state.HadException()) {
      return;
    }
    if (!detector.NeedsRecheck() &&
        !RecheckNodeInsertionStructuralPrereq(new_children, ref_child,
                                              exception_state)) {
      return;
    }
  }

  // 4. Adopt node into parent’s node document.
  // 5. Insert node into parent before reference child.
  NodeVector post_insertion_notification_targets;
  {
    SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());
    ChildListMutationScope mutation(*this);
    InsertNodeVector(new_children, ref_child, AdoptAndInsertBefore(),
                     post_insertion_notification_targets);
  }
  DidInsertNodeVector(new_children, ref_child,
                      post_insertion_notification_targets);
}

Node* ContainerNode::InsertBefore(Node* new_child,
                                  Node* ref_child,
                                  ExceptionState& exception_state) {
  DCHECK(new_child);
  // https://dom.spec.whatwg.org/#concept-node-pre-insert

  // insertBefore(node, null) is equivalent to appendChild(node)
  if (!ref_child)
    return AppendChild(new_child, exception_state);

  // 1. Ensure pre-insertion validity of node into parent before child.
  if (!EnsurePreInsertionValidity(new_child, /*new_children*/ nullptr,
                                  ref_child, /*old_child*/ nullptr,
                                  exception_state)) {
    return new_child;
  }

  // 2. Let reference child be child.
  // 3. If reference child is node, set it to node’s next sibling.
  if (ref_child == new_child) {
    if (!new_child->HasNextSibling()) {
      return AppendChild(new_child, exception_state);
    }
    ref_child = new_child->nextSibling();
  }

  // 4. Adopt node into parent’s node document.
  NodeVector targets;
  DOMTreeMutationDetector detector(*new_child, *this);
  if (!CollectChildrenAndRemoveFromOldParent(*new_child, targets,
                                             exception_state))
    return new_child;
  if (!detector.NeedsRecheck()) {
    if (!RecheckNodeInsertionStructuralPrereq(targets, ref_child,
                                              exception_state))
      return new_child;
  }

  // 5. Insert node into parent before reference child.
  NodeVector post_insertion_notification_targets;
  {
    SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());
    ChildListMutationScope mutation(*this);
    InsertNodeVector(targets, ref_child, AdoptAndInsertBefore(),
                     post_insertion_notification_targets);
  }
  DidInsertNodeVector(targets, ref_child, post_insertion_notification_targets);
  return new_child;
}

Node* ContainerNode::InsertBefore(Node* new_child, Node* ref_child) {
  return InsertBefore(new_child, ref_child, ASSERT_NO_EXCEPTION);
}

void ContainerNode::InsertBeforeCommon(Node& next_child, Node& new_child) {
#if DCHECK_IS_ON()
  DCHECK(EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  DCHECK(ScriptForbiddenScope::IsScriptForbidden());
  // Use insertBefore if you need to handle reparenting (and want DOM mutation
  // events).
  DCHECK(!new_child.parentNode());
  DCHECK(!new_child.HasNextSibling());
  DCHECK(!new_child.HasPreviousSibling());
  DCHECK(!new_child.IsShadowRoot());

  Node* prev = next_child.previousSibling();
  DCHECK_NE(last_child_, prev);
  next_child.SetPreviousSibling(&new_child);
  if (prev) {
    DCHECK_NE(firstChild(), next_child);
    DCHECK_EQ(prev->nextSibling(), next_child);
    prev->SetNextSibling(&new_child);
  } else {
    DCHECK(firstChild() == next_child);
    SetFirstChild(&new_child);
  }
  new_child.SetParentOrShadowHostNode(this);
  new_child.SetPreviousSibling(prev);
  new_child.SetNextSibling(&next_child);
}

void ContainerNode::AppendChildCommon(Node& child) {
#if DCHECK_IS_ON()
  DCHECK(EventDispatchForbiddenScope::IsEventDispatchForbidden());
#endif
  DCHECK(ScriptForbiddenScope::IsScriptForbidden());

  child.SetParentOrShadowHostNode(this);
  if (last_child_) {
    child.SetPreviousSibling(last_child_);
    last_child_->SetNextSibling(&child);
  } else {
    SetFirstChild(&child);
  }
  SetLastChild(&child);
}

bool ContainerNode::CheckParserAcceptChild(const Node& new_child) const {
  auto* document = DynamicTo<Document>(this);
  if (!document)
    return true;
  // TODO(esprehn): Are there other conditions where the parser can create
  // invalid trees?
  return document->CanAcceptChild(&new_child, /*new_children*/ nullptr,
                                  /*next*/ nullptr, /*old_child*/ nullptr,
                                  IGNORE_EXCEPTION_FOR_TESTING);
}

void ContainerNode::ParserInsertBefore(Node* new_child, Node& next_child) {
  DCHECK(new_child);
  DCHECK(next_child.parentNode() == this ||
         (DynamicTo<DocumentFragment>(this) &&
          DynamicTo<DocumentFragment>(this)->IsTemplateContent()));
  DCHECK(!new_child->IsDocumentFragment());
  DCHECK(!IsA<HTMLTemplateElement>(this));

  if (next_child.previousSibling() == new_child ||
      &next_child == new_child)  // nothing to do
    return;

  if (!CheckParserAcceptChild(*new_child))
    return;

  // FIXME: parserRemoveChild can run script which could then insert the
  // newChild back into the page. Loop until the child is actually removed.
  // See: fast/parser/execute-script-during-adoption-agency-removal.html
  while (ContainerNode* parent = new_child->parentNode())
    parent->ParserRemoveChild(*new_child);

  // This can happen if foster parenting moves nodes into a template
  // content document, but next_child is still a "direct" child of the
  // template.
  if (next_child.parentNode() != this)
    return;

  if (GetDocument() != new_child->GetDocument())
    GetDocument().adoptNode(new_child, ASSERT_NO_EXCEPTION);

  {
    EventDispatchForbiddenScope assert_no_event_dispatch;
    ScriptForbiddenScope forbid_script;

    AdoptAndInsertBefore()(*this, *new_child, &next_child);
    DCHECK_EQ(new_child->ConnectedSubframeCount(), 0u);
    ChildListMutationScope(*this).ChildAdded(*new_child);
  }

  NotifyNodeInserted(*new_child, ChildrenChangeSource::kParser);
}

void ContainerNode::ReplaceChild(const VectorOf<Node>& new_children,
                                 Node* old_child,
                                 ExceptionState& exception_state) {
  // https://dom.spec.whatwg.org/#concept-node-replace
  if (!old_child) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "The node to be replaced is null.");
    return;
  }

  if (!EnsurePreInsertionValidity(/*new_child*/ nullptr, &new_children,
                                  /*next*/ nullptr, old_child,
                                  exception_state)) {
    return;
  }

  // 7. Let reference child be child’s next sibling.
  Node* next = old_child->nextSibling();

  bool needs_recheck = false;
  if (new_children.size() == 1u) {
    // If there's exactly one child then Node::ConvertNodeUnionsIntoNodes
    // didn't remove it from the old parent.
    Node* new_child = new_children[0];

    // 8. If reference child is node, set it to node’s next sibling.
    if (next == new_child) {
      next = new_child->nextSibling();
    }

    // Though the following CollectChildrenAndRemoveFromOldParent() also calls
    // RemoveChild(), we'd like to call RemoveChild() here to make a separated
    // MutationRecord.
    DOMTreeMutationDetector detector(*new_child, *this);
    new_child->remove(exception_state);
    if (exception_state.HadException()) {
      return;
    }
    if (!detector.NeedsRecheck()) {
      needs_recheck = true;
    }
  }

  NodeVector post_insertion_notification_targets;
  {
    // 9. Let previousSibling be child’s previous sibling.
    // 11. Let removedNodes be the empty list.
    // 15. Queue a mutation record of "childList" for target parent with
    // addedNodes nodes, removedNodes removedNodes, nextSibling reference child,
    // and previousSibling previousSibling.
    ChildListMutationScope mutation(*this);

    // 12. If child’s parent is not null, run these substeps:
    //    1. Set removedNodes to a list solely containing child.
    //    2. Remove child from its parent with the suppress observers flag set.
    if (ContainerNode* old_child_parent = old_child->parentNode()) {
      DOMTreeMutationDetector detector(*old_child, *this);
      old_child_parent->RemoveChild(old_child, exception_state);
      if (exception_state.HadException()) {
        return;
      }
      if (!detector.NeedsRecheck()) {
        needs_recheck = true;
      }
    }

    if (needs_recheck && !RecheckNodeInsertionStructuralPrereq(
                             new_children, next, exception_state)) {
      return;
    }

    SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());

    // 10. Adopt node into parent’s node document.
    // 14. Insert node into parent before reference child with the suppress
    // observers flag set.
    if (next) {
      InsertNodeVector(new_children, next, AdoptAndInsertBefore(),
                       post_insertion_notification_targets);
    } else {
      InsertNodeVector(new_children, nullptr, AdoptAndAppendChild(),
                       post_insertion_notification_targets);
    }
  }
  DidInsertNodeVector(new_children, next, post_insertion_notification_targets);
}

Node* ContainerNode::ReplaceChild(Node* new_child,
                                  Node* old_child,
                                  ExceptionState& exception_state) {
  DCHECK(new_child);
  // https://dom.spec.whatwg.org/#concept-node-replace

  if (!old_child) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotFoundError,
                                      "The node to be replaced is null.");
    return nullptr;
  }

  // Step 2 to 6.
  if (!EnsurePreInsertionValidity(new_child, /*new_children*/ nullptr,
                                  /*next*/ nullptr, old_child,
                                  exception_state)) {
    return old_child;
  }

  // 7. Let reference child be child’s next sibling.
  Node* next = old_child->nextSibling();
  // 8. If reference child is node, set it to node’s next sibling.
  if (next == new_child)
    next = new_child->nextSibling();

  bool needs_recheck = false;
  // 10. Adopt node into parent’s node document.
  // TODO(tkent): Actually we do only RemoveChild() as a part of 'adopt'
  // operation.
  //
  // Though the following CollectChildrenAndRemoveFromOldParent() also calls
  // RemoveChild(), we'd like to call RemoveChild() here to make a separated
  // MutationRecord.
  if (ContainerNode* new_child_parent = new_child->parentNode()) {
    DOMTreeMutationDetector detector(*new_child, *this);
    new_child_parent->RemoveChild(new_child, exception_state);
    if (exception_state.HadException())
      return nullptr;
    if (!detector.NeedsRecheck())
      needs_recheck = true;
  }

  NodeVector targets;
  NodeVector post_insertion_notification_targets;
  {
    // 9. Let previousSibling be child’s previous sibling.
    // 11. Let removedNodes be the empty list.
    // 15. Queue a mutation record of "childList" for target parent with
    // addedNodes nodes, removedNodes removedNodes, nextSibling reference child,
    // and previousSibling previousSibling.
    ChildListMutationScope mutation(*this);

    // 12. If child’s parent is not null, run these substeps:
    //    1. Set removedNodes to a list solely containing child.
    //    2. Remove child from its parent with the suppress observers flag set.
    if (ContainerNode* old_child_parent = old_child->parentNode()) {
      DOMTreeMutationDetector detector(*old_child, *this);
      old_child_parent->RemoveChild(old_child, exception_state);
      if (exception_state.HadException())
        return nullptr;
      if (!detector.NeedsRecheck())
        needs_recheck = true;
    }

    SlotAssignmentRecalcForbiddenScope forbid_slot_recalc(GetDocument());

    // 13. Let nodes be node’s children if node is a DocumentFragment node, and
    // a list containing solely node otherwise.
    DOMTreeMutationDetector detector(*new_child, *this);
    if (!CollectChildrenAndRemoveFromOldParent(*new_child, targets,
                                               exception_state))
      return old_child;
    if (!detector.NeedsRecheck() || needs_recheck) {
      if (!RecheckNodeInsertionStructuralPrereq(targets, next, exception_state))
        return old_child;
    }

    // 10. Adopt node into parent’s node document.
    // 14. Insert node into parent before reference child with the suppress
    // observers flag set.
    if (next) {
      InsertNodeVector(targets, next, AdoptAndInsertBefore(),
                       post_insertion_notification_targets);
    } else {
      InsertNodeVector(targets, nullptr, AdoptAndAppendChild(),
                       post_insertion_notification_targets);
    }
  }
  DidInsertNodeVector(targets, next, post_insertion_notification_targets);

  // 16. Return child.
  return old_child;
}

Node* ContainerNode::ReplaceChild(Node* new_child, Node* old_child) {
  return ReplaceChild(new_child, old_child, ASSERT_NO_EXCEPTION);
}

void ContainerNode::WillRemoveChild(Node& child) {
  DCHECK_EQ(child.parentNode(), this);
  ChildListMutationScope(*this).WillRemoveChild(child);
  child.NotifyMutationObserversNodeWillDetach();
  DispatchChildRemovalEvents(child);

  // Only disconnect subframes in the non-state-preserving-atomic-move case,
  // i.e., the traditional case where we intend to *fully* remove a node from
  // the tree, instead of atomically re-inserting it.
  if (!GetDocument().StatePreservingAtomicMoveInProgress()) {
    // TODO(crbug.com/40150299): Mutation events should be suppressed during a
    // state-preserving atomic move. Once this is implemented, enable the
    // following CHECK which asserts that during this kind of move, the child
    // node could not have moved documents during `DispatchChildRemovalEvents()`
    // above.
    //
    // CHECK_EQ(GetDocument(), child.GetDocument());
    ChildFrameDisconnector(
        child, ChildFrameDisconnector::DisconnectReason::kDisconnectSelf)
        .Disconnect();
  }

  if (GetDocument() != child.GetDocument()) {
    // |child| was moved to another document by the DOM mutation event handler.
    return;
  }

  // |nodeWillBeRem
```