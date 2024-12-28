Response:
Let's break down the thought process for summarizing the provided C++ code snippet.

1. **Understand the Goal:** The core request is to summarize the functionality of the given `node.cc` code within the Chromium Blink engine. Specifically, the request asks to identify its relationship to JavaScript, HTML, and CSS, provide examples of logic, user errors, debugging clues, and finally, summarize its function as part 2 of a 5-part series.

2. **Initial Scan and Keyword Identification:**  Quickly read through the code, looking for familiar DOM manipulation methods and data structures. Keywords that jump out are: `appendChild`, `insertBefore`, `removeChild`, `replaceChild`, `prepend`, `append`, `before`, `after`, `replaceWith`, `replaceChildren`, `remove`, `cloneNode`, `normalize`. The presence of `ExceptionState` suggests error handling related to DOM operations. The use of `V8UnionNodeOrStringOrTrustedScript` hints at the integration with JavaScript (V8 being the JavaScript engine).

3. **Categorize Functionality:** Group the identified methods into logical categories. A natural categorization emerges around:
    * **Node Insertion:** `appendChild`, `insertBefore`, `prepend`, `append`, `before`, `after`.
    * **Node Removal:** `removeChild`, `remove`.
    * **Node Replacement:** `replaceChild`, `replaceWith`, `replaceChildren`.
    * **Node Cloning:** `cloneNode`.
    * **Node Normalization:** `normalize`.
    * **Node Traversal (related to insertion/replacement):**  `FindViablePreviousSibling`, `FindViableNextSibling`.
    * **JavaScript Integration:**  `ConvertNodeUnionsIntoNode`, `ConvertNodeUnionsIntoNodes`. The `TrustedScript` part also points to security considerations.
    * **Error Handling:** The repeated use of `ExceptionState`.

4. **Analyze Each Category for Relationships to Web Technologies:**

    * **JavaScript:** The functions converting `V8UnionNodeOrStringOrTrustedScript` are the most direct link. These functions are clearly bridging the gap between JavaScript values (which can be nodes, strings, or `TrustedScript` objects) and the internal Blink `Node` representation. The `prepend`, `append`, `before`, `after`, `replaceWith`, and `replaceChildren` methods are directly exposed to JavaScript.

    * **HTML:** The core purpose of these functions is to manipulate the HTML DOM tree. Insertion, removal, and replacement directly change the structure represented by the HTML. The `ContainerNode` type and the mention of `DocumentFragment` are related to HTML's structural elements.

    * **CSS:** While this particular code doesn't directly manipulate CSS properties, the changes made by these functions *trigger* CSS updates. When the DOM structure changes, the browser needs to recalculate styles for affected elements. The code touches on concepts like "style invalidation" and "layout tree updates," which are crucial for rendering based on CSS.

5. **Develop Examples (Hypothetical Inputs and Outputs):** For core manipulation functions, create simple HTML snippets and JavaScript calls to illustrate the behavior. This solidifies understanding and helps explain the logic. Think about different scenarios (inserting at the beginning, end, middle, with different node types).

6. **Identify Potential User Errors:** Consider common mistakes developers make when working with the DOM. Examples include:
    * Trying to insert nodes into non-container nodes.
    * Trying to remove a node that isn't a child.
    * Incorrectly handling the return values of these functions.
    * Security issues related to inserting untrusted content.

7. **Outline Debugging Steps:**  Think about how a developer might end up in this code during debugging. This usually involves:
    * Setting breakpoints in JavaScript code calling these methods.
    * Stepping through the C++ code.
    * Examining the DOM structure before and after the operation.

8. **Address the "Part 2 of 5" Aspect:**  Recognize that this snippet focuses on *modifying* the DOM structure. It doesn't cover things like node creation, querying, or event handling (which might be covered in other parts). This helps frame the summary.

9. **Synthesize the Summary:** Combine the analyzed information into a concise and informative summary. Emphasize the core responsibility of DOM manipulation, its relationship to the web technologies, and its role within the larger Blink rendering engine. Use clear and accessible language.

10. **Review and Refine:** Read through the summary to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. Ensure the examples are correct and easy to understand. Make sure the explanation of user errors and debugging is practical.

**Self-Correction/Refinement Example During the Process:**

* **Initial Thought:**  "These functions just manipulate the DOM."
* **Refinement:**  "While true, I need to be more specific. They handle *insertion*, *removal*, and *replacement*. Also, the interaction with `TrustedScript` is important for security, and the connection to style recalculation is a consequence of these manipulations."
* **Further Refinement:** "The `ConvertNodeUnions` functions are crucial for understanding how JavaScript interacts with this C++ code. I should highlight that these act as a bridge."

By following this structured approach and actively refining understanding, a comprehensive and accurate summary can be generated.
这是 `blink/renderer/core/dom/node.cc` 文件的第二部分，延续了第一部分关于 `Node` 类功能的实现。 这部分代码主要集中在 **修改 DOM 树结构** 的操作上， 提供了各种插入、删除、替换节点的方法，并且考虑了与 JavaScript、HTML 和 CSS 的交互。

**功能归纳 (基于提供的代码片段):**

这部分 `node.cc` 的主要功能是实现 `Node` 类中用于修改 DOM 树结构的方法， 这些方法可以直接被 JavaScript 调用，从而允许网页动态地改变其内容和结构。 具体来说，它实现了以下核心功能：

* **插入节点:**
    * `insertBefore(new_child, ref_child, exception_state)`: 在指定的子节点之前插入一个新节点。
    * `insertBefore(new_child, ref_child)`:  `insertBefore` 的无异常版本。
    * `appendChild(new_child, exception_state)`: 在当前节点的子节点列表末尾添加一个新节点。
    * `appendChild(new_child)`: `appendChild` 的无异常版本。
    * `prepend(nodes, exception_state)`: 在当前节点的子节点列表开头插入一组节点（可以是 Node 或字符串）。
    * `append(nodes, exception_state)`: 在当前节点的子节点列表末尾添加一组节点（可以是 Node 或字符串）。
    * `before(nodes, exception_state)`: 在当前节点的前面插入一组节点（可以是 Node 或字符串）。
    * `after(nodes, exception_state)`: 在当前节点的后面插入一组节点（可以是 Node 或字符串）。
* **删除节点:**
    * `removeChild(old_child, exception_state)`: 从当前节点移除一个子节点。
    * `removeChild(old_child)`: `removeChild` 的无异常版本。
    * `remove(exception_state)`: 将当前节点从其父节点中移除。
    * `remove()`: `remove` 的无异常版本。
* **替换节点:**
    * `replaceChild(new_child, old_child, exception_state)`: 将一个已存在的子节点替换为新的节点。
    * `replaceChild(new_child, old_child)`: `replaceChild` 的无异常版本。
    * `replaceWith(nodes, exception_state)`: 将当前节点替换为一组节点（可以是 Node 或字符串）。
    * `replaceChildren(node_unions, exception_state)`:  替换当前节点的所有子节点为一组新的节点（可以是 Node 或字符串）。
* **辅助功能:**
    * `ConvertNodeUnionsIntoNode` 和 `ConvertNodeUnionsIntoNodes`: 将 JavaScript 传递的 `Node` 或字符串或 `TrustedScript` 类型转换为实际的 `Node` 对象，用于插入操作。 这涉及到创建文本节点来表示字符串。
    * `FindViablePreviousSibling` 和 `FindViableNextSibling`:  在插入一组节点时，查找合适的兄弟节点作为插入的参考点，跳过要插入的节点本身。
    * `IsNodeInNodes`:  判断一个节点是否在一组节点中。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 这部分代码是 JavaScript 操作 DOM 的底层实现。 JavaScript 代码可以直接调用这些方法来动态修改网页内容。

    **假设输入与输出:**
    * **假设输入 (JavaScript):**
      ```javascript
      const parentElement = document.getElementById('parent');
      const newElement = document.createElement('div');
      newElement.textContent = 'New Div';
      parentElement.appendChild(newElement);
      ```
    * **输出 (C++ 调用):** 将会调用 `Node::appendChild(newElement 的 C++ 对象, ...)`。  Blink 引擎会将 JavaScript 的 `newElement` 对象映射到其内部的 `Element` 对象。

    * **假设输入 (JavaScript):**
      ```javascript
      const parentElement = document.getElementById('parent');
      const textNode = 'Some text';
      parentElement.prepend(textNode);
      ```
    * **输出 (C++ 调用):** 将会调用 `Node::prepend`， 并且内部会调用 `Node::ConvertNodeUnionsIntoNode` 创建一个 `Text` 节点来表示字符串 `"Some text"`。

* **HTML:** 这些方法直接影响 HTML 结构的呈现。 通过插入、删除和替换节点，可以动态地改变网页的 DOM 树，从而改变用户看到的页面内容。

    **举例说明:**  `appendChild` 可以用于动态添加列表项到 `<ul>` 或 `<ol>` 元素中，或者向一个 `<div>` 容器中添加新的内容块。 `removeChild` 可以用于响应用户交互，例如点击“删除”按钮后移除一个元素。

* **CSS:**  DOM 结构的变化可能会触发浏览器的样式重新计算和重排（reflow/relayout）。 当插入、删除或移动节点时，元素的 CSS 样式可能会受到影响，导致页面布局和渲染的更新。

    **举例说明:**  如果使用 `appendChild` 向一个设置了 `display: flex` 的容器中添加新的子元素，那么浏览器的 CSS 引擎需要重新计算容器内元素的布局。  删除一个应用了特定 CSS 样式的元素也会导致该样式不再生效。

**逻辑推理与假设输入输出:**

* **`ConvertNodeUnionsIntoNode` 和 `ConvertNodeUnionsIntoNodes` 的逻辑:**
    * **假设输入:** JavaScript 调用 `element.append("Hello", document.createElement("span"), "<script>alert('XSS')</script>")`。
    * **逻辑推理:**
        * 对于字符串 `"Hello"`，会创建一个 `Text` 节点。
        * 对于 `document.createElement("span")`，直接使用传入的 `Element` 对象。
        * 对于字符串 `"<script>alert('XSS')</script>"`，如果启用了 Trusted Types，会进行安全检查，否则也会创建一个 `Text` 节点，将其内容作为纯文本插入，防止脚本执行（除非在特定的上下文中，例如 `<script>` 标签的内容）。
    * **输出:** 一个包含 `Text` 节点（内容为 "Hello"）， `Element` 节点 (`<span>`)， 和 `Text` 节点（内容为 `<script>alert('XSS')</script>`）的集合或 `DocumentFragment`。

* **`FindViablePreviousSibling` 和 `FindViableNextSibling` 的逻辑:**
    * **假设输入:**  一个包含节点 A, B, C 的父节点，并且想要在节点 B 之前插入一组节点 [X, B, Y]。
    * **逻辑推理:**  `FindViablePreviousSibling` 会从节点 B 开始向前查找，跳过要插入的节点 X 和 B，找到节点 A 作为参考的兄弟节点。
    * **输出:** 返回节点 A。

**用户或编程常见的使用错误:**

* **尝试在非 `ContainerNode` 上调用插入/删除方法:**  例如，尝试在 `Text` 节点上调用 `appendChild` 会抛出 `HierarchyRequestError` 异常，因为文本节点不能拥有子节点。
    * **用户操作:**  JavaScript 代码错误地将文本节点当作元素节点来操作。
    * **调试线索:** 异常信息会指出节点类型不支持该方法。检查 JavaScript 代码中调用这些方法的对象类型。
* **尝试删除不存在的子节点:** 调用 `removeChild` 时，如果传入的节点不是当前节点的子节点，会抛出 `NotFoundError` 异常。
    * **用户操作:**  JavaScript 代码中可能存在逻辑错误，导致尝试删除已经被删除的节点或者错误的节点。
    * **调试线索:** 异常信息会指出找不到要删除的节点。检查 JavaScript 代码中节点的引用和父子关系。
* **插入的节点类型不符合规范:**  某些节点只能作为特定类型节点的子节点。 例如，`<!DOCTYPE>` 节点只能作为 `Document` 节点的子节点。 尝试将它添加到其他类型的节点会抛出 `HierarchyRequestError`。
    * **用户操作:**  JavaScript 代码尝试构建不合法的 DOM 结构。
    * **调试线索:** 异常信息会指出节点类型不符合层级要求。仔细检查要插入的节点类型和目标父节点的类型。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户在浏览器中与网页交互:** 例如，点击按钮、填写表单、滚动页面等。
2. **JavaScript 事件处理程序被触发:**  用户的交互可能绑定了 JavaScript 事件处理程序。
3. **JavaScript 代码执行，调用 DOM 操作方法:**  事件处理程序中的 JavaScript 代码可能会调用如 `appendChild`, `removeChild`, `insertBefore` 等方法来修改 DOM 结构。
4. **Blink 引擎接收到 JavaScript 的 DOM 操作请求:** JavaScript 引擎会将这些请求传递给 Blink 引擎。
5. **`blink/renderer/core/dom/node.cc` 中的相应方法被调用:** 例如，如果 JavaScript 调用了 `element.appendChild(newNode)`,  那么 `Node::appendChild` 方法会被执行。

**调试线索:**

* **在 JavaScript 代码中设置断点:**  在调用 DOM 操作方法的地方设置断点，可以查看调用时的参数和上下文。
* **使用浏览器的开发者工具:**  可以使用 Chrome DevTools 的 "Elements" 面板来观察 DOM 树的变化。 "Break on subtree modifications" 功能可以在 DOM 树发生变化时暂停 JavaScript 执行。
* **在 C++ 代码中设置断点 (如果可以构建 Chromium):**  可以在 `blink/renderer/core/dom/node.cc` 中相关的方法处设置断点，例如 `Node::appendChild`，来深入了解 Blink 引擎的执行过程。
* **查看异常信息:**  浏览器控制台会显示 JavaScript 抛出的异常信息，这些信息通常包含了错误类型和描述，可以帮助定位问题。

总而言之，这部分 `node.cc` 代码是 Blink 引擎中处理 DOM 结构修改的核心部分，它连接了 JavaScript 代码和底层的 DOM 树操作，并确保了这些操作的正确性和安全性。 理解这部分代码的功能对于理解浏览器如何动态渲染网页至关重要。

Prompt: 
```
这是目录为blink/renderer/core/dom/node.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能

"""
ld_child, exception_state);

  exception_state.ThrowDOMException(
      DOMExceptionCode::kHierarchyRequestError,
      "This node type does not support this method.");
  return nullptr;
}

Node* Node::replaceChild(Node* new_child, Node* old_child) {
  return replaceChild(new_child, old_child, ASSERT_NO_EXCEPTION);
}

Node* Node::removeChild(Node* old_child, ExceptionState& exception_state) {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (this_node)
    return this_node->RemoveChild(old_child, exception_state);

  exception_state.ThrowDOMException(
      DOMExceptionCode::kNotFoundError,
      "This node type does not support this method.");
  return nullptr;
}

Node* Node::removeChild(Node* old_child) {
  return removeChild(old_child, ASSERT_NO_EXCEPTION);
}

Node* Node::appendChild(Node* new_child, ExceptionState& exception_state) {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (this_node)
    return this_node->AppendChild(new_child, exception_state);

  exception_state.ThrowDOMException(
      DOMExceptionCode::kHierarchyRequestError,
      "This node type does not support this method.");
  return nullptr;
}

Node* Node::appendChild(Node* new_child) {
  return appendChild(new_child, ASSERT_NO_EXCEPTION);
}

static bool IsNodeInNodes(
    const Node* const node,
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes) {
  for (const V8UnionNodeOrStringOrTrustedScript* node_or_string : nodes) {
    if (node_or_string->IsNode() && node_or_string->GetAsNode() == node)
      return true;
  }
  return false;
}

static Node* FindViablePreviousSibling(
    const Node& node,
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes) {
  for (Node* sibling = node.previousSibling(); sibling;
       sibling = sibling->previousSibling()) {
    if (!IsNodeInNodes(sibling, nodes))
      return sibling;
  }
  return nullptr;
}

static Node* FindViableNextSibling(
    const Node& node,
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes) {
  for (Node* sibling = node.nextSibling(); sibling;
       sibling = sibling->nextSibling()) {
    if (!IsNodeInNodes(sibling, nodes))
      return sibling;
  }
  return nullptr;
}

static Node* NodeOrStringToNode(
    const V8UnionNodeOrStringOrTrustedScript* node_or_string,
    Document& document,
    bool needs_trusted_types_check,
    const char* property_name,
    ExceptionState& exception_state) {
  if (!needs_trusted_types_check) {
    // Without trusted type checks, we simply extract the string from whatever
    // constituent type we find.
    switch (node_or_string->GetContentType()) {
      case V8UnionNodeOrStringOrTrustedScript::ContentType::kNode:
        return node_or_string->GetAsNode();
      case V8UnionNodeOrStringOrTrustedScript::ContentType::kString:
        return Text::Create(document, node_or_string->GetAsString());
      case V8UnionNodeOrStringOrTrustedScript::ContentType::kTrustedScript:
        return Text::Create(document,
                            node_or_string->GetAsTrustedScript()->toString());
    }
    NOTREACHED();
  }

  // With trusted type checks, we can process trusted script or non-text nodes
  // directly. Strings or text nodes need to be checked.
  if (node_or_string->IsNode() && !node_or_string->GetAsNode()->IsTextNode())
    return node_or_string->GetAsNode();

  if (node_or_string->IsTrustedScript()) {
    return Text::Create(document,
                        node_or_string->GetAsTrustedScript()->toString());
  }

  String string_value = node_or_string->IsString()
                            ? node_or_string->GetAsString()
                            : node_or_string->GetAsNode()->textContent();

  string_value =
      TrustedTypesCheckForScript(string_value, document.GetExecutionContext(),
                                 "Node", property_name, exception_state);
  if (exception_state.HadException())
    return nullptr;
  return Text::Create(document, string_value);
}

// Converts |node_unions| from bindings into actual Nodes by converting strings
// and script into text nodes via NodeOrStringToNode.
// Returns nullptr if an exception was thrown.
// static
Node* Node::ConvertNodeUnionsIntoNode(
    const ContainerNode* parent,
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& node_unions,
    Document& document,
    const char* property_name,
    ExceptionState& exception_state) {
  DCHECK(!RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled());

  bool needs_check = IsA<HTMLScriptElement>(parent) &&
                     document.GetExecutionContext() &&
                     document.GetExecutionContext()->RequireTrustedTypes();
  VectorOf<Node> nodes;
  for (const auto& node_union : node_unions) {
    Node* node = NodeOrStringToNode(node_union, document, needs_check,
                                    property_name, exception_state);
    if (exception_state.HadException()) {
      return nullptr;
    }
    if (node) {
      nodes.push_back(node);
    }
  }

  if (nodes.size() == 1u) {
    return nodes[0];
  }

  Node* fragment = DocumentFragment::Create(document);
  for (const auto& node : nodes) {
    fragment->appendChild(node, exception_state);
    if (exception_state.HadException()) {
      return nullptr;
    }
  }
  return fragment;
}

// Converts |node_unions| from bindings into actual Nodes by converting strings
// and script into text nodes via NodeOrStringToNode.
// Returns nullptr if an exception was thrown.
// static
VectorOf<Node> Node::ConvertNodeUnionsIntoNodes(
    const ContainerNode* parent,
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& node_unions,
    Document& document,
    const char* property_name,
    ExceptionState& exception_state) {
  DCHECK(RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled());

  bool needs_check = IsA<HTMLScriptElement>(parent) &&
                     document.GetExecutionContext() &&
                     document.GetExecutionContext()->RequireTrustedTypes();
  VectorOf<Node> nodes;
  for (const auto& node_union : node_unions) {
    Node* node = NodeOrStringToNode(node_union, document, needs_check,
                                    property_name, exception_state);
    if (exception_state.HadException()) {
      nodes.clear();
      return nodes;
    }
    if (node) {
      if (auto* fragment = DynamicTo<DocumentFragment>(node)) {
        NodeVector fragment_nodes;
        GetChildNodes(*fragment, fragment_nodes);
        fragment->RemoveChildren();
        nodes.AppendVector(fragment_nodes);
      } else {
        nodes.push_back(node);
      }
    }
  }

  // When there's more than one node, we need to pretend that we're inserting
  // the nodes into a document fragment (which we later insert into the
  // intended parent, which transfers them from the document fragment), but we
  // don't actually do that because of the costs of inserting and later
  // removing (which require walking the entire tree).  Not actually inserting
  // into a DocumentFragment is web observable in some edge cases, and
  // https://github.com/whatwg/dom/issues/1313 proposes to specify this new
  // (faster) behavior instead.
  //
  // TODO(https://github.com/whatwg/dom/issues/1313): We should consider not
  // having different behavior depending on how many nodes are here, which
  // makes it a strange API.
  //
  // The only pre-insertion check that could fail when inserting into a
  // DocumentFragment is the ChildTypeAllowed check.  This will be checked
  // again later when we insert the nodes into their intended parent.
  // However, this does mean we differ from the spec in two ways:
  // * we allow the use of DocumentType nodes (when their eventual parent is a
  //   Document) in these methods where the spec would disallow them.
  // * we perform some of the checks at different times, which means that when
  //   an exception is thrown it could be a different exception from the one
  //   the spec calls for, and we could leave the tree in a different state
  //   than exactly following the spec would lead to.

  if (nodes.size() > 1u) {
    // Remove each node from its parent, and if a node occurs multiple
    // times in the list, remove all except the *last* occurrence.
    HeapHashSet<Member<Node>> nodes_seen;
    HeapVector<Member<Node>> nodes_to_remove;
    for (Node* node : nodes) {
      auto add_result = nodes_seen.insert(node);
      if (add_result.is_new_entry) {
        node->remove(exception_state);
        if (exception_state.HadException()) {
          nodes.clear();
          return nodes;
        }
      } else {
        nodes_to_remove.push_back(node);
      }
    }
    // The same node might be in nodes_to_remove more than once; for
    // each occurrence we will remove one occurrence.  This is slow, but
    // it's handling what is essentially an error case.
    for (Node* node : nodes_to_remove) {
      wtf_size_t index = nodes.Find(node);
      CHECK_NE(index, kNotFound);
      nodes.EraseAt(index);
    }
  }

  return nodes;
}

void Node::prepend(
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes,
    ExceptionState& exception_state) {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (!this_node) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "This node type does not support this method.");
    return;
  }

  if (RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled()) {
    VectorOf<Node> node_vector = ConvertNodeUnionsIntoNodes(
        this_node, nodes, GetDocument(), "prepend", exception_state);
    if (exception_state.HadException()) {
      return;
    }
    this_node->InsertBefore(node_vector, this_node->firstChild(),
                            exception_state);
  } else {
    if (Node* node = ConvertNodeUnionsIntoNode(this_node, nodes, GetDocument(),
                                               "prepend", exception_state)) {
      this_node->InsertBefore(node, this_node->firstChild(), exception_state);
    }
  }
}

void Node::append(
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes,
    ExceptionState& exception_state) {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (!this_node) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "This node type does not support this method.");
    return;
  }

  if (RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled()) {
    VectorOf<Node> node_vector = ConvertNodeUnionsIntoNodes(
        this_node, nodes, GetDocument(), "append", exception_state);
    if (exception_state.HadException()) {
      return;
    }
    this_node->AppendChildren(node_vector, exception_state);
  } else {
    if (Node* node = ConvertNodeUnionsIntoNode(this_node, nodes, GetDocument(),
                                               "append", exception_state)) {
      this_node->AppendChild(node, exception_state);
    }
  }
}

void Node::before(
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes,
    ExceptionState& exception_state) {
  ContainerNode* parent = parentNode();
  if (!parent)
    return;
  Node* viable_previous_sibling = FindViablePreviousSibling(*this, nodes);
  if (RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled()) {
    VectorOf<Node> node_vector = ConvertNodeUnionsIntoNodes(
        parent, nodes, GetDocument(), "before", exception_state);
    if (exception_state.HadException()) {
      return;
    }
    parent->InsertBefore(node_vector,
                         viable_previous_sibling
                             ? viable_previous_sibling->nextSibling()
                             : parent->firstChild(),
                         exception_state);
  } else {
    if (Node* node = ConvertNodeUnionsIntoNode(parent, nodes, GetDocument(),
                                               "before", exception_state)) {
      parent->InsertBefore(node,
                           viable_previous_sibling
                               ? viable_previous_sibling->nextSibling()
                               : parent->firstChild(),
                           exception_state);
    }
  }
}

void Node::after(
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes,
    ExceptionState& exception_state) {
  ContainerNode* parent = parentNode();
  if (!parent)
    return;
  Node* viable_next_sibling = FindViableNextSibling(*this, nodes);
  if (RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled()) {
    VectorOf<Node> node_vector = ConvertNodeUnionsIntoNodes(
        parent, nodes, GetDocument(), "after", exception_state);
    if (exception_state.HadException()) {
      return;
    }
    parent->InsertBefore(node_vector, viable_next_sibling, exception_state);
  } else {
    if (Node* node = ConvertNodeUnionsIntoNode(parent, nodes, GetDocument(),
                                               "after", exception_state)) {
      parent->InsertBefore(node, viable_next_sibling, exception_state);
    }
  }
}

void Node::replaceWith(
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& nodes,
    ExceptionState& exception_state) {
  ContainerNode* parent = parentNode();
  if (!parent)
    return;
  Node* viable_next_sibling = FindViableNextSibling(*this, nodes);
  if (RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled()) {
    VectorOf<Node> node_vector = ConvertNodeUnionsIntoNodes(
        parent, nodes, GetDocument(), "replaceWith", exception_state);
    if (exception_state.HadException()) {
      return;
    }
    if (parent == parentNode()) {
      parent->ReplaceChild(node_vector, this, exception_state);
    } else {
      parent->InsertBefore(node_vector, viable_next_sibling, exception_state);
    }
  } else {
    Node* node = ConvertNodeUnionsIntoNode(parent, nodes, GetDocument(),
                                           "replaceWith", exception_state);
    if (exception_state.HadException()) {
      return;
    }
    if (parent == parentNode()) {
      parent->ReplaceChild(node, this, exception_state);
    } else {
      parent->InsertBefore(node, viable_next_sibling, exception_state);
    }
  }
}

// https://dom.spec.whatwg.org/#dom-parentnode-replacechildren
void Node::replaceChildren(
    const HeapVector<Member<V8UnionNodeOrStringOrTrustedScript>>& node_unions,
    ExceptionState& exception_state) {
  auto* this_node = DynamicTo<ContainerNode>(this);
  if (!this_node) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "This node type does not support this method.");
    return;
  }

  if (RuntimeEnabledFeatures::SkipTemporaryDocumentFragmentEnabled()) {
    VectorOf<Node> nodes = ConvertNodeUnionsIntoNodes(
        this_node, node_unions, GetDocument(), "replace", exception_state);
    if (exception_state.HadException()) {
      return;
    }
    this_node->ReplaceChildren(nodes, exception_state);
  } else {
    Node* node = ConvertNodeUnionsIntoNode(
        this_node, node_unions, GetDocument(), "replace", exception_state);
    if (!exception_state.HadException()) {
      this_node->ReplaceChildren(node, exception_state);
    }
  }
}

void Node::remove(ExceptionState& exception_state) {
  if (ContainerNode* parent = parentNode())
    parent->RemoveChild(this, exception_state);
}

void Node::remove() {
  remove(ASSERT_NO_EXCEPTION);
}

Element* Node::previousElementSibling() {
  return ElementTraversal::PreviousSibling(*this);
}

Element* Node::nextElementSibling() {
  return ElementTraversal::NextSibling(*this);
}

Node* Node::cloneNode(bool deep, ExceptionState& exception_state) const {
  // https://dom.spec.whatwg.org/#dom-node-clonenode

  // 1. If this is a shadow root, then throw a "NotSupportedError" DOMException.
  if (IsShadowRoot()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "ShadowRoot nodes are not clonable.");
    return nullptr;
  }

  // 2. Return a clone of this, with the clone children flag set if deep is
  // true, and the clone shadows flag set if this is a DocumentFragment whose
  // host is an HTML template element.
  NodeCloningData data;
  if (deep) {
    data.Put(CloneOption::kIncludeDescendants);
  }
  return Clone(GetDocument(), data, /*append_to*/ nullptr);
}

Node* Node::cloneNode(bool deep) const {
  return cloneNode(deep, ASSERT_NO_EXCEPTION);
}

void Node::normalize() {
  // Go through the subtree beneath us, normalizing all nodes. This means that
  // any two adjacent text nodes are merged and any empty text nodes are
  // removed.

  Node* node = this;
  while (Node* first_child = node->firstChild())
    node = first_child;
  while (node) {
    if (node == this)
      break;

    if (node->getNodeType() == kTextNode)
      node = To<Text>(node)->MergeNextSiblingNodesIfPossible();
    else
      node = NodeTraversal::NextPostOrder(*node);
  }
}

LayoutBox* Node::GetLayoutBox() const {
  return DynamicTo<LayoutBox>(GetLayoutObject());
}

LayoutBoxModelObject* Node::GetLayoutBoxModelObject() const {
  return DynamicTo<LayoutBoxModelObject>(GetLayoutObject());
}

PhysicalRect Node::BoundingBox() const {
  if (GetLayoutObject())
    return PhysicalRect(GetLayoutObject()->AbsoluteBoundingBoxRect());
  return PhysicalRect();
}

gfx::Rect Node::PixelSnappedBoundingBox() const {
  return ToPixelSnappedRect(BoundingBox());
}

PhysicalRect Node::BoundingBoxForScrollIntoView() const {
  if (GetLayoutObject()) {
    return GetLayoutObject()->AbsoluteBoundingBoxRectForScrollIntoView();
  }

  return PhysicalRect();
}

Node& Node::ShadowIncludingRoot() const {
  if (isConnected())
    return GetDocument();
  Node* root = const_cast<Node*>(this);
  while (Node* host = root->OwnerShadowHost())
    root = host;
  while (Node* ancestor = root->parentNode())
    root = ancestor;
  DCHECK(!root->OwnerShadowHost());
  return *root;
}

bool Node::IsClosedShadowHiddenFrom(const Node& other) const {
  if (!IsInShadowTree() || GetTreeScope() == other.GetTreeScope())
    return false;

  const TreeScope* scope = &GetTreeScope();
  for (; scope->ParentTreeScope(); scope = scope->ParentTreeScope()) {
    const ContainerNode& root = scope->RootNode();
    auto* shadow_root = DynamicTo<ShadowRoot>(root);
    if (shadow_root && !shadow_root->IsOpen())
      break;
  }

  for (TreeScope* other_scope = &other.GetTreeScope(); other_scope;
       other_scope = other_scope->ParentTreeScope()) {
    if (other_scope == scope)
      return false;
  }
  return true;
}

void Node::SetIsLink(bool is_link) {
  SetFlag(is_link && !SVGImage::IsInSVGImage(To<Element>(this)), kIsLinkFlag);
}

void Node::SetNeedsStyleInvalidation() {
  DCHECK(IsContainerNode());
  DCHECK(!GetDocument().InvalidationDisallowed());
  SetFlag(kNeedsStyleInvalidationFlag);
  MarkAncestorsWithChildNeedsStyleInvalidation();
}

void Node::MarkAncestorsWithChildNeedsStyleInvalidation() {
  ScriptForbiddenScope forbid_script_during_raw_iteration;
  ContainerNode* ancestor = ParentOrShadowHostNode();
  bool parent_dirty = ancestor && ancestor->NeedsStyleInvalidation();
  for (; ancestor && !ancestor->ChildNeedsStyleInvalidation();
       ancestor = ancestor->ParentOrShadowHostNode()) {
    if (!ancestor->isConnected())
      return;
    ancestor->SetChildNeedsStyleInvalidation();
    if (ancestor->NeedsStyleInvalidation())
      break;
  }
  if (!isConnected())
    return;
  // If the parent node is already dirty, we can keep the same invalidation
  // root. The early return here is a performance optimization.
  if (parent_dirty)
    return;
  GetDocument().GetStyleEngine().UpdateStyleInvalidationRoot(ancestor, this);
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

void Node::MarkSubtreeNeedsStyleRecalcForFontUpdates() {
  if (GetStyleChangeType() == kSubtreeStyleChange)
    return;

  if (auto* element = DynamicTo<Element>(this)) {
    const ComputedStyle* style = element->GetComputedStyle();
    if (!style)
      return;

    // We require font-specific metrics to resolve length units 'ex' and 'ch',
    // and to compute the adjusted font size when 'font-size-adjust' is set. All
    // other style computations are unaffected by font loading.
    if (!NeedsStyleRecalc()) {
      if (style->DependsOnFontMetrics() ||
          element->PseudoElementStylesDependOnFontMetrics()) {
        SetNeedsStyleRecalc(
            kLocalStyleChange,
            StyleChangeReasonForTracing::Create(style_change_reason::kFonts));
      }
    }

    if (Node* shadow_root = GetShadowRoot())
      shadow_root->MarkSubtreeNeedsStyleRecalcForFontUpdates();
  }

  for (Node* child = firstChild(); child; child = child->nextSibling())
    child->MarkSubtreeNeedsStyleRecalcForFontUpdates();
}

bool Node::ShouldSkipMarkingStyleDirty() const {
  // If our parent element does not have a computed style, it's not necessary to
  // mark this node for style recalc.
  if (Element* parent = GetStyleRecalcParent()) {
    return !parent->GetComputedStyle();
  }
  if (const Element* element = DynamicTo<Element>(this)) {
    const Element* root_element = GetDocument().documentElement();
    if (!root_element || element == root_element) {
      // This is the root element, or we are about to insert the root element.
      // Should always allow marking it dirty.
      return false;
    }
    // This is an element outside the flat tree without a parent. Should only
    // mark dirty if it has an ensured style.
    return !element->GetComputedStyle();
  }
  // Text nodes outside the flat tree do not need to be marked for style recalc.
  return true;
}

void Node::MarkAncestorsWithChildNeedsStyleRecalc() {
  Element* style_parent = GetStyleRecalcParent();
  bool parent_dirty = style_parent && style_parent->IsDirtyForStyleRecalc();
  Element* ancestor = style_parent;
  for (; ancestor && !ancestor->ChildNeedsStyleRecalc();
       ancestor = ancestor->GetStyleRecalcParent()) {
    if (!ancestor->isConnected())
      return;
    ancestor->SetChildNeedsStyleRecalc();
    if (ancestor->IsDirtyForStyleRecalc())
      break;

    // If we reach a locked ancestor, we should abort since the ancestor marking
    // will be done when the lock is committed.
    if (ancestor->ChildStyleRecalcBlockedByDisplayLock())
      break;
  }
  if (!isConnected())
    return;
  // If the parent node is already dirty, we can keep the same recalc root. The
  // early return here is a performance optimization.
  if (parent_dirty)
    return;
  // If we are outside the flat tree we should not update the recalc root
  // because we should not traverse those nodes from StyleEngine::RecalcStyle().
  const ComputedStyle* current_style = nullptr;
  if (Element* element = DynamicTo<Element>(this)) {
    current_style = element->GetComputedStyle();
  }
  if (!current_style && style_parent) {
    current_style = style_parent->GetComputedStyle();
  }
  if (current_style && current_style->IsEnsuredOutsideFlatTree()) {
    return;
  }
  // If we're in a locked subtree, then we should not update the style recalc
  // roots. These would be updated when we commit the lock. If we have locked
  // display locks somewhere in the document, we iterate up the ancestor chain
  // to check if we're in one such subtree.
  if (GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount() >
      0) {
    for (Element* ancestor_copy = ancestor; ancestor_copy;
         ancestor_copy = ancestor_copy->GetStyleRecalcParent()) {
      if (ancestor_copy->ChildStyleRecalcBlockedByDisplayLock())
        return;
    }
  }

  GetDocument().GetStyleEngine().UpdateStyleRecalcRoot(ancestor, this);
  GetDocument().ScheduleLayoutTreeUpdateIfNeeded();
}

Element* Node::FlatTreeParentForChildDirty() const {
  if (IsPseudoElement())
    return ParentOrShadowHostElement();
  if (IsChildOfShadowHost()) {
    if (auto* data = GetFlatTreeNodeData())
      return data->AssignedSlot();
    return nullptr;
  }
  Element* parent = ParentOrShadowHostElement();
  if (HTMLSlotElement* slot = DynamicTo<HTMLSlotElement>(parent)) {
    if (slot->HasAssignedNodesNoRecalc())
      return nullptr;
  }
  return parent;
}

void Node::MarkAncestorsWithChildNeedsReattachLayoutTree() {
  DCHECK(isConnected());
  Element* ancestor = GetReattachParent();
  bool parent_dirty = ancestor && ancestor->IsDirtyForRebuildLayoutTree();
  DCHECK(!ancestor || !ChildNeedsReattachLayoutTree() ||
         !ancestor->ChildNeedsReattachLayoutTree() || NeedsReattachLayoutTree())
      << "If both this and the parent are already marked with "
         "ChildNeedsReattachLayoutTree(), something is broken and "
         "UpdateLayoutTreeRebuildRoot() will be confused about common "
         "ancestors.";
  for (; ancestor && !ancestor->ChildNeedsReattachLayoutTree();
       ancestor = ancestor->GetReattachParent()) {
    ancestor->SetChildNeedsReattachLayoutTree();
    if (ancestor->IsDirtyForRebuildLayoutTree())
      break;

    // If we reach a locked ancestor, we should abort since the ancestor marking
    // will be done when the context is unlocked.
    if (ancestor->ChildStyleRecalcBlockedByDisplayLock())
      break;
  }
  // If the parent node is already dirty, we can keep the same rebuild root. The
  // early return here is a performance optimization.
  if (parent_dirty)
    return;

  // If we're in a locked subtree, then we should not update the layout tree
  // rebuild root. It would be updated when we unlock the context. In other
  // words, the only way we have a node in the locked subtree is if the ancestor
  // has a locked display lock context or it is dirty for reattach. In either of
  // those cases, we have a dirty bit trail up to the display lock context,
  // which will be propagated when the lock is removed.
  if (GetDocument().GetDisplayLockDocumentState().LockedDisplayLockCount() >
      0) {
    for (Element* ancestor_copy = ancestor; ancestor_copy;
         ancestor_copy = ancestor_copy->GetReattachParent()) {
      if (ancestor_copy->ChildStyleRecalcBlockedByDisplayLock())
        return;
    }
  }
  GetDocument().GetStyleEngine().UpdateLayoutTreeRebuildRoot(ancestor, this);
}

void Node::SetNeedsReattachLayoutTree() {
  DCHECK(GetDocument().InStyleRecalc());
  DCHECK(GetDocument().GetStyleEngine().MarkReattachAllowed());
  DCHECK(!GetDocument().InvalidationDisallowed());
  DCHECK(IsElementNode() || IsTextNode());
  DCHECK(InActiveDocument());
  SetFlag(kNeedsReattachLayoutTree);
  MarkAncestorsWithChildNeedsReattachLayoutTree();
}

void Node::SetNeedsStyleRecalc(StyleChangeType change_type,
                               const StyleChangeReasonForTracing& reason) {
  DCHECK(GetDocument().GetStyleEngine().MarkStyleDirtyAllowed());
  DCHECK(!GetDocument().InvalidationDisallowed());
  DCHECK(change_type != kNoStyleChange);
  DCHECK(IsElementNode() || IsTextNode());

  if (!InActiveDocument())
    return;
  if (ShouldSkipMarkingStyleDirty())
    return;

  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT_WITH_CATEGORIES(
      TRACE_DISABLED_BY_DEFAULT("devtools.timeline.invalidationTracking"),
      "StyleRecalcInvalidationTracking",
      inspector_style_recalc_invalidation_tracking_event::Data, this,
      change_type, reason);

  StyleChangeType existing_change_type = GetStyleChangeType();
  if (change_type > existing_change_type)
    SetStyleChange(change_type);

  if (existing_change_type == kNoStyleChange)
    MarkAncestorsWithChildNeedsStyleRecalc();

  // NOTE: If we are being called from SetNeedsAnimationStyleRecalc(), the
  // AnimationStyleChange bit may be reset to 'true'.
  if (auto* this_element = DynamicTo<Element>(this)) {
    this_element->SetAnimationStyleChange(false);

    // The style walk for the pseudo tree created for a ViewTransition is
    // done after resolving style for the author DOM. See
    // StyleEngine::RecalcTransitionPseudoStyle.
    // Since the dirty bits from the originating element (root element) are not
    // propagated to these pseudo elements during the default walk, we need to
    // invalidate style for these elements here.
    if (this_element->IsDocumentElement()) {
      auto update_style_change = [](PseudoElement* pseudo_element) {
        pseudo_element->SetNeedsStyleRecalc(
            kLocalStyleChange, StyleChangeReasonForTracing::Create(
                                   style_change_reason::kViewTransition));
      };
      ViewTransitionUtils::ForEachTransitionPseudo(GetDocument(),
                                                   update_style_change);
    }
  }

  if (auto* svg_element = DynamicTo<SVGElement>(this))
    svg_element->SetNeedsStyleRecalcForInstances(change_type, reason);
}

void Node::ClearNeedsStyleRecalc() {
  node_flags_ &= ~kStyleChangeMask;
  ClearFlag(kForceReattachLayoutTree);
  if (!data_) {
    return;
  }
  if (auto* element = DynamicTo<Element>(this)) {
    element->SetAnimationStyleChange(false);
  }
}

bool Node::InActiveDocument() const {
  return isConnected() && GetDocument().IsActive();
}

bool Node::ShouldHaveFocusAppearance() const {
  DCHECK(IsFocused());
  return true;
}

void Node::FocusabilityLost() {
  if (IsA<HTMLFormElement>(this) || IsA<HTMLFormControlElement>(this)) {
    GetDocument().DidChangeFormRelatedElementDynamically(
        DynamicTo<HTMLElement>(this), WebFormRelatedChangeType::kHide);
  }
}

LinkHighlightCandidate Node::IsLinkHighlightCandidate() const {
  if (const LayoutObject* layout_object = GetLayoutObject()) {
    const ECursor cursor = layout_object->StyleRef().Cursor();
    if (cursor == ECursor::kPointer)
      return LinkHighlightCandidate::kYes;
    if (cursor != ECursor::kAuto)
      return LinkHighlightCandidate::kNo;
    if (EventHandler::UsesHandCursor(this))
      return LinkHighlightCandidate::kYes;
  }
  return LinkHighlightCandidate::kMayBe;
}

unsigned Node::NodeIndex() const {
  const Node* temp_node = previousSibling();
  unsigned count = 0;
  for (count = 0; temp_node; count++)
    temp_node = temp_node->previousSibling();
  return count;
}

NodeListsNodeData* Node::NodeLists() {
  return data_ ? data_->NodeLists() : nullptr;
}

void Node::ClearNodeLists() {
  RareData()->ClearNodeLists();
}

FlatTreeNodeData& Node::EnsureFlatTreeNodeData() {
  return EnsureRareData().EnsureFlatTreeNodeData();
}

FlatTreeNodeData* Node::GetFlatTreeNodeData() const {
  if (!data_) {
    return nullptr;
  }
  return RareData()->GetFlatTreeNodeData();
}

void Node::ClearFlatTreeNodeData() {
  if (FlatTreeNodeData* data = GetFlatTreeNodeData())
    data->Clear();
}

void Node::ClearFlatTreeNodeDataIfHostChanged(const ContainerNode& parent) {
  if (FlatTreeNodeData* data = GetFlatTreeNodeData()) {
    if (data->AssignedSlot() &&
        data->AssignedSlot()->OwnerShadowHost() != &parent) {
      data->Clear();
    }
  }
}

bool Node::IsDescendantOf(const Node* other) const {
  DCHECK(this);  // Necessary for clusterfuzz tooling to get a useful backtrace

  // Return true if other is an ancestor of this, otherwise false
  if (!other || isConnected() != other->isConnected())
    return false;
  if (other->GetTreeScope() != GetTreeScope())
    return false;
  if (other->IsTreeScope())
    return !IsTreeScope();
  for (const ContainerNode* n = parentNode(); n; n = n->parentNode()) {
    if (n == other)
      return true;
  }
  return false;
}

bool Node::IsDescendantOrShadowDescendantOf(const Node* other) const {
  if (IsDescendantOf(other))
    return true;

  for (auto* host = OwnerShadowHost(); host; host = host->OwnerShadowHost()) {
    if (other->contains(host))
      return true;
  }
  return false;
}

bool Node::contains(const Node* node) const {
  if (!node)
    return false;
  return this == node || node->IsDescendantOf(this);
}

bool Node::IsShadowIncludingInclusiveAncestorOf(const Node& node) const {
  return this == &node || IsShadowIncludingAncestorOf(node);
}

bool Node::IsShadowIncludingAncestorOf(const Node& node) const {
  // In the following case, contains(host) below returns true.
  if (this == &node)
    return false;

  if (GetDocument() != node.GetDocument())
    return false;

  if (isConnected() != node.isConnected())
    return false;

  auto* this_node = DynamicTo<ContainerNode>(this);
  bool has_children = this_node ? this_node->HasChildren() : false;
  bool has_shadow = IsShadowHost(this);
  if (!has_children && !has_shadow)
    return false;

  for (const Node* host = &node; host; host = host->OwnerShadowHost()) {
    if (GetTreeScope() == host->GetTreeScope())
      return contains(host);
  }

  return false;
}

bool Node::ContainsIncludingHostElements(const Node& node) const {
  const Node* current = &node;
  do {
    if (current == this)
      return true;
    auto* curr_fragment = DynamicTo<DocumentFragment>
"""


```