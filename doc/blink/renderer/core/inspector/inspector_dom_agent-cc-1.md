Response:
The user wants a summary of the functionality of the provided C++ code snippet from `inspector_dom_agent.cc`. I need to identify the key features and relate them to web technologies like JavaScript, HTML, and CSS where applicable. I should also look for examples of logical reasoning within the code and potential user errors.

Here's a breakdown of the code's functionality:

1. **Node Manipulation:**  Functions for setting and removing attributes, setting node names and values, removing nodes, setting outer HTML.
2. **DOM Traversal and Search:**  Functions for searching the DOM tree based on various criteria (selectors, text, attributes, XPath).
3. **Remote Object Handling:**  Functions for interacting with DOM nodes represented as remote objects (likely in the context of the browser's debugging protocol).
4. **DOM Modification:** Functions for copying and moving nodes.
5. **Undo/Redo:** Functions for managing DOM modifications.
6. **Focus Management:** Function to focus on a specific DOM element.
7. **File Input Handling:** Function to simulate setting files for `<input type="file">` elements.
8. **Node Creation Stack Traces:** Functions to enable and retrieve the stack trace of when a node was created.
9. **Layout and Box Model:** Functions to retrieve the box model and content quads of a node.
10. **Node Location:** Function to find the DOM node at a specific screen coordinate.
11. **Node Resolution:** Function to obtain a remote object representation of a DOM node.
12. **Attribute Retrieval:** Function to get all attributes of an element.
13. **Node Request:** Function to get the node ID for a given remote object ID.
14. **Container Queries:** Functions related to finding and querying elements based on container queries.
15. **Element Relationships:** Functions to get related elements, such as the target of a popover or an anchor element.

Now, I'll organize these into a concise summary addressing the user's specific requests.
这是 `blink/renderer/core/inspector/inspector_dom_agent.cc` 源代码文件的**第 2 部分**，主要负责以下与 DOM 相关的操作和信息查询功能，这些功能被开发者工具用于检查和修改网页的 DOM 结构：

**功能归纳：**

* **属性操作:**
    * **`setAttributeValue`**: 设置指定元素的属性值。
    * **`setAttributesAsText`**:  以文本形式设置元素的多个属性。
    * **`removeAttribute`**: 移除指定元素的属性。
* **节点操作:**
    * **`removeNode`**: 移除指定节点。
    * **`setNodeName`**: 修改指定节点的标签名。
    * **`getOuterHTML`**: 获取指定节点的外部 HTML 字符串表示。
    * **`setOuterHTML`**:  替换指定节点的外部 HTML 内容。
    * **`setNodeValue`**: 设置指定节点的值（例如，文本节点的内容）。
* **DOM 搜索:**
    * **`performSearch`**: 在文档中执行搜索，查找匹配指定查询的节点。支持 CSS 选择器、文本搜索、属性搜索和 XPath 查询。
    * **`getSearchResults`**: 获取指定搜索 ID 的结果集中指定范围的节点 ID。
    * **`discardSearchResults`**: 丢弃指定搜索 ID 的搜索结果。
* **远程对象关联:**
    * **`NodeForRemoteObjectId`**:  根据远程对象 ID 获取对应的 DOM 节点。
* **DOM 修改操作 (复制和移动):**
    * **`copyTo`**: 将指定节点复制到另一个元素下。
    * **`moveTo`**: 将指定节点移动到另一个元素下。
* **历史记录 (Undo/Redo):**
    * **`undo`**: 撤销上一步 DOM 操作。
    * **`redo`**: 重做上一步撤销的 DOM 操作。
    * **`markUndoableState`**: 标记当前 DOM 状态为可撤销的状态。
* **焦点控制:**
    * **`focus`**: 将焦点设置到指定的 DOM 元素。
* **文件输入处理:**
    * **`setFileInputFiles`**:  模拟在 `<input type="file">` 元素中选择文件。
* **节点创建堆栈信息:**
    * **`setNodeStackTracesEnabled`**: 启用或禁用捕获节点创建时的堆栈信息。
    * **`getNodeStackTraces`**: 获取指定节点的创建堆栈信息。
* **布局信息查询:**
    * **`getBoxModel`**: 获取指定节点的盒模型信息（如 margin, border, padding, content）。
    * **`getContentQuads`**: 获取指定节点内容区域的四边形坐标。
* **位置到节点映射:**
    * **`getNodeForLocation`**: 根据屏幕坐标查找对应的 DOM 节点。
* **节点解析:**
    * **`resolveNode`**:  将节点 ID 或后端节点 ID 解析为可以在 JavaScript 中访问的远程对象。
* **属性获取:**
    * **`getAttributes`**: 获取指定元素的所有属性名和值。
* **节点请求:**
    * **`requestNode`**: 根据远程对象 ID 请求获取对应的节点 ID。
* **容器查询:**
    * **`getContainerForNode`**:  查找指定元素的符合特定条件的父级容器元素。
    * **`getQueryingDescendantsForContainer`**: 获取作为指定容器查询目标的后代元素。
* **元素关系查询:**
    * **`getElementByRelation`**:  根据元素间的特定关系（例如 `popovertarget`）获取相关元素。
    * **`getAnchorElement`**: 获取指定元素的锚点元素。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

* **JavaScript:** 这些功能主要通过开发者工具的 JavaScript API 暴露出来，供开发者在控制台中或通过扩展程序与页面 DOM 交互。
    * **例 1 (`setAttributeValue`)**:  在 JavaScript 控制台中，开发者可以使用类似 `await setAttributeValue({ elementId: 123, name: 'class', value: 'new-class' })` 的命令来修改元素的 class 属性。
    * **例 2 (`performSearch`)**: 开发者可以使用类似 `await DOM.performSearch({ query: '.my-element' })` 的命令来查找所有 class 为 `my-element` 的元素。
    * **例 3 (`resolveNode`)**: 当在 "Elements" 面板中选中一个元素时，开发者工具可能会使用 `resolveNode` 来获取该元素的远程对象，以便在 "Console" 中进行操作。

* **HTML:** 这些功能直接操作 HTML 结构。
    * **例 1 (`setOuterHTML`)**:  可以用来完全替换一个 HTML 元素及其子元素。假设有一个 `div` 元素的 ID 为 `myDiv`，调用 `setOuterHTML` 将其替换为 `<p>新的内容</p>`。
    * **例 2 (`removeNode`)**:  可以移除页面上的任何 HTML 节点。

* **CSS:**  部分功能与 CSS 有关，特别是布局和样式相关的操作。
    * **例 1 (`getBoxModel`)**: 开发者可以利用这个功能来查看元素的 CSS 盒模型，了解 margin、border、padding 等属性的值，这对于调试布局问题非常有用。
    * **例 2 (`getNodeForLocation`)**: 当开发者在 "Elements" 面板中点击 "Select an element in the page to inspect" 按钮后，移动鼠标时，开发者工具会使用这个功能来高亮鼠标悬停的元素，这依赖于 CSS 渲染的布局信息。
    * **例 3 (`getContainerForNode`, `getQueryingDescendantsForContainer`)**: 这些功能直接服务于 CSS 容器查询的调试和检查。

**逻辑推理的假设输入与输出示例:**

* **假设输入 (`performSearch`)**:  用户在开发者工具的 "Elements" 面板的搜索框中输入 `.my-class`。
* **输出 (`performSearch`)**:  `performSearch` 函数会遍历当前页面的 DOM 树，查找所有 class 属性包含 `my-class` 的元素，并将匹配的节点信息（通常是节点 ID）存储起来，并返回一个搜索 ID 和匹配数量。后续可以使用 `getSearchResults` 根据搜索 ID 获取具体的节点 ID 列表。

* **假设输入 (`getNodeForLocation`)**: 用户点击浏览器窗口的坐标 (100, 200)。
* **输出 (`getNodeForLocation`)**:  该函数会进行命中测试，确定该坐标下的最底层的 DOM 元素，并返回该元素的后端节点 ID、所属的 Frame ID 以及可能的节点 ID (如果 DOM 代理已启用)。

**用户或编程常见的使用错误举例说明:**

* **错误使用 `setAttributeValue`**:
    * **用户错误**:  尝试设置一个不存在的元素的属性，例如，提供的 `element_id` 在当前 DOM 树中找不到对应的元素。`AssertEditableElement` 会失败并返回错误响应。
    * **编程错误**:  传递了错误的属性名或属性值类型，虽然这通常不会导致 `setAttributeValue` 本身出错，但可能会导致页面渲染异常。

* **错误使用 `setOuterHTML`**:
    * **用户错误**: 提供的 `outer_html` 字符串不是有效的 HTML 片段，例如，标签没有正确闭合。这会导致解析错误，函数会返回错误响应。
    * **编程错误**: 尝试在不允许修改的节点上调用 `setOuterHTML`，例如，文档根节点的一些特殊子节点。

* **错误使用 `getSearchResults`**:
    * **用户错误**: 提供的 `from_index` 或 `to_index` 超出有效范围，或者 `from_index` 大于等于 `to_index`。函数会返回 "Invalid search result range" 的错误。
    * **编程错误**: 在调用 `performSearch` 之前就尝试调用 `getSearchResults`，此时找不到对应的 `search_id`，会导致 "No search session with given id found" 的错误。

总之，这个代码片段实现了开发者工具中用于检查和操作 DOM 结构的核心功能，它连接了前端开发者与网页的底层 DOM 表示，使得开发者能够进行实时的查看、修改和调试。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_dom_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共4部分，请归纳一下它的功能

"""
ode_to_push;
  while (Node* parent = InnerParentNode(node))
    node = parent;

  // Node being pushed is detached -> push subtree root.
  NodeToIdMap* new_map = MakeGarbageCollected<NodeToIdMap>();
  NodeToIdMap* dangling_map = new_map;
  dangling_node_to_id_maps_.push_back(new_map);
  auto children = std::make_unique<protocol::Array<protocol::DOM::Node>>();
  children->emplace_back(BuildObjectForNode(node, 0, false, dangling_map));
  GetFrontend()->setChildNodes(0, std::move(children));

  return PushNodePathToFrontend(node_to_push, dangling_map);
}

int InspectorDOMAgent::BoundNodeId(Node* node) const {
  auto it = document_node_to_id_map_->find(node);
  return it != document_node_to_id_map_->end() ? it->value : 0;
}

protocol::Response InspectorDOMAgent::setAttributeValue(int element_id,
                                                        const String& name,
                                                        const String& value) {
  Element* element = nullptr;
  protocol::Response response = AssertEditableElement(element_id, element);
  if (!response.IsSuccess())
    return response;
  return dom_editor_->SetAttribute(element, name, value);
}

protocol::Response InspectorDOMAgent::setAttributesAsText(int element_id,
                                                          const String& text,
                                                          Maybe<String> name) {
  Element* element = nullptr;
  protocol::Response response = AssertEditableElement(element_id, element);
  if (!response.IsSuccess())
    return response;

  bool is_html_document = IsA<HTMLDocument>(element->GetDocument());

  auto getContextElement = [](Element* element,
                              bool is_html_document) -> Element* {
    // Not all elements can represent the context (e.g. <iframe>). Use
    // the owner <svg> element if there is any, falling back to <body>,
    // falling back to nullptr (in the case of non-SVG XML documents).
    if (auto* svg_element = DynamicTo<SVGElement>(element)) {
      SVGSVGElement* owner = svg_element->ownerSVGElement();
      if (owner)
        return owner;
    }

    if (is_html_document)
      return element->GetDocument().body();

    return nullptr;
  };

  Element* contextElement = getContextElement(element, is_html_document);

  auto getParsedElement = [](Element* element, Element* contextElement,
                             const String& text, bool is_html_document) {
    String markup = element->IsSVGElement()
                        ? "<svg " + text + "></svg>"
                        : element->IsMathMLElement()
                              ? "<math " + text + "></math>"
                              : "<span " + text + "></span>";
    DocumentFragment* fragment =
        element->GetDocument().createDocumentFragment();
    if (is_html_document && contextElement)
      fragment->ParseHTML(markup, contextElement, kAllowScriptingContent);
    else
      fragment->ParseXML(markup, contextElement, IGNORE_EXCEPTION);
    return DynamicTo<Element>(fragment->firstChild());
  };

  Element* parsed_element =
      getParsedElement(element, contextElement, text, is_html_document);
  if (!parsed_element) {
    return protocol::Response::ServerError(
        "Could not parse value as attributes");
  }

  bool should_ignore_case = is_html_document && element->IsHTMLElement();
  String case_adjusted_name = should_ignore_case
                                  ? name.value_or("").DeprecatedLower()
                                  : name.value_or("");

  AttributeCollection attributes = parsed_element->Attributes();
  if (attributes.IsEmpty() && name.has_value()) {
    return dom_editor_->RemoveAttribute(element, case_adjusted_name);
  }

  bool found_original_attribute = false;
  for (auto& attribute : attributes) {
    // Add attribute pair
    String attribute_name = attribute.GetName().ToString();
    if (should_ignore_case)
      attribute_name = attribute_name.DeprecatedLower();
    found_original_attribute |=
        name.has_value() && attribute_name == case_adjusted_name;
    response =
        dom_editor_->SetAttribute(element, attribute_name, attribute.Value());
    if (!response.IsSuccess())
      return response;
  }

  if (!found_original_attribute && name.has_value() &&
      name.value().LengthWithStrippedWhiteSpace() > 0) {
    return dom_editor_->RemoveAttribute(element, case_adjusted_name);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::removeAttribute(int element_id,
                                                      const String& name) {
  Element* element = nullptr;
  protocol::Response response = AssertEditableElement(element_id, element);
  if (!response.IsSuccess())
    return response;

  return dom_editor_->RemoveAttribute(element, name);
}

protocol::Response InspectorDOMAgent::removeNode(int node_id) {
  Node* node = nullptr;
  protocol::Response response = AssertEditableNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  ContainerNode* parent_node = node->parentNode();
  if (!parent_node)
    return protocol::Response::ServerError("Cannot remove detached node");

  return dom_editor_->RemoveChild(parent_node, node);
}

protocol::Response InspectorDOMAgent::setNodeName(int node_id,
                                                  const String& tag_name,
                                                  int* new_id) {
  *new_id = 0;

  Element* old_element = nullptr;
  protocol::Response response = AssertElement(node_id, old_element);
  if (!response.IsSuccess())
    return response;

  DummyExceptionStateForTesting exception_state;
  Element* new_elem = old_element->GetDocument().CreateElementForBinding(
      AtomicString(tag_name), exception_state);
  if (exception_state.HadException())
    return ToResponse(exception_state);

  // Copy over the original node's attributes.
  new_elem->CloneAttributesFrom(*old_element);

  // Copy over the original node's children.
  for (Node* child = old_element->firstChild(); child;
       child = old_element->firstChild()) {
    response = dom_editor_->InsertBefore(new_elem, child, nullptr);
    if (!response.IsSuccess())
      return response;
  }

  // Replace the old node with the new node
  ContainerNode* parent = old_element->parentNode();
  response =
      dom_editor_->InsertBefore(parent, new_elem, old_element->nextSibling());
  if (!response.IsSuccess())
    return response;
  response = dom_editor_->RemoveChild(parent, old_element);
  if (!response.IsSuccess())
    return response;

  *new_id = PushNodePathToFrontend(new_elem);
  if (children_requested_.Contains(node_id))
    PushChildNodesToFrontend(*new_id);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getOuterHTML(Maybe<int> node_id,
                                                   Maybe<int> backend_node_id,
                                                   Maybe<String> object_id,
                                                   WTF::String* outer_html) {
  Node* node = nullptr;
  protocol::Response response =
      AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess())
    return response;

  *outer_html = CreateMarkup(node);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::setOuterHTML(int node_id,
                                                   const String& outer_html) {
  if (!node_id) {
    DCHECK(document_);
    DOMPatchSupport dom_patch_support(dom_editor_.Get(), *document_.Get());
    dom_patch_support.PatchDocument(outer_html);
    return protocol::Response::Success();
  }

  Node* node = nullptr;
  protocol::Response response = AssertEditableNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  Document* document = DynamicTo<Document>(node);
  if (!document) {
    document = node->ownerDocument();
  }
  if (!document ||
      (!IsA<HTMLDocument>(document) && !IsA<XMLDocument>(document)))
    return protocol::Response::ServerError("Not an HTML/XML document");

  Node* new_node = nullptr;
  response = dom_editor_->SetOuterHTML(node, outer_html, &new_node);
  if (!response.IsSuccess())
    return response;

  if (!new_node) {
    // The only child node has been deleted.
    return protocol::Response::Success();
  }

  int new_id = PushNodePathToFrontend(new_node);

  bool children_requested = children_requested_.Contains(node_id);
  if (children_requested)
    PushChildNodesToFrontend(new_id);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::setNodeValue(int node_id,
                                                   const String& value) {
  Node* node = nullptr;
  protocol::Response response = AssertEditableNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  if (node->getNodeType() != Node::kTextNode)
    return protocol::Response::ServerError("Can only set value of text nodes");

  return dom_editor_->SetNodeValue(node, value);
}

static Node* NextNodeWithShadowDOMInMind(const Node& current,
                                         const Node* stay_within,
                                         bool include_user_agent_shadow_dom) {
  // At first traverse the subtree.

  if (ShadowRoot* shadow_root = current.GetShadowRoot()) {
    if (!shadow_root->IsUserAgent() || include_user_agent_shadow_dom)
      return shadow_root;
  }
  if (current.hasChildren())
    return current.firstChild();

  // Then traverse siblings of the node itself and its ancestors.
  const Node* node = &current;
  do {
    if (node == stay_within)
      return nullptr;
    auto* shadow_root = DynamicTo<ShadowRoot>(node);
    if (shadow_root) {
      Element& host = shadow_root->host();
      if (host.HasChildren())
        return host.firstChild();
    }
    if (node->nextSibling())
      return node->nextSibling();
    node = shadow_root ? &shadow_root->host() : node->parentNode();
  } while (node);

  return nullptr;
}

protocol::Response InspectorDOMAgent::performSearch(
    const String& whitespace_trimmed_query,
    Maybe<bool> optional_include_user_agent_shadow_dom,
    String* search_id,
    int* result_count) {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent is not enabled");

  // FIXME: Few things are missing here:
  // 1) Search works with node granularity - number of matches within node is
  //    not calculated.
  // 2) There is no need to push all search results to the front-end at a time,
  //    pushing next / previous result is sufficient.

  bool include_user_agent_shadow_dom =
      optional_include_user_agent_shadow_dom.value_or(false);

  unsigned query_length = whitespace_trimmed_query.length();
  bool start_tag_found = !whitespace_trimmed_query.find('<');
  bool start_closing_tag_found = !whitespace_trimmed_query.Find("</");
  bool end_tag_found =
      whitespace_trimmed_query.ReverseFind('>') + 1 == query_length;
  bool start_quote_found = !whitespace_trimmed_query.find('"');
  bool end_quote_found =
      whitespace_trimmed_query.ReverseFind('"') + 1 == query_length;
  bool exact_attribute_match = start_quote_found && end_quote_found;

  String tag_name_query = whitespace_trimmed_query;
  String attribute_query = whitespace_trimmed_query;
  if (start_closing_tag_found)
    tag_name_query = tag_name_query.Right(tag_name_query.length() - 2);
  else if (start_tag_found)
    tag_name_query = tag_name_query.Right(tag_name_query.length() - 1);
  if (end_tag_found)
    tag_name_query = tag_name_query.Left(tag_name_query.length() - 1);
  if (start_quote_found)
    attribute_query = attribute_query.Right(attribute_query.length() - 1);
  if (end_quote_found)
    attribute_query = attribute_query.Left(attribute_query.length() - 1);

  HeapVector<Member<Document>> docs = Documents();
  HeapLinkedHashSet<Member<Node>> result_collector;

  // Selector evaluation
  for (Document* document : docs) {
    DummyExceptionStateForTesting exception_state;
    StaticElementList* element_list = document->QuerySelectorAll(
        AtomicString(whitespace_trimmed_query), exception_state);
    if (exception_state.HadException() || !element_list) {
      continue;
    }

    unsigned size = element_list->length();
    for (unsigned i = 0; i < size; ++i) {
      result_collector.insert(element_list->item(i));
    }
  }

  for (Document* document : docs) {
    Node* document_element = document->documentElement();
    Node* node = document_element;
    if (!node)
      continue;

    // Manual plain text search.
    for (; node; node = NextNodeWithShadowDOMInMind(
                     *node, document_element, include_user_agent_shadow_dom)) {
      switch (node->getNodeType()) {
        case Node::kTextNode:
        case Node::kCommentNode:
        case Node::kCdataSectionNode: {
          String text = node->nodeValue();
          if (text.FindIgnoringCase(whitespace_trimmed_query) != kNotFound)
            result_collector.insert(node);
          break;
        }
        case Node::kElementNode: {
          if ((!start_tag_found && !end_tag_found &&
               (node->nodeName().FindIgnoringCase(tag_name_query) !=
                kNotFound)) ||
              (start_tag_found && end_tag_found &&
               DeprecatedEqualIgnoringCase(node->nodeName(), tag_name_query)) ||
              (start_tag_found && !end_tag_found &&
               node->nodeName().StartsWithIgnoringCase(tag_name_query)) ||
              (!start_tag_found && end_tag_found &&
               node->nodeName().EndsWithIgnoringCase(tag_name_query))) {
            result_collector.insert(node);
            break;
          }
          // Go through all attributes and serialize them.
          const auto* element = To<Element>(node);
          AttributeCollection attributes = element->Attributes();
          for (auto& attribute : attributes) {
            // Add attribute pair
            if (attribute.LocalName().FindIgnoringCase(whitespace_trimmed_query,
                                                       0) != kNotFound) {
              result_collector.insert(node);
              break;
            }
            size_t found_position =
                attribute.Value().FindIgnoringCase(attribute_query, 0);
            if (found_position != kNotFound) {
              if (!exact_attribute_match ||
                  (!found_position &&
                   attribute.Value().length() == attribute_query.length())) {
                result_collector.insert(node);
                break;
              }
            }
          }
          break;
        }
        default:
          break;
      }
    }
  }

  // XPath evaluation
  for (Document* document : docs) {
    DCHECK(document);
    DummyExceptionStateForTesting exception_state;
    XPathResult* result = DocumentXPathEvaluator::evaluate(
        *document, whitespace_trimmed_query, document, nullptr,
        XPathResult::kOrderedNodeSnapshotType, ScriptValue(), exception_state);
    if (exception_state.HadException() || !result)
      continue;

    wtf_size_t size = result->snapshotLength(exception_state);
    for (wtf_size_t i = 0; !exception_state.HadException() && i < size; ++i) {
      Node* node = result->snapshotItem(i, exception_state);
      if (exception_state.HadException())
        break;

      if (node->getNodeType() == Node::kAttributeNode)
        node = To<Attr>(node)->ownerElement();
      result_collector.insert(node);
    }
  }

  *search_id = IdentifiersFactory::CreateIdentifier();
  HeapVector<Member<Node>>* results_it =
      search_results_
          .insert(*search_id, MakeGarbageCollected<HeapVector<Member<Node>>>())
          .stored_value->value;

  for (auto& result : result_collector)
    results_it->push_back(result);

  *result_count = results_it->size();
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getSearchResults(
    const String& search_id,
    int from_index,
    int to_index,
    std::unique_ptr<protocol::Array<int>>* node_ids) {
  SearchResults::iterator it = search_results_.find(search_id);
  if (it == search_results_.end()) {
    return protocol::Response::ServerError(
        "No search session with given id found");
  }

  int size = it->value->size();
  if (from_index < 0 || to_index > size || from_index >= to_index)
    return protocol::Response::ServerError("Invalid search result range");

  *node_ids = std::make_unique<protocol::Array<int>>();
  for (int i = from_index; i < to_index; ++i)
    (*node_ids)->emplace_back(PushNodePathToFrontend((*it->value)[i].Get()));
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::discardSearchResults(
    const String& search_id) {
  search_results_.erase(search_id);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::NodeForRemoteObjectId(
    const String& object_id,
    Node*& node) {
  v8::HandleScope handles(isolate_);
  v8::Local<v8::Value> value;
  v8::Local<v8::Context> context;
  std::unique_ptr<v8_inspector::StringBuffer> error;
  if (!v8_session_->unwrapObject(&error, ToV8InspectorStringView(object_id),
                                 &value, &context, nullptr)) {
    return protocol::Response::ServerError(
        ToCoreString(std::move(error)).Utf8());
  }
  node = V8Node::ToWrappable(isolate_, value);
  if (!node) {
    return protocol::Response::ServerError(
        "Object id doesn't reference a Node");
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::copyTo(int node_id,
                                             int target_element_id,
                                             Maybe<int> anchor_node_id,
                                             int* new_node_id) {
  Node* node = nullptr;
  protocol::Response response = AssertEditableNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  Element* target_element = nullptr;
  response = AssertEditableElement(target_element_id, target_element);
  if (!response.IsSuccess())
    return response;

  Node* anchor_node = nullptr;
  if (anchor_node_id.has_value() && anchor_node_id.value()) {
    response = AssertEditableChildNode(target_element, anchor_node_id.value(),
                                       anchor_node);
    if (!response.IsSuccess())
      return response;
  }

  // The clone is deep by default.
  Node* cloned_node = node->cloneNode(true);
  if (!cloned_node)
    return protocol::Response::ServerError("Failed to clone node");
  response =
      dom_editor_->InsertBefore(target_element, cloned_node, anchor_node);
  if (!response.IsSuccess())
    return response;

  *new_node_id = PushNodePathToFrontend(cloned_node);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::moveTo(int node_id,
                                             int target_element_id,
                                             Maybe<int> anchor_node_id,
                                             int* new_node_id) {
  Node* node = nullptr;
  protocol::Response response = AssertEditableNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  Element* target_element = nullptr;
  response = AssertEditableElement(target_element_id, target_element);
  if (!response.IsSuccess())
    return response;

  Node* current = target_element;
  while (current) {
    if (current == node) {
      return protocol::Response::ServerError(
          "Unable to move node into self or descendant");
    }
    current = current->parentNode();
  }

  Node* anchor_node = nullptr;
  if (anchor_node_id.has_value() && anchor_node_id.value()) {
    response = AssertEditableChildNode(target_element, anchor_node_id.value(),
                                       anchor_node);
    if (!response.IsSuccess())
      return response;
  }

  response = dom_editor_->InsertBefore(target_element, node, anchor_node);
  if (!response.IsSuccess())
    return response;

  *new_node_id = PushNodePathToFrontend(node);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::undo() {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent is not enabled");
  DummyExceptionStateForTesting exception_state;
  history_->Undo(exception_state);
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorDOMAgent::redo() {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent is not enabled");
  DummyExceptionStateForTesting exception_state;
  history_->Redo(exception_state);
  return InspectorDOMAgent::ToResponse(exception_state);
}

protocol::Response InspectorDOMAgent::markUndoableState() {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent is not enabled");
  history_->MarkUndoableState();
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::focus(Maybe<int> node_id,
                                            Maybe<int> backend_node_id,
                                            Maybe<String> object_id) {
  Node* node = nullptr;
  protocol::Response response =
      AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess())
    return response;
  auto* element = DynamicTo<Element>(node);
  if (!element)
    return protocol::Response::ServerError("Node is not an Element");
  element->GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kInspector);
  if (!element->IsFocusable())
    return protocol::Response::ServerError("Element is not focusable");
  element->Focus(FocusParams(FocusTrigger::kUserGesture));
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::setFileInputFiles(
    std::unique_ptr<protocol::Array<String>> files,
    Maybe<int> node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id) {
  Node* node = nullptr;
  protocol::Response response =
      AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess())
    return response;

  auto* html_input_element = DynamicTo<HTMLInputElement>(node);
  if (!html_input_element ||
      html_input_element->FormControlType() != FormControlType::kInputFile) {
    return protocol::Response::ServerError("Node is not a file input element");
  }

  Vector<String> paths;
  for (const String& file : *files)
    paths.push_back(file);
  To<HTMLInputElement>(node)->SetFilesFromPaths(paths);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::setNodeStackTracesEnabled(bool enable) {
  capture_node_stack_traces_.Set(enable);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getNodeStackTraces(
    int node_id,
    protocol::Maybe<v8_inspector::protocol::Runtime::API::StackTrace>*
        creation) {
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;

  auto it = node_to_creation_source_location_map_.find(node);
  if (it != node_to_creation_source_location_map_.end()) {
    SourceLocation& source_location = it->value->GetSourceLocation();
    *creation = source_location.BuildInspectorObject();
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getBoxModel(
    Maybe<int> node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id,
    std::unique_ptr<protocol::DOM::BoxModel>* model) {
  Node* node = nullptr;
  protocol::Response response =
      AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess())
    return response;

  bool result = InspectorHighlight::GetBoxModel(node, model, true);
  if (!result)
    return protocol::Response::ServerError("Could not compute box model.");
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getContentQuads(
    Maybe<int> node_id,
    Maybe<int> backend_node_id,
    Maybe<String> object_id,
    std::unique_ptr<protocol::Array<protocol::Array<double>>>* quads) {
  Node* node = nullptr;
  protocol::Response response =
      AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess())
    return response;
  bool result = InspectorHighlight::GetContentQuads(node, quads);
  if (!result)
    return protocol::Response::ServerError("Could not compute content quads.");
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getNodeForLocation(
    int x,
    int y,
    Maybe<bool> optional_include_user_agent_shadow_dom,
    Maybe<bool> optional_ignore_pointer_events_none,
    int* backend_node_id,
    String* frame_id,
    Maybe<int>* node_id) {
  bool include_user_agent_shadow_dom =
      optional_include_user_agent_shadow_dom.value_or(false);
  Document* document = inspected_frames_->Root()->GetDocument();
  PhysicalOffset document_point(
      LayoutUnit(x * inspected_frames_->Root()->LayoutZoomFactor()),
      LayoutUnit(y * inspected_frames_->Root()->LayoutZoomFactor()));
  HitTestRequest::HitTestRequestType hit_type =
      HitTestRequest::kMove | HitTestRequest::kReadOnly |
      HitTestRequest::kAllowChildFrameContent;
  if (optional_ignore_pointer_events_none.value_or(false)) {
    hit_type |= HitTestRequest::kIgnorePointerEventsNone;
  }
  HitTestRequest request(hit_type);
  HitTestLocation location(document->View()->DocumentToFrame(document_point));
  HitTestResult result(request, location);
  document->GetFrame()->ContentLayoutObject()->HitTest(location, result);
  if (!include_user_agent_shadow_dom)
    result.SetToShadowHostIfInUAShadowRoot();
  Node* node = result.InnerPossiblyPseudoNode();
  while (node && node->getNodeType() == Node::kTextNode)
    node = node->parentNode();
  if (!node)
    return protocol::Response::ServerError("No node found at given location");
  *backend_node_id = IdentifiersFactory::IntIdForNode(node);
  LocalFrame* frame = node->GetDocument().GetFrame();
  *frame_id = IdentifiersFactory::FrameId(frame);
  if (enabled_.Get() && document_ &&
      document_node_to_id_map_->Contains(document_)) {
    *node_id = PushNodePathToFrontend(node);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::resolveNode(
    protocol::Maybe<int> node_id,
    protocol::Maybe<int> backend_node_id,
    protocol::Maybe<String> object_group,
    protocol::Maybe<int> execution_context_id,
    std::unique_ptr<v8_inspector::protocol::Runtime::API::RemoteObject>*
        result) {
  String object_group_name = object_group.value_or("");
  Node* node = nullptr;

  if (node_id.has_value() == backend_node_id.has_value()) {
    return protocol::Response::ServerError(
        "Either nodeId or backendNodeId must be specified.");
  }

  if (node_id.has_value()) {
    node = NodeForId(node_id.value());
  } else {
    node = DOMNodeIds::NodeForId(backend_node_id.value());
  }

  if (!node)
    return protocol::Response::ServerError("No node with given id found");
  *result = ResolveNode(v8_session_, node, object_group_name,
                        std::move(execution_context_id));
  if (!*result) {
    return protocol::Response::ServerError(
        "Node with given id does not belong to the document");
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getAttributes(
    int node_id,
    std::unique_ptr<protocol::Array<String>>* result) {
  Element* element = nullptr;
  protocol::Response response = AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  *result = BuildArrayForElementAttributes(element);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::requestNode(const String& object_id,
                                                  int* node_id) {
  Node* node = nullptr;
  protocol::Response response = NodeForRemoteObjectId(object_id, node);
  if (!response.IsSuccess())
    return response;
  *node_id = PushNodePathToFrontend(node);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getContainerForNode(
    int node_id,
    protocol::Maybe<String> container_name,
    protocol::Maybe<protocol::DOM::PhysicalAxes> physical_axes,
    protocol::Maybe<protocol::DOM::LogicalAxes> logical_axes,
    protocol::Maybe<bool> queries_scroll_state,
    Maybe<int>* container_node_id) {
  Element* element = nullptr;
  protocol::Response response = AssertElement(node_id, element);
  if (!response.IsSuccess())
    return response;

  PhysicalAxes physical = kPhysicalAxesNone;
  LogicalAxes logical = kLogicalAxesNone;

  if (physical_axes.has_value()) {
    if (physical_axes.value() == protocol::DOM::PhysicalAxesEnum::Horizontal) {
      physical = kPhysicalAxesHorizontal;
    } else if (physical_axes.value() ==
               protocol::DOM::PhysicalAxesEnum::Vertical) {
      physical = kPhysicalAxesVertical;
    } else if (physical_axes.value() == protocol::DOM::PhysicalAxesEnum::Both) {
      physical = kPhysicalAxesBoth;
    }
  }
  if (logical_axes.has_value()) {
    if (logical_axes.value() == protocol::DOM::LogicalAxesEnum::Inline) {
      logical = kLogicalAxesInline;
    } else if (logical_axes.value() == protocol::DOM::LogicalAxesEnum::Block) {
      logical = kLogicalAxesBlock;
    } else if (logical_axes.value() == protocol::DOM::LogicalAxesEnum::Both) {
      logical = kLogicalAxesBoth;
    }
  }

  element->GetDocument().UpdateStyleAndLayoutTreeForElement(
      element, DocumentUpdateReason::kInspector);
  StyleResolver& style_resolver = element->GetDocument().GetStyleResolver();
  // Container rule origin no longer known at this point, match name from all
  // scopes.
  Element* container = style_resolver.FindContainerForElement(
      element,
      ContainerSelector(AtomicString(container_name.value_or(g_null_atom)),
                        physical, logical,
                        queries_scroll_state.value_or(false)),
      nullptr /* selector_tree_scope */);
  if (container)
    *container_node_id = PushNodePathToFrontend(container);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getQueryingDescendantsForContainer(
    int node_id,
    std::unique_ptr<protocol::Array<int>>* node_ids) {
  Element* container = nullptr;
  protocol::Response response = AssertElement(node_id, container);
  if (!response.IsSuccess())
    return response;

  *node_ids = std::make_unique<protocol::Array<int>>();
  NodeToIdMap* nodes_map = document_node_to_id_map_.Get();
  for (Element* descendant : GetContainerQueryingDescendants(container)) {
    int id = PushNodePathToFrontend(descendant, nodes_map);
    (*node_ids)->push_back(id);
  }

  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getElementByRelation(
    int node_id,
    const String& relation,
    int* related_element_id) {
  *related_element_id = 0;
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess()) {
    return response;
  }

  Element* element = nullptr;
  if (relation == protocol::DOM::GetElementByRelation::RelationEnum::PopoverTarget) {
      if (auto* invoker = DynamicTo<HTMLFormControlElement>(node)) {
        element = invoker->popoverTargetElement().popover;
      }
  }

  if (element) {
    *related_element_id = PushNodePathToFrontend(element);
  }
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getAnchorElement(
    int node_id,
    protocol::Maybe<String> anchor_specifier,
    int* anchor_element_id) {
  *anchor_element_id = 0;
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess()) {
    return response;
  }

  const LayoutObject* querying_object = node->GetLayoutObject();
  if (!querying_object) {
    return protocol::Response::ServerError(
        "No layout object for node, perhaps orphan or hidden node");
  }

  const auto* box = DynamicTo<LayoutBox>(querying_object);
  if (!box || !box->Container()) {
    return protocol::Response::ServerError(
        "The box or the container of the box does not exist");
  }

  const LayoutObject* target_object;
  if (anchor_specifier.has_value()) {
    target_object = box->FindTargetAnchor(*MakeGarbageCollected<ScopedCSSName>(
        AtomicString(anchor_specifier.value()),
        &querying_object->GetDocument()));
  } else {
    const ComputedStyle& style = box->StyleRef();
    target_object = style.PositionAnchor()
                        ? box->FindTargetAnchor(*style.PositionAnchor())
                        : box->AcceptableImplicitAnchor();
  }

  if (target_object) {
    Element* element = DynamicTo<Element>(target_object->GetNode());
    if (element) {
      *anchor_element_id = PushNodePathToFrontend(element);
    }
  }
  return protocol::Response::Succes
"""


```