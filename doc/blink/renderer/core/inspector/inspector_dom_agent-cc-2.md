Response:
The user wants a summary of the functionality of the provided C++ code snippet from `inspector_dom_agent.cc`. The summary should include:

1. **Core Functionality:** What the code does.
2. **Relation to Web Technologies:** How it interacts with JavaScript, HTML, and CSS, with examples.
3. **Logical Reasoning:**  Examples of how the code might infer or deduce information, with input and output.
4. **Common Errors:**  Illustrate typical mistakes users or programmers could make when interacting with this functionality.
5. **Overall Summary:** A concise recap of the agent's purpose.

**Plan:**

1. **Analyze the code:** Read through the methods and their logic to understand the core responsibilities. Focus on methods related to node manipulation, attribute handling, shadow DOM, and container queries.
2. **Identify web technology connections:**  Look for points where the code interacts with DOM elements, attributes, styles (computed styles), and shadow roots.
3. **Infer logical reasoning:** Consider scenarios where the code makes decisions based on the current state of the DOM or CSS rules.
4. **Brainstorm potential errors:**  Think about common mistakes when dealing with DOM manipulation or inspector tools.
5. **Structure the response:** Organize the findings into the requested categories (functionality, web tech relation, logic, errors, summary).
这是 `blink/renderer/core/inspector/inspector_dom_agent.cc` 文件的第三部分，其主要功能是构建和管理 DOM 树的表示，以便在开发者工具的前端进行检查和交互。它负责将 Blink 引擎内部的 DOM 结构转换为开发者工具可以理解的协议格式。

**主要功能归纳：**

* **构建 DOM 节点对象：** `BuildObjectForNode` 方法是核心，它递归地将 Blink 内部的 `Node` 对象（例如 `Element`, `Text`, `Comment` 等）转换为 `protocol::DOM::Node` 对象，这是开发者工具前端所使用的表示形式。
* **处理子节点和属性：**  `BuildArrayForContainerChildren` 和 `BuildArrayForElementAttributes` 方法分别负责构建节点的子节点数组和属性数组。
* **处理 Shadow DOM：** 代码包含处理 Shadow Root 的逻辑，例如 `GetShadowRootType` 用于获取 Shadow Root 的类型，并且 `BuildObjectForNode` 会递归处理 Shadow Root 中的节点。
* **处理伪元素和 Slot：**  `BuildArrayForPseudoElements` 和 `BuildDistributedNodesForSlot` 方法分别用于构建伪元素数组和 Slot 分发的节点数组。
* **与样式相关的信息：**  尽管这部分代码不是直接操作样式，但它会获取和传递与样式相关的一些信息，例如是否是 SVG 元素，以及关联的 Frame ID。
* **处理 Frame：** 代码会识别和处理 Frame 元素及其关联的文档，并将其包含在构建的 DOM 树中。
* **辅助方法：** 提供了一系列静态辅助方法，用于获取文档的 URL、Base URL、兼容性模式，以及判断节点是否应该被跳过（例如空白文本节点）。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

1. **HTML:**
   * **功能体现:**  该代码负责解析和表示 HTML 结构，将 HTML 标签、属性和文本内容转换为开发者工具前端可以理解的对象。
   * **举例说明:** 当 HTML 中存在一个 `<div>` 元素时，`BuildObjectForNode` 会创建一个 `protocol::DOM::Node` 对象，其 `nodeType` 为 1 (Element 节点)，`nodeName` 为 "div"，`localName` 也为 "div"。如果 `<div>` 有属性 `id="container"`，`BuildArrayForElementAttributes` 会创建一个包含 "id" 和 "container" 的字符串数组。

2. **CSS:**
   * **功能体现:** 虽然这部分代码不直接解析 CSS 规则，但它会检查和利用 CSS 的一些特性，例如 Container Queries 和伪元素。
   * **Container Queries 举例说明:** `GetContainerQueryingDescendants` 和 `ContainerQueriedByElement` 方法用于查找受特定容器查询影响的元素。
     * **假设输入:** 一个 `<div>` 元素 `container` 设置了 `container-name: my-container;` 和 `container-type: inline-size;`。另一个 `<div>` 元素 `element` 的 CSS 规则中包含 `@container my-container (min-width: 300px) { ... }`。
     * **逻辑推理:** `ContainerQueriedByElement(container, element)` 会遍历 `element` 的 CSS 规则，找到 `CSSContainerRule`，然后检查 `container` 是否与该规则匹配。
     * **输出:** 如果 `container` 的尺寸满足条件，`ContainerQueriedByElement` 返回 `true`。
   * **伪元素举例说明:** 当遇到一个包含伪元素（如 `::before` 或 `::after`）的元素时，`BuildArrayForPseudoElements` 会为这些伪元素创建 `protocol::DOM::Node` 对象，并设置 `pseudoType` 属性为相应的类型。

3. **JavaScript:**
   * **功能体现:**  开发者工具前端使用此代码构建的 DOM 树，JavaScript 可以通过开发者工具进行交互，例如查询节点、修改属性等。
   * **举例说明:**  当 JavaScript 代码通过 `document.getElementById('myElement')` 获取一个元素时，开发者工具可以通过这个代码生成的 DOM 树来显示该元素的详细信息，包括其属性、子节点等。 此外，当 JavaScript 操作 DOM (例如创建新节点、修改属性) 时，相关的事件会触发 `InspectorDOMAgent` 的方法，进而更新开发者工具前端的 DOM 树表示。

**逻辑推理举例说明：**

* **假设输入:** 一个 `Node` 对象 `node`。
* **逻辑推理:** `BuildObjectForNode` 方法会根据 `node->getNodeType()` 的值来确定节点的类型（例如 `kTextNode`, `kElementNode`），并设置 `protocol::DOM::Node` 对象的 `nodeType` 属性。如果节点是文本节点，并且文本内容超过了 `kMaxTextSize`，则会进行截断并添加省略号。
* **输出:** 一个 `protocol::DOM::Node` 对象，其 `nodeType` 属性对应于 `node` 的实际类型，`nodeValue` 属性包含节点的文本内容（可能被截断）。

**涉及用户或者编程常见的使用错误举例说明：**

* **忘记启用 DOM 代理:** 如果开发者工具的 DOM 面板没有启用，则 `InspectorDOMAgent` 不会工作，前端无法获取最新的 DOM 结构。 这会导致开发者在前端进行 DOM 操作时，看到的结果与实际页面不符。
* **在未加载完成的文档上操作:**  在文档加载完成之前，尝试通过开发者工具对 DOM 进行修改或查询，可能会导致不可预测的结果，因为 DOM 结构可能尚未完全构建。
* **依赖于节点 ID 的持久性:**  开发者工具生成的节点 ID 仅在当前检查会话中有效。如果重新加载页面或刷新开发者工具，节点 ID 会改变。因此，不应该在持久化的逻辑中硬编码或依赖这些 ID。
* **误解 Shadow DOM 的边界:**  在操作包含 Shadow DOM 的元素时，可能会错误地认为可以直接访问 Shadow Root 内部的节点。需要理解 Shadow DOM 的封装性，并使用正确的 API（例如 `querySelector` 在 Shadow Root 上调用）才能访问内部节点。

**总结一下它的功能:**

这部分 `InspectorDOMAgent` 的代码主要负责将 Blink 引擎内部的 DOM 结构转换为开发者工具前端可以理解和展示的格式。它通过遍历 DOM 树，提取节点信息、属性、子节点、Shadow DOM 内容等，并将这些信息构建成符合 Chrome DevTools Protocol 规范的对象，从而使得开发者可以通过浏览器内置的开发者工具来检查和调试网页的 DOM 结构。

Prompt: 
```
这是目录为blink/renderer/core/inspector/inspector_dom_agent.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
s();
}

// static
const HeapVector<Member<Element>>
InspectorDOMAgent::GetContainerQueryingDescendants(Element* container) {
  // This won't work for edge cases with display locking
  // (https://crbug.com/1235306).
  container->GetDocument().UpdateStyleAndLayoutTreeForSubtree(
      container, DocumentUpdateReason::kInspector);

  HeapVector<Member<Element>> querying_descendants;
  for (Element& element : ElementTraversal::DescendantsOf(*container)) {
    if (ContainerQueriedByElement(container, &element))
      querying_descendants.push_back(element);
  }

  return querying_descendants;
}

// static
bool InspectorDOMAgent::ContainerQueriedByElement(Element* container,
                                                  Element* element) {
  const ComputedStyle* style = element->GetComputedStyle();
  if (!style || !style->DependsOnContainerQueries()) {
    return false;
  }

  StyleResolver& style_resolver = element->GetDocument().GetStyleResolver();
  RuleIndexList* matched_rules =
      style_resolver.CssRulesForElement(element, StyleResolver::kAllCSSRules);
  if (!matched_rules) {
    return false;
  }
  for (auto it = matched_rules->rbegin(); it != matched_rules->rend(); ++it) {
    CSSRule* parent_rule = it->first;
    while (parent_rule) {
      auto* container_rule = DynamicTo<CSSContainerRule>(parent_rule);
      if (container_rule) {
        // Container rule origin no longer known at this point, match name from
        // all scopes.
        if (container == style_resolver.FindContainerForElement(
                             element, container_rule->Selector(),
                             nullptr /* selector_tree_scope */)) {
          return true;
        }
      }

      parent_rule = parent_rule->parentRule();
    }
  }

  return false;
}

// static
String InspectorDOMAgent::DocumentURLString(Document* document) {
  if (!document || document->Url().IsNull())
    return "";
  return document->Url().GetString();
}

// static
String InspectorDOMAgent::DocumentBaseURLString(Document* document) {
  return document->BaseURL().GetString();
}

// static
protocol::DOM::ShadowRootType InspectorDOMAgent::GetShadowRootType(
    ShadowRoot* shadow_root) {
  switch (shadow_root->GetMode()) {
    case ShadowRootMode::kUserAgent:
      return protocol::DOM::ShadowRootTypeEnum::UserAgent;
    case ShadowRootMode::kOpen:
      return protocol::DOM::ShadowRootTypeEnum::Open;
    case ShadowRootMode::kClosed:
      return protocol::DOM::ShadowRootTypeEnum::Closed;
  }
  NOTREACHED();
}

// static
protocol::DOM::CompatibilityMode
InspectorDOMAgent::GetDocumentCompatibilityMode(Document* document) {
  switch (document->GetCompatibilityMode()) {
    case Document::CompatibilityMode::kQuirksMode:
      return protocol::DOM::CompatibilityModeEnum::QuirksMode;
    case Document::CompatibilityMode::kLimitedQuirksMode:
      return protocol::DOM::CompatibilityModeEnum::LimitedQuirksMode;
    case Document::CompatibilityMode::kNoQuirksMode:
      return protocol::DOM::CompatibilityModeEnum::NoQuirksMode;
  }
  NOTREACHED();
}

std::unique_ptr<protocol::DOM::Node> InspectorDOMAgent::BuildObjectForNode(
    Node* node,
    int depth,
    bool pierce,
    NodeToIdMap* nodes_map,
    protocol::Array<protocol::DOM::Node>* flatten_result) {
  // If no `nodes_map` is provided, do the best effort to provide a node id,
  // but do not create one if it's not there, since absence of the map implies
  // we're not pushing the node to the front-end at the moment.
  const int id = nodes_map ? Bind(node, nodes_map) : BoundNodeId(node);
  String local_name;
  String node_value;

  switch (node->getNodeType()) {
    case Node::kTextNode:
    case Node::kCommentNode:
    case Node::kCdataSectionNode:
      node_value = node->nodeValue();
      if (node_value.length() > kMaxTextSize)
        node_value = node_value.Left(kMaxTextSize) + kEllipsisUChar;
      break;
    case Node::kAttributeNode:
      local_name = To<Attr>(node)->localName();
      break;
    case Node::kElementNode:
      local_name = To<Element>(node)->localName();
      break;
    default:
      break;
  }

  std::unique_ptr<protocol::DOM::Node> value =
      protocol::DOM::Node::create()
          .setNodeId(id)
          .setBackendNodeId(IdentifiersFactory::IntIdForNode(node))
          .setNodeType(static_cast<int>(node->getNodeType()))
          .setNodeName(node->nodeName())
          .setLocalName(local_name)
          .setNodeValue(node_value)
          .build();

  if (node->IsSVGElement())
    value->setIsSVG(true);

  bool force_push_children = false;
  if (auto* element = DynamicTo<Element>(node)) {
    value->setAttributes(BuildArrayForElementAttributes(element));

    if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
      if (frame_owner->ContentFrame()) {
        value->setFrameId(
            IdentifiersFactory::FrameId(frame_owner->ContentFrame()));
      }
      if (Document* doc = frame_owner->contentDocument()) {
        value->setContentDocument(BuildObjectForNode(
            doc, pierce ? depth : 0, pierce, nodes_map, flatten_result));
      }
    }

    if (node->parentNode() && node->parentNode()->IsDocumentNode()) {
      LocalFrame* frame = node->GetDocument().GetFrame();
      if (frame)
        value->setFrameId(IdentifiersFactory::FrameId(frame));
    }

    if (ShadowRoot* root = element->GetShadowRoot()) {
      auto shadow_roots =
          std::make_unique<protocol::Array<protocol::DOM::Node>>();
      shadow_roots->emplace_back(BuildObjectForNode(
          root, pierce ? depth : 0, pierce, nodes_map, flatten_result));
      value->setShadowRoots(std::move(shadow_roots));
      force_push_children = true;
    }

    if (IsA<HTMLLinkElement>(*element)) {
      force_push_children = true;
    }

    if (auto* template_element = DynamicTo<HTMLTemplateElement>(*element)) {
      if (DocumentFragment* content = template_element->content()) {
        value->setTemplateContent(
            BuildObjectForNode(content, 0, pierce, nodes_map, flatten_result));
        force_push_children = true;
      }
    }

    if (element->IsPseudoElement()) {
      value->setPseudoType(
          ProtocolPseudoElementType(element->GetPseudoIdForStyling()));
      if (auto tag = To<PseudoElement>(element)->view_transition_name())
        value->setPseudoIdentifier(tag);
    } else {
      if (!element->ownerDocument()->xmlVersion().empty())
        value->setXmlVersion(element->ownerDocument()->xmlVersion());
      if (auto* slot = element->AssignedSlotWithoutRecalc())
        value->setAssignedSlot(BuildBackendNode(slot));
    }
    std::unique_ptr<protocol::Array<protocol::DOM::Node>> pseudo_elements =
        BuildArrayForPseudoElements(element, nodes_map);
    if (pseudo_elements) {
      value->setPseudoElements(std::move(pseudo_elements));
      force_push_children = true;
    }

    if (auto* slot = DynamicTo<HTMLSlotElement>(*element)) {
      if (node->IsInShadowTree()) {
        value->setDistributedNodes(BuildDistributedNodesForSlot(slot));
        force_push_children = true;
      }
    }
  } else if (auto* document = DynamicTo<Document>(node)) {
    value->setDocumentURL(DocumentURLString(document));
    value->setBaseURL(DocumentBaseURLString(document));
    value->setXmlVersion(document->xmlVersion());
    value->setCompatibilityMode(GetDocumentCompatibilityMode(document));
  } else if (auto* doc_type = DynamicTo<DocumentType>(node)) {
    value->setPublicId(doc_type->publicId());
    value->setSystemId(doc_type->systemId());
  } else if (node->IsAttributeNode()) {
    auto* attribute = To<Attr>(node);
    value->setName(attribute->name());
    value->setValue(attribute->value());
  } else if (auto* shadow_root = DynamicTo<ShadowRoot>(node)) {
    value->setShadowRootType(GetShadowRootType(shadow_root));
  }

  if (node->IsContainerNode()) {
    int node_count = InnerChildNodeCount(node, IncludeWhitespace());
    value->setChildNodeCount(node_count);
    if (nodes_map == document_node_to_id_map_)
      cached_child_count_.Set(id, node_count);
    if (nodes_map && force_push_children && !depth)
      depth = 1;
    std::unique_ptr<protocol::Array<protocol::DOM::Node>> children =
        BuildArrayForContainerChildren(node, depth, pierce, nodes_map,
                                       flatten_result);
    if (!children->empty() ||
        depth)  // Push children along with shadow in any case.
      value->setChildren(std::move(children));
  }
  if (isNodeScrollable(node)) {
    value->setIsScrollable(true);
  }
  return value;
}

std::unique_ptr<protocol::Array<String>>
InspectorDOMAgent::BuildArrayForElementAttributes(Element* element) {
  auto attributes_value = std::make_unique<protocol::Array<String>>();
  // Go through all attributes and serialize them.
  for (const blink::Attribute& attribute : element->Attributes()) {
    // Add attribute pair
    attributes_value->emplace_back(attribute.GetName().ToString());
    attributes_value->emplace_back(attribute.Value());
  }
  return attributes_value;
}

std::unique_ptr<protocol::Array<protocol::DOM::Node>>
InspectorDOMAgent::BuildArrayForContainerChildren(
    Node* container,
    int depth,
    bool pierce,
    NodeToIdMap* nodes_map,
    protocol::Array<protocol::DOM::Node>* flatten_result) {
  auto children = std::make_unique<protocol::Array<protocol::DOM::Node>>();
  if (depth == 0) {
    if (!nodes_map)
      return children;
    // Special-case the only text child - pretend that container's children have
    // been requested.
    Node* first_child = container->firstChild();
    if (first_child && first_child->getNodeType() == Node::kTextNode &&
        !first_child->nextSibling()) {
      std::unique_ptr<protocol::DOM::Node> child_node =
          BuildObjectForNode(first_child, 0, pierce, nodes_map, flatten_result);
      child_node->setParentId(Bind(container, nodes_map));
      if (flatten_result) {
        flatten_result->emplace_back(std::move(child_node));
      } else {
        children->emplace_back(std::move(child_node));
      }
      children_requested_.insert(Bind(container, nodes_map));
    }
    return children;
  }

  InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace =
      IncludeWhitespace();
  Node* child = InnerFirstChild(container, include_whitespace);
  depth--;
  if (nodes_map)
    children_requested_.insert(Bind(container, nodes_map));

  while (child) {
    std::unique_ptr<protocol::DOM::Node> child_node =
        BuildObjectForNode(child, depth, pierce, nodes_map, flatten_result);
    child_node->setParentId(Bind(container, nodes_map));
    if (flatten_result) {
      flatten_result->emplace_back(std::move(child_node));
    } else {
      children->emplace_back(std::move(child_node));
    }
    if (nodes_map)
      children_requested_.insert(Bind(container, nodes_map));
    child = InnerNextSibling(child, include_whitespace);
  }
  return children;
}

std::unique_ptr<protocol::Array<protocol::DOM::Node>>
InspectorDOMAgent::BuildArrayForPseudoElements(Element* element,
                                               NodeToIdMap* nodes_map) {
  protocol::Array<protocol::DOM::Node> pseudo_elements;
  auto add_pseudo = [&](PseudoElement* pseudo_element) {
    pseudo_elements.emplace_back(
        BuildObjectForNode(pseudo_element, 0, false, nodes_map));
  };
  ForEachSupportedPseudo(element, add_pseudo);

  if (pseudo_elements.empty())
    return nullptr;
  return std::make_unique<protocol::Array<protocol::DOM::Node>>(
      std::move(pseudo_elements));
}

std::unique_ptr<protocol::DOM::BackendNode> InspectorDOMAgent::BuildBackendNode(
    Node* slot_element) {
  return protocol::DOM::BackendNode::create()
      .setNodeType(slot_element->getNodeType())
      .setNodeName(slot_element->nodeName())
      .setBackendNodeId(IdentifiersFactory::IntIdForNode(slot_element))
      .build();
}

std::unique_ptr<protocol::Array<protocol::DOM::BackendNode>>
InspectorDOMAgent::BuildDistributedNodesForSlot(HTMLSlotElement* slot_element) {
  // TODO(hayato): In Shadow DOM v1, the concept of distributed nodes should
  // not be used anymore. DistributedNodes should be replaced with
  // AssignedNodes() when IncrementalShadowDOM becomes stable and Shadow DOM v0
  // is removed.
  auto distributed_nodes =
      std::make_unique<protocol::Array<protocol::DOM::BackendNode>>();
  for (auto& node : slot_element->AssignedNodes()) {
    if (ShouldSkipNode(node, IncludeWhitespace()))
      continue;
    distributed_nodes->emplace_back(BuildBackendNode(node));
  }
  return distributed_nodes;
}

// static
Node* InspectorDOMAgent::InnerFirstChild(
    Node* node,
    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace) {
  node = node->firstChild();
  while (ShouldSkipNode(node, include_whitespace))
    node = node->nextSibling();
  return node;
}

// static
Node* InspectorDOMAgent::InnerNextSibling(
    Node* node,
    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace) {
  do {
    node = node->nextSibling();
  } while (ShouldSkipNode(node, include_whitespace));
  return node;
}

// static
Node* InspectorDOMAgent::InnerPreviousSibling(
    Node* node,
    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace) {
  do {
    node = node->previousSibling();
  } while (ShouldSkipNode(node, include_whitespace));
  return node;
}

// static
unsigned InspectorDOMAgent::InnerChildNodeCount(
    Node* node,
    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace) {
  unsigned count = 0;
  Node* child = InnerFirstChild(node, include_whitespace);
  while (child) {
    count++;
    child = InnerNextSibling(child, include_whitespace);
  }
  return count;
}

// static
Node* InspectorDOMAgent::InnerParentNode(Node* node) {
  if (auto* document = DynamicTo<Document>(node)) {
    return document->LocalOwner();
  }
  return node->ParentOrShadowHostNode();
}

// static
bool InspectorDOMAgent::ShouldSkipNode(
    Node* node,
    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace) {
  if (include_whitespace == InspectorDOMAgent::IncludeWhitespaceEnum::ALL)
    return false;

  bool is_whitespace = node && node->getNodeType() == Node::kTextNode &&
                       node->nodeValue().LengthWithStrippedWhiteSpace() == 0;

  return is_whitespace;
}

// static
void InspectorDOMAgent::CollectNodes(
    Node* node,
    int depth,
    bool pierce,
    InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace,
    base::RepeatingCallback<bool(Node*)> filter,
    HeapVector<Member<Node>>* result) {
  if (filter && filter.Run(node))
    result->push_back(node);
  if (--depth <= 0)
    return;

  auto* element = DynamicTo<Element>(node);
  if (pierce && element) {
    if (auto* frame_owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
      if (frame_owner->ContentFrame() &&
          frame_owner->ContentFrame()->IsLocalFrame()) {
        if (Document* doc = frame_owner->contentDocument())
          CollectNodes(doc, depth, pierce, include_whitespace, filter, result);
      }
    }

    ShadowRoot* root = element->GetShadowRoot();
    if (pierce && root)
      CollectNodes(root, depth, pierce, include_whitespace, filter, result);
  }

  for (Node* child = InnerFirstChild(node, include_whitespace); child;
       child = InnerNextSibling(child, include_whitespace)) {
    CollectNodes(child, depth, pierce, include_whitespace, filter, result);
  }
}

void InspectorDOMAgent::DomContentLoadedEventFired(LocalFrame* frame) {
  if (frame != inspected_frames_->Root())
    return;

  // Re-push document once it is loaded.
  DiscardFrontendBindings();
  if (enabled_.Get())
    GetFrontend()->documentUpdated();
}

void InspectorDOMAgent::InvalidateFrameOwnerElement(
    HTMLFrameOwnerElement* frame_owner) {
  if (!frame_owner)
    return;

  int frame_owner_id = BoundNodeId(frame_owner);
  if (!frame_owner_id)
    return;

  // Re-add frame owner element together with its new children.
  int parent_id = BoundNodeId(InnerParentNode(frame_owner));
  GetFrontend()->childNodeRemoved(parent_id, frame_owner_id);
  Unbind(frame_owner);

  std::unique_ptr<protocol::DOM::Node> value =
      BuildObjectForNode(frame_owner, 0, false, document_node_to_id_map_.Get());
  Node* previous_sibling =
      InnerPreviousSibling(frame_owner, IncludeWhitespace());
  int prev_id = previous_sibling ? BoundNodeId(previous_sibling) : 0;
  GetFrontend()->childNodeInserted(parent_id, prev_id, std::move(value));
}

void InspectorDOMAgent::DidCommitLoad(LocalFrame*, DocumentLoader* loader) {
  Document* document = loader->GetFrame()->GetDocument();
  NotifyDidAddDocument(document);

  LocalFrame* inspected_frame = inspected_frames_->Root();
  if (loader->GetFrame() != inspected_frame) {
    InvalidateFrameOwnerElement(
        loader->GetFrame()->GetDocument()->LocalOwner());
    return;
  }

  SetDocument(inspected_frame->GetDocument());
}

void InspectorDOMAgent::DidRestoreFromBackForwardCache(LocalFrame* frame) {
  if (!enabled_.Get())
    return;
  DCHECK_EQ(frame, inspected_frames_->Root());
  Document* document = frame->GetDocument();
  DCHECK_EQ(document_, document);
  // We don't load a new document for BFCache navigations, so |document_|
  // doesn't actually update (the agent is initialized with the restored main
  // document), but the frontend doesn't know this yet, and we need to notify
  // it.
  GetFrontend()->documentUpdated();
}

void InspectorDOMAgent::DidInsertDOMNode(Node* node) {
  InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace =
      IncludeWhitespace();
  if (ShouldSkipNode(node, include_whitespace))
    return;

  // We could be attaching existing subtree. Forget the bindings.
  Unbind(node);

  ContainerNode* parent = node->parentNode();
  if (!parent)
    return;
  // Return if parent is not mapped yet.
  int parent_id = BoundNodeId(parent);
  if (!parent_id)
    return;

  if (!children_requested_.Contains(parent_id)) {
    // No children are mapped yet -> only notify on changes of child count.
    auto it = cached_child_count_.find(parent_id);
    int count = (it != cached_child_count_.end() ? it->value : 0) + 1;
    cached_child_count_.Set(parent_id, count);
    GetFrontend()->childNodeCountUpdated(parent_id, count);
  } else {
    // Children have been requested -> return value of a new child.
    Node* prev_sibling = InnerPreviousSibling(node, include_whitespace);
    int prev_id = prev_sibling ? BoundNodeId(prev_sibling) : 0;
    std::unique_ptr<protocol::DOM::Node> value =
        BuildObjectForNode(node, 0, false, document_node_to_id_map_.Get());
    GetFrontend()->childNodeInserted(parent_id, prev_id, std::move(value));
  }
}

void InspectorDOMAgent::WillRemoveDOMNode(Node* node) {
  if (ShouldSkipNode(node, IncludeWhitespace()))
    return;
  DOMNodeRemoved(node);
}

void InspectorDOMAgent::DOMNodeRemoved(Node* node) {
  ContainerNode* parent = node->parentNode();

  // If parent is not mapped yet -> ignore the event.
  int parent_id = BoundNodeId(parent);
  if (!parent_id)
    return;

  if (!children_requested_.Contains(parent_id)) {
    // No children are mapped yet -> only notify on changes of child count.
    int count = cached_child_count_.at(parent_id) - 1;
    cached_child_count_.Set(parent_id, count);
    GetFrontend()->childNodeCountUpdated(parent_id, count);
  } else {
    GetFrontend()->childNodeRemoved(parent_id, BoundNodeId(node));
  }
  Unbind(node);
}

void InspectorDOMAgent::WillModifyDOMAttr(Element*,
                                          const AtomicString& old_value,
                                          const AtomicString& new_value) {
  suppress_attribute_modified_event_ = (old_value == new_value);
}

void InspectorDOMAgent::DidModifyDOMAttr(Element* element,
                                         const QualifiedName& name,
                                         const AtomicString& value) {
  bool should_suppress_event = suppress_attribute_modified_event_;
  suppress_attribute_modified_event_ = false;
  if (should_suppress_event)
    return;

  int id = BoundNodeId(element);
  // If node is not mapped yet -> ignore the event.
  if (!id)
    return;

  NotifyDidModifyDOMAttr(element);

  GetFrontend()->attributeModified(id, name.ToString(), value);
}

void InspectorDOMAgent::DidRemoveDOMAttr(Element* element,
                                         const QualifiedName& name) {
  int id = BoundNodeId(element);
  // If node is not mapped yet -> ignore the event.
  if (!id)
    return;

  NotifyDidModifyDOMAttr(element);

  GetFrontend()->attributeRemoved(id, name.ToString());
}

void InspectorDOMAgent::StyleAttributeInvalidated(
    const HeapVector<Member<Element>>& elements) {
  auto node_ids = std::make_unique<protocol::Array<int>>();
  for (unsigned i = 0, size = elements.size(); i < size; ++i) {
    Element* element = elements.at(i);
    int id = BoundNodeId(element);
    // If node is not mapped yet -> ignore the event.
    if (!id)
      continue;

    NotifyDidModifyDOMAttr(element);
    node_ids->emplace_back(id);
  }
  GetFrontend()->inlineStyleInvalidated(std::move(node_ids));
}

void InspectorDOMAgent::CharacterDataModified(CharacterData* character_data) {
  int id = BoundNodeId(character_data);
  if (id && ShouldSkipNode(character_data, IncludeWhitespace())) {
    DOMNodeRemoved(character_data);
    return;
  }
  if (!id) {
    // Push text node if it is being created.
    DidInsertDOMNode(character_data);
    return;
  }
  GetFrontend()->characterDataModified(id, character_data->data());
}

InspectorRevalidateDOMTask* InspectorDOMAgent::RevalidateTask() {
  if (!revalidate_task_)
    revalidate_task_ = MakeGarbageCollected<InspectorRevalidateDOMTask>(this);
  return revalidate_task_.Get();
}

void InspectorDOMAgent::DidInvalidateStyleAttr(Node* node) {
  // If node is not mapped yet -> ignore the event.
  if (!BoundNodeId(node))
    return;
  RevalidateTask()->ScheduleStyleAttrRevalidationFor(To<Element>(node));
}

bool InspectorDOMAgent::isNodeScrollable(Node* node) {
  if (auto* box = DynamicTo<LayoutBox>(node->GetLayoutObject())) {
    if (!box->Style()) {
      return false;
    }
    return box->IsUserScrollable();
  }
  return false;
}

void InspectorDOMAgent::DidPushShadowRoot(Element* host, ShadowRoot* root) {
  if (!host->ownerDocument())
    return;

  int host_id = BoundNodeId(host);
  if (!host_id)
    return;

  PushChildNodesToFrontend(host_id, 1);
  GetFrontend()->shadowRootPushed(
      host_id,
      BuildObjectForNode(root, 0, false, document_node_to_id_map_.Get()));
}

void InspectorDOMAgent::WillPopShadowRoot(Element* host, ShadowRoot* root) {
  if (!host->ownerDocument())
    return;

  int host_id = BoundNodeId(host);
  int root_id = BoundNodeId(root);
  if (host_id && root_id)
    GetFrontend()->shadowRootPopped(host_id, root_id);
}

void InspectorDOMAgent::DidPerformSlotDistribution(
    HTMLSlotElement* slot_element) {
  int insertion_point_id = BoundNodeId(slot_element);
  if (insertion_point_id)
    GetFrontend()->distributedNodesUpdated(
        insertion_point_id, BuildDistributedNodesForSlot(slot_element));
}

void InspectorDOMAgent::FrameDocumentUpdated(LocalFrame* frame) {
  Document* document = frame->GetDocument();
  if (!document)
    return;

  if (frame != inspected_frames_->Root())
    return;

  // Only update the main frame document, nested frame document updates are not
  // required (will be handled by invalidateFrameOwnerElement()).
  SetDocument(document);
}

void InspectorDOMAgent::FrameOwnerContentUpdated(
    LocalFrame* frame,
    HTMLFrameOwnerElement* frame_owner) {
  if (!frame_owner->contentDocument()) {
    // frame_owner does not point to frame at this point, so Unbind it
    // explicitly.
    Unbind(frame->GetDocument());
  }

  // Revalidating owner can serialize empty frame owner - that's what we are
  // looking for when disconnecting.
  InvalidateFrameOwnerElement(frame_owner);
}

void InspectorDOMAgent::PseudoElementCreated(PseudoElement* pseudo_element) {
  Element* parent = pseudo_element->ParentOrShadowHostElement();
  if (!parent)
    return;
  if (!PseudoElement::IsWebExposed(pseudo_element->GetPseudoIdForStyling(),
                                   parent)) {
    return;
  }
  int parent_id = BoundNodeId(parent);
  if (!parent_id)
    return;

  PushChildNodesToFrontend(parent_id, 1);
  GetFrontend()->pseudoElementAdded(
      parent_id, BuildObjectForNode(pseudo_element, 0, false,
                                    document_node_to_id_map_.Get()));
}

void InspectorDOMAgent::TopLayerElementsChanged() {
  GetFrontend()->topLayerElementsUpdated();
}

void InspectorDOMAgent::PseudoElementDestroyed(PseudoElement* pseudo_element) {
  int pseudo_element_id = BoundNodeId(pseudo_element);
  if (!pseudo_element_id)
    return;

  // If a PseudoElement is bound, its parent element must be bound, too.
  Element* parent = pseudo_element->ParentOrShadowHostElement();
  DCHECK(parent);
  int parent_id = BoundNodeId(parent);
  // Since the pseudo element tree created for a view transition is destroyed
  // with in-order traversal, the parent node (::view-transition) are destroyed
  // before its children
  // (::view-transition-group).
  DCHECK(parent_id || IsTransitionPseudoElement(pseudo_element->GetPseudoId()));

  Unbind(pseudo_element);
  GetFrontend()->pseudoElementRemoved(parent_id, pseudo_element_id);
}

void InspectorDOMAgent::NodeCreated(Node* node) {
  if (!capture_node_stack_traces_.Get())
    return;

  std::unique_ptr<SourceLocation> creation_source_location =
      SourceLocation::CaptureWithFullStackTrace();
  if (creation_source_location) {
    node_to_creation_source_location_map_.Set(
        node, MakeGarbageCollected<InspectorSourceLocation>(
                  std::move(creation_source_location)));
  }
}

void InspectorDOMAgent::UpdateScrollableFlag(
    Node* node,
    std::optional<bool> override_flag) {
  if (!node) {
    return;
  }
  int nodeId = BoundNodeId(node);
  // If node is not mapped yet -> ignore the event.
  if (!nodeId) {
    return;
  }
  GetFrontend()->scrollableFlagUpdated(nodeId, override_flag.has_value()
                                                   ? override_flag.value()
                                                   : isNodeScrollable(node));
}

namespace {

ShadowRoot* ShadowRootForNode(Node* node, const String& type) {
  auto* element = DynamicTo<Element>(node);
  if (!element)
    return nullptr;
  if (type == "a")
    return element->AuthorShadowRoot();
  if (type == "u")
    return element->UserAgentShadowRoot();
  return nullptr;
}

Document* DocumentForFrameOwner(Node* node) {
  if (auto* owner = DynamicTo<HTMLFrameOwnerElement>(node)) {
    return owner->contentDocument();
  }
  return nullptr;
}

}  // namespace

Node* InspectorDOMAgent::NodeForPath(const String& path) {
  // The path is of form "1,HTML,2,BODY,1,DIV" (<index> and <nodeName>
  // interleaved).  <index> may also be "a" (author shadow root) or "u"
  // (user-agent shadow root), in which case <nodeName> MUST be
  // "#document-fragment".
  // The first component after an iframe will always be "d,#document".
  if (!document_)
    return nullptr;

  Node* node = document_.Get();
  Vector<String> path_tokens;
  path.Split(',', path_tokens);
  if (!path_tokens.size())
    return nullptr;

  InspectorDOMAgent::IncludeWhitespaceEnum include_whitespace =
      IncludeWhitespace();
  for (wtf_size_t i = 0; i < path_tokens.size() - 1; i += 2) {
    bool success = true;
    String& index_value = path_tokens[i];
    wtf_size_t child_number = index_value.ToUInt(&success);
    Node* child;
    String child_name = path_tokens[i + 1];
    if (!success) {
      if (index_value == "d") {
        child = DocumentForFrameOwner(node);
      } else {
        child = ShadowRootForNode(node, index_value);
      }
    } else {
      if (child_number >= InnerChildNodeCount(node, include_whitespace))
        return nullptr;

      child = InnerFirstChild(node, include_whitespace);
    }
    for (wtf_size_t j = 0; child && j < child_number; ++j)
      child = InnerNextSibling(child, include_whitespace);

    if (!child || child->nodeName() != child_name)
      return nullptr;
    node = child;
  }
  return node;
}

protocol::Response InspectorDOMAgent::pushNodeByPathToFrontend(
    const String& path,
    int* node_id) {
  if (!enabled_.Get())
    return protocol::Response::ServerError("DOM agent is not enabled");
  if (Node* node = NodeForPath(path))
    *node_id = PushNodePathToFrontend(node);
  else
    return protocol::Response::ServerError("No node with given path found");
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::pushNodesByBackendIdsToFrontend(
    std::unique_ptr<protocol::Array<int>> backend_node_ids,
    std::unique_ptr<protocol::Array<int>>* result) {
  if (!document_ || !BoundNodeId(document_)) {
    return protocol::Response::ServerError(
        "Document needs to be requested first");
  }

  *result = std::make_unique<protocol::Array<int>>();
  for (int id : *backend_node_ids) {
    Node* node = DOMNodeIds::NodeForId(id);
    if (node && node->GetDocument().GetFrame() &&
        inspected_frames_->Contains(node->GetDocument().GetFrame()))
      (*result)->emplace_back(PushNodePathToFrontend(node));
    else
      (*result)->emplace_back(0);
  }
  return protocol::Response::Success();
}

class InspectableNode final
    : public v8_inspector::V8InspectorSession::Inspectable {
 public:
  explicit InspectableNode(Node* node) : node_id_(node->GetDomNodeId()) {}

  v8::Local<v8::Value> get(v8::Local<v8::Context> context) override {
    return NodeV8Value(context, DOMNodeIds::NodeForId(node_id_));
  }

 private:
  DOMNodeId node_id_;
};

protocol::Response InspectorDOMAgent::setInspectedNode(int node_id) {
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;
  v8_session_->addInspectedObject(std::make_unique<InspectableNode>(node));
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::getRelayoutBoundary(
    int node_id,
    int* relayout_boundary_node_id) {
  Node* node = nullptr;
  protocol::Response response = AssertNode(node_id, node);
  if (!response.IsSuccess())
    return response;
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object) {
    return protocol::Response::ServerError(
        "No layout object for node, perhaps orphan or hidden node");
  }
  while (layout_object && !layout_object->IsDocumentElement() &&
         !layout_object->IsRelayoutBoundary())
    layout_object = layout_object->Container();
  Node* result_node =
      layout_object ? layout_object->GeneratingNode() : node->ownerDocument();
  *relayout_boundary_node_id = PushNodePathToFrontend(result_node);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::describeNode(
    protocol::Maybe<int> node_id,
    protocol::Maybe<int> backend_node_id,
    protocol::Maybe<String> object_id,
    protocol::Maybe<int> depth,
    protocol::Maybe<bool> pierce,
    std::unique_ptr<protocol::DOM::Node>* result) {
  Node* node = nullptr;
  protocol::Response response =
      AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess())
    return response;
  if (!node)
    return protocol::Response::ServerError("Node not found");
  *result = BuildObjectForNode(node, depth.value_or(0), pierce.value_or(false),
                               nullptr, nullptr);
  return protocol::Response::Success();
}

protocol::Response InspectorDOMAgent::scrollIntoViewIfNeeded(
    protocol::Maybe<int> node_id,
    protocol::Maybe<int> backend_node_id,
    protocol::Maybe<String> object_id,
    protocol::Maybe<protocol::DOM::Rect> rect) {
  Node* node = nullptr;
  protocol::Response response =
      AssertNode(node_id, backend_node_id, object_id, node);
  if (!response.IsSuccess())
    return response;
  node->GetDocument().EnsurePaintLocationDataValidForNode(
      node, DocumentUpdateReason::kInspector);
  if (!node->isConnected())
    return protocol::Response::ServerError("Node is detached from document");
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object) {
    node = LayoutTreeBuilderTraversal::FirstLayoutChild(*node);
    if (node)
      layout_object = node->GetLayoutObject();
  }
  if (!layout_object) {
    return protocol::Response::ServerError(
        "Node does not have a layout object");
  }
  PhysicalRect rect_to_scroll =
      PhysicalRect::EnclosingRect(layout_object->AbsoluteBoundingBoxRectF());
  if (rect) {
    rect_to_scroll.SetX(rect_to_scroll.X() + LayoutUnit(rect->getX()));
    rect_to_scroll.SetY(rect_to_scroll.Y() + LayoutUnit(rect->getY()));
    rec
"""


```