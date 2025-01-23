Response:
The user wants a summary of the functionality of the provided C++ code snippet from the `blink/renderer/core/dom/range.cc` file. This is part 2 of a 3-part series, so I should focus on the functionality within this specific snippet.

Here's a breakdown of the code and its functionalities:

1. **`insertNode` function:** Handles inserting a new node into the DOM within the context of a `Range`. It considers various factors like the type of the new node, the start node of the range, and potential exceptions.
2. **`toString` function:**  Converts the content within the `Range` into a text string. It iterates through the nodes within the range and appends the text content of Text and CDATA nodes.
3. **`GetText` function:** Retrieves the plain text content of the `Range`. It utilizes the `PlainText` function with specific options.
4. **`createContextualFragment` function:**  Parses a string of HTML or SVG markup and creates a DocumentFragment within the context of the `Range`. It handles different scenarios based on the start node of the range.
5. **`detach` function:**  A no-op according to the DOM specification.
6. **`CheckNodeWOffset` function:**  Performs checks on a given node and offset, throwing exceptions for invalid node types or out-of-bounds offsets.
7. **`CheckNodeBA` function:** Checks if a given node is valid for certain Range operations (like setting start/end). It validates the node's type and its position in the DOM tree.
8. **`cloneRange` function:** Creates a new `Range` object that is a copy of the current one.
9. **`setStartAfter`, `setEndBefore`, `setEndAfter` functions:**  Modify the start or end boundary of the `Range` relative to a given node.
10. **`selectNode` function:**  Sets the `Range` to encompass an entire given node.
11. **`selectNodeContents` function:** Sets the `Range` to encompass the contents of a given node.
12. **`surroundContents` function:** Moves the content within the `Range` into a new parent node, effectively "surrounding" the content.
13. **`setStartBefore` function:** Sets the start boundary of the `Range` to be immediately before a given node.
14. **`CheckExtractPrecondition` function:**  Performs checks before extracting content from a `Range`, ensuring it doesn't contain disallowed node types.
15. **`FirstNode`, `PastLastNode` functions:**  Return the first and "past the last" node within the `Range`.
16. **`BoundingBox` function:** Calculates the bounding box of the content within the `Range`.
17. **`AreRangesEqual` function:**  A utility function to check if two `Range` objects are equal.
18. **`BoundaryNodeChildrenWillBeRemoved`, `BoundaryShadowNodeChildrenWillBeRemoved` functions:**  Adjust the `Range` boundaries when child nodes are about to be removed from a container.
19. **`NodeChildrenWillBeRemoved`, `FixupRemovedChildrenAcrossShadowBoundary` functions:** Call the boundary adjustment functions when children are removed.
20. **`BoundaryNodeWillBeRemoved`, `BoundaryShadowNodeWillBeRemoved` functions:** Adjust the `Range` boundaries when a specific node is about to be removed.
21. **`NodeWillBeRemoved`, `FixupRemovedNodeAcrossShadowBoundary` functions:** Call the boundary adjustment functions when a node is removed.
22. **`BoundaryTextInserted` function:** Updates the `Range` boundaries when text is inserted into a node within the `Range`.
23. **`DidInsertText` function:**  Calls the boundary update function after text insertion.
24. **`BoundaryTextRemoved` function:** Updates the `Range` boundaries when text is removed from a node within the `Range`.
25. **`DidRemoveText` function:** Calls the boundary update function after text removal.
26. **`BoundaryTextNodesMerged` function:** Updates the `Range` boundaries when two text nodes are merged.
27. **`DidMergeTextNodes` function:** Calls the boundary update function after text nodes are merged.
28. **`UpdateOwnerDocumentIfNeeded` function:** Updates the owner document of the `Range` if it has changed (e.g., due to moving nodes between documents).
29. **`BoundaryTextNodeSplit` function:** Updates the `Range` boundaries when a text node is split.
30. **`DidSplitTextNode` function:** Calls the boundary update function after a text node is split.
31. **`expand` function:**  Expands the `Range` to encompass units like words, sentences, blocks, or the entire document.
32. **`getClientRects` function:** Returns a list of client rectangles that enclose the content of the `Range`.
33. **`getBoundingClientRect` function:** Returns the smallest rectangle that encloses all the client rectangles of the `Range`.
34. **`ComputeTextQuads` function:** (Static helper) Computes the quads (rectangles) for a range of text within a `LayoutText` object.
35. **`GetBorderAndTextQuads` function:**  Calculates the quads encompassing the content of the `Range`, considering both element borders and text.
36. **`BoundingRect` function:** Calculates the bounding rectangle of the `Range`.
37. **`UpdateSelectionIfAddedToSelection` function:** Updates the browser's selection if this `Range` is set as the selection.

Based on this analysis, I can now formulate the summary.
这是blink渲染引擎中`Range`对象实现的一部分，主要负责**对DOM树中的一段连续区域进行操作和查询**。 它是DOM规范中定义的核心接口，用于在文档中选择一个内容范围。

以下是这段代码片段中 `Range` 对象的主要功能归纳：

**1. 插入节点 (`insertNode`)：**

*   **功能:** 在 `Range` 的起始位置插入一个新的节点。
*   **与 JavaScript/HTML/CSS 的关系:**  JavaScript 可以通过 `range.insertNode(newNode)` 方法调用此功能。这会直接修改 DOM 树，影响页面的 HTML 结构和最终渲染的 CSS 样式。
*   **举例:**
    *   **假设输入:**  一个包含文本 "world" 的 `div` 元素，一个 `Range` 对象选择了 "w" 的位置，以及一个包含文本 "hello " 的新的 `Text` 节点。
    *   **输出:**  `div` 元素的内容变为 "hello world"， `Range` 的结束位置可能会被调整。
*   **用户/编程常见错误:**
    *   尝试插入一个已经存在于 DOM 树中的节点，而没有先将其移除。这会导致节点被移动，而不是复制。
    *   尝试在不允许的位置插入节点，例如在 `Attr` 节点内部，会导致 `HierarchyRequestError` 异常。
*   **用户操作如何到达:** 用户通过 JavaScript 调用 `range.insertNode()` 方法。例如，用户点击按钮触发一个 JavaScript 函数，该函数创建一个新的 DOM 元素并使用 `range.insertNode()` 将其插入到当前选中的文本位置。

**2. 转换为字符串 (`toString`)：**

*   **功能:** 将 `Range` 所包含的内容转换为一个字符串。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.toString()` 方法调用此功能，获取 `Range` 选区内的文本内容。
*   **举例:**
    *   **假设输入:** 一个包含 "<div>Hello <b>world</b>!</div>" 的 HTML 结构，一个 `Range` 对象选择了 "Hello world"。
    *   **输出:** 字符串 "Hello world"。
*   **用户/编程常见错误:**  无明显的常见用户错误，主要是编程逻辑错误，例如假设 `toString()` 会返回 HTML 标签，但它只返回文本内容。

**3. 获取纯文本 (`GetText`)：**

*   **功能:** 获取 `Range` 所包含内容的纯文本形式，会处理一些特殊字符。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.textContent` 属性（在某些浏览器中）或一些自定义方法实现类似功能。
*   **举例:**
    *   **假设输入:**  一个包含 "<div>Hello <img src='icon.png'>world</div>" 的 HTML 结构，一个 `Range` 对象选择了整个 `div` 的内容。
    *   **输出:** 字符串 "Hello ￼world" (其中 "￼" 可能代表图片占位符)。

**4. 创建上下文片段 (`createContextualFragment`)：**

*   **功能:**  根据给定的 HTML 或 SVG 字符串，在 `Range` 的上下文中创建一个 `DocumentFragment`。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.createContextualFragment(markupString)` 方法调用此功能。这对于动态生成和插入 HTML 片段非常有用。
*   **举例:**
    *   **假设输入:**  一个空的 `div` 元素，一个 `Range` 对象选择了该 `div` 的起始位置，以及 HTML 字符串 "<p>New paragraph</p>"。
    *   **输出:**  创建一个包含 `<p>New paragraph</p>` 的 `DocumentFragment` 对象。这个片段可以随后被插入到 DOM 中。
*   **用户/编程常见错误:**  提供的 `markupString` 不是有效的 HTML 或 SVG，会导致解析错误。

**5. 分离 (`detach`)：**

*   **功能:**  根据 DOM 规范，这是一个空操作（no-op）。在早期的浏览器版本中可能有释放资源的作用。

**6. 检查节点和偏移量 (`CheckNodeWOffset`)：**

*   **功能:**  验证给定的节点和偏移量是否有效，例如检查偏移量是否超出节点长度，或者节点类型是否允许作为 `Range` 的边界点。
*   **与 JavaScript/HTML/CSS 的关系:**  这是内部方法，用于在 JavaScript 操作 `Range` 时进行参数校验，防止无效操作导致崩溃或错误。
*   **举例:**
    *   **假设输入:** 一个包含 "Hello" 的 `Text` 节点，偏移量为 10。
    *   **输出:** 抛出一个 `IndexSizeError` 异常，因为偏移量超出了文本节点的长度。

**7. 检查节点是否有效 (`CheckNodeBA`)：**

*   **功能:**  检查给定的节点是否可以作为 `Range` 的边界点，排除一些不允许的节点类型。
*   **与 JavaScript/HTML/CSS 的关系:**  内部方法，用于参数校验。
*   **举例:**
    *   **假设输入:**  一个 `Document` 节点。
    *   **输出:** 抛出一个 `InvalidNodeTypeError` 异常，因为 `Document` 节点不能直接作为 `Range` 的边界点。

**8. 克隆 Range (`cloneRange`)：**

*   **功能:** 创建一个新的 `Range` 对象，它是当前 `Range` 的副本。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.cloneRange()` 方法调用。
*   **举例:**  如果一个 `Range` 选择了 "hello"，克隆后会得到另一个独立的 `Range` 对象，也选择了 "hello"。

**9. 设置起始/结束位置 (after/before) (`setStartAfter`, `setEndBefore`, `setEndAfter`)：**

*   **功能:**  调整 `Range` 的起始或结束位置，使其位于给定节点的前面或后面。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过相应的方法调用。例如，`range.setStartAfter(node)` 将 `Range` 的起始位置设置为 `node` 之后。

**10. 选择节点 (`selectNode`)：**

*   **功能:** 将 `Range` 的起始和结束位置设置为包围给定节点。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.selectNode(node)` 方法调用。这会选中整个节点。

**11. 选择节点内容 (`selectNodeContents`)：**

*   **功能:** 将 `Range` 的起始和结束位置设置为给定节点的内部内容的开始和结束。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.selectNodeContents(node)` 方法调用。这会选中节点的所有子节点和文本内容。

**12. 包裹内容 (`surroundContents`)：**

*   **功能:** 将 `Range` 所包含的内容移动到一个新的父节点中。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.surroundContents(newNode)` 方法调用。
*   **举例:**  如果一个 `Range` 选择了 "world"，并使用一个 `<span>` 元素作为 `newNode` 调用 `surroundContents`，则会将 "world" 放入一个 `<span>` 标签中。

**13. 设置起始位置 (before) (`setStartBefore`)：**

*   **功能:** 将 `Range` 的起始位置设置为给定节点之前。

**14. 检查提取前提条件 (`CheckExtractPrecondition`)：**

*   **功能:** 在提取 `Range` 内容之前，检查 `Range` 是否包含不允许被提取的节点类型（例如 `DocumentType`）。

**15. 获取第一个/最后一个节点 (`FirstNode`, `PastLastNode`)：**

*   **功能:**  返回 `Range` 中第一个和“超过最后一个”的节点，用于遍历 `Range` 的内容。

**16. 获取边界框 (`BoundingBox`)：**

*   **功能:** 计算 `Range` 内容在页面上的边界矩形。
*   **与 JavaScript/HTML/CSS 的关系:**  虽然 JavaScript 没有直接对应的方法，但可以结合 `getClientRects` 和 `getBoundingClientRect` 来实现类似功能。这涉及到元素的布局和渲染。

**17. 判断 Range 是否相等 (`AreRangesEqual`)：**

*   **功能:**  比较两个 `Range` 对象是否指向相同的文档位置。

**18. 处理节点移除 (`BoundaryNodeChildrenWillBeRemoved`, `BoundaryShadowNodeChildrenWillBeRemoved`, `NodeChildrenWillBeRemoved`, `FixupRemovedChildrenAcrossShadowBoundary`, `BoundaryNodeWillBeRemoved`, `BoundaryShadowNodeWillBeRemoved`, `NodeWillBeRemoved`, `FixupRemovedNodeAcrossShadowBoundary`)：**

*   **功能:**  在 DOM 树中的节点被移除时，更新 `Range` 对象的边界点，以保持 `Range` 的有效性。这些方法处理了普通 DOM 树和 Shadow DOM 树的情况。

**19. 处理文本插入/移除/合并/分割 (`BoundaryTextInserted`, `DidInsertText`, `BoundaryTextRemoved`, `DidRemoveText`, `BoundaryTextNodesMerged`, `DidMergeTextNodes`, `BoundaryTextNodeSplit`, `DidSplitTextNode`)：**

*   **功能:**  在 `Range` 包含的文本节点发生插入、删除、合并或分割操作时，更新 `Range` 对象的边界点。

**20. 更新所有者文档 (`UpdateOwnerDocumentIfNeeded`)：**

*   **功能:**  如果 `Range` 的边界点移动到了不同的文档，则更新 `Range` 对象所关联的文档。

**21. 扩展 Range (`expand`)：**

*   **功能:**  将 `Range` 的边界扩展到更大的逻辑单元，例如单词、句子、段落或整个文档。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.expand(unit)` 方法调用。
*   **举例:**  如果一个 `Range` 只选择了一个单词的一部分，调用 `expand('word')` 会将 `Range` 扩展到包含整个单词。

**22. 获取客户端矩形列表 (`getClientRects`)：**

*   **功能:** 返回一个 `DOMRectList` 对象，其中包含了 `Range` 内容在视口中的所有独立的矩形区域。这对于处理多行文本选择非常有用。
*   **与 JavaScript/HTML/CSS 的关系:**  JavaScript 可以通过 `range.getClientRects()` 方法调用。这直接关系到元素的布局和渲染。

**23. 获取边界客户端矩形 (`getBoundingClientRect`)：**

*   **功能:** 返回一个 `DOMRect` 对象，它代表了包围 `Range` 内容的最小矩形。
*   **与 JavaScript/HTML/CSS 的关系:** JavaScript 可以通过 `range.getBoundingClientRect()` 方法调用。这同样关系到元素的布局和渲染。

**24. 计算文本 Quad (`ComputeTextQuads`)：**

*   **功能:** （静态辅助函数）计算 `LayoutText` 对象中指定范围文本的四边形（Quad）。这是计算 `getClientRects` 和 `getBoundingClientRect` 的基础。

**25. 获取边框和文本 Quad (`GetBorderAndTextQuads`)：**

*   **功能:** 计算 `Range` 内容的边框和文本的四边形，用于确定其在页面上的渲染区域。

**26. 获取边界矩形 (`BoundingRect`)：**

*   **功能:**  计算 `Range` 的边界矩形，是 `getBoundingClientRect` 的底层实现。

**27. 当添加到选择时更新选择 (`UpdateSelectionIfAddedToSelection`)：**

*   **功能:** 当这个 `Range` 被设置为文档的选择时，更新浏览器的选择状态。
*   **与 JavaScript/HTML/CSS 的关系:** 这与浏览器的选择 API 相关，例如 `window.getSelection()`。

总而言之，这段代码实现了 `Range` 接口的核心功能，包括在文档中选择区域、插入/提取内容、获取文本表示、进行各种边界调整以及获取渲染相关的几何信息。它在 JavaScript 操作 DOM 时扮演着关键角色，使得开发者能够精确地操作和查询文档的特定部分。

### 提示词
```
这是目录为blink/renderer/core/dom/range.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
node itself.");
    return;
  }

  // According to the specification, the following condition is checked in the
  // step 6. However our EnsurePreInsertionValidity() supports only
  // ContainerNode parent.
  if (start_node.IsAttributeNode()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kHierarchyRequestError,
        "Nodes of type '" + new_node->nodeName() +
            "' may not be inserted inside nodes of type 'Attr'.");
    return;
  }

  // 2. Let referenceNode be null.
  Node* reference_node = nullptr;
  // 3. If range’s start node is a Text node, set referenceNode to that Text
  // node.
  // 4. Otherwise, set referenceNode to the child of start node whose index is
  // start offset, and null if there is no such child.
  if (start_is_text)
    reference_node = &start_node;
  else
    reference_node = NodeTraversal::ChildAt(start_node, start_.Offset());

  // 5. Let parent be range’s start node if referenceNode is null, and
  // referenceNode’s parent otherwise.
  ContainerNode& parent = reference_node ? *reference_node->parentNode()
                                         : To<ContainerNode>(start_node);

  // 6. Ensure pre-insertion validity of node into parent before referenceNode.
  if (!parent.EnsurePreInsertionValidity(new_node, /*new_children*/ nullptr,
                                         reference_node, nullptr,
                                         exception_state)) {
    return;
  }

  EventQueueScope scope;
  // 7. If range's start node is a Text node, set referenceNode to the result of
  // splitting it with offset range’s start offset.
  if (start_is_text) {
    reference_node =
        To<Text>(start_node).splitText(start_.Offset(), exception_state);
    if (exception_state.HadException())
      return;
  }

  // 8. If node is referenceNode, set referenceNode to its next sibling.
  if (new_node == reference_node)
    reference_node = reference_node->nextSibling();

  // 9. If node's parent is not null, remove node from its parent.
  if (new_node->parentNode()) {
    new_node->remove(exception_state);
    if (exception_state.HadException())
      return;
  }

  // 10. Let newOffset be parent's length if referenceNode is null, and
  // referenceNode's index otherwise.
  unsigned new_offset = reference_node
                            ? reference_node->NodeIndex()
                            : AbstractRange::LengthOfContents(&parent);

  // 11. Increase newOffset by node's length if node is a DocumentFragment node,
  // and one otherwise.
  new_offset += new_node->IsDocumentFragment()
                    ? AbstractRange::LengthOfContents(new_node)
                    : 1;

  // 12. Pre-insert node into parent before referenceNode.
  parent.insertBefore(new_node, reference_node, exception_state);
  if (exception_state.HadException())
    return;

  // 13. If range's start and end are the same, set range's end to (parent,
  // newOffset).
  if (start_ == end_)
    setEnd(&parent, new_offset, exception_state);
}

String Range::toString() const {
  StringBuilder builder;

  Node* past_last = PastLastNode();
  for (Node* n = FirstNode(); n != past_last; n = NodeTraversal::Next(*n)) {
    Node::NodeType type = n->getNodeType();
    if (type == Node::kTextNode || type == Node::kCdataSectionNode) {
      String data = To<CharacterData>(n)->data();
      unsigned length = data.length();
      unsigned start =
          (n == start_.Container()) ? std::min(start_.Offset(), length) : 0;
      unsigned end = (n == end_.Container())
                         ? std::min(std::max(start, end_.Offset()), length)
                         : length;
      builder.Append(data, start, end - start);
    }
  }

  return builder.ReleaseString();
}

String Range::GetText() const {
  DCHECK(!owner_document_->NeedsLayoutTreeUpdate());
  return PlainText(EphemeralRange(this),
                   TextIteratorBehavior::Builder()
                       .SetEmitsObjectReplacementCharacter(true)
                       .Build());
}

DocumentFragment* Range::createContextualFragment(
    const String& markup,
    ExceptionState& exception_state) {
  // Algorithm:
  // http://domparsing.spec.whatwg.org/#extensions-to-the-range-interface

  DCHECK(!markup.IsNull());

  Node* node = &start_.Container();

  // Step 1.
  Element* element;
  if (!start_.Offset() &&
      (node->IsDocumentNode() || node->IsDocumentFragment()))
    element = nullptr;
  else if (auto* node_element = DynamicTo<Element>(node))
    element = node_element;
  else
    element = node->parentElement();

  // Step 2.
  if (!element || IsA<HTMLHtmlElement>(element)) {
    Document& document = node->GetDocument();

    if (document.IsSVGDocument()) {
      element = document.documentElement();
      if (!element)
        element = MakeGarbageCollected<SVGSVGElement>(document);
    } else {
      // Optimization over spec: try to reuse the existing <body> element, if it
      // is available.
      element = document.body();
      if (!element)
        element = MakeGarbageCollected<HTMLBodyElement>(document);
    }
  }

  // Steps 3, 4, 5.
  return blink::CreateContextualFragment(
      markup, element, kAllowScriptingContentAndDoNotMarkAlreadyStarted,
      exception_state);
}

void Range::detach() {
  // This is now a no-op as per the DOM specification.
}

Node* Range::CheckNodeWOffset(Node* n,
                              unsigned offset,
                              ExceptionState& exception_state) {
  switch (n->getNodeType()) {
    case Node::kDocumentTypeNode:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidNodeTypeError,
          "The node provided is of type '" + n->nodeName() + "'.");
      return nullptr;
    case Node::kCdataSectionNode:
    case Node::kCommentNode:
    case Node::kTextNode:
      if (offset > To<CharacterData>(n)->length()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "The offset " + String::Number(offset) +
                " is larger than the node's length (" +
                String::Number(To<CharacterData>(n)->length()) + ").");
      } else if (offset >
                 static_cast<unsigned>(std::numeric_limits<int>::max())) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "The offset " + String::Number(offset) + " is invalid.");
      }
      return nullptr;
    case Node::kProcessingInstructionNode:
      if (offset > To<ProcessingInstruction>(n)->data().length()) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "The offset " + String::Number(offset) +
                " is larger than the node's length (" +
                String::Number(To<ProcessingInstruction>(n)->data().length()) +
                ").");
      } else if (offset >
                 static_cast<unsigned>(std::numeric_limits<int>::max())) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "The offset " + String::Number(offset) + " is invalid.");
      }
      return nullptr;
    case Node::kAttributeNode:
    case Node::kDocumentFragmentNode:
    case Node::kDocumentNode:
    case Node::kElementNode: {
      if (!offset)
        return nullptr;
      if (offset > static_cast<unsigned>(std::numeric_limits<int>::max())) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "The offset " + String::Number(offset) + " is invalid.");
        return nullptr;
      }
      Node* child_before = NodeTraversal::ChildAt(*n, offset - 1);
      if (!child_before) {
        exception_state.ThrowDOMException(
            DOMExceptionCode::kIndexSizeError,
            "There is no child at offset " + String::Number(offset) + ".");
      }
      return child_before;
    }
  }
  NOTREACHED();
}

void Range::CheckNodeBA(Node* n, ExceptionState& exception_state) const {
  if (!n) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return;
  }

  // InvalidNodeTypeError: Raised if the root container of refNode is not an
  // Attr, Document, DocumentFragment or ShadowRoot node, or part of a SVG
  // shadow DOM tree, or if refNode is a Document, DocumentFragment, ShadowRoot,
  // Attr, Entity, or Notation node.

  if (!n->parentNode()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidNodeTypeError,
                                      "the given Node has no parent.");
    return;
  }

  switch (n->getNodeType()) {
    case Node::kAttributeNode:
    case Node::kDocumentFragmentNode:
    case Node::kDocumentNode:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidNodeTypeError,
          "The node provided is of type '" + n->nodeName() + "'.");
      return;
    case Node::kCdataSectionNode:
    case Node::kCommentNode:
    case Node::kDocumentTypeNode:
    case Node::kElementNode:
    case Node::kProcessingInstructionNode:
    case Node::kTextNode:
      break;
  }

  Node* root = n;
  while (ContainerNode* parent = root->parentNode())
    root = parent;

  switch (root->getNodeType()) {
    case Node::kAttributeNode:
    case Node::kDocumentNode:
    case Node::kDocumentFragmentNode:
    case Node::kElementNode:
      break;
    case Node::kCdataSectionNode:
    case Node::kCommentNode:
    case Node::kDocumentTypeNode:
    case Node::kProcessingInstructionNode:
    case Node::kTextNode:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidNodeTypeError,
          "The node provided is of type '" + n->nodeName() + "'.");
      return;
  }
}

Range* Range::cloneRange() const {
  return MakeGarbageCollected<Range>(*owner_document_.Get(),
                                     &start_.Container(), start_.Offset(),
                                     &end_.Container(), end_.Offset());
}

void Range::setStartAfter(Node* ref_node, ExceptionState& exception_state) {
  CheckNodeBA(ref_node, exception_state);
  if (exception_state.HadException())
    return;

  setStart(ref_node->parentNode(), ref_node->NodeIndex() + 1, exception_state);
}

void Range::setEndBefore(Node* ref_node, ExceptionState& exception_state) {
  CheckNodeBA(ref_node, exception_state);
  if (exception_state.HadException())
    return;

  setEnd(ref_node->parentNode(), ref_node->NodeIndex(), exception_state);
}

void Range::setEndAfter(Node* ref_node, ExceptionState& exception_state) {
  CheckNodeBA(ref_node, exception_state);
  if (exception_state.HadException())
    return;

  setEnd(ref_node->parentNode(), ref_node->NodeIndex() + 1, exception_state);
}

void Range::selectNode(Node* ref_node, ExceptionState& exception_state) {
  if (!ref_node) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return;
  }

  if (!ref_node->parentNode()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidNodeTypeError,
                                      "the given Node has no parent.");
    return;
  }

  switch (ref_node->getNodeType()) {
    case Node::kCdataSectionNode:
    case Node::kCommentNode:
    case Node::kDocumentTypeNode:
    case Node::kElementNode:
    case Node::kProcessingInstructionNode:
    case Node::kTextNode:
      break;
    case Node::kAttributeNode:
    case Node::kDocumentFragmentNode:
    case Node::kDocumentNode:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidNodeTypeError,
          "The node provided is of type '" + ref_node->nodeName() + "'.");
      return;
  }

  RangeUpdateScope scope(this);
  setStartBefore(ref_node);
  setEndAfter(ref_node);
}

void Range::selectNodeContents(Node* ref_node,
                               ExceptionState& exception_state) {
  if (!ref_node) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return;
  }

  // InvalidNodeTypeError: Raised if refNode or an ancestor of refNode is an
  // Entity, Notation
  // or DocumentType node.
  for (Node* n = ref_node; n; n = n->parentNode()) {
    switch (n->getNodeType()) {
      case Node::kAttributeNode:
      case Node::kCdataSectionNode:
      case Node::kCommentNode:
      case Node::kDocumentFragmentNode:
      case Node::kDocumentNode:
      case Node::kElementNode:
      case Node::kProcessingInstructionNode:
      case Node::kTextNode:
        break;
      case Node::kDocumentTypeNode:
        exception_state.ThrowDOMException(
            DOMExceptionCode::kInvalidNodeTypeError,
            "The node provided is of type '" + ref_node->nodeName() + "'.");
        return;
    }
  }

  RangeUpdateScope scope(this);
  if (owner_document_ != ref_node->GetDocument())
    SetDocument(ref_node->GetDocument());

  start_.SetToStartOfNode(*ref_node);
  end_.SetToEndOfNode(*ref_node);
}

bool Range::selectNodeContents(Node* ref_node, Position& start, Position& end) {
  if (!ref_node) {
    return false;
  }

  for (Node* n = ref_node; n; n = n->parentNode()) {
    switch (n->getNodeType()) {
      case Node::kAttributeNode:
      case Node::kCdataSectionNode:
      case Node::kCommentNode:
      case Node::kDocumentFragmentNode:
      case Node::kDocumentNode:
      case Node::kElementNode:
      case Node::kProcessingInstructionNode:
      case Node::kTextNode:
        break;
      case Node::kDocumentTypeNode:
        return false;
    }
  }

  RangeBoundaryPoint start_boundary_point(*ref_node);
  start_boundary_point.SetToStartOfNode(*ref_node);
  start = start_boundary_point.ToPosition();
  RangeBoundaryPoint end_boundary_point(*ref_node);
  end_boundary_point.SetToEndOfNode(*ref_node);
  end = end_boundary_point.ToPosition();
  return true;
}

// https://dom.spec.whatwg.org/#dom-range-surroundcontents
void Range::surroundContents(Node* new_parent,
                             ExceptionState& exception_state) {
  if (!new_parent) {
    // FIXME: Generated bindings code never calls with null, and neither should
    // other callers!
    exception_state.ThrowTypeError("The node provided is null.");
    return;
  }

  // 1. If a non-Text node is partially contained in the context object, then
  // throw an InvalidStateError.
  Node* start_node = &start_.Container();
  Node* end_node = &end_.Container();
  if (start_node->IsTextNode()) {
    start_node = start_node->parentNode();
  }
  if (end_node->IsTextNode()) {
    end_node = end_node->parentNode();
  }
  if (start_node != end_node) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "The Range has partially selected a non-Text node.");
    return;
  }

  // 2. If newParent is a Document, DocumentType, or DocumentFragment node, then
  // throw an InvalidNodeTypeError.
  switch (new_parent->getNodeType()) {
    case Node::kAttributeNode:
    case Node::kDocumentFragmentNode:
    case Node::kDocumentNode:
    case Node::kDocumentTypeNode:
      exception_state.ThrowDOMException(
          DOMExceptionCode::kInvalidNodeTypeError,
          "The node provided is of type '" + new_parent->nodeName() + "'.");
      return;
    case Node::kCdataSectionNode:
    case Node::kCommentNode:
    case Node::kElementNode:
    case Node::kProcessingInstructionNode:
    case Node::kTextNode:
      break;
  }

  EventQueueScope scope;

  // 3. Let fragment be the result of extracting context object.
  DocumentFragment* fragment = extractContents(exception_state);
  if (exception_state.HadException())
    return;

  // 4. If newParent has children, replace all with null within newParent.
  while (Node* n = new_parent->firstChild()) {
    To<ContainerNode>(new_parent)->RemoveChild(n, exception_state);
    if (exception_state.HadException())
      return;
  }

  // 5. If newParent has children, replace all with null within newParent.
  insertNode(new_parent, exception_state);
  if (exception_state.HadException())
    return;

  // 6. Append fragment to newParent.
  new_parent->appendChild(fragment, exception_state);
  if (exception_state.HadException())
    return;

  // 7. Select newParent within context object.
  selectNode(new_parent, exception_state);
}

void Range::setStartBefore(Node* ref_node, ExceptionState& exception_state) {
  CheckNodeBA(ref_node, exception_state);
  if (exception_state.HadException())
    return;

  setStart(ref_node->parentNode(), ref_node->NodeIndex(), exception_state);
}

void Range::CheckExtractPrecondition(ExceptionState& exception_state) {
  DCHECK(BoundaryPointsValid());

  if (!commonAncestorContainer())
    return;

  Node* past_last = PastLastNode();
  for (Node* n = FirstNode(); n != past_last; n = NodeTraversal::Next(*n)) {
    if (n->IsDocumentTypeNode()) {
      exception_state.ThrowDOMException(
          DOMExceptionCode::kHierarchyRequestError,
          "The Range contains a doctype node.");
      return;
    }
  }
}

Node* Range::FirstNode() const {
  return StartPosition().NodeAsRangeFirstNode();
}

Node* Range::PastLastNode() const {
  return EndPosition().NodeAsRangePastLastNode();
}

gfx::Rect Range::BoundingBox() const {
  return ComputeTextRect(EphemeralRange(this));
}

bool AreRangesEqual(const Range* a, const Range* b) {
  if (a == b)
    return true;
  if (!a || !b)
    return false;
  return a->StartPosition() == b->StartPosition() &&
         a->EndPosition() == b->EndPosition();
}

static inline void BoundaryNodeChildrenWillBeRemoved(
    RangeBoundaryPoint& boundary,
    ContainerNode& container) {
  if (container.contains(&boundary.Container())) {
    boundary.SetToStartOfNode(container);
  }
}

static void BoundaryShadowNodeChildrenWillBeRemoved(
    RangeBoundaryPoint& boundary,
    ContainerNode& container) {
  if (boundary.Container().IsDescendantOrShadowDescendantOf(&container)) {
    boundary.SetToStartOfNode(container);
  }
}

void Range::NodeChildrenWillBeRemoved(ContainerNode& container) {
  DCHECK_EQ(container.GetDocument(), owner_document_);
  BoundaryNodeChildrenWillBeRemoved(start_, container);
  BoundaryNodeChildrenWillBeRemoved(end_, container);
}

void Range::FixupRemovedChildrenAcrossShadowBoundary(ContainerNode& container) {
  DCHECK_EQ(container.GetDocument(), owner_document_);
  BoundaryShadowNodeChildrenWillBeRemoved(start_, container);
  BoundaryShadowNodeChildrenWillBeRemoved(end_, container);
}

// Returns true if `boundary` was modified.
static inline bool BoundaryNodeWillBeRemoved(RangeBoundaryPoint& boundary,
                                             Node& node_to_be_removed) {
  if (boundary.ChildBefore() == node_to_be_removed) {
    boundary.ChildBeforeWillBeRemoved();
    return true;
  }

  for (Node* n = &boundary.Container(); n; n = n->parentNode()) {
    if (n == node_to_be_removed) {
      boundary.SetToBeforeChild(node_to_be_removed);
      return true;
    }
  }
  return false;
}

static inline void BoundaryShadowNodeWillBeRemoved(RangeBoundaryPoint& boundary,
                                                   Node& node_to_be_removed) {
  DCHECK_NE(boundary.ChildBefore(), node_to_be_removed);

  for (Node* node = &boundary.Container(); node;
       node = node->ParentOrShadowHostElement()) {
    if (node == node_to_be_removed) {
      boundary.SetToBeforeChild(node_to_be_removed);
      return;
    }
  }
}

void Range::NodeWillBeRemoved(Node& node) {
  DCHECK_EQ(node.GetDocument(), owner_document_);
  DCHECK_NE(node, owner_document_.Get());

  // FIXME: Once DOMNodeRemovedFromDocument mutation event removed, we
  // should change following if-statement to DCHECK(!node->parentNode).
  if (!node.parentNode())
    return;
  const bool is_collapsed = collapsed();
  const bool start_updated = BoundaryNodeWillBeRemoved(start_, node);
  if (is_collapsed) {
    if (start_updated)
      end_ = start_;
  } else {
    BoundaryNodeWillBeRemoved(end_, node);
  }
}

void Range::FixupRemovedNodeAcrossShadowBoundary(Node& node) {
  BoundaryShadowNodeWillBeRemoved(start_, node);
  BoundaryShadowNodeWillBeRemoved(end_, node);
}

static inline void BoundaryTextInserted(RangeBoundaryPoint& boundary,
                                        const CharacterData& text,
                                        unsigned offset,
                                        unsigned length) {
  if (boundary.Container() != &text)
    return;
  boundary.MarkValid();
  unsigned boundary_offset = boundary.Offset();
  if (offset >= boundary_offset)
    return;
  boundary.SetOffset(boundary_offset + length);
}

void Range::DidInsertText(const CharacterData& text,
                          unsigned offset,
                          unsigned length) {
  DCHECK_EQ(text.GetDocument(), owner_document_);
  BoundaryTextInserted(start_, text, offset, length);
  BoundaryTextInserted(end_, text, offset, length);
}

static inline void BoundaryTextRemoved(RangeBoundaryPoint& boundary,
                                       const CharacterData& text,
                                       unsigned offset,
                                       unsigned length) {
  if (boundary.Container() != &text)
    return;
  boundary.MarkValid();
  unsigned boundary_offset = boundary.Offset();
  if (offset >= boundary_offset)
    return;
  if (offset + length >= boundary_offset)
    boundary.SetOffset(offset);
  else
    boundary.SetOffset(boundary_offset - length);
}

void Range::DidRemoveText(const CharacterData& text,
                          unsigned offset,
                          unsigned length) {
  DCHECK_EQ(text.GetDocument(), owner_document_);
  BoundaryTextRemoved(start_, text, offset, length);
  BoundaryTextRemoved(end_, text, offset, length);
}

static inline void BoundaryTextNodesMerged(RangeBoundaryPoint& boundary,
                                           const NodeWithIndex& old_node,
                                           unsigned offset) {
  if (boundary.Container() == old_node.GetNode()) {
    Node* const previous_sibling = old_node.GetNode().previousSibling();
    DCHECK(previous_sibling);
    boundary.Set(*previous_sibling, boundary.Offset() + offset, nullptr);
  } else if (boundary.Container() == old_node.GetNode().parentNode() &&
             boundary.Offset() == static_cast<unsigned>(old_node.Index())) {
    Node* const previous_sibling = old_node.GetNode().previousSibling();
    DCHECK(previous_sibling);
    boundary.Set(*previous_sibling, offset, nullptr);
  }
}

void Range::DidMergeTextNodes(const NodeWithIndex& old_node, unsigned offset) {
  DCHECK_EQ(old_node.GetNode().GetDocument(), owner_document_);
  DCHECK(old_node.GetNode().parentNode());
  DCHECK(old_node.GetNode().IsTextNode());
  DCHECK(old_node.GetNode().previousSibling());
  DCHECK(old_node.GetNode().previousSibling()->IsTextNode());
  BoundaryTextNodesMerged(start_, old_node, offset);
  BoundaryTextNodesMerged(end_, old_node, offset);
}

void Range::UpdateOwnerDocumentIfNeeded() {
  Document& new_document = start_.Container().GetDocument();
  DCHECK_EQ(new_document, end_.Container().GetDocument());
  if (new_document == owner_document_)
    return;
  owner_document_->DetachRange(this);
  owner_document_ = &new_document;
  owner_document_->AttachRange(this);
}

static inline void BoundaryTextNodeSplit(RangeBoundaryPoint& boundary,
                                         const Text& old_node) {
  unsigned boundary_offset = boundary.Offset();
  if (boundary.ChildBefore() == &old_node) {
    boundary.Set(boundary.Container(), boundary_offset + 1,
                 old_node.nextSibling());
  } else if (boundary.Container() == &old_node &&
             boundary_offset > old_node.length()) {
    Node* const next_sibling = old_node.nextSibling();
    DCHECK(next_sibling);
    boundary.Set(*next_sibling, boundary_offset - old_node.length(), nullptr);
  }
}

void Range::DidSplitTextNode(const Text& old_node) {
  DCHECK_EQ(old_node.GetDocument(), owner_document_);
  DCHECK(old_node.parentNode());
  DCHECK(old_node.nextSibling());
  DCHECK(old_node.nextSibling()->IsTextNode());
  BoundaryTextNodeSplit(start_, old_node);
  BoundaryTextNodeSplit(end_, old_node);
  DCHECK(BoundaryPointsValid());
}

void Range::expand(const String& unit, ExceptionState& exception_state) {
  if (!StartPosition().IsConnected() || !EndPosition().IsConnected())
    return;
  owner_document_->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);
  VisiblePosition start = CreateVisiblePosition(StartPosition());
  VisiblePosition end = CreateVisiblePosition(EndPosition());
  if (unit == "word") {
    start = CreateVisiblePosition(StartOfWordPosition(start.DeepEquivalent()));
    end = CreateVisiblePosition(EndOfWordPosition(end.DeepEquivalent()));
  } else if (unit == "sentence") {
    start =
        CreateVisiblePosition(StartOfSentencePosition(start.DeepEquivalent()));
    end = CreateVisiblePosition(EndOfSentence(end.DeepEquivalent()));
  } else if (unit == "block") {
    start = StartOfParagraph(start);
    end = EndOfParagraph(end);
  } else if (unit == "document") {
    start = CreateVisiblePosition(StartOfDocument(start.DeepEquivalent()));
    end = EndOfDocument(end);
  } else {
    return;
  }
  setStart(start.DeepEquivalent().ComputeContainerNode(),
           start.DeepEquivalent().ComputeOffsetInContainerNode(),
           exception_state);
  setEnd(end.DeepEquivalent().ComputeContainerNode(),
         end.DeepEquivalent().ComputeOffsetInContainerNode(), exception_state);
}

DOMRectList* Range::getClientRects() const {
  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();
  DisplayLockUtilities::ScopedForcedUpdate force_locks(
      this, DisplayLockContext::ForcedPhase::kLayout);
  owner_document_->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  Vector<gfx::QuadF> quads;
  GetBorderAndTextQuads(quads);

  return MakeGarbageCollected<DOMRectList>(quads);
}

DOMRect* Range::getBoundingClientRect() const {
  // TODO(crbug.com/1499981): This should be removed once synchronized scrolling
  // impact is understood.
  SyncScrollAttemptHeuristic::DidAccessScrollOffset();
  return DOMRect::FromRectF(BoundingRect());
}

// TODO(editing-dev): We should make
// |Document::AdjustQuadsForScrollAndAbsoluteZoom()| as const function
// and takes |const LayoutObject&|.
static Vector<gfx::QuadF> ComputeTextQuads(const Document& owner_document,
                                           const LayoutText& layout_text,
                                           unsigned start_offset,
                                           unsigned end_offset) {
  Vector<gfx::QuadF> text_quads;
  layout_text.AbsoluteQuadsForRange(text_quads, start_offset, end_offset);
  const_cast<Document&>(owner_document)
      .AdjustQuadsForScrollAndAbsoluteZoom(
          text_quads, const_cast<LayoutText&>(layout_text));
  return text_quads;
}

// https://www.w3.org/TR/cssom-view-1/#dom-range-getclientrects
void Range::GetBorderAndTextQuads(Vector<gfx::QuadF>& quads) const {
  Node* start_container = &start_.Container();
  Node* end_container = &end_.Container();
  Node* stop_node = PastLastNode();

  // Stores the elements selected by the range.
  HeapHashSet<Member<const Node>> selected_elements;
  for (Node* node = FirstNode(); node != stop_node;
       node = NodeTraversal::Next(*node)) {
    if (!node->IsElementNode())
      continue;
    auto* parent_node = node->parentNode();
    if ((parent_node && selected_elements.Contains(parent_node)) ||
        (!node->contains(start_container) && !node->contains(end_container))) {
      DCHECK_LE(StartPosition(), Position::BeforeNode(*node));
      DCHECK_GE(EndPosition(), Position::AfterNode(*node));
      selected_elements.insert(node);
    }
  }

  for (const Node* node = FirstNode(); node != stop_node;
       node = NodeTraversal::Next(*node)) {
    auto* element_node = DynamicTo<Element>(node);
    if (element_node) {
      if (!selected_elements.Contains(node) ||
          selected_elements.Contains(node->parentNode()))
        continue;
      LayoutObject* const layout_object = element_node->GetLayoutObject();
      if (!layout_object)
        continue;
      Vector<gfx::QuadF> element_quads;
      layout_object->AbsoluteQuads(element_quads);
      owner_document_->AdjustQuadsForScrollAndAbsoluteZoom(element_quads,
                                                           *layout_object);

      quads.AppendVector(element_quads);
      continue;
    }

    auto* const text_node = DynamicTo<Text>(node);
    if (!text_node)
      continue;
    LayoutText* const layout_text = text_node->GetLayoutObject();
    if (!layout_text)
      continue;

    // TODO(editing-dev): Offset in |LayoutText| doesn't match to DOM offset
    // when |text-transform| applied. We should map DOM offset to offset in
    // |LayouText| for |start_offset| and |end_offset|.
    const unsigned start_offset =
        (node == start_container) ? start_.Offset() : 0;
    const unsigned end_offset = (node == end_container)
                                    ? end_.Offset()
                                    : std::numeric_limits<unsigned>::max();
    if (!layout_text->IsTextFragment()) {
      quads.AppendVector(ComputeTextQuads(*owner_document_, *layout_text,
                                          start_offset, end_offset));
      continue;
    }

    // Handle ::first-letter
    const auto& first_letter_part =
        *To<LayoutTextFragment>(AssociatedLayoutObjectOf(*node, 0));
    const bool overlaps_with_first_letter =
        start_offset < first_letter_part.FragmentLength() ||
        (start_offset == first_letter_part.FragmentLength() &&
         end_offset == start_offset);
    if (overlaps_with_first_letter) {
      const unsigned start_in_first_letter = start_offset;
      const unsigned end_in_first_letter =
          std::min(end_offset, first_letter_part.FragmentLength());
      quads.AppendVector(ComputeTextQuads(*owner_document_, first_letter_part,
                                          start_in_first_letter,
                                          end_in_first_letter));
    }
    const auto& remaining_part = *To<LayoutTextFragment>(layout_text);
    if (end_offset > remaining_part.Start()) {
      const unsigned start_in_remaining_part =
          std::max(start_offset, remaining_part.Start()) -
          remaining_part.Start();
      // TODO(editing-dev): As we previously set |end_offset == UINT_MAX| as a
      // hacky support for |text-transform|, we need the same hack here.
      const unsigned end_in_remaining_part =
          end_offset == UINT_MAX ? end_offset
                                 : end_offset - remaining_part.Start();
      quads.AppendVector(ComputeTextQuads(*owner_document_, remaining_part,
                                          start_in_remaining_part,
                                          end_in_remaining_part));
    }
  }
}

gfx::RectF Range::BoundingRect() const {
  std::optional<DisplayLockUtilities::ScopedForcedUpdate> force_locks;
  if (!collapsed()) {
    force_locks = DisplayLockUtilities::ScopedForcedUpdate(
        this, DisplayLockContext::ForcedPhase::kLayout);
  } else {
    force_locks = DisplayLockUtilities::ScopedForcedUpdate(
        FirstNode(), DisplayLockContext::ForcedPhase::kLayout);
  }
  owner_document_->UpdateStyleAndLayout(DocumentUpdateReason::kJavaScript);

  Vector<gfx::QuadF> quads;
  GetBorderAndTextQuads(quads);

  gfx::RectF result;
  for (const gfx::QuadF& quad : quads)
    result.Union(quad.BoundingBox());  // Skips empty rects.

  // If all rects are empty, return the first rect.
  if (result.IsEmpty() && !quads.empty())
    return quads.front().BoundingBox();

  return result;
}

void Range::UpdateSelectionIfAddedToSelection() {
  if (!OwnerDocument().GetFrame())
    return;
  FrameSelection& selection = OwnerDocument().GetFrame()->Selection();
  if (this != selection.DocumentCachedRange())
    return;
  DCHECK(startContainer()->isConnected());
  DCHECK(startContainer()->GetDocument() == OwnerDocument());
  DCHECK(endContainer()->isConnected());
  DCHECK(endContainer()->GetDocument() == OwnerDocument());
  EventDispatchForbiddenScope no_events;
  selection.SetSelection(SelectionInDOMTree::Builder()
                             .Collapse(StartPosition())
                             .Extend(EndPosition())
                             .Build(),
                         SetSelectionOptions::Builder()
                             .SetShouldCloseTyping(true)
                             .
```