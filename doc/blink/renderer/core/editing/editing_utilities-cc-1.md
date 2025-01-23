Response:
Let's break down the thought process for analyzing this code snippet.

**1. Understanding the Request:**

The core request is to analyze a specific C++ source file within the Chromium Blink engine (`editing_utilities.cc`). The key is to identify the file's purpose, its relationships to web technologies (JavaScript, HTML, CSS), provide examples, infer logic, point out potential errors, and explain how a user action might lead to this code being executed. Importantly, it's the *second* part of a larger file analysis.

**2. Initial Code Scan & Keyword Recognition:**

The first step is a quick scan for common programming patterns and recognizable terms related to web editing:

* **Functions with names like `EnclosingBlock`, `DirectionOfEnclosingBlockOf`, `TableElementJustBefore`, `PositionBeforeNode`, `PositionAfterNode`:** These clearly deal with traversing the document structure and identifying specific elements.
* **Functions dealing with `Position` and `VisiblePosition`:** These are core concepts in Blink's editing model, representing locations within the document.
* **Functions like `IsHTMLListElement`, `IsListItem`, `IsPresentationalHTMLElement`:**  These are type checks for specific HTML elements, directly linking to HTML structure.
* **Functions like `StringWithRebalancedWhitespace`, `RepeatString`:** These relate to string manipulation, likely for text editing.
* **Functions with `CreateTabSpanElement`:** This indicates handling of tab characters within editable content.
* **Functions like `UserSelectContainBoundaryOf`, `PositionRespectingEditingBoundary`, `AdjustForEditingBoundary`:** These seem related to selection and editing boundaries, possibly for handling nested editable regions.
* **Functions involving `InputEvent` and `DispatchBeforeInput...`:** This strongly suggests interaction with the browser's event system for handling user input related to editing.
* **Templates (`template <typename Strategy>`)**: This signifies the use of different strategies for traversing the DOM (e.g., flat tree vs. DOM tree), hinting at different use cases within the editing system.

**3. Grouping Functionality by Theme:**

Based on the keywords and function names, I can start grouping the functions by their apparent purpose:

* **DOM Traversal & Element Identification:**  `EnclosingBlock`, `EnclosingBlockFlowElement`, `EnclosingTableCell`, `EnclosingElementWithTag`, `EnclosingAnchorElement`, `EnclosingNodeOfType`, `HighestEnclosingNodeOfType`, `TableElementJustBefore`, `TableElementJustAfter`, `AssociatedElementOf`.
* **Position Manipulation:** `PositionBeforeNode`, `PositionAfterNode`, `PositionRespectingEditingBoundary`, `AdjustForEditingBoundary`, `ComputePlaceholderToCollapseAt`, `ComputePositionForNodeRemoval`.
* **Text Direction:** `DirectionOfEnclosingBlockOf`, `PrimaryDirectionOf`.
* **String Manipulation for Editing:** `StringWithRebalancedWhitespace`, `RepeatString`.
* **List Handling:** `IsHTMLListElement`, `IsListItem`, `IsListItemTag`, `IsListElementTag`.
* **Formatting/Presentational Elements:** `IsPresentationalHTMLElement`.
* **Tab Handling:** `IsTabHTMLSpanElement`, `CreateTabSpanElement`.
* **Selection & Range Manipulation:** `IndexForVisiblePosition`, `VisiblePositionForIndex`, `MakeRange`, `NormalizeRange`, `AreSameRanges`.
* **Element Type Checks:** `IsDisplayInsideTable`, `IsTableCell`, `IsMailHTMLBlockquoteElement`, `ElementCannotHaveEndTag`, `IsRenderedAsNonInlineTableImageOrHR`, `IsNonTableCellHTMLBlockElement`, `IsBlockFlowElement`, `IsInPasswordField`.
* **Input Event Handling:** `TargetRangesForInputEvent`, `DispatchBeforeInputInsertText`, `DispatchBeforeInputEditorCommand`, `DispatchBeforeInputDataTransfer`, `InsertTextAndSendInputEventsOfTypeInsertReplacementText`.
* **Grapheme Boundary Calculation:** `ComputeDistanceToLeftGraphemeBoundary`, `ComputeDistanceToRightGraphemeBoundary`.
* **Coordinate Conversion:** `LocalToAbsoluteQuadOf`.
* **Placeholder Handling:** `IsInPlaceholder`, `ComputePlaceholderToCollapseAt`.
* **User-Select Containment:** `UserSelectContainBoundaryOf`.
* **Default Paragraph Creation:** `CreateDefaultParagraphElement`.

**4. Identifying Relationships to Web Technologies:**

Now, connect the function groups to JavaScript, HTML, and CSS:

* **HTML:**  Functions checking for specific HTML tags (`IsHTMLListElement`, `IsListItemTag`, etc.) are directly related to HTML structure. Functions manipulating element attributes (like `setAttribute` in `CreateTabSpanElement`) also relate to HTML.
* **CSS:** Functions like `DirectionOfEnclosingBlockOf` rely on the `direction` CSS property. `IsBlockFlowElement` is based on CSS display properties. The `CreateTabSpanElement` sets the `white-space:pre` CSS property. `UserSelectContainBoundaryOf` deals with the `user-select` CSS property (though it notes it's not fully implemented).
* **JavaScript:** The `DispatchBeforeInput...` functions are part of the Input Events API, which is heavily used by JavaScript to handle user input. The concept of `StaticRangeVector` relates to JavaScript's `StaticRange` object. The manipulation of selections (`VisiblePosition`, `EphemeralRange`) is fundamental to how JavaScript interacts with editable content.

**5. Inferring Logic and Providing Examples:**

For key functions, consider their inputs and outputs. For instance, `EnclosingBlock` takes a `Node` and returns the containing block-level element. I can create hypothetical DOM structures to illustrate this:

* **Input:** A `<span>` element nested within a `<p>` element.
* **Output:** The `<p>` element.

Similarly, for `StringWithRebalancedWhitespace`, I can imagine scenarios where whitespace needs adjustment based on context (start/end of paragraph).

**6. Identifying Potential Errors and User Actions:**

Think about common user actions that might trigger these functions and how errors could arise:

* **Incorrect Cursor Placement:**  Functions like `EnclosingBlock` rely on accurate cursor positions. A bug in cursor placement logic could lead to incorrect results.
* **Unexpected DOM Structure:** If the DOM is malformed or doesn't conform to expected structures, functions relying on ancestry or specific element types might fail.
* **CSS Conflicts:**  CSS properties like `display` can affect whether an element is considered a block. Conflicts could lead to unexpected behavior in functions like `EnclosingBlock`.
* **JavaScript Interference:** JavaScript code manipulating the DOM or selections could interfere with the assumptions made by these utility functions.
* **Pasting Content:** The `DispatchBeforeInputDataTransfer` function is directly involved in handling pasted content. Malformed or unexpected pasted data could lead to errors.

**7. Tracing User Actions (Debugging Clues):**

Think about what a user would do to end up in this code:

* **Typing Text:**  This would trigger input events and potentially involve functions like `DispatchBeforeInputInsertText`.
* **Pasting Content:**  This would lead to `DispatchBeforeInputDataTransfer`.
* **Selecting Text:**  Functions related to `VisiblePosition` and `EphemeralRange` would be involved.
* **Moving the Cursor:**  Functions that determine enclosing elements based on the cursor position would be called.
* **Creating Lists or Tables:** Functions checking for list and table elements would be used.
* **Using Formatting Options (Bold, Italics):** Functions related to presentational HTML elements might be involved.

**8. Focus on Part 2:**

Since the request specifies "Part 2," I need to ensure the summary focuses on the functionality present *in this specific snippet*. I avoid drawing conclusions about parts of the file not shown.

**9. Refinement and Clarity:**

Finally, review and refine the analysis. Ensure the explanations are clear, concise, and use appropriate terminology. Provide concrete examples where possible. Structure the answer logically, grouping related functionalities.

This iterative process of scanning, grouping, connecting, inferring, and considering errors helps to create a comprehensive analysis of the given code snippet.
这是 blink/renderer/core/editing/editing_utilities.cc 文件的第二部分，主要包含了一系列用于编辑功能的实用工具函数。总结一下这部分的功能：

**核心功能归纳:**

这部分代码主要提供了一系列用于处理和操作文档中元素、位置、文本方向、以及编辑事件的辅助函数。 这些函数旨在简化和统一 Blink 编辑器核心功能的实现。

**具体功能细分:**

1. **查找封闭块级元素:**
   - `EnclosingBlock()`:  多个重载版本，用于查找包含给定节点或位置的最近的块级元素。它考虑了编辑边界，可以控制是否跨越可编辑区域。
   - `EnclosingBlockFlowElement()`: 查找包含给定节点的最近的块级流动元素 (block flow element)，包括 `<body>` 元素。
   - **与 HTML 和 CSS 的关系:** 块级元素是 HTML 结构的基础，其渲染方式受 CSS 的 `display` 属性影响（例如 `block`, `table` 等）。这些函数用于理解内容在页面上的布局。
   - **假设输入与输出:**
      - **输入:** 一个 `<span>` 节点，它位于一个 `<p>` 元素中。
      - **输出:** 指向该 `<p>` 元素的指针。
      - **输入:** 光标在表格的某个单元格内。
      - **输出:** 指向包含该表格的 `<div>` 元素的指针 (假设表格不是最外层的块级元素)。

2. **确定封闭块级元素的文本方向:**
   - `DirectionOfEnclosingBlockOf()`:  确定包含给定位置的块级元素的文本方向 (从左到右 LTR 或从右到左 RTL)。
   - `PrimaryDirectionOf()`:  查找节点及其祖先中第一个块级流动元素的文本方向。
   - **与 HTML 和 CSS 的关系:** 文本方向受 HTML 属性 `dir` 和 CSS 属性 `direction` 影响，对于正确渲染双向文本至关重要。
   - **假设输入与输出:**
      - **输入:** 光标在一个 `<div>` 元素内的文本节点中，该 `<div>` 的 CSS 设置了 `direction: rtl;`。
      - **输出:** `TextDirection::kRtl`。

3. **处理空白字符:**
   - `StringWithRebalancedWhitespace()`:  根据上下文（是否是段落的开始，是否需要在末尾添加 `&nbsp;`）调整字符串中的空白字符。
   - **与 HTML 的关系:**  HTML 中对空白字符的处理有特殊规则，此函数可能用于确保粘贴或插入的文本格式正确。
   - **假设输入与输出:**
      - **输入:** 字符串 "  Hello  World  "，`start_is_start_of_paragraph` 为 true，`should_emit_nbs_pbefore_end` 为 false。
      - **输出:** 可能输出 " Hello World "，移除了多余的前后空格。

4. **重复字符串:**
   - `RepeatString()`:  简单地将给定的字符串重复指定的次数。

5. **查找表格元素:**
   - `TableElementJustBefore()`:  查找给定可见位置之前的表格元素。
   - `TableElementJustAfter()`: 查找给定可见位置之后的表格元素。
   - `EnclosingTableCell()`: 查找包含给定位置的表格单元格元素。
   - **与 HTML 的关系:** 这些函数专门用于处理 HTML 表格结构。

6. **获取节点边界的位置:**
   - `PositionBeforeNode()`: 返回节点开始前的位置。
   - `PositionAfterNode()`: 返回节点结束后位置。

7. **判断元素类型:**
   - `IsHTMLListElement()`: 判断节点是否是列表元素 (`<ul>`, `<ol>`, `<dl>`)。
   - `IsListItem()`: 判断节点是否是列表项 (`<li>`)。
   - `IsListItemTag()`: 判断节点是否是列表项标签 (`<li>`, `<dd>`, `<dt>`)。
   - `IsListElementTag()`: 判断节点是否是列表标签 (`<ul>`, `<ol>`, `<dl>`)。
   - `IsPresentationalHTMLElement()`: 判断节点是否是表示样式的 HTML 元素 (`<u>`, `<s>`, `<i>`, `<b>` 等)。
   - **与 HTML 的关系:** 这些函数用于识别不同类型的 HTML 元素，以便根据元素的语义进行编辑操作。

8. **查找关联的元素和带有特定标签的元素:**
   - `AssociatedElementOf()`: 获取与给定位置关联的元素。
   - `EnclosingElementWithTag()`: 查找包含给定位置且具有特定标签名的祖先元素。

9. **查找特定类型的封闭节点:**
   - `EnclosingNodeOfType()`:  查找包含给定位置且满足特定类型判断函数的最近的祖先节点。
   - `HighestEnclosingNodeOfType()`:  查找包含给定位置且满足特定类型判断函数的最高层级的祖先节点。

10. **查找封闭的链接元素:**
    - `EnclosingAnchorElement()`: 查找包含给定位置的 `<a>` 链接元素。

11. **判断表格显示类型和是否是表格单元格:**
    - `IsDisplayInsideTable()`: 判断节点是否是一个显示类型为 `table` 的元素 (通常是 `<table>`)。
    - `IsTableCell()`: 判断节点是否是表格单元格 (`<td>` 或 `<th>`)。
    - **与 HTML 和 CSS 的关系:** 涉及到 HTML 表格结构以及 CSS 的渲染属性。

12. **创建默认段落元素:**
    - `CreateDefaultParagraphElement()`: 根据编辑器的默认段落分隔符设置（`<p>` 或 `<div>`）创建相应的段落元素。

13. **处理制表符:**
    - `IsTabHTMLSpanElement()`: 判断节点是否是由制表符组成的 `<span>` 元素。
    - `IsTabHTMLSpanElementTextNode()`: 判断节点是否是制表符 `<span>` 元素内的文本节点。
    - `TabSpanElement()`:  如果给定节点是制表符文本节点，则返回其父 `<span>` 元素。
    - `CreateTabSpanElement()`: 创建包含制表符的 `<span>` 元素，并设置 `white-space:pre` 样式。
    - **与 HTML 和 CSS 的关系:**  使用 `<span>` 元素和 CSS 样式来模拟制表符的显示效果。

14. **处理占位符:**
    - `IsInPlaceholder()`: 判断给定位置是否在文本控件的占位符元素内。
    - `ComputePlaceholderToCollapseAt()`:  计算在特定位置插入内容时，应该被折叠的占位符的位置。

15. **处理用户选择包含边界:**
    - `UserSelectContainBoundaryOf()`: 返回具有 `user-select: contain` 行为的边界元素（目前主要指根可编辑元素和文本控件的内部编辑器）。
    - **与 HTML 和 CSS 的关系:**  与 CSS 的 `user-select` 属性相关，用于控制选择的范围。

16. **调整位置以适应编辑边界:**
    - `PositionRespectingEditingBoundary()`:  根据点击测试结果调整位置，使其尊重编辑边界。
    - `AdjustForEditingBoundary()`: 调整给定的位置，确保其位于可编辑区域内。

17. **计算节点移除后的位置:**
    - `ComputePositionForNodeRemoval()`:  计算在移除指定节点后，给定位置应该调整到的新位置。

18. **判断邮件引用的块引用元素:**
    - `IsMailHTMLBlockquoteElement()`: 判断节点是否是用于邮件引用的 `<blockquote>` 元素（具有 `type="cite"` 属性）。

19. **判断元素是否不能有结束标签:**
    - `ElementCannotHaveEndTag()`: 判断给定的节点是否是不能有结束标签的 HTML 元素（例如 `<img>`, `<br>`）。

20. **处理可见位置和索引的转换:**
    - `IndexForVisiblePosition()`: 将可见位置转换为在容器节点内的索引。
    - `VisiblePositionForIndex()`: 将索引转换为可见位置。
    - `MakeRange()`: 根据两个可见位置创建范围。
    - `NormalizeRange()`: 规范化给定的范围。
    - `AreSameRanges()`: 判断节点的所有子节点的范围是否与给定的起始和结束位置一致。

21. **判断元素的渲染特性:**
    - `IsRenderedAsNonInlineTableImageOrHR()`: 判断节点是否被渲染为非内联的表格、图片或水平线。
    - `IsNonTableCellHTMLBlockElement()`: 判断节点是否是非表格单元格的块级 HTML 元素。
    - `IsBlockFlowElement()`: 判断节点是否是块级流动元素。

22. **判断是否在密码输入框内:**
    - `IsInPasswordField()`: 判断给定位置是否在密码输入框 (`<input type="password">`) 内。

23. **计算到左右字形边界的距离:**
    - `ComputeDistanceToLeftGraphemeBoundary()`: 计算当前位置到左侧最近字形边界的距离。
    - `ComputeDistanceToRightGraphemeBoundary()`: 计算当前位置到右侧最近字形边界的距离。

24. **坐标转换:**
    - `LocalToAbsoluteQuadOf()`: 将局部 Caret 矩形转换为绝对坐标的四边形。

25. **事件分发辅助函数 (重要):**
    - `TargetRangesForInputEvent()`: 为输入事件获取目标范围。
    - `DispatchBeforeInputInsertText()`:  分发 `beforeinput` 事件，用于插入文本。
    - `DispatchBeforeInputEditorCommand()`: 分发 `beforeinput` 事件，用于编辑器命令。
    - `DispatchBeforeInputDataTransfer()`: 分发 `beforeinput` 事件，用于数据传输（例如粘贴）。
    - `InsertTextAndSendInputEventsOfTypeInsertReplacementText()`: 插入文本并发送类型为 `insertReplacementText` 的输入事件。
    - **与 JavaScript 的关系:** 这些函数直接关联到浏览器的事件系统，特别是 `beforeinput` 事件，该事件允许 JavaScript 拦截和修改用户的输入操作。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript 和 `DispatchBeforeInputInsertText`:** 当用户在可编辑区域输入 "a" 时，浏览器会触发 `beforeinput` 事件。Blink 的编辑器代码会调用 `DispatchBeforeInputInsertText` 来创建一个 `beforeinput` 事件对象，并将其分发到目标节点。JavaScript 代码可以监听这个事件，并可能阻止默认的插入行为或修改要插入的文本。
* **HTML 和 `EnclosingBlock`:**  如果用户在一个 `<span>` 元素内点击，并且该 `<span>` 元素嵌套在一个 `<p>` 元素和一个 `<div>` 元素中，`EnclosingBlock` 函数可能会被调用来确定包含光标的块级元素是 `<p>` 还是 `<div>`，这取决于具体的调用上下文和编辑边界规则。
* **CSS 和 `DirectionOfEnclosingBlockOf`:** 当需要确定光标所在位置的文本渲染方向时，`DirectionOfEnclosingBlockOf` 会被调用。它会检查包含该位置的块级元素的 CSS `direction` 属性，以判断文本应该是从左到右还是从右到左渲染。

**逻辑推理的假设输入与输出:**

* **假设输入 (对于 `IsHTMLListElement`):** 一个指向 `<ol>` 元素的 `Node*` 指针。
* **输出:** `true`。

* **假设输入 (对于 `EnclosingTableCell`):** 一个 `Position` 对象，表示光标在 `<td>` 元素内的文本节点中。
* **输出:** 指向该 `<td>` 元素的 `Element*` 指针。

**涉及的用户或编程常见的使用错误举例:**

* **错误地假设 `EnclosingBlock` 总是返回最近的父元素:** `EnclosingBlock` 考虑了编辑边界，如果光标在一个非可编辑的子元素内，它可能返回更上层的可编辑块级元素。开发者需要理解 `EditingBoundaryCrossingRule` 参数的作用。
* **忘记处理 `beforeinput` 事件的取消:** 使用 `DispatchBeforeInput...` 分发事件后，如果 JavaScript 代码取消了该事件，编辑器需要根据取消状态进行相应的处理，否则可能会导致用户输入丢失或其他意外行为。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在一个可编辑的 `<div>` 元素中输入文本 "hello"。**
2. **浏览器捕获用户的输入事件。**
3. **Blink 的事件处理机制识别出这是针对可编辑内容的输入。**
4. **在文本真正插入之前，Blink 编辑器的代码会调用 `DispatchBeforeInputInsertText`，传递目标节点（`<div>` 元素）和要插入的文本 "h"。**
5. **`DispatchBeforeInputInsertText` 函数会创建一个 `beforeinput` 事件对象。**
6. **该事件对象被分发到 `<div>` 元素。**
7. **如果页面上有 JavaScript 代码监听了 `beforeinput` 事件，该代码会首先执行。**
8. **如果 `beforeinput` 事件没有被取消，Blink 编辑器的代码会继续执行文本插入操作。**

**总结这部分的功能:**

总而言之，这部分 `editing_utilities.cc` 文件提供了一组核心的、底层的工具函数，用于处理 Blink 编辑器中的各种操作，例如查找元素、处理位置、确定文本方向、处理特殊字符、管理事件等等。 这些函数是构建更高级编辑功能的基础，并且与 HTML 的结构、CSS 的渲染以及 JavaScript 的事件处理机制紧密相关。理解这些工具函数的功能有助于深入理解 Blink 编辑器的内部工作原理。

### 提示词
```
这是目录为blink/renderer/core/editing/editing_utilities.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
|enclosingBlock()| should use
// |Position| version The enclosing block of [table, x] for example, should be
// the block that contains the table and not the table, and this function should
// be the only one responsible for knowing about these kinds of special cases.
Element* EnclosingBlock(const Node* node, EditingBoundaryCrossingRule rule) {
  if (!node)
    return nullptr;
  return EnclosingBlock(FirstPositionInOrBeforeNode(*node), rule);
}

template <typename Strategy>
Element* EnclosingBlockAlgorithm(const PositionTemplate<Strategy>& position,
                                 EditingBoundaryCrossingRule rule) {
  Node* enclosing_node = EnclosingNodeOfType(position, IsEnclosingBlock, rule);
  return DynamicTo<Element>(enclosing_node);
}

Element* EnclosingBlock(const Position& position,
                        EditingBoundaryCrossingRule rule) {
  return EnclosingBlockAlgorithm<EditingStrategy>(position, rule);
}

Element* EnclosingBlock(const PositionInFlatTree& position,
                        EditingBoundaryCrossingRule rule) {
  return EnclosingBlockAlgorithm<EditingInFlatTreeStrategy>(position, rule);
}

Element* EnclosingBlockFlowElement(const Node& node) {
  if (IsBlockFlowElement(node))
    return const_cast<Element*>(To<Element>(&node));

  for (Node& runner : NodeTraversal::AncestorsOf(node)) {
    if (IsBlockFlowElement(runner) || IsA<HTMLBodyElement>(runner))
      return To<Element>(&runner);
  }
  return nullptr;
}

template <typename Strategy>
TextDirection DirectionOfEnclosingBlockOfAlgorithm(
    const PositionTemplate<Strategy>& position) {
  DCHECK(position.IsNotNull());
  Element* enclosing_block_element =
      EnclosingBlock(PositionTemplate<Strategy>::FirstPositionInOrBeforeNode(
                         *position.ComputeContainerNode()),
                     kCannotCrossEditingBoundary);
  if (!enclosing_block_element)
    return TextDirection::kLtr;
  LayoutObject* layout_object = enclosing_block_element->GetLayoutObject();
  return layout_object ? layout_object->Style()->Direction()
                       : TextDirection::kLtr;
}

TextDirection DirectionOfEnclosingBlockOf(const Position& position) {
  return DirectionOfEnclosingBlockOfAlgorithm<EditingStrategy>(position);
}

TextDirection DirectionOfEnclosingBlockOf(const PositionInFlatTree& position) {
  return DirectionOfEnclosingBlockOfAlgorithm<EditingInFlatTreeStrategy>(
      position);
}

TextDirection PrimaryDirectionOf(const Node& node) {
  TextDirection primary_direction = TextDirection::kLtr;
  for (const LayoutObject* r = node.GetLayoutObject(); r; r = r->Parent()) {
    if (r->IsLayoutBlockFlow()) {
      primary_direction = r->Style()->Direction();
      break;
    }
  }

  return primary_direction;
}

String StringWithRebalancedWhitespace(const String& string,
                                      bool start_is_start_of_paragraph,
                                      bool should_emit_nbs_pbefore_end) {
  unsigned length = string.length();

  StringBuilder rebalanced_string;
  rebalanced_string.ReserveCapacity(length);

  UChar char_to_append = 0;
  for (wtf_size_t index = 0; index < length; index++) {
    char_to_append = WhitespaceRebalancingCharToAppend(
        string, start_is_start_of_paragraph, should_emit_nbs_pbefore_end, index,
        char_to_append);
    rebalanced_string.Append(char_to_append);
  }

  DCHECK_EQ(rebalanced_string.length(), length);

  return rebalanced_string.ToString();
}

String RepeatString(const String& string, unsigned count) {
  StringBuilder builder;
  builder.ReserveCapacity(string.length() * count);
  for (unsigned counter = 0; counter < count; ++counter)
    builder.Append(string);
  return builder.ToString();
}

template <typename Strategy>
static Element* TableElementJustBeforeAlgorithm(
    const VisiblePositionTemplate<Strategy>& visible_position) {
  const PositionTemplate<Strategy> upstream(
      MostBackwardCaretPosition(visible_position.DeepEquivalent()));
  if (IsDisplayInsideTable(upstream.AnchorNode()) &&
      upstream.AtLastEditingPositionForNode())
    return To<Element>(upstream.AnchorNode());

  return nullptr;
}

Element* TableElementJustBefore(const VisiblePosition& visible_position) {
  return TableElementJustBeforeAlgorithm<EditingStrategy>(visible_position);
}

Element* TableElementJustBefore(
    const VisiblePositionInFlatTree& visible_position) {
  return TableElementJustBeforeAlgorithm<EditingInFlatTreeStrategy>(
      visible_position);
}

Element* EnclosingTableCell(const Position& p) {
  return To<Element>(EnclosingNodeOfType(p, IsTableCell));
}
Element* EnclosingTableCell(const PositionInFlatTree& p) {
  return To<Element>(EnclosingNodeOfType(p, IsTableCell));
}

Element* TableElementJustAfter(const VisiblePosition& visible_position) {
  Position downstream(
      MostForwardCaretPosition(visible_position.DeepEquivalent()));
  if (IsDisplayInsideTable(downstream.AnchorNode()) &&
      downstream.AtFirstEditingPositionForNode())
    return To<Element>(downstream.AnchorNode());

  return nullptr;
}

// Returns the position at the beginning of a node
Position PositionBeforeNode(const Node& node) {
  DCHECK(!NeedsLayoutTreeUpdate(node));
  if (node.hasChildren())
    return FirstPositionInOrBeforeNode(node);
  DCHECK(node.parentNode()) << node;
  DCHECK(!node.parentNode()->IsShadowRoot()) << node.parentNode();
  return Position::InParentBeforeNode(node);
}

// Returns the position at the ending of a node
Position PositionAfterNode(const Node& node) {
  DCHECK(!NeedsLayoutTreeUpdate(node));
  if (node.hasChildren())
    return LastPositionInOrAfterNode(node);
  DCHECK(node.parentNode()) << node.parentNode();
  DCHECK(!node.parentNode()->IsShadowRoot()) << node.parentNode();
  return Position::InParentAfterNode(node);
}

bool IsHTMLListElement(const Node* n) {
  return (n && (IsA<HTMLUListElement>(*n) || IsA<HTMLOListElement>(*n) ||
                IsA<HTMLDListElement>(*n)));
}

bool IsListItem(const Node* n) {
  return n && n->GetLayoutObject() && n->GetLayoutObject()->IsListItem();
}

bool IsListItemTag(const Node* n) {
  return n && (n->HasTagName(html_names::kLiTag) ||
               n->HasTagName(html_names::kDdTag) ||
               n->HasTagName(html_names::kDtTag));
}

bool IsListElementTag(const Node* n) {
  return n && (n->HasTagName(html_names::kUlTag) ||
               n->HasTagName(html_names::kOlTag) ||
               n->HasTagName(html_names::kDlTag));
}

bool IsPresentationalHTMLElement(const Node* node) {
  const auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return false;

  return element->HasTagName(html_names::kUTag) ||
         element->HasTagName(html_names::kSTag) ||
         element->HasTagName(html_names::kStrikeTag) ||
         element->HasTagName(html_names::kITag) ||
         element->HasTagName(html_names::kEmTag) ||
         element->HasTagName(html_names::kBTag) ||
         element->HasTagName(html_names::kStrongTag);
}

Element* AssociatedElementOf(const Position& position) {
  Node* node = position.AnchorNode();
  if (!node)
    return nullptr;

  if (auto* element = DynamicTo<Element>(node))
    return element;

  ContainerNode* parent = NodeTraversal::Parent(*node);
  return DynamicTo<Element>(parent);
}

Element* EnclosingElementWithTag(const Position& p,
                                 const QualifiedName& tag_name) {
  if (p.IsNull())
    return nullptr;

  ContainerNode* root = HighestEditableRoot(p);
  for (Node& runner : NodeTraversal::InclusiveAncestorsOf(*p.AnchorNode())) {
    auto* ancestor = DynamicTo<Element>(runner);
    if (!ancestor)
      continue;
    if (root && !IsEditable(*ancestor))
      continue;
    if (ancestor->HasTagName(tag_name))
      return ancestor;
    if (ancestor == root)
      return nullptr;
  }

  return nullptr;
}

template <typename Strategy>
static Node* EnclosingNodeOfTypeAlgorithm(const PositionTemplate<Strategy>& p,
                                          bool (*node_is_of_type)(const Node*),
                                          EditingBoundaryCrossingRule rule) {
  // TODO(yosin) support CanSkipCrossEditingBoundary
  DCHECK(rule == kCanCrossEditingBoundary ||
         rule == kCannotCrossEditingBoundary)
      << rule;
  if (p.IsNull())
    return nullptr;

  ContainerNode* const root =
      rule == kCannotCrossEditingBoundary ? RootEditableElementOf(p) : nullptr;
  for (Node* n = p.AnchorNode(); n; n = Strategy::Parent(*n)) {
    // Don't return a non-editable node if the input position was editable,
    // since the callers from editing will no doubt want to perform editing
    // inside the returned node.
    if (root && !IsEditable(*n))
      continue;
    if (node_is_of_type(n))
      return n;
    if (n == root)
      return nullptr;
  }

  return nullptr;
}

Node* EnclosingNodeOfType(const Position& p,
                          bool (*node_is_of_type)(const Node*),
                          EditingBoundaryCrossingRule rule) {
  return EnclosingNodeOfTypeAlgorithm<EditingStrategy>(p, node_is_of_type,
                                                       rule);
}

Node* EnclosingNodeOfType(const PositionInFlatTree& p,
                          bool (*node_is_of_type)(const Node*),
                          EditingBoundaryCrossingRule rule) {
  return EnclosingNodeOfTypeAlgorithm<EditingInFlatTreeStrategy>(
      p, node_is_of_type, rule);
}

Node* HighestEnclosingNodeOfType(const Position& p,
                                 bool (*node_is_of_type)(const Node*),
                                 EditingBoundaryCrossingRule rule,
                                 Node* stay_within) {
  Node* highest = nullptr;
  ContainerNode* root =
      rule == kCannotCrossEditingBoundary ? HighestEditableRoot(p) : nullptr;
  for (Node* n = p.ComputeContainerNode(); n && n != stay_within;
       n = n->parentNode()) {
    if (root && !IsEditable(*n))
      continue;
    if (node_is_of_type(n))
      highest = n;
    if (n == root)
      break;
  }

  return highest;
}

Element* EnclosingAnchorElement(const Position& p) {
  if (p.IsNull())
    return nullptr;

  for (Element* ancestor =
           ElementTraversal::FirstAncestorOrSelf(*p.AnchorNode());
       ancestor; ancestor = ElementTraversal::FirstAncestor(*ancestor)) {
    if (ancestor->IsLink())
      return ancestor;
  }
  return nullptr;
}

bool IsDisplayInsideTable(const Node* node) {
  return node && node->GetLayoutObject() && IsA<HTMLTableElement>(node);
}

bool IsTableCell(const Node* node) {
  DCHECK(node);
  LayoutObject* r = node->GetLayoutObject();
  return r ? r->IsTableCell() : IsA<HTMLTableCellElement>(*node);
}

HTMLElement* CreateDefaultParagraphElement(Document& document) {
  switch (document.GetFrame()->GetEditor().DefaultParagraphSeparator()) {
    case EditorParagraphSeparator::kIsDiv:
      return MakeGarbageCollected<HTMLDivElement>(document);
    case EditorParagraphSeparator::kIsP:
      return MakeGarbageCollected<HTMLParagraphElement>(document);
  }

  NOTREACHED();
}

bool IsTabHTMLSpanElement(const Node* node) {
  const auto* span = DynamicTo<HTMLSpanElement>(node);
  if (!span) {
    return false;
  }
  const Node* const first_child = NodeTraversal::FirstChild(*span);
  auto* first_child_text_node = DynamicTo<Text>(first_child);
  if (!first_child_text_node) {
    return false;
  }
  if (!first_child_text_node->data().Contains('\t')) {
    return false;
  }
  // TODO(editing-dev): Hoist the call of UpdateStyleAndLayoutTree to callers.
  // See crbug.com/590369 for details.
  span->GetDocument().UpdateStyleAndLayoutTree();
  const ComputedStyle* style = span->GetComputedStyle();
  return style && style->WhiteSpace() == EWhiteSpace::kPre;
}

bool IsTabHTMLSpanElementTextNode(const Node* node) {
  return node && node->IsTextNode() && node->parentNode() &&
         IsTabHTMLSpanElement(node->parentNode());
}

HTMLSpanElement* TabSpanElement(const Node* node) {
  return IsTabHTMLSpanElementTextNode(node)
             ? To<HTMLSpanElement>(node->parentNode())
             : nullptr;
}

static HTMLSpanElement* CreateTabSpanElement(Document& document,
                                             Text* tab_text_node) {
  // Make the span to hold the tab.
  auto* span_element = MakeGarbageCollected<HTMLSpanElement>(document);
  span_element->setAttribute(html_names::kStyleAttr,
                             AtomicString("white-space:pre"));

  // Add tab text to that span.
  if (!tab_text_node)
    tab_text_node = document.CreateEditingTextNode("\t");

  span_element->AppendChild(tab_text_node);

  return span_element;
}

HTMLSpanElement* CreateTabSpanElement(Document& document,
                                      const String& tab_text) {
  return CreateTabSpanElement(document, document.createTextNode(tab_text));
}

HTMLSpanElement* CreateTabSpanElement(Document& document) {
  return CreateTabSpanElement(document, nullptr);
}

static bool IsInPlaceholder(const TextControlElement& text_control,
                            const Position& position) {
  const auto* const placeholder_element = text_control.PlaceholderElement();
  if (!placeholder_element)
    return false;
  return placeholder_element->contains(position.ComputeContainerNode());
}

// Returns user-select:contain boundary element of specified position.
// Because of we've not yet implemented "user-select:contain", we consider
// following elements having "user-select:contain"
//  - root editable
//  - inner editor of text control (<input> and <textarea>)
// Note: inner editor of readonly text control isn't content editable.
// TODO(yosin): We should handle elements with "user-select:contain".
// See http:/crbug.com/658129
static Element* UserSelectContainBoundaryOf(const Position& position) {
  if (auto* text_control = EnclosingTextControl(position)) {
    if (IsInPlaceholder(*text_control, position))
      return nullptr;
    // for <input readonly>. See http://crbug.com/185089
    return text_control->InnerEditorElement();
  }
  // Note: Until we implement "user-select:contain", we treat root editable
  // element and text control as having "user-select:contain".
  if (Element* editable = RootEditableElementOf(position))
    return editable;
  return nullptr;
}

PositionWithAffinity PositionRespectingEditingBoundary(
    const Position& position,
    const HitTestResult& hit_test_result) {
  Node* target_node = hit_test_result.InnerPossiblyPseudoNode();
  DCHECK(target_node);
  const LayoutObject* target_object = target_node->GetLayoutObject();
  if (!target_object)
    return PositionWithAffinity();

  Element* editable_element = UserSelectContainBoundaryOf(position);
  if (!editable_element || editable_element->contains(target_node))
    return hit_test_result.GetPosition();

  const LayoutObject* editable_object = editable_element->GetLayoutObject();
  if (!editable_object || !editable_object->VisibleToHitTesting())
    return PositionWithAffinity();

  // TODO(yosin): Is this kIgnoreTransforms correct here?
  PhysicalOffset selection_end_point = hit_test_result.LocalPoint();
  PhysicalOffset absolute_point = target_object->LocalToAbsolutePoint(
      selection_end_point, kIgnoreTransforms);
  selection_end_point =
      editable_object->AbsoluteToLocalPoint(absolute_point, kIgnoreTransforms);
  target_object = editable_object;
  // TODO(kojii): Support fragment-based |PositionForPoint|. LayoutObject-based
  // |PositionForPoint| may not work if NG block fragmented.
  return target_object->PositionForPoint(selection_end_point);
}

PositionWithAffinity AdjustForEditingBoundary(
    const PositionWithAffinity& position_with_affinity) {
  if (position_with_affinity.IsNull())
    return position_with_affinity;
  const Position& position = position_with_affinity.GetPosition();
  const Node& node = *position.ComputeContainerNode();
  if (IsEditable(node))
    return position_with_affinity;
  // TODO(yosin): Once we fix |MostBackwardCaretPosition()| to handle
  // positions other than |kOffsetInAnchor|, we don't need to use
  // |adjusted_position|, e.g. <outer><inner contenteditable> with position
  // before <inner> vs. outer@0[1].
  // [1] editing/selection/click-outside-editable-div.html
  const Position& adjusted_position = IsEditable(*position.AnchorNode())
                                          ? position.ToOffsetInAnchor()
                                          : position;
  const Position& forward =
      MostForwardCaretPosition(adjusted_position, kCanCrossEditingBoundary);
  if (IsEditable(*forward.ComputeContainerNode()))
    return PositionWithAffinity(forward);
  const Position& backward =
      MostBackwardCaretPosition(adjusted_position, kCanCrossEditingBoundary);
  if (IsEditable(*backward.ComputeContainerNode()))
    return PositionWithAffinity(backward);
  return PositionWithAffinity(adjusted_position,
                              position_with_affinity.Affinity());
}

PositionWithAffinity AdjustForEditingBoundary(const Position& position) {
  return AdjustForEditingBoundary(PositionWithAffinity(position));
}

Position ComputePlaceholderToCollapseAt(const Position& insertion_pos) {
  Position placeholder;
  // We want to remove preserved newlines and brs that will collapse (and thus
  // become unnecessary) when content is inserted just before them.
  // FIXME: We shouldn't really have to do this, but removing placeholders is a
  // workaround for 9661.
  // If the caret is just before a placeholder, downstream will normalize the
  // caret to it.
  Position downstream(MostForwardCaretPosition(insertion_pos));
  if (LineBreakExistsAtPosition(downstream)) {
    // FIXME: This doesn't handle placeholders at the end of anonymous blocks.
    VisiblePosition caret = CreateVisiblePosition(insertion_pos);
    if (IsEndOfBlock(caret) && IsStartOfParagraph(caret)) {
      placeholder = downstream;
    }
    // Don't remove the placeholder yet, otherwise the block we're inserting
    // into would collapse before we get a chance to insert into it.  We check
    // for a placeholder now, though, because doing so requires the creation of
    // a VisiblePosition, and if we did that post-insertion it would force a
    // layout.
  }
  return placeholder;
}

Position ComputePositionForNodeRemoval(const Position& position,
                                       const Node& node) {
  if (position.IsNull())
    return position;
  Node* container_node;
  Node* anchor_node;
  switch (position.AnchorType()) {
    case PositionAnchorType::kAfterChildren:
      container_node = position.ComputeContainerNode();
      if (!container_node ||
          !node.IsShadowIncludingInclusiveAncestorOf(*container_node)) {
        return position;
      }
      return Position::InParentBeforeNode(node);
    case PositionAnchorType::kOffsetInAnchor:
      container_node = position.ComputeContainerNode();
      if (container_node == node.parentNode() &&
          static_cast<unsigned>(position.OffsetInContainerNode()) >
              node.NodeIndex()) {
        return Position(container_node, position.OffsetInContainerNode() - 1);
      }
      if (!container_node ||
          !node.IsShadowIncludingInclusiveAncestorOf(*container_node)) {
        return position;
      }
      return Position::InParentBeforeNode(node);
    case PositionAnchorType::kAfterAnchor:
      anchor_node = position.AnchorNode();
      if (!anchor_node ||
          !node.IsShadowIncludingInclusiveAncestorOf(*anchor_node))
        return position;
      return Position::InParentBeforeNode(node);
    case PositionAnchorType::kBeforeAnchor:
      anchor_node = position.AnchorNode();
      if (!anchor_node ||
          !node.IsShadowIncludingInclusiveAncestorOf(*anchor_node))
        return position;
      return Position::InParentBeforeNode(node);
  }
  NOTREACHED() << "We should handle all PositionAnchorType";
}

bool IsMailHTMLBlockquoteElement(const Node* node) {
  const auto* element = DynamicTo<HTMLElement>(*node);
  if (!element)
    return false;

  return element->HasTagName(html_names::kBlockquoteTag) &&
         element->getAttribute(html_names::kTypeAttr) == "cite";
}

bool ElementCannotHaveEndTag(const Node& node) {
  auto* html_element = DynamicTo<HTMLElement>(node);
  if (!html_element)
    return false;

  return !html_element->ShouldSerializeEndTag();
}

// FIXME: indexForVisiblePosition and visiblePositionForIndex use TextIterators
// to convert between VisiblePositions and indices. But TextIterator iteration
// using TextIteratorEmitsCharactersBetweenAllVisiblePositions does not exactly
// match VisiblePosition iteration, so using them to preserve a selection during
// an editing opertion is unreliable. TextIterator's
// TextIteratorEmitsCharactersBetweenAllVisiblePositions mode needs to be fixed,
// or these functions need to be changed to iterate using actual
// VisiblePositions.
// FIXME: Deploy these functions everywhere that TextIterators are used to
// convert between VisiblePositions and indices.
int IndexForVisiblePosition(const VisiblePosition& visible_position,
                            ContainerNode*& scope) {
  if (visible_position.IsNull())
    return 0;

  Position p(visible_position.DeepEquivalent());
  Document& document = *p.GetDocument();
  DCHECK(!document.NeedsLayoutTreeUpdate());

  ShadowRoot* shadow_root = p.AnchorNode()->ContainingShadowRoot();

  if (shadow_root)
    scope = shadow_root;
  else
    scope = document.documentElement();

  EphemeralRange range(Position::FirstPositionInNode(*scope),
                       p.ParentAnchoredEquivalent());

  const TextIteratorBehavior& behavior =
      TextIteratorBehavior::Builder(
          TextIteratorBehavior::AllVisiblePositionsRangeLengthBehavior())
          .SetSuppressesExtraNewlineEmission(true)
          .Build();
  return TextIterator::RangeLength(range.StartPosition(), range.EndPosition(),
                                   behavior);
}

EphemeralRange MakeRange(const VisiblePosition& start,
                         const VisiblePosition& end) {
  if (start.IsNull() || end.IsNull())
    return EphemeralRange();

  Position s = start.DeepEquivalent().ParentAnchoredEquivalent();
  Position e = end.DeepEquivalent().ParentAnchoredEquivalent();
  if (s.IsNull() || e.IsNull())
    return EphemeralRange();

  return EphemeralRange(s, e);
}

template <typename Strategy>
static EphemeralRangeTemplate<Strategy> NormalizeRangeAlgorithm(
    const EphemeralRangeTemplate<Strategy>& range) {
  DCHECK(range.IsNotNull());
  DCHECK(!range.GetDocument().NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      range.GetDocument().Lifecycle());

  // TODO(yosin) We should not call |parentAnchoredEquivalent()|, it is
  // redundant.
  const PositionTemplate<Strategy> normalized_start =
      MostForwardCaretPosition(range.StartPosition())
          .ParentAnchoredEquivalent();
  const PositionTemplate<Strategy> normalized_end =
      MostBackwardCaretPosition(range.EndPosition()).ParentAnchoredEquivalent();
  // The order of the positions of |start| and |end| can be swapped after
  // upstream/downstream. e.g. editing/pasteboard/copy-display-none.html
  if (normalized_start.CompareTo(normalized_end) > 0)
    return EphemeralRangeTemplate<Strategy>(normalized_end, normalized_start);
  return EphemeralRangeTemplate<Strategy>(normalized_start, normalized_end);
}

EphemeralRange NormalizeRange(const EphemeralRange& range) {
  return NormalizeRangeAlgorithm<EditingStrategy>(range);
}

EphemeralRangeInFlatTree NormalizeRange(const EphemeralRangeInFlatTree& range) {
  return NormalizeRangeAlgorithm<EditingInFlatTreeStrategy>(range);
}

VisiblePosition VisiblePositionForIndex(int index, ContainerNode* scope) {
  if (!scope)
    return VisiblePosition();
  DCHECK(!scope->GetDocument().NeedsLayoutTreeUpdate());
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      scope->GetDocument().Lifecycle());

  EphemeralRange range =
      PlainTextRange(index).CreateRangeForSelectionIndexing(*scope);
  // Check for an invalid index. Certain editing operations invalidate indices
  // because of problems with
  // TextIteratorEmitsCharactersBetweenAllVisiblePositions.
  if (range.IsNull())
    return VisiblePosition();
  return CreateVisiblePosition(range.StartPosition());
}

template <typename Strategy>
bool AreSameRangesAlgorithm(Node* node,
                            const PositionTemplate<Strategy>& start_position,
                            const PositionTemplate<Strategy>& end_position) {
  DCHECK(node);
  const EphemeralRange range =
      CreateVisibleSelection(
          SelectionInDOMTree::Builder().SelectAllChildren(*node).Build())
          .ToNormalizedEphemeralRange();
  return ToPositionInDOMTree(start_position) == range.StartPosition() &&
         ToPositionInDOMTree(end_position) == range.EndPosition();
}

bool AreSameRanges(Node* node,
                   const Position& start_position,
                   const Position& end_position) {
  return AreSameRangesAlgorithm<EditingStrategy>(node, start_position,
                                                 end_position);
}

bool AreSameRanges(Node* node,
                   const PositionInFlatTree& start_position,
                   const PositionInFlatTree& end_position) {
  return AreSameRangesAlgorithm<EditingInFlatTreeStrategy>(node, start_position,
                                                           end_position);
}

bool IsRenderedAsNonInlineTableImageOrHR(const Node* node) {
  if (!node)
    return false;
  LayoutObject* layout_object = node->GetLayoutObject();
  if (!layout_object || layout_object->IsInline()) {
    return false;
  }
  return layout_object->IsTable() || layout_object->IsImage() ||
         layout_object->IsHR();
}

bool IsNonTableCellHTMLBlockElement(const Node* node) {
  const auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return false;

  return element->HasTagName(html_names::kListingTag) ||
         element->HasTagName(html_names::kOlTag) ||
         element->HasTagName(html_names::kPreTag) ||
         element->HasTagName(html_names::kTableTag) ||
         element->HasTagName(html_names::kUlTag) ||
         element->HasTagName(html_names::kXmpTag) ||
         element->HasTagName(html_names::kH1Tag) ||
         element->HasTagName(html_names::kH2Tag) ||
         element->HasTagName(html_names::kH3Tag) ||
         element->HasTagName(html_names::kH4Tag) ||
         element->HasTagName(html_names::kH5Tag);
}

bool IsBlockFlowElement(const Node& node) {
  LayoutObject* layout_object = node.GetLayoutObject();
  return node.IsElementNode() && layout_object &&
         layout_object->IsLayoutBlockFlow();
}

bool IsInPasswordField(const Position& position) {
  TextControlElement* text_control = EnclosingTextControl(position);
  auto* html_input_element = DynamicTo<HTMLInputElement>(text_control);
  return html_input_element && html_input_element->FormControlType() ==
                                   FormControlType::kInputPassword;
}

// If current position is at grapheme boundary, return 0; otherwise, return the
// distance to its nearest left grapheme boundary.
wtf_size_t ComputeDistanceToLeftGraphemeBoundary(const Position& position) {
  const Position& adjusted_position = PreviousPositionOf(
      NextPositionOf(position, PositionMoveType::kGraphemeCluster),
      PositionMoveType::kGraphemeCluster);
  DCHECK_EQ(position.AnchorNode(), adjusted_position.AnchorNode());
  DCHECK_GE(position.ComputeOffsetInContainerNode(),
            adjusted_position.ComputeOffsetInContainerNode());
  return static_cast<wtf_size_t>(
      position.ComputeOffsetInContainerNode() -
      adjusted_position.ComputeOffsetInContainerNode());
}

// If current position is at grapheme boundary, return 0; otherwise, return the
// distance to its nearest right grapheme boundary.
wtf_size_t ComputeDistanceToRightGraphemeBoundary(const Position& position) {
  const Position& adjusted_position = NextPositionOf(
      PreviousPositionOf(position, PositionMoveType::kGraphemeCluster),
      PositionMoveType::kGraphemeCluster);
  DCHECK_EQ(position.AnchorNode(), adjusted_position.AnchorNode());
  DCHECK_GE(adjusted_position.ComputeOffsetInContainerNode(),
            position.ComputeOffsetInContainerNode());
  return static_cast<wtf_size_t>(
      adjusted_position.ComputeOffsetInContainerNode() -
      position.ComputeOffsetInContainerNode());
}

gfx::QuadF LocalToAbsoluteQuadOf(const LocalCaretRect& caret_rect) {
  return caret_rect.layout_object->LocalRectToAbsoluteQuad(caret_rect.rect);
}

const StaticRangeVector* TargetRangesForInputEvent(const Node& node) {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited. see http://crbug.com/590369 for more details.
  node.GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  if (!IsRichlyEditable(node))
    return nullptr;
  const EphemeralRange& range =
      FirstEphemeralRangeOf(node.GetDocument()
                                .GetFrame()
                                ->Selection()
                                .ComputeVisibleSelectionInDOMTree());
  if (range.IsNull())
    return nullptr;
  return MakeGarbageCollected<StaticRangeVector>(1, StaticRange::Create(range));
}

DispatchEventResult DispatchBeforeInputInsertText(
    Node* target,
    const String& data,
    InputEvent::InputType input_type,
    const StaticRangeVector* ranges) {
  if (!target)
    return DispatchEventResult::kNotCanceled;
  // TODO(editing-dev): Pass appropriate |ranges| after it's defined on spec.
  // http://w3c.github.io/editing/input-events.html#dom-inputevent-inputtype
  InputEvent* before_input_event = InputEvent::CreateBeforeInput(
      input_type, data, InputEvent::EventIsComposing::kNotComposing,
      ranges ? ranges : TargetRangesForInputEvent(*target));
  return target->DispatchEvent(*before_input_event);
}

DispatchEventResult DispatchBeforeInputEditorCommand(
    Node* target,
    InputEvent::InputType input_type,
    const StaticRangeVector* ranges) {
  if (!target)
    return DispatchEventResult::kNotCanceled;
  InputEvent* before_input_event = InputEvent::CreateBeforeInput(
      input_type, g_null_atom, InputEvent::EventIsComposing::kNotComposing,
      ranges);
  return target->DispatchEvent(*before_input_event);
}

DispatchEventResult DispatchBeforeInputDataTransfer(
    Node* target,
    InputEvent::InputType input_type,
    DataTransfer* data_transfer) {
  if (!target)
    return DispatchEventResult::kNotCanceled;

  DCHECK(input_type == InputEvent::InputType::kInsertFromPaste ||
         input_type == InputEvent::InputType::kInsertReplacementText ||
         input_type == InputEvent::InputType::kInsertFromDrop ||
         input_type == InputEvent::InputType::kDeleteByCut)
      << "Unsupported inputType: " << (int)input_type;

  InputEvent* before_input_event;

  if (IsRichlyEditable(*target) || !data_transfer) {
    before_input_event = InputEvent::CreateBeforeInput(
        input_type, data_transfer, InputEvent::EventIsComposing::kNotComposing,
        TargetRangesForInputEvent(*target));
  } else {
    const String& data = data_transfer->getData(kMimeTypeTextPlain);
    // TODO(editing-dev): Pass appropriate |ranges| after it's defined on spec.
    // http://w3c.github.io/editing/input-events.html#dom-inputevent-inputtype
    before_input_event = InputEvent::CreateBeforeInput(
        input_type, data, InputEvent::EventIsComposing::kNotComposing,
        TargetRangesForInputEvent(*target));
  }
  return target->DispatchEvent(*before_input_event);
}

void InsertTextAndSendInputEventsOfTypeInsertReplacementText(
    LocalFrame& frame,
    const String& replacement,
    bool allow_edit_context) {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  frame.GetDocument()->UpdateStyleAndLayout(DocumentUpdateReason::kSpellCheck);

  Document& current_document = *frame.GetDocument();

  // Dispatch 'beforeinput'.
  Element* const target = FindEventTargetFrom(
      frame, frame.Selection().ComputeVisibleSelectionInDOMTree());

  // Copy the original target text into a string, in case the 'beforeinput'
  // event handler modifies the text.
  const String before_input_target_string = target->GetInnerTextWithoutUpdate();

  DataTransfer* const data_transfer = DataTransfer::Create(
      DataTransfer::DataTransferType::kInsertReplacementText,
      DataTransferAccessPolicy::kReadable,
      DataObject::CreateFromString(replacement));

  const bool is_canceled =
      DispatchBeforeInputDataTransfer(
          target, InputEvent::InputType::kInsertReplacementText,
          data_transfer) != DispatchEventResult::kNotCa
```