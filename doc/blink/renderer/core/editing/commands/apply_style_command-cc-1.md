Response:
The user wants a summary of the functionality of the `apply_style_command.cc` file in the Chromium Blink engine, focusing on its relationship with web technologies (JavaScript, HTML, CSS), providing examples, and addressing potential user errors. This is the second part of a three-part response.

Here's a breakdown of the code provided in this part:

1. **`ApplyStyleCommand::ApplyToNodeRange`**: This function handles applying styles within a given node range. It deals with embedding elements and calls `FixRangeAndApplyInlineStyle`.
2. **`ApplyStyleCommand::FixRangeAndApplyInlineStyle`**: This function adjusts the start and end positions of the range and then calls `ApplyInlineStyleToNodeRange`. It also handles cases where the start position might be after the end position.
3. **`ContainsNonEditableRegion`**: A helper function to check if a node contains non-editable regions.
4. **`InlineRunToApplyStyle` class**:  A helper class to group nodes for style application.
5. **`ApplyStyleCommand::ApplyInlineStyleToNodeRange`**: This is the core logic for iterating through nodes in a range and applying styles. It handles plain text regions, block elements, and determines if inline styles should be applied to a run of nodes. It also calls `RemoveConflictingInlineStyleFromRun`.
6. **`ApplyStyleCommand::IsStyledInlineElementToRemove`**:  Checks if an element matches the criteria for removal.
7. **`ApplyStyleCommand::ShouldApplyInlineStyleToRun`**: Determines if inline styles should be applied to a contiguous run of nodes based on existing styles.
8. **`ApplyStyleCommand::RemoveConflictingInlineStyleFromRun`**: Removes conflicting inline styles from a run of nodes.
9. **`ApplyStyleCommand::RemoveInlineStyleFromElement`**:  Removes inline styles from a specific HTML element.
10. **`ApplyStyleCommand::ReplaceWithSpanOrRemoveIfWithoutAttributes`**: Replaces an element with a `<span>` or removes it if it has no attributes (or only the style attribute which is empty).
11. **`ApplyStyleCommand::RemoveImplicitlyStyledElement`**: Removes elements that have implicit styling (e.g., `<b>`, `<i>`).
12. **`ApplyStyleCommand::RemoveCSSStyle`**: Removes specific CSS properties from an element's inline style.
13. **`UnsplittableElementForPosition`**:  Finds the nearest ancestor element that should not be split (e.g., a table cell).
14. **`ApplyStyleCommand::HighestAncestorWithConflictingInlineStyle`**: Finds the highest ancestor element with conflicting inline styles.
15. **`ApplyStyleCommand::ApplyInlineStyleToPushDown`**: Applies inline styles to a specific node, handling block elements and text nodes.
16. **`ApplyStyleCommand::PushDownInlineStyleAroundNode`**:  Recursively moves conflicting styles from ancestor elements down to the target node.
17. **`ApplyStyleCommand::RemoveInlineStyle`**: Removes inline styles from a given range. This involves pushing down styles from ancestors and iterating through nodes to remove styles.
18. **`ApplyStyleCommand::ElementFullySelected`**: Checks if an element is fully selected within a given range.
19. **`ApplyStyleCommand::SplitTextAtStart`**: Splits a text node at the start position.
20. **`ApplyStyleCommand::SplitTextAtEnd`**: Splits a text node at the end position.
21. **`ApplyStyleCommand::SplitTextElementAtStart`**: Splits a text node and its containing element at the start position.
22. **`ApplyStyleCommand::SplitTextElementAtEnd`**: Splits a text node and its containing element at the end position.
23. **`ApplyStyleCommand::ShouldSplitTextElement`**: Determines if a text element should be split based on conflicting styles.
24. **`ApplyStyleCommand::IsValidCaretPositionInTextNode`**: Checks if a position is a valid caret position within a text node.
25. **`ApplyStyleCommand::MergeStartWithPreviousIfIdentical`**: This function's implementation is incomplete in the provided snippet.

Based on this, the primary function of this part of the code is the detailed logic for applying and removing inline styles to a range of content in the document. It handles various edge cases, including non-editable regions, block elements, and implicitly styled elements.
这是`blink/renderer/core/editing/commands/apply_style_command.cc`文件的第二部分，主要专注于**对指定节点范围应用或移除内联样式**的详细逻辑。

**功能归纳：**

1. **对节点范围应用内联样式 (`ApplyInlineStyleToNodeRange`)**:
   - 遍历指定起始节点到终止节点之间的所有节点。
   - 区分可编辑和不可编辑区域，以及富文本和纯文本区域。
   - 对于纯文本区域，如果完全选中，则直接将样式添加到其父元素的 `style` 属性中。
   - 对于可编辑的富文本区域，会识别出连续的兄弟节点，组成一个“run”（运行单元）。
   - 针对每个 "run"，会先调用 `RemoveConflictingInlineStyleFromRun` 移除冲突的内联样式。
   - 然后，计算应用样式的正确位置，并最终调用 `ApplyInlineStyleChange` 来实际添加样式。

2. **移除冲突的内联样式 (`RemoveConflictingInlineStyleFromRun`)**:
   - 遍历指定 "run" 中的每个元素节点。
   - 调用 `RemoveInlineStyleFromElement` 来移除与要应用的样式冲突的现有样式。
   - 在移除过程中，会处理节点被移除的情况，并更新 "run" 的起始和结束节点。

3. **从元素中移除内联样式 (`RemoveInlineStyleFromElement`)**:
   - 检查元素是否是需要移除的特定样式内联元素（由 `IsStyledInlineElementToRemove` 决定）。如果是，则移除该元素并保留其子节点。
   - 移除元素中由隐式样式产生的效果，例如 `<b>` 标签产生的加粗效果。
   - 移除元素 `style` 属性中与目标样式冲突的 CSS 属性。

4. **替换为 `<span>` 或移除元素 (`ReplaceWithSpanOrRemoveIfWithoutAttributes`)**:
   - 如果元素除了 `style` 属性之外没有其他属性，则移除该元素并保留其子节点。
   - 否则，将该元素替换为一个 `<span>` 元素，并保留其子节点和属性。

5. **移除隐式样式元素 (`RemoveImplicitlyStyledElement`)**:
   - 移除像 `<b>`、`<i>` 这样的标签，如果它们的隐式样式与要应用的样式冲突。
   - 将这些标签替换为 `<span>` 标签，或者在没有其他属性的情况下直接移除。
   - 处理像 `font` 标签的特殊情况，如果为空或者只剩下不重要的属性也会被移除。

6. **移除 CSS 样式 (`RemoveCSSStyle`)**:
   - 从元素的 `style` 属性中移除与目标样式冲突的 CSS 属性。
   - 如果移除后元素变成没有属性的 `<span>`，则会移除该 `<span>` 并保留其子节点。

7. **查找不可分割的祖先元素 (`UnsplittableElementForPosition`)**:
   - 用于查找不应该被分割的最近的祖先元素，例如表格单元格。

8. **查找具有冲突内联样式的最高祖先 (`HighestAncestorWithConflictingInlineStyle`)**:
   - 查找指定节点向上遍历的祖先元素中，第一个具有与要应用的样式冲突的内联样式的元素。

9. **将内联样式向下推 (`PushDownInlineStyleAroundNode`, `ApplyInlineStyleToPushDown`)**:
   - 用于处理当要移除样式时，需要将父元素的样式“下推”到子元素的情况，以保持视觉效果。
   - `PushDownInlineStyleAroundNode` 找到需要向下推样式的祖先元素。
   - `ApplyInlineStyleToPushDown` 实际将样式应用到指定的节点。

10. **移除内联样式 (`RemoveInlineStyle`)**:
    - 这是移除内联样式的主要入口点。
    - 首先调用 `PushDownInlineStyleAroundNode` 将可能存在的父级样式向下推。
    - 然后遍历选区内的节点，对于完全选中的元素，调用 `RemoveInlineStyleFromElement` 来移除样式。
    - 在移除过程中，会更新选区的起始和结束位置，以应对节点被移除的情况。

11. **判断元素是否完全选中 (`ElementFullySelected`)**:
    - 判断一个元素是否完全包含在给定的选区范围内。

12. **分割文本节点 (`SplitTextAtStart`, `SplitTextAtEnd`)**:
    - 在选区的起始或结束位置分割文本节点。

13. **分割包含元素的文本节点 (`SplitTextElementAtStart`, `SplitTextElementAtEnd`)**:
    - 在选区的起始或结束位置分割文本节点，并可能涉及到分割包含该文本节点的元素。

14. **判断是否应该分割文本元素 (`ShouldSplitTextElement`)**:
    - 判断一个元素是否应该被分割，通常基于其内联样式是否需要被移除。

15. **判断是否是文本节点中的有效光标位置 (`IsValidCaretPositionInTextNode`)**:
    - 检查给定的位置是否是文本节点中一个有效的光标位置（不在文本节点的开头或结尾）。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

* **HTML**: 这个文件直接操作 HTML 结构，例如创建、移除和替换 HTML 元素 (`<span>` 元素)。
    * **例子**: 当你选中一段加粗的文字，并点击“取消加粗”按钮时，这段代码可能会将 `<b>` 标签替换为 `<span>` 标签，或者直接移除 `<b>` 标签，将文字保留下来。
* **CSS**: 这个文件负责应用和移除 CSS 样式，尤其是内联样式 (`style` 属性)。
    * **例子**: 当你选中一段文字并设置字体颜色为红色时，这段代码会将 `style="color: red;"` 添加到包含这段文字的元素上。当你取消这个颜色时，这段代码会移除 `color: red;` 这个 CSS 属性。
* **JavaScript**: 虽然这个文件是用 C++ 写的，但它服务的对象是 Web 页面，这些页面通常包含 JavaScript。JavaScript 可以通过 DOM API 触发样式更改，最终会调用到这里的 C++ 代码。
    * **例子**: 一个富文本编辑器（用 JavaScript 实现）的用户界面，当用户点击“加粗”按钮时，JavaScript 会调用浏览器的 API 来修改选区内的样式，最终会触发 `ApplyStyleCommand` 的执行。

**逻辑推理 (假设输入与输出):**

假设用户选中了以下 HTML 片段中的 "world"：

```html
<div>Hello <b>world</b>!</div>
```

并且想将 "world" 的字体颜色设置为蓝色。

* **假设输入**:
    * `start`:  文本节点 "world" 的起始位置
    * `end`:  文本节点 "world" 的结束位置
    * `style`: 一个 `EditingStyle` 对象，包含 `color: blue;`

* **逻辑推理**:
    1. `ApplyStyleCommand::ApplyToNodeRange` 会被调用。
    2. `FixRangeAndApplyInlineStyle` 会调整范围。
    3. `ApplyInlineStyleToNodeRange` 会识别出 "world" 所在的文本节点。
    4. `RemoveConflictingInlineStyleFromRun` 可能会检查 `<b>` 标签是否有冲突的样式（本例中没有）。
    5. `ApplyInlineStyleChange` 会在 `<b>` 标签内创建一个新的 `<span>` 标签包裹 "world"，并设置其 `style` 属性为 `color: blue;`。

* **预期输出**:

```html
<div>Hello <b><span style="color: blue;">world</span></b>!</div>
```

**用户或编程常见的使用错误举例说明：**

* **用户错误**:  用户在不可编辑区域尝试应用样式，这段代码会识别出不可编辑区域并跳过样式应用。
    * **调试线索**: 检查 `IsEditable(*node)` 的返回值。
* **编程错误**:  在实现富文本编辑器时，JavaScript 没有正确计算选区范围，导致传递给 `ApplyStyleCommand` 的起始和结束位置不正确。这可能会导致样式应用到错误的元素或范围。
    * **调试线索**: 检查传递给命令的 `start` 和 `end` 位置是否与用户实际选中的内容一致。可以使用浏览器的开发者工具查看选区的详细信息。
* **编程错误**:  在自定义的输入处理逻辑中，没有正确处理换行符或特殊字符，导致在应用样式时出现意外的分割或合并。
    * **调试线索**: 观察在包含换行符或其他特殊字符的文本上应用样式时的行为，检查是否调用了 `SplitTextAtStart` 或 `SplitTextAtEnd` 等分割函数。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户在网页上进行文本选择**: 用户通过鼠标拖拽或者键盘操作在网页上选中了一段文本。
2. **用户触发样式更改操作**: 用户点击了富文本编辑器的“加粗”、“斜体”、“颜色”等按钮，或者使用了相应的快捷键。
3. **JavaScript 处理用户操作**: 网页上的 JavaScript 代码监听到了用户的操作，并根据用户的选择和操作，调用了浏览器的编辑相关的 API，例如 `document.execCommand('bold')` 或 `document.execCommand('foreColor', false, 'blue')`。
4. **浏览器引擎接收到命令**: 浏览器引擎接收到 JavaScript 的命令，并将其转换为内部的编辑命令。对于样式相关的操作，通常会涉及到 `ApplyStyleCommand`。
5. **`ApplyStyleCommand` 被创建和执行**: 浏览器引擎会创建一个 `ApplyStyleCommand` 对象，并传入相关的参数，例如要应用的样式和选区的范围。
6. **执行 `ApplyStyleCommand` 的 `DoApply` 方法**: 在 `DoApply` 方法中，会调用到这里列出的各种函数，例如 `ApplyToNodeRange`、`ApplyInlineStyleToNodeRange` 等，来完成具体的样式应用或移除逻辑。

通过以上步骤，我们可以追踪用户操作是如何一步步地触发到 `apply_style_command.cc` 文件中的代码执行的。在调试过程中，可以在 JavaScript 代码中设置断点，查看 `document.execCommand` 的调用情况，然后在 C++ 代码中设置断点，查看 `ApplyStyleCommand` 的执行过程，以及各个关键函数的参数和返回值，从而定位问题。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/apply_style_command.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
);
    HTMLElement* embedding_end_element = HighestEmbeddingAncestor(
        end.AnchorNode(), EnclosingBlock(end.AnchorNode()));

    if (embedding_start_element || embedding_end_element) {
      Position embedding_apply_start =
          embedding_start_element
              ? Position::InParentAfterNode(*embedding_start_element)
              : start;
      Position embedding_apply_end =
          embedding_end_element
              ? Position::InParentBeforeNode(*embedding_end_element)
              : end;
      DCHECK(embedding_apply_start.IsNotNull());
      DCHECK(embedding_apply_end.IsNotNull());

      if (!embedding_style) {
        style_without_embedding = style->Copy();
        embedding_style =
            style_without_embedding->ExtractAndRemoveTextDirection(
                GetDocument().GetExecutionContext()->GetSecureContextMode());
      }
      FixRangeAndApplyInlineStyle(embedding_style, embedding_apply_start,
                                  embedding_apply_end, editing_state);
      if (editing_state->IsAborted())
        return;

      style_to_apply = style_without_embedding;
    }
  }

  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
  FixRangeAndApplyInlineStyle(style_to_apply, start, end, editing_state);
  if (editing_state->IsAborted())
    return;

  // Remove dummy style spans created by splitting text elements.
  CleanupUnstyledAppleStyleSpans(start_dummy_span_ancestor, editing_state);
  if (editing_state->IsAborted())
    return;
  if (end_dummy_span_ancestor != start_dummy_span_ancestor)
    CleanupUnstyledAppleStyleSpans(end_dummy_span_ancestor, editing_state);
}

void ApplyStyleCommand::FixRangeAndApplyInlineStyle(
    EditingStyle* style,
    const Position& start,
    const Position& end,
    EditingState* editing_state) {
  Node* start_node = start.AnchorNode();
  DCHECK(start_node);

  if (start.ComputeEditingOffset() >= CaretMaxOffset(start.AnchorNode())) {
    start_node = NodeTraversal::Next(*start_node);
    if (!start_node ||
        ComparePositions(end, FirstPositionInOrBeforeNode(*start_node)) < 0)
      return;
  }

  Node* past_end_node = end.AnchorNode();
  if (end.ComputeEditingOffset() >= CaretMaxOffset(end.AnchorNode()))
    past_end_node = NodeTraversal::NextSkippingChildren(*end.AnchorNode());

  // FIXME: Callers should perform this operation on a Range that includes the
  // br if they want style applied to the empty line.
  if (start == end && IsA<HTMLBRElement>(*start.AnchorNode()))
    past_end_node = NodeTraversal::Next(*start.AnchorNode());

  // Start from the highest fully selected ancestor so that we can modify the
  // fully selected node. e.g. When applying font-size: large on <font
  // color="blue">hello</font>, we need to include the font element in our run
  // to generate <font color="blue" size="4">hello</font> instead of <font
  // color="blue"><font size="4">hello</font></font>
  Element* editable_root = RootEditableElement(*start_node);
  if (start_node != editable_root) {
    // TODO(editing-dev): Investigate why |start| can be after |end| here in
    // some cases. For example, in web test
    // editing/style/make-text-writing-direction-inline-{mac,win}.html
    // blink::Range object will collapse to end in this case but EphemeralRange
    // will trigger DCHECK, so we have to explicitly handle this.
    const EphemeralRange& range =
        start <= end ? EphemeralRange(start, end) : EphemeralRange(end, start);
    while (editable_root && start_node->parentNode() != editable_root &&
           IsNodeVisiblyContainedWithin(*start_node->parentNode(), range))
      start_node = start_node->parentNode();
  }

  ApplyInlineStyleToNodeRange(style, start_node, past_end_node, editing_state);
}

static bool ContainsNonEditableRegion(Node& node) {
  if (!IsEditable(node))
    return true;

  Node* sibling = NodeTraversal::NextSkippingChildren(node);
  for (Node* descendent = node.firstChild();
       descendent && descendent != sibling;
       descendent = NodeTraversal::Next(*descendent)) {
    if (!IsEditable(*descendent))
      return true;
  }

  return false;
}

class InlineRunToApplyStyle {
  DISALLOW_NEW();

 public:
  InlineRunToApplyStyle(Node* start, Node* end, Node* past_end_node)
      : start(start), end(end), past_end_node(past_end_node) {
    DCHECK_EQ(start->parentNode(), end->parentNode());
  }

  bool StartAndEndAreStillInDocument() {
    return start && end && start->isConnected() && end->isConnected();
  }

  void Trace(Visitor* visitor) const {
    visitor->Trace(start);
    visitor->Trace(end);
    visitor->Trace(past_end_node);
    visitor->Trace(position_for_style_computation);
    visitor->Trace(dummy_element);
  }

  Member<Node> start;
  Member<Node> end;
  Member<Node> past_end_node;
  Position position_for_style_computation;
  Member<HTMLSpanElement> dummy_element;
  StyleChange change;
};

}  // namespace blink

WTF_ALLOW_INIT_WITH_MEM_FUNCTIONS(blink::InlineRunToApplyStyle)

namespace blink {

void ApplyStyleCommand::ApplyInlineStyleToNodeRange(
    EditingStyle* style,
    Node* start_node,
    Node* past_end_node,
    EditingState* editing_state) {
  if (remove_only_)
    return;

  Range* range = MakeGarbageCollected<Range>(GetDocument(), StartPosition(),
                                             EndPosition());
  GetDocument().UpdateStyleAndLayoutForRange(range,
                                             DocumentUpdateReason::kEditing);

  HeapVector<InlineRunToApplyStyle> runs;
  Node* node = start_node;
  for (Node* next; node && node != past_end_node; node = next) {
    next = NodeTraversal::Next(*node);

    if (!node->GetLayoutObject() || !IsEditable(*node))
      continue;

    auto* element = DynamicTo<HTMLElement>(node);
    if (!IsRichlyEditable(*node) && element) {
      // This is a plaintext-only region. Only proceed if it's fully selected.
      // pastEndNode is the node after the last fully selected node, so if it's
      // inside node then node isn't fully selected.
      if (past_end_node && past_end_node->IsDescendantOf(element))
        break;
      // Add to this element's inline style and skip over its contents.
      next = NodeTraversal::NextSkippingChildren(*node);
      if (!style->Style())
        continue;
      MutableCSSPropertyValueSet* inline_style =
          CopyStyleOrCreateEmpty(element->InlineStyle());
      inline_style->MergeAndOverrideOnConflict(style->Style());
      SetNodeAttribute(element, html_names::kStyleAttr,
                       AtomicString(inline_style->AsText()));
      continue;
    }

    if (IsEnclosingBlock(node))
      continue;

    if (node->hasChildren()) {
      if (node->contains(past_end_node) || ContainsNonEditableRegion(*node) ||
          !IsEditable(*node->parentNode()))
        continue;
      if (EditingIgnoresContent(*node)) {
        next = NodeTraversal::NextSkippingChildren(*node);
        continue;
      }
    }

    Node* run_start = node;
    Node* run_end = node;
    Node* sibling = node->nextSibling();
    while (sibling && sibling != past_end_node &&
           !sibling->contains(past_end_node) &&
           (!IsEnclosingBlock(sibling) || IsA<HTMLBRElement>(*sibling)) &&
           !ContainsNonEditableRegion(*sibling)) {
      run_end = sibling;
      sibling = run_end->nextSibling();
    }
    DCHECK(run_end);
    next = NodeTraversal::NextSkippingChildren(*run_end);

    Node* past_run_end_node = NodeTraversal::NextSkippingChildren(*run_end);
    if (!ShouldApplyInlineStyleToRun(style, run_start, past_run_end_node))
      continue;

    runs.push_back(
        InlineRunToApplyStyle(run_start, run_end, past_run_end_node));
  }

  for (auto& run : runs) {
    RemoveConflictingInlineStyleFromRun(style, run.start, run.end,
                                        run.past_end_node, editing_state);
    if (editing_state->IsAborted())
      return;
    if (run.StartAndEndAreStillInDocument()) {
      run.position_for_style_computation = PositionToComputeInlineStyleChange(
          run.start, run.dummy_element, editing_state);
      if (editing_state->IsAborted())
        return;
    }
  }

  GetDocument().UpdateStyleAndLayoutForRange(range,
                                             DocumentUpdateReason::kEditing);

  for (auto& run : runs) {
    if (run.position_for_style_computation.IsNotNull())
      run.change = StyleChange(style, run.position_for_style_computation);
  }

  for (auto& run : runs) {
    if (run.dummy_element) {
      RemoveNode(run.dummy_element, editing_state);
      if (editing_state->IsAborted())
        return;
    }
    if (run.StartAndEndAreStillInDocument()) {
      ApplyInlineStyleChange(run.start.Release(), run.end.Release(), run.change,
                             kAddStyledElement, editing_state);
      if (editing_state->IsAborted())
        return;
    }
  }
}

bool ApplyStyleCommand::IsStyledInlineElementToRemove(Element* element) const {
  return (styled_inline_element_ &&
          element->HasTagName(styled_inline_element_->TagQName())) ||
         (is_inline_element_to_remove_function_ &&
          is_inline_element_to_remove_function_(element));
}

bool ApplyStyleCommand::ShouldApplyInlineStyleToRun(EditingStyle* style,
                                                    Node* run_start,
                                                    Node* past_end_node) {
  DCHECK(style);
  DCHECK(run_start);

  for (Node* node = run_start; node && node != past_end_node;
       node = NodeTraversal::Next(*node)) {
    if (node->hasChildren())
      continue;
    // We don't consider is_inline_element_to_remove_function_ here because we
    // never apply style when is_inline_element_to_remove_function_ is specified
    if (!style->StyleIsPresentInComputedStyleOfNode(node))
      return true;
    if (styled_inline_element_ &&
        !EnclosingElementWithTag(Position::BeforeNode(*node),
                                 styled_inline_element_->TagQName()))
      return true;
  }
  return false;
}

void ApplyStyleCommand::RemoveConflictingInlineStyleFromRun(
    EditingStyle* style,
    Member<Node>& run_start,
    Member<Node>& run_end,
    Node* past_end_node,
    EditingState* editing_state) {
  DCHECK(run_start);
  DCHECK(run_end);
  Node* next = run_start;
  for (Node* node = next; node && node->isConnected() && node != past_end_node;
       node = next) {
    if (EditingIgnoresContent(*node)) {
      DCHECK(!node->contains(past_end_node)) << node << " " << past_end_node;
      next = NodeTraversal::NextSkippingChildren(*node);
    } else {
      next = NodeTraversal::Next(*node);
    }

    auto* element = DynamicTo<HTMLElement>(*node);
    if (!element)
      continue;

    Node* previous_sibling = element->previousSibling();
    Node* next_sibling = element->nextSibling();
    ContainerNode* parent = element->parentNode();
    RemoveInlineStyleFromElement(style, element, editing_state, kRemoveAlways);
    if (editing_state->IsAborted())
      return;
    if (!element->isConnected()) {
      // FIXME: We might need to update the start and the end of current
      // selection here but need a test.
      if (run_start == *element)
        run_start = previous_sibling ? previous_sibling->nextSibling()
                                     : parent->firstChild();
      if (run_end == *element)
        run_end = next_sibling ? next_sibling->previousSibling()
                               : parent->lastChild();
    }
  }
}

bool ApplyStyleCommand::RemoveInlineStyleFromElement(
    EditingStyle* style,
    HTMLElement* element,
    EditingState* editing_state,
    InlineStyleRemovalMode mode,
    EditingStyle* extracted_style) {
  DCHECK(element);
  GetDocument().UpdateStyleAndLayoutTree();
  if (!element->parentNode() || !IsEditable(*element->parentNode()))
    return false;

  if (IsStyledInlineElementToRemove(element)) {
    if (mode == kRemoveNone)
      return true;
    if (extracted_style)
      extracted_style->MergeInlineStyleOfElement(element,
                                                 EditingStyle::kOverrideValues);
    RemoveNodePreservingChildren(element, editing_state);
    if (editing_state->IsAborted())
      return false;
    return true;
  }

  bool removed = RemoveImplicitlyStyledElement(style, element, mode,
                                               extracted_style, editing_state);
  if (editing_state->IsAborted())
    return false;

  if (!element->isConnected())
    return removed;

  // If the node was converted to a span, the span may still contain relevant
  // styles which must be removed (e.g. <b style='font-weight: bold'>)
  if (RemoveCSSStyle(style, element, editing_state, mode, extracted_style))
    removed = true;
  if (editing_state->IsAborted())
    return false;

  return removed;
}

void ApplyStyleCommand::ReplaceWithSpanOrRemoveIfWithoutAttributes(
    HTMLElement* elem,
    EditingState* editing_state) {
  if (HasNoAttributeOrOnlyStyleAttribute(elem, kStyleAttributeShouldBeEmpty))
    RemoveNodePreservingChildren(elem, editing_state);
  else
    ReplaceElementWithSpanPreservingChildrenAndAttributes(elem);
}

bool ApplyStyleCommand::RemoveImplicitlyStyledElement(
    EditingStyle* style,
    HTMLElement* element,
    InlineStyleRemovalMode mode,
    EditingStyle* extracted_style,
    EditingState* editing_state) {
  DCHECK(style);
  if (mode == kRemoveNone) {
    DCHECK(!extracted_style);
    return style->ConflictsWithImplicitStyleOfElement(element) ||
           style->ConflictsWithImplicitStyleOfAttributes(element);
  }

  DCHECK(mode == kRemoveIfNeeded || mode == kRemoveAlways);
  if (style->ConflictsWithImplicitStyleOfElement(
          element, extracted_style,
          mode == kRemoveAlways ? EditingStyle::kExtractMatchingStyle
                                : EditingStyle::kDoNotExtractMatchingStyle)) {
    ReplaceWithSpanOrRemoveIfWithoutAttributes(element, editing_state);
    if (editing_state->IsAborted())
      return false;
    return true;
  }

  // unicode-bidi and direction are pushed down separately so don't push down
  // with other styles
  Vector<QualifiedName> attributes;
  if (!style->ExtractConflictingImplicitStyleOfAttributes(
          element,
          extracted_style ? EditingStyle::kPreserveWritingDirection
                          : EditingStyle::kDoNotPreserveWritingDirection,
          extracted_style, attributes,
          mode == kRemoveAlways ? EditingStyle::kExtractMatchingStyle
                                : EditingStyle::kDoNotExtractMatchingStyle))
    return false;

  for (const auto& attribute : attributes)
    RemoveElementAttribute(element, attribute);

  if (IsEmptyFontTag(element) ||
      IsSpanWithoutAttributesOrUnstyledStyleSpan(element)) {
    RemoveNodePreservingChildren(element, editing_state);
    if (editing_state->IsAborted())
      return false;
  }

  return true;
}

bool ApplyStyleCommand::RemoveCSSStyle(EditingStyle* style,
                                       HTMLElement* element,
                                       EditingState* editing_state,
                                       InlineStyleRemovalMode mode,
                                       EditingStyle* extracted_style) {
  DCHECK(style);
  DCHECK(element);

  if (mode == kRemoveNone)
    return style->ConflictsWithInlineStyleOfElement(element);

  Vector<CSSPropertyID> properties;
  if (!style->ConflictsWithInlineStyleOfElement(element, extracted_style,
                                                properties))
    return false;

  // FIXME: We should use a mass-removal function here but we don't have an
  // undoable one yet.
  for (const auto& property : properties)
    RemoveCSSProperty(element, property);

  if (IsSpanWithoutAttributesOrUnstyledStyleSpan(element))
    RemoveNodePreservingChildren(element, editing_state);

  return true;
}

// Finds the enclosing element until which the tree can be split.
// When a user hits ENTER, they won't expect this element to be split into two.
// You may pass it as the second argument of splitTreeToNode.
static Element* UnsplittableElementForPosition(const Position& p) {
  // Since enclosingNodeOfType won't search beyond the highest root editable
  // node, this code works even if the closest table cell was outside of the
  // root editable node.
  auto* enclosing_cell = To<Element>(EnclosingNodeOfType(p, &IsTableCell));
  if (enclosing_cell)
    return enclosing_cell;

  return RootEditableElementOf(p);
}

HTMLElement* ApplyStyleCommand::HighestAncestorWithConflictingInlineStyle(
    EditingStyle* style,
    Node* node) {
  if (!node)
    return nullptr;

  Node* unsplittable_element =
      UnsplittableElementForPosition(FirstPositionInOrBeforeNode(*node));
  HTMLElement* result = nullptr;
  for (Node* n = node; n; n = n->parentNode()) {
    auto* html_element = DynamicTo<HTMLElement>(n);
    if (html_element && ShouldRemoveInlineStyleFromElement(style, html_element))
      result = html_element;
    // Should stop at the editable root (cannot cross editing boundary) and
    // also stop at the unsplittable element to be consistent with other UAs
    if (n == unsplittable_element)
      break;
  }

  return result;
}

void ApplyStyleCommand::ApplyInlineStyleToPushDown(
    Node* node,
    EditingStyle* style,
    EditingState* editing_state) {
  DCHECK(node);

  node->GetDocument().UpdateStyleAndLayoutTree();

  if (!style || style->IsEmpty() || !node->GetLayoutObject() ||
      IsA<HTMLIFrameElement>(*node))
    return;

  EditingStyle* new_inline_style = style;
  auto* html_element = DynamicTo<HTMLElement>(node);
  if (html_element && html_element->InlineStyle()) {
    new_inline_style = style->Copy();
    new_inline_style->MergeInlineStyleOfElement(html_element,
                                                EditingStyle::kOverrideValues);
  }

  const auto* layout_object = node->GetLayoutObject();
  // Since addInlineStyleIfNeeded can't add styles to block-flow layout objects,
  // add style attribute instead.
  // FIXME: applyInlineStyleToRange should be used here instead.
  if ((layout_object->IsLayoutBlockFlow() || node->hasChildren()) &&
      html_element) {
    SetNodeAttribute(html_element, html_names::kStyleAttr,
                     AtomicString(new_inline_style->Style()->AsText()));
    return;
  }

  if (layout_object->IsText() &&
      To<LayoutText>(layout_object)->IsAllCollapsibleWhitespace())
    return;

  // We can't wrap node with the styled element here because new styled element
  // will never be removed if we did. If we modified the child pointer in
  // pushDownInlineStyleAroundNode to point to new style element then we fall
  // into an infinite loop where we keep removing and adding styled element
  // wrapping node.
  AddInlineStyleIfNeeded(new_inline_style, node, node, editing_state);
}

void ApplyStyleCommand::PushDownInlineStyleAroundNode(
    EditingStyle* style,
    Node* target_node,
    EditingState* editing_state) {
  HTMLElement* highest_ancestor =
      HighestAncestorWithConflictingInlineStyle(style, target_node);
  if (!highest_ancestor)
    return;

  // The outer loop is traversing the tree vertically from highestAncestor to
  // targetNode
  Node* current = highest_ancestor;
  // Along the way, styled elements that contain targetNode are removed and
  // accumulated into elementsToPushDown. Each child of the removed element,
  // exclusing ancestors of targetNode, is then wrapped by clones of elements in
  // elementsToPushDown.
  HeapVector<Member<Element>> elements_to_push_down;
  while (current && current != target_node && current->contains(target_node)) {
    NodeVector current_children;
    GetChildNodes(To<ContainerNode>(*current), current_children);
    Element* styled_element = nullptr;
    if (current->IsStyledElement() &&
        IsStyledInlineElementToRemove(To<Element>(current))) {
      styled_element = To<Element>(current);
      elements_to_push_down.push_back(styled_element);
    }

    EditingStyle* style_to_push_down = MakeGarbageCollected<EditingStyle>();
    if (auto* html_element = DynamicTo<HTMLElement>(current)) {
      RemoveInlineStyleFromElement(style, html_element, editing_state,
                                   kRemoveIfNeeded, style_to_push_down);
      if (editing_state->IsAborted())
        return;
    }

    // The inner loop will go through children on each level
    // FIXME: we should aggregate inline child elements together so that we
    // don't wrap each child separately.
    for (const auto& current_child : current_children) {
      Node* child = current_child;
      if (!child->parentNode())
        continue;
      if (!child->contains(target_node) && elements_to_push_down.size()) {
        for (const auto& element : elements_to_push_down) {
          Element& wrapper = element->CloneWithoutChildren();
          wrapper.removeAttribute(html_names::kStyleAttr);
          // Delete id attribute from the second element because the same id
          // cannot be used for more than one element
          element->removeAttribute(html_names::kIdAttr);
          if (IsA<HTMLAnchorElement>(element.Get()))
            element->removeAttribute(html_names::kNameAttr);
          SurroundNodeRangeWithElement(child, child, &wrapper, editing_state);
          if (editing_state->IsAborted())
            return;
        }
      }

      // Apply style to all nodes containing targetNode and their siblings but
      // NOT to targetNode But if we've removed styledElement then go ahead and
      // always apply the style.
      if (child != target_node || styled_element) {
        ApplyInlineStyleToPushDown(child, style_to_push_down, editing_state);
        if (editing_state->IsAborted())
          return;
      }

      // We found the next node for the outer loop (contains targetNode)
      // When reached targetNode, stop the outer loop upon the completion of the
      // current inner loop
      if (child == target_node || child->contains(target_node))
        current = child;
    }
  }
}

void ApplyStyleCommand::RemoveInlineStyle(EditingStyle* style,
                                          const EphemeralRange& range,
                                          EditingState* editing_state) {
  Position start = range.StartPosition();
  Position end = range.EndPosition();
  DCHECK(Position::CommonAncestorTreeScope(start, end)) << start << " " << end;
  // FIXME: We should assert that start/end are not in the middle of a text
  // node.

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  Position push_down_start = MostForwardCaretPosition(start);
  // If the pushDownStart is at the end of a text node, then this node is not
  // fully selected. Move it to the next deep quivalent position to avoid
  // removing the style from this node. e.g. if pushDownStart was at
  // Position("hello", 5) in <b>hello<div>world</div></b>, we want
  // Position("world", 0) instead.
  const unsigned push_down_start_offset =
      push_down_start.ComputeOffsetInContainerNode();
  auto* push_down_start_container =
      DynamicTo<Text>(push_down_start.ComputeContainerNode());
  if (push_down_start_container &&
      push_down_start_offset == push_down_start_container->length())
    push_down_start = NextVisuallyDistinctCandidate(push_down_start);

  // TODO(editing-dev): Use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  Position push_down_end = MostBackwardCaretPosition(end);
  // If pushDownEnd is at the start of a text node, then this node is not fully
  // selected. Move it to the previous deep equivalent position to avoid
  // removing the style from this node.
  Node* push_down_end_container = push_down_end.ComputeContainerNode();
  if (push_down_end_container && push_down_end_container->IsTextNode() &&
      !push_down_end.ComputeOffsetInContainerNode())
    push_down_end = PreviousVisuallyDistinctCandidate(push_down_end);

  PushDownInlineStyleAroundNode(style, push_down_start.AnchorNode(),
                                editing_state);
  if (editing_state->IsAborted())
    return;
  PushDownInlineStyleAroundNode(style, push_down_end.AnchorNode(),
                                editing_state);
  if (editing_state->IsAborted())
    return;

  // If pushDownInlineStyleAroundNode has pruned start.anchorNode() or
  // end.anchorNode(), use pushDownStart or pushDownEnd instead, which
  // pushDownInlineStyleAroundNode won't prune.
  if (start.IsNull() || start.IsOrphan())
    start = push_down_start;
  if (end.IsNull() || end.IsOrphan())
    end = push_down_end;

  // Current ending selection resetting algorithm assumes |start| and |end|
  // are in a same DOM tree even if they are not in document.
  if (!Position::CommonAncestorTreeScope(start, end))
    return;

  // The s and e variables store the positions used to set the ending selection
  // after style removal takes place. This will help callers to recognize when
  // either the start node or the end node are removed from the document during
  // the work of this function.
  Position s = start;
  Position e = end;
  Node* node = start.AnchorNode();
  while (node) {
    Node* next_to_process = nullptr;
    if (!EditingIgnoresContent(*node))
      next_to_process = NodeTraversal::Next(*node);
    else if (!node->contains(end.AnchorNode()))
      next_to_process = NodeTraversal::NextSkippingChildren(*node);
    auto* elem = DynamicTo<HTMLElement>(node);
    if (elem && ElementFullySelected(*elem, start, end)) {
      Node* prev = NodeTraversal::PreviousPostOrder(*elem);
      Node* next = NodeTraversal::Next(*elem);
      EditingStyle* style_to_push_down = nullptr;
      Node* child_node = nullptr;
      if (IsStyledInlineElementToRemove(elem)) {
        style_to_push_down = MakeGarbageCollected<EditingStyle>();
        child_node = elem->firstChild();
      }

      RemoveInlineStyleFromElement(style, elem, editing_state, kRemoveIfNeeded,
                                   style_to_push_down);
      if (editing_state->IsAborted())
        return;
      if (!elem->isConnected()) {
        if (s.AnchorNode() == elem) {
          if (s == e) {
            s = e = Position::BeforeNode(*next).ToOffsetInAnchor();
          } else {
            // Since elem must have been fully selected, and it is at the start
            // of the selection, it is clear we can set the new s offset to 0.
            DCHECK(s.IsBeforeAnchor() || s.IsBeforeChildren() ||
                   s.OffsetInContainerNode() <= 0)
                << s;
            s = next ? FirstPositionInOrBeforeNode(*next) : Position();
          }
        }
        if (e.AnchorNode() == elem) {
          // Since elem must have been fully selected, and it is at the end
          // of the selection, it is clear we can set the new e offset to
          // the max range offset of prev.
          DCHECK(s.IsAfterAnchor() ||
                 !OffsetIsBeforeLastNodeOffset(s.OffsetInContainerNode(),
                                               s.ComputeContainerNode()))
              << s;
          e = prev ? LastPositionInOrAfterNode(*prev) : Position();
        }
      }

      if (style_to_push_down) {
        for (; child_node; child_node = child_node->nextSibling()) {
          ApplyInlineStyleToPushDown(child_node, style_to_push_down,
                                     editing_state);
          if (editing_state->IsAborted())
            return;
        }
      }
    }
    if (node == end.AnchorNode())
      break;
    node = next_to_process;
  }

  UpdateStartEnd(EphemeralRange(s, e));
}

bool ApplyStyleCommand::ElementFullySelected(const HTMLElement& element,
                                             const Position& start,
                                             const Position& end) const {
  // The tree may have changed and Position::upstream() relies on an up-to-date
  // layout.
  element.GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kEditing);

  return ComparePositions(FirstPositionInOrBeforeNode(element), start) >= 0 &&
         ComparePositions(
             MostBackwardCaretPosition(LastPositionInOrAfterNode(element)),
             end) <= 0;
}

void ApplyStyleCommand::SplitTextAtStart(const Position& start,
                                         const Position& end) {
  DCHECK(start.ComputeContainerNode()->IsTextNode()) << start;

  Position new_end;
  if (end.IsOffsetInAnchor() &&
      start.ComputeContainerNode() == end.ComputeContainerNode())
    new_end =
        Position(end.ComputeContainerNode(),
                 end.OffsetInContainerNode() - start.OffsetInContainerNode());
  else
    new_end = end;

  auto* text = To<Text>(start.ComputeContainerNode());
  SplitTextNode(text, start.OffsetInContainerNode());
  UpdateStartEnd(EphemeralRange(Position::FirstPositionInNode(*text), new_end));
}

void ApplyStyleCommand::SplitTextAtEnd(const Position& start,
                                       const Position& end) {
  DCHECK(end.ComputeContainerNode()->IsTextNode()) << end;

  bool should_update_start =
      start.IsOffsetInAnchor() &&
      start.ComputeContainerNode() == end.ComputeContainerNode();
  auto* text = To<Text>(end.AnchorNode());
  SplitTextNode(text, end.OffsetInContainerNode());

  auto* prev_text_node = DynamicTo<Text>(text->previousSibling());
  if (!prev_text_node)
    return;

  Position new_start =
      should_update_start
          ? Position(prev_text_node, start.OffsetInContainerNode())
          : start;
  UpdateStartEnd(
      EphemeralRange(new_start, Position::LastPositionInNode(*prev_text_node)));
}

void ApplyStyleCommand::SplitTextElementAtStart(const Position& start,
                                                const Position& end) {
  DCHECK(start.ComputeContainerNode()->IsTextNode()) << start;

  Position new_end;
  if (start.ComputeContainerNode() == end.ComputeContainerNode())
    new_end =
        Position(end.ComputeContainerNode(),
                 end.OffsetInContainerNode() - start.OffsetInContainerNode());
  else
    new_end = end;

  SplitTextNodeContainingElement(To<Text>(start.ComputeContainerNode()),
                                 start.OffsetInContainerNode());
  UpdateStartEnd(EphemeralRange(
      Position::BeforeNode(*start.ComputeContainerNode()), new_end));
}

void ApplyStyleCommand::SplitTextElementAtEnd(const Position& start,
                                              const Position& end) {
  DCHECK(end.ComputeContainerNode()->IsTextNode()) << end;

  bool should_update_start =
      start.ComputeContainerNode() == end.ComputeContainerNode();
  SplitTextNodeContainingElement(To<Text>(end.ComputeContainerNode()),
                                 end.OffsetInContainerNode());

  Node* parent_element = end.ComputeContainerNode()->parentNode();
  if (!parent_element || !parent_element->previousSibling())
    return;

  auto* first_text_node =
      DynamicTo<Text>(parent_element->previousSibling()->lastChild());
  if (!first_text_node)
    return;

  Position new_start =
      should_update_start
          ? Position(first_text_node, start.OffsetInContainerNode())
          : start;
  UpdateStartEnd(
      EphemeralRange(new_start, Position::AfterNode(*first_text_node)));
}

bool ApplyStyleCommand::ShouldSplitTextElement(Element* element,
                                               EditingStyle* style) {
  auto* html_element = DynamicTo<HTMLElement>(element);
  if (!html_element)
    return false;

  return ShouldRemoveInlineStyleFromElement(style, html_element);
}

bool ApplyStyleCommand::IsValidCaretPositionInTextNode(
    const Position& position) {
  DCHECK(position.IsNotNull());

  Node* node = position.ComputeContainerNode();
  if (!position.IsOffsetInAnchor() || !node->IsTextNode())
    return false;
  int offset_in_text = position.OffsetInContainerNode();
  return offset_in_text > CaretMinOffset(node) &&
         offset_in_text < CaretMaxOffset(node);
}

bool ApplyStyleCommand::MergeStartWithPreviousIfIdentical(
    const Position& start,
    const Position& end,
    EditingState* editing_state) {
  Node* start_node = start.ComputeContainerNode();
  int start_offset = start.ComputeOffsetInContainerNode();
  if (start_offset)
    return false;

  if (IsAtomicNode(start_node)) {
    // note: prior siblings could be unrendered elements. it's silly to miss the
    // merge opportunity just for that.
    if (start_node->previousSibling())
      return false;

    start_node = start_node->parentNode();
  }

  if (!start_node->IsElementNode())
   
"""


```