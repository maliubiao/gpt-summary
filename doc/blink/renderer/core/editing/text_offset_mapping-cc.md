Response:
Let's break down the thought process for analyzing the `text_offset_mapping.cc` file.

1. **Understanding the Goal:** The core request is to understand the functionality of this C++ file within the Chromium Blink rendering engine, specifically concerning its relationship to JavaScript, HTML, and CSS, along with debugging considerations.

2. **Initial Scan for Keywords and Core Concepts:**  I'd start by quickly skimming the file, looking for recurring terms and recognizable patterns. Keywords like "offset," "text," "position," "node," "layout," "inline," "block," "range," and the namespaces `blink` and `editing` immediately stand out. The `#include` directives point to related classes and utilities. This initial scan suggests the file is about mapping character offsets within the rendered text content of a web page.

3. **Identifying the Main Class:**  The name `TextOffsetMapping` in the file itself and throughout the code strongly suggests this is the central class. I'd focus on understanding its methods and members.

4. **Deconstructing the `TextOffsetMapping` Class:**
    * **Constructor:**  The constructors take an `InlineContents` object and optionally a `TextIteratorBehavior`. This suggests that `TextOffsetMapping` operates on a specific segment of inline content. The `TextIteratorBehavior` hint points to how the text content is extracted (e.g., handling of whitespace, visibility).
    * **`ComputeTextOffset`:** This method clearly calculates the character offset of a given `PositionInFlatTree`. The comparison with `range_.StartPosition()` and `range_.EndPosition()` indicates it works within a defined range. The use of `TextIteratorInFlatTree::RangeLength` confirms its role in offset calculation.
    * **`GetPositionBefore` and `GetPositionAfter`:** These methods reverse the process, finding the `PositionInFlatTree` corresponding to a given character offset. The use of `CharacterIteratorInFlatTree` reinforces the text traversal nature of the class.
    * **`ComputeRange`:** This method creates an `EphemeralRangeInFlatTree` based on start and end character offsets.
    * **`FindNonWhitespaceCharacterFrom`:** A utility method to find the next non-whitespace character.
    * **`BackwardRangeOf` and `ForwardRangeOf`:** These static methods return `BackwardRange` and `ForwardRange` objects, which manage iteration over `InlineContents` in either direction.
    * **`FindInlineContentsInternal`, `FindBackwardInlineContents`, `FindForwardInlineContents`:** These static methods are crucial for determining the relevant `InlineContents` for a given position. They involve traversing the DOM tree.
    * **Inner Classes (`BackwardRange`, `ForwardRange`, `InlineContents`):** These provide structure for managing inline content segments and their iteration. The `InlineContents` class is particularly important, defining a contiguous block of inline layout objects.

5. **Analyzing the `InlineContents` Class:**
    * **Constructor:** Takes a `LayoutBlockFlow` and optionally first/last layout objects and surrounding inline-block elements. This indicates that an `InlineContents` represents a run of inline content within a block.
    * **`GetRange`:**  Crucially, this method determines the `EphemeralRangeInFlatTree` encompassing the inline content. It handles cases with and without explicit first/last elements.
    * **`FirstPositionAfterBlockFlow` and `LastPositionBeforeBlockFlow`:** These methods find the positions immediately before and after the current `InlineContents`, useful for iterating between segments.
    * **`NextOf` and `PreviousOf`:** Static methods for obtaining the next and previous `InlineContents` segments.

6. **Connecting to JavaScript, HTML, and CSS:**
    * **JavaScript:**  The file plays a crucial role in implementing JavaScript APIs related to text selection and manipulation. Methods like `window.getSelection()`, `selection.modify()`, and working with `Range` objects rely on the accurate mapping of text offsets to DOM positions provided by this code.
    * **HTML:** The structure of the HTML directly influences how inline content is laid out and thus how `TextOffsetMapping` works. Different HTML elements (text nodes, inline elements, block-level elements) create the context for offset calculations.
    * **CSS:** CSS styling, particularly the `display` property (e.g., `inline`, `inline-block`), affects the layout of elements and whether they are considered part of an inline flow. The code explicitly handles `inline-block` elements.

7. **Inferring Functionality and Purpose:** Based on the analysis, the primary function of `text_offset_mapping.cc` is to bridge the gap between character-based offsets and the tree-like structure of the DOM. It allows the browser engine to:
    * Determine the precise DOM node and offset corresponding to a character position within the rendered text.
    * Calculate the range of DOM nodes representing a given text selection.
    * Navigate between segments of inline content.

8. **Considering Logic and Assumptions:**  The code makes assumptions about the structure of the layout tree and the behavior of different CSS properties. The comments, especially the `TODO`s and the notes about specific bug reports, provide valuable insight into edge cases and areas of ongoing development. The handling of pseudo-elements, shadow DOM, and text controls are important considerations.

9. **Identifying Potential User/Programming Errors:**  Incorrectly assuming a direct one-to-one mapping between character offsets and DOM structure is a common mistake. For example, HTML entities, line breaks, and the presence of non-text elements can complicate things. JavaScript code that tries to manipulate DOM ranges based on simple string offsets without considering the underlying DOM structure could lead to unexpected results.

10. **Debugging Scenarios:**  Understanding how a user's action leads to this code is essential for debugging. Selecting text, moving the text cursor, or using JavaScript to manipulate selections are typical user actions that would involve `TextOffsetMapping`.

11. **Structuring the Answer:** Finally, I'd organize the findings into logical sections: Functionality, Relationship to JS/HTML/CSS, Logic/Assumptions, User Errors, and Debugging. Using examples and code snippets helps illustrate the concepts. The inclusion of the "step-by-step user action" adds practical debugging context.

This systematic breakdown, from high-level overview to detailed code analysis and consideration of the surrounding context, allows for a comprehensive understanding of the `text_offset_mapping.cc` file and its role within the Blink rendering engine.好的，让我们详细分析一下 `blink/renderer/core/editing/text_offset_mapping.cc` 文件的功能。

**文件功能概述**

`text_offset_mapping.cc` 文件的核心功能是在 Blink 渲染引擎中，**将文本内容中的字符偏移量（offset）映射到 DOM 树中的具体位置（PositionInFlatTree）**，反之亦然。它还负责识别和管理文档中的**内联内容（InlineContents）**片段，这对于处理文本选择、光标移动等编辑操作至关重要。

更具体地说，这个文件提供了以下关键功能：

1. **计算文本偏移量:** 给定一个 DOM 树中的位置 (`PositionInFlatTree`)，计算该位置之前有多少个可见的字符。
2. **根据偏移量获取位置:** 给定一个字符偏移量，找到该偏移量对应的 DOM 树中的位置 (`PositionInFlatTree`)。可以获取偏移量之前或之后的位置。
3. **计算文本范围:** 给定起始和结束字符偏移量，创建一个包含这些偏移量之间内容的 DOM 树范围 (`EphemeralRangeInFlatTree`).
4. **查找非空白字符:** 从给定的偏移量开始，查找下一个非空白字符的偏移量。
5. **识别内联内容片段:**  将文档的内联内容划分为多个 `InlineContents` 片段，每个片段代表一个连续的内联布局对象的序列。
6. **在内联内容片段之间导航:**  提供了在文档中向前或向后遍历 `InlineContents` 片段的能力。

**与 JavaScript, HTML, CSS 的关系**

这个文件在 Blink 渲染引擎中扮演着桥梁的角色，连接了底层的 DOM 结构和上层的 JavaScript API 以及 CSS 样式对文本布局的影响。

* **JavaScript:**
    * **文本选择 API (`window.getSelection()`):** 当用户在网页上选择文本时，JavaScript 的 `Selection` 对象需要知道选择的起始和结束位置在 DOM 树中的哪里。`TextOffsetMapping` 帮助将用户选择的字符范围转换为 DOM 树中的 `PositionInFlatTree` 对象，从而允许引擎高亮显示选中的文本并进行复制、粘贴等操作。
        * **举例:** 用户通过鼠标拖拽选中一段文本，JavaScript 可以通过 `window.getSelection()` 获取到选中的范围。Blink 内部会使用 `TextOffsetMapping` 将选中的字符偏移量转换为对应的 DOM 节点和偏移量。
    * **Range API:** JavaScript 的 `Range` 对象用于表示文档中的一个片段。`TextOffsetMapping` 提供的功能可以帮助创建和操作 `Range` 对象，例如根据字符偏移量创建一个 `Range`。
        * **举例:** JavaScript 代码可以使用 `document.createRange()` 创建一个 `Range` 对象，然后使用 `setStart()` 和 `setEnd()` 方法来设置范围的起始和结束位置。`TextOffsetMapping` 可以根据字符偏移量计算出对应的 DOM 位置，传递给 `setStart()` 和 `setEnd()`。
    * **光标操作:** 当用户在可编辑的区域移动光标时，浏览器需要更新光标在 DOM 树中的位置。`TextOffsetMapping` 帮助将光标的字符偏移量映射到正确的 DOM 位置。
        * **举例:** 在一个 `<textarea>` 或设置了 `contenteditable` 的 `<div>` 中，用户按下左右方向键移动光标。Blink 会使用 `TextOffsetMapping` 来确定光标移动后的新 DOM 位置。
    * **`selection.modify()` 方法:** 这个方法允许 JavaScript 以单词、行等单位来扩展或移动选择。`TextOffsetMapping` 参与了确定这些单位的边界。
        * **假设输入:** 当前选择的起始位置在 "Hello world!" 字符串中 "w" 的前面。
        * **JavaScript 调用:** `window.getSelection().modify('extend', 'forward', 'word');`
        * **`TextOffsetMapping` 的输出:** 将选择的结束位置移动到 "d!" 的后面，因为 "world" 是一个单词。

* **HTML:**
    * **DOM 结构:** HTML 定义了网页的文档结构，`TextOffsetMapping` 的核心任务就是在这个 DOM 结构中进行偏移量和位置的转换。不同的 HTML 元素（如文本节点、inline 元素、block 元素）会影响文本的布局和偏移量的计算。
        * **举例:**  考虑 HTML 代码 `<span>Hello</span> <span>world</span>`。`TextOffsetMapping` 需要能够区分 "Hello" 和 "world" 两个单词的偏移量，并知道它们分别位于不同的 `<span>` 元素中。
    * **可编辑内容 (`contenteditable`):** 当 HTML 元素设置了 `contenteditable` 属性后，用户可以编辑其中的文本。`TextOffsetMapping` 在处理用户输入和光标移动时起着关键作用。

* **CSS:**
    * **文本布局:** CSS 样式影响文本的渲染和布局，例如字体、字号、行高、`display` 属性等。这些布局信息会影响字符偏移量到 DOM 位置的映射。
        * **举例:**  如果一个 `<span>` 元素设置了 `display: inline-block;`，它会被视为一个原子级的内联元素，`TextOffsetMapping` 需要考虑到这一点来正确计算偏移量。代码中 `ComputeInlineContentsAsBlockFlow` 函数就处理了 `inline-block` 元素的情况。
    * **伪元素 (`::before`, `::after`, `::first-line` 等):**  CSS 伪元素会在元素的前后插入内容或对元素的部分内容进行样式化。`TextOffsetMapping` 需要能够处理这些伪元素，并在计算偏移量时考虑它们的影响。代码注释中提到了 `::first-line` 伪元素。

**逻辑推理的假设输入与输出**

假设我们有以下简单的 HTML 结构：

```html
<div>Hello <b>world</b>!</div>
```

并且光标位于 "o" 和空格之间。

* **假设输入:**  光标的 `PositionInFlatTree` 指向文本节点 "Hello " 中 "o" 之后的位置。
* **`ComputeTextOffset` 的输出:** 计算出的偏移量可能是 5 (假设空格也算一个字符)。
* **假设输入:**  字符偏移量为 7。
* **`GetPositionBefore` 的输出:** 返回的 `PositionInFlatTree` 将指向文本节点 "world" 中 "o" 之前的位置。
* **假设输入:**  起始偏移量为 0，结束偏移量为 5。
* **`ComputeRange` 的输出:**  返回一个 `EphemeralRangeInFlatTree` 对象，该对象包含文本节点 "Hello " 的内容。

**用户或编程常见的使用错误**

* **错误地假设偏移量是线性的:**  开发者可能会错误地认为字符偏移量是文档中从头到尾的简单线性递增。但实际上，DOM 结构、HTML 标签、CSS 样式（例如 `display: none` 的元素不会被计算在内）都会影响偏移量的计算。
    * **举例:**  如果 HTML 是 `<span>a</span><span style="display:none">b</span><span>c</span>`，那么字符 "c" 的偏移量是 1，而不是 2。
* **没有考虑到文本迭代器的行为:** `TextOffsetMapping` 的行为受到 `TextIteratorBehavior` 的影响，例如是否包含不可见字符、是否将某些字符视为一个单位等。开发者如果没有正确配置 `TextIteratorBehavior`，可能会导致偏移量计算错误。
* **在异步操作后使用过期的位置信息:**  DOM 结构可能会在 JavaScript 执行期间发生变化。如果基于旧的 `PositionInFlatTree` 或偏移量进行操作，可能会导致错误。

**用户操作如何一步步到达这里作为调试线索**

1. **用户在浏览器中打开一个网页。**
2. **网页加载并渲染，Blink 引擎构建 DOM 树和布局树。**
3. **用户进行以下操作之一：**
    * **鼠标拖拽选择文本:**  用户的鼠标事件会被捕获，Blink 需要确定选择的起始和结束位置。这会触发对 `TextOffsetMapping` 的调用，将屏幕坐标转换为 DOM 位置和偏移量。
    * **在可编辑区域点击或移动光标:**  用户的键盘和鼠标事件会导致光标位置的改变。Blink 会使用 `TextOffsetMapping` 来更新光标在 DOM 树中的精确位置。
    * **使用键盘快捷键进行文本选择 (如 Shift + 箭头键):**  这些操作也会触发对选择范围的修改，最终会调用 `TextOffsetMapping` 来计算新的选择边界。
    * **JavaScript 代码操作文本选择或 Range:**  例如，JavaScript 代码调用 `window.getSelection().addRange()` 或创建一个 `Range` 对象并设置其起始和结束位置。这些操作会间接地调用 `TextOffsetMapping` 来进行 DOM 位置和偏移量的转换。
4. **在 Blink 引擎内部，当需要将用户操作引起的文本位置变化映射到 DOM 树时，或者需要将 DOM 树中的位置转换为文本偏移量时，就会执行 `text_offset_mapping.cc` 中的代码。**

**调试线索示例:**

假设用户在编辑一个 `contenteditable` 的 `<div>` 时遇到了光标定位错误。调试时可以：

1. **在 `TextOffsetMapping::ComputeTextOffset` 或 `TextOffsetMapping::GetPositionBefore` 等关键方法中设置断点。**
2. **重现用户的操作，观察断点是否被触发。**
3. **检查传递给这些方法的 `PositionInFlatTree` 对象，查看其指向的 DOM 节点和偏移量是否正确。**
4. **检查 `TextIteratorBehavior` 的配置，确保其与预期的行为一致。**
5. **查看调用堆栈，追踪用户操作是如何最终调用到 `TextOffsetMapping` 的。**

总而言之，`blink/renderer/core/editing/text_offset_mapping.cc` 是 Blink 引擎中一个至关重要的文件，它负责在文本内容的线性偏移量和 DOM 树的结构化位置之间建立精确的映射关系，是实现文本选择、光标操作等编辑功能的基础。理解其功能有助于深入理解浏览器如何处理网页上的文本内容。

### 提示词
```
这是目录为blink/renderer/core/editing/text_offset_mapping.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/text_offset_mapping.h"

#include <ostream>

#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"

namespace blink {

namespace {

// TODO(editing-dev): We may not need to do full-subtree traversal, but we're
// not sure, e.g. ::first-line. See |enum PseudoId| for list of pseudo elements
// used in Blink.
bool HasNonPsuedoNode(const LayoutObject& parent) {
  if (parent.NonPseudoNode())
    return true;
  for (const LayoutObject* runner = &parent; runner;
       runner = runner->NextInPreOrder(&parent)) {
    if (runner->NonPseudoNode())
      return true;
  }
  // Following HTML reach here:
  //  [1] <div style="columns: 5 31px">...</div>; http://crbug.com/832055
  //  [2] <select></select>; http://crbug.com/834623
  return false;
}

bool CanBeInlineContentsContainer(const LayoutObject& layout_object) {
  const auto* block_flow = DynamicTo<LayoutBlockFlow>(layout_object);
  if (!block_flow)
    return false;
  if (!block_flow->ChildrenInline() || block_flow->IsAtomicInlineLevel())
    return false;
  if (block_flow->IsRuby()) {
    // We should not make |LayoutRubyAsBlock| as inline contents container,
    // because ruby base text comes after ruby text in layout tree.
    // See ParameterizedTextOffsetMappingTest.RangeOfBlockWithRubyAsBlock
    return false;
  }
  if (block_flow->NonPseudoNode()) {
    // It is OK as long as |block_flow| is associated to non-pseudo |Node| even
    // if it is empty block or containing only anonymous objects.
    // See LinkSelectionClickEventsTest.SingleAndDoubleClickWillBeHandled
    return true;
  }
  // Since we can't create |EphemeralRange|, we exclude a |LayoutBlockFlow| if
  // its entire subtree is anonymous, e.g. |LayoutMultiColumnSet|,
  // and with anonymous layout objects.
  return HasNonPsuedoNode(*block_flow);
}

Node* PreviousNodeSkippingAncestors(const Node& node) {
  ContainerNode* parent = FlatTreeTraversal::Parent(node);
  for (Node* runner = FlatTreeTraversal::Previous(node); runner;
       runner = FlatTreeTraversal::Previous(*runner)) {
    if (runner != parent)
      return runner;
    parent = FlatTreeTraversal::Parent(*runner);
  }
  return nullptr;
}

// Returns outer most nested inline formatting context.
const LayoutBlockFlow& RootInlineContentsContainerOf(
    const LayoutBlockFlow& block_flow) {
  DCHECK(block_flow.ChildrenInline()) << block_flow;
  const LayoutBlockFlow* root_block_flow = &block_flow;
  for (const LayoutBlock* runner = block_flow.ContainingBlock(); runner;
       runner = runner->ContainingBlock()) {
    auto* containing_block_flow = DynamicTo<LayoutBlockFlow>(runner);
    if (!containing_block_flow || !runner->ChildrenInline())
      break;
    root_block_flow = containing_block_flow;
  }
  DCHECK(!root_block_flow->IsAtomicInlineLevel())
      << block_flow << ' ' << root_block_flow;
  return *root_block_flow;
}

bool ShouldSkipChildren(const Node& node) {
  if (IsTextControl(node))
    return true;
  const ShadowRoot* const root = node.GetShadowRoot();
  return root && root->IsUserAgent();
}

LayoutObject* NextForInlineContents(const LayoutObject& layout_object,
                                    const LayoutObject& container) {
  if (layout_object.IsBlockInInline())
    return layout_object.NextInPreOrderAfterChildren(&container);
  const Node* const node = layout_object.NonPseudoNode();
  if (node && ShouldSkipChildren(*node))
    return layout_object.NextInPreOrderAfterChildren(&container);
  return layout_object.NextInPreOrder(&container);
}

const Node* FindFirstNonPseudoNodeIn(const LayoutObject& container) {
  for (const LayoutObject* layout_object = container.SlowFirstChild();
       layout_object;
       layout_object = NextForInlineContents(*layout_object, container)) {
    if (auto* node = layout_object->NonPseudoNode())
      return node;
  }
  return nullptr;
}

const Node* FindLastNonPseudoNodeIn(const LayoutObject& container) {
  const Node* last_node = nullptr;
  for (const LayoutObject* layout_object = container.SlowFirstChild();
       layout_object;
       layout_object = NextForInlineContents(*layout_object, container)) {
    if (auto* node = layout_object->NonPseudoNode())
      last_node = node;
  }
  return last_node;
}

// TODO(editing-dev): We should have |ComputeInlineContents()| computing first
// and last layout objects representing a run of inline layout objects in
// |LayoutBlockFlow| instead of using |ComputeInlineContentsAsBlockFlow()|.
//
// For example "<p>a<b>CD<p>EF</p>G</b>h</p>", where b has display:inline-block.
// We should have three ranges:
//  1. aCD
//  2. EF
//  3. Gh
// See RangeWithNestedInlineBlock* tests.

// Note: Since "inline-block" is not considered as text segment
// boundary, we should not consider it as block for scanning.
// Example in selection text:
//  <div>|ab<b style="display:inline-block">CD</b>ef</div>
//  selection.modify('extent', 'forward', 'word')
//  <div>^ab<b style="display:inline-block">CD</b>ef|</div>
// See also test cases for "inline-block" and "float" in |TextIterator|
//
// This is a helper function to compute inline layout object run from
// |LayoutBlockFlow|.
const LayoutBlockFlow* ComputeInlineContentsAsBlockFlow(
    const LayoutObject& layout_object) {
  const auto* block = DynamicTo<LayoutBlock>(layout_object);
  if (!block)
    block = layout_object.ContainingBlock();

  DCHECK(block) << layout_object;
  const auto* block_flow = DynamicTo<LayoutBlockFlow>(block);
  if (!block_flow)
    return nullptr;
  if (!block_flow->ChildrenInline())
    return nullptr;
  if (block_flow->IsAtomicInlineLevel() ||
      (!RuntimeEnabledFeatures::
           TextSegmentBoundaryForElementWithFloatStyleEnabled() &&
       block_flow->IsFloatingOrOutOfFlowPositioned())) {
    const LayoutBlockFlow& root_block_flow =
        RootInlineContentsContainerOf(*block_flow);
    // Skip |root_block_flow| if it's an anonymous wrapper created for
    // pseudo elements. See test AnonymousBlockFlowWrapperForFloatPseudo.
    if (!CanBeInlineContentsContainer(root_block_flow))
      return nullptr;
    return &root_block_flow;
  }
  if (!CanBeInlineContentsContainer(*block_flow))
    return nullptr;
  return block_flow;
}

TextOffsetMapping::InlineContents CreateInlineContentsFromBlockFlow(
    const LayoutBlockFlow& block_flow,
    const LayoutObject& target) {
  DCHECK(block_flow.ChildrenInline()) << block_flow;
  DCHECK(target.NonPseudoNode()) << target;
  const LayoutObject* layout_object = nullptr;
  const LayoutObject* block_in_inline_before = nullptr;
  const LayoutObject* first = nullptr;
  const LayoutObject* last = nullptr;
  for (layout_object = block_flow.FirstChild(); layout_object;
       layout_object = NextForInlineContents(*layout_object, block_flow)) {
    if (layout_object->NonPseudoNode()) {
      last = layout_object;
      if (!first)
        first = layout_object;
    }
    if (layout_object == &target) {
      // Note: When |target| is in subtree of user agent shadow root, we don't
      // reach here. See  http://crbug.com/1224206
      last = first;
      break;
    }
    if (layout_object->IsBlockInInline()) {
      if (target.IsDescendantOf(layout_object)) {
        // Note: We reach here when `target` is `position:absolute` or
        // `position:fixed`, aka `IsOutOfFlowPositioned()`, because
        // `LayoutObject::ContainingBlock()` handles them specially.
        // See http://crbug.com/1324970
        last = first;
        break;
      }
      block_in_inline_before = layout_object;
      first = last = nullptr;
    }
  }
  if (!first) {
    DCHECK(block_flow.NonPseudoNode()) << block_flow;
    return TextOffsetMapping::InlineContents(block_flow);
  }
  const LayoutObject* block_in_inline_after = nullptr;
  for (; layout_object;
       layout_object = NextForInlineContents(*layout_object, block_flow)) {
    if (layout_object->IsBlockInInline()) {
      block_in_inline_after = layout_object;
      break;
    }
    if (layout_object->NonPseudoNode()) {
      last = layout_object;
    }
  }
  DCHECK(last);
  return TextOffsetMapping::InlineContents(
      block_flow, block_in_inline_before, *first, *last, block_in_inline_after);
}

TextOffsetMapping::InlineContents ComputeInlineContentsFromNode(
    const Node& node) {
  const LayoutObject* const layout_object = node.GetLayoutObject();
  if (!layout_object)
    return TextOffsetMapping::InlineContents();
  const LayoutBlockFlow* const block_flow =
      ComputeInlineContentsAsBlockFlow(*layout_object);
  if (!block_flow)
    return TextOffsetMapping::InlineContents();
  return CreateInlineContentsFromBlockFlow(*block_flow, *layout_object);
}

String Ensure16Bit(const String& text) {
  String text16(text);
  text16.Ensure16Bit();
  return text16;
}

}  // namespace

TextOffsetMapping::TextOffsetMapping(const InlineContents& inline_contents,
                                     const TextIteratorBehavior& behavior)
    : behavior_(behavior),
      range_(inline_contents.GetRange()),
      text16_(Ensure16Bit(PlainText(range_, behavior_))) {}

TextOffsetMapping::TextOffsetMapping(const InlineContents& inline_contents)
    : TextOffsetMapping(inline_contents,
                        TextIteratorBehavior::Builder()
                            .SetEmitsCharactersBetweenAllVisiblePositions(true)
                            .SetEmitsSmallXForTextSecurity(true)
                            .Build()) {}

int TextOffsetMapping::ComputeTextOffset(
    const PositionInFlatTree& position) const {
  if (position <= range_.StartPosition())
    return 0;
  if (position >= range_.EndPosition())
    return text16_.length();
  return TextIteratorInFlatTree::RangeLength(range_.StartPosition(), position,
                                             behavior_);
}

PositionInFlatTree TextOffsetMapping::GetPositionBefore(unsigned offset) const {
  DCHECK_LE(offset, text16_.length());
  CharacterIteratorInFlatTree iterator(range_, behavior_);
  if (offset >= 1 && offset == text16_.length()) {
    iterator.Advance(offset - 1);
    return iterator.GetPositionAfter();
  }
  iterator.Advance(offset);
  return iterator.GetPositionBefore();
}

PositionInFlatTree TextOffsetMapping::GetPositionAfter(unsigned offset) const {
  DCHECK_LE(offset, text16_.length());
  CharacterIteratorInFlatTree iterator(range_, behavior_);
  iterator.Advance(offset);
  return iterator.GetPositionAfter();
}

EphemeralRangeInFlatTree TextOffsetMapping::ComputeRange(unsigned start,
                                                         unsigned end) const {
  DCHECK_LE(end, text16_.length());
  DCHECK_LE(start, end);
  if (start == end)
    return EphemeralRangeInFlatTree();
  return EphemeralRangeInFlatTree(GetPositionBefore(start),
                                  GetPositionAfter(end));
}

unsigned TextOffsetMapping::FindNonWhitespaceCharacterFrom(
    unsigned offset) const {
  for (unsigned runner = offset; runner < text16_.length(); ++runner) {
    if (!IsWhitespace(text16_[runner]))
      return runner;
  }
  return text16_.length();
}

// static
TextOffsetMapping::BackwardRange TextOffsetMapping::BackwardRangeOf(
    const PositionInFlatTree& position) {
  return BackwardRange(FindBackwardInlineContents(position));
}

// static
TextOffsetMapping::ForwardRange TextOffsetMapping::ForwardRangeOf(
    const PositionInFlatTree& position) {
  return ForwardRange(FindForwardInlineContents(position));
}

// static
template <typename Traverser>
TextOffsetMapping::InlineContents TextOffsetMapping::FindInlineContentsInternal(
    const Node* start_node,
    Traverser traverser) {
  for (const Node* node = start_node; node; node = traverser(*node)) {
    const InlineContents inline_contents = ComputeInlineContentsFromNode(*node);
    if (inline_contents.IsNotNull())
      return inline_contents;
  }
  return InlineContents();
}

// static
TextOffsetMapping::InlineContents TextOffsetMapping::FindBackwardInlineContents(
    const PositionInFlatTree& position) {
  const Node* previous_node = position.NodeAsRangeLastNode();
  if (!previous_node)
    return InlineContents();

  if (const TextControlElement* enclosing_text_control =
          EnclosingTextControl(position)) {
    if (!FlatTreeTraversal::IsDescendantOf(*previous_node,
                                           *enclosing_text_control)) {
      // The first position in a text control reaches here.
      return InlineContents();
    }

    return TextOffsetMapping::FindInlineContentsInternal(
        previous_node, [enclosing_text_control](const Node& node) {
          return FlatTreeTraversal::Previous(node, enclosing_text_control);
        });
  }

  auto previous_skipping_text_control = [](const Node& node) -> const Node* {
    DCHECK(!EnclosingTextControl(&node));
    const Node* previous = PreviousNodeSkippingAncestors(node);
    if (!previous)
      return previous;
    const TextControlElement* previous_text_control =
        EnclosingTextControl(previous);
    if (previous_text_control)
      return previous_text_control;
    if (ShadowRoot* root = previous->ContainingShadowRoot()) {
      if (root->IsUserAgent())
        return root->OwnerShadowHost();
    }
    return previous;
  };

  if (const TextControlElement* last_enclosing_text_control =
          EnclosingTextControl(previous_node)) {
    // Example, <input value=foo><span>bar</span>, span@beforeAnchor
    return TextOffsetMapping::FindInlineContentsInternal(
        last_enclosing_text_control, previous_skipping_text_control);
  }
  return TextOffsetMapping::FindInlineContentsInternal(
      previous_node, previous_skipping_text_control);
}

// static
// Note: "doubleclick-whitespace-img-crash.html" call |NextWordPosition())
// with AfterNode(IMG) for <body><img></body>
TextOffsetMapping::InlineContents TextOffsetMapping::FindForwardInlineContents(
    const PositionInFlatTree& position) {
  const Node* next_node = position.NodeAsRangeFirstNode();
  if (!next_node)
    return InlineContents();

  if (const TextControlElement* enclosing_text_control =
          EnclosingTextControl(position)) {
    if (!FlatTreeTraversal::IsDescendantOf(*next_node,
                                           *enclosing_text_control)) {
      // The last position in a text control reaches here.
      return InlineContents();
    }

    return TextOffsetMapping::FindInlineContentsInternal(
        next_node, [enclosing_text_control](const Node& node) {
          return FlatTreeTraversal::Next(node, enclosing_text_control);
        });
  }

  auto next_skipping_text_control = [](const Node& node) {
    DCHECK(!EnclosingTextControl(&node));
    if (ShouldSkipChildren(node))
      return FlatTreeTraversal::NextSkippingChildren(node);
    return FlatTreeTraversal::Next(node);
  };
  DCHECK(!EnclosingTextControl(next_node));
  return TextOffsetMapping::FindInlineContentsInternal(
      next_node, next_skipping_text_control);
}

// ----

TextOffsetMapping::InlineContents::InlineContents(
    const LayoutBlockFlow& block_flow)
    : block_flow_(&block_flow) {
  DCHECK(block_flow_->NonPseudoNode());
  DCHECK(CanBeInlineContentsContainer(*block_flow_)) << block_flow_;
}

// |first| and |last| should not be anonymous object.
// Note: "extend_selection_10_ltr_backward_word.html" has a block starts with
// collapsible whitespace with anonymous object.
TextOffsetMapping::InlineContents::InlineContents(
    const LayoutBlockFlow& block_flow,
    const LayoutObject* block_in_inline_before,
    const LayoutObject& first,
    const LayoutObject& last,
    const LayoutObject* block_in_inline_after)
    : block_flow_(&block_flow),
      block_in_inline_before_(block_in_inline_before),
      first_(&first),
      last_(&last),
      block_in_inline_after_(block_in_inline_after) {
  DCHECK(!block_in_inline_before_ || block_in_inline_before_->IsBlockInInline())
      << block_in_inline_before_;
  DCHECK(!block_in_inline_after_ || block_in_inline_after_->IsBlockInInline())
      << block_in_inline_after_;
  DCHECK(first_->NonPseudoNode()) << first_;
  DCHECK(last_->NonPseudoNode()) << last_;
  DCHECK(CanBeInlineContentsContainer(*block_flow_)) << block_flow_;
  DCHECK(first_->IsDescendantOf(block_flow_));
  DCHECK(last_->IsDescendantOf(block_flow_));
}

bool TextOffsetMapping::InlineContents::operator==(
    const InlineContents& other) const {
  return block_flow_ == other.block_flow_;
}

const LayoutBlockFlow* TextOffsetMapping::InlineContents::GetEmptyBlock()
    const {
  DCHECK(block_flow_ && !first_ && !last_);
  return block_flow_;
}

const LayoutObject& TextOffsetMapping::InlineContents::FirstLayoutObject()
    const {
  DCHECK(first_);
  return *first_;
}

const LayoutObject& TextOffsetMapping::InlineContents::LastLayoutObject()
    const {
  DCHECK(last_);
  return *last_;
}

EphemeralRangeInFlatTree TextOffsetMapping::InlineContents::GetRange() const {
  DCHECK(block_flow_);
  if (!first_) {
    const Node& node = *block_flow_->NonPseudoNode();
    return EphemeralRangeInFlatTree(
        PositionInFlatTree::FirstPositionInNode(node),
        PositionInFlatTree::LastPositionInNode(node));
  }
  const Node& first_node = *first_->NonPseudoNode();
  const Node& last_node = *last_->NonPseudoNode();
  auto* first_text_node = DynamicTo<Text>(first_node);
  auto* last_text_node = DynamicTo<Text>(last_node);
  return EphemeralRangeInFlatTree(
      first_text_node ? PositionInFlatTree(first_node, 0)
                      : PositionInFlatTree::BeforeNode(first_node),
      last_text_node ? PositionInFlatTree(last_node, last_text_node->length())
                     : PositionInFlatTree::AfterNode(last_node));
}

PositionInFlatTree
TextOffsetMapping::InlineContents::LastPositionBeforeBlockFlow() const {
  DCHECK(block_flow_);
  if (block_in_inline_before_) {
    for (const LayoutObject* block = block_in_inline_before_->SlowLastChild();
         block; block = block->PreviousSibling()) {
      if (auto* block_node = block->NonPseudoNode())
        return PositionInFlatTree::LastPositionInNode(*block_node);
      if (auto* last_node = FindLastNonPseudoNodeIn(*block)) {
        return PositionInFlatTree::AfterNode(*last_node);
      }
    }
  }
  if (const Node* node = block_flow_->NonPseudoNode()) {
    if (!FlatTreeTraversal::Parent(*node)) {
      // Reached start of document.
      return PositionInFlatTree();
    }
    return PositionInFlatTree::BeforeNode(*node);
  }
  DCHECK(first_);
  DCHECK(first_->NonPseudoNode());
  DCHECK(FlatTreeTraversal::Parent(*first_->NonPseudoNode()));
  return PositionInFlatTree::BeforeNode(*first_->NonPseudoNode());
}

PositionInFlatTree
TextOffsetMapping::InlineContents::FirstPositionAfterBlockFlow() const {
  DCHECK(block_flow_);
  if (block_in_inline_after_) {
    for (const LayoutObject* block = block_in_inline_after_->SlowFirstChild();
         block; block = block->NextSibling()) {
      if (auto* block_node = block->NonPseudoNode())
        return PositionInFlatTree::BeforeNode(*block_node);
      if (auto* first_node = FindFirstNonPseudoNodeIn(*block)) {
        return PositionInFlatTree::BeforeNode(*first_node);
      }
    }
  }
  if (const Node* node = block_flow_->NonPseudoNode()) {
    if (!FlatTreeTraversal::Parent(*node)) {
      // Reached end of document.
      return PositionInFlatTree();
    }
    return PositionInFlatTree::AfterNode(*node);
  }
  DCHECK(last_);
  DCHECK(last_->NonPseudoNode());
  DCHECK(FlatTreeTraversal::Parent(*last_->NonPseudoNode()));
  return PositionInFlatTree::AfterNode(*last_->NonPseudoNode());
}

// static
TextOffsetMapping::InlineContents TextOffsetMapping::InlineContents::NextOf(
    const InlineContents& inline_contents) {
  const PositionInFlatTree position_after =
      inline_contents.FirstPositionAfterBlockFlow();
  if (position_after.IsNull())
    return InlineContents();
  return TextOffsetMapping::FindForwardInlineContents(position_after);
}

// static
TextOffsetMapping::InlineContents TextOffsetMapping::InlineContents::PreviousOf(
    const InlineContents& inline_contents) {
  const PositionInFlatTree position_before =
      inline_contents.LastPositionBeforeBlockFlow();
  if (position_before.IsNull())
    return InlineContents();
  return TextOffsetMapping::FindBackwardInlineContents(position_before);
}

std::ostream& operator<<(
    std::ostream& ostream,
    const TextOffsetMapping::InlineContents& inline_contents) {
  return ostream << '[' << inline_contents.FirstLayoutObject() << ", "
                 << inline_contents.LastLayoutObject() << ']';
}

// ----

TextOffsetMapping::InlineContents TextOffsetMapping::BackwardRange::Iterator::
operator*() const {
  DCHECK(current_.IsNotNull());
  return current_;
}

void TextOffsetMapping::BackwardRange::Iterator::operator++() {
  DCHECK(current_.IsNotNull());
  current_ = TextOffsetMapping::InlineContents::PreviousOf(current_);
}

// ----

TextOffsetMapping::InlineContents TextOffsetMapping::ForwardRange::Iterator::
operator*() const {
  DCHECK(current_.IsNotNull());
  return current_;
}

void TextOffsetMapping::ForwardRange::Iterator::operator++() {
  DCHECK(current_.IsNotNull());
  current_ = TextOffsetMapping::InlineContents::NextOf(current_);
}

}  // namespace blink
```