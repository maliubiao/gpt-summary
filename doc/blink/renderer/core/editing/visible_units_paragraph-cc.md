Response:
Let's break down the thought process for analyzing the `visible_units_paragraph.cc` file.

1. **Initial Scan and Purpose Identification:**  The first thing I'd do is quickly scan the code for keywords and structural elements. I see `#include`, namespaces (`blink`), function definitions (`StartOfParagraph`, `EndOfParagraph`, `IsStartOfParagraph`, etc.), and comments. The filename itself, "visible_units_paragraph.cc", strongly suggests that this code deals with the concept of paragraphs as visible units within the Blink rendering engine.

2. **Core Functionality - The "What":**  The function names are very descriptive: `StartOfParagraph`, `EndOfParagraph`, `StartOfNextParagraph`, `InSameParagraph`, `IsStartOfParagraph`, `IsEndOfParagraph`, and `ExpandToParagraphBoundary`. This immediately tells me the primary purpose of this file: to define how Blink determines the start and end of paragraphs for various editing operations.

3. **Key Concepts - The "How":** I then delve into the function implementations. I notice the following recurring patterns and concepts:
    * **`VisiblePosition` and `Position`:** These are fundamental classes in Blink's editing model, representing locations within the DOM tree. The distinction between them (visible vs. deep) is important.
    * **`EditingStrategy` and `EditingInFlatTreeStrategy`:** These template parameters suggest different ways of traversing the DOM, likely related to shadow DOM or flattened tree representations.
    * **`EditingBoundaryCrossingRule`:** This enum appears frequently, indicating different behaviors when encountering editable/non-editable boundaries within the document.
    * **Traversal Logic (Forward and Backward):** The code iterates through the DOM using methods like `PreviousPostOrder`, `Next`, `NextSkippingChildren`, etc., to find paragraph boundaries.
    * **Layout Information:**  The code interacts with `LayoutObject` and `ComputedStyle` to check for line breaks (`<br>`), block boundaries, visibility, and `user-select: all`.
    * **Text Handling:** It specifically looks for newline characters (`\n`) within text nodes, respecting `white-space: pre-*` styles.
    * **Special Cases:** There are checks for tables, images, and horizontal rules (`<hr>`), indicating these elements can influence paragraph boundaries.
    * **Editable Regions:** The code considers whether nodes are editable and uses `HighestEditableRoot` to limit traversal.

4. **Relating to Web Technologies (HTML, CSS, JavaScript):** Now I connect these internal Blink concepts to the web technologies they represent:
    * **HTML:** Paragraphs are primarily defined by `<p>` tags, but other block-level elements can also create paragraph-like structures. `<br>` tags are explicit line breaks within a paragraph. `user-select: all` is a CSS property affecting selection behavior. Tables (`<table>`) can influence paragraph segmentation.
    * **CSS:**  `white-space: pre`, `pre-wrap`, `pre-line` directly affect how whitespace and newlines are rendered and thus influence paragraph boundaries as detected by this code. `visibility: hidden` elements are skipped. `display: table-inside` elements are treated specially.
    * **JavaScript:** JavaScript can manipulate the DOM structure, insert/remove elements, and change styles. This can indirectly trigger the logic in `visible_units_paragraph.cc` when the user interacts with the page or when scripts modify the content. Specifically, selection and caret positioning are key scenarios.

5. **Logical Reasoning (Assumptions and Outputs):** To illustrate the logic, I create simple examples:
    * **Input:** A cursor position within a text node.
    * **Output:** The `VisiblePosition` at the very beginning of the paragraph.
    * **Input:** A cursor at the beginning of a `<p>` tag.
    * **Output:** The same position.
    * **Input:** A cursor just before a `<br>`.
    * **Output:** The `VisiblePosition` just before the `<br>`.

6. **Common Usage Errors (Developer Perspective):** I consider how a developer might misuse or misunderstand these concepts:
    * **Incorrectly assuming `<br>` always starts a new paragraph:** It's a line break *within* a paragraph.
    * **Not considering `white-space` CSS:**  Assuming newlines in the HTML source always create paragraph breaks.
    * **Overlooking editable boundaries:**  Expecting paragraph navigation to cross into non-editable regions without specifying the correct boundary crossing rule.

7. **User Interaction and Debugging:**  I trace back how a user action might lead to this code being executed:
    * **Typing text:**  The caret needs to know where the paragraph boundaries are for line wrapping and selection.
    * **Moving the caret (arrow keys, mouse clicks):** The browser needs to calculate the next/previous paragraph boundary.
    * **Selecting text (dragging the mouse, Shift+arrow keys):**  The selection needs to expand to paragraph boundaries.
    * **Copying and pasting:**  The browser might need to determine the paragraph structure of the copied content.

8. **Structure and Organization of the Explanation:** Finally, I organize my findings into logical sections: function, relationships, reasoning, errors, and debugging. Using clear headings and bullet points makes the information easier to digest. I also make sure to include specific code snippets and examples where appropriate.

Essentially, the process involves understanding the code's *purpose*, dissecting its *mechanisms*, connecting it to broader *web concepts*, illustrating its *logic*, identifying potential *pitfalls*, and understanding its role in the *user experience* and *debugging process*.
这个文件 `visible_units_paragraph.cc` 是 Chromium Blink 引擎中负责处理文本段落级别可见单元操作的核心代码。它的主要功能是定义和实现了一系列算法，用于确定文本内容中段落的起始和结束位置，以及在段落之间进行导航。

以下是对其功能的详细列举和说明：

**主要功能:**

1. **定义段落的起始和结束:**  该文件包含用于确定给定位置所在段落的起始和结束位置的算法。这涉及到遍历 DOM 树，考虑各种因素，例如：
    * **块级元素:**  `<p>`, `<div>`, `<h1>` 等块级元素通常标志着段落的开始或结束。
    * **换行符 (`<br>`):** `<br>` 标签会在段落内创建软换行。
    * **`white-space` CSS 属性:**  `white-space: pre`, `white-space: pre-wrap`, `white-space: pre-line` 等属性会影响如何识别段落内的换行。
    * **可编辑边界:**  考虑内容是否可编辑，以及是否允许跨越可编辑边界进行段落导航。
    * **`user-select: all` CSS 属性:**  具有此属性的元素内的内容被视为一个独立的单元。
    * **表格和图片等特殊元素:**  处理表格单元格、图片等元素对段落边界的影响。

2. **段落导航:**  提供了在段落之间移动光标或进行选择的功能，例如：
    * **`StartOfNextParagraph`:**  找到下一个段落的起始位置。
    * **`InSameParagraph`:**  判断两个给定的位置是否在同一个段落内。

3. **判断是否在段落的起始或结束:**  提供了判断给定位置是否是其所在段落的起始或结束位置的功能。

4. **扩展选区到段落边界:**  `ExpandToParagraphBoundary` 函数可以将一个给定的选区（`EphemeralRange`) 扩展到包含该选区的整个段落的边界。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这个文件中的代码是 Blink 渲染引擎的一部分，它负责解析和渲染 HTML、CSS，并响应用户的交互和 JavaScript 的操作。

* **HTML:**
    * **段落分隔:**  HTML 的 `<p>` 标签是最直接的段落定义方式。`visible_units_paragraph.cc` 中的算法会识别这些标签作为段落的边界。
    * **换行:**  `<br>` 标签在 HTML 中表示强制换行，该文件会考虑 `<br>` 对段落划分的影响。
    * **其他块级元素:**  `<div>`, `<h1>` 等块级元素也会被视为段落分隔符。

    **例子:**
    ```html
    <p>This is the first paragraph.</p>
    <div>This is content in a div, treated as a separate paragraph.</div>
    <p>This is the second paragraph with a <br> line break.</p>
    ```
    在这个例子中，`visible_units_paragraph.cc` 的算法会将三个不同的部分识别为三个独立的段落。

* **CSS:**
    * **`white-space`:**  CSS 的 `white-space` 属性决定了如何处理元素中的空白符和换行符。
        * `white-space: normal` (默认):  多个空格合并为一个，换行符被忽略（除非是块级元素）。
        * `white-space: pre`:  保留所有的空格和换行符。
        * `white-space: pre-wrap`:  保留空格和换行符，并在必要时换行。
        * `white-space: pre-line`:  合并空格，但保留换行符。

    **例子:**
    ```html
    <p style="white-space: pre;">This is a paragraph
    with multiple
    lines.</p>
    ```
    当 `white-space` 设置为 `pre` 时，`visible_units_paragraph.cc` 的算法会识别出段落内的换行符并进行相应的处理。

    * **`user-select: all`:**  当一个元素的 CSS 属性 `user-select` 设置为 `all` 时，用户点击该元素时会选中整个元素的内容。`visible_units_paragraph.cc` 会将具有此属性的元素视为一个独立的单元，在段落导航时会跳过其内部。

* **JavaScript:**
    * **DOM 操作:** JavaScript 可以动态地修改 DOM 结构，例如插入、删除元素。这些操作可能会影响段落的边界，`visible_units_paragraph.cc` 的逻辑会在 DOM 结构变化后重新计算段落边界。
    * **Selection API:** JavaScript 的 Selection API 允许获取和修改用户选中的文本范围。`visible_units_paragraph.cc` 中的函数，例如 `ExpandToParagraphBoundary`，可能会被 Selection API 的实现所使用，以便将选区扩展到整个段落。

    **例子:**
    ```javascript
    const paragraph = document.querySelector('p');
    const startOfParagraph = blink.StartOfParagraph(paragraph); // 假设 blink 对象提供了访问 Blink 内部功能的接口
    ```
    虽然 JavaScript 不能直接调用 C++ 代码，但 JavaScript 的高级功能（如选区操作）的实现会依赖于 Blink 引擎的底层机制，而 `visible_units_paragraph.cc` 就提供了这些机制。

**逻辑推理 (假设输入与输出):**

假设我们有以下 HTML 结构：

```html
<p>This is the first line.<br>This is the second line.</p>
```

**假设输入:** 光标位于 "second" 这个单词的开头。

**输出 (`StartOfParagraph`):**  返回指向 "This is the first line." 的起始位置的 `VisiblePosition` 对象。

**输出 (`EndOfParagraph`):** 返回指向 "This is the second line." 的末尾位置的 `VisiblePosition` 对象。

**假设输入:** 光标位于 `<p>` 标签的开头。

**输出 (`IsStartOfParagraph`):** 返回 `true`。

**假设输入:** 光标位于 "line." 的末尾。

**输出 (`IsEndOfParagraph`):** 返回 `true`。

**用户或编程常见的使用错误:**

1. **错误地假设 `<br>` 标签会开始一个新的段落。**  `<br>` 只是在当前段落内创建一个换行，并不会像 `<p>` 那样分割段落。用户可能会期望按下 Enter 键创建新的段落，但如果编辑器只插入 `<br>`，则会被视为同一个段落。

2. **不理解 `white-space` 属性对段落划分的影响。**  开发者可能会在代码中使用换行来组织文本，但如果 CSS 设置了 `white-space: normal`，这些换行将被忽略，所有内容会被视为一个长段落。

3. **在可编辑区域和非可编辑区域之间进行段落导航时，没有考虑到 `EditingBoundaryCrossingRule`。**  如果代码期望在按下 Ctrl+上/下箭头时跨越非可编辑区域跳转到上/下一个段落，但没有设置合适的边界穿越规则，则可能会停留在可编辑区域的边界。

**用户操作如何一步步地到达这里 (调试线索):**

1. **用户在可编辑的网页内容中进行文本编辑:**  这是最常见的情况。当用户在文本框或 `contenteditable` 元素中输入、删除、移动光标或选择文本时，Blink 引擎需要跟踪光标的位置和选区的范围。

2. **用户按下键盘上的方向键 (上/下箭头):**  当用户按下上或下箭头键时，浏览器需要计算光标应该移动到的位置。如果用户同时按下了 Ctrl 键 (或者 Command 键在 macOS 上)，浏览器通常会尝试将光标移动到上一个或下一个段落的开头或结尾。这时，`StartOfParagraph` 和 `EndOfParagraph` 等函数会被调用来确定段落的边界。

3. **用户使用鼠标进行文本选择:**  当用户拖动鼠标选择文本时，浏览器需要实时更新选区的范围。`ExpandToParagraphBoundary` 函数可能会被用来实现 "按段落选择" 的功能，或者在某些情况下，作为扩展选区的逻辑的一部分。

4. **用户执行复制或粘贴操作:**  当用户复制一段文本时，浏览器可能需要确定被复制内容的段落结构，以便在粘贴时保持格式。

5. **JavaScript 代码操作 Selection API:**  如果 JavaScript 代码使用 `window.getSelection()` 或 `document.createRange()` 等 API 来获取或修改选区，这些操作最终会依赖于 Blink 引擎的底层实现，包括 `visible_units_paragraph.cc` 中的逻辑。

**作为调试线索:**

如果你在调试 Blink 引擎中与文本编辑或选区相关的 Bug，并且涉及到跨段落的操作，那么 `visible_units_paragraph.cc` 文件很可能是一个关键的调查点。你可以：

* **设置断点:**  在 `StartOfParagraph`, `EndOfParagraph` 等函数的入口处设置断点，观察在特定用户操作下这些函数是如何被调用的，以及传入的参数和计算结果。
* **查看调用栈:**  当程序执行到 `visible_units_paragraph.cc` 中的代码时，查看调用栈可以帮助你理解这个函数的调用路径，从而找到触发这段代码的用户操作或 JavaScript 代码。
* **分析 DOM 结构和 CSS 样式:**  仔细检查相关的 HTML 结构和 CSS 样式，确保它们与你对段落边界的预期一致。特别是 `white-space` 和 `user-select` 属性可能会导致意想不到的行为。

总而言之，`visible_units_paragraph.cc` 是 Blink 引擎中处理文本编辑和呈现中段落概念的关键组成部分，它连接了 HTML 结构、CSS 样式以及用户的交互行为。理解其功能对于调试与文本编辑相关的渲染问题至关重要。

Prompt: 
```
这是目录为blink/renderer/core/editing/visible_units_paragraph.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009 Apple Inc. All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/visible_units.h"

#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"

namespace blink {

namespace {

bool NodeIsUserSelectAll(const Node* node) {
  return node && node->GetLayoutObject() &&
         node->GetLayoutObject()->Style()->UsedUserSelect() ==
             EUserSelect::kAll;
}

template <typename Strategy>
PositionTemplate<Strategy> StartOfParagraphAlgorithm(
    const PositionTemplate<Strategy>& position,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  Node* const start_node = position.AnchorNode();

  if (!start_node)
    return PositionTemplate<Strategy>();

  if (IsRenderedAsNonInlineTableImageOrHR(start_node))
    return PositionTemplate<Strategy>::BeforeNode(*start_node);

  Element* const start_block = EnclosingBlock(
      PositionTemplate<Strategy>::FirstPositionInOrBeforeNode(*start_node),
      kCannotCrossEditingBoundary);
  ContainerNode* const highest_root = HighestEditableRoot(position);
  const bool start_node_is_editable = IsEditable(*start_node);

  Node* candidate_node = start_node;
  PositionAnchorType candidate_type = position.AnchorType();
  int candidate_offset = position.ComputeEditingOffset();

  Node* previous_node_iterator = start_node;
  auto previousNodeSkippingChildren = [&]() -> Node* {
    // Like Strategy::PreviousPostOrder(*previous_node_iterator, start_block),
    // but skipping children.
    for (const Node* parent = previous_node_iterator; parent;
         parent = Strategy::Parent(*parent)) {
      if (parent == start_block)
        return nullptr;
      if (Node* previous_sibling = Strategy::PreviousSibling(*parent))
        return previous_sibling;
    }
    return nullptr;
  };
  auto previousNode = [&]() -> Node* {
    DCHECK(previous_node_iterator);
    if (previous_node_iterator == start_node) {
      // For the first iteration, take the anchor type and offset into account.
      Node* before_position = position.ComputeNodeBeforePosition();
      if (!before_position)
        return previousNodeSkippingChildren();
      if (before_position != previous_node_iterator)
        return before_position;
    }
    return Strategy::PreviousPostOrder(*previous_node_iterator, start_block);
  };

  while (previous_node_iterator) {
    if (boundary_crossing_rule == kCannotCrossEditingBoundary &&
        !NodeIsUserSelectAll(previous_node_iterator) &&
        IsEditable(*previous_node_iterator) != start_node_is_editable)
      break;
    if (boundary_crossing_rule == kCanSkipOverEditingBoundary) {
      while (previous_node_iterator &&
             IsEditable(*previous_node_iterator) != start_node_is_editable) {
        previous_node_iterator = previousNode();
      }
      if (!previous_node_iterator ||
          !previous_node_iterator->IsDescendantOf(highest_root))
        break;
    }

    const LayoutObject* layout_object =
        previous_node_iterator->GetLayoutObject();
    if (!layout_object) {
      previous_node_iterator = previousNode();
      continue;
    }
    const ComputedStyle& style = layout_object->StyleRef();
    if (style.Visibility() != EVisibility::kVisible) {
      previous_node_iterator = previousNode();
      continue;
    }

    if (layout_object->IsBR() || IsEnclosingBlock(previous_node_iterator))
      break;

    if (layout_object->IsText() &&
        To<LayoutText>(layout_object)->ResolvedTextLength()) {
      if (style.ShouldPreserveBreaks()) {
        const String& text = To<LayoutText>(layout_object)->TransformedText();
        int index = text.length();
        if (previous_node_iterator == start_node && candidate_offset < index)
          index = max(0, candidate_offset);
        while (--index >= 0) {
          if (text[index] == '\n') {
            return PositionTemplate<Strategy>(To<Text>(previous_node_iterator),
                                              index + 1);
          }
        }
      }
      candidate_node = previous_node_iterator;
      candidate_type = PositionAnchorType::kOffsetInAnchor;
      candidate_offset = 0;
      previous_node_iterator = previousNode();
    } else if (EditingIgnoresContent(*previous_node_iterator) ||
               IsDisplayInsideTable(previous_node_iterator)) {
      candidate_node = previous_node_iterator;
      candidate_type = PositionAnchorType::kBeforeAnchor;
      previous_node_iterator = previousNodeSkippingChildren();
    } else {
      previous_node_iterator = previousNode();
    }
  }

  if (candidate_type == PositionAnchorType::kOffsetInAnchor)
    return PositionTemplate<Strategy>(candidate_node, candidate_offset);

  return PositionTemplate<Strategy>(candidate_node, candidate_type);
}

template <typename Strategy>
VisiblePositionTemplate<Strategy> StartOfParagraphAlgorithm(
    const VisiblePositionTemplate<Strategy>& visible_position,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  const PositionTemplate<Strategy>& start = StartOfParagraphAlgorithm(
      visible_position.DeepEquivalent(), boundary_crossing_rule);
#if DCHECK_IS_ON()
  if (start.IsNotNull() && visible_position.IsNotNull())
    DCHECK_LE(start, visible_position.DeepEquivalent());
#endif
  return CreateVisiblePosition(start);
}

template <typename Strategy>
PositionTemplate<Strategy> EndOfParagraphAlgorithm(
    const PositionTemplate<Strategy>& position,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  Node* const start_node = position.AnchorNode();

  if (!start_node)
    return PositionTemplate<Strategy>();

  if (IsRenderedAsNonInlineTableImageOrHR(start_node))
    return PositionTemplate<Strategy>::AfterNode(*start_node);

  Element* const start_block = EnclosingBlock(
      PositionTemplate<Strategy>::FirstPositionInOrBeforeNode(*start_node),
      kCannotCrossEditingBoundary);
  ContainerNode* const highest_root = HighestEditableRoot(position);
  const bool start_node_is_editable = IsEditable(*start_node);

  Node* candidate_node = start_node;
  PositionAnchorType candidate_type = position.AnchorType();
  int candidate_offset = position.ComputeEditingOffset();

  Node* next_node_iterator = start_node;
  auto nextNode = [&]() -> Node* {
    DCHECK(next_node_iterator);
    if (next_node_iterator == start_node) {
      // For the first iteration, take the anchor type and offset into account.
      Node* after_position = position.ComputeNodeAfterPosition();
      if (!after_position)
        return Strategy::NextSkippingChildren(*next_node_iterator, start_block);
      if (after_position != candidate_node)
        return after_position;
    }
    return Strategy::Next(*next_node_iterator, start_block);
  };
  // If the first node in the paragraph is non editable, the position has
  // enclosing node as its anchor node. The following while loop breaks out
  // without iterating over next node if next_node_iterator is an enclosing
  // block. Move to next node here since it is needed only for the start_node.
  if (start_node == start_block) {
    next_node_iterator = nextNode();
  }
  while (next_node_iterator) {
    if (boundary_crossing_rule == kCannotCrossEditingBoundary &&
        !NodeIsUserSelectAll(next_node_iterator) &&
        IsEditable(*next_node_iterator) != start_node_is_editable)
      break;
    if (boundary_crossing_rule == kCanSkipOverEditingBoundary) {
      while (next_node_iterator &&
             IsEditable(*next_node_iterator) != start_node_is_editable) {
        if (!next_node_iterator->IsDescendantOf(highest_root)) {
          break;
        }
        candidate_node = next_node_iterator;
        candidate_type = PositionAnchorType::kAfterAnchor;
        next_node_iterator =
            Strategy::NextSkippingChildren(*next_node_iterator, start_block);
      }
      if (!next_node_iterator ||
          !next_node_iterator->IsDescendantOf(highest_root))
        break;
    }

    LayoutObject* const layout_object = next_node_iterator->GetLayoutObject();
    if (!layout_object) {
      next_node_iterator = nextNode();
      continue;
    }
    const ComputedStyle& style = layout_object->StyleRef();
    if (style.Visibility() != EVisibility::kVisible) {
      next_node_iterator = nextNode();
      continue;
    }

    if (layout_object->IsBR() || IsEnclosingBlock(next_node_iterator))
      break;

    // TODO(editing-dev): We avoid returning a position where the layoutObject
    // can't accept the caret.
    if (layout_object->IsText() &&
        To<LayoutText>(layout_object)->ResolvedTextLength()) {
      auto* const layout_text = To<LayoutText>(layout_object);
      if (style.ShouldPreserveBreaks()) {
        const String& text = layout_text->TransformedText();
        const int length = text.length();
        for (int i = (next_node_iterator == start_node ? candidate_offset : 0);
             i < length; ++i) {
          if (text[i] == '\n') {
            return PositionTemplate<Strategy>(
                To<Text>(next_node_iterator),
                i + layout_text->TextStartOffset());
          }
        }
      }

      candidate_node = next_node_iterator;
      candidate_type = PositionAnchorType::kOffsetInAnchor;
      candidate_offset =
          layout_text->CaretMaxOffset() + layout_text->TextStartOffset();
      next_node_iterator = nextNode();
    } else if (EditingIgnoresContent(*next_node_iterator) ||
               IsDisplayInsideTable(next_node_iterator)) {
      candidate_node = next_node_iterator;
      candidate_type = PositionAnchorType::kAfterAnchor;
      next_node_iterator =
          Strategy::NextSkippingChildren(*next_node_iterator, start_block);
    } else {
      next_node_iterator = nextNode();
    }
  }

  if (candidate_type == PositionAnchorType::kOffsetInAnchor)
    return PositionTemplate<Strategy>(candidate_node, candidate_offset);

  return PositionTemplate<Strategy>(candidate_node, candidate_type);
}

template <typename Strategy>
VisiblePositionTemplate<Strategy> EndOfParagraphAlgorithm(
    const VisiblePositionTemplate<Strategy>& visible_position,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  const PositionTemplate<Strategy>& end = EndOfParagraphAlgorithm(
      visible_position.DeepEquivalent(), boundary_crossing_rule);
#if DCHECK_IS_ON()
  if (visible_position.IsNotNull() && end.IsNotNull())
    DCHECK_LE(visible_position.DeepEquivalent(), end);
#endif
  return CreateVisiblePosition(end);
}

template <typename Strategy>
bool IsStartOfParagraphAlgorithm(
    const VisiblePositionTemplate<Strategy>& pos,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  DCHECK(pos.IsValid()) << pos;
  return pos.IsNotNull() &&
         pos.DeepEquivalent() ==
             StartOfParagraph(pos, boundary_crossing_rule).DeepEquivalent();
}

template <typename Strategy>
bool IsEndOfParagraphAlgorithm(
    const VisiblePositionTemplate<Strategy>& pos,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  DCHECK(pos.IsValid()) << pos;
  return pos.IsNotNull() &&
         pos.DeepEquivalent() ==
             EndOfParagraph(pos, boundary_crossing_rule).DeepEquivalent();
}

}  // namespace

VisiblePosition StartOfParagraph(
    const VisiblePosition& c,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  return StartOfParagraphAlgorithm<EditingStrategy>(c, boundary_crossing_rule);
}

VisiblePositionInFlatTree StartOfParagraph(
    const VisiblePositionInFlatTree& c,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  return StartOfParagraphAlgorithm<EditingInFlatTreeStrategy>(
      c, boundary_crossing_rule);
}

VisiblePosition EndOfParagraph(
    const VisiblePosition& c,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  return EndOfParagraphAlgorithm<EditingStrategy>(c, boundary_crossing_rule);
}

Position EndOfParagraph(const Position& c,
                        EditingBoundaryCrossingRule boundary_crossing_rule) {
  return EndOfParagraphAlgorithm<EditingStrategy>(c, boundary_crossing_rule);
}

VisiblePositionInFlatTree EndOfParagraph(
    const VisiblePositionInFlatTree& c,
    EditingBoundaryCrossingRule boundary_crossing_rule) {
  return EndOfParagraphAlgorithm<EditingInFlatTreeStrategy>(
      c, boundary_crossing_rule);
}

// TODO(editing-dev): isStartOfParagraph(startOfNextParagraph(pos)) is not
// always true
VisiblePosition StartOfNextParagraph(const VisiblePosition& visible_position) {
  DCHECK(visible_position.IsValid()) << visible_position;
  Position paragraph_end(EndOfParagraph(visible_position.DeepEquivalent(),
                                        kCanSkipOverEditingBoundary));
  // EndOfParagraph preserves the candidate_type, so if we are already at the
  // end node we must ensure we get the next position to avoid infinite loops.
  if (paragraph_end == visible_position.DeepEquivalent()) {
    paragraph_end =
        Position::AfterNode(*visible_position.DeepEquivalent().AnchorNode());
  }
  DCHECK(!paragraph_end.IsBeforeAnchor());
  DCHECK(visible_position.DeepEquivalent() < paragraph_end ||
         visible_position.DeepEquivalent() == paragraph_end &&
             paragraph_end.IsAfterAnchor());
  VisiblePosition after_paragraph_end(
      NextPositionOf(paragraph_end, kCannotCrossEditingBoundary));
  // It may happen that an element's next visually equivalent candidate is set
  // to such element when creating the VisualPosition. This may cause infinite
  // loops when we are iterating over parapgrahs.
  if (after_paragraph_end.DeepEquivalent() == paragraph_end) {
    after_paragraph_end =
        VisiblePosition::AfterNode(*paragraph_end.AnchorNode());
  }
  // The position after the last position in the last cell of a table
  // is not the start of the next paragraph.
  if (TableElementJustBefore(after_paragraph_end))
    return NextPositionOf(after_paragraph_end, kCannotCrossEditingBoundary);
  return after_paragraph_end;
}

// TODO(editing-dev): isStartOfParagraph(startOfNextParagraph(pos)) is not
// always true
bool InSameParagraph(const VisiblePosition& a,
                     const VisiblePosition& b,
                     EditingBoundaryCrossingRule boundary_crossing_rule) {
  DCHECK(a.IsValid()) << a;
  DCHECK(b.IsValid()) << b;
  return a.IsNotNull() &&
         StartOfParagraph(a, boundary_crossing_rule).DeepEquivalent() ==
             StartOfParagraph(b, boundary_crossing_rule).DeepEquivalent();
}

bool IsStartOfParagraph(const VisiblePosition& pos,
                        EditingBoundaryCrossingRule boundary_crossing_rule) {
  return IsStartOfParagraphAlgorithm<EditingStrategy>(pos,
                                                      boundary_crossing_rule);
}

bool IsStartOfParagraph(const VisiblePositionInFlatTree& pos) {
  return IsStartOfParagraphAlgorithm<EditingInFlatTreeStrategy>(
      pos, kCannotCrossEditingBoundary);
}

bool IsEndOfParagraph(const VisiblePosition& pos,
                      EditingBoundaryCrossingRule boundary_crossing_rule) {
  return IsEndOfParagraphAlgorithm<EditingStrategy>(pos,
                                                    boundary_crossing_rule);
}

bool IsEndOfParagraph(const VisiblePositionInFlatTree& pos) {
  return IsEndOfParagraphAlgorithm<EditingInFlatTreeStrategy>(
      pos, kCannotCrossEditingBoundary);
}

EphemeralRange ExpandToParagraphBoundary(const EphemeralRange& range) {
  const VisiblePosition& start = CreateVisiblePosition(range.StartPosition());
  DCHECK(start.IsNotNull()) << range.StartPosition();
  const Position& paragraph_start = StartOfParagraph(start).DeepEquivalent();
  DCHECK(paragraph_start.IsNotNull()) << range.StartPosition();

  const VisiblePosition& end = CreateVisiblePosition(range.EndPosition());
  DCHECK(end.IsNotNull()) << range.EndPosition();
  const Position& paragraph_end = EndOfParagraph(end).DeepEquivalent();
  DCHECK(paragraph_end.IsNotNull()) << range.EndPosition();

  // TODO(editing-dev): There are some cases (crbug.com/640112) where we get
  // |paragraphStart > paragraphEnd|, which is the reason we cannot directly
  // return |EphemeralRange(paragraphStart, paragraphEnd)|. This is not
  // desired, though. We should do more investigation to ensure that why
  // |paragraphStart <= paragraphEnd| is violated.
  const Position& result_start =
      paragraph_start.IsNotNull() && paragraph_start <= range.StartPosition()
          ? paragraph_start
          : range.StartPosition();
  const Position& result_end =
      paragraph_end.IsNotNull() && paragraph_end >= range.EndPosition()
          ? paragraph_end
          : range.EndPosition();
  return EphemeralRange(result_start, result_end);
}

}  // namespace blink

"""

```