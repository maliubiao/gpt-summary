Response:
Let's break down the thought process for analyzing this C++ code and generating the explanation.

**1. Initial Understanding and Goal:**

The core request is to understand the purpose of `inline_caret_position.cc` within the Chromium Blink rendering engine. Specifically, it asks about its function, relationships with web technologies (HTML, CSS, JavaScript), logic, and potential user/developer errors.

**2. High-Level Code Inspection (Skimming):**

The first step is to quickly read through the code, paying attention to:

* **File Name and Directory:** `blink/renderer/core/layout/inline/inline_caret_position.cc`. This immediately tells us it's related to layout, specifically inline elements, and caret positioning.
* **Includes:**  The included headers reveal dependencies on other Blink components: `editing/bidi_adjustment.h`, `editing/position_with_affinity.h`, `editing/text_affinity.h`,  `layout/inline/...`, and `layout/layout_block_flow.h`. This reinforces the focus on editing, bidirectional text handling (Bidi), and inline layout.
* **Namespace:** `blink` and the anonymous namespace `namespace { ... }`  indicate standard C++ organization within Blink.
* **Key Data Structures:**  `InlineCaretPosition`, `InlineCursor`, `TextAffinity`, `PositionWithAffinity`. Recognizing these is crucial for understanding the code's actions.
* **Key Functions:**  `ComputeInlineCaretPosition`, `TryResolveInlineCaretPositionInTextFragment`, `TryResolveInlineCaretPositionByBoxFragmentSide`,  `AdjustInlineCaretPositionForBidiText`, `ToPositionInDOMTreeWithAffinity`. These names suggest the core functionalities.
* **Enums and Structs:** `ResolutionType`, `InlineCaretPositionResolution`. These define specific states and data structures used within the algorithms.
* **Conditional Compilation:**  `RuntimeEnabledFeatures::BidiCaretAffinityEnabled()`. This hints at feature flags that can alter behavior.
* **Assertions (DCHECK):**  These provide valuable insights into expected conditions and potential errors.

**3. Deeper Dive into Core Functionality:**

Now, focus on the main functions and algorithms:

* **`ComputeInlineCaretPosition` (the main function):**  The comments at the top are extremely helpful. They describe the input (LayoutBlockFlow, offset, affinity) and the "caret resolution process." The iteration over inline fragments and the `TryResolveInlineCaretPositionInXXX` functions are key.
* **"Caret Resolution Process":**  Understanding the `ResolutionType` enum (`kFailed`, `kFoundCandidate`, `kResolved`) and how the `TryResolveInlineCaretPositionInXXX` functions use it is essential. This is the core logic of the file.
* **`TryResolveInlineCaretPositionInTextFragment`:** This handles caret positioning within text nodes. The logic around `OffsetMapping`, handling of leading/trailing bidi control characters, and soft line wraps is important.
* **`TryResolveInlineCaretPositionByBoxFragmentSide`:** This deals with caret positioning around atomic inline elements (like images).
* **`AdjustInlineCaretPositionForBidiText`:** This clearly handles bidirectional text adjustments, using the `BidiAdjustment` class.
* **`ToPositionInDOMTreeWithAffinity`:** This function converts the internal `InlineCaretPosition` representation back to a DOM `PositionWithAffinity`, which is how the browser interacts with the DOM.

**4. Connecting to Web Technologies:**

With an understanding of the core functionality, we can connect it to HTML, CSS, and JavaScript:

* **HTML:** The code directly deals with the structure of the HTML document as represented by the layout tree (LayoutBlockFlow, LayoutInline, LayoutText). The caret position relates to where a user's cursor would be placed within the HTML content.
* **CSS:** CSS styles influence the layout, including inline formatting, text direction (Bidi), and whether whitespace is collapsible. The code explicitly checks for properties like `NeedsTrailingSpace()` and `IsCollapsibleWhiteSpace()`.
* **JavaScript:** JavaScript can manipulate the DOM, set the selection, and trigger events related to text input and cursor movement. The `InlineCaretPosition` is fundamental to how the browser understands and manages these actions.

**5. Logic and Assumptions (Hypothetical Inputs and Outputs):**

Think about concrete examples:

* **Simple Text:** Input: "Hello", offset: 2, affinity: Downstream. Output: Caret after 'll'.
* **Atomic Inline (Image):** Input: `<img>`, offset: 0 (before), affinity: Downstream. Output: Caret before the image.
* **Bidi Text:** Input: `<p dir="rtl">שלום</p>`, offset: 2, affinity: Downstream. The output would need to consider the right-to-left direction and place the caret accordingly. This is where `AdjustInlineCaretPositionForBidiText` becomes important.
* **Line Breaks:**  Think about how the caret behaves at the beginning and end of lines, especially with soft wraps. The checks for `HasSoftWrapToNextLine()` are relevant here.

**6. Identifying Potential Errors:**

Examine the code for potential issues:

* **DCHECK Failures:**  The comments within the code highlight specific cases where `DCHECK`s might fail (e.g., with `<area>` elements or when `OffsetMapping` is null). These point to possible edge cases or bugs.
* **"TODO" Comments:** These indicate areas where the developers are aware of potential limitations or future work (e.g., handling caret positions in empty containers, the comment about RUBY elements).
* **Complexity Around Bidi:** Bidirectional text is inherently complex. The code dealing with `TextAffinity` and the `BidiAdjustment` class suggests areas where subtle bugs could occur.
* **Assumptions about Layout:**  The code relies on the layout tree being in a consistent state. Rapid DOM manipulations or asynchronous updates could potentially lead to unexpected behavior.

**7. Structuring the Explanation:**

Organize the findings logically:

* **Functionality:** Start with a clear, concise summary of the file's purpose.
* **Relationship to Web Technologies:**  Provide specific examples of how the code interacts with HTML, CSS, and JavaScript.
* **Logic and Assumptions:** Illustrate the core logic with simple examples of inputs and outputs.
* **Common Errors:**  Focus on user errors (interacting with the caret) and potential developer errors (related to layout and DOM manipulation).

**Self-Correction/Refinement During the Process:**

* **Initial Skim might miss nuances:**  On a second read, pay closer attention to the specific conditions in `if` statements and the details of the algorithms.
* **Connecting to Web Tech requires examples:**  Don't just say it's related to HTML; give concrete examples like how it affects cursor placement in text content.
* **Logic needs concrete illustrations:**  Abstract descriptions of the "caret resolution process" are less helpful than showing how it works with simple text or images.
* **Error identification requires careful reading:** Look for comments, `DCHECK`s, and areas of complexity that might be prone to errors.

By following this structured thought process, combining code inspection with an understanding of web technologies and potential pitfalls, it's possible to generate a comprehensive and accurate explanation of the given C++ source code.
好的，让我们来分析一下 `blink/renderer/core/layout/inline/inline_caret_position.cc` 文件的功能。

**文件功能概述:**

`inline_caret_position.cc` 文件的核心功能是**计算和确定在 inline 格式化上下文中光标（caret）的精确位置**。  这涉及到在文本、原子级 inline 元素（例如 `<img>`）之间以及行的起始和结束位置定位光标。

更具体地说，它负责：

1. **将逻辑偏移量和文本亲和性转换为实际的屏幕坐标光标位置。**  当用户尝试将光标移动到 inline 文本的特定位置时，浏览器需要将这个逻辑上的偏移量（字符索引）转换为屏幕上的像素坐标。
2. **处理双向文本 (Bidi)。**  它需要考虑文本的阅读方向（从左到右或从右到左），以确保光标放置在视觉上正确的位置。
3. **处理行尾换行和软换行。**  光标在行尾和软换行处的定位需要特殊处理。
4. **处理原子级 inline 元素的光标位置。**  光标可以位于原子级 inline 元素之前或之后。
5. **将内部的光标位置表示转换为 DOM 树中的位置 (Position)。**  这使得其他浏览器组件可以使用计算出的光标位置。

**与 JavaScript, HTML, CSS 的关系及举例:**

这个文件位于渲染引擎的核心布局部分，它直接服务于浏览器如何渲染和交互用户界面。因此，它与 JavaScript, HTML, 和 CSS 都有着密切的关系：

* **HTML:**  `inline_caret_position.cc` 处理的是 HTML 文档中 inline 元素的内容。它需要理解文本节点和原子级 inline 元素（如 `<img>`, `<button>` 中的文本）的结构，才能确定光标应该放在哪里。
    * **举例:**  考虑以下 HTML 代码：
      ```html
      <p>This is some <strong>bold</strong> text.</p>
      ```
      当用户点击 "some" 和 "bold" 之间时，`inline_caret_position.cc` 负责计算光标应该放在 "some " 之后，"bold" 之前的精确位置。它需要考虑到 `<strong>` 标签是一个单独的 inline 元素。

* **CSS:** CSS 样式会影响 inline 元素的布局和渲染，进而影响光标的位置。例如，`direction` 属性会影响文本的阅读方向，`white-space` 属性会影响空格和换行的处理。
    * **举例:**
      ```html
      <div style="direction: rtl;">这是一个从右到左的文本。</div>
      ```
      在这种情况下，`inline_caret_position.cc` 需要根据 `direction: rtl;` 的样式来计算光标的视觉位置。当用户试图在文本中间插入光标时，它会出现在视觉上正确的位置，即使逻辑偏移量是从左到右计算的。

* **JavaScript:** JavaScript 可以通过 DOM API (例如 `Selection` 和 `Range` 对象) 来获取和设置光标的位置。浏览器内部会使用 `inline_caret_position.cc` 计算出的位置来响应 JavaScript 的操作。
    * **举例:**  当 JavaScript 代码调用 `window.getSelection().collapse(node, offset)` 来将光标移动到特定位置时，渲染引擎会调用 `inline_caret_position.cc` 中的函数来将这个 DOM 节点和偏移量转换为实际的屏幕光标位置。

**逻辑推理和假设输入与输出:**

假设输入：

* **`context` (LayoutBlockFlow):**  一个包含 inline 元素的块级布局对象。例如，一个 `<p>` 元素对应的布局对象。
* **`offset` (unsigned):**  文本内容中的一个逻辑偏移量（字符索引）。
* **`affinity` (TextAffinity):**  表示光标的亲和性，是偏向上游（前一个字符）还是下游（后一个字符）。这在边界情况下很重要。
* **`layout_text` (const LayoutText*):**  可选的，指向特定的文本布局对象的指针。

假设场景： 用户在以下 HTML 中尝试将光标放在 "World" 的 "o" 和 "r" 之间：

```html
<p>Hello World!</p>
```

* **输入:**
    * `context`:  `<p>` 元素的 `LayoutBlockFlow` 对象。
    * `offset`:  假设 "Hello " 有 6 个字符，那么 "o" 的偏移量可能是 7。
    * `affinity`:  `TextAffinity::kDownstream` (通常情况下)。
    * `layout_text`: 指向 "World" 文本节点的 `LayoutText` 对象。

* **输出:**
    * **`InlineCaretPosition`:**  一个表示光标位置的对象，包含以下信息：
        * **`cursor` (InlineCursor):**  一个迭代器，指向包含光标位置的 inline 片段。
        * **`position_type` (InlineCaretPositionType):**  指示光标的位置类型，例如 `kAtTextOffset` (在文本偏移量处)。
        * **`text_offset` (std::optional<unsigned>):**  如果 `position_type` 是 `kAtTextOffset`，则表示文本偏移量，在本例中可能是 7。

**用户或编程常见的使用错误:**

1. **在 JavaScript 中设置了错误的偏移量:**  如果 JavaScript 代码计算出的偏移量超出了文本节点的长度，或者指向了错误的节点，那么 `inline_caret_position.cc` 可能会返回一个不正确的光标位置，或者导致程序崩溃。
    * **举例:**  一个文本节点包含 "abc"，长度为 3。如果 JavaScript 代码尝试将光标设置在偏移量 5 的位置，这是一个错误。

2. **在处理 Bidi 文本时假设了错误的文本方向:**  开发者在处理双向文本时，如果没有正确理解文本的逻辑顺序和视觉顺序，可能会导致光标位置的计算出现偏差。
    * **举例:**  在一个从右到左的段落中，逻辑上的第一个字符可能在视觉上的最右边。如果开发者假设光标总是从左到右移动，那么在 Bidi 文本中可能会遇到问题。

3. **在动态更新 DOM 后没有更新光标位置:**  如果 JavaScript 代码在修改 DOM 结构后，没有显式地更新光标位置，那么光标可能会停留在错误的地方。
    * **举例:**  如果用户正在编辑一个文本框，并且 JavaScript 代码动态地插入或删除了文本内容，那么可能需要重新计算光标的位置以保持一致性。

**总结:**

`inline_caret_position.cc` 是 Blink 渲染引擎中一个至关重要的文件，它负责精确地计算和定位 inline 格式化上下文中的光标。它需要理解 HTML 结构、CSS 样式，并为 JavaScript 的光标操作提供底层支持。理解其功能有助于我们更好地理解浏览器是如何渲染和交互文本内容的。

Prompt: 
```
这是目录为blink/renderer/core/layout/inline/inline_caret_position.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/layout/inline/inline_caret_position.h"

#include "third_party/blink/renderer/core/editing/bidi_adjustment.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/text_affinity.h"
#include "third_party/blink/renderer/core/layout/inline/fragment_item.h"
#include "third_party/blink/renderer/core/layout/inline/inline_cursor.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/inline/physical_line_box_fragment.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"

namespace blink {

namespace {

// The calculation takes the following input:
// - An inline formatting context as a |LayoutBlockFlow|
// - An offset in the |text_content_| string of the above context
// - A TextAffinity
//
// The calculation iterates all inline fragments in the context, and tries to
// compute an InlineCaretPosition using the "caret resolution process" below:
//
// The (offset, affinity) pair is compared against each inline fragment to see
// if the corresponding caret should be placed in the fragment, using the
// |TryResolveInlineCaretPositionInXXX()| functions. These functions may return:
// - Failed, indicating that the caret must not be placed in the fragment;
// - Resolved, indicating that the care should be placed in the fragment, and
//   no further search is required. The result InlineCaretPosition is returned
//   together.
// - FoundCandidate, indicating that the caret may be placed in the fragment;
//   however, further search may find a better position. The candidate
//   InlineCaretPosition is also returned together.

enum class ResolutionType { kFailed, kFoundCandidate, kResolved };
struct InlineCaretPositionResolution {
  STACK_ALLOCATED();

 public:
  ResolutionType type = ResolutionType::kFailed;
  InlineCaretPosition caret_position;
};

bool CanResolveInlineCaretPositionBeforeFragment(const InlineCursor& cursor,
                                                 TextAffinity affinity) {
  if (affinity == TextAffinity::kDownstream) {
    return true;
  }
  if (RuntimeEnabledFeatures::BidiCaretAffinityEnabled()) {
    return false;
  }
  InlineCursor current_line(cursor);
  current_line.MoveToContainingLine();
  // A fragment after line wrap must be the first logical leaf in its line.
  InlineCursor first_logical_leaf(current_line);
  first_logical_leaf.MoveToFirstLogicalLeaf();
  if (cursor != first_logical_leaf) {
    return true;
  }
  InlineCursor last_line(current_line);
  last_line.MoveToPreviousLine();
  return !last_line || !last_line.Current().HasSoftWrapToNextLine();
}

bool CanResolveInlineCaretPositionAfterFragment(const InlineCursor& cursor,
                                                TextAffinity affinity) {
  if (affinity == TextAffinity::kUpstream) {
    return true;
  }
  if (RuntimeEnabledFeatures::BidiCaretAffinityEnabled()) {
    return false;
  }
  InlineCursor current_line(cursor);
  current_line.MoveToContainingLine();
  // A fragment before line wrap must be the last logical leaf in its line.
  InlineCursor last_logical_leaf(current_line);
  last_logical_leaf.MoveToLastLogicalLeaf();
  if (cursor != last_logical_leaf) {
    return true;
  }
  return !current_line.Current().HasSoftWrapToNextLine();
}

// Returns a |kFailed| resolution if |offset| doesn't belong to the text
// fragment. Otherwise, return either |kFoundCandidate| or |kResolved| depending
// on |affinity|.
InlineCaretPositionResolution TryResolveInlineCaretPositionInTextFragment(
    const InlineCursor& cursor,
    unsigned offset,
    TextAffinity affinity) {
  if (cursor.Current().IsGeneratedText()) {
    return InlineCaretPositionResolution();
  }

  const OffsetMapping& mapping =
      *OffsetMapping::GetFor(cursor.Current().GetLayoutObject());

  // A text fragment natually allows caret placement in offset range
  // [StartOffset(), EndOffset()], i.e., from before the first character to
  // after the last character.
  // Besides, leading/trailing bidi control characters are ignored since their
  // two sides are considered the same caret position. Hence, if there are n and
  // m leading and trailing bidi control characters, then the allowed offset
  // range is [StartOffset() - n, EndOffset() + m].
  // Note that we don't ignore other characters that are not in fragments. For
  // example, a trailing space of a line is not in any fragment, but its two
  // sides are still different caret positions, so we don't ignore it.
  const TextOffsetRange current_offset = cursor.Current().TextOffset();
  const unsigned start_offset = current_offset.start;
  const unsigned end_offset = current_offset.end;
  if (offset < start_offset &&
      !mapping.HasBidiControlCharactersOnly(offset, start_offset)) {
    return InlineCaretPositionResolution();
  }
  if (affinity == TextAffinity::kUpstream && offset == current_offset.end + 1 &&
      cursor.Current().Style().NeedsTrailingSpace() &&
      cursor.Current().Style().IsCollapsibleWhiteSpace(
          mapping.GetText()[offset - 1])) {
    // |offset| is after soft line wrap, e.g. "abc |xyz".
    // See http://crbug.com/1183269 and |AdjustForSoftLineWrap()|
    return {ResolutionType::kResolved,
            {cursor, InlineCaretPositionType::kAtTextOffset, offset - 1}};
  }
  if (offset > current_offset.end &&
      !mapping.HasBidiControlCharactersOnly(end_offset, offset)) {
    return InlineCaretPositionResolution();
  }

  offset = std::max(offset, start_offset);
  offset = std::min(offset, end_offset);
  InlineCaretPosition candidate = {
      cursor, InlineCaretPositionType::kAtTextOffset, offset};

  // Offsets in the interior of a fragment can be resolved directly.
  if (offset > start_offset && offset < end_offset) {
    return {ResolutionType::kResolved, candidate};
  }

  if (offset == start_offset &&
      CanResolveInlineCaretPositionBeforeFragment(cursor, affinity)) {
    return {ResolutionType::kResolved, candidate};
  }

  if (offset == end_offset && !cursor.Current().IsLineBreak() &&
      CanResolveInlineCaretPositionAfterFragment(cursor, affinity)) {
    return {ResolutionType::kResolved, candidate};
  }

  // We may have a better candidate
  return {ResolutionType::kFoundCandidate, candidate};
}

unsigned GetTextOffsetBefore(const Node& node) {
  // TODO(xiaochengh): Design more straightforward way to get text offset of
  // atomic inline box.
  DCHECK(node.GetLayoutObject()->IsAtomicInlineLevel());
  const Position before_node = Position::BeforeNode(node);
  std::optional<unsigned> maybe_offset_before =
      OffsetMapping::GetFor(before_node)->GetTextContentOffset(before_node);
  // We should have offset mapping for atomic inline boxes.
  DCHECK(maybe_offset_before.has_value());
  return *maybe_offset_before;
}

// Returns a |kFailed| resolution if |offset| doesn't belong to the atomic
// inline box fragment. Otherwise, return either |kFoundCandidate| or
// |kResolved| depending on |affinity|.
InlineCaretPositionResolution TryResolveInlineCaretPositionByBoxFragmentSide(
    const InlineCursor& cursor,
    unsigned offset,
    TextAffinity affinity) {
  const Node* const node = cursor.Current().GetNode();
  // There is no caret position at a pseudo or generated box side.
  if (!node || node->IsPseudoElement()) {
    // TODO(xiaochengh): This leads to false negatives for, e.g., RUBY, where an
    // anonymous wrapping inline block is created.
    return InlineCaretPositionResolution();
  }

  const unsigned offset_before = GetTextOffsetBefore(*node);
  const unsigned offset_after = offset_before + 1;
  // TODO(xiaochengh): Ignore bidi control characters before & after the box.
  if (offset != offset_before && offset != offset_after) {
    return InlineCaretPositionResolution();
  }
  const InlineCaretPositionType position_type =
      offset == offset_before ? InlineCaretPositionType::kBeforeBox
                              : InlineCaretPositionType::kAfterBox;
  InlineCaretPosition candidate{cursor, position_type, std::nullopt};

  if (offset == offset_before &&
      CanResolveInlineCaretPositionBeforeFragment(cursor, affinity)) {
    return {ResolutionType::kResolved, candidate};
  }

  if (offset == offset_after &&
      CanResolveInlineCaretPositionAfterFragment(cursor, affinity)) {
    return {ResolutionType::kResolved, candidate};
  }

  return {ResolutionType::kFoundCandidate, candidate};
}

InlineCaretPositionResolution TryResolveInlineCaretPositionWithFragment(
    const InlineCursor& cursor,
    unsigned offset,
    TextAffinity affinity) {
  if (cursor.Current().IsText()) {
    return TryResolveInlineCaretPositionInTextFragment(cursor, offset,
                                                       affinity);
  }
  if (cursor.Current().IsAtomicInline()) {
    return TryResolveInlineCaretPositionByBoxFragmentSide(cursor, offset,
                                                          affinity);
  }
  return InlineCaretPositionResolution();
}

bool NeedsBidiAdjustment(const InlineCaretPosition& caret_position) {
  if (RuntimeEnabledFeatures::BidiCaretAffinityEnabled()) {
    return false;
  }
  if (caret_position.IsNull()) {
    return false;
  }
  if (caret_position.position_type != InlineCaretPositionType::kAtTextOffset) {
    return true;
  }
  DCHECK(caret_position.text_offset.has_value());
  const TextOffsetRange offset = caret_position.cursor.Current().TextOffset();
  const unsigned start_offset = offset.start;
  const unsigned end_offset = offset.end;
  DCHECK_GE(*caret_position.text_offset, start_offset);
  DCHECK_LE(*caret_position.text_offset, end_offset);
  // Bidi adjustment is needed only for caret positions at bidi boundaries.
  // Caret positions in the middle of a text fragment can't be at bidi
  // boundaries, and hence, don't need any adjustment.
  return *caret_position.text_offset == start_offset ||
         *caret_position.text_offset == end_offset;
}

InlineCaretPosition AdjustInlineCaretPositionForBidiText(
    const InlineCaretPosition& caret_position) {
  if (!NeedsBidiAdjustment(caret_position)) {
    return caret_position;
  }
  return BidiAdjustment::AdjustForInlineCaretPositionResolution(caret_position);
}

bool IsUpstreamAfterLineBreak(const InlineCaretPosition& caret_position) {
  if (caret_position.position_type != InlineCaretPositionType::kAtTextOffset) {
    return false;
  }

  DCHECK(caret_position.cursor.IsNotNull());
  DCHECK(caret_position.text_offset.has_value());

  if (!caret_position.cursor.Current().IsLineBreak()) {
    return false;
  }
  return *caret_position.text_offset ==
         caret_position.cursor.Current().TextEndOffset();
}

InlineCaretPosition BetterCandidateBetween(const InlineCaretPosition& current,
                                           const InlineCaretPosition& other,
                                           unsigned offset) {
  DCHECK(!other.IsNull());
  if (current.IsNull()) {
    return other;
  }

  // There shouldn't be too many cases where we have multiple candidates.
  // Make sure all of them are captured and handled here.

  // Only known case: either |current| or |other| is upstream after line break.
  DCHECK(current.ToPositionInDOMTreeWithAffinity().Affinity() ==
             TextAffinity::kUpstream ||
         other.ToPositionInDOMTreeWithAffinity().Affinity() ==
             TextAffinity::kUpstream);
  if (IsUpstreamAfterLineBreak(current)) {
    DCHECK(!IsUpstreamAfterLineBreak(other));
    return other;
  }
  return current;
}

InlineCaretPosition ComputeInlineCaretPositionAfterInline(
    const PositionWithAffinity& position_with_affinity) {
  const Position& position = position_with_affinity.GetPosition();
  const LayoutInline& layout_inline =
      *To<LayoutInline>(position.AnchorNode()->GetLayoutObject());

  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(layout_inline);
  // This DCHECK can fail with the <area> element.
  // DCHECK(cursor);
  if (!cursor) {
    return InlineCaretPosition();
  }
  InlineCursor line = cursor;
  line.MoveToContainingLine();
  DCHECK(line);

  if (IsLtr(line.Current().BaseDirection())) {
    cursor.MoveToVisualLastForSameLayoutObject();
  } else {
    cursor.MoveToVisualFirstForSameLayoutObject();
  }

  if (cursor.Current().IsText()) {
    const unsigned offset =
        line.Current().BaseDirection() == cursor.Current().ResolvedDirection()
            ? cursor.Current()->EndOffset()
            : cursor.Current()->StartOffset();
    return AdjustInlineCaretPositionForBidiText(
        {cursor, InlineCaretPositionType::kAtTextOffset, offset});
  }

  if (cursor.Current().IsAtomicInline()) {
    const InlineCaretPositionType type =
        line.Current().BaseDirection() == cursor.Current().ResolvedDirection()
            ? InlineCaretPositionType::kAfterBox
            : InlineCaretPositionType::kBeforeBox;
    return AdjustInlineCaretPositionForBidiText({cursor, type, std::nullopt});
  }

  return AdjustInlineCaretPositionForBidiText(
      {cursor, InlineCaretPositionType::kAfterBox, std::nullopt});
}
InlineCaretPosition ComputeInlineCaretPositionBeforeInline(
    const PositionWithAffinity& position_with_affinity) {
  const Position& position = position_with_affinity.GetPosition();
  const LayoutInline& layout_inline =
      *To<LayoutInline>(position.AnchorNode()->GetLayoutObject());

  InlineCursor cursor;
  cursor.MoveToIncludingCulledInline(layout_inline);
  // This DCHECK can fail with the <area> element.
  // DCHECK(cursor);
  if (!cursor) {
    return InlineCaretPosition();
  }
  InlineCursor line = cursor;
  line.MoveToContainingLine();
  DCHECK(line);

  if (IsLtr(line.Current().BaseDirection())) {
    cursor.MoveToVisualFirstForSameLayoutObject();
  } else {
    cursor.MoveToVisualLastForSameLayoutObject();
  }

  if (cursor.Current().IsText()) {
    const unsigned offset =
        line.Current().BaseDirection() == cursor.Current().ResolvedDirection()
            ? cursor.Current()->StartOffset()
            : cursor.Current()->EndOffset();
    return AdjustInlineCaretPositionForBidiText(
        {cursor, InlineCaretPositionType::kAtTextOffset, offset});
  }

  if (cursor.Current().IsAtomicInline()) {
    const InlineCaretPositionType type =
        line.Current().BaseDirection() == cursor.Current().ResolvedDirection()
            ? InlineCaretPositionType::kBeforeBox
            : InlineCaretPositionType::kAfterBox;
    return AdjustInlineCaretPositionForBidiText({cursor, type, std::nullopt});
  }

  return AdjustInlineCaretPositionForBidiText(
      {cursor, InlineCaretPositionType::kBeforeBox, std::nullopt});
}

}  // namespace

// The main function for compute an InlineCaretPosition. See the comments at the
// top of this file for details.
InlineCaretPosition ComputeInlineCaretPosition(const LayoutBlockFlow& context,
                                               unsigned offset,
                                               TextAffinity affinity,
                                               const LayoutText* layout_text) {
  InlineCursor cursor(context);

  InlineCaretPosition candidate;
  if (layout_text && layout_text->HasInlineFragments()) {
    cursor.MoveTo(*layout_text);
  }
  for (; cursor; cursor.MoveToNextIncludingFragmentainer()) {
    const InlineCaretPositionResolution resolution =
        TryResolveInlineCaretPositionWithFragment(cursor, offset, affinity);

    if (resolution.type == ResolutionType::kFailed) {
      continue;
    }

    // TODO(xiaochengh): Handle caret poisition in empty container (e.g. empty
    // line box).

    if (resolution.type == ResolutionType::kResolved) {
      candidate = resolution.caret_position;
      if (!layout_text ||
          candidate.cursor.Current().GetLayoutObject() == layout_text) {
        return AdjustInlineCaretPositionForBidiText(resolution.caret_position);
      }
      continue;
    }

    DCHECK_EQ(ResolutionType::kFoundCandidate, resolution.type);
    candidate =
        BetterCandidateBetween(candidate, resolution.caret_position, offset);
  }

  return AdjustInlineCaretPositionForBidiText(candidate);
}

InlineCaretPosition ComputeInlineCaretPosition(
    const PositionWithAffinity& position_with_affinity) {
  const Position& position = position_with_affinity.GetPosition();

  if (position.IsNull()) {
    return InlineCaretPosition();
  }

  const LayoutObject* layout_object = position.AnchorNode()->GetLayoutObject();
  if (!layout_object || !layout_object->IsInLayoutNGInlineFormattingContext()) {
    return InlineCaretPosition();
  }

  if (layout_object->IsLayoutInline()) {
    if (position.IsBeforeAnchor()) {
      return ComputeInlineCaretPositionBeforeInline(position_with_affinity);
    }
    if (position.IsAfterAnchor()) {
      return ComputeInlineCaretPositionAfterInline(position_with_affinity);
    }
    NOTREACHED() << "Caller should not pass a position inside inline: "
                 << position;
  }

  LayoutBlockFlow* const context = NGInlineFormattingContextOf(position);
  if (!context) {
    // We reach here for empty <div>[1].
    // [1] third_party/blink/web_tests/editing/caret/caret-in-inline-block.html
    return InlineCaretPosition();
  }

  const OffsetMapping* const mapping = InlineNode::GetOffsetMapping(context);
  if (!mapping) {
    // A block containing the position might be display-locked.
    // See editing/caret/caret-display-locked-crash.html
    return InlineCaretPosition();
  }
  const std::optional<unsigned> maybe_offset =
      mapping->GetTextContentOffset(position);
  if (!maybe_offset.has_value()) {
    // We can reach here with empty text nodes.
    if (auto* data = DynamicTo<Text>(position.AnchorNode())) {
      DCHECK_EQ(data->length(), 0u);
    } else {
      // TODO(xiaochengh): Investigate if we reach here.
      NOTREACHED();
    }
  }

  const LayoutText* const layout_text =
      position.IsOffsetInAnchor() && IsA<Text>(position.AnchorNode())
          ? To<LayoutText>(AssociatedLayoutObjectOf(
                *position.AnchorNode(), position.OffsetInContainerNode()))
          : nullptr;

  const unsigned offset = maybe_offset.value_or(0);
  const TextAffinity affinity = position_with_affinity.Affinity();
  // For upstream position, we use offset before ZWS to distinguish downstream
  // and upstream position when line breaking before ZWS.
  // "    Zabc" where "Z" represents zero-width-space.
  // See AccessibilitySelectionTest.FromCurrentSelectionInTextareaWithAffinity
  const unsigned adjusted_offset =
      affinity == TextAffinity::kUpstream && offset &&
              mapping->GetText()[offset - 1] == kZeroWidthSpaceCharacter
          ? offset - 1
          : offset;
  return ComputeInlineCaretPosition(*context, adjusted_offset, affinity,
                                    layout_text);
}

Position InlineCaretPosition::ToPositionInDOMTree() const {
  return ToPositionInDOMTreeWithAffinity().GetPosition();
}

PositionWithAffinity InlineCaretPosition::ToPositionInDOMTreeWithAffinity()
    const {
  if (IsNull()) {
    return PositionWithAffinity();
  }
  switch (position_type) {
    case InlineCaretPositionType::kBeforeBox:
      if (const Node* node = cursor.Current().GetNode()) {
        return PositionWithAffinity(Position::BeforeNode(*node),
                                    TextAffinity::kDownstream);
      }
      return PositionWithAffinity();
    case InlineCaretPositionType::kAfterBox:
      if (const Node* node = cursor.Current().GetNode()) {
        return PositionWithAffinity(Position::AfterNode(*node),
                                    TextAffinity::kUpstreamIfPossible);
      }
      return PositionWithAffinity();
    case InlineCaretPositionType::kAtTextOffset:
      // In case of ::first-letter, |cursor.Current().GetNode()| is null.
      DCHECK(text_offset.has_value());
      const OffsetMapping* mapping =
          OffsetMapping::GetFor(cursor.Current().GetLayoutObject());
      if (!mapping) {
        // TODO(yosin): We're not sure why |mapping| is |nullptr|. It seems
        // we are attempt to use destroyed/moved |FragmentItem|.
        // See http://crbug.com/1145514
        DUMP_WILL_BE_NOTREACHED()
            << cursor << " " << cursor.Current().GetLayoutObject();
        return PositionWithAffinity();
      }
      const TextAffinity affinity =
          *text_offset == cursor.Current().TextEndOffset()
              ? TextAffinity::kUpstreamIfPossible
              : TextAffinity::kDownstream;
      const Position position = affinity == TextAffinity::kDownstream
                                    ? mapping->GetLastPosition(*text_offset)
                                    : mapping->GetFirstPosition(*text_offset);
      if (position.IsNull()) {
        return PositionWithAffinity();
      }
      return PositionWithAffinity(position, affinity);
  }
  NOTREACHED();
}

}  // namespace blink

"""

```