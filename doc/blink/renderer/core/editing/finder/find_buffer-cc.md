Response:
Let's break down the thought process for analyzing the `find_buffer.cc` file.

1. **Understand the Goal:** The request asks for a breakdown of the file's functionality, its relationship to web technologies, logic analysis, potential user errors, and debugging context.

2. **Initial Scan for Keywords and Imports:**  Quickly look for recurring terms and included headers. This gives a high-level idea of the file's purpose. Keywords like "find," "search," "text," "range," "node," "element," "buffer" stand out. The includes point to DOM manipulation (`dom/document.h`, `dom/node.h`), editing (`editing_utilities.h`, `ephemeral_range.h`), styling (`css/style_change_reason.h`, `style/computed_style.h`), layout (`layout/...`), and text processing (`platform/text/...`). The presence of `third_party/blink/renderer/core/editing/finder/...` strongly suggests this file is central to the "find in page" functionality.

3. **Identify the Core Class:** The code clearly defines a class named `FindBuffer`. This will be the central focus of the analysis.

4. **Analyze the Constructor and Key Methods:**
    * **Constructor (`FindBuffer::FindBuffer`)**: It takes an `EphemeralRangeInFlatTree` and a `RubySupport` enum. This immediately suggests it's working on a specific portion of the document's structure for finding text. The `CollectTextUntilBlockBoundary` method called within the constructor is crucial; it likely populates the buffer.
    * **`FindMatchInRange`**: This method searches within a given range, using `FindBuffer` internally. The timeout parameter is interesting, indicating a mechanism to prevent long-running searches.
    * **`FindMatches`**: This is the core search logic, likely using the `TextSearcherICU`.
    * **`CollectTextUntilBlockBoundary`**:  This is where the text extraction and buffering happen. The logic for handling block boundaries and the `RubySupport` is important.
    * **`RangeFromBufferIndex`**: Converts buffer indices back to DOM ranges.
    * **`PositionAtStartOfCharacterAtIndex`, `PositionAtEndOfCharacterAtIndex`**: These methods map buffer positions back to DOM positions, highlighting the link between the buffer and the document structure.
    * **Helper Functions (e.g., `ShouldIgnoreContents`, `CharConstantForNode`, `GetVisibleTextNode`, `GetFirstBlockLevelAncestorInclusive`, `IsInSameUninterruptedBlock`)**: These provide the supporting logic for determining what text to include in the buffer and how to navigate the DOM.

5. **Determine the Functionality:** Based on the method names and included headers, the primary function of `FindBuffer` is to:
    * Efficiently extract and store a contiguous block of searchable text from a DOM range into a buffer.
    * Perform text searches within this buffer.
    * Map the search results back to the original DOM structure.
    * Handle special cases like inline elements, block boundaries, and elements that should be ignored during the search (e.g., scripts, styles, hidden elements).

6. **Relate to Web Technologies (JavaScript, HTML, CSS):**
    * **HTML:** The code directly interacts with various HTML elements (`HTMLInputElement`, `HTMLDivElement`, `HTMLSpanElement`, etc.). The concept of block boundaries is fundamental to HTML structure.
    * **CSS:** The code checks computed styles (`GetComputedStyle`) to determine visibility (`display: none`, `visibility: hidden`). This is crucial for "find in page" not matching hidden content.
    * **JavaScript:** While this specific C++ file doesn't directly execute JavaScript, it's part of the Blink rendering engine that *interprets* and *renders* the HTML and CSS that JavaScript manipulates. The "find in page" feature is often triggered and controlled by browser UI elements, which might involve JavaScript interactions on the webpage itself (e.g., to highlight matches).

7. **Logical Reasoning and Examples:**
    * **Input/Output:** Think about how the `CollectTextUntilBlockBoundary` method works. Given an HTML snippet and a starting range, what text will be in the buffer, and what will `node_after_block_` point to?
    * **Conditional Logic:** Analyze the `ShouldIgnoreContents` function. Why are certain elements ignored?  What happens if the `InertElementNonSearchableEnabled` flag is set?

8. **User/Programming Errors:** Consider how users or developers might misuse the "find in page" functionality or related APIs. For example:
    * Searching for text that's visually present but hidden by CSS.
    * Relying on "find in page" to locate content within `<script>` or `<style>` tags.

9. **Debugging Clues and User Actions:**  Trace the user's interaction that leads to this code being executed. The user initiates a "find in page" action, enters a search term, and navigates through the results. This triggers the browser to call the relevant Blink functions, eventually reaching the `FindBuffer` to perform the actual search within the rendered document.

10. **Structure the Answer:**  Organize the findings into logical sections as requested: Functionality, Relationship to Web Technologies, Logic Analysis, User Errors, and Debugging. Use clear and concise language. Provide specific examples where possible.

11. **Refine and Review:** Read through the generated answer. Are there any ambiguities?  Is the explanation clear and accurate?  Could any examples be improved?  Ensure all parts of the request are addressed. For example, initially I might forget to explicitly mention the role of `TextSearcherICU`, but reviewing the code reveals its importance. Similarly, ensuring the explanation of how inert elements are handled is accurate is crucial.
好的，让我们来详细分析一下 `blink/renderer/core/editing/finder/find_buffer.cc` 文件的功能。

**文件功能概述**

`find_buffer.cc` 文件是 Chromium Blink 引擎中负责实现 "在页面中查找" (Find in Page) 功能的核心组件之一。它的主要职责是：

1. **构建查找缓冲区 (Find Buffer):**  它会从 DOM 树的一部分提取文本内容，并将其存储在一个缓冲区中。这个缓冲区是为了高效地进行文本搜索而创建的。
2. **管理不同层级的查找 (Ruby 支持):**  如果页面包含 Ruby 注音标记（用于在文本上方或旁边显示发音），`FindBuffer` 可以创建和管理多个缓冲区，每个缓冲区代表不同的层级（例如，基础文本层和注音标记层）。
3. **执行文本搜索:**  利用 `TextSearcherICU` 类，在构建的缓冲区中查找指定的文本字符串。
4. **将搜索结果映射回 DOM:**  将缓冲区中的匹配项的位置信息转换回 DOM 树中的节点和偏移量，以便在页面上高亮显示或定位找到的文本。
5. **处理各种 DOM 结构和特性:**  它需要考虑各种 HTML 元素、属性以及 CSS 样式，以确定哪些内容应该被包含在查找范围内，哪些应该被忽略。例如，隐藏的元素、脚本、样式等通常会被排除在外。

**与 JavaScript, HTML, CSS 的关系**

`FindBuffer` 的功能与 JavaScript, HTML, CSS 都有密切关系：

* **HTML (文档结构):**
    * `FindBuffer` 接收一个 `EphemeralRangeInFlatTree` 作为输入，这代表了 DOM 树中的一个范围。它需要遍历和解析 HTML 结构来提取文本内容。
    * 它会识别不同的 HTML 元素，例如 `<p>`, `<div>`, `<span>`, `<a>`, `<input>`, `<textarea>` 等，并根据元素的类型和属性决定如何处理其内容。
    * **举例:**  如果 HTML 中有 `<p>This is some <b>bold</b> text.</p>`，`FindBuffer` 会提取出 "This is some bold text."，同时需要处理 `<b>` 标签，确保 "bold" 文本也被包含在内。
    * **举例 (忽略内容):**  对于 `<script>console.log("hello");</script>` 标签，`FindBuffer` 会通过 `ShouldIgnoreContents` 方法判断并忽略其内部的 JavaScript 代码。

* **CSS (样式):**
    * `FindBuffer` 需要考虑 CSS 样式来判断哪些内容是可见的，哪些是隐藏的。例如，`display: none` 或 `visibility: hidden` 的元素及其子元素通常会被排除在查找范围之外。
    * **举例:** 如果 HTML 中有 `<div style="display: none;">Hidden text</div>`，`FindBuffer` 在进行查找时会忽略 "Hidden text"。
    * `EnsureComputedStyleForFind` 函数用于获取节点的计算样式，这是判断可见性的关键。

* **JavaScript (交互和动态内容):**
    * 虽然 `find_buffer.cc` 本身是 C++ 代码，但它服务于浏览器的 "在页面中查找" 功能，这个功能通常由浏览器 UI 触发，并且可能与页面上的 JavaScript 交互。
    * JavaScript 可以动态地修改 DOM 结构和内容，`FindBuffer` 需要基于当前渲染的 DOM 树进行查找。
    * **用户操作举例:** 用户在浏览器中按下 `Ctrl+F` (或 `Cmd+F`) 调出查找栏，输入搜索文本，然后点击 "下一个" 或 "上一个" 按钮。这些用户操作最终会触发 Blink 引擎的查找逻辑，包括 `FindBuffer` 的执行。
    * **调试线索:** 如果用户报告 "在页面中查找" 无法找到 JavaScript 动态生成的内容，一个调试方向是检查 `FindBuffer` 是否正确地遍历了动态更新的 DOM 树部分。

**逻辑推理 (假设输入与输出)**

假设有以下 HTML 片段：

```html
<div>
  <p>Hello world!</p>
  <span>This is a test.</span>
</div>
```

**假设输入:**

* `range`:  一个 `EphemeralRangeInFlatTree` 对象，包含了整个 `<div>` 元素。
* `search_text`: "world"
* `options`:  默认查找选项 (不区分大小写，向前查找)。

**逻辑推理过程:**

1. `FindBuffer` 的构造函数会被调用，传入 `range` 和其他参数。
2. `CollectTextUntilBlockBoundary` 方法会被调用，它会遍历 `<div>` 及其子元素。
3. 对于 `<p>` 元素，提取出文本 "Hello world!" 并添加到缓冲区。
4. 对于 `<span>` 元素，提取出文本 "This is a test." 并添加到缓冲区。
5. 最终构建的缓冲区内容可能是 "Hello world!This is a test." (具体取决于实现细节，例如是否添加空格或其他分隔符)。
6. `FindMatches` 方法会被调用，传入 `search_text` "world"。
7. `TextSearcherICU` 会在缓冲区中查找 "world"。
8. 找到匹配项 "world" 在缓冲区中的起始位置和长度。
9. `RangeFromBufferIndex` 会将缓冲区中的位置信息转换回 DOM 树中的 `Text` 节点 ( `<p>` 元素的子节点) 和偏移量。

**假设输出:**

* `FindMatches` 方法返回的 `FindResults` 对象会包含一个匹配项，该匹配项指向 `<p>` 元素下的 "world" 文本。
* 如果在浏览器中执行查找，"world" 这部分文本会被高亮显示。

**用户或编程常见的使用错误**

1. **查找隐藏内容:** 用户可能期望找到通过 CSS 隐藏 (`display: none` 或 `visibility: hidden`) 的文本，但 `FindBuffer` 通常会忽略这些内容。
    * **举例:** 用户在页面上看不到某个文本，但知道它在 HTML 源代码中，尝试使用 "在页面中查找" 功能，却找不到。
2. **查找脚本或样式中的文本:**  用户可能会尝试查找 `<script>` 或 `<style>` 标签内部的 JavaScript 或 CSS 代码，但 `FindBuffer` 通常会排除这些内容。
3. **依赖于错误的假设:**  用户可能假设 "在页面中查找" 功能会按照源代码的顺序进行查找，但实际上它是基于渲染后的 DOM 树进行查找的。这在动态生成内容或使用了 CSS 布局的情况下可能会导致意外。
4. **编程错误 (Blink 开发):**
    * 在 `ShouldIgnoreContents` 中添加了错误的判断条件，导致本应被查找的内容被忽略。
    * 在 `CollectTextUntilBlockBoundary` 中处理特殊字符或 HTML 结构时出现错误，导致缓冲区内容不完整或不正确。
    * 在将缓冲区索引映射回 DOM 位置时出现错误，导致高亮显示的位置不正确。

**用户操作是如何一步步的到达这里 (作为调试线索)**

1. **用户触发 "在页面中查找":** 用户通常通过键盘快捷键 (例如 `Ctrl+F` 或 `Cmd+F`) 或者浏览器菜单中的 "查找" 选项来启动 "在页面中查找" 功能。
2. **浏览器 UI 显示查找栏:** 浏览器会显示一个输入框，供用户输入要查找的文本。
3. **用户输入搜索文本:** 用户在查找栏中输入他们想要查找的字符串。
4. **用户开始查找 (例如点击 "下一个" 按钮):** 当用户点击 "下一个" 或 "上一个" 按钮，或者按下 `Enter` 键时，浏览器会开始执行查找操作。
5. **Blink 引擎接收查找请求:** 浏览器的 UI 组件会将查找请求传递给 Blink 引擎。
6. **创建 Finder 对象:** Blink 引擎会创建一个或多个负责查找操作的对象，例如 `LocalFrameView::findText()`, `TextFinder` 等。
7. **确定查找范围:**  根据当前的选择或上次查找的位置，确定本次查找的起始范围。这会创建一个 `EphemeralRangeInFlatTree` 对象。
8. **创建 `FindBuffer` 对象:**  为了高效地进行查找，会创建一个 `FindBuffer` 对象，并传入当前的查找范围。
9. **`CollectTextUntilBlockBoundary` 执行:**  `FindBuffer` 的构造函数会调用 `CollectTextUntilBlockBoundary` 方法，从指定的范围内提取文本内容到缓冲区。
10. **`FindMatches` 执行:** `TextFinder` 或其他查找管理对象会调用 `FindBuffer::FindMatches` 方法，传入要查找的文本和查找选项。
11. **`TextSearcherICU` 进行搜索:** `FindMatches` 方法内部会使用 `TextSearcherICU` 在缓冲区中执行实际的文本搜索。
12. **找到匹配项 (或未找到):** `TextSearcherICU` 返回搜索结果，包括匹配项在缓冲区中的位置信息。
13. **将结果映射回 DOM:** `FindBuffer` 使用 `RangeFromBufferIndex` 等方法将缓冲区中的匹配位置转换回 DOM 树中的节点和偏移量。
14. **高亮显示或定位:** 浏览器会将找到的文本在页面上高亮显示，或者将页面滚动到匹配的位置。
15. **用户继续查找:** 如果用户点击 "下一个" 或 "上一个"，上述过程会重复进行，但查找范围会相应调整。

**调试线索:**

* 如果用户报告查找功能异常，例如找不到某些文本，或者高亮显示的位置不正确，可以断点调试 `find_buffer.cc` 中的关键方法，例如 `CollectTextUntilBlockBoundary` 和 `RangeFromBufferIndex`。
* 检查构建的缓冲区内容是否正确包含了预期的文本。
* 检查 `ShouldIgnoreContents` 的逻辑是否正确地排除了不应被查找的内容。
* 检查将缓冲区索引映射回 DOM 位置的计算是否正确。
* 考虑页面的 DOM 结构是否复杂或动态变化，这可能会影响 `FindBuffer` 的行为。
* 查看 `FindOptions` 中设置的查找选项，例如是否区分大小写，是否只在当前选择中查找等。

希望以上详细的解释能够帮助你理解 `blink/renderer/core/editing/finder/find_buffer.cc` 文件的功能和作用。

Prompt: 
```
这是目录为blink/renderer/core/editing/finder/find_buffer.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/finder/find_buffer.h"

#include "base/time/time.h"
#include "third_party/blink/renderer/core/css/style_change_reason.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/finder/chunk_graph_utils.h"
#include "third_party/blink/renderer/core/editing/finder/find_results.h"
#include "third_party/blink/renderer/core/editing/iterators/text_searcher_icu.h"
#include "third_party/blink/renderer/core/fullscreen/fullscreen.h"
#include "third_party/blink/renderer/core/html/forms/html_form_control_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_dialog_element.h"
#include "third_party/blink/renderer/core/html/html_iframe_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_meter_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_progress_element.h"
#include "third_party/blink/renderer/core/html/html_script_element.h"
#include "third_party/blink/renderer/core/html/html_style_element.h"
#include "third_party/blink/renderer/core/html/html_wbr_element.h"
#include "third_party/blink/renderer/core/html/media/html_audio_element.h"
#include "third_party/blink/renderer/core/html/media/html_video_element.h"
#include "third_party/blink/renderer/core/layout/inline/inline_node.h"
#include "third_party/blink/renderer/core/layout/inline/offset_mapping.h"
#include "third_party/blink/renderer/core/layout/layout_block_flow.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/style/computed_style.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/text/unicode_utilities.h"
#include "third_party/blink/renderer/platform/wtf/text/character_names.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

// Returns true if the search should ignore the given |node|'s contents. In
// other words, we don't need to recurse into the node's children.
bool FindBuffer::ShouldIgnoreContents(const Node& node) {
  if (node.getNodeType() == Node::kCommentNode) {
    return true;
  }

  // A modal dialog and fullscreen element can escape inertness of ancestors.
  // See https://issues.chromium.org/issues/40506558.
  if (RuntimeEnabledFeatures::InertElementNonSearchableEnabled()) {
    const Element* modal_element = node.GetDocument().ActiveModalDialog();
    if (!modal_element) {
      modal_element = Fullscreen::FullscreenElementFrom(node.GetDocument());
    }
    if (modal_element && modal_element != &node) {
      // If `modal_element` is the child of `node`, `node` should not ignore
      // contents to avoid skipping `modal_element`.
      if (FlatTreeTraversal::IsDescendantOf(*modal_element, node)) {
        return false;
      }
      // https://html.spec.whatwg.org/multipage/interaction.html#modal-dialogs-and-inert-subtrees
      // > While document is so blocked, every node that is connected to
      // > document, with the exception of the subject element and its flat tree
      // > descendants, must become inert.
      if (!FlatTreeTraversal::IsDescendantOf(node, *modal_element)) {
        return true;
      }
    }
  }

  const auto* element = DynamicTo<HTMLElement>(node);
  if (!element)
    return false;
  return (RuntimeEnabledFeatures::InertElementNonSearchableEnabled() &&
          element->IsInertRoot()) ||
         (!element->ShouldSerializeEndTag() &&
          !IsA<HTMLInputElement>(*element)) ||
         (IsA<TextControlElement>(*element) &&
          !To<TextControlElement>(*element).SuggestedValue().empty()) ||
         IsA<HTMLIFrameElement>(*element) || IsA<HTMLImageElement>(*element) ||
         IsA<HTMLMeterElement>(*element) || IsA<HTMLObjectElement>(*element) ||
         IsA<HTMLProgressElement>(*element) ||
         (IsA<HTMLSelectElement>(*element) &&
          To<HTMLSelectElement>(*element).UsesMenuList()) ||
         IsA<HTMLStyleElement>(*element) || IsA<HTMLScriptElement>(*element) ||
         IsA<HTMLVideoElement>(*element) || IsA<HTMLAudioElement>(*element) ||
         (element->GetDisplayLockContext() &&
          element->GetDisplayLockContext()->IsLocked() &&
          !element->GetDisplayLockContext()->IsActivatable(
              DisplayLockActivationReason::kFindInPage));
}

std::optional<UChar> FindBuffer::CharConstantForNode(const Node& node) {
  if (!IsA<HTMLElement>(node)) {
    return std::nullopt;
  }
  if (IsA<HTMLWBRElement>(To<HTMLElement>(node))) {
    return std::nullopt;
  }
  if (IsA<HTMLBRElement>(To<HTMLElement>(node))) {
    return kNewlineCharacter;
  }
  return kNonCharacter;
}

namespace {

// Characters in a buffer for a different annotation level are replaced with
// kSkippedChar.
constexpr UChar kSkippedChar = 0;

// Returns the first ancestor element that isn't searchable. In other words,
// either ShouldIgnoreContents() returns true for it or it has a display: none
// style.  Returns nullptr if no such ancestor exists.
Node* GetOutermostNonSearchableAncestor(const Node& node) {
  Node* display_none = nullptr;
  for (Node& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(node)) {
    Element* element_ancestor = DynamicTo<Element>(&ancestor);
    if (!element_ancestor)
      continue;
    const ComputedStyle* style = element_ancestor->GetComputedStyle();
    if (!style || style->IsEnsuredInDisplayNone()) {
      display_none = element_ancestor;
      continue;
    }
    if (FindBuffer::ShouldIgnoreContents(*element_ancestor)) {
      return element_ancestor;
    }
    if (display_none)
      return display_none;
  }
  return nullptr;
}

const ComputedStyle* EnsureComputedStyleForFind(Node& node) {
  Element* element = DynamicTo<Element>(node);
  if (!element) {
    element = FlatTreeTraversal::ParentElement(node);
  }
  if (element) {
    return element->EnsureComputedStyle();
  }
  return nullptr;
}

// Returns the next/previous node after |start_node| (including start node) that
// is a text node and is searchable and visible.
template <class Direction>
Node* GetVisibleTextNode(Node& start_node) {
  Node* node = &start_node;
  // Move to outside display none subtree if we're inside one.
  while (Node* ancestor = GetOutermostNonSearchableAncestor(*node)) {
    if (!ancestor)
      return nullptr;
    node = Direction::NextSkippingSubtree(*ancestor);
    if (!node)
      return nullptr;
  }
  // Move to first text node that's visible.
  while (node) {
    const ComputedStyle* style = EnsureComputedStyleForFind(*node);
    if (FindBuffer::ShouldIgnoreContents(*node) ||
        (style && style->Display() == EDisplay::kNone)) {
      // This element and its descendants are not visible, skip it.
      node = Direction::NextSkippingSubtree(*node);
      continue;
    }
    if (style && style->Visibility() == EVisibility::kVisible &&
        node->IsTextNode() &&
        (!RuntimeEnabledFeatures::FindTextSkipCollapsedTextEnabled() ||
         node->GetLayoutObject())) {
      return node;
    }
    // This element is hidden, but node might be visible,
    // or this is not a text node, so we move on.
    node = Direction::Next(*node);
  }
  return nullptr;
}

// Returns true if the given |node| is considered a 'block' for find-in-page,
// scroll-to-text and link-to-text even though it might not have a separate
// LayoutBlockFlow. For example, input fields should be considered a block
// boundary.
bool IsExplicitFindBoundary(const Node& node) {
  return IsTextControl(node);
}

// Checks if |start| appears before |end| in flat-tree order.
bool AreInOrder(const Node& start, const Node& end) {
  const Node* node = &start;
  while (node && !node->isSameNode(&end)) {
    node = FlatTreeTraversal::Next(*node);
  }
  return node->isSameNode(&end);
}

bool IsIfcWithRuby(const Node& block_ancestor) {
  if (const auto* block_flow =
          DynamicTo<LayoutBlockFlow>(block_ancestor.GetLayoutObject())) {
    if (const auto* node_data = block_flow->GetInlineNodeData()) {
      return node_data->HasRuby();
    }
  }
  return false;
}

}  // namespace

// FindBuffer implementation.
FindBuffer::FindBuffer(const EphemeralRangeInFlatTree& range,
                       RubySupport ruby_support) {
  DCHECK(range.IsNotNull() && !range.IsCollapsed()) << range;
  CollectTextUntilBlockBoundary(range, ruby_support);
}

bool FindBuffer::IsInvalidMatch(MatchResultICU match) const {
  // Invalid matches are a result of accidentally matching elements that are
  // replaced with the kNonCharacter, and may lead to crashes. To avoid
  // crashing, we should skip the matches that are invalid - they would have
  // either an empty position or a non-offset-in-anchor position.
  const unsigned start_index = match.start;
  PositionInFlatTree start_position =
      PositionAtStartOfCharacterAtIndex(start_index);
  if (start_position.IsNull() || !start_position.IsOffsetInAnchor())
    return true;

  const unsigned end_index = match.start + match.length;
  DCHECK_LE(start_index, end_index);
  PositionInFlatTree end_position =
      PositionAtEndOfCharacterAtIndex(end_index - 1);
  if (end_position.IsNull() || !end_position.IsOffsetInAnchor())
    return true;
  return false;
}

EphemeralRangeInFlatTree FindBuffer::FindMatchInRange(
    const EphemeralRangeInFlatTree& range,
    String search_text,
    FindOptions options,
    std::optional<base::TimeDelta> timeout_ms) {
  if (!range.StartPosition().IsConnected())
    return EphemeralRangeInFlatTree();

  base::TimeTicks start_time;

  EphemeralRangeInFlatTree last_match_range;
  Node* first_node = range.StartPosition().NodeAsRangeFirstNode();
  Node* past_last_node = range.EndPosition().NodeAsRangePastLastNode();
  Node* node = first_node;
  while (node && node != past_last_node) {
    if (start_time.is_null()) {
      start_time = base::TimeTicks::Now();
    } else {
      auto time_elapsed = base::TimeTicks::Now() - start_time;
      if (timeout_ms.has_value() && time_elapsed > timeout_ms.value()) {
        return EphemeralRangeInFlatTree(
            PositionInFlatTree::FirstPositionInNode(*node),
            PositionInFlatTree::FirstPositionInNode(*node));
      }
    }

    if (GetOutermostNonSearchableAncestor(*node)) {
      node = FlatTreeTraversal::NextSkippingChildren(*node);
      continue;
    }
    if (!node->IsTextNode()) {
      node = FlatTreeTraversal::Next(*node);
      continue;
    }
    // If we're in the same node as the start position, start from the start
    // position instead of the start of this node.
    PositionInFlatTree start_position =
        node == first_node ? range.StartPosition()
                           : PositionInFlatTree::FirstPositionInNode(*node);
    if (start_position >= range.EndPosition())
      break;

    FindBuffer buffer(
        EphemeralRangeInFlatTree(start_position, range.EndPosition()),
        options.IsRubySupported() ? RubySupport::kEnabledIfNecessary
                                  : RubySupport::kDisabled);
    FindResults match_results = buffer.FindMatches(search_text, options);
    if (!match_results.IsEmpty()) {
      if (!options.IsBackwards()) {
        MatchResultICU match = match_results.front();
        return buffer.RangeFromBufferIndex(match.start,
                                           match.start + match.length);
      }
      MatchResultICU match = match_results.back();
      last_match_range =
          buffer.RangeFromBufferIndex(match.start, match.start + match.length);
    }
    node = buffer.PositionAfterBlock().ComputeContainerNode();
  }
  return last_match_range;
}

const Node& FindBuffer::GetFirstBlockLevelAncestorInclusive(const Node& node) {
  // Gets lowest inclusive ancestor that has block display value.
  // <div id=outer>a<div id=inner>b</div>c</div>
  // If we run this on "a" or "c" text node in we will get the outer div.
  // If we run it on the "b" text node we will get the inner div.
  if (!node.GetLayoutObject())
    return *node.GetDocument().documentElement();

  for (const Node& ancestor : FlatTreeTraversal::InclusiveAncestorsOf(node)) {
    if (!ancestor.GetLayoutObject())
      continue;
    if (!IsInSameUninterruptedBlock(ancestor, node))
      return ancestor;
  }

  return *node.GetDocument().documentElement();
}

bool FindBuffer::IsInSameUninterruptedBlock(const Node& start_node,
                                            const Node& end_node) {
  DCHECK(AreInOrder(start_node, end_node));
  DCHECK(start_node.GetLayoutObject());
  DCHECK(end_node.GetLayoutObject());

  if (start_node.isSameNode(&end_node))
    return true;

  if (IsExplicitFindBoundary(start_node) || IsExplicitFindBoundary(end_node))
    return false;

  LayoutBlockFlow& start_block_flow =
      *OffsetMapping::GetInlineFormattingContextOf(
          *start_node.GetLayoutObject());
  LayoutBlockFlow& end_block_flow =
      *OffsetMapping::GetInlineFormattingContextOf(*end_node.GetLayoutObject());
  if (start_block_flow != end_block_flow)
    return false;

  // It's possible that 2 nodes are in the same block flow but there is a node
  // in between that has a separate block flow. An example is an input field.
  for (const Node* node = &start_node; !node->isSameNode(&end_node);
       node = FlatTreeTraversal::Next(*node)) {
    const ComputedStyle* style =
        node->GetComputedStyleForElementOrLayoutObject();
    if (ShouldIgnoreContents(*node) || !style ||
        style->Display() == EDisplay::kNone ||
        style->Visibility() != EVisibility::kVisible) {
      continue;
    }

    if (node->GetLayoutObject() &&
        *OffsetMapping::GetInlineFormattingContextOf(
            *node->GetLayoutObject()) != start_block_flow) {
      return false;
    }
  }

  return true;
}

Node* FindBuffer::ForwardVisibleTextNode(Node& start_node) {
  struct ForwardDirection {
    static Node* Next(const Node& node) {
      return FlatTreeTraversal::Next(node);
    }
    static Node* NextSkippingSubtree(const Node& node) {
      return FlatTreeTraversal::NextSkippingChildren(node);
    }
  };
  return GetVisibleTextNode<ForwardDirection>(start_node);
}

Node* FindBuffer::BackwardVisibleTextNode(Node& start_node) {
  struct BackwardDirection {
    static Node* Next(const Node& node) {
      return FlatTreeTraversal::Previous(node);
    }
    static Node* NextSkippingSubtree(const Node& node) {
      // Unlike |NextSkippingChildren|, |Previous| already skips given nodes
      // subtree.
      return FlatTreeTraversal::Previous(node);
    }
  };
  return GetVisibleTextNode<BackwardDirection>(start_node);
}

FindResults FindBuffer::FindMatches(const String& search_text,
                                    const blink::FindOptions options) {
  // We should return empty result if it's impossible to get a match (buffer is
  // empty), or when something went wrong in layout, in which case
  // |offset_mapping_| is null.
  if (buffer_.empty() || !offset_mapping_) {
    return FindResults();
  }
  if (!RuntimeEnabledFeatures::FindDecomposedInShortTextEnabled() &&
      search_text.length() > buffer_.size()) {
    return FindResults();
  }
  String search_text_16_bit = search_text;
  search_text_16_bit.Ensure16Bit();
  FoldQuoteMarksAndSoftHyphens(search_text_16_bit);
  return FindResults(this, &text_searcher_, buffer_, &buffer_list_,
                     search_text_16_bit, options);
}

void FindBuffer::CollectTextUntilBlockBoundary(
    const EphemeralRangeInFlatTree& range,
    RubySupport ruby_support) {
  // Collects text until block boundary located at or after |start_node|
  // to |buffer_|. Saves the next starting node after the block to
  // |node_after_block_|.
  DCHECK(range.IsNotNull() && !range.IsCollapsed()) << range;

  node_after_block_ = nullptr;
  const Node* const first_node = range.StartPosition().NodeAsRangeFirstNode();
  if (!first_node)
    return;
  // Get first visible text node from |start_position|.
  Node* node =
      ForwardVisibleTextNode(*range.StartPosition().NodeAsRangeFirstNode());
  if (!node || !node->isConnected())
    return;

  const Node& block_ancestor = GetFirstBlockLevelAncestorInclusive(*node);
  const Node* just_after_block = FlatTreeTraversal::Next(
      FlatTreeTraversal::LastWithinOrSelf(block_ancestor));

  // Collect all text under |block_ancestor| to |buffer_|,
  // unless we meet another block on the way. If so, we should split.
  // Example: <div id="outer">a<span>b</span>c<div>d</div></div>
  // Will try to collect all text in outer div but will actually
  // stop when it encounters the inner div. So buffer will be "abc".

  // Used for checking if we reached a new block.
  Node* last_added_text_node = nullptr;

  // We will also stop if we encountered/passed |end_node|.
  Node* end_node = range.EndPosition().NodeAsRangeLastNode();

  bool use_chunk_graph = false;
  if (RuntimeEnabledFeatures::FindRubyInPageEnabled()) {
    use_chunk_graph = ruby_support == RubySupport::kEnabledForcefully ||
                      (ruby_support == RubySupport::kEnabledIfNecessary &&
                       IsIfcWithRuby(block_ancestor));
  }
  if (use_chunk_graph) {
    auto [corpus_chunk_list, level_list, next_node] =
        BuildChunkGraph(*node, end_node, block_ancestor, just_after_block);
    node_after_block_ = next_node;

    buffer_ = SerializeLevelInGraph(corpus_chunk_list, String(), range);
    FoldQuoteMarksAndSoftHyphens(base::span(buffer_));
    buffer_list_.resize(0);
    buffer_list_.reserve(level_list.size());
    for (const auto& level : level_list) {
      buffer_list_.push_back(
          SerializeLevelInGraph(corpus_chunk_list, level, range));
      FoldQuoteMarksAndSoftHyphens(base::span(buffer_list_.back()));
    }
    return;
  }

  while (node && node != just_after_block) {
    if (ShouldIgnoreContents(*node)) {
      if (end_node && (end_node == node ||
                       FlatTreeTraversal::IsDescendantOf(*end_node, *node))) {
        // For setting |node_after_block| later.
        node = FlatTreeTraversal::NextSkippingChildren(*node);
        break;
      }
      // Replace the node with char constants so we wouldn't encounter this node
      // or its descendants later.
      ReplaceNodeWithCharConstants(*node, buffer_);
      node = FlatTreeTraversal::NextSkippingChildren(*node);
      continue;
    }
    const ComputedStyle* style = EnsureComputedStyleForFind(*node);
    if (style->Display() == EDisplay::kNone) {
      // This element and its descendants are not visible, skip it.
      // We can safely just check the computed style of this node since
      // we guarantee |block_ancestor| is visible.
      if (end_node && (end_node == node ||
                       FlatTreeTraversal::IsDescendantOf(*end_node, *node))) {
        // For setting |node_after_block| later.
        node = FlatTreeTraversal::NextSkippingChildren(*node);
        break;
      }
      node = FlatTreeTraversal::NextSkippingChildren(*node);
      if (node && !FlatTreeTraversal::IsDescendantOf(*node, block_ancestor))
        break;
      continue;
    }

    if (style->Visibility() == EVisibility::kVisible &&
        node->GetLayoutObject()) {
      // This node is in its own sub-block separate from our starting position.
      if (last_added_text_node && last_added_text_node->GetLayoutObject() &&
          !IsInSameUninterruptedBlock(*last_added_text_node, *node))
        break;

      const auto* text_node = DynamicTo<Text>(node);
      if (text_node) {
        last_added_text_node = node;
        AddTextToBuffer(*text_node, range, buffer_, &buffer_node_mappings_);
      }
    }
    if (node == end_node) {
      node = FlatTreeTraversal::Next(*node);
      break;
    }
    node = FlatTreeTraversal::Next(*node);
  }
  node_after_block_ = node;
  FoldQuoteMarksAndSoftHyphens(base::span(buffer_));
}

void FindBuffer::ReplaceNodeWithCharConstants(const Node& node,
                                              Vector<UChar>& buffer) {
  if (std::optional<UChar> ch = CharConstantForNode(node)) {
    buffer.push_back(*ch);
  }
}

EphemeralRangeInFlatTree FindBuffer::RangeFromBufferIndex(
    unsigned start_index,
    unsigned end_index) const {
  DCHECK_LE(start_index, end_index);
  PositionInFlatTree start_position =
      PositionAtStartOfCharacterAtIndex(start_index);
  PositionInFlatTree end_position =
      PositionAtEndOfCharacterAtIndex(end_index - 1);
  return EphemeralRangeInFlatTree(start_position, end_position);
}

const FindBuffer::BufferNodeMapping* FindBuffer::MappingForIndex(
    unsigned index) const {
  // Get the first entry that starts at a position higher than offset, and
  // move back one entry.
  auto it = std::upper_bound(
      buffer_node_mappings_.begin(), buffer_node_mappings_.end(), index,
      [](const unsigned offset, const BufferNodeMapping& entry) {
        return offset < entry.offset_in_buffer;
      });
  if (it == buffer_node_mappings_.begin())
    return nullptr;
  auto entry = std::prev(it);
  return &*entry;
}

PositionInFlatTree FindBuffer::PositionAtStartOfCharacterAtIndex(
    unsigned index) const {
  DCHECK_LT(index, buffer_.size());
  DCHECK(offset_mapping_);
  const BufferNodeMapping* entry = MappingForIndex(index);
  if (!entry)
    return PositionInFlatTree();
  return ToPositionInFlatTree(offset_mapping_->GetLastPosition(
      index - entry->offset_in_buffer + entry->offset_in_mapping));
}

PositionInFlatTree FindBuffer::PositionAtEndOfCharacterAtIndex(
    unsigned index) const {
  DCHECK_LT(index, buffer_.size());
  DCHECK(offset_mapping_);
  const BufferNodeMapping* entry = MappingForIndex(index);
  if (!entry)
    return PositionInFlatTree();
  return ToPositionInFlatTree(offset_mapping_->GetFirstPosition(
      index - entry->offset_in_buffer + entry->offset_in_mapping + 1));
}

Vector<UChar> FindBuffer::SerializeLevelInGraph(
    const HeapVector<Member<CorpusChunk>>& chunk_list,
    const String& level,
    const EphemeralRangeInFlatTree& range) {
  Vector<BufferNodeMapping>* mappings =
      level.empty() ? &buffer_node_mappings_ : nullptr;
  Vector<UChar> buffer;
  const CorpusChunk* chunk = chunk_list[0];
  for (wtf_size_t index = 0; chunk; ++index) {
    if (chunk != chunk_list[index]) {
      for (const auto& text_or_char : chunk_list[index]->TextList()) {
        if (text_or_char.text) {
          wtf_size_t start = buffer.size();
          AddTextToBuffer(*text_or_char.text, range, buffer, mappings);
          for (wtf_size_t i = start; i < buffer.size(); ++i) {
            buffer[i] = kSkippedChar;
          }
        } else {
          buffer.push_back(kSkippedChar);
        }
      }
      continue;
    }
    for (const auto& text_or_char : chunk->TextList()) {
      if (text_or_char.text) {
        AddTextToBuffer(*text_or_char.text, range, buffer, mappings);
      } else {
        buffer.push_back(text_or_char.code_point);
      }
    }
    chunk = chunk->FindNext(level);
  }
  return buffer;
}

void FindBuffer::AddTextToBuffer(const Text& text_node,
                                 const EphemeralRangeInFlatTree& range,
                                 Vector<UChar>& buffer,
                                 Vector<BufferNodeMapping>* mappings) {
  LayoutBlockFlow& block_flow = *OffsetMapping::GetInlineFormattingContextOf(
      *text_node.GetLayoutObject());
  if (!offset_mapping_) {
    offset_mapping_ = InlineNode::GetOffsetMapping(&block_flow);

    if (!offset_mapping_) [[unlikely]] {
      // TODO(crbug.com/955678): There are certain cases where we fail to
      // compute the |OffsetMapping| due to failures in layout. As the root
      // cause is hard to fix at the moment, we just work around it here.
      return;
    }
  }

  Position node_start =
      (&text_node == range.StartPosition().ComputeContainerNode())
          ? ToPositionInDOMTree(range.StartPosition().ToOffsetInAnchor())
          : Position::FirstPositionInNode(text_node);
  Position node_end =
      (&text_node == range.EndPosition().ComputeContainerNode())
          ? ToPositionInDOMTree(range.EndPosition().ToOffsetInAnchor())
          : Position::LastPositionInNode(text_node);
  unsigned last_unit_end = 0;
  bool first_unit = true;
  const String mapped_text = offset_mapping_->GetText();
  for (const OffsetMappingUnit& unit :
       offset_mapping_->GetMappingUnitsForDOMRange(
           EphemeralRange(node_start, node_end))) {
    if (first_unit || last_unit_end != unit.TextContentStart()) {
      if (mappings) {
        // This is the first unit, or the units are not consecutive, so we need
        // to insert a new BufferNodeMapping.
        mappings->push_back(
            BufferNodeMapping({buffer.size(), unit.TextContentStart()}));
      }
      first_unit = false;
    }
    String text_for_unit =
        mapped_text.Substring(unit.TextContentStart(),
                              unit.TextContentEnd() - unit.TextContentStart());
    text_for_unit.Ensure16Bit();
    buffer.AppendSpan(text_for_unit.Span16());
    last_unit_end = unit.TextContentEnd();
  }
}

Vector<String> FindBuffer::BuffersForTesting() const {
  Vector<String> result;
  result.reserve(1 + buffer_list_.size());
  result.push_back(String(buffer_));
  for (const auto& buffer : buffer_list_) {
    result.push_back(String(buffer));
  }
  return result;
}

}  // namespace blink

"""

```