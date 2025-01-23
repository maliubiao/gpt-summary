Response:
Let's break down the thought process for analyzing this C++ file.

1. **Understand the Goal:** The primary goal is to understand the *purpose* and *functionality* of the `editing_commands_utilities.cc` file within the Blink rendering engine. We also need to identify connections to web technologies (HTML, CSS, JavaScript), potential user errors, and debugging clues.

2. **Initial Scan and Keywords:**  Read through the file quickly, looking for common keywords related to editing, DOM manipulation, and rendering. Keywords like "editing," "selection," "node," "element," "position," "layout," "style," "table," "list," "command," "undo," "input event," etc., stand out. The file header also mentions "commands," reinforcing the core functionality.

3. **Categorize Functions:** Start grouping functions based on their apparent purpose. This involves looking at function names and the types they operate on. Some initial categories might be:

    * **Node/Element Manipulation:** Functions dealing with finding specific nodes or elements (`HighestNodeToRemoveInPruning`, `IsTableStructureNode`, `IsInlineElement`, `EnclosingEmptyListItem`, `AreIdenticalElements`, `EnclosingList`, `EnclosingListChild`, `OutermostEnclosingList`).
    * **Position/Selection Handling:** Functions dealing with locations within the document and the currently selected content (`PositionBeforeContainingSpecialElement`, `PositionAfterContainingSpecialElement`, `LineBreakExistsAtPosition`, `PreviousCharacterPosition`, `LeadingCollapsibleWhitespacePosition`, `LineBreakExistsAtVisiblePosition`, `SelectionForParagraphIteration`, `CorrectedSelectionAfterCommand`, `ChangeSelectionAfterCommand`).
    * **Layout/Rendering Checks:** Functions determining if elements are rendered or how they are displayed (`IsNodeRendered`, `IsInlineNode`, `IsVisiblyAdjacent`).
    * **HTML Structure/Manipulation:** Functions dealing with the document's HTML structure, particularly in the context of editing (`CreateHTMLElement`, `TidyUpHTMLStructure`).
    * **Event Dispatching:** Functions for triggering events related to editing changes (`DispatchEditableContentChangedEvents`, `DispatchInputEvent`, `DispatchInputEventEditableContentChanged`).
    * **Block Handling:** Functions that identify the boundaries of blocks of content (`StartOfBlock`, `EndOfBlock`, `IsStartOfBlock`, `IsEndOfBlock`).
    * **Utility/Helper Functions:**  Functions providing general assistance (`NumEnclosingMailBlockquotes`, `NonBreakingSpaceString`, `DeletionInputTypeFromTextGranularity`, `IsComposingFromCommand`).

4. **Deep Dive into Function Logic:** For each function, try to understand what it does step-by-step. Look at the arguments, return values, and internal logic.

    * **Example:** For `HighestNodeToRemoveInPruning`, notice the loop that iterates up the DOM tree. The conditions inside the `if` statement (`!layout_object->CanHaveChildren()`, `HasARenderedDescendant`, etc.) suggest it's trying to find the highest node that *can* be safely removed without impacting rendered content.

5. **Identify Relationships with Web Technologies:** As you understand the function logic, think about how it relates to HTML, CSS, and JavaScript.

    * **HTML:** Functions like `CreateHTMLElement`, `EnclosingList`, and the logic in `TidyUpHTMLStructure` directly manipulate or inspect HTML elements and their structure.
    * **CSS:** Functions like `IsInlineElement`, `IsNodeRendered`, and the checks on `layout_object->Style()` directly interact with CSS properties to determine how elements are displayed.
    * **JavaScript:** While the C++ code doesn't *execute* JavaScript, its actions are often triggered by user interactions that could originate from JavaScript (e.g., `document.execCommand()`). The dispatching of `InputEvent`s is crucial for informing JavaScript about changes made through editing.

6. **Consider Edge Cases and Errors:**  Think about situations where things might go wrong or where users might make mistakes.

    * **Example:**  In `TidyUpHTMLStructure`, the code explicitly handles cases where the HTML structure is invalid. This suggests that user actions or JavaScript might lead to such states.

7. **Trace User Interactions:**  Try to imagine the sequence of user actions that could lead to the execution of code within this file. Focus on editing-related actions.

    * **Example:**  Typing text, deleting text, selecting text, using the "bold" or "italic" buttons, pasting content, dragging and dropping, etc. These actions often translate into calls to `document.execCommand()` or direct DOM manipulation, which then rely on the utilities in this file.

8. **Formulate Hypotheses and Examples:** Based on your understanding, create concrete examples to illustrate the functionality and relationships.

    * **Input/Output:**  For functions like `HighestNodeToRemoveInPruning`, imagine a specific DOM tree and how the function would traverse it and which node it would return.
    * **JavaScript/HTML/CSS:**  Show how a JavaScript command might trigger a function in this file and how that function might interact with the HTML or CSS of the page.
    * **User Errors:**  Describe scenarios where a user action might lead to a state handled by functions like `TidyUpHTMLStructure`.

9. **Organize and Refine:** Structure your findings logically. Use headings and bullet points to make the information clear and easy to understand. Review your explanations and examples for accuracy and clarity. Make sure you address all aspects of the prompt (functionality, web tech relationships, logic, errors, debugging).

10. **Self-Correction/Refinement:**  As you analyze, you might realize your initial assumptions were incorrect. Go back and adjust your understanding and explanations. For instance, you might initially think a function does one thing, but closer examination reveals a subtle difference in its behavior. The provided comments and copyright information can also offer clues about the file's history and purpose. The included header files also provide valuable context about the types of objects and operations involved.

By following this systematic process, you can effectively analyze a complex source code file like `editing_commands_utilities.cc` and extract the necessary information to answer the prompt comprehensively.
这个文件 `blink/renderer/core/editing/commands/editing_commands_utilities.cc` 是 Chromium Blink 引擎中负责处理编辑命令的辅助工具函数集合。它包含了一系列静态函数，这些函数被各种编辑命令（例如插入文本、删除文本、设置样式等）所调用，以执行一些通用的、底层的操作和判断。

以下是该文件主要的功能及其与 JavaScript, HTML, CSS 的关系，逻辑推理，用户错误和调试线索：

**主要功能:**

1. **DOM 结构分析和操作:**
   - **查找特定节点:**  例如 `HighestNodeToRemoveInPruning` 用于查找在修剪操作中最高的可移除节点。
   - **判断节点类型和属性:** 例如 `IsTableStructureNode` 判断节点是否是表格结构的一部分，`IsInlineElement` 判断节点是否是内联元素。
   - **遍历 DOM 树:**  很多函数内部使用 `NodeTraversal` 来遍历节点及其祖先或子节点。
   - **创建和操作 HTML 元素:** 例如 `CreateHTMLElement` 用于创建 HTML 元素。
   - **查找封闭元素:** 例如 `EnclosingList` 查找封闭的列表元素。

2. **位置 (Position) 和选择 (Selection) 处理:**
   - **比较和调整位置:** 例如 `PositionBeforeContainingSpecialElement` 和 `PositionAfterContainingSpecialElement` 用于调整光标位置以避开特定的 HTML 元素。
   - **判断行首行尾:** 例如 `IsStartOfParagraph` 和 `IsEndOfParagraph` (虽然这里没有直接定义，但有调用) 用于判断是否在段落的开始或结尾。
   - **判断可见位置:** 例如 `LineBreakExistsAtVisiblePosition` 判断在可见位置是否存在换行符。
   - **处理选择范围:** 例如 `SelectionForParagraphIteration` 用于调整选择范围以便进行段落迭代。
   - **处理空格:** 例如 `LeadingCollapsibleWhitespacePosition` 用于查找前导的可折叠空格的位置.

3. **编辑相关的判断:**
   - **判断是否可编辑:**  很多函数内部会检查节点或其祖先是否是可编辑的。
   - **判断元素是否相同:** `AreIdenticalElements` 判断两个元素是否具有相同的标签名和属性。
   - **判断是否需要布局更新:**  一些函数会断言 `!NeedsLayoutTreeUpdate(pos)`，表明它们假设在调用时布局已经是最新的。

4. **事件派发:**
   - **派发编辑内容改变事件:** `DispatchEditableContentChangedEvents` 和 `DispatchInputEventEditableContentChanged` 用于在编辑操作后通知相关的元素。

5. **HTML 结构整理:**
   - **修复无效的 HTML 结构:** `TidyUpHTMLStructure` 用于在 `document.execCommand()` 操作前，尝试修复一些常见的无效 HTML 结构，以保证编辑命令的正确执行。

6. **输入事件类型转换:**
   - `DeletionInputTypeFromTextGranularity` 将删除方向和粒度转换为对应的输入事件类型。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:**
    - **`document.execCommand()`:** 这个文件中的功能很大程度上是为了支持 JavaScript 中 `document.execCommand()` 方法的各种编辑命令。当 JavaScript 调用 `document.execCommand('bold')` 时，Blink 引擎会执行相应的 C++ 代码，而这些 C++ 代码很可能会用到 `editing_commands_utilities.cc` 中的函数来辅助完成操作。
    - **事件触发:**  `DispatchInputEvent` 等函数用于派发 `input` 事件，这些事件会被 JavaScript 监听并处理，例如用于实现富文本编辑器的撤销/重做功能。
    - **假设输入与输出:** 假设 JavaScript 调用 `document.execCommand('insertText', false, 'Hello');`，这个命令最终会调用 Blink 的 C++ 代码，其中可能会使用到 `LeadingCollapsibleWhitespacePosition` 来判断插入位置前是否有需要处理的空格，最终将 "Hello" 插入到 DOM 中。

* **HTML:**
    - **DOM 结构操作:** 该文件中的函数直接操作 HTML 元素，例如创建、查找、修改元素。像 `EnclosingList` 可以找到一个节点所在的最近的 `<ul>` 或 `<ol>` 元素。
    - **表格和列表处理:** 很多函数专门处理表格 (`IsTableStructureNode`) 和列表 (`EnclosingList`, `EnclosingListChild`)，因为这些结构在富文本编辑中比较复杂。
    - **假设输入与输出:** 假设当前光标在一个 `<li>` 元素内，调用一个删除命令，可能会用到 `EnclosingEmptyListItem` 来判断这个 `<li>` 是否是空的，并决定如何处理删除操作。

* **CSS:**
    - **样式判断:** `IsInlineElement` 函数通过检查元素的 `ComputedStyle` 来判断其 `display` 属性是否为 `inline` 或 `ruby`。`IsNodeRendered` 判断元素的 `visibility` 属性是否为 `visible`。
    - **布局影响:** 该文件中的很多操作会间接影响页面的布局。例如，插入或删除节点可能会导致重新布局。
    - **假设输入与输出:** 假设光标在一个 `<span>` 元素内，该元素通过 CSS 设置了 `display: inline;`，那么 `IsInlineElement` 函数会返回 `true`。

**逻辑推理 (假设输入与输出):**

* **假设输入:** 光标位于一个空的 `<li>` 元素内： `<ul><li>|</li></ul>`，其中 `|` 代表光标位置。
* **调用的函数:** `EnclosingEmptyListItem(visible_pos)`
* **逻辑推理:** 该函数会检查光标所在的位置是否在一个列表项内，并且该列表项是否为空（即行首也是行尾）。
* **输出:** 函数会返回该 `<li>` 元素的指针。

* **假设输入:** 光标位于一个表格单元格内： `<table><tr><td>|Text</td></tr></table>`。
* **调用的函数:**  在执行某些编辑命令时，可能会调用 `IsTableStructureNode(node)`，其中 `node` 是光标所在的 `<td>` 元素。
* **逻辑推理:** 函数会检查该节点的 `LayoutObject` 是否是 `LayoutTableCell` 类型。
* **输出:** 函数会返回 `true`.

**用户或编程常见的使用错误:**

1. **在不可编辑区域尝试编辑:** 用户可能会尝试在 `contenteditable="false"` 的元素内部进行编辑操作。该文件中的很多函数会检查元素的可编辑性，以避免在不可编辑区域执行编辑操作。
2. **操作无效的 DOM 结构:** 用户或 JavaScript 代码可能会导致 DOM 结构变得无效，例如缺少 `<body>` 标签。`TidyUpHTMLStructure` 尝试解决这类问题，但这本身也暗示了用户或编程可能犯的错误。
3. **假设布局总是最新的:** 开发者可能会错误地假设在调用某些编辑命令时，DOM 的布局总是最新的。该文件中一些函数的断言 `!NeedsLayoutTreeUpdate(pos)` 表明了这种潜在的错误，即需要在调用这些函数前确保布局已经更新。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在可编辑区域进行操作:** 用户在带有 `contenteditable="true"` 属性的元素或者使用了 `designMode` 的文档中进行操作，例如：
   - **输入文本:**  按下键盘上的字符键。
   - **删除文本:**  按下 Backspace 或 Delete 键。
   - **选择文本并执行格式化命令:** 例如选中文字后点击 "加粗" 按钮。
   - **粘贴内容:**  使用 Ctrl+V 或右键菜单粘贴。
   - **使用浏览器的编辑菜单:**  例如 "剪切", "复制", "粘贴" 等。

2. **浏览器捕获用户操作:**  浏览器会捕获这些用户交互事件。

3. **浏览器触发相应的编辑命令:**  对于用户的编辑操作，浏览器会将其转换为内部的编辑命令。例如，按下字符键可能会触发一个 "insertText" 命令。执行格式化操作会触发相应的格式化命令（例如 "bold", "italic"）。

4. **`document.execCommand()` 调用 (对于某些操作):**  一些编辑操作可能会通过 JavaScript 调用 `document.execCommand()` 来触发，虽然现代 Web 标准更倾向于使用 `Input Events API`。

5. **Blink 引擎执行编辑命令:**  浏览器会将这些编辑命令传递给 Blink 引擎的渲染模块进行处理.

6. **调用 `editing_commands_utilities.cc` 中的函数:**  在执行具体的编辑命令的过程中，相关的命令处理代码会调用 `editing_commands_utilities.cc` 中提供的辅助函数来完成一些底层的 DOM 操作、位置计算、样式判断等任务。

**调试线索:**

* **断点调试:**  在 `editing_commands_utilities.cc` 中设置断点，可以跟踪特定编辑命令执行过程中调用的辅助函数，观察 DOM 结构、位置信息和样式信息的变化。
* **日志输出:**  可以在关键函数中添加日志输出，打印出函数的输入参数和返回值，帮助理解函数的行为。
* **DOM Inspector:**  结合浏览器的开发者工具中的 DOM Inspector，可以实时查看 DOM 树的结构和属性，与代码的执行情况进行对照。
* **研究调用堆栈:**  当程序执行到 `editing_commands_utilities.cc` 中的函数时，查看调用堆栈可以了解是哪个编辑命令或者哪个模块调用了这些工具函数。
* **理解编辑命令的执行流程:**  深入理解 Blink 引擎中各种编辑命令的实现流程，有助于定位问题发生的位置。例如，了解 "insertText" 命令会涉及到哪些步骤，哪些辅助函数会被调用。

总而言之，`editing_commands_utilities.cc` 是 Blink 引擎中编辑功能的核心支撑模块之一，它提供了一系列基础工具函数，使得各种复杂的编辑操作能够可靠地执行。理解这个文件的功能对于理解 Blink 引擎的编辑机制至关重要。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/editing_commands_utilities.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2004, 2005, 2006, 2007 Apple Inc. All rights reserved.
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

// Copyright 2018 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"

#include "third_party/blink/public/web/web_local_frame_client.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/selection_for_undo_step.h"
#include "third_party/blink/renderer/core/editing/commands/typing_command.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_client.h"
#include "third_party/blink/renderer/core/frame/web_feature_forward.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_frame_set_element.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html/html_html_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/layout/layout_text.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"

namespace blink {

static bool HasARenderedDescendant(const Node* node,
                                   const Node* excluded_node) {
  for (const Node* n = node->firstChild(); n;) {
    if (n == excluded_node) {
      n = NodeTraversal::NextSkippingChildren(*n, node);
      continue;
    }
    if (n->GetLayoutObject())
      return true;
    n = NodeTraversal::Next(*n, node);
  }
  return false;
}

Node* HighestNodeToRemoveInPruning(Node* node, const Node* exclude_node) {
  Node* previous_node = nullptr;
  Element* element = node ? RootEditableElement(*node) : nullptr;
  for (; node; node = node->parentNode()) {
    if (LayoutObject* layout_object = node->GetLayoutObject()) {
      if (!layout_object->CanHaveChildren() ||
          HasARenderedDescendant(node, previous_node) || element == node ||
          exclude_node == node)
        return previous_node;
    }
    previous_node = node;
  }
  return nullptr;
}

bool IsTableStructureNode(const Node* node) {
  LayoutObject* layout_object = node->GetLayoutObject();
  return (layout_object &&
          (layout_object->IsTableCell() || layout_object->IsTableRow() ||
           layout_object->IsTableSection() ||
           layout_object->IsLayoutTableCol()));
}

bool IsNodeRendered(const Node& node) {
  LayoutObject* layout_object = node.GetLayoutObject();
  if (!layout_object)
    return false;

  return layout_object->Style()->Visibility() == EVisibility::kVisible;
}

bool IsInlineElement(const Node* node) {
  const Element* element = DynamicTo<Element>(node);
  if (!element) {
    return false;
  }
  const ComputedStyle* style = element->GetComputedStyle();
  // Should we apply IsDisplayInlineType()?
  return style && (style->Display() == EDisplay::kInline ||
                   style->Display() == EDisplay::kRuby);
}

bool IsInlineNode(const Node* node) {
  if (!node) {
    return false;
  }

  if (IsInlineElement(node)) {
    return true;
  }

  if (LayoutObject* layout_object = node->GetLayoutObject()) {
    return layout_object->IsInline();
  }
  return false;
}

// FIXME: This method should not need to call
// isStartOfParagraph/isEndOfParagraph
Node* EnclosingEmptyListItem(const VisiblePosition& visible_pos) {
  DCHECK(visible_pos.IsValid());

  // Check that position is on a line by itself inside a list item
  Node* list_child_node =
      EnclosingListChild(visible_pos.DeepEquivalent().AnchorNode());
  if (!list_child_node || !IsStartOfParagraph(visible_pos) ||
      !IsEndOfParagraph(visible_pos))
    return nullptr;

  VisiblePosition first_in_list_child =
      CreateVisiblePosition(FirstPositionInOrBeforeNode(*list_child_node));
  VisiblePosition last_in_list_child =
      CreateVisiblePosition(LastPositionInOrAfterNode(*list_child_node));

  if (first_in_list_child.DeepEquivalent() != visible_pos.DeepEquivalent() ||
      last_in_list_child.DeepEquivalent() != visible_pos.DeepEquivalent())
    return nullptr;

  return list_child_node;
}

bool AreIdenticalElements(const Node& first, const Node& second) {
  const auto* first_element = DynamicTo<Element>(first);
  const auto* second_element = DynamicTo<Element>(second);
  if (!first_element || !second_element)
    return false;

  if (!first_element->HasTagName(second_element->TagQName()))
    return false;

  if (!first_element->HasEquivalentAttributes(*second_element))
    return false;

  return IsEditable(*first_element) && IsEditable(*second_element);
}

// FIXME: need to dump this
static bool IsSpecialHTMLElement(const Node& n) {
  if (!n.IsHTMLElement())
    return false;

  if (n.IsLink())
    return true;

  LayoutObject* layout_object = n.GetLayoutObject();
  if (!layout_object)
    return false;

  if (layout_object->Style()->IsDisplayTableBox())
    return true;

  if (layout_object->IsFloating())
    return true;

  return false;
}

static HTMLElement* FirstInSpecialElement(const Position& pos) {
  DCHECK(!NeedsLayoutTreeUpdate(pos));
  Element* element = RootEditableElement(*pos.ComputeContainerNode());
  for (Node& runner : NodeTraversal::InclusiveAncestorsOf(*pos.AnchorNode())) {
    if (RootEditableElement(runner) != element)
      break;
    if (IsSpecialHTMLElement(runner)) {
      auto* special_element = To<HTMLElement>(&runner);
      VisiblePosition v_pos = CreateVisiblePosition(pos);
      VisiblePosition first_in_element =
          CreateVisiblePosition(FirstPositionInOrBeforeNode(*special_element));
      if (IsDisplayInsideTable(special_element) &&
          !IsListItem(v_pos.DeepEquivalent().ComputeContainerNode()) &&
          v_pos.DeepEquivalent() ==
              NextPositionOf(first_in_element).DeepEquivalent())
        return special_element;
      if (v_pos.DeepEquivalent() == first_in_element.DeepEquivalent())
        return special_element;
    }
  }
  return nullptr;
}

static HTMLElement* LastInSpecialElement(const Position& pos) {
  DCHECK(!NeedsLayoutTreeUpdate(pos));
  Element* element = RootEditableElement(*pos.ComputeContainerNode());
  for (Node& runner : NodeTraversal::InclusiveAncestorsOf(*pos.AnchorNode())) {
    if (RootEditableElement(runner) != element)
      break;
    if (IsSpecialHTMLElement(runner)) {
      auto* special_element = To<HTMLElement>(&runner);
      VisiblePosition v_pos = CreateVisiblePosition(pos);
      VisiblePosition last_in_element =
          CreateVisiblePosition(LastPositionInOrAfterNode(*special_element));
      if (IsDisplayInsideTable(special_element) &&
          v_pos.DeepEquivalent() ==
              PreviousPositionOf(last_in_element).DeepEquivalent())
        return special_element;
      if (v_pos.DeepEquivalent() == last_in_element.DeepEquivalent())
        return special_element;
    }
  }
  return nullptr;
}

Position PositionBeforeContainingSpecialElement(
    const Position& pos,
    HTMLElement** containing_special_element) {
  DCHECK(!NeedsLayoutTreeUpdate(pos));
  HTMLElement* n = FirstInSpecialElement(pos);
  if (!n)
    return pos;
  Position result = Position::InParentBeforeNode(*n);
  if (result.IsNull() || RootEditableElement(*result.AnchorNode()) !=
                             RootEditableElement(*pos.AnchorNode()))
    return pos;
  if (containing_special_element)
    *containing_special_element = n;
  return result;
}

Position PositionAfterContainingSpecialElement(
    const Position& pos,
    HTMLElement** containing_special_element) {
  DCHECK(!NeedsLayoutTreeUpdate(pos));
  HTMLElement* n = LastInSpecialElement(pos);
  if (!n)
    return pos;
  Position result = Position::InParentAfterNode(*n);
  if (result.IsNull() || RootEditableElement(*result.AnchorNode()) !=
                             RootEditableElement(*pos.AnchorNode()))
    return pos;
  if (containing_special_element)
    *containing_special_element = n;
  return result;
}

bool LineBreakExistsAtPosition(const Position& position) {
  if (position.IsNull())
    return false;

  if (IsA<HTMLBRElement>(*position.AnchorNode()) &&
      position.AtFirstEditingPositionForNode())
    return true;

  if (!position.AnchorNode()->GetLayoutObject())
    return false;

  const auto* text_node = DynamicTo<Text>(position.AnchorNode());
  if (!text_node ||
      text_node->GetLayoutObject()->Style()->ShouldCollapseBreaks()) {
    return false;
  }

  unsigned offset = position.OffsetInContainerNode();
  return offset < text_node->length() && text_node->data()[offset] == '\n';
}

// return first preceding DOM position rendered at a different location, or
// "this"
static Position PreviousCharacterPosition(const Position& position,
                                          TextAffinity affinity) {
  DCHECK(!NeedsLayoutTreeUpdate(position));
  if (position.IsNull())
    return Position();

  Element* from_root_editable_element =
      RootEditableElement(*position.AnchorNode());

  bool at_start_of_line =
      IsStartOfLine(CreateVisiblePosition(position, affinity));
  bool rendered = IsVisuallyEquivalentCandidate(position);

  Position current_pos = position;
  while (!current_pos.AtStartOfTree()) {
    // TODO(yosin) When we use |previousCharacterPosition()| other than
    // finding leading whitespace, we should use |Character| instead of
    // |CodePoint|.
    current_pos = PreviousPositionOf(current_pos, PositionMoveType::kCodeUnit);

    if (RootEditableElement(*current_pos.AnchorNode()) !=
        from_root_editable_element)
      return position;

    if (at_start_of_line || !rendered) {
      if (IsVisuallyEquivalentCandidate(current_pos))
        return current_pos;
    } else if (RendersInDifferentPosition(position, current_pos)) {
      return current_pos;
    }
  }

  return position;
}

// This assumes that it starts in editable content.
Position LeadingCollapsibleWhitespacePosition(const Position& position,
                                              TextAffinity affinity,
                                              WhitespacePositionOption option) {
  DCHECK(!NeedsLayoutTreeUpdate(position));
  DCHECK(IsEditablePosition(position)) << position;
  if (position.IsNull())
    return Position();

  if (IsA<HTMLBRElement>(*MostBackwardCaretPosition(position).AnchorNode()))
    return Position();

  const Position& prev = PreviousCharacterPosition(position, affinity);
  if (prev == position)
    return Position();
  const Node* const anchor_node = prev.AnchorNode();
  auto* anchor_text_node = DynamicTo<Text>(anchor_node);
  if (!anchor_text_node)
    return Position();
  if (EnclosingBlockFlowElement(*anchor_node) !=
      EnclosingBlockFlowElement(*position.AnchorNode()))
    return Position();
  if (option == kNotConsiderNonCollapsibleWhitespace &&
      anchor_node->GetLayoutObject() &&
      anchor_node->GetLayoutObject()->Style()->ShouldPreserveWhiteSpaces()) {
    return Position();
  }
  const String& string = anchor_text_node->data();
  const UChar previous_character = string[prev.ComputeOffsetInContainerNode()];
  const bool is_space = option == kConsiderNonCollapsibleWhitespace
                            ? (IsSpaceOrNewline(previous_character) ||
                               previous_character == kNoBreakSpaceCharacter)
                            : IsCollapsibleWhitespace(previous_character);
  if (!is_space || !IsEditablePosition(prev))
    return Position();
  return prev;
}

unsigned NumEnclosingMailBlockquotes(const Position& p) {
  unsigned num = 0;
  for (const Node* n = p.AnchorNode(); n; n = n->parentNode()) {
    if (IsMailHTMLBlockquoteElement(n))
      num++;
  }
  return num;
}

bool LineBreakExistsAtVisiblePosition(const VisiblePosition& visible_position) {
  return LineBreakExistsAtPosition(
      MostForwardCaretPosition(visible_position.DeepEquivalent()));
}

HTMLElement* CreateHTMLElement(Document& document, const QualifiedName& name) {
  DCHECK_EQ(name.NamespaceURI(), html_names::xhtmlNamespaceURI)
      << "Unexpected namespace: " << name;
  return To<HTMLElement>(document.CreateElement(
      name, CreateElementFlags::ByCloneNode(), g_null_atom));
}

HTMLElement* EnclosingList(const Node* node) {
  if (!node)
    return nullptr;

  ContainerNode* root = HighestEditableRoot(FirstPositionInOrBeforeNode(*node));

  for (Node& runner : NodeTraversal::AncestorsOf(*node)) {
    if (IsA<HTMLUListElement>(runner) || IsA<HTMLOListElement>(runner))
      return To<HTMLElement>(&runner);
    if (runner == root)
      return nullptr;
  }

  return nullptr;
}

Node* EnclosingListChild(const Node* node) {
  if (!node)
    return nullptr;
  // Check for a list item element, or for a node whose parent is a list
  // element. Such a node will appear visually as a list item (but without a
  // list marker)
  ContainerNode* root = HighestEditableRoot(FirstPositionInOrBeforeNode(*node));

  // FIXME: This function is inappropriately named if it starts with node
  // instead of node->parentNode()
  for (Node* n = const_cast<Node*>(node); n && n->parentNode();
       n = n->parentNode()) {
    if ((IsListItemTag(n) || IsListElementTag(n->parentNode())) && n != root) {
      return n;
    }
    if (n == root || IsTableCell(n))
      return nullptr;
  }

  return nullptr;
}

HTMLElement* OutermostEnclosingList(const Node* node,
                                    const HTMLElement* root_list) {
  HTMLElement* list = EnclosingList(node);
  if (!list)
    return nullptr;

  while (HTMLElement* next_list = EnclosingList(list)) {
    if (next_list == root_list)
      break;
    list = next_list;
  }

  return list;
}

// Determines whether two positions are visibly next to each other (first then
// second) while ignoring whitespaces and unrendered nodes
static bool IsVisiblyAdjacent(const Position& first, const Position& second) {
  return CreateVisiblePosition(first).DeepEquivalent() ==
         CreateVisiblePosition(MostBackwardCaretPosition(second))
             .DeepEquivalent();
}

bool CanMergeLists(const Element& first_list, const Element& second_list) {
  if (!first_list.IsHTMLElement() || !second_list.IsHTMLElement())
    return false;

  DCHECK(!NeedsLayoutTreeUpdate(first_list));
  DCHECK(!NeedsLayoutTreeUpdate(second_list));
  return first_list.HasTagName(
             second_list
                 .TagQName())  // make sure the list types match (ol vs. ul)
         && IsEditable(first_list) &&
         IsEditable(second_list)  // both lists are editable
         &&
         RootEditableElement(first_list) ==
             RootEditableElement(second_list)  // don't cross editing boundaries
         && IsVisiblyAdjacent(Position::InParentAfterNode(first_list),
                              Position::InParentBeforeNode(second_list));
  // Make sure there is no visible content between this li and the previous list
}

// Modifies selections that have an end point at the edge of a table
// that contains the other endpoint so that they don't confuse
// code that iterates over selected paragraphs.
VisibleSelection SelectionForParagraphIteration(
    const VisibleSelection& original) {
  VisibleSelection new_selection(original);
  VisiblePosition start_of_selection(new_selection.VisibleStart());
  VisiblePosition end_of_selection(new_selection.VisibleEnd());

  // If the end of the selection to modify is just after a table, and if the
  // start of the selection is inside that table, then the last paragraph that
  // we'll want modify is the last one inside the table, not the table itself (a
  // table is itself a paragraph).
  if (Element* table = TableElementJustBefore(end_of_selection)) {
    DCHECK(start_of_selection.IsNotNull()) << new_selection;
    if (start_of_selection.DeepEquivalent().AnchorNode()->IsDescendantOf(
            table)) {
      const VisiblePosition& new_end =
          PreviousPositionOf(end_of_selection, kCannotCrossEditingBoundary);
      if (new_end.IsNotNull()) {
        new_selection = CreateVisibleSelection(
            SelectionInDOMTree::Builder()
                .Collapse(start_of_selection.ToPositionWithAffinity())
                .Extend(new_end.DeepEquivalent())
                .Build());
      } else {
        new_selection = CreateVisibleSelection(
            SelectionInDOMTree::Builder()
                .Collapse(start_of_selection.ToPositionWithAffinity())
                .Build());
      }
    }
  }

  // If the start of the selection to modify is just before a table, and if the
  // end of the selection is inside that table, then the first paragraph we'll
  // want to modify is the first one inside the table, not the paragraph
  // containing the table itself.
  if (Element* table = TableElementJustAfter(start_of_selection)) {
    DCHECK(end_of_selection.IsNotNull()) << new_selection;
    if (end_of_selection.DeepEquivalent().AnchorNode()->IsDescendantOf(table)) {
      const VisiblePosition new_start =
          NextPositionOf(start_of_selection, kCannotCrossEditingBoundary);
      if (new_start.IsNotNull()) {
        new_selection = CreateVisibleSelection(
            SelectionInDOMTree::Builder()
                .Collapse(new_start.ToPositionWithAffinity())
                .Extend(end_of_selection.DeepEquivalent())
                .Build());
      } else {
        new_selection = CreateVisibleSelection(
            SelectionInDOMTree::Builder()
                .Collapse(end_of_selection.ToPositionWithAffinity())
                .Build());
      }
    }
  }

  return new_selection;
}

const String& NonBreakingSpaceString() {
  DEFINE_STATIC_LOCAL(String, non_breaking_space_string,
                      (base::span_from_ref(kNoBreakSpaceCharacter)));
  return non_breaking_space_string;
}

// TODO(tkent): This is a workaround of some crash bugs in the editing code,
// which assumes a document has a valid HTML structure. We should make the
// editing code more robust, and should remove this hack. crbug.com/580941.
void TidyUpHTMLStructure(Document& document) {
  // IsEditable() needs up-to-date ComputedStyle.
  document.UpdateStyleAndLayoutTree();
  const bool needs_valid_structure =
      IsEditable(document) ||
      (document.documentElement() && IsEditable(*document.documentElement()));
  if (!needs_valid_structure)
    return;

  Element* const current_root = document.documentElement();
  if (current_root && IsA<HTMLHtmlElement>(current_root))
    return;
  Element* const existing_head =
      current_root && IsA<HTMLHeadElement>(current_root) ? current_root
                                                         : nullptr;
  Element* const existing_body =
      current_root && (IsA<HTMLBodyElement>(current_root) ||
                       IsA<HTMLFrameSetElement>(current_root))
          ? current_root
          : nullptr;
  // We ensure only "the root is <html>."
  // documentElement as rootEditableElement is problematic.  So we move
  // non-<html> root elements under <body>, and the <body> works as
  // rootEditableElement.
  document.AddConsoleMessage(MakeGarbageCollected<ConsoleMessage>(
      mojom::ConsoleMessageSource::kJavaScript,
      mojom::ConsoleMessageLevel::kWarning,
      "document.execCommand() doesn't work with an invalid HTML structure. It "
      "is corrected automatically."));
  UseCounter::Count(document, WebFeature::kExecCommandAltersHTMLStructure);

  auto* const root = MakeGarbageCollected<HTMLHtmlElement>(document);
  if (existing_head)
    root->AppendChild(existing_head);
  auto* const body = existing_body
                         ? existing_body
                         : MakeGarbageCollected<HTMLBodyElement>(document);
  if (document.documentElement() && body != document.documentElement())
    body->AppendChild(document.documentElement());
  root->AppendChild(body);
  DCHECK(!document.documentElement());
  document.AppendChild(root);

  // TODO(tkent): Should we check and move Text node children of <html>?
}

InputEvent::InputType DeletionInputTypeFromTextGranularity(
    DeleteDirection direction,
    TextGranularity granularity) {
  using InputType = InputEvent::InputType;
  switch (direction) {
    case DeleteDirection::kForward:
      if (granularity == TextGranularity::kWord)
        return InputType::kDeleteWordForward;
      if (granularity == TextGranularity::kLineBoundary)
        return InputType::kDeleteSoftLineForward;
      if (granularity == TextGranularity::kParagraphBoundary)
        return InputType::kDeleteHardLineForward;
      return InputType::kDeleteContentForward;
    case DeleteDirection::kBackward:
      if (granularity == TextGranularity::kWord)
        return InputType::kDeleteWordBackward;
      if (granularity == TextGranularity::kLineBoundary)
        return InputType::kDeleteSoftLineBackward;
      if (granularity == TextGranularity::kParagraphBoundary)
        return InputType::kDeleteHardLineBackward;
      return InputType::kDeleteContentBackward;
    default:
      return InputType::kNone;
  }
}

void DispatchEditableContentChangedEvents(Element* start_root,
                                          Element* end_root) {
  if (start_root) {
    start_root->DefaultEventHandler(
        *Event::Create(event_type_names::kWebkitEditableContentChanged));
  }
  if (end_root && end_root != start_root) {
    end_root->DefaultEventHandler(
        *Event::Create(event_type_names::kWebkitEditableContentChanged));
  }
}

static void DispatchInputEvent(Element* target,
                               InputEvent::InputType input_type,
                               const String& data,
                               InputEvent::EventIsComposing is_composing) {
  if (!target)
    return;
  // TODO(editing-dev): Pass appreciate |ranges| after it's defined on spec.
  // http://w3c.github.io/editing/input-events.html#dom-inputevent-inputtype
  InputEvent* const input_event =
      InputEvent::CreateInput(input_type, data, is_composing, nullptr);
  target->DispatchScopedEvent(*input_event);
}

void DispatchInputEventEditableContentChanged(
    Element* start_root,
    Element* end_root,
    InputEvent::InputType input_type,
    const String& data,
    InputEvent::EventIsComposing is_composing) {
  if (start_root)
    DispatchInputEvent(start_root, input_type, data, is_composing);
  if (end_root && end_root != start_root)
    DispatchInputEvent(end_root, input_type, data, is_composing);
}

SelectionInDOMTree CorrectedSelectionAfterCommand(
    const SelectionForUndoStep& passed_selection,
    Document* document) {
  if (!passed_selection.Anchor().IsValidFor(*document) ||
      !passed_selection.Focus().IsValidFor(*document)) {
    return SelectionInDOMTree();
  }
  if (RuntimeEnabledFeatures::RemoveVisibleSelectionInDOMSelectionEnabled()) {
    document->UpdateStyleAndLayout(DocumentUpdateReason::kEditing);
    return CreateVisibleSelection(passed_selection.AsSelection()).AsSelection();
  } else {
    return passed_selection.AsSelection();
  }
}

void ChangeSelectionAfterCommand(LocalFrame* frame,
                                 const SelectionInDOMTree& new_selection,
                                 const SetSelectionOptions& options) {
  if (new_selection.IsNone())
    return;
  // See <rdar://problem/5729315> Some shouldChangeSelectedDOMRange contain
  // Ranges for selections that are no longer valid
  const bool selection_did_not_change_dom_position =
      new_selection == frame->Selection().GetSelectionInDOMTree() &&
      options.IsDirectional() == frame->Selection().IsDirectional();
  const bool handle_visible =
      frame->Selection().IsHandleVisible() && new_selection.IsRange();
  frame->Selection().SetSelection(new_selection,
                                  SetSelectionOptions::Builder(options)
                                      .SetShouldShowHandle(handle_visible)
                                      .SetIsDirectional(options.IsDirectional())
                                      .Build());

  // Some editing operations change the selection visually without affecting its
  // position within the DOM. For example when you press return in the following
  // (the caret is marked by ^):
  // <div contentEditable="true"><div>^Hello</div></div>
  // WebCore inserts <div><br></div> *before* the current block, which correctly
  // moves the paragraph down but which doesn't change the caret's DOM position
  // (["hello", 0]). In these situations the above FrameSelection::setSelection
  // call does not call LocalFrameClient::DidChangeSelection(), which, on the
  // Mac, sends selection change notifications and starts a new kill ring
  // sequence, but we want to do these things (matches AppKit).
  if (!selection_did_not_change_dom_position)
    return;
  frame->Client()->DidChangeSelection(
      !frame->Selection().GetSelectionInDOMTree().IsRange(),
      blink::SyncCondition::kNotForced);
}

InputEvent::EventIsComposing IsComposingFromCommand(
    const CompositeEditCommand* command) {
  auto* typing_command = DynamicTo<TypingCommand>(command);
  if (typing_command &&
      typing_command->CompositionType() != TypingCommand::kTextCompositionNone)
    return InputEvent::EventIsComposing::kIsComposing;
  return InputEvent::EventIsComposing::kNotComposing;
}

// ---------

VisiblePosition StartOfBlock(const VisiblePosition& visible_position,
                             EditingBoundaryCrossingRule rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  Position position = visible_position.DeepEquivalent();
  Element* start_block =
      position.ComputeContainerNode()
          ? EnclosingBlock(position.ComputeContainerNode(), rule)
          : nullptr;
  return start_block ? VisiblePosition::FirstPositionInNode(*start_block)
                     : VisiblePosition();
}

VisiblePosition EndOfBlock(const VisiblePosition& visible_position,
                           EditingBoundaryCrossingRule rule) {
  DCHECK(visible_position.IsValid()) << visible_position;
  Position position = visible_position.DeepEquivalent();
  Element* end_block =
      position.ComputeContainerNode()
          ? EnclosingBlock(position.ComputeContainerNode(), rule)
          : nullptr;
  return end_block ? VisiblePosition::LastPositionInNode(*end_block)
                   : VisiblePosition();
}

bool IsStartOfBlock(const VisiblePosition& pos) {
  DCHECK(pos.IsValid()) << pos;
  return pos.IsNotNull() &&
         pos.DeepEquivalent() ==
             StartOfBlock(pos, kCanCrossEditingBoundary).DeepEquivalent();
}

bool IsEndOfBlock(const VisiblePosition& pos) {
  DCHECK(pos.IsValid()) << pos;
  return pos.IsNotNull() &&
         pos.DeepEquivalent() ==
             EndOfBlock(pos, kCanCrossEditingBoundary).DeepEquivalent();
}

}  // namespace blink
```