Response:
My thought process to answer the request about `editing_utilities.cc` goes like this:

1. **Understand the Goal:** The request asks for a summary of the file's functionality, its relationship to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, common usage errors, debugging clues, and a final summary for Part 1.

2. **Initial Scan and Keywords:** I quickly scan the `#include` directives and the namespace declaration (`namespace blink`). This immediately tells me:
    * It's a C++ file within the Blink rendering engine (Chromium).
    * It deals with `editing`.
    * It interacts with core web concepts like `clipboard`, `DOM`, `range`, `selection`, `ime`, `text`, `html`, `css`, and `layout`.

3. **Categorize Functionality Based on Includes:** I group the functionalities based on the included headers. This provides a structured way to analyze the code:

    * **Core Editing Concepts:**  `editing_strategy.h`, `editor.h`, `ephemeral_range.h`, `frame_selection.h`, `visible_position.h`, `visible_selection.h`, `visible_units.h`, `plain_text_range.h`, `position_iterator.h`, `position_with_affinity.h`, `selection_template.h`, `serializers/html_interchange.h`. These suggest the file manages the selection, manipulation, and representation of text and content within the editor.

    * **Input and IME:** `ime/edit_context.h`, `ime/input_method_controller.h`. This indicates involvement in handling user input, especially through Input Method Editors (for languages like Chinese, Japanese, Korean).

    * **DOM Manipulation:** `dom/document.h`, `dom/element_traversal.h`, `dom/node_computed_style.h`, `dom/range.h`, `dom/shadow_root.h`, `dom/text.h`. This confirms the file works directly with the Document Object Model (the tree-like structure of a web page).

    * **HTML Elements:**  Numerous `#include`s for specific HTML elements (`html_input_element.h`, `html_div_element.h`, etc.). This strongly suggests the utilities handle editing interactions within these specific elements.

    * **Clipboard Operations:** `clipboard/clipboard_mime_types.h`, `clipboard/data_object.h`, `clipboard/data_transfer.h`, `clipboard/data_transfer_access_policy.h`, `clipboard/system_clipboard.h`. This shows involvement in copy/paste and drag-and-drop functionalities.

    * **Layout and Rendering:** `layout/hit_test_result.h`, `layout/layout_image.h`, `layout/layout_object.h`. This indicates the utilities need to understand the visual layout of the page to perform editing actions correctly.

    * **Text Handling:** `iterators/text_iterator.h`, `wtf/text/string_builder.h`, `wtf/text/unicode.h`. This points to functionalities for iterating through text, building strings, and handling Unicode characters.

    * **State Machines:** `state_machines/backspace_state_machine.h`, etc. This implies the file uses state machines to manage complex editing operations like backspace and navigating through grapheme boundaries.

4. **Infer Functionality from Names and Comments:** I look at the copyright notice and any comments in the code (though the provided snippet has minimal comments). The copyright indicates Apple's initial involvement. The function names themselves often provide strong hints (e.g., `IsEditable`, `RootEditableElement`, `NextCandidate`, `PreviousGraphemeBoundaryOf`).

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**

    * **HTML:** The file directly manipulates HTML elements. Examples include checking if an element is editable (`IsEditable`), finding the root editable element (`RootEditableElement`), and handling input within specific HTML form elements (`HTMLInputElement`, `HTMLTextAreaElement`).
    * **CSS:** The code checks computed styles (`node.GetComputedStyleForElementOrLayoutObject()`) to determine if an element is editable based on the `user-modify` CSS property.
    * **JavaScript:** While this C++ code doesn't directly *execute* JavaScript, it provides the underlying functionality that JavaScript interacts with. For instance, when a user types in an input field (handled by JavaScript event listeners), the browser relies on code like this to manage the text insertion and cursor movement. JavaScript's `document.execCommand()` or the Selection API would indirectly trigger these utilities.

6. **Identify Potential Logical Reasoning (Hypothetical):**  Many of the functions involve moving the cursor or determining boundaries. I create simple "input/output" scenarios:

    * **`NextCandidate`:**  Imagine a cursor is before a `<span>`. The output would be the position *inside* the `<span>`.
    * **`PreviousGraphemeBoundaryOf`:** Given a text node with "你好世界" and the cursor is after "好", the output would be the position after "你".

7. **Consider Common User/Programming Errors:**

    * **User Error:**  Trying to edit content that is not marked as editable (e.g., a `<div>` without `contenteditable="true"`).
    * **Programming Error:** Incorrectly calculating offsets, leading to cursor placement issues or text manipulation errors. For example, not handling edge cases (beginning or end of a text node).

8. **Trace User Operations (Debugging Clues):** I think about the series of actions a user might take that would lead to this code being executed:

    * Typing text in an editable field.
    * Copying and pasting content.
    * Using the arrow keys to navigate within text.
    * Selecting text with the mouse.
    * Using IME to input characters.

9. **Summarize for Part 1:**  Based on all the above, I synthesize a concise summary highlighting the key responsibilities of the file.

**Self-Correction/Refinement:** Initially, I might focus too much on specific function implementations. However, the request asks for a *functional overview*. So, I adjust my approach to focus on the *purpose* and *relationships* of the utilities rather than the intricate details of every function. I also ensure I explicitly connect the C++ code to the high-level web technologies.
好的，让我们来分析一下 `blink/renderer/core/editing/editing_utilities.cc` 文件的功能。

基于文件头部注释和引入的头文件，我们可以归纳出这个文件的主要功能是：**提供一系列用于处理 Blink 渲染引擎中编辑功能的实用工具函数。** 这些工具函数涵盖了文本的选取、光标的移动、可编辑性的判断、剪贴板操作、以及与 HTML 结构交互等多个方面。

下面我们详细列举一下它的功能，并说明其与 JavaScript, HTML, CSS 的关系，以及可能的逻辑推理、用户错误和调试线索：

**核心功能归纳：**

1. **判断节点的可编辑性 (Editability):**
    *   `IsEditable(const Node& node)`: 判断一个节点是否可编辑。
    *   `IsRichlyEditable(const Node& node)`: 判断一个节点是否支持富文本编辑。
    *   `IsRootEditableElement(const Node& node)`: 判断一个节点是否是根可编辑元素。
    *   `RootEditableElement(const Node& node)`: 获取一个节点的根可编辑元素。
    *   `HighestEditableRoot(const Position& position)`: 获取一个位置所在的最高级可编辑根节点。
    *   这些功能与 HTML 中 `contenteditable` 属性以及 CSS 的 `user-modify` 属性密切相关。

2. **处理文本光标 (Caret) 和选择 (Selection):**
    *   `NextCandidate(const Position& position)` / `PreviousCandidate(const Position& position)`:  在文档中移动光标到下一个/上一个视觉上等价的位置。
    *   `NextVisuallyDistinctCandidate(const Position& position)` / `PreviousVisuallyDistinctCandidate(const Position& position)`: 移动光标到下一个/上一个视觉上不同的位置。
    *   `FirstEditablePositionAfterPositionInRoot(...)` / `LastEditablePositionBeforePositionInRoot(...)`: 在一个根节点内查找给定位置之后/之前的第一个/最后一个可编辑位置。
    *   `PreviousPositionOf(const Position& position, PositionMoveType move_type)` / `NextPositionOf(const Position& position, PositionMoveType move_type)`:  根据不同的移动类型（字符、字形等）移动光标。
    *   这些功能直接影响用户在编辑器中的光标移动和文本选择行为，与 JavaScript 中的 Selection API 紧密相关。

3. **处理文本边界 (Text Boundaries):**
    *   `PreviousGraphemeBoundaryOf(const Node& node, int current)` / `NextGraphemeBoundaryOf(const Node& node, int current)`:  查找给定节点中给定偏移量之前/之后的字形边界。
    *   这些功能对于正确处理多语言文本和复合字符至关重要，也影响着 JavaScript 中使用 Intl API 进行文本处理的结果。

4. **与 HTML 结构交互:**
    *   `IsAtomicNode(const Node* node)`: 判断一个节点是否是原子节点 (例如 `<img>`, `<br>`)。
    *   `IsNodeFullyContained(const EphemeralRange& range, const Node& node)`: 判断一个节点是否完全包含在一个给定的范围内。
    *   这些功能用于理解和操作文档的 DOM 结构，是编辑功能的基础。

5. **剪贴板操作 (Clipboard):**
    *   虽然当前代码片段没有直接展示剪贴板操作的具体函数，但引入了 `clipboard` 相关的头文件，表明这个文件中可能包含或将来会包含处理剪贴板数据的功能。这涉及到用户进行复制、粘贴等操作。

6. **布局更新判断 (Layout Updates):**
    *   `NeedsLayoutTreeUpdate(const Node& node)`: 判断一个节点是否需要布局树更新。
    *   这些函数确保在进行编辑操作后，渲染引擎能够正确地重新布局和渲染页面。

**与 JavaScript, HTML, CSS 的关系举例：**

*   **HTML:**
    *   `IsEditable()` 函数会检查节点的 `contenteditable` 属性，例如：
        ```html
        <div contenteditable="true">This text is editable.</div>
        ```
    *   `RootEditableElement()` 可以用来找到包含用户正在编辑的文本的顶级可编辑元素。
*   **CSS:**
    *   `HasEditableLevel()` 会考虑 CSS 的 `user-modify` 属性，例如：
        ```css
        .readonly {
          user-modify: read-only;
        }
        ```
        如果一个元素的 CSS 样式中设置了 `user-modify: read-only;`，那么 `IsEditable()` 将返回 `false`。
*   **JavaScript:**
    *   当 JavaScript 代码使用 Selection API 获取用户选中的文本范围时，底层的 C++ 代码（包括这个文件中的函数）会被调用来确定选区的起始和结束位置。
    *   当用户在可编辑区域输入文本时，浏览器会触发 JavaScript 事件（如 `input` 或 `keydown`），然后 Blink 引擎会使用这里的工具函数来插入、删除或修改文本。
    *   `NextCandidate()` 和 `PreviousCandidate()` 等函数的功能，与 JavaScript 中通过 `Selection.modify()` 方法移动光标的功能相对应。

**逻辑推理举例：**

假设输入：一个 `Position` 对象，指向一个 `<span>` 元素的起始位置。
函数：`NextCandidate(const Position& position)`

逻辑推理：`NextCandidate` 函数会遍历 DOM 树，找到下一个视觉上等价的可以放置光标的位置。在这种情况下，下一个有效的光标位置通常是 `<span>` 元素内部的第一个文本节点的位置（如果存在）。

假设输出：一个 `Position` 对象，指向 `<span>` 元素内部的第一个文本节点的位置。

**用户或编程常见的使用错误举例：**

*   **用户错误：** 用户可能尝试在未设置为可编辑的区域进行编辑。例如，在一个普通的 `<div>` 元素上点击并尝试输入文本，但该 `<div>` 没有设置 `contenteditable="true"` 属性。在这种情况下，这里的 `IsEditable()` 函数会返回 `false`，阻止编辑操作。
*   **编程错误：** 开发者在 JavaScript 中手动创建或修改 DOM 结构后，没有正确更新编辑相关的状态，可能导致光标位置错误或者编辑行为异常。例如，在可编辑元素中插入新的节点后，如果没有重新计算光标的有效位置，可能会导致光标跳跃到错误的地方。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户在一个网页上与可编辑内容进行交互。**  这可能是：
    *   点击一个设置了 `contenteditable="true"` 的 `<div>` 元素。
    *   在一个 `<textarea>` 或 `<input>` 元素中输入文本。
    *   使用鼠标拖拽来选择文本。
    *   使用键盘上的方向键、Home、End 等键来移动光标。
    *   执行复制 (Ctrl+C) 或粘贴 (Ctrl+V) 操作。
    *   使用输入法 (IME) 输入非英文字符。

2. **浏览器接收到用户的输入事件。** 例如，`mousedown`, `mouseup`, `keydown`, `keypress`, `input`, `compositionstart`, `compositionupdate`, `compositionend` 等。

3. **浏览器事件处理代码会调用 Blink 渲染引擎的相应模块。** 对于编辑相关的操作，通常会涉及到 `blink/renderer/core/editing` 目录下的代码。

4. **在处理这些事件的过程中，会需要执行各种编辑相关的操作，例如判断光标位置、移动光标、插入或删除文本等。**  这时，`editing_utilities.cc` 中提供的各种实用工具函数就会被调用。

5. **例如：**
    *   当用户按下方向键时，`FrameSelection::moveBy()` 或类似的方法会被调用，进而调用 `editing_utilities.cc` 中的 `NextCandidate()` 或 `PreviousCandidate()` 来计算新的光标位置。
    *   当用户输入字符时，`Editor::insertText()` 或类似的方法会被调用，这可能涉及到检查插入位置的可编辑性 (`IsEditable()`) 和计算新的光标位置。
    *   当用户执行粘贴操作时，剪贴板模块会读取剪贴板数据，然后 `editing_utilities.cc` 中的相关函数可能会被用来处理粘贴的内容，例如确定插入位置和进行格式转换。

**第 1 部分功能归纳：**

总而言之，`blink/renderer/core/editing/editing_utilities.cc` 的第 1 部分主要提供了 **关于判断和操作文档中可编辑区域和文本光标的基础工具函数**。这些函数是 Blink 引擎处理用户编辑行为的核心组成部分，与 HTML 的可编辑属性、CSS 的样式控制以及 JavaScript 的编辑 API 紧密相关。它们负责确定哪些内容可以编辑，以及如何在可编辑内容中移动和定位光标，为更高级的编辑功能提供了基础支持。

Prompt: 
```
这是目录为blink/renderer/core/editing/editing_utilities.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
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

#include "third_party/blink/renderer/core/editing/editing_utilities.h"

#include <array>

#include "base/trace_event/trace_event.h"
#include "third_party/blink/renderer/core/clipboard/clipboard_mime_types.h"
#include "third_party/blink/renderer/core/clipboard/data_object.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer.h"
#include "third_party/blink/renderer/core/clipboard/data_transfer_access_policy.h"
#include "third_party/blink/renderer/core/clipboard/system_clipboard.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/shadow_root.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/commands/editing_commands_utilities.h"
#include "third_party/blink/renderer/core/editing/editing_strategy.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/ime/edit_context.h"
#include "third_party/blink/renderer/core/editing/ime/input_method_controller.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/local_caret_rect.h"
#include "third_party/blink/renderer/core/editing/plain_text_range.h"
#include "third_party/blink/renderer/core/editing/position_iterator.h"
#include "third_party/blink/renderer/core/editing/position_with_affinity.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/serializers/html_interchange.h"
#include "third_party/blink/renderer/core/editing/state_machines/backspace_state_machine.h"
#include "third_party/blink/renderer/core/editing/state_machines/backward_grapheme_boundary_state_machine.h"
#include "third_party/blink/renderer/core/editing/state_machines/forward_grapheme_boundary_state_machine.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/html/canvas/html_canvas_element.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html/forms/html_select_element.h"
#include "third_party/blink/renderer/core/html/forms/html_text_area_element.h"
#include "third_party/blink/renderer/core/html/forms/text_control_element.h"
#include "third_party/blink/renderer/core/html/html_body_element.h"
#include "third_party/blink/renderer/core/html/html_br_element.h"
#include "third_party/blink/renderer/core/html/html_div_element.h"
#include "third_party/blink/renderer/core/html/html_dlist_element.h"
#include "third_party/blink/renderer/core/html/html_embed_element.h"
#include "third_party/blink/renderer/core/html/html_image_element.h"
#include "third_party/blink/renderer/core/html/html_li_element.h"
#include "third_party/blink/renderer/core/html/html_object_element.h"
#include "third_party/blink/renderer/core/html/html_olist_element.h"
#include "third_party/blink/renderer/core/html/html_paragraph_element.h"
#include "third_party/blink/renderer/core/html/html_span_element.h"
#include "third_party/blink/renderer/core/html/html_table_cell_element.h"
#include "third_party/blink/renderer/core/html/html_table_element.h"
#include "third_party/blink/renderer/core/html/html_ulist_element.h"
#include "third_party/blink/renderer/core/html/image_document.h"
#include "third_party/blink/renderer/core/html/parser/html_parser_idioms.h"
#include "third_party/blink/renderer/core/html_element_factory.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/input_type_names.h"
#include "third_party/blink/renderer/core/layout/hit_test_result.h"
#include "third_party/blink/renderer/core/layout/layout_image.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/svg/svg_image_element.h"
#include "third_party/blink/renderer/platform/graphics/static_bitmap_image.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/wtf/std_lib_extras.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"
#include "third_party/blink/renderer/platform/wtf/text/unicode.h"

namespace blink {

using mojom::blink::FormControlType;

namespace {

std::ostream& operator<<(std::ostream& os, PositionMoveType type) {
  static const std::array<const char*, 3> kTexts = {
      "CodeUnit", "BackwardDeletion", "GraphemeCluster"};
  DCHECK_LT(static_cast<size_t>(type), kTexts.size())
      << "Unknown PositionMoveType value";
  return os << kTexts[static_cast<size_t>(type)];
}

UChar WhitespaceRebalancingCharToAppend(const String& string,
                                        bool start_is_start_of_paragraph,
                                        bool should_emit_nbsp_before_end,
                                        wtf_size_t index,
                                        UChar previous) {
  DCHECK_LT(index, string.length());

  if (!IsWhitespace(string[index]))
    return string[index];

  if (!index && start_is_start_of_paragraph)
    return kNoBreakSpaceCharacter;
  if (index + 1 == string.length() && should_emit_nbsp_before_end)
    return kNoBreakSpaceCharacter;

  // Generally, alternate between space and no-break space.
  if (previous == ' ')
    return kNoBreakSpaceCharacter;
  if (previous == kNoBreakSpaceCharacter)
    return ' ';

  // Run of two or more spaces starts with a no-break space (crbug.com/453042).
  if (index + 1 < string.length() && IsWhitespace(string[index + 1]))
    return kNoBreakSpaceCharacter;

  return ' ';
}

}  // namespace

bool NeedsLayoutTreeUpdate(const Node& node) {
  const Document& document = node.GetDocument();
  if (document.NeedsLayoutTreeUpdate())
    return true;
  // TODO(yosin): We should make |document::needsLayoutTreeUpdate()| to
  // check |LayoutView::needsLayout()|.
  return document.View() && document.View()->NeedsLayout();
}

template <typename PositionType>
static bool NeedsLayoutTreeUpdateAlgorithm(const PositionType& position) {
  const Node* node = position.AnchorNode();
  if (!node)
    return false;
  return NeedsLayoutTreeUpdate(*node);
}

bool NeedsLayoutTreeUpdate(const Position& position) {
  return NeedsLayoutTreeUpdateAlgorithm<Position>(position);
}

bool NeedsLayoutTreeUpdate(const PositionInFlatTree& position) {
  return NeedsLayoutTreeUpdateAlgorithm<PositionInFlatTree>(position);
}

// Atomic means that the node has no children, or has children which are ignored
// for the purposes of editing.
bool IsAtomicNode(const Node* node) {
  return node && (!node->hasChildren() || EditingIgnoresContent(*node));
}

bool IsAtomicNodeInFlatTree(const Node* node) {
  return node && (!FlatTreeTraversal::HasChildren(*node) ||
                  EditingIgnoresContent(*node));
}

bool IsNodeFullyContained(const EphemeralRange& range, const Node& node) {
  if (range.IsNull())
    return false;

  if (!NodeTraversal::CommonAncestor(*range.StartPosition().AnchorNode(), node))
    return false;

  return range.StartPosition() <= Position::BeforeNode(node) &&
         Position::AfterNode(node) <= range.EndPosition();
}

// TODO(editing-dev): We should implement real version which refers
// "user-select" CSS property.
bool IsUserSelectContain(const Node& node) {
  return IsA<HTMLTextAreaElement>(node) || IsA<HTMLInputElement>(node) ||
         IsA<HTMLSelectElement>(node);
}

enum EditableLevel { kEditable, kRichlyEditable };
static bool HasEditableLevel(const Node& node, EditableLevel editable_level) {
  DCHECK(node.GetDocument().IsActive());
  // TODO(editing-dev): We should have this check:
  // DCHECK_GE(node.document().lifecycle().state(),
  //           DocumentLifecycle::StyleClean);
  if (node.IsPseudoElement())
    return false;

  // Ideally we'd call DCHECK(!needsStyleRecalc()) here, but
  // ContainerNode::setFocus() calls setNeedsStyleRecalc(), so the assertion
  // would fire in the middle of Document::setFocusedNode().

  for (const Node& ancestor : NodeTraversal::InclusiveAncestorsOf(node)) {
    if (!(ancestor.IsHTMLElement() || ancestor.IsDocumentNode()))
      continue;
    // An inert subtree should not contain any content or controls which are
    // critical to understanding or using aspects of the page which are not in
    // the inert state. Content in an inert subtree will not be perceivable by
    // all users, or interactive. See
    // https://html.spec.whatwg.org/multipage/interaction.html#the-inert-attribute.
    // To prevent the invisible inert element being overlooked, the
    // inert attribute of the element is initially assessed. See
    // https://issues.chromium.org/issues/41490809.
    if (RuntimeEnabledFeatures::InertElementNonEditableEnabled()) {
      const Element* element = DynamicTo<Element>(ancestor);
      if (element && element->IsInertRoot()) {
        return false;
      }
    }
    if (const ComputedStyle* style =
            ancestor.GetComputedStyleForElementOrLayoutObject()) {
      switch (style->UsedUserModify()) {
        case EUserModify::kReadOnly:
          return false;
        case EUserModify::kReadWrite:
          return true;
        case EUserModify::kReadWritePlaintextOnly:
          return editable_level != kRichlyEditable;
      }
    }
  }

  return false;
}

bool IsEditable(const Node& node) {
  // TODO(editing-dev): We shouldn't check editable style in inactive documents.
  // We should hoist this check in the call stack, replace it by a DCHECK of
  // active document and ultimately cleanup the code paths with inactive
  // documents.  See crbug.com/667681
  if (!node.GetDocument().IsActive())
    return false;

  return HasEditableLevel(node, kEditable);
}

bool IsRichlyEditable(const Node& node) {
  // TODO(editing-dev): We shouldn't check editable style in inactive documents.
  // We should hoist this check in the call stack, replace it by a DCHECK of
  // active document and ultimately cleanup the code paths with inactive
  // documents.  See crbug.com/667681
  if (!node.GetDocument().IsActive())
    return false;

  return HasEditableLevel(node, kRichlyEditable);
}

bool IsRootEditableElement(const Node& node) {
  return IsEditable(node) && node.IsElementNode() &&
         (!node.parentNode() || !IsEditable(*node.parentNode()) ||
          !node.parentNode()->IsElementNode() ||
          &node == node.GetDocument().body());
}

Element* RootEditableElement(const Node& node) {
  const Element* result = nullptr;
  for (const Node* n = &node; n && IsEditable(*n); n = n->parentNode()) {
    if (auto* element = DynamicTo<Element>(n))
      result = element;
    if (node.GetDocument().body() == n)
      break;
  }
  return const_cast<Element*>(result);
}

ContainerNode* HighestEditableRoot(const Position& position) {
  if (position.IsNull())
    return nullptr;

  ContainerNode* highest_root = RootEditableElementOf(position);
  if (!highest_root)
    return nullptr;

  if (IsA<HTMLBodyElement>(*highest_root))
    return highest_root;

  ContainerNode* node = highest_root->parentNode();
  while (node) {
    if (IsEditable(*node))
      highest_root = node;
    if (IsA<HTMLBodyElement>(*node))
      break;
    node = node->parentNode();
  }

  return highest_root;
}

ContainerNode* HighestEditableRoot(const PositionInFlatTree& position) {
  return HighestEditableRoot(ToPositionInDOMTree(position));
}

bool IsEditablePosition(const Position& position) {
  const Node* node = position.ComputeContainerNode();
  if (!node)
    return false;
  DCHECK(node->GetDocument().IsActive());
  if (node->GetDocument().Lifecycle().GetState() >=
      DocumentLifecycle::kInStyleRecalc) {
    // TODO(yosin): Update the condition and DCHECK here given that
    // https://codereview.chromium.org/2665823002/ avoided this function from
    // being called during InStyleRecalc.
  } else {
    DCHECK(!NeedsLayoutTreeUpdate(position)) << position;
  }

  if (IsDisplayInsideTable(node))
    node = node->parentNode();

  if (node->IsDocumentNode())
    return false;
  return IsEditable(*node);
}

bool IsEditablePosition(const PositionInFlatTree& p) {
  return IsEditablePosition(ToPositionInDOMTree(p));
}

bool IsRichlyEditablePosition(const Position& p) {
  const Node* node = p.AnchorNode();
  if (!node)
    return false;

  if (IsDisplayInsideTable(node))
    node = node->parentNode();

  return IsRichlyEditable(*node);
}

Element* RootEditableElementOf(const Position& p) {
  Node* node = p.ComputeContainerNode();
  if (!node)
    return nullptr;

  if (IsDisplayInsideTable(node))
    node = node->parentNode();

  return RootEditableElement(*node);
}

Element* RootEditableElementOf(const PositionInFlatTree& p) {
  return RootEditableElementOf(ToPositionInDOMTree(p));
}

template <typename Strategy>
PositionTemplate<Strategy> NextCandidateAlgorithm(
    const PositionTemplate<Strategy>& position) {
  TRACE_EVENT0("input", "EditingUtility::nextCandidateAlgorithm");
  PositionIteratorAlgorithm<Strategy> p(position);

  p.Increment();
  while (!p.AtEnd()) {
    PositionTemplate<Strategy> candidate = p.ComputePosition();
    if (IsVisuallyEquivalentCandidate(candidate))
      return candidate;

    p.Increment();
  }

  return PositionTemplate<Strategy>();
}

Position NextCandidate(const Position& position) {
  return NextCandidateAlgorithm<EditingStrategy>(position);
}

PositionInFlatTree NextCandidate(const PositionInFlatTree& position) {
  return NextCandidateAlgorithm<EditingInFlatTreeStrategy>(position);
}

// |nextVisuallyDistinctCandidate| is similar to |nextCandidate| except
// for returning position which |downstream()| not equal to initial position's
// |downstream()|.
template <typename Strategy>
static PositionTemplate<Strategy> NextVisuallyDistinctCandidateAlgorithm(
    const PositionTemplate<Strategy>& position) {
  TRACE_EVENT0("input",
               "EditingUtility::nextVisuallyDistinctCandidateAlgorithm");
  if (position.IsNull())
    return PositionTemplate<Strategy>();

  PositionIteratorAlgorithm<Strategy> p(position);
  const PositionTemplate<Strategy> downstream_start =
      MostForwardCaretPosition(position);
  const PositionTemplate<Strategy> upstream_start =
      MostBackwardCaretPosition(position);

  p.Increment();
  while (!p.AtEnd()) {
    PositionTemplate<Strategy> candidate = p.ComputePosition();
    if (IsVisuallyEquivalentCandidate(candidate) &&
        MostForwardCaretPosition(candidate) != downstream_start &&
        MostBackwardCaretPosition(candidate) != upstream_start)
      return candidate;

    p.Increment();
  }

  return PositionTemplate<Strategy>();
}

Position NextVisuallyDistinctCandidate(const Position& position) {
  return NextVisuallyDistinctCandidateAlgorithm<EditingStrategy>(position);
}

PositionInFlatTree NextVisuallyDistinctCandidate(
    const PositionInFlatTree& position) {
  return NextVisuallyDistinctCandidateAlgorithm<EditingInFlatTreeStrategy>(
      position);
}

template <typename Strategy>
PositionTemplate<Strategy> PreviousCandidateAlgorithm(
    const PositionTemplate<Strategy>& position) {
  TRACE_EVENT0("input", "EditingUtility::previousCandidateAlgorithm");
  PositionIteratorAlgorithm<Strategy> p(position);

  p.Decrement();
  while (!p.AtStart()) {
    PositionTemplate<Strategy> candidate = p.ComputePosition();
    if (IsVisuallyEquivalentCandidate(candidate))
      return candidate;

    p.Decrement();
  }

  return PositionTemplate<Strategy>();
}

Position PreviousCandidate(const Position& position) {
  return PreviousCandidateAlgorithm<EditingStrategy>(position);
}

PositionInFlatTree PreviousCandidate(const PositionInFlatTree& position) {
  return PreviousCandidateAlgorithm<EditingInFlatTreeStrategy>(position);
}

// |previousVisuallyDistinctCandidate| is similar to |previousCandidate| except
// for returning position which |downstream()| not equal to initial position's
// |downstream()|.
template <typename Strategy>
PositionTemplate<Strategy> PreviousVisuallyDistinctCandidateAlgorithm(
    const PositionTemplate<Strategy>& position) {
  TRACE_EVENT0("input",
               "EditingUtility::previousVisuallyDistinctCandidateAlgorithm");
  if (position.IsNull())
    return PositionTemplate<Strategy>();

  PositionIteratorAlgorithm<Strategy> p(position);
  PositionTemplate<Strategy> downstream_start =
      MostForwardCaretPosition(position);
  const PositionTemplate<Strategy> upstream_start =
      MostBackwardCaretPosition(position);

  p.Decrement();
  while (!p.AtStart()) {
    PositionTemplate<Strategy> candidate = p.ComputePosition();
    if (IsVisuallyEquivalentCandidate(candidate) &&
        MostForwardCaretPosition(candidate) != downstream_start &&
        MostBackwardCaretPosition(candidate) != upstream_start)
      return candidate;

    p.Decrement();
  }

  return PositionTemplate<Strategy>();
}

Position PreviousVisuallyDistinctCandidate(const Position& position) {
  return PreviousVisuallyDistinctCandidateAlgorithm<EditingStrategy>(position);
}

PositionInFlatTree PreviousVisuallyDistinctCandidate(
    const PositionInFlatTree& position) {
  return PreviousVisuallyDistinctCandidateAlgorithm<EditingInFlatTreeStrategy>(
      position);
}

template <typename Strategy>
PositionTemplate<Strategy> FirstEditablePositionAfterPositionInRootAlgorithm(
    const PositionTemplate<Strategy>& position,
    const Node& highest_root) {
  DCHECK(!NeedsLayoutTreeUpdate(highest_root))
      << position << ' ' << highest_root;
  // position falls before highestRoot.
  if (position.CompareTo(PositionTemplate<Strategy>::FirstPositionInNode(
          highest_root)) == -1 &&
      IsEditable(highest_root))
    return PositionTemplate<Strategy>::FirstPositionInNode(highest_root);

  PositionTemplate<Strategy> editable_position = position;

  if (position.AnchorNode()->GetTreeScope() != highest_root.GetTreeScope()) {
    Node* shadow_ancestor = highest_root.GetTreeScope().AncestorInThisScope(
        editable_position.AnchorNode());
    if (!shadow_ancestor)
      return PositionTemplate<Strategy>();

    editable_position = PositionTemplate<Strategy>::AfterNode(*shadow_ancestor);
  }

  Node* non_editable_node = nullptr;
  while (editable_position.AnchorNode() &&
         !IsEditablePosition(editable_position) &&
         editable_position.AnchorNode()->IsDescendantOf(&highest_root)) {
    non_editable_node = editable_position.AnchorNode();
    editable_position = IsAtomicNode(editable_position.AnchorNode())
                            ? PositionTemplate<Strategy>::InParentAfterNode(
                                  *editable_position.AnchorNode())
                            : NextVisuallyDistinctCandidate(editable_position);
  }

  if (editable_position.AnchorNode() &&
      editable_position.AnchorNode() != &highest_root &&
      !editable_position.AnchorNode()->IsDescendantOf(&highest_root))
    return PositionTemplate<Strategy>();

  // If `non_editable_node` is the last child of
  // `editable_position.AnchorNode()`, obtain the next sibling position.
  // - If we do not obtain the next sibling position, we will be unable to
  //   access the next paragraph within the `InsertListCommand::DoApply` while
  //   loop. See http://crbug.com/571420 for more details.
  // - If `non_editable_node` is not the last child, we will bypass the next
  //   editable sibling position. See http://crbug.com/1334557 for more details.
  bool need_obtain_next =
      non_editable_node && editable_position.AnchorNode() &&
      non_editable_node == editable_position.AnchorNode()->lastChild();
  if (need_obtain_next) {
    // Make sure not to move out of |highest_root|
    const PositionTemplate<Strategy> boundary =
        PositionTemplate<Strategy>::LastPositionInNode(highest_root);
    // `NextVisuallyDistinctCandidate` is similar to `NextCandidate`, but
    // it skips the next visually equivalent of `editable_position`.
    // `editable_position` is already "visually distinct" relative to
    // `position`, so use `NextCandidate` here.
    // See http://crbug.com/1406207 for more details.
    const PositionTemplate<Strategy> next_candidate =
        NextCandidate(editable_position);
    editable_position = next_candidate.IsNotNull()
                            ? std::min(boundary, next_candidate)
                            : boundary;
  }
  return editable_position;
}

Position FirstEditablePositionAfterPositionInRoot(const Position& position,
                                                  const Node& highest_root) {
  return FirstEditablePositionAfterPositionInRootAlgorithm<EditingStrategy>(
      position, highest_root);
}

PositionInFlatTree FirstEditablePositionAfterPositionInRoot(
    const PositionInFlatTree& position,
    const Node& highest_root) {
  return FirstEditablePositionAfterPositionInRootAlgorithm<
      EditingInFlatTreeStrategy>(position, highest_root);
}

template <typename Strategy>
PositionTemplate<Strategy> LastEditablePositionBeforePositionInRootAlgorithm(
    const PositionTemplate<Strategy>& position,
    const Node& highest_root) {
  DCHECK(!NeedsLayoutTreeUpdate(highest_root))
      << position << ' ' << highest_root;
  // When position falls after highestRoot, the result is easy to compute.
  if (position.CompareTo(
          PositionTemplate<Strategy>::LastPositionInNode(highest_root)) == 1)
    return PositionTemplate<Strategy>::LastPositionInNode(highest_root);

  PositionTemplate<Strategy> editable_position = position;

  if (position.AnchorNode()->GetTreeScope() != highest_root.GetTreeScope()) {
    Node* shadow_ancestor = highest_root.GetTreeScope().AncestorInThisScope(
        editable_position.AnchorNode());
    if (!shadow_ancestor)
      return PositionTemplate<Strategy>();

    editable_position = PositionTemplate<Strategy>::FirstPositionInOrBeforeNode(
        *shadow_ancestor);
  }

  while (editable_position.AnchorNode() &&
         !IsEditablePosition(editable_position) &&
         editable_position.AnchorNode()->IsDescendantOf(&highest_root))
    editable_position =
        IsAtomicNode(editable_position.AnchorNode())
            ? PositionTemplate<Strategy>::InParentBeforeNode(
                  *editable_position.AnchorNode())
            : PreviousVisuallyDistinctCandidate(editable_position);

  if (editable_position.AnchorNode() &&
      editable_position.AnchorNode() != &highest_root &&
      !editable_position.AnchorNode()->IsDescendantOf(&highest_root))
    return PositionTemplate<Strategy>();
  return editable_position;
}

Position LastEditablePositionBeforePositionInRoot(const Position& position,
                                                  const Node& highest_root) {
  return LastEditablePositionBeforePositionInRootAlgorithm<EditingStrategy>(
      position, highest_root);
}

PositionInFlatTree LastEditablePositionBeforePositionInRoot(
    const PositionInFlatTree& position,
    const Node& highest_root) {
  return LastEditablePositionBeforePositionInRootAlgorithm<
      EditingInFlatTreeStrategy>(position, highest_root);
}

template <typename StateMachine>
int FindNextBoundaryOffset(const String& str, int current) {
  StateMachine machine;
  TextSegmentationMachineState state = TextSegmentationMachineState::kInvalid;

  for (int i = current - 1; i >= 0; --i) {
    state = machine.FeedPrecedingCodeUnit(str[i]);
    if (state != TextSegmentationMachineState::kNeedMoreCodeUnit)
      break;
  }
  if (current == 0 || state == TextSegmentationMachineState::kNeedMoreCodeUnit)
    state = machine.TellEndOfPrecedingText();
  if (state == TextSegmentationMachineState::kFinished)
    return current + machine.FinalizeAndGetBoundaryOffset();
  const int length = str.length();
  DCHECK_EQ(TextSegmentationMachineState::kNeedFollowingCodeUnit, state);
  for (int i = current; i < length; ++i) {
    state = machine.FeedFollowingCodeUnit(str[i]);
    if (state != TextSegmentationMachineState::kNeedMoreCodeUnit)
      break;
  }
  return current + machine.FinalizeAndGetBoundaryOffset();
}

// Explicit instantiation to avoid link error for the usage in EditContext.
template int FindNextBoundaryOffset<BackwardGraphemeBoundaryStateMachine>(
    const String& str,
    int current);
template int FindNextBoundaryOffset<ForwardGraphemeBoundaryStateMachine>(
    const String& str,
    int current);

int PreviousGraphemeBoundaryOf(const Node& node, int current) {
  // TODO(yosin): Need to support grapheme crossing |Node| boundary.
  DCHECK_GE(current, 0);
  auto* text_node = DynamicTo<Text>(node);
  if (current <= 1 || !text_node)
    return current - 1;
  const String& text = text_node->data();
  // TODO(yosin): Replace with DCHECK for out-of-range request.
  if (static_cast<unsigned>(current) > text.length())
    return current - 1;
  return FindNextBoundaryOffset<BackwardGraphemeBoundaryStateMachine>(text,
                                                                      current);
}

static int PreviousBackwardDeletionOffsetOf(const Node& node, int current) {
  DCHECK_GE(current, 0);
  if (current <= 1)
    return 0;
  auto* text_node = DynamicTo<Text>(node);
  if (!text_node)
    return current - 1;

  const String& text = text_node->data();
  DCHECK_LT(static_cast<unsigned>(current - 1), text.length());
  return FindNextBoundaryOffset<BackspaceStateMachine>(text, current);
}

int NextGraphemeBoundaryOf(const Node& node, int current) {
  // TODO(yosin): Need to support grapheme crossing |Node| boundary.
  auto* text_node = DynamicTo<Text>(node);
  if (!text_node)
    return current + 1;
  const String& text = text_node->data();
  const int length = text.length();
  DCHECK_LE(current, length);
  if (current >= length - 1)
    return current + 1;
  return FindNextBoundaryOffset<ForwardGraphemeBoundaryStateMachine>(text,
                                                                     current);
}

template <typename Strategy>
PositionTemplate<Strategy> PreviousPositionOfAlgorithm(
    const PositionTemplate<Strategy>& position,
    PositionMoveType move_type) {
  Node* const node = position.AnchorNode();
  if (!node)
    return position;

  const int offset = position.ComputeEditingOffset();

  if (offset > 0) {
    if (EditingIgnoresContent(*node))
      return PositionTemplate<Strategy>::BeforeNode(*node);
    if (Node* child = Strategy::ChildAt(*node, offset - 1)) {
      return PositionTemplate<Strategy>::LastPositionInOrAfterNode(*child);
    }

    // There are two reasons child might be 0:
    //   1) The node is node like a text node that is not an element, and
    //      therefore has no children. Going backward one character at a
    //      time is correct.
    //   2) The old offset was a bogus offset like (<br>, 1), and there is
    //      no child. Going from 1 to 0 is correct.
    switch (move_type) {
      case PositionMoveType::kCodeUnit:
        return PositionTemplate<Strategy>(node, offset - 1);
      case PositionMoveType::kBackwardDeletion:
        return PositionTemplate<Strategy>(
            node, PreviousBackwardDeletionOffsetOf(*node, offset));
      case PositionMoveType::kGraphemeCluster:
        return PositionTemplate<Strategy>(
            node, PreviousGraphemeBoundaryOf(*node, offset));
      default:
        NOTREACHED() << "Unhandled moveType: " << move_type;
    }
  }

  if (ContainerNode* parent = Strategy::Parent(*node)) {
    if (EditingIgnoresContent(*parent))
      return PositionTemplate<Strategy>::BeforeNode(*parent);
    // TODO(yosin) We should use |Strategy::index(Node&)| instead of
    // |Node::nodeIndex()|.
    return PositionTemplate<Strategy>(parent, node->NodeIndex());
  }
  return position;
}

Position PreviousPositionOf(const Position& position,
                            PositionMoveType move_type) {
  return PreviousPositionOfAlgorithm<EditingStrategy>(position, move_type);
}

PositionInFlatTree PreviousPositionOf(const PositionInFlatTree& position,
                                      PositionMoveType move_type) {
  return PreviousPositionOfAlgorithm<EditingInFlatTreeStrategy>(position,
                                                                move_type);
}

template <typename Strategy>
PositionTemplate<Strategy> NextPositionOfAlgorithm(
    const PositionTemplate<Strategy>& position,
    PositionMoveType move_type) {
  // TODO(yosin): We should have printer for PositionMoveType.
  DCHECK(move_type != PositionMoveType::kBackwardDeletion);

  Node* node = position.AnchorNode();
  if (!node)
    return position;

  const int offset = position.ComputeEditingOffset();

  if (Node* child = Strategy::ChildAt(*node, offset)) {
    return PositionTemplate<Strategy>::FirstPositionInOrBeforeNode(*child);
  }

  // TODO(yosin) We should use |Strategy::lastOffsetForEditing()| instead of
  // DOM tree version.
  if (!Strategy::HasChildren(*node) &&
      offset < EditingStrategy::LastOffsetForEditing(node)) {
    // There are two reasons child might be 0:
    //   1) The node is node like a text node that is not an element, and
    //      therefore has no children. Going forward one character at a time
    //      is correct.
    //   2) The new offset is a bogus offset like (<br>, 1), and there is no
    //      child. Going from 0 to 1 is correct.
    switch (move_type) {
      case PositionMoveType::kCodeUnit:
        return PositionTemplate<Strategy>::EditingPositionOf(node, offset + 1);
      case PositionMoveType::kBackwardDeletion:
        NOTREACHED() << "BackwardDeletion is only available for prevPositionOf "
                     << "functions.";
      case PositionMoveType::kGraphemeCluster:
        return PositionTemplate<Strategy>::EditingPositionOf(
            node, NextGraphemeBoundaryOf(*node, offset));
      default:
        NOTREACHED() << "Unhandled moveType: " << move_type;
    }
  }

  if (ContainerNode* parent = Strategy::Parent(*node))
    return PositionTemplate<Strategy>::EditingPositionOf(
        parent, Strategy::Index(*node) + 1);
  return position;
}

Position NextPositionOf(const Position& position, PositionMoveType move_type) {
  return NextPositionOfAlgorithm<EditingStrategy>(position, move_type);
}

PositionInFlatTree NextPositionOf(const PositionInFlatTree& position,
                                  PositionMoveType move_type) {
  return NextPositionOfAlgorithm<EditingInFlatTreeStrategy>(position,
                                                            move_type);
}

bool IsEnclosingBlock(const Node* node) {
  return node && node->GetLayoutObject() &&
         !node->GetLayoutObject()->IsInline();
}

// TODO(yosin) Deploy this in all of the places where |enclosingBlockFlow()| and
// |enclosingBlockFlowOrTableElement()| are used.
// TODO(yosin) Callers of |Node| version of
"""


```