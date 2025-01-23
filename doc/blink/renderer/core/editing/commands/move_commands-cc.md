Response:
Let's break down the thought process for analyzing the given C++ code.

**1. Initial Understanding - What is the file about?**

The filename `move_commands.cc` and the namespace `blink` strongly suggest this file deals with commands related to moving within a web page in the Chromium browser (specifically, within the Blink rendering engine). The copyright notices further confirm it's part of a long-standing project.

**2. High-Level Functionality - What does it do?**

Scanning the code, we see a lot of functions with names like `ExecuteMoveBackward`, `ExecuteMoveForwardAndModifySelection`, etc. These clearly correspond to user actions that move the cursor or selection. The presence of `SelectionModifyAlteration` and `TextGranularity` further reinforces this.

**3. Core Concepts - What are the key abstractions?**

Several important concepts emerge:

* **`LocalFrame`:** Represents a frame within a web page. Operations occur within a specific frame.
* **`Selection`:**  Represents the current text selection or cursor position.
* **`SelectionModifier`:** A helper class for manipulating the selection.
* **`TextGranularity`:** Defines the unit of movement (character, word, line, etc.).
* **`SelectionModifyDirection`:** Specifies the direction of movement (forward, backward, up, down, etc.).
* **`SelectionModifyAlteration`:** Indicates whether the movement is just moving the cursor or extending the selection.
* **Caret Browsing:** A mode where the user can navigate the page using the keyboard.

**4. Mapping to User Actions - How does this connect to the user?**

The function names directly map to common keyboard shortcuts or browser menu actions. For example:

* `ExecuteMoveBackward` -> Left arrow key
* `ExecuteMoveForwardAndModifySelection` -> Shift + Right arrow key
* `ExecuteMovePageDown` -> Page Down key

**5. Relationship to Web Technologies (JavaScript, HTML, CSS) - Where do they intersect?**

* **JavaScript:** JavaScript can programmatically manipulate the selection. This C++ code provides the underlying mechanisms for those manipulations. Events triggered by user actions or JavaScript code will eventually call these functions.
* **HTML:** The structure of the HTML document is what the navigation is based on. Moving by paragraph or line relies on the HTML structure. Focusable elements are HTML elements.
* **CSS:** CSS affects the layout and rendering of text. While this code doesn't directly manipulate CSS, it needs to be aware of how elements are laid out (e.g., for line breaks) to perform accurate movement. The `VerticalScrollDistance` function explicitly checks CSS `overflow-y` properties.

**6. Logical Reasoning and Assumptions - What assumptions are made and what are the potential outcomes?**

* **Assumption:** The code assumes a valid `LocalFrame` and a valid selection object.
* **Assumption:** Caret browsing is a specific browser feature.
* **Output:** The primary output is the modification of the `Selection` object within the `LocalFrame`. This changes the cursor position or the selected text. The focus might also change.

**7. Common Errors - What can go wrong?**

* **No focused element:**  Some functions handle the case where there's no focused element, but others might rely on it.
* **Invalid selection:** If the selection is in an invalid state, the movement might not work as expected.
* **Caret browsing inconsistencies:**  The logic for caret browsing introduces specific edge cases.

**8. Debugging Clues - How can this code be reached?**

The key is to trace user interactions or JavaScript calls that trigger selection changes. Keyboard events are the most common way to reach this code.

**Self-Correction/Refinement during the thought process:**

* Initially, I might just focus on individual functions. But then, realizing the common patterns and the use of helper classes like `SelectionModifier`, I would generalize my understanding to the overall purpose of the file.
* I might initially miss the connection to caret browsing. Looking closer at the `UpdateFocusForCaretBrowsing` and `UpdateSelectionForCaretBrowsing` functions would highlight this specific functionality.
* I would initially focus on the "move" aspect. Then, seeing the "...AndModifySelection" functions, I'd realize the dual purpose of moving and extending the selection.

By following these steps, which involve a mix of code reading, pattern recognition, understanding the underlying concepts, and considering the context within a browser engine,  we can arrive at a comprehensive explanation of the `move_commands.cc` file.
这个文件 `blink/renderer/core/editing/commands/move_commands.cc` 是 Chromium Blink 引擎的一部分，**主要负责实现各种光标和文本选择的移动命令**。 这些命令响应用户的键盘输入（例如方向键、Page Up/Down、Home/End 等）或浏览器内部的请求，来改变当前网页中光标的位置或选中的文本范围。

以下是它的具体功能：

**1. 实现各种光标移动命令：**

   - **按字符移动:**  向左 (`ExecuteMoveBackward`, `ExecuteMoveLeft`)，向右 (`ExecuteMoveForward`, `ExecuteMoveRight`)。
   - **按单词移动:** 向左 (`ExecuteMoveWordBackward`, `ExecuteMoveWordLeft`)，向右 (`ExecuteMoveWordForward`, `ExecuteMoveWordRight`)。
   - **按行移动:** 向上 (`ExecuteMoveUp`)，向下 (`ExecuteMoveDown`)，行首 (`ExecuteMoveToBeginningOfLine`, `ExecuteMoveToLeftEndOfLine`)，行尾 (`ExecuteMoveToEndOfLine`, `ExecuteMoveToRightEndOfLine`)。
   - **按段落移动:** 向上 (`ExecuteMoveParagraphBackward`)，向下 (`ExecuteMoveParagraphForward`)，段首 (`ExecuteMoveToBeginningOfParagraph`)，段尾 (`ExecuteMoveToEndOfParagraph`)。
   - **按句子移动:** 向前到句首 (`ExecuteMoveToBeginningOfSentence`)，向后到句尾 (`ExecuteMoveToEndOfSentence`)。
   - **按页面移动:** 向上翻页 (`ExecuteMovePageUp`)，向下翻页 (`ExecuteMovePageDown`)。
   - **按文档移动:** 到文档开头 (`ExecuteMoveToBeginningOfDocument`)，到文档结尾 (`ExecuteMoveToEndOfDocument`)。

**2. 实现带选择的移动命令：**

   - 对于上述每一种移动命令，都有一个对应的 "AndModifySelection" 版本 (`ExecuteMoveBackwardAndModifySelection` 等)。这些命令在移动光标的同时，会扩展或缩小当前的文本选择范围。

**3. 处理 Caret Browsing 模式下的移动：**

   - `UpdateFocusForCaretBrowsing`: 当开启 Caret Browsing 模式时，移动光标可能会需要更新焦点元素，尤其是在光标移动到一个只读的元素上时，需要将焦点移动到其父级可聚焦元素。
   - `UpdateSelectionForCaretBrowsing`:  在 Caret Browsing 模式下，如果当前没有选中文本且页面有可聚焦元素，则在移动时需要先创建一个初始的空选择。

**4. 计算垂直滚动距离：**

   - `VerticalScrollDistance`: 用于计算 `ExecuteMovePageUp` 和 `ExecuteMovePageDown` 命令需要滚动的距离。它会考虑当前焦点元素的样式（`overflow-y`）和视口的大小，以确定一个合适的滚动步长。

**5. 核心移动逻辑：**

   - `MoveSelection`:  执行基本的移动光标操作，调用 `frame.Selection().Modify` 方法。
   - `ModifySelectionWithPageGranularity`: 处理翻页操作时的选择修改。

**与 JavaScript, HTML, CSS 的关系：**

这个文件是 Blink 渲染引擎的 C++ 代码，它位于浏览器底层，直接操作 DOM 树和布局信息。它与前端技术的关系体现在：

* **JavaScript:** JavaScript 可以通过 `document.execCommand()` 方法触发这些移动命令。例如，`document.execCommand('moveRight')` 会最终调用 `ExecuteMoveRight` 函数。
    * **举例：** 一个富文本编辑器可能会使用 JavaScript 监听键盘事件，并在用户按下右方向键时调用 `document.execCommand('moveRight')` 来移动光标。
    * **假设输入：** 用户在一个文本输入框中按下右方向键。
    * **输出：** 光标向右移动一个字符。

* **HTML:** HTML 定义了网页的结构，移动命令会根据 HTML 元素的边界（例如段落标签 `<p>`，换行符 `<br>`）来确定移动的距离和目标位置。
    * **举例：** `ExecuteMoveParagraphForward` 命令会查找下一个段落的起始位置，这依赖于 HTML 中 `<p>` 标签的结构。
    * **假设输入：** 光标位于一个段落的中间，用户触发 "移动到下一个段落" 的操作。
    * **输出：** 光标移动到下一个 `<p>` 标签开始的位置。

* **CSS:** CSS 的 `overflow` 属性会影响 `VerticalScrollDistance` 函数的计算，从而影响翻页命令的滚动距离。CSS 还可以影响元素的 `user-modify` 属性，这会影响 Caret Browsing 模式下的焦点处理 (`UpdateFocusForCaretBrowsing`)。
    * **举例：** 如果一个 `<div>` 元素设置了 `overflow-y: scroll;`，那么在计算翻页距离时，会考虑这个 `div` 的高度。
    * **假设输入：** 焦点在一个设置了 `overflow-y: scroll` 的 `div` 元素内部，用户按下 Page Down 键。
    * **输出：**  `VerticalScrollDistance` 计算出该 `div` 的滚动步长，并滚动相应的距离。

**逻辑推理的举例：**

* **假设输入：** 用户开启了 Caret Browsing 模式，并且当前光标位于一个 `<span>` 元素内部，这个 `<span>` 元素是只读的（可能是通过 CSS `user-modify: read-only;` 设置的）。然后用户按下方向键移动光标。
* **逻辑推理：** `UpdateFocusForCaretBrowsing` 函数会被调用。它会检查当前光标所在的节点是否为只读。如果是，它会向上遍历 DOM 树，找到第一个可聚焦的父元素，并将焦点设置到该元素上。
* **输出：** 焦点会移动到 `<span>` 元素的父级可聚焦元素上。

**用户或编程常见的使用错误：**

* **在不可编辑区域尝试移动光标：**  虽然移动命令可以执行，但在只读文本或非文本元素上移动光标可能不会产生明显的效果。例如，在一个 `<img>` 标签上使用方向键。
* **Caret Browsing 模式下的误解：** 用户可能不理解 Caret Browsing 模式的工作原理，例如为什么在某些情况下焦点会意外地跳转到其他元素。
* **JavaScript 中错误的 `execCommand` 参数：** 开发者可能传递了错误的命令名称给 `document.execCommand()`，导致预期的移动操作没有发生。

**用户操作如何一步步到达这里 (调试线索)：**

1. **用户交互：** 用户在网页上进行操作，例如按下键盘上的方向键、Page Up/Down、Home/End 等键，或者通过鼠标点击来改变焦点。
2. **浏览器事件捕获：** 浏览器捕获到这些用户输入事件（例如 `keydown`, `keypress`, `click`）。
3. **事件处理：** 浏览器内部的事件处理机制会将这些事件路由到相应的处理逻辑。
4. **命令触发：** 对于键盘事件，浏览器可能会识别出这些事件对应于特定的编辑命令（例如，按下右方向键通常会映射到 "moveRight" 命令）。
5. **`document.execCommand` (JavaScript):** 如果网页的 JavaScript 代码使用了 `document.execCommand()` 方法来触发移动命令，那么 JavaScript 引擎会调用相应的 Blink 内部函数。
6. **Blink 内部路由：** Blink 引擎接收到命令请求，并将其路由到 `core/editing/editor.cc` 中的 `Editor::ExecuteCommand` 或类似的方法。
7. **命令查找和执行：** `Editor::ExecuteCommand` 方法会根据命令名称查找对应的处理函数，最终会找到 `move_commands.cc` 中相应的 `Execute...` 函数。
8. **执行移动逻辑：** `Execute...` 函数会调用 `MoveSelection` 或 `ModifySelectionWithPageGranularity` 等函数来实际修改 `FrameSelection` 对象，从而改变光标位置或文本选择。
9. **UI 更新：**  `FrameSelection` 的改变会导致渲染引擎重新绘制页面，以反映光标或选区的变化。

**调试线索：**

* **断点：** 在 `move_commands.cc` 中相关的 `Execute...` 函数入口处设置断点，可以观察用户操作是否触发了这些函数。
* **事件监听：** 在 JavaScript 中监听 `keydown` 事件，可以查看按下的键码，判断是否对应于移动命令。
* **`document.queryCommandState` 和 `document.queryCommandEnabled`：** 可以使用这两个 JavaScript 方法来检查某个编辑命令的当前状态，帮助理解为什么某些移动操作可能不起作用。
* **Caret Browsing 状态：** 检查浏览器的 Caret Browsing 设置，确认是否开启了该模式，以及这是否影响了移动行为。
* **DOM 结构和 CSS 样式：** 检查相关的 HTML 元素结构和 CSS 样式，特别是 `overflow` 和 `user-modify` 属性，以理解它们如何影响移动行为。

### 提示词
```
这是目录为blink/renderer/core/editing/commands/move_commands.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007, 2008 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
 * Copyright (C) 2009 Igalia S.L.
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

#include "third_party/blink/renderer/core/editing/commands/move_commands.h"

#include "third_party/blink/public/mojom/input/focus_type.mojom-blink.h"
#include "third_party/blink/renderer/core/dom/focus_params.h"
#include "third_party/blink/renderer/core/dom/node_computed_style.h"
#include "third_party/blink/renderer/core/editing/editing_behavior.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/layout/layout_box.h"
#include "third_party/blink/renderer/core/paint/paint_layer_scrollable_area.h"

namespace blink {

unsigned MoveCommands::VerticalScrollDistance(LocalFrame& frame) {
  const Element* focused_element = frame.GetDocument()->FocusedElement();
  if (!focused_element) {
    if (frame.IsCaretBrowsingEnabled()) {
      focused_element = frame.GetDocument()->ActiveElement();
    }

    if (!focused_element)
      return 0;
  }
  LayoutObject* const layout_object = focused_element->GetLayoutObject();
  if (!layout_object || !layout_object->IsBox())
    return 0;
  auto& layout_box = To<LayoutBox>(*layout_object);
  const ComputedStyle* const style = layout_box.Style();
  if (!style)
    return 0;
  if (!(style->OverflowY() == EOverflow::kScroll ||
        style->OverflowY() == EOverflow::kAuto ||
        IsEditable(*focused_element) || frame.IsCaretBrowsingEnabled()))
    return 0;
  const ScrollableArea& scrollable_area = *frame.View()->LayoutViewport();
  const int height = std::min<int>(layout_box.ClientHeight().ToInt(),
                                   scrollable_area.VisibleHeight());
  return static_cast<unsigned>(
      max(max<int>(height * ScrollableArea::MinFractionToStepWhenPaging(),
                   height - scrollable_area.MaxOverlapBetweenPages()),
          1));
}

bool MoveCommands::ModifySelectionWithPageGranularity(
    LocalFrame& frame,
    SelectionModifyAlteration alter,
    unsigned vertical_distance,
    SelectionModifyVerticalDirection direction) {
  if (alter == SelectionModifyAlteration::kMove)
    UpdateSelectionForCaretBrowsing(frame);

  SelectionModifier selection_modifier(
      frame, frame.Selection().GetSelectionInDOMTree());
  selection_modifier.SetSelectionIsDirectional(
      frame.Selection().IsDirectional());
  if (!selection_modifier.ModifyWithPageGranularity(alter, vertical_distance,
                                                    direction)) {
    return false;
  }

  frame.Selection().SetSelection(
      selection_modifier.Selection().AsSelection(),
      SetSelectionOptions::Builder()
          .SetSetSelectionBy(SetSelectionBy::kUser)
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetCursorAlignOnScroll(alter == SelectionModifyAlteration::kMove
                                      ? CursorAlignOnScroll::kAlways
                                      : CursorAlignOnScroll::kIfNeeded)
          .SetIsDirectional(alter == SelectionModifyAlteration::kExtend ||
                            frame.GetEditor()
                                .Behavior()
                                .ShouldConsiderSelectionAsDirectional())
          .Build());

  UpdateFocusForCaretBrowsing(frame);

  return true;
}

bool MoveCommands::MoveSelection(LocalFrame& frame,
                                 SelectionModifyDirection direction,
                                 TextGranularity granularity) {
  UpdateSelectionForCaretBrowsing(frame);
  const bool modified =
      frame.Selection().Modify(SelectionModifyAlteration::kMove, direction,
                               granularity, SetSelectionBy::kUser);
  if (modified)
    UpdateFocusForCaretBrowsing(frame);

  return modified;
}

void MoveCommands::UpdateFocusForCaretBrowsing(LocalFrame& frame) {
  if (!frame.IsCaretBrowsingEnabled())
    return;

  SelectionInDOMTree selection = frame.Selection().GetSelectionInDOMTree();
  if (!selection.IsCaret())
    return;

  Node* node = selection.Focus().ComputeContainerNode();
  if (!node)
    return;

  const ComputedStyle* style = node->GetComputedStyleForElementOrLayoutObject();
  if (!style || style->UsedUserModify() != EUserModify::kReadOnly) {
    return;
  }

  Element* new_focused_element = nullptr;

  while (node) {
    if (node->IsElementNode() && To<Element>(node)->IsFocusable()) {
      new_focused_element = To<Element>(node);
      break;
    }
    node = node->ParentOrShadowHostNode();
  }

  if (new_focused_element == frame.GetDocument()->FocusedElement())
    return;

  frame.GetDocument()->SetFocusedElement(
      new_focused_element,
      FocusParams(SelectionBehaviorOnFocus::kNone,
                  mojom::blink::FocusType::kNone, nullptr));
}

void MoveCommands::UpdateSelectionForCaretBrowsing(LocalFrame& frame) {
  if (!frame.IsCaretBrowsingEnabled())
    return;

  if (frame.Selection().SelectionHasFocus())
    return;

  Element* activeElement = frame.GetDocument()->ActiveElement();
  if (!activeElement)
    return;

  frame.Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position::FirstPositionInOrBeforeNode(*activeElement))
          .Build(),
      SetSelectionOptions::Builder()
          .SetShouldCloseTyping(true)
          .SetShouldClearTypingStyle(true)
          .SetDoNotSetFocus(true)
          .Build());
}

bool MoveCommands::ExecuteMoveBackward(LocalFrame& frame,
                                       Event*,
                                       EditorCommandSource,
                                       const String&) {
  MoveSelection(frame, SelectionModifyDirection::kBackward,
                TextGranularity::kCharacter);
  return true;
}

bool MoveCommands::ExecuteMoveBackwardAndModifySelection(LocalFrame& frame,
                                                         Event*,
                                                         EditorCommandSource,
                                                         const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kBackward,
                           TextGranularity::kCharacter, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveDown(LocalFrame& frame,
                                   Event*,
                                   EditorCommandSource,
                                   const String&) {
  return MoveSelection(frame, SelectionModifyDirection::kForward,
                       TextGranularity::kLine);
}

bool MoveCommands::ExecuteMoveDownAndModifySelection(LocalFrame& frame,
                                                     Event*,
                                                     EditorCommandSource,
                                                     const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kForward,
                           TextGranularity::kLine, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveForward(LocalFrame& frame,
                                      Event*,
                                      EditorCommandSource,
                                      const String&) {
  MoveSelection(frame, SelectionModifyDirection::kForward,
                TextGranularity::kCharacter);
  return true;
}

bool MoveCommands::ExecuteMoveForwardAndModifySelection(LocalFrame& frame,
                                                        Event*,
                                                        EditorCommandSource,
                                                        const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kForward,
                           TextGranularity::kCharacter, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveLeft(LocalFrame& frame,
                                   Event*,
                                   EditorCommandSource,
                                   const String&) {
  return MoveSelection(frame, SelectionModifyDirection::kLeft,
                       TextGranularity::kCharacter);
}

bool MoveCommands::ExecuteMoveLeftAndModifySelection(LocalFrame& frame,
                                                     Event*,
                                                     EditorCommandSource,
                                                     const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kLeft,
                           TextGranularity::kCharacter, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMovePageDown(LocalFrame& frame,
                                       Event*,
                                       EditorCommandSource,
                                       const String&) {
  const unsigned distance = VerticalScrollDistance(frame);
  if (!distance)
    return false;
  return ModifySelectionWithPageGranularity(
      frame, SelectionModifyAlteration::kMove, distance,
      SelectionModifyVerticalDirection::kDown);
}

bool MoveCommands::ExecuteMovePageDownAndModifySelection(LocalFrame& frame,
                                                         Event*,
                                                         EditorCommandSource,
                                                         const String&) {
  const unsigned distance = VerticalScrollDistance(frame);
  if (!distance)
    return false;
  return ModifySelectionWithPageGranularity(
      frame, SelectionModifyAlteration::kExtend, distance,
      SelectionModifyVerticalDirection::kDown);
}

bool MoveCommands::ExecuteMovePageUp(LocalFrame& frame,
                                     Event*,
                                     EditorCommandSource,
                                     const String&) {
  const unsigned distance = VerticalScrollDistance(frame);
  if (!distance)
    return false;
  return ModifySelectionWithPageGranularity(
      frame, SelectionModifyAlteration::kMove, distance,
      SelectionModifyVerticalDirection::kUp);
}

bool MoveCommands::ExecuteMovePageUpAndModifySelection(LocalFrame& frame,
                                                       Event*,
                                                       EditorCommandSource,
                                                       const String&) {
  const unsigned distance = VerticalScrollDistance(frame);
  if (!distance)
    return false;
  return ModifySelectionWithPageGranularity(
      frame, SelectionModifyAlteration::kExtend, distance,
      SelectionModifyVerticalDirection::kUp);
}

bool MoveCommands::ExecuteMoveParagraphBackward(LocalFrame& frame,
                                                Event*,
                                                EditorCommandSource,
                                                const String&) {
  MoveSelection(frame, SelectionModifyDirection::kBackward,
                TextGranularity::kParagraph);
  return true;
}

bool MoveCommands::ExecuteMoveParagraphBackwardAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kBackward,
                           TextGranularity::kParagraph, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveParagraphForward(LocalFrame& frame,
                                               Event*,
                                               EditorCommandSource,
                                               const String&) {
  MoveSelection(frame, SelectionModifyDirection::kForward,
                TextGranularity::kParagraph);
  return true;
}

bool MoveCommands::ExecuteMoveParagraphForwardAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kForward,
                           TextGranularity::kParagraph, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveRight(LocalFrame& frame,
                                    Event*,
                                    EditorCommandSource,
                                    const String&) {
  return MoveSelection(frame, SelectionModifyDirection::kRight,
                       TextGranularity::kCharacter);
}

bool MoveCommands::ExecuteMoveRightAndModifySelection(LocalFrame& frame,
                                                      Event*,
                                                      EditorCommandSource,
                                                      const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kRight,
                           TextGranularity::kCharacter, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfDocument(LocalFrame& frame,
                                                    Event*,
                                                    EditorCommandSource,
                                                    const String&) {
  MoveSelection(frame, SelectionModifyDirection::kBackward,
                TextGranularity::kDocumentBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfDocumentAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kBackward,
      TextGranularity::kDocumentBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfLine(LocalFrame& frame,
                                                Event*,
                                                EditorCommandSource,
                                                const String&) {
  MoveSelection(frame, SelectionModifyDirection::kBackward,
                TextGranularity::kLineBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfLineAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kBackward,
      TextGranularity::kLineBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfParagraph(LocalFrame& frame,
                                                     Event*,
                                                     EditorCommandSource,
                                                     const String&) {
  MoveSelection(frame, SelectionModifyDirection::kBackward,
                TextGranularity::kParagraphBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfParagraphAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kBackward,
      TextGranularity::kParagraphBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfSentence(LocalFrame& frame,
                                                    Event*,
                                                    EditorCommandSource,
                                                    const String&) {
  MoveSelection(frame, SelectionModifyDirection::kBackward,
                TextGranularity::kSentenceBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToBeginningOfSentenceAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kBackward,
      TextGranularity::kSentenceBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfDocument(LocalFrame& frame,
                                              Event*,
                                              EditorCommandSource,
                                              const String&) {
  MoveSelection(frame, SelectionModifyDirection::kForward,
                TextGranularity::kDocumentBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfDocumentAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kForward,
      TextGranularity::kDocumentBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfLine(LocalFrame& frame,
                                          Event*,
                                          EditorCommandSource,
                                          const String&) {
  MoveSelection(frame, SelectionModifyDirection::kForward,
                TextGranularity::kLineBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfLineAndModifySelection(LocalFrame& frame,
                                                            Event*,
                                                            EditorCommandSource,
                                                            const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kForward,
      TextGranularity::kLineBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfParagraph(LocalFrame& frame,
                                               Event*,
                                               EditorCommandSource,
                                               const String&) {
  MoveSelection(frame, SelectionModifyDirection::kForward,
                TextGranularity::kParagraphBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfParagraphAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kForward,
      TextGranularity::kParagraphBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfSentence(LocalFrame& frame,
                                              Event*,
                                              EditorCommandSource,
                                              const String&) {
  MoveSelection(frame, SelectionModifyDirection::kForward,
                TextGranularity::kSentenceBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToEndOfSentenceAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kForward,
      TextGranularity::kSentenceBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToLeftEndOfLine(LocalFrame& frame,
                                              Event*,
                                              EditorCommandSource,
                                              const String&) {
  MoveSelection(frame, SelectionModifyDirection::kLeft,
                TextGranularity::kLineBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToLeftEndOfLineAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kLeft,
      TextGranularity::kLineBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveToRightEndOfLine(LocalFrame& frame,
                                               Event*,
                                               EditorCommandSource,
                                               const String&) {
  MoveSelection(frame, SelectionModifyDirection::kRight,
                TextGranularity::kLineBoundary);
  return true;
}

bool MoveCommands::ExecuteMoveToRightEndOfLineAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(
      SelectionModifyAlteration::kExtend, SelectionModifyDirection::kRight,
      TextGranularity::kLineBoundary, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveUp(LocalFrame& frame,
                                 Event*,
                                 EditorCommandSource,
                                 const String&) {
  return MoveSelection(frame, SelectionModifyDirection::kBackward,
                       TextGranularity::kLine);
}

bool MoveCommands::ExecuteMoveUpAndModifySelection(LocalFrame& frame,
                                                   Event*,
                                                   EditorCommandSource,
                                                   const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kBackward,
                           TextGranularity::kLine, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveWordBackward(LocalFrame& frame,
                                           Event*,
                                           EditorCommandSource,
                                           const String&) {
  MoveSelection(frame, SelectionModifyDirection::kBackward,
                TextGranularity::kWord);
  return true;
}

bool MoveCommands::ExecuteMoveWordBackwardAndModifySelection(
    LocalFrame& frame,
    Event*,
    EditorCommandSource,
    const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kBackward,
                           TextGranularity::kWord, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveWordForward(LocalFrame& frame,
                                          Event*,
                                          EditorCommandSource,
                                          const String&) {
  MoveSelection(frame, SelectionModifyDirection::kForward,
                TextGranularity::kWord);
  return true;
}

bool MoveCommands::ExecuteMoveWordForwardAndModifySelection(LocalFrame& frame,
                                                            Event*,
                                                            EditorCommandSource,
                                                            const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kForward,
                           TextGranularity::kWord, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveWordLeft(LocalFrame& frame,
                                       Event*,
                                       EditorCommandSource,
                                       const String&) {
  MoveSelection(frame, SelectionModifyDirection::kLeft, TextGranularity::kWord);
  return true;
}

bool MoveCommands::ExecuteMoveWordLeftAndModifySelection(LocalFrame& frame,
                                                         Event*,
                                                         EditorCommandSource,
                                                         const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kLeft,
                           TextGranularity::kWord, SetSelectionBy::kUser);
  return true;
}

bool MoveCommands::ExecuteMoveWordRight(LocalFrame& frame,
                                        Event*,
                                        EditorCommandSource,
                                        const String&) {
  MoveSelection(frame, SelectionModifyDirection::kRight,
                TextGranularity::kWord);
  return true;
}

bool MoveCommands::ExecuteMoveWordRightAndModifySelection(LocalFrame& frame,
                                                          Event*,
                                                          EditorCommandSource,
                                                          const String&) {
  frame.Selection().Modify(SelectionModifyAlteration::kExtend,
                           SelectionModifyDirection::kRight,
                           TextGranularity::kWord, SetSelectionBy::kUser);
  return true;
}

}  // namespace blink
```