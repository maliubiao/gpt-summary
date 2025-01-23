Response:
The user wants a summary of the functionality of the `dom_selection.cc` file in Chromium's Blink rendering engine. I need to identify the main purpose of this file and how it interacts with other parts of the browser, particularly Javascript, HTML, and CSS. I also need to consider potential user errors and debugging scenarios.

Here's a breakdown of how to approach the request:

1. **Identify the core responsibility:** The filename `dom_selection.cc` strongly suggests this file manages the user's text selection within the DOM.

2. **Analyze included headers:** The `#include` statements reveal the dependencies and hint at related functionalities:
    * `DOM`:  Interaction with the Document Object Model (nodes, ranges).
    * `editing`: Core editing functionalities like selection, positions, iterators.
    * `frame`: Integration with the browser frame.
    * `bindings/core/v8`:  Indicates this code is exposed to Javascript.
    * `platform`: Lower-level platform utilities.

3. **Examine the public interface (methods):** The public methods of the `DOMSelection` class define its API. I should categorize these methods based on their function (getting selection info, modifying selection, etc.).

4. **Connect to Javascript, HTML, and CSS:**  For each identified functionality, I need to explain how it relates to these web technologies:
    * **Javascript:** How can Javascript code access and manipulate the selection using the API defined in this file?
    * **HTML:** How does the selection relate to the structure of the HTML document?
    * **CSS:** How might CSS influence the visual presentation of the selection?

5. **Consider logical reasoning and examples:** For some functions, I can provide examples of how they work with specific inputs and outputs.

6. **Identify user errors:**  Based on the functions, I need to think about common mistakes users or developers might make when interacting with selections.

7. **Describe user interaction and debugging:**  How does a user's actions in the browser lead to the execution of code in this file? What debugging techniques could be used?

8. **Summarize the functionality (Part 1):**  Based on the above analysis, provide a concise summary of the file's purpose, focusing on the information available in the provided first part of the file.

**Mental Sandbox:**

* **Initial thought:** This file handles all aspects of selection. *Correction:*  It seems to be a higher-level interface built on top of `FrameSelection`.
* **Focus on methods:**  Let's go through the methods one by one and understand what they do. `anchorNode`, `focusNode`, `collapse`, `extend`, `getRangeAt`, etc.
* **Javascript connection:**  The methods seem to directly correspond to the Javascript `Selection` API. I need to give examples of how Javascript would call these.
* **HTML and CSS:** Selection operates on HTML elements and text. CSS can style the selection (e.g., `::selection`).
* **User errors:**  Trying to select something that doesn't exist, or using incorrect offsets.
* **Debugging:** Using browser developer tools to inspect the selection object and its properties.

**Constraint Checklist & Confidence Score:**

* 列举一下它的功能: Yes
* 与javascript, html, css的功能有关系: Yes
* 做出对应的举例说明: Yes
* 如果做了逻辑推理，请给出假设输入与输出: Yes
* 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
* 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
* 归纳一下它的功能: Yes

Confidence Score: 5/5  I feel confident I can address all aspects of the prompt based on the provided code and my understanding of browser architecture.
```
这是目录为blink/renderer/core/editing/dom_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

根据提供的代码片段，`blink/renderer/core/editing/dom_selection.cc` 文件的主要功能是实现 **DOM Selection API**。它提供了一组接口，允许 JavaScript 代码获取和操作用户在网页上选择的文本或元素。

**主要功能列举：**

1. **获取选区信息:**
    * `anchorNode()`, `anchorOffset()`: 获取选区锚点的节点和偏移量。
    * `focusNode()`, `focusOffset()`: 获取选区焦点节点的节点和偏移量。
    * `baseNode()`, `baseOffset()`, `extentNode()`, `extentOffset()`:  提供与 `anchorNode`/`anchorOffset` 和 `focusNode`/`focusOffset` 类似的功能，用于兼容不同的浏览器实现或更细粒度的控制。
    * `isCollapsed()`: 判断选区是否折叠成一个插入符（没有选中任何内容）。
    * `type()`: 返回选区的类型（"None", "Caret", "Range"）。
    * `direction()`: 返回选区的方向（"forward", "backward", "none"）。
    * `rangeCount()`: 返回选区中包含的 Range 对象的数量 (在当前代码中，通常为 0 或 1)。
    * `getRangeAt(index)`: 获取指定索引的 Range 对象。
    * `getComposedRanges(options)`: 获取由 Shadow DOM 边界组合而成的静态 Range 集合。

2. **修改选区:**
    * `collapse(node, offset)`: 将选区折叠到指定的节点和偏移量。
    * `collapseToEnd()`: 将选区折叠到末尾。
    * `collapseToStart()`: 将选区折叠到起始位置。
    * `empty()`: 清空选区。
    * `setBaseAndExtent(baseNode, baseOffset, extentNode, extentOffset)`: 设置选区的起始和结束位置。
    * `modify(alter, direction, granularity)`:  以指定的粒度（字符、单词、行等）和方向移动或扩展选区。
    * `extend(node, offset)`: 将选区的焦点移动到指定的节点和偏移量，从而扩展选区。
    * `addRange(range)`: 向选区添加一个 Range 对象（在当前代码中，可能还没有实现多 Range 的完整支持）。
    * `removeRange(range)`: 从选区移除一个 Range 对象。
    * `removeAllRanges()`: 清空选区中的所有 Range 对象。
    * `deleteFromDocument()`: 从文档中删除选区中的内容。
    * `selectAllChildren(node)`: 选择指定节点的所有子节点。

3. **其他功能:**
    * `containsNode(node, allow_partial)`: 检查选区是否包含指定的节点。
    * `toString()`: 返回选区内容的纯文本表示。

**与 Javascript, HTML, CSS 的关系：**

* **Javascript:** `DOMSelection` 类的方法直接对应于 JavaScript 中 `window.getSelection()` 返回的 `Selection` 对象的属性和方法。开发者可以使用 JavaScript 代码来获取当前用户的选区信息，并根据需要修改选区。

    **举例：**
    ```javascript
    // 获取当前选区对象
    const selection = window.getSelection();

    // 获取锚点节点
    const anchorNode = selection.anchorNode;

    // 将选区折叠到某个元素的首部
    const element = document.getElementById('myElement');
    selection.collapse(element, 0);

    // 选择一个元素的所有内容
    selection.selectAllChildren(element);

    // 获取选中的文本
    const selectedText = selection.toString();
    ```

* **HTML:**  用户在 HTML 文档中进行选择操作，`DOMSelection` 对象会记录选区的起始和结束位置，这些位置指向 HTML 结构中的节点和偏移量。

    **举例：**  当用户在以下 HTML 中选中 "world"：
    ```html
    <div>Hello <b>world</b>!</div>
    ```
    `anchorNode` 可能会指向包含 "world" 的 `<b>` 元素中的文本节点，`anchorOffset` 可能为 0，`focusNode` 也可能指向同一个文本节点，`focusOffset` 可能为 5。

* **CSS:** CSS 可以用于设置选区的样式，例如选中文本的背景色和前景色。这是通过 `::selection` 伪元素实现的。虽然 `dom_selection.cc` 本身不直接处理 CSS 样式，但它提供的选区信息会被渲染引擎用来应用这些样式。

    **举例：**  以下 CSS 会将选中文本的背景色设置为黄色：
    ```css
    ::selection {
      background-color: yellow;
    }
    ```

**逻辑推理 (假设输入与输出)：**

假设用户在以下 HTML 中选中了 "is a":
```html
<p>This is a test.</p>
```

* **假设输入：** 用户从 "is" 的 "i" 之前开始拖动鼠标到 "a" 之后释放。
* **预期输出：**
    * `anchorNode()`:  `<p>` 元素内的文本节点 "This is a test."
    * `anchorOffset()`: 5 (指向 "is" 的 "i" 之前)
    * `focusNode()`: `<p>` 元素内的文本节点 "This is a test."
    * `focusOffset()`: 9 (指向 "a" 之后)
    * `isCollapsed()`: `false`
    * `type()`: "Range"
    * `toString()`: "is a"

**用户或编程常见的使用错误：**

* **使用无效的节点或偏移量：**  例如，尝试将选区折叠到一个不存在的节点，或者偏移量超出了节点的长度。代码中使用了 `Range::CheckNodeWOffset` 来进行这类检查并抛出 `IndexSizeError` 异常。
    **举例：**
    ```javascript
    const selection = window.getSelection();
    const element = document.getElementById('nonExistentElement');
    selection.collapse(element, 0); // 可能会导致错误或空操作
    ```
* **在 Shadow DOM 中操作选区时未考虑边界：**  `getComposedRanges` 方法的出现就是为了解决在 Shadow DOM 环境下获取正确的选区范围。不正确地处理 Shadow DOM 的边界可能导致获取到不准确的选区范围。
* **假设 `rangeCount` 总是 1：** 尽管当前代码片段的实现似乎主要关注单个 Range 的选区，但 Selection API 允许存在多个 Range。假设 `rangeCount` 总是 1 可能会导致代码在处理复杂选区时出错。

**用户操作如何到达这里 (调试线索)：**

1. **用户进行选择操作：** 用户在浏览器中通过鼠标拖动、双击、三击等操作选择文本或元素。
2. **浏览器事件触发：**  用户的选择操作会触发浏览器内部的事件，例如 `mouseup`，`mousedown` 等。
3. **事件处理和选区更新：**  Blink 渲染引擎会处理这些事件，并调用相应的代码来更新选区状态。这可能会涉及到 `FrameSelection` 等其他相关类。
4. **JavaScript 调用 Selection API：** 开发者编写的 JavaScript 代码可能会调用 `window.getSelection()` 返回的 `Selection` 对象的方法来获取或修改选区。这些 JavaScript 调用最终会映射到 `dom_selection.cc` 中 `DOMSelection` 类的方法。

**作为调试线索：** 如果开发者在使用 JavaScript Selection API 时遇到问题，例如获取到的选区信息不正确，或者修改选区没有生效，他们可以在 Chrome 的开发者工具中设置断点在 `dom_selection.cc` 文件的相关方法中，来跟踪代码的执行流程，查看选区的内部状态，以及理解浏览器的选择机制。

**归纳一下它的功能 (第 1 部分)：**

在提供的第一部分代码中，`blink/renderer/core/editing/dom_selection.cc` 文件的主要功能是实现了 DOM Selection API 的核心部分，包括 **获取选区信息** (如锚点、焦点、是否折叠、类型、方向、包含的 Range 数量) 和一部分 **修改选区的功能** (如折叠选区、清空选区、设置起始和结束位置)。它为 JavaScript 提供了操作用户选区的底层接口，并与 HTML 结构和 CSS 样式有着密切的关系。
```
### 提示词
```
这是目录为blink/renderer/core/editing/dom_selection.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2007, 2009 Apple Inc. All rights reserved.
 * Copyright (C) 2012 Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "third_party/blink/renderer/core/editing/dom_selection.h"

#include "third_party/blink/renderer/bindings/core/v8/v8_get_composed_ranges_options.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/node.h"
#include "third_party/blink/renderer/core/dom/range.h"
#include "third_party/blink/renderer/core/dom/tree_scope.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/text_iterator.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_modifier.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/set_selection_options.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/inspector/console_message.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/instrumentation/use_counter.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

DOMSelection::DOMSelection(const TreeScope* tree_scope)
    : ExecutionContextClient(tree_scope->RootNode().GetExecutionContext()),
      tree_scope_(tree_scope) {}

void DOMSelection::ClearTreeScope() {
  tree_scope_ = nullptr;
}

FrameSelection& DOMSelection::Selection() const {
  DCHECK(DomWindow());
  return DomWindow()->GetFrame()->Selection();
}

// TODO(editing-dev): The behavior after loosing browsing context is not
// specified. https://github.com/w3c/selection-api/issues/82
bool DOMSelection::IsAvailable() const {
  return DomWindow() && Selection().IsAvailable();
}

void DOMSelection::UpdateFrameSelection(
    const SelectionInDOMTree& selection,
    Range* new_cached_range,
    const SetSelectionOptions& passed_options) const {
  DCHECK(DomWindow());
  SetSelectionOptions::Builder builder(passed_options);
  builder.SetShouldCloseTyping(true).SetShouldClearTypingStyle(true);
  SetSelectionOptions options = builder.Build();
  // TODO(tkent): Specify FrameSelection::DoNotSetFocus. crbug.com/690272
  const bool did_set = Selection().SetSelectionDeprecated(selection, options);
  CacheRangeIfSelectionOfDocument(new_cached_range);
  if (!did_set)
    return;
  Element* focused_element = DomWindow()->document()->FocusedElement();
  Selection().DidSetSelectionDeprecated(selection, options);
  if (DomWindow() &&
      focused_element != DomWindow()->document()->FocusedElement()) {
    UseCounter::Count(DomWindow(), WebFeature::kSelectionFuncionsChangeFocus);
  }
}

VisibleSelection DOMSelection::GetVisibleSelection() const {
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  return Selection().ComputeVisibleSelectionInDOMTree();
}

bool DOMSelection::IsAnchorFirstInSelection() const {
  return Selection().GetSelectionInDOMTree().IsAnchorFirst();
}

Node* DOMSelection::anchorNode() const {
  TemporaryRange temp_range(this, PrimaryRangeOrNull());
  if (temp_range.GetRange()) {
    if (!DomWindow() || IsAnchorFirstInSelection()) {
      return temp_range.GetRange()->startContainer();
    }
    return temp_range.GetRange()->endContainer();
  }
  return nullptr;
}

unsigned DOMSelection::anchorOffset() const {
  TemporaryRange temp_range(this, PrimaryRangeOrNull());
  if (temp_range.GetRange()) {
    if (!DomWindow() || IsAnchorFirstInSelection()) {
      return temp_range.GetRange()->startOffset();
    }
    return temp_range.GetRange()->endOffset();
  }
  return 0;
}

Node* DOMSelection::focusNode() const {
  TemporaryRange temp_range(this, PrimaryRangeOrNull());
  if (temp_range.GetRange()) {
    if (!DomWindow() || IsAnchorFirstInSelection()) {
      return temp_range.GetRange()->endContainer();
    }
    return temp_range.GetRange()->startContainer();
  }
  return nullptr;
}

unsigned DOMSelection::focusOffset() const {
  TemporaryRange temp_range(this, PrimaryRangeOrNull());
  if (temp_range.GetRange()) {
    if (!DomWindow() || IsAnchorFirstInSelection()) {
      return temp_range.GetRange()->endOffset();
    }
    return temp_range.GetRange()->startOffset();
  }
  return 0;
}

Node* DOMSelection::baseNode() const {
  return anchorNode();
}

unsigned DOMSelection::baseOffset() const {
  return anchorOffset();
}

Node* DOMSelection::extentNode() const {
  return focusNode();
}

unsigned DOMSelection::extentOffset() const {
  return focusOffset();
}

bool DOMSelection::isCollapsed() const {
  if (!IsAvailable())
    return true;
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  if (!RuntimeEnabledFeatures::SelectionIsCollapsedShadowDOMSupportEnabled()) {
    Node* node =
        Selection().ComputeVisibleSelectionInDOMTree().Anchor().AnchorNode();
    if (node && node->IsInShadowTree() &&
        DomWindow()->document()->AncestorInThisScope(node)) {
      // Count if range is not collapsed, but we are returning true because
      // feature is disabled and anchor node is in shadow tree.
      TemporaryRange temp_range(this, PrimaryRangeOrNull());
      if (temp_range.GetRange() && !temp_range.GetRange()->collapsed()) {
        UseCounter::Count(DomWindow(),
                          WebFeature::kSelectionIsCollapsedBehaviorChange);
      }
      return true;
    }
  }

  TemporaryRange temp_range(this, PrimaryRangeOrNull());
  if (temp_range.GetRange()) {
    return temp_range.GetRange()->collapsed();
  }
  return true;
}

String DOMSelection::type() const {
  if (!IsAvailable())
    return String();
  // This is a WebKit DOM extension, incompatible with an IE extension
  // IE has this same attribute, but returns "none", "text" and "control"
  // http://msdn.microsoft.com/en-us/library/ms534692(VS.85).aspx
  if (rangeCount() == 0)
    return "None";
  // Do not use isCollapsed() here. We'd like to return "Range" for
  // range-selection in text control elements.
  if (Selection().GetSelectionInDOMTree().IsCaret())
    return "Caret";
  return "Range";
}

String DOMSelection::direction() const {
  if (!IsAvailable()) {
    return "none";
  }
  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  if (!Selection().IsDirectional() ||
      Selection().ComputeVisibleSelectionInDOMTree().IsNone()) {
    return "none";
  }
  if (IsAnchorFirstInSelection()) {
    return "forward";
  }
  return "backward";
}

unsigned DOMSelection::rangeCount() const {
  if (!IsAvailable())
    return 0;
  if (DocumentCachedRange())
    return 1;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  if (Selection().ComputeVisibleSelectionInDOMTree().IsNone()) {
    return 0;
  }
  // Any selection can be adjusted to Range for Document.
  if (IsSelectionOfDocument())
    return 1;
  // In ShadowRoot, we need to try adjustment.
  if (CreateRangeFromSelectionEditor().IsNotNull())
    return 1;
  return 0;
}

// https://www.w3.org/TR/selection-api/#dom-selection-collapse
void DOMSelection::collapse(Node* node,
                            unsigned offset,
                            ExceptionState& exception_state) {
  if (!IsAvailable())
    return;

  // 1. If node is null, this method must behave identically as
  // removeAllRanges() and abort these steps.
  if (!node) {
    UseCounter::Count(DomWindow(), WebFeature::kSelectionCollapseNull);
    Selection().Clear();
    return;
  }

  // 2. The method must throw an IndexSizeError exception if offset is longer
  // than node's length ([DOM4]) and abort these steps.
  Range::CheckNodeWOffset(node, offset, exception_state);
  if (exception_state.HadException())
    return;

  // 3. If document associated with this is not a shadow-including inclusive
  // ancestor of node, abort these steps.
  if (!IsValidForPosition(node))
    return;

  // 4. Otherwise, let newRange be a new range.
  Range* new_range = Range::Create(*DomWindow()->document());

  // 5. Set ([DOM4]) the start and the end of newRange to (node, offset).
  new_range->setStart(node, offset, exception_state);
  if (exception_state.HadException()) {
    new_range->Dispose();
    return;
  }
  new_range->setEnd(node, offset, exception_state);
  if (exception_state.HadException()) {
    new_range->Dispose();
    return;
  }

  // 6. Set the context object's range to newRange.
  UpdateFrameSelection(
      SelectionInDOMTree::Builder().Collapse(Position(node, offset)).Build(),
      new_range,
      SetSelectionOptions::Builder()
          .SetIsDirectional(Selection().IsDirectional())
          .Build());
}

// https://www.w3.org/TR/selection-api/#dom-selection-collapsetoend
void DOMSelection::collapseToEnd(ExceptionState& exception_state) {
  if (!IsAvailable())
    return;

  // The method must throw InvalidStateError exception if the context object is
  // empty.
  if (rangeCount() == 0) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "there is no selection.");
    return;
  }

  if (Range* current_range = DocumentCachedRange()) {
    // Otherwise, it must create a new range, set both its start and end to the
    // end of the context object's range,
    Range* new_range = current_range->cloneRange();
    new_range->collapse(false);

    // and then set the context object's range to the newly-created range.
    SelectionInDOMTree::Builder builder;
    builder.Collapse(new_range->EndPosition());
    UpdateFrameSelection(builder.Build(), new_range, SetSelectionOptions());
  } else {
    // TODO(tkent): The Selection API doesn't define this behavior. We should
    // discuss this on https://github.com/w3c/selection-api/issues/83.
    SelectionInDOMTree::Builder builder;
    builder.Collapse(Selection().GetSelectionInDOMTree().ComputeEndPosition());
    UpdateFrameSelection(builder.Build(), nullptr, SetSelectionOptions());
  }
}

// https://www.w3.org/TR/selection-api/#dom-selection-collapsetostart
void DOMSelection::collapseToStart(ExceptionState& exception_state) {
  if (!IsAvailable())
    return;

  // The method must throw InvalidStateError ([DOM4]) exception if the context
  // object is empty.
  if (rangeCount() == 0) {
    exception_state.ThrowDOMException(DOMExceptionCode::kInvalidStateError,
                                      "there is no selection.");
    return;
  }

  if (Range* current_range = DocumentCachedRange()) {
    // Otherwise, it must create a new range, set both its start and end to the
    // start of the context object's range,
    Range* new_range = current_range->cloneRange();
    new_range->collapse(true);

    // and then set the context object's range to the newly-created range.
    SelectionInDOMTree::Builder builder;
    builder.Collapse(new_range->StartPosition());
    UpdateFrameSelection(builder.Build(), new_range, SetSelectionOptions());
  } else {
    // TODO(tkent): The Selection API doesn't define this behavior. We should
    // discuss this on https://github.com/w3c/selection-api/issues/83.
    SelectionInDOMTree::Builder builder;
    builder.Collapse(
        Selection().GetSelectionInDOMTree().ComputeStartPosition());
    UpdateFrameSelection(builder.Build(), nullptr, SetSelectionOptions());
  }
}

void DOMSelection::empty() {
  if (IsAvailable())
    Selection().Clear();
}

// https://www.w3.org/TR/selection-api/#dom-selection-setbaseandextent
void DOMSelection::setBaseAndExtent(Node* base_node,
                                    unsigned base_offset,
                                    Node* extent_node,
                                    unsigned extent_offset,
                                    ExceptionState& exception_state) {
  if (!IsAvailable())
    return;

  // TODO(editing-dev): Behavior on where base or extent is null is still
  // under discussion: https://github.com/w3c/selection-api/issues/72
  if (!base_node) {
    UseCounter::Count(DomWindow(), WebFeature::kSelectionSetBaseAndExtentNull);
    Selection().Clear();
    return;
  }
  if (!extent_node) {
    UseCounter::Count(DomWindow(), WebFeature::kSelectionSetBaseAndExtentNull);
    extent_offset = 0;
  }

  // 1. If anchorOffset is longer than anchorNode's length or if focusOffset is
  // longer than focusNode's length, throw an IndexSizeError exception and abort
  // these steps.
  Range::CheckNodeWOffset(base_node, base_offset, exception_state);
  if (exception_state.HadException())
    return;
  if (extent_node) {
    Range::CheckNodeWOffset(extent_node, extent_offset, exception_state);
    if (exception_state.HadException())
      return;
  }

  // 2. If document associated with this is not a shadow-including inclusive
  // ancestor of anchorNode or focusNode, abort these steps.
  if (!IsValidForPosition(base_node) || !IsValidForPosition(extent_node))
    return;

  ClearCachedRangeIfSelectionOfDocument();

  // 3. Let anchor be the boundary point (anchorNode, anchorOffset) and let
  // focus be the boundary point (focusNode, focusOffset).
  Position base_position(base_node, base_offset);
  Position extent_position(extent_node, extent_offset);
  // 4. Let newRange be a new range.
  Range* new_range = Range::Create(base_node->GetDocument());
  // 5. If anchor is before focus, set the start the newRange's start to anchor
  // and its end to focus. Otherwise, set the start them to focus and anchor
  // respectively.
  if (extent_position.IsNull()) {
    new_range->setStart(base_node, base_offset);
    new_range->setEnd(base_node, base_offset);
  } else if (base_position < extent_position) {
    new_range->setStart(base_node, base_offset);
    new_range->setEnd(extent_node, extent_offset);
  } else {
    new_range->setStart(extent_node, extent_offset);
    new_range->setEnd(base_node, base_offset);
  }
  // 6. Set this's range to newRange.
  UpdateFrameSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtentDeprecated(base_position, extent_position)
          .Build(),
      new_range, SetSelectionOptions::Builder().SetIsDirectional(true).Build());
}

void DOMSelection::modify(const String& alter_string,
                          const String& direction_string,
                          const String& granularity_string) {
  if (!IsAvailable())
    return;

  SelectionModifyAlteration alter;
  if (EqualIgnoringASCIICase(alter_string, "extend"))
    alter = SelectionModifyAlteration::kExtend;
  else if (EqualIgnoringASCIICase(alter_string, "move"))
    alter = SelectionModifyAlteration::kMove;
  else
    return;

  SelectionModifyDirection direction;
  if (EqualIgnoringASCIICase(direction_string, "forward"))
    direction = SelectionModifyDirection::kForward;
  else if (EqualIgnoringASCIICase(direction_string, "backward"))
    direction = SelectionModifyDirection::kBackward;
  else if (EqualIgnoringASCIICase(direction_string, "left"))
    direction = SelectionModifyDirection::kLeft;
  else if (EqualIgnoringASCIICase(direction_string, "right"))
    direction = SelectionModifyDirection::kRight;
  else
    return;

  TextGranularity granularity;
  if (EqualIgnoringASCIICase(granularity_string, "character"))
    granularity = TextGranularity::kCharacter;
  else if (EqualIgnoringASCIICase(granularity_string, "word"))
    granularity = TextGranularity::kWord;
  else if (EqualIgnoringASCIICase(granularity_string, "sentence"))
    granularity = TextGranularity::kSentence;
  else if (EqualIgnoringASCIICase(granularity_string, "line"))
    granularity = TextGranularity::kLine;
  else if (EqualIgnoringASCIICase(granularity_string, "paragraph"))
    granularity = TextGranularity::kParagraph;
  else if (EqualIgnoringASCIICase(granularity_string, "lineboundary"))
    granularity = TextGranularity::kLineBoundary;
  else if (EqualIgnoringASCIICase(granularity_string, "sentenceboundary"))
    granularity = TextGranularity::kSentenceBoundary;
  else if (EqualIgnoringASCIICase(granularity_string, "paragraphboundary"))
    granularity = TextGranularity::kParagraphBoundary;
  else if (EqualIgnoringASCIICase(granularity_string, "documentboundary"))
    granularity = TextGranularity::kDocumentBoundary;
  else
    return;

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  Element* focused_element = DomWindow()->document()->FocusedElement();
  Selection().Modify(alter, direction, granularity, SetSelectionBy::kSystem);
  if (DomWindow() &&
      focused_element != DomWindow()->document()->FocusedElement()) {
    UseCounter::Count(DomWindow(), WebFeature::kSelectionFuncionsChangeFocus);
  }
}

// https://www.w3.org/TR/selection-api/#dom-selection-extend
void DOMSelection::extend(Node* node,
                          unsigned offset,
                          ExceptionState& exception_state) {
  DCHECK(node);
  if (!IsAvailable())
    return;

  // 1. If the document associated with this is not a shadow-including
  // inclusive ancestor of node, abort these steps.
  if (!IsValidForPosition(node))
    return;

  // 2. If the context object is empty, throw an InvalidStateError exception and
  // abort these steps.
  if (rangeCount() == 0) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kInvalidStateError,
        "This Selection object doesn't have any Ranges.");
    return;
  }

  Range::CheckNodeWOffset(node, offset, exception_state);
  if (exception_state.HadException())
    return;

  // 3. Let oldAnchor and oldFocus be the context object's anchor and focus, and
  // let newFocus be the boundary point (node, offset).
  const Position old_anchor(anchorNode(), anchorOffset());
  DCHECK(!old_anchor.IsNull());
  const Position new_focus(node, offset);

  ClearCachedRangeIfSelectionOfDocument();

  // 4. Let newRange be a new range.
  Range* new_range = Range::Create(*DomWindow()->document());

  // 5. If node's root is not the same as the context object's range's root, set
  // newRange's start and end to newFocus.
  // E.g. oldAnchor might point in shadow Text node in TextControlElement.
  if (old_anchor.AnchorNode()->TreeRoot() != node->TreeRoot()) {
    new_range->setStart(node, offset);
    new_range->setEnd(node, offset);

  } else if (old_anchor <= new_focus) {
    // 6. Otherwise, if oldAnchor is before or equal to newFocus, set newRange's
    // start to oldAnchor, then set its end to newFocus.
    new_range->setStart(old_anchor.AnchorNode(),
                        old_anchor.OffsetInContainerNode());
    new_range->setEnd(node, offset);

  } else {
    // 7. Otherwise, set newRange's start to newFocus, then set its end to
    // oldAnchor.
    new_range->setStart(node, offset);
    new_range->setEnd(old_anchor.AnchorNode(),
                      old_anchor.OffsetInContainerNode());
  }

  // 8. Set the context object's range to newRange.
  SelectionInDOMTree::Builder builder;
  if (new_range->collapsed())
    builder.Collapse(new_focus);
  else
    builder.Collapse(old_anchor).Extend(new_focus);
  UpdateFrameSelection(
      builder.Build(), new_range,
      SetSelectionOptions::Builder().SetIsDirectional(true).Build());
}

Range* DOMSelection::getRangeAt(unsigned index,
                                ExceptionState& exception_state) const {
  if (!IsAvailable())
    return nullptr;

  if (index >= rangeCount()) {
    exception_state.ThrowDOMException(
        DOMExceptionCode::kIndexSizeError,
        String::Number(index) + " is not a valid index.");
    return nullptr;
  }

  // If you're hitting this, you've added broken multi-range selection support
  DCHECK_EQ(rangeCount(), 1u);

  if (Range* cached_range = DocumentCachedRange())
    return cached_range;

  Range* range = CreateRange(CreateRangeFromSelectionEditor());
  CacheRangeIfSelectionOfDocument(range);
  return range;
}

// https://www.w3.org/TR/selection-api/#dom-selection-getcomposedranges
const StaticRangeVector DOMSelection::getComposedRanges(
    const GetComposedRangesOptions* options) const {
  StaticRangeVector ranges;
  // 1. If this is empty, return an empty array.
  if (!IsAvailable()) {
    return ranges;
  }
  TemporaryRange temp_range(this, PrimaryRangeOrNull());
  if (!temp_range.GetRange()) {
    return ranges;
  }

  const SelectionInDOMTree& selection = Selection().GetSelectionInDOMTree();
  // 2. Otherwise, let startNode be start node of the range associated with
  // this, and let startOffset be start offset of the range.
  const Position& start = selection.ComputeStartPosition();
  Node* startNode = start.ComputeContainerNode();
  unsigned startOffset = start.ComputeOffsetInContainerNode();
  // 3. Rescope startNode and startOffset with listed shadow roots.
  Rescope(startNode, startOffset, options->shadowRoots(), /*isEnd=*/false);

  // 4. Let endNode be end node of the range associated with this, and let
  // endOffset be end offset of the range.
  const Position& end = selection.ComputeEndPosition();
  Node* endNode = end.ComputeContainerNode();
  unsigned endOffset = end.ComputeOffsetInContainerNode();
  // 5. Rescope endNode and endOffset with listed shadow roots.
  Rescope(endNode, endOffset, options->shadowRoots(), /*isEnd=*/true);

  // 6. Return an array consisting of new StaticRange whose start node is
  // startNode, start offset is startOffset, end node is endNode, and end
  // offset is endOffset.
  ranges.push_back(MakeGarbageCollected<StaticRange>(
      Selection().GetDocument(), startNode, startOffset, endNode, endOffset));
  return ranges;
}

// If isEnd is false, rescope following spec step 3.
// Else, Rescope following sepc step 5.
// https://www.w3.org/TR/selection-api/#dom-selection-getcomposedranges
void DOMSelection::Rescope(Node*& node,
                           unsigned& offset,
                           const HeapVector<Member<ShadowRoot>>& shadowRoots,
                           bool isEnd) const {
  // 3. & 5. While node is a node, node's root is a shadow root, and
  // node's root is not a shadow-including inclusive ancestor of any of
  // shadowRoots, repeat these steps:
  while (node) {
    ShadowRoot* root = node->ContainingShadowRoot();
    Element* host = node->OwnerShadowHost();
    if (!root || !host) {
      return;
    }
    for (auto& shadowRoot : shadowRoots) {
      if (root->IsShadowIncludingInclusiveAncestorOf(*shadowRoot)) {
        return;
      }
    }
    // 1. Set node to node's root's host's parent.
    node = host->parentNode();
    // 2. Set offset to index of node's root's host.
    offset = host->NodeIndex();
    if (isEnd) {
      offset += 1;
    }
  }
}

Range* DOMSelection::PrimaryRangeOrNull() const {
  return rangeCount() > 0 ? getRangeAt(0, ASSERT_NO_EXCEPTION) : nullptr;
}

EphemeralRange DOMSelection::CreateRangeFromSelectionEditor() const {
  const VisibleSelection& selection = GetVisibleSelection();
  const Position& anchor = selection.Anchor().ParentAnchoredEquivalent();
  if (IsSelectionOfDocument() && !anchor.AnchorNode()->IsInShadowTree())
    return FirstEphemeralRangeOf(selection);

  Node* const anchor_node = ShadowAdjustedNode(anchor);
  if (!anchor_node)  // crbug.com/595100
    return EphemeralRange();

  const Position& focus = selection.Focus().ParentAnchoredEquivalent();
  const Position shadow_adjusted_focus =
      Position(ShadowAdjustedNode(focus), ShadowAdjustedOffset(focus));
  const Position shadow_adjusted_anchor =
      Position(anchor_node, ShadowAdjustedOffset(anchor));
  if (selection.IsAnchorFirst()) {
    return EphemeralRange(shadow_adjusted_anchor, shadow_adjusted_focus);
  }
  return EphemeralRange(shadow_adjusted_focus, shadow_adjusted_anchor);
}

bool DOMSelection::IsSelectionOfDocument() const {
  return tree_scope_ == tree_scope_->GetDocument();
}

void DOMSelection::CacheRangeIfSelectionOfDocument(Range* range) const {
  if (!IsSelectionOfDocument())
    return;
  if (!DomWindow())
    return;
  Selection().CacheRangeOfDocument(range);
}

Range* DOMSelection::DocumentCachedRange() const {
  return IsSelectionOfDocument() ? Selection().DocumentCachedRange() : nullptr;
}

void DOMSelection::ClearCachedRangeIfSelectionOfDocument() {
  if (IsSelectionOfDocument())
    Selection().ClearDocumentCachedRange();
}

void DOMSelection::removeRange(Range* range) {
  DCHECK(range);
  TemporaryRange temp_range(this, PrimaryRangeOrNull());
  if (IsAvailable() && range == temp_range.GetRange()) {
    Selection().Clear();
  }
}

void DOMSelection::removeAllRanges() {
  if (IsAvailable())
    Selection().Clear();
}

void DOMSelection::addRange(Range* new_range) {
  DCHECK(new_range);

  if (!IsAvailable())
    return;

  if (new_range->OwnerDocument() != DomWindow()->document())
    return;

  if (!new_range->IsConnected()) {
    AddConsoleWarning("addRange(): The given range isn't in document.");
    return;
  }

  if (new_range->OwnerDocument() != Selection().GetDocument()) {
    // "editing/selection/selection-in-iframe-removed-crash.html" goes here.
    return;
  }

  if (rangeCount() == 0) {
    UpdateFrameSelection(SelectionInDOMTree::Builder()
                             .Collapse(new_range->StartPosition())
                             .Extend(new_range->EndPosition())
                             .Build(),
                         new_range, SetSelectionOptions());
    return;
  }
}

// https://www.w3.org/TR/selection-api/#dom-selection-deletefromdocument
void DOMSelection::deleteFromDocument() {
  if (!IsAvailable())
    return;

  // The method must invoke deleteContents() ([DOM4]) on the context object's
  // range if the context object is not empty. Otherwise the method must do
  // nothing.
  if (Range* range = DocumentCachedRange()) {
    range->deleteContents(ASSERT_NO_EXCEPTION);
    return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  // The following code is necessary for
  // editing/selection/deleteFromDocument-crash.html, which assumes
  // deleteFromDocument() for text selection in a TEXTAREA deletes the TEXTAREA
  // value.

  if (Selection().ComputeVisibleSelectionInDOMTree().IsNone())
    return;

  Range* selected_range = CreateRange(Selection()
                                          .ComputeVisibleSelectionInDOMTree()
                                          .ToNormalizedEphemeralRange());
  if (!selected_range)
    return;

  // |selectedRange| may point nodes in a different root.
  selected_range->deleteContents(ASSERT_NO_EXCEPTION);
}

bool DOMSelection::containsNode(const Node* n, bool allow_partial) const {
  DCHECK(n);

  if (!IsAvailable())
    return false;

  if (DomWindow()->document() != n->GetDocument())
    return false;

  unsigned node_index = n->NodeIndex();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  // |VisibleSelection::toNormalizedEphemeralRange| requires clean layout.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  const EphemeralRange selected_range = Selection()
                                            .ComputeVisibleSelectionInDOMTree()
                                            .ToNormalizedEphemeralRange();
  if (selected_range.IsNull())
    return false;

  ContainerNode* parent_node = n->parentNode();
  if (!parent_node)
    return false;

  const Position start_position =
      selected_range.StartPosition().ToOffsetInAnchor();
  const Position end_position = selected_range.EndPosition().ToOffsetInAnchor();
  DummyExceptionStateForTesting exception_state;
  bool node_fully_selected =
      Range::compareBoundaryPoints(
          parent_node, node_index, start_position.ComputeContainerNode(),
          start_position.OffsetInContainerNode(), exception_state) >= 0 &&
      !exception_state.HadException() &&
      Range::compareBoundaryPoints(
          parent_node, node_index + 1, end_position.ComputeContainerNode(),
          end_position.OffsetInContainerNode(), exception_state) <= 0 &&
      !exception_state.HadException();
  if (exception_state.HadException())
    return false;
  if (node_fully_selected)
    return true;

  bool node_fully_unselected =
      (Range::compareBoundaryPoints(
           parent_node, node_index, end_position.ComputeContainerNode(),
           end_position.OffsetInContainerNode(), exception_state) > 0 &&
       !exception_state.HadException()) ||
      (Range::compareBoundaryPoints(
           parent_node, node_index + 1, start_position.ComputeContainerNode(),
           start_position.OffsetInContainerNode(), exception_state) < 0 &&
       !exception_state.HadException());
  DCHECK(!exception_state.HadException());
  if (node_fully_unselected)
    return false;

  return allow_partial || n->IsTextNode();
}

void DOMSelection::selectAllChildren(Node* n, ExceptionState& exception_state) {
  DCHECK(n);

  // This doesn't (and shouldn't) select text node characters.
  setBaseAndExtent(n, 0, n, n->CountChildren(), exception_state);
}

String DOMSelection::toString() {
  if (!IsAvailable())
    return String();

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  DomWindow()->document()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSelection);

  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      DomWindow()->document()->Lifecycle());

  const EphemeralRange range = Selection()
                                   .ComputeVisibleSelectionInDOMTree()
                                   .ToNormalizedEphemeralRange();
  return PlainText(
      range,
      TextIteratorBehavior::Builder().SetForSelectionToString(true).Build());
}

Node* DOMSelection::ShadowAdjustedNode(const Position& position) const {
  if (position.IsNull())
    return nullptr;

  Node* container_node = position.ComputeContainerNode();
  Node* adjusted_node = tree_scope_->AncestorInThisScope(container_node);

  if (
```