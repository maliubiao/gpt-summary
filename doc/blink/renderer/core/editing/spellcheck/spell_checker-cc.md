Response:
Let's break down the thought process for analyzing the `spell_checker.cc` file and generating the detailed explanation.

**1. Understanding the Core Task:**

The first step is to recognize the file's purpose based on its name and location: `blink/renderer/core/editing/spellcheck/spell_checker.cc`. This clearly indicates it's part of Blink's rendering engine, specifically responsible for spell checking within the editing context.

**2. Initial Code Scan for Keywords and Functionality:**

Next, I'd quickly scan the code for important keywords and patterns:

* **`SpellChecker` class:** This is the central entity.
* **`SpellCheckRequester` and `IdleSpellCheckController`:** These are dependencies, suggesting different ways spell checking is triggered (immediate requests vs. background checks).
* **`WebTextCheckClient` and `WebSpellCheckPanelHostClient`:** These point to interactions with higher-level platform APIs for actual spell checking and UI display.
* **`DocumentMarkerController`:** This indicates the mechanism for visually highlighting misspelled words.
* **Functions like `IsSpellCheckingEnabled`, `IgnoreSpelling`, `AdvanceToNextMisspelling`, `MarkAndReplaceFor`, `RemoveMarkers`:** These clearly define the core functionalities.
* **Mentions of `JavaScript`, `HTML`, `CSS`:** While not explicitly coded within this file, the context of a browser engine implies these connections.

**3. Deconstructing Key Functions and Their Roles:**

I'd then focus on the most important functions, understanding their inputs, outputs, and side effects:

* **`IsSpellCheckingEnabled()`:** Simple check, likely relies on platform settings.
* **`IgnoreSpelling()`:** Removes existing spelling markers, demonstrating how user actions affect the state.
* **`AdvanceToNextMisspelling()`:**  A more complex function involving searching for misspelled words, selecting them, and updating the UI. This involves text iteration, boundary checks, and interaction with the `SpellCheckPanelHostClient`.
* **`MarkAndReplaceFor()`:**  This is crucial for receiving spell-checking results and updating the document with markers. It handles asynchronous results and checks for content modifications to prevent incorrect marking.
* **`RemoveMarkers()`:**  Manages the removal of visual indicators of spelling errors.

**4. Identifying Relationships with JavaScript, HTML, and CSS:**

This requires understanding the browser's architecture:

* **JavaScript:**  JavaScript can trigger actions that lead to spell checking (user input, programmatic content modification). It can also interact with the spell-checking UI if exposed through browser APIs.
* **HTML:**  The structure of the HTML document is what the spell checker operates on. Editable elements (like `<textarea>` or elements with `contenteditable`) are the targets for spell checking. Attributes like `spellcheck="true/false"` directly influence behavior.
* **CSS:** CSS defines the visual presentation of the spell-checking markers (the red squiggly lines).

**5. Formulating Hypotheses and Examples:**

Based on the function descriptions, I would create hypothetical scenarios:

* **Input/Output for `AdvanceToNextMisspelling()`:** A text example with a misspelling and the expected selection change.
* **User Errors:**  Common mistakes users or developers might make related to spell checking (disabling it, incorrect HTML attributes).

**6. Tracing User Actions (Debugging Clues):**

This involves thinking about the user's journey and how they interact with spell checking:

* Typing in an editable field.
* Right-clicking to access the context menu and selecting spell-checking options.
* Using browser settings to enable/disable spell checking.
* Programmatically manipulating content using JavaScript.

**7. Organizing the Information:**

Finally, I'd structure the information logically:

* Start with a concise summary of the file's purpose.
* List the key functionalities.
* Provide detailed explanations of important functions.
* Clearly illustrate the relationships with JavaScript, HTML, and CSS with examples.
* Present the input/output hypotheses.
* Detail potential user errors.
* Outline the user actions that lead to the code being executed (debugging clues).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focusing only on the direct code in `spell_checker.cc`.
* **Correction:** Realizing the need to consider the broader context of Blink, JavaScript, HTML, and CSS interaction.
* **Initial thought:** Simply listing function names.
* **Correction:** Providing a more detailed explanation of the purpose and logic of key functions.
* **Initial thought:**  Generic examples.
* **Correction:** Crafting specific and illustrative examples related to HTML attributes and JavaScript actions.

By following these steps, combining code analysis with an understanding of web technologies, I can construct a comprehensive and informative explanation of the `spell_checker.cc` file.
好的，我们来详细分析一下 `blink/renderer/core/editing/spellcheck/spell_checker.cc` 这个文件。

**文件功能概述**

`spell_checker.cc` 文件实现了 Chromium Blink 引擎中的拼写检查核心功能。它负责以下任务：

1. **启用和禁用拼写检查：**  管理特定上下文中（例如，可编辑元素内）的拼写检查是否激活。
2. **识别拼写错误：**  利用平台提供的拼写检查服务（通过 `WebTextCheckClient`）来识别文本中的拼写错误。
3. **标记拼写错误：**  使用 `DocumentMarkerController` 在文档中创建标记（通常显示为红色波浪线）来指示拼写错误的单词。
4. **提供拼写建议：**  与平台拼写检查服务交互，获取拼写错误的建议更正。
5. **处理用户交互：**  响应用户的拼写检查相关操作，例如忽略拼写错误、显示拼写建议面板、替换拼写错误等。
6. **异步拼写检查：**  管理异步的拼写检查请求，避免阻塞主线程。
7. **空闲时拼写检查：**  利用空闲时间进行拼写检查，提升性能。
8. **与拼写检查面板交互：**  通过 `WebSpellCheckPanelHostClient` 与浏览器的拼写检查面板进行通信。

**与 JavaScript, HTML, CSS 的关系及举例说明**

这个 `spell_checker.cc` 文件虽然是 C++ 代码，但它直接关系到用户在网页上与文本交互时的拼写检查体验，因此与 JavaScript, HTML, CSS 有着密切的联系。

**1. HTML (结构):**

* **可编辑内容 (contenteditable):**  拼写检查主要针对可编辑的 HTML 元素，例如 `<textarea>` 或设置了 `contenteditable="true"` 的 `<div>` 元素。`SpellChecker` 会检查这些元素内的文本。
    * **示例:**
      ```html
      <textarea spellcheck="true">Thi is a mispelled word.</textarea>
      <div contenteditable="true" spellcheck="true">Another typpo here.</div>
      ```
      在这个例子中，`spellcheck="true"` 属性告诉浏览器对这些元素启用拼写检查。`SpellChecker` 会识别 "Thi" 和 "typpo" 是拼写错误。

* **`<input>` 元素:**  对于 `<input type="text">` 类型的输入框，拼写检查也是一个重要特性。
    * **示例:**
      ```html
      <input type="text" spellcheck="true" value="I hav a drem.">
      ```
      `SpellChecker` 会标记 "hav" 和 "drem" 为拼写错误。

* **`spellcheck` 属性:**  HTML 元素的 `spellcheck` 属性（全局属性）直接控制了是否对该元素及其子元素进行拼写检查。`SpellChecker::IsSpellCheckingEnabledAt()` 等函数会读取这个属性来判断是否需要进行拼写检查。

**2. JavaScript (行为):**

* **动态修改内容:** JavaScript 可以动态地修改 HTML 元素的内容。当可编辑元素的内容发生变化时，`SpellChecker` 会接收到通知并可能触发新的拼写检查。
    * **示例:**
      ```javascript
      const textarea = document.querySelector('textarea');
      textarea.value = 'New contnet with mistkes.'; // 修改文本内容
      ```
      当 JavaScript 修改了 `textarea` 的值后，`SpellChecker` 会检查新的文本内容。

* **程序化地触发拼写检查相关操作:**  虽然不是直接调用 `spell_checker.cc` 中的函数，但 JavaScript 可以通过浏览器提供的 API（例如，用户右键点击时弹出的上下文菜单中的拼写建议）间接地触发 `SpellChecker` 的功能。

* **监听事件:** JavaScript 可以监听 `input` 或 `change` 等事件，这些事件表明用户正在输入或修改文本，从而间接地触发拼写检查的流程。

**3. CSS (样式):**

* **拼写错误标记的样式:**  虽然 `spell_checker.cc` 不直接处理 CSS，但浏览器会使用特定的 CSS 样式来渲染拼写错误标记（通常是红色波浪线）。这个样式是浏览器预定义的，但 CSS 可能会影响其最终呈现效果（例如，通过继承或覆盖相关样式）。
    * **示例:**  虽然不能直接控制拼写错误的波浪线颜色，但 CSS 可能会影响其显示或隐藏，例如通过设置 `text-decoration: none;` 可能会隐藏掉拼写错误的下划线（但这通常不推荐，因为会影响用户体验）。

**逻辑推理 (假设输入与输出)**

假设用户在一个启用了拼写检查的 `<textarea>` 中输入了以下内容：

**假设输入:**

```
This is an exmaple of a misspeled word.
```

**逻辑推理过程:**

1. **用户输入:** 用户在 `<textarea>` 中输入文本。
2. **`SpellChecker` 接收通知:**  Blink 引擎的事件处理机制会通知 `SpellChecker` 内容发生了变化。
3. **文本提取:** `SpellChecker` 从 `<textarea>` 中提取出需要检查的文本。
4. **拼写检查请求:** `SpellChecker` 通过 `WebTextCheckClient` 向操作系统的拼写检查服务发送请求，检查 "exmaple" 和 "misspeled" 这两个单词。
5. **接收结果:**  拼写检查服务返回结果，指出这两个单词是拼写错误，并可能提供建议的更正 ("example", "misspelled")。
6. **创建标记:** `SpellChecker` 使用 `DocumentMarkerController` 在文档中为 "exmaple" 和 "misspeled" 创建拼写错误标记。
7. **渲染:**  渲染引擎根据标记信息，在浏览器中将这两个单词下方显示红色波浪线。

**预期输出:**

用户在浏览器中会看到 "exmaple" 和 "misspeled" 这两个单词下方有红色波浪线。

**用户或编程常见的使用错误**

1. **用户禁用拼写检查:** 用户可以在浏览器的设置中全局禁用拼写检查，或者在特定网站或元素上禁用。这会导致 `SpellChecker` 不会进行拼写检查。

2. **HTML 属性设置错误:**
   * **忘记设置 `spellcheck="true"`:** 如果可编辑元素没有设置 `spellcheck="true"`，浏览器默认可能不会进行拼写检查。
   * **设置 `spellcheck="false"`:** 显式地禁用了拼写检查。

3. **编程错误导致拼写检查失效:**
   * **动态创建元素后未正确触发拼写检查:**  如果通过 JavaScript 动态创建可编辑元素并添加到文档中，可能需要手动触发拼写检查的初始化流程，否则 `SpellChecker` 可能不会立即生效。
   * **在非预期的元素上启用拼写检查:** 虽然可以对任意元素设置 `spellcheck="true"`，但拼写检查通常只在文本输入元素或可编辑元素上有意义。在其他元素上启用可能不会产生预期的效果。

**用户操作如何一步步到达这里 (调试线索)**

假设用户在一个网页的 `<textarea>` 中输入了一些文本，并且发现某些单词下方出现了红色的波浪线（拼写错误标记）。以下是用户操作逐步到达 `spell_checker.cc` 的过程：

1. **用户打开网页:** 用户在浏览器中打开一个包含可编辑元素的网页。
2. **用户聚焦可编辑元素:** 用户点击 `<textarea>` 或设置了 `contenteditable="true"` 的元素，使其获得焦点。
3. **用户开始输入文本:** 用户在可编辑元素中输入文本，例如输入 "missteke"。
4. **输入事件触发:** 用户的输入操作会触发浏览器的输入事件 (e.g., `input` event)。
5. **Blink 引擎接收事件:** Blink 渲染引擎接收到输入事件。
6. **文本内容变化:** Blink 引擎检测到可编辑元素的内容发生了变化。
7. **`SpellChecker` 接收通知:**  Blink 的编辑模块会通知 `SpellChecker` 相关的文本内容发生了改变。
8. **`IdleSpellCheckController` 或 `SpellCheckRequester` 启动:**  根据策略，可能是空闲拼写检查控制器或立即的拼写检查请求器开始工作。
9. **`FindFirstMisspelling` 或类似函数被调用:**  `SpellChecker` 会调用相关函数来查找文本中的拼写错误。
10. **`WebTextCheckClient` 调用:** `SpellChecker` 通过 `GetTextCheckerClient()` 获取平台拼写检查客户端，并调用其 `CheckSpelling` 等方法。
11. **平台拼写检查服务工作:** 操作系统或浏览器内置的拼写检查服务对文本进行分析。
12. **拼写检查结果返回:** 拼写检查服务将结果（例如，哪些单词拼写错误）返回给 Blink。
13. **`MarkAndReplaceFor` 函数被调用:** `SpellChecker` 的 `MarkAndReplaceFor` 函数接收到拼写检查结果。
14. **创建 `DocumentMarker`:** `MarkAndReplaceFor` 函数使用 `DocumentMarkerController` 为拼写错误的单词创建 `SpellCheckMarker`。
15. **渲染更新:**  渲染引擎根据 `DocumentMarker` 的信息，在浏览器中绘制红色的波浪线。

**调试线索:**

* **断点:** 可以在 `SpellChecker` 的关键函数（例如 `FindFirstMisspelling`, `MarkAndReplaceFor`, `IsSpellCheckingEnabledAt`）设置断点，观察代码执行流程。
* **日志输出:** 在相关代码中添加日志输出，记录文本内容、拼写检查结果等信息。
* **检查 HTML 结构和属性:**  确认可编辑元素是否正确设置了 `spellcheck="true"` 属性。
* **检查浏览器设置:** 确认浏览器的拼写检查功能是否已启用。
* **使用开发者工具:**  浏览器的开发者工具可以帮助查看元素的属性、事件监听器等，有助于理解拼写检查的触发和工作原理。

希望以上分析能够帮助你更好地理解 `blink/renderer/core/editing/spellcheck/spell_checker.cc` 文件的功能和它在浏览器拼写检查流程中的作用。

### 提示词
```
这是目录为blink/renderer/core/editing/spellcheck/spell_checker.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2006, 2007, 2008, 2011 Apple Inc. All rights reserved.
 * Copyright (C) 2008 Nokia Corporation and/or its subsidiary(-ies)
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

#include "third_party/blink/renderer/core/editing/spellcheck/spell_checker.h"

#include "third_party/blink/public/platform/web_spell_check_panel_host_client.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/public/web/web_text_check_client.h"
#include "third_party/blink/public/web/web_text_decoration_type.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/element.h"
#include "third_party/blink/renderer/core/dom/element_traversal.h"
#include "third_party/blink/renderer/core/dom/node_traversal.h"
#include "third_party/blink/renderer/core/editing/editing_utilities.h"
#include "third_party/blink/renderer/core/editing/editor.h"
#include "third_party/blink/renderer/core/editing/ephemeral_range.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/iterators/character_iterator.h"
#include "third_party/blink/renderer/core/editing/markers/document_marker_controller.h"
#include "third_party/blink/renderer/core/editing/markers/spell_check_marker.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/spellcheck/cold_mode_spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/spellcheck/idle_spell_check_controller.h"
#include "third_party/blink/renderer/core/editing/spellcheck/spell_check_requester.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_dom_window.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/html/forms/html_input_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_object.h"
#include "third_party/blink/renderer/core/loader/empty_clients.h"
#include "third_party/blink/renderer/core/page/page.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/text/text_break_iterator.h"
#include "third_party/blink/renderer/platform/wtf/text/string_builder.h"

namespace blink {

namespace {

// Returns whether ranges [0, checking_range_length) and
// [location, location + length) intersect
bool CheckingRangeCovers(int checking_range_length, int location, int length) {
  DCHECK_GE(checking_range_length, 0);
  DCHECK_GE(length, 0);
  return location + length > 0 && location < checking_range_length;
}

bool IsWhiteSpaceOrPunctuation(UChar c) {
  return IsSpaceOrNewline(c) || WTF::unicode::IsPunct(c);
}

}  // namespace

static WebSpellCheckPanelHostClient& GetEmptySpellCheckPanelHostClient() {
  DEFINE_STATIC_LOCAL(EmptySpellCheckPanelHostClient, client, ());
  return client;
}

WebSpellCheckPanelHostClient& SpellChecker::SpellCheckPanelHostClient() const {
  WebSpellCheckPanelHostClient* spell_check_panel_host_client =
      GetFrame().Client()->SpellCheckPanelHostClient();
  if (!spell_check_panel_host_client)
    return GetEmptySpellCheckPanelHostClient();
  return *spell_check_panel_host_client;
}

WebTextCheckClient* SpellChecker::GetTextCheckerClient() const {
  // There is no frame client if the frame is detached.
  if (!GetFrame().Client())
    return nullptr;
  return GetFrame().Client()->GetTextCheckerClient();
}

SpellChecker::SpellChecker(LocalDOMWindow& window)
    : window_(&window),
      spell_check_requester_(MakeGarbageCollected<SpellCheckRequester>(window)),
      idle_spell_check_controller_(
          MakeGarbageCollected<IdleSpellCheckController>(
              window,
              *spell_check_requester_)) {}

LocalFrame& SpellChecker::GetFrame() const {
  DCHECK(window_->GetFrame());
  return *window_->GetFrame();
}

bool SpellChecker::IsSpellCheckingEnabled() const {
  if (WebTextCheckClient* client = GetTextCheckerClient())
    return client->IsSpellCheckingEnabled();
  return false;
}

void SpellChecker::IgnoreSpelling() {
  RemoveMarkers(GetFrame()
                    .Selection()
                    .ComputeVisibleSelectionInDOMTree()
                    .ToNormalizedEphemeralRange(),
                DocumentMarker::MarkerTypes::Spelling());
}

void SpellChecker::AdvanceToNextMisspelling(bool start_before_selection) {
  DocumentLifecycle::DisallowTransitionScope disallow_transition(
      GetFrame().GetDocument()->Lifecycle());

  // The basic approach is to search in two phases - from the selection end to
  // the end of the doc, and then we wrap and search from the doc start to
  // (approximately) where we started.

  // Start at the end of the selection, search to edge of document. Starting at
  // the selection end makes repeated "check spelling" commands work.
  VisibleSelection selection(
      GetFrame().Selection().ComputeVisibleSelectionInDOMTree());
  Position spelling_search_start, spelling_search_end;
  Range::selectNodeContents(GetFrame().GetDocument(), spelling_search_start,
                            spelling_search_end);

  bool started_with_selection = false;
  if (selection.Start().AnchorNode()) {
    started_with_selection = true;
    if (start_before_selection) {
      VisiblePosition start(selection.VisibleStart());
      // We match AppKit's rule: Start 1 character before the selection.
      VisiblePosition one_before_start = PreviousPositionOf(start);
      spelling_search_start =
          (one_before_start.IsNotNull() ? one_before_start : start)
              .ToParentAnchoredPosition();
    } else {
      spelling_search_start = selection.VisibleEnd().ToParentAnchoredPosition();
    }
  }

  Position position = spelling_search_start;
  if (!IsEditablePosition(position)) {
    // This shouldn't happen in very often because the Spelling menu items
    // aren't enabled unless the selection is editable.  This can happen in Mail
    // for a mix of non-editable and editable content (like Stationary), when
    // spell checking the whole document before sending the message.  In that
    // case the document might not be editable, but there are editable pockets
    // that need to be spell checked.

    if (!GetFrame().GetDocument()->documentElement())
      return;
    position = CreateVisiblePosition(
                   FirstEditablePositionAfterPositionInRoot(
                       position, *GetFrame().GetDocument()->documentElement()))
                   .DeepEquivalent();
    if (position.IsNull())
      return;

    spelling_search_start = position.ParentAnchoredEquivalent();
    started_with_selection = false;  // won't need to wrap
  }

  // topNode defines the whole range we want to operate on
  ContainerNode* top_node = HighestEditableRoot(position);
  // TODO(yosin): |lastOffsetForEditing()| is wrong here if
  // |editingIgnoresContent(highestEditableRoot())| returns true, e.g. <table>
  spelling_search_end = Position::EditingPositionOf(
      top_node, EditingStrategy::LastOffsetForEditing(top_node));

  // If spellingSearchRange starts in the middle of a word, advance to the
  // next word so we start checking at a word boundary. Going back by one char
  // and then forward by a word does the trick.
  if (started_with_selection) {
    const Position& one_before_start =
        PreviousPositionOf(CreateVisiblePosition(spelling_search_start))
            .DeepEquivalent();
    if (one_before_start.IsNotNull() &&
        RootEditableElementOf(one_before_start) ==
            RootEditableElementOf(spelling_search_start)) {
      spelling_search_start =
          CreateVisiblePosition(EndOfWordPosition(one_before_start),
                                TextAffinity::kUpstreamIfPossible)
              .ToParentAnchoredPosition();
    }
    // else we were already at the start of the editable node
  }

  if (spelling_search_start == spelling_search_end)
    return;  // nothing to search in

  // We go to the end of our first range instead of the start of it, just to be
  // sure we don't get foiled by any word boundary problems at the start. It
  // means we might do a tiny bit more searching.
  Node* search_end_node_after_wrap = spelling_search_end.ComputeContainerNode();
  int search_end_offset_after_wrap =
      spelling_search_end.OffsetInContainerNode();

  std::pair<String, int> misspelled_item(String(), 0);
  String& misspelled_word = misspelled_item.first;
  int& misspelling_offset = misspelled_item.second;
  misspelled_item =
      FindFirstMisspelling(spelling_search_start, spelling_search_end);

  // If we did not find a misspelled word, wrap and try again (but don't bother
  // if we started at the beginning of the block rather than at a selection).
  if (started_with_selection && !misspelled_word) {
    spelling_search_start = Position::EditingPositionOf(top_node, 0);
    // going until the end of the very first chunk we tested is far enough
    spelling_search_end = Position::EditingPositionOf(
        search_end_node_after_wrap, search_end_offset_after_wrap);
    misspelled_item =
        FindFirstMisspelling(spelling_search_start, spelling_search_end);
  }

  if (misspelled_word.empty()) {
    SpellCheckPanelHostClient().UpdateSpellingUIWithMisspelledWord({});
  } else {
    // We found a misspelling. Select the misspelling, update the spelling
    // panel, and store a marker so we draw the red squiggle later.

    const EphemeralRange misspelling_range = CalculateCharacterSubrange(
        EphemeralRange(spelling_search_start, spelling_search_end),
        misspelling_offset, misspelled_word.length());
    GetFrame().Selection().SetSelectionAndEndTyping(
        SelectionInDOMTree::Builder()
            .SetBaseAndExtent(misspelling_range)
            .Build());
    GetFrame().Selection().RevealSelection();
    SpellCheckPanelHostClient().UpdateSpellingUIWithMisspelledWord(
        misspelled_word);
    GetFrame().GetDocument()->Markers().AddSpellingMarker(misspelling_range);
  }
}

void SpellChecker::ShowSpellingGuessPanel() {
  if (SpellCheckPanelHostClient().IsShowingSpellingUI()) {
    SpellCheckPanelHostClient().ShowSpellingUI(false);
    return;
  }

  AdvanceToNextMisspelling(true);
  SpellCheckPanelHostClient().ShowSpellingUI(true);
}

static void AddMarker(Document* document,
                      const EphemeralRange& checking_range,
                      DocumentMarker::MarkerType type,
                      int location,
                      int length,
                      const Vector<String>& descriptions) {
  DCHECK(type == DocumentMarker::kSpelling || type == DocumentMarker::kGrammar)
      << type;
  DCHECK_GT(length, 0);
  DCHECK_GE(location, 0);
  const EphemeralRange& range_to_mark =
      CalculateCharacterSubrange(checking_range, location, length);
  if (!SpellChecker::IsSpellCheckingEnabledAt(range_to_mark.StartPosition()))
    return;
  if (!SpellChecker::IsSpellCheckingEnabledAt(range_to_mark.EndPosition()))
    return;

  StringBuilder description;
  for (wtf_size_t i = 0; i < descriptions.size(); ++i) {
    if (i != 0)
      description.Append('\n');
    description.Append(descriptions[i]);
  }

  if (type == DocumentMarker::kSpelling) {
    document->Markers().AddSpellingMarker(range_to_mark,
                                          description.ToString());
    return;
  }

  DCHECK_EQ(type, DocumentMarker::kGrammar);
  document->Markers().AddGrammarMarker(range_to_mark, description.ToString());
}

void SpellChecker::MarkAndReplaceFor(
    SpellCheckRequest* request,
    const Vector<TextCheckingResult>& results) {
  TRACE_EVENT0("blink", "SpellChecker::markAndReplaceFor");
  DCHECK(request);
  if (!GetFrame().Selection().IsAvailable()) {
    // "editing/spelling/spellcheck-async-remove-frame.html" reaches here.
    return;
  }
  if (!request->IsValid())
    return;
  if (request->RootEditableElement()->GetDocument() !=
      GetFrame().Selection().GetDocument()) {
    // we ignore |request| made for another document.
    // "editing/spelling/spellcheck-sequencenum.html" and others reach here.
    return;
  }

  // TODO(editing-dev): The use of UpdateStyleAndLayout
  // needs to be audited.  See http://crbug.com/590369 for more details.
  GetFrame().GetDocument()->UpdateStyleAndLayout(
      DocumentUpdateReason::kSpellCheck);

  EphemeralRange checking_range(request->CheckingRange());

  // Abort marking if the content of the checking change has been modified.
  String current_content =
      PlainText(checking_range, TextIteratorBehavior::Builder()
                                    .SetEmitsObjectReplacementCharacter(true)
                                    .Build());
  if (current_content != request->GetText()) {
    // "editing/spelling/spellcheck-async-mutation.html" reaches here.
    return;
  }

  // Clear the stale markers.
  RemoveMarkers(checking_range, DocumentMarker::MarkerTypes::Misspelling());

  if (!results.size())
    return;

  const int checking_range_length = TextIterator::RangeLength(checking_range);
  for (const TextCheckingResult& result : results) {
    const int result_location = result.location;
    const int result_length = result.length;

    // Only mark misspelling if result falls within checking range.
    switch (result.decoration) {
      case kTextDecorationTypeSpelling:
        if (result_location < 0 ||
            result_location + result_length > checking_range_length)
          continue;
        AddMarker(GetFrame().GetDocument(), checking_range,
                  DocumentMarker::kSpelling, result_location, result_length,
                  result.replacements);
        continue;

      case kTextDecorationTypeGrammar:
        if (!CheckingRangeCovers(checking_range_length, result_location,
                                 result_length)) {
          continue;
        }
        DCHECK_GT(result_length, 0);
        DCHECK_GE(result_location, 0);
        for (const GrammarDetail& detail : result.details) {
          DCHECK_GT(detail.length, 0);
          DCHECK_GE(detail.location, 0);
          if (!CheckingRangeCovers(checking_range_length,
                                   result_location + detail.location,
                                   detail.length)) {
            continue;
          }
          AddMarker(GetFrame().GetDocument(), checking_range,
                    DocumentMarker::kGrammar, result_location + detail.location,
                    detail.length, result.replacements);
        }
        continue;
    }
    NOTREACHED();
  }
}

void SpellChecker::DidEndEditingOnTextField(Element* e) {
  TRACE_EVENT0("blink", "SpellChecker::didEndEditingOnTextField");

  // Remove markers when deactivating a selection in an <input type="text"/>.
  // Prevent new ones from appearing too.
  HTMLElement* inner_editor = ToTextControl(e)->InnerEditorElement();
  RemoveSpellingAndGrammarMarkers(*inner_editor);
}

void SpellChecker::RemoveSpellingAndGrammarMarkers(const HTMLElement& element,
                                                   ElementsType elements_type) {
  // TODO(editing-dev): The use of updateStyleAndLayoutIgnorePendingStylesheets
  // needs to be audited.  See http://crbug.com/590369 for more details.
  if (elements_type == ElementsType::kOnlyNonEditable) {
    GetFrame().GetDocument()->UpdateStyleAndLayoutTreeForElement(
        &element, DocumentUpdateReason::kSpellCheck);
  }

  for (Node& node : NodeTraversal::InclusiveDescendantsOf(element)) {
    auto* text_node = DynamicTo<Text>(node);
    if ((elements_type == ElementsType::kAll || !IsEditable(node)) &&
        text_node) {
      GetFrame().GetDocument()->Markers().RemoveMarkersForNode(
          *text_node, DocumentMarker::MarkerTypes::Misspelling());
    }
  }
}

DocumentMarkerGroup* SpellChecker::GetSpellCheckMarkerGroupUnderSelection()
    const {
  const VisibleSelection& selection =
      GetFrame().Selection().ComputeVisibleSelectionInDOMTree();
  if (selection.IsNone())
    return {};

  // Caret and range selections always return valid normalized ranges.
  const EphemeralRange& selection_range = FirstEphemeralRangeOf(selection);

  return GetFrame()
      .GetDocument()
      ->Markers()
      .FirstMarkerGroupIntersectingEphemeralRange(
          selection_range, DocumentMarker::MarkerTypes::Misspelling());
}

std::pair<String, String> SpellChecker::SelectMisspellingAsync() {
  const DocumentMarkerGroup* const marker_group =
      GetSpellCheckMarkerGroupUnderSelection();
  if (!marker_group)
    return {};

  const VisibleSelection& selection =
      GetFrame().Selection().ComputeVisibleSelectionInDOMTree();
  // Caret and range selections (one of which we must have since we found a
  // marker) always return valid normalized ranges.
  const EphemeralRange& selection_range =
      selection.ToNormalizedEphemeralRange();

  const EphemeralRange marker_range(marker_group->StartPosition(),
                                    marker_group->EndPosition());
  const String& marked_text = PlainText(marker_range);
  if (marked_text.StripWhiteSpace(&IsWhiteSpaceOrPunctuation) !=
      PlainText(selection_range).StripWhiteSpace(&IsWhiteSpaceOrPunctuation))
    return {};
  const Text* text_node =
      To<Text>(selection_range.StartPosition().ComputeContainerNode());
  const SpellCheckMarker* marker =
      To<SpellCheckMarker>(marker_group->GetMarkerForText(text_node));
  return std::make_pair(marked_text, marker->Description());
}

void SpellChecker::ReplaceMisspelledRange(const String& text) {
  const DocumentMarkerGroup* const marker_group =
      GetSpellCheckMarkerGroupUnderSelection();
  if (!marker_group)
    return;

  GetFrame().Selection().SetSelectionAndEndTyping(
      SelectionInDOMTree::Builder()
          .Collapse(marker_group->StartPosition())
          .Extend(marker_group->EndPosition())
          .Build());

  InsertTextAndSendInputEventsOfTypeInsertReplacementText(GetFrame(), text);
}

void SpellChecker::RespondToChangedSelection() {
  idle_spell_check_controller_->RespondToChangedSelection();
}

void SpellChecker::RespondToChangedContents() {
  idle_spell_check_controller_->RespondToChangedContents();
}

void SpellChecker::RespondToChangedEnablement(const HTMLElement& element,
                                              bool enabled) {
  if (enabled) {
    idle_spell_check_controller_->RespondToChangedEnablement();
  } else {
    RemoveSpellingAndGrammarMarkers(element);
    idle_spell_check_controller_->SetSpellCheckingDisabled(element);
  }
}

void SpellChecker::RemoveSpellingMarkers() {
  GetFrame().GetDocument()->Markers().RemoveMarkersOfTypes(
      DocumentMarker::MarkerTypes::Misspelling());
}

void SpellChecker::RemoveSpellingMarkersUnderWords(
    const Vector<String>& words) {
  DocumentMarkerController& marker_controller =
      GetFrame().GetDocument()->Markers();
  marker_controller.RemoveSpellingMarkersUnderWords(words);
}

static Node* FindFirstMarkable(Node* node) {
  while (node) {
    LayoutObject* layout_object = node->GetLayoutObject();
    if (!layout_object)
      return nullptr;
    if (layout_object->IsText())
      return node;
    if (layout_object->IsTextControl()) {
      node = To<TextControlElement>(node)
                 ->VisiblePositionForIndex(1)
                 .DeepEquivalent()
                 .AnchorNode();
    } else if (node->hasChildren()) {
      node = node->firstChild();
    } else {
      node = node->nextSibling();
    }
  }

  return nullptr;
}

bool SpellChecker::SelectionStartHasMarkerFor(
    DocumentMarker::MarkerType marker_type,
    int from,
    int length) const {
  Node* node = FindFirstMarkable(GetFrame()
                                     .Selection()
                                     .ComputeVisibleSelectionInDOMTree()
                                     .Start()
                                     .AnchorNode());
  auto* text_node = DynamicTo<Text>(node);
  if (!text_node)
    return false;

  unsigned start_offset = static_cast<unsigned>(from);
  unsigned end_offset = static_cast<unsigned>(from + length);
  DocumentMarkerVector markers =
      GetFrame().GetDocument()->Markers().MarkersFor(*text_node);
  for (wtf_size_t i = 0; i < markers.size(); ++i) {
    DocumentMarker* marker = markers[i];
    if (marker->StartOffset() <= start_offset &&
        end_offset <= marker->EndOffset() && marker->GetType() == marker_type)
      return true;
  }

  return false;
}

void SpellChecker::RemoveMarkers(const EphemeralRange& range,
                                 DocumentMarker::MarkerTypes marker_types) {
  DCHECK(!GetFrame().GetDocument()->NeedsLayoutTreeUpdate());

  if (range.IsNull())
    return;

  GetFrame().GetDocument()->Markers().RemoveMarkersInRange(range, marker_types);
}

void SpellChecker::Trace(Visitor* visitor) const {
  visitor->Trace(window_);
  visitor->Trace(spell_check_requester_);
  visitor->Trace(idle_spell_check_controller_);
}

Vector<TextCheckingResult> SpellChecker::FindMisspellings(const String& text) {
  Vector<UChar> characters;
  text.AppendTo(characters);

  TextBreakIterator* iterator = WordBreakIterator(characters);
  if (!iterator)
    return Vector<TextCheckingResult>();

  Vector<TextCheckingResult> results;
  int word_start = iterator->current();
  while (word_start >= 0) {
    int word_end = iterator->next();
    if (word_end < 0)
      break;
    auto word_length = static_cast<size_t>(word_end - word_start);
    size_t misspelling_location = 0;
    size_t misspelling_length = 0;
    if (WebTextCheckClient* text_checker_client = GetTextCheckerClient()) {
      // SpellCheckWord will write (0, 0) into the output vars, which is what
      // our caller expects if the word is spelled correctly.
      text_checker_client->CheckSpelling(
          String(base::span(characters)
                     .subspan(static_cast<size_t>(word_start), word_length)),
          misspelling_location, misspelling_length, nullptr);
    } else {
      misspelling_location = 0;
    }
    if (misspelling_length > 0) {
      DCHECK_GE(misspelling_location, 0u);
      DCHECK_LE(misspelling_location + misspelling_length, word_length);
      TextCheckingResult misspelling;
      misspelling.decoration = kTextDecorationTypeSpelling;
      misspelling.location =
          base::checked_cast<int>(word_start + misspelling_location);
      misspelling.length = base::checked_cast<int>(misspelling_length);
      results.push_back(misspelling);
    }
    word_start = word_end;
  }
  return results;
}

std::pair<String, int> SpellChecker::FindFirstMisspelling(const Position& start,
                                                          const Position& end) {
  String misspelled_word;

  // Initialize out parameters; they will be updated if we find something to
  // return.
  String first_found_item;
  int first_found_offset = 0;

  // Expand the search range to encompass entire paragraphs, since text checking
  // needs that much context. Determine the character offset from the start of
  // the paragraph to the start of the original search range, since we will want
  // to ignore results in this area.
  EphemeralRange paragraph_range =
      ExpandToParagraphBoundary(EphemeralRange(start, start));
  Position paragraph_start = paragraph_range.StartPosition();
  Position paragraph_end = paragraph_range.EndPosition();

  const int total_range_length =
      TextIterator::RangeLength(paragraph_start, end);
  const int range_start_offset =
      TextIterator::RangeLength(paragraph_start, start);
  int total_length_processed = 0;

  bool first_iteration = true;
  bool last_iteration = false;
  while (total_length_processed < total_range_length) {
    // Iterate through the search range by paragraphs, checking each one for
    // spelling.
    int current_length =
        TextIterator::RangeLength(paragraph_start, paragraph_end);
    int current_start_offset = first_iteration ? range_start_offset : 0;
    int current_end_offset = current_length;
    if (InSameParagraph(CreateVisiblePosition(paragraph_start),
                        CreateVisiblePosition(end))) {
      // Determine the character offset from the end of the original search
      // range to the end of the paragraph, since we will want to ignore results
      // in this area.
      current_end_offset = TextIterator::RangeLength(paragraph_start, end);
      last_iteration = true;
    }
    if (current_start_offset < current_end_offset) {
      String paragraph_string = PlainText(paragraph_range);
      if (paragraph_string.length() > 0) {
        int spelling_location = 0;

        Vector<TextCheckingResult> results = FindMisspellings(paragraph_string);

        for (unsigned i = 0; i < results.size(); i++) {
          const TextCheckingResult* result = &results[i];
          if (result->location >= current_start_offset &&
              result->location + result->length <= current_end_offset) {
            DCHECK_GT(result->length, 0);
            DCHECK_GE(result->location, 0);
            spelling_location = result->location;
            misspelled_word =
                paragraph_string.Substring(result->location, result->length);
            DCHECK(misspelled_word.length());
            break;
          }
        }

        if (!misspelled_word.empty()) {
          int spelling_offset = spelling_location - current_start_offset;
          if (!first_iteration)
            spelling_offset +=
                TextIterator::RangeLength(start, paragraph_start);
          first_found_offset = spelling_offset;
          first_found_item = misspelled_word;
          break;
        }
      }
    }
    if (last_iteration ||
        total_length_processed + current_length >= total_range_length)
      break;
    Position new_paragraph_start =
        StartOfNextParagraph(CreateVisiblePosition(paragraph_end))
            .DeepEquivalent();
    if (new_paragraph_start.IsNull())
      break;

    paragraph_range = ExpandToParagraphBoundary(
        EphemeralRange(new_paragraph_start, new_paragraph_start));
    paragraph_start = paragraph_range.StartPosition();
    paragraph_end = paragraph_range.EndPosition();
    first_iteration = false;
    total_length_processed += current_length;
  }
  return std::make_pair(first_found_item, first_found_offset);
}

void SpellChecker::ElementRemoved(Element* element) {
  GetIdleSpellCheckController().GetColdModeRequester().ElementRemoved(element);
}

// static
bool SpellChecker::IsSpellCheckingEnabledAt(const Position& position) {
  if (position.IsNull())
    return false;
  if (TextControlElement* text_control = EnclosingTextControl(position)) {
    if (auto* input = DynamicTo<HTMLInputElement>(text_control)) {
      if (!input->IsFocusedElementInDocument())
        return false;
    }
  }
  HTMLElement* element =
      Traversal<HTMLElement>::FirstAncestorOrSelf(*position.AnchorNode());
  return element && element->IsSpellCheckingEnabled() && IsEditable(*element);
}

STATIC_ASSERT_ENUM(kWebTextDecorationTypeSpelling, kTextDecorationTypeSpelling);
STATIC_ASSERT_ENUM(kWebTextDecorationTypeGrammar, kTextDecorationTypeGrammar);

}  // namespace blink
```