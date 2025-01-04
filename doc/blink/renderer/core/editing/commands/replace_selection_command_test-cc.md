Response:
Let's break down the thought process for analyzing this C++ test file.

1. **Understand the Core Purpose:** The file name `replace_selection_command_test.cc` immediately suggests its primary function: testing the `ReplaceSelectionCommand` class. This class likely deals with replacing selected content in an editor.

2. **Identify Key Imports:**  Scan the `#include` directives. This gives hints about the functionality being tested and the context.
    * `replace_selection_command.h`:  Confirms we're testing this specific command class.
    * `testing/gtest/include/gtest/gtest.h`:  Indicates it's a unit test file using the Google Test framework.
    * `core/dom/*`:  Suggests DOM manipulation is involved (Document, DocumentFragment, Text, Element).
    * `core/editing/*`:  Points to editing-related functionalities like Selection, Position, VisibleSelection.
    * `core/frame/*`: Implies interactions with the frame structure of the browser (LocalFrame, LocalFrameView, Settings).
    * `core/html_names.h`:  Likely used for creating HTML elements by tag name.
    * `core/layout/*`: Suggests interactions with the layout tree (LayoutView).
    * `core/testing/editing_test_base.h`, `core/testing/dummy_page_holder.h`:  Indicate this test runs within a simulated browser environment.
    * `platform/bindings/exception_state.h`: Might be relevant for handling errors during DOM operations, although not prominently used in this specific file.
    * `<memory>`: Used for smart pointers (like `std::unique_ptr`, although not explicitly used in the snippets, the broader Chromium codebase uses them extensively, and the `MakeGarbageCollected` function returns something similar in concept).

3. **Analyze the Test Structure:** Observe the use of `TEST_F(ReplaceSelectionCommandTest, ...)` macros. This is standard Google Test syntax for creating test cases within a fixture class. The fixture `ReplaceSelectionCommandTest` inherits from `EditingTestBase`, which likely provides helper methods for setting up the DOM and selections.

4. **Examine Individual Test Cases:**  Go through each `TEST_F` block and understand its intent. The comments often provide valuable clues (e.g., "This is a regression test for...").

    * **`pastingEmptySpan`:**  Focuses on the behavior when pasting an empty `<span>`. It checks if this results in any DOM changes. This relates to how the editor handles potentially redundant elements.
    * **`pasteSpanInText`:** Tests pasting a `<span>` containing a `<div>` into existing text. It's a quirk mode scenario, highlighting potential differences in handling in different browser modes.
    * **`TextAutosizingDoesntInflateText`:** Specifically addresses a bug where text autosizing might incorrectly split elements during replacement. It sets up a scenario with autosizing enabled and checks if the replacement preserves the structure.
    * **`TrailingNonVisibleTextCrash`:**  A crash regression test. It tries to replace a selection with content that has trailing whitespace and verifies that no crash occurs.
    * **`CrashWithNoSelection`:** Another crash regression test, this time focusing on the case where there's no active selection.
    * **`SmartPlainTextPaste`:** Tests the "smart paste" functionality, where extra spacing might be added when pasting plain text. This is relevant to user experience.
    * **`TableAndImages`:**  Aims to prevent crashes when inserting images within a table structure at a specific location.
    * **`InsertImageAfterEmptyBlockInInline`:** Checks correct insertion of an image after an empty block element within an inline element.
    * **`InsertImageAfterWhiteSpace`:**  Focuses on inserting an image after whitespace in a button context.
    * **`InsertImageInNonEditableBlock1` and `InsertImageInNonEditableBlock2`:** These tests cover scenarios where an insertion point is within an editable area nested inside a non-editable block. They verify that the insertion happens correctly, potentially creating line breaks.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** Consider how the tested C++ code relates to these front-end technologies.

    * **HTML:** The tests heavily manipulate HTML structure using methods like `SetBodyContent`, `ParseHTML`, `CreateRawElement`. The assertions (`EXPECT_EQ`) often compare the resulting `innerHTML` of the body, which directly reflects the HTML structure.
    * **JavaScript:** While this is a C++ test, the functionality being tested is directly triggered by user actions in a web browser, many of which can be initiated or manipulated via JavaScript (e.g., `document.execCommand('insertHTML', ...)`, setting `designMode`). The tested code *implements* the behavior that JavaScript might invoke.
    * **CSS:** The `TextAutosizingDoesntInflateText` test explicitly mentions and tests the influence of CSS properties (specifically text autosizing). The `kMatchStyle` option in other tests also implies an awareness of CSS styling during the replacement.

6. **Infer Logic and Assumptions:**  For each test, deduce the likely input and expected output. For example, in `pastingEmptySpan`, the assumption is pasting an empty span *should not* change the DOM. In `pasteSpanInText`, the logic is about correctly inserting the pasted content at the cursor position within existing tags, respecting the quirks mode.

7. **Identify Potential User Errors:** Think about how a user interacting with a web page might trigger the code being tested and what common mistakes they could make. Pasting is a primary trigger. Selecting text and then pasting is a fundamental user interaction. Trying to paste into unexpected locations (like within a non-editable area) is another.

8. **Trace User Actions (Debugging Clues):** Consider the sequence of user events that could lead to the execution of `ReplaceSelectionCommand`. This helps understand how to reproduce issues. Typing, selecting text with the mouse, using keyboard shortcuts for copying and pasting, or JavaScript manipulating the selection or inserting content are all relevant.

9. **Consider Edge Cases and Regression Prevention:** Notice that many tests are explicitly labeled as regression tests. This means they are designed to prevent previously fixed bugs from reappearing. This highlights the importance of testing edge cases and scenarios where things might go wrong.

10. **Focus on the `ReplaceSelectionCommand`'s Responsibilities:**  Throughout the analysis, keep in mind the core task of `ReplaceSelectionCommand`: taking a fragment of HTML (or plain text) and inserting it into the DOM, replacing the current selection. The various test cases explore different aspects of this central responsibility, such as handling empty content, nested elements, styling, and potential crash scenarios.
这个C++源代码文件 `replace_selection_command_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `ReplaceSelectionCommand` 类的功能。 `ReplaceSelectionCommand` 的作用是在编辑器中替换当前选定的内容。

**以下是该文件的主要功能：**

1. **单元测试 `ReplaceSelectionCommand` 的各种场景:**  该文件包含了多个使用 Google Test 框架编写的测试用例 (`TEST_F`)，每个测试用例都针对 `ReplaceSelectionCommand` 在不同情况下的行为进行验证。

2. **模拟和验证 DOM 操作:**  测试用例会设置特定的 DOM 结构（使用 `SetBodyContent`），模拟用户选择内容（使用 `Selection().SetSelection`），然后创建一个要插入的 `DocumentFragment`，并使用 `ReplaceSelectionCommand` 执行替换操作。最后，通过断言 (`EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`) 检查 DOM 是否按预期被修改。

3. **回归测试:**  许多测试用例都是为了解决之前发现的 bug 而编写的回归测试，以确保这些 bug 不会再次出现。这些测试用例的命名通常会包含关联的 bug 编号 (例如 `crbug.com/619131`)。

4. **测试不同的 `ReplaceSelectionCommand` 选项:**  `ReplaceSelectionCommand` 接受一个 `CommandOptions` 参数，用于控制替换行为。测试用例会尝试不同的选项组合，例如：
    * `kPreventNesting`: 防止在某些情况下嵌套元素。
    * `kSanitizeFragment`: 清理要插入的 HTML 片段。
    * `kSelectReplacement`: 替换后选中插入的内容。
    * `kSmartReplace`: 智能替换，例如在粘贴时添加空格。
    * `kMatchStyle`: 尝试匹配插入位置的样式。

**与 JavaScript, HTML, CSS 的关系：**

`ReplaceSelectionCommand` 的功能直接影响用户在网页编辑器中通过 JavaScript 操作内容、编辑 HTML 结构和应用 CSS 样式时的行为。

* **JavaScript:** JavaScript 代码可以使用 `document.execCommand('insertHTML', ...)` 或 `document.execCommand('paste', ...)` 等命令来触发内容替换操作。这些命令最终可能会调用到 Blink 引擎的 `ReplaceSelectionCommand`。
    * **举例:** 用户在富文本编辑器中选中一段文字，然后按下 Ctrl+V 粘贴内容。浏览器会将粘贴事件传递给渲染引擎，引擎可能会创建一个 `ReplaceSelectionCommand` 来将剪贴板的内容插入到选定位置。JavaScript 也可以通过编程方式创建和执行类似的命令。

* **HTML:** `ReplaceSelectionCommand` 的核心功能是操作 HTML 结构。它负责将新的 HTML 片段插入到现有的 DOM 树中，替换选定的部分。测试用例中大量使用了 HTML 标签和属性，例如 `<span>`, `<div>`, `<b>`, `<table>`, `<img>`, 以及 `contenteditable` 属性。
    * **举例:** 测试用例 `pasteSpanInText` 模拟了在 `<b>text</b>` 中间粘贴 `<span><div>bar</div></span>` 的场景，验证了 HTML 结构是否正确地变成了 `<b>t</b>bar<b>ext</b>`。

* **CSS:**  `ReplaceSelectionCommand` 的某些选项会考虑 CSS 样式。例如，`kMatchStyle` 选项会尝试让插入的内容继承或匹配周围的样式。
    * **举例:** 测试用例 `TextAutosizingDoesntInflateText` 验证了在启用文本自动调整大小的情况下，替换操作不会因为样式差异而错误地拆分元素。这涉及到字体大小等 CSS 属性。

**逻辑推理、假设输入与输出:**

让我们以测试用例 `pastingEmptySpan` 为例进行逻辑推理：

* **假设输入:**
    * 初始 HTML 内容为 "foo"。
    * 用户在 "foo" 的开头 (位置 0) 创建一个空的选择。
    * 要插入的 HTML 片段是一个空的 `<span>` 元素。
    * 使用了 `kPreventNesting`, `kSanitizeFragment`, `kSelectReplacement`, `kSmartReplace` 等选项。
* **逻辑推理:** 由于要插入的是一个空的 `<span>`，并且设置了 `kPreventNesting` 和 `kSanitizeFragment`，引擎可能会认为插入这个空元素没有实际意义，因此应该避免任何 DOM 结构的修改。
* **预期输出:**  DOM 结构保持不变，仍然是 "foo"。

**用户或编程常见的使用错误:**

1. **在非 `contenteditable` 元素中尝试替换:** 如果用户或 JavaScript 代码尝试在一个没有 `contenteditable` 属性的元素中进行内容替换，`ReplaceSelectionCommand` 可能不会执行任何操作，或者可能会抛出异常。
    * **举例:**  如果页面结构是 `<div>Static Content</div>`，并且尝试选中 "Static" 并粘贴内容，通常不会成功，除非通过一些特殊手段或者 JavaScript 代码强制修改了 DOM。

2. **粘贴或插入未经过适当清理的 HTML 片段:**  如果插入的 HTML 片段包含恶意脚本或不规范的标签，可能会导致安全问题或页面渲染错误。`ReplaceSelectionCommand` 的 `kSanitizeFragment` 选项可以帮助缓解这个问题，但开发者仍然需要在其他层面进行输入验证和清理。
    * **举例:** 用户复制了一段包含 `<script>alert('XSS');</script>` 的文本并粘贴到编辑器中。如果没有适当的清理，这段脚本可能会被执行，导致跨站脚本攻击。

3. **在复杂的嵌套结构中进行替换，导致意外的 DOM 结构:** 在复杂的 HTML 结构中进行替换操作，尤其是在涉及到表格、列表等元素时，可能会导致意外的 DOM 结构。测试用例中的 `TableAndImages` 旨在防止这种情况下的崩溃。
    * **举例:** 用户在一个复杂的表格单元格中选中部分内容并粘贴，可能会导致表格结构错乱。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户打开一个网页，该网页包含可编辑区域:**  例如，一个带有 `<div contenteditable="true"></div>` 的元素，或者使用像 `<textarea>` 或富文本编辑器。

2. **用户在可编辑区域中进行选择:**  可以使用鼠标拖动或者键盘快捷键 (Shift + 方向键) 来选中一部分文本或元素。

3. **用户执行替换操作:**  这通常可以通过以下方式触发：
    * **粘贴 (Ctrl+V 或右键点击 -> 粘贴):**  浏览器会从剪贴板获取内容，并尝试替换当前选定的内容。
    * **输入文本 (如果当前有选定的内容):**  用户开始输入新的字符，选定的内容会被新输入的字符替换。
    * **使用 JavaScript 代码:**  JavaScript 可以调用 `document.execCommand('insertHTML', ...)` 或其他 DOM 操作方法来替换选定的内容。例如，富文本编辑器通常会使用 JavaScript 来处理各种编辑操作。

4. **浏览器接收到替换指令:**  浏览器内核 (例如 Chromium 的 Blink 引擎) 会接收到用户的操作或 JavaScript 的指令，需要执行内容替换。

5. **创建并执行 `ReplaceSelectionCommand`:**  Blink 引擎会创建一个 `ReplaceSelectionCommand` 对象，并将要插入的内容和相关的选项传递给它。

6. **`ReplaceSelectionCommand::Apply()` 方法被调用:**  该方法会执行实际的 DOM 操作，将新的内容插入到文档中，替换选定的部分。这个过程会涉及到对 DOM 树的修改，例如插入新的节点、删除旧的节点等。

7. **测试文件模拟上述步骤:** `replace_selection_command_test.cc` 中的测试用例通过代码模拟了这些步骤，例如设置 `designMode("on")` 来启用编辑模式，使用 `Selection().SetSelection()` 来模拟用户选择，创建 `DocumentFragment` 来表示要插入的内容，并最终调用 `command->Apply()` 来模拟执行替换操作。通过检查最终的 DOM 结构，可以验证 `ReplaceSelectionCommand` 的行为是否符合预期。

总而言之，`replace_selection_command_test.cc` 是一个关键的测试文件，用于确保 Blink 引擎在处理内容替换操作时的正确性和稳定性，这直接关系到用户在网页上进行编辑操作时的体验。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/replace_selection_command_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/commands/replace_selection_command.h"

#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/document_fragment.h"
#include "third_party/blink/renderer/core/dom/parser_content_policy.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/frame/local_frame_view.h"
#include "third_party/blink/renderer/core/frame/settings.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/core/layout/layout_view.h"
#include "third_party/blink/renderer/core/testing/dummy_page_holder.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

#include <memory>

namespace blink {

class ReplaceSelectionCommandTest : public EditingTestBase {};

// This is a regression test for https://crbug.com/619131
TEST_F(ReplaceSelectionCommandTest, pastingEmptySpan) {
  GetDocument().setDesignMode("on");
  SetBodyContent("foo");

  LocalFrame* frame = GetDocument().GetFrame();
  frame->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(GetDocument().body(), 0))
          .Build(),
      SetSelectionOptions());

  DocumentFragment* fragment = GetDocument().createDocumentFragment();
  fragment->AppendChild(GetDocument().CreateRawElement(html_names::kSpanTag));

  // |options| are taken from |Editor::replaceSelectionWithFragment()| with
  // |selectReplacement| and |smartReplace|.
  ReplaceSelectionCommand::CommandOptions options =
      ReplaceSelectionCommand::kPreventNesting |
      ReplaceSelectionCommand::kSanitizeFragment |
      ReplaceSelectionCommand::kSelectReplacement |
      ReplaceSelectionCommand::kSmartReplace;
  auto* command = MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), fragment, options);

  EXPECT_TRUE(command->Apply()) << "the replace command should have succeeded";
  EXPECT_EQ("foo", GetDocument().body()->innerHTML()) << "no DOM tree mutation";
}

// This is a regression test for https://crbug.com/668808
TEST_F(ReplaceSelectionCommandTest, pasteSpanInText) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  GetDocument().setDesignMode("on");
  SetBodyContent("<b>text</b>");

  Element* b_element = GetDocument().QuerySelector(AtomicString("b"));
  LocalFrame* frame = GetDocument().GetFrame();
  frame->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(b_element->firstChild(), 1))
          .Build(),
      SetSelectionOptions());

  DocumentFragment* fragment = GetDocument().createDocumentFragment();
  fragment->ParseHTML("<span><div>bar</div></span>", b_element);

  ReplaceSelectionCommand::CommandOptions options = 0;
  auto* command = MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), fragment, options);

  EXPECT_TRUE(command->Apply()) << "the replace command should have succeeded";
  EXPECT_EQ("<b>t</b>bar<b>ext</b>", GetDocument().body()->innerHTML())
      << "'bar' should have been inserted";
}

// Helper function to set autosizing multipliers on a document.
bool SetTextAutosizingMultiplier(Document* document, float multiplier) {
  bool multiplier_set = false;
  for (LayoutObject* layout_object = document->GetLayoutView(); layout_object;
       layout_object = layout_object->NextInPreOrder()) {
    if (layout_object->Style()) {
      ComputedStyleBuilder builder(layout_object->StyleRef());
      builder.SetTextAutosizingMultiplier(multiplier);
      layout_object->SetStyle(builder.TakeStyle(),
                              LayoutObject::ApplyStyleChanges::kNo);
      multiplier_set = true;
    }
  }
  return multiplier_set;
}

// This is a regression test for https://crbug.com/768261
TEST_F(ReplaceSelectionCommandTest, TextAutosizingDoesntInflateText) {
  GetDocument().GetSettings()->SetTextAutosizingEnabled(true);
  GetDocument().setDesignMode("on");
  SetBodyContent("<div><span style='font-size: 12px;'>foo bar</span></div>");
  SetTextAutosizingMultiplier(&GetDocument(), 2.0);

  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Element* span = GetDocument().QuerySelector(AtomicString("span"));

  // Select "bar".
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(span->firstChild(), 4))
          .Extend(Position(span->firstChild(), 7))
          .Build(),
      SetSelectionOptions());

  DocumentFragment* fragment = GetDocument().createDocumentFragment();
  fragment->ParseHTML("baz", span);

  ReplaceSelectionCommand::CommandOptions options =
      ReplaceSelectionCommand::kMatchStyle;

  auto* command = MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), fragment, options);

  EXPECT_TRUE(command->Apply()) << "the replace command should have succeeded";
  // The span element should not have been split to increase the font size.
  EXPECT_EQ(1u, div->CountChildren());
}

// This is a regression test for https://crbug.com/781282
TEST_F(ReplaceSelectionCommandTest, TrailingNonVisibleTextCrash) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(SetSelectionTextToBody("<div>^foo|</div>"),
                           SetSelectionOptions());

  DocumentFragment* fragment = GetDocument().createDocumentFragment();
  fragment->ParseHTML("<div>bar</div> ",
                      GetDocument().QuerySelector(AtomicString("div")));
  ReplaceSelectionCommand::CommandOptions options = 0;
  auto* command = MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), fragment, options);

  // Crash should not occur on applying ReplaceSelectionCommand
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ("<div>bar</div>|<br>", GetSelectionTextFromBody());
}

// This is a regression test for https://crbug.com/796840
TEST_F(ReplaceSelectionCommandTest, CrashWithNoSelection) {
  GetDocument().setDesignMode("on");
  SetBodyContent("<div></div>");
  ReplaceSelectionCommand::CommandOptions options = 0;
  auto* command = MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), nullptr, options);

  // Crash should not occur on applying ReplaceSelectionCommand
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ("<div></div>", GetSelectionTextFromBody());
}

// http://crbug.com/877127
TEST_F(ReplaceSelectionCommandTest, SmartPlainTextPaste) {
  // After typing "abc", Enter, "def".
  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>abc<div>def</div>|</div>"),
      SetSelectionOptions());
  DocumentFragment& fragment = *GetDocument().createDocumentFragment();
  fragment.appendChild(Text::Create(GetDocument(), "XYZ"));
  const ReplaceSelectionCommand::CommandOptions options =
      ReplaceSelectionCommand::kPreventNesting |
      ReplaceSelectionCommand::kSanitizeFragment |
      ReplaceSelectionCommand::kMatchStyle |
      ReplaceSelectionCommand::kSmartReplace;
  auto& command = *MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), &fragment, options,
      InputEvent::InputType::kInsertFromPaste);

  EXPECT_TRUE(command.Apply());
  // Smart paste inserts a space before pasted text.
  EXPECT_EQ("<div contenteditable>abc<div>def XYZ|</div></div>",
            GetSelectionTextFromBody());
}

// http://crbug.com/1155687
TEST_F(ReplaceSelectionCommandTest, TableAndImages) {
  GetDocument().setDesignMode("on");
  SetBodyContent("<table>&#x20;<tbody></tbody>&#x20;</table>");
  Element* tbody = GetDocument().QuerySelector(AtomicString("tbody"));
  tbody->AppendChild(GetDocument().CreateRawElement(html_names::kImgTag));
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(tbody, 1)).Build(),
      SetSelectionOptions());

  DocumentFragment* fragment = GetDocument().createDocumentFragment();
  fragment->AppendChild(GetDocument().CreateRawElement(html_names::kImgTag));
  auto& command = *MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), fragment, ReplaceSelectionCommand::kPreventNesting,
      InputEvent::InputType::kNone);

  // Should not crash
  EXPECT_TRUE(command.Apply());
  EXPECT_EQ("<table> <tbody><img><img>|</tbody> </table>",
            GetSelectionTextFromBody());
}

// https://crbug.com/1186610
TEST_F(ReplaceSelectionCommandTest, InsertImageAfterEmptyBlockInInline) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(SetSelectionTextToBody("<span><div></div>|a</span>"),
                           SetSelectionOptions());

  DocumentFragment& fragment = *GetDocument().createDocumentFragment();
  fragment.appendChild(GetDocument().CreateRawElement(html_names::kImgTag));
  auto& command = *MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), &fragment, ReplaceSelectionCommand::kPreventNesting,
      InputEvent::InputType::kNone);

  // Should not crash
  EXPECT_TRUE(command.Apply());
  EXPECT_EQ("<span><div></div></span><img>|<span>a</span>",
            GetSelectionTextFromBody());
}

// https://crbug.com/1173134
TEST_F(ReplaceSelectionCommandTest, InsertImageAfterWhiteSpace) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<button><div></div><svg></svg>&#x20;|</button>x<input>"),
      SetSelectionOptions());

  DocumentFragment& fragment = *GetDocument().createDocumentFragment();
  fragment.appendChild(GetDocument().CreateRawElement(html_names::kImgTag));
  auto& command = *MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), &fragment, ReplaceSelectionCommand::kPreventNesting,
      InputEvent::InputType::kNone);

  // Should not crash
  EXPECT_TRUE(command.Apply());
  EXPECT_EQ("<button><div></div><svg></svg></button><img>|x<input>",
            GetSelectionTextFromBody());
}

// https://crbug.com/1246674
TEST_F(ReplaceSelectionCommandTest, InsertImageInNonEditableBlock1) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<div contenteditable=\"false\"><span contenteditable>"
          "a|b</span></div>"),
      SetSelectionOptions());

  DocumentFragment& fragment = *GetDocument().createDocumentFragment();
  fragment.appendChild(GetDocument().CreateRawElement(html_names::kImgTag));
  auto& command = *MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), &fragment, ReplaceSelectionCommand::kPreventNesting,
      InputEvent::InputType::kNone);

  // Should not crash
  EXPECT_TRUE(command.Apply());
  EXPECT_EQ(
      "<div contenteditable=\"false\"><span contenteditable>"
      "a<img>|<br>b</span></div>",
      GetSelectionTextFromBody());
}

// https://crbug.com/1246674
TEST_F(ReplaceSelectionCommandTest, InsertImageInNonEditableBlock2) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody("<strong xml:space><div contenteditable=\"false\">"
                             "<span contenteditable><div>a|b</div></span>"
                             "</div></strong>"),
      SetSelectionOptions());

  DocumentFragment& fragment = *GetDocument().createDocumentFragment();
  fragment.appendChild(GetDocument().CreateRawElement(html_names::kImgTag));
  auto& command = *MakeGarbageCollected<ReplaceSelectionCommand>(
      GetDocument(), &fragment, ReplaceSelectionCommand::kPreventNesting,
      InputEvent::InputType::kNone);

  // Should not crash
  EXPECT_TRUE(command.Apply());
  EXPECT_EQ(
      "<strong xml:space><div contenteditable=\"false\">"
      "<span contenteditable><div>a</div><img>|<div>b</div></span>"
      "</div></strong>",
      GetSelectionTextFromBody());
}
}  // namespace blink

"""

```