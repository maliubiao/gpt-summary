Response:
My thinking process to analyze the C++ test file and generate the detailed explanation would go like this:

1. **Understand the Core Purpose:** The filename `insert_text_command_test.cc` immediately tells me this file is for testing the `InsertTextCommand` class. The `.cc` extension signifies C++ code within the Chromium project. The `test` suffix confirms its testing nature.

2. **Identify the Testing Framework:** The presence of `TEST_F` macros and the inclusion of `editing_test_base.h` strongly indicates this uses the standard Chromium testing infrastructure built upon Google Test.

3. **Analyze Individual Test Cases:** I'd go through each `TEST_F` block sequentially. For each test, I'd:

    * **Read the Test Name:** The test name (e.g., `WithTypingStyle`, `InsertChar`) often provides a high-level description of what's being tested.

    * **Examine the Setup:**  Look for lines like `SetBodyContent(...)`, `Selection().SetSelection(...)`, `GetDocument().execCommand(...)`. These lines set up the initial DOM structure and selection state – the *input* to the `InsertTextCommand`.

    * **Identify the Action:** The core action is always `GetDocument().execCommand("insertText", ...)`. This is the trigger for the `InsertTextCommand` being tested.

    * **Analyze the Assertion:** The `EXPECT_EQ(...)` lines are crucial. They define the *expected output* after the `InsertTextCommand` is executed. I'd pay close attention to the expected HTML structure and the final selection position.

    * **Look for Special Conditions or Edge Cases:** Some tests explicitly mention crbug.com links, which often point to specific bug fixes being tested. Other tests might set specific styles (`white-space:pre`) or document modes (`Document::kQuirksMode`). These indicate the test is targeting a particular scenario.

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**

    * **HTML:** The `SetBodyContent` and `EXPECT_EQ` lines directly deal with HTML structure. I'd analyze how the inserted text affects the DOM. Pay attention to tag creation, attribute changes, and text node modifications.

    * **CSS:**  Tests involving styles (like `white-space:pre`) demonstrate the interaction between the command and CSS rendering rules. The `WithTypingStyle` test explicitly checks how inline styles are applied during text insertion.

    * **JavaScript:** While this specific file doesn't directly execute JavaScript, the underlying `execCommand` function is the same one exposed to JavaScript. I'd consider how a user interacting with a web page via JavaScript (e.g., typing in a `contenteditable` div) would trigger similar behavior.

5. **Infer Logical Reasoning and Assumptions:**

    * **Input/Output:**  For each test, I'd clearly define the "before" (initial DOM and selection) and "after" (expected DOM and selection) states. The inserted text is a key part of the input.

    * **Implicit Assumptions:** I'd note any assumptions made by the tests, like the presence of specific DOM elements or the selection being within a `contenteditable` region.

6. **Identify Potential User/Programming Errors:**

    * **User Errors:** Consider how a user typing in a web page might encounter the scenarios tested. Examples: Inserting text at the beginning/end of elements, inserting special characters (spaces, tabs), pasting text, selecting across multiple lines.

    * **Programming Errors:**  Think about potential mistakes in the `InsertTextCommand` implementation that these tests aim to catch. Examples: Incorrectly splitting text nodes, failing to apply styles, mishandling whitespace, crashing in specific DOM structures.

7. **Trace User Steps for Debugging:**

    * I would imagine a user interacting with a webpage. How would they get into the specific selection states tested?  This involves understanding how users select text, place the cursor, and trigger text insertion (typing, pasting). I'd break down the steps into a sequence of user actions.

8. **Structure the Explanation:**  Finally, I'd organize my findings into a clear and structured explanation, addressing each part of the prompt:

    * **File Function:** A concise summary of the file's purpose.
    * **Relationship to Web Technologies:**  Specific examples linking the tests to HTML, CSS, and JavaScript concepts.
    * **Logical Reasoning (Input/Output):** For key tests, provide concrete examples of the initial state, the inserted text, and the expected resulting state.
    * **User/Programming Errors:** Illustrate common mistakes that might lead to the tested scenarios.
    * **User Steps for Debugging:** Describe how a user's actions could lead to the tested states, providing debugging context.

By following this systematic approach, I can thoroughly analyze the C++ test file and generate a comprehensive explanation that covers its functionality, its relationship to web technologies, its logical reasoning, potential errors, and debugging relevance.这个C++源代码文件 `insert_text_command_test.cc` 是 Chromium Blink 渲染引擎的一部分，专门用于测试 `InsertTextCommand` 类的功能。 `InsertTextCommand` 类负责处理在可编辑区域插入文本的操作。

以下是该文件的详细功能分解：

**核心功能：测试 `InsertTextCommand` 类的各种场景**

该文件通过一系列的单元测试来验证 `InsertTextCommand` 类在不同情况下的行为是否正确。这些测试覆盖了以下方面：

* **插入普通文本:** 测试在各种DOM结构中插入普通字符、空格和制表符的行为。
* **处理样式:** 测试插入文本时是否正确应用或保留已有的样式（例如，通过 `fontSizeDelta` 设置的字体大小）。
* **处理空白字符:**  特别关注在插入文本时如何处理和规范化空格、制表符等空白字符，尤其是在段落前后。
* **处理特定HTML元素:** 测试在特定的HTML元素（如 `<option>`, `<span>`, `<a>`, `<ruby>`, `<strike>`, `<navi>`, `<rtc>`)内部或周围插入文本时的行为，包括一些可能导致崩溃的边缘情况。
* **处理选区:** 测试在不同类型的选区（例如，跨越多个元素、折叠选区）插入文本的行为。
* **处理`white-space` CSS属性:**  测试当目标位置的父元素设置了 `white-space: pre` 属性时，如何插入空白字符和制表符。
* **处理兼容模式:** 测试在 Quirks 模式下插入文本的行为。

**与 JavaScript, HTML, CSS 的关系：**

该测试文件直接关系到用户在网页上通过 JavaScript 调用编辑命令（如 `document.execCommand('insertText', ...)`）或者直接在可编辑区域输入文本时所触发的行为。

* **JavaScript:**  `document.execCommand('insertText', false, 'your text')`  是 JavaScript 中用于插入文本的命令。该测试文件模拟了这种命令的执行，并验证了 Blink 引擎如何处理。例如，测试用例中使用了 `GetDocument().execCommand("insertText", false, ...)` 来模拟 JavaScript 的调用。
* **HTML:** 测试用例使用 HTML 字符串来设置可编辑区域的内容 (`SetBodyContent`)，并断言插入文本后的 HTML 结构是否符合预期 (`EXPECT_EQ(..., GetDocument().body()->innerHTML())`). 例如，测试插入文本后，`<span>` 标签是否被正确分割或保留，新的文本节点是否被正确创建等。
* **CSS:**  测试用例涉及到 `white-space` 属性的测试，例如 `InsertSpaceToWhiteSpacePre` 和 `InsertTabToWhiteSpacePre`。这些测试验证了当 CSS 样式影响空白字符的处理方式时，插入文本命令的行为是否符合预期。 另外，`WithTypingStyle` 测试也涉及到通过 `fontSizeDelta` 命令设置的样式。

**举例说明：**

* **JavaScript:** 当用户在一个 `contenteditable` 的 `<div>` 中使用 JavaScript 执行 `document.execCommand('insertText', false, 'Hello')` 时，Blink 引擎会调用 `InsertTextCommand` 来执行插入操作。该测试文件中的用例模拟了这种场景。
* **HTML:**  假设 HTML 是 `<p contenteditable>abc^def</p>`，光标位置用 `^` 表示。 如果执行插入 "X" 的操作，`InsertTextCommand` 应该将 HTML 变为 `<p contenteditable>abcX|def</p>`，光标移动到插入文本之后。 测试用例通过断言插入后的 HTML 结构来验证这一点。
* **CSS:** 如果 HTML 是 `<p contenteditable><span style="white-space:pre">a^c</span></p>`，并且用户输入一个空格，由于 `white-space: pre`，空格应该被保留。 `InsertSpaceToWhiteSpacePre` 测试验证了插入空格后，HTML 是否变为  `<p contenteditable><span style="white-space:pre">a </span> | <span style="white-space:pre">c</span></p>` (请注意，实际输出可能因 Blink 的具体实现而略有不同，测试用例中的输出展示了当时的具体行为)。

**逻辑推理和假设输入与输出：**

以下列举一些测试用例的假设输入和预期输出：

* **测试用例:** `InsertChar`
    * **假设输入:** HTML `<p contenteditable><span>\ta|c</span></p>`，光标位于 `a` 和 `c` 之间，插入文本 "B"。
    * **预期输出:** HTML `<p contenteditable><span>\taB|c</span></p>`。 逻辑推理是，在同一个文本节点内插入字符，不应该分割文本节点。

* **测试用例:** `InsertSpaceToWhiteSpacePre`
    * **假设输入:** HTML `<p contenteditable><span style='white-space:pre'>\ta|c</span></p>`，光标位于 `a` 和 `c` 之间，插入两个空格 "  "。
    * **预期输出:** HTML `<p contenteditable><span style=\"white-space:pre\">\ta</span>\xC2\xA0\xC2\xA0|<span style=\"white-space:pre\">c</span></p>`。 逻辑推理是，在 `white-space: pre` 的元素内插入空格应该保留空格，并且由于 HTML 中空格可能被折叠，所以用 `\xC2\xA0` (不间断空格) 表示。

* **测试用例:** `WhitespaceFixupBeforeParagraph`
    * **假设输入:** HTML `<div contenteditable>qux ^bar|<p>baz</p></div>`，光标位于 "qux" 之后，"bar" 之前，插入空字符串 "" (可以理解为移动光标)。
    * **预期输出:** HTML `<div contenteditable>qux\xC2\xA0|<p>baz</p></div>`。 逻辑推理是，光标位于普通文本和块级元素之间，为了防止空格被折叠，需要将空格转换为不间断空格。

**用户或编程常见的使用错误：**

* **用户错误:**
    * **在不期望的地方插入文本:** 用户可能会在只读区域或者不应该编辑的元素内部尝试输入，这可能导致意想不到的结果或者操作失败。
    * **复制粘贴包含格式的文本:** 用户复制包含复杂样式的文本并粘贴到编辑器中，`InsertTextCommand` 需要正确处理这些样式，如果处理不当可能会导致样式丢失或混乱。
    * **连续输入特殊字符:**  用户可能会连续输入空格或制表符，引擎需要正确处理这些连续的空白字符，避免显示异常。

* **编程错误:**
    * **`InsertTextCommand` 实现中的逻辑错误:** 例如，在处理特定元素（如 `<option>`）时没有考虑到其特殊性，导致插入文本的行为不正确。 例如，早期的版本可能没有正确处理将文本插入到 `<option>` 标签的情况，导致样式没有应用。
    * **没有正确处理边界情况:**  例如，在段落的开头或结尾插入文本时，可能没有正确处理空白字符的规范化。
    * **在复杂的 DOM 结构中插入文本时出现崩溃:**  某些特定的 DOM 结构和选区状态可能会触发 `InsertTextCommand` 中的 bug，导致程序崩溃。 测试用例 `AnchorElementWithBlockCrash` 和 `MultilineSelectionCrash` 就是为了防止这类崩溃。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户在网页上与 `contenteditable` 元素进行交互:**  这是最常见的入口点。 用户可能会点击一个设置了 `contenteditable="true"` 属性的元素，使其获得焦点。
2. **用户开始输入文本:** 用户按下键盘上的字符键，或者使用输入法输入文字。
3. **浏览器捕获用户的输入事件:** 浏览器会捕获键盘事件（例如 `keypress`, `input`）。
4. **浏览器或网页脚本调用 `document.execCommand('insertText', ...)`:**  当用户输入文本时，浏览器通常会自动调用 `insertText` 命令。此外，网页的 JavaScript 代码也可以显式调用此命令。
5. **Blink 引擎接收到 `insertText` 命令:**  渲染引擎接收到该命令，并将其分发给相应的处理模块。
6. **`InsertTextCommand::Apply()` 被调用:**  负责处理插入文本逻辑的 `InsertTextCommand` 类的 `Apply()` 方法会被调用。
7. **执行插入逻辑:** `Apply()` 方法会根据当前的选区和要插入的文本，修改 DOM 树。这包括创建新的文本节点、分割已有的文本节点、移动光标等等。

**调试线索:**

* **在 `contenteditable` 元素上设置断点:**  在 Blink 引擎的源代码中，可以在 `InsertTextCommand::Apply()` 方法的入口处设置断点。
* **查看调用堆栈:** 当断点触发时，可以查看调用堆栈，了解 `InsertTextCommand` 是如何被调用的，以及之前的函数调用路径。
* **检查当前的选区状态:**  在调试器中，可以检查当前的 `FrameSelection` 对象，查看选区的起始和结束位置，以及选区所在的 DOM 节点。
* **单步执行代码:**  可以单步执行 `InsertTextCommand::Apply()` 方法中的代码，观察 DOM 树是如何被修改的，以及变量的值是如何变化的。
* **使用 Blink 的日志输出:** Blink 引擎可能包含一些用于调试编辑操作的日志输出，可以查看这些日志来获取更多信息。

总而言之，`insert_text_command_test.cc` 文件通过大量的测试用例，确保了 Blink 引擎在处理文本插入操作时的正确性和健壮性，涵盖了各种可能的场景和边缘情况，对于保证用户在网页上进行编辑操作的稳定性和一致性至关重要。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/insert_text_command_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/commands/insert_text_command.h"

#include "build/buildflag.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"

namespace blink {

class InsertTextCommandTest : public EditingTestBase {};

// http://crbug.com/714311
TEST_F(InsertTextCommandTest, WithTypingStyle) {
  SetBodyContent("<div contenteditable=true><option id=sample></option></div>");
  Element* const sample = GetDocument().getElementById(AtomicString("sample"));
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(Position(sample, 0)).Build(),
      SetSelectionOptions());
  // Register typing style to make |InsertTextCommand| to attempt to apply
  // style to inserted text.
  GetDocument().execCommand("fontSizeDelta", false, "+3", ASSERT_NO_EXCEPTION);
  auto* const command =
      MakeGarbageCollected<InsertTextCommand>(GetDocument(), "x");
  command->Apply();

  EXPECT_EQ(
      "<div contenteditable=\"true\"><option id=\"sample\">x</option></div>",
      GetDocument().body()->innerHTML())
      << "Content of OPTION is distributed into shadow node as text"
         "without applying typing style.";
}

// http://crbug.com/741826
TEST_F(InsertTextCommandTest, InsertChar) {
  Selection().SetSelection(
      SetSelectionTextToBody("<p contenteditable><span>\ta|c</span></p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "B", ASSERT_NO_EXCEPTION);
  EXPECT_EQ("<p contenteditable><span>\taB|c</span></p>",
            GetSelectionTextFromBody())
      << "We should not split Text node";
}

// http://crbug.com/741826
TEST_F(InsertTextCommandTest, InsertCharToWhiteSpacePre) {
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<p contenteditable><span style='white-space:pre'>\ta|c</span></p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "B", ASSERT_NO_EXCEPTION);
  EXPECT_EQ(
      "<p contenteditable>"
      "<span style=\"white-space:pre\">\ta</span>"
      "B|"
      "<span style=\"white-space:pre\">c</span>"
      "</p>",
      GetSelectionTextFromBody())
      << "This is a just record current behavior. We should not split SPAN.";
}

// http://crbug.com/741826
TEST_F(InsertTextCommandTest, InsertSpace) {
  Selection().SetSelection(
      SetSelectionTextToBody("<p contenteditable><span>\ta|c</span></p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "  ", ASSERT_NO_EXCEPTION);
  EXPECT_EQ("<p contenteditable><span>\ta\xC2\xA0 |c</span></p>",
            GetSelectionTextFromBody())
      << "We should insert U+0020 without splitting SPAN";
}

// http://crbug.com/741826
TEST_F(InsertTextCommandTest, InsertSpaceToWhiteSpacePre) {
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<p contenteditable><span style='white-space:pre'>\ta|c</span></p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "  ", ASSERT_NO_EXCEPTION);
  EXPECT_EQ(
      "<p contenteditable>"
      "<span style=\"white-space:pre\">\ta</span>"
      "\xC2\xA0\xC2\xA0|"
      "<span style=\"white-space:pre\">c</span></p>",
      GetSelectionTextFromBody())
      << "We should insert U+0020 without splitting SPAN";
}

// http://crbug.com/741826
TEST_F(InsertTextCommandTest, InsertTab) {
  Selection().SetSelection(
      SetSelectionTextToBody("<p contenteditable><span>\ta|c</span></p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "\t", ASSERT_NO_EXCEPTION);
  EXPECT_EQ(
      "<p contenteditable>"
      "<span>\ta<span style=\"white-space:pre\">\t|</span>c</span>"
      "</p>",
      GetSelectionTextFromBody());
}

// http://crbug.com/741826
TEST_F(InsertTextCommandTest, InsertTabToWhiteSpacePre) {
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<p contenteditable><span style='white-space:pre'>\ta|c</span></p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "\t", ASSERT_NO_EXCEPTION);
  EXPECT_EQ(
      "<p contenteditable><span style=\"white-space:pre\">\ta\t|c</span></p>",
      GetSelectionTextFromBody());
}

// http://crbug.com/752860
TEST_F(InsertTextCommandTest, WhitespaceFixupBeforeParagraph) {
  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>qux ^bar|<p>baz</p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "", ASSERT_NO_EXCEPTION);
  // The space after "qux" should have been converted to a no-break space
  // (U+00A0) to prevent it from being collapsed.
  EXPECT_EQ("<div contenteditable>qux\xC2\xA0|<p>baz</p></div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>qux^ bar|<p>baz</p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  // The newly-inserted space should have been converted to a no-break space
  // (U+00A0) to prevent it from being collapsed.
  EXPECT_EQ("<div contenteditable>qux\xC2\xA0|<p>baz</p></div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>qux^bar| <p>baz</p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "", ASSERT_NO_EXCEPTION);
  // The space after "bar" was already being collapsed before the edit. It
  // should not have been converted to a no-break space.
  EXPECT_EQ("<div contenteditable>qux|<p>baz</p></div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>qux^bar |<p>baz</p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  // The newly-inserted space should have been converted to a no-break space
  // (U+00A0) to prevent it from being collapsed.
  EXPECT_EQ("<div contenteditable>qux\xC2\xA0|<p>baz</p></div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>qux\t^bar|<p>baz</p>"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "", ASSERT_NO_EXCEPTION);
  // The tab should have been converted to a no-break space (U+00A0) to prevent
  // it from being collapsed.
  EXPECT_EQ("<div contenteditable>qux\xC2\xA0|<p>baz</p></div>",
            GetSelectionTextFromBody());
}

TEST_F(InsertTextCommandTest, WhitespaceFixupAfterParagraph) {
  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable><p>baz</p>^bar| qux"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "", ASSERT_NO_EXCEPTION);
  // The space before "qux" should have been converted to a no-break space
  // (U+00A0) to prevent it from being collapsed.
  EXPECT_EQ("<div contenteditable><p>baz</p>|\xC2\xA0qux</div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable><p>baz</p>^bar |qux"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  // The newly-inserted space should have been converted to a no-break space
  // (U+00A0) to prevent it from being collapsed.
  EXPECT_EQ("<div contenteditable><p>baz</p>\xC2\xA0|qux</div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable><p>baz</p> ^bar|qux"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "", ASSERT_NO_EXCEPTION);
  // The space before "bar" was already being collapsed before the edit. It
  // should not have been converted to a no-break space.
  EXPECT_EQ("<div contenteditable><p>baz</p>|qux</div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable><p>baz</p>^ bar|qux"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, " ", ASSERT_NO_EXCEPTION);
  // The newly-inserted space should have been converted to a no-break space
  // (U+00A0) to prevent it from being collapsed.
  EXPECT_EQ("<div contenteditable><p>baz</p>\xC2\xA0|qux</div>",
            GetSelectionTextFromBody());

  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable><p>baz</p>^bar|\tqux"),
      SetSelectionOptions());
  GetDocument().execCommand("insertText", false, "", ASSERT_NO_EXCEPTION);
  // The tab should have been converted to a no-break space (U+00A0) to prevent
  // it from being collapsed.
  EXPECT_EQ("<div contenteditable><p>baz</p>|\xC2\xA0qux</div>",
            GetSelectionTextFromBody());
}

// http://crbug.com/779376
TEST_F(InsertTextCommandTest, NoVisibleSelectionAfterDeletingSelection) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  InsertStyleElement(
      ":root { font-size: 10px; }"
      "ruby { display: inline-block; height: 100%; }"
      "navi { float: left; }");
  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable>"
                             "  <ruby><strike>"
                             "    <navi></navi>"
                             "    <rtc>^&#xbbc3;&#xff17;&#x8e99;&#x1550;</rtc>"
                             "  </strike></ruby>"
                             "  <hr>|"
                             "</div>"),
      SetSelectionOptions());
  // Shouldn't crash inside
  GetDocument().execCommand("insertText", false, "x", ASSERT_NO_EXCEPTION);
  // This is only for recording the current behavior, which can be changed.
  EXPECT_EQ(
      "<div contenteditable>"
      "  <ruby><strike>"
      "    <navi></navi>"
      "    ^</strike></ruby>"
      "|</div>",
      GetSelectionTextFromBody());
}

// http://crbug.com/778901
TEST_F(InsertTextCommandTest, CheckTabSpanElementNoCrash) {
  InsertStyleElement(
      "head {-webkit-text-stroke-color: black; display: list-item;}");
  Element* head = GetDocument().QuerySelector(AtomicString("head"));
  Element* style = GetDocument().QuerySelector(AtomicString("style"));
  Element* body = GetDocument().body();
  body->parentNode()->appendChild(style);
  GetDocument().setDesignMode("on");

  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(head, 0))
                               .Extend(Position(body, 0))
                               .Build(),
                           SetSelectionOptions());

  // Shouldn't crash inside
  GetDocument().execCommand("insertText", false, "\t", ASSERT_NO_EXCEPTION);

  // This only records the current behavior, which is not necessarily correct.
  EXPECT_EQ(
      "<body><span style=\"white-space:pre\">\t|</span></body>"
      "<style>"
      "head {-webkit-text-stroke-color: black; display: list-item;}"
      "</style>",
      SelectionSample::GetSelectionText(*GetDocument().documentElement(),
                                        Selection().GetSelectionInDOMTree()));
}

// http://crbug.com/792548
TEST_F(InsertTextCommandTest, AnchorElementWithBlockCrash) {
  GetDocument().setDesignMode("on");
  SetBodyContent("<a href=\"www\" style=\"display:block\">");
  // We need the below DOM with selection.
  // <a href=\"www\" style=\"display:block\">
  //   <a href=\"www\" style=\"display: inline !important;\">
  //   <i>^home|</i>
  //   </a>
  // </a>
  // Since the HTML parser rejects it as there are nested <a> elements.
  // We are constructing the remaining DOM manually.
  Element* const anchor = GetDocument().QuerySelector(AtomicString("a"));
  Element* nested_anchor = GetDocument().CreateRawElement(html_names::kATag);
  Element* iElement = GetDocument().CreateRawElement(html_names::kITag);

  nested_anchor->setAttribute(html_names::kHrefAttr, AtomicString("www"));
  iElement->setInnerHTML("home");

  anchor->AppendChild(nested_anchor);
  nested_anchor->AppendChild(iElement);

  Node* const iElement_text_node = iElement->firstChild();
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(iElement_text_node, 0),
                            Position(iElement_text_node, 4))
          .Build(),
      SetSelectionOptions());
  // Crash happens here with when '\n' is inserted.
  GetDocument().execCommand("inserttext", false, "a\n", ASSERT_NO_EXCEPTION);
  EXPECT_EQ(
      "<a href=\"www\" style=\"display:block\"><i>a</i></a><a href=\"www\" "
      "style=\"display:block\"><i>|<br></i></a>",
      GetSelectionTextFromBody());
}

// http://crbug.com/1197977
TEST_F(InsertTextCommandTest, MultilineSelectionCrash) {
  // Force line break between A and B.
  InsertStyleElement("body { width: 1px; }");
  Selection().SetSelection(SetSelectionTextToBody("A^<span> B|</span>"),
                           SetSelectionOptions());
  GetDocument().setDesignMode("on");

  // Shouldn't crash inside.
  GetDocument().execCommand("InsertText", false, "x", ASSERT_NO_EXCEPTION);
  EXPECT_EQ("A<span>x|</span>", GetSelectionTextFromBody());
}

}  // namespace blink

"""

```