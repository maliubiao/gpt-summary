Response:
My thinking process to analyze the given C++ test file went through these stages:

1. **Understand the Purpose:** The file name `apply_block_element_command_test.cc` immediately suggests it's testing the functionality of a command related to applying block-level elements in the Blink rendering engine. The `_test.cc` suffix confirms it's a unit test file.

2. **Identify Key Classes:** I scanned the `#include` directives to find the core classes involved. The most important ones are:
    * `FormatBlockCommand`: This class is clearly the focus of the tests. It likely handles the logic of wrapping selections with block-level elements.
    * `IndentOutdentCommand`: This class also appears frequently, suggesting it interacts with or is tested alongside `FormatBlockCommand`. It's related to indenting and outdenting content.
    * `EditingTestBase`: This is a standard testing utility class in Blink, providing a test fixture and helper methods.
    * `Selection`, `Position`, `SelectionInDOMTree`: These deal with text selection and cursor placement in the document.
    * `Document`, `Element`, `DocumentFragment`: These are core DOM classes representing the document structure.
    * `html_names`:  Provides constants for HTML tag names.

3. **Analyze Test Case Structure:**  I observed that each `TEST_F` function represents a specific test case for the `ApplyBlockElementCommandTest` fixture. Each test typically follows a pattern:
    * **Setup:**  Setting up the initial HTML content using `SetBodyContent` or `insertAdjacentHTML`. Sometimes, applying CSS with `InsertStyleElement`. Enabling `designMode` to make the document editable.
    * **Selection:** Setting the text selection using `Selection().SetSelection()`. The `^` and `|` markers in the HTML strings within `SetSelectionTextToBody` are key to defining the selection.
    * **Action:** Creating and applying the command (`FormatBlockCommand` or `IndentOutdentCommand`).
    * **Assertion:** Using `EXPECT_EQ` or `EXPECT_TRUE`/`EXPECT_FALSE` to verify the outcome, usually by comparing the resulting HTML with an expected string or checking the return value of the `Apply()` method.

4. **Infer Functionality from Test Names and Content:**  I paid close attention to the names of the test cases and the specific HTML structures they manipulated. This helped deduce the tested scenarios:
    * `selectionCrossingOverBody`:  Handles selections that span the document head and body.
    * `visibilityChangeDuringCommand`: Deals with changes in element visibility during command execution.
    * `IndentHeadingIntoBlockquote`: Tests how indenting affects headings within blockquotes.
    * `InsertPlaceHolderAtDisconnectedPosition`: Focuses on inserting placeholders in specific DOM structures.
    * `FormatBlockCrossingUserModifyBoundary`: Tests the interaction with elements having `-webkit-user-modify: read-only`.
    * `FormatBlockWithTableCrossingUserModifyBoundary`: Similar to the previous, but with tables.
    * `FormatBlockWithDirectChildrenOfRoot`: Addresses formatting when the selection includes direct children of the root element.
    * `OutdentEmptyBlockquote`: Tests outdenting empty blockquotes.
    * `IndentSVGWithTable`: Checks indenting within SVG content containing tables.
    * Various `IndentOutdentLines...`: Test cases focusing on indenting and outdenting across line breaks (`<br>`).

5. **Relate to Web Technologies (JavaScript, HTML, CSS):**  With an understanding of the tested scenarios, I could connect them to the core web technologies:
    * **HTML:**  The tests directly manipulate HTML structure and tags (e.g., `<pre>`, `<div>`, `<blockquote>`, `<table>`, `<input>`, `<button>`, `<svg>`, `<foreignObject>`). The `FormatBlockCommand` is explicitly about applying block-level HTML elements.
    * **CSS:**  Several tests involve CSS, particularly the `-webkit-user-modify` property, which affects the editability of content. The `visibility` property is also tested.
    * **JavaScript:** While this C++ code doesn't *directly* execute JavaScript, the tested commands are fundamental to the browser's editing capabilities, which are often triggered or manipulated via JavaScript. For example, a rich text editor implemented in JavaScript would rely on these underlying commands.

6. **Identify Logic and Assumptions:**  I noted the test cases that specifically mentioned "regression test for crbug.com/...", indicating they were designed to prevent previously fixed bugs from reappearing. I also observed comments within the tests, like "// This only records the current behavior, which can be wrong," indicating areas where the current implementation might not be ideal.

7. **Consider User/Programming Errors and Debugging:** Based on the tested scenarios, I could infer potential user actions that might trigger these code paths (e.g., selecting text across different elements, indenting/outdenting, applying formatting). The test cases themselves serve as debugging examples, showing how specific inputs lead to certain outputs or highlight potential issues (like crashes).

8. **Structure the Explanation:** Finally, I organized my findings into the requested categories: functionality, relationship to web technologies, logic/assumptions, user/programming errors, and debugging clues. I used specific examples from the test file to illustrate each point.

Essentially, I approached this like reverse-engineering the purpose of the code by examining its inputs, actions, and expected outputs within a testing context. The test names and comments were invaluable clues. My knowledge of web development and browser architecture helped me bridge the gap between the C++ code and the higher-level concepts of HTML, CSS, and JavaScript.
这个文件 `apply_block_element_command_test.cc` 是 Chromium Blink 引擎中负责测试 `FormatBlockCommand` 和 `IndentOutdentCommand` 这两个编辑命令功能的测试文件。这些命令用于在富文本编辑场景中应用或修改块级元素，例如将选中的文本包裹在 `<p>`、`<div>`、`<blockquote>` 等标签中，或者进行缩进和取消缩进操作。

**功能列表:**

1. **测试 `FormatBlockCommand` 的功能:**
   - 将选中的文本或节点包裹在指定的块级元素中。
   - 处理跨越不同类型元素边界的选择。
   - 处理与 `user-modify: read-only` 属性的交互。
   - 处理选择包含文档根元素直接子节点的情况。
   - 处理包含占位符节点的情况。
   - 处理包含仅有换行符的文本节点的情况。

2. **测试 `IndentOutdentCommand` 的功能:**
   - 对选中的文本或节点进行缩进（通常是包裹在 `<blockquote>` 中）。
   - 对选中的文本或节点取消缩进（移除包裹的 `<blockquote>`）。
   - 处理在 `visibility` 属性改变时执行命令的情况。
   - 处理嵌套在其他块级元素内的标题元素的缩进。
   - 处理包含 SVG 和 Table 元素的缩进。
   - 处理包含多个 `<br>` 标签的行的缩进和取消缩进。
   - 处理包含注释节点等 "垃圾" 节点的缩进和取消缩进。
   - 处理空 `<blockquote>` 元素的取消缩进。

**与 JavaScript, HTML, CSS 的关系：**

这些命令直接影响浏览器渲染的 HTML 结构和样式，并且通常是通过 JavaScript API 触发的。

* **HTML:** `FormatBlockCommand` 的核心功能就是操作 HTML 结构，它会创建或修改 HTML 标签，例如 `<p>`, `<div>`, `<blockquote>`, `<pre>`, `<footer>` 等。测试用例中通过 `SetBodyContent` 和 `insertAdjacentHTML` 设置初始 HTML 结构，并通过 `GetDocument().documentElement()->innerHTML()` 检查命令执行后的 HTML 结果。

   **举例:** `TEST_F(ApplyBlockElementCommandTest, InsertPlaceHolderAtDisconnectedPosition)` 测试将选中的 `<input>` 元素包裹在 `<pre>` 标签中。

* **CSS:** 某些测试用例涉及到 CSS 属性，特别是 `-webkit-user-modify` 和 `visibility` 属性。`FormatBlockCommand` 需要考虑如何处理被设置为 `read-only` 的内容，避免破坏只读属性的元素。`IndentOutdentCommand` 的实现会涉及到 `blockquote` 元素的默认样式 (例如 `margin-left`)。

   **举例:** `TEST_F(ApplyBlockElementCommandTest, FormatBlockCrossingUserModifyBoundary)` 测试当选择跨越设置了 `-webkit-user-modify:read-only` 属性的 `<b>` 标签时，`FormatBlockCommand` 的行为。

* **JavaScript:**  虽然这个文件是 C++ 代码，但这些命令通常是由 JavaScript 代码通过 `document.execCommand()` 或 Selection API 触发的。例如，用户在富文本编辑器中点击 "段落" 按钮，可能会调用 `document.execCommand('formatBlock', false, 'p')`，从而触发 Blink 引擎中的 `FormatBlockCommand`。

**逻辑推理 (假设输入与输出):**

**假设输入 (对于 `FormatBlockCommand`):**

1. **HTML:** `<div contenteditable="true">hello world</div>`
2. **Selection:** 用户选中 "hello"
3. **Command:** `FormatBlockCommand` 应用 `p` 标签

**预期输出:** `<div contenteditable="true"><p>hello</p> world</div>`

**假设输入 (对于 `IndentOutdentCommand`):**

1. **HTML:** `<div contenteditable="true">hello world</div>`
2. **Selection:** 用户选中 "hello world"
3. **Command:** `IndentOutdentCommand` 应用 `Indent`

**预期输出:** `<div contenteditable="true"><blockquote style="margin: 0 0 0 40px; border: none; padding: 0px;">hello world</blockquote></div>`

**涉及用户或者编程常见的使用错误，举例说明:**

1. **错误地将块级元素应用于不可编辑区域:**  如果用户尝试在 `contenteditable="false"` 的区域应用 `FormatBlockCommand`，命令应该不会生效或产生预期的结果。`TEST_F(ApplyBlockElementCommandTest, selectionCrossingOverBody)` 测试了类似的情况，选择跨越了 `contenteditable="false"` 的 body。

2. **在复杂的嵌套结构中进行缩进/取消缩进可能导致意外的结构变化:** 例如，在包含表格或其他特殊元素的结构中进行缩进，可能不会得到用户期望的布局。`TEST_F(ApplyBlockElementCommandTest, IndentSVGWithTable)` 和 `TEST_F(ApplyBlockElementCommandTest, IndentHeadingIntoBlockquote)` 覆盖了这类场景。

3. **错误地假设命令会处理所有类型的选择和 DOM 结构:** 开发者可能会错误地认为 `FormatBlockCommand` 可以将任意选择转换为任意块级元素，但实际上可能存在边界情况或限制，例如无法直接将行内元素转换为顶级块级元素而保持其原始上下文。

**用户操作是如何一步步的到达这里，作为调试线索:**

以下是一个用户操作流程，可能触发 `FormatBlockCommand`，从而导致相关代码被执行：

1. **用户打开一个支持富文本编辑的网页。** 例如，一个在线文档编辑器或邮件客户端。
2. **用户在该编辑区域输入了一些文本。**
3. **用户使用鼠标或键盘选中部分文本。**
4. **用户点击富文本编辑器的工具栏上的 "标题 1" 或 "段落" 按钮。**  这通常会调用 JavaScript 代码，例如：
   ```javascript
   document.execCommand('formatBlock', false, 'h1');
   // 或者
   document.execCommand('formatBlock', false, 'p');
   ```
5. **浏览器接收到 `formatBlock` 命令，并将其传递给 Blink 引擎的编辑模块。**
6. **Blink 引擎根据命令的参数（例如 'h1' 或 'p'）创建并执行 `FormatBlockCommand` 对象。**
7. **`FormatBlockCommand` 会操作 DOM 树，将选中的文本包裹在相应的 HTML 标签中。**
8. **测试文件 `apply_block_element_command_test.cc` 中的测试用例模拟了各种用户选择和命令参数的组合，用于确保 `FormatBlockCommand` 在各种情况下都能正确工作。**

对于 `IndentOutdentCommand`，用户操作可能是：

1. **用户选中一段或多段文本。**
2. **用户点击编辑器工具栏上的 "增加缩进" 或 "减少缩进" 按钮。** 这可能对应于 JavaScript 调用：
   ```javascript
   document.execCommand('indent');
   // 或者
   document.execCommand('outdent');
   ```
3. **Blink 引擎接收到 `indent` 或 `outdent` 命令，并执行 `IndentOutdentCommand`。**

**调试线索:**

当在 Chromium 浏览器或使用 Blink 引擎的 Electron 应用中进行富文本编辑时遇到与块级元素格式化或缩进相关的问题，可以考虑以下调试线索：

* **查看浏览器的开发者工具中的 Console 面板，看是否有 JavaScript 错误与编辑操作相关。**
* **使用 "Sources" 或 "Debugger" 面板，在执行 `document.execCommand('formatBlock', ...)` 或 `document.execCommand('indent')` 等 JavaScript 代码时设置断点，追踪命令的执行流程。**
* **如果怀疑是 Blink 引擎内部的问题，可以尝试构建 Chromium 并使用调试版本的浏览器，在 `core/editing/commands/format_block_command.cc` 或 `core/editing/commands/indent_outdent_command.cc` 中设置断点，深入查看命令的具体执行逻辑。**
* **参考 `apply_block_element_command_test.cc` 中的测试用例，了解各种边界情况和已知的 bug 修复，可以帮助理解问题的根源。** 例如，如果遇到跨越 `user-modify: read-only` 边界的问题，可以查看相关的测试用例，了解 Blink 引擎是如何处理这种情况的。
* **仔细检查 HTML 结构和 CSS 样式，看是否有样式冲突或其他因素影响了命令的执行结果。**

总而言之，`apply_block_element_command_test.cc` 是 Blink 引擎中保证富文本编辑核心功能稳定性和正确性的重要组成部分。它通过大量的测试用例覆盖了各种场景，确保 `FormatBlockCommand` 和 `IndentOutdentCommand` 能够按照预期工作。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/apply_block_element_command_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/qualified_name.h"
#include "third_party/blink/renderer/core/editing/commands/format_block_command.h"
#include "third_party/blink/renderer/core/editing/commands/indent_outdent_command.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/position.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"
#include "third_party/blink/renderer/core/editing/visible_selection.h"
#include "third_party/blink/renderer/core/html/html_head_element.h"
#include "third_party/blink/renderer/core/html_names.h"
#include "third_party/blink/renderer/platform/bindings/exception_state.h"

#include <memory>

namespace blink {

class ApplyBlockElementCommandTest : public EditingTestBase {};

// This is a regression test for https://crbug.com/639534
TEST_F(ApplyBlockElementCommandTest, selectionCrossingOverBody) {
  GetDocument().head()->insertAdjacentHTML(
      "afterbegin",
      "<style> .CLASS13 { -webkit-user-modify: read-write; }</style></head>",
      ASSERT_NO_EXCEPTION);
  GetDocument().body()->insertAdjacentHTML(
      "afterbegin",
      "\n<pre><var id='va' class='CLASS13'>\nC\n</var></pre><input />",
      ASSERT_NO_EXCEPTION);
  GetDocument().body()->insertAdjacentText("beforebegin", "foo",
                                           ASSERT_NO_EXCEPTION);

  GetDocument().body()->setContentEditable("false", ASSERT_NO_EXCEPTION);
  GetDocument().setDesignMode("on");
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .SetBaseAndExtent(Position(GetDocument().documentElement(), 1),
                            Position(GetDocument()
                                         .getElementById(AtomicString("va"))
                                         ->firstChild(),
                                     2))
          .Build(),
      SetSelectionOptions());

  auto* command = MakeGarbageCollected<FormatBlockCommand>(
      GetDocument(), html_names::kFooterTag);
  command->Apply();

  EXPECT_EQ(
      "<head>"
      "<style> .CLASS13 { -webkit-user-modify: read-write; }</style>"
      "</head>foo"
      "<body contenteditable=\"false\">\n"
      "<pre><var id=\"va\" class=\"CLASS13\">\nC\n</var></pre><input></body>",
      GetDocument().documentElement()->innerHTML());
}

// This is a regression test for https://crbug.com/660801
TEST_F(ApplyBlockElementCommandTest, visibilityChangeDuringCommand) {
  GetDocument().head()->insertAdjacentHTML(
      "afterbegin", "<style>li:first-child { visibility:visible; }</style>",
      ASSERT_NO_EXCEPTION);
  SetBodyContent("<ul style='visibility:hidden'><li>xyz</li></ul>");
  GetDocument().setDesignMode("on");

  UpdateAllLifecyclePhasesForTest();
  Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(
              Position(GetDocument().QuerySelector(AtomicString("li")), 0))
          .Build(),
      SetSelectionOptions());

  auto* command = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kIndent);
  command->Apply();

  EXPECT_EQ(
      "<head><style>li:first-child { visibility:visible; }</style></head>"
      "<body><ul style=\"visibility:hidden\"><ul></ul><li>xyz</li></ul></body>",
      GetDocument().documentElement()->innerHTML());
}

// This is a regression test for https://crbug.com/712510
TEST_F(ApplyBlockElementCommandTest, IndentHeadingIntoBlockquote) {
  SetBodyContent(
      "<div contenteditable=\"true\">"
      "<h6><button><table></table></button></h6>"
      "<object></object>"
      "</div>");
  Element* button = GetDocument().QuerySelector(AtomicString("button"));
  Element* object = GetDocument().QuerySelector(AtomicString("object"));
  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(button, 0))
                               .Extend(Position(object, 0))
                               .Build(),
                           SetSelectionOptions());

  auto* command = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kIndent);
  command->Apply();

  // This only records the current behavior, which can be wrong.
  EXPECT_EQ(
      "<div contenteditable=\"true\">"
      "<blockquote style=\"margin: 0 0 0 40px; border: none; padding: 0px;\">"
      "<h6><button></button></h6>"
      "<h6><button><table></table></button></h6>"
      "</blockquote>"
      "<br>"
      "<object></object>"
      "</div>",
      GetDocument().body()->innerHTML());
}

// This is a regression test for https://crbug.com/806525
TEST_F(ApplyBlockElementCommandTest, InsertPlaceHolderAtDisconnectedPosition) {
  GetDocument().setDesignMode("on");
  InsertStyleElement(".input:nth-of-type(2n+1) { visibility:collapse; }");
  Selection().SetSelection(
      SetSelectionTextToBody(
          "^<input><input class=\"input\" style=\"position:absolute\">|"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<FormatBlockCommand>(GetDocument(),
                                                           html_names::kPreTag);
  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<pre>^<input>|</pre><input class=\"input\" style=\"position:absolute\">",
      GetSelectionTextFromBody());
}

// https://crbug.com/873084
TEST_F(ApplyBlockElementCommandTest, FormatBlockCrossingUserModifyBoundary) {
  InsertStyleElement("*{-webkit-user-modify:read-write}");
  Selection().SetSelection(
      SetSelectionTextToBody(
          "^<b style=\"-webkit-user-modify:read-only\"><button></button></b>|"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<FormatBlockCommand>(GetDocument(),
                                                           html_names::kPreTag);
  // Shouldn't crash here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<pre>|<br></pre>"
      "<b style=\"-webkit-user-modify:read-only\"><button></button></b>",
      GetSelectionTextFromBody());
}

// https://crbug.com/873084
TEST_F(ApplyBlockElementCommandTest,
       FormatBlockWithTableCrossingUserModifyBoundary) {
  InsertStyleElement("*{-webkit-user-modify:read-write}");
  Selection().SetSelection(
      SetSelectionTextToBody("^<table></table>"
                             "<kbd "
                             "style=\"-webkit-user-modify:read-only\"><button><"
                             "/button></kbd>|"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<FormatBlockCommand>(GetDocument(),
                                                           html_names::kPreTag);
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<pre><table>|</table></pre>"
      "<kbd style=\"-webkit-user-modify:read-only\"><button></button></kbd>",
      GetSelectionTextFromBody());
}

// https://crbug.com/1172656
TEST_F(ApplyBlockElementCommandTest, FormatBlockWithDirectChildrenOfRoot) {
  GetDocument().setDesignMode("on");
  DocumentFragment* fragment = DocumentFragment::Create(GetDocument());
  Element* root = GetDocument().documentElement();
  fragment->ParseXML("a<div>b</div>c", root, ASSERT_NO_EXCEPTION);
  root->setTextContent("");
  root->appendChild(fragment);
  UpdateAllLifecyclePhasesForTest();

  Selection().SetSelection(
      SelectionInDOMTree::Builder().SelectAllChildren(*root).Build(),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<FormatBlockCommand>(GetDocument(),
                                                           html_names::kPreTag);
  // Shouldn't crash here.
  EXPECT_FALSE(command->Apply());
  const SelectionInDOMTree& selection = Selection().GetSelectionInDOMTree();
  EXPECT_EQ("^a<div>b</div>c|",
            SelectionSample::GetSelectionText(*root, selection));
}

// This is a regression test for https://crbug.com/1180699
TEST_F(ApplyBlockElementCommandTest, OutdentEmptyBlockquote) {
  Vector<std::string> selection_texts = {
      "<blockquote style='padding:5px'>|</blockquote>",
      "a<blockquote style='padding:5px'>|</blockquote>",
      "<blockquote style='padding:5px'>|</blockquote>b",
      "a<blockquote style='padding:5px'>|</blockquote>b"};
  Vector<std::string> expectations = {"|", "a|<br>", "|<br>b", "a<br>|b"};

  GetDocument().setDesignMode("on");
  for (unsigned i = 0; i < selection_texts.size(); ++i) {
    Selection().SetSelection(SetSelectionTextToBody(selection_texts[i]),
                             SetSelectionOptions());
    auto* command = MakeGarbageCollected<IndentOutdentCommand>(
        GetDocument(), IndentOutdentCommand::kOutdent);

    // Shouldn't crash here.
    command->Apply();
    EXPECT_EQ(expectations[i], GetSelectionTextFromBody());
  }
}

// This is a regression test for https://crbug.com/1188871
TEST_F(ApplyBlockElementCommandTest, IndentSVGWithTable) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(SetSelectionTextToBody("<svg><foreignObject>|"
                                                  "<table>&#x20;</table>&#x20;x"
                                                  "</foreignObject></svg>"),
                           SetSelectionOptions());
  auto* command = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kIndent);

  // Shouldn't crash here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<blockquote style=\"margin: 0 0 0 40px; border: none; padding: 0px;\">"
      "<svg><foreignObject><table>| </table></foreignObject></svg>"
      "</blockquote>"
      "<svg><foreignObject> x</foreignObject></svg>",
      GetSelectionTextFromBody());
}

// This is a regression test for https://crbug.com/673056
TEST_F(ApplyBlockElementCommandTest, IndentOutdentLinesDoubleBr) {
  Selection().SetSelection(SetSelectionTextToBody("<div contenteditable>"
                                                  "|a<br><br>"
                                                  "b"
                                                  "</div>"),
                           SetSelectionOptions());

  auto* indent = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kIndent);
  EXPECT_TRUE(indent->Apply());

  EXPECT_EQ(
      "<div contenteditable>"
      "<blockquote style=\"margin: 0 0 0 40px; border: none; padding: 0px;\">"
      "|a"
      "</blockquote>"
      "<br>"
      "b"
      "</div>",
      GetSelectionTextFromBody());

  auto* outdent = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kOutdent);

  // When moving "a" out of the blockquote, the empty line should be preserved.
  EXPECT_TRUE(outdent->Apply());
  EXPECT_EQ(
      "<div contenteditable>"
      "|a"
      "<br>"
      "<br>"
      "b"
      "</div>",
      GetSelectionTextFromBody());
}

// This is a regression test for https://crbug.com/673056
TEST_F(ApplyBlockElementCommandTest, IndentOutdentLinesCrash) {
  Selection().SetSelection(SetSelectionTextToBody("<div contenteditable>"
                                                  "^a<br>"
                                                  "b|<br><br>"
                                                  "c"
                                                  "</div>"),
                           SetSelectionOptions());

  auto* indent = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kIndent);

  EXPECT_TRUE(indent->Apply());
  EXPECT_EQ(
      "<div contenteditable>"
      "<blockquote style=\"margin: 0 0 0 40px; border: none; padding: 0px;\">"
      "^a<br>"
      "b|"
      "</blockquote>"
      "<br>"
      "c"
      "</div>",
      GetSelectionTextFromBody());

  auto* outdent = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kOutdent);

  // Shouldn't crash, and the empty line between b and c should be preserved.
  EXPECT_TRUE(outdent->Apply());
  EXPECT_EQ(
      "<div contenteditable>"
      "^a<br>"
      "b|<br><br>"
      "c"
      "</div>",
      GetSelectionTextFromBody());
}

// This is a regression test for https://crbug.com/673056
TEST_F(ApplyBlockElementCommandTest, IndentOutdentLinesWithJunkCrash) {
  Selection().SetSelection(SetSelectionTextToBody("<div contenteditable>"
                                                  "^a<br>"
                                                  "b|<br>"
                                                  "<!----><br>"
                                                  "c"
                                                  "</div>"),
                           SetSelectionOptions());

  auto* indent = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kIndent);

  EXPECT_TRUE(indent->Apply());
  EXPECT_EQ(
      "<div contenteditable>"
      "<blockquote style=\"margin: 0 0 0 40px; border: none; padding: 0px;\">"
      "^a<br>"
      "b|"
      "</blockquote>"
      "<!----><br>"
      "c"
      "</div>",
      GetSelectionTextFromBody());

  auto* outdent = MakeGarbageCollected<IndentOutdentCommand>(
      GetDocument(), IndentOutdentCommand::kOutdent);

  // Shouldn't crash.
  EXPECT_TRUE(outdent->Apply());

  // TODO(editing-dev): The result is wrong. We should preserve the empty line
  // between b and c.
  EXPECT_EQ(
      "<div contenteditable>"
      "^a<br>"
      "b|"
      "<!----><br>"
      "c"
      "</div>",
      GetSelectionTextFromBody());
}

// http://crbug.com/1264470
TEST_F(ApplyBlockElementCommandTest, SplitTextNodeWithJustNewline) {
  InsertStyleElement("b {-webkit-text-security: square;}");
  Selection().SetSelection(SetSelectionTextToBody("<pre contenteditable>"
                                                  "<b>|<p>X</p>\n</b>"
                                                  "</pre>"),
                           SetSelectionOptions());

  auto* const format_block = MakeGarbageCollected<FormatBlockCommand>(
      GetDocument(), html_names::kDivTag);

  ASSERT_TRUE(format_block->Apply());
  EXPECT_EQ("<pre contenteditable><b><div>|X</div>\n</b></pre>",
            GetSelectionTextFromBody());
}

}  // namespace blink

"""

```