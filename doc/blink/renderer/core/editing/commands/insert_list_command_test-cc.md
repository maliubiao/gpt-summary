Response:
The user wants to understand the functionality of the `insert_list_command_test.cc` file in the Chromium Blink engine. I need to analyze the provided C++ code and extract information about its purpose, relationship with web technologies, logical deductions (if any), potential user errors, and how a user might reach this code.

**Plan:**

1. **Identify the primary purpose:** The filename and the class name `InsertListCommandTest` strongly suggest this file contains unit tests for the `InsertListCommand` class.
2. **Analyze the tests:**  Go through each test case and understand what specific scenarios it's testing. Look for patterns and the types of issues being addressed (e.g., crashes, incorrect output).
3. **Relate to web technologies:**  Examine how the test cases interact with HTML structure (lists, tables, divs, spans, input elements, etc.), CSS styles (visibility, display properties), and JavaScript interaction (designMode, contenteditable).
4. **Identify logical deductions:**  Determine if the tests demonstrate any specific logic related to list manipulation, such as merging lists, handling empty elements, or dealing with non-editable content. Formulate input and expected output for these scenarios.
5. **Infer user errors:**  Based on the bugs the tests are designed to prevent (indicated by the `crbug.com` references), deduce what common user actions or edge cases might trigger these issues.
6. **Trace user actions:**  Consider how a user interacting with a web page in an editable context might perform actions that would eventually lead to the execution of the `InsertListCommand`. This will involve thinking about rich text editing scenarios.
这个文件 `insert_list_command_test.cc` 是 Chromium Blink 引擎中的一个 C++ 源代码文件，其主要功能是 **测试 `InsertListCommand` 类的各种功能和边界情况**。 `InsertListCommand` 类负责处理在可编辑内容中插入和移除列表的操作，例如将选中的文本转换为无序列表（`<ul>`）或有序列表（`<ol>`），或者将列表项转换为普通段落。

**与 JavaScript, HTML, CSS 的关系：**

这个测试文件直接测试的是 C++ 代码，但其测试的场景和功能与 JavaScript, HTML, CSS 紧密相关，因为 `InsertListCommand` 的最终效果是修改 HTML 结构和样式。

* **HTML:**  测试用例中大量使用了 HTML 结构来模拟各种编辑场景，例如：
    * 创建不同的 HTML 元素（`<div>`, `<p>`, `<span>`, `<ul>`, `<ol>`, `<li>`, `<table>`, `<input>`, `<textarea>`, `<select>`, `<ruby>`, `<time>`, `<meter>`, `<pre>`）。
    * 设置元素的属性，如 `contenteditable`。
    * 模拟复杂的嵌套结构。
    * 断言操作后的 HTML 结构是否符合预期。

    **举例：**
    ```c++
    SetBodyContent("\nd\n<ol>");
    // ...
    EXPECT_EQ("<ol><li>\nd\n</li></ol>", GetDocument().body()->innerHTML());
    ```
    这段代码设置了 HTML 内容，并断言执行插入列表命令后，`<body>` 元素的 `innerHTML` 是否变成了预期的 `<ol><li>\nd\n</li></ol>`。

* **CSS:** 测试用例中会使用 CSS 来模拟一些特定的渲染状态，这些状态可能会影响编辑命令的行为：
    * 使用 `visibility: hidden;` 来测试隐藏元素的情况。
    * 使用 `-webkit-appearance: checkbox;` 来模拟特定元素的渲染效果。
    * 使用 `display: table-cell;` 或 `display: inline-block;` 来测试不同 display 属性的影响。
    * 使用 `width: 100vw;` 来模拟特定布局。

    **举例：**
    ```c++
    InsertStyleElement("br { visibility:hidden; }");
    // ...
    EXPECT_EQ("^<button><ul><li><br></li></ul></button>|",
              GetSelectionTextFromBody());
    ```
    这段代码插入了一个 CSS 样式，将 `br` 元素的 `visibility` 设置为 `hidden`，然后测试在这种情况下插入列表命令的行为。

* **JavaScript:**  虽然这个测试文件是 C++ 代码，但它通过 Blink 引擎提供的接口与 JavaScript 的行为相关联。
    * `GetDocument().setDesignMode("on");`  模拟了用户在浏览器中启用 `designMode`，这使得页面内容可编辑，是触发编辑命令的前提。
    * 测试用例中通过 `Selection()` 对象来模拟用户在页面上的选区，而用户的选择通常是通过 JavaScript 与 DOM 交互来实现的。

    **隐式关系：** 当用户在可编辑的网页上使用类似“创建无序列表”或“创建有序列表”的富文本编辑功能时，浏览器内部可能会调用类似的 `InsertListCommand` 来修改 DOM 结构。 这些富文本编辑功能通常由 JavaScript 实现。

**逻辑推理 (假设输入与输出)：**

以下是一些基于测试用例的逻辑推理示例：

**假设输入 1:**
* HTML: `"<p>foo</p><p>bar</p>"`
* 用户选中 "foo" 这部分文本。
* 执行插入有序列表命令。

**预期输出 1:**
* HTML: `<ol><li>foo</li></ol><p>bar</p>`  (第一个段落被转换为列表项，第二个段落保持不变)

**假设输入 2:**
* HTML: `<ol><li>item1</li><li>item2</li></ol>`
* 用户选中 "item1" 这部分文本。
* 执行插入无序列表命令。

**预期输出 2:**
* HTML: `<ul><li>item1</li></ul><ol><li>item2</li></ol>` (选中的列表项被转换为新的无序列表，剩余的保持原有的有序列表)

**假设输入 3 (基于 "ShouldCleanlyRemoveSpuriousTextNode" 测试):**
* HTML: `\nd\n<ol>` (注意 `\n` 代表换行符)
* 光标选中第一个换行符到 `d` 字符之间的区域。
* 执行插入有序列表命令。

**预期输出 3:**
* HTML: `<ol><li>\nd\n</li></ol>` (额外的空文本节点被清理，选中的内容被包裹在 `<li>` 中)

**涉及用户或编程常见的使用错误：**

这些测试用例实际上是在预防和检测开发过程中的错误，但从用户的角度来看，也反映了一些用户操作可能触发的潜在问题：

* **在复杂的 HTML 结构中插入列表：**  例如，在表格单元格 (`<td>`)、`ruby` 元素、或者具有特定 CSS 属性的元素中插入列表，可能会导致意想不到的结构变化或渲染问题 (例如 `ListifyInputInTableCell` 和 `ListifyInputInTableCell1` 测试用例)。
* **在不可见或特殊渲染的元素中插入列表：** 例如，在 `visibility: hidden` 或 `display: none` 的元素内部或周围插入列表，可能会导致行为不一致或错误 (例如 `InsertListOnEmptyHiddenElements` 和 `InsertListWithCollapsedVisibility` 测试用例)。
* **在包含非可编辑内容的区域操作：**  当选区包含 `contenteditable="false"` 的元素时，插入列表命令需要正确处理这些不可编辑的部分，避免崩溃或产生错误的结构 (例如 `UnlistifyParagraphWithNonEditable` 和 `ListItemWithSpace` 测试用例)。
* **在特定的边界条件下操作：**  例如，选区从一个元素的末尾延伸到另一个元素之后 (`SelectionFromEndOfTableToAfterTable` 测试用例)，或者选区包含特殊的节点类型 (`TimeAndMeterInRoot` 测试用例)，这些边界情况容易出现 bug。
* **处理空格和换行符：**  在 `<pre>` 元素中插入列表需要特别注意保留换行符 (`PreservedNewline` 测试用例)。

**用户操作是如何一步步的到达这里，作为调试线索：**

一个用户操作最终触发 `InsertListCommand` 的过程通常如下：

1. **用户打开一个网页，并且该网页的某些区域是可编辑的。** 这可以通过 HTML 元素的 `contenteditable` 属性设置为 `true`，或者整个文档处于 `designMode` 开启状态来实现。
2. **用户在可编辑区域选中一段文本或者将光标放置在某个位置。** 用户的选择会被浏览器记录下来，形成一个选区（Selection）。
3. **用户执行插入列表的操作。** 这通常通过以下几种方式触发：
    * **点击富文本编辑器工具栏上的“无序列表”或“有序列表”按钮。** 这些按钮通常会执行相应的 JavaScript 代码。
    * **使用键盘快捷键。** 某些富文本编辑器会绑定快捷键来插入列表。
    * **通过浏览器的上下文菜单。**  在某些情况下，右键点击可能会出现插入列表的选项。
4. **JavaScript 代码接收到用户的操作，并调用 Blink 引擎提供的接口来执行插入列表的命令。**  这个接口最终会创建并执行一个 `InsertListCommand` 对象。
5. **`InsertListCommand` 对象根据当前的选区和要插入的列表类型（有序或无序），对 DOM 树进行修改。** 这个过程中会涉及到复杂的逻辑，例如判断当前选区是否在已有的列表中，如何分割和合并列表项等。

**调试线索：**

当开发者需要调试与插入列表功能相关的问题时，`insert_list_command_test.cc` 文件可以提供以下线索：

* **明确的测试用例：**  每个测试用例都针对一个特定的场景，可以帮助开发者理解在特定条件下 `InsertListCommand` 的预期行为。
* **复现步骤：**  测试用例中的 HTML 结构和选区设置可以作为复现 bug 的步骤。开发者可以在一个本地的 Blink 环境中运行这些测试用例，观察是否会出现问题。
* **断言信息：**  测试用例中的 `EXPECT_TRUE` 和 `EXPECT_EQ` 等断言语句指明了预期的结果。如果实际结果与预期不符，就说明 `InsertListCommand` 的实现可能存在 bug。
* **关联的 Bug ID：**  测试用例中经常会引用 `crbug.com` 的链接，这些链接指向了 Chromium 的 bug 跟踪系统，可以提供关于该测试用例所要解决的具体 bug 的背景信息和复现步骤。
* **逐步执行：** 开发者可以使用调试器逐步执行 `InsertListCommand` 的代码，结合测试用例的输入和预期输出，来定位问题所在。

总而言之，`insert_list_command_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎在处理用户插入和移除列表操作时的正确性和健壮性，涵盖了各种复杂场景和潜在的错误情况，并与 HTML, CSS 和 JavaScript 的行为紧密相关。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/insert_list_command_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2016 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/commands/insert_list_command.h"

#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/selection_template.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/testing/selection_sample.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"

namespace blink {

class InsertListCommandTest : public EditingTestBase {};

TEST_F(InsertListCommandTest, ShouldCleanlyRemoveSpuriousTextNode) {
  GetDocument().SetCompatibilityMode(Document::kQuirksMode);
  // Needs to be editable to use InsertListCommand.
  GetDocument().setDesignMode("on");
  // Set up the condition:
  // * Selection is a range, to go down into
  //   InsertListCommand::listifyParagraph.
  // * The selection needs to have a sibling list to go down into
  //   InsertListCommand::mergeWithNeighboringLists.
  // * Should be the same type (ordered list) to go into
  //   CompositeEditCommand::mergeIdenticalElements.
  // * Should have no actual children to fail the listChildNode check
  //   in InsertListCommand::doApplyForSingleParagraph.
  // * There needs to be an extra text node to trigger its removal in
  //   CompositeEditCommand::mergeIdenticalElements.
  // The removeNode is what updates document lifecycle to VisualUpdatePending
  // and makes FrameView::needsLayout return true.
  SetBodyContent("\nd\n<ol>");
  Text* empty_text = GetDocument().createTextNode("");
  GetDocument().body()->InsertBefore(empty_text,
                                     GetDocument().body()->firstChild());
  UpdateAllLifecyclePhasesForTest();
  GetDocument().GetFrame()->Selection().SetSelection(
      SelectionInDOMTree::Builder()
          .Collapse(Position(GetDocument().body(), 0))
          .Extend(Position(GetDocument().body(), 2))
          .Build(),
      SetSelectionOptions());

  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kOrderedList);
  // This should not DCHECK.
  EXPECT_TRUE(command->Apply())
      << "The insert ordered list command should have succeeded";
  EXPECT_EQ("<ol><li>\nd\n</li></ol>", GetDocument().body()->innerHTML());
}

// Refer https://crbug.com/794356
TEST_F(InsertListCommandTest, UnlistifyParagraphCrashOnVisuallyEmptyParagraph) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody("^<dl>"
                             "<textarea style='float:left;'></textarea>"
                             "</dl>|"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kUnorderedList);
  // Crash happens here.
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ(
      "<dl><ul>"
      "|<textarea style=\"float:left;\"></textarea>"
      "</ul></dl>",
      GetSelectionTextFromBody());
}

TEST_F(InsertListCommandTest, UnlistifyParagraphCrashOnNonLi) {
  // Checks that InsertOrderedList does not cause a crash when the caret is in a
  // non-<li> child of a list which contains non-<li> blocks.
  GetDocument().setDesignMode("on");
  Selection().SetSelection(SetSelectionTextToBody("<ol><div>|"
                                                  "<p>foo</p><p>bar</p>"
                                                  "</div></ol>"),
                           SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kOrderedList);
  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ("|foo<br><ol><p>bar</p></ol>", GetSelectionTextFromBody());
}

// Refer https://crbug.com/798176
TEST_F(InsertListCommandTest, CleanupNodeSameAsDestinationNode) {
  GetDocument().setDesignMode("on");
  InsertStyleElement(
      "* { -webkit-appearance:checkbox; }"
      "br { visibility:hidden; }"
      "colgroup { -webkit-column-count:2; }");
  Selection().SetSelection(SetSelectionTextToBody("^<table><col></table>"
                                                  "<button></button>|"),
                           SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kUnorderedList);
  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<ul><li><table><colgroup><col>"
      "</colgroup></table></li>"
      "<li><button>|</button></li></ul><br>",
      GetSelectionTextFromBody());
}

TEST_F(InsertListCommandTest, InsertListOnEmptyHiddenElements) {
  GetDocument().setDesignMode("on");
  InsertStyleElement("br { visibility:hidden; }");
  Selection().SetSelection(SetSelectionTextToBody("^<button></button>|"),
                           SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kUnorderedList);

  // Crash happens here.
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ("^<button><ul><li><br></li></ul></button>|",
            GetSelectionTextFromBody());
}

// Refer https://crbug.com/797520
TEST_F(InsertListCommandTest, InsertListWithCollapsedVisibility) {
  GetDocument().setDesignMode("on");
  InsertStyleElement(
      "ul { visibility:collapse; }"
      "dl { visibility:visible; }");

  Selection().SetSelection(SetSelectionTextToBody("^<dl>a</dl>|"),
                           SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kOrderedList);

  // Crash happens here.
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ("^<dl><ol></ol><ul>a</ul></dl>|", GetSelectionTextFromBody());
}

// Refer https://crbug.com/1183158
TEST_F(InsertListCommandTest, UnlistifyParagraphWithNonEditable) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody("<li>a|<div contenteditable=false>b</div></li>"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kUnorderedList);

  // Crash happens here.
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ("<ul><li>a|<div contenteditable=\"false\">b</div></li></ul><br>",
            GetSelectionTextFromBody());
}

// Refer https://crbug.com/1188327
TEST_F(InsertListCommandTest, NestedSpansJustInsideBody) {
  InsertStyleElement("span { appearance: checkbox; }");
  GetDocument().setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody("<span><span><span>a</span></span></span>|b"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kUnorderedList);

  // Crash happens here.
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ(
      "<ul><li><br>a</li></ul><span><span><span>^a</span></span></span>b|",
      GetSelectionTextFromBody());
}

TEST_F(InsertListCommandTest, ListifyInputInTableCell) {
  GetDocument().setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody(
          "^<ruby><div style='display: table-cell'><input style='display: "
          "table-cell' type='file' maxlength='100'><select>|"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kUnorderedList);

  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<ruby><div style=\"display: "
      "table-cell\"><ul><li>^<br></li><li><ruby><div style=\"display: "
      "table-cell\">|<input maxlength=\"100\" style=\"display: table-cell\" "
      "type=\"file\"></div></ruby></li><li><select></select></li></ul></div></"
      "ruby>",
      GetSelectionTextFromBody());
}

TEST_F(InsertListCommandTest, ListifyInputInTableCell1) {
  GetDocument().setDesignMode("on");
  InsertStyleElement(
      "rb { display: table-cell; }"
      "input { float: left; }");
  Selection().SetSelection(
      SetSelectionTextToBody("<div contenteditable='true'><ol><li>^<br></li>"
                             "<li><ruby><rb><input></input></rb></ruby></li>"
                             "<li>XXX</li></ol><div>|</div>"),
      SetSelectionOptions());
  auto* command = MakeGarbageCollected<InsertListCommand>(
      GetDocument(), InsertListCommand::kOrderedList);

  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<div contenteditable=\"true\">^<br><ol><li><ruby><rb><ol><li><br></li>"
      "<li><ruby><rb><input></rb></ruby></li><li><br></li><li><br></li></ol>"
      "</rb></ruby></li></ol>|XXX<div></div></div>",
      GetSelectionTextFromBody());
}

// Refer https://crbug.com/1295037
TEST_F(InsertListCommandTest, NonCanonicalVisiblePosition) {
  Document& document = GetDocument();
  document.setDesignMode("on");
  InsertStyleElement("select { width: 100vw; }");
  SetBodyInnerHTML(
      "<textarea></textarea><svg></svg><select></select><div><input></div>");
  const Position& base =
      Position::BeforeNode(*document.QuerySelector(AtomicString("select")));
  const Position& extent =
      Position::AfterNode(*document.QuerySelector(AtomicString("input")));
  Selection().SetSelection(
      SelectionInDOMTree::Builder().Collapse(base).Extend(extent).Build(),
      SetSelectionOptions());

  // |base| and |extent| are 'canonical' with regard to VisiblePosition.
  ASSERT_EQ(CreateVisiblePosition(base).DeepEquivalent(), base);
  ASSERT_EQ(CreateVisiblePosition(extent).DeepEquivalent(), extent);

  // But |base| is not canonical with regard to CanonicalPositionOf.
  ASSERT_NE(CanonicalPositionOf(base), base);
  ASSERT_EQ(CanonicalPositionOf(extent), extent);

  auto* command = MakeGarbageCollected<InsertListCommand>(
      document, InsertListCommand::kUnorderedList);

  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<ul><li><textarea></textarea><svg></svg>^<select></select></li>"
      "<li><input>|</li></ul>",
      GetSelectionTextFromBody());
}

// Refer https://crbug.com/1316041
TEST_F(InsertListCommandTest, TimeAndMeterInRoot) {
  Document& document = GetDocument();
  document.setDesignMode("on");

  Element* root = document.documentElement();
  Element* time = document.CreateRawElement(html_names::kTimeTag);
  Element* meter = document.CreateRawElement(html_names::kMeterTag);
  time->appendChild(meter);
  root->insertBefore(time, root->firstChild());

  Selection().SetSelection(SelectionInDOMTree::Builder()
                               .Collapse(Position(time, 0))
                               .Extend(Position::LastPositionInNode(*time))
                               .Build(),
                           SetSelectionOptions());

  auto* command = MakeGarbageCollected<InsertListCommand>(
      document, InsertListCommand::kUnorderedList);

  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ("<ul><li>|<time></time></li></ul><head></head><body></body>",
            SelectionSample::GetSelectionText(
                *root, Selection().GetSelectionInDOMTree()));
}

// Refer https://crbug.com/1312348
TEST_F(InsertListCommandTest, PreservedNewline) {
  Document& document = GetDocument();
  document.setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody("<pre><span></span>\nX^<div></div>|</pre>"),
      SetSelectionOptions());

  auto* command = MakeGarbageCollected<InsertListCommand>(
      document, InsertListCommand::kOrderedList);

  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ("<pre><span></span>\n<ol><li>|X</li></ol><div></div></pre>",
            GetSelectionTextFromBody());
}

// Refer https://crbug.com/1343673
TEST_F(InsertListCommandTest, EmptyInlineBlock) {
  Document& document = GetDocument();
  document.setDesignMode("on");
  InsertStyleElement("span { display: inline-block; min-height: 1px; }");
  Selection().SetSelection(
      SetSelectionTextToBody("<ul><li><span>|</span></li></ul>"),
      SetSelectionOptions());

  auto* command = MakeGarbageCollected<InsertListCommand>(
      document, InsertListCommand::kUnorderedList);

  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ("<ul><li><span></span></li></ul>|<br>", GetSelectionTextFromBody());
}

// Refer https://crbug.com/1350571
TEST_F(InsertListCommandTest, SelectionFromEndOfTableToAfterTable) {
  Document& document = GetDocument();
  document.setDesignMode("on");
  Selection().SetSelection(SetSelectionTextToBody("<table><td>^</td></table>|"),
                           SetSelectionOptions());

  auto* command = MakeGarbageCollected<InsertListCommand>(
      document, InsertListCommand::kOrderedList);

  // Crash happens here.
  EXPECT_TRUE(command->Apply());
  EXPECT_EQ(
      "<table><tbody><tr><td><ol><li>|<br></li></ol></td></tr></tbody></table>",
      GetSelectionTextFromBody());
}

// Refer https://crbug.com/1366749
TEST_F(InsertListCommandTest, ListItemWithSpace) {
  Document& document = GetDocument();
  document.setDesignMode("on");
  Selection().SetSelection(
      SetSelectionTextToBody(
          "<li>^ <div contenteditable='false'>A</div>B|</li>"),
      SetSelectionOptions());

  auto* command = MakeGarbageCollected<InsertListCommand>(
      document, InsertListCommand::kOrderedList);

  // Crash happens here.
  EXPECT_FALSE(command->Apply());
  EXPECT_EQ("<ul><li> <div contenteditable=\"false\">A</div>B|</li></ul><br>",
            GetSelectionTextFromBody());
}
}

"""

```