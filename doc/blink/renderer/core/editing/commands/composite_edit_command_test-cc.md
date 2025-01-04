Response:
My thinking process to answer the request about `composite_edit_command_test.cc` goes like this:

1. **Understand the Goal:** The primary goal is to explain what this test file does, its relevance to web technologies, how it's used, common errors, and how one might reach this code during debugging.

2. **Identify the Core Functionality:** The file name `composite_edit_command_test.cc` immediately suggests it's a test file for something called `CompositeEditCommand`. The `#include` directives confirm this and give context: editing, DOM manipulation, and selections.

3. **Analyze the Test Structure:**  The code uses the `TEST_F` macro, which is a standard Google Test (gtest) construct. This tells me it's a unit test suite. Each `TEST_F` block represents a specific test case.

4. **Examine Individual Test Cases:** I'll go through each `TEST_F` block and try to understand its purpose. Key elements to look for are:
    * **Setup:**  How is the initial HTML structure created (`SetBodyContent`)?
    * **Action:** What method of `SampleCommand` (a custom class inheriting from `CompositeEditCommand`) is being called?
    * **Assertions:** What is being checked (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`)? These reveal the expected behavior of the command under test.

5. **Relate to Web Technologies (HTML, CSS, JavaScript):**
    * **HTML:** The `SetBodyContent` calls directly manipulate the HTML structure. The tests often involve creating specific HTML elements and checking the resulting DOM after the command executes.
    * **CSS:** Some tests involve applying CSS styles (`InsertStyleElement`) to check how the editing commands interact with styling (e.g., `user-modify`, `user-select`, `display: inline-block`).
    * **JavaScript:** While this particular file doesn't directly execute JavaScript, the underlying editing commands are often triggered by user actions that *could* be initiated by JavaScript (e.g., `document.execCommand`). The tests ensure these commands work correctly regardless of how they are triggered.

6. **Infer Logical Reasoning and Assumptions:** For each test, I consider the "given" (the initial HTML) and the "when" (the command being executed). The assertions then represent the "then" (the expected outcome). I'll try to articulate this as "Assumption" (input) and "Output".

7. **Identify Potential User Errors:**  By looking at the test cases, I can deduce scenarios where a user's action might lead to unexpected behavior. For example, attempting to edit content marked as non-editable or trying to manipulate disconnected DOM nodes.

8. **Trace User Actions to the Code:** This requires thinking about how a user interacts with a web page and how those interactions are translated into browser operations. Common editing actions like typing, deleting, moving text, and applying formatting are the starting points. I then need to connect these high-level actions to the lower-level editing commands being tested.

9. **Structure the Answer:**  Organize the information logically:
    * Start with a concise summary of the file's purpose.
    * Detail the functionality with specific examples from the tests.
    * Explain the relationship to HTML, CSS, and JavaScript with concrete examples.
    * Provide input/output examples to illustrate the logic.
    * Describe common user errors that might trigger these code paths.
    * Explain the user journey to reach this code for debugging.

10. **Refine and Elaborate:** Review the answer for clarity, accuracy, and completeness. Provide sufficient detail without being overly technical. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the technical aspects of the C++ code.
* **Correction:** Realize the prompt asks for the *relevance* to web technologies. Shift focus to explain how the C++ code underpins user-facing features.

* **Initial thought:**  Simply list the tests.
* **Correction:**  Instead, group tests by functionality (inserting nodes, moving paragraphs) to make the explanation more coherent.

* **Initial thought:**  Assume the reader is a C++ developer.
* **Correction:**  Explain concepts in a way that is accessible to someone with a broader understanding of web development (HTML, CSS, JavaScript).

By following this systematic approach, I can generate a comprehensive and informative answer that addresses all aspects of the request.
这个文件 `composite_edit_command_test.cc` 是 Chromium Blink 引擎中用于测试 `CompositeEditCommand` 类的单元测试文件。`CompositeEditCommand` 类是 Blink 编辑器中用于执行复合编辑操作的基础类，它允许将多个小的编辑操作组合成一个逻辑上的原子操作。

**主要功能：**

1. **测试 `CompositeEditCommand` 类的基本功能:** 该文件通过创建继承自 `CompositeEditCommand` 的 `SampleCommand` 类，并针对其特定的方法进行测试，来验证 `CompositeEditCommand` 基类的核心功能是否正常工作。
2. **测试插入节点操作 (`InsertNodeBefore`, `InsertNodeAfter`):** 测试在可编辑区域和不可编辑区域插入节点的不同行为，以及处理断开连接的节点的情况。
3. **测试移动段落内容到新块 (`MoveParagraphContentsToNewBlockIfNecessary`):** 测试在不同场景下，将段落内容移动到新的块级元素中的逻辑，包括处理只读样式、UA Shadow DOM 以及带有 `<br>` 标签的元素。
4. **测试移动段落 (`MoveParagraphs`):** 测试在各种复杂的 HTML 结构中移动段落的功能，包括带有 `<br>` 标签、inline-block 元素以及表格和标题的情况。
5. **测试编辑状态 (`EditingState`):**  验证在不同的操作场景下，编辑状态是否正确地被更新和维护，例如操作是否被中止 (`IsAborted`)。

**与 JavaScript, HTML, CSS 的关系：**

该文件测试的 `CompositeEditCommand` 类是 Blink 引擎编辑功能的核心组成部分，它直接影响用户在网页上进行编辑操作的行为。这些操作通常是由用户的交互（例如键盘输入、鼠标操作）触发，并可能通过 JavaScript 的 `document.execCommand()` 方法调用。

* **HTML:** 测试用例通过 `SetBodyContent()` 方法设置 HTML 结构，模拟不同的编辑场景。例如，测试在 `<div>` 元素中插入节点，或者移动包含特定 HTML 标签（如 `<br>`, `<span>`, `<table>`）的段落。测试结果通过比较操作后的 HTML 结构来验证。
    * **例子:**  `TEST_F(CompositeEditCommandTest, insertNodeBefore)`  测试在 `<div>` 中插入节点后，`<div>` 的 `innerHTML()` 是否符合预期。
* **CSS:**  某些测试用例会使用 `InsertStyleElement()` 插入 CSS 样式，来模拟特定的渲染和行为。例如，测试 `MoveParagraphContentsToNewBlockWithNonEditableStyle` 用来检查当元素具有 `-webkit-user-modify:read-only` 样式时，移动段落内容的操作是否会中止。
    * **例子:**  `TEST_F(CompositeEditCommandTest, MoveParagraphContentsToNewBlockWithNonEditableStyle)`  设置了阻止用户修改的 CSS 样式，然后测试移动段落内容的操作是否被阻止。
* **JavaScript:**  尽管这个测试文件本身是 C++ 代码，它测试的功能是 JavaScript 可以触发的。例如，用户在可编辑区域按下回车键可能会触发创建新段落的操作，而 `MoveParagraphContentsToNewBlockIfNecessary` 的逻辑可能被调用。开发者可以使用 `document.execCommand('insertBrOnReturn')` 等命令来间接触发这些编辑操作。

**逻辑推理 (假设输入与输出):**

* **假设输入 (针对 `insertNodeBefore` 测试):**
    * HTML: `<div contenteditable><b></b></div>`
    * 操作: 调用 `sample.InsertNodeBefore(insert_child, ref_child, &editing_state)`，其中 `insert_child` 是文本节点 "foo"，`ref_child` 是 `<b>` 元素。
* **预期输出:**
    * `editing_state.IsAborted()` 为 `false` (操作未中止)。
    * `div->innerHTML()` 为 `"foo<b></b>"`。

* **假设输入 (针对 `MoveParagraphContentsToNewBlockWithNonEditableStyle` 测试):**
    * HTML: `<style>div{-webkit-user-modify:read-only;user-select:none;}</style>foo`
    * 操作: 调用 `sample.MoveParagraphContentsToNewBlockIfNecessary(Position(text, 0), &editing_state)`。
* **预期输出:**
    * `editing_state.IsAborted()` 为 `true` (操作被中止)。
    * `body->innerHTML()` 保持不变或者进行了最小的、不影响原始内容的调整，但不会成功移动段落内容。

**用户或编程常见的使用错误：**

* **尝试在不可编辑区域进行编辑操作:**  `TEST_F(CompositeEditCommandTest, insertNodeBeforeInUneditable)`  模拟了这种情况。用户或者程序尝试在 `contenteditable="false"` 的元素内部插入节点，这是一个常见的错误。引擎应该阻止此类操作。
* **操作断开连接的 DOM 节点:** `TEST_F(CompositeEditCommandTest, insertNodeBeforeDisconnectedNode)` 和 `TEST_F(CompositeEditCommandTest, InsertNodeOnDisconnectedParent)`  测试了这种情况。当尝试操作已经从文档树中移除的节点时，编辑命令应该能够处理这种情况，通常不会执行任何操作或者中止操作。这是一个编程错误，因为通常不应该尝试操作不存在于当前文档结构中的节点。
* **在复杂的 DOM 结构中进行编辑操作导致意外结果:**  `MoveParagraphs` 系列的测试用例旨在覆盖各种复杂的 HTML 结构，例如包含 inline-block 元素、`<br>` 标签、表格和标题等，这些都是用户可能创建的复杂页面结构，编辑器的行为需要正确且符合预期。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户在可编辑区域进行编辑:** 用户可能在网页上一个 `contenteditable` 属性设置为 `true` 的区域内进行输入、粘贴、拖拽或者使用格式化工具。
2. **浏览器捕获用户操作:** 浏览器的事件监听器会捕获用户的操作，例如 `keydown`, `mouseup`, `dragend` 等事件。
3. **事件处理与命令调用:** 浏览器会根据用户的操作类型，调用相应的编辑命令。例如，按下 Enter 键可能触发插入换行符或创建新段落的命令。这些命令最终会通过 `CompositeEditCommand` 或其子类来执行。
4. **执行复合编辑操作:**  如果一个操作包含多个步骤（例如，粘贴一段富文本可能涉及创建多个节点和设置样式），则会使用 `CompositeEditCommand` 将这些步骤组合成一个原子操作。
5. **进入 `composite_edit_command_test.cc` 的场景:**  当开发者在 Chromium 引擎中进行编辑功能的开发或调试时，他们可能会编写或运行 `composite_edit_command_test.cc` 中的单元测试来验证他们修改的代码是否正确工作。

**调试线索：**

* **如果用户报告了编辑相关的 bug (例如，插入文本错位，移动段落失败):** 开发者可能会首先尝试复现 bug，然后分析相关的代码路径，这很可能涉及到 `CompositeEditCommand` 及其子类的执行。
* **通过断点调试:** 开发者可以在 `CompositeEditCommand` 的 `DoApply()` 方法或者其子类的方法中设置断点，来跟踪编辑命令的执行流程。
* **查看日志输出:**  Blink 引擎通常会有详细的日志输出，可以帮助开发者了解在执行编辑操作时，哪些命令被调用，以及编辑状态的变化。
* **单元测试失败:** 如果 `composite_edit_command_test.cc` 中的某个测试用例失败了，这通常意味着相关的编辑逻辑存在问题，开发者需要分析失败的测试用例，找到导致失败的原因。

总而言之，`composite_edit_command_test.cc` 是一个至关重要的测试文件，用于确保 Blink 引擎的编辑功能稳定可靠。它通过模拟各种用户操作可能触发的场景，来验证编辑命令的正确性，并帮助开发者发现和修复潜在的 bug。

Prompt: 
```
这是目录为blink/renderer/core/editing/commands/composite_edit_command_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/editing/commands/composite_edit_command.h"

#include "third_party/blink/renderer/core/css/css_property_value_set.h"
#include "third_party/blink/renderer/core/dom/document.h"
#include "third_party/blink/renderer/core/dom/text.h"
#include "third_party/blink/renderer/core/editing/frame_selection.h"
#include "third_party/blink/renderer/core/editing/testing/editing_test_base.h"
#include "third_party/blink/renderer/core/editing/visible_position.h"
#include "third_party/blink/renderer/core/editing/visible_units.h"
#include "third_party/blink/renderer/core/frame/local_frame.h"
#include "third_party/blink/renderer/core/keywords.h"

namespace blink {

namespace {

class SampleCommand final : public CompositeEditCommand {
 public:
  SampleCommand(Document&);

  void InsertNodeBefore(Node*,
                        Node* ref_child,
                        EditingState*,
                        ShouldAssumeContentIsAlwaysEditable =
                            kDoNotAssumeContentIsAlwaysEditable);
  void InsertNodeAfter(Node*, Node*, EditingState*);

  void MoveParagraphContentsToNewBlockIfNecessary(const Position&,
                                                  EditingState*);
  void MoveParagraphs(const VisiblePosition& start_of_paragraph_to_move,
                      const VisiblePosition& end_of_paragraph_to_move,
                      const VisiblePosition& destination,
                      EditingState* editing_state);

  // CompositeEditCommand member implementations
  void DoApply(EditingState*) final {}
  InputEvent::InputType GetInputType() const final {
    return InputEvent::InputType::kNone;
  }
};

SampleCommand::SampleCommand(Document& document)
    : CompositeEditCommand(document) {}

void SampleCommand::InsertNodeBefore(
    Node* insert_child,
    Node* ref_child,
    EditingState* editing_state,
    ShouldAssumeContentIsAlwaysEditable
        should_assume_content_is_always_editable) {
  CompositeEditCommand::InsertNodeBefore(
      insert_child, ref_child, editing_state,
      should_assume_content_is_always_editable);
}

void SampleCommand::InsertNodeAfter(Node* insert_child,
                                    Node* ref_child,
                                    EditingState* editing_state) {
  CompositeEditCommand::InsertNodeAfter(insert_child, ref_child, editing_state);
}

void SampleCommand::MoveParagraphContentsToNewBlockIfNecessary(
    const Position& position,
    EditingState* editing_state) {
  CompositeEditCommand::MoveParagraphContentsToNewBlockIfNecessary(
      position, editing_state);
}

void SampleCommand::MoveParagraphs(
    const VisiblePosition& start_of_paragraph_to_move,
    const VisiblePosition& end_of_paragraph_to_move,
    const VisiblePosition& destination,
    EditingState* editing_state) {
  CompositeEditCommand::MoveParagraphs(start_of_paragraph_to_move,
                                       end_of_paragraph_to_move, destination,
                                       editing_state);
}

}  // namespace

class CompositeEditCommandTest : public EditingTestBase {};

TEST_F(CompositeEditCommandTest, insertNodeBefore) {
  SetBodyContent("<div contenteditable><b></b></div>");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Node* insert_child = GetDocument().createTextNode("foo");
  Element* ref_child = GetDocument().QuerySelector(AtomicString("b"));
  Element* div = GetDocument().QuerySelector(AtomicString("div"));

  EditingState editing_state;
  sample.InsertNodeBefore(insert_child, ref_child, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("foo<b></b>", div->innerHTML());
}

TEST_F(CompositeEditCommandTest, insertNodeBeforeInUneditable) {
  SetBodyContent("<div><b></b></div>");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Node* insert_child = GetDocument().createTextNode("foo");
  Element* ref_child = GetDocument().QuerySelector(AtomicString("b"));

  EditingState editing_state;
  sample.InsertNodeBefore(insert_child, ref_child, &editing_state);
  EXPECT_TRUE(editing_state.IsAborted());
}

TEST_F(CompositeEditCommandTest, insertNodeBeforeDisconnectedNode) {
  SetBodyContent("<div><b></b></div>");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Node* insert_child = GetDocument().createTextNode("foo");
  Element* ref_child = GetDocument().QuerySelector(AtomicString("b"));
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  div->remove();

  EditingState editing_state;
  sample.InsertNodeBefore(insert_child, ref_child, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("<b></b>", div->innerHTML())
      << "InsertNodeBeforeCommand does nothing for disconnected node";
}

TEST_F(CompositeEditCommandTest, insertNodeBeforeWithDirtyLayoutTree) {
  SetBodyContent("<div><b></b></div>");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Node* insert_child = GetDocument().createTextNode("foo");
  Element* ref_child = GetDocument().QuerySelector(AtomicString("b"));
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  div->setAttribute(html_names::kContenteditableAttr, keywords::kTrue);

  EditingState editing_state;
  sample.InsertNodeBefore(insert_child, ref_child, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("foo<b></b>", div->innerHTML());
}

TEST_F(CompositeEditCommandTest,
       MoveParagraphContentsToNewBlockWithNonEditableStyle) {
  SetBodyContent(
      "<style>div{-webkit-user-modify:read-only;user-select:none;}</style>"
      "foo");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Element* body = GetDocument().body();
  Node* text = body->lastChild();
  body->setAttribute(html_names::kContenteditableAttr, keywords::kTrue);
  GetDocument().UpdateStyleAndLayout(DocumentUpdateReason::kTest);

  EditingState editing_state;
  sample.MoveParagraphContentsToNewBlockIfNecessary(Position(text, 0),
                                                    &editing_state);
  EXPECT_TRUE(editing_state.IsAborted());
  EXPECT_EQ(
      "<div><br></div>"
      "<style>div{-webkit-user-modify:read-only;user-select:none;}</style>"
      "foo",
      body->innerHTML());
}

TEST_F(CompositeEditCommandTest,
       MoveParagraphContentsToNewBlockWithUAShadowDOM1) {
  SetBodyContent("<object contenteditable><input></object>");
  base::RunLoop().RunUntilIdle();

  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Element* input = GetDocument().QuerySelector(AtomicString("input"));
  Position pos = Position::BeforeNode(*input);
  EditingState editing_state;

  // Should not crash
  sample.MoveParagraphContentsToNewBlockIfNecessary(pos, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("<object contenteditable=\"\"><div><input></div></object>",
            GetDocument().body()->innerHTML());
}

TEST_F(CompositeEditCommandTest,
       MoveParagraphContentsToNewBlockWithUAShadowDOM2) {
  GetDocument().setDesignMode("on");
  SetBodyContent("<span></span><button><meter></meter></button>");

  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Element* button = GetDocument().QuerySelector(AtomicString("button"));
  Position pos = Position(button, 0);
  EditingState editing_state;

  // Should not crash
  sample.MoveParagraphContentsToNewBlockIfNecessary(pos, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("<div></div><span></span><button><meter></meter></button>",
            GetDocument().body()->innerHTML());
}

TEST_F(CompositeEditCommandTest,
       MoveParagraphContentsToNewBlockWithButtonAndBr) {
  GetDocument().setDesignMode("on");
  InsertStyleElement("br { content: 'x'; }");
  SetBodyContent("<button><br></button>");

  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Element* button = GetDocument().QuerySelector(AtomicString("button"));
  Position pos = Position(button, 0);
  EditingState editing_state;

  // Should not crash
  sample.MoveParagraphContentsToNewBlockIfNecessary(pos, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("<button><div><br></div><br></button>",
            GetDocument().body()->innerHTML());
}

TEST_F(CompositeEditCommandTest, InsertNodeOnDisconnectedParent) {
  SetBodyContent("<p><b></b></p>");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Node* insert_child = GetDocument().QuerySelector(AtomicString("b"));
  Element* ref_child = GetDocument().QuerySelector(AtomicString("p"));
  ref_child->remove();
  EditingState editing_state_before;
  // editing state should abort here.
  sample.InsertNodeBefore(insert_child, ref_child, &editing_state_before);
  EXPECT_TRUE(editing_state_before.IsAborted());

  EditingState editing_state_after;
  // editing state should abort here.
  sample.InsertNodeAfter(insert_child, ref_child, &editing_state_after);
  EXPECT_TRUE(editing_state_after.IsAborted());
}

TEST_F(CompositeEditCommandTest, MoveParagraphsWithBr) {
  SetBodyContent("<ol><li><span><br></span></li></ol><br>");

  EditingState editing_state;
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Element* li = GetDocument().QuerySelector(AtomicString("li"));
  Element* br1 = GetDocument().QuerySelector(AtomicString("ol br"));
  Element* br2 = GetDocument().QuerySelector(AtomicString("ol + br"));
  br1->setTextContent("x");
  UpdateAllLifecyclePhasesForTest();

  // The start precedes the end, but when using MostFor/BackwardCaretPosition
  // to constrain the range, the resulting end would precede the start.
  const VisiblePosition& start = VisiblePosition::FirstPositionInNode(*li);
  const VisiblePosition& end = VisiblePosition::LastPositionInNode(*li);
  const VisiblePosition& destination = VisiblePosition::BeforeNode(*br2);
  EXPECT_EQ(start.DeepEquivalent(), Position::BeforeNode(*br1));
  EXPECT_EQ(end.DeepEquivalent(), Position(br1, 0));
  EXPECT_EQ(destination.DeepEquivalent(), Position::BeforeNode(*br2));
  EXPECT_LT(start.DeepEquivalent(), end.DeepEquivalent());
  EXPECT_GT(MostForwardCaretPosition(start.DeepEquivalent()),
            MostBackwardCaretPosition(end.DeepEquivalent()));

  // Should not crash
  sample.MoveParagraphs(start, end, destination, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("<ol><li><span><br></span></li></ol><br>",
            GetDocument().body()->innerHTML());
}

TEST_F(CompositeEditCommandTest, MoveParagraphsWithInlineBlocks) {
  InsertStyleElement("span {display: inline-block; width: 0; height: 10px}");
  SetBodyContent("<div><span></span><span></span>&#x20;</div><br>");

  EditingState editing_state;
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Element* div = GetDocument().QuerySelector(AtomicString("div"));
  Element* span1 = GetDocument().QuerySelector(AtomicString("span"));
  Element* span2 = GetDocument().QuerySelector(AtomicString("span + span"));
  Element* br = GetDocument().QuerySelector(AtomicString("br"));

  // The start precedes the end, but when using MostFor/BackwardCaretPosition
  // to constrain the range, the resulting end would precede the start.
  const VisiblePosition& start = VisiblePosition::FirstPositionInNode(*div);
  const VisiblePosition& end = VisiblePosition::LastPositionInNode(*div);
  const VisiblePosition& destination = VisiblePosition::BeforeNode(*br);
  EXPECT_EQ(start.DeepEquivalent(), Position::BeforeNode(*span1));
  EXPECT_EQ(end.DeepEquivalent(), Position::BeforeNode(*span2));
  EXPECT_EQ(destination.DeepEquivalent(), Position::BeforeNode(*br));
  EXPECT_LT(start.DeepEquivalent(), end.DeepEquivalent());
  EXPECT_GT(MostForwardCaretPosition(start.DeepEquivalent()),
            MostBackwardCaretPosition(end.DeepEquivalent()));

  // Should not crash
  sample.MoveParagraphs(start, end, destination, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("<div><span></span><span></span> </div><br>",
            GetDocument().body()->innerHTML());
}

TEST_F(CompositeEditCommandTest, MoveParagraphsWithTableAndCaption) {
  Document& document = GetDocument();
  document.setDesignMode("on");
  InsertStyleElement(
      "table { writing-mode: vertical-lr; }"
      "caption { appearance: radio; }");
  SetBodyInnerHTML("<table><caption><div><br></div><input></caption></table>");

  EditingState editing_state;
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());
  Element* br = document.QuerySelector(AtomicString("br"));
  Element* input = document.QuerySelector(AtomicString("input"));

  const VisiblePosition& start = VisiblePosition::FirstPositionInNode(*input);
  const VisiblePosition& end = VisiblePosition::AfterNode(*input);
  const VisiblePosition& destination = VisiblePosition::BeforeNode(*br);
  EXPECT_EQ(start.DeepEquivalent(), Position::BeforeNode(*input));
  EXPECT_EQ(end.DeepEquivalent(), Position::AfterNode(*input));
  EXPECT_EQ(destination.DeepEquivalent(), Position::BeforeNode(*br));

  // Should not crash. See http://crbug.com/1310613
  sample.MoveParagraphs(start, end, destination, &editing_state);
  EXPECT_FALSE(editing_state.IsAborted());
  EXPECT_EQ("<table><caption><div><input></div></caption></table>",
            GetDocument().body()->innerHTML());
}

TEST_F(CompositeEditCommandTest,
       MoveParagraphContentsToNewBlockWithNullVisiblePosition1) {
  EditingState editing_state;
  Document& document = GetDocument();
  Element* body = document.body();
  document.setDesignMode("on");
  SetBodyInnerHTML("<div contenteditable=false><br></div>");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());

  // Should not crash. See http://crbug.com/1351899
  sample.MoveParagraphContentsToNewBlockIfNecessary(Position(body, 0),
                                                    &editing_state);
  EXPECT_TRUE(editing_state.IsAborted());
  EXPECT_EQ("<div contenteditable=\"false\"><br></div>", body->innerHTML());
}

TEST_F(CompositeEditCommandTest,
       MoveParagraphContentsToNewBlockWithNullVisiblePosition2) {
  EditingState editing_state;
  Document& document = GetDocument();
  Element* body = document.body();
  document.setDesignMode("on");
  InsertStyleElement("div, input {-webkit-user-modify: read-only}");
  SetBodyInnerHTML("<input>");
  SampleCommand& sample = *MakeGarbageCollected<SampleCommand>(GetDocument());

  // Should not crash. See http://crbug.com/1351899
  sample.MoveParagraphContentsToNewBlockIfNecessary(Position(body, 0),
                                                    &editing_state);
  EXPECT_TRUE(editing_state.IsAborted());
  EXPECT_EQ("<div><br></div><input>", body->innerHTML());
}

}  // namespace blink

"""

```